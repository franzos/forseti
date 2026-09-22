//! `/sso/{slug}` + `/sso/callback` — the browser-facing SSO flow.
//!
//! Start redirects to Jackson's authorize endpoint with a signed state
//! cookie binding the round-trip; the callback exchanges the code,
//! resolves the asserted email to a Kratos identity (link → verified
//! match → JIT create), then establishes a native Kratos session via an
//! admin-minted recovery link.
//!
//! Every can't-start cause renders ONE uniform neutral page so the URL
//! can't be used to probe which orgs have SSO configured.

use std::sync::OnceLock;
use std::time::Duration;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{self, AuditCtx, AuditEvent, action, target_kind};
use crate::audit_metadata;
use crate::commercial::license::{Feature, FeatureStatus};
use crate::config::SamlConfig;
use crate::orgs;
use crate::ory::Identity;
use crate::ory::kratos;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::saml::{db, jackson, state_cookie};
use crate::signed_cookie::unix_seconds_now;
use crate::state::AppState;
use crate::web::{append_set_cookie, render_error_boundary};

// SAML keys, not literals: the ACS callback carries no request locale
// (`start` has no headers at all), so these are looked up under
// `default_locale()` at render time. See `neutral_unavailable`/`error_page`.
const VALIDATION_FAILED_KEY: &str = "error-boundary-sso-validation-failed-body";
const UPSTREAM_FAILED_KEY: &str = "error-boundary-sso-upstream-failed-body";

/// Jackson speaks the workspace reqwest (0.13); the Ory SDK's shared client
/// is the renamed reqwest-0.12 type, so it can't be reused here.
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client builds")
    })
}

/// Uniform "no SSO here" page — identical for unknown slug, missing or
/// disabled connection, and locked license, so responses don't leak
/// which orgs have SSO.
fn neutral_unavailable(state: &AppState) -> Response {
    let locale = crate::locale::default_locale();
    render_error_boundary(
        state,
        &locale,
        &crate::i18n::lookup(&locale, "error-boundary-sso-unavailable-title"),
        &crate::i18n::lookup(&locale, "error-boundary-sso-unavailable-body"),
        "/login",
        crate::i18n::lookup(&locale, "error-boundary-cta-sign-in"),
    )
}

/// `body_key` is a Fluent key (see `VALIDATION_FAILED_KEY`/`UPSTREAM_FAILED_KEY`).
fn error_page(state: &AppState, body_key: &str) -> Response {
    let locale = crate::locale::default_locale();
    render_error_boundary(
        state,
        &locale,
        &crate::i18n::lookup(&locale, "error-boundary-sso-failed-title"),
        &crate::i18n::lookup(&locale, body_key),
        "/login",
        crate::i18n::lookup(&locale, "error-boundary-cta-sign-in"),
    )
}

/// Why a sign-on was refused; drives the copy on `saml_blocked.html`.
#[derive(Clone, Copy)]
pub(crate) enum BlockedReason {
    /// Existing identity holds the email but hasn't verified it.
    Unverified,
    /// Verified identity matches but isn't a member of this org yet.
    CrossOrgNotMember,
    /// JIT create hit a 409 the verified-lookup missed.
    Conflict,
    /// The asserted address is on the operator admin allowlist. A tenant IdP
    /// is never a route to an operator account.
    AdminAllowlisted,
    /// Nobody holds the address and the org has not proven its domain, so
    /// provisioning it would let the IdP squat an arbitrary address.
    UnprovenDomain,
    /// The user came back from the credential-confirmation bounce signed in as
    /// somebody else, or not signed in at all.
    ConfirmFailed,
}

#[derive(Template)]
#[template(path = "saml_blocked.html")]
struct BlockedTemplate {
    chrome: PageChrome,
    email: String,
    reason: BlockedReason,
}

fn render_blocked(state: &AppState, email: &str, reason: BlockedReason) -> Response {
    render(&BlockedTemplate {
        // SAML callback path; no request Parts available, locale is inert
        chrome: PageChrome::from_parts(
            state,
            String::new(),
            None,
            String::new(),
            crate::locale::default_locale(),
        ),
        email: email.to_string(),
        reason,
    })
}

/// Signed state-cookie payload: `s` = nonce echoed via `?state=`,
/// `o` = resolved org id (so the callback never trusts a query param
/// for tenant selection).
#[derive(Deserialize, serde::Serialize)]
struct StatePayload {
    s: String,
    o: String,
}

pub async fn start(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    actx: AuditCtx,
) -> Response {
    // Defensive: the router is only mounted when [saml] is configured.
    let Some(cfg) = state.cfg.saml.as_ref() else {
        return neutral_unavailable(&state);
    };
    // GraceReadOnly keeps logins working; only a hard lock gates.
    if matches!(state.license.feature(Feature::Saml), FeatureStatus::Locked) {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::SAML_LOGIN_FAILED)
                .failed("license locked")
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "reason" => "license_locked",
                    "org_slug" => slug.as_str(),
                )),
        )
        .await;
        return neutral_unavailable(&state);
    }
    let org = match orgs::db::org_by_slug(&state.db, &slug).await {
        Ok(Some(org)) => org,
        Ok(None) => return neutral_unavailable(&state),
        Err(e) => {
            tracing::error!(error = ?e, "saml start: org lookup failed");
            return error_page(&state, UPSTREAM_FAILED_KEY);
        }
    };
    match db::get_connection(&state.db, &org.id).await {
        Ok(Some(conn)) if conn.is_enabled() => {}
        Ok(_) => return neutral_unavailable(&state),
        Err(e) => {
            tracing::error!(error = ?e, "saml start: connection lookup failed");
            return error_page(&state, UPSTREAM_FAILED_KEY);
        }
    }

    let nonce = uuid::Uuid::new_v4().to_string();
    let payload = match serde_json::to_vec(&StatePayload {
        s: nonce.clone(),
        o: org.id.clone(),
    }) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = ?e, "saml start: state payload encode failed");
            return error_page(&state, UPSTREAM_FAILED_KEY);
        }
    };
    let codec = state_cookie(state.cfg.self_.is_https());
    let encoded = codec.encode(&state.cookie_secret, &payload, unix_seconds_now());
    let url = jackson::authorize_url(cfg, &state.cfg.self_.url, &org.id, &nonce);
    let mut resp = Redirect::to(&url).into_response();
    append_set_cookie(&mut resp, Some(codec.set_header(&encoded)));
    resp
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
    headers: HeaderMap,
    actx: AuditCtx,
) -> Response {
    let codec = state_cookie(state.cfg.self_.is_https());
    let clear = codec.clear_header();
    let Some(cfg) = state.cfg.saml.as_ref() else {
        let mut resp = neutral_unavailable(&state);
        append_set_cookie(&mut resp, Some(clear));
        return resp;
    };

    let payload: Option<StatePayload> = codec
        .decode(&state.cookie_secret, &headers, unix_seconds_now())
        .and_then(|b| serde_json::from_slice(&b).ok());
    let validated = match (payload, q.state.as_deref(), q.code.as_deref()) {
        (Some(p), Some(qs), Some(code)) if p.s == qs && !code.is_empty() => {
            Some((p.o, code.to_string()))
        }
        _ => None,
    };
    let Some((org_id, code)) = validated else {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::SAML_LOGIN_FAILED)
                .failed("state validation failed")
                .with_ctx(&actx)
                .metadata(audit_metadata!("reason" => "state_mismatch")),
        )
        .await;
        let mut resp = error_page(&state, VALIDATION_FAILED_KEY);
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        append_set_cookie(&mut resp, Some(clear));
        return resp;
    };

    let client = http_client();
    let token =
        match jackson::exchange_code(cfg, client, &state.cfg.self_.url, &org_id, &code).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = ?e, "saml callback: token exchange failed");
                return fail_upstream(&state, &actx, &org_id, "token_exchange", clear).await;
            }
        };
    let profile = match jackson::userinfo(cfg, client, &token).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = ?e, "saml callback: userinfo failed");
            return fail_upstream(&state, &actx, &org_id, "userinfo", clear).await;
        }
    };

    let email = profile.email.trim().to_lowercase();
    // RFC 5321 caps addresses at 254 octets; anything longer is not a
    // usable address and must not reach templates or the audit log.
    if email.is_empty() || email.len() > 254 {
        let reason = if email.is_empty() {
            "missing_email"
        } else {
            "oversized_email"
        };
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::SAML_LOGIN_FAILED)
                .failed("idp asserted no usable email")
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "reason" => reason,
                    "org_id" => org_id.as_str(),
                )),
        )
        .await;
        let mut resp = error_page(&state, "error-boundary-sso-no-email-body");
        append_set_cookie(&mut resp, Some(clear));
        return resp;
    }

    let subject = profile.id.trim().to_string();
    let identity = match resolve_identity(&state, cfg, &actx, &org_id, &email, &profile).await {
        Ok(Resolution::Identity(identity)) => identity,
        // RFC 9700 §4.16: the assertion names an account that already exists
        // here. The IdP's word is not proof the user holds it, so bounce them
        // through their own Kratos credential first. Nothing is written yet;
        // the pending link rides a signed cookie across the round trip.
        Ok(Resolution::ConfirmCredential { identity_id }) => {
            let pending = PendingLink {
                o: org_id.clone(),
                e: email.clone(),
                s: subject,
                i: identity_id.clone(),
            };
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::SAML_LINK_CONFIRM_REQUIRED)
                    .actor_user(identity_id, email.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!("org_id" => org_id.as_str())),
            )
            .await;
            let codec = crate::saml::pending_link_cookie(state.cfg.self_.is_https());
            let payload = serde_json::to_vec(&pending).unwrap_or_default();
            let encoded = codec.encode(&state.cookie_secret, &payload, unix_seconds_now());
            let mut resp = Redirect::to(&format!(
                "/login?refresh=true&return_to={}",
                ory_client::apis::urlencode(format!(
                    "{}/sso/confirm",
                    state.cfg.self_.url.trim_end_matches('/')
                ))
            ))
            .into_response();
            append_set_cookie(&mut resp, Some(clear));
            append_set_cookie(&mut resp, Some(codec.set_header(&encoded)));
            return resp;
        }
        Ok(Resolution::Blocked {
            action: block_action,
            reason,
            block_reason,
            identity_id,
        }) => {
            let event = AuditEvent::new(block_action).failed(reason).with_ctx(&actx);
            let event = match identity_id {
                Some(id) => event
                    .actor_user(id, email.clone())
                    .metadata(audit_metadata!(
                        "reason" => reason,
                        "org_id" => org_id.as_str(),
                    )),
                // No identity id on a 409-conflict; "asserted_address" carries the
                // IdP-asserted email — an address, not a credential, so safe to audit.
                None => event.metadata(audit_metadata!(
                    "reason" => reason,
                    "org_id" => org_id.as_str(),
                    "asserted_address" => email.as_str(),
                )),
            };
            let _ = audit::log(&state.db, event).await;
            let mut resp = render_blocked(&state, &email, block_reason);
            append_set_cookie(&mut resp, Some(clear));
            return resp;
        }
        Err(e) => {
            tracing::error!(error = ?e, "saml callback: identity resolution failed");
            return fail_upstream(&state, &actx, &org_id, "identity_resolution", clear).await;
        }
    };
    let identity_id = identity.id.clone();

    // Membership is best-effort: a DB blip must not abort an otherwise
    // valid login.
    match orgs::db::find_member(&state.db, &identity_id, &org_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            // Race-safe join that drops the Default floor for non-allowlisted
            // identities in the same txn (H1 — SAML is a floor site).
            let drop_default = !state
                .cfg
                .admin
                .is_admin_actor(&email, crate::ory::identity_addresses(&identity));
            if let Err(e) = orgs::db::join_org_race_safe(
                &state.db,
                &identity_id,
                &org_id,
                orgs::Role::Member,
                drop_default,
            )
            .await
            {
                tracing::error!(error = ?e, "saml callback: org membership add failed");
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "saml callback: org membership lookup failed");
        }
    }

    // The link is a bearer credential that lands in the browser's URL bar and
    // history, and redeeming it opens Kratos' password-change window. One
    // minute is the shortest Kratos honours exactly; it's consumed on the next
    // hop, so there's nothing to gain from a longer window.
    let link =
        match kratos::admin_create_recovery_link(&state.ory, &identity_id, "1m", Some("/")).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = ?e, "saml callback: recovery link mint failed");
                return fail_upstream(&state, &actx, &org_id, "recovery_link", clear).await;
            }
        };
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::SAML_LOGIN_SUCCEEDED)
            .actor_user(identity_id.clone(), email)
            .target(target_kind::IDENTITY, identity_id)
            .with_ctx(&actx)
            .metadata(audit_metadata!("org_id" => org_id.as_str())),
    )
    .await;
    let mut resp = Redirect::to(&link).into_response();
    append_set_cookie(&mut resp, Some(clear));
    // The recovery redemption dumps SSO arrivals on the settings-password
    // page; this breadcrumb lets that handler bounce them home.
    let secure = if state.cfg.self_.is_https() {
        "; Secure"
    } else {
        ""
    };
    append_set_cookie(
        &mut resp,
        Some(format!(
            "forseti_sso_arrival=1; Path=/settings; Max-Age=60; HttpOnly; SameSite=Lax{secure}"
        )),
    );
    resp
}

/// Pending link carried across the credential-confirmation bounce. Signed, so
/// a user cannot rewrite which identity or org they are about to be linked
/// into; and re-checked against the live session on the way back, so even a
/// valid cookie only links the identity the holder actually signed in as.
#[derive(serde::Serialize, Deserialize)]
struct PendingLink {
    /// Org id.
    o: String,
    /// IdP-asserted email.
    e: String,
    /// IdP subject (NameID); empty for transient-NameID IdPs.
    s: String,
    /// The pre-existing Kratos identity the assertion matched.
    i: String,
}

/// `GET /sso/confirm` — the return leg of the credential-confirmation bounce.
///
/// The user has just authenticated at Kratos with their own credential. If
/// that session is the identity the assertion matched, the link is written and
/// they land on the dashboard; anything else is refused. No session is minted
/// here — the Kratos login the user just completed *is* the session, which is
/// the point: an assertion alone can never produce one.
pub async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    session: crate::extractors::OptionalSession,
) -> Response {
    let codec = crate::saml::pending_link_cookie(state.cfg.self_.is_https());
    let clear = codec.clear_header();

    let Some(pending) = codec
        .decode(&state.cookie_secret, &headers, unix_seconds_now())
        .and_then(|b| serde_json::from_slice::<PendingLink>(&b).ok())
    else {
        // No pending link (expired, tampered, or a direct visit).
        let mut resp = neutral_unavailable(&state);
        append_set_cookie(&mut resp, Some(clear));
        return resp;
    };

    // The load-bearing check: the live session must BE the matched identity.
    // Without this, anyone holding the cookie could link someone else's
    // account to the IdP.
    let signed_in_as = session
        .ok()
        .and_then(|s| s.identity.as_ref().map(|i| i.id.clone()));
    if signed_in_as.as_deref() != Some(pending.i.as_str()) {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::SAML_LOGIN_FAILED)
                .failed("credential confirmation did not match")
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "reason" => "confirm_identity_mismatch",
                    "org_id" => pending.o.as_str(),
                )),
        )
        .await;
        let mut resp = render_blocked(&state, &pending.e, BlockedReason::ConfirmFailed);
        append_set_cookie(&mut resp, Some(clear));
        return resp;
    }

    // Re-run the policy against live facts, now with the confirmation in hand.
    // The callback's snapshot could be up to 10 minutes old.
    let matched_is_member = matches!(
        orgs::db::find_member(&state.db, &pending.i, &pending.o).await,
        Ok(Some(_))
    );
    let decision = saml_link_decision(LinkFacts {
        matched_identity: true,
        matched_verified: true,
        matched_is_member,
        is_admin_email: state.cfg.admin.is_admin(&pending.e),
        org_domain_verified: false,
        credential_confirmed: true,
    });
    if decision != LinkDecision::LinkExisting {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::SAML_LOGIN_FAILED)
                .failed("link refused at confirmation")
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "reason" => "confirm_refused",
                    "org_id" => pending.o.as_str(),
                )),
        )
        .await;
        let mut resp = render_blocked(&state, &pending.e, BlockedReason::CrossOrgNotMember);
        append_set_cookie(&mut resp, Some(clear));
        return resp;
    }

    let subject_opt = (!pending.s.is_empty()).then_some(pending.s.as_str());
    if let Err(e) =
        db::upsert_link(&state.db, &pending.o, &pending.e, subject_opt, &pending.i).await
    {
        tracing::error!(error = ?e, "saml confirm: upsert_link failed");
        let mut resp = error_page(&state, UPSTREAM_FAILED_KEY);
        append_set_cookie(&mut resp, Some(clear));
        return resp;
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::SAML_LINK_CONFIRMED)
            .actor_user(pending.i.clone(), pending.e.clone())
            .target(target_kind::IDENTITY, pending.i.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!("org_id" => pending.o.as_str())),
    )
    .await;
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::SAML_IDENTITY_LINKED)
            .actor_user(pending.i.clone(), pending.e.clone())
            .target(target_kind::IDENTITY, pending.i.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!("org_id" => pending.o.as_str())),
    )
    .await;

    // Org membership, same best-effort shape as the callback's.
    if !matched_is_member {
        let drop_default = !state.cfg.admin.is_admin(&pending.e);
        if let Err(e) = orgs::db::join_org_race_safe(
            &state.db,
            &pending.i,
            &pending.o,
            orgs::Role::Member,
            drop_default,
        )
        .await
        {
            tracing::error!(error = ?e, "saml confirm: org membership add failed");
        }
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::SAML_LOGIN_SUCCEEDED)
            .actor_user(pending.i.clone(), pending.e.clone())
            .target(target_kind::IDENTITY, pending.i)
            .with_ctx(&actx)
            .metadata(audit_metadata!("org_id" => pending.o.as_str())),
    )
    .await;

    let mut resp = Redirect::to("/").into_response();
    append_set_cookie(&mut resp, Some(clear));
    resp
}

/// Shared upstream-failure tail: audit, render the retry page, clear the
/// state cookie.
async fn fail_upstream(
    state: &AppState,
    actx: &AuditCtx,
    org_id: &str,
    reason: &'static str,
    clear: String,
) -> Response {
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::SAML_LOGIN_FAILED)
            .failed(reason)
            .with_ctx(actx)
            .metadata(audit_metadata!(
                "reason" => reason,
                "org_id" => org_id,
            )),
    )
    .await;
    let mut resp = error_page(state, UPSTREAM_FAILED_KEY);
    append_set_cookie(&mut resp, Some(clear));
    resp
}

/// What to do with an IdP assertion, given only the facts — no I/O, so the
/// policy is testable on its own.
///
/// RFC 9700 §4.16: a federated assertion must never silently link to a
/// pre-existing local account keyed on an email claim. A tenant IdP can assert
/// any string it likes, so "the IdP says this user is alice@corp.example" is a
/// claim about identity, not proof of control over Forseti's alice@corp.example.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkDecision {
    /// Refuse outright.
    Refuse(RefuseReason),
    /// A pre-existing identity matches: make the user prove they hold it, by
    /// logging in with their own Kratos credential, before we link or mint a
    /// session.
    ConfirmCredential,
    /// The assertion names an existing identity the user has already proven
    /// control of during this flow. Link it.
    LinkExisting,
    /// No identity holds this address and the org has proven the domain:
    /// provision one.
    JitCreate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefuseReason {
    /// The asserted address is on the operator admin allowlist. A tenant IdP
    /// must never be a route to an operator account, confirmed or not.
    AdminAllowlisted,
    /// The matching identity has not verified the address.
    UnverifiedMatch,
    /// The matching identity is not a member of this org.
    CrossOrgNotMember,
    /// Nothing holds the address and the org has not proven its domain, so a
    /// tenant IdP would be squatting an arbitrary address.
    UnprovenDomain,
}

/// Facts about one assertion, as gathered by [`resolve_identity`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkFacts {
    /// An existing Kratos identity holds the asserted address.
    pub(crate) matched_identity: bool,
    /// That identity has the address verified.
    pub(crate) matched_verified: bool,
    /// That identity is already a member of this org.
    pub(crate) matched_is_member: bool,
    /// The asserted address is in `[admin].allowed_emails`.
    pub(crate) is_admin_email: bool,
    /// The asserted address's domain is a verified domain of this org.
    pub(crate) org_domain_verified: bool,
    /// The user has just proven control of the matched identity by logging in
    /// with their own Kratos credential (the `ConfirmCredential` return leg).
    pub(crate) credential_confirmed: bool,
}

/// The linking policy. Order matters: the admin refusal outranks everything,
/// including a successful credential confirmation, so a tenant IdP is never a
/// path to an operator account.
pub(crate) fn saml_link_decision(facts: LinkFacts) -> LinkDecision {
    if facts.is_admin_email {
        return LinkDecision::Refuse(RefuseReason::AdminAllowlisted);
    }
    if facts.matched_identity {
        if !facts.matched_verified {
            return LinkDecision::Refuse(RefuseReason::UnverifiedMatch);
        }
        // Kratos identities are global; an org IdP asserting an address that
        // belongs to another org's user must not reach it.
        if !facts.matched_is_member {
            return LinkDecision::Refuse(RefuseReason::CrossOrgNotMember);
        }
        if facts.credential_confirmed {
            return LinkDecision::LinkExisting;
        }
        return LinkDecision::ConfirmCredential;
    }
    if facts.org_domain_verified {
        return LinkDecision::JitCreate;
    }
    LinkDecision::Refuse(RefuseReason::UnprovenDomain)
}

enum Resolution {
    Identity(Box<Identity>),
    /// A pre-existing identity matched: bounce the user through their own
    /// Kratos login (`refresh=true`) and come back here.
    ConfirmCredential {
        identity_id: String,
    },
    Blocked {
        // Audit action this block is logged under — unverified/conflict use
        // SAML_LOGIN_BLOCKED_UNVERIFIED; the cross-org guard uses SAML_LOGIN_FAILED.
        action: &'static str,
        reason: &'static str,
        // Drives the user-facing copy on the blocked page.
        block_reason: BlockedReason,
        // Known for unverified matches; absent for create-conflicts.
        identity_id: Option<String>,
    },
}

/// Subject → email → Kratos identity decision tree. Durable hit: a
/// saml_links row keyed on the stable IdP subject (NameID) survives an
/// email change at the IdP. Falls back to the legacy email-keyed row, then
/// a verified-email match (link on first login), then JIT create. Both
/// link paths backfill the subject. Unverified matches and create-conflicts
/// fail closed to the blocked page.
async fn resolve_identity(
    state: &AppState,
    cfg: &SamlConfig,
    actx: &AuditCtx,
    org_id: &str,
    email: &str,
    profile: &jackson::JacksonProfile,
) -> anyhow::Result<Resolution> {
    // Opaque subject; empty for transient-NameID IdPs, where the subject
    // branch is skipped and keying stays email-only.
    let subject = profile.id.trim();
    let subject_opt = (!subject.is_empty()).then_some(subject);

    // The operator refusal runs BEFORE the link lookups, not just on a fresh
    // match. An identity linked while it was an ordinary member, and later
    // promoted by adding its address to `[admin].allowed_emails`, would
    // otherwise keep sailing through the durable-link fast path forever — a
    // tenant IdP minting operator sessions, which is the exact thing this
    // refusal exists to prevent. Raw `is_admin`, deliberately: this refuses to
    // touch an allowlisted address rather than granting anything.
    if state.cfg.admin.is_admin(email) {
        return Ok(Resolution::Blocked {
            action: action::SAML_LOGIN_FAILED,
            reason: "admin_allowlisted_email",
            block_reason: BlockedReason::AdminAllowlisted,
            identity_id: None,
        });
    }

    // Durable subject lookup (org-scoped, cross-org-safe). Safe to trust: a
    // row only exists because a previous login proved control of the identity
    // (or JIT-created it), and the table is keyed by org so one tenant's IdP
    // can never ride another tenant's link.
    if let Some(subject) = subject_opt
        && let Some((linked, row_email)) = db::link_subject(&state.db, org_id, subject).await?
    {
        match kratos::admin_get_identity_optional(&state.ory, &linked).await? {
            Some(identity) => return Ok(Resolution::Identity(Box::new(identity))),
            None => db::delete_link(&state.db, org_id, &row_email).await?,
        }
    }

    // Legacy/bootstrap: existing email-keyed link.
    if let Some(linked) = db::link_for(&state.db, org_id, email).await? {
        match kratos::admin_get_identity_optional(&state.ory, &linked).await? {
            // Backfill the subject onto the legacy row.
            Some(identity) => {
                db::upsert_link(&state.db, org_id, email, subject_opt, &identity.id).await?;
                return Ok(Resolution::Identity(Box::new(identity)));
            }
            None => db::delete_link(&state.db, org_id, email).await?,
        }
    }

    // Nothing is linked yet. Gather the facts and let the policy decide; the
    // IdP's word alone never reaches a pre-existing identity.
    let matched = kratos::admin_find_identity_by_email(&state.ory, email).await?;
    let matched_is_member = match matched.as_ref() {
        Some((identity, _)) => orgs::db::find_member(&state.db, &identity.id, org_id)
            .await?
            .is_some(),
        None => false,
    };
    let org_domain_verified = match orgs::email_domain(email) {
        Some(domain) => orgs::domains::get_domain(&state.db, org_id, &domain)
            .await?
            .is_some_and(|row| row.verified_at.is_some()),
        None => false,
    };
    let facts = LinkFacts {
        matched_identity: matched.is_some(),
        matched_verified: matched.as_ref().is_some_and(|(_, verified)| *verified),
        matched_is_member,
        is_admin_email: state.cfg.admin.is_admin(email),
        org_domain_verified,
        // The callback never arrives confirmed; `confirm` is the return leg.
        credential_confirmed: false,
    };

    match saml_link_decision(facts) {
        LinkDecision::Refuse(RefuseReason::AdminAllowlisted) => {
            return Ok(Resolution::Blocked {
                action: action::SAML_LOGIN_FAILED,
                reason: "admin_allowlisted_email",
                block_reason: BlockedReason::AdminAllowlisted,
                identity_id: matched.map(|(i, _)| i.id),
            });
        }
        LinkDecision::Refuse(RefuseReason::UnverifiedMatch) => {
            return Ok(Resolution::Blocked {
                action: action::SAML_LOGIN_BLOCKED_UNVERIFIED,
                reason: "unverified_email",
                block_reason: BlockedReason::Unverified,
                identity_id: matched.map(|(i, _)| i.id),
            });
        }
        LinkDecision::Refuse(RefuseReason::CrossOrgNotMember) => {
            return Ok(Resolution::Blocked {
                action: action::SAML_LOGIN_FAILED,
                reason: "cross_org_not_member",
                block_reason: BlockedReason::CrossOrgNotMember,
                identity_id: matched.map(|(i, _)| i.id),
            });
        }
        LinkDecision::Refuse(RefuseReason::UnprovenDomain) => {
            return Ok(Resolution::Blocked {
                action: action::SAML_LOGIN_FAILED,
                reason: "unproven_domain",
                block_reason: BlockedReason::UnprovenDomain,
                identity_id: None,
            });
        }
        LinkDecision::ConfirmCredential => {
            let identity_id = matched
                .expect("a match is what produced this decision")
                .0
                .id;
            return Ok(Resolution::ConfirmCredential { identity_id });
        }
        // Unreachable from the callback: `credential_confirmed` is false here,
        // so a match always yields `ConfirmCredential`. `confirm` does the link.
        LinkDecision::LinkExisting => {
            let identity_id = matched
                .expect("a match is what produced this decision")
                .0
                .id;
            return Ok(Resolution::ConfirmCredential { identity_id });
        }
        LinkDecision::JitCreate => {}
    }

    match kratos::admin_create_identity_verified(
        &state.ory,
        &cfg.identity_schema_id,
        email,
        &profile.first_name,
        &profile.last_name,
    )
    .await?
    {
        Some(identity) => {
            db::upsert_link(&state.db, org_id, email, subject_opt, &identity.id).await?;
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::SAML_IDENTITY_JIT_CREATED)
                    .actor_user(identity.id.clone(), email)
                    .target(target_kind::IDENTITY, identity.id.clone())
                    .with_ctx(actx)
                    .metadata(audit_metadata!("org_id" => org_id)),
            )
            .await;
            Ok(Resolution::Identity(Box::new(identity)))
        }
        // 409: the verified-lookup missed a passwordless/imported identity.
        None => Ok(Resolution::Blocked {
            action: action::SAML_LOGIN_BLOCKED_UNVERIFIED,
            reason: "email_conflict",
            block_reason: BlockedReason::Conflict,
            identity_id: None,
        }),
    }
}

#[cfg(test)]
mod link_decision_tests {
    use super::*;

    /// A genuinely new user at an org that has proven its domain.
    fn new_user() -> LinkFacts {
        LinkFacts {
            matched_identity: false,
            matched_verified: false,
            matched_is_member: false,
            is_admin_email: false,
            org_domain_verified: true,
            credential_confirmed: false,
        }
    }

    /// A verified, in-org identity already holds the asserted address.
    fn existing_member() -> LinkFacts {
        LinkFacts {
            matched_identity: true,
            matched_verified: true,
            matched_is_member: true,
            is_admin_email: false,
            org_domain_verified: true,
            credential_confirmed: false,
        }
    }

    #[test]
    fn a_new_user_on_a_verified_domain_is_provisioned() {
        assert_eq!(saml_link_decision(new_user()), LinkDecision::JitCreate);
    }

    #[test]
    fn a_new_user_on_an_unproven_domain_is_refused() {
        // Otherwise a tenant IdP could squat any address it liked.
        let facts = LinkFacts {
            org_domain_verified: false,
            ..new_user()
        };
        assert_eq!(
            saml_link_decision(facts),
            LinkDecision::Refuse(RefuseReason::UnprovenDomain)
        );
    }

    #[test]
    fn an_existing_member_must_confirm_before_linking() {
        // This is the impersonation finding: the IdP asserting a member's
        // address used to hand over that member's session.
        assert_eq!(
            saml_link_decision(existing_member()),
            LinkDecision::ConfirmCredential
        );
    }

    #[test]
    fn an_existing_member_links_once_the_credential_is_confirmed() {
        let facts = LinkFacts {
            credential_confirmed: true,
            ..existing_member()
        };
        assert_eq!(saml_link_decision(facts), LinkDecision::LinkExisting);
    }

    #[test]
    fn an_admin_allowlisted_address_is_refused_even_when_confirmed() {
        // A tenant IdP is never a route to an operator account, and no amount
        // of confirming changes that.
        let facts = LinkFacts {
            is_admin_email: true,
            credential_confirmed: true,
            ..existing_member()
        };
        assert_eq!(
            saml_link_decision(facts),
            LinkDecision::Refuse(RefuseReason::AdminAllowlisted)
        );
        // Also for an address nobody holds yet, on a proven domain.
        let facts = LinkFacts {
            is_admin_email: true,
            ..new_user()
        };
        assert_eq!(
            saml_link_decision(facts),
            LinkDecision::Refuse(RefuseReason::AdminAllowlisted)
        );
    }

    #[test]
    fn an_unverified_match_is_refused_before_anything_else() {
        let facts = LinkFacts {
            matched_verified: false,
            ..existing_member()
        };
        assert_eq!(
            saml_link_decision(facts),
            LinkDecision::Refuse(RefuseReason::UnverifiedMatch)
        );
        // Confirming does not rescue it either.
        let facts = LinkFacts {
            matched_verified: false,
            credential_confirmed: true,
            ..existing_member()
        };
        assert_eq!(
            saml_link_decision(facts),
            LinkDecision::Refuse(RefuseReason::UnverifiedMatch)
        );
    }

    #[test]
    fn a_verified_identity_outside_the_org_is_refused() {
        // Kratos identities are global; one org's IdP must not reach another
        // org's user, confirmation or not.
        let facts = LinkFacts {
            matched_is_member: false,
            ..existing_member()
        };
        assert_eq!(
            saml_link_decision(facts),
            LinkDecision::Refuse(RefuseReason::CrossOrgNotMember)
        );
        let facts = LinkFacts {
            matched_is_member: false,
            credential_confirmed: true,
            ..existing_member()
        };
        assert_eq!(
            saml_link_decision(facts),
            LinkDecision::Refuse(RefuseReason::CrossOrgNotMember)
        );
    }

    /// The pure policy covers a FRESH assertion. `resolve_identity` runs the
    /// operator refusal before the link lookups too, so an identity linked as
    /// an ordinary member and later promoted to operator stops working through
    /// SSO rather than becoming a tenant-IdP-mintable operator session.
    /// Guarded here so the ordering can't be refactored away silently.
    #[test]
    fn the_operator_refusal_is_checked_before_any_link_lookup() {
        let src = include_str!("flow.rs");
        let guard = src
            .find("if state.cfg.admin.is_admin(email) {")
            .expect("resolve_identity refuses an allowlisted address");
        let subject_lookup = src
            .find("db::link_subject(&state.db, org_id, subject)")
            .expect("the durable subject lookup");
        let email_lookup = src
            .find("db::link_for(&state.db, org_id, email)")
            .expect("the legacy email lookup");
        assert!(
            guard < subject_lookup && guard < email_lookup,
            "the operator refusal must run before both link fast paths"
        );
    }

    #[test]
    fn a_match_never_falls_through_to_provisioning() {
        // Whatever the domain state, a matched identity is never JIT-created.
        for domain_verified in [true, false] {
            for confirmed in [true, false] {
                let facts = LinkFacts {
                    org_domain_verified: domain_verified,
                    credential_confirmed: confirmed,
                    ..existing_member()
                };
                assert_ne!(saml_link_decision(facts), LinkDecision::JitCreate);
            }
        }
    }
}
