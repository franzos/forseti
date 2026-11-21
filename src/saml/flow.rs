//! `/sso/{slug}` + `/sso/callback` — the browser-facing SSO flow.
//!
//! Start redirects to Jackson's authorize endpoint with a signed state
//! cookie binding the round-trip; the callback exchanges the code,
//! resolves the asserted email to an identity (link → verified
//! match → JIT create), then hands the browser a session through the
//! identity backend.
//!
//! Every can't-start cause renders ONE uniform neutral page so the URL
//! can't be used to probe which orgs have SSO configured.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use askama::Template;
use axum::Extension;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{self, AuditCtx, AuditEvent, action, target_kind};
use crate::audit_metadata;
use crate::backend::IdentityBackend;
use crate::backend::identity::{Identity, SessionOrigin};
use crate::commercial::license::{Feature, FeatureStatus};
use crate::config::SamlConfig;
use crate::orgs;
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

/// The Jackson client: the Kratos client's timeouts, its own pool.
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
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
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
                crate::web::urlencode(format!(
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
            let drop_default = !state.cfg.admin.is_admin_actor(&email, identity.addresses());
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

    let origin = SessionOrigin {
        method: "saml",
        ip: crate::client_ip::client_ip(
            &headers,
            &state.cfg.proxy,
            peer.map(|Extension(ConnectInfo(addr))| addr.ip()),
        ),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    };
    let browser = match state
        .identity
        .establish_browser_session(&identity_id, "/", origin)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = ?e, "saml callback: browser session failed");
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
    let mut resp = Redirect::to(&browser.location).into_response();
    append_set_cookie(&mut resp, Some(clear));
    for cookie in browser.set_cookies {
        append_set_cookie(&mut resp, Some(cookie));
    }
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

    let Some((minted_at, pending)) = codec
        .decode_with_issued_at(&state.cookie_secret, &headers, unix_seconds_now())
        .and_then(|(ts, b)| {
            serde_json::from_slice::<PendingLink>(&b)
                .ok()
                .map(|p| (ts, p))
        })
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

    // Holding the session is not proof: it must come from the bounce itself.
    // An older, ambient session would let a cross-site GET here write the link.
    if !authenticated_since(session.ok(), minted_at) {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::SAML_LOGIN_FAILED)
                .failed("credential confirmation was not fresh")
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "reason" => "confirm_not_fresh",
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

/// One `RefuseReason` → audit action + blocked-page mapping for every link path.
fn blocked_resolution_for(reason: RefuseReason, identity_id: Option<String>) -> Resolution {
    let (action, reason_str, block_reason, identity_id) = match reason {
        RefuseReason::AdminAllowlisted => (
            action::SAML_LOGIN_FAILED,
            "admin_allowlisted_email",
            BlockedReason::AdminAllowlisted,
            identity_id,
        ),
        RefuseReason::UnverifiedMatch => (
            action::SAML_LOGIN_BLOCKED_UNVERIFIED,
            "unverified_email",
            BlockedReason::Unverified,
            identity_id,
        ),
        RefuseReason::CrossOrgNotMember => (
            action::SAML_LOGIN_FAILED,
            "cross_org_not_member",
            BlockedReason::CrossOrgNotMember,
            identity_id,
        ),
        RefuseReason::UnprovenDomain => (
            action::SAML_LOGIN_FAILED,
            "unproven_domain",
            BlockedReason::UnprovenDomain,
            None,
        ),
    };
    Resolution::Blocked {
        action,
        reason: reason_str,
        block_reason,
        identity_id,
    }
}

/// A `saml_links` hit is not a standing grant: re-run the link decision on the
/// linked identity's live facts, so a removed member or an identity holding a
/// verified allowlisted address is refused like a fresh match would be.
async fn resolve_established_link(
    state: &AppState,
    org_id: &str,
    identity: Identity,
) -> anyhow::Result<Resolution> {
    let matched_is_member = orgs::db::find_member(&state.db, &identity.id, org_id)
        .await?
        .is_some();
    let addrs = identity.addresses();
    let is_admin_email = addrs
        .unwrap_or_default()
        .iter()
        .any(|a| state.cfg.admin.is_admin_actor(&a.value, addrs));
    let facts = LinkFacts {
        matched_identity: true,
        matched_verified: true,
        matched_is_member,
        is_admin_email,
        org_domain_verified: false,
        credential_confirmed: true,
    };
    match saml_link_decision(facts) {
        LinkDecision::LinkExisting => Ok(Resolution::Identity(Box::new(identity))),
        LinkDecision::Refuse(reason) => Ok(blocked_resolution_for(reason, Some(identity.id))),
        LinkDecision::ConfirmCredential | LinkDecision::JitCreate => {
            anyhow::bail!("a confirmed, verified match only links or refuses")
        }
    }
}

/// Whether an email-keyed link may be reused: its stored subject is unset or
/// matches the asserted one, or the assertion carries no subject (transient
/// NameID, where refusing would leave the user no way to rebind).
fn stored_subject_usable(stored: Option<&str>, asserted: Option<&str>) -> bool {
    match (stored, asserted) {
        (Some(stored), Some(asserted)) => stored == asserted,
        _ => true,
    }
}

/// Subject → email → Kratos identity decision tree. Durable hit: a
/// saml_links row keyed on the stable IdP subject (NameID) survives an
/// email change at the IdP. Falls back to the legacy email-keyed row (unless
/// it is bound to a different subject), then a verified-email match (link on
/// first login), then JIT create. The email path backfills a missing
/// subject. Unverified matches and create-conflicts
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
        match state.identity.admin_get_identity_optional(&linked).await? {
            Some(identity) => return resolve_established_link(state, org_id, identity).await,
            None => db::delete_link(&state.db, org_id, &row_email).await?,
        }
    }

    // Legacy/bootstrap: existing email-keyed link. A row bound to another
    // subject falls through to the fresh-match path below.
    if let Some((linked, stored_subject)) = db::link_for(&state.db, org_id, email).await?
        && stored_subject_usable(stored_subject.as_deref(), subject_opt)
    {
        match state.identity.admin_get_identity_optional(&linked).await? {
            Some(identity) => {
                if stored_subject.is_none()
                    && let Some(subject) = subject_opt
                {
                    db::backfill_subject(&state.db, org_id, email, subject).await?;
                }
                return resolve_established_link(state, org_id, identity).await;
            }
            None => db::delete_link(&state.db, org_id, email).await?,
        }
    }

    // Nothing is linked yet. Gather the facts and let the policy decide; the
    // IdP's word alone never reaches a pre-existing identity.
    let matched = state.identity.admin_find_identity_by_email(email).await?;
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
        LinkDecision::Refuse(reason) => {
            return Ok(blocked_resolution_for(reason, matched.map(|(i, _)| i.id)));
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

    match state
        .identity
        .admin_create_identity_verified(
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

/// Slack for Kratos's clock running behind Forseti's when comparing the two.
const CONFIRM_CLOCK_SKEW_SECS: i64 = 60;

/// Whether `session` authenticated no earlier than `minted_at` (unix seconds).
fn authenticated_since(
    session: Option<&crate::backend::identity::Session>,
    minted_at: u64,
) -> bool {
    let Ok(minted_at) = i64::try_from(minted_at) else {
        return false;
    };
    session
        .and_then(crate::oauth::reauth::session_auth_time)
        .is_some_and(|t| t.timestamp().saturating_add(CONFIRM_CLOCK_SKEW_SECS) >= minted_at)
}

#[cfg(test)]
mod confirm_freshness_tests {
    use super::*;

    fn session_at(rfc3339: Option<&str>) -> crate::backend::identity::Session {
        let mut s = crate::backend::identity::Session {
            id: "sess-1".to_string(),
            ..Default::default()
        };
        s.authenticated_at = rfc3339.map(str::to_string);
        s
    }

    // 2026-01-01T10:00:00Z
    const MINTED: u64 = 1_767_261_600;

    #[test]
    fn sign_in_after_the_bounce_counts() {
        let s = session_at(Some("2026-01-01T10:00:30Z"));
        assert!(authenticated_since(Some(&s), MINTED));
    }

    #[test]
    fn ambient_session_from_before_the_bounce_is_refused() {
        let s = session_at(Some("2026-01-01T09:00:00Z"));
        assert!(!authenticated_since(Some(&s), MINTED));
    }

    #[test]
    fn small_clock_skew_is_tolerated() {
        let s = session_at(Some("2026-01-01T09:59:30Z"));
        assert!(authenticated_since(Some(&s), MINTED));
    }

    #[test]
    fn missing_session_or_timestamp_is_refused() {
        assert!(!authenticated_since(None, MINTED));
        assert!(!authenticated_since(Some(&session_at(None)), MINTED));
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

    /// C1 (round-3 review): both link fast paths returned the linked identity
    /// without re-running the link decision.
    #[test]
    fn both_link_fast_paths_rerun_the_link_decision() {
        let src = include_str!("flow.rs");
        let body_start = src
            .find("async fn resolve_identity(")
            .expect("resolve_identity");
        let body = &src[body_start..];
        let fresh_match = body
            .find("state.identity.admin_find_identity_by_email(")
            .expect("the fresh-match lookup");
        let fast_paths = &body[..fresh_match];
        for anchor in [
            "db::link_subject(&state.db, org_id, subject)",
            "db::link_for(&state.db, org_id, email)",
        ] {
            let at = fast_paths.find(anchor).expect(anchor);
            let rest = &fast_paths[at..];
            let arm_end = rest.find("None =>").expect("the stale-link arm");
            assert!(
                rest[..arm_end].contains("resolve_established_link(state, org_id, identity)"),
                "{anchor}: a link hit must go through resolve_established_link"
            );
        }
        assert!(
            !fast_paths.contains("Resolution::Identity("),
            "no fast path may construct Resolution::Identity directly"
        );
    }

    #[test]
    fn stored_subject_usable_table() {
        for (stored, asserted, usable) in [
            (None, None, true),
            (None, Some("s1"), true),
            (Some("s1"), None, true),
            (Some("s1"), Some("s1"), true),
            (Some("s1"), Some("s2"), false),
        ] {
            assert_eq!(
                stored_subject_usable(stored, asserted),
                usable,
                "stored {stored:?}, asserted {asserted:?}"
            );
        }
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

#[cfg(all(test, feature = "identity-native"))]
mod native_callback_tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, header};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use tower::ServiceExt as _;

    use super::*;
    use crate::backend::identity::{Aal, WhoamiOutcome};
    use crate::config::{AppConfig, Redacted};
    use crate::identity_native::NativeBackend;

    const SECRET: &[u8] = &[0x42; 32];
    const EMAIL: &str = "sso@acme.test";
    const SUBJECT: &str = "idp-subject-1";

    async fn jackson_stub(subject: &'static str) -> String {
        let app = Router::new()
            .route(
                "/api/oauth/token",
                post(|| async { Json(serde_json::json!({ "access_token": "at" })) }),
            )
            .route(
                "/api/oauth/userinfo",
                get(move |headers: HeaderMap| async move {
                    let bearer = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok());
                    if bearer != Some("Bearer at") {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    Json(serde_json::json!({
                        "id": subject,
                        "email": EMAIL,
                        "firstName": "Sam",
                        "lastName": "So",
                    }))
                    .into_response()
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// The native callback for an identity linked to org `o1`, verified or never verified: the
    /// response, the backend, the database and the identity id.
    async fn callback_for_linked(
        verified: bool,
    ) -> (Response, Arc<NativeBackend>, crate::db::DbPool, String) {
        callback_for(verified, Some(SUBJECT), SUBJECT).await
    }

    /// As [`callback_for_linked`], with the link's stored subject and the asserted subject (empty:
    /// none) given.
    async fn callback_for(
        verified: bool,
        stored_subject: Option<&str>,
        asserted_subject: &'static str,
    ) -> (Response, Arc<NativeBackend>, crate::db::DbPool, String) {
        let mut cfg = AppConfig::test_fixture();
        cfg.saml = Some(SamlConfig {
            jackson_url: jackson_stub(asserted_subject).await,
            jackson_internal_url: None,
            jackson_api_key: Redacted("api-key".to_string()),
            client_secret_verifier: Redacted("verifier".to_string()),
            identity_schema_id: "default".to_string(),
            sp_entity_id: None,
        });
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::new(&cfg, &db, SECRET);
        let identity = backend
            .admin_create_identity_verified("default", EMAIL, "Sam", "So")
            .await
            .unwrap()
            .unwrap();
        if !verified {
            use crate::schema::identities;
            use diesel::prelude::*;
            let id = identity.id.clone();
            let unverify = async {
                Ok::<_, anyhow::Error>(crate::db_interact!(db, |c| {
                    diesel::update(identities::table.find(&id))
                        .set((
                            identities::email_verified_at.eq(None::<String>),
                            identities::first_verified_at.eq(None::<String>),
                        ))
                        .execute(c)
                })?)
            };
            unverify.await.unwrap();
        }
        orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        orgs::db::add_member_race_safe(&db, &identity.id, "o1", orgs::Role::Member)
            .await
            .unwrap();
        db::upsert_link(&db, "o1", EMAIL, stored_subject, &identity.id)
            .await
            .unwrap();
        let state = AppState::for_test(cfg, db.clone(), backend.clone(), SECRET);
        let router = crate::saml::router().with_state(state);

        let payload = serde_json::to_vec(&StatePayload {
            s: "nonce-1".to_string(),
            o: "o1".to_string(),
        })
        .unwrap();
        let state_value =
            crate::saml::state_cookie(false).encode(SECRET, &payload, unix_seconds_now());
        let req = Request::get("/sso/callback?code=c0de&state=nonce-1")
            .header(header::COOKIE, format!("forseti_saml_state={state_value}"))
            .header(header::USER_AGENT, "Mozilla/5.0 sso")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        (resp, backend, db, identity.id)
    }

    fn set_cookies(resp: &Response) -> Vec<&str> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn the_callback_signs_the_browser_in_with_a_saml_session() {
        let (resp, backend, _, identity) = callback_for_linked(true).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::LOCATION], "/");
        let cookies = set_cookies(&resp);
        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("forseti_saml_state=;"))
        );
        assert!(
            !cookies
                .iter()
                .any(|c| c.starts_with("forseti_sso_arrival="))
        );
        let session = cookies
            .iter()
            .find(|c| c.starts_with("forseti_session="))
            .expect("a session cookie");
        let pair = session.split(';').next().unwrap();
        let WhoamiOutcome::Ok(s) = backend.whoami(Some(pair)).await.unwrap() else {
            panic!("whoami accepts the cookie");
        };
        assert_eq!(
            s.identity.as_ref().map(|i| i.id.as_str()),
            Some(identity.as_str())
        );
        assert_eq!(s.authenticator_assurance_level, Some(Aal::Aal1));
        let methods: Vec<_> = s
            .authentication_methods
            .iter()
            .flatten()
            .map(|m| m.method.as_deref().unwrap())
            .collect();
        assert_eq!(methods, ["saml"]);
    }

    #[tokio::test]
    async fn a_never_verified_linked_identity_gets_no_session_and_a_failure_row() {
        let (resp, _, db, _) = callback_for_linked(false).await;
        assert!(
            !set_cookies(&resp)
                .iter()
                .any(|c| c.starts_with("forseti_session=")),
            "no session"
        );
        let (rows, _) = audit::query(&db, audit::AuditFilter::default())
            .await
            .unwrap();
        let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
        assert!(
            !actions.contains(&action::SAML_LOGIN_SUCCEEDED),
            "{actions:?}"
        );
        let failed = rows
            .iter()
            .find(|r| r.action == action::SAML_LOGIN_FAILED)
            .expect("a saml.login.failed row");
        assert!(!failed.succeeded());
        let meta: serde_json::Value = serde_json::from_str(&failed.metadata).unwrap();
        assert_eq!(meta["org_id"], "o1");
        assert_eq!(meta["reason"], "recovery_link");
    }

    fn has_session(resp: &Response) -> bool {
        set_cookies(resp)
            .iter()
            .any(|c| c.starts_with("forseti_session="))
    }

    async fn stored_subject(db: &crate::db::DbPool) -> Option<String> {
        db::link_for(db, "o1", EMAIL).await.unwrap().unwrap().1
    }

    #[tokio::test]
    async fn email_link_with_other_subject_goes_to_confirmation() {
        let (resp, _, db, _) = callback_for(true, Some("idp-subject-other"), SUBJECT).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers()[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with("/login?refresh=true"), "{location}");
        assert!(
            set_cookies(&resp)
                .iter()
                .any(|c| c.starts_with("forseti_saml_pending="))
        );
        assert!(!has_session(&resp), "no session");
        assert_eq!(
            stored_subject(&db).await.as_deref(),
            Some("idp-subject-other")
        );
    }

    #[tokio::test]
    async fn email_link_without_subject_logs_in_and_backfills() {
        let (resp, _, db, _) = callback_for(true, None, SUBJECT).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::LOCATION], "/");
        assert!(has_session(&resp));
        assert_eq!(stored_subject(&db).await.as_deref(), Some(SUBJECT));
    }

    #[tokio::test]
    async fn assertion_without_subject_logs_in_and_keeps_the_stored_subject() {
        let (resp, _, db, _) = callback_for(true, Some("idp-subject-other"), "").await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::LOCATION], "/");
        assert!(has_session(&resp));
        assert_eq!(
            stored_subject(&db).await.as_deref(),
            Some("idp-subject-other")
        );
    }
}
