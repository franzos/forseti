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

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::commercial::license::{Feature, FeatureStatus};
use crate::config::SamlConfig;
use crate::orgs;
use crate::ory::kratos;
use crate::ory::Identity;
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

    let identity = match resolve_identity(&state, cfg, &actx, &org_id, &email, &profile).await {
        Ok(Resolution::Identity(identity)) => identity,
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
            if let Err(e) =
                orgs::db::add_member(&state.db, &org_id, &identity_id, orgs::Role::Member, None)
                    .await
            {
                tracing::error!(error = ?e, "saml callback: org membership add failed");
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "saml callback: org membership lookup failed");
        }
    }

    let link = match kratos::admin_create_recovery_link(&state.ory, &identity_id, "15m", Some("/"))
        .await
    {
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

enum Resolution {
    Identity(Box<Identity>),
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

    // Durable subject lookup (org-scoped, cross-org-safe).
    if let Some(subject) = subject_opt {
        if let Some((linked, row_email)) = db::link_subject(&state.db, org_id, subject).await? {
            match kratos::admin_get_identity_optional(&state.ory, &linked).await? {
                Some(identity) => return Ok(Resolution::Identity(Box::new(identity))),
                None => db::delete_link(&state.db, org_id, &row_email).await?,
            }
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

    match kratos::admin_find_identity_by_email(&state.ory, email).await? {
        Some((identity, true)) => {
            // Fail closed on cross-org capture: Kratos identities/sessions are
            // global, so an org IdP asserting an email that belongs to another
            // org's user must NOT auto-link+session it. Only link a pre-existing
            // verified identity that is already a member of THIS org.
            if orgs::db::find_member(&state.db, &identity.id, org_id)
                .await?
                .is_none()
            {
                return Ok(Resolution::Blocked {
                    action: action::SAML_LOGIN_FAILED,
                    reason: "cross_org_not_member",
                    block_reason: BlockedReason::CrossOrgNotMember,
                    identity_id: Some(identity.id),
                });
            }
            db::upsert_link(&state.db, org_id, email, subject_opt, &identity.id).await?;
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::SAML_IDENTITY_LINKED)
                    .actor_user(identity.id.clone(), email)
                    .target(target_kind::IDENTITY, identity.id.clone())
                    .with_ctx(actx)
                    .metadata(audit_metadata!("org_id" => org_id)),
            )
            .await;
            return Ok(Resolution::Identity(Box::new(identity)));
        }
        Some((identity, false)) => {
            return Ok(Resolution::Blocked {
                action: action::SAML_LOGIN_BLOCKED_UNVERIFIED,
                reason: "unverified_email",
                block_reason: BlockedReason::Unverified,
                identity_id: Some(identity.id),
            });
        }
        None => {}
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
