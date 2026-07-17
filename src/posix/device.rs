//! Host-authenticated RFC 8628 device-auth endpoints (`/posix/v1/device/*`),
//! gated by [`RequirePosixHost`]. The daemon initiates a device flow for a
//! named `username`, a human approves it in the browser, and Forseti binds the
//! approving identity to the named POSIX account before returning `approved`.
//!
//! The binding ([`evaluate_binding`]) is re-run LIVE at the poll that observes
//! the token: host scope and account state can change between init and approval,
//! so the init-time check is necessary but never sufficient.
//!
//! Codes (`device_code`/`user_code`) and tokens are NEVER logged.

use axum::extract::{Json as JsonBody, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::audit::{self, action, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::ory::hydra;
use crate::posix::db::{self, device_status, DeviceSession};
use crate::posix::host_auth::RequirePosixHost;
use crate::posix::scope;
use crate::rate_limit;
use crate::state::AppState;

/// Second-factor `amr` methods that satisfy a `force_mfa` host (R11). `pwd` is
/// deliberately absent: a password alone is never a second factor. A const
/// allowlist (not `len(amr) > 1`) so a future Kratos method can't silently count.
const SECOND_FACTOR_AMR: &[&str] = &[
    "totp",
    "webauthn",
    "lookup_secret",
    "webauthn_v2",
    "totp_v2",
];

const AAL2: &str = "aal2";

// --- wire shapes ---------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeviceInitRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
struct DeviceInitResponse {
    user_code: String,
    verification_uri: String,
    /// Omitted for `force_mfa` hosts (R1): forces manual code entry and defeats
    /// one-click `verification_uri_complete` phishing.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri_complete: Option<String>,
    interval: i64,
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct DevicePollRequest {
    pub device_code: String,
}

/// Poll outcome returned to the daemon. `interval` rides on `pending` so Forseti
/// owns the daemon-side backoff (R12). `reason` is a coarse, non-sensitive
/// denial tag, never a code or token.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum DevicePollResponse {
    Pending { interval: i64 },
    Approved,
    Denied { reason: &'static str },
    Expired,
}

fn json_error(status: StatusCode) -> Response {
    status.into_response()
}

/// The configured PAM client secret, or `None` when unset/empty. An empty
/// secret sends `client_secret_basic` with a blank password (Hydra rejects it),
/// so callers treat a missing secret as a hard misconfig and never hit Hydra.
fn require_client_secret(cfg: &crate::config::PosixConfig) -> Option<String> {
    cfg.pam_client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// --- rate limit ----------------------------------------------------------

/// Coarse per-IP rate limit on `device/init`; hosts behind one NAT share a
/// bucket. The real defense against breaching Hydra's `slow_down` is Forseti's
/// own backoff (the daemon honours the `interval` we return).
//
// TODO(R12): replace with a host-id KeyExtractor reading the Basic-auth
// host_id so one compromised host can't exhaust the bucket for its NAT peers.
const DEVICE_INIT_RATE_PER_MINUTE: u32 = 60;

fn rate_limit_error(_err: tower_governor::GovernorError) -> Response {
    StatusCode::TOO_MANY_REQUESTS.into_response()
}

pub fn router(trust_xff: bool) -> Router<AppState> {
    let init = Router::new().route("/posix/v1/device/init", post(device_init));
    let init = rate_limit::single_window(
        init,
        trust_xff,
        60_000,
        DEVICE_INIT_RATE_PER_MINUTE,
        rate_limit_error,
    );
    init.merge(Router::new().route("/posix/v1/device/poll", post(device_poll)))
}

// --- device/init ---------------------------------------------------------

/// `POST /posix/v1/device/init {username}`: start a device flow for a named
/// account on this host. Account must be `enabled` AND visible on the host;
/// denied/unknown both return 404 so the host can't probe which it was.
async fn device_init(
    State(state): State<AppState>,
    host: RequirePosixHost,
    actx: AuditCtx,
    JsonBody(req): JsonBody<DeviceInitRequest>,
) -> Response {
    let cfg = &state.cfg.posix;
    let username = req.username;

    // Deny and unknown collapse to the same 404 (don't reveal which).
    let account = match db::account_by_username(&state.db, &username).await {
        Ok(Some(a)) => a,
        Ok(None) => return json_error(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!(error = ?e, "device_init: account lookup failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if account.enabled != 1 {
        return json_error(StatusCode::NOT_FOUND);
    }
    match scope::account_visible_on_host(&state.db, &host, &account).await {
        Ok(true) => {}
        Ok(false) => return json_error(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!(error = ?e, "device_init: scope check failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let Some(secret) = require_client_secret(cfg) else {
        tracing::error!(
            "posix device auth is enabled but [posix].pam_client_secret is unset; run posix-init-client or set it"
        );
        return json_error(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let authz = match hydra::device_authorization(&state.ory, &cfg.pam_client_id, &secret, "openid")
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = ?e, "device_init: hydra device_authorization failed");
            return json_error(StatusCode::BAD_GATEWAY);
        }
    };

    // A code UNIQUE collision (Ok(false)) is a rare Hydra clash; reject so the
    // daemon restarts the flow, never 500.
    let expires_at = (Utc::now() + chrono::Duration::seconds(authz.expires_in)).to_rfc3339();
    match db::insert_device_session(
        &state.db,
        &authz.device_code,
        &authz.user_code,
        &host.host_id,
        &username,
        &expires_at,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!("device_init: device session code collision; rejecting init");
            return json_error(StatusCode::CONFLICT);
        }
        Err(e) => {
            tracing::error!(error = ?e, "device_init: insert_device_session failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // Audit: hostname + username only, never codes.
    let ev = AuditEvent::new(action::POSIX_DEVICE_AUTH_INITIATED)
        .target(audit::target_kind::POSIX_ACCOUNT, username.clone())
        .with_ctx(&actx)
        .metadata(audit_metadata!(
            "host_id" => host.host_id.clone(),
            "username" => username.clone(),
            "force_mfa" => host.force_mfa,
        ));
    let _ = audit::log(&state.db, ev).await;

    // Suppress verification_uri_complete for force_mfa hosts (R1).
    let verification_uri_complete = if host.force_mfa {
        None
    } else {
        authz.verification_uri_complete
    };

    Json(DeviceInitResponse {
        user_code: authz.user_code,
        verification_uri: authz.verification_uri,
        verification_uri_complete,
        interval: authz.interval,
        expires_in: authz.expires_in,
    })
    .into_response()
}

// --- device/poll ---------------------------------------------------------

/// `POST /posix/v1/device/poll {device_code}`: poll for the flow's outcome.
/// The session MUST belong to the authenticated host. On a Hydra token, runs
/// the binding ([`evaluate_binding`]) before approving.
async fn device_poll(
    State(state): State<AppState>,
    host: RequirePosixHost,
    actx: AuditCtx,
    JsonBody(req): JsonBody<DevicePollRequest>,
) -> Response {
    let cfg = &state.cfg.posix;
    let now = Utc::now();

    // Session must belong to THIS host (else 404, don't leak another host's flow).
    let _ = db::lazy_prune_expired(&state.db, &now.to_rfc3339()).await;
    let session = match db::device_session_by_code(&state.db, &req.device_code).await {
        Ok(Some(s)) if s.host_id == host.host_id => s,
        Ok(_) => return json_error(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!(error = ?e, "device_poll: session lookup failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Single-use: a replay after approve returns the settled state, never re-polls.
    match session.status.as_str() {
        device_status::APPROVED => return Json(DevicePollResponse::Approved).into_response(),
        device_status::DENIED => {
            return Json(DevicePollResponse::Denied { reason: "denied" }).into_response()
        }
        _ => {}
    }

    if session_expired(&session, &now.to_rfc3339()) {
        let _ = db::deny_device_session(&state.db, &session.device_code).await;
        return Json(DevicePollResponse::Expired).into_response();
    }

    let Some(secret) = require_client_secret(cfg) else {
        tracing::error!(
            "posix device auth is enabled but [posix].pam_client_secret is unset; run posix-init-client or set it"
        );
        return json_error(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let outcome = match hydra::poll_device_token(
        &state.ory,
        &cfg.pam_client_id,
        &secret,
        &session.device_code,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = ?e, "device_poll: hydra poll failed");
            return json_error(StatusCode::BAD_GATEWAY);
        }
    };

    match outcome {
        hydra::DeviceTokenOutcome::Pending => Json(DevicePollResponse::Pending {
            interval: hydra_interval(false),
        })
        .into_response(),
        // On slow_down, hand the daemon a longer interval (R12) so it can't
        // push Forseti to breach Hydra's rate.
        hydra::DeviceTokenOutcome::SlowDown => Json(DevicePollResponse::Pending {
            interval: hydra_interval(true),
        })
        .into_response(),
        hydra::DeviceTokenOutcome::Expired => {
            let _ = db::deny_device_session(&state.db, &session.device_code).await;
            Json(DevicePollResponse::Expired).into_response()
        }
        hydra::DeviceTokenOutcome::Denied => {
            let _ = db::deny_device_session(&state.db, &session.device_code).await;
            audit_denied(&state, &actx, &host, &session, "user_denied").await;
            Json(DevicePollResponse::Denied { reason: "denied" }).into_response()
        }
        hydra::DeviceTokenOutcome::Token(token) => {
            handle_token(&state, &actx, &host, &session, &token).await
        }
    }
}

/// Binding entrypoint: validate the id_token, resolve the approver's account,
/// run [`evaluate_binding`], and atomically approve/deny. The atomic
/// `WHERE status='pending'` guard prevents a double-approve.
async fn handle_token(
    state: &AppState,
    actx: &AuditCtx,
    host: &RequirePosixHost,
    session: &DeviceSession,
    token: &hydra::TokenSet,
) -> Response {
    let cfg = &state.cfg.posix;

    // Validate the id_token: alg-pinned, iss/aud/azp/exp/iat.
    let Some(id_token) = token.id_token.as_deref() else {
        audit_denied(state, actx, host, session, "token_invalid").await;
        return deny_and_respond(state, session, "token_invalid").await;
    };
    let issuer = cfg
        .hydra_issuer
        .clone()
        .unwrap_or_else(|| state.cfg.hydra.public_url.clone());
    let claims = match hydra::verify_id_token(
        &state.ory,
        id_token,
        &issuer,
        &cfg.pam_client_id,
        cfg.id_token_iat_window_secs,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "device_poll: id_token validation failed");
            audit_denied(state, actx, host, session, "token_invalid").await;
            return deny_and_respond(state, session, "token_invalid").await;
        }
    };

    let account = match db::account_by_identity(&state.db, &claims.sub).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            audit_denied(state, actx, host, session, "no_account").await;
            return deny_and_respond(state, session, "no_account").await;
        }
        Err(e) => {
            tracing::error!(error = ?e, "device_poll: account_by_identity failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Live binding: named-target match, enabled, scope, force_mfa.
    let scope_ok = match scope::account_visible_on_host(&state.db, host, &account).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "device_poll: live scope check failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let now = Utc::now().timestamp();
    let decision = evaluate_binding(
        &BindingInputs {
            requested_username: &session.requested_username,
            account_username: &account.username,
            account_enabled: account.enabled == 1,
            scope_ok,
            host_force_mfa: host.force_mfa,
            acr: claims.acr.as_deref(),
            amr: &claims.amr,
            auth_time: claims.auth_time,
        },
        now,
        cfg.mfa_auth_time_window_secs as i64,
    );

    if let Err(reason) = decision {
        audit_denied(state, actx, host, session, reason).await;
        return deny_and_respond(state, session, reason).await;
    }

    // Atomic single-use approve; false means already terminal, never double-approve.
    match db::approve_device_session(&state.db, &session.device_code, &claims.sub).await {
        Ok(true) => {
            let ev = AuditEvent::new(action::POSIX_DEVICE_AUTH_APPROVED)
                .actor_user(&claims.sub, "")
                .target(audit::target_kind::POSIX_ACCOUNT, account.username.clone())
                .with_ctx(actx)
                .metadata(audit_metadata!(
                    "host_id" => host.host_id.clone(),
                    "username" => account.username.clone(),
                ));
            let _ = audit::log(&state.db, ev).await;
            Json(DevicePollResponse::Approved).into_response()
        }
        Ok(false) => {
            // Lost the race to a concurrent terminal transition; report what settled.
            match db::device_session_by_code(&state.db, &session.device_code).await {
                Ok(Some(s)) if s.status == device_status::APPROVED => {
                    Json(DevicePollResponse::Approved).into_response()
                }
                _ => Json(DevicePollResponse::Denied { reason: "denied" }).into_response(),
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "device_poll: approve_device_session failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Atomically deny (best-effort) and return the denial response.
async fn deny_and_respond(
    state: &AppState,
    session: &DeviceSession,
    reason: &'static str,
) -> Response {
    let _ = db::deny_device_session(&state.db, &session.device_code).await;
    Json(DevicePollResponse::Denied { reason }).into_response()
}

async fn audit_denied(
    state: &AppState,
    actx: &AuditCtx,
    host: &RequirePosixHost,
    session: &DeviceSession,
    reason: &'static str,
) {
    let ev = AuditEvent::new(action::POSIX_DEVICE_AUTH_DENIED)
        .target(
            audit::target_kind::POSIX_ACCOUNT,
            session.requested_username.clone(),
        )
        .with_ctx(actx)
        .severity(audit::severity::WARNING)
        .metadata(audit_metadata!(
            "host_id" => host.host_id.clone(),
            "username" => session.requested_username.clone(),
            "reason" => reason,
        ));
    let _ = audit::log(&state.db, ev).await;
}

// --- the pure binding decision -------------------------------------------

/// Inputs to the pure binding decision (no DB, no network); the I/O lives in
/// `handle_token`.
struct BindingInputs<'a> {
    requested_username: &'a str,
    account_username: &'a str,
    account_enabled: bool,
    /// Result of the LIVE `account_visible_on_host` re-check at poll time.
    scope_ok: bool,
    host_force_mfa: bool,
    acr: Option<&'a str>,
    amr: &'a [String],
    auth_time: Option<i64>,
}

/// The binding (R4 + R11). Returns `Ok(())` to approve or `Err(reason)` with a
/// coarse, non-sensitive denial tag. All required:
/// 1. The approver IS the named target: `account.username == requested`.
/// 2. The account is `enabled`.
/// 3. The account is visible on the host (LIVE scope re-check).
/// 4. For `force_mfa` hosts: `acr == "aal2"`, `amr` contains a pinned
///    second factor, and `auth_time` is within the freshness window.
fn evaluate_binding(
    inputs: &BindingInputs<'_>,
    now: i64,
    mfa_auth_time_window_secs: i64,
) -> Result<(), &'static str> {
    if inputs.account_username != inputs.requested_username {
        return Err("binding");
    }
    if !inputs.account_enabled {
        return Err("binding");
    }
    if !inputs.scope_ok {
        return Err("binding");
    }

    if inputs.host_force_mfa {
        if inputs.acr != Some(AAL2) {
            return Err("mfa_required");
        }
        let has_second_factor = inputs
            .amr
            .iter()
            .any(|m| SECOND_FACTOR_AMR.contains(&m.as_str()));
        if !has_second_factor {
            return Err("mfa_required");
        }
        match inputs.auth_time {
            Some(t) if now - t <= mfa_auth_time_window_secs && t <= now + 60 => {}
            _ => return Err("mfa_required"),
        }
    }

    Ok(())
}

// --- small helpers -------------------------------------------------------

/// Lexicographic expiry check on the fixed-width RFC 3339 timestamps.
fn session_expired(session: &DeviceSession, now_rfc3339: &str) -> bool {
    session.expires_at.as_str() < now_rfc3339
}

/// Daemon poll interval: 5s base (RFC 8628 default), 10s on a Hydra `slow_down`
/// so Forseti's own polling stays under Hydra's rate (R12).
fn hydra_interval(slow_down: bool) -> i64 {
    if slow_down {
        10
    } else {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_inputs<'a>(
        requested: &'a str,
        username: &'a str,
        amr: &'a [String],
    ) -> BindingInputs<'a> {
        BindingInputs {
            requested_username: requested,
            account_username: username,
            account_enabled: true,
            scope_ok: true,
            host_force_mfa: false,
            acr: Some(AAL2),
            amr,
            auth_time: None,
        }
    }

    #[test]
    fn binding_approves_when_named_target_matches() {
        let amr = vec!["pwd".to_string()];
        let inputs = base_inputs("alice", "alice", &amr);
        assert!(evaluate_binding(&inputs, 1000, 300).is_ok());
    }

    #[test]
    fn binding_denies_wrong_user() {
        // Approver authenticated as bob but the flow named alice.
        let amr = vec!["pwd".to_string()];
        let inputs = base_inputs("alice", "bob", &amr);
        assert_eq!(evaluate_binding(&inputs, 1000, 300), Err("binding"));
    }

    #[test]
    fn binding_denies_disabled_account() {
        let amr = vec!["pwd".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.account_enabled = false;
        assert_eq!(evaluate_binding(&inputs, 1000, 300), Err("binding"));
    }

    #[test]
    fn binding_denies_out_of_scope() {
        let amr = vec!["pwd".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.scope_ok = false;
        assert_eq!(evaluate_binding(&inputs, 1000, 300), Err("binding"));
    }

    #[test]
    fn force_mfa_denies_aal1() {
        let amr = vec!["pwd".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.host_force_mfa = true;
        inputs.acr = Some("aal1");
        inputs.auth_time = Some(1000);
        assert_eq!(evaluate_binding(&inputs, 1000, 300), Err("mfa_required"));
    }

    #[test]
    fn force_mfa_denies_aal2_without_second_factor() {
        // acr says aal2 but amr carries only pwd, no real second factor.
        let amr = vec!["pwd".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.host_force_mfa = true;
        inputs.auth_time = Some(1000);
        assert_eq!(evaluate_binding(&inputs, 1000, 300), Err("mfa_required"));
    }

    #[test]
    fn force_mfa_approves_aal2_with_totp_fresh() {
        let amr = vec!["pwd".to_string(), "totp".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.host_force_mfa = true;
        inputs.auth_time = Some(1000);
        assert!(evaluate_binding(&inputs, 1100, 300).is_ok());
    }

    #[test]
    fn force_mfa_approves_webauthn() {
        let amr = vec!["webauthn".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.host_force_mfa = true;
        inputs.auth_time = Some(1000);
        assert!(evaluate_binding(&inputs, 1000, 300).is_ok());
    }

    #[test]
    fn force_mfa_denies_stale_auth_time() {
        // AAL2 + totp but the session is hours old → reject (R11 freshness).
        let amr = vec!["totp".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.host_force_mfa = true;
        inputs.auth_time = Some(1000);
        assert_eq!(
            evaluate_binding(&inputs, 1000 + 3600, 300),
            Err("mfa_required")
        );
    }

    #[test]
    fn force_mfa_denies_missing_auth_time() {
        let amr = vec!["totp".to_string()];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.host_force_mfa = true;
        inputs.auth_time = None;
        assert_eq!(evaluate_binding(&inputs, 1000, 300), Err("mfa_required"));
    }

    #[test]
    fn non_mfa_host_ignores_acr() {
        // force_mfa false → acr/amr/auth_time are irrelevant.
        let amr: Vec<String> = vec![];
        let mut inputs = base_inputs("alice", "alice", &amr);
        inputs.acr = None;
        inputs.auth_time = None;
        assert!(evaluate_binding(&inputs, 1000, 300).is_ok());
    }

    #[test]
    fn require_client_secret_rejects_unset_and_empty() {
        let mut cfg = crate::config::PosixConfig::default();
        assert_eq!(require_client_secret(&cfg), None);
        cfg.pam_client_secret = Some(String::new().into());
        assert_eq!(require_client_secret(&cfg), None);
        cfg.pam_client_secret = Some("s3cret".into());
        assert_eq!(require_client_secret(&cfg).as_deref(), Some("s3cret"));
    }

    #[test]
    fn session_expiry_is_lexicographic() {
        let s = DeviceSession {
            device_code: "dc".into(),
            user_code: "uc".into(),
            host_id: "h".into(),
            requested_username: "alice".into(),
            status: device_status::PENDING.into(),
            identity_id: None,
            created_at: "2026-06-23T00:00:00+00:00".into(),
            expires_at: "2026-06-23T00:10:00+00:00".into(),
        };
        assert!(!session_expired(&s, "2026-06-23T00:05:00+00:00"));
        assert!(session_expired(&s, "2026-06-23T00:11:00+00:00"));
    }
}
