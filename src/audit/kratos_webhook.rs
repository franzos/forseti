//! `POST /internal/audit/kratos` — Kratos flow-hook receiver.
//!
//! Kratos's self-service flows (registration, settings, recovery,
//! verification) support `web_hook` actions that fire a normalised JSON
//! payload on flow completion. We register the same hook URL on every
//! flow with a per-hook `action` wrapper field, so the receiver parses
//! one stable shape regardless of which flow fired.
//!
//! ## Auth
//!
//! Bearer token (`Authorization: Bearer <token>`) matched against
//! `[audit].webhook_token`. The endpoint should be reachable only from
//! the trust boundary (the internal listener bound to loopback / a
//! private interface; see `[internal] bind` in `config.toml`); the token
//! is defence-in-depth, not the primary boundary. Forseti refuses to
//! boot when `webhook_token` is empty, so by the time a request reaches
//! this handler the token is guaranteed non-empty.
//!
//! ## Replay protection
//!
//! Bearer alone lets anyone who intercepts a single request replay it
//! arbitrarily later. The receiver adds a freshness window on top: the
//! jsonnet body surfaces `ctx.flow.issued_at` (RFC 3339), and a payload
//! whose `issued_at` is older than `MAX_PAYLOAD_AGE` (1h) or skewed more
//! than `MAX_PAYLOAD_SKEW` (1 min) into the future is *flagged* —
//! recorded with a `metadata.freshness` marker and counted — not
//! dropped. The window covers the longest Kratos flow lifespan (settings
//! flows default to 1h), so a "stale" reading means a genuinely old
//! `issued_at` (replay or clock skew), not a slow user. Payloads missing
//! `issued_at` are written unflagged — older Kratos versions omit it.
//!
//! The window is telemetry, not the guard: the real guard remains the
//! internal listener + bearer. Duplicate rows in an append-only log are
//! harmless, so the receiver doesn't dedupe.
//!
//! Full HMAC-of-body signing is the standard webhook pattern (Stripe /
//! GitHub), but Kratos's `web_hook` action ships static headers only —
//! it can't compute an HMAC at send time. Closing that gap requires a
//! reverse proxy in front of Kratos to sign, or upstream support in
//! Kratos.
//!
//! ## Responses
//!
//! The scheme is deliberately "401 for auth, 204 for everything else":
//!
//! - `401 Unauthorized` on missing / wrong token
//! - `204 No Content` on every other outcome — accepted row, flagged
//!   (stale/future) row, malformed body, or unknown action
//!
//! User-flow safety comes from `response.ignore: true` on the Kratos
//! side: hooks are fire-and-forget, so Kratos never reads our status and
//! a slow or erroring receiver can't stall the flow. As defence in depth
//! the receiver only ever returns 401 or 204 — it is structurally
//! incapable of returning a flow-breaking 4xx/5xx even if a future
//! Kratos config regresses to a blocking hook. (Earlier code returned
//! 400 on bad payloads; a 400 from a *blocking* hook aborts the user's
//! flow, which was the production bug. `can_interrupt: false` does *not*
//! make a hook non-blocking.)
//!
//! The failure signal lives out-of-band instead: two in-process counters
//! on `/admin/status` — rejected (malformed body / unknown action) and
//! freshness anomalies (stale / future) — plus `warn!` logs.
//!
//! ## Events covered
//!
//! Flow-driven only: `identity.created` (registration), `password.changed`
//! (settings.password), `password.recovered` (recovery),
//! `verification.completed` (verification), `mfa.*` (settings.{totp,
//! webauthn, lookup}), `auth.login` / `auth.login_failed` (login flow).
//! Admin-API identity writes (update/delete) are emitted from Forseti's
//! own admin handlers — Kratos doesn't fire flow hooks for admin-API
//! operations.

use axum::{
    extract::{Json, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditEvent, SafeMetadata};
use crate::state::AppState;

/// Flag payloads whose `issued_at` is older than this as "stale". Covers
/// the longest Kratos flow lifespan (settings flows default to 1h), so a
/// stale reading is a genuinely old timestamp, not a slow user.
const MAX_PAYLOAD_AGE: chrono::Duration = chrono::Duration::hours(1);

/// Tolerance for `issued_at` skew into the future — Kratos and Forseti
/// may run on different hosts with drifting clocks.
const MAX_PAYLOAD_SKEW: chrono::Duration = chrono::Duration::minutes(1);

/// Build the sub-router. Mounted from `app::run`.
pub fn router() -> Router<AppState> {
    Router::new().route("/internal/audit/kratos", post(receive))
}

/// Stable payload shape produced by the shared `audit_event.jsonnet`
/// template. Per-flow ctx differences are flattened into this struct in
/// the template, so the receiver doesn't branch on which flow fired.
#[derive(Debug, Deserialize)]
pub struct KratosAuditPayload {
    /// Identity that completed the flow. Optional because some flows
    /// (e.g. failed login on an unknown email) don't yield an id.
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub actor_email: Option<String>,
    /// Target of the action. For identity-shaped events this echoes
    /// `actor_id`; included so the template stays uniform.
    #[serde(default)]
    pub target_id: Option<String>,
    /// RFC 3339 timestamp the Kratos flow was issued at. Populated by
    /// the jsonnet template from `ctx.flow.issued_at`. Used as the
    /// freshness lower bound — see the "Replay protection" section in
    /// the module docs. `None` when the flow ctx didn't carry the
    /// field (older Kratos versions omit it on some hooks).
    #[serde(default)]
    pub issued_at: Option<DateTime<Utc>>,
    /// Free-form metadata bag from the jsonnet (flow_id, method, etc.).
    /// Goes through `SafeMetadata` so any sensitive-looking key the
    /// template accidentally surfaces is rejected at write time.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Per-hook action selector, passed as `?action=...` on the webhook URL.
/// Kratos's web_hook ctx doesn't carry the hook identity, and a single
/// jsonnet template is materially simpler than one-per-hook — so we
/// route the action through the URL.
#[derive(Debug, Deserialize)]
pub struct ActionQuery {
    pub action: String,
}

/// Bearer-token auth + payload → audit event.
///
/// Default-org floor placement is no longer driven by a webhook — see
/// `crate::orgs::ensure_default_floor` and its caller in
/// `crate::orgs::middleware::auto_join_default_org`. This receiver is purely the
/// audit-write side.
pub async fn receive(
    State(state): State<AppState>,
    Query(q): Query<ActionQuery>,
    headers: axum::http::HeaderMap,
    body: Result<Json<KratosAuditPayload>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let action_str_opt = map_action(&q.action);

    // `app::run` refuses to boot with an unset accept-list, so this is
    // never empty at runtime. Keep the explicit check anyway as defence in
    // depth against a future code path that constructs `AuditConfig`
    // outside the boot path.
    if state.cfg.audit.webhook_token.is_unset() {
        return (
            StatusCode::UNAUTHORIZED,
            "audit webhook token not configured",
        )
            .into_response();
    }
    // Case-insensitive scheme match per RFC 6750 §2.1 — mirrors the DCR
    // `parse_authorization` helper in `oauth/register/iat.rs`.
    let Some(presented) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, token)| token.trim())
        .filter(|t| !t.is_empty())
    else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    };
    let Some(matched_idx) = match_webhook_token(state.cfg.audit.webhook_token.entries(), presented)
    else {
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    };
    audit::record_kratos_webhook_matched(matched_idx);

    // Unknown action / malformed body are a Kratos contract or config
    // mismatch, not an auth failure. Count them and return 204 — never a
    // flow-breaking status (see the Responses section in the module docs).
    let action_str = match action_str_opt {
        Some(s) => s,
        None => {
            tracing::warn!(action = %q.action, "kratos audit webhook: unknown action");
            audit::record_kratos_webhook_rejected();
            return StatusCode::NO_CONTENT.into_response();
        }
    };

    let payload = match body {
        Ok(Json(p)) => p,
        Err(_) => {
            tracing::warn!("kratos audit webhook: malformed body");
            audit::record_kratos_webhook_rejected();
            return StatusCode::NO_CONTENT.into_response();
        }
    };

    // Freshness: flag stale / future-dated payloads (telemetry) but still
    // write the row. Missing `issued_at` writes unflagged — older Kratos
    // versions omit the field on some hooks.
    let freshness_flag: Option<&'static str> = match payload.issued_at {
        Some(issued_at) => {
            let age = Utc::now().signed_duration_since(issued_at);
            if age > MAX_PAYLOAD_AGE {
                tracing::warn!(
                    action = action_str,
                    age_secs = age.num_seconds(),
                    "kratos audit webhook: stale payload"
                );
                Some("stale")
            } else if age < -MAX_PAYLOAD_SKEW {
                tracing::warn!(
                    action = action_str,
                    skew_secs = (-age).num_seconds(),
                    "kratos audit webhook: future-dated payload"
                );
                Some("future")
            } else {
                None
            }
        }
        None => None,
    };
    if freshness_flag.is_some() {
        audit::record_kratos_webhook_freshness_anomaly();
    }

    let mut meta_value = payload.metadata.clone();
    if let (Some(flag), serde_json::Value::Object(m)) = (freshness_flag, &mut meta_value) {
        m.insert(
            "freshness".to_string(),
            serde_json::Value::String(flag.to_string()),
        );
    }
    let metadata = build_safe_metadata(meta_value);
    let event = build_kratos_event(action_str, &payload, metadata);
    let _ = audit::log(&state.db, event).await;
    audit::record_kratos_webhook_received();

    StatusCode::NO_CONTENT.into_response()
}

/// Index of the first accept-list entry the presented bearer matches, or
/// `None`. Hashes both sides before `ct_eq`: subtle's slice impl
/// short-circuits on unequal lengths, which would leak a length oracle for
/// the configured token; fixed-length digests dodge that. Every entry is
/// checked (no early break), so the accept-list size isn't observable via
/// timing.
fn match_webhook_token(entries: &[String], presented: &str) -> Option<usize> {
    use sha2::Digest;
    let presented_hash = sha2::Sha256::digest(presented.as_bytes());
    let mut matched: Option<usize> = None;
    for (i, tok) in entries.iter().enumerate() {
        let configured_hash = sha2::Sha256::digest(tok.as_bytes());
        if bool::from(subtle::ConstantTimeEq::ct_eq(
            presented_hash.as_slice(),
            configured_hash.as_slice(),
        )) {
            matched.get_or_insert(i);
        }
    }
    matched
}

/// Map an inbound action string onto the typed vocabulary. Unknown values
/// are rejected at the receiver rather than leaked through `Box::leak` —
/// keeps the action column tightly scoped to the agreed set and avoids
/// memory growth from a misconfigured Kratos.
fn map_action(s: &str) -> Option<&'static str> {
    Some(match s {
        "identity.created" => action::IDENTITY_CREATED,
        "password.changed" => action::PASSWORD_CHANGED,
        "password.recovered" => action::PASSWORD_RECOVERED,
        "verification.completed" => action::VERIFICATION_COMPLETED,
        "auth.login" => action::AUTH_LOGIN,
        "auth.login_failed" => action::AUTH_LOGIN_FAILED,
        "mfa.totp.enrolled" => action::MFA_TOTP_ENROLLED,
        "mfa.totp.disabled" => action::MFA_TOTP_DISABLED,
        "mfa.lookup.regenerated" => action::MFA_LOOKUP_REGENERATED,
        "mfa.webauthn.added" => action::MFA_WEBAUTHN_ADDED,
        "mfa.webauthn.removed" => action::MFA_WEBAUTHN_REMOVED,
        "profile.updated" => action::PROFILE_UPDATED,
        _ => return None,
    })
}

/// Build the event. Flow-driven events have the user as actor (since the
/// user initiated the flow); the webhook is merely the delivery channel.
/// If the payload doesn't carry an identity (e.g. failed login on an
/// unknown email) we fall back to `actor_webhook("kratos")` so the row
/// has *some* attribution.
fn build_kratos_event(
    action_str: &'static str,
    payload: &KratosAuditPayload,
    metadata: SafeMetadata,
) -> AuditEvent {
    let mut event = AuditEvent::new(action_str);
    event = match payload.actor_id.as_deref() {
        Some(id) => event.actor_user(id, payload.actor_email.as_deref().unwrap_or("")),
        None => event.actor_webhook("kratos"),
    };
    let target_id = payload.target_id.as_deref().or(payload.actor_id.as_deref());
    if let Some(t) = target_id {
        event = event.target(target_kind::IDENTITY, t.to_string());
    }
    event.metadata(metadata)
}

/// Convert freeform JSON metadata to `SafeMetadata`. Top-level object
/// keys go through the deny-list; anything that's not an object becomes
/// `{ "value": <json> }`.
fn build_safe_metadata(value: serde_json::Value) -> SafeMetadata {
    match value {
        serde_json::Value::Object(map) => SafeMetadata::from_json_object(map),
        other => SafeMetadata::from_pairs(&[("value", other)]),
    }
}

#[cfg(test)]
mod tests {
    use super::match_webhook_token;

    fn entries(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn webhook_token_single_entry_matches() {
        let e = entries(&["secret"]);
        assert_eq!(match_webhook_token(&e, "secret"), Some(0));
    }

    #[test]
    fn webhook_token_accept_list_matches_old_entry() {
        // Rotation in flight: ["new", "old"] still accepts the old token.
        let e = entries(&["new", "old"]);
        assert_eq!(match_webhook_token(&e, "old"), Some(1));
    }

    #[test]
    fn webhook_token_accept_list_matches_new_entry() {
        let e = entries(&["new", "old"]);
        assert_eq!(match_webhook_token(&e, "new"), Some(0));
    }

    #[test]
    fn webhook_token_unknown_is_rejected() {
        let e = entries(&["new", "old"]);
        assert_eq!(match_webhook_token(&e, "unknown"), None);
    }

    #[test]
    fn webhook_token_empty_list_never_matches() {
        assert_eq!(match_webhook_token(&[], "anything"), None);
    }
}
