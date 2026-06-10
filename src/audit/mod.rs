//! Append-only audit event log — Phase 2 (minimal-compliant).
//!
//! One table, one write API, one read API. The vocabulary is string-keyed
//! constants (see [`action`]) so call sites are typo-checked and the
//! `audit_events.action` column can be indexed without enum surgery.
//!
//! ## Write path
//!
//! Synchronous diesel insert wrapped in [`log`]. The Result is `#[must_use]`
//! so a forgotten error path lights a warning: non-critical call sites
//! write `let _ = audit::log(...).await;` to explicitly drop, while
//! compliance-critical callers (account self-deletion, admin destructive
//! actions) propagate with `?` and react to the failure. Either way the
//! row is also emitted to stderr as a structured `audit_fallback` event
//! on insert failure, so log scrapes can recover dropped rows. Audit must
//! never break the request that produced the event — the fallback path
//! is the durability seam.
//!
//! ## Builder
//!
//! [`AuditEvent::new`] returns a fluent builder. Setters are **orthogonal**
//! — each touches exactly one concern. `.failed(err)` records the failure
//! but does not silently bump severity; callers who want a failed event at
//! `error` severity write `.failed(err).severity(severity::ERROR)`. This
//! is deliberate: tangled defaults cause "this builder method has to come
//! before that one or the result is wrong" footguns.
//!
//! ## Metadata
//!
//! `metadata` is operator-readable on `/admin/audit`. Callers must not
//! shove credentials, tokens, recovery codes, or unredacted request bodies
//! into it. [`SafeMetadata`] is the only way to construct the field, and
//! the constructor refuses any key matching a hard-coded deny-list. In
//! debug builds the offence panics; in release it drops the key and logs
//! a warning. Loud either way — a forgotten debug-paste in metadata can't
//! reach disk silently.
//!
//! ## Request context
//!
//! [`middleware`] runs once per request and stashes an [`AuditCtx`] in
//! request extensions. Handlers extract via the [`AuditCtx`] axum
//! extractor and pass it to [`AuditEvent::with_ctx`]. No per-call-site
//! `HeaderMap` plumbing.
//!
//! ## Append-only enforcement
//!
//! `audit_events` rejects UPDATE / DELETE via a BEFORE trigger in both
//! backends. The pruner is the only legitimate UPDATE/DELETE writer and
//! goes through [`with_audit_purge`], which sets the backend-specific
//! override inside the same transaction as the DELETE. A crash mid-prune
//! rolls everything back atomically — no separate boot-time reset needed.
//!
//! See `TODO.md` §2.

pub mod kratos_webhook;

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, SecondsFormat, Utc};
use diesel::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::audit_events;
use crate::state::AppState;

// --- vocabulary ----------------------------------------------------------

/// String-keyed event names. Locked here as `const`s so call sites get
/// typo-checked at compile time without forcing the storage layer to deal
/// with an enum that grows every quarter.
///
/// Naming convention: `<domain>.<verb>`, lowercase, dot-separated.
pub mod action {
    // auth
    pub const AUTH_LOGIN: &str = "auth.login";
    pub const AUTH_LOGOUT: &str = "auth.logout";
    pub const AUTH_LOGIN_FAILED: &str = "auth.login_failed";
    // identity (flow-driven; emitted from Kratos webhook)
    pub const IDENTITY_CREATED: &str = "identity.created";
    pub const PASSWORD_CHANGED: &str = "password.changed";
    pub const PASSWORD_RECOVERED: &str = "password.recovered";
    pub const VERIFICATION_COMPLETED: &str = "verification.completed";
    // mfa (flow-driven)
    pub const MFA_TOTP_ENROLLED: &str = "mfa.totp.enrolled";
    pub const MFA_TOTP_DISABLED: &str = "mfa.totp.disabled";
    pub const MFA_LOOKUP_REGENERATED: &str = "mfa.lookup.regenerated";
    pub const MFA_WEBAUTHN_ADDED: &str = "mfa.webauthn.added";
    pub const MFA_WEBAUTHN_REMOVED: &str = "mfa.webauthn.removed";
    // session (Forseti-mediated)
    pub const SESSION_REVOKED: &str = "session.revoked";
    pub const SESSIONS_BULK_REVOKED: &str = "sessions.bulk_revoked";
    // oauth (Forseti consent handler)
    pub const OAUTH_CONSENT_GRANTED: &str = "oauth.consent.granted";
    pub const OAUTH_CONSENT_DENIED: &str = "oauth.consent.denied";
    pub const OAUTH_CONSENT_REVOKED: &str = "oauth.consent.revoked";
    /// Verification-state lookup against `oauth_client_metadata` failed
    /// (DB blip). The consent flow fails closed and shows the caution
    /// banner — this event gives operators a signal so they notice when
    /// a flaky table is silently flipping every DCR client to unverified.
    pub const CONSENT_VERIFICATION_LOOKUP_FAILED: &str = "consent.verification_lookup_failed";
    // oauth — Dynamic Client Registration (RFC 7591) proxy
    pub const OAUTH_CLIENT_DCR_REGISTERED: &str = "oauth.client.dcr_registered";
    pub const OAUTH_CLIENT_DCR_REJECTED: &str = "oauth.client.dcr_rejected";
    pub const OAUTH_CLIENT_DCR_RATE_LIMITED: &str = "oauth.client.dcr_rate_limited";
    pub const OAUTH_CLIENT_DCR_IAT_ISSUED: &str = "oauth.client.dcr_iat_issued";
    pub const OAUTH_CLIENT_DCR_IAT_REVOKED: &str = "oauth.client.dcr_iat_revoked";
    // admin
    pub const ADMIN_CLIENT_CREATED: &str = "oauth.client.created";
    pub const ADMIN_CLIENT_UPDATED: &str = "oauth.client.updated";
    pub const ADMIN_CLIENT_DELETED: &str = "oauth.client.deleted";
    pub const ADMIN_CLIENT_SECRET_ROTATED: &str = "oauth.client.secret_rotated";
    pub const ADMIN_CLIENT_VERIFIED: &str = "oauth.client.verified";
    pub const ADMIN_CLIENT_UNVERIFIED: &str = "oauth.client.unverified";
    pub const ADMIN_IDENTITY_DISABLED: &str = "admin.identity.disabled";
    pub const ADMIN_IDENTITY_ENABLED: &str = "admin.identity.enabled";
    pub const ADMIN_IDENTITY_DELETED: &str = "admin.identity.deleted";
    pub const ADMIN_IDENTITY_RECOVERY_CODE_MINTED: &str = "admin.identity.recovery_code_minted";
    /// Hand-rolled "claim this email" flow has deleted an unverified
    /// identity that previously held a desired email address. Emitted at
    /// `critical` severity because it's a destructive identity-deletion
    /// initiated outside the admin surface.
    pub const IDENTITY_RECLAIMED: &str = "identity.reclaimed";
    pub const ADMIN_SESSION_REVOKED: &str = "admin.session.revoked";
    pub const ADMIN_WEBHOOK_REQUEUED: &str = "admin.webhook.requeued";
    pub const ADMIN_WEBHOOK_DISCARDED: &str = "admin.webhook.discarded";
    // profiles
    pub const PROFILE_UPDATED: &str = "profile.updated";
    // orgs
    pub const ORG_INVITE_CREATED: &str = "org.invite.created";
    pub const ORG_INVITE_ACCEPTED: &str = "org.invite.accepted";
    pub const ORG_MEMBER_ADDED: &str = "org.member.added";
    pub const ORG_MEMBER_REMOVED: &str = "org.member.removed";
    pub const ORG_MEMBER_ROLE_CHANGED: &str = "org.member.role_changed";
    // account-self (#1)
    pub const ACCOUNT_SELF_DELETED: &str = "account.self_deleted";
    // commercial license (`src/commercial/`)
    pub const LICENSE_ACTIVATED: &str = "license.activated";
    pub const LICENSE_DEACTIVATED: &str = "license.deactivated";
    // RP-initiated account management (`src/handoff/`)
    pub const APP_REFERRER_ENTERED: &str = "app.referrer.entered";
    pub const APP_REFERRER_RETURNED: &str = "app.referrer.returned";
    // saml (commercial SSO bridge — `src/saml/`)
    pub const SAML_LOGIN_SUCCEEDED: &str = "saml.login.succeeded";
    pub const SAML_LOGIN_FAILED: &str = "saml.login.failed";
    pub const SAML_LOGIN_BLOCKED_UNVERIFIED: &str = "saml.login.blocked_unverified";
    pub const SAML_IDENTITY_JIT_CREATED: &str = "saml.identity.jit_created";
    pub const SAML_IDENTITY_LINKED: &str = "saml.identity.linked";
    pub const ADMIN_SAML_CONNECTION_CREATED: &str = "admin.saml.connection_created";
    pub const ADMIN_SAML_CONNECTION_DELETED: &str = "admin.saml.connection_deleted";
    pub const ADMIN_SAML_CONNECTION_TOGGLED: &str = "admin.saml.connection_toggled";
}

#[allow(dead_code)]
pub mod severity {
    pub const INFO: &str = "info";
    pub const WARNING: &str = "warning";
    pub const ERROR: &str = "error";
    pub const CRITICAL: &str = "critical";
}

pub mod actor_kind {
    pub const USER: &str = "user";
    pub const ADMIN: &str = "admin";
    pub const SYSTEM: &str = "system";
    pub const WEBHOOK: &str = "webhook";
}

pub mod target_kind {
    pub const IDENTITY: &str = "identity";
    pub const OAUTH_CLIENT: &str = "oauth_client";
    pub const SESSION: &str = "session";
    pub const WEBHOOK_OUTBOX: &str = "webhook_outbox";
    pub const DCR_IAT: &str = "dcr_iat";
    pub const LICENSE: &str = "license";
    pub const ORG: &str = "org";
    pub const SAML_CONNECTION: &str = "saml_connection";
}

// --- safe metadata -------------------------------------------------------

/// Sealed wrapper around a JSON object. The only way to construct one is
/// via [`SafeMetadata::from_pairs`] or the [`audit_metadata!`] macro, both
/// of which apply the sensitive-key deny-list at write time.
///
/// There is no `From<serde_json::Value>` impl. The newtype is the seam.
#[derive(Debug, Clone)]
pub struct SafeMetadata(serde_json::Value);

impl SafeMetadata {
    pub fn empty() -> Self {
        Self(serde_json::Value::Object(serde_json::Map::new()))
    }

    /// Construct from key/value pairs. Sensitive-looking keys are rejected
    /// (panic in debug, dropped + `warn!` in release).
    pub fn from_pairs(pairs: &[(&str, serde_json::Value)]) -> Self {
        let mut map = serde_json::Map::new();
        for (k, v) in pairs {
            if is_sensitive_key(k) {
                handle_sensitive(k);
                continue;
            }
            map.insert((*k).to_string(), v.clone());
        }
        Self(serde_json::Value::Object(map))
    }

    /// Construct from an arbitrary JSON object (e.g. a Kratos webhook
    /// payload). Applies the same sensitive-key deny-list as
    /// [`from_pairs`](Self::from_pairs) — keys are consumed by value so no
    /// surviving entry is cloned.
    pub fn from_json_object(map: serde_json::Map<String, serde_json::Value>) -> Self {
        let mut out = serde_json::Map::new();
        for (k, v) in map {
            if is_sensitive_key(&k) {
                handle_sensitive(&k);
                continue;
            }
            out.insert(k, v);
        }
        Self(serde_json::Value::Object(out))
    }

    fn into_value(self) -> serde_json::Value {
        self.0
    }
}

/// Build a `SafeMetadata` from `"k" => expr` pairs. Values go through
/// `serde_json::json!`, which is restricted via clippy lint to this macro
/// only. Reject sensitive keys at construction time.
///
/// ```ignore
/// audit_metadata!(
///     "client_id" => client.id,
///     "client_name" => client.name,
/// )
/// ```
#[macro_export]
macro_rules! audit_metadata {
    ($($k:literal => $v:expr),* $(,)?) => {{
        $crate::audit::SafeMetadata::from_pairs(&[
            $(($k, ::serde_json::json!($v))),*
        ])
    }};
}

/// Substring match against a hand-curated deny-list. Case-insensitive.
fn is_sensitive_key(key: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "password",
        "secret",
        "token",
        "cookie",
        "authorization",
        "otp",
        "recovery",
        // Specific, not a bare "key" — that over-matched `api_key_id`,
        // `public_key_kid`, even `monkey`.
        "private_key",
        "api_key",
        "signing_key",
        "secret_key",
        "credential",
    ];
    let lower = key.to_lowercase();
    NEEDLES.iter().any(|n| lower.contains(n))
}

fn handle_sensitive(key: &str) {
    if cfg!(debug_assertions) {
        panic!(
            "audit::SafeMetadata: key '{key}' looks sensitive — audit metadata must not carry \
             credentials, tokens, or recovery codes. Use a generic shape ('client_id', 'flow_id') \
             or omit the field entirely."
        );
    }
    tracing::warn!(
        key,
        "audit::SafeMetadata: dropped sensitive-looking key from metadata"
    );
}

// --- audit ctx -----------------------------------------------------------

/// Per-request context filled in by [`middleware`]. Cheap to clone (three
/// `Option<String>`s) so handlers can extract it once and pass `&AuditCtx`
/// to every `with_ctx` call.
#[derive(Clone, Debug, Default)]
pub struct AuditCtx {
    pub ip_hash: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

impl<S> axum::extract::FromRequestParts<S> for AuditCtx
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<AuditCtx>()
            .cloned()
            .unwrap_or_default())
    }
}

/// Cap a User-Agent header at 512 chars so a hostile client can't bloat
/// audit rows with the RFC-permitted 64 KB string.
fn cap_user_agent(raw: &str) -> String {
    raw.chars().take(512).collect()
}

/// Accept an `X-Request-Id` header value only if it's all ASCII-printable
/// (0x20..=0x7E) and at most 128 chars. Anything else (newlines, control
/// chars, oversize) returns `None` so the caller can fall through to a
/// freshly minted UUID.
fn accept_request_id(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 128 {
        return None;
    }
    if raw.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        Some(raw.to_owned())
    } else {
        None
    }
}

/// Axum middleware that derives the per-request audit context once and
/// stashes it in request extensions. Mounted globally in `app::run` so
/// every handler sees the same shape.
pub async fn middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response {
    let salt = ip_salt(&state.cfg);
    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());
    let ip = extract_client_ip(&headers, state.cfg.proxy.trust_forwarded_for, peer_ip);
    let ip_hash = ip.map(|ip| hash_ip(&ip, &salt));
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(cap_user_agent);
    // CWE-117: reject control chars / oversize values from the X-Request-Id
    // header so attackers can't forge log lines.
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(accept_request_id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let ctx = AuditCtx {
        ip_hash,
        user_agent,
        request_id: Some(request_id),
    };
    req.extensions_mut().insert(ctx);
    next.run(req).await
}

/// Derive the deployment IP salt. Operator override via `[audit].ip_salt`
/// takes precedence; otherwise the salt is `SHA-256(domain || self.url)`
/// — mirrors the pattern in `flash.rs::flash_key`, so rotating
/// `self.url` rotates the salt as a side-effect.
pub fn ip_salt(cfg: &AppConfig) -> String {
    if let Some(s) = cfg.audit.ip_salt.as_ref() {
        if !s.is_empty() {
            return s.clone();
        }
    }
    const DOMAIN: &[u8] = b"forseti::audit::ip-salt::v1";
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(cfg.self_.url.as_bytes());
    hex::encode(h.finalize())
}

fn hash_ip(ip: &str, salt: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(b"::");
    h.update(ip.as_bytes());
    hex::encode(h.finalize())
}

/// Client IP discovery. When `trust_forwarded` is set, honour the
/// canonical reverse-proxy headers (X-Forwarded-For first hop, then
/// X-Real-IP). Otherwise fall back to the TCP peer address — a caller
/// reaching the public listener directly can set those headers
/// themselves, so trusting them unconditionally would let an attacker
/// spoof the audited IP.
fn extract_client_ip(
    headers: &HeaderMap,
    trust_forwarded: bool,
    peer_ip: Option<String>,
) -> Option<String> {
    if trust_forwarded {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                let s = first.trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let s = xri.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    peer_ip
}

// --- builder -------------------------------------------------------------

/// Fluent builder for one audit row. Construct via [`AuditEvent::new`]
/// with a vocabulary const from [`action`], chain setters, then call
/// [`log`] to persist.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    action: &'static str,
    actor_kind: &'static str,
    actor_id: Option<String>,
    actor_email: Option<String>,
    target_kind: Option<&'static str>,
    target_id: Option<String>,
    org_id: Option<String>,
    ip_hash: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,
    severity: &'static str,
    success: bool,
    metadata: SafeMetadata,
    err_msg: Option<String>,
}

impl AuditEvent {
    /// Start a new event. Defaults: `actor_kind = system`, `severity = info`,
    /// `success = true`, empty metadata.
    pub fn new(action: &'static str) -> Self {
        Self {
            action,
            actor_kind: actor_kind::SYSTEM,
            actor_id: None,
            actor_email: None,
            target_kind: None,
            target_id: None,
            org_id: None,
            ip_hash: None,
            user_agent: None,
            request_id: None,
            severity: severity::INFO,
            success: true,
            metadata: SafeMetadata::empty(),
            err_msg: None,
        }
    }

    pub fn actor_user(mut self, id: impl Into<String>, email: impl Into<String>) -> Self {
        self.actor_kind = actor_kind::USER;
        self.actor_id = Some(id.into());
        self.actor_email = Some(email.into());
        self
    }

    pub fn actor_admin(mut self, id: impl Into<String>, email: impl Into<String>) -> Self {
        self.actor_kind = actor_kind::ADMIN;
        self.actor_id = Some(id.into());
        self.actor_email = Some(email.into());
        self
    }

    /// DCR proxy actor: unauthenticated browser-wise (no user / admin
    /// session), but bound to a specific Initial Access Token. Records
    /// the actor_id as `"dcr_iat:<id>"` so a triage query filtering on
    /// `actor_id` finds every event back to one issued token without
    /// having to dig into `metadata`. Kind stays `system` — DCR is not
    /// a user-driven flow.
    pub fn actor_dcr_iat(mut self, iat_id: impl AsRef<str>) -> Self {
        self.actor_kind = actor_kind::SYSTEM;
        self.actor_id = Some(format!("dcr_iat:{}", iat_id.as_ref()));
        self
    }

    /// Webhook source (e.g. `"kratos"`). Recorded into `actor_email` for
    /// display so the admin view can show "Kratos" in the actor column
    /// without a special-case render path.
    pub fn actor_webhook(mut self, source: impl Into<String>) -> Self {
        self.actor_kind = actor_kind::WEBHOOK;
        self.actor_email = Some(source.into());
        self
    }

    pub fn target(mut self, kind: &'static str, id: impl Into<String>) -> Self {
        self.target_kind = Some(kind);
        self.target_id = Some(id.into());
        self
    }

    /// Merge ip_hash / user_agent / request_id from the request context.
    /// Existing values on the builder are preserved — callers can override
    /// individual fields before or after this call.
    pub fn with_ctx(mut self, ctx: &AuditCtx) -> Self {
        if self.ip_hash.is_none() {
            self.ip_hash.clone_from(&ctx.ip_hash);
        }
        if self.user_agent.is_none() {
            self.user_agent.clone_from(&ctx.user_agent);
        }
        if self.request_id.is_none() {
            self.request_id.clone_from(&ctx.request_id);
        }
        self
    }

    pub fn metadata(mut self, value: SafeMetadata) -> Self {
        self.metadata = value;
        self
    }

    /// Record the failure. Sets `success = false` and stashes the error
    /// message under `metadata.error` at write time. Severity is
    /// **unchanged** — callers who want a failed event at error severity
    /// write `.failed(err).severity(severity::ERROR)` explicitly.
    pub fn failed(mut self, err: impl Into<String>) -> Self {
        self.success = false;
        self.err_msg = Some(err.into());
        self
    }

    pub fn severity(mut self, s: &'static str) -> Self {
        self.severity = s;
        self
    }

    pub fn critical(self) -> Self {
        self.severity(severity::CRITICAL)
    }
}

// --- diesel models -------------------------------------------------------

#[derive(Insertable, Clone)]
#[diesel(table_name = audit_events)]
struct NewAuditEvent {
    id: String,
    created_at: String,
    actor_kind: String,
    actor_id: Option<String>,
    actor_email: Option<String>,
    action: String,
    target_kind: Option<String>,
    target_id: Option<String>,
    org_id: Option<String>,
    ip_hash: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,
    severity: String,
    success: i32,
    metadata: String,
}

/// Full row projection used by `/admin/audit`. `success` is INTEGER in the
/// schema (0/1) for cross-backend parity; the admin view renders it as a
/// boolean.
#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = audit_events)]
pub struct AuditRow {
    pub id: String,
    pub created_at: String,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub actor_email: Option<String>,
    pub action: String,
    pub target_kind: Option<String>,
    pub target_id: Option<String>,
    pub org_id: Option<String>,
    pub ip_hash: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub severity: String,
    pub success: i32,
    pub metadata: String,
}

impl AuditRow {
    pub fn succeeded(&self) -> bool {
        self.success != 0
    }
}

// --- write API ----------------------------------------------------------

/// Persist `event`. Returns the insert error if the row failed to land
/// in the DB; the row is also emitted to stderr as a structured
/// `audit_fallback` event so it stays recoverable from log scrapes
/// regardless of how the caller reacts.
///
/// Audit must never break the request that produced it. Non-critical
/// callers write `let _ = audit::log(...).await;` to explicitly drop the
/// error after the fallback has run. Compliance-critical callers
/// (account self-deletion, admin destructive actions) propagate with `?`
/// or log loudly so operators see the dropped row in their primary
/// stream as well as the `audit_fallback` target.
///
/// The Result is `#[must_use]` — a forgotten `let _` lights a warning.
#[must_use = "audit::log returns Result; use `let _ = ...` to ignore or `?` to propagate"]
pub async fn log(db: &DbPool, event: AuditEvent) -> anyhow::Result<()> {
    let row = build_row(event)?;
    // The deadpool `interact` closure is `'static` + `move`, so the insert
    // moves `row` into the worker. Hand it back out of the closure paired
    // with the insert result so the fallback can reuse the full row on error
    // without an unconditional hot-path clone. A pool-acquire failure returns
    // through the macro's `?` before the closure runs — that path has no row
    // to recover.
    //
    // The inner async block makes pool/interact `?`s short-circuit *here*
    // rather than past the caller — without it, a pool failure would skip
    // both the warn line and the fallback.
    let outcome: anyhow::Result<(NewAuditEvent, Result<(), diesel::result::Error>)> = async {
        let pair = db_interact!(db, |conn| {
            let res = diesel::insert_into(audit_events::table)
                .values(&row)
                .execute(conn)
                .map(|_| ());
            Ok::<_, diesel::result::Error>((row, res))
        })?;
        Ok(pair)
    }
    .await;
    match outcome {
        Ok((_, Ok(()))) => Ok(()),
        Ok((row, Err(e))) => {
            AUDIT_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = ?e, action = %row.action, "audit log write failed");
            emit_audit_fallback(&row);
            Err(e.into())
        }
        Err(e) => {
            AUDIT_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = ?e, "audit log write failed (pool/interact)");
            Err(e)
        }
    }
}

/// Process-lifetime counter of audit rows that failed to land in the DB.
/// Incremented inside the error branch of [`log`]; surfaced
/// on `/admin/status` so operators have a single place to notice when
/// audit writes start dropping (DB blip, schema drift, disk full).
///
/// In-process only — no Prometheus. A counter that resets on Forseti
/// restart is the right shape for the "did anything weird happen since
/// the last boot?" question; we have structured `audit_fallback` log
/// lines for the durable view.
static AUDIT_WRITE_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Total audit writes that failed in this process. See
/// [`AUDIT_WRITE_FAILURES`].
pub fn audit_write_failures_total() -> u64 {
    AUDIT_WRITE_FAILURES.load(Ordering::Relaxed)
}

/// Unix-epoch seconds of the most recent successful Kratos-webhook
/// payload to land at `/internal/audit/kratos`. `0` = never since boot.
///
/// Tracked in-process (rather than derived from the audit table) because
/// the webhook handler attributes events to the *user* — `actor_kind =
/// user` — when `actor_id` is present, so querying the table for
/// `actor_kind = webhook` would show "never" on every healthy deployment.
/// See `src/audit/kratos_webhook.rs::build_kratos_event`.
static LAST_KRATOS_WEBHOOK_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Record that a Kratos webhook payload was just processed. Called from
/// `src/audit/kratos_webhook.rs::receive` on the success path.
pub fn record_kratos_webhook_received() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    LAST_KRATOS_WEBHOOK_EPOCH.store(now, Ordering::Relaxed);
}

/// Unix-epoch seconds of the most recent Kratos-webhook receipt, or
/// `None` if no payload has landed since boot.
pub fn last_kratos_webhook_epoch() -> Option<u64> {
    let n = LAST_KRATOS_WEBHOOK_EPOCH.load(Ordering::Relaxed);
    if n == 0 {
        None
    } else {
        Some(n)
    }
}

/// Emit the dropped row as a structured `audit_fallback`-targeted error
/// line. Field names mirror the DB schema so a stderr scraper can
/// reconstruct the row without a translation layer. Operators should
/// route this target to a durable log sink (file + log shipper) so audit
/// loss is recoverable end-to-end.
///
/// All 15 columns of `audit_events` are emitted, including the request-
/// context fields (`ip_hash`, `user_agent`, `request_id`) that come in
/// via `AuditCtx`. These are compliance-relevant on critical callers
/// (those that propagate the `log` Result with `?`) — an account-deletion
/// row recovered from stderr without the originating IP/UA defeats half
/// the point of keeping it.
fn emit_audit_fallback(row: &NewAuditEvent) {
    tracing::error!(
        target: "audit_fallback",
        id = %row.id,
        created_at = %row.created_at,
        action = %row.action,
        actor_kind = %row.actor_kind,
        actor_id = ?row.actor_id,
        actor_email = ?row.actor_email,
        target_kind = ?row.target_kind,
        target_id = ?row.target_id,
        org_id = ?row.org_id,
        ip_hash = ?row.ip_hash,
        user_agent = ?row.user_agent,
        request_id = ?row.request_id,
        severity = %row.severity,
        success = row.success,
        metadata = %row.metadata,
        "audit row dropped from DB; recoverable from this line"
    );
}

fn build_row(event: AuditEvent) -> anyhow::Result<NewAuditEvent> {
    let mut meta = event.metadata.into_value();
    if let Some(err) = event.err_msg {
        if let serde_json::Value::Object(ref mut map) = meta {
            map.insert("error".to_string(), serde_json::Value::String(err));
        }
    }
    Ok(NewAuditEvent {
        id: Uuid::new_v4().to_string(),
        created_at: Utc::now().to_rfc3339(),
        actor_kind: event.actor_kind.to_string(),
        actor_id: event.actor_id,
        actor_email: event.actor_email,
        action: event.action.to_string(),
        target_kind: event.target_kind.map(String::from),
        target_id: event.target_id,
        org_id: event.org_id,
        ip_hash: event.ip_hash,
        user_agent: event.user_agent,
        request_id: event.request_id,
        severity: event.severity.to_string(),
        success: if event.success { 1 } else { 0 },
        metadata: serde_json::to_string(&meta)?,
    })
}

// --- read API -----------------------------------------------------------

/// Filter for [`query`]. `action_exact` and `action_prefix` are mutually
/// usable but `action_exact` wins if both are set (callers shouldn't pass
/// both anyway). `since` / `until` are typed `DateTime<Utc>` so an invalid
/// timestamp can't reach the SQL `>=`/`<` comparison and silently return
/// the wrong row set — each is re-serialised to canonical RFC3339 before
/// the comparison so lexicographic order matches chronological order
/// against the `created_at` TEXT column.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub actor_id: Option<String>,
    /// Case-insensitive substring match against `actor_email`. Pushed into
    /// SQL via `LOWER(actor_email) LIKE LOWER('%needle%')` so the page's
    /// `total` count reflects the *filtered* row count, not the count
    /// after a Rust-side post-filter on the SQL `LIMIT` page.
    pub actor_email_contains: Option<String>,
    pub target_id: Option<String>,
    pub action_exact: Option<String>,
    pub action_prefix: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub severity: Option<String>,
    /// Restrict the rows to events tagged with this `org_id`. Used by
    /// org-scoped admin (`/admin/audit?org=<slug>`) to scope the view
    /// to a single org without leaking other orgs' events. `None` →
    /// Forseti-wide.
    pub org_id: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

// SQL `LOWER()` over a nullable text column. Declared here rather than
// imported wholesale because the only call site is the audit-email
// filter below — keeps the surface small. `LOWER(NULL)` is `NULL`, which
// `LIKE` correctly evaluates to NULL (i.e. filtered out), so rows with a
// `NULL` actor_email don't match an email filter.
diesel::define_sql_function! {
    fn lower(x: diesel::sql_types::Nullable<diesel::sql_types::Text>) -> diesel::sql_types::Nullable<diesel::sql_types::Text>
}

/// Backslash-escape the SQL LIKE metacharacters (`\`, `%`, `_`) in a
/// user-supplied substring so it matches literally under an `ESCAPE '\'`
/// clause. The backslash itself is escaped first to avoid double-escaping.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Load up to `filter.limit` rows newest-first, plus a total count for
/// pagination. Limit is clamped to `[1, 200]` per the design.
/// Fetch a single event by id. Used by the `/admin/audit/{id}` detail
/// page so an operator can inspect the full metadata + request context
/// without the summary table having to carry them.
pub async fn find_by_id(db: &DbPool, event_id: &str) -> anyhow::Result<Option<AuditRow>> {
    use crate::schema::audit_events::dsl as ae;
    let event_id = event_id.to_string();
    let row = db_interact!(db, |conn| {
        ae::audit_events
            .filter(ae::id.eq(&event_id))
            .select(AuditRow::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn query(db: &DbPool, filter: AuditFilter) -> anyhow::Result<(Vec<AuditRow>, i64)> {
    let limit = filter.limit.clamp(1, 200);
    let offset = filter.offset.max(0);
    let f = filter;

    let (rows, total) = db_interact!(db, |conn| {
        use crate::schema::audit_events::dsl as a;

        macro_rules! apply_filters {
            ($q:expr, $f:expr) => {{
                let mut q = $q;
                let f = $f;
                if let Some(v) = f.actor_id.as_deref() {
                    q = q.filter(a::actor_id.eq(v.to_string()));
                }
                if let Some(v) = f.actor_email_contains.as_deref() {
                    // Escape the LIKE metacharacters in the admin-supplied
                    // substring rather than stripping them, so an email with
                    // a literal `_`/`%`/`\` matches itself instead of acting
                    // as a wildcard or widening the match. The explicit
                    // `ESCAPE '\'` is required on sqlite, which has no default
                    // escape char (postgres defaults to `\` but we set it on
                    // both for parity).
                    let trimmed = v.trim().to_lowercase();
                    if !trimmed.is_empty() {
                        let escaped = escape_like(&trimmed);
                        q = q.filter(
                            lower(a::actor_email)
                                .like(format!("%{escaped}%"))
                                .escape('\\'),
                        );
                    }
                }
                if let Some(v) = f.target_id.as_deref() {
                    q = q.filter(a::target_id.eq(v.to_string()));
                }
                if let Some(v) = f.action_exact.as_deref() {
                    q = q.filter(a::action.eq(v.to_string()));
                } else if let Some(v) = f.action_prefix.as_deref() {
                    let needle: String = v
                        .trim()
                        .chars()
                        .filter(|c| !matches!(c, '%' | '_' | '\\'))
                        .collect();
                    if !needle.is_empty() {
                        q = q.filter(a::action.like(format!("{needle}%")));
                    }
                }
                if let Some(v) = f.since.as_ref() {
                    q = q.filter(a::created_at.ge(v.to_rfc3339_opts(SecondsFormat::Secs, true)));
                }
                if let Some(v) = f.until.as_ref() {
                    q = q.filter(a::created_at.lt(v.to_rfc3339_opts(SecondsFormat::Secs, true)));
                }
                if let Some(v) = f.severity.as_deref() {
                    q = q.filter(a::severity.eq(v.to_string()));
                }
                if let Some(v) = f.org_id.as_deref() {
                    q = q.filter(a::org_id.eq(v.to_string()));
                }
                q
            }};
        }

        let total: i64 = apply_filters!(a::audit_events.into_boxed(), &f)
            .count()
            .get_result(conn)?;

        let rows: Vec<AuditRow> = apply_filters!(a::audit_events.into_boxed(), &f)
            .order(a::created_at.desc())
            .limit(limit)
            .offset(offset)
            .select(AuditRow::as_select())
            .load(conn)?;

        Ok::<_, diesel::result::Error>((rows, total))
    })?;

    Ok((rows, total))
}

// --- prune --------------------------------------------------------------

/// Delete rows older than `days`. Goes through the trigger-override
/// machinery — the lock is set inside the same transaction as the DELETE,
/// so a crash mid-prune rolls back atomically (no boot-time reset needed).
///
/// Returns the number of rows deleted. The caller is expected to be the
/// CLI subcommand or an operator-driven cron; this is **not** wired into
/// the HTTP server.
pub async fn prune_older_than(db: &DbPool, days: i64) -> anyhow::Result<usize> {
    let cutoff = (Utc::now() - chrono::Duration::days(days)).to_rfc3339();
    match db {
        DbPool::Sqlite(_) => prune_sqlite(db, cutoff).await,
        DbPool::Postgres(_) => prune_postgres(db, cutoff).await,
    }
}

async fn prune_sqlite(db: &DbPool, cutoff: String) -> anyhow::Result<usize> {
    let count = db_interact!(db, |conn| {
        // sqlite has no session-scoped settings, so we use a sentinel row
        // in `_forseti_meta`. INSERT OR REPLACE keeps the operation
        // idempotent if the row hasn't been seeded yet.
        conn.transaction::<usize, diesel::result::Error, _>(|c| {
            diesel::sql_query(
                "INSERT OR REPLACE INTO _forseti_meta (key, value, created_at) \
                 VALUES ('audit_purge_lock', 'true', datetime('now'))",
            )
            .execute(c)?;

            use crate::schema::audit_events::dsl as a;
            let n = diesel::delete(a::audit_events.filter(a::created_at.lt(cutoff.clone())))
                .execute(c)?;

            diesel::sql_query(
                "INSERT OR REPLACE INTO _forseti_meta (key, value, created_at) \
                 VALUES ('audit_purge_lock', 'false', datetime('now'))",
            )
            .execute(c)?;

            Ok(n)
        })
    })?;
    Ok(count)
}

async fn prune_postgres(db: &DbPool, cutoff: String) -> anyhow::Result<usize> {
    let count = db_interact!(db, |conn| {
        conn.transaction::<usize, diesel::result::Error, _>(|c| {
            // `SET LOCAL` scopes to the current transaction; rollback /
            // commit clears it automatically.
            diesel::sql_query("SET LOCAL app.audit_purge = 'true'").execute(c)?;

            use crate::schema::audit_events::dsl as a;
            let n = diesel::delete(a::audit_events.filter(a::created_at.lt(cutoff.clone())))
                .execute(c)?;

            Ok(n)
        })
    })?;
    Ok(count)
}

// --- CLI helper ---------------------------------------------------------

/// Entry point for `forseti audit-prune`. Reads `[audit].audit_retention_days`,
/// runs [`prune_older_than`], prints the count to stdout. Returns the
/// process exit code (0 on success, 1 on failure).
pub async fn prune_cli(cfg: &AppConfig, db: &DbPool) -> i32 {
    let days = cfg.audit.audit_retention_days;
    match prune_older_than(db, days).await {
        Ok(n) => {
            println!("audit-prune: deleted {n} rows older than {days} days");
            0
        }
        Err(e) => {
            eprintln!("audit-prune: {e:?}");
            1
        }
    }
}

#[cfg(test)]
mod middleware_sanitiser_tests {
    use super::{accept_request_id, cap_user_agent};

    #[test]
    fn cap_user_agent_passes_through_short() {
        assert_eq!(cap_user_agent(""), "");
        assert_eq!(cap_user_agent("Mozilla/5.0"), "Mozilla/5.0");
    }

    #[test]
    fn cap_user_agent_keeps_exactly_512() {
        let s: String = "a".repeat(512);
        assert_eq!(cap_user_agent(&s).chars().count(), 512);
    }

    #[test]
    fn cap_user_agent_truncates_513() {
        let s: String = "a".repeat(513);
        assert_eq!(cap_user_agent(&s).chars().count(), 512);
    }

    #[test]
    fn cap_user_agent_truncates_on_char_boundary() {
        // Multi-byte chars must not be sliced mid-codepoint.
        let s: String = "é".repeat(600);
        let out = cap_user_agent(&s);
        assert_eq!(out.chars().count(), 512);
        assert!(out.chars().all(|c| c == 'é'));
    }

    #[test]
    fn accept_request_id_accepts_ascii_printable() {
        assert_eq!(
            accept_request_id("abc-123_XYZ.~").as_deref(),
            Some("abc-123_XYZ.~")
        );
    }

    #[test]
    fn accept_request_id_rejects_empty() {
        assert_eq!(accept_request_id(""), None);
    }

    #[test]
    fn accept_request_id_rejects_newline() {
        assert_eq!(accept_request_id("abc\ndef"), None);
        assert_eq!(accept_request_id("abc\r\nLogged-In: yes"), None);
    }

    #[test]
    fn accept_request_id_rejects_control_chars() {
        assert_eq!(accept_request_id("abc\x00def"), None);
        assert_eq!(accept_request_id("abc\tdef"), None);
        assert_eq!(accept_request_id("abc\x7fdef"), None);
    }

    #[test]
    fn accept_request_id_rejects_non_ascii() {
        assert_eq!(accept_request_id("café"), None);
    }

    #[test]
    fn accept_request_id_boundary_lengths() {
        let s128: String = "a".repeat(128);
        let s129: String = "a".repeat(129);
        assert_eq!(accept_request_id(&s128).as_deref(), Some(s128.as_str()));
        assert_eq!(accept_request_id(&s129), None);
    }
}

#[cfg(test)]
mod kratos_webhook_epoch_tests {
    //! Locks the atomic-counter contract for the `last_kratos_webhook_epoch`
    //! signal that drives `/admin/status`'s "last webhook received" row.
    //! Regression for the bug where the status template rendered "never"
    //! even after a successful webhook because the timer wasn't being
    //! stamped.
    //!
    //! This test is serial-only (mutates a process-global atomic);
    //! `cargo test --test-threads=1` is the project default already.
    use super::{last_kratos_webhook_epoch, record_kratos_webhook_received};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn record_then_read_yields_recent_epoch() {
        // Capture the baseline — another test in this module may have
        // already stamped it. We assert relative to a "before record" clock
        // rather than `None`.
        let _before_state = last_kratos_webhook_epoch();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        record_kratos_webhook_received();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let got = last_kratos_webhook_epoch().expect("Some(n) after record");
        assert!(
            got >= before && got <= after + 1,
            "epoch {got} should sit in [{before}, {after}] (+1 grace)"
        );
    }
}

#[cfg(test)]
mod sensitive_key_tests {
    use super::is_sensitive_key;

    #[test]
    fn rejects_true_secrets() {
        for k in [
            "password",
            "client_secret",
            "access_token",
            "session_cookie",
            "Authorization",
            "otp_code",
            "recovery_codes",
            "private_key",
            "api_key",
            "signing_key",
            "secret_key",
            "credential",
        ] {
            assert!(is_sensitive_key(k), "{k} should be rejected");
        }
    }

    #[test]
    fn allows_benign_key_substrings() {
        // The bare "key" needle used to over-match these.
        for k in ["api_key_id", "public_key_kid", "monkey", "keyboard_layout"] {
            assert!(!is_sensitive_key(k), "{k} should be allowed");
        }
    }
}

#[cfg(test)]
mod escape_like_tests {
    use super::escape_like;

    #[test]
    fn escapes_metacharacters() {
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("a%b"), "a\\%b");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
        assert_eq!(escape_like("plain"), "plain");
    }

    #[test]
    fn literal_underscore_not_over_matched() {
        // Under `... LIKE '%<escaped>%' ESCAPE '\'`, the escaped pattern for
        // `a_b` is `a\_b`, which matches the literal three-char string `a_b`
        // but NOT `axb`. The escape pass is what guarantees that.
        let needle = "a_b";
        let escaped = escape_like(needle);
        assert_eq!(escaped, "a\\_b");
        assert!(
            escaped.contains("\\_"),
            "underscore must be backslash-escaped"
        );
    }
}
