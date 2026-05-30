//! Shared application state.
//!
//! Lifted out of `main.rs` so sub-modules (notably `admin`) can use the
//! same type for their `Router<AppState>` without re-declaring or routing
//! around a private definition. The struct itself is intentionally tiny —
//! anything heavy goes inside `AppConfig` or `OryClients`, which both
//! cheaply `Clone` through `Arc` / inner `reqwest::Client` handles.

use std::sync::Arc;

use crate::commercial::LicenseHandle;
use crate::config::AppConfig;
use crate::db::DbPool;
use crate::ory::OryClients;
use crate::webhook::{SigningKey, WorkerHandle};

/// Shared application state passed to every handler via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub ory: Arc<OryClients>,
    pub db: DbPool,
    /// Heartbeat for the background webhook worker. `/readyz` returns 503
    /// when the worker hasn't ticked recently — surfaces silent panics or
    /// runtime starvation before they manifest as undelivered webhooks.
    pub webhook_worker: WorkerHandle,
    /// RSA signing key for outbound Security Event Tokens (account
    /// lifecycle webhooks). Public half is served as JWKS at
    /// `/.well-known/webhook-jwks.json`.
    pub signing_key: SigningKey,
    /// Commercial-tier license state. Lock-free; swapped on activation
    /// at `/admin/license`. `Unlicensed` for OSS deployments.
    pub license: LicenseHandle,
    /// Master secret feeding the signed-cookie codec
    /// ([`crate::signed_cookie`]). Resolved once at startup from
    /// `[security].cookie_secret`; falls back to a per-boot ephemeral
    /// 32-byte key when unset.
    pub cookie_secret: Arc<[u8]>,
}
