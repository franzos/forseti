//! Shared application state.
//!
//! Lifted out of `main.rs` so sub-modules (notably `admin`) can use the
//! same type for their `Router<AppState>` without re-declaring or routing
//! around a private definition. The struct itself is intentionally tiny —
//! anything heavy goes inside `AppConfig` or `OryClients`, which both
//! cheaply `Clone` through `Arc` / inner `reqwest::Client` handles.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::commercial::LicenseHandle;
use crate::config::AppConfig;
use crate::db::DbPool;
use crate::ory::discovery::OidcDiscovery;
use crate::ory::OryClients;
use crate::webhook::{SigningKey, WorkerHandle};

/// TTL for the cached Hydra discovery doc.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
struct CachedDiscovery {
    fetched_at: Instant,
    doc: OidcDiscovery,
}

/// Lazily-populated, TTL'd cache of Hydra's OIDC discovery doc. Shared
/// across handlers; one fetch amortised over `DISCOVERY_TTL`.
#[derive(Clone, Default)]
pub struct DiscoveryCache(Arc<Mutex<Option<CachedDiscovery>>>);

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
    /// Cached Hydra OIDC discovery doc (issuer + endpoints) for the admin
    /// client detail page. Lazily fetched; falls back to config-derived
    /// paths on error.
    pub discovery: DiscoveryCache,
}

impl AppState {
    /// Return the cached discovery doc + an `ok` flag, refreshing if stale.
    /// Returns `(doc, true)` on a fresh/cached hit. On a cold fetch failure
    /// (no prior cache) returns `(OidcDiscovery::default(), false)` — an
    /// EMPTY doc, NOT a guess derived from `public_url`. The card's per-row
    /// `{% if !conn.x.is_empty() %}` guards then hide every endpoint, so we
    /// never show a wrong issuer; the operator sees only a "couldn't reach
    /// Hydra" note plus the non-endpoint client values.
    ///
    /// The lock is released before the network fetch (never held across the
    /// await) — a cold-boot burst may double-fetch, which is idempotent and
    /// cheaper than serialising every admin behind one mutex for the fetch.
    pub async fn openid_configuration(&self) -> (OidcDiscovery, bool) {
        {
            let guard = self.discovery.0.lock().await;
            if let Some(c) = guard.as_ref() {
                if c.fetched_at.elapsed() < DISCOVERY_TTL {
                    return (c.doc.clone(), true);
                }
            }
        }
        match crate::ory::discovery::fetch(&self.ory, &self.cfg.hydra.public_url).await {
            Ok(doc) => {
                let mut guard = self.discovery.0.lock().await;
                *guard = Some(CachedDiscovery {
                    fetched_at: Instant::now(),
                    doc: doc.clone(),
                });
                (doc, true)
            }
            Err(e) => {
                tracing::warn!(error = ?e, "hydra discovery fetch failed");
                // Serve a stale value if we have one; otherwise an empty doc.
                let guard = self.discovery.0.lock().await;
                match guard.as_ref() {
                    // Stale but valid (only ever cached from a successful fetch);
                    // serve it without warning — issuer/endpoints are stable.
                    Some(c) => (c.doc.clone(), true),
                    None => (OidcDiscovery::default(), false),
                }
            }
        }
    }
}
