//! Shared application state passed to every handler via `State<AppState>`.
//! Intentionally tiny: heavy state lives in `AppConfig` / `OryClients`, both cheap to `Clone`.

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
    /// Heartbeat for the background webhook worker; `/readyz` returns 503 when it hasn't ticked recently.
    pub webhook_worker: WorkerHandle,
    /// RSA signing key for outbound Security Event Tokens; public half served at `/.well-known/webhook-jwks.json`.
    pub signing_key: SigningKey,
    /// Commercial-tier license state. Lock-free; swapped on activation at `/admin/license`.
    pub license: LicenseHandle,
    /// Master secret for the signed-cookie codec ([`crate::signed_cookie`]); ephemeral per-boot key when unset.
    pub cookie_secret: Arc<[u8]>,
    /// Cached Hydra OIDC discovery doc; lazily fetched, falls back to config-derived paths on error.
    pub discovery: DiscoveryCache,
}

impl AppState {
    /// Return the cached discovery doc + an `ok` flag, refreshing if stale. A cold fetch failure returns an
    /// EMPTY doc (not a `public_url` guess) so the template's `is_empty()` guards hide endpoints rather than
    /// show a wrong issuer. The lock is released before the network fetch; a cold-boot double-fetch is idempotent.
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
                    // Stale but valid (issuer/endpoints are stable); serve it without warning.
                    Some(c) => (c.doc.clone(), true),
                    None => (OidcDiscovery::default(), false),
                }
            }
        }
    }
}
