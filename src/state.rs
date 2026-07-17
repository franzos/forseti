//! Shared application state passed to every handler via `State<AppState>`.
//! Intentionally tiny: heavy state lives in `AppConfig` / `OryClients`, both cheap to `Clone`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::response::Response;
use tokio::sync::Mutex;

use crate::commercial::LicenseHandle;
use crate::config::{AppConfig, Redacted};
use crate::db::DbPool;
use crate::logo_cache::LogoCache;
use crate::ory::discovery::OidcDiscovery;
use crate::ory::OryClients;
use crate::webhook::{SigningKey, WorkerHandle};

/// TTL for the cached Hydra discovery doc.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
/// Backoff between refresh attempts while Hydra is down and a stale doc is served.
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct CachedDiscovery {
    next_refresh_at: Instant,
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
    /// Heartbeat for the background webhook worker; `/readyz` reports degraded (still 200) when it hasn't ticked recently.
    pub webhook_worker: WorkerHandle,
    /// Ed25519 signing key for outbound Security Event Tokens; public half served at `/.well-known/webhook-jwks.json`.
    pub signing_key: SigningKey,
    /// Commercial-tier license state. Lock-free; swapped on activation at `/admin/license`.
    pub license: LicenseHandle,
    /// Master secret for the signed-cookie codec ([`crate::signed_cookie`]); ephemeral per-boot key when unset.
    pub cookie_secret: Arc<[u8]>,
    /// Cached Hydra OIDC discovery doc; lazily fetched, falls back to config-derived paths on error.
    pub discovery: DiscoveryCache,
    /// Bounded in-process cache of served org logo blobs; see [`crate::logo_cache`].
    pub logo_cache: Arc<Mutex<LogoCache>>,
    /// Prometheus render handle backing `/metrics`; see [`crate::metrics`].
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    /// Bearer token a scraper must present at `/metrics`. `None` = endpoint disabled (404).
    pub metrics_scrape_token: Option<Redacted>,
}

impl AppState {
    /// Return the cached discovery doc + an `ok` flag, refreshing if stale. A cold fetch failure returns an
    /// EMPTY doc (not a `public_url` guess) so the template's `is_empty()` guards hide endpoints rather than
    /// show a wrong issuer. The lock is released before the network fetch; a cold-boot double-fetch is idempotent.
    pub async fn openid_configuration(&self) -> (OidcDiscovery, bool) {
        {
            let guard = self.discovery.0.lock().await;
            if let Some(c) = guard.as_ref() {
                if Instant::now() < c.next_refresh_at {
                    return (c.doc.clone(), true);
                }
            }
        }
        match crate::ory::discovery::fetch(&self.ory, &self.cfg.hydra.public_url).await {
            Ok(doc) => {
                let mut guard = self.discovery.0.lock().await;
                *guard = Some(CachedDiscovery {
                    next_refresh_at: Instant::now() + DISCOVERY_TTL,
                    doc: doc.clone(),
                });
                (doc, true)
            }
            Err(e) => {
                tracing::warn!(error = ?e, "hydra discovery fetch failed");
                // Serve a stale value if we have one; otherwise an empty doc.
                let mut guard = self.discovery.0.lock().await;
                match guard.as_mut() {
                    // Stale but valid (issuer/endpoints are stable); serve it without warning,
                    // and push the next refresh out so a Hydra outage doesn't turn every
                    // request into a failing network fetch.
                    Some(c) => {
                        c.next_refresh_at = Instant::now() + DISCOVERY_RETRY;
                        (c.doc.clone(), true)
                    }
                    None => (OidcDiscovery::default(), false),
                }
            }
        }
    }

    /// Read and clear the path-scoped flash cookie, deriving secret/ttl/secure from state.
    /// Returns `(msg, clear_cookie_header)` (empty msg when absent/invalid).
    pub fn take_flash(&self, headers: &HeaderMap, path: &str) -> (String, Option<String>) {
        crate::flash::take_flash(
            headers,
            &self.cookie_secret,
            self.cfg.flash.cookie_ttl_seconds,
            path,
            self.cfg.self_.is_https(),
        )
    }

    /// Build the `Set-Cookie` header value staging `msg` for the next render at `path`.
    pub fn store_flash(&self, path: &str, msg: &str) -> String {
        crate::flash::store_flash(
            &self.cookie_secret,
            self.cfg.flash.cookie_ttl_seconds,
            path,
            msg,
            self.cfg.self_.is_https(),
        )
    }

    /// Stage `msg` for `target` then 303-redirect there carrying the flash cookie.
    pub fn flash_redirect(&self, target: &str, msg: &str) -> Response {
        let cookie = self.store_flash(target, msg);
        crate::flash::redirect_with_cookie(target, &cookie)
    }
}
