//! Shared application state passed to every handler via `State<AppState>`.
//! Intentionally tiny: heavy state lives in `AppConfig` / `OryClients`, both cheap to `Clone`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::response::Response;
use tokio::sync::Mutex;

use crate::commercial::LicenseHandle;
use crate::config::AppConfig;
use crate::db::DbPool;
use crate::logo_cache::LogoCache;
use crate::ory::OryClients;
use crate::ory::discovery::OidcDiscovery;
use crate::webhook::{SigningKey, WorkerHandle};

/// TTL for the cached Hydra discovery doc.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
/// Backoff between refresh attempts while Hydra is down and a stale doc is served.
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct CachedDiscovery {
    next_refresh_at: Instant,
    doc: OidcDiscovery,
    /// Full document as Hydra served it; the CIMD discovery augmentation
    /// works on this rather than the typed admin-UI subset.
    raw: Arc<serde_json::Value>,
}

/// Lazily-populated, TTL'd cache of Hydra's OIDC discovery doc. Shared
/// across handlers; one fetch amortised over `DISCOVERY_TTL`.
#[derive(Clone, Default)]
pub struct DiscoveryCache(Arc<Mutex<Option<CachedDiscovery>>>);

#[derive(Clone)]
struct CachedProviders {
    next_refresh_at: Instant,
    ids: Arc<[String]>,
}

/// TTL'd cache of the upstream provider ids Kratos offers, probed on the
/// same schedule as [`DiscoveryCache`].
#[derive(Clone, Default)]
pub struct ProviderCache(Arc<Mutex<Option<CachedProviders>>>);

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
    /// Salt for audit IP pseudonymization, derived once at boot from `[audit].ip_salt` or the cookie secret.
    pub ip_salt: Arc<str>,
    /// Cached Hydra OIDC discovery doc; lazily fetched, falls back to config-derived paths on error.
    pub discovery: DiscoveryCache,
    /// Cached upstream provider ids offered by Kratos; see [`AppState::idp_provider_ids`].
    pub idp_providers: ProviderCache,
    /// Bounded in-process cache of served org logo blobs; see [`crate::logo_cache`].
    pub logo_cache: Arc<Mutex<LogoCache>>,
    /// Prometheus render handle backing `/metrics`; see [`crate::metrics`].
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
}

impl AppState {
    /// Return the cached discovery doc + an `ok` flag, refreshing if stale. A cold fetch failure returns an
    /// EMPTY doc (not a `public_url` guess) so the template's `is_empty()` guards hide endpoints rather than
    /// show a wrong issuer.
    pub async fn openid_configuration(&self) -> (OidcDiscovery, bool) {
        match self.cached_discovery().await {
            Some(c) => (c.doc, true),
            None => (OidcDiscovery::default(), false),
        }
    }

    /// The cached discovery doc exactly as Hydra served it, for consumers that
    /// need fields beyond the [`OidcDiscovery`] subset. `None` only on a cold
    /// cache with Hydra unreachable.
    pub async fn openid_configuration_raw(&self) -> Option<Arc<serde_json::Value>> {
        self.cached_discovery().await.map(|c| c.raw)
    }

    /// Shared cache/refresh policy: serve fresh, refresh when stale, serve stale with a retry
    /// backoff while Hydra is down. The lock is released before the network fetch; a cold-boot
    /// double-fetch is idempotent.
    async fn cached_discovery(&self) -> Option<CachedDiscovery> {
        {
            let guard = self.discovery.0.lock().await;
            if let Some(c) = guard.as_ref()
                && Instant::now() < c.next_refresh_at
            {
                return Some(c.clone());
            }
        }
        match crate::ory::discovery::fetch(&self.ory, &self.cfg.hydra.public_url).await {
            Ok((doc, raw)) => {
                let cached = CachedDiscovery {
                    next_refresh_at: Instant::now() + DISCOVERY_TTL,
                    doc,
                    raw: Arc::new(raw),
                };
                let mut guard = self.discovery.0.lock().await;
                *guard = Some(cached.clone());
                Some(cached)
            }
            Err(e) => {
                tracing::warn!(error = ?e, "hydra discovery fetch failed");
                // Serve a stale value if we have one; otherwise nothing.
                let mut guard = self.discovery.0.lock().await;
                match guard.as_mut() {
                    // Stale but valid (issuer/endpoints are stable); serve it without warning,
                    // and push the next refresh out so a Hydra outage doesn't turn every
                    // request into a failing network fetch.
                    Some(c) => {
                        c.next_refresh_at = Instant::now() + DISCOVERY_RETRY;
                        Some(c.clone())
                    }
                    None => None,
                }
            }
        }
    }

    /// Upstream provider ids Kratos offers, refreshing if stale. One caller
    /// probes while the others get the stale list; the last good list is kept
    /// while Kratos is down, and a cold failure gives an empty one, both
    /// retried after `DISCOVERY_RETRY`.
    pub async fn idp_provider_ids(&self) -> Arc<[String]> {
        {
            let mut guard = self.idp_providers.0.lock().await;
            if let Some(c) = guard.as_mut() {
                if Instant::now() < c.next_refresh_at {
                    return c.ids.clone();
                }
                // Claim the refresh: concurrent callers get the stale list
                // instead of each waiting on their own probe.
                c.next_refresh_at = Instant::now() + DISCOVERY_RETRY;
            }
        }
        let fetched = crate::ory::kratos::probe_oidc_provider_ids(&self.ory).await;
        let mut guard = self.idp_providers.0.lock().await;
        match fetched {
            Ok(ids) => {
                let ids: Arc<[String]> = ids.into();
                *guard = Some(CachedProviders {
                    next_refresh_at: Instant::now() + DISCOVERY_TTL,
                    ids: ids.clone(),
                });
                ids
            }
            Err(e) => {
                tracing::warn!(error = ?e, "kratos provider probe failed");
                let cached = guard.get_or_insert_with(|| CachedProviders {
                    next_refresh_at: Instant::now(),
                    ids: Arc::from(Vec::new()),
                });
                cached.next_refresh_at = Instant::now() + DISCOVERY_RETRY;
                cached.ids.clone()
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
