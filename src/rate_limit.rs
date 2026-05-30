//! Shared per-IP rate-limit helper.
//!
//! Wraps `tower_governor::GovernorLayer` so callers don't have to
//! re-do the burst-size + refill-period arithmetic on each call. The
//! error handler is caller-supplied so JSON endpoints (RFC 7591 DCR)
//! and HTML endpoints (`/claim-email`) can render limit-exceeded
//! responses in their own shapes.

use std::sync::Arc;

use axum::response::Response;
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor};
use tower_governor::GovernorLayer;

use crate::state::AppState;

/// Mount one `tower_governor` bucket onto `r`. Generic over the key
/// extractor so callers pick the trust model (`PeerIpKeyExtractor` for
/// strict mode, `SmartIpKeyExtractor` when an upstream proxy is
/// trusted). `total_ms` is the rolling window in milliseconds;
/// `per_window` is the burst size — the cap on requests per window.
/// `per_window == 0` disables the bucket and returns `r` unmodified.
pub(crate) fn apply<K, F>(
    r: Router<AppState>,
    extractor: K,
    total_ms: u64,
    per_window: u32,
    error_handler: F,
) -> Router<AppState>
where
    K: tower_governor::key_extractor::KeyExtractor + Send + Sync + 'static,
    <K as tower_governor::key_extractor::KeyExtractor>::Key: Send + Sync,
    F: Fn(tower_governor::GovernorError) -> Response + Send + Sync + 'static,
{
    if per_window == 0 {
        return r;
    }
    let per_ms = (total_ms / per_window as u64).max(1);
    let Some(cfg) = GovernorConfigBuilder::default()
        .per_millisecond(per_ms)
        .burst_size(per_window)
        .key_extractor(extractor)
        .finish()
    else {
        return r;
    };
    r.layer(GovernorLayer::new(Arc::new(cfg)).error_handler(error_handler))
}

/// Attach paired per-minute + per-hour buckets to `r`, picking the key
/// extractor from the deployment-shape `trust_xff` flag
/// (`cfg.proxy.trust_forwarded_for`). Collapses the
/// `if trust { Smart } else { Peer }` × two-windows ladder that every
/// rate-limited entry point used to duplicate.
pub(crate) fn dual_window<F>(
    r: Router<AppState>,
    trust_xff: bool,
    per_minute: u32,
    per_hour: u32,
    error_handler: F,
) -> Router<AppState>
where
    F: Fn(tower_governor::GovernorError) -> Response + Copy + Send + Sync + 'static,
{
    if trust_xff {
        let r = apply(r, SmartIpKeyExtractor, 60_000, per_minute, error_handler);
        apply(r, SmartIpKeyExtractor, 3_600_000, per_hour, error_handler)
    } else {
        let r = apply(r, PeerIpKeyExtractor, 60_000, per_minute, error_handler);
        apply(r, PeerIpKeyExtractor, 3_600_000, per_hour, error_handler)
    }
}
