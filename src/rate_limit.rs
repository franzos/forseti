//! Shared per-IP rate-limit helper wrapping `tower_governor::GovernorLayer`. The error handler is
//! caller-supplied so JSON (RFC 7591 DCR) and HTML (`/claim-email`) endpoints render their own shapes.

use std::sync::Arc;

use axum::response::Response;
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor};
use tower_governor::GovernorLayer;

use crate::state::AppState;

/// Mount one `tower_governor` bucket onto `r`. The key extractor picks the trust model (`PeerIpKeyExtractor`
/// strict, `SmartIpKeyExtractor` when a proxy is trusted). `total_ms` is the window, `per_window` the burst cap;
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

/// Plain-text `429` for browser-facing endpoints, with `Retry-After` when the
/// governor surfaces a wait time. `context` only labels the trace line. JSON
/// endpoints (RFC 7591 DCR) render their own shape instead.
pub(crate) fn plain_text_error(
    context: &'static str,
) -> impl Fn(tower_governor::GovernorError) -> Response + Copy {
    move |err| {
        use axum::http::StatusCode;
        let retry = match &err {
            tower_governor::GovernorError::TooManyRequests { wait_time, .. } => Some(*wait_time),
            _ => None,
        };
        tracing::trace!(error = ?err, context, "per-IP rate limit triggered");
        let mut builder = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "text/plain; charset=utf-8");
        if let Some(s) = retry {
            builder = builder.header("retry-after", s.to_string());
        }
        builder
            .body(axum::body::Body::from(
                "Too many requests. Wait a moment and try again.",
            ))
            .expect("static response is well-formed")
    }
}

/// Attach paired per-minute + per-hour buckets to `r`, picking the key extractor from `trust_xff`
/// (`cfg.proxy.trust_forwarded_for`).
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
