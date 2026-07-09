//! Shared per-IP rate-limit helper wrapping `tower_governor::GovernorLayer`. The error handler is
//! caller-supplied so JSON (RFC 7591 DCR) and HTML (`/claim-email`) endpoints render their own shapes.

use std::sync::{Arc, Mutex};

use axum::response::Response;
use axum::Router;
use tokio_util::sync::CancellationToken;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{GlobalKeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor};
use tower_governor::GovernorLayer;

use crate::state::AppState;

/// Every keyed limiter registers a `retain_recent` closure here; without the
/// periodic sweep the per-IP maps grow unboundedly (memory-exhaustion DoS).
static RETAINERS: Mutex<Vec<Box<dyn Fn() + Send + Sync>>> = Mutex::new(Vec::new());

/// Spawn the single background sweep that drops stale per-IP entries from all
/// registered limiters. Wired to the same shutdown token as the other workers.
pub(crate) fn spawn_retention(shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = tick.tick() => {
                    let retainers = RETAINERS
                        .lock()
                        .expect("retainer registry mutex poisoned"); // registered closures never panic
                    for retain in retainers.iter() {
                        retain();
                    }
                }
            }
        }
    });
}

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
    <K as tower_governor::key_extractor::KeyExtractor>::Key: Send + Sync + 'static,
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
    let cfg = Arc::new(cfg);
    let limiter = cfg.limiter().clone();
    RETAINERS
        .lock()
        .expect("retainer registry mutex poisoned")
        .push(Box::new(move || limiter.retain_recent()));
    r.layer(GovernorLayer::new(cfg).error_handler(error_handler))
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

/// Attach one bucket to `r`, picking the key extractor from `trust_xff`
/// (`cfg.proxy.trust_forwarded_for`).
pub(crate) fn single_window<F>(
    r: Router<AppState>,
    trust_xff: bool,
    total_ms: u64,
    per_window: u32,
    error_handler: F,
) -> Router<AppState>
where
    F: Fn(tower_governor::GovernorError) -> Response + Send + Sync + 'static,
{
    if trust_xff {
        apply(r, SmartIpKeyExtractor, total_ms, per_window, error_handler)
    } else {
        apply(r, PeerIpKeyExtractor, total_ms, per_window, error_handler)
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

/// Layer a global (all-callers-share-one-bucket) pair on top of `dual_window`'s
/// per-IP pair. Per-IP alone is bypassed by distributed signup and, when
/// `trust_xff` trusts a spoofable header, by forged `X-Forwarded-For`; the
/// global bucket bounds total traffic regardless of claimed source.
pub(crate) fn dual_window_with_global<F>(
    r: Router<AppState>,
    trust_xff: bool,
    per_minute: u32,
    per_hour: u32,
    global_per_minute: u32,
    global_per_hour: u32,
    error_handler: F,
) -> Router<AppState>
where
    F: Fn(tower_governor::GovernorError) -> Response + Copy + Send + Sync + 'static,
{
    let r = dual_window(r, trust_xff, per_minute, per_hour, error_handler);
    let r = apply(
        r,
        GlobalKeyExtractor,
        60_000,
        global_per_minute,
        error_handler,
    );
    apply(
        r,
        GlobalKeyExtractor,
        3_600_000,
        global_per_hour,
        error_handler,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RETAINERS is a process-global static; cargo runs tests in parallel
    // threads by default, so two tests asserting on its length race each
    // other (and a failing assert while a guard is alive poisons the mutex
    // for the rest of the suite). Serialize the RETAINERS-touching tests here.
    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn apply_registers_retainer_only_for_active_buckets() {
        let _guard = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = RETAINERS.lock().unwrap().len();
        let r: Router<AppState> = Router::new();
        let r = apply(r, PeerIpKeyExtractor, 60_000, 0, plain_text_error("test"));
        let after_noop = RETAINERS.lock().unwrap().len();
        assert_eq!(after_noop, before);
        let _r = apply(r, PeerIpKeyExtractor, 60_000, 5, plain_text_error("test"));
        let after_active = RETAINERS.lock().unwrap().len();
        assert_eq!(after_active, before + 1);
    }

    #[test]
    fn dual_window_with_global_registers_four_retainers() {
        let _guard = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = RETAINERS.lock().unwrap().len();
        let r: Router<AppState> = Router::new();
        let _r = dual_window_with_global(r, false, 10, 60, 120, 1200, plain_text_error("test"));
        let after = RETAINERS.lock().unwrap().len();
        assert_eq!(after, before + 4);
    }
}
