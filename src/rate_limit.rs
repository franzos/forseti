//! Shared per-IP rate-limit helper wrapping `tower_governor::GovernorLayer`. The error handler is
//! caller-supplied so JSON (the CIMD shim) and HTML (`/claim-email`) endpoints render their own shapes.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::response::Response;
use tokio_util::sync::CancellationToken;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::GlobalKeyExtractor;

use crate::client_ip::ClientIpKeyExtractor;
use crate::config::ProxyConfig;
use crate::state::AppState;

/// Global bucket derived for per-IP-only routes: the per-IP cap times this.
/// A ceiling on total traffic regardless of claimed source, so a
/// misconfigured proxy (or a forged forwarded-for chain) can't turn a
/// code-guess endpoint into an unbounded one.
const GLOBAL_BACKSTOP_FACTOR: u32 = 20;

/// Every keyed limiter registers a `retain_recent` closure here; without the
/// periodic sweep the per-IP maps grow unboundedly (memory-exhaustion DoS).
static RETAINERS: Mutex<Vec<Box<dyn Fn() + Send + Sync>>> = Mutex::new(Vec::new());

/// Spawn the single background sweep that drops stale per-IP entries from all
/// registered limiters. Wired to the same shutdown token as the other workers.
pub(crate) fn spawn_retention(shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
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
    })
}

/// Mount one `tower_governor` bucket onto `r`. The key extractor picks the trust model
/// (`ClientIpKeyExtractor` over `[proxy]`, or `GlobalKeyExtractor`). `total_ms` is the window,
/// `per_window` the burst cap; `per_window == 0` disables the bucket and returns `r` unmodified.
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
/// endpoints render their own shape instead.
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

/// Attach one per-client bucket to `r`, keyed per `[proxy]`.
pub(crate) fn single_window<F>(
    r: Router<AppState>,
    proxy: &ProxyConfig,
    total_ms: u64,
    per_window: u32,
    error_handler: F,
) -> Router<AppState>
where
    F: Fn(tower_governor::GovernorError) -> Response + Send + Sync + 'static,
{
    let key = ClientIpKeyExtractor::from_config(proxy);
    apply(r, key, total_ms, per_window, error_handler)
}

/// Attach paired per-minute + per-hour per-client buckets to `r`, keyed per `[proxy]`.
pub(crate) fn dual_window<F>(
    r: Router<AppState>,
    proxy: &ProxyConfig,
    per_minute: u32,
    per_hour: u32,
    error_handler: F,
) -> Router<AppState>
where
    F: Fn(tower_governor::GovernorError) -> Response + Copy + Send + Sync + 'static,
{
    let key = ClientIpKeyExtractor::from_config(proxy);
    let r = apply(r, key, 60_000, per_minute, error_handler);
    apply(r, key, 3_600_000, per_hour, error_handler)
}

/// [`dual_window`] plus a derived global pair ([`GLOBAL_BACKSTOP_FACTOR`]
/// times each per-client cap) for routes that have no operator-facing
/// global knob of their own.
pub(crate) fn dual_window_with_backstop<F>(
    r: Router<AppState>,
    proxy: &ProxyConfig,
    per_minute: u32,
    per_hour: u32,
    error_handler: F,
) -> Router<AppState>
where
    F: Fn(tower_governor::GovernorError) -> Response + Copy + Send + Sync + 'static,
{
    dual_window_with_global(
        r,
        proxy,
        per_minute,
        per_hour,
        per_minute.saturating_mul(GLOBAL_BACKSTOP_FACTOR),
        per_hour.saturating_mul(GLOBAL_BACKSTOP_FACTOR),
        error_handler,
    )
}

/// Layer a global (all-callers-share-one-bucket) pair on top of `dual_window`'s
/// per-client pair. Per-client alone is bypassed by distributed signup and by
/// a forwarded-for chain the proxy failed to append to; the global bucket
/// bounds total traffic regardless of claimed source.
pub(crate) fn dual_window_with_global<F>(
    r: Router<AppState>,
    proxy: &ProxyConfig,
    per_minute: u32,
    per_hour: u32,
    global_per_minute: u32,
    global_per_hour: u32,
    error_handler: F,
) -> Router<AppState>
where
    F: Fn(tower_governor::GovernorError) -> Response + Copy + Send + Sync + 'static,
{
    let r = dual_window(r, proxy, per_minute, per_hour, error_handler);
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
        let key = ClientIpKeyExtractor::from_config(&ProxyConfig::default());
        let r: Router<AppState> = Router::new();
        let r = apply(r, key, 60_000, 0, plain_text_error("test"));
        let after_noop = RETAINERS.lock().unwrap().len();
        assert_eq!(after_noop, before);
        let _r = apply(r, key, 60_000, 5, plain_text_error("test"));
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
        let _r = dual_window_with_global(
            r,
            &ProxyConfig::default(),
            10,
            60,
            120,
            1200,
            plain_text_error("test"),
        );
        let after = RETAINERS.lock().unwrap().len();
        assert_eq!(after, before + 4);
    }

    #[test]
    fn dual_window_with_backstop_registers_four_retainers() {
        let _guard = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = RETAINERS.lock().unwrap().len();
        let r: Router<AppState> = Router::new();
        let _r =
            dual_window_with_backstop(r, &ProxyConfig::default(), 5, 30, plain_text_error("test"));
        let after = RETAINERS.lock().unwrap().len();
        assert_eq!(after, before + 4);
    }
}

/// A process-local "at most `limit` per `window` per key" counter, for
/// throttles that key on something the governor layer can't see — a recipient
/// address, an org id — rather than on the client IP.
///
/// Process-local on purpose, matching `orgs::domains`'s challenge cooldown: a
/// multi-instance deployment multiplies the effective rate by the instance
/// count, and the audit trail (every mint is logged with its actor) stays the
/// real backstop. A shared counter would need a round-trip on a path that is
/// otherwise a single insert.
pub(crate) struct KeyedQuota {
    window: std::time::Duration,
    limit: usize,
    hits: std::sync::Mutex<std::collections::HashMap<String, Vec<std::time::Instant>>>,
}

impl KeyedQuota {
    pub(crate) fn new(window: std::time::Duration, limit: usize) -> Self {
        Self {
            window,
            limit,
            hits: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record an attempt against `key`. `false` means the caller is over the
    /// limit and should refuse; the attempt is not recorded in that case, so a
    /// refused caller doesn't extend their own lockout.
    pub(crate) fn admit(&self, key: &str) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = std::time::Instant::now();
        let mut map = self
            .hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < self.window);
            !times.is_empty()
        });
        let entry = map.entry(key.to_string()).or_default();
        if entry.len() >= self.limit {
            return false;
        }
        entry.push(now);
        true
    }
}

#[cfg(test)]
mod keyed_quota_tests {
    use super::KeyedQuota;
    use std::time::Duration;

    #[test]
    fn the_first_n_are_admitted_and_the_next_is_not() {
        let q = KeyedQuota::new(Duration::from_secs(3600), 3);
        assert!(q.admit("a@example.com"));
        assert!(q.admit("a@example.com"));
        assert!(q.admit("a@example.com"));
        assert!(!q.admit("a@example.com"), "the fourth is over the limit");
    }

    #[test]
    fn keys_are_independent() {
        let q = KeyedQuota::new(Duration::from_secs(3600), 1);
        assert!(q.admit("a@example.com"));
        assert!(!q.admit("a@example.com"));
        assert!(
            q.admit("b@example.com"),
            "a different recipient is unaffected"
        );
    }

    #[test]
    fn a_refused_attempt_does_not_extend_the_lockout() {
        let q = KeyedQuota::new(Duration::from_millis(80), 1);
        assert!(q.admit("a@example.com"));
        assert!(!q.admit("a@example.com"));
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            q.admit("a@example.com"),
            "the window is measured from the admitted attempt, not the refused one"
        );
    }

    #[test]
    fn a_zero_limit_disables_the_quota() {
        let q = KeyedQuota::new(Duration::from_secs(3600), 0);
        for _ in 0..100 {
            assert!(q.admit("a@example.com"));
        }
    }
}
