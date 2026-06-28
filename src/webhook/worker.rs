//! Background outbox worker + reconciler scheduler + per-row HTTP delivery.
//!
//! ## Retry policy
//!
//! `1m * 2^attempt` with ±25% jitter, capped at 6h. Max 12 attempts and a
//! 72h max age — whichever fires first transitions the row to `DEAD`.
//! Defaults match Stripe-shape conventions.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::db::DbPool;
use crate::db_interact;
use crate::ory::OryClients;
use crate::schema::webhook_outbox;

use super::outbox::{reconcile_pending, state, OutboxRow};

/// Heartbeat handle for the webhook worker. Exposes the unix-seconds
/// timestamp of the worker's last completed tick; `/readyz` reads this to
/// detect a stuck/dead worker without having to peek into tokio internals.
#[derive(Clone, Debug)]
pub struct WorkerHandle {
    last_tick: Arc<AtomicI64>,
}

impl WorkerHandle {
    fn new() -> Self {
        Self {
            last_tick: Arc::new(AtomicI64::new(Utc::now().timestamp())),
        }
    }

    /// Seconds since the worker last finished a tick (whether or not the
    /// tick did anything). A wedged or panicking worker shows up as a
    /// monotonically growing value here.
    pub fn seconds_since_last_tick(&self) -> i64 {
        Utc::now()
            .timestamp()
            .saturating_sub(self.last_tick.load(Ordering::Relaxed))
    }
}

/// Spawn a periodic reconcile task. Runs `reconcile_pending` on a
/// 60s interval so stuck `PENDING` rows get processed without waiting
/// for a Forseti restart. `reconcile_pending` is bounded to rows older
/// than 5 minutes, so this can't interfere with in-flight saga steps.
///
/// Separate from [`spawn_worker`] on purpose: the worker drains
/// `CONFIRMED` rows (delivery), the reconciler resolves `PENDING`
/// rows stranded by a crash between outbox write and Kratos delete.
/// Different responsibilities, different cadences, no shared state
/// beyond the `DbPool` + `OryClients` handles.
pub fn spawn_reconcile(db: DbPool, ory: Arc<OryClients>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        // First tick fires after the interval, not immediately —
        // startup reconciliation is already performed by `app::run`
        // calling `reconcile_pending` directly.
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("webhook reconcile task: shutdown received, exiting");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(e) = reconcile_pending(&db, &ory).await {
                        tracing::warn!(error = %e, "periodic webhook reconcile failed");
                    }
                }
            }
        }
    });
}

/// Spawn the background outbox worker. Drains CONFIRMED rows, sends them,
/// applies retry/backoff on failure, transitions to DEAD when exhausted.
/// One worker per process; safe for sqlite (single-instance) and
/// acceptable for postgres single-active-instance deploys.
///
/// The returned [`WorkerHandle`] is stored in `AppState` so `/readyz` can
/// detect a stalled worker. `drain_once` propagates errors via `anyhow`
/// and its callees never panic, so a failed tick is logged and the
/// supervisor keeps looping.
pub fn spawn_worker(
    db: DbPool,
    cfg: crate::config::WebhookConfig,
    shutdown: CancellationToken,
) -> WorkerHandle {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        // Disable redirects: a 302 from a configured webhook URL to an
        // internal address would otherwise bypass the SSRF guard at
        // `validate_webhook_url`. The receiver gets one shot per
        // delivery; misconfigured redirect chains surface as transport
        // failures in the outbox row.
        .redirect(reqwest::redirect::Policy::none())
        // Connect-time SSRF guard: re-check every resolved address against
        // the blocklist so a public hostname that rebinds to an internal IP
        // can't slip past the save-time `validate_webhook_url` check.
        .dns_resolver(super::validate::guarded_resolver())
        .build()
        .expect("reqwest client builds");
    let handle = WorkerHandle::new();
    let last_tick = handle.last_tick.clone();
    let tick = Duration::from_secs(cfg.tick_seconds);
    tokio::spawn(async move {
        loop {
            // Check the shutdown token before kicking off another tick.
            // A drain already in flight (HTTP `reqwest::send().await`)
            // is *not* cancelled mid-flight — RFC 8417 receivers may have
            // accepted the SET and we want the bookkeeping to land
            // either way. Cancellation only prevents the *next* tick.
            if shutdown.is_cancelled() {
                tracing::info!("webhook worker: shutdown received, exiting");
                break;
            }
            if let Err(e) = drain_once(&db, &http, &cfg).await {
                tracing::warn!(error = %e, "webhook worker tick failed");
            }
            last_tick.store(Utc::now().timestamp(), Ordering::Relaxed);
            // Sleep, but wake immediately on shutdown so we don't
            // linger up to `tick_seconds` after the signal.
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("webhook worker: shutdown received during sleep, exiting");
                    break;
                }
                _ = tokio::time::sleep(tick) => {}
            }
        }
    });
    handle
}

async fn drain_once(
    db: &DbPool,
    http: &reqwest::Client,
    cfg: &crate::config::WebhookConfig,
) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    let candidates: Vec<OutboxRow> = db_interact!(db, |conn| {
        webhook_outbox::table
            .filter(webhook_outbox::state.eq(state::CONFIRMED))
            .filter(webhook_outbox::delivered_at.is_null())
            .filter(webhook_outbox::next_attempt_at.le(&now))
            .order(webhook_outbox::next_attempt_at.asc())
            .limit(32)
            .select(OutboxRow::as_select())
            .load(conn)
    })?;

    const DRAIN_CONCURRENCY: usize = 6;
    futures_util::stream::iter(candidates)
        .for_each_concurrent(DRAIN_CONCURRENCY, |row| {
            process_outbox_row(db.clone(), http.clone(), row, cfg.clone())
        })
        .await;
    Ok(())
}

/// Claim and deliver a single outbox row. A lost claim race or a claim
/// error is logged and dropped — the row stays visible for the next tick.
async fn process_outbox_row(
    db: DbPool,
    http: reqwest::Client,
    row: OutboxRow,
    cfg: crate::config::WebhookConfig,
) {
    match try_claim(&db, &row, &cfg).await {
        Ok(true) => deliver(&db, &http, row, &cfg).await,
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(error = %e, row_id = %row.id, "webhook claim failed");
        }
    }
}

/// Compare-and-swap claim. Returns true iff this worker won the race.
/// The claim pushes `next_attempt_at` out by `cfg.claim_lease_seconds`;
/// the terminal [`record_outcome`] overwrites it with the real next
/// attempt (or DEAD / delivered_at) regardless. Crash-safe: if the
/// worker dies after a successful claim, the row simply becomes visible
/// to other workers once the lease elapses.
async fn try_claim(
    db: &DbPool,
    row: &OutboxRow,
    cfg: &crate::config::WebhookConfig,
) -> anyhow::Result<bool> {
    let lease_until =
        (Utc::now() + chrono::Duration::seconds(cfg.claim_lease_seconds)).to_rfc3339();
    let id = row.id.clone();
    let original_next = row.next_attempt_at.clone();
    let n: usize = db_interact!(db, |conn| {
        diesel::update(
            webhook_outbox::table
                .filter(webhook_outbox::id.eq(&id))
                .filter(webhook_outbox::state.eq(state::CONFIRMED))
                .filter(webhook_outbox::delivered_at.is_null())
                .filter(webhook_outbox::next_attempt_at.eq(&original_next)),
        )
        .set(webhook_outbox::next_attempt_at.eq(&lease_until))
        .execute(conn)
    })?;
    Ok(n > 0)
}

async fn deliver(
    db: &DbPool,
    http: &reqwest::Client,
    row: OutboxRow,
    cfg: &crate::config::WebhookConfig,
) {
    // The payload column already holds the compact JWS minted at
    // enqueue time. `iat` inside the SET is bound to *that* moment, not
    // delivery time — RFC 8417 doesn't require recomputation on retry,
    // and re-signing per retry would invalidate any receiver-side
    // dedupe that hashed the body.
    let req = http
        .post(&row.url)
        .header("Content-Type", "application/secevent+jwt")
        .header("X-Forseti-Event", &row.event_id)
        .body(row.payload.clone());

    let response = req.send().await;

    let outcome = match response {
        Ok(resp) if resp.status().is_success() => DeliveryOutcome::Success,
        Ok(resp) => DeliveryOutcome::Failure(format!("HTTP {}", resp.status())),
        Err(e) => DeliveryOutcome::Failure(format!("transport: {e}")),
    };

    if let Err(e) = record_outcome(db, &row, outcome, cfg).await {
        // The claim lease expires and `max_age_hours` ageing eventually
        // DEADs the row, so a failed bookkeeping write is recoverable on a
        // later tick — log and move on.
        tracing::error!(error = %e, row_id = %row.id, "webhook bookkeeping failed");
    }
}

enum DeliveryOutcome {
    Success,
    Failure(String),
}

async fn record_outcome(
    db: &DbPool,
    row: &OutboxRow,
    outcome: DeliveryOutcome,
    cfg: &crate::config::WebhookConfig,
) -> anyhow::Result<()> {
    match outcome {
        DeliveryOutcome::Success => {
            let now = Utc::now().to_rfc3339();
            let id = row.id.clone();
            let new_attempts = row.attempts + 1;
            db_interact!(db, |conn| {
                diesel::update(webhook_outbox::table.filter(webhook_outbox::id.eq(&id)))
                    .set((
                        webhook_outbox::delivered_at.eq(Some(now.clone())),
                        webhook_outbox::attempts.eq(new_attempts),
                        webhook_outbox::last_error.eq::<Option<String>>(None),
                    ))
                    .execute(conn)
            })?;
            tracing::info!(
                action = "webhook.delivered",
                row_id = %row.id,
                event_id = %row.event_id,
                client_id = %row.client_id,
                attempts = row.attempts + 1,
                "webhook delivered"
            );
        }
        DeliveryOutcome::Failure(err) => {
            let attempts = row.attempts + 1;
            let exhausted = attempts >= cfg.max_attempts
                || aged_out(&row.id, &row.created_at, cfg.max_age_hours);
            let id = row.id.clone();
            if exhausted {
                let err_for_db = err.clone();
                db_interact!(db, |conn| {
                    diesel::update(webhook_outbox::table.filter(webhook_outbox::id.eq(&id)))
                        .set((
                            webhook_outbox::state.eq(state::DEAD),
                            webhook_outbox::attempts.eq(attempts),
                            webhook_outbox::last_error.eq(Some(err_for_db)),
                        ))
                        .execute(conn)
                })?;
                tracing::warn!(
                    action = "webhook.dead_lettered",
                    row_id = %row.id,
                    event_id = %row.event_id,
                    client_id = %row.client_id,
                    attempts,
                    error = %err,
                    "webhook dead-lettered"
                );
            } else {
                let next = (Utc::now()
                    + chrono::Duration::seconds(backoff_seconds(
                        attempts,
                        cfg.backoff_cap_seconds,
                    )))
                .to_rfc3339();
                let err_for_db = err.clone();
                let next_for_log = next.clone();
                db_interact!(db, |conn| {
                    diesel::update(webhook_outbox::table.filter(webhook_outbox::id.eq(&id)))
                        .set((
                            webhook_outbox::attempts.eq(attempts),
                            webhook_outbox::next_attempt_at.eq(&next),
                            webhook_outbox::last_error.eq(Some(err_for_db)),
                        ))
                        .execute(conn)
                })?;
                tracing::info!(
                    action = "webhook.retry_scheduled",
                    row_id = %row.id,
                    attempts,
                    next_attempt_at = %next_for_log,
                    error = %err,
                    "webhook retry scheduled"
                );
            }
        }
    }
    Ok(())
}

fn aged_out(row_id: &str, created_at: &str, max_age_hours: i64) -> bool {
    match DateTime::parse_from_rfc3339(created_at) {
        Ok(created) => (Utc::now() - created.with_timezone(&Utc)).num_hours() >= max_age_hours,
        Err(e) => {
            // Fail closed: an unparseable timestamp is a poison row. Returning
            // `false` would retry it forever; instead treat it as aged-out so
            // the outbox transitions to DEAD on the next attempt.
            tracing::error!(
                row_id = %row_id,
                created_at,
                error = %e,
                "webhook outbox row has unparseable created_at; treating as aged-out"
            );
            true
        }
    }
}

/// Exponential backoff with ±25% jitter, capped at `cap_secs`.
fn backoff_seconds(attempt: i32, cap_secs: i64) -> i64 {
    use rand::Rng;
    // Anything past 30d is operator misconfig — the outbox DEADs rows long
    // before that. Clamping here keeps the f64 jitter math well inside range
    // and stops a zero/negative `cap_secs` from panicking `random_range`.
    const MAX_CAP_SECS: i64 = 30 * 24 * 60 * 60;
    let cap_secs = cap_secs.clamp(1, MAX_CAP_SECS);
    let base: i64 = 60_i64.saturating_mul(1_i64 << attempt.min(20));
    let capped = base.min(cap_secs);
    let jitter_range = (capped as f64) * 0.25;
    let delta = if jitter_range > 0.0 {
        rand::rng().random_range(-jitter_range..=jitter_range) as i64
    } else {
        0
    };
    capped.saturating_add(delta).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_with_attempt_and_caps() {
        const CAP: i64 = 6 * 60 * 60;
        // Average across runs to smooth the ±25% jitter.
        let avg = |attempt: i32| -> f64 {
            let n = 50;
            (0..n)
                .map(|_| backoff_seconds(attempt, CAP) as f64)
                .sum::<f64>()
                / n as f64
        };
        let a1 = avg(1);
        let a3 = avg(3);
        let a6 = avg(6);
        assert!(
            a1 < a3,
            "attempt 1 ({}s) should be < attempt 3 ({}s)",
            a1,
            a3
        );
        assert!(
            a3 < a6,
            "attempt 3 ({}s) should be < attempt 6 ({}s)",
            a3,
            a6
        );
        for _ in 0..50 {
            let v = backoff_seconds(20, CAP);
            assert!(v >= (CAP as f64 * 0.74) as i64);
            assert!(v <= (CAP as f64 * 1.26) as i64);
        }
        for _ in 0..20 {
            assert!(backoff_seconds(0, CAP) >= 1);
        }
    }

    #[test]
    fn backoff_survives_misconfigured_cap() {
        // i64::MAX as cap_secs would overflow the f64 jitter math without the clamp.
        for attempt in [0, 5, 20] {
            let v = backoff_seconds(attempt, i64::MAX);
            assert!(v >= 1, "backoff must be positive, got {v}");
        }
        // Zero / negative caps must not panic random_range.
        assert!(backoff_seconds(3, 0) >= 1);
        assert!(backoff_seconds(3, -1) >= 1);
    }

    #[test]
    fn aged_out_boundary() {
        const MAX: i64 = 72;
        let fresh = Utc::now().to_rfc3339();
        assert!(!aged_out("row-1", &fresh, MAX));
        let old = (Utc::now() - chrono::Duration::hours(MAX + 1)).to_rfc3339();
        assert!(aged_out("row-2", &old, MAX));
        // Unparseable timestamp is treated as aged-out (fail-closed).
        assert!(aged_out("row-3", "not-a-date", MAX));
    }
}
