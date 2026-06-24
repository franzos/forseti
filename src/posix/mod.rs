//! POSIX provisioning surface (name validation, id allocation, NSS plumbing).

pub mod allocate;
pub mod db;
pub mod device;
pub mod host_auth;
pub mod offline;
pub mod resolver;
pub mod scope;

use axum::Router;

use crate::state::AppState;

/// Internal-listener POSIX router: the NSS/SSH resolver plus the
/// host-authenticated device-auth endpoints. Both are gated by
/// `RequirePosixHost`; mounted together on `internal_app`.
pub fn router() -> Router<AppState> {
    resolver::router().merge(device::router())
}

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::db::DbPool;
use crate::ory::OryClients;

/// Batch size for the reconcile sweep's bulk Kratos existence check. Maps
/// to one `?ids=` query per batch; kept modest so a single Kratos error
/// only forces us to skip a small slice rather than the whole sweep.
const RECONCILE_BATCH: usize = 100;

/// Remove posix rows whose Kratos identity no longer exists (covers
/// out-of-band Kratos admin-API deletes the per-site cascade can't see).
///
/// Conservative by design: a missing id is purged ONLY when the Kratos
/// lookup for its batch succeeds and the id is absent from the result.
/// If the Kratos call errors (outage, transport), the batch is skipped
/// and nothing is deleted — a "don't know" must never purge a live
/// user's account. Returns the number of accounts removed.
pub async fn reconcile_orphans(db: &DbPool, ory: &Arc<OryClients>) -> anyhow::Result<usize> {
    // Sweep expired device-auth sessions while we're here — cheap, and keeps
    // abandoned flows from lingering past their Hydra expiry.
    match db::lazy_prune_expired(db, &chrono::Utc::now().to_rfc3339()).await {
        Ok(n) if n > 0 => tracing::info!(
            pruned = n,
            "posix reconcile: removed expired device sessions"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "posix reconcile: device-session prune failed"),
    }

    // Sweep the union of identities holding posix accounts AND offline
    // secrets: an identity can carry an offline verifier without a posix
    // account, and its row must be purged once the Kratos identity is gone.
    let mut id_set: std::collections::HashSet<String> =
        db::all_account_identity_ids(db).await?.into_iter().collect();
    match db::all_offline_secret_identity_ids(db).await {
        Ok(offline_ids) => id_set.extend(offline_ids),
        Err(e) => tracing::warn!(error = %e, "posix reconcile: offline-secret id scan failed; continuing with account ids"),
    }
    let ids: Vec<String> = id_set.into_iter().collect();
    if ids.is_empty() {
        return Ok(0);
    }
    let total = ids.len();
    let mut removed = 0usize;
    let mut skipped_batches = 0usize;

    for batch in ids.chunks(RECONCILE_BATCH) {
        let batch_vec: Vec<String> = batch.to_vec();
        let present = match crate::ory::kratos::admin_list_identities_by_ids(ory, batch_vec).await {
            Ok(found) => found,
            Err(e) => {
                // Treat a Kratos failure as "don't know" — never purge.
                tracing::warn!(error = %e, "posix reconcile: kratos lookup failed for a batch; skipping (no purge)");
                skipped_batches += 1;
                continue;
            }
        };
        let present_ids: std::collections::HashSet<&str> =
            present.iter().map(|i| i.id.as_str()).collect();

        for id in batch {
            if present_ids.contains(id.as_str()) {
                continue;
            }
            // In the result of a successful lookup but absent → the
            // Kratos identity is gone. Purge its orphaned posix rows.
            match db::delete_account_rows(db, id).await {
                Ok(()) => {
                    removed += 1;
                    tracing::info!(identity_id = %id, "posix reconcile: purged orphaned posix rows (kratos identity gone)");
                }
                Err(e) => {
                    tracing::error!(error = ?e, identity_id = %id, "posix reconcile: failed to purge orphaned posix rows");
                }
            }
            // ...and its offline verifier, so a deleted identity can't keep an
            // offline credential alive on any host past the next pull.
            if let Err(e) = db::delete_offline_secret(db, id).await {
                tracing::error!(error = ?e, identity_id = %id, "posix reconcile: failed to purge orphaned offline secret");
            }
        }
    }

    tracing::info!(
        scanned = total,
        removed,
        skipped_batches,
        "posix reconcile: sweep complete"
    );
    Ok(removed)
}

/// Hourly sweep that purges posix rows for identities deleted out-of-band
/// (directly via the Kratos admin API), which the per-delete-site cascade
/// can't observe. Mirrors `webhook::spawn_reconcile`.
pub fn spawn_reconcile(db: DbPool, ory: Arc<OryClients>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60 * 60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("posix reconcile task: shutdown received, exiting");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(e) = reconcile_orphans(&db, &ory).await {
                        tracing::warn!(error = %e, "periodic posix reconcile failed");
                    }
                }
            }
        }
    });
}
