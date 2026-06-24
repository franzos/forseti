//! Identity-management helpers + CLI subcommands.
//!
//! Today this carries the unverified-account reaper (`unverified-prune`
//! CLI) and the hand-rolled "claim this email" flow. Future
//! identity-shaped helpers (bulk-disable, etc.) land here too.

pub mod claim_email;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ory_client::apis::identity_api;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::ory::OryClients;

/// Entry point for the `unverified-prune` subcommand. Mirrors `audit-prune`:
/// reads `[identity].unverified_ttl_days`, deletes Kratos identities that
/// have at least one unverified address AND were created more than N days
/// ago. Returns the process exit code (0 on success, 1 on failure).
pub async fn prune_unverified_cli(cfg: &AppConfig, db: &DbPool, ory: &OryClients) -> i32 {
    let ttl_days = cfg.identity.unverified_ttl_days;
    match prune_unverified(db, ory, ttl_days).await {
        Ok((deleted, scanned)) => {
            println!(
                "unverified-prune: scanned {scanned} identities, deleted {deleted} older than {ttl_days} days with at least one unverified address"
            );
            0
        }
        Err(e) => {
            eprintln!("unverified-prune: {e:?}");
            1
        }
    }
}

/// Walk every identity Kratos knows about and delete the unverified-and-old
/// ones. Returns `(deleted, scanned)`.
///
/// Single-page bounded: the typed Kratos SDK doesn't surface the `Link:
/// <...>; rel="next"` header that carries the cursor for the next page,
/// so we can't safely walk past one page without risking re-scanning the
/// same rows. We log a `warn!` if a full page came back (caller should
/// re-run the prune after deletes to drain the rest) and document the
/// limitation in `docs/operator-guide.md`.
pub async fn prune_unverified(
    db: &DbPool,
    ory: &OryClients,
    ttl_days: i64,
) -> anyhow::Result<(u64, u64)> {
    let cutoff = Utc::now() - ChronoDuration::days(ttl_days.max(0));
    let mut deleted: u64 = 0;
    let mut scanned: u64 = 0;
    let page_size: i64 = 250;

    let batch = identity_api::list_identities(
        &ory.kratos_admin,
        None,
        None,
        Some(page_size),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos list_identities failed: {e}"))?;

    scanned += batch.len() as u64;

    for ident in &batch {
        if should_prune(ident, cutoff) {
            if let Err(e) = identity_api::delete_identity(&ory.kratos_admin, &ident.id).await {
                tracing::warn!(error = ?e, id = %ident.id, "unverified-prune: delete failed");
                continue;
            }
            // Cascade: purge POSIX rows. Best-effort; an orphan is a
            // security issue (usable login for a deleted identity) but
            // must not stop the prune.
            if let Err(e) = crate::posix::db::delete_account_rows(db, &ident.id).await {
                tracing::error!(error = ?e, identity_id = %ident.id, "failed to purge posix rows on identity delete");
            }
            deleted += 1;
        }
    }

    if batch.len() == page_size as usize {
        tracing::warn!(
            page_size,
            "unverified-prune: full page returned; Kratos likely has more identities than \
             one page. The SDK doesn't expose the Link header cursor, so additional pages \
             aren't walked — re-run `forseti unverified-prune` until the run reports a \
             non-full page."
        );
    }
    Ok((deleted, scanned))
}

/// True when this identity is older than `cutoff` AND has no verified
/// verifiable address.
///
/// Predicate semantics — prune iff:
///  - `created_at` parses and is older than `cutoff`, AND
///  - `verifiable_addresses` is present and non-empty, AND
///  - NONE of those addresses are verified.
///
/// A verified primary email with an unverified secondary recovery address
/// must NOT be pruned — the user has at least one verified channel and
/// would lose access otherwise. Identities with no verifiable addresses
/// are ignored too: they're typically API-only identities (or test
/// fixtures) that have no concept of "verified".
fn should_prune(ident: &ory_client::models::Identity, cutoff: DateTime<Utc>) -> bool {
    // Kratos returns `created_at` as an ISO-8601 string in the SDK
    // (`Option<String>`). Parse it; an unparseable timestamp is suspicious
    // enough that we skip rather than delete.
    let Some(created_at_str) = ident.created_at.as_deref() else {
        return false;
    };
    let Ok(created_at) = DateTime::parse_from_rfc3339(created_at_str) else {
        return false;
    };
    if created_at.with_timezone(&Utc) > cutoff {
        return false;
    }
    let Some(addrs) = ident.verifiable_addresses.as_ref() else {
        return false;
    };
    if addrs.is_empty() {
        return false;
    }
    addrs.iter().all(|a| !a.verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ory_client::models::verifiable_identity_address::ViaEnum;
    use ory_client::models::{Identity, VerifiableIdentityAddress};

    fn addr(value: &str, verified: bool) -> VerifiableIdentityAddress {
        VerifiableIdentityAddress::new(
            "completed".to_string(),
            value.to_string(),
            verified,
            ViaEnum::Email,
        )
    }

    fn ident(created_at: Option<&str>, addrs: Option<Vec<VerifiableIdentityAddress>>) -> Identity {
        let mut id = Identity::new(
            "test-id".to_string(),
            "default".to_string(),
            String::new(),
            None,
        );
        id.created_at = created_at.map(str::to_string);
        id.verifiable_addresses = addrs;
        id
    }

    fn cutoff() -> DateTime<Utc> {
        // Anything before 2026-01-01 is "old".
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn should_prune_single_unverified_old_identity() {
        let id = ident(
            Some("2025-01-01T00:00:00Z"),
            Some(vec![addr("a@example.com", false)]),
        );
        assert!(should_prune(&id, cutoff()));
    }

    #[test]
    fn should_not_prune_verified_primary_with_unverified_secondary() {
        let id = ident(
            Some("2025-01-01T00:00:00Z"),
            Some(vec![
                addr("primary@example.com", true),
                addr("secondary@example.com", false),
            ]),
        );
        assert!(!should_prune(&id, cutoff()));
    }

    #[test]
    fn should_not_prune_no_verifiable_addresses() {
        let id_none = ident(Some("2025-01-01T00:00:00Z"), None);
        assert!(!should_prune(&id_none, cutoff()));
        let id_empty = ident(Some("2025-01-01T00:00:00Z"), Some(Vec::new()));
        assert!(!should_prune(&id_empty, cutoff()));
    }

    #[test]
    fn should_not_prune_when_timestamp_parse_fails() {
        let id = ident(
            Some("not-a-timestamp"),
            Some(vec![addr("a@example.com", false)]),
        );
        assert!(!should_prune(&id, cutoff()));
        let id_missing = ident(None, Some(vec![addr("a@example.com", false)]));
        assert!(!should_prune(&id_missing, cutoff()));
    }

    #[test]
    fn should_not_prune_recently_created_identity() {
        let id = ident(
            Some("2027-01-01T00:00:00Z"),
            Some(vec![addr("a@example.com", false)]),
        );
        assert!(!should_prune(&id, cutoff()));
    }
}
