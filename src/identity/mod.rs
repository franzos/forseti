//! Identity-management helpers + CLI subcommands.
//!
//! Today this carries the unverified-account reaper (`unverified-prune`
//! CLI) and the hand-rolled "claim this email" flow. Future
//! identity-shaped helpers (bulk-disable, etc.) land here too.

pub mod claim_email;
pub mod delete;
pub mod pseudonymise;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ory_client::apis::identity_api;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::ory::{self, OryClients};
use crate::webhook::SigningKey;
use delete::{DeleteActor, DeleteEnv, DeleteError, DeleteReason, DeleteRequest, delete_identity};

/// The webhook signing key for a CLI verb; `None` after printing the error.
fn cli_signing_key(cfg: &AppConfig, verb: &str) -> Option<SigningKey> {
    let (signing_key, generated) = match delete::signing_key_from_config(cfg) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{verb}: webhook signing key: {e:?}");
            return None;
        }
    };
    if generated {
        eprintln!(
            "{verb}: no webhook signing key at {}; generated one. Receivers of the deletion notifications must reload the JWKS",
            cfg.webhook.signing_key_path
        );
    }
    Some(signing_key)
}

/// Entry point for the `delete-identity` subcommand. Returns the process
/// exit code: 0 deleted, 1 refused or failed, 2 confirmation needed but
/// stdin is not a terminal.
pub async fn delete_identity_cli(
    cfg: &AppConfig,
    db: &DbPool,
    ory: &OryClients,
    id: &str,
    yes: bool,
    force: bool,
) -> i32 {
    use std::io::{IsTerminal as _, Write as _};

    if !yes {
        if !std::io::stdin().is_terminal() {
            eprintln!(
                "delete-identity: stdin is not a terminal; pass --yes to skip the confirmation"
            );
            return 2;
        }
        let identity = match ory::kratos::admin_get_identity_full_optional(ory, id).await {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                eprintln!("delete-identity: identity {id} not found");
                return 1;
            }
            Err(e) => {
                eprintln!("delete-identity: {e:?}");
                return 1;
            }
        };
        let email = delete::verified_emails(&identity).into_iter().next();
        match &email {
            Some(email) => {
                print!("Delete identity {id} ({email})? Type the id or the email to confirm: ")
            }
            None => print!("Delete identity {id} (no verified email)? Type the id to confirm: "),
        }
        let _ = std::io::stdout().flush();
        let mut typed = String::new();
        if std::io::stdin().read_line(&mut typed).is_err() {
            eprintln!("delete-identity: could not read the confirmation");
            return 1;
        }
        let typed = typed.trim();
        let matches_email = email
            .as_deref()
            .is_some_and(|e| typed.eq_ignore_ascii_case(e));
        if typed != id && !matches_email {
            eprintln!("delete-identity: confirmation does not match; nothing deleted");
            return 1;
        }
    }

    let Some(signing_key) = cli_signing_key(cfg, "delete-identity") else {
        return 1;
    };
    let env = DeleteEnv {
        db,
        ory,
        signing_key: &signing_key,
        self_url: &cfg.self_.url,
        issuer: cfg.hydra.issuer_or_public(),
    };
    let req = DeleteRequest {
        identity_id: id.to_string(),
        reason: DeleteReason::Cli,
        actor: DeleteActor::System {
            source: "delete-identity".to_string(),
        },
        force,
        ctx: None,
        metadata: crate::audit::SafeMetadata::empty(),
    };
    match delete_identity(&env, req).await {
        Ok(report) => {
            println!(
                "delete-identity: deleted {} (event {})",
                report.identity_id, report.event_id
            );
            println!("removed: {}", report.removed.summary());
            if report.orphans.is_empty() {
                println!("left as orphans: none");
            } else {
                let steps: Vec<String> = report
                    .orphans
                    .iter()
                    .map(|o| format!("{} ({})", o.step, o.error))
                    .collect();
                println!("left as orphans: {}", steps.join(", "));
            }
            for org in &report.orgs_left_without_owner {
                println!("left without an owner: {org}");
            }
            0
        }
        Err(DeleteError::SoleOwner(names)) => {
            eprintln!(
                "delete-identity: refused: {id} is the only owner of {} and other members remain; transfer ownership or pass --force",
                names.join(", ")
            );
            1
        }
        Err(e) => {
            eprintln!("delete-identity: {e}");
            1
        }
    }
}

/// Entry point for the `unverified-prune` subcommand. Mirrors `audit-prune`:
/// reads `[identity].unverified_ttl_days`, deletes Kratos identities that
/// have at least one unverified address AND were created more than N days
/// ago. Returns the process exit code (0 on success, 1 on failure).
pub async fn prune_unverified_cli(cfg: &AppConfig, db: &DbPool, ory: &OryClients) -> i32 {
    let Some(signing_key) = cli_signing_key(cfg, "unverified-prune") else {
        return 1;
    };
    let env = DeleteEnv {
        db,
        ory,
        signing_key: &signing_key,
        self_url: &cfg.self_.url,
        issuer: cfg.hydra.issuer_or_public(),
    };
    let ttl_days = cfg.identity.unverified_ttl_days;
    match prune_unverified(&env, ttl_days, None).await {
        Ok(outcome) => {
            println!(
                "unverified-prune: scanned {} identities, deleted {} older than {ttl_days} days with at least one unverified address, {} failed",
                outcome.scanned, outcome.deleted, outcome.failed
            );
            for o in &outcome.orphans {
                println!("  {}: left behind {}", o.identity_id, o.steps.join(", "));
            }
            0
        }
        Err(e) => {
            eprintln!("unverified-prune: {e:?}");
            1
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PruneOutcome {
    pub deleted: u64,
    pub failed: u64,
    pub scanned: u64,
    /// Identities deleted with a best-effort step left undone.
    pub orphans: Vec<PruneOrphan>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PruneOrphan {
    pub identity_id: String,
    pub steps: Vec<&'static str>,
}

/// Walk every identity Kratos knows about and delete the unverified-and-old
/// ones through [`delete_identity`]. `only` restricts the run to one identity
/// id, fetched directly instead of listed.
///
/// Single-page bounded: the typed Kratos SDK doesn't surface the `Link:
/// <...>; rel="next"` header that carries the cursor for the next page,
/// so we can't safely walk past one page without risking re-scanning the
/// same rows. We log a `warn!` if a full page came back (caller should
/// re-run the prune after deletes to drain the rest) and document the
/// limitation in `docs/operator-guide.md`.
pub async fn prune_unverified(
    env: &DeleteEnv<'_>,
    ttl_days: i64,
    only: Option<&str>,
) -> anyhow::Result<PruneOutcome> {
    let cutoff = Utc::now() - ChronoDuration::days(ttl_days.max(0));
    let page_size: i64 = 250;

    let batch = match only {
        Some(id) => vec![crate::ory::kratos::admin_get_identity(env.ory, id).await?],
        None => identity_api::list_identities(
            &env.ory.kratos_admin,
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
        .map_err(|e| anyhow::anyhow!("kratos list_identities failed: {e}"))?,
    };

    let mut outcome = PruneOutcome {
        scanned: batch.len() as u64,
        ..PruneOutcome::default()
    };
    for ident in &batch {
        if !should_prune(ident, cutoff) {
            continue;
        }
        let req = DeleteRequest {
            identity_id: ident.id.clone(),
            reason: DeleteReason::Prune,
            actor: DeleteActor::System {
                source: "unverified-prune".to_string(),
            },
            force: false,
            ctx: None,
            metadata: crate::audit::SafeMetadata::empty(),
        };
        match delete_identity(env, req).await {
            Ok(report) => {
                outcome.deleted += 1;
                if !report.orphans.is_empty() {
                    outcome.orphans.push(PruneOrphan {
                        identity_id: report.identity_id,
                        steps: report.orphans.iter().map(|o| o.step).collect(),
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, id = %ident.id, "unverified-prune: delete failed");
                outcome.failed += 1;
            }
        }
    }

    if only.is_none() && batch.len() == page_size as usize {
        tracing::warn!(
            page_size,
            "unverified-prune: full page returned; Kratos likely has more identities than \
             one page. The SDK doesn't expose the Link header cursor, so additional pages \
             aren't walked — re-run `forseti unverified-prune` until the run reports a \
             non-full page."
        );
    }
    Ok(outcome)
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

    type Leftovers = (i64, Vec<(String, Option<String>)>);

    /// Profile rows left for `id` and the `(actor_kind, actor_email)` of its
    /// prune audit rows.
    async fn leftovers(db: &DbPool, id: &str) -> anyhow::Result<Leftovers> {
        use crate::schema::{audit_events, member_profiles};
        use diesel::prelude::*;
        let id = id.to_string();
        let out = crate::db_interact!(db, |conn| {
            let profiles = member_profiles::table
                .filter(member_profiles::identity_id.eq(&id))
                .count()
                .get_result::<i64>(conn)?;
            let audit = audit_events::table
                .filter(audit_events::target_id.eq(&id))
                .filter(audit_events::action.eq(crate::audit::action::IDENTITY_PRUNED))
                .select((audit_events::actor_kind, audit_events::actor_email))
                .load::<(String, Option<String>)>(conn)?;
            Ok::<_, diesel::result::Error>((profiles, audit))
        })?;
        Ok(out)
    }

    /// Runs against the playground's Kratos and Hydra admin APIs with a
    /// private sqlite pool; skipped when they aren't reachable.
    #[tokio::test]
    async fn prune_deletes_one_unverified_identity_and_its_rows() {
        use uuid::Uuid;

        let kratos_admin = std::env::var("FORSETI_TEST_KRATOS_ADMIN_URL")
            .unwrap_or_else(|_| "http://localhost:4434".to_string());
        let hydra_admin = std::env::var("FORSETI_TEST_HYDRA_ADMIN_URL")
            .unwrap_or_else(|_| "http://localhost:4445".to_string());
        let http = ory_reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("http client");
        for base in [&kratos_admin, &hydra_admin] {
            let ready = http
                .get(format!("{base}/health/ready"))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if !ready {
                eprintln!("skipping prune test: {base} not reachable");
                return;
            }
        }
        let mk = |base: &str| ory_client::apis::configuration::Configuration {
            base_path: base.to_string(),
            client: http.clone(),
            ..Default::default()
        };
        let ory = OryClients {
            kratos_public: mk(&kratos_admin),
            kratos_admin: mk(&kratos_admin),
            hydra_public: mk(&hydra_admin),
            hydra_admin: mk(&hydra_admin),
        };
        let db = crate::orgs::db::test_pool().await;
        let key_path = std::env::temp_dir().join(format!("forseti-prune-{}.pem", Uuid::new_v4()));
        let signing_key =
            crate::webhook::SigningKey::load_or_generate(&key_path).expect("signing key");
        let env = DeleteEnv {
            db: &db,
            ory: &ory,
            signing_key: &signing_key,
            self_url: "http://localhost:3000",
            issuer: "http://localhost:3000/hydra",
        };

        let email = format!("prune-{}@example.com", Uuid::new_v4().simple());
        let body = ory_client::models::CreateIdentityBody::new(
            "default".to_string(),
            serde_json::json!({ "email": email, "name": { "first": "Prune", "last": "Test" } }),
        );
        let created = identity_api::create_identity(&ory.kratos_admin, Some(body))
            .await
            .expect("create unverified identity");
        let id = created.id.clone();
        crate::profiles::set_username(&db, &id, &format!("prune-{}", &id[..8]))
            .await
            .expect("seed profile row");

        let outcome = prune_unverified(&env, 0, Some(&id)).await.expect("prune");
        let _ = std::fs::remove_file(&key_path);
        assert_eq!(
            (outcome.scanned, outcome.deleted, outcome.failed),
            (1, 1, 0),
            "{outcome:?}"
        );
        assert!(outcome.orphans.is_empty(), "{:?}", outcome.orphans);
        assert!(
            crate::ory::kratos::admin_get_identity_optional(&ory, &id)
                .await
                .expect("kratos lookup")
                .is_none(),
            "identity must be gone from Kratos"
        );

        let (profiles, audit) = leftovers(&db, &id).await.expect("query");
        assert_eq!(profiles, 0, "profile row must be removed");
        assert_eq!(
            audit,
            vec![("system".to_string(), Some("unverified-prune".to_string()))]
        );
    }
}
