//! Shared host-scope decision for the POSIX surface. The resolver and the
//! M2 device-auth endpoints must agree EXACTLY on "is this account visible to
//! this host", so the decision lives here once instead of being reimplemented.

use crate::db::DbPool;
use crate::posix::db;
use crate::posix::host_auth::RequirePosixHost;

/// Is this account visible/authorizable to this host under M1's scoping?
///
/// - Unscoped host (`allowed_gid` `None`) → any account is visible (`true`).
/// - Scoped host → the `allowed_gid` must be a `kind="org"` group AND the
///   account must be a member of it. A misconfigured `allowed_gid` (missing /
///   not org) fails closed (`false`).
///
/// `enabled`-agnostic by design: callers check `account.enabled` separately,
/// matching how the resolver composes the decision (the `enabled == 1` filter
/// happens on the account lookup before the scope check is reached).
pub async fn account_visible_on_host(
    db: &DbPool,
    host: &RequirePosixHost,
    account: &db::PosixAccount,
) -> anyhow::Result<bool> {
    let Some(gid) = host.allowed_gid else {
        return Ok(true);
    };
    // Re-assert the stored allowed_gid is an org group every time — never trust
    // it alone (defense in depth, mirrors the resolver's `resolve_scope`).
    match db::group_by_gid(db, gid).await? {
        Some(g) if g.kind == "org" => {}
        _ => {
            tracing::warn!(
                host_id = %host.host_id,
                gid,
                "posix scope: host's allowed_gid is missing or not an org group; failing closed"
            );
            return Ok(false);
        }
    }
    db::is_member(db, gid, &account.identity_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use crate::posix::db::PosixAccount;

    fn dummy_account() -> PosixAccount {
        PosixAccount {
            identity_id: "id-1".into(),
            username: "alice".into(),
            uid: 1000,
            gid: 1000,
            gecos: String::new(),
            shell: "/bin/bash".into(),
            home_dir: "/home/alice".into(),
            enabled: 1,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn memory_pool() -> DbPool {
        DbPool::init(&DatabaseConfig {
            url: "sqlite://:memory:".into(),
            skip_migrations: true,
        })
        .expect("in-memory sqlite pool")
    }

    // Unscoped host (allowed_gid None) → any account is visible. Short-circuits
    // before any DB query, so the in-memory pool is never touched.
    //
    // The org-reassert + membership branches require a live DB; their
    // behavioral coverage is the resolver integration tests
    // (tests/integration/posix.rs: resolver_scoped_host_enforces_gid,
    // resolver_unscoped_host_basic_lookups), which still drive this path.
    #[tokio::test]
    async fn unscoped_host_sees_any_account() {
        let db = memory_pool();
        let host = RequirePosixHost {
            host_id: "host-1".into(),
            allowed_gid: None,
            force_mfa: false,
        };
        let account = dummy_account();
        assert!(account_visible_on_host(&db, &host, &account)
            .await
            .expect("unscoped check"));
    }
}
