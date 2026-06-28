//! Shared host-scope decision so the resolver and the device-auth endpoints
//! agree EXACTLY on "is this account visible to this host".
//!
//! Scope is org/team based:
//! - No allowed teams: whole-org scoped, any provisioned member of the host's
//!   org is visible.
//! - One or more allowed teams: team scoped (any-of-N), visible iff a
//!   provisioned member of at least one. Each team's org is asserted == the
//!   host's org inside the db helper, so a cross-org team can't widen visibility.

use crate::db::DbPool;
use crate::posix::db;
use crate::posix::host_auth::RequirePosixHost;

/// Is this account visible/authorizable on this host?
pub async fn account_visible_on_host(
    db: &DbPool,
    host: &RequirePosixHost,
    account: &db::PosixAccount,
) -> anyhow::Result<bool> {
    let org = &host.org_id;
    let team_ids = db::host_allowed_team_ids(db, &host.host_id).await?;
    if team_ids.is_empty() {
        return db::is_org_member_provisioned(db, org, &account.identity_id).await;
    }
    for tid in team_ids {
        if db::is_team_member_provisioned(db, org, &tid, &account.identity_id).await? {
            return Ok(true);
        }
    }
    Ok(false)
}
