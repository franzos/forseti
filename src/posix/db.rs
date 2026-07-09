//! Diesel queries for the POSIX integration tables.
//!
//! uid/gid are conceptually `u32`; diesel maps the `Integer` columns to `i32`,
//! so we cast at the boundary.
#![allow(dead_code)]

use chrono::Utc;
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{
    device_sessions, host_allowed_groups, host_enrollments, offline_secrets, posix_accounts,
    posix_group_members, posix_groups, ssh_authorized_keys,
};

/// Hard cap on every unbounded list query here (see `orgs::db::MAX_ROWS_PER_LIST`).
pub const MAX_ROWS_PER_LIST: i64 = 500;

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = posix_accounts)]
pub struct PosixAccount {
    pub identity_id: String,
    pub username: String,
    pub uid: i32,
    pub gid: i32,
    pub gecos: String,
    pub shell: String,
    pub home_dir: String,
    pub enabled: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = posix_groups)]
pub struct PosixGroup {
    pub gid: i32,
    pub name: String,
    pub kind: String,
    pub created_at: String,
}

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = ssh_authorized_keys)]
pub struct SshKey {
    pub id: String,
    pub identity_id: String,
    pub public_key: String,
    pub comment: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = host_enrollments)]
pub struct HostEnrollment {
    pub id: String,
    pub hostname: String,
    pub secret_hash: String,
    pub org_id: String,
    pub force_mfa: i32,
    pub created_by: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

/// A host a provisioned identity can resolve on, plus the org it belongs to.
#[derive(Debug, Clone)]
pub struct HostReach {
    pub hostname: String,
    pub org_id: String,
}

// --- reads ---------------------------------------------------------------

/// Hosts a provisioned identity can resolve on. Requires an ENABLED posix
/// account. A host is reachable iff `host.org_id` is one of the identity's
/// orgs AND the host is whole-org (no scoped teams) OR the identity is in one
/// of the host's scoped teams. Set-based bulk queries intersected in memory,
/// not a per-host live-predicate loop. Sorted by hostname.
pub async fn hosts_reachable_by(db: &DbPool, identity_id: &str) -> anyhow::Result<Vec<HostReach>> {
    use crate::schema::{org_team_members, organization_members};
    use std::collections::{HashMap, HashSet};

    match account_by_identity(db, identity_id).await? {
        Some(a) if a.enabled == 1 => {}
        _ => return Ok(vec![]),
    }

    let org_ids: Vec<String> = {
        let id = identity_id.to_string();
        db_interact!(db, |conn| {
            organization_members::table
                .filter(organization_members::identity_id.eq(&id))
                .select(organization_members::org_id)
                .load(conn)
        })?
    };
    if org_ids.is_empty() {
        return Ok(vec![]);
    }
    let team_ids: Vec<String> = {
        let id = identity_id.to_string();
        db_interact!(db, |conn| {
            org_team_members::table
                .filter(org_team_members::identity_id.eq(&id))
                .select(org_team_members::team_id)
                .load(conn)
        })?
    };

    let hosts: Vec<(String, String, String)> = {
        let orgs = org_ids.clone();
        db_interact!(db, |conn| {
            host_enrollments::table
                .filter(host_enrollments::org_id.eq_any(&orgs))
                .order(host_enrollments::hostname.asc())
                .limit(MAX_ROWS_PER_LIST)
                .select((
                    host_enrollments::id,
                    host_enrollments::hostname,
                    host_enrollments::org_id,
                ))
                .load(conn)
        })?
    };
    if hosts.is_empty() {
        return Ok(vec![]);
    }

    // Team scopes for those hosts; an absent host_id means whole-org.
    let host_ids: Vec<String> = hosts.iter().map(|(id, _, _)| id.clone()).collect();
    let scope_rows: Vec<(String, String)> = db_interact!(db, |conn| {
        host_allowed_groups::table
            .filter(host_allowed_groups::host_id.eq_any(&host_ids))
            .select((host_allowed_groups::host_id, host_allowed_groups::team_id))
            .load(conn)
    })?;
    let mut scoped: HashMap<String, Vec<String>> = HashMap::new();
    for (hid, tid) in scope_rows {
        scoped.entry(hid).or_default().push(tid);
    }
    let my_teams: HashSet<&str> = team_ids.iter().map(String::as_str).collect();

    // Whole-org hosts always reach; scoped hosts need a team hit.
    let out = hosts
        .into_iter()
        .filter(|(hid, _, _)| match scoped.get(hid) {
            None => true,
            Some(teams) => teams.iter().any(|t| my_teams.contains(t.as_str())),
        })
        .map(|(_, hostname, org_id)| HostReach { hostname, org_id })
        .collect();
    Ok(out)
}

pub async fn host_by_id(db: &DbPool, id: &str) -> anyhow::Result<Option<HostEnrollment>> {
    let id = id.to_string();
    let row: Option<HostEnrollment> = db_interact!(db, |conn| {
        host_enrollments::table
            .filter(host_enrollments::id.eq(&id))
            .select(HostEnrollment::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Host-enrollment admin list projection. Omits `secret_hash` so the hash
/// never flows through view models.
#[derive(Queryable, Debug, Clone)]
pub struct HostListRow {
    pub id: String,
    pub hostname: String,
    pub org_id: String,
    pub force_mfa: i32,
    pub created_by: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

pub async fn list_hosts(db: &DbPool) -> anyhow::Result<Vec<HostListRow>> {
    let rows: Vec<HostListRow> = db_interact!(db, |conn| {
        host_enrollments::table
            .order(host_enrollments::created_at.desc())
            .limit(MAX_ROWS_PER_LIST)
            .select((
                host_enrollments::id,
                host_enrollments::hostname,
                host_enrollments::org_id,
                host_enrollments::force_mfa,
                host_enrollments::created_by,
                host_enrollments::created_at,
                host_enrollments::last_seen_at,
            ))
            .load(conn)
    })?;
    Ok(rows)
}

pub async fn touch_last_seen(db: &DbPool, id: &str, now_rfc3339: &str) -> anyhow::Result<()> {
    let id = id.to_string();
    let now = now_rfc3339.to_string();
    db_interact!(db, |conn| {
        diesel::update(host_enrollments::table.filter(host_enrollments::id.eq(&id)))
            .set(host_enrollments::last_seen_at.eq(&now))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// The org a host belongs to.
pub async fn host_org_id(db: &DbPool, host_id: &str) -> anyhow::Result<Option<String>> {
    let id = host_id.to_string();
    Ok(db_interact!(db, |conn| {
        host_enrollments::table
            .filter(host_enrollments::id.eq(&id))
            .select(host_enrollments::org_id)
            .first(conn)
            .optional()
    })?)
}

/// The team uuids a host is scoped to (any-of-N). Empty → whole-org access.
pub async fn host_allowed_team_ids(db: &DbPool, host_id: &str) -> anyhow::Result<Vec<String>> {
    let id = host_id.to_string();
    Ok(db_interact!(db, |conn| {
        host_allowed_groups::table
            .filter(host_allowed_groups::host_id.eq(&id))
            .select(host_allowed_groups::team_id)
            .load(conn)
    })?)
}

/// Atomically replace a host's allowed-team set. Caller MUST have validated
/// every team belongs to the host's org.
pub async fn set_host_allowed_team_ids(
    db: &DbPool,
    host_id: &str,
    team_ids: &[String],
) -> anyhow::Result<()> {
    let (id, teams) = (host_id.to_string(), team_ids.to_vec());
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(host_allowed_groups::table.filter(host_allowed_groups::host_id.eq(&id)))
                .execute(c)?;
            for tid in &teams {
                diesel::insert_into(host_allowed_groups::table)
                    .values(NewHostAllowedGroup {
                        host_id: &id,
                        team_id: tid,
                    })
                    .execute(c)?;
            }
            Ok(())
        })
    })?;
    Ok(())
}

/// Ensure the team has a gid (allocated from the team band on first host-scope)
/// and return it. Idempotent.
pub async fn find_or_create_team_gid(
    db: &DbPool,
    team_id: &str,
    group_gid_base: u32,
) -> anyhow::Result<i32> {
    use crate::schema::org_teams;
    let id = team_id.to_string();
    let existing: Option<Option<i32>> = db_interact!(db, |conn| {
        org_teams::table
            .filter(org_teams::id.eq(&id))
            .select(org_teams::gid)
            .first(conn)
            .optional()
    })?;
    if let Some(Some(gid)) = existing {
        return Ok(gid);
    }
    let gid = crate::posix::sequences::next_in_band(db, "team_gid", group_gid_base).await? as i32;
    let id2 = team_id.to_string();
    // Guarded claim: only a still-null gid may be set, so a lost race can
    // never flip a gid another host already observed.
    let n: usize = db_interact!(db, |conn| {
        diesel::update(
            org_teams::table
                .filter(org_teams::id.eq(&id2))
                .filter(org_teams::gid.is_null()),
        )
        .set(org_teams::gid.eq(gid))
        .execute(conn)
    })?;
    if n == 1 {
        return Ok(gid);
    }
    // Lost the race; return the winner's gid (ours is abandoned, never reused).
    let id3 = team_id.to_string();
    let current: Option<Option<i32>> = db_interact!(db, |conn| {
        org_teams::table
            .filter(org_teams::id.eq(&id3))
            .select(org_teams::gid)
            .first(conn)
            .optional()
    })?;
    match current {
        Some(Some(g)) => Ok(g),
        _ => anyhow::bail!("team '{team_id}' not found while allocating gid"),
    }
}

/// The team (within `org_id`) carrying `gid`, if any.
pub async fn team_by_gid_in_org(
    db: &DbPool,
    org_id: &str,
    gid: u32,
) -> anyhow::Result<Option<crate::orgs::teams::Team>> {
    use crate::orgs::teams::Team;
    use crate::schema::org_teams;
    let (org, g) = (org_id.to_string(), gid as i32);
    Ok(db_interact!(db, |conn| {
        org_teams::table
            .filter(org_teams::org_id.eq(&org))
            .filter(org_teams::gid.eq(g))
            .select(Team::as_select())
            .first(conn)
            .optional()
    })?)
}

/// The team (within `org_id`) whose POSIX name matches, if any.
pub async fn team_by_posix_name_in_org(
    db: &DbPool,
    org_id: &str,
    name: &str,
) -> anyhow::Result<Option<crate::orgs::teams::Team>> {
    for t in crate::orgs::teams::list_teams(db, org_id).await? {
        if crate::posix::allocate::posix_group_name(&t) == name {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

/// Enabled provisioned members of a team, intersected with current org
/// membership. The team is asserted to belong to `org_id`. CAPPED: enumeration
/// only, NEVER a single account's auth decision (use `is_team_member_provisioned`).
pub async fn accounts_in_team(
    db: &DbPool,
    org_id: &str,
    team_id: &str,
) -> anyhow::Result<Vec<PosixAccount>> {
    use crate::schema::{org_team_members, org_teams, organization_members};
    let (org, tid) = (org_id.to_string(), team_id.to_string());
    Ok(db_interact!(db, |conn| {
        posix_accounts::table
            .inner_join(
                org_team_members::table
                    .on(org_team_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .inner_join(
                organization_members::table
                    .on(organization_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(org_team_members::team_id.eq(&tid))
            .filter(
                org_team_members::team_id.eq_any(
                    org_teams::table
                        .filter(org_teams::org_id.eq(&org))
                        .select(org_teams::id),
                ),
            )
            .filter(organization_members::org_id.eq(&org))
            .filter(posix_accounts::enabled.eq(1))
            .order(posix_accounts::username.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(PosixAccount::as_select())
            .load(conn)
    })?)
}

/// Enabled provisioned members of an org (whole-org host access). CAPPED: enumeration only.
pub async fn accounts_in_org(db: &DbPool, org_id: &str) -> anyhow::Result<Vec<PosixAccount>> {
    use crate::schema::organization_members;
    let org = org_id.to_string();
    Ok(db_interact!(db, |conn| {
        posix_accounts::table
            .inner_join(
                organization_members::table
                    .on(organization_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(organization_members::org_id.eq(&org))
            .filter(posix_accounts::enabled.eq(1))
            .order(posix_accounts::username.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(PosixAccount::as_select())
            .load(conn)
    })?)
}

/// UNCAPPED [`accounts_in_team`] for the offline-verifier projection ONLY:
/// the host wholesale-replaces its keystore, so a capped read would silently
/// drop offline credentials for members past the cap.
pub async fn all_accounts_in_team(
    db: &DbPool,
    org_id: &str,
    team_id: &str,
) -> anyhow::Result<Vec<PosixAccount>> {
    use crate::schema::{org_team_members, org_teams, organization_members};
    let (org, tid) = (org_id.to_string(), team_id.to_string());
    Ok(db_interact!(db, |conn| {
        posix_accounts::table
            .inner_join(
                org_team_members::table
                    .on(org_team_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .inner_join(
                organization_members::table
                    .on(organization_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(org_team_members::team_id.eq(&tid))
            .filter(
                org_team_members::team_id.eq_any(
                    org_teams::table
                        .filter(org_teams::org_id.eq(&org))
                        .select(org_teams::id),
                ),
            )
            .filter(organization_members::org_id.eq(&org))
            .filter(posix_accounts::enabled.eq(1))
            .order(posix_accounts::username.asc())
            .select(PosixAccount::as_select())
            .load(conn)
    })?)
}

/// UNCAPPED [`accounts_in_org`] for the offline-verifier projection ONLY: it
/// must be complete or members past the cap lose offline credentials.
pub async fn all_accounts_in_org(db: &DbPool, org_id: &str) -> anyhow::Result<Vec<PosixAccount>> {
    use crate::schema::organization_members;
    let org = org_id.to_string();
    Ok(db_interact!(db, |conn| {
        posix_accounts::table
            .inner_join(
                organization_members::table
                    .on(organization_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(organization_members::org_id.eq(&org))
            .filter(posix_accounts::enabled.eq(1))
            .order(posix_accounts::username.asc())
            .select(PosixAccount::as_select())
            .load(conn)
    })?)
}

/// O(1) existence check for the WHOLE-ORG auth decision. NO cap: a 501st member
/// must still log in.
pub async fn is_org_member_provisioned(
    db: &DbPool,
    org_id: &str,
    identity_id: &str,
) -> anyhow::Result<bool> {
    use crate::schema::organization_members;
    let (org, id) = (org_id.to_string(), identity_id.to_string());
    let found: Option<i32> = db_interact!(db, |conn| {
        posix_accounts::table
            .inner_join(
                organization_members::table
                    .on(organization_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(organization_members::org_id.eq(&org))
            .filter(posix_accounts::identity_id.eq(&id))
            .filter(posix_accounts::enabled.eq(1))
            .select(posix_accounts::uid)
            .first(conn)
            .optional()
    })?;
    Ok(found.is_some())
}

/// O(1) existence check for the TEAM auth decision (team asserted in `org_id`). NO cap.
/// A 501st member must still log in.
pub async fn is_team_member_provisioned(
    db: &DbPool,
    org_id: &str,
    team_id: &str,
    identity_id: &str,
) -> anyhow::Result<bool> {
    use crate::schema::{org_team_members, org_teams, organization_members};
    let (org, tid, id) = (
        org_id.to_string(),
        team_id.to_string(),
        identity_id.to_string(),
    );
    let found: Option<i32> = db_interact!(db, |conn| {
        posix_accounts::table
            .inner_join(
                org_team_members::table
                    .on(org_team_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .inner_join(
                organization_members::table
                    .on(organization_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(org_team_members::team_id.eq(&tid))
            .filter(
                org_team_members::team_id.eq_any(
                    org_teams::table
                        .filter(org_teams::org_id.eq(&org))
                        .select(org_teams::id),
                ),
            )
            .filter(organization_members::org_id.eq(&org))
            .filter(posix_accounts::identity_id.eq(&id))
            .filter(posix_accounts::enabled.eq(1))
            .select(posix_accounts::uid)
            .first(conn)
            .optional()
    })?;
    Ok(found.is_some())
}

/// The account whose PRIMARY gid is `gid` (UPG owner lookup).
pub async fn account_by_primary_gid(db: &DbPool, gid: u32) -> anyhow::Result<Option<PosixAccount>> {
    let g = gid as i32;
    Ok(db_interact!(db, |conn| {
        posix_accounts::table
            .filter(posix_accounts::gid.eq(g))
            .select(PosixAccount::as_select())
            .first(conn)
            .optional()
    })?)
}

/// Count of hosts belonging to an org (org-delete precondition).
pub async fn count_hosts_in_org(db: &DbPool, org_id: &str) -> anyhow::Result<i64> {
    let org = org_id.to_string();
    Ok(db_interact!(db, |conn| {
        host_enrollments::table
            .filter(host_enrollments::org_id.eq(&org))
            .count()
            .get_result(conn)
    })?)
}

/// Enabled-only: a disabled account frees its seat.
pub async fn count_accounts(db: &DbPool) -> anyhow::Result<u32> {
    let n: i64 = db_interact!(db, |conn| {
        posix_accounts::table
            .filter(posix_accounts::enabled.eq(1))
            .count()
            .get_result(conn)
    })?;
    Ok(n.max(0) as u32)
}

// all_uids/all_gids are intentionally UNCAPPED: id allocation needs the true max.
pub async fn all_uids(db: &DbPool) -> anyhow::Result<Vec<u32>> {
    let rows: Vec<i32> = db_interact!(db, |conn| {
        posix_accounts::table.select(posix_accounts::uid).load(conn)
    })?;
    Ok(rows.into_iter().map(|v| v as u32).collect())
}

pub async fn all_gids(db: &DbPool) -> anyhow::Result<Vec<u32>> {
    let rows: Vec<i32> = db_interact!(db, |conn| {
        posix_groups::table.select(posix_groups::gid).load(conn)
    })?;
    Ok(rows.into_iter().map(|v| v as u32).collect())
}

/// Every distinct `identity_id` with a posix account row. Uncapped: the
/// reconcile sweep must see ALL accounts or it would skip orphans past the cap.
pub async fn all_account_identity_ids(db: &DbPool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<String> = db_interact!(db, |conn| {
        posix_accounts::table
            .select(posix_accounts::identity_id)
            .load(conn)
    })?;
    Ok(rows)
}

pub async fn account_by_username(db: &DbPool, name: &str) -> anyhow::Result<Option<PosixAccount>> {
    let n = name.to_string();
    let row: Option<PosixAccount> = db_interact!(db, |conn| {
        posix_accounts::table
            .filter(posix_accounts::username.eq(&n))
            .select(PosixAccount::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn account_by_identity(
    db: &DbPool,
    identity_id: &str,
) -> anyhow::Result<Option<PosixAccount>> {
    let id = identity_id.to_string();
    let row: Option<PosixAccount> = db_interact!(db, |conn| {
        posix_accounts::table
            .filter(posix_accounts::identity_id.eq(&id))
            .select(PosixAccount::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn account_by_uid(db: &DbPool, uid: u32) -> anyhow::Result<Option<PosixAccount>> {
    let u = uid as i32;
    let row: Option<PosixAccount> = db_interact!(db, |conn| {
        posix_accounts::table
            .filter(posix_accounts::uid.eq(u))
            .select(PosixAccount::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn list_enabled_accounts(db: &DbPool) -> anyhow::Result<Vec<PosixAccount>> {
    let rows: Vec<PosixAccount> = db_interact!(db, |conn| {
        posix_accounts::table
            .filter(posix_accounts::enabled.eq(1))
            .order(posix_accounts::username.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(PosixAccount::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

pub async fn group_by_name(db: &DbPool, name: &str) -> anyhow::Result<Option<PosixGroup>> {
    let n = name.to_string();
    let row: Option<PosixGroup> = db_interact!(db, |conn| {
        posix_groups::table
            .filter(posix_groups::name.eq(&n))
            .select(PosixGroup::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn group_by_gid(db: &DbPool, gid: u32) -> anyhow::Result<Option<PosixGroup>> {
    let g = gid as i32;
    let row: Option<PosixGroup> = db_interact!(db, |conn| {
        posix_groups::table
            .filter(posix_groups::gid.eq(g))
            .select(PosixGroup::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn list_groups(db: &DbPool) -> anyhow::Result<Vec<PosixGroup>> {
    let rows: Vec<PosixGroup> = db_interact!(db, |conn| {
        posix_groups::table
            .order(posix_groups::name.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(PosixGroup::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

pub async fn group_member_usernames(db: &DbPool, gid: u32) -> anyhow::Result<Vec<String>> {
    let g = gid as i32;
    let rows: Vec<String> = db_interact!(db, |conn| {
        posix_group_members::table
            .inner_join(
                posix_accounts::table
                    .on(posix_group_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(posix_group_members::gid.eq(g))
            .filter(posix_accounts::enabled.eq(1))
            .order(posix_accounts::username.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(posix_accounts::username)
            .load(conn)
    })?;
    Ok(rows)
}

/// Enabled accounts that are members of a `posix_groups` `gid`. Retained for the
/// user-private-group range; the resolver reads org/team membership at request time.
pub async fn accounts_in_gid(db: &DbPool, gid: u32) -> anyhow::Result<Vec<PosixAccount>> {
    let g = gid as i32;
    let rows: Vec<PosixAccount> = db_interact!(db, |conn| {
        posix_group_members::table
            .inner_join(
                posix_accounts::table
                    .on(posix_group_members::identity_id.eq(posix_accounts::identity_id)),
            )
            .filter(posix_group_members::gid.eq(g))
            .filter(posix_accounts::enabled.eq(1))
            .order(posix_accounts::username.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(PosixAccount::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// Whether `identity_id` is a member of `gid`. The caller checks `enabled`
/// separately on the account row.
pub async fn is_member(db: &DbPool, gid: u32, identity_id: &str) -> anyhow::Result<bool> {
    let g = gid as i32;
    let id = identity_id.to_string();
    let found: Option<i32> = db_interact!(db, |conn| {
        posix_group_members::table
            .filter(posix_group_members::gid.eq(g))
            .filter(posix_group_members::identity_id.eq(&id))
            .select(posix_group_members::gid)
            .first(conn)
            .optional()
    })?;
    Ok(found.is_some())
}

pub async fn authorized_keys_for(db: &DbPool, identity_id: &str) -> anyhow::Result<Vec<SshKey>> {
    let id = identity_id.to_string();
    let rows: Vec<SshKey> = db_interact!(db, |conn| {
        ssh_authorized_keys::table
            .filter(ssh_authorized_keys::identity_id.eq(&id))
            .order(ssh_authorized_keys::created_at.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(SshKey::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

// --- writes --------------------------------------------------------------

#[derive(Insertable)]
#[diesel(table_name = posix_accounts)]
struct NewPosixAccount<'a> {
    identity_id: &'a str,
    username: &'a str,
    uid: i32,
    gid: i32,
    gecos: &'a str,
    shell: &'a str,
    home_dir: &'a str,
    enabled: i32,
    created_at: String,
    updated_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = posix_groups)]
struct NewPosixGroup<'a> {
    gid: i32,
    name: &'a str,
    kind: &'a str,
    created_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = posix_group_members)]
struct NewGroupMember<'a> {
    gid: i32,
    identity_id: &'a str,
    added_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = host_enrollments)]
struct NewHostEnrollment<'a> {
    id: &'a str,
    hostname: &'a str,
    secret_hash: &'a str,
    org_id: &'a str,
    force_mfa: i32,
    created_by: Option<&'a str>,
    created_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = host_allowed_groups)]
struct NewHostAllowedGroup<'a> {
    host_id: &'a str,
    team_id: &'a str,
}

#[derive(Insertable)]
#[diesel(table_name = ssh_authorized_keys)]
struct NewSshKey<'a> {
    id: &'a str,
    identity_id: &'a str,
    public_key: &'a str,
    comment: &'a str,
    created_at: String,
    expires_at: Option<&'a str>,
}

/// Atomically insert an account, its primary (user-kind) group, and the
/// membership row, taking uid/user-gid from the never-colliding sequence
/// allocator. uid/gid come from `posix_sequences`, so there's no id race to
/// retry; username/identity/group-name collisions are checked up front.
pub async fn provision_account(
    db: &DbPool,
    identity_id: &str,
    username: &str,
    uid_base: u32,
    user_gid_base: u32,
    shell: &str,
    home_dir: &str,
) -> anyhow::Result<PosixAccount> {
    if account_by_username(db, username).await?.is_some() {
        anyhow::bail!("username '{username}' is already taken");
    }
    if account_by_identity(db, identity_id).await?.is_some() {
        anyhow::bail!("identity '{identity_id}' already has a posix account");
    }
    if group_by_name(db, username).await?.is_some() {
        anyhow::bail!("group name '{username}' is already taken");
    }
    let uid = crate::posix::sequences::next_in_band(db, "uid", uid_base).await? as i32;
    let gid = crate::posix::sequences::next_in_band(db, "user_gid", user_gid_base).await? as i32;

    let ident = identity_id.to_string();
    let user = username.to_string();
    let shell = shell.to_string();
    let home = home_dir.to_string();
    let now = Utc::now().to_rfc3339();
    let account: PosixAccount = db_interact!(db, |conn| {
        conn.transaction::<PosixAccount, diesel::result::Error, _>(|c| {
            diesel::insert_into(posix_accounts::table)
                .values(NewPosixAccount {
                    identity_id: &ident,
                    username: &user,
                    uid,
                    gid,
                    gecos: "",
                    shell: &shell,
                    home_dir: &home,
                    enabled: 1,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                })
                .execute(c)?;
            diesel::insert_into(posix_groups::table)
                .values(NewPosixGroup {
                    gid,
                    name: &user,
                    kind: "user",
                    created_at: now.clone(),
                })
                .execute(c)?;
            diesel::insert_into(posix_group_members::table)
                .values(NewGroupMember {
                    gid,
                    identity_id: &ident,
                    added_at: now.clone(),
                })
                .execute(c)?;
            posix_accounts::table
                .filter(posix_accounts::identity_id.eq(&ident))
                .select(PosixAccount::as_select())
                .first(c)
        })
    })?;
    Ok(account)
}

pub async fn set_account_enabled(
    db: &DbPool,
    identity_id: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let id = identity_id.to_string();
    let flag = i32::from(enabled);
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::update(posix_accounts::table.filter(posix_accounts::identity_id.eq(&id)))
            .set((
                posix_accounts::enabled.eq(flag),
                posix_accounts::updated_at.eq(&now),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Cascade-delete every POSIX row tied to `identity_id`: keys, memberships, the
/// account's primary (user-kind) group, and the account itself. Idempotent.
pub async fn delete_account_rows(db: &DbPool, identity_id: &str) -> anyhow::Result<()> {
    let id = identity_id.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(
                ssh_authorized_keys::table.filter(ssh_authorized_keys::identity_id.eq(&id)),
            )
            .execute(c)?;
            diesel::delete(
                posix_group_members::table.filter(posix_group_members::identity_id.eq(&id)),
            )
            .execute(c)?;
            // Delete ONLY this account's primary (user-kind) group, never an
            // org/generic group, keyed by the account's own gid.
            let primary_gid: Option<i32> = posix_accounts::table
                .filter(posix_accounts::identity_id.eq(&id))
                .select(posix_accounts::gid)
                .first(c)
                .optional()?;
            if let Some(gid) = primary_gid {
                diesel::delete(
                    posix_groups::table
                        .filter(posix_groups::gid.eq(gid))
                        .filter(posix_groups::kind.eq("user")),
                )
                .execute(c)?;
            }
            diesel::delete(posix_accounts::table.filter(posix_accounts::identity_id.eq(&id)))
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

pub async fn insert_host(
    db: &DbPool,
    id: &str,
    hostname: &str,
    secret_hash: &str,
    org_id: &str,
    force_mfa: bool,
    created_by: Option<&str>,
) -> anyhow::Result<()> {
    let id = id.to_string();
    let hostname = hostname.to_string();
    let secret_hash = secret_hash.to_string();
    let org_id = org_id.to_string();
    let created_by = created_by.map(str::to_string);
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(host_enrollments::table)
            .values(NewHostEnrollment {
                id: &id,
                hostname: &hostname,
                secret_hash: &secret_hash,
                org_id: &org_id,
                force_mfa: i32::from(force_mfa),
                created_by: created_by.as_deref(),
                created_at: now.clone(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn update_host(
    db: &DbPool,
    id: &str,
    hostname: &str,
    force_mfa: bool,
) -> anyhow::Result<()> {
    let id = id.to_string();
    let hostname = hostname.to_string();
    db_interact!(db, |conn| {
        diesel::update(host_enrollments::table.filter(host_enrollments::id.eq(&id)))
            .set((
                host_enrollments::hostname.eq(&hostname),
                host_enrollments::force_mfa.eq(i32::from(force_mfa)),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn delete_host(db: &DbPool, id: &str) -> anyhow::Result<()> {
    let id = id.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(device_sessions::table.filter(device_sessions::host_id.eq(&id)))
                .execute(c)?;
            diesel::delete(host_allowed_groups::table.filter(host_allowed_groups::host_id.eq(&id)))
                .execute(c)?;
            diesel::delete(host_enrollments::table.filter(host_enrollments::id.eq(&id)))
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

/// Replace a host's secret hash. Returns rows affected so the caller can
/// distinguish "rotated" from "no such host".
pub async fn rotate_host_secret(
    db: &DbPool,
    id: &str,
    new_secret_hash: &str,
) -> anyhow::Result<usize> {
    let id = id.to_string();
    let hash = new_secret_hash.to_string();
    let n: usize = db_interact!(db, |conn| {
        diesel::update(host_enrollments::table.filter(host_enrollments::id.eq(&id)))
            .set(host_enrollments::secret_hash.eq(&hash))
            .execute(conn)
    })?;
    Ok(n)
}

pub async fn insert_ssh_key(
    db: &DbPool,
    identity_id: &str,
    public_key: &str,
    comment: &str,
    expires_at: Option<&str>,
) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let ident = identity_id.to_string();
    let key = public_key.to_string();
    let comment = comment.to_string();
    let expires = expires_at.map(str::to_string);
    let now = Utc::now().to_rfc3339();
    let inserted = id.clone();
    db_interact!(db, |conn| {
        diesel::insert_into(ssh_authorized_keys::table)
            .values(NewSshKey {
                id: &id,
                identity_id: &ident,
                public_key: &key,
                comment: &comment,
                created_at: now.clone(),
                expires_at: expires.as_deref(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(inserted)
}

pub async fn delete_ssh_key(db: &DbPool, id: &str) -> anyhow::Result<()> {
    let id = id.to_string();
    db_interact!(db, |conn| {
        diesel::delete(ssh_authorized_keys::table.filter(ssh_authorized_keys::id.eq(&id)))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn add_group_member(db: &DbPool, gid: u32, identity_id: &str) -> anyhow::Result<()> {
    let g = gid as i32;
    let ident = identity_id.to_string();
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(posix_group_members::table)
            .values(NewGroupMember {
                gid: g,
                identity_id: &ident,
                added_at: now.clone(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

// --- device sessions (RFC 8628 device-auth state) ------------------------
//
// `device_code` is the Hydra-issued bearer secret (PK, never logged). Status
// transitions are atomic single-use UPDATEs so a replay or double-poll can't
// re-approve. Timestamps are fixed-width RFC 3339 UTC, so expiry comparisons
// are lexicographic-safe.

/// Status consts kept as `&str` so the UPDATE guards and handlers agree on spelling.
pub mod device_status {
    pub const PENDING: &str = "pending";
    pub const APPROVED: &str = "approved";
    pub const DENIED: &str = "denied";
}

#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = device_sessions)]
pub struct DeviceSession {
    pub device_code: String,
    pub user_code: String,
    pub host_id: String,
    pub requested_username: String,
    pub status: String,
    pub identity_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = device_sessions)]
struct NewDeviceSession<'a> {
    device_code: &'a str,
    user_code: &'a str,
    host_id: &'a str,
    requested_username: &'a str,
    status: &'a str,
    created_at: String,
    expires_at: &'a str,
}

/// Insert a `pending` device session. Returns `Ok(false)` on a
/// `device_code`/`user_code` UNIQUE collision so the caller rejects the init
/// cleanly (daemon restarts the flow) rather than 500ing on the constraint.
pub async fn insert_device_session(
    db: &DbPool,
    device_code: &str,
    user_code: &str,
    host_id: &str,
    requested_username: &str,
    expires_at: &str,
) -> anyhow::Result<bool> {
    let dc = device_code.to_string();
    let uc = user_code.to_string();
    let host = host_id.to_string();
    let user = requested_username.to_string();
    let exp = expires_at.to_string();
    let now = Utc::now().to_rfc3339();
    let res: Result<(), diesel::result::Error> = db_interact!(db, |conn| {
        diesel::insert_into(device_sessions::table)
            .values(NewDeviceSession {
                device_code: &dc,
                user_code: &uc,
                host_id: &host,
                requested_username: &user,
                status: device_status::PENDING,
                created_at: now,
                expires_at: &exp,
            })
            .execute(conn)
            .map(|_| ())
    });
    match res {
        Ok(()) => Ok(true),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn device_session_by_code(
    db: &DbPool,
    device_code: &str,
) -> anyhow::Result<Option<DeviceSession>> {
    let dc = device_code.to_string();
    let row: Option<DeviceSession> = db_interact!(db, |conn| {
        device_sessions::table
            .filter(device_sessions::device_code.eq(&dc))
            .select(DeviceSession::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn device_session_by_user_code(
    db: &DbPool,
    user_code: &str,
) -> anyhow::Result<Option<DeviceSession>> {
    let uc = user_code.to_string();
    let row: Option<DeviceSession> = db_interact!(db, |conn| {
        device_sessions::table
            .filter(device_sessions::user_code.eq(&uc))
            .select(DeviceSession::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Atomic single-use approve: flip `pending` to `approved` and stamp the
/// approving identity, ONLY if still `pending`. Returns `true` iff exactly one
/// row transitioned, so a replay that finds it terminal gets `false` and must
/// not re-approve.
pub async fn approve_device_session(
    db: &DbPool,
    device_code: &str,
    identity_id: &str,
) -> anyhow::Result<bool> {
    let dc = device_code.to_string();
    let id = identity_id.to_string();
    let n: usize = db_interact!(db, |conn| {
        diesel::update(
            device_sessions::table
                .filter(device_sessions::device_code.eq(&dc))
                .filter(device_sessions::status.eq(device_status::PENDING)),
        )
        .set((
            device_sessions::status.eq(device_status::APPROVED),
            device_sessions::identity_id.eq(&id),
        ))
        .execute(conn)
    })?;
    Ok(n == 1)
}

/// Atomic single-use deny: flip `pending` to `denied`, ONLY if still `pending`.
/// Returns `true` iff exactly one row transitioned.
pub async fn deny_device_session(db: &DbPool, device_code: &str) -> anyhow::Result<bool> {
    let dc = device_code.to_string();
    let n: usize = db_interact!(db, |conn| {
        diesel::update(
            device_sessions::table
                .filter(device_sessions::device_code.eq(&dc))
                .filter(device_sessions::status.eq(device_status::PENDING)),
        )
        .set(device_sessions::status.eq(device_status::DENIED))
        .execute(conn)
    })?;
    Ok(n == 1)
}

/// Opportunistic prune of expired rows (`expires_at < now`). `now_rfc3339` is
/// compared lexicographically, safe for fixed-width RFC 3339 UTC timestamps.
pub async fn lazy_prune_expired(db: &DbPool, now_rfc3339: &str) -> anyhow::Result<usize> {
    let now = now_rfc3339.to_string();
    let n: usize = db_interact!(db, |conn| {
        diesel::delete(device_sessions::table.filter(device_sessions::expires_at.lt(&now)))
            .execute(conn)
    })?;
    Ok(n)
}

// --- offline secrets (M3a offline-auth verifiers) ------------------------
//
// `verifier` is an Argon2id PHC string (see `posix::offline::mint_verifier`);
// the server stores no pepper. Provisioning ships these to enabled + scoped +
// non-force_mfa hosts; reconcile purges rows for deleted identities.

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = offline_secrets)]
pub struct OfflineSecretRow {
    pub identity_id: String,
    pub verifier: String,
    pub algo_version: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = offline_secrets)]
struct NewOfflineSecret<'a> {
    identity_id: &'a str,
    verifier: &'a str,
    algo_version: i32,
    created_at: String,
    updated_at: String,
}

/// Set-or-replace an identity's offline verifier. `created_at` is preserved on
/// conflict; only `verifier`, `algo_version`, and `updated_at` change.
pub async fn upsert_offline_secret(
    db: &DbPool,
    identity_id: &str,
    verifier: &str,
    algo_version: i32,
) -> anyhow::Result<()> {
    let id = identity_id.to_string();
    let v = verifier.to_string();
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(offline_secrets::table)
            .values(NewOfflineSecret {
                identity_id: &id,
                verifier: &v,
                algo_version,
                created_at: now.clone(),
                updated_at: now.clone(),
            })
            .on_conflict(offline_secrets::identity_id)
            .do_update()
            .set((
                offline_secrets::verifier.eq(&v),
                offline_secrets::algo_version.eq(algo_version),
                offline_secrets::updated_at.eq(&now),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn get_offline_secret(
    db: &DbPool,
    identity_id: &str,
) -> anyhow::Result<Option<OfflineSecretRow>> {
    let id = identity_id.to_string();
    let row: Option<OfflineSecretRow> = db_interact!(db, |conn| {
        offline_secrets::table
            .filter(offline_secrets::identity_id.eq(&id))
            .select(OfflineSecretRow::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Clear an identity's offline verifier. Returns `true` iff a row was removed,
/// so the caller can distinguish "cleared" from "never set".
pub async fn delete_offline_secret(db: &DbPool, identity_id: &str) -> anyhow::Result<bool> {
    let id = identity_id.to_string();
    let n: usize = db_interact!(db, |conn| {
        diesel::delete(offline_secrets::table.filter(offline_secrets::identity_id.eq(&id)))
            .execute(conn)
    })?;
    Ok(n > 0)
}

/// Offline verifiers for a set of identities in one query, as
/// `(identity_id, verifier, algo_version)`. `ids` is the already-scoped
/// candidate set, so it's bounded.
pub async fn offline_secrets_for_identities(
    db: &DbPool,
    ids: Vec<String>,
) -> anyhow::Result<Vec<(String, String, i32)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<(String, String, i32)> = db_interact!(db, |conn| {
        offline_secrets::table
            .filter(offline_secrets::identity_id.eq_any(&ids))
            .select((
                offline_secrets::identity_id,
                offline_secrets::verifier,
                offline_secrets::algo_version,
            ))
            .load(conn)
    })?;
    Ok(rows)
}

/// Every identity id with an offline verifier. Uncapped: the reconcile sweep
/// must see ALL rows.
pub async fn all_offline_secret_identity_ids(db: &DbPool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<String> = db_interact!(db, |conn| {
        offline_secrets::table
            .select(offline_secrets::identity_id)
            .load(conn)
    })?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use crate::orgs::teams;
    use crate::orgs::{self, Role};

    async fn temp_pool() -> DbPool {
        let path = std::env::temp_dir().join(format!("forseti-posix-{}.db", Uuid::new_v4()));
        let db = DbPool::init(&DatabaseConfig {
            url: format!("sqlite://{}", path.display()),
            skip_migrations: true,
        })
        .expect("pool");
        db.run_migrations().await.expect("migrate");
        db
    }

    async fn provision(db: &DbPool, identity: &str, username: &str) {
        provision_account(db, identity, username, 10_000, 20_000, "/bin/bash", "/home")
            .await
            .expect("provision");
    }

    #[tokio::test]
    async fn hosts_reachable_by_intersects_org_and_team_scopes() {
        let db = temp_pool().await;
        provision(&db, "alice", "alice").await;
        orgs::db::add_member_race_safe(&db, "alice", "orgA", Role::Member)
            .await
            .unwrap();

        let t1 = teams::create_team(&db, "orgA", "Platform", None)
            .await
            .unwrap();
        let t2 = teams::create_team(&db, "orgA", "Security", None)
            .await
            .unwrap();
        teams::add_member(&db, &t1.id, "alice").await.unwrap();

        insert_host(&db, "h-whole", "whole.example", "x", "orgA", false, None)
            .await
            .unwrap();
        insert_host(&db, "h-t1", "t1.example", "x", "orgA", false, None)
            .await
            .unwrap();
        set_host_allowed_team_ids(&db, "h-t1", std::slice::from_ref(&t1.id))
            .await
            .unwrap();
        insert_host(&db, "h-t2", "t2.example", "x", "orgA", false, None)
            .await
            .unwrap();
        set_host_allowed_team_ids(&db, "h-t2", std::slice::from_ref(&t2.id))
            .await
            .unwrap();
        // foreign-org host: alice is not a member of orgB.
        insert_host(
            &db,
            "h-foreign",
            "foreign.example",
            "x",
            "orgB",
            false,
            None,
        )
        .await
        .unwrap();

        let reach: Vec<String> = hosts_reachable_by(&db, "alice")
            .await
            .unwrap()
            .into_iter()
            .map(|h| h.hostname)
            .collect();
        // whole-org + team-scoped-she's-in, sorted by hostname; NOT t2, NOT foreign.
        assert_eq!(reach, vec!["t1.example", "whole.example"]);

        // no posix account → empty.
        orgs::db::add_member_race_safe(&db, "bob", "orgA", Role::Member)
            .await
            .unwrap();
        assert!(hosts_reachable_by(&db, "bob").await.unwrap().is_empty());

        // disabled account → empty.
        set_account_enabled(&db, "alice", false).await.unwrap();
        assert!(hosts_reachable_by(&db, "alice").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn team_gid_is_allocated_once_and_never_flips() {
        let db = temp_pool().await;
        let t = teams::create_team(&db, "orgA", "Platform", None)
            .await
            .unwrap();

        let first = find_or_create_team_gid(&db, &t.id, 3_000_000)
            .await
            .unwrap();
        assert!(first >= 3_000_000);
        let second = find_or_create_team_gid(&db, &t.id, 3_000_000)
            .await
            .unwrap();
        assert_eq!(first, second);

        // Unknown team must error, never hand out an unstored gid.
        assert!(find_or_create_team_gid(&db, "no-such-team", 3_000_000)
            .await
            .is_err());
    }
}
