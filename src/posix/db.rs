//! Diesel queries for the POSIX integration tables (posix_accounts,
//! posix_groups, posix_group_members, ssh_authorized_keys).
//!
//! Mirrors `orgs/db.rs`: every public fn is async (via [`db_interact`]) and
//! returns `anyhow::Result<_>`. uid/gid are conceptually `u32`; diesel maps
//! the `Integer` columns to `i32`, so we cast at the boundary.
#![allow(dead_code)] // wired by the resolver (B2) / admin / provisioning tasks.

use chrono::Utc;
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use crate::db::DbPool;
use crate::db_interact;
use crate::posix::allocate::next_id;
use crate::schema::{
    device_sessions, host_enrollments, offline_secrets, posix_accounts, posix_group_members,
    posix_groups, ssh_authorized_keys,
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
    pub org_id: Option<String>,
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
    pub allowed_gid: Option<i32>,
    pub force_mfa: i32,
    pub created_by: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

// --- reads ---------------------------------------------------------------

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

/// List projection for the host-enrollment admin surface. Deliberately
/// omits `secret_hash` — the admin list never needs it and we don't want
/// the hash flowing through view models.
#[derive(Queryable, Debug, Clone)]
pub struct HostListRow {
    pub id: String,
    pub hostname: String,
    pub allowed_gid: Option<i32>,
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
                host_enrollments::allowed_gid,
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

// all_uids/all_gids are intentionally UNCAPPED (unlike the other list queries):
// id allocation needs the true max, so capping them would break it.
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

/// Every distinct `identity_id` with a posix account row. Uncapped on
/// purpose: the reconcile sweep must see ALL accounts, not a `MAX_ROWS`
/// slice, or it would silently skip orphans past the cap.
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

/// Enabled accounts that are members of `gid`. Powers the resolver's
/// org-scoped `passwd_all`.
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
    org_id: Option<&'a str>,
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
    allowed_gid: Option<i32>,
    force_mfa: i32,
    created_by: Option<&'a str>,
    created_at: String,
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

/// Race-safe account provisioning. Allocates the next free uid/gid, inserts the
/// account, its primary (user-kind) group, and the membership row — all atomically.
///
/// Username, identity, and group-name collisions are *user* errors / idempotency
/// cases, checked up front so they never enter the retry loop. uid/gid are
/// read-derived (`max+1`), so a lost race manifests as a UniqueViolation; we
/// retry, re-reading the maxes each attempt.
pub async fn provision_account(
    db: &DbPool,
    identity_id: &str,
    username: &str,
    uid_base: u32,
    gid_base: u32,
    shell: &str,
    home_dir: &str,
) -> anyhow::Result<PosixAccount> {
    if account_by_username(db, username).await?.is_some() {
        anyhow::bail!("username '{username}' is already taken");
    }
    let existing: Option<String> = {
        let id = identity_id.to_string();
        db_interact!(db, |conn| {
            posix_accounts::table
                .filter(posix_accounts::identity_id.eq(&id))
                .select(posix_accounts::identity_id)
                .first(conn)
                .optional()
        })?
    };
    if existing.is_some() {
        anyhow::bail!("identity '{identity_id}' already has a posix account");
    }
    if group_by_name(db, username).await?.is_some() {
        anyhow::bail!("group name '{username}' is already taken");
    }

    let mut last_err: Option<diesel::result::Error> = None;
    for _ in 0..5 {
        let ident = identity_id.to_string();
        let user = username.to_string();
        let shell = shell.to_string();
        let home = home_dir.to_string();
        let now = Utc::now().to_rfc3339();

        let res: Result<PosixAccount, diesel::result::Error> = db_interact!(db, |conn| {
            conn.transaction::<PosixAccount, diesel::result::Error, _>(|c| {
                // Re-read maxes inside EACH attempt: the next id is derived from
                // them, so a retry after a lost race must observe the winner's row.
                let max_uid: Option<i32> = posix_accounts::table
                    .select(diesel::dsl::max(posix_accounts::uid))
                    .first(c)?;
                let max_gid: Option<i32> = posix_groups::table
                    .select(diesel::dsl::max(posix_groups::gid))
                    .first(c)?;
                let uids: Vec<u32> = max_uid.map(|v| vec![v as u32]).unwrap_or_default();
                let gids: Vec<u32> = max_gid.map(|v| vec![v as u32]).unwrap_or_default();
                let uid = next_id(uid_base, &uids) as i32;
                let gid = next_id(gid_base, &gids) as i32;

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
                        org_id: None,
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
        });

        match res {
            Ok(account) => return Ok(account),
            // sqlite doesn't surface constraint names through diesel, so we can't
            // tell a uid clash from a gid/name clash here; any UniqueViolation is a
            // lost id race → retry (username was pre-checked above). Other errors propagate.
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                info,
            )) => {
                last_err = Some(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    info,
                ));
            }
            Err(e) => return Err(e.into()),
        }
    }
    match last_err {
        Some(e) => {
            Err(anyhow::Error::from(e)
                .context("could not allocate a free uid/gid after 5 attempts"))
        }
        None => anyhow::bail!("provision_account exhausted retries"),
    }
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
/// account's primary (user-kind) group, and the account itself. Idempotent —
/// safe to call when the account row is already gone.
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
            // Delete ONLY this account's primary (user-kind) group — never an
            // org/generic group — keyed by the account's own gid.
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
    allowed_gid: Option<i32>,
    force_mfa: bool,
    created_by: Option<&str>,
) -> anyhow::Result<()> {
    let id = id.to_string();
    let hostname = hostname.to_string();
    let secret_hash = secret_hash.to_string();
    let created_by = created_by.map(str::to_string);
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(host_enrollments::table)
            .values(NewHostEnrollment {
                id: &id,
                hostname: &hostname,
                secret_hash: &secret_hash,
                allowed_gid,
                force_mfa: i32::from(force_mfa),
                created_by: created_by.as_deref(),
                created_at: now.clone(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn delete_host(db: &DbPool, id: &str) -> anyhow::Result<()> {
    let id = id.to_string();
    db_interact!(db, |conn| {
        diesel::delete(host_enrollments::table.filter(host_enrollments::id.eq(&id)))
            .execute(conn)
            .map(|_| ())
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

pub async fn insert_generic_group(db: &DbPool, gid: u32, name: &str) -> anyhow::Result<()> {
    let g = gid as i32;
    let name = name.to_string();
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(posix_groups::table)
            .values(NewPosixGroup {
                gid: g,
                name: &name,
                org_id: None,
                kind: "generic",
                created_at: now.clone(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Ensure an `org`-kind posix group exists for each org the identity belongs
/// to, and that the identity is a member. Idempotent + concurrency-safe: one
/// org → one group (keyed by org_id), shared by all its members.
///
/// `orgs` is a slice of `(org_id, group_name)`. For each org we find-or-create
/// the group keyed by `org_id` (not by name), then add the membership. Both
/// steps swallow the relevant UniqueViolation so concurrent provisions of the
/// same org converge on one group + one membership row.
pub async fn sync_org_groups(
    db: &DbPool,
    gid_base: u32,
    identity_id: &str,
    orgs: &[(String, String)],
) -> anyhow::Result<()> {
    for (org_id, group_name) in orgs {
        let oid = org_id.clone();
        let name = group_name.clone();
        let ident = identity_id.to_string();

        // 1. Find-or-create the org group, keyed by org_id, with a bounded
        //    retry on a lost gid/name race (mirrors provision_account).
        let mut last_err: Option<diesel::result::Error> = None;
        let mut resolved_gid: Option<i32> = None;
        for _ in 0..5 {
            let oid = oid.clone();
            let name = name.clone();
            let res: Result<i32, diesel::result::Error> = db_interact!(db, |conn| {
                conn.transaction::<i32, diesel::result::Error, _>(|c| {
                    let existing: Option<i32> = posix_groups::table
                        .filter(posix_groups::org_id.eq(&oid))
                        .filter(posix_groups::kind.eq("org"))
                        .select(posix_groups::gid)
                        .first(c)
                        .optional()?;
                    if let Some(gid) = existing {
                        return Ok(gid);
                    }
                    // A name collision against an existing NON-org group is a
                    // real conflict — surface it. (UNIQUE on `name`.) The
                    // same-org idempotent case never reaches here: the SELECT
                    // above already returned that row's gid.
                    let by_name: Option<String> = posix_groups::table
                        .filter(posix_groups::name.eq(&name))
                        .select(posix_groups::kind)
                        .first(c)
                        .optional()?;
                    if matches!(by_name, Some(ref kind) if kind != "org") {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    let max_gid: Option<i32> = posix_groups::table
                        .select(diesel::dsl::max(posix_groups::gid))
                        .first(c)?;
                    let gids: Vec<u32> = max_gid.map(|v| vec![v as u32]).unwrap_or_default();
                    let gid = next_id(gid_base, &gids) as i32;
                    let now = Utc::now().to_rfc3339();
                    diesel::insert_into(posix_groups::table)
                        .values(NewPosixGroup {
                            gid,
                            name: &name,
                            org_id: Some(&oid),
                            kind: "org",
                            created_at: now,
                        })
                        .execute(c)?;
                    Ok(gid)
                })
            });
            match res {
                Ok(gid) => {
                    resolved_gid = Some(gid);
                    break;
                }
                // Lost race: another writer created the group (gid or name
                // collision). Re-read by org_id on the next attempt to pick up
                // the winner's gid.
                Err(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    info,
                )) => {
                    last_err = Some(diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::UniqueViolation,
                        info,
                    ));
                }
                // A real name conflict with a non-org group — don't retry.
                Err(diesel::result::Error::RollbackTransaction) => {
                    anyhow::bail!(
                        "posix group name '{group_name}' already taken by a non-org group \
                         (org_id {org_id})"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
        let gid = match resolved_gid {
            Some(g) => g,
            None => {
                return Err(last_err
                    .map(anyhow::Error::from)
                    .unwrap_or_else(|| anyhow::anyhow!("sync_org_groups exhausted retries"))
                    .context("could not resolve an org posix group after 5 attempts"));
            }
        };

        // 2. Add the membership idempotently — swallow the (gid, identity_id)
        //    PK UniqueViolation (already a member → fine).
        let now = Utc::now().to_rfc3339();
        db_interact!(db, |conn| {
            match diesel::insert_into(posix_group_members::table)
                .values(NewGroupMember {
                    gid,
                    identity_id: &ident,
                    added_at: now,
                })
                .execute(conn)
            {
                Ok(_) => Ok(()),
                Err(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                )) => Ok(()),
                Err(e) => Err(e),
            }
        })?;
    }
    Ok(())
}

/// Remove `identity_id` from the `org`-kind posix group mirroring `org_id`.
/// Counterpart to [`sync_org_groups`]: called when org membership is revoked
/// so an org-scoped host stops resolving the ex-member. No-op when no such
/// org group (or membership) exists.
pub async fn remove_identity_from_org_group(
    db: &DbPool,
    org_id: &str,
    identity_id: &str,
) -> anyhow::Result<()> {
    let oid = org_id.to_string();
    let ident = identity_id.to_string();
    db_interact!(db, |conn| {
        let gid: Option<i32> = posix_groups::table
            .filter(posix_groups::org_id.eq(&oid))
            .filter(posix_groups::kind.eq("org"))
            .select(posix_groups::gid)
            .first(conn)
            .optional()?;
        if let Some(gid) = gid {
            diesel::delete(
                posix_group_members::table
                    .filter(posix_group_members::gid.eq(gid))
                    .filter(posix_group_members::identity_id.eq(&ident)),
            )
            .execute(conn)?;
        }
        Ok::<_, diesel::result::Error>(())
    })?;
    Ok(())
}

/// Delete the `org`-kind posix group mirroring `org_id` and all of its
/// membership rows. Called when the org itself is deleted. Transactional,
/// reverse order (members before the group). No-op when no such group exists.
pub async fn delete_org_group(db: &DbPool, org_id: &str) -> anyhow::Result<()> {
    let oid = org_id.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            let gid: Option<i32> = posix_groups::table
                .filter(posix_groups::org_id.eq(&oid))
                .filter(posix_groups::kind.eq("org"))
                .select(posix_groups::gid)
                .first(c)
                .optional()?;
            if let Some(gid) = gid {
                diesel::delete(posix_group_members::table.filter(posix_group_members::gid.eq(gid)))
                    .execute(c)?;
                diesel::delete(posix_groups::table.filter(posix_groups::gid.eq(gid))).execute(c)?;
            }
            Ok(())
        })
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
// One row per device-auth flow the daemon initiates for a host. `device_code`
// is the Hydra-issued bearer secret (PK, never logged); `user_code` is the
// correlation key the verification screen looks up by. Status transitions
// (`pending` → `approved`/`denied`) are atomic single-use UPDATEs so a replay
// or a double-poll can't re-approve. Timestamps are ISO-8601 UTC strings, so
// expiry comparisons are lexicographic-safe (same fixed-width RFC 3339 shape).

/// Terminal/active states a device session can be in. Stored as the raw
/// string in `status`; kept as `&str` consts so the UPDATE guards and the
/// handlers agree on spelling.
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

/// Insert a freshly-minted device session in the `pending` state. `expires_at`
/// is seeded from Hydra's `expires_in` at the call site.
///
/// Returns `Ok(false)` on a `device_code`/`user_code` UNIQUE collision so the
/// caller can reject this init cleanly (Hydra mints both, so a clash is rare —
/// the daemon simply restarts the flow) rather than 500ing on the constraint.
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

/// Atomic single-use approve: flip `pending` → `approved` and stamp the
/// approving identity, but ONLY if the row is still `pending`. Returns
/// `true` iff exactly one row transitioned — so a replay/double-poll that
/// finds the row already terminal gets `false` and must not re-approve.
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

/// Atomic single-use deny: flip `pending` → `denied`, ONLY if still
/// `pending`. Returns `true` iff exactly one row transitioned.
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

/// Opportunistic prune of expired rows (`expires_at < now`). Called on read
/// and folded into the reconcile tick. `now_rfc3339` is compared
/// lexicographically — safe for fixed-width RFC 3339 UTC timestamps. Returns
/// the number of rows removed.
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
// One row per identity that set a dedicated offline passphrase. `verifier` is
// an Argon2id PHC string (see `posix::offline::mint_verifier`); the server
// stores no pepper. Wholesale-replace provisioning ships these to enabled +
// scoped + non-force_mfa hosts; reconcile purges rows for deleted identities.

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

/// Fetch the offline verifiers for a set of identities in one query, returned
/// as `(identity_id, verifier, algo_version)` tuples. Powers the
/// `offline_verifiers` projection so it doesn't issue one query per candidate
/// account. `ids` is the already-scoped candidate set, so it's bounded.
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

/// Every identity id with an offline verifier. Uncapped on purpose: the
/// reconcile sweep must see ALL rows, not a `MAX_ROWS` slice.
pub async fn all_offline_secret_identity_ids(db: &DbPool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<String> = db_interact!(db, |conn| {
        offline_secrets::table
            .select(offline_secrets::identity_id)
            .load(conn)
    })?;
    Ok(rows)
}
