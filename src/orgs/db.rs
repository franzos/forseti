//! Diesel queries for the organizations / organization_members /
//! organization_invites tables.

use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use diesel::prelude::*;
use serde::Serialize;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{
    host_allowed_groups, org_allowed_domains, org_logos, org_team_members, org_teams,
    organization_invites, organization_members, organizations, saml_connections, saml_links,
};

/// `support_email` + `logo_url` override the global `[brand]` config when set.
// `created_by` is selected by `as_select()` but not read at runtime.
#[allow(dead_code)]
#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = organizations)]
pub struct Org {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub support_email: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
    pub member_visibility: String,
    pub theme_preset: Option<String>,
    pub brand_primary: Option<String>,
    pub brand_on_primary: Option<String>,
    pub brand_secondary: Option<String>,
    pub public_login_enabled: i32,
    pub has_logo: i32,
    pub access_mode: String,
    pub domain_join_policy: String,
}

// `added_by` is selected by `as_select()` but not read at runtime.
#[allow(dead_code)]
#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = organization_members)]
pub struct OrgMember {
    pub org_id: String,
    pub identity_id: String,
    pub role: String,
    pub added_at: String,
    pub added_by: Option<String>,
    pub hidden_from_directory: i32,
}

/// Org + role view-model for the nav dropdown; carries name + slug per row.
/// The brand columns ride along so authenticated chrome can theme by the
/// active org without a second query.
#[derive(Debug, Clone, Serialize)]
pub struct Membership {
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub role: String,
    pub theme_preset: Option<String>,
    pub brand_primary: Option<String>,
    pub brand_on_primary: Option<String>,
    pub brand_secondary: Option<String>,
    pub has_logo: i32,
}

// `invited_by` / `accepted_by` are selected by `as_select()` but not read.
#[allow(dead_code)]
#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = organization_invites)]
pub struct OrgInvite {
    pub token: String,
    pub org_id: String,
    pub email: String,
    pub role: String,
    pub invited_by: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub accepted_at: Option<String>,
    pub accepted_by: Option<String>,
}

impl OrgInvite {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|t| t < now)
            .unwrap_or(true)
    }

    pub fn is_accepted(&self) -> bool {
        self.accepted_at.is_some()
    }
}

/// Defence-in-depth cap on every unbounded list query in this module; pages
/// needing more rows must paginate explicitly.
pub const MAX_ROWS_PER_LIST: i64 = 500;

// --- reads ---------------------------------------------------------------

pub async fn count_orgs(db: &DbPool) -> anyhow::Result<u32> {
    let n: i64 = db_interact!(db, |conn| { organizations::table.count().get_result(conn) })?;
    Ok(n.max(0) as u32)
}

pub async fn org_by_slug(db: &DbPool, slug: &str) -> anyhow::Result<Option<Org>> {
    let s = slug.to_string();
    let row: Option<Org> = db_interact!(db, |conn| {
        organizations::table
            .filter(organizations::slug.eq(&s))
            .select(Org::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn list_orgs(db: &DbPool) -> anyhow::Result<Vec<Org>> {
    let rows: Vec<Org> = db_interact!(db, |conn| {
        organizations::table
            .order(organizations::name.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(Org::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

pub async fn org_by_id(db: &DbPool, id: &str) -> anyhow::Result<Option<Org>> {
    let s = id.to_string();
    let row: Option<Org> = db_interact!(db, |conn| {
        organizations::table
            .filter(organizations::id.eq(&s))
            .select(Org::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn list_memberships(db: &DbPool, identity_id: &str) -> anyhow::Result<Vec<Membership>> {
    list_memberships_limited(db, identity_id, MAX_ROWS_PER_LIST).await
}

/// [`list_memberships`] with a caller-supplied row cap, pushed into SQL so a
/// large membership set isn't loaded just to be truncated in-memory.
pub async fn list_memberships_limited(
    db: &DbPool,
    identity_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<Membership>> {
    let id = identity_id.to_string();
    let rows: Vec<(OrgMember, Org)> = db_interact!(db, |conn| {
        organization_members::table
            .inner_join(organizations::table)
            .filter(organization_members::identity_id.eq(&id))
            .order(organization_members::added_at.asc())
            .limit(limit)
            .select((OrgMember::as_select(), Org::as_select()))
            .load(conn)
    })?;
    let mut out: Vec<Membership> = rows
        .into_iter()
        .map(|(m, o)| Membership {
            org_id: m.org_id,
            slug: o.slug,
            name: o.name,
            role: m.role,
            theme_preset: o.theme_preset,
            brand_primary: o.brand_primary,
            brand_on_primary: o.brand_on_primary,
            brand_secondary: o.brand_secondary,
            has_logo: o.has_logo,
        })
        .collect();
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

/// Both facts the Default floor decision needs, in a single query: whether the
/// identity already holds the Default membership, and how many non-default
/// memberships it holds. Count is over `organization_members` only, never team
/// membership. Capped read + in-memory split (this runs on every authenticated
/// request for the whole Default-only population).
pub async fn floor_membership_facts(
    db: &DbPool,
    identity_id: &str,
) -> anyhow::Result<(bool, usize)> {
    let i = identity_id.to_string();
    let org_ids: Vec<String> = db_interact!(db, |conn| {
        organization_members::table
            .filter(organization_members::identity_id.eq(&i))
            .limit(MAX_ROWS_PER_LIST)
            .select(organization_members::org_id)
            .load::<String>(conn)
    })?;
    let default_present = org_ids.iter().any(|id| id == super::DEFAULT_ORG_ID);
    let non_default_count = org_ids
        .iter()
        .filter(|id| id.as_str() != super::DEFAULT_ORG_ID)
        .count();
    Ok((default_present, non_default_count))
}

pub async fn find_member(
    db: &DbPool,
    identity_id: &str,
    org_id: &str,
) -> anyhow::Result<Option<OrgMember>> {
    let i = identity_id.to_string();
    let o = org_id.to_string();
    let row: Option<OrgMember> = db_interact!(db, |conn| {
        organization_members::table
            .filter(organization_members::identity_id.eq(&i))
            .filter(organization_members::org_id.eq(&o))
            .select(OrgMember::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn list_members(db: &DbPool, org_id: &str) -> anyhow::Result<Vec<OrgMember>> {
    list_members_paged(db, org_id, MAX_ROWS_PER_LIST, 0).await
}

/// Paginated `list_members`. Orders by `added_at` then `identity_id` so the
/// page boundary is stable when `added_at` ties.
pub async fn list_members_paged(
    db: &DbPool,
    org_id: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<OrgMember>> {
    let o = org_id.to_string();
    let rows: Vec<OrgMember> = db_interact!(db, |conn| {
        organization_members::table
            .filter(organization_members::org_id.eq(&o))
            .order((
                organization_members::added_at.asc(),
                organization_members::identity_id.asc(),
            ))
            .limit(limit)
            .offset(offset)
            .select(OrgMember::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// Pairs each member with their Kratos email trait via one bulk `ids` call,
/// then an in-memory join.
pub async fn list_member_profiles(
    db: &DbPool,
    ory: &Arc<crate::ory::OryClients>,
    org_id: &str,
) -> anyhow::Result<Vec<(OrgMember, String, String)>> {
    let members = list_members(db, org_id).await?;
    if members.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = members.iter().map(|m| m.identity_id.clone()).collect();
    let identities = crate::ory::kratos::admin_list_identities_by_ids(ory, ids)
        .await
        .unwrap_or_default();
    let by_id: std::collections::HashMap<&str, &serde_json::Value> = identities
        .iter()
        .filter_map(|id| id.traits.as_ref().map(|t| (id.id.as_str(), t)))
        .collect();
    Ok(members
        .into_iter()
        .map(|m| {
            let traits = by_id.get(m.identity_id.as_str());
            let email = traits
                .and_then(|t| t.get("email").and_then(|v| v.as_str()))
                .map(str::to_string)
                .unwrap_or_default();
            let first = traits
                .and_then(|t| t.get("name").and_then(|n| n.get("first")))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let last = traits
                .and_then(|t| t.get("name").and_then(|n| n.get("last")))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let display_name = match (first.is_empty(), last.is_empty()) {
                (true, true) => String::new(),
                (false, true) => first.to_string(),
                (true, false) => last.to_string(),
                (false, false) => format!("{first} {last}"),
            };
            (m, email, display_name)
        })
        .collect())
}

// --- writes --------------------------------------------------------------

#[derive(Insertable)]
#[diesel(table_name = organizations)]
struct NewOrg<'a> {
    id: &'a str,
    slug: &'a str,
    name: &'a str,
    created_at: String,
    created_by: Option<&'a str>,
}

pub async fn create_org(
    db: &DbPool,
    id: &str,
    slug: &str,
    name: &str,
    created_by: Option<&str>,
) -> anyhow::Result<()> {
    let id = id.to_string();
    let slug = slug.to_string();
    let name = name.to_string();
    let created_by = created_by.map(str::to_string);
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(organizations::table)
            .values(NewOrg {
                id: &id,
                slug: &slug,
                name: &name,
                created_at: now.clone(),
                created_by: created_by.as_deref(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn update_branding(
    db: &DbPool,
    org_id: &str,
    name: &str,
    slug: &str,
    logo_url: Option<&str>,
    support_email: Option<&str>,
) -> anyhow::Result<()> {
    let id = org_id.to_string();
    let name = name.to_string();
    let slug = slug.to_string();
    let logo_url = logo_url.map(str::to_string);
    let support_email = support_email.map(str::to_string);
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set((
                organizations::name.eq(&name),
                organizations::slug.eq(&slug),
                organizations::logo_url.eq(logo_url.clone()),
                organizations::support_email.eq(support_email.clone()),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn update_theme(
    db: &DbPool,
    org_id: &str,
    preset: Option<&str>,
    primary: Option<&str>,
    on_primary: Option<&str>,
    secondary: Option<&str>,
    public_login_enabled: i32,
) -> anyhow::Result<()> {
    let id = org_id.to_string();
    let preset = preset.map(str::to_string);
    let primary = primary.map(str::to_string);
    let on_primary = on_primary.map(str::to_string);
    let secondary = secondary.map(str::to_string);
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set((
                organizations::theme_preset.eq(preset.clone()),
                organizations::brand_primary.eq(primary.clone()),
                organizations::brand_on_primary.eq(on_primary.clone()),
                organizations::brand_secondary.eq(secondary.clone()),
                organizations::public_login_enabled.eq(public_login_enabled),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn set_access_mode(
    db: &DbPool,
    org_id: &str,
    mode: crate::orgs::AccessMode,
) -> anyhow::Result<()> {
    let id = org_id.to_string();
    let mode = mode.as_str().to_string();
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set(organizations::access_mode.eq(&mode))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Sets the internal org's domain-join policy (`invite_only` | `auto_join`).
/// Mirrors [`set_access_mode`]; the caller (settings page) gates it to
/// non-Default Internal orgs.
pub async fn set_domain_join_policy(
    db: &DbPool,
    org_id: &str,
    policy: crate::orgs::DomainJoinPolicy,
) -> anyhow::Result<()> {
    let id = org_id.to_string();
    let policy = policy.as_str().to_string();
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set(organizations::domain_join_policy.eq(&policy))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Test-only raw writer for an arbitrary `domain_join_policy` string, so the
/// fail-closed parse can be exercised with a value the typed writer can't emit.
#[cfg(test)]
pub(crate) async fn set_domain_join_policy_raw(
    db: &DbPool,
    org_id: &str,
    value: &str,
) -> anyhow::Result<()> {
    let id = org_id.to_string();
    let v = value.to_string();
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set(organizations::domain_join_policy.eq(&v))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Sets the external-mode defaults (§4) at org creation and at the
/// Internal->External switch: admins-only directory + public login on.
/// Admins-only is subsequently hard-enforced in the member-visibility
/// handler; public login stays togglable so an owner can pause signups.
pub async fn apply_external_defaults(db: &DbPool, org_id: &str) -> anyhow::Result<()> {
    let id = org_id.to_string();
    let visibility = crate::orgs::visibility::MemberVisibility::AdminsOnly
        .as_str()
        .to_string();
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set((
                organizations::member_visibility.eq(&visibility),
                organizations::public_login_enabled.eq(1),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn set_public_login_enabled(
    db: &DbPool,
    org_id: &str,
    enabled: i32,
) -> anyhow::Result<()> {
    let id = org_id.to_string();
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set(organizations::public_login_enabled.eq(enabled))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Pre-auth-readable projection of an org's public branding. Excludes
/// `support_email` and members; readers only return a row when the org
/// has opted in (`public_login_enabled=1`). `slug` + `has_logo` let callers
/// point themed chrome at `/branding/{slug}/logo` without a second query.
#[derive(Queryable, Debug, Clone, Serialize)]
pub struct PublicBranding {
    pub name: String,
    pub slug: String,
    pub preset: Option<String>,
    pub primary: Option<String>,
    pub on_primary: Option<String>,
    pub secondary: Option<String>,
    pub has_logo: i32,
    pub access_mode: String,
}

pub async fn public_branding_by_id(
    db: &DbPool,
    id: &str,
) -> anyhow::Result<Option<PublicBranding>> {
    let i = id.to_string();
    let row: Option<PublicBranding> = db_interact!(db, |conn| {
        organizations::table
            .filter(organizations::id.eq(&i))
            .filter(organizations::public_login_enabled.eq(1))
            .select((
                organizations::name,
                organizations::slug,
                organizations::theme_preset,
                organizations::brand_primary,
                organizations::brand_on_primary,
                organizations::brand_secondary,
                organizations::has_logo,
                organizations::access_mode,
            ))
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn public_branding_by_slug(
    db: &DbPool,
    slug: &str,
) -> anyhow::Result<Option<PublicBranding>> {
    let s = slug.to_string();
    let row: Option<PublicBranding> = db_interact!(db, |conn| {
        organizations::table
            .filter(organizations::slug.eq(&s))
            .filter(organizations::public_login_enabled.eq(1))
            .select((
                organizations::name,
                organizations::slug,
                organizations::theme_preset,
                organizations::brand_primary,
                organizations::brand_on_primary,
                organizations::brand_secondary,
                organizations::has_logo,
                organizations::access_mode,
            ))
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Bulk-deletes an org and its membership rows. Members whose only non-default
/// org was this one are re-homed to the Default floor lazily on their next
/// authenticated request (M1: this path relies on the lazy floor, not an inline
/// re-add).
pub async fn delete_org(db: &DbPool, org_id: &str) -> anyhow::Result<()> {
    let id = org_id.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(
                organization_members::table.filter(organization_members::org_id.eq(&id)),
            )
            .execute(c)?;
            diesel::delete(
                organization_invites::table.filter(organization_invites::org_id.eq(&id)),
            )
            .execute(c)?;
            // App-level cascade (no FK): purge SAML email links + the
            // connection before the org row so neither is orphaned.
            diesel::delete(saml_links::table.filter(saml_links::org_id.eq(&id))).execute(c)?;
            diesel::delete(saml_connections::table.filter(saml_connections::org_id.eq(&id)))
                .execute(c)?;
            let team_ids: Vec<String> = org_teams::table
                .filter(org_teams::org_id.eq(&id))
                .select(org_teams::id)
                .load(c)?;
            if !team_ids.is_empty() {
                diesel::delete(
                    org_team_members::table.filter(org_team_members::team_id.eq_any(&team_ids)),
                )
                .execute(c)?;
                diesel::delete(
                    host_allowed_groups::table
                        .filter(host_allowed_groups::team_id.eq_any(&team_ids)),
                )
                .execute(c)?;
                diesel::delete(org_teams::table.filter(org_teams::id.eq_any(&team_ids)))
                    .execute(c)?;
            }
            diesel::delete(org_logos::table.filter(org_logos::org_id.eq(&id))).execute(c)?;
            // A surviving verified row would permanently occupy the global
            // partial-unique index, blocking re-verification of that domain
            // by any org.
            diesel::delete(org_allowed_domains::table.filter(org_allowed_domains::org_id.eq(&id)))
                .execute(c)?;
            diesel::delete(organizations::table.filter(organizations::id.eq(&id))).execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

#[derive(Insertable)]
#[diesel(table_name = organization_members)]
struct NewMember<'a> {
    org_id: &'a str,
    identity_id: &'a str,
    role: &'a str,
    added_at: String,
    added_by: Option<&'a str>,
}

/// Run `$body` (a `Result<_, diesel::result::Error>` block naming the
/// connection `$c`) in one serialized transaction. SQLite uses BEGIN IMMEDIATE
/// so a read-then-write txn grabs the write lock up front (a deferred BEGIN
/// upgrades reader->writer and returns SQLITE_BUSY immediately, bypassing
/// busy_timeout); Postgres (MVCC) uses a plain transaction.
macro_rules! serialized_txn {
    ($db:expr, $c:ident, $body:block) => {{
        match $db {
            DbPool::Sqlite(pool) => {
                let conn = pool
                    .get()
                    .await
                    .map_err(|e| anyhow::anyhow!("sqlite pool: {e}"))?;
                conn.interact(move |$c: &mut diesel::sqlite::SqliteConnection| {
                    $c.immediate_transaction::<_, diesel::result::Error, _>(|$c| $body)
                })
                .await
                .map_err(|e| anyhow::anyhow!("sqlite interact: {e}"))??;
            }
            DbPool::Postgres(pool) => {
                let conn = pool
                    .get()
                    .await
                    .map_err(|e| anyhow::anyhow!("postgres pool: {e}"))?;
                conn.interact(move |$c: &mut diesel::pg::PgConnection| {
                    $c.transaction::<_, diesel::result::Error, _>(|$c| $body)
                })
                .await
                .map_err(|e| anyhow::anyhow!("postgres interact: {e}"))??;
            }
        }
    }};
}

/// Atomically add the non-allowlisted Default floor row: insert Default as
/// `Member` iff the identity holds zero non-default memberships, checked inside
/// the same serialized txn (H4 — the count and the insert must not interleave
/// with a concurrent tenant join). Idempotent on a duplicate Default insert, so
/// an allowlisted operator's existing Default `Owner` row survives unchanged.
/// Also serves the leave path's re-add: a genuine last-leave leaves zero
/// non-default rows, so the same "insert Default Member iff count==0" applies.
pub async fn add_default_floor_member_txn(db: &DbPool, identity_id: &str) -> anyhow::Result<()> {
    let ident = identity_id.to_string();
    let now = Utc::now().to_rfc3339();
    serialized_txn!(db, c, {
        let non_default: i64 = organization_members::table
            .filter(organization_members::identity_id.eq(&ident))
            .filter(organization_members::org_id.ne(super::DEFAULT_ORG_ID))
            .count()
            .get_result(c)?;
        if non_default == 0 {
            match diesel::insert_into(organization_members::table)
                .values(NewMember {
                    org_id: super::DEFAULT_ORG_ID,
                    identity_id: &ident,
                    role: super::Role::Member.as_str(),
                    added_at: now.clone(),
                    added_by: None,
                })
                .execute(c)
            {
                Ok(_) => {}
                Err(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                )) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });
    Ok(())
}

/// Race-safe non-default join that maintains the Default floor: in one
/// serialized txn, insert the tenant membership then (for non-allowlisted
/// identities: `drop_default = true`) delete the Default row, in that order
/// (H4). Allowlisted operators pass `drop_default = false` and keep Default.
/// Idempotent on a duplicate tenant insert. The delete is a no-op for a Default
/// `org_id`, so this can never remove the very row it just inserted.
pub async fn join_org_race_safe(
    db: &DbPool,
    identity_id: &str,
    org_id: &str,
    role: super::Role,
    drop_default: bool,
) -> anyhow::Result<()> {
    let ident = identity_id.to_string();
    let org = org_id.to_string();
    let role_s = role.as_str();
    let now = Utc::now().to_rfc3339();
    serialized_txn!(db, c, {
        match diesel::insert_into(organization_members::table)
            .values(NewMember {
                org_id: &org,
                identity_id: &ident,
                role: role_s,
                added_at: now.clone(),
                added_by: None,
            })
            .execute(c)
        {
            Ok(_) => {}
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {}
            Err(e) => return Err(e),
        }
        if drop_default && org != super::DEFAULT_ORG_ID {
            diesel::delete(
                organization_members::table
                    .filter(organization_members::identity_id.eq(&ident))
                    .filter(organization_members::org_id.eq(super::DEFAULT_ORG_ID)),
            )
            .execute(c)?;
        }
        Ok(())
    });
    Ok(())
}

/// Race-safe membership insert for any org (self-serve external join, and
/// eventually domain auto-join). No owner-promotion — that stays Default-only
/// (a first external joiner becoming owner would be a privilege bug) — so a
/// single INSERT with the unique constraint as the race guard is enough.
pub async fn add_member_race_safe(
    db: &DbPool,
    identity_id: &str,
    org_id: &str,
    role: super::Role,
) -> anyhow::Result<()> {
    let ident = identity_id.to_string();
    let org = org_id.to_string();
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        match diesel::insert_into(organization_members::table)
            .values(NewMember {
                org_id: &org,
                identity_id: &ident,
                role: role.as_str(),
                added_at: now.clone(),
                added_by: None,
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
    Ok(())
}

pub async fn remove_member(db: &DbPool, org_id: &str, identity_id: &str) -> anyhow::Result<()> {
    let org = org_id.to_string();
    let ident = identity_id.to_string();
    db_interact!(db, |conn| {
        diesel::delete(
            organization_members::table
                .filter(organization_members::org_id.eq(&org))
                .filter(organization_members::identity_id.eq(&ident)),
        )
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}

/// Drop every membership row for `identity_id` across all orgs, so a deleted
/// identity leaves no dangling rows (which would trip the last-owner guard
/// with phantom owners). Returns the number of rows removed.
//
// Org-team membership lives in `org_team_members`, not `posix_group_members`,
// so this also purges team rows via `teams::remove_identity_from_all_teams`.
pub async fn remove_member_everywhere(db: &DbPool, identity_id: &str) -> anyhow::Result<usize> {
    let ident = identity_id.to_string();
    let affected = db_interact!(db, |conn| {
        diesel::delete(
            organization_members::table.filter(organization_members::identity_id.eq(&ident)),
        )
        .execute(conn)
    })?;
    if let Err(e) = super::teams::remove_identity_from_all_teams(db, identity_id).await {
        tracing::error!(error = ?e, identity_id, "failed to purge org-team membership on identity delete");
    }
    Ok(affected)
}

/// An org would be left ungovernable by this identity's departure iff the
/// identity is the *sole* owner and at least one other member remains. A solo
/// org (only member) and a co-owned org are both fine to leave.
pub(crate) fn blocks_self_deletion(owners: i64, members: i64) -> bool {
    owners == 1 && members > 1
}

/// Orgs where `identity_id` is the sole owner AND another member exists,
/// returned as `(org_id, org_name)` to block account self-deletion. A solo
/// org (sole owner, no other members) is intentionally not returned.
///
/// Two grouped count queries instead of a `FILTER` keep this backend-agnostic
/// across sqlite/postgres.
pub async fn orgs_where_sole_owner_with_other_members(
    db: &DbPool,
    identity_id: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    use diesel::dsl::count_star;

    let ident = identity_id.to_string();
    db_interact!(db, |conn| {
        let owned: Vec<String> = organization_members::table
            .filter(organization_members::identity_id.eq(&ident))
            .filter(organization_members::role.eq(super::Role::Owner.as_str()))
            .limit(MAX_ROWS_PER_LIST)
            .select(organization_members::org_id)
            .load::<String>(conn)?;
        if owned.is_empty() {
            return Ok(Vec::new());
        }

        let owner_counts: Vec<(String, i64)> = organization_members::table
            .filter(organization_members::org_id.eq_any(&owned))
            .filter(organization_members::role.eq(super::Role::Owner.as_str()))
            .group_by(organization_members::org_id)
            .select((organization_members::org_id, count_star()))
            .load::<(String, i64)>(conn)?;
        let member_counts: Vec<(String, i64)> = organization_members::table
            .filter(organization_members::org_id.eq_any(&owned))
            .group_by(organization_members::org_id)
            .select((organization_members::org_id, count_star()))
            .load::<(String, i64)>(conn)?;

        use std::collections::HashMap;
        let owners: HashMap<String, i64> = owner_counts.into_iter().collect();
        let members: HashMap<String, i64> = member_counts.into_iter().collect();

        let blocking: Vec<String> = owned
            .into_iter()
            .filter(|org_id| {
                blocks_self_deletion(
                    owners.get(org_id).copied().unwrap_or(0),
                    members.get(org_id).copied().unwrap_or(0),
                )
            })
            .collect();
        if blocking.is_empty() {
            return Ok(Vec::new());
        }

        organizations::table
            .filter(organizations::id.eq_any(&blocking))
            .select((organizations::id, organizations::name))
            .load::<(String, String)>(conn)
    })
    .map_err(Into::into)
}

pub async fn update_role(
    db: &DbPool,
    org_id: &str,
    identity_id: &str,
    role: super::Role,
) -> anyhow::Result<()> {
    let org = org_id.to_string();
    let ident = identity_id.to_string();
    let role_s = role.as_str().to_string();
    db_interact!(db, |conn| {
        diesel::update(
            organization_members::table
                .filter(organization_members::org_id.eq(&org))
                .filter(organization_members::identity_id.eq(&ident)),
        )
        .set(organization_members::role.eq(&role_s))
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}

pub async fn set_member_visibility(
    db: &DbPool,
    org_id: &str,
    v: crate::orgs::visibility::MemberVisibility,
) -> anyhow::Result<()> {
    let (id, val) = (org_id.to_string(), v.as_str().to_string());
    db_interact!(db, |conn| {
        diesel::update(organizations::table.filter(organizations::id.eq(&id)))
            .set(organizations::member_visibility.eq(&val))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn set_member_hidden(
    db: &DbPool,
    org_id: &str,
    identity_id: &str,
    hidden: bool,
) -> anyhow::Result<()> {
    let (oid, iid) = (org_id.to_string(), identity_id.to_string());
    let flag = i32::from(hidden);
    db_interact!(db, |conn| {
        diesel::update(
            organization_members::table
                .filter(organization_members::org_id.eq(&oid))
                .filter(organization_members::identity_id.eq(&iid)),
        )
        .set(organization_members::hidden_from_directory.eq(flag))
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}

// --- invites -------------------------------------------------------------

#[derive(Insertable)]
#[diesel(table_name = organization_invites)]
struct NewInvite<'a> {
    token: &'a str,
    org_id: &'a str,
    email: &'a str,
    role: &'a str,
    invited_by: Option<&'a str>,
    created_at: String,
    expires_at: String,
}

pub async fn insert_invite(
    db: &DbPool,
    token: &str,
    org_id: &str,
    email: &str,
    role: super::Role,
    invited_by: Option<&str>,
    ttl_days: i64,
) -> anyhow::Result<()> {
    let token = token.to_string();
    let org = org_id.to_string();
    let email = email.to_string();
    let role_s = role.as_str();
    let invited_by = invited_by.map(str::to_string);
    let now = Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now + ChronoDuration::days(ttl_days)).to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(organization_invites::table)
            .values(NewInvite {
                token: &token,
                org_id: &org,
                email: &email,
                role: role_s,
                invited_by: invited_by.as_deref(),
                created_at: created_at.clone(),
                expires_at: expires_at.clone(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn fetch_invite(db: &DbPool, token: &str) -> anyhow::Result<Option<OrgInvite>> {
    let t = token.to_string();
    let row: Option<OrgInvite> = db_interact!(db, |conn| {
        organization_invites::table
            .filter(organization_invites::token.eq(&t))
            .select(OrgInvite::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn list_org_invites(db: &DbPool, org_id: &str) -> anyhow::Result<Vec<OrgInvite>> {
    let o = org_id.to_string();
    let rows: Vec<OrgInvite> = db_interact!(db, |conn| {
        organization_invites::table
            .filter(organization_invites::org_id.eq(&o))
            .filter(organization_invites::accepted_at.is_null())
            .order(organization_invites::created_at.desc())
            .limit(MAX_ROWS_PER_LIST)
            .select(OrgInvite::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// Outcome of [`finalize_invite_txn`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteFinalizeOutcome {
    /// Membership row written and invite stamped accepted.
    Accepted,
    /// Invite already accepted before this txn ran; no write happened.
    AlreadyAccepted,
}

/// Atomically write the membership row (if missing) and stamp the invite
/// accepted. Returns [`InviteFinalizeOutcome::AlreadyAccepted`] (no state
/// change) when the invite was already used.
///
/// The `UPDATE ... WHERE accepted_at IS NULL` pattern is the concurrency
/// guard: zero rows affected means a concurrent caller already accepted. The
/// membership insert's unique `(org_id, identity_id)` swallows the duplicate.
pub async fn finalize_invite_txn(
    db: &DbPool,
    token: &str,
    org_id: &str,
    identity_id: &str,
    role: super::Role,
    drop_default: bool,
) -> anyhow::Result<InviteFinalizeOutcome> {
    let token = token.to_string();
    let org = org_id.to_string();
    let ident = identity_id.to_string();
    let role_s = role.as_str();
    let now = Utc::now().to_rfc3339();
    let outcome = db_interact!(db, |conn| {
        conn.transaction::<InviteFinalizeOutcome, diesel::result::Error, _>(|c| {
            // Swallow the unique-constraint violation (ON CONFLICT DO NOTHING
            // equivalent) so the txn doesn't abort when already a member.
            match diesel::insert_into(organization_members::table)
                .values(NewMember {
                    org_id: &org,
                    identity_id: &ident,
                    role: role_s,
                    added_at: now.clone(),
                    added_by: None,
                })
                .execute(c)
            {
                Ok(_) => {}
                Err(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                )) => {
                    // Already a member; proceed to stamp the invite accepted.
                }
                Err(e) => return Err(e),
            }

            // Maintain the Default floor: a non-allowlisted invitee joining a
            // tenant org drops Default in the same txn (insert-then-delete).
            if drop_default && org != super::DEFAULT_ORG_ID {
                diesel::delete(
                    organization_members::table
                        .filter(organization_members::identity_id.eq(&ident))
                        .filter(organization_members::org_id.eq(super::DEFAULT_ORG_ID)),
                )
                .execute(c)?;
            }

            // Only the writer observing `accepted_at IS NULL` updates a row;
            // zero rows means a concurrent (or prior) caller already accepted.
            let affected = diesel::update(
                organization_invites::table
                    .filter(organization_invites::token.eq(&token))
                    .filter(organization_invites::accepted_at.is_null()),
            )
            .set((
                organization_invites::accepted_at.eq(Some(now.clone())),
                organization_invites::accepted_by.eq(Some(ident.clone())),
            ))
            .execute(c)?;
            if affected == 0 {
                return Ok(InviteFinalizeOutcome::AlreadyAccepted);
            }
            Ok(InviteFinalizeOutcome::Accepted)
        })
    })?;
    Ok(outcome)
}

// --- slug helpers --------------------------------------------------------

/// Slugs that would shadow a top-level route (`/o`, `/admin`, ...) if an org
/// claimed them. Checked at create time; never enforced retroactively.
pub const RESERVED_SLUGS: &[&str] = &[
    "o",
    "admin",
    "login",
    "logout",
    "register",
    "registration",
    "oauth",
    "oauth2",
    "static",
    "settings",
    "consent",
    "error",
    "api",
    "well-known",
];

pub fn is_reserved_slug(slug: &str) -> bool {
    RESERVED_SLUGS.contains(&slug)
}

/// Auto-generate a URL-safe slug from a human-readable name. Drops anything
/// that isn't `[a-z0-9-]`; collapses runs of dashes; trims leading/trailing
/// dashes. Empty result falls back to `"org"`.
pub fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        let lower = ch.to_ascii_lowercase();
        let push = if lower.is_ascii_alphanumeric() {
            prev_dash = false;
            lower
        } else if !prev_dash {
            prev_dash = true;
            '-'
        } else {
            continue;
        };
        out.push(push);
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "org".to_string()
    } else {
        trimmed
    }
}

/// Suggest a unique slug from `name`, appending `-2`, `-3`, ... on collision.
/// The `LIKE` prefix is safe: `base` comes from `slugify`, so `[a-z0-9-]+`.
pub async fn suggest_slug(db: &DbPool, name: &str) -> anyhow::Result<String> {
    let base = slugify(name);
    let prefix = format!("{base}%");
    let existing: Vec<String> = db_interact!(db, |conn| {
        organizations::table
            .filter(organizations::slug.like(&prefix))
            .order(organizations::slug.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(organizations::slug)
            .load(conn)
    })?;
    let taken: std::collections::HashSet<String> = existing.into_iter().collect();
    if !taken.contains(&base) && !is_reserved_slug(&base) {
        return Ok(base);
    }
    for n in 2..=1000 {
        let candidate = format!("{base}-{n}");
        if !taken.contains(&candidate) && !is_reserved_slug(&candidate) {
            return Ok(candidate);
        }
    }
    anyhow::bail!("could not find a free slug after 1000 attempts")
}

/// Single-connection `:memory:` pool: sqlite's `:memory:` database lives
/// only on the connection that created it, so the pool must never hand out
/// a second connection or the migrated schema disappears. Shared across
/// `orgs::db` and sibling test modules (e.g. `orgs::logo`).
#[cfg(test)]
pub(crate) async fn test_pool() -> DbPool {
    use deadpool_diesel::sqlite::{Manager, Pool, Runtime};
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    const TEST_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

    let manager = Manager::new(":memory:", Runtime::Tokio1);
    let pool = Pool::builder(manager)
        .max_size(1)
        .build()
        .expect("build test sqlite pool");
    let conn = pool.get().await.expect("get test conn");
    conn.interact(|c: &mut diesel::sqlite::SqliteConnection| {
        c.run_pending_migrations(TEST_MIGRATIONS).map(|_| ())
    })
    .await
    .expect("interact panic")
    .expect("run test migrations");
    DbPool::Sqlite(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::{Role, DEFAULT_ORG_ID};
    use chrono::TimeZone;

    #[tokio::test]
    async fn set_access_mode_persists_external() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None).await.unwrap();
        set_access_mode(&db, "o1", crate::orgs::AccessMode::External)
            .await
            .unwrap();
        let row = org_by_id(&db, "o1").await.unwrap().unwrap();
        assert_eq!(row.access_mode, "external");
    }

    #[tokio::test]
    async fn apply_external_defaults_enforces_admins_only_and_public_login() {
        let db = test_pool().await;
        create_org(&db, "o2", "acme2", "Acme2", None).await.unwrap();
        apply_external_defaults(&db, "o2").await.unwrap();
        let row = org_by_id(&db, "o2").await.unwrap().unwrap();
        assert_eq!(row.member_visibility, "admins_only");
        assert_eq!(row.public_login_enabled, 1);
    }

    #[tokio::test]
    async fn set_public_login_enabled_toggles_flag() {
        let db = test_pool().await;
        create_org(&db, "o3", "acme3", "Acme3", None).await.unwrap();
        set_public_login_enabled(&db, "o3", 1).await.unwrap();
        assert_eq!(
            org_by_id(&db, "o3")
                .await
                .unwrap()
                .unwrap()
                .public_login_enabled,
            1
        );
        set_public_login_enabled(&db, "o3", 0).await.unwrap();
        assert_eq!(
            org_by_id(&db, "o3")
                .await
                .unwrap()
                .unwrap()
                .public_login_enabled,
            0
        );
    }

    #[tokio::test]
    async fn internal_to_external_transition_applies_all_guardrails() {
        let db = test_pool().await;
        create_org(&db, "o4", "acme4", "Acme4", None).await.unwrap();
        set_access_mode(&db, "o4", crate::orgs::AccessMode::External)
            .await
            .unwrap();
        apply_external_defaults(&db, "o4").await.unwrap();
        let row = org_by_id(&db, "o4").await.unwrap().unwrap();
        assert_eq!(row.access_mode, "external");
        assert_eq!(row.member_visibility, "admins_only");
        assert_eq!(row.public_login_enabled, 1);
    }

    #[tokio::test]
    async fn external_to_internal_leaves_member_visibility_alone() {
        let db = test_pool().await;
        create_org(&db, "o5", "acme5", "Acme5", None).await.unwrap();
        set_access_mode(&db, "o5", crate::orgs::AccessMode::External)
            .await
            .unwrap();
        apply_external_defaults(&db, "o5").await.unwrap();
        set_access_mode(&db, "o5", crate::orgs::AccessMode::Internal)
            .await
            .unwrap();
        set_public_login_enabled(&db, "o5", 0).await.unwrap();
        let row = org_by_id(&db, "o5").await.unwrap().unwrap();
        assert_eq!(row.access_mode, "internal");
        assert_eq!(row.public_login_enabled, 0);
        assert_eq!(
            row.member_visibility, "admins_only",
            "External->Internal must not loosen visibility"
        );
    }

    #[tokio::test]
    async fn public_branding_hidden_until_enabled() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None)
            .await
            .expect("create_org");

        // Not yet enabled: hidden.
        update_theme(&db, "o1", Some("classic"), Some("#111827"), None, None, 0)
            .await
            .expect("update_theme");
        let hidden = public_branding_by_slug(&db, "acme")
            .await
            .expect("query by_slug");
        assert!(hidden.is_none());

        update_theme(&db, "o1", Some("classic"), Some("#111827"), None, None, 1)
            .await
            .expect("update_theme");
        let visible = public_branding_by_slug(&db, "acme")
            .await
            .expect("query by_slug")
            .expect("branding should be visible once enabled");
        assert_eq!(visible.name, "Acme");
        assert_eq!(visible.slug, "acme");
        assert_eq!(visible.preset.as_deref(), Some("classic"));
        assert_eq!(visible.primary.as_deref(), Some("#111827"));
        assert_eq!(visible.has_logo, 0);
        assert_eq!(visible.access_mode, "internal");

        let by_id = public_branding_by_id(&db, "o1")
            .await
            .expect("query by_id")
            .expect("branding should be visible by id too");
        assert_eq!(by_id.name, "Acme");
        assert_eq!(by_id.access_mode, "internal");
    }

    fn invite_with_expiry(expires_at: &str) -> OrgInvite {
        OrgInvite {
            token: "t".to_string(),
            org_id: "o".to_string(),
            email: "a@b.c".to_string(),
            role: "member".to_string(),
            invited_by: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            accepted_at: None,
            accepted_by: None,
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 19, 12, 0, 0).unwrap()
    }

    #[test]
    fn invite_is_expired_past() {
        let inv = invite_with_expiry("2026-01-01T00:00:00Z");
        assert!(inv.is_expired(now()));
    }

    #[test]
    fn sole_owner_with_other_members_blocks() {
        assert!(blocks_self_deletion(1, 2));
    }

    #[test]
    fn solo_org_does_not_block() {
        assert!(!blocks_self_deletion(1, 1));
    }

    #[test]
    fn co_owned_org_does_not_block() {
        assert!(!blocks_self_deletion(2, 3));
    }

    #[test]
    fn invite_is_expired_future() {
        let inv = invite_with_expiry("2026-12-31T00:00:00Z");
        assert!(!inv.is_expired(now()));
    }

    #[test]
    fn invite_is_expired_malformed_treated_as_expired() {
        let inv = invite_with_expiry("not-a-date");
        // Bad timestamps fail closed to "expired".
        assert!(inv.is_expired(now()));
    }

    #[test]
    fn slugify_basic() {
        assert_eq!(slugify("Acme Co"), "acme-co");
        assert_eq!(slugify("Already-Lower"), "already-lower");
    }

    #[test]
    fn slugify_collapses_separators() {
        assert_eq!(slugify("Hello,   World!!!"), "hello-world");
        assert_eq!(slugify("a---b"), "a-b");
    }

    #[test]
    fn slugify_handles_unicode_by_dropping() {
        let s = slugify("Café Münchën");
        assert!(s.starts_with("caf"));
        assert!(s.contains('-'));
        assert!(!s.starts_with('-') && !s.ends_with('-'));
    }

    #[test]
    fn slugify_edge_cases() {
        assert_eq!(slugify(""), "org");
        assert_eq!(slugify("!!!"), "org");
        assert_eq!(slugify("---hi---"), "hi");
    }

    #[tokio::test]
    async fn delete_org_purges_the_logo_blob() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None)
            .await
            .expect("create_org");
        let bytes = b"fake-png-bytes".to_vec();
        let etag = crate::orgs::logo::etag_of(&bytes);
        crate::orgs::logo::upsert(&db, "o1", bytes, "image/png", &etag)
            .await
            .expect("upsert logo");

        delete_org(&db, "o1").await.expect("delete_org");

        assert!(
            crate::orgs::logo::get(&db, "o1")
                .await
                .expect("get")
                .is_none(),
            "logo blob should be deleted alongside the org"
        );
    }

    #[tokio::test]
    async fn delete_org_purges_allowed_domains() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None).await.unwrap();
        crate::orgs::domains::add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        crate::orgs::domains::mark_domain_verified(&db, "o1", "acme.com")
            .await
            .unwrap();

        delete_org(&db, "o1").await.expect("delete_org");

        // The verified row must not survive: it would otherwise hold the global
        // partial-unique index and block any org from re-verifying acme.com.
        create_org(&db, "o2", "acme-inc", "Acme Inc", None)
            .await
            .unwrap();
        crate::orgs::domains::add_pending_domain(&db, "o2", "acme.com", "dns_txt", "tok2", None)
            .await
            .unwrap();
        assert_eq!(
            crate::orgs::domains::mark_domain_verified(&db, "o2", "acme.com")
                .await
                .unwrap(),
            crate::orgs::domains::DomainVerifyOutcome::Verified
        );
    }

    #[tokio::test]
    async fn add_member_race_safe_inserts_member_role() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None).await.unwrap();
        add_member_race_safe(&db, "ident-1", "o1", crate::orgs::Role::Member)
            .await
            .unwrap();
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", "o1").await,
            Some(crate::orgs::Role::Member)
        );
    }

    #[tokio::test]
    async fn add_member_race_safe_swallows_duplicate_insert() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None).await.unwrap();
        add_member_race_safe(&db, "ident-1", "o1", crate::orgs::Role::Member)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", "o1", crate::orgs::Role::Member)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn suggest_slug_skips_reserved_words() {
        let db = test_pool().await;
        let slug = suggest_slug(&db, "Admin").await.expect("suggest_slug");
        assert!(
            !is_reserved_slug(&slug),
            "suggested a reserved slug: {slug}"
        );
        assert_eq!(slug, "admin-2");
    }

    // --- Default floor: single-query facts, atomic add, join+drop, leave ---

    async fn in_default(db: &DbPool, ident: &str) -> bool {
        crate::orgs::org_role(db, ident, DEFAULT_ORG_ID)
            .await
            .is_some()
    }

    #[tokio::test]
    async fn floor_membership_facts_splits_default_from_tenant() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Member)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", "acme-id", Role::Member)
            .await
            .unwrap();
        let (default_present, non_default) = floor_membership_facts(&db, "ident-1").await.unwrap();
        assert!(default_present);
        assert_eq!(non_default, 1);
    }

    #[tokio::test]
    async fn add_default_floor_member_txn_adds_when_member_less() {
        let db = test_pool().await;
        add_default_floor_member_txn(&db, "ident-1").await.unwrap();
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Member)
        );
    }

    #[tokio::test]
    async fn add_default_floor_member_txn_skips_when_holding_tenant() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", "acme-id", Role::Member)
            .await
            .unwrap();
        add_default_floor_member_txn(&db, "ident-1").await.unwrap();
        assert!(!in_default(&db, "ident-1").await);
    }

    #[tokio::test]
    async fn join_org_race_safe_drops_default_when_flagged() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Member)
            .await
            .unwrap();
        join_org_race_safe(&db, "ident-1", "acme-id", Role::Member, true)
            .await
            .unwrap();
        assert!(!in_default(&db, "ident-1").await);
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", "acme-id").await,
            Some(Role::Member)
        );
    }

    #[tokio::test]
    async fn join_org_race_safe_keeps_default_for_allowlisted() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Owner)
            .await
            .unwrap();
        // Allowlisted operators call with drop_default=false and keep Default.
        join_org_race_safe(&db, "ident-1", "acme-id", Role::Member, false)
            .await
            .unwrap();
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Owner)
        );
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", "acme-id").await,
            Some(Role::Member)
        );
    }

    #[tokio::test]
    async fn org_creation_owner_not_left_in_default() {
        let db = test_pool().await;
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Member)
            .await
            .unwrap();
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        join_org_race_safe(&db, "ident-1", "acme-id", Role::Owner, true)
            .await
            .unwrap();
        assert!(!in_default(&db, "ident-1").await);
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", "acme-id").await,
            Some(Role::Owner)
        );
    }

    #[tokio::test]
    async fn leave_last_non_default_readds_default() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        // Joined a tenant org, Default already dropped.
        join_org_race_safe(&db, "ident-1", "acme-id", Role::Member, true)
            .await
            .unwrap();
        assert!(!in_default(&db, "ident-1").await);
        remove_member(&db, "acme-id", "ident-1").await.unwrap();
        add_default_floor_member_txn(&db, "ident-1").await.unwrap();
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Member)
        );
    }

    #[tokio::test]
    async fn leave_one_of_two_non_default_does_not_readd_default() {
        let db = test_pool().await;
        create_org(&db, "a-id", "a", "A", None).await.unwrap();
        create_org(&db, "b-id", "b", "B", None).await.unwrap();
        join_org_race_safe(&db, "ident-1", "a-id", Role::Member, true)
            .await
            .unwrap();
        join_org_race_safe(&db, "ident-1", "b-id", Role::Member, true)
            .await
            .unwrap();
        remove_member(&db, "a-id", "ident-1").await.unwrap();
        add_default_floor_member_txn(&db, "ident-1").await.unwrap();
        assert!(!in_default(&db, "ident-1").await);
    }

    #[tokio::test]
    async fn remove_member_everywhere_leaves_no_default_row() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Member)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", "acme-id", Role::Member)
            .await
            .unwrap();
        remove_member_everywhere(&db, "ident-1").await.unwrap();
        assert!(!in_default(&db, "ident-1").await);
        assert_eq!(crate::orgs::org_role(&db, "ident-1", "acme-id").await, None);
    }

    #[tokio::test]
    async fn floor_add_and_join_never_leave_both_rows() {
        // SQLite serializes writers, so a genuine interleave can't occur; assert
        // both sequential orderings converge to "tenant only, no Default".
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        // Order 1: floor-add then join.
        add_default_floor_member_txn(&db, "ident-1").await.unwrap();
        join_org_race_safe(&db, "ident-1", "acme-id", Role::Member, true)
            .await
            .unwrap();
        assert!(!in_default(&db, "ident-1").await);

        // Order 2: join then floor-add (floor sees a non-default org, no-ops).
        join_org_race_safe(&db, "ident-2", "acme-id", Role::Member, true)
            .await
            .unwrap();
        add_default_floor_member_txn(&db, "ident-2").await.unwrap();
        assert!(!in_default(&db, "ident-2").await);
    }

    #[tokio::test]
    async fn finalize_invite_txn_drops_default_for_non_allowlisted() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Member)
            .await
            .unwrap();
        insert_invite(&db, "tok", "acme-id", "u@acme.com", Role::Member, None, 7)
            .await
            .unwrap();
        let outcome = finalize_invite_txn(&db, "tok", "acme-id", "ident-1", Role::Member, true)
            .await
            .unwrap();
        assert_eq!(outcome, InviteFinalizeOutcome::Accepted);
        assert!(!in_default(&db, "ident-1").await);
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", "acme-id").await,
            Some(Role::Member)
        );
    }

    #[tokio::test]
    async fn finalize_invite_txn_keeps_default_for_allowlisted() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Owner)
            .await
            .unwrap();
        insert_invite(
            &db,
            "tok",
            "acme-id",
            "boss@acme.com",
            Role::Member,
            None,
            7,
        )
        .await
        .unwrap();
        finalize_invite_txn(&db, "tok", "acme-id", "ident-1", Role::Member, false)
            .await
            .unwrap();
        assert_eq!(
            crate::orgs::org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Owner)
        );
    }
}
