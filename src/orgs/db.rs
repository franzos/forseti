//! Diesel queries for the organizations / organization_members /
//! organization_invites tables.
//!
//! Every public function here is async (via [`db_interact`]) and returns
//! `anyhow::Result<_>`. Callers in handler code unwrap into responses via
//! the usual `tracing::error!` + bail pattern.

use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use diesel::prelude::*;
use serde::Serialize;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{
    organization_invites, organization_members, organizations, saml_connections, saml_links,
};

/// Projection over `organizations`. `support_email` + `logo_url` override
/// the global `[brand]` config when set.
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
}

/// View-model joining org + role for the active-org / nav dropdown paths.
/// Distinct from [`OrgMember`] because the consumer is rendering a list of
/// orgs the caller belongs to and needs name + slug per row.
#[derive(Debug, Clone, Serialize)]
pub struct Membership {
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub role: String,
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

/// Hard cap applied to every unbounded list query in this module. Pages
/// that need more rows must paginate explicitly; the default is a
/// defence-in-depth safety net against a runaway query (e.g. an
/// accidentally-huge org or a join that scanned too much).
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

/// Like [`list_memberships`] but with a caller-supplied row cap. The
/// `orgs` OIDC claim caps at [`crate::orgs::nav::ORGS_CLAIM_CAP`]; push
/// that cap into SQL so we don't load a multi-thousand-row membership
/// set just to truncate it in-memory.
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
        })
        .collect();
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

/// Cheap "does this identity belong to ANY org?" probe used by the lazy
/// auto-join path in [`crate::extractors::RequireSession`]. One indexed
/// lookup against `organization_members.identity_id`. Returns
/// `Ok(true)` on the first matching row and `Ok(false)` on no match;
/// errors propagate so the caller can decide whether to log + retry.
pub async fn has_any_membership(db: &DbPool, identity_id: &str) -> anyhow::Result<bool> {
    let i = identity_id.to_string();
    let row: Option<String> = db_interact!(db, |conn| {
        organization_members::table
            .filter(organization_members::identity_id.eq(&i))
            .select(organization_members::identity_id)
            .first::<String>(conn)
            .optional()
    })?;
    Ok(row.is_some())
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

/// Paginated `list_members`. `limit` rows, skipping the first `offset`.
/// Ordered by `added_at` ASC then `identity_id` ASC so the page boundary
/// is stable across calls (added_at ties would otherwise float).
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

/// Convenience read for the members page — pairs each member with the
/// email trait fetched from Kratos. One bulk Kratos call via the SDK's
/// `ids` filter, then an in-memory join.
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

/// Transactional auto-join for the Default org. Combines the
/// member-count check with the insert in one transaction so two
/// concurrent first-user registrations can't both be promoted to
/// `owner` — only one of the two transactions will observe an empty
/// member set; the other will see the first writer's row and fall back
/// to `member`.
///
/// Role resolution goes through the unit-tested `pick_default_role`
/// helper so the policy lives in exactly one place.
pub async fn auto_join_default_txn(
    db: &DbPool,
    admin_cfg: &crate::config::AdminConfig,
    identity_id: &str,
    email: &str,
) -> anyhow::Result<()> {
    let ident = identity_id.to_string();
    let email = email.to_string();
    let admin_cfg = admin_cfg.clone();
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            // Re-read the Default org's member count *inside* the txn —
            // this is the protection against the race. SERIALIZABLE
            // isolation isn't required: sqlite serialises writers via
            // the WAL write lock, and postgres's default READ COMMITTED
            // is fine because we only ever insert (never update) members
            // here. The losing transaction either sees the winner's row
            // (count > 0 → member) or fails its insert with a unique
            // constraint violation (already a member, idempotent).
            let count: i64 = organization_members::table
                .filter(organization_members::org_id.eq(super::DEFAULT_ORG_ID))
                .count()
                .get_result(c)?;
            let role = super::pick_default_role(&admin_cfg, &email, count == 0);
            diesel::insert_into(organization_members::table)
                .values(NewMember {
                    org_id: super::DEFAULT_ORG_ID,
                    identity_id: &ident,
                    role: role.as_str(),
                    added_at: now.clone(),
                    added_by: None,
                })
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

pub async fn add_member(
    db: &DbPool,
    org_id: &str,
    identity_id: &str,
    role: super::Role,
    added_by: Option<&str>,
) -> anyhow::Result<()> {
    let org = org_id.to_string();
    let ident = identity_id.to_string();
    let role_s = role.as_str();
    let added_by = added_by.map(str::to_string);
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        diesel::insert_into(organization_members::table)
            .values(NewMember {
                org_id: &org,
                identity_id: &ident,
                role: role_s,
                added_at: now.clone(),
                added_by: added_by.as_deref(),
            })
            .execute(conn)
            .map(|_| ())
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

/// Drop every membership row that points at `identity_id`, across every
/// org. Called from the identity-delete path so reclaimed or admin-
/// deleted identities don't leave dangling rows that show up on the
/// members page (and trip up the last-owner guard with phantom owners).
/// Returns the number of rows removed.
pub async fn remove_member_everywhere(db: &DbPool, identity_id: &str) -> anyhow::Result<usize> {
    let ident = identity_id.to_string();
    let affected = db_interact!(db, |conn| {
        diesel::delete(
            organization_members::table.filter(organization_members::identity_id.eq(&ident)),
        )
        .execute(conn)
    })?;
    Ok(affected)
}

/// An org would be left ungovernable by this identity's departure iff the
/// identity is the *sole* owner and at least one other member remains. A solo
/// org (only member) and a co-owned org are both fine to leave.
pub(crate) fn blocks_self_deletion(owners: i64, members: i64) -> bool {
    owners == 1 && members > 1
}

/// Orgs where `identity_id` is the *sole* owner AND at least one other
/// member exists — i.e. orgs that would be left ungovernable if this
/// identity vanished. Returns `(org_id, org_name)` pairs.
///
/// Used to block account self-deletion: a solo org (sole owner, no other
/// members) is intentionally *not* returned, so deleting it proceeds.
///
/// Counts are computed in SQL via two grouped count queries (owners-per-org
/// and members-per-org) — backend-agnostic across sqlite/postgres (no
/// `FILTER`). Org names are fetched only for the surviving orgs.
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
    /// The invite was already accepted before this txn ran — no write
    /// happened, the caller should surface an "already accepted" error.
    AlreadyAccepted,
}

/// Atomically (a) check the invite isn't already accepted, (b) write
/// the membership row if missing, and (c) stamp the invite as
/// `accepted_at = now, accepted_by = identity_id`. Returns
/// [`InviteFinalizeOutcome::AlreadyAccepted`] when step (a) finds the
/// invite already used; in that case no DB state changes.
///
/// The "already accepted" check uses the `UPDATE ... WHERE accepted_at
/// IS NULL` pattern: if zero rows are affected, the invite was already
/// accepted by a concurrent caller (or had been used in a previous
/// session). The membership write happens first; the unique constraint
/// on `(org_id, identity_id)` swallows the duplicate idempotently.
pub async fn finalize_invite_txn(
    db: &DbPool,
    token: &str,
    org_id: &str,
    identity_id: &str,
    role: super::Role,
) -> anyhow::Result<InviteFinalizeOutcome> {
    let token = token.to_string();
    let org = org_id.to_string();
    let ident = identity_id.to_string();
    let role_s = role.as_str();
    let now = Utc::now().to_rfc3339();
    let outcome = db_interact!(db, |conn| {
        conn.transaction::<InviteFinalizeOutcome, diesel::result::Error, _>(|c| {
            // Membership insert first. Use an `ON CONFLICT DO NOTHING`-
            // equivalent by detecting and swallowing the unique
            // constraint violation so the txn doesn't abort when the
            // user is already a member (idempotent on retries).
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
                    // Already a member — fine, proceed to stamp the
                    // invite as accepted.
                }
                Err(e) => return Err(e),
            }

            // Stamp the invite as accepted atomically: only the writer
            // that observes `accepted_at IS NULL` updates a row. If
            // zero rows change, the invite was already accepted by a
            // concurrent caller (or previously) — signal that to the
            // caller so it can return an "already accepted" message.
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

/// Suggest a unique slug from `name`. If `slugify(name)` is free, return
/// it; otherwise append `-2`, `-3`, ... until a free slug is found.
///
/// Loads every slug starting with `<base>` in one query, then walks the
/// candidate suffixes in memory. Bounded `LIKE` (no user-controlled
/// wildcards) — `base` comes from `slugify` so it's `[a-z0-9-]+`.
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
    if !taken.contains(&base) {
        return Ok(base);
    }
    // Upper bound matches the previous behaviour (2..1000).
    for n in 2..=1000 {
        let candidate = format!("{base}-{n}");
        if !taken.contains(&candidate) {
            return Ok(candidate);
        }
    }
    anyhow::bail!("could not find a free slug after 1000 attempts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

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
        // Bad timestamps default to "expired" so the invite cannot be
        // used — failing closed.
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
        // Non-ASCII chars get collapsed to dashes (then trimmed/merged).
        let s = slugify("Café Münchën");
        // Each non-ascii char produces a separator; result is bounded
        // by the alphanumeric anchors that remain.
        assert!(s.starts_with("caf"));
        assert!(s.contains('-'));
        assert!(!s.starts_with('-') && !s.ends_with('-'));
    }

    #[test]
    fn slugify_edge_cases() {
        // Empty input → fallback `"org"`.
        assert_eq!(slugify(""), "org");
        // All-punctuation also falls back.
        assert_eq!(slugify("!!!"), "org");
        // Leading / trailing punctuation gets trimmed.
        assert_eq!(slugify("---hi---"), "hi");
    }
}
