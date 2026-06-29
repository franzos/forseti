//! Org-domain teams: the canonical, single-copy team model. The POSIX resolver
//! reads `org_team_members` at request time; nothing is mirrored or synced.
#![allow(dead_code)] // wired incrementally by the settings surface / resolver.

use chrono::Utc;
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{org_team_members, org_teams};

pub const MAX_ROWS_PER_LIST: i64 = 500;

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = org_teams)]
pub struct Team {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub slug: String,
    pub gid: Option<i32>,
    pub parent_id: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
}

#[derive(Insertable)]
#[diesel(table_name = org_teams)]
struct NewTeam<'a> {
    id: &'a str,
    org_id: &'a str,
    name: &'a str,
    slug: &'a str,
    gid: Option<i32>,
    parent_id: Option<&'a str>,
    created_at: String,
    created_by: Option<&'a str>,
}

/// url/identifier-safe slug: lowercase, `[a-z0-9-]`, runs of other chars collapse to '-'.
fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in s.trim().to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

pub async fn create_team(
    db: &DbPool,
    org_id: &str,
    name: &str,
    created_by: Option<&str>,
) -> anyhow::Result<Team> {
    let id = Uuid::new_v4().to_string();
    let slug = slugify(name);
    anyhow::ensure!(
        !slug.is_empty(),
        "team name must contain at least one alphanumeric"
    );
    let (org, nm, sl, cb, now) = (
        org_id.to_string(),
        name.to_string(),
        slug,
        created_by.map(str::to_string),
        Utc::now().to_rfc3339(),
    );
    let team: Team = db_interact!(db, |conn| {
        diesel::insert_into(org_teams::table)
            .values(NewTeam {
                id: &id,
                org_id: &org,
                name: &nm,
                slug: &sl,
                gid: None,
                parent_id: None,
                created_at: now,
                created_by: cb.as_deref(),
            })
            .execute(conn)?;
        org_teams::table
            .filter(org_teams::id.eq(&id))
            .select(Team::as_select())
            .first(conn)
    })?;
    Ok(team)
}

pub async fn rename_team(db: &DbPool, team_id: &str, name: &str) -> anyhow::Result<()> {
    let (id, nm, sl) = (team_id.to_string(), name.to_string(), slugify(name));
    anyhow::ensure!(
        !sl.is_empty(),
        "team name must contain at least one alphanumeric"
    );
    // slug is immutable; DB UNIQUE no longer fires on rename, so guard the collision here
    db_interact!(db, |conn| {
        conn.transaction::<_, anyhow::Error, _>(|c| {
            let org_id: String = org_teams::table
                .filter(org_teams::id.eq(&id))
                .select(org_teams::org_id)
                .first(c)?;
            let clash: i64 = org_teams::table
                .filter(org_teams::org_id.eq(&org_id))
                .filter(org_teams::slug.eq(&sl))
                .filter(org_teams::id.ne(&id))
                .count()
                .get_result(c)?;
            anyhow::ensure!(clash == 0, "another team in this org already uses slug `{sl}`");
            diesel::update(org_teams::table.filter(org_teams::id.eq(&id)))
                .set(org_teams::name.eq(&nm))
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

/// Delete a team + its members + any host scopes referencing it (by uuid, so
/// no gid-reuse hazard), in one transaction.
pub async fn delete_team(db: &DbPool, team_id: &str) -> anyhow::Result<()> {
    use crate::schema::host_allowed_groups;
    let id = team_id.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(host_allowed_groups::table.filter(host_allowed_groups::team_id.eq(&id)))
                .execute(c)?;
            diesel::delete(org_team_members::table.filter(org_team_members::team_id.eq(&id)))
                .execute(c)?;
            diesel::delete(org_teams::table.filter(org_teams::id.eq(&id))).execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

pub async fn list_teams(db: &DbPool, org_id: &str) -> anyhow::Result<Vec<Team>> {
    let org = org_id.to_string();
    let rows = db_interact!(db, |conn| {
        org_teams::table
            .filter(org_teams::org_id.eq(&org))
            .order(org_teams::name.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(Team::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// (team, member_count) for an org, ordered by name.
pub async fn list_teams_with_counts(db: &DbPool, org_id: &str) -> anyhow::Result<Vec<(Team, i64)>> {
    let teams = list_teams(db, org_id).await?;
    let mut out = Vec::with_capacity(teams.len());
    for t in teams {
        let tid = t.id.clone();
        let n: i64 = db_interact!(db, |conn| {
            org_team_members::table
                .filter(org_team_members::team_id.eq(&tid))
                .count()
                .get_result(conn)
        })?;
        out.push((t, n));
    }
    Ok(out)
}

/// identity_ids that are members of `team_id`.
pub async fn team_member_ids(db: &DbPool, team_id: &str) -> anyhow::Result<Vec<String>> {
    let tid = team_id.to_string();
    Ok(db_interact!(db, |conn| {
        org_team_members::table
            .filter(org_team_members::team_id.eq(&tid))
            .select(org_team_members::identity_id)
            .load(conn)
    })?)
}

pub async fn teams_for_identity(
    db: &DbPool,
    org_id: &str,
    identity_id: &str,
) -> anyhow::Result<Vec<Team>> {
    let (org, id) = (org_id.to_string(), identity_id.to_string());
    let rows = db_interact!(db, |conn| {
        org_teams::table
            .inner_join(org_team_members::table.on(org_team_members::team_id.eq(org_teams::id)))
            .filter(org_teams::org_id.eq(&org))
            .filter(org_team_members::identity_id.eq(&id))
            .order(org_teams::name.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(Team::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// The identity's teams across all their orgs, ordered by name. Each `Team`
/// carries its `org_id` so the profile view can group without a second lookup.
pub async fn teams_for_identity_any_org(
    db: &DbPool,
    identity_id: &str,
) -> anyhow::Result<Vec<Team>> {
    let id = identity_id.to_string();
    let rows = db_interact!(db, |conn| {
        org_teams::table
            .inner_join(org_team_members::table.on(org_team_members::team_id.eq(org_teams::id)))
            .filter(org_team_members::identity_id.eq(&id))
            .order(org_teams::name.asc())
            .limit(MAX_ROWS_PER_LIST)
            .select(Team::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

pub async fn add_member(db: &DbPool, team_id: &str, identity_id: &str) -> anyhow::Result<()> {
    let (tid, id, now) = (
        team_id.to_string(),
        identity_id.to_string(),
        Utc::now().to_rfc3339(),
    );
    db_interact!(db, |conn| {
        diesel::insert_into(org_team_members::table)
            .values((
                org_team_members::team_id.eq(&tid),
                org_team_members::identity_id.eq(&id),
                org_team_members::source.eq("manual"),
                org_team_members::added_at.eq(&now),
            ))
            .on_conflict((org_team_members::team_id, org_team_members::identity_id))
            .do_nothing()
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn remove_member(db: &DbPool, team_id: &str, identity_id: &str) -> anyhow::Result<()> {
    let (tid, id) = (team_id.to_string(), identity_id.to_string());
    db_interact!(db, |conn| {
        diesel::delete(
            org_team_members::table
                .filter(org_team_members::team_id.eq(&tid))
                .filter(org_team_members::identity_id.eq(&id)),
        )
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}

/// True iff `a` and `b` share at least one team in `org_id`.
///
/// Load-then-`eq_any` over a subquery: `org_team_members` would otherwise
/// appear in both the join and the inner select, which the codebase avoids.
pub async fn shared_team(db: &DbPool, org_id: &str, a: &str, b: &str) -> anyhow::Result<bool> {
    let (org, a, b) = (org_id.to_string(), a.to_string(), b.to_string());
    let n: i64 = db_interact!(db, |conn| {
        let b_ids: Vec<String> = org_team_members::table
            .filter(org_team_members::identity_id.eq(&b))
            .select(org_team_members::team_id)
            .load(conn)?;
        if b_ids.is_empty() {
            return Ok(0i64);
        }
        org_team_members::table
            .inner_join(org_teams::table.on(org_teams::id.eq(org_team_members::team_id)))
            .filter(org_teams::org_id.eq(&org))
            .filter(org_team_members::identity_id.eq(&a))
            .filter(org_team_members::team_id.eq_any(&b_ids))
            .count()
            .get_result(conn)
    })?;
    Ok(n > 0)
}

/// identity_ids in `org_id` sharing >= 1 team with `viewer_id` (same_group
/// filtering without N+1), excluding the viewer.
pub async fn co_team_member_ids(
    db: &DbPool,
    org_id: &str,
    viewer_id: &str,
) -> anyhow::Result<Vec<String>> {
    let (org, vid) = (org_id.to_string(), viewer_id.to_string());
    let team_ids: Vec<String> = db_interact!(db, |conn| {
        org_teams::table
            .inner_join(org_team_members::table.on(org_team_members::team_id.eq(org_teams::id)))
            .filter(org_teams::org_id.eq(&org))
            .filter(org_team_members::identity_id.eq(&vid))
            .select(org_team_members::team_id)
            .load(conn)
    })?;
    if team_ids.is_empty() {
        return Ok(vec![]);
    }
    let vid = viewer_id.to_string();
    let others: Vec<String> = db_interact!(db, |conn| {
        org_team_members::table
            .filter(org_team_members::team_id.eq_any(&team_ids))
            .filter(org_team_members::identity_id.ne(&vid))
            .select(org_team_members::identity_id)
            .distinct()
            .load(conn)
    })?;
    Ok(others)
}

/// Purge an identity's team memberships across an org's teams (member removal).
pub async fn remove_identity_from_org_teams(
    db: &DbPool,
    org_id: &str,
    identity_id: &str,
) -> anyhow::Result<()> {
    let (org, id) = (org_id.to_string(), identity_id.to_string());
    db_interact!(db, |conn| {
        let team_ids: Vec<String> = org_teams::table
            .filter(org_teams::org_id.eq(&org))
            .select(org_teams::id)
            .load(conn)?;
        diesel::delete(
            org_team_members::table
                .filter(org_team_members::identity_id.eq(&id))
                .filter(org_team_members::team_id.eq_any(&team_ids)),
        )
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}

/// Purge ALL team memberships for an identity (identity delete).
pub async fn remove_identity_from_all_teams(db: &DbPool, identity_id: &str) -> anyhow::Result<()> {
    let id = identity_id.to_string();
    db_interact!(db, |conn| {
        diesel::delete(org_team_members::table.filter(org_team_members::identity_id.eq(&id)))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use uuid::Uuid;

    async fn temp_pool() -> DbPool {
        let path = std::env::temp_dir().join(format!("forseti-teams-{}.db", Uuid::new_v4()));
        let db = DbPool::init(&DatabaseConfig {
            url: format!("sqlite://{}", path.display()),
            skip_migrations: true,
        })
        .expect("pool");
        db.run_migrations().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn create_add_share_roundtrip() {
        let db = temp_pool().await;
        let t = create_team(&db, "org1", "Platform", None).await.unwrap();
        add_member(&db, &t.id, "alice").await.unwrap();
        add_member(&db, &t.id, "bob").await.unwrap();
        assert!(shared_team(&db, "org1", "alice", "bob").await.unwrap());
        remove_member(&db, &t.id, "bob").await.unwrap();
        assert!(!shared_team(&db, "org1", "alice", "bob").await.unwrap());
        let mine = teams_for_identity(&db, "org1", "alice").await.unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].name, "Platform");
    }

    #[tokio::test]
    async fn counts_and_member_ids() {
        let db = temp_pool().await;
        let alpha = create_team(&db, "org1", "Alpha", None).await.unwrap();
        let _beta = create_team(&db, "org1", "Beta", None).await.unwrap();
        add_member(&db, &alpha.id, "alice").await.unwrap();
        add_member(&db, &alpha.id, "bob").await.unwrap();

        let counts = list_teams_with_counts(&db, "org1").await.unwrap();
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[0].0.name, "Alpha");
        assert_eq!(counts[0].1, 2);
        assert_eq!(counts[1].0.name, "Beta");
        assert_eq!(counts[1].1, 0);

        let mut ids = team_member_ids(&db, &alpha.id).await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[tokio::test]
    async fn duplicate_name_in_org_rejected() {
        let db = temp_pool().await;
        create_team(&db, "org1", "Platform", None).await.unwrap();
        assert!(create_team(&db, "org1", "Platform", None).await.is_err());
        assert!(create_team(&db, "org2", "Platform", None).await.is_ok());
    }

    #[tokio::test]
    async fn rename_changes_name_keeps_slug() {
        let db = temp_pool().await;
        let t = create_team(&db, "org1", "Platform", None).await.unwrap();
        assert_eq!(t.slug, "platform");
        rename_team(&db, &t.id, "Platform Team").await.unwrap();
        let teams = list_teams(&db, "org1").await.unwrap();
        let renamed = teams.iter().find(|x| x.id == t.id).unwrap();
        assert_eq!(renamed.name, "Platform Team");
        assert_eq!(renamed.slug, "platform"); // slug is immutable after creation
    }

    #[tokio::test]
    async fn rename_rejects_slug_collision() {
        let db = temp_pool().await;
        let _a = create_team(&db, "org1", "Platform", None).await.unwrap(); // slug "platform"
        let b = create_team(&db, "org1", "SRE", None).await.unwrap();       // slug "sre"
        // Renaming B to a name that slugifies to "platform" must be rejected.
        assert!(rename_team(&db, &b.id, "platform").await.is_err());
    }

    #[tokio::test]
    async fn rename_still_rejects_empty_slug_name() {
        let db = temp_pool().await;
        let t = create_team(&db, "org1", "Platform", None).await.unwrap();
        assert!(rename_team(&db, &t.id, "!!!").await.is_err());
    }
}
