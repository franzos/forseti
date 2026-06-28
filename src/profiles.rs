//! Forseti-owned member profiles, gated by `[profiles].enabled`. Opt-in data
//! keyed by Kratos identity_id, surfaced three ways: edit at
//! `/settings/profile`, view at `/users/{identity_id}` (shared-org gated), and
//! OIDC `profile` / `extended_profile` claims (see `src/oauth/consent.rs`).

use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::member_profiles;

pub mod identicon;
pub(crate) mod view;

use axum::routing::get;
use axum::Router;

pub(crate) fn router() -> Router<crate::state::AppState> {
    Router::new().route("/users/{identity_id}", get(view::show_profile))
}

/// One `member_profiles` row; `links` is stored as JSON, exposed as a `Vec`.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub bio: Option<String>,
    pub location: Option<String>,
    pub pronouns: Option<String>,
    pub website: Option<String>,
    pub avatar_url: Option<String>,
    pub links: Vec<ProfileLink>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileLink {
    pub label: String,
    pub url: String,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = member_profiles)]
struct ProfileRow {
    bio: Option<String>,
    location: Option<String>,
    pronouns: Option<String>,
    website: Option<String>,
    avatar_url: Option<String>,
    links_json: Option<String>,
    updated_at: String,
}

impl From<ProfileRow> for Profile {
    fn from(r: ProfileRow) -> Self {
        let links = r
            .links_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<ProfileLink>>(s).ok())
            .unwrap_or_default();
        Profile {
            bio: r.bio,
            location: r.location,
            pronouns: r.pronouns,
            website: r.website,
            avatar_url: r.avatar_url,
            links,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = member_profiles)]
struct KeyedProfileRow {
    identity_id: String,
    bio: Option<String>,
    location: Option<String>,
    pronouns: Option<String>,
    website: Option<String>,
    avatar_url: Option<String>,
    links_json: Option<String>,
    updated_at: String,
}

impl From<KeyedProfileRow> for Profile {
    fn from(r: KeyedProfileRow) -> Self {
        let links = r
            .links_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<ProfileLink>>(s).ok())
            .unwrap_or_default();
        Profile {
            bio: r.bio,
            location: r.location,
            pronouns: r.pronouns,
            website: r.website,
            avatar_url: r.avatar_url,
            links,
            updated_at: r.updated_at,
        }
    }
}

/// Bulk-fetch profiles; missing rows are absent from the map. Empty input
/// short-circuits without touching the DB.
pub async fn fetch_many(db: &DbPool, identity_ids: &[&str]) -> Result<HashMap<String, Profile>> {
    if identity_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let ids: Vec<String> = identity_ids.iter().map(|s| (*s).to_string()).collect();
    let rows: Vec<KeyedProfileRow> = db_interact!(db, |conn| {
        member_profiles::table
            .filter(member_profiles::identity_id.eq_any(&ids))
            .select(KeyedProfileRow::as_select())
            .load::<KeyedProfileRow>(conn)
    })?;
    Ok(rows
        .into_iter()
        .map(|row| (row.identity_id.clone(), Profile::from(row)))
        .collect())
}

/// Fetch a single profile; a missing row returns an empty `Profile`.
pub async fn fetch(db: &DbPool, id: &str) -> Result<Profile> {
    let id_owned = id.to_string();
    let row: Option<ProfileRow> = db_interact!(db, |conn| {
        member_profiles::table
            .filter(member_profiles::identity_id.eq(&id_owned))
            .select(ProfileRow::as_select())
            .first::<ProfileRow>(conn)
            .optional()
    })?;
    Ok(row.map(Profile::from).unwrap_or_default())
}

#[derive(Insertable)]
#[diesel(table_name = member_profiles)]
struct ProfileUpsert {
    identity_id: String,
    bio: Option<String>,
    location: Option<String>,
    pronouns: Option<String>,
    website: Option<String>,
    avatar_url: Option<String>,
    links_json: Option<String>,
    updated_at: String,
}

/// Input bundle for [`upsert`]; blank fields collapse to NULL so callers can
/// clear a field by sending it empty.
pub struct ProfileInput<'a> {
    pub identity_id: &'a str,
    pub bio: &'a str,
    pub location: &'a str,
    pub pronouns: &'a str,
    pub website: &'a str,
    pub avatar_url: &'a str,
    pub links: &'a [ProfileLink],
}

/// Insert-or-update the profile for `identity_id`.
pub async fn upsert(db: &DbPool, input: ProfileInput<'_>) -> Result<()> {
    let null_if_empty = |s: &str| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    let links_json = if input.links.is_empty() {
        None
    } else {
        Some(serde_json::to_string(input.links)?)
    };
    let row = ProfileUpsert {
        identity_id: input.identity_id.to_string(),
        bio: null_if_empty(input.bio),
        location: null_if_empty(input.location),
        pronouns: null_if_empty(input.pronouns),
        website: null_if_empty(input.website),
        avatar_url: null_if_empty(input.avatar_url),
        links_json,
        updated_at: Utc::now().to_rfc3339(),
    };
    db_interact!(db, |conn| {
        // ON CONFLICT DO UPDATE so two concurrent first-saves don't trip the
        // PK constraint. Supported by both backends (sqlite >= 3.24).
        use diesel::upsert::excluded;
        diesel::insert_into(member_profiles::table)
            .values(&row)
            .on_conflict(member_profiles::identity_id)
            .do_update()
            .set((
                member_profiles::bio.eq(excluded(member_profiles::bio)),
                member_profiles::location.eq(excluded(member_profiles::location)),
                member_profiles::pronouns.eq(excluded(member_profiles::pronouns)),
                member_profiles::website.eq(excluded(member_profiles::website)),
                member_profiles::avatar_url.eq(excluded(member_profiles::avatar_url)),
                member_profiles::links_json.eq(excluded(member_profiles::links_json)),
                member_profiles::updated_at.eq(excluded(member_profiles::updated_at)),
            ))
            .execute(conn)?;
        Ok::<_, diesel::result::Error>(())
    })?;
    Ok(())
}
