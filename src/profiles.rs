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
use crate::schema::{member_profiles, member_username_history};

pub mod identicon;
pub mod username;
pub(crate) mod view;

use axum::Router;
use axum::routing::get;

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
    /// Handle in the casing the user typed; emitted as `preferred_username`.
    pub username: Option<String>,
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
    username: Option<String>,
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
            username: r.username,
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
    username: Option<String>,
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
            username: r.username,
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
    username: Option<String>,
    username_lc: Option<String>,
}

#[derive(Insertable)]
#[diesel(table_name = member_username_history)]
struct UsernameTombstone {
    username_lc: String,
    identity_id: String,
    released_at: String,
}

/// Input bundle for [`upsert`]; blank fields collapse to NULL so callers can
/// clear a field by sending it empty. `username` must already have passed
/// [`username::validate`].
pub struct ProfileInput<'a> {
    pub identity_id: &'a str,
    pub bio: &'a str,
    pub location: &'a str,
    pub pronouns: &'a str,
    pub website: &'a str,
    pub avatar_url: &'a str,
    pub links: &'a [ProfileLink],
    pub username: &'a str,
}

/// Minimum gap between two handle changes. Slows down an attacker cycling
/// handles to land on one an RP has already mapped to someone's account.
pub const USERNAME_CHANGE_COOLDOWN_DAYS: i64 = 30;

/// Why a profile save was rejected. `UsernameTaken` covers both a live holder
/// and a tombstoned handle — the two are deliberately indistinguishable, so
/// the form can't be used to enumerate handles anyone ever held.
#[derive(Debug)]
pub enum SaveError {
    UsernameTaken,
    UsernameCooldown,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for SaveError {
    fn from(e: anyhow::Error) -> Self {
        SaveError::Other(e)
    }
}

enum TxError {
    Taken,
    Cooldown,
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for TxError {
    fn from(e: diesel::result::Error) -> Self {
        TxError::Db(e)
    }
}

/// Insert-or-update the profile for `identity_id`. Handle changes are settled
/// in the same transaction as the rest of the profile, so a concurrent save
/// can't slip between the availability check and the write.
pub async fn upsert(db: &DbPool, input: ProfileInput<'_>) -> Result<(), SaveError> {
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
        Some(serde_json::to_string(input.links).map_err(|e| SaveError::Other(e.into()))?)
    };
    let username = null_if_empty(input.username);
    let row = ProfileUpsert {
        identity_id: input.identity_id.to_string(),
        bio: null_if_empty(input.bio),
        location: null_if_empty(input.location),
        pronouns: null_if_empty(input.pronouns),
        website: null_if_empty(input.website),
        avatar_url: null_if_empty(input.avatar_url),
        links_json,
        updated_at: Utc::now().to_rfc3339(),
        username_lc: username.as_deref().map(username::fold),
        username,
    };
    // The username checks (current holder, history tombstone, cooldown) all read
    // before the upsert writes, so this has to claim the write lock up front.
    let outcome: Result<(), TxError> = crate::serialized_txn!(db, (), TxError, |conn| {
        use diesel::upsert::excluded;
        let old_lc: Option<String> = member_profiles::table
            .filter(member_profiles::identity_id.eq(&row.identity_id))
            .select(member_profiles::username_lc)
            .first::<Option<String>>(conn)
            .optional()?
            .flatten();

        if old_lc != row.username_lc {
            if let Some(new_lc) = row.username_lc.as_deref() {
                let holder: Option<String> = member_profiles::table
                    .filter(member_profiles::username_lc.eq(new_lc))
                    .select(member_profiles::identity_id)
                    .first::<String>(conn)
                    .optional()?;
                if holder.is_some_and(|h| h != row.identity_id) {
                    return Err(TxError::Taken);
                }
                let past: Option<String> = member_username_history::table
                    .filter(member_username_history::username_lc.eq(new_lc))
                    .select(member_username_history::identity_id)
                    .first::<String>(conn)
                    .optional()?;
                if past.is_some_and(|h| h != row.identity_id) {
                    return Err(TxError::Taken);
                }
            }
            if let Some(released) = old_lc {
                let last: Option<String> = member_username_history::table
                    .filter(member_username_history::identity_id.eq(&row.identity_id))
                    .select(member_username_history::released_at)
                    .order(member_username_history::released_at.desc())
                    .first::<String>(conn)
                    .optional()?;
                let too_soon = last
                    .as_deref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .is_some_and(|t| {
                        Utc::now().signed_duration_since(t)
                            < chrono::Duration::days(USERNAME_CHANGE_COOLDOWN_DAYS)
                    });
                if too_soon {
                    return Err(TxError::Cooldown);
                }
                // Re-releasing a handle this identity previously held just
                // refreshes the tombstone; it's still theirs to reclaim.
                diesel::insert_into(member_username_history::table)
                    .values(&UsernameTombstone {
                        username_lc: released,
                        identity_id: row.identity_id.clone(),
                        released_at: row.updated_at.clone(),
                    })
                    .on_conflict(member_username_history::username_lc)
                    .do_update()
                    .set(
                        member_username_history::released_at
                            .eq(excluded(member_username_history::released_at)),
                    )
                    .execute(conn)?;
            }
        }

        // ON CONFLICT DO UPDATE so two concurrent first-saves don't trip
        // the PK constraint. Supported by both backends (sqlite >= 3.24).
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
                member_profiles::username.eq(excluded(member_profiles::username)),
                member_profiles::username_lc.eq(excluded(member_profiles::username_lc)),
            ))
            .execute(conn)?;
        Ok(())
    });
    match outcome {
        Ok(()) => Ok(()),
        Err(TxError::Taken) => Err(SaveError::UsernameTaken),
        Err(TxError::Cooldown) => Err(SaveError::UsernameCooldown),
        // The unique index is the backstop for the check above losing a race.
        Err(TxError::Db(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ))) => Err(SaveError::UsernameTaken),
        Err(TxError::Db(e)) => Err(SaveError::Other(e.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::db::test_pool;

    fn input<'a>(identity_id: &'a str, username: &'a str) -> ProfileInput<'a> {
        ProfileInput {
            identity_id,
            bio: "",
            location: "",
            pronouns: "",
            website: "",
            avatar_url: "",
            links: &[],
            username,
        }
    }

    async fn set_username(db: &DbPool, id: &str, username: &str) -> Result<(), SaveError> {
        upsert(db, input(id, username)).await
    }

    /// Backdate this identity's tombstones so the cooldown is out of the way.
    async fn expire_cooldown(db: &DbPool, id: &str) -> Result<()> {
        let old = (Utc::now() - chrono::Duration::days(60)).to_rfc3339();
        let id = id.to_string();
        db_interact!(db, |conn| {
            diesel::update(
                member_username_history::table.filter(member_username_history::identity_id.eq(&id)),
            )
            .set(member_username_history::released_at.eq(&old))
            .execute(conn)
        })?;
        Ok(())
    }

    async fn tombstone_count(db: &DbPool) -> Result<i64> {
        let n = db_interact!(db, |conn| {
            member_username_history::table
                .count()
                .get_result::<i64>(conn)
        })?;
        Ok(n)
    }

    #[tokio::test]
    async fn username_round_trips_and_is_optional() {
        let db = test_pool().await;
        set_username(&db, "a", "").await.unwrap();
        assert_eq!(fetch(&db, "a").await.unwrap().username, None);

        set_username(&db, "a", "FranzG").await.unwrap();
        assert_eq!(
            fetch(&db, "a").await.unwrap().username.as_deref(),
            Some("FranzG")
        );
    }

    #[tokio::test]
    async fn second_identity_cannot_take_a_live_handle_in_any_casing() {
        let db = test_pool().await;
        set_username(&db, "a", "franz").await.unwrap();
        assert!(matches!(
            set_username(&db, "b", "FRANZ").await,
            Err(SaveError::UsernameTaken)
        ));
        // ... and the loser keeps no handle at all.
        assert_eq!(fetch(&db, "b").await.unwrap().username, None);
    }

    #[tokio::test]
    async fn resaving_the_same_handle_is_not_a_conflict() {
        let db = test_pool().await;
        set_username(&db, "a", "franz").await.unwrap();
        set_username(&db, "a", "franz").await.unwrap();
        // Unchanged handle means nothing was released.
        assert_eq!(tombstone_count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn released_handle_is_tombstoned_and_unavailable_to_others() {
        let db = test_pool().await;
        set_username(&db, "a", "franz").await.unwrap();
        set_username(&db, "a", "franz2").await.unwrap();

        assert!(matches!(
            set_username(&db, "b", "franz").await,
            Err(SaveError::UsernameTaken)
        ));
    }

    #[tokio::test]
    async fn previous_holder_can_reclaim_their_own_handle() {
        let db = test_pool().await;
        set_username(&db, "a", "franz").await.unwrap();
        set_username(&db, "a", "franz2").await.unwrap();
        expire_cooldown(&db, "a").await.unwrap();

        set_username(&db, "a", "franz").await.unwrap();
        assert_eq!(
            fetch(&db, "a").await.unwrap().username.as_deref(),
            Some("franz")
        );
    }

    #[tokio::test]
    async fn second_change_within_the_cooldown_is_refused() {
        let db = test_pool().await;
        set_username(&db, "a", "franz").await.unwrap();
        // First change is free; it's the one that starts the clock.
        set_username(&db, "a", "franz2").await.unwrap();
        assert!(matches!(
            set_username(&db, "a", "franz3").await,
            Err(SaveError::UsernameCooldown)
        ));
        assert_eq!(
            fetch(&db, "a").await.unwrap().username.as_deref(),
            Some("franz2")
        );

        expire_cooldown(&db, "a").await.unwrap();
        set_username(&db, "a", "franz3").await.unwrap();
    }

    #[tokio::test]
    async fn other_profile_fields_still_save_while_a_handle_is_held() {
        let db = test_pool().await;
        set_username(&db, "a", "franz").await.unwrap();
        upsert(
            &db,
            ProfileInput {
                bio: "hello",
                ..input("a", "franz")
            },
        )
        .await
        .unwrap();
        let p = fetch(&db, "a").await.unwrap();
        assert_eq!(p.bio.as_deref(), Some("hello"));
        assert_eq!(p.username.as_deref(), Some("franz"));
    }
}
