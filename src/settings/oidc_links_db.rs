//! `oidc_links` queries: record when Forseti first observed each linked OIDC
//! provider for an identity, so the linked-providers page can show a
//! "Connected {date}" without intercepting the Kratos link flow.

use chrono::Utc;
use diesel::prelude::*;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::oidc_links;

#[derive(Insertable)]
#[diesel(table_name = oidc_links)]
struct NewLink<'a> {
    identity_id: &'a str,
    provider: &'a str,
    first_seen_at: String,
}

/// Record `(identity_id, provider)` as seen, keeping the earliest timestamp:
/// insert with the current time, ignore a duplicate, then read back the stored
/// `first_seen_at`. Idempotent, so repeated renders don't move the date.
pub(crate) async fn upsert_seen(
    db: &DbPool,
    identity_id: &str,
    provider: &str,
) -> anyhow::Result<String> {
    let ident = identity_id.to_string();
    let prov = provider.to_string();
    let now = Utc::now().to_rfc3339();
    let stored: String = db_interact!(db, |conn| {
        diesel::insert_into(oidc_links::table)
            .values(NewLink {
                identity_id: &ident,
                provider: &prov,
                first_seen_at: now.clone(),
            })
            .on_conflict((oidc_links::identity_id, oidc_links::provider))
            .do_nothing()
            .execute(conn)?;
        oidc_links::table
            .filter(oidc_links::identity_id.eq(&ident))
            .filter(oidc_links::provider.eq(&prov))
            .select(oidc_links::first_seen_at)
            .first::<String>(conn)
    })?;
    Ok(stored)
}

/// All `(provider, first_seen_at)` rows for an identity.
pub(crate) async fn list_for_identity(
    db: &DbPool,
    identity_id: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    let ident = identity_id.to_string();
    let rows: Vec<(String, String)> = db_interact!(db, |conn| {
        oidc_links::table
            .filter(oidc_links::identity_id.eq(&ident))
            .select((oidc_links::provider, oidc_links::first_seen_at))
            .load(conn)
    })?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::db::test_pool;

    #[tokio::test]
    async fn upsert_seen_is_idempotent_and_stable() {
        let db = test_pool().await;
        let first = upsert_seen(&db, "ident-1", "github").await.unwrap();
        // A second observation must not add a row nor move the timestamp.
        let second = upsert_seen(&db, "ident-1", "github").await.unwrap();
        assert_eq!(first, second);

        let rows = list_for_identity(&db, "ident-1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], ("github".to_string(), first));
    }
}
