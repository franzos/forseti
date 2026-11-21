//! Diesel queries for saml_connections + saml_links.

use diesel::prelude::*;
use serde::Serialize;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{saml_connections, saml_links};

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = saml_connections)]
pub struct SamlConnection {
    pub org_id: String,
    pub enabled: i32,
    pub display_name: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl SamlConnection {
    pub fn is_enabled(&self) -> bool {
        self.enabled != 0
    }
}

pub async fn get_connection(db: &DbPool, org_id: &str) -> anyhow::Result<Option<SamlConnection>> {
    let o = org_id.to_string();
    let row = db_interact!(db, |conn| {
        saml_connections::table
            .filter(saml_connections::org_id.eq(&o))
            .select(SamlConnection::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

pub async fn list_connections(db: &DbPool) -> anyhow::Result<Vec<SamlConnection>> {
    let rows = db_interact!(db, |conn| {
        saml_connections::table
            .order(saml_connections::created_at.asc())
            .limit(crate::orgs::db::MAX_ROWS_PER_LIST)
            .select(SamlConnection::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

#[derive(Insertable)]
#[diesel(table_name = saml_connections)]
struct NewConnection<'a> {
    org_id: &'a str,
    enabled: i32,
    display_name: &'a str,
    created_by: &'a str,
    created_at: String,
    updated_at: String,
}

/// The org already has a row in `saml_connections` (keyed by `org_id`).
#[derive(Debug)]
pub struct ConnectionExists;

impl std::fmt::Display for ConnectionExists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("organization already has a SAML connection")
    }
}

impl std::error::Error for ConnectionExists {}

pub async fn insert_connection(
    db: &DbPool,
    org_id: &str,
    display_name: &str,
    created_by: &str,
) -> anyhow::Result<()> {
    let o = org_id.to_string();
    let d = display_name.to_string();
    let c = created_by.to_string();
    let now = crate::db::now_rfc3339();
    let result = db_interact!(db, |conn| {
        diesel::insert_into(saml_connections::table)
            .values(NewConnection {
                org_id: &o,
                enabled: 1,
                display_name: &d,
                created_by: &c,
                created_at: now.clone(),
                updated_at: now.clone(),
            })
            .execute(conn)
    });
    match result {
        Ok(_) => Ok(()),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Err(ConnectionExists.into()),
        Err(e) => Err(e.into()),
    }
}

/// Returns true when a row was flipped (false = no connection for org).
pub async fn set_enabled(db: &DbPool, org_id: &str, enabled: bool) -> anyhow::Result<bool> {
    let o = org_id.to_string();
    let v = if enabled { 1 } else { 0 };
    let now = crate::db::now_rfc3339();
    let affected = db_interact!(db, |conn| {
        diesel::update(saml_connections::table.filter(saml_connections::org_id.eq(&o)))
            .set((
                saml_connections::enabled.eq(v),
                saml_connections::updated_at.eq(now.clone()),
            ))
            .execute(conn)
    })?;
    Ok(affected > 0)
}

pub async fn delete_connection(db: &DbPool, org_id: &str) -> anyhow::Result<()> {
    let o = org_id.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(saml_links::table.filter(saml_links::org_id.eq(&o))).execute(c)?;
            diesel::delete(saml_connections::table.filter(saml_connections::org_id.eq(&o)))
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

// --- links ---------------------------------------------------------------

/// Email-keyed lookup, org-scoped. Returns `(identity_id, idp_subject)`.
pub async fn link_for(
    db: &DbPool,
    org_id: &str,
    email: &str,
) -> anyhow::Result<Option<(String, Option<String>)>> {
    let o = org_id.to_string();
    let e = email.to_lowercase();
    let row: Option<(String, Option<String>)> = db_interact!(db, |conn| {
        saml_links::table
            .filter(saml_links::org_id.eq(&o))
            .filter(saml_links::email.eq(&e))
            .select((saml_links::identity_id, saml_links::idp_subject))
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Records the subject on an email-keyed link that has none. Returns true
/// when a row was filled; a stored subject is never overwritten.
pub async fn backfill_subject(
    db: &DbPool,
    org_id: &str,
    email: &str,
    idp_subject: &str,
) -> anyhow::Result<bool> {
    let o = org_id.to_string();
    let e = email.to_lowercase();
    let s = idp_subject.to_string();
    let affected = db_interact!(db, |conn| {
        diesel::update(
            saml_links::table
                .filter(saml_links::org_id.eq(&o))
                .filter(saml_links::email.eq(&e))
                .filter(saml_links::idp_subject.is_null()),
        )
        .set(saml_links::idp_subject.eq(&s))
        .execute(conn)
    })?;
    Ok(affected > 0)
}

/// Durable lookup by the stable IdP subject (NameID), org-scoped. Returns
/// `(identity_id, email)` so a stale row can be pruned by its email key.
/// The subject is opaque — never lowercased (unlike email).
pub async fn link_subject(
    db: &DbPool,
    org_id: &str,
    idp_subject: &str,
) -> anyhow::Result<Option<(String, String)>> {
    if idp_subject.is_empty() {
        return Ok(None);
    }
    let o = org_id.to_string();
    let s = idp_subject.to_string();
    let row: Option<(String, String)> = db_interact!(db, |conn| {
        saml_links::table
            .filter(saml_links::org_id.eq(&o))
            .filter(saml_links::idp_subject.eq(&s))
            .select((saml_links::identity_id, saml_links::email))
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

#[derive(Insertable)]
#[diesel(table_name = saml_links)]
struct NewLink<'a> {
    org_id: &'a str,
    email: &'a str,
    identity_id: &'a str,
    created_at: String,
    idp_subject: Option<&'a str>,
}

/// Insert, or repoint the existing (org, email) row at `identity_id`. The
/// subject is written only when one is given, so a subjectless relink never
/// clears a stored durable key.
pub async fn upsert_link(
    db: &DbPool,
    org_id: &str,
    email: &str,
    idp_subject: Option<&str>,
    identity_id: &str,
) -> anyhow::Result<()> {
    let o = org_id.to_string();
    let e = email.to_lowercase();
    let i = identity_id.to_string();
    let s = idp_subject.map(str::to_string);
    let now = crate::db::now_rfc3339();
    db_interact!(db, |conn| {
        let insert = diesel::insert_into(saml_links::table)
            .values(NewLink {
                org_id: &o,
                email: &e,
                identity_id: &i,
                created_at: now.clone(),
                idp_subject: s.as_deref(),
            })
            .on_conflict((saml_links::org_id, saml_links::email))
            .do_update();
        match s.as_deref() {
            Some(subject) => insert
                .set((
                    saml_links::identity_id.eq(&i),
                    saml_links::idp_subject.eq(subject),
                ))
                .execute(conn),
            None => insert.set(saml_links::identity_id.eq(&i)).execute(conn),
        }
    })?;
    Ok(())
}

#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = saml_links)]
pub struct SamlLink {
    pub org_id: String,
    pub email: String,
    pub idp_subject: Option<String>,
    pub created_at: String,
}

/// Every SAML link of an identity across orgs, oldest first. Uncapped: the
/// account export reads it.
pub async fn links_for_identity(db: &DbPool, identity_id: &str) -> anyhow::Result<Vec<SamlLink>> {
    let i = identity_id.to_string();
    let rows: Vec<SamlLink> = db_interact!(db, |conn| {
        saml_links::table
            .filter(saml_links::identity_id.eq(&i))
            .order(saml_links::created_at.asc())
            .select(SamlLink::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// Stale-link cleanup when the Kratos identity behind a link is gone.
pub async fn delete_link(db: &DbPool, org_id: &str, email: &str) -> anyhow::Result<()> {
    let o = org_id.to_string();
    let e = email.to_lowercase();
    db_interact!(db, |conn| {
        diesel::delete(
            saml_links::table
                .filter(saml_links::org_id.eq(&o))
                .filter(saml_links::email.eq(&e)),
        )
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::db::test_pool;

    #[tokio::test]
    async fn connection_without_created_by_round_trips() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "org-s", "org-s", "Org S", None)
            .await
            .unwrap();
        let now = crate::db::now_rfc3339();
        let inserted: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::insert_into(saml_connections::table)
                    .values((
                        saml_connections::org_id.eq("org-s"),
                        saml_connections::enabled.eq(1),
                        saml_connections::display_name.eq("idp"),
                        saml_connections::created_by.eq(None::<String>),
                        saml_connections::created_at.eq(&now),
                        saml_connections::updated_at.eq(&now),
                    ))
                    .execute(conn)
            })?)
        }
        .await;
        assert_eq!(inserted.unwrap(), 1);
        let row = get_connection(&db, "org-s").await.unwrap().unwrap();
        assert_eq!(row.created_by, None);
        assert!(row.is_enabled());
    }

    #[tokio::test]
    async fn insert_connection_twice_is_connection_exists() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "org-s", "org-s", "Org S", None)
            .await
            .unwrap();
        insert_connection(&db, "org-s", "idp", "admin")
            .await
            .unwrap();
        let err = insert_connection(&db, "org-s", "idp", "admin")
            .await
            .expect_err("duplicate insert must fail");
        assert!(
            err.downcast_ref::<ConnectionExists>().is_some(),
            "expected ConnectionExists, got: {err}"
        );
    }

    fn link(identity: &str, subject: Option<&str>) -> Option<(String, Option<String>)> {
        Some((identity.to_string(), subject.map(str::to_string)))
    }

    #[tokio::test]
    async fn link_for_returns_the_subject() {
        let db = test_pool().await;
        upsert_link(&db, "o1", "A@x.test", Some("sub-1"), "id1")
            .await
            .unwrap();
        upsert_link(&db, "o1", "b@x.test", None, "id2")
            .await
            .unwrap();
        assert_eq!(
            link_for(&db, "o1", "a@x.test").await.unwrap(),
            link("id1", Some("sub-1"))
        );
        assert_eq!(
            link_for(&db, "o1", "b@x.test").await.unwrap(),
            link("id2", None)
        );
    }

    #[tokio::test]
    async fn upsert_repoints_identity_and_subject() {
        let db = test_pool().await;
        upsert_link(&db, "o1", "a@x.test", Some("sub-1"), "id1")
            .await
            .unwrap();
        upsert_link(&db, "o1", "a@x.test", Some("sub-2"), "id2")
            .await
            .unwrap();
        assert_eq!(
            link_for(&db, "o1", "a@x.test").await.unwrap(),
            link("id2", Some("sub-2"))
        );
    }

    #[tokio::test]
    async fn upsert_without_subject_keeps_the_stored_subject() {
        let db = test_pool().await;
        upsert_link(&db, "o1", "a@x.test", Some("sub-1"), "id1")
            .await
            .unwrap();
        upsert_link(&db, "o1", "a@x.test", None, "id2")
            .await
            .unwrap();
        assert_eq!(
            link_for(&db, "o1", "a@x.test").await.unwrap(),
            link("id2", Some("sub-1"))
        );
    }

    #[tokio::test]
    async fn backfill_only_fills_a_null_subject() {
        let db = test_pool().await;
        upsert_link(&db, "o1", "a@x.test", None, "id1")
            .await
            .unwrap();
        upsert_link(&db, "o1", "b@x.test", Some("sub-b"), "id2")
            .await
            .unwrap();
        assert!(
            backfill_subject(&db, "o1", "A@x.test", "sub-a")
                .await
                .unwrap()
        );
        assert!(
            !backfill_subject(&db, "o1", "a@x.test", "sub-z")
                .await
                .unwrap()
        );
        assert!(
            !backfill_subject(&db, "o1", "b@x.test", "sub-z")
                .await
                .unwrap()
        );
        assert!(
            !backfill_subject(&db, "o1", "c@x.test", "sub-z")
                .await
                .unwrap()
        );
        assert_eq!(
            link_for(&db, "o1", "a@x.test").await.unwrap(),
            link("id1", Some("sub-a"))
        );
        assert_eq!(
            link_for(&db, "o1", "b@x.test").await.unwrap(),
            link("id2", Some("sub-b"))
        );
    }

    #[tokio::test]
    #[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
    async fn upsert_link_conflict_succeeds_on_postgres() {
        let db = crate::db::test_postgres_pool().await;
        let org = format!("test-{}", uuid::Uuid::new_v4());
        let email = "pg@x.test";
        upsert_link(&db, &org, email, Some("sub-1"), "id1")
            .await
            .unwrap();
        let second = upsert_link(&db, &org, email, Some("sub-2"), "id2").await;
        let row = link_subject(&db, &org, "sub-2").await;
        delete_link(&db, &org, email).await.unwrap();
        second.unwrap();
        assert_eq!(row.unwrap(), Some(("id2".to_string(), email.to_string())));
    }
}
