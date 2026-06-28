//! Diesel queries for saml_connections + saml_links.

use chrono::Utc;
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
    pub created_by: String,
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

pub async fn insert_connection(
    db: &DbPool,
    org_id: &str,
    display_name: &str,
    created_by: &str,
) -> anyhow::Result<()> {
    let o = org_id.to_string();
    let d = display_name.to_string();
    let c = created_by.to_string();
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
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
            .map(|_| ())
    })?;
    Ok(())
}

/// Returns true when a row was flipped (false = no connection for org).
pub async fn set_enabled(db: &DbPool, org_id: &str, enabled: bool) -> anyhow::Result<bool> {
    let o = org_id.to_string();
    let v = if enabled { 1 } else { 0 };
    let now = Utc::now().to_rfc3339();
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

pub async fn link_for(db: &DbPool, org_id: &str, email: &str) -> anyhow::Result<Option<String>> {
    let o = org_id.to_string();
    let e = email.to_lowercase();
    let row: Option<String> = db_interact!(db, |conn| {
        saml_links::table
            .filter(saml_links::org_id.eq(&o))
            .filter(saml_links::email.eq(&e))
            .select(saml_links::identity_id)
            .first(conn)
            .optional()
    })?;
    Ok(row)
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

/// Idempotent: a concurrent duplicate insert is swallowed; on conflict the
/// existing row is always repointed at the new identity, and the subject is
/// refreshed only when this login carries one — backfilling legacy email-only
/// rows without letting a subjectless relink NULL out a stored durable key.
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
    let now = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            match diesel::insert_into(saml_links::table)
                .values(NewLink {
                    org_id: &o,
                    email: &e,
                    identity_id: &i,
                    created_at: now.clone(),
                    idp_subject: s.as_deref(),
                })
                .execute(c)
            {
                Ok(_) => Ok(()),
                Err(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                )) => {
                    let target = saml_links::table
                        .filter(saml_links::org_id.eq(&o))
                        .filter(saml_links::email.eq(&e));
                    match s.as_deref() {
                        Some(subject) => diesel::update(target)
                            .set((
                                saml_links::identity_id.eq(&i),
                                saml_links::idp_subject.eq(subject),
                            ))
                            .execute(c)
                            .map(|_| ()),
                        None => diesel::update(target)
                            .set(saml_links::identity_id.eq(&i))
                            .execute(c)
                            .map(|_| ()),
                    }
                }
                Err(e) => Err(e),
            }
        })
    })?;
    Ok(())
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
