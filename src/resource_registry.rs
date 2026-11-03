//! Operator-enrolled resource servers (RFC 8707 audiences).
//!
//! The consent-time audience allow-list: `resolve_granted_audience`'s
//! `allowed` arm reads enabled rows here instead of the deprecated
//! `[oauth].allowed_resource_audiences` config list. Rows are created by
//! admins (`/admin/resources`) or the one-time startup config import.
//! `corroboration` records the advisory RFC 9728 check result — a badge,
//! never a gate.

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::resource_registry as rr;

/// Corroboration status values. Keep in sync with the column default in
/// the migration.
pub mod corroboration {
    /// Never checked (fresh row, or created before a check ran).
    pub const UNCHECKED: &str = "unchecked";
    /// RFC 9728 document fetched and it matched resource + issuer.
    pub const CORROBORATED: &str = "corroborated";
    /// Fetch failed (DNS, TLS, timeout, non-2xx).
    pub const UNREACHABLE: &str = "unreachable";
    /// Document fetched but `resource`/`authorization_servers` disagreed.
    pub const MISMATCH: &str = "mismatch";
}

/// Full row projection for the admin list + consent read paths.
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = rr)]
pub struct Row {
    pub id: i64,
    /// Canonical resource URI, or a verbatim non-URI legacy identifier.
    pub resource: String,
    pub display_name: String,
    pub org_id: String,
    pub enabled: bool,
    pub corroboration: String,
    pub corroborated_at: Option<NaiveDateTime>,
    pub created_by: Option<String>,
    pub created_at: NaiveDateTime,
    /// Space-separated `metadata_admin` keys; see [`parse_access_token_claims`].
    pub access_token_claims: String,
}

/// Claims Hydra sets itself, plus the ID-token-only ones resource servers use
/// to tell an ID token from an access token.
const RESERVED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "client_id",
    "scp",
    "ext",
    "nonce",
    "at_hash",
];
const MAX_CLAIMS: usize = 10;
const MAX_CLAIM_LEN: usize = 64;

/// Parse the admin form's claim list (whitespace- or comma-separated) into
/// unique, validated names, in input order.
pub fn parse_access_token_claims(input: &str) -> Result<Vec<String>, String> {
    let mut claims: Vec<String> = Vec::new();
    for name in input.split(|c: char| c == ',' || c.is_whitespace()) {
        if name.is_empty() || claims.iter().any(|c| c == name) {
            continue;
        }
        if name.len() > MAX_CLAIM_LEN
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
        {
            return Err(format!(
                "\"{name}\" is not a valid claim name: use up to {MAX_CLAIM_LEN} letters, digits, \
                 '_', '-', '.' or ':'."
            ));
        }
        if RESERVED_CLAIMS.contains(&name) {
            return Err(format!(
                "\"{name}\" is a reserved claim and can't be copied from metadata."
            ));
        }
        claims.push(name.to_string());
    }
    if claims.len() > MAX_CLAIMS {
        return Err(format!("At most {MAX_CLAIMS} claims per resource."));
    }
    Ok(claims)
}

/// Caller-supplied fields for a new row; `enabled`, `corroboration` and the
/// timestamps come from the column defaults.
#[derive(Debug, Clone)]
pub struct NewResource {
    pub resource: String,
    pub display_name: String,
    pub org_id: String,
    pub created_by: String,
}

#[derive(Insertable)]
#[diesel(table_name = rr)]
struct InsertRow<'a> {
    resource: &'a str,
    display_name: &'a str,
    org_id: &'a str,
    created_by: &'a str,
}

/// The `resource` strings of enabled rows — the consent-time `allowed` arm.
pub async fn list_enabled(db: &DbPool) -> anyhow::Result<Vec<String>> {
    let resources: Vec<String> = db_interact!(db, |conn| {
        rr::table
            .filter(rr::enabled.eq(true))
            .select(rr::resource)
            .order(rr::resource.asc())
            .load(conn)
    })?;
    Ok(resources)
}

/// `(resource, claims)` for enabled rows that carry access-token claims.
pub async fn list_enabled_claims(db: &DbPool) -> anyhow::Result<Vec<(String, Vec<String>)>> {
    let rows: Vec<(String, String)> = db_interact!(db, |conn| {
        rr::table
            .filter(rr::enabled.eq(true))
            .filter(rr::access_token_claims.ne(""))
            .select((rr::resource, rr::access_token_claims))
            .order(rr::resource.asc())
            .load(conn)
    })?;
    Ok(rows
        .into_iter()
        .map(|(resource, claims)| {
            let claims = claims.split_whitespace().map(str::to_string).collect();
            (resource, claims)
        })
        .collect())
}

/// Replace a row's access-token claims. Zero-row match returns Ok.
pub async fn set_access_token_claims(
    db: &DbPool,
    id: i64,
    claims: &[String],
) -> anyhow::Result<()> {
    let joined = claims.join(" ");
    db_interact!(db, |conn| {
        diesel::update(rr::table.filter(rr::id.eq(id)))
            .set(rr::access_token_claims.eq(joined.clone()))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Every row, enabled or not, for the admin list.
pub async fn list_all(db: &DbPool) -> anyhow::Result<Vec<Row>> {
    let rows: Vec<Row> = db_interact!(db, |conn| {
        rr::table
            .select(Row::as_select())
            .order(rr::resource.asc())
            .load(conn)
    })?;
    Ok(rows)
}

/// INSERT a fresh row. Errs on a duplicate `resource` (UNIQUE) so the admin
/// create form can surface the conflict; the config-import path uses
/// [`insert_ignore`] instead.
pub async fn insert(db: &DbPool, new: NewResource) -> anyhow::Result<()> {
    db_interact!(db, |conn| {
        diesel::insert_into(rr::table)
            .values(InsertRow {
                resource: &new.resource,
                display_name: &new.display_name,
                org_id: &new.org_id,
                created_by: &new.created_by,
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Idempotent INSERT via ON CONFLICT DO NOTHING for the startup config
/// import. Returns whether a row was actually inserted.
pub async fn insert_ignore(db: &DbPool, new: NewResource) -> anyhow::Result<bool> {
    let n = db_interact!(db, |conn| {
        diesel::insert_into(rr::table)
            .values(InsertRow {
                resource: &new.resource,
                display_name: &new.display_name,
                org_id: &new.org_id,
                created_by: &new.created_by,
            })
            .on_conflict_do_nothing()
            .execute(conn)
    })?;
    Ok(n > 0)
}

/// Single row by id, for the admin per-row handlers and their scope check.
pub async fn get(db: &DbPool, id: i64) -> anyhow::Result<Option<Row>> {
    let row: Option<Row> = db_interact!(db, |conn| {
        rr::table
            .filter(rr::id.eq(id))
            .select(Row::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Row by its unique `resource` string (the admin create path re-reads the
/// fresh row's id after INSERT).
pub async fn find_by_resource(db: &DbPool, resource: &str) -> anyhow::Result<Option<Row>> {
    let r = resource.to_string();
    let row: Option<Row> = db_interact!(db, |conn| {
        rr::table
            .filter(rr::resource.eq(&r))
            .select(Row::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Flip a row's `enabled` flag. Zero-row match (unknown id) returns Ok.
pub async fn set_enabled(db: &DbPool, id: i64, enabled: bool) -> anyhow::Result<()> {
    db_interact!(db, |conn| {
        diesel::update(rr::table.filter(rr::id.eq(id)))
            .set(rr::enabled.eq(enabled))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Remove a row. Idempotent: deleting an unknown id returns Ok.
pub async fn delete(db: &DbPool, id: i64) -> anyhow::Result<()> {
    db_interact!(db, |conn| {
        diesel::delete(rr::table.filter(rr::id.eq(id)))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Record an RFC 9728 check result (a [`corroboration`] value) and stamp
/// `corroborated_at`. Zero-row match returns Ok.
pub async fn set_corroboration(db: &DbPool, id: i64, status: &str) -> anyhow::Result<()> {
    let status = status.to_string();
    let now = Utc::now().naive_utc();
    db_interact!(db, |conn| {
        diesel::update(rr::table.filter(rr::id.eq(id)))
            .set((
                rr::corroboration.eq(status.clone()),
                rr::corroborated_at.eq(Some(now)),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_resource(resource: &str) -> NewResource {
        NewResource {
            resource: resource.to_string(),
            display_name: resource.to_string(),
            org_id: "default".to_string(),
            created_by: "test@example.com".to_string(),
        }
    }

    #[tokio::test]
    async fn insert_defaults_and_list_enabled_excludes_disabled() {
        let db = crate::orgs::db::test_pool().await;

        insert(&db, new_resource("https://a.example.com/mcp"))
            .await
            .expect("insert a");
        insert(&db, new_resource("https://b.example.com/mcp"))
            .await
            .expect("insert b");

        let rows = list_all(&db).await.expect("list_all");
        assert_eq!(rows.len(), 2);
        let a = &rows[0];
        assert_eq!(a.resource, "https://a.example.com/mcp");
        assert!(a.enabled);
        assert_eq!(a.corroboration, corroboration::UNCHECKED);
        assert!(a.corroborated_at.is_none());
        assert_eq!(a.org_id, "default");
        assert_eq!(a.created_by.as_deref(), Some("test@example.com"));

        assert_eq!(
            list_enabled(&db).await.expect("list_enabled"),
            vec![
                "https://a.example.com/mcp".to_string(),
                "https://b.example.com/mcp".to_string(),
            ]
        );

        set_enabled(&db, a.id, false).await.expect("disable a");
        assert_eq!(
            list_enabled(&db).await.expect("list_enabled after disable"),
            vec!["https://b.example.com/mcp".to_string()]
        );
        // list_all still carries the disabled row, flag flipped.
        let rows = list_all(&db).await.expect("list_all after disable");
        assert_eq!(rows.len(), 2);
        assert!(!rows[0].enabled);

        set_enabled(&db, a.id, true).await.expect("re-enable a");
        assert_eq!(list_enabled(&db).await.expect("list_enabled").len(), 2);
    }

    #[test]
    fn parse_access_token_claims_validates_and_dedupes() {
        assert_eq!(parse_access_token_claims(""), Ok(vec![]));
        assert_eq!(
            parse_access_token_claims(" forgejo_aud, team:id  forgejo_aud\n"),
            Ok(vec!["forgejo_aud".to_string(), "team:id".to_string()])
        );
        for bad in ["sub", "ext", "nonce", "a b=c", "ünicode", &"x".repeat(65)] {
            assert!(
                parse_access_token_claims(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        let eleven = (0..11)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_access_token_claims(&eleven).is_err());
    }

    #[tokio::test]
    async fn access_token_claims_round_trip_and_skip_disabled_rows() {
        let db = crate::orgs::db::test_pool().await;
        insert(&db, new_resource("https://a.example.com/mcp"))
            .await
            .expect("insert a");
        insert(&db, new_resource("https://b.example.com/mcp"))
            .await
            .expect("insert b");
        let rows = list_all(&db).await.expect("list_all");
        assert_eq!(rows[0].access_token_claims, "");
        assert!(list_enabled_claims(&db).await.expect("none yet").is_empty());

        let claims = vec!["forgejo_aud".to_string(), "team".to_string()];
        set_access_token_claims(&db, rows[0].id, &claims)
            .await
            .expect("set claims");
        assert_eq!(
            get(&db, rows[0].id)
                .await
                .expect("get")
                .expect("row")
                .access_token_claims,
            "forgejo_aud team"
        );
        assert_eq!(
            list_enabled_claims(&db).await.expect("list_enabled_claims"),
            vec![("https://a.example.com/mcp".to_string(), claims.clone())]
        );

        set_enabled(&db, rows[0].id, false).await.expect("disable");
        assert!(list_enabled_claims(&db).await.expect("disabled").is_empty());

        set_enabled(&db, rows[0].id, true).await.expect("enable");
        set_access_token_claims(&db, rows[0].id, &[])
            .await
            .expect("clear claims");
        assert!(list_enabled_claims(&db).await.expect("cleared").is_empty());
    }

    #[tokio::test]
    async fn duplicate_resource_errs_on_insert_but_not_insert_ignore() {
        let db = crate::orgs::db::test_pool().await;

        insert(&db, new_resource("https://dup.example.com"))
            .await
            .expect("first insert");
        assert!(
            insert(&db, new_resource("https://dup.example.com"))
                .await
                .is_err(),
            "second insert of the same resource must hit the UNIQUE constraint"
        );

        assert!(
            !insert_ignore(&db, new_resource("https://dup.example.com"))
                .await
                .expect("insert_ignore existing"),
            "insert_ignore must report no row inserted for an existing resource"
        );
        assert!(
            insert_ignore(&db, new_resource("https://fresh.example.com"))
                .await
                .expect("insert_ignore fresh"),
            "insert_ignore must report the row inserted for a fresh resource"
        );
        assert_eq!(list_all(&db).await.expect("list_all").len(), 2);
    }

    #[tokio::test]
    async fn set_corroboration_stamps_timestamp() {
        let db = crate::orgs::db::test_pool().await;

        insert(&db, new_resource("https://c.example.com"))
            .await
            .expect("insert");
        let id = list_all(&db).await.expect("list_all")[0].id;

        set_corroboration(&db, id, corroboration::CORROBORATED)
            .await
            .expect("set_corroboration");
        let row = &list_all(&db).await.expect("list_all")[0];
        assert_eq!(row.corroboration, corroboration::CORROBORATED);
        let first = row.corroborated_at.expect("corroborated_at stamped");

        set_corroboration(&db, id, corroboration::UNREACHABLE)
            .await
            .expect("re-check");
        let row = &list_all(&db).await.expect("list_all")[0];
        assert_eq!(row.corroboration, corroboration::UNREACHABLE);
        assert!(
            row.corroborated_at.expect("still stamped") >= first,
            "re-check must refresh the stamp"
        );
    }

    #[tokio::test]
    async fn delete_removes_row_and_is_idempotent() {
        let db = crate::orgs::db::test_pool().await;

        insert(&db, new_resource("https://d.example.com"))
            .await
            .expect("insert");
        let id = list_all(&db).await.expect("list_all")[0].id;

        delete(&db, id).await.expect("delete");
        assert!(list_all(&db).await.expect("list_all").is_empty());
        assert!(list_enabled(&db).await.expect("list_enabled").is_empty());

        delete(&db, id).await.expect("delete unknown id");
    }

    #[tokio::test]
    async fn row_without_created_by_round_trips() {
        let db = crate::orgs::db::test_pool().await;
        let inserted: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::insert_into(rr::table)
                    .values((
                        rr::resource.eq("https://anon.example.com/mcp"),
                        rr::display_name.eq("anon"),
                        rr::org_id.eq("default"),
                        rr::created_by.eq(None::<String>),
                    ))
                    .execute(conn)
            })?)
        }
        .await;
        assert_eq!(inserted.unwrap(), 1);
        let rows = list_all(&db).await.expect("list_all");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].created_by, None);
        assert_eq!(rows[0].resource, "https://anon.example.com/mcp");
        assert!(rows[0].enabled);
    }
}
