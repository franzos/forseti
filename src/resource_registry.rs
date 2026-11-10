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
use crate::orgs::DEFAULT_ORG_ID;
use crate::schema::organization_members as om;
use crate::schema::resource_registry as rr;
use crate::{db_interact, serialized_txn};

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
    /// Empty when self-service is off; see [`Row::self_service`].
    pub self_service_claim: String,
    pub self_service_issuer: String,
    pub self_service_client_id: String,
    pub self_service_template: String,
}

/// Upstream OIDC public client through which users prove the value of one of
/// the row's access-token claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfService {
    pub claim: String,
    pub issuer: String,
    pub client_id: String,
    pub template: String,
}

impl Row {
    pub fn self_service(&self) -> Option<SelfService> {
        if self.self_service_claim.is_empty() {
            return None;
        }
        Some(SelfService {
            claim: self.self_service_claim.clone(),
            issuer: self.self_service_issuer.clone(),
            client_id: self.self_service_client_id.clone(),
            template: self.self_service_template.clone(),
        })
    }
}

/// A write that would let a self-service claim appear on more than one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimConflict {
    pub claim: String,
}

impl std::fmt::Display for ClaimConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "claim \"{}\" is already used by another resource",
            self.claim
        )
    }
}

impl std::error::Error for ClaimConflict {}

enum TxnError {
    Db(diesel::result::Error),
    Conflict(String),
}

impl From<diesel::result::Error> for TxnError {
    fn from(e: diesel::result::Error) -> Self {
        Self::Db(e)
    }
}

impl TxnError {
    /// `self_service_claim` names the conflict when the partial unique index
    /// fires, which is the only unique column these updates write.
    fn into_anyhow(self, self_service_claim: &str) -> anyhow::Error {
        match self {
            Self::Conflict(claim) => ClaimConflict { claim }.into(),
            Self::Db(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) if !self_service_claim.is_empty() => ClaimConflict {
                claim: self_service_claim.to_string(),
            }
            .into(),
            Self::Db(e) => e.into(),
        }
    }
}

/// Serializes conflict-checked writes so the cross-row check can't race.
trait LockRegistry {
    fn lock_registry(&mut self) -> diesel::QueryResult<()>;
}

impl LockRegistry for diesel::sqlite::SqliteConnection {
    // `serialized_txn!` already opens sqlite transactions with BEGIN IMMEDIATE.
    fn lock_registry(&mut self) -> diesel::QueryResult<()> {
        Ok(())
    }
}

impl LockRegistry for diesel::pg::PgConnection {
    // READ COMMITTED alone lets two writers each miss the other's new claim.
    fn lock_registry(&mut self) -> diesel::QueryResult<()> {
        diesel::sql_query("LOCK TABLE resource_registry IN SHARE ROW EXCLUSIVE MODE")
            .execute(self)
            .map(|_| ())
    }
}

#[diesel::dsl::auto_type]
fn other_rows(except_id: i64) -> _ {
    rr::table
        .filter(rr::id.ne(except_id))
        .select((rr::self_service_claim, rr::access_token_claims))
}

/// The first claim that conflicts with a row other than `except_id`:
/// `self_service_claim` when another row has it as its self-service claim or
/// lists it, else any of `claims` that is another row's self-service claim.
/// An empty `self_service_claim` checks `claims` only.
fn claim_conflict<C>(
    conn: &mut C,
    except_id: i64,
    self_service_claim: &str,
    claims: &[String],
) -> diesel::QueryResult<Option<String>>
where
    C: Connection + LockRegistry,
    for<'a> other_rows: diesel::query_dsl::LoadQuery<'a, C, (String, String)>,
{
    conn.lock_registry()?;
    let others: Vec<(String, String)> = other_rows(except_id).load(conn)?;
    Ok(find_conflict(&others, self_service_claim, claims))
}

fn find_conflict(
    others: &[(String, String)],
    self_service_claim: &str,
    claims: &[String],
) -> Option<String> {
    for (other_self_service, other_claims) in others {
        if !self_service_claim.is_empty()
            && (other_self_service == self_service_claim
                || other_claims
                    .split_whitespace()
                    .any(|c| c == self_service_claim))
        {
            return Some(self_service_claim.to_string());
        }
        if !other_self_service.is_empty()
            && let Some(claim) = claims.iter().find(|c| *c == other_self_service)
        {
            return Some(claim.clone());
        }
    }
    None
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

/// Replace a row's access-token claims. Errs with [`ClaimConflict`] when one
/// of them is another row's self-service claim. Zero-row match returns Ok.
pub async fn set_access_token_claims(
    db: &DbPool,
    id: i64,
    claims: &[String],
) -> anyhow::Result<()> {
    let claims = claims.to_vec();
    let result = serialized_txn!(db, (), TxnError, |c| {
        if let Some(claim) = claim_conflict(c, id, "", &claims)? {
            return Err(TxnError::Conflict(claim));
        }
        diesel::update(rr::table.filter(rr::id.eq(id)))
            .set(rr::access_token_claims.eq(claims.join(" ")))
            .execute(c)?;
        Ok(())
    });
    result.map_err(|e| e.into_anyhow(""))
}

/// Replace a row's access-token claims and self-service config together;
/// `None` turns self-service off. Errs with [`ClaimConflict`] when the
/// self-service claim appears on another row, or one of `claims` is another
/// row's self-service claim. Zero-row match returns Ok.
pub async fn set_claims_and_self_service(
    db: &DbPool,
    id: i64,
    claims: &[String],
    self_service: Option<&SelfService>,
) -> anyhow::Result<()> {
    let claims = claims.to_vec();
    let ss = self_service.cloned().unwrap_or(SelfService {
        claim: String::new(),
        issuer: String::new(),
        client_id: String::new(),
        template: String::new(),
    });
    let ss_claim = ss.claim.clone();
    let result = serialized_txn!(db, (), TxnError, |c| {
        if let Some(claim) = claim_conflict(c, id, &ss.claim, &claims)? {
            return Err(TxnError::Conflict(claim));
        }
        diesel::update(rr::table.filter(rr::id.eq(id)))
            .set((
                rr::access_token_claims.eq(claims.join(" ")),
                rr::self_service_claim.eq(&ss.claim),
                rr::self_service_issuer.eq(&ss.issuer),
                rr::self_service_client_id.eq(&ss.client_id),
                rr::self_service_template.eq(&ss.template),
            ))
            .execute(c)?;
        Ok(())
    });
    result.map_err(|e| e.into_anyhow(&ss_claim))
}

/// Enabled rows with self-service configured.
pub async fn list_self_service(db: &DbPool) -> anyhow::Result<Vec<Row>> {
    let rows: Vec<Row> = db_interact!(db, |conn| {
        rr::table
            .filter(rr::enabled.eq(true))
            .filter(rr::self_service_claim.ne(""))
            .select(Row::as_select())
            .order(rr::resource.asc())
            .load(conn)
    })?;
    Ok(rows)
}

/// The rows `identity_id` may see: default-org rows for everyone, others
/// only for members of the row's org.
pub async fn visible_to(
    db: &DbPool,
    identity_id: &str,
    rows: Vec<Row>,
) -> anyhow::Result<Vec<Row>> {
    let mut orgs: Vec<String> = rows
        .iter()
        .filter(|r| r.org_id != DEFAULT_ORG_ID)
        .map(|r| r.org_id.clone())
        .collect();
    orgs.sort();
    orgs.dedup();
    let member_of: Vec<String> = if orgs.is_empty() {
        Vec::new()
    } else {
        let identity_id = identity_id.to_string();
        db_interact!(db, |conn| {
            om::table
                .filter(om::identity_id.eq(&identity_id))
                .filter(om::org_id.eq_any(&orgs))
                .select(om::org_id)
                .load(conn)
        })?
    };
    Ok(rows
        .into_iter()
        .filter(|r| r.org_id == DEFAULT_ORG_ID || member_of.contains(&r.org_id))
        .collect())
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

    fn self_service(claim: &str) -> SelfService {
        SelfService {
            claim: claim.to_string(),
            issuer: "https://git.example.com".to_string(),
            client_id: "client-1".to_string(),
            template: "u:{sub}:{uuid}".to_string(),
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    async fn two_rows(db: &DbPool) -> (i64, i64) {
        insert(db, new_resource("https://a.example.com/mcp"))
            .await
            .expect("insert a");
        insert(db, new_resource("https://b.example.com/mcp"))
            .await
            .expect("insert b");
        let rows = list_all(db).await.expect("list_all");
        (rows[0].id, rows[1].id)
    }

    fn conflict_claim(r: anyhow::Result<()>) -> String {
        r.expect_err("must conflict")
            .downcast::<ClaimConflict>()
            .expect("ClaimConflict")
            .claim
    }

    #[tokio::test]
    async fn self_service_round_trip_and_listing() {
        let db = crate::orgs::db::test_pool().await;
        let (a, _) = two_rows(&db).await;
        assert!(get(&db, a).await.unwrap().unwrap().self_service().is_none());
        assert!(list_self_service(&db).await.unwrap().is_empty());

        let ss = self_service("forgejo_aud");
        set_claims_and_self_service(&db, a, &strings(&["forgejo_aud", "team"]), Some(&ss))
            .await
            .expect("set");
        let row = get(&db, a).await.unwrap().unwrap();
        assert_eq!(row.access_token_claims, "forgejo_aud team");
        assert_eq!(row.self_service(), Some(ss.clone()));
        let listed = list_self_service(&db).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, a);

        set_enabled(&db, a, false).await.unwrap();
        assert!(list_self_service(&db).await.unwrap().is_empty());
        set_enabled(&db, a, true).await.unwrap();

        set_claims_and_self_service(&db, a, &strings(&["forgejo_aud"]), None)
            .await
            .expect("turn off");
        let row = get(&db, a).await.unwrap().unwrap();
        assert_eq!(row.access_token_claims, "forgejo_aud");
        assert!(row.self_service().is_none());
        assert_eq!(row.self_service_issuer, "");
        assert!(list_self_service(&db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn self_service_claim_index_is_unique_when_set() {
        let db = crate::orgs::db::test_pool().await;
        let (a, b) = two_rows(&db).await;
        let set = |id: i64, claim: &'static str| {
            let db = db.clone();
            async move {
                let r: anyhow::Result<diesel::QueryResult<usize>> = async {
                    Ok(db_interact!(db, |conn| {
                        diesel::update(rr::table.filter(rr::id.eq(id)))
                            .set(rr::self_service_claim.eq(claim))
                            .execute(conn)
                    }))
                }
                .await;
                r.expect("interact")
            }
        };
        set(a, "forgejo_aud").await.expect("first row");
        let err = set(b, "forgejo_aud").await.expect_err("index must refuse");
        assert!(matches!(
            err,
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _
            )
        ));
        set(b, "other").await.expect("distinct claim");
        set(a, "").await.expect("clear a");
        set(b, "").await.expect("empty claims don't collide");
    }

    #[test]
    fn unique_violation_maps_to_claim_conflict() {
        let e = TxnError::Db(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            Box::new(String::from("UNIQUE constraint failed")),
        ))
        .into_anyhow("forgejo_aud");
        assert_eq!(
            e.downcast::<ClaimConflict>().expect("ClaimConflict").claim,
            "forgejo_aud"
        );
    }

    #[tokio::test]
    async fn self_service_claim_conflicts_in_both_directions() {
        let db = crate::orgs::db::test_pool().await;
        let (a, b) = two_rows(&db).await;
        set_claims_and_self_service(&db, a, &strings(&["aud_x"]), Some(&self_service("aud_x")))
            .await
            .expect("a owns aud_x");

        // Another row may not list a self-service claim, through either setter.
        assert_eq!(
            conflict_claim(set_access_token_claims(&db, b, &strings(&["team", "aud_x"])).await),
            "aud_x"
        );
        assert_eq!(
            conflict_claim(set_claims_and_self_service(&db, b, &strings(&["aud_x"]), None).await),
            "aud_x"
        );
        assert_eq!(
            conflict_claim(
                set_claims_and_self_service(
                    &db,
                    b,
                    &strings(&["aud_x"]),
                    Some(&self_service("aud_x"))
                )
                .await
            ),
            "aud_x"
        );
        assert_eq!(get(&db, b).await.unwrap().unwrap().access_token_claims, "");

        // A claim another row lists may not become a self-service claim.
        set_access_token_claims(&db, b, &strings(&["shared"]))
            .await
            .expect("plain claim on b");
        assert_eq!(
            conflict_claim(
                set_claims_and_self_service(
                    &db,
                    a,
                    &strings(&["aud_x", "shared"]),
                    Some(&self_service("shared"))
                )
                .await
            ),
            "shared"
        );
        let row = get(&db, a).await.unwrap().unwrap();
        assert_eq!(row.self_service_claim, "aud_x");
        assert_eq!(row.access_token_claims, "aud_x");

        // Plain claims may be shared, and a row never conflicts with itself.
        set_access_token_claims(&db, a, &strings(&["aud_x", "shared"]))
            .await
            .expect("plain claim shared");
        set_claims_and_self_service(
            &db,
            a,
            &strings(&["aud_x", "shared"]),
            Some(&self_service("aud_x")),
        )
        .await
        .expect("rewrite own self-service claim");
    }

    #[tokio::test]
    async fn visible_to_default_org_for_everyone_named_org_for_members() {
        use crate::orgs::{Role, db as orgs_db};

        let db = crate::orgs::db::test_pool().await;
        for org in ["org-a", "org-b"] {
            orgs_db::create_org(&db, org, org, org, None)
                .await
                .expect("create org");
        }
        orgs_db::add_member_race_safe(&db, "ident-1", "org-a", Role::Member)
            .await
            .expect("add member");
        for (resource, org) in [
            ("https://default.example.com", DEFAULT_ORG_ID),
            ("https://a.example.com", "org-a"),
            ("https://b.example.com", "org-b"),
        ] {
            insert(
                &db,
                NewResource {
                    org_id: org.to_string(),
                    ..new_resource(resource)
                },
            )
            .await
            .expect("insert");
        }
        let visible = |ident: &'static str| {
            let db = db.clone();
            async move {
                let rows = list_all(&db).await.expect("list_all");
                visible_to(&db, ident, rows)
                    .await
                    .expect("visible_to")
                    .into_iter()
                    .map(|r| r.org_id)
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(visible("ident-1").await, vec!["org-a", DEFAULT_ORG_ID]);
        assert_eq!(visible("ident-2").await, vec![DEFAULT_ORG_ID]);
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
