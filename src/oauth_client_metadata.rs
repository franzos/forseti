//! Forseti-owned trust-boundary state for Hydra OAuth2 clients.
//!
//! Why this lives Forseti-side, not on the Hydra client's
//! `metadata.forseti.*`: a DCR client's `registration_access_token` (RAT)
//! can PUT the full client representation via RFC 7592 (Hydra-handled),
//! including `metadata`. So trust state on the Hydra client would be
//! self-forgeable: a client could flip its own `verification` to
//! `"verified"`. This table is unreachable by the RAT (no Forseti route
//! mutates it from a Hydra-issued credential).
//!
//! Back-compat: a missing row defaults to `verified`; legacy clients came in
//! through the admin UI (the act of vouching). Verify/unverify lazily insert
//! a row for legacy clients an admin touches.

use chrono::Utc;
use diesel::prelude::*;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::oauth_client_metadata as ocm;

/// Source provenance values. Keep in sync with the column default in
/// the migration.
pub mod source {
    /// Created through the admin UI. Implicitly verified at create time.
    pub const ADMIN: &str = "admin";
    /// Self-registered via the DCR proxy. Always starts `unverified`.
    pub const DCR: &str = "dcr";
}

/// Verification state values.
pub mod verification {
    pub const VERIFIED: &str = "verified";
    pub const UNVERIFIED: &str = "unverified";
}

/// Full row projection for the read paths. `verification` stays a string to
/// match the column; bool-only callers use [`Row::is_verified`].
// Selects every column to stay in lockstep with the table; several columns
// aren't field-accessed in Rust yet.
#[allow(dead_code)]
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = ocm)]
pub struct Row {
    pub client_id: String,
    pub verification: String,
    pub verified_by: Option<String>,
    pub verified_at: Option<String>,
    pub verification_revoked_by: Option<String>,
    pub verification_revoked_at: Option<String>,
    pub source: String,
    pub dcr_iat_id: Option<String>,
    pub dcr_registered_at: Option<String>,
    pub created_at: String,
    /// DCR caller-declared audience (space-separated). Captured at
    /// registration time when the body carried `audience: [...]`. NULL
    /// for clients that didn't declare one — `resource_url` may still
    /// be set lazily on first consent for those.
    pub audience: Option<String>,
    /// First observed `resource=` URL (or first audience entry). Captured
    /// lazily on first consent, first-writer-wins via `WHERE resource_url IS
    /// NULL`.
    pub resource_url: Option<String>,
    /// Owning organization id; defaults to `'default'` for pre-orgs clients.
    pub org_id: String,
    /// Curated app-template slug stamped at admin-create time; drives the
    /// app logo on the client list. Cosmetic only.
    pub template_slug: Option<String>,
}

impl Row {
    pub fn is_verified(&self) -> bool {
        self.verification == verification::VERIFIED
    }

    /// True when this row records a DCR-registered client. Drives the
    /// "Self-registered" badge.
    pub fn is_self_registered(&self) -> bool {
        self.source == source::DCR
    }
}

#[derive(Insertable)]
#[diesel(table_name = ocm)]
struct InsertRow<'a> {
    client_id: &'a str,
    verification: &'a str,
    verified_by: Option<&'a str>,
    verified_at: Option<String>,
    source: &'a str,
    dcr_iat_id: Option<&'a str>,
    dcr_registered_at: Option<String>,
    created_at: String,
    audience: Option<&'a str>,
    resource_url: Option<&'a str>,
    org_id: &'a str,
    template_slug: Option<&'a str>,
}

/// Fetch the row for `client_id`. `Ok(None)` when none exists; the caller
/// decides the missing-row case (consent + admin list default to "verified").
pub async fn get(db: &DbPool, client_id: &str) -> anyhow::Result<Option<Row>> {
    let id = client_id.to_string();
    let row: Option<Row> = db_interact!(db, |conn| {
        ocm::table
            .filter(ocm::client_id.eq(&id))
            .select(Row::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Fetch rows for a batch of client ids (unordered). The admin list merges
/// these with Hydra's clients in Rust, since the two tables can't be JOINed.
pub async fn get_many(db: &DbPool, client_ids: &[String]) -> anyhow::Result<Vec<Row>> {
    if client_ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = client_ids.to_vec();
    let rows: Vec<Row> = db_interact!(db, |conn| {
        ocm::table
            .filter(ocm::client_id.eq_any(&ids))
            .select(Row::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// INSERT a fresh row for a DCR-registered client (always `unverified`).
/// `iat_id` is `Some` for an IAT-bound registration, `None` for anonymous.
/// Errs if the row exists (shouldn't, `client_id` is Hydra-minted) so the
/// caller logs loudly without retrying.
pub async fn insert_dcr(
    db: &DbPool,
    client_id: &str,
    iat_id: Option<&str>,
    audience: Option<&str>,
    org_id: &str,
    now: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    let now_str = now.to_rfc3339();
    let id = client_id.to_string();
    let iat = iat_id.map(str::to_string);
    let aud = audience.map(str::to_string);
    let org = org_id.to_string();
    db_interact!(db, |conn| {
        diesel::insert_into(ocm::table)
            .values(InsertRow {
                client_id: &id,
                verification: verification::UNVERIFIED,
                verified_by: None,
                verified_at: None,
                source: source::DCR,
                dcr_iat_id: iat.as_deref(),
                dcr_registered_at: Some(now_str.clone()),
                created_at: now_str.clone(),
                audience: aud.as_deref(),
                resource_url: None,
                org_id: &org,
                template_slug: None,
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// INSERT a fresh row for an admin-created client. Implicitly verified
/// — the act of an admin creating the client through the form is the
/// vouching.
pub async fn insert_admin_verified(
    db: &DbPool,
    client_id: &str,
    admin_email: &str,
    org_id: &str,
    template_slug: Option<&str>,
    now: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    let now_str = now.to_rfc3339();
    let id = client_id.to_string();
    let admin = admin_email.to_string();
    let org = org_id.to_string();
    let template = template_slug.map(str::to_string);
    db_interact!(db, |conn| {
        diesel::insert_into(ocm::table)
            .values(InsertRow {
                client_id: &id,
                verification: verification::VERIFIED,
                verified_by: Some(&admin),
                verified_at: Some(now_str.clone()),
                source: source::ADMIN,
                dcr_iat_id: None,
                dcr_registered_at: None,
                created_at: now_str.clone(),
                audience: None,
                resource_url: None,
                org_id: &org,
                template_slug: template.as_deref(),
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Inside an open transaction (`$c`): return the prior verification state for
/// `$id` ("verified"/"unverified"/"missing"), lazy-inserting a baseline
/// `unverified`/`source = "admin"` row when absent so the caller's UPDATE
/// always lands.
///
/// A macro, not a function: `db_interact!` monomorphizes the body for both
/// connection types, and a shared helper would need full dual-backend bounds.
macro_rules! ensure_row_and_prior {
    ($c:expr, $id:expr, $now:expr) => {{
        let existing: Option<Row> = ocm::table
            .filter(ocm::client_id.eq($id))
            .select(Row::as_select())
            .first($c)
            .optional()?;
        match existing {
            Some(r) => r.verification,
            None => {
                diesel::insert_into(ocm::table)
                    .values(InsertRow {
                        client_id: $id,
                        verification: verification::UNVERIFIED,
                        verified_by: None,
                        verified_at: None,
                        source: source::ADMIN,
                        dcr_iat_id: None,
                        dcr_registered_at: None,
                        created_at: $now.clone(),
                        audience: None,
                        resource_url: None,
                        org_id: crate::orgs::DEFAULT_ORG_ID,
                        template_slug: None,
                    })
                    .execute($c)?;
                "missing".to_string()
            }
        }
    }};
}

/// Flip `verification` to `"verified"`, record the vouching admin +
/// timestamp, and clear any prior revocation markers. If no row exists
/// (legacy client created before this table shipped), one is lazily
/// inserted first (see [`ensure_row_and_prior`]).
///
/// Returns the prior verification state ("verified" / "unverified" /
/// "missing") so the audit row can record what flipped.
pub async fn mark_verified(
    db: &DbPool,
    client_id: &str,
    admin_email: &str,
) -> anyhow::Result<String> {
    let now = Utc::now().to_rfc3339();
    let id = client_id.to_string();
    let admin = admin_email.to_string();
    let prior: String = db_interact!(db, |conn| {
        conn.transaction::<String, diesel::result::Error, _>(|c| {
            let prior = ensure_row_and_prior!(c, &id, now);
            diesel::update(ocm::table.filter(ocm::client_id.eq(&id)))
                .set((
                    ocm::verification.eq(verification::VERIFIED),
                    ocm::verified_by.eq(Some(admin.clone())),
                    ocm::verified_at.eq(Some(now.clone())),
                    ocm::verification_revoked_by.eq::<Option<String>>(None),
                    ocm::verification_revoked_at.eq::<Option<String>>(None),
                ))
                .execute(c)?;
            Ok(prior)
        })
    })?;
    Ok(prior)
}

/// Flip `verification` to `"unverified"`, record the revoking admin +
/// timestamp. `verified_by` / `verified_at` are left in place so the
/// trust history survives the revocation. Lazy-inserts when no row
/// exists (a legacy client being unverified for the first time; see
/// [`ensure_row_and_prior`]).
///
/// Returns the prior verification state ("verified" / "unverified" /
/// "missing").
pub async fn mark_unverified(
    db: &DbPool,
    client_id: &str,
    admin_email: &str,
) -> anyhow::Result<String> {
    let now = Utc::now().to_rfc3339();
    let id = client_id.to_string();
    let admin = admin_email.to_string();
    let prior: String = db_interact!(db, |conn| {
        conn.transaction::<String, diesel::result::Error, _>(|c| {
            let prior = ensure_row_and_prior!(c, &id, now);
            diesel::update(ocm::table.filter(ocm::client_id.eq(&id)))
                .set((
                    ocm::verification.eq(verification::UNVERIFIED),
                    ocm::verification_revoked_by.eq(Some(admin.clone())),
                    ocm::verification_revoked_at.eq(Some(now.clone())),
                ))
                .execute(c)?;
            Ok(prior)
        })
    })?;
    Ok(prior)
}

/// Count rows belonging to `org_id`. The org-delete precondition: refuses to
/// drop the org while any client references it, so Hydra clients aren't
/// orphaned.
pub async fn count_for_org(db: &DbPool, org_id: &str) -> anyhow::Result<u32> {
    let org = org_id.to_string();
    let n: i64 = db_interact!(db, |conn| {
        ocm::table
            .filter(ocm::org_id.eq(&org))
            .count()
            .get_result(conn)
    })?;
    Ok(n.max(0) as u32)
}

/// Stamp `resource_url` only when not yet recorded. First-writer-wins via
/// `WHERE resource_url IS NULL`; a zero-row match (already captured, or no
/// row) still returns Ok.
pub async fn upsert_resource_url_if_missing(
    db: &DbPool,
    client_id: &str,
    resource_url: &str,
) -> anyhow::Result<()> {
    let id = client_id.to_string();
    let url = resource_url.to_string();
    db_interact!(db, |conn| {
        diesel::update(
            ocm::table
                .filter(ocm::client_id.eq(&id))
                .filter(ocm::resource_url.is_null()),
        )
        .set(ocm::resource_url.eq(Some(url.clone())))
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}
