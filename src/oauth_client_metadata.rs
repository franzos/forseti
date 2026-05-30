//! Forseti-owned trust-boundary state for Hydra OAuth2 clients.
//!
//! Why this lives Forseti-side rather than on `metadata.forseti.*` of the
//! Hydra client itself: DCR-registered clients receive a
//! `registration_access_token` (RAT) in the response of `POST
//! /oauth2/register`. RFC 7592's PUT `/oauth2/register/{id}` (Hydra
//! handles that directly — Forseti does not proxy that path) lets the
//! RAT-bearer replace the full client representation, **including
//! `metadata`**. So if verification state lived on the Hydra client, a
//! self-registered client could flip its own
//! `metadata.forseti.verification` from `"unverified"` to `"verified"`
//! and forge the trust badge on the consent screen. Verified against
//! Hydra v26.2.0 `client/handler.go::setOidcDynamicClient` (lines 285,
//! 338-388), which persists the request's `Metadata` field
//! unconditionally.
//!
//! Everything in this module reads/writes the `oauth_client_metadata`
//! table only. The RAT cannot reach this table — there is no Forseti
//! route that mutates rows based on a Hydra-issued credential.
//!
//! Trust-boundary fields:
//!
//! - `verification`: `"verified"` | `"unverified"`. Drives the consent
//!   badge and the admin list filter.
//! - `verified_by` / `verified_at`: who vouched and when. Preserved on
//!   revocation so the trust history survives.
//! - `verification_revoked_by` / `verification_revoked_at`: who pulled
//!   the vouch and when. Cleared on re-verification.
//! - `source`: `"admin"` | `"dcr"`. Provenance. Drives the
//!   "Self-registered" pill on the admin list.
//! - `dcr_iat_id` / `dcr_registered_at`: link back to the IAT used for
//!   self-registration. Durable counterpart to the audit row.
//!
//! Back-compat: a missing row defaults to `verified` on the consent
//! screen and admin list. Clients created before this table existed
//! came in through the admin UI, which is the act of vouching — the
//! implicit-trust rule applies retroactively. Lazy creation on first
//! verify/unverify action handles the trickle of legacy clients
//! touched by an admin.

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

/// Full row projection for the read paths. `verification`-as-string is
/// preserved (rather than collapsed to a bool) so the diesel column
/// shape stays in sync with the table — callers that only need the bool
/// use [`Row::is_verified`].
// `Selectable` selects every column so the projection stays in lockstep
// with the table; several columns aren't field-accessed in Rust yet.
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
    /// First observed `resource=` URL on the auth URL, or the first
    /// entry of `requested_access_token_audience` as a fallback.
    /// Captured lazily on the client's first successful consent and
    /// never overwritten — first-writer-wins via a `WHERE resource_url
    /// IS NULL` predicate.
    pub resource_url: Option<String>,
    /// Owning organization id. Defaults to `'default'` for clients
    /// created before orgs landed (backfilled by the migration). Read
    /// path lands in a follow-up (step 11 in
    /// `TODO_LICENSING_FEATURES.md`) — the field is part of the row
    /// shape today so we don't have to migrate the diesel projection
    /// again when filter UIs ship.
    pub org_id: String,
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
}

/// Fetch the row for `client_id`. `Ok(None)` when no row exists — the
/// caller decides how to treat the missing-row case (consent screen +
/// admin list both default to "verified" for legacy clients; verify /
/// unverify lazily insert).
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

/// Fetch rows for a batch of client ids. Result vector is unordered;
/// callers index it through a `client_id` lookup. Used by the admin
/// list page to merge verification state in memory after Hydra returns
/// the page of clients (Hydra owns the clients table, Forseti owns
/// the metadata table — we can't `JOIN` across them, so the merge
/// happens in Rust).
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

/// INSERT a fresh row for a DCR-registered client. Called from the DCR
/// proxy after Hydra confirms the registration. `iat_id` is `Some` when
/// the registration presented a valid Initial Access Token, and `None`
/// for anonymous DCR (the default — Claude and friends self-register
/// without any way to present an IAT, so the proxy lets them through and
/// relies on the `unverified` badge + admin review as the safety
/// mechanism). Returns Err if the row already exists (which shouldn't
/// happen — `client_id` is Hydra-minted and globally unique) so the
/// caller can log loudly without retrying.
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
    now: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    let now_str = now.to_rfc3339();
    let id = client_id.to_string();
    let admin = admin_email.to_string();
    let org = org_id.to_string();
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
            })
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

/// Inside an open transaction (concrete connection `$c`): fetch the prior
/// verification state for `$id` ("verified" / "unverified" / "missing")
/// and, when no row exists, lazy-insert a baseline `unverified` /
/// `source = "admin"` legacy row so the caller's follow-up UPDATE always
/// lands. Legacy clients predate this table; they came in via the admin
/// UI, hence the `"admin"` provenance. Evaluates to the prior state.
///
/// A macro (not a function) because `db_interact!` monomorphizes the
/// transaction body for both the SQLite and Postgres connection types —
/// a shared helper would need full dual-backend diesel bounds.
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

/// Stamp `resource_url` on the row for `client_id`, but only when it
/// hasn't been recorded yet. Called from the consent flow after Hydra
/// accepts the grant, so Forseti captures "what is this client
/// actually used to talk to?" without depending on the DCR caller
/// having declared an audience up front.
///
/// First-writer-wins: the UPDATE predicate `WHERE resource_url IS NULL`
/// means concurrent first-consents from multiple users can't race —
/// subsequent writers find zero rows match and the UPDATE is a no-op.
/// Returns Ok even when the predicate matched zero rows (already
/// captured, or no row at all for this client — legacy clients without
/// Forseti metadata).
/// Count rows belonging to `org_id`. Used as the org-delete precondition
/// check — refuses to drop the org row while any client still references
/// it, so we don't orphan Hydra clients (which Forseti can't
/// authoritatively migrate without operator input).
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
