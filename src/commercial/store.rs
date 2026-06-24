//! Persistence for the activated license.
//!
//! The `forseti_license` table is singleton (PK pinned to the literal
//! `'singleton'` in both the sqlite and Postgres schemas), so the two
//! operations Forseti needs collapse to:
//!
//!  * `load` — read the single row at boot, decode + verify the blob,
//!    return a [`LicenseStatus`] (or `Unlicensed` when the table is
//!    empty).
//!  * `save` — upsert the row from a verified license.
//!  * `clear` — DELETE the row on operator-initiated deactivation.

use chrono::Utc;
use diesel::prelude::*;

use crate::commercial::license::{classify, License, LicenseStatus};
use crate::commercial::verify;
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::forseti_license;

/// Hard-coded primary key — enforced by the `CHECK (id = 'singleton')`
/// constraint in the migration.
const SINGLETON_ID: &str = "singleton";

/// Single marketed tier today; written to the denormalised `tier` column
/// for operator inspection only. The runtime never branches on it.
const TIER_WIRE: &str = "business";

// The other columns are kept denormalized for operator inspection of the DB;
// the runtime only reads `blob` and re-derives the rest from the verified blob.
#[derive(Insertable, AsChangeset)]
#[diesel(table_name = forseti_license)]
struct UpsertRow {
    id: String,
    blob: String,
    license_id: String,
    customer: String,
    email: String,
    tier: String,
    issued_at: String,
    expires_at: Option<String>,
    features: String,
    max_orgs: Option<i32>,
    max_seats: Option<i32>,
    activated_at: String,
    verified_at: String,
}

/// Read + verify the persisted license at boot. Returns
/// [`LicenseStatus::Unlicensed`] when the table is empty (OSS-tier).
///
/// Verification failure on a previously-accepted blob (e.g. someone
/// rotated the pubkey but didn't re-issue) logs a warning and falls back
/// to `Unlicensed` so Forseti still boots — the operator has to
/// re-activate via the settings page.
pub async fn load(db: &DbPool, grace_days: i64) -> LicenseStatus {
    let status = match read_row(db).await {
        Ok(None) => LicenseStatus::Unlicensed,
        Ok(Some(blob)) => match verify::decode_and_verify(&blob) {
            Ok(license) => classify(license, grace_days, Utc::now()),
            Err(e) => {
                tracing::warn!(error = %e, "license: persisted blob no longer verifies (likely pubkey rotated); operator must re-activate");
                LicenseStatus::Unlicensed
            }
        },
        Err(e) => {
            tracing::error!(error = ?e, "license: failed to read row at boot; treating as unlicensed");
            LicenseStatus::Unlicensed
        }
    };
    log_status(&status);
    status
}

fn log_status(status: &LicenseStatus) {
    match status {
        LicenseStatus::Unlicensed => tracing::info!("license: unlicensed (OSS tier)"),
        LicenseStatus::Active(l) => tracing::info!(
            customer = %l.customer,
            features = ?l.features,
            expires_at = ?l.expires_at,
            "license: active"
        ),
        LicenseStatus::Grace(l) => tracing::warn!(
            customer = %l.customer,
            expires_at = ?l.expires_at,
            "license: in grace period (past expiry, gated features read-only)"
        ),
        LicenseStatus::Expired(l) => tracing::warn!(
            customer = %l.customer,
            expires_at = ?l.expires_at,
            "license: expired past grace window; gated features locked"
        ),
    }
}

async fn read_row(db: &DbPool) -> anyhow::Result<Option<String>> {
    let blob: Option<String> = db_interact!(db, |conn| {
        forseti_license::table
            .filter(forseti_license::id.eq(SINGLETON_ID))
            .select(forseti_license::blob)
            .first(conn)
            .optional()
    })?;
    Ok(blob)
}

/// Upsert the singleton row from a freshly-verified license. Called by
/// the activate handler after [`verify::decode_and_verify`] returns Ok.
pub async fn save(db: &DbPool, blob: &str, license: &License) -> anyhow::Result<()> {
    let max_orgs = license
        .max_orgs
        .map(i32::try_from)
        .transpose()
        .map_err(|_| anyhow::anyhow!("license max_orgs exceeds i32::MAX"))?;
    let max_seats = license
        .max_seats
        .map(i32::try_from)
        .transpose()
        .map_err(|_| anyhow::anyhow!("license max_seats exceeds i32::MAX"))?;
    let row = UpsertRow {
        id: SINGLETON_ID.into(),
        blob: blob.trim().to_string(),
        license_id: license.license_id.clone(),
        customer: license.customer.clone(),
        email: license.email.clone(),
        tier: TIER_WIRE.to_string(),
        issued_at: license.issued_at.to_rfc3339(),
        expires_at: license.expires_at.map(|d| d.to_rfc3339()),
        features: serde_json::to_string(
            &license
                .features
                .iter()
                .map(|f| f.wire_name())
                .collect::<Vec<_>>(),
        )?,
        max_orgs,
        max_seats,
        activated_at: Utc::now().to_rfc3339(),
        verified_at: Utc::now().to_rfc3339(),
    };
    db_interact!(db, |conn| {
        // Diesel's per-backend upsert helpers diverge between sqlite and
        // postgres, so we do the classic transactional delete + insert.
        // The PK is fixed so the row count stays exactly one.
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(forseti_license::table.filter(forseti_license::id.eq(SINGLETON_ID)))
                .execute(c)?;
            diesel::insert_into(forseti_license::table)
                .values(&row)
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

/// Delete the singleton row (operator-initiated deactivation).
pub async fn clear(db: &DbPool) -> anyhow::Result<()> {
    db_interact!(db, |conn| {
        diesel::delete(forseti_license::table.filter(forseti_license::id.eq(SINGLETON_ID)))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}
