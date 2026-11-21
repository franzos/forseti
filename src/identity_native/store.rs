//! Identity rows and their conversion to the domain [`Identity`].

use std::collections::HashMap;

use anyhow::{Result, bail};
use diesel::prelude::*;
use diesel::query_dsl::LoadQuery;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde_json::{Map, Value, json};

use super::codes::MailedCode;
use super::flows::FlowRow;
use crate::backend::identity::{
    Credential, FlowKind, Identity, IdentityState, RecoveryAddress, VerifiableAddress,
};
use crate::db::DbPool;
use crate::schema::{
    identities, identity_codes, identity_credentials, identity_flows, identity_mail_outbox,
    identity_oidc_links, identity_sessions, offline_secrets, oidc_links,
};
use crate::{db_interact, serialized_txn};

/// Most characters in a first or last name.
pub(super) const NAME_MAX_CHARS: usize = 256;

/// Kratos caps `page_size` at 1000.
pub(super) const MAX_PAGE_SIZE: i64 = 1000;

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = identities)]
pub(super) struct IdentityRow {
    pub id: String,
    pub email: String,
    pub email_norm: String,
    pub email_verified_at: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub preferred_language: Option<String>,
    pub state: String,
    pub state_changed_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub metadata_public: Option<String>,
    pub metadata_admin: Option<String>,
    /// Set the first time the address is verified and never cleared.
    pub first_verified_at: Option<String>,
}

/// One credential kind of an identity, without its config. Provider links appear as one `oidc`
/// summary.
#[derive(Debug, Clone)]
pub(super) struct CredentialSummary {
    pub kind: String,
    pub version: i32,
    pub created_at: String,
    pub updated_at: String,
    /// `provider:subject` per link on the `oidc` summary; empty on stored credentials.
    pub links: Vec<String>,
}

/// One upstream provider account linked to an identity.
#[derive(Queryable, Selectable, Insertable, Debug, Clone, PartialEq)]
#[diesel(table_name = identity_oidc_links)]
pub(super) struct LinkRow {
    pub provider: String,
    pub subject: String,
    pub identity_id: String,
    pub created_at: String,
}

type CredentialCols = (String, String, i32, String, String);
type LinkCols = (String, String, String, String);

#[diesel::dsl::auto_type]
fn credentials_of(ids: Vec<String>) -> _ {
    identity_credentials::table
        .filter(identity_credentials::identity_id.eq_any(ids))
        .select((
            identity_credentials::identity_id,
            identity_credentials::kind,
            identity_credentials::version,
            identity_credentials::created_at,
            identity_credentials::updated_at,
        ))
}

#[diesel::dsl::auto_type]
fn links_of_identities(ids: Vec<String>) -> _ {
    identity_oidc_links::table
        .filter(identity_oidc_links::identity_id.eq_any(ids))
        .order((identity_oidc_links::provider, identity_oidc_links::subject))
        .select((
            identity_oidc_links::identity_id,
            identity_oidc_links::provider,
            identity_oidc_links::subject,
            identity_oidc_links::created_at,
        ))
}

/// The credential summaries of each of `ids`, keyed by identity id; identities without any are
/// absent. Runs on the caller's connection so it can share a checkout with the rows it decorates.
pub(super) fn credential_summaries<C>(
    conn: &mut C,
    ids: &[String],
) -> QueryResult<HashMap<String, Vec<CredentialSummary>>>
where
    for<'a> credentials_of: LoadQuery<'a, C, CredentialCols>,
    for<'a> links_of_identities: LoadQuery<'a, C, LinkCols>,
{
    let mut by_identity: HashMap<String, Vec<CredentialSummary>> = HashMap::new();
    if ids.is_empty() {
        return Ok(by_identity);
    }
    let creds: Vec<CredentialCols> = credentials_of(ids.to_vec()).load(conn)?;
    for (identity_id, kind, version, created_at, updated_at) in creds {
        by_identity
            .entry(identity_id)
            .or_default()
            .push(CredentialSummary {
                kind,
                version,
                created_at,
                updated_at,
                links: Vec::new(),
            });
    }
    let links: Vec<LinkCols> = links_of_identities(ids.to_vec()).load(conn)?;
    let mut oidc: HashMap<String, CredentialSummary> = HashMap::new();
    for (identity_id, provider, subject, created_at) in links {
        let summary = oidc
            .entry(identity_id)
            .or_insert_with(|| CredentialSummary {
                kind: "oidc".to_string(),
                version: 0,
                created_at: created_at.clone(),
                updated_at: created_at.clone(),
                links: Vec::new(),
            });
        if created_at < summary.created_at {
            summary.created_at.clone_from(&created_at);
        }
        if created_at > summary.updated_at {
            summary.updated_at = created_at;
        }
        summary.links.push(format!("{provider}:{subject}"));
    }
    for (identity_id, summary) in oidc {
        by_identity.entry(identity_id).or_default().push(summary);
    }
    Ok(by_identity)
}

/// One credential with its config, which holds secrets and never leaves this module tree.
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = identity_credentials)]
pub(super) struct CredentialRow {
    pub id: String,
    pub config: String,
    pub version: i32,
}

/// Kratos's identity schema caps the address at 320 characters.
pub(super) const EMAIL_MAX_CHARS: usize = 320;

/// Whether `email` may be stored and mailed to.
pub(super) fn is_mailable(email: &str) -> bool {
    crate::mailer::is_valid_email(email)
}

fn ensure_mailable(email: &str) -> Result<()> {
    if !is_mailable(email) {
        bail!("the address has characters the native identity store does not accept");
    }
    Ok(())
}

/// Lookup key for an email address: matching is case-insensitive.
pub(super) fn email_norm(email: &str) -> String {
    email.to_lowercase()
}

/// Key of an attempt counter for an address someone typed: a fixed-size hash, so the counters
/// never hold the text.
pub(super) fn address_key(email: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(email_norm(email).as_bytes()))
}

fn state_str(state: IdentityState) -> &'static str {
    match state {
        IdentityState::Active => "active",
        IdentityState::Inactive => "inactive",
    }
}

// Anything but "active" reads as inactive so a bad value fails closed.
fn parse_state(s: &str) -> IdentityState {
    if s == "active" {
        IdentityState::Active
    } else {
        IdentityState::Inactive
    }
}

fn parse_json(field: &str, text: Option<&str>) -> Result<Option<Value>> {
    text.map(|t| {
        serde_json::from_str(t).map_err(|e| anyhow::anyhow!("identities.{field} is not JSON: {e}"))
    })
    .transpose()
}

pub(super) fn to_identity(row: IdentityRow, creds: Vec<CredentialSummary>) -> Result<Identity> {
    let mut traits = Map::new();
    traits.insert("email".into(), json!(row.email));
    let mut name = Map::new();
    if let Some(first) = &row.first_name {
        name.insert("first".into(), json!(first));
    }
    if let Some(last) = &row.last_name {
        name.insert("last".into(), json!(last));
    }
    if !name.is_empty() {
        traits.insert("name".into(), Value::Object(name));
    }
    if let Some(lang) = &row.preferred_language {
        traits.insert("preferred_language".into(), json!(lang));
    }

    // Kratos identifies password credentials by the lowercased email, second factors by the
    // identity id, oidc by `provider:subject`.
    let credentials: HashMap<String, Credential> = creds
        .into_iter()
        .map(|c| {
            let identifiers = match c.kind.as_str() {
                "oidc" => c.links,
                "password" => vec![row.email_norm.clone()],
                _ => vec![row.id.clone()],
            };
            let cred = Credential {
                identifiers: Some(identifiers),
                config: None,
                created_at: Some(c.created_at),
                updated_at: Some(c.updated_at),
                version: Some(i64::from(c.version)),
            };
            (c.kind, cred)
        })
        .collect();

    let verified = row.email_verified_at.is_some();
    Ok(Identity {
        schema_id: "default".to_string(),
        traits: Some(Value::Object(traits)),
        state: Some(parse_state(&row.state)),
        state_changed_at: Some(row.state_changed_at),
        external_id: None,
        organization_id: None,
        metadata_public: parse_json("metadata_public", row.metadata_public.as_deref())?,
        metadata_admin: parse_json("metadata_admin", row.metadata_admin.as_deref())?,
        verifiable_addresses: Some(vec![VerifiableAddress {
            id: None,
            value: row.email.clone(),
            via: "email".to_string(),
            status: if verified { "completed" } else { "pending" }.to_string(),
            verified,
            verified_at: row.email_verified_at,
            created_at: Some(row.created_at.clone()),
            updated_at: Some(row.updated_at.clone()),
        }]),
        recovery_addresses: Some(vec![RecoveryAddress {
            id: None,
            value: row.email,
            via: "email".to_string(),
            created_at: Some(row.created_at.clone()),
            updated_at: Some(row.updated_at.clone()),
        }]),
        credentials: (!credentials.is_empty()).then_some(credentials),
        // Needs the configured providers; the backend sets it.
        sole_sign_in_is_oidc: None,
        id: row.id,
        created_at: Some(row.created_at),
        updated_at: Some(row.updated_at),
    })
}

/// Attach each row's credential summaries; keeps the row order.
async fn with_credentials(db: &DbPool, rows: Vec<IdentityRow>) -> Result<Vec<Identity>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let mut by_identity = db_interact!(db, |conn| { credential_summaries(conn, &ids) })?;
    rows.into_iter()
        .map(|row| {
            let creds = by_identity.remove(&row.id).unwrap_or_default();
            to_identity(row, creds)
        })
        .collect()
}

async fn one(db: &DbPool, row: Option<IdentityRow>) -> Result<Option<Identity>> {
    Ok(with_credentials(db, row.into_iter().collect()).await?.pop())
}

pub(super) async fn get(db: &DbPool, id: &str) -> Result<Option<Identity>> {
    let id = id.to_string();
    let row = db_interact!(db, |conn| {
        identities::table
            .find(&id)
            .select(IdentityRow::as_select())
            .first(conn)
            .optional()
    })?;
    one(db, row).await
}

/// The identity holding `email` and whether that address is verified.
pub(super) async fn find_by_email(db: &DbPool, email: &str) -> Result<Option<(Identity, bool)>> {
    let norm = email_norm(email);
    let row = db_interact!(db, |conn| {
        identities::table
            .filter(identities::email_norm.eq(&norm))
            .select(IdentityRow::as_select())
            .first(conn)
            .optional()
    })?;
    let verified = row.as_ref().is_some_and(|r| r.email_verified_at.is_some());
    Ok(one(db, row).await?.map(|identity| (identity, verified)))
}

/// The identity holding `email` and its password credential config, in one query so a known and
/// an unknown address cost the same round trips.
pub(super) async fn login_target(
    db: &DbPool,
    email: &str,
) -> Result<Option<(IdentityRow, Option<String>)>> {
    let norm = email_norm(email);
    Ok(db_interact!(db, |conn| {
        identities::table
            .left_join(
                identity_credentials::table.on(identity_credentials::identity_id
                    .eq(identities::id)
                    .and(identity_credentials::kind.eq("password"))),
            )
            .filter(identities::email_norm.eq(&norm))
            .select((
                IdentityRow::as_select(),
                identity_credentials::config.nullable(),
            ))
            .first(conn)
            .optional()
    })?)
}

/// The identity row holding `email`, without credentials.
pub(super) async fn row_by_email(db: &DbPool, email: &str) -> Result<Option<IdentityRow>> {
    let norm = email_norm(email);
    Ok(db_interact!(db, |conn| {
        identities::table
            .filter(identities::email_norm.eq(&norm))
            .select(IdentityRow::as_select())
            .first(conn)
            .optional()
    })?)
}

/// Mark the identity's address verified, if it is still `email`, and stamp `first_verified_at`
/// unless it already is. The row afterwards; `None` when the identity is gone or holds another
/// address now.
pub(super) async fn mark_verified(
    db: &DbPool,
    id: &str,
    email: &str,
) -> Result<Option<IdentityRow>> {
    let (id, norm) = (id.to_string(), email_norm(email));
    let now = crate::db::now_rfc3339();
    Ok(db_interact!(db, |conn| {
        conn.transaction(|c| {
            let target = identities::table
                .find(&id)
                .filter(identities::email_norm.eq(&norm));
            diesel::update(target.filter(identities::email_verified_at.is_null()))
                .set((
                    identities::email_verified_at.eq(&now),
                    identities::updated_at.eq(&now),
                ))
                .execute(c)?;
            diesel::update(target.filter(identities::first_verified_at.is_null()))
                .set(identities::first_verified_at.eq(&now))
                .execute(c)?;
            target.select(IdentityRow::as_select()).first(c).optional()
        })
    })?)
}

/// Insert an active, unverified identity and its password credential in one transaction;
/// `Ok(None)` when the address is already taken, and then nothing is written.
pub(super) async fn create_with_password(
    db: &DbPool,
    email: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    password_config: &str,
) -> Result<Option<IdentityRow>> {
    ensure_mailable(email)?;
    let now = crate::db::now_rfc3339();
    let row = IdentityRow {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.to_string(),
        email_norm: email_norm(email),
        email_verified_at: None,
        first_name: first_name.map(str::to_string),
        last_name: last_name.map(str::to_string),
        preferred_language: None,
        state: state_str(IdentityState::Active).to_string(),
        state_changed_at: now.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
        metadata_public: None,
        metadata_admin: None,
        first_verified_at: None,
    };
    let (insert, config) = (row.clone(), password_config.to_string());
    let outcome = db_interact!(db, |conn| {
        Ok::<_, DieselError>(conn.transaction::<_, Taken, _>(|c| {
            diesel::insert_into(identities::table)
                .values(&insert)
                .execute(c)
                .map_err(|e| match e {
                    DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                        Taken::Address
                    }
                    other => Taken::Db(other),
                })?;
            diesel::insert_into(identity_credentials::table)
                .values((
                    identity_credentials::id.eq(uuid::Uuid::new_v4().to_string()),
                    identity_credentials::identity_id.eq(&insert.id),
                    identity_credentials::kind.eq("password"),
                    identity_credentials::config.eq(&config),
                    identity_credentials::version.eq(0),
                    identity_credentials::created_at.eq(&now),
                    identity_credentials::updated_at.eq(&now),
                ))
                .execute(c)?;
            Ok(())
        }))
    })?;
    match outcome {
        Ok(()) => Ok(Some(row)),
        Err(Taken::Address) => Ok(None),
        Err(Taken::Db(e)) => Err(e.into()),
    }
}

/// Why a transaction rolled back: a unique constraint (the address, or a provider account
/// already linked) or another database error.
enum Taken {
    Address,
    Db(DieselError),
}

impl From<DieselError> for Taken {
    fn from(e: DieselError) -> Self {
        Self::Db(e)
    }
}

/// The identity row with this id, without credentials.
pub(super) async fn row_by_id(db: &DbPool, id: &str) -> Result<Option<IdentityRow>> {
    let id = id.to_string();
    Ok(db_interact!(db, |conn| {
        identities::table
            .find(&id)
            .select(IdentityRow::as_select())
            .first(conn)
            .optional()
    })?)
}

pub(super) fn is_active(row: &IdentityRow) -> bool {
    parse_state(&row.state) == IdentityState::Active
}

/// The identity's credential of `kind` (`password`, `totp`, `lookup_secret`).
pub(super) async fn credential(
    db: &DbPool,
    identity_id: &str,
    kind: &str,
) -> Result<Option<CredentialRow>> {
    let (identity_id, kind) = (identity_id.to_string(), kind.to_string());
    Ok(db_interact!(db, |conn| {
        identity_credentials::table
            .filter(identity_credentials::identity_id.eq(&identity_id))
            .filter(identity_credentials::kind.eq(&kind))
            .select(CredentialRow::as_select())
            .first(conn)
            .optional()
    })?)
}

/// Insert a credential at version 0; `false` when the identity already has one of `kind`.
#[cfg(test)]
pub(super) async fn insert_credential(
    db: &DbPool,
    identity_id: &str,
    kind: &str,
    config: &str,
) -> Result<bool> {
    let (identity_id, kind, config) = (
        identity_id.to_string(),
        kind.to_string(),
        config.to_string(),
    );
    let now = crate::db::now_rfc3339();
    Ok(db_interact!(db, |conn| {
        match diesel::insert_into(identity_credentials::table)
            .values((
                identity_credentials::id.eq(uuid::Uuid::new_v4().to_string()),
                identity_credentials::identity_id.eq(&identity_id),
                identity_credentials::kind.eq(&kind),
                identity_credentials::config.eq(&config),
                identity_credentials::version.eq(0),
                identity_credentials::created_at.eq(&now),
                identity_credentials::updated_at.eq(&now),
            ))
            .execute(conn)
        {
            Ok(_) => Ok(true),
            Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => Ok(false),
            Err(e) => Err(e),
        }
    })?)
}

/// Replace a credential's config if it is still at `version`, bumping the version. `false` when
/// another writer got there first.
pub(super) async fn swap_credential_config(
    db: &DbPool,
    id: &str,
    version: i32,
    config: &str,
) -> Result<bool> {
    let (id, config) = (id.to_string(), config.to_string());
    let now = crate::db::now_rfc3339();
    let updated = db_interact!(db, |conn| {
        diesel::update(
            identity_credentials::table
                .find(&id)
                .filter(identity_credentials::version.eq(version)),
        )
        .set((
            identity_credentials::config.eq(&config),
            identity_credentials::version.eq(version + 1),
            identity_credentials::updated_at.eq(&now),
        ))
        .execute(conn)
    })?;
    Ok(updated > 0)
}

/// The submitting browser of a settings write: its session, which must still be live when the
/// write runs, and whether the write needs an identity whose address was verified once.
#[derive(Debug, Clone, Copy)]
pub(super) struct Writer<'a> {
    pub(super) identity_id: &'a str,
    pub(super) session_id: &'a str,
    pub(super) verified_only: bool,
}

/// Why a [`Writer`]'s write was refused; nothing was written.
#[derive(Debug, PartialEq)]
pub(super) enum Refused {
    /// The session was revoked or expired, or the identity is gone.
    SignedOut,
    NotVerified,
}

#[diesel::dsl::auto_type]
fn identity_lock(identity_id: String) -> _ {
    diesel::dsl::update(identities::table.filter(identities::id.eq(identity_id)))
        .set(identities::updated_at.eq(identities::updated_at))
}

#[diesel::dsl::auto_type]
fn live_session(session_id: String, identity_id: String, now: String) -> _ {
    identity_sessions::table
        .filter(identity_sessions::id.eq(session_id))
        .filter(identity_sessions::identity_id.eq(identity_id))
        .filter(identity_sessions::revoked_at.is_null())
        .filter(identity_sessions::expires_at.gt(now))
        .select(identity_sessions::id)
}

#[diesel::dsl::auto_type]
fn first_verified_of(identity_id: String) -> _ {
    identities::table
        .filter(identities::id.eq(identity_id))
        .select(identities::first_verified_at)
}

/// Take the identity row lock [`verify_recovered`] takes, then check the writer's session is
/// still live and, for a gated write, the identity verified once. Runs first in the write's
/// serialized transaction, so a reset either committed before and is seen, or waits.
fn admit<C>(conn: &mut C, writer: &OwnedWriter) -> QueryResult<Option<Refused>>
where
    C: Connection,
    identity_lock: diesel::query_dsl::methods::ExecuteDsl<C>,
    for<'a> live_session: LoadQuery<'a, C, String>,
    for<'a> first_verified_of: LoadQuery<'a, C, Option<String>>,
{
    if identity_lock(writer.identity_id.clone()).execute(conn)? == 0 {
        return Ok(Some(Refused::SignedOut));
    }
    let live: Vec<String> = live_session(
        writer.session_id.clone(),
        writer.identity_id.clone(),
        crate::db::now_rfc3339(),
    )
    .load(conn)?;
    if live.is_empty() {
        return Ok(Some(Refused::SignedOut));
    }
    if writer.verified_only {
        let first: Vec<Option<String>> =
            first_verified_of(writer.identity_id.clone()).load(conn)?;
        if first.into_iter().flatten().next().is_none() {
            return Ok(Some(Refused::NotVerified));
        }
    }
    Ok(None)
}

/// A [`Writer`] that moves into a pool closure.
struct OwnedWriter {
    identity_id: String,
    session_id: String,
    verified_only: bool,
}

impl From<Writer<'_>> for OwnedWriter {
    fn from(w: Writer<'_>) -> Self {
        Self {
            identity_id: w.identity_id.to_string(),
            session_id: w.session_id.to_string(),
            verified_only: w.verified_only,
        }
    }
}

/// Store `config` as the writer's identity's credential of `kind`. `replace` overwrites one it
/// has, bumping its version; without it an existing one is kept and the answer is `Ok(false)`.
pub(super) async fn write_credential(
    db: &DbPool,
    writer: Writer<'_>,
    kind: &str,
    config: &str,
    replace: bool,
) -> Result<Result<bool, Refused>> {
    let writer = OwnedWriter::from(writer);
    let (kind, config) = (kind.to_string(), config.to_string());
    let now = crate::db::now_rfc3339();
    Ok(
        serialized_txn!(db, Result<bool, Refused>, DieselError, |c| {
            if let Some(refused) = admit(c, &writer)? {
                return Ok(Err(refused));
            }
            let own = identity_credentials::table
                .filter(identity_credentials::identity_id.eq(&writer.identity_id))
                .filter(identity_credentials::kind.eq(&kind));
            if diesel::select(diesel::dsl::exists(own)).get_result::<bool>(c)? {
                if !replace {
                    return Ok(Ok(false));
                }
                diesel::update(own)
                    .set((
                        identity_credentials::config.eq(&config),
                        identity_credentials::version.eq(identity_credentials::version + 1),
                        identity_credentials::updated_at.eq(&now),
                    ))
                    .execute(c)?;
                return Ok(Ok(true));
            }
            diesel::insert_into(identity_credentials::table)
                .values((
                    identity_credentials::id.eq(uuid::Uuid::new_v4().to_string()),
                    identity_credentials::identity_id.eq(&writer.identity_id),
                    identity_credentials::kind.eq(&kind),
                    identity_credentials::config.eq(&config),
                    identity_credentials::version.eq(0),
                    identity_credentials::created_at.eq(&now),
                    identity_credentials::updated_at.eq(&now),
                ))
                .execute(c)?;
            Ok(Ok(true))
        })?,
    )
}

/// Delete the identity's credentials of `kinds` in one statement; returns how many went.
pub(super) async fn delete_credentials(
    db: &DbPool,
    identity_id: &str,
    kinds: &[&str],
) -> Result<usize> {
    let identity_id = identity_id.to_string();
    let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_string()).collect();
    Ok(db_interact!(db, |conn| {
        diesel::delete(
            identity_credentials::table
                .filter(identity_credentials::identity_id.eq(&identity_id))
                .filter(identity_credentials::kind.eq_any(&kinds)),
        )
        .execute(conn)
    })?)
}

/// How [`update_profile`] ended.
#[derive(Debug, PartialEq)]
pub(super) enum ProfileSaved {
    Saved,
    /// Another identity holds the new address; nothing was written.
    Taken,
    Gone,
    /// The writer's session is no longer live; nothing was written.
    SignedOut,
}

/// A new address and the verification flow, code and mail that go with it.
pub(super) struct AddressChange {
    pub(super) email: String,
    pub(super) verification: FlowRow,
    pub(super) code: MailedCode,
}

/// Set the identity's names and, given `change`, request a new address: the identity keeps its
/// address until the change's code is entered ([`apply_address_change`]). Earlier pending changes
/// of the identity and their codes are dropped, and the change's flow, code and mail are stored,
/// all in one transaction behind the writer's [`admit`]. `Taken` when another identity holds the
/// new address now; then nothing is written.
pub(super) async fn update_profile(
    db: &DbPool,
    writer: Writer<'_>,
    first_name: Option<&str>,
    last_name: Option<&str>,
    change: Option<AddressChange>,
) -> Result<ProfileSaved> {
    if let Some(change) = &change {
        ensure_mailable(&change.email)?;
    }
    let writer = OwnedWriter::from(writer);
    let first = first_name.map(str::to_string);
    let last = last_name.map(str::to_string);
    let now = crate::db::now_rfc3339();
    Ok(serialized_txn!(db, ProfileSaved, DieselError, |c| {
        if admit(c, &writer)?.is_some() {
            return Ok(ProfileSaved::SignedOut);
        }
        let id = &writer.identity_id;
        if let Some(change) = &change {
            let held = identities::table
                .filter(identities::email_norm.eq(email_norm(&change.email)))
                .filter(identities::id.ne(id));
            if diesel::select(diesel::dsl::exists(held)).get_result::<bool>(c)? {
                return Ok(ProfileSaved::Taken);
            }
        }
        let updated = diesel::update(identities::table.find(id))
            .set((
                identities::first_name.eq(&first),
                identities::last_name.eq(&last),
                identities::updated_at.eq(&now),
            ))
            .execute(c)?;
        if updated == 0 {
            return Ok(ProfileSaved::Gone);
        }
        if let Some(change) = &change {
            let pending: Vec<String> = identity_flows::table
                .filter(identity_flows::identity_id.eq(id))
                .filter(identity_flows::kind.eq(FlowKind::Verification.path_segment()))
                .select(identity_flows::id)
                .load(c)?;
            diesel::delete(identity_codes::table.filter(identity_codes::flow_id.eq_any(&pending)))
                .execute(c)?;
            diesel::delete(identity_flows::table.filter(identity_flows::id.eq_any(&pending)))
                .execute(c)?;
            diesel::insert_into(identity_flows::table)
                .values(&change.verification)
                .execute(c)?;
            diesel::insert_into(identity_codes::table)
                .values(&change.code.code)
                .execute(c)?;
            diesel::insert_into(identity_mail_outbox::table)
                .values(&change.code.mail)
                .execute(c)?;
        }
        Ok(ProfileSaved::Saved)
    })?)
}

/// How [`apply_address_change`] ended.
#[derive(Debug)]
pub(super) enum AddressApplied {
    /// The identity holds the new address, verified; its row afterwards.
    Applied(Box<IdentityRow>),
    /// Another identity holds the address; nothing was written.
    Taken,
    /// The identity is gone or inactive; nothing was written.
    Gone,
    /// The writer's session is no longer live; nothing was written.
    SignedOut,
}

/// Move the writer's identity to `email`, proven by the code just used: verified now,
/// `first_verified_at` stamped if it was not, and every code of the identity retired, under the
/// identity row lock and the writer's [`admit`].
pub(super) async fn apply_address_change(
    db: &DbPool,
    writer: Writer<'_>,
    email: &str,
) -> Result<AddressApplied> {
    ensure_mailable(email)?;
    let writer = OwnedWriter::from(writer);
    let (email, norm) = (email.to_string(), email_norm(email));
    let now = crate::db::now_rfc3339();
    let outcome = serialized_txn!(db, AddressApplied, Taken, |c| {
        if admit(c, &writer)?.is_some() {
            return Ok(AddressApplied::SignedOut);
        }
        let id = &writer.identity_id;
        let target = identities::table.find(id);
        let row: IdentityRow = target.select(IdentityRow::as_select()).first(c)?;
        if !is_active(&row) {
            return Ok(AddressApplied::Gone);
        }
        diesel::update(target)
            .set((
                identities::email.eq(&email),
                identities::email_norm.eq(&norm),
                identities::email_verified_at.eq(&now),
                identities::updated_at.eq(&now),
            ))
            .execute(c)
            .map_err(|e| match e {
                DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => Taken::Address,
                other => Taken::Db(other),
            })?;
        diesel::update(target.filter(identities::first_verified_at.is_null()))
            .set(identities::first_verified_at.eq(&now))
            .execute(c)?;
        diesel::delete(identity_codes::table.filter(identity_codes::identity_id.eq(id)))
            .execute(c)?;
        Ok(AddressApplied::Applied(Box::new(
            target.select(IdentityRow::as_select()).first(c)?,
        )))
    });
    match outcome {
        Ok(applied) => Ok(applied),
        Err(Taken::Address) => Ok(AddressApplied::Taken),
        Err(Taken::Db(e)) => Err(e.into()),
    }
}

/// One page ordered `created_at DESC, id DESC`. `after` is the id of the last row of the previous
/// page; an unknown id gives an empty page. `email` keeps only the identity with exactly that address.
pub(super) async fn list(
    db: &DbPool,
    page_size: i64,
    after: Option<&str>,
    email: Option<&str>,
) -> Result<Vec<Identity>> {
    let limit = page_size.clamp(1, MAX_PAGE_SIZE);
    let after = after.map(str::to_string);
    let norm = email.map(email_norm);
    let rows: Vec<IdentityRow> = db_interact!(db, |conn| {
        let cursor = match &after {
            None => None,
            Some(token) => {
                let found = identities::table
                    .find(token)
                    .select((identities::created_at, identities::id))
                    .first::<(String, String)>(conn)
                    .optional()?;
                match found {
                    Some(c) => Some(c),
                    None => return Ok(Vec::new()),
                }
            }
        };
        let mut query = identities::table
            .select(IdentityRow::as_select())
            .order((identities::created_at.desc(), identities::id.desc()))
            .limit(limit)
            .into_boxed();
        if let Some((created, id)) = cursor {
            query = query.filter(
                identities::created_at
                    .lt(created.clone())
                    .or(identities::created_at
                        .eq(created)
                        .and(identities::id.lt(id))),
            );
        }
        if let Some(norm) = &norm {
            query = query.filter(identities::email_norm.eq(norm.clone()));
        }
        query.load(conn)
    })?;
    with_credentials(db, rows).await
}

pub(super) async fn list_by_ids(db: &DbPool, ids: Vec<String>) -> Result<Vec<Identity>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<IdentityRow> = db_interact!(db, |conn| {
        identities::table
            .filter(identities::id.eq_any(&ids))
            .select(IdentityRow::as_select())
            .load(conn)
    })?;
    with_credentials(db, rows).await
}

/// Insert an active identity; `Ok(None)` when the address is already taken.
pub(super) async fn create(
    db: &DbPool,
    email: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    verified: bool,
) -> Result<Option<Identity>> {
    ensure_mailable(email)?;
    let now = crate::db::now_rfc3339();
    let row = IdentityRow {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.to_string(),
        email_norm: email_norm(email),
        email_verified_at: verified.then(|| now.clone()),
        first_name: first_name.map(str::to_string),
        last_name: last_name.map(str::to_string),
        preferred_language: None,
        state: state_str(IdentityState::Active).to_string(),
        state_changed_at: now.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
        metadata_public: None,
        metadata_admin: None,
        first_verified_at: verified.then_some(now),
    };
    let insert = row.clone();
    let inserted = db_interact!(db, |conn| {
        match diesel::insert_into(identities::table)
            .values(&insert)
            .execute(conn)
        {
            Ok(_) => Ok(true),
            Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => Ok(false),
            Err(e) => Err(e),
        }
    })?;
    if !inserted {
        return Ok(None);
    }
    to_identity(row, Vec::new()).map(Some)
}

/// `false` when the identity does not exist.
pub(super) async fn set_language(db: &DbPool, id: &str, lang: &str) -> Result<bool> {
    let (id, lang) = (id.to_string(), lang.to_string());
    let now = crate::db::now_rfc3339();
    let updated = db_interact!(db, |conn| {
        diesel::update(identities::table.find(&id))
            .set((
                identities::preferred_language.eq(&lang),
                identities::updated_at.eq(&now),
            ))
            .execute(conn)
    })?;
    Ok(updated > 0)
}

/// `state_changed_at` moves only when the state actually changes.
pub(super) async fn set_state(db: &DbPool, id: &str, state: IdentityState) -> Result<()> {
    let id = id.to_string();
    let state = state_str(state);
    let now = crate::db::now_rfc3339();
    db_interact!(db, |conn| {
        diesel::update(
            identities::table
                .find(&id)
                .filter(identities::state.ne(state)),
        )
        .set((
            identities::state.eq(state),
            identities::state_changed_at.eq(&now),
            identities::updated_at.eq(&now),
        ))
        .execute(conn)
    })?;
    Ok(())
}

/// Sets (`Some`) or removes (`None`) one key of a `metadata_admin` object and leaves every other key
/// alone; a null document counts as empty. Returns the new document, `None` when nothing changes,
/// and whether the key held a non-null value before.
fn patch_metadata_key(
    current: Option<&str>,
    key: &str,
    value: Option<&str>,
) -> Result<(Option<String>, bool)> {
    let mut map = match parse_json("metadata_admin", current)? {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map,
        Some(_) => bail!("metadata_admin is not an object"),
    };
    let was_set = map.get(key).is_some_and(|v| !v.is_null());
    let changed = match value {
        Some(v) => {
            map.insert(key.to_string(), Value::String(v.to_string()));
            true
        }
        None => map.remove(key).is_some(),
    };
    let doc = changed.then(|| Value::Object(map).to_string());
    Ok((doc, was_set))
}

/// Read-modify-write rounds before a contended metadata patch gives up.
const METADATA_PATCH_ATTEMPTS: usize = 5;

/// [`patch_metadata_key`] on a stored identity; `None` when the identity does not exist. The write
/// only lands if the document is still the one read, so concurrent patches of different keys both
/// survive on either database.
pub(super) async fn patch_metadata_admin(
    db: &DbPool,
    id: &str,
    key: &str,
    value: Option<&str>,
) -> Result<Option<bool>> {
    let (id, key, value) = (id.to_string(), key.to_string(), value.map(str::to_string));
    let now = crate::db::now_rfc3339();
    db_interact!(db, |c| {
        for _ in 0..METADATA_PATCH_ATTEMPTS {
            let current: Option<Option<String>> = identities::table
                .find(&id)
                .select(identities::metadata_admin)
                .first(c)
                .optional()?;
            let Some(current) = current else {
                return Ok(None);
            };
            let (doc, was_set) = patch_metadata_key(current.as_deref(), &key, value.as_deref())?;
            let Some(doc) = doc else {
                return Ok(Some(was_set));
            };
            let changes = (
                identities::metadata_admin.eq(doc),
                identities::updated_at.eq(&now),
            );
            let target = identities::table.find(&id);
            let swapped = match &current {
                Some(prev) => diesel::update(target.filter(identities::metadata_admin.eq(prev)))
                    .set(changes)
                    .execute(c)?,
                None => diesel::update(target.filter(identities::metadata_admin.is_null()))
                    .set(changes)
                    .execute(c)?,
            };
            if swapped > 0 {
                return Ok(Some(was_set));
            }
        }
        Err(anyhow::anyhow!(
            "metadata_admin of identity {id} changed on every one of {METADATA_PATCH_ATTEMPTS} attempts"
        ))
    })
}

/// Delete an identity; its credentials, sessions, flows, codes and mail go with it through
/// `ON DELETE CASCADE`. `false` when it did not exist.
pub(super) async fn delete(db: &DbPool, id: &str) -> Result<bool> {
    let id = id.to_string();
    let deleted = db_interact!(db, |conn| {
        diesel::delete(identities::table.find(&id)).execute(conn)
    })?;
    Ok(deleted > 0)
}

fn new_link(provider: &str, subject: &str, identity_id: &str, created_at: &str) -> LinkRow {
    LinkRow {
        provider: provider.to_string(),
        subject: subject.to_string(),
        identity_id: identity_id.to_string(),
        created_at: created_at.to_string(),
    }
}

/// The identity linked to `subject` at `provider`.
pub(super) async fn link_owner(
    db: &DbPool,
    provider: &str,
    subject: &str,
) -> Result<Option<String>> {
    let (provider, subject) = (provider.to_string(), subject.to_string());
    Ok(db_interact!(db, |conn| {
        identity_oidc_links::table
            .find((&provider, &subject))
            .select(identity_oidc_links::identity_id)
            .first(conn)
            .optional()
    })?)
}

/// The identity's links, ordered by provider.
pub(super) async fn links_of(db: &DbPool, identity_id: &str) -> Result<Vec<LinkRow>> {
    let identity_id = identity_id.to_string();
    Ok(db_interact!(db, |conn| {
        identity_oidc_links::table
            .filter(identity_oidc_links::identity_id.eq(&identity_id))
            .order(identity_oidc_links::provider)
            .select(LinkRow::as_select())
            .load(conn)
    })?)
}

/// How [`create_with_link`] ended. Nothing is written unless `Created`.
#[derive(Debug)]
pub(super) enum CreateWithLink {
    Created(Box<IdentityRow>),
    EmailTaken,
    /// The provider account is linked to another identity.
    LinkTaken,
}

/// Why [`create_with_link`]'s transaction rolled back.
enum LinkAbort {
    Email,
    Link,
    Db(DieselError),
}

impl From<DieselError> for LinkAbort {
    fn from(e: DieselError) -> Self {
        Self::Db(e)
    }
}

/// Insert an active identity with a verified address and its link to `subject` at `provider` in
/// one transaction. The address must have been proven, by the provider or by a mailed code.
pub(super) async fn create_with_link(
    db: &DbPool,
    email: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    provider: &str,
    subject: &str,
) -> Result<CreateWithLink> {
    ensure_mailable(email)?;
    let now = crate::db::now_rfc3339();
    let row = IdentityRow {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.to_string(),
        email_norm: email_norm(email),
        email_verified_at: Some(now.clone()),
        first_name: first_name.map(str::to_string),
        last_name: last_name.map(str::to_string),
        preferred_language: None,
        state: state_str(IdentityState::Active).to_string(),
        state_changed_at: now.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
        metadata_public: None,
        metadata_admin: None,
        first_verified_at: Some(now.clone()),
    };
    let insert = row.clone();
    let link = new_link(provider, subject, &row.id, &now);
    let outcome = db_interact!(db, |conn| {
        Ok::<_, DieselError>(conn.transaction::<_, LinkAbort, _>(|c| {
            diesel::insert_into(identities::table)
                .values(&insert)
                .execute(c)
                .map_err(|e| match e {
                    DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                        LinkAbort::Email
                    }
                    other => LinkAbort::Db(other),
                })?;
            diesel::insert_into(identity_oidc_links::table)
                .values(&link)
                .execute(c)
                .map_err(|e| match e {
                    DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                        LinkAbort::Link
                    }
                    other => LinkAbort::Db(other),
                })?;
            Ok(())
        }))
    })?;
    match outcome {
        Ok(()) => Ok(CreateWithLink::Created(Box::new(row))),
        Err(LinkAbort::Email) => Ok(CreateWithLink::EmailTaken),
        Err(LinkAbort::Link) => Ok(CreateWithLink::LinkTaken),
        Err(LinkAbort::Db(e)) => Err(e.into()),
    }
}

/// How [`insert_link`] ended.
#[derive(Debug, PartialEq)]
pub(super) enum LinkInserted {
    Linked,
    /// The provider account is linked already, or the identity has a link to this provider;
    /// nothing was written.
    Taken,
}

/// Link `subject` at `provider` to the writer's identity, behind its [`admit`].
pub(super) async fn link_for(
    db: &DbPool,
    writer: Writer<'_>,
    provider: &str,
    subject: &str,
) -> Result<Result<LinkInserted, Refused>> {
    let link = new_link(
        provider,
        subject,
        writer.identity_id,
        &crate::db::now_rfc3339(),
    );
    let writer = OwnedWriter::from(writer);
    let outcome = serialized_txn!(db, Result<LinkInserted, Refused>, Taken, |c| {
        if let Some(refused) = admit(c, &writer)? {
            return Ok(Err(refused));
        }
        diesel::insert_into(identity_oidc_links::table)
            .values(&link)
            .execute(c)
            .map_err(|e| match e {
                DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => Taken::Address,
                other => Taken::Db(other),
            })?;
        Ok(Ok(LinkInserted::Linked))
    });
    match outcome {
        Ok(done) => Ok(done),
        Err(Taken::Address) => Ok(Ok(LinkInserted::Taken)),
        Err(Taken::Db(e)) => Err(e.into()),
    }
}

/// Link `subject` at `provider` to an existing identity.
#[cfg(test)]
pub(super) async fn insert_link(
    db: &DbPool,
    identity_id: &str,
    provider: &str,
    subject: &str,
) -> Result<LinkInserted> {
    let link = new_link(provider, subject, identity_id, &crate::db::now_rfc3339());
    Ok(db_interact!(db, |conn| {
        match diesel::insert_into(identity_oidc_links::table)
            .values(&link)
            .execute(conn)
        {
            Ok(_) => Ok(LinkInserted::Linked),
            Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
                Ok(LinkInserted::Taken)
            }
            Err(e) => Err(e),
        }
    })?)
}

/// How [`delete_link`] ended.
#[derive(Debug, PartialEq)]
pub(super) enum LinkDeleted {
    Deleted,
    /// Without it the identity would have no password and no link to a configured provider;
    /// nothing was written.
    LastMethod,
    NotLinked,
}

/// Remove the identity's link to `provider` and its `oidc_links` first-seen row, unless the
/// identity would be left with no password and no link to one of `configured`.
pub(super) async fn delete_link(
    db: &DbPool,
    identity_id: &str,
    provider: &str,
    configured: &[&str],
) -> Result<LinkDeleted> {
    let (identity_id, provider) = (identity_id.to_string(), provider.to_string());
    let configured: Vec<String> = configured.iter().map(|p| (*p).to_string()).collect();
    Ok(serialized_txn!(db, LinkDeleted, DieselError, |c| {
        // A row lock on Postgres, so two unlinks on one identity cannot both pass the guard.
        let locked = diesel::update(identities::table.find(&identity_id))
            .set(identities::updated_at.eq(identities::updated_at))
            .execute(c)?;
        let own = identity_oidc_links::table
            .filter(identity_oidc_links::identity_id.eq(&identity_id))
            .filter(identity_oidc_links::provider.eq(&provider));
        if locked == 0 || !diesel::select(diesel::dsl::exists(own)).get_result::<bool>(c)? {
            return Ok(LinkDeleted::NotLinked);
        }
        let has_password = diesel::select(diesel::dsl::exists(
            identity_credentials::table
                .filter(identity_credentials::identity_id.eq(&identity_id))
                .filter(identity_credentials::kind.eq("password")),
        ))
        .get_result::<bool>(c)?;
        let other_usable = diesel::select(diesel::dsl::exists(
            identity_oidc_links::table
                .filter(identity_oidc_links::identity_id.eq(&identity_id))
                .filter(identity_oidc_links::provider.ne(&provider))
                .filter(identity_oidc_links::provider.eq_any(&configured)),
        ))
        .get_result::<bool>(c)?;
        if !has_password && !other_usable {
            return Ok(LinkDeleted::LastMethod);
        }
        diesel::delete(own).execute(c)?;
        diesel::delete(
            oidc_links::table
                .filter(oidc_links::identity_id.eq(&identity_id))
                .filter(oidc_links::provider.eq(&provider)),
        )
        .execute(c)?;
        Ok(LinkDeleted::Deleted)
    })?)
}

#[diesel::dsl::auto_type]
fn identity_links_delete(identity_id: String) -> _ {
    diesel::dsl::delete(
        identity_oidc_links::table.filter(identity_oidc_links::identity_id.eq(identity_id)),
    )
}

#[diesel::dsl::auto_type]
fn first_seen_delete(identity_id: String) -> _ {
    diesel::dsl::delete(oidc_links::table.filter(oidc_links::identity_id.eq(identity_id)))
}

/// Remove every link of the identity and its `oidc_links` first-seen rows on the caller's
/// connection, inside its transaction; returns how many links went.
fn delete_links<C>(conn: &mut C, identity_id: &str) -> QueryResult<usize>
where
    C: Connection,
    identity_links_delete: diesel::query_dsl::methods::ExecuteDsl<C>,
    first_seen_delete: diesel::query_dsl::methods::ExecuteDsl<C>,
{
    let removed = identity_links_delete(identity_id.to_string()).execute(conn)?;
    first_seen_delete(identity_id.to_string()).execute(conn)?;
    Ok(removed)
}

/// What [`verify_recovered`] removed from a never-verified identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Reset {
    pub(super) sessions: usize,
    pub(super) credentials: usize,
    pub(super) links: usize,
    pub(super) offline_secrets: usize,
}

/// [`mark_verified`] for an address proven by a mailed recovery code. An identity whose address
/// was never verified before first loses its live sessions, every credential, every provider
/// link, its offline passphrase, its outstanding codes and its pending address changes, in the
/// same transaction. The row afterwards and the reset, if one happened; `None` when
/// the identity is gone or holds another address now.
pub(super) async fn verify_recovered(
    db: &DbPool,
    id: &str,
    email: &str,
) -> Result<Option<(IdentityRow, Option<Reset>)>> {
    let (id, norm) = (id.to_string(), email_norm(email));
    let now = crate::db::now_rfc3339();
    Ok(serialized_txn!(
        db,
        Option<(IdentityRow, Option<Reset>)>,
        DieselError,
        |c| {
            let target = identities::table
                .find(&id)
                .filter(identities::email_norm.eq(&norm));
            // A row lock on Postgres, so the never-verified decision holds until commit.
            let locked = diesel::update(target)
                .set(identities::updated_at.eq(identities::updated_at))
                .execute(c)?;
            if locked == 0 {
                return Ok(None);
            }
            let first: Option<String> = target.select(identities::first_verified_at).first(c)?;
            let reset = if first.is_none() {
                let sessions = diesel::update(
                    identity_sessions::table
                        .filter(identity_sessions::identity_id.eq(&id))
                        .filter(identity_sessions::revoked_at.is_null())
                        .filter(identity_sessions::expires_at.gt(&now)),
                )
                .set(identity_sessions::revoked_at.eq(&now))
                .execute(c)?;
                let credentials = diesel::delete(
                    identity_credentials::table.filter(identity_credentials::identity_id.eq(&id)),
                )
                .execute(c)?;
                let links = delete_links(c, &id)?;
                let offline_secrets = diesel::delete(
                    offline_secrets::table.filter(offline_secrets::identity_id.eq(&id)),
                )
                .execute(c)?;
                // The code being redeemed is already marked used; nothing reads it again.
                diesel::delete(identity_codes::table.filter(identity_codes::identity_id.eq(&id)))
                    .execute(c)?;
                // Pending address changes: a resend on one would mail a fresh code.
                diesel::delete(
                    identity_flows::table
                        .filter(identity_flows::identity_id.eq(&id))
                        .filter(identity_flows::kind.eq(FlowKind::Verification.path_segment())),
                )
                .execute(c)?;
                Some(Reset {
                    sessions,
                    credentials,
                    links,
                    offline_secrets,
                })
            } else {
                None
            };
            diesel::update(target.filter(identities::email_verified_at.is_null()))
                .set((
                    identities::email_verified_at.eq(&now),
                    identities::updated_at.eq(&now),
                ))
                .execute(c)?;
            diesel::update(target.filter(identities::first_verified_at.is_null()))
                .set(identities::first_verified_at.eq(&now))
                .execute(c)?;
            let row = target.select(IdentityRow::as_select()).first(c)?;
            Ok(Some((row, reset)))
        }
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;
    use diesel::sqlite::SqliteConnection;

    async fn sql<T: Send + 'static>(
        db: &DbPool,
        f: impl FnOnce(&mut SqliteConnection) -> QueryResult<T> + Send + 'static,
    ) -> T {
        let DbPool::Sqlite(pool) = db else {
            unreachable!("test_pool is sqlite")
        };
        pool.get()
            .await
            .unwrap()
            .interact(f)
            .await
            .unwrap()
            .unwrap()
    }

    async fn seed(db: &DbPool, email: &str, created_at: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let row = IdentityRow {
            id: id.clone(),
            email: email.to_string(),
            email_norm: email_norm(email),
            email_verified_at: None,
            first_name: None,
            last_name: None,
            preferred_language: None,
            state: "active".to_string(),
            state_changed_at: created_at.to_string(),
            created_at: created_at.to_string(),
            updated_at: created_at.to_string(),
            metadata_public: None,
            metadata_admin: None,
            first_verified_at: None,
        };
        sql(db, move |conn| {
            diesel::insert_into(identities::table)
                .values(&row)
                .execute(conn)
        })
        .await;
        id
    }

    async fn add_credential(db: &DbPool, identity_id: &str, kind: &str) {
        let (identity_id, kind) = (identity_id.to_string(), kind.to_string());
        let now = crate::db::now_rfc3339();
        sql(db, move |conn| {
            diesel::insert_into(identity_credentials::table)
                .values((
                    identity_credentials::id.eq(uuid::Uuid::new_v4().to_string()),
                    identity_credentials::identity_id.eq(&identity_id),
                    identity_credentials::kind.eq(&kind),
                    identity_credentials::config.eq("{}"),
                    identity_credentials::version.eq(0),
                    identity_credentials::created_at.eq(&now),
                    identity_credentials::updated_at.eq(&now),
                ))
                .execute(conn)
        })
        .await;
    }

    fn ids(page: &[Identity]) -> Vec<String> {
        page.iter().map(|i| i.id.clone()).collect()
    }

    #[tokio::test]
    async fn get_distinguishes_missing_from_present() {
        let db = test_pool().await;
        assert!(get(&db, "nope").await.unwrap().is_none());
        let id = seed(&db, "A@Example.test", "2026-01-01T00:00:00.000000+00:00").await;
        let found = get(&db, &id).await.unwrap().expect("present");
        assert_eq!(found.traits.unwrap()["email"], "A@Example.test");
        assert!(found.credentials.is_none());
        let addr = &found.verifiable_addresses.unwrap()[0];
        assert_eq!(
            (addr.value.as_str(), addr.via.as_str(), addr.status.as_str()),
            ("A@Example.test", "email", "pending")
        );
        assert!(!addr.verified);
    }

    #[tokio::test]
    async fn get_errors_when_the_table_is_unreadable() {
        let db = test_pool().await;
        sql(&db, |conn| {
            diesel::sql_query("DROP TABLE identities").execute(conn)
        })
        .await;
        assert!(get(&db, "any").await.is_err());
    }

    #[tokio::test]
    async fn credentials_carry_kind_and_identifier_but_no_config() {
        let db = test_pool().await;
        let id = seed(&db, "Cred@Example.test", "2026-01-01T00:00:00.000000+00:00").await;
        add_credential(&db, &id, "password").await;
        add_credential(&db, &id, "totp").await;
        let creds = get(&db, &id).await.unwrap().unwrap().credentials.unwrap();
        assert_eq!(
            creds["password"].identifiers.as_deref(),
            Some(&["cred@example.test".to_string()][..])
        );
        assert_eq!(
            creds["totp"].identifiers.as_deref(),
            Some(&[id.clone()][..])
        );
        assert!(creds.values().all(|c| c.config.is_none()));
        assert!(!creds.contains_key("lookup_secret"));
    }

    #[tokio::test]
    async fn email_filter_is_exact_and_case_insensitive() {
        let db = test_pool().await;
        let id = seed(&db, "Bob@Example.test", "2026-01-01T00:00:00.000000+00:00").await;
        seed(
            &db,
            "bob@example.testing",
            "2026-01-02T00:00:00.000000+00:00",
        )
        .await;
        let hits = list(&db, 25, None, Some("bob@EXAMPLE.test")).await.unwrap();
        assert_eq!(ids(&hits), std::slice::from_ref(&id));
        assert!(list(&db, 25, None, Some("bob@")).await.unwrap().is_empty());
        assert_eq!(
            find_by_email(&db, "BOB@example.TEST")
                .await
                .unwrap()
                .map(|(i, _)| i.id),
            Some(id)
        );
        assert!(find_by_email(&db, "bob").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn keyset_paging_follows_the_last_id_token() {
        let db = test_pool().await;
        let t1 = "2026-01-01T00:00:00.000000+00:00";
        let t2 = "2026-01-02T00:00:00.000000+00:00";
        let mut same_instant = vec![
            seed(&db, "a@x.test", t1).await,
            seed(&db, "b@x.test", t1).await,
            seed(&db, "c@x.test", t1).await,
        ];
        same_instant.sort();
        same_instant.reverse();
        let newest = seed(&db, "d@x.test", t2).await;
        let mut expected = vec![newest];
        expected.extend(same_instant);

        let mut seen = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = list(&db, 2, token.as_deref(), None).await.unwrap();
            if page.is_empty() {
                break;
            }
            seen.extend(ids(&page));
            token = page.last().map(|i| i.id.clone());
        }
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn unknown_page_token_gives_an_empty_page() {
        let db = test_pool().await;
        seed(&db, "a@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert!(
            list(&db, 25, Some("missing"), None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn list_by_ids_skips_unknown_ids() {
        let db = test_pool().await;
        let a = seed(&db, "a@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert!(list_by_ids(&db, Vec::new()).await.unwrap().is_empty());
        let found = list_by_ids(&db, vec![a.clone(), "missing".into()])
            .await
            .unwrap();
        assert_eq!(ids(&found), [a]);
    }

    #[tokio::test]
    async fn create_rejects_a_taken_address_in_any_case() {
        let db = test_pool().await;
        let created = create(&db, "New@Example.test", Some("Ada"), Some("L"), true)
            .await
            .unwrap()
            .expect("created");
        let traits = created.traits.as_ref().unwrap();
        assert_eq!(traits["name"]["first"], "Ada");
        let addr = &created.verifiable_addresses.as_ref().unwrap()[0];
        assert!(addr.verified && addr.status == "completed");
        assert_eq!(created.state, Some(IdentityState::Active));
        assert_eq!(get(&db, &created.id).await.unwrap(), Some(created));
        assert!(
            create(&db, "new@example.TEST", None, None, false)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn state_change_stamps_only_a_real_transition() {
        let db = test_pool().await;
        let t0 = "2026-01-01T00:00:00.000000+00:00";
        let id = seed(&db, "s@x.test", t0).await;
        set_state(&db, &id, IdentityState::Active).await.unwrap();
        assert_eq!(
            get(&db, &id)
                .await
                .unwrap()
                .unwrap()
                .state_changed_at
                .as_deref(),
            Some(t0)
        );
        set_state(&db, &id, IdentityState::Inactive).await.unwrap();
        let after = get(&db, &id).await.unwrap().unwrap();
        assert_eq!(after.state, Some(IdentityState::Inactive));
        assert_ne!(after.state_changed_at.as_deref(), Some(t0));
    }

    #[tokio::test]
    async fn language_is_a_trait() {
        let db = test_pool().await;
        assert!(!set_language(&db, "missing", "de").await.unwrap());
        let id = seed(&db, "l@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert!(set_language(&db, &id, "de").await.unwrap());
        let traits = get(&db, &id).await.unwrap().unwrap().traits.unwrap();
        assert_eq!(traits["preferred_language"], "de");
    }

    #[test]
    fn metadata_patch_matches_the_kratos_json_patch() {
        assert_eq!(
            patch_metadata_key(None, "k", Some("v")).unwrap(),
            (Some(r#"{"k":"v"}"#.into()), false)
        );
        assert_eq!(
            patch_metadata_key(Some("null"), "k", Some("v")).unwrap(),
            (Some(r#"{"k":"v"}"#.into()), false)
        );
        assert_eq!(
            patch_metadata_key(Some(r#"{"a":1,"k":"old"}"#), "k", Some("new")).unwrap(),
            (Some(r#"{"a":1,"k":"new"}"#.into()), true)
        );
        assert_eq!(
            patch_metadata_key(Some(r#"{"a":1,"k":"v"}"#), "k", None).unwrap(),
            (Some(r#"{"a":1}"#.into()), true)
        );
        assert_eq!(
            patch_metadata_key(Some(r#"{"k":null}"#), "k", None).unwrap(),
            (Some("{}".into()), false)
        );
        assert_eq!(
            patch_metadata_key(Some(r#"{"a":1}"#), "k", None).unwrap(),
            (None, false)
        );
        assert_eq!(patch_metadata_key(None, "k", None).unwrap(), (None, false));
        assert!(patch_metadata_key(Some("[1]"), "k", Some("v")).is_err());
        assert!(patch_metadata_key(Some("[1]"), "k", None).is_err());
        assert_eq!(
            patch_metadata_key(Some("{}"), "a/b~c", Some("v")).unwrap(),
            (Some(r#"{"a/b~c":"v"}"#.into()), false)
        );
    }

    #[tokio::test]
    async fn metadata_patch_on_a_stored_identity() {
        let db = test_pool().await;
        assert_eq!(
            patch_metadata_admin(&db, "missing", "k", Some("v"))
                .await
                .unwrap(),
            None
        );
        let id = seed(&db, "m@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert_eq!(
            patch_metadata_admin(&db, &id, "k", Some("v"))
                .await
                .unwrap(),
            Some(false)
        );
        patch_metadata_admin(&db, &id, "other", Some("o"))
            .await
            .unwrap();
        assert_eq!(
            patch_metadata_admin(&db, &id, "k", None).await.unwrap(),
            Some(true)
        );
        let identity = get(&db, &id).await.unwrap().unwrap();
        assert_eq!(identity.metadata_admin, Some(json!({ "other": "o" })));
        assert!(identity.metadata_public.is_none());
    }

    // A temp trigger plays a concurrent writer: it lands `other` between the read and the swap.
    async fn race_metadata_writes(db: &DbPool, when: &'static str) {
        sql(db, move |conn| {
            diesel::sql_query(format!(
                "CREATE TEMP TRIGGER race BEFORE UPDATE OF metadata_admin ON main.identities \
                 WHEN {when} BEGIN \
                 UPDATE identities SET metadata_admin = '{{\"other\":\"x\"}}' WHERE id = OLD.id; \
                 SELECT RAISE(IGNORE); END"
            ))
            .execute(conn)
        })
        .await;
    }

    #[tokio::test]
    async fn metadata_patch_retries_when_the_document_moved() {
        let db = test_pool().await;
        let id = seed(&db, "r@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        race_metadata_writes(&db, "NEW.metadata_admin NOT LIKE '%\"other\"%'").await;
        assert_eq!(
            patch_metadata_admin(&db, &id, "k", Some("v"))
                .await
                .unwrap(),
            Some(false)
        );
        let identity = get(&db, &id).await.unwrap().unwrap();
        assert_eq!(
            identity.metadata_admin,
            Some(json!({ "other": "x", "k": "v" }))
        );
    }

    #[tokio::test]
    async fn metadata_patch_gives_up_when_always_contended() {
        let db = test_pool().await;
        let id = seed(&db, "g@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        race_metadata_writes(&db, "1").await;
        assert!(
            patch_metadata_admin(&db, &id, "k", Some("v"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn credential_config_swaps_only_from_the_version_read() {
        let db = test_pool().await;
        let id = seed(&db, "cas@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert!(credential(&db, &id, "totp").await.unwrap().is_none());
        assert!(
            insert_credential(&db, &id, "totp", "{\"a\":1}")
                .await
                .unwrap()
        );
        assert!(!insert_credential(&db, &id, "totp", "{}").await.unwrap());
        let read = credential(&db, &id, "totp").await.unwrap().unwrap();
        assert_eq!((read.config.as_str(), read.version), ("{\"a\":1}", 0));

        assert!(
            swap_credential_config(&db, &read.id, read.version, "{\"a\":2}")
                .await
                .unwrap()
        );
        assert!(
            !swap_credential_config(&db, &read.id, read.version, "{\"a\":3}")
                .await
                .unwrap(),
            "a second writer holding the old version loses"
        );
        let now = credential(&db, &id, "totp").await.unwrap().unwrap();
        assert_eq!((now.config.as_str(), now.version), ("{\"a\":2}", 1));
        assert!(credential(&db, &id, "password").await.unwrap().is_none());
    }

    async fn link(db: &DbPool, identity_id: &str, provider: &str, subject: &str) {
        assert_eq!(
            insert_link(db, identity_id, provider, subject)
                .await
                .unwrap(),
            LinkInserted::Linked
        );
    }

    async fn first_seen(db: &DbPool, identity_id: &str) -> Vec<String> {
        crate::settings::oidc_links_db::list_for_identity(db, identity_id)
            .await
            .unwrap()
            .into_iter()
            .map(|(provider, _)| provider)
            .collect()
    }

    #[tokio::test]
    async fn links_appear_as_one_oidc_credential_of_provider_subject_pairs() {
        let db = test_pool().await;
        let id = seed(&db, "o@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        let other = seed(&db, "p@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        add_credential(&db, &id, "password").await;
        link(&db, &id, "google", "g-1").await;
        link(&db, &id, "github", "42").await;
        link(&db, &other, "github", "43").await;

        let creds = get(&db, &id).await.unwrap().unwrap().credentials.unwrap();
        assert_eq!(
            creds["oidc"].identifiers.as_deref(),
            Some(&["github:42".to_string(), "google:g-1".to_string()][..])
        );
        assert!(creds["oidc"].config.is_none());
        assert_eq!(
            creds["password"].identifiers.as_deref(),
            Some(&["o@x.test".to_string()][..])
        );

        let listed = list(&db, 25, None, None).await.unwrap();
        let oidc: Vec<_> = listed
            .iter()
            .map(|i| i.credentials.as_ref().unwrap()["oidc"].identifiers.clone())
            .collect();
        assert_eq!(oidc.len(), 2);
        assert!(oidc.contains(&Some(vec!["github:43".to_string()])));

        let unlinked = seed(&db, "u@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert!(
            get(&db, &unlinked)
                .await
                .unwrap()
                .unwrap()
                .credentials
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_provider_account_links_to_one_identity_only() {
        let db = test_pool().await;
        let a = seed(&db, "a@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        let b = seed(&db, "b@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert!(link_owner(&db, "github", "42").await.unwrap().is_none());
        link(&db, &a, "github", "42").await;
        assert_eq!(
            insert_link(&db, &b, "github", "42").await.unwrap(),
            LinkInserted::Taken
        );
        assert_eq!(
            insert_link(&db, &a, "github", "42").await.unwrap(),
            LinkInserted::Taken
        );
        assert_eq!(link_owner(&db, "github", "42").await.unwrap(), Some(a));
        assert!(link_owner(&db, "google", "42").await.unwrap().is_none());
        link(&db, &b, "google", "42").await;
        assert!(
            links_of(&db, &b)
                .await
                .unwrap()
                .iter()
                .all(|l| l.provider == "google")
        );
    }

    #[tokio::test]
    async fn an_identity_has_one_link_per_provider() {
        let db = test_pool().await;
        let id = seed(&db, "one@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        link(&db, &id, "github", "1").await;
        assert_eq!(
            insert_link(&db, &id, "github", "2").await.unwrap(),
            LinkInserted::Taken
        );
        link(&db, &id, "google", "1").await;
        let links = links_of(&db, &id).await.unwrap();
        assert_eq!(
            links
                .iter()
                .map(|l| (l.provider.as_str(), l.subject.as_str()))
                .collect::<Vec<_>>(),
            [("github", "1"), ("google", "1")]
        );
        assert!(links.iter().all(|l| l.identity_id == id));
    }

    #[tokio::test]
    async fn links_go_with_their_identity() {
        let db = test_pool().await;
        let gone = seed(&db, "gone@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        let keep = seed(&db, "keep@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        link(&db, &gone, "github", "1").await;
        link(&db, &keep, "github", "2").await;
        assert!(delete(&db, &gone).await.unwrap());
        assert!(link_owner(&db, "github", "1").await.unwrap().is_none());
        assert_eq!(link_owner(&db, "github", "2").await.unwrap(), Some(keep));
        assert!(
            insert_link(&db, "missing", "github", "3").await.is_err(),
            "a link needs an identity"
        );
    }

    #[tokio::test]
    async fn create_with_link_writes_both_or_nothing() {
        let db = test_pool().await;
        let CreateWithLink::Created(row) =
            create_with_link(&db, "Up@x.test", Some("Ada"), None, "github", "42")
                .await
                .unwrap()
        else {
            panic!("created")
        };
        assert!(row.email_verified_at.is_some());
        assert_eq!(row.first_verified_at, row.email_verified_at);
        assert_eq!(
            row_by_id(&db, &row.id)
                .await
                .unwrap()
                .unwrap()
                .first_verified_at,
            row.first_verified_at
        );
        assert_eq!(
            link_owner(&db, "github", "42").await.unwrap(),
            Some(row.id.clone())
        );

        assert!(matches!(
            create_with_link(&db, "up@X.test", None, None, "github", "43")
                .await
                .unwrap(),
            CreateWithLink::EmailTaken
        ));
        assert!(link_owner(&db, "github", "43").await.unwrap().is_none());

        assert!(matches!(
            create_with_link(&db, "other@x.test", None, None, "github", "42")
                .await
                .unwrap(),
            CreateWithLink::LinkTaken
        ));
        assert!(row_by_email(&db, "other@x.test").await.unwrap().is_none());
        assert!(
            create_with_link(&db, "a<b>@x.test", None, None, "github", "44")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unlinking_keeps_a_usable_sign_in_method() {
        let db = test_pool().await;
        let id = seed(&db, "u@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        link(&db, &id, "github", "1").await;
        link(&db, &id, "retired", "2").await;
        for provider in ["github", "retired"] {
            crate::settings::oidc_links_db::upsert_seen(&db, &id, provider)
                .await
                .unwrap();
        }

        assert_eq!(
            delete_link(&db, &id, "google", &["github", "google"])
                .await
                .unwrap(),
            LinkDeleted::NotLinked
        );
        assert_eq!(
            delete_link(&db, "missing", "github", &["github"])
                .await
                .unwrap(),
            LinkDeleted::NotLinked
        );
        assert_eq!(
            delete_link(&db, &id, "github", &["github"]).await.unwrap(),
            LinkDeleted::LastMethod,
            "a link to a provider no longer configured does not count"
        );
        assert_eq!(links_of(&db, &id).await.unwrap().len(), 2);

        assert_eq!(
            delete_link(&db, &id, "retired", &["github"]).await.unwrap(),
            LinkDeleted::Deleted
        );
        assert_eq!(first_seen(&db, &id).await, ["github"]);
        assert_eq!(
            delete_link(&db, &id, "github", &["github"]).await.unwrap(),
            LinkDeleted::LastMethod
        );

        add_credential(&db, &id, "password").await;
        assert_eq!(
            delete_link(&db, &id, "github", &["github"]).await.unwrap(),
            LinkDeleted::Deleted
        );
        assert!(links_of(&db, &id).await.unwrap().is_empty());
        assert!(first_seen(&db, &id).await.is_empty());
    }

    #[tokio::test]
    async fn delete_links_clears_links_and_first_seen_rows() {
        let db = test_pool().await;
        let id = seed(&db, "d@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        let other = seed(&db, "e@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        link(&db, &id, "github", "1").await;
        link(&db, &id, "google", "1").await;
        link(&db, &other, "github", "2").await;
        for (identity, provider) in [(&id, "github"), (&id, "google"), (&other, "github")] {
            crate::settings::oidc_links_db::upsert_seen(&db, identity, provider)
                .await
                .unwrap();
        }
        async fn drop(db: &DbPool, id: &str) -> usize {
            let id = id.to_string();
            sql(db, move |c| delete_links(c, &id)).await
        }
        assert_eq!(drop(&db, &id).await, 2);
        assert!(links_of(&db, &id).await.unwrap().is_empty());
        assert!(first_seen(&db, &id).await.is_empty());
        assert_eq!(links_of(&db, &other).await.unwrap().len(), 1);
        assert_eq!(first_seen(&db, &other).await, ["github"]);
        assert_eq!(drop(&db, &id).await, 0);
    }

    #[tokio::test]
    async fn first_verified_at_is_set_once() {
        let db = test_pool().await;
        let id = seed(&db, "v@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        assert!(
            mark_verified(&db, &id, "other@x.test")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            row_by_id(&db, &id)
                .await
                .unwrap()
                .unwrap()
                .first_verified_at
                .is_none()
        );

        let first = mark_verified(&db, &id, "V@x.test")
            .await
            .unwrap()
            .unwrap()
            .first_verified_at
            .expect("stamped");
        let id2 = id.clone();
        sql(&db, move |conn| {
            diesel::update(identities::table.find(&id2))
                .set(identities::email_verified_at.eq(None::<String>))
                .execute(conn)
        })
        .await;
        let again = mark_verified(&db, &id, "v@x.test").await.unwrap().unwrap();
        assert!(again.email_verified_at.is_some());
        assert_eq!(again.first_verified_at, Some(first));

        let created = create(&db, "c@x.test", None, None, true)
            .await
            .unwrap()
            .unwrap();
        assert!(
            row_by_id(&db, &created.id)
                .await
                .unwrap()
                .unwrap()
                .first_verified_at
                .is_some()
        );
        let unverified = create(&db, "n@x.test", None, None, false)
            .await
            .unwrap()
            .unwrap();
        assert!(
            row_by_id(&db, &unverified.id)
                .await
                .unwrap()
                .unwrap()
                .first_verified_at
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_cascades_to_every_child_table() {
        let db = test_pool().await;
        let keep = seed(&db, "keep@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        let gone = seed(&db, "gone@x.test", "2026-01-01T00:00:00.000000+00:00").await;
        for id in [&keep, &gone] {
            add_credential(&db, id, "password").await;
            let id = id.clone();
            let now = crate::db::now_rfc3339();
            sql(&db, move |conn| {
                let session = format!("s-{id}");
                let flow = format!("f-{id}");
                diesel::insert_into(identity_sessions::table)
                    .values((
                        identity_sessions::id.eq(&session),
                        identity_sessions::identity_id.eq(&id),
                        identity_sessions::token_hash.eq(format!("h-{id}")),
                        identity_sessions::aal.eq("aal1"),
                        identity_sessions::methods.eq("[]"),
                        identity_sessions::issued_at.eq(&now),
                        identity_sessions::authenticated_at.eq(&now),
                        identity_sessions::expires_at.eq(&now),
                    ))
                    .execute(conn)?;
                diesel::insert_into(identity_flows::table)
                    .values((
                        identity_flows::id.eq(&flow),
                        identity_flows::kind.eq("settings"),
                        identity_flows::state.eq("show_form"),
                        identity_flows::identity_id.eq(&id),
                        identity_flows::session_id.eq(&session),
                        identity_flows::request_url.eq("/settings"),
                        identity_flows::context.eq("{}"),
                        identity_flows::issued_at.eq(&now),
                        identity_flows::expires_at.eq(&now),
                    ))
                    .execute(conn)?;
                diesel::insert_into(identity_codes::table)
                    .values((
                        identity_codes::id.eq(format!("c-{id}")),
                        identity_codes::flow_id.eq(&flow),
                        identity_codes::purpose.eq("verification"),
                        identity_codes::identity_id.eq(&id),
                        identity_codes::address.eq("c@x.test"),
                        identity_codes::code_mac.eq("mac"),
                        identity_codes::expires_at.eq(&now),
                        identity_codes::created_at.eq(&now),
                    ))
                    .execute(conn)?;
                diesel::insert_into(identity_mail_outbox::table)
                    .values((
                        identity_mail_outbox::id.eq(format!("m-{id}")),
                        identity_mail_outbox::identity_id.eq(&id),
                        identity_mail_outbox::recipient.eq("x@x.test"),
                        identity_mail_outbox::kind.eq("verification"),
                        identity_mail_outbox::payload.eq("sealed"),
                        identity_mail_outbox::state.eq("queued"),
                        identity_mail_outbox::next_attempt_at.eq(&now),
                        identity_mail_outbox::created_at.eq(&now),
                    ))
                    .execute(conn)
            })
            .await;
        }

        assert!(delete(&db, &gone).await.unwrap());
        assert!(!delete(&db, &gone).await.unwrap());
        assert!(get(&db, &gone).await.unwrap().is_none());

        let counts: Vec<i64> = sql(&db, |conn| {
            Ok(vec![
                identity_credentials::table.count().get_result(conn)?,
                identity_sessions::table.count().get_result(conn)?,
                identity_flows::table.count().get_result(conn)?,
                identity_codes::table.count().get_result(conn)?,
                identity_mail_outbox::table.count().get_result(conn)?,
            ])
        })
        .await;
        assert_eq!(
            counts,
            [1, 1, 1, 1, 1],
            "only the kept identity's rows remain"
        );
        assert!(
            get(&db, &keep)
                .await
                .unwrap()
                .unwrap()
                .credentials
                .is_some()
        );
    }
}
