//! Identity rows and their conversion to the domain [`Identity`].

use std::collections::HashMap;

use anyhow::{Result, bail};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde_json::{Map, Value, json};

use super::codes::MailedCode;
use super::flows::FlowRow;
use crate::backend::identity::{
    Credential, Identity, IdentityState, RecoveryAddress, VerifiableAddress,
};
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{
    identities, identity_codes, identity_credentials, identity_flows, identity_mail_outbox,
};

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
}

#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = identity_credentials)]
pub(super) struct CredentialSummary {
    pub identity_id: String,
    pub kind: String,
    pub version: i32,
    pub created_at: String,
    pub updated_at: String,
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

/// Whether `email` may be stored and mailed to: [`crate::mailer::is_valid_email`] without the
/// RFC 5322 specials that let an address carry a display name, a comment or a second recipient.
pub(super) fn is_mailable(email: &str) -> bool {
    crate::mailer::is_valid_email(email)
        && !email.chars().any(|c| {
            matches!(
                c,
                '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | ':' | '"' | '\\'
            )
        })
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

    // Kratos identifies password credentials by the lowercased email, second factors by the identity id.
    let credentials: HashMap<String, Credential> = creds
        .into_iter()
        .map(|c| {
            let identifier = if c.kind == "password" {
                row.email_norm.clone()
            } else {
                row.id.clone()
            };
            let cred = Credential {
                identifiers: Some(vec![identifier]),
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
    let creds: Vec<CredentialSummary> = db_interact!(db, |conn| {
        identity_credentials::table
            .filter(identity_credentials::identity_id.eq_any(&ids))
            .select(CredentialSummary::as_select())
            .load(conn)
    })?;
    let mut by_identity: HashMap<String, Vec<CredentialSummary>> = HashMap::new();
    for c in creds {
        by_identity
            .entry(c.identity_id.clone())
            .or_default()
            .push(c);
    }
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

/// Mark the identity's address verified, if it is still `email`. The row afterwards; `None` when
/// the identity is gone or holds another address now.
pub(super) async fn mark_verified(
    db: &DbPool,
    id: &str,
    email: &str,
) -> Result<Option<IdentityRow>> {
    let (id, norm) = (id.to_string(), email_norm(email));
    let now = crate::db::now_rfc3339();
    Ok(db_interact!(db, |conn| {
        let target = identities::table
            .find(&id)
            .filter(identities::email_norm.eq(&norm));
        diesel::update(target.filter(identities::email_verified_at.is_null()))
            .set((
                identities::email_verified_at.eq(&now),
                identities::updated_at.eq(&now),
            ))
            .execute(conn)?;
        target
            .select(IdentityRow::as_select())
            .first(conn)
            .optional()
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

/// Why [`create_with_password`]'s transaction rolled back.
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

/// Read-compare-swap rounds before a contended credential replacement gives up.
const PUT_ATTEMPTS: usize = 3;

/// Store `config` as the identity's credential of `kind`, replacing the one it has with a
/// compare-and-swap on the version read.
pub(super) async fn put_credential(
    db: &DbPool,
    identity_id: &str,
    kind: &str,
    config: &str,
) -> Result<()> {
    for _ in 0..PUT_ATTEMPTS {
        let stored = match credential(db, identity_id, kind).await? {
            Some(cred) => swap_credential_config(db, &cred.id, cred.version, config).await?,
            None => insert_credential(db, identity_id, kind, config).await?,
        };
        if stored {
            return Ok(());
        }
    }
    bail!("credential {kind} of identity {identity_id} kept changing")
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
}

/// A new address and the verification flow, code and mail that go with it.
pub(super) struct AddressChange {
    pub(super) email: String,
    pub(super) verification: FlowRow,
    pub(super) code: MailedCode,
}

/// Set the identity's names and, given `change`, its address. A new address clears
/// `email_verified_at`, retires the identity's verification and recovery codes and stores the
/// change's flow, code and mail, all in one transaction.
pub(super) async fn update_profile(
    db: &DbPool,
    id: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    change: Option<AddressChange>,
) -> Result<ProfileSaved> {
    if let Some(change) = &change {
        ensure_mailable(&change.email)?;
    }
    let id = id.to_string();
    let first = first_name.map(str::to_string);
    let last = last_name.map(str::to_string);
    let now = crate::db::now_rfc3339();
    let outcome = db_interact!(db, |conn| {
        Ok::<_, DieselError>(conn.transaction::<_, Taken, _>(|c| {
            let target = identities::table.find(&id);
            let updated = match &change {
                Some(change) => diesel::update(target)
                    .set((
                        identities::first_name.eq(&first),
                        identities::last_name.eq(&last),
                        identities::email.eq(&change.email),
                        identities::email_norm.eq(email_norm(&change.email)),
                        identities::email_verified_at.eq(None::<String>),
                        identities::updated_at.eq(&now),
                    ))
                    .execute(c)
                    .map_err(|e| match e {
                        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                            Taken::Address
                        }
                        other => Taken::Db(other),
                    })?,
                None => diesel::update(target)
                    .set((
                        identities::first_name.eq(&first),
                        identities::last_name.eq(&last),
                        identities::updated_at.eq(&now),
                    ))
                    .execute(c)?,
            };
            if updated > 0
                && let Some(change) = &change
            {
                diesel::delete(identity_codes::table.filter(identity_codes::identity_id.eq(&id)))
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
            Ok(updated > 0)
        }))
    })?;
    match outcome {
        Ok(true) => Ok(ProfileSaved::Saved),
        Ok(false) => Ok(ProfileSaved::Gone),
        Err(Taken::Address) => Ok(ProfileSaved::Taken),
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
        updated_at: now,
        metadata_public: None,
        metadata_admin: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;
    use crate::schema::{identity_codes, identity_flows, identity_mail_outbox, identity_sessions};
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
