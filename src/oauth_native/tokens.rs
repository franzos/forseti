//! Authorization and device code redemption and refresh token rotation, over
//! `oauth_authorization_codes` and `oauth_refresh_tokens`.
//!
//! Every consume is a conditional `UPDATE ... WHERE used_at IS NULL AND expires_at > now`; its
//! row count decides the outcome, so of two concurrent redeems exactly one wins on either backend.
//! Used rows are kept so a replay can be told from an unknown value: a replayed code or refresh
//! token deletes the refresh tokens of its family. Access tokens already issued are JWTs and run
//! out within [`super::ACCESS_TOKEN_TTL_SECS`]. Every transaction that inserts or deletes refresh
//! tokens locks the grant first, so a family delete sees the successor of any rotation before it.

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::grants::GrantRow;
use super::{REFRESH_TOKEN_TTL_SECS, from_json, parse_time, random_token, token_hash};
use crate::db::{DbPool, rfc3339};
use crate::schema::{oauth_authorization_codes, oauth_consent_grants, oauth_refresh_tokens};
use crate::{db_interact, serialized_txn};

/// Scopes that ask for a refresh token.
const OFFLINE_SCOPES: [&str; 2] = ["offline", "offline_access"];

/// Why a code or refresh token request was refused, as the RFC 6749 section 5.2 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Invalid {
    Grant,
    Scope,
    Target,
}

impl Invalid {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Grant => "invalid_grant",
            Self::Scope => "invalid_scope",
            Self::Target => "invalid_target",
        }
    }

    pub(super) fn description(self) -> &'static str {
        match self {
            Self::Grant => "the grant is invalid, expired, used or revoked",
            Self::Scope => "the requested scope exceeds the grant",
            Self::Target => "a requested resource is not in the grant",
        }
    }
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Invalid {}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = oauth_authorization_codes)]
struct CodeRow {
    grant_id: String,
    client_id: String,
    session_id: String,
    redirect_uri: String,
    code_challenge: Option<String>,
    nonce: Option<String>,
    scope: String,
    audience: String,
    auth_time: String,
    acr: Option<String>,
    amr: String,
    family_id: String,
    used_at: Option<String>,
}

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = oauth_refresh_tokens)]
pub(super) struct RefreshRow {
    pub(super) id: String,
    pub(super) token_hash: String,
    pub(super) family_id: String,
    pub(super) grant_id: String,
    pub(super) client_id: String,
    pub(super) subject: String,
    pub(super) session_id: String,
    pub(super) scope: String,
    pub(super) audience: String,
    pub(super) auth_time: String,
    pub(super) acr: Option<String>,
    pub(super) amr: String,
    pub(super) created_at: String,
    pub(super) expires_at: String,
    pub(super) used_at: Option<String>,
}

/// A code exchange by the client `client_id`, already authenticated.
pub(super) struct CodeExchange<'a> {
    pub(super) client_id: &'a str,
    pub(super) code: &'a str,
    pub(super) redirect_uri: Option<&'a str>,
    pub(super) code_verifier: Option<&'a str>,
    /// RFC 8707 `resource` values narrowing the access token audience.
    pub(super) resource: &'a [String],
    /// Whether the client is registered for the `refresh_token` grant.
    pub(super) refresh_allowed: bool,
}

/// A refresh by the client `client_id`, already authenticated.
pub(super) struct RefreshExchange<'a> {
    pub(super) client_id: &'a str,
    pub(super) refresh_token: &'a str,
    /// A narrower scope for this response only.
    pub(super) scope: Option<&'a [String]>,
    /// A narrower audience for this response only.
    pub(super) resource: &'a [String],
}

/// What a successful exchange hands to token minting.
#[derive(Debug)]
pub(super) struct Issued {
    pub(super) grant: GrantRow,
    pub(super) session_id: String,
    pub(super) auth_time: DateTime<Utc>,
    pub(super) acr: Option<String>,
    pub(super) amr: Vec<String>,
    /// Set on a code exchange only.
    pub(super) nonce: Option<String>,
    /// The scope and audience of this response.
    pub(super) scope: Vec<String>,
    pub(super) audience: Vec<String>,
    pub(super) refresh_token: Option<String>,
}

/// How a consuming transaction ended. A replay commits the family's deletion.
enum Consumed {
    Won(Box<GrantRow>),
    Replayed,
    Refused,
}

/// RFC 7636: `S256` only. A challenge needs a verifier of 43 to 128 unreserved characters whose
/// hash matches, compared in constant time; a verifier without a challenge is refused.
fn pkce_holds(challenge: Option<&str>, verifier: Option<&str>) -> bool {
    match (challenge, verifier) {
        (None, None) => true,
        (Some(challenge), Some(verifier)) => {
            let well_formed = (43..=128).contains(&verifier.len())
                && verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
            let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            well_formed && bool::from(computed.as_bytes().ct_eq(challenge.as_bytes()))
        }
        _ => false,
    }
}

/// Serialises the transactions that rotate or delete the refresh tokens of one grant.
trait LockGrant {
    fn lock_grant(&mut self, grant_id: &str) -> diesel::QueryResult<()>;
}

impl LockGrant for diesel::sqlite::SqliteConnection {
    // `serialized_txn!` already opens sqlite transactions with BEGIN IMMEDIATE.
    fn lock_grant(&mut self, _grant_id: &str) -> diesel::QueryResult<()> {
        Ok(())
    }
}

impl LockGrant for diesel::pg::PgConnection {
    // Under READ COMMITTED a family delete misses the successor of an uncommitted rotation.
    fn lock_grant(&mut self, grant_id: &str) -> diesel::QueryResult<()> {
        oauth_consent_grants::table
            .find(grant_id)
            .select(oauth_consent_grants::id)
            .for_update()
            .first::<String>(self)
            .optional()
            .map(|_| ())
    }
}

/// `requested` when every entry is in `granted`, else `invalid_scope`; nothing requested keeps
/// `granted`.
fn narrowed_scope(granted: &[String], requested: &[String]) -> Result<Vec<String>, Invalid> {
    if requested.is_empty() {
        return Ok(granted.to_vec());
    }
    let mut out: Vec<String> = Vec::with_capacity(requested.len());
    for r in requested {
        if !granted.contains(r) {
            return Err(Invalid::Scope);
        }
        if !out.contains(r) {
            out.push(r.clone());
        }
    }
    Ok(out)
}

/// Each requested resource as the grant holds it: verbatim, else by the canonical form consent
/// grants under. One that matches neither way is `invalid_target`; nothing requested keeps the
/// whole audience.
fn narrowed_audience(granted: &[String], requested: &[String]) -> Result<Vec<String>, Invalid> {
    use crate::oauth::canonical_resource;
    if requested.is_empty() {
        return Ok(granted.to_vec());
    }
    let mut out: Vec<String> = Vec::with_capacity(requested.len());
    for r in requested {
        let held = granted
            .iter()
            .find(|g| *g == r)
            .or_else(|| {
                let wanted = canonical_resource(r)?;
                granted
                    .iter()
                    .find(|g| canonical_resource(g).as_deref() == Some(wanted.as_str()))
            })
            .ok_or(Invalid::Target)?;
        if !out.contains(held) {
            out.push(held.clone());
        }
    }
    Ok(out)
}

fn offline_granted(scope: &[String]) -> bool {
    scope.iter().any(|s| OFFLINE_SCOPES.contains(&s.as_str()))
}

/// The stored row of a refresh token, used, expired or not.
pub(super) async fn find_refresh(db: &DbPool, token: &str) -> Result<Option<RefreshRow>> {
    let hash = token_hash(token);
    Ok(db_interact!(db, |c| {
        oauth_refresh_tokens::table
            .filter(oauth_refresh_tokens::token_hash.eq(hash))
            .select(RefreshRow::as_select())
            .first(c)
            .optional()
    })?)
}

/// RFC 7009 revocation of a refresh token of `client_id`: its family is deleted and the grant's
/// `tokens_revoked_at` set. An unknown, foreign or expired token changes nothing; the result says
/// whether the token was revoked.
pub(super) async fn revoke_refresh(
    db: &DbPool,
    client_id: &str,
    token: &str,
    now: DateTime<Utc>,
) -> Result<bool> {
    let Some(row) = find_refresh(db, token).await? else {
        return Ok(false);
    };
    if row.client_id != client_id || row.expires_at <= rfc3339(now) {
        return Ok(false);
    }
    let (grant_id, family_id, revoked_at) = (row.grant_id, row.family_id, rfc3339(now));
    serialized_txn!(db, (), DieselError, |c| {
        c.lock_grant(&grant_id)?;
        diesel::delete(
            oauth_refresh_tokens::table.filter(oauth_refresh_tokens::family_id.eq(&family_id)),
        )
        .execute(c)?;
        diesel::update(oauth_consent_grants::table.find(&grant_id))
            .set(oauth_consent_grants::tokens_revoked_at.eq(Some(revoked_at)))
            .execute(c)?;
        Ok(())
    })?;
    Ok(true)
}

async fn delete_family(db: &DbPool, grant_id: &str, family_id: &str) -> Result<()> {
    let (grant_id, family_id) = (grant_id.to_string(), family_id.to_string());
    serialized_txn!(db, usize, DieselError, |c| {
        c.lock_grant(&grant_id)?;
        diesel::delete(
            oauth_refresh_tokens::table.filter(oauth_refresh_tokens::family_id.eq(&family_id)),
        )
        .execute(c)
    })?;
    Ok(())
}

struct Successor<'a> {
    family_id: &'a str,
    grant: &'a GrantRow,
    session_id: &'a str,
    scope: &'a str,
    audience: &'a str,
    auth_time: &'a str,
    acr: Option<&'a str>,
    amr: &'a str,
}

/// A fresh refresh token and the row that stores its hash.
fn new_refresh(s: &Successor<'_>, now: DateTime<Utc>) -> (String, RefreshRow) {
    let token = random_token();
    let row = RefreshRow {
        id: uuid::Uuid::new_v4().to_string(),
        token_hash: token_hash(&token),
        family_id: s.family_id.to_string(),
        grant_id: s.grant.id.clone(),
        client_id: s.grant.client_id.clone(),
        subject: s.grant.subject.clone(),
        session_id: s.session_id.to_string(),
        scope: s.scope.to_string(),
        audience: s.audience.to_string(),
        auth_time: s.auth_time.to_string(),
        acr: s.acr.map(str::to_string),
        amr: s.amr.to_string(),
        created_at: rfc3339(now),
        expires_at: rfc3339(now + chrono::Duration::seconds(REFRESH_TOKEN_TTL_SECS)),
        used_at: None,
    };
    (token, row)
}

async fn find_code(db: &DbPool, hash: &str) -> Result<Option<CodeRow>> {
    let hash = hash.to_string();
    Ok(db_interact!(db, |c| {
        oauth_authorization_codes::table
            .find(hash)
            .select(CodeRow::as_select())
            .first(c)
            .optional()
    })?)
}

/// Redeems a code once. Checks run in order: the code exists and belongs to the client, it was
/// issued to a redirect URI (a device code has none) that matches byte for byte, PKCE holds; a
/// failure there changes nothing. Then [`consume`].
pub(super) async fn redeem_code(
    db: &DbPool,
    x: &CodeExchange<'_>,
    now: DateTime<Utc>,
) -> Result<Issued> {
    let hash = token_hash(x.code);
    let row = find_code(db, &hash).await?.ok_or(Invalid::Grant)?;
    if row.client_id != x.client_id
        || row.redirect_uri.is_empty()
        || x.redirect_uri != Some(row.redirect_uri.as_str())
        || !pkce_holds(row.code_challenge.as_deref(), x.code_verifier)
    {
        return Err(Invalid::Grant.into());
    }
    consume(db, row, hash, x.resource, x.refresh_allowed, now).await
}

/// Redeems the code an approved device authorization stored under `device_code_hash`, once. It
/// must belong to the client and carry no redirect URI, else nothing changes. Then [`consume`].
pub(super) async fn redeem_device_code(
    db: &DbPool,
    client_id: &str,
    device_code_hash: &str,
    resource: &[String],
    refresh_allowed: bool,
    now: DateTime<Utc>,
) -> Result<Issued> {
    let row = find_code(db, device_code_hash)
        .await?
        .ok_or(Invalid::Grant)?;
    if row.client_id != client_id || !row.redirect_uri.is_empty() {
        return Err(Invalid::Grant.into());
    }
    let hash = device_code_hash.to_string();
    consume(db, row, hash, resource, refresh_allowed, now).await
}

/// A used code deletes its family's refresh tokens; an unused, unexpired one is consumed and
/// yields the grant, with a refresh token when allowed and an offline scope was granted.
async fn consume(
    db: &DbPool,
    row: CodeRow,
    hash: String,
    resource: &[String],
    refresh_allowed: bool,
    now: DateTime<Utc>,
) -> Result<Issued> {
    if row.used_at.is_some() {
        delete_family(db, &row.grant_id, &row.family_id).await?;
        return Err(Invalid::Grant.into());
    }
    let scope: Vec<String> = from_json(&row.scope)?;
    let audience = narrowed_audience(&from_json::<Vec<String>>(&row.audience)?, resource)?;
    let amr: Vec<String> = from_json(&row.amr)?;
    let auth_time = parse_time(&row.auth_time)?;
    let wants_refresh = refresh_allowed && offline_granted(&scope);

    let now_s = rfc3339(now);
    let (outcome, refresh_token) = {
        let row = CodeRowParts::from(&row);
        serialized_txn!(db, (Consumed, Option<String>), DieselError, |c| {
            c.lock_grant(&row.grant_id)?;
            let consumed = diesel::update(
                oauth_authorization_codes::table
                    .filter(oauth_authorization_codes::code_hash.eq(&hash))
                    .filter(oauth_authorization_codes::used_at.is_null())
                    .filter(oauth_authorization_codes::expires_at.gt(&now_s)),
            )
            .set(oauth_authorization_codes::used_at.eq(Some(&now_s)))
            .execute(c)?;
            if consumed == 0 {
                let used: Option<Option<String>> = oauth_authorization_codes::table
                    .find(&hash)
                    .select(oauth_authorization_codes::used_at)
                    .first(c)
                    .optional()?;
                if matches!(used, Some(Some(_))) {
                    diesel::delete(
                        oauth_refresh_tokens::table
                            .filter(oauth_refresh_tokens::family_id.eq(&row.family_id)),
                    )
                    .execute(c)?;
                    return Ok((Consumed::Replayed, None));
                }
                return Ok((Consumed::Refused, None));
            }
            let Some(grant) = oauth_consent_grants::table
                .find(&row.grant_id)
                .select(GrantRow::as_select())
                .first(c)
                .optional()?
            else {
                return Err(DieselError::RollbackTransaction);
            };
            let refresh = if wants_refresh {
                let (token, new_row) = new_refresh(
                    &Successor {
                        family_id: &row.family_id,
                        grant: &grant,
                        session_id: &row.session_id,
                        scope: &row.scope,
                        audience: &row.audience,
                        auth_time: &row.auth_time,
                        acr: row.acr.as_deref(),
                        amr: &row.amr,
                    },
                    now,
                );
                diesel::insert_into(oauth_refresh_tokens::table)
                    .values(&new_row)
                    .execute(c)?;
                Some(token)
            } else {
                None
            };
            Ok((Consumed::Won(Box::new(grant)), refresh))
        })
        .or_else(rollback_as_refused)?
    };
    let Consumed::Won(grant) = outcome else {
        return Err(Invalid::Grant.into());
    };
    Ok(Issued {
        grant: *grant,
        session_id: row.session_id,
        auth_time,
        acr: row.acr,
        amr,
        nonce: row.nonce,
        scope,
        audience,
        refresh_token,
    })
}

/// The owned columns the code transaction needs.
struct CodeRowParts {
    grant_id: String,
    family_id: String,
    session_id: String,
    scope: String,
    audience: String,
    auth_time: String,
    acr: Option<String>,
    amr: String,
}

impl From<&CodeRow> for CodeRowParts {
    fn from(r: &CodeRow) -> Self {
        Self {
            grant_id: r.grant_id.clone(),
            family_id: r.family_id.clone(),
            session_id: r.session_id.clone(),
            scope: r.scope.clone(),
            audience: r.audience.clone(),
            auth_time: r.auth_time.clone(),
            acr: r.acr.clone(),
            amr: r.amr.clone(),
        }
    }
}

/// A grant revoked between the read and the consume rolls the transaction back.
fn rollback_as_refused<T: Default>(e: DieselError) -> Result<(Consumed, T), DieselError> {
    match e {
        DieselError::RollbackTransaction => Ok((Consumed::Refused, T::default())),
        other => Err(other),
    }
}

/// Rotates a refresh token. Checks run in order: the token exists and belongs to the client
/// (else nothing changes), a used token deletes its whole family, an expired one is refused, a
/// narrower scope or resource must be within the grant. Then the token is consumed and its
/// successor, carrying the full grant, inserted in the same transaction.
pub(super) async fn refresh(
    db: &DbPool,
    x: &RefreshExchange<'_>,
    now: DateTime<Utc>,
) -> Result<Issued> {
    let row = find_refresh(db, x.refresh_token)
        .await?
        .filter(|r| r.client_id == x.client_id)
        .ok_or(Invalid::Grant)?;
    if row.used_at.is_some() {
        delete_family(db, &row.grant_id, &row.family_id).await?;
        return Err(Invalid::Grant.into());
    }
    let now_s = rfc3339(now);
    if row.expires_at <= now_s {
        return Err(Invalid::Grant.into());
    }
    let granted_scope: Vec<String> = from_json(&row.scope)?;
    let scope = narrowed_scope(&granted_scope, x.scope.unwrap_or_default())?;
    let audience = narrowed_audience(&from_json::<Vec<String>>(&row.audience)?, x.resource)?;
    let amr: Vec<String> = from_json(&row.amr)?;
    let auth_time = parse_time(&row.auth_time)?;

    let (outcome, refresh_token) = {
        let row = row.clone();
        serialized_txn!(db, (Consumed, Option<String>), DieselError, |c| {
            c.lock_grant(&row.grant_id)?;
            let consumed = diesel::update(
                oauth_refresh_tokens::table
                    .filter(oauth_refresh_tokens::id.eq(&row.id))
                    .filter(oauth_refresh_tokens::used_at.is_null())
                    .filter(oauth_refresh_tokens::expires_at.gt(&now_s)),
            )
            .set(oauth_refresh_tokens::used_at.eq(Some(&now_s)))
            .execute(c)?;
            if consumed == 0 {
                let used: Option<Option<String>> = oauth_refresh_tokens::table
                    .find(&row.id)
                    .select(oauth_refresh_tokens::used_at)
                    .first(c)
                    .optional()?;
                if matches!(used, Some(Some(_))) {
                    diesel::delete(
                        oauth_refresh_tokens::table
                            .filter(oauth_refresh_tokens::family_id.eq(&row.family_id)),
                    )
                    .execute(c)?;
                    return Ok((Consumed::Replayed, None));
                }
                return Ok((Consumed::Refused, None));
            }
            let Some(grant) = oauth_consent_grants::table
                .find(&row.grant_id)
                .select(GrantRow::as_select())
                .first(c)
                .optional()?
            else {
                return Err(DieselError::RollbackTransaction);
            };
            let (token, successor) = new_refresh(
                &Successor {
                    family_id: &row.family_id,
                    grant: &grant,
                    session_id: &row.session_id,
                    scope: &row.scope,
                    audience: &row.audience,
                    auth_time: &row.auth_time,
                    acr: row.acr.as_deref(),
                    amr: &row.amr,
                },
                now,
            );
            diesel::insert_into(oauth_refresh_tokens::table)
                .values(&successor)
                .execute(c)?;
            Ok((Consumed::Won(Box::new(grant)), Some(token)))
        })
        .or_else(rollback_as_refused)?
    };
    let Consumed::Won(grant) = outcome else {
        return Err(Invalid::Grant.into());
    };
    Ok(Issued {
        grant: *grant,
        session_id: row.session_id,
        auth_time,
        acr: row.acr,
        amr,
        nonce: None,
        scope,
        audience,
        refresh_token,
    })
}

#[cfg(test)]
mod tests;
