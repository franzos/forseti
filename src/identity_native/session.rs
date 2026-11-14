//! Sign-in sessions: rows, the session cookie, whoami and the logout token.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use axum_extra::extract::cookie::{Cookie, SameSite};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use super::NativeBackend;
use super::codes::{self, MacKey};
use super::store::{self, CredentialSummary, IdentityRow, MAX_PAGE_SIZE};
use crate::backend::identity::{Aal, AuthMethod, Session, SessionDevice, WhoamiOutcome};
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{identities, identity_credentials, identity_sessions};

const COOKIE_NAME: &str = "forseti_session";
/// On https; `__Host-` pins Secure, Path=/ and no Domain in the browser.
const COOKIE_NAME_SECURE: &str = "__Host-forseti_session";

/// Kratos's default page size for an identity's sessions.
const IDENTITY_PAGE_SIZE: i64 = 250;

/// Revoked and expired rows are kept this long for the session lists, then deleted.
const RETENTION_DAYS: i64 = 30;

/// Read-modify-write rounds before a contended method append gives up.
const APPEND_ATTEMPTS: usize = 5;

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = identity_sessions)]
pub(super) struct SessionRow {
    pub id: String,
    pub identity_id: String,
    pub token_hash: String,
    pub aal: String,
    pub methods: String,
    pub issued_at: String,
    pub authenticated_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// One entry of `identity_sessions.methods`.
#[derive(Serialize, Deserialize)]
struct StoredMethod {
    method: String,
    aal: String,
    completed_at: String,
}

/// Where a session was created from.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Device<'a> {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
}

/// A new session and the cookie value that carries it.
#[derive(Debug)]
pub(super) struct Issued {
    pub id: String,
    pub token: String,
}

pub(super) fn cookie_name(secure: bool) -> &'static str {
    if secure {
        COOKIE_NAME_SECURE
    } else {
        COOKIE_NAME
    }
}

/// `Set-Cookie` value carrying `token` for `lifespan`.
pub(super) fn set_cookie(token: &str, secure: bool, lifespan: chrono::Duration) -> String {
    let mut s = Cookie::build((cookie_name(secure), token))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .build()
        .to_string();
    s.push_str(&format!("; Max-Age={}", lifespan.num_seconds().max(0)));
    s
}

/// `Set-Cookie` value that removes the session cookie.
pub(super) fn clear_cookie(secure: bool) -> String {
    let mut s = Cookie::build((cookie_name(secure), ""))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .build()
        .to_string();
    s.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    s
}

fn parse_aal(s: &str) -> Result<Aal> {
    match s {
        "aal1" => Ok(Aal::Aal1),
        "aal2" => Ok(Aal::Aal2),
        other => Err(anyhow!("stored AAL {other:?} is not aal1 or aal2")),
    }
}

/// Sessions only ever hold AAL1 or AAL2.
fn storable(aal: Aal) -> Result<Aal> {
    match aal {
        Aal::Aal1 | Aal::Aal2 => Ok(aal),
        other => Err(anyhow!("a session cannot be recorded at {other}")),
    }
}

fn parse_methods(text: &str) -> Result<Vec<StoredMethod>> {
    serde_json::from_str(text).map_err(|e| anyhow!("identity_sessions.methods is not valid: {e}"))
}

fn methods_json(methods: &[StoredMethod]) -> String {
    serde_json::to_string(methods).expect("method list serialises")
}

fn is_live(row: &SessionRow, now: &str) -> bool {
    row.revoked_at.is_none() && row.expires_at.as_str() > now
}

fn to_session(
    row: SessionRow,
    identity: Option<IdentityRow>,
    creds: Vec<CredentialSummary>,
    now: &str,
) -> Result<Session> {
    let active = is_live(&row, now);
    let methods = parse_methods(&row.methods)?
        .into_iter()
        .map(|m| {
            Ok(AuthMethod {
                aal: Some(parse_aal(&m.aal)?),
                completed_at: Some(m.completed_at),
                method: Some(m.method),
                ..AuthMethod::default()
            })
        })
        .collect::<Result<_>>()?;
    let aal = parse_aal(&row.aal)?;
    let identity = identity
        .map(|i| store::to_identity(i, creds).map(Box::new))
        .transpose()?;
    Ok(Session {
        id: row.id,
        active: Some(active),
        authenticator_assurance_level: Some(aal),
        authentication_methods: Some(methods),
        devices: Some(vec![SessionDevice {
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            location: None,
        }]),
        issued_at: Some(row.issued_at),
        authenticated_at: Some(row.authenticated_at),
        expires_at: Some(row.expires_at),
        identity,
    })
}

/// Group credential summaries by identity id.
fn by_identity(creds: Vec<CredentialSummary>) -> HashMap<String, Vec<CredentialSummary>> {
    let mut map: HashMap<String, Vec<CredentialSummary>> = HashMap::new();
    for c in creds {
        map.entry(c.identity_id.clone()).or_default().push(c);
    }
    map
}

/// Insert a session for `identity_id` completed by `method` at `aal`.
pub(super) async fn create(
    db: &DbPool,
    identity_id: &str,
    method: &str,
    aal: Aal,
    lifespan: chrono::Duration,
    device: Device<'_>,
) -> Result<Issued> {
    let aal = storable(aal)?;
    let now = chrono::Utc::now();
    let expires = now
        .checked_add_signed(lifespan)
        .ok_or_else(|| anyhow!("session lifespan {lifespan} is out of range"))?;
    let now = crate::db::rfc3339(now);
    let token = codes::new_session_token();
    let row = SessionRow {
        id: uuid::Uuid::new_v4().to_string(),
        identity_id: identity_id.to_string(),
        token_hash: codes::session_token_hash(&token),
        aal: aal.as_str().to_string(),
        methods: methods_json(&[StoredMethod {
            method: method.to_string(),
            aal: aal.as_str().to_string(),
            completed_at: now.clone(),
        }]),
        issued_at: now.clone(),
        authenticated_at: now,
        expires_at: crate::db::rfc3339(expires),
        revoked_at: None,
        ip_address: device.ip.map(|ip| ip.to_string()),
        user_agent: device.user_agent.map(crate::audit::cap_user_agent),
    };
    let id = row.id.clone();
    db_interact!(db, |c| {
        diesel::insert_into(identity_sessions::table)
            .values(&row)
            .execute(c)
    })?;
    Ok(Issued { id, token })
}

/// How [`record_method`] ended.
#[derive(Debug, PartialEq)]
enum Recorded {
    Done,
    NotLive,
    /// The session moved off the expected token before this change landed.
    Superseded,
}

/// A token rotation to apply with the method: the session must still carry `from`.
struct Rotation {
    from: String,
    to: String,
}

/// Record `method` on a live session, advance `authenticated_at` and raise the AAL to `aal` if it
/// is higher; the AAL never drops. The method list keeps the newest entry per method name, oldest
/// first. With `rotation` the session moves to a new token.
async fn record_method(
    db: &DbPool,
    id: &str,
    method: &str,
    aal: Aal,
    rotation: Option<Rotation>,
) -> Result<Recorded> {
    let aal = storable(aal)?;
    let (id, method) = (id.to_string(), method.to_string());
    db_interact!(db, |c| {
        for _ in 0..APPEND_ATTEMPTS {
            let now = crate::db::now_rfc3339();
            let row: Option<SessionRow> = identity_sessions::table
                .find(&id)
                .select(SessionRow::as_select())
                .first(c)
                .optional()?;
            let Some(row) = row.filter(|r| is_live(r, &now)) else {
                return Ok(Recorded::NotLive);
            };
            if rotation.as_ref().is_some_and(|r| r.from != row.token_hash) {
                return Ok(Recorded::Superseded);
            }
            let mut methods = parse_methods(&row.methods)?;
            methods.retain(|m| m.method != method);
            methods.push(StoredMethod {
                method: method.clone(),
                aal: aal.as_str().to_string(),
                completed_at: now.clone(),
            });
            let raised = parse_aal(&row.aal)?.max(aal);
            let token_hash = rotation.as_ref().map_or(&row.token_hash, |r| &r.to);
            let updated = diesel::update(
                identity_sessions::table
                    .find(&id)
                    .filter(identity_sessions::token_hash.eq(&row.token_hash))
                    .filter(identity_sessions::methods.eq(&row.methods))
                    .filter(identity_sessions::revoked_at.is_null()),
            )
            .set((
                identity_sessions::aal.eq(raised.as_str()),
                identity_sessions::methods.eq(methods_json(&methods)),
                identity_sessions::authenticated_at.eq(&now),
                identity_sessions::token_hash.eq(token_hash),
            ))
            .execute(c)?;
            if updated > 0 {
                return Ok(Recorded::Done);
            }
        }
        Err(anyhow!(
            "session {id} changed on every one of {APPEND_ATTEMPTS} attempts"
        ))
    })
}

/// What a step-up did.
#[derive(Debug, PartialEq)]
pub(super) enum StepUp {
    /// The new cookie value; the old one stops working.
    Rotated(String),
    /// A concurrent step-up moved the session to another token first; nothing was changed.
    Superseded,
    NotLive,
}

/// A further authentication step on the live `session`: records `method`, raises the AAL, and
/// moves the session from the token the caller holds to a new one.
pub(super) async fn step_up(
    db: &DbPool,
    session: &SessionRow,
    method: &str,
    aal: Aal,
) -> Result<StepUp> {
    let token = codes::new_session_token();
    let rotation = Rotation {
        from: session.token_hash.clone(),
        to: codes::session_token_hash(&token),
    };
    Ok(
        match record_method(db, &session.id, method, aal, Some(rotation)).await? {
            Recorded::Done => StepUp::Rotated(token),
            Recorded::Superseded => StepUp::Superseded,
            Recorded::NotLive => StepUp::NotLive,
        },
    )
}

/// Re-authentication on a live session: records `method` and advances `authenticated_at`, keeping
/// the token and an AAL already reached. `false` when the session is not live.
pub(super) async fn refresh(db: &DbPool, id: &str, method: &str, aal: Aal) -> Result<bool> {
    Ok(record_method(db, id, method, aal, None).await? == Recorded::Done)
}

/// The live session with this id.
pub(super) async fn find_live(db: &DbPool, id: &str) -> Result<Option<SessionRow>> {
    let id = id.to_string();
    let now = crate::db::now_rfc3339();
    let row: Option<SessionRow> = db_interact!(db, |c| {
        identity_sessions::table
            .find(&id)
            .select(SessionRow::as_select())
            .first(c)
            .optional()
    })?;
    Ok(row.filter(|r| is_live(r, &now)))
}

/// Whether `id` is a live session of `identity_id`.
pub(super) async fn is_live_for(db: &DbPool, identity_id: &str, id: &str) -> Result<bool> {
    let (identity_id, id) = (identity_id.to_string(), id.to_string());
    let now = crate::db::now_rfc3339();
    Ok(db_interact!(db, |c| {
        diesel::select(diesel::dsl::exists(
            identity_sessions::table
                .filter(identity_sessions::id.eq(&id))
                .filter(identity_sessions::identity_id.eq(&identity_id))
                .filter(identity_sessions::revoked_at.is_null())
                .filter(identity_sessions::expires_at.gt(&now)),
        ))
        .get_result::<bool>(c)
    })?)
}

/// The live session `token` belongs to.
pub(super) async fn find_live_by_token(db: &DbPool, token: &str) -> Result<Option<SessionRow>> {
    let hash = codes::session_token_hash(token);
    let now = crate::db::now_rfc3339();
    let row: Option<SessionRow> = db_interact!(db, |c| {
        identity_sessions::table
            .filter(identity_sessions::token_hash.eq(&hash))
            .select(SessionRow::as_select())
            .first(c)
            .optional()
    })?;
    Ok(row.filter(|r| is_live(r, &now)))
}

/// Sessions with their identities, and those identities' credential summaries.
type SessionPage = (Vec<(SessionRow, IdentityRow)>, Vec<CredentialSummary>);

enum By {
    TokenHash(String),
    Id(String),
}

/// One session joined to its identity and the identity's credential summaries, in one checkout.
async fn load_with_identity(
    db: &DbPool,
    by: By,
) -> Result<Option<(SessionRow, IdentityRow, Vec<CredentialSummary>)>> {
    Ok(db_interact!(db, |c| {
        let query = identity_sessions::table
            .inner_join(identities::table)
            .select((SessionRow::as_select(), IdentityRow::as_select()))
            .into_boxed();
        let query = match &by {
            By::TokenHash(hash) => query.filter(identity_sessions::token_hash.eq(hash.clone())),
            By::Id(id) => query.filter(identity_sessions::id.eq(id.clone())),
        };
        let Some((session, identity)) = query.first(c).optional()? else {
            return QueryResult::Ok(None);
        };
        let creds = identity_credentials::table
            .filter(identity_credentials::identity_id.eq(&identity.id))
            .select(CredentialSummary::as_select())
            .load(c)?;
        Ok(Some((session, identity, creds)))
    })?)
}

/// Kratos's whoami under `highest_available`: a session of an identity with TOTP needs AAL2.
pub(super) async fn whoami(db: &DbPool, token: &str) -> Result<WhoamiOutcome> {
    let found = load_with_identity(db, By::TokenHash(codes::session_token_hash(token))).await?;
    let now = crate::db::now_rfc3339();
    let Some((session, identity, creds)) = found else {
        return Ok(WhoamiOutcome::None);
    };
    if !is_live(&session, &now) || identity.state != "active" {
        return Ok(WhoamiOutcome::None);
    }
    let aal = match parse_aal(&session.aal) {
        Ok(aal) => aal,
        Err(e) => {
            tracing::error!(error = %e, session_id = %session.id, "session has an unreadable AAL");
            return Ok(WhoamiOutcome::None);
        }
    };
    let aal2_available = creds.iter().any(|c| c.kind == "totp");
    if aal2_available && aal < Aal::Aal2 {
        return Ok(WhoamiOutcome::InsufficientAal);
    }
    let id = session.id.clone();
    match to_session(session, Some(identity), creds, &now) {
        Ok(session) => Ok(WhoamiOutcome::Ok(Box::new(session))),
        Err(e) => {
            tracing::error!(error = %e, session_id = %id, "session is unreadable; treated as signed out");
            Ok(WhoamiOutcome::None)
        }
    }
}

/// `rows` as sessions, leaving out (and logging) any row that does not read.
fn readable<I>(rows: I) -> Vec<Session>
where
    I: IntoIterator<Item = (String, Result<Session>)>,
{
    rows.into_iter()
        .filter_map(|(id, read)| {
            read.map_err(|e| {
                tracing::error!(error = %e, session_id = %id, "session is unreadable; left out of the list");
            })
            .ok()
        })
        .collect()
}

/// One session with its identity, live or not.
pub(super) async fn get(db: &DbPool, id: &str) -> Result<Option<Session>> {
    let now = crate::db::now_rfc3339();
    load_with_identity(db, By::Id(id.to_string()))
        .await?
        .map(|(session, identity, creds)| to_session(session, Some(identity), creds, &now))
        .transpose()
}

/// Every session of an identity, newest first, at most `limit`.
pub(super) async fn list_for_identity(
    db: &DbPool,
    identity_id: &str,
    limit: Option<i64>,
) -> Result<Vec<Session>> {
    let identity_id = identity_id.to_string();
    let rows: Vec<SessionRow> = db_interact!(db, |c| {
        let mut query = identity_sessions::table
            .filter(identity_sessions::identity_id.eq(identity_id))
            .select(SessionRow::as_select())
            .order((
                identity_sessions::issued_at.desc(),
                identity_sessions::id.desc(),
            ))
            .into_boxed();
        if let Some(limit) = limit {
            query = query.limit(limit);
        }
        query.load(c)
    })?;
    let now = crate::db::now_rfc3339();
    Ok(readable(rows.into_iter().map(|r| {
        (r.id.clone(), to_session(r, None, Vec::new(), &now))
    })))
}

/// [`list_for_identity`] with the default page size.
pub(super) async fn list_page_for_identity(db: &DbPool, identity_id: &str) -> Result<Vec<Session>> {
    list_for_identity(db, identity_id, Some(IDENTITY_PAGE_SIZE)).await
}

/// The identity's live sessions, newest first, without `except`.
pub(super) async fn live_for_identity(
    db: &DbPool,
    identity_id: &str,
    except: Option<&str>,
) -> Result<Vec<Session>> {
    let (identity_id, except) = (identity_id.to_string(), except.map(str::to_string));
    let now = crate::db::now_rfc3339();
    let cutoff = now.clone();
    let rows: Vec<SessionRow> = db_interact!(db, |c| {
        let mut query = identity_sessions::table
            .filter(identity_sessions::identity_id.eq(identity_id))
            .filter(identity_sessions::revoked_at.is_null())
            .filter(identity_sessions::expires_at.gt(cutoff))
            .select(SessionRow::as_select())
            .order((
                identity_sessions::issued_at.desc(),
                identity_sessions::id.desc(),
            ))
            .into_boxed();
        if let Some(except) = except {
            query = query.filter(identity_sessions::id.ne(except));
        }
        query.load(c)
    })?;
    Ok(readable(rows.into_iter().map(|r| {
        (r.id.clone(), to_session(r, None, Vec::new(), &now))
    })))
}

/// One page of every session, ordered `issued_at DESC, id DESC`, each with its identity. `after`
/// is the id of the last row of the previous page; an unknown id gives an empty page. `active`
/// keeps only live (`Some(true)`) or only revoked and expired (`Some(false)`) sessions.
pub(super) async fn list_all(
    db: &DbPool,
    page_size: i64,
    after: Option<&str>,
    active: Option<bool>,
) -> Result<Vec<Session>> {
    let limit = page_size.clamp(1, MAX_PAGE_SIZE);
    let after = after.map(str::to_string);
    let now = crate::db::now_rfc3339();
    let cutoff = now.clone();
    let loaded: Option<SessionPage> = db_interact!(db, |c| {
        let cursor = match &after {
            None => None,
            Some(token) => {
                let found = identity_sessions::table
                    .find(token)
                    .select((identity_sessions::issued_at, identity_sessions::id))
                    .first::<(String, String)>(c)
                    .optional()?;
                match found {
                    Some(found) => Some(found),
                    None => return QueryResult::Ok(None),
                }
            }
        };
        let mut query = identity_sessions::table
            .inner_join(identities::table)
            .select((SessionRow::as_select(), IdentityRow::as_select()))
            .order((
                identity_sessions::issued_at.desc(),
                identity_sessions::id.desc(),
            ))
            .limit(limit)
            .into_boxed();
        if let Some((issued, id)) = cursor {
            query = query.filter(
                identity_sessions::issued_at
                    .lt(issued.clone())
                    .or(identity_sessions::issued_at
                        .eq(issued)
                        .and(identity_sessions::id.lt(id))),
            );
        }
        match active {
            Some(true) => {
                query = query.filter(
                    identity_sessions::revoked_at
                        .is_null()
                        .and(identity_sessions::expires_at.gt(cutoff)),
                );
            }
            Some(false) => {
                query = query.filter(
                    identity_sessions::revoked_at
                        .is_not_null()
                        .or(identity_sessions::expires_at.le(cutoff)),
                );
            }
            None => {}
        }
        let rows: Vec<(SessionRow, IdentityRow)> = query.load(c)?;
        let ids: Vec<&String> = rows.iter().map(|(_, i)| &i.id).collect();
        let creds = identity_credentials::table
            .filter(identity_credentials::identity_id.eq_any(ids))
            .select(CredentialSummary::as_select())
            .load(c)?;
        Ok(Some((rows, creds)))
    })?;
    let Some((rows, creds)) = loaded else {
        return Ok(Vec::new());
    };
    let creds = by_identity(creds);
    Ok(readable(rows.into_iter().map(|(session, identity)| {
        let own = creds.get(&identity.id).cloned().unwrap_or_default();
        (
            session.id.clone(),
            to_session(session, Some(identity), own, &now),
        )
    })))
}

/// Revoke a session, only when it belongs to `owner` if one is given. `true` when the session
/// exists (and matches the owner), whether it was live or already revoked.
pub(super) async fn revoke(db: &DbPool, id: &str, owner: Option<&str>) -> Result<bool> {
    let (id, owner) = (id.to_string(), owner.map(str::to_string));
    let now = crate::db::now_rfc3339();
    db_interact!(db, |c| {
        let mut target = identity_sessions::table
            .filter(identity_sessions::id.eq(id.clone()))
            .into_boxed();
        if let Some(owner) = &owner {
            target = target.filter(identity_sessions::identity_id.eq(owner.clone()));
        }
        let exists: Option<Option<String>> = target
            .select(identity_sessions::revoked_at)
            .first(c)
            .optional()?;
        match exists {
            None => QueryResult::Ok(false),
            Some(Some(_)) => Ok(true),
            Some(None) => {
                diesel::update(
                    identity_sessions::table
                        .find(&id)
                        .filter(identity_sessions::revoked_at.is_null()),
                )
                .set(identity_sessions::revoked_at.eq(&now))
                .execute(c)?;
                Ok(true)
            }
        }
    })
    .map_err(Into::into)
}

/// Revoke the session `token` belongs to; `false` when it was not live.
pub(super) async fn revoke_by_token(db: &DbPool, token: &str) -> Result<bool> {
    let hash = codes::session_token_hash(token);
    let now = crate::db::now_rfc3339();
    let revoked = db_interact!(db, |c| {
        diesel::update(
            identity_sessions::table
                .filter(identity_sessions::token_hash.eq(&hash))
                .filter(identity_sessions::revoked_at.is_null())
                .filter(identity_sessions::expires_at.gt(&now)),
        )
        .set(identity_sessions::revoked_at.eq(&now))
        .execute(c)
    })?;
    Ok(revoked > 0)
}

/// Revoke every live session of an identity except `keep`; returns how many were revoked.
pub(super) async fn revoke_all(db: &DbPool, identity_id: &str, keep: Option<&str>) -> Result<u64> {
    // Session ids are never empty, so no `keep` spares nothing.
    let (identity_id, keep) = (identity_id.to_string(), keep.unwrap_or("").to_string());
    let now = crate::db::now_rfc3339();
    let revoked = db_interact!(db, |c| {
        diesel::update(
            identity_sessions::table
                .filter(identity_sessions::identity_id.eq(&identity_id))
                .filter(identity_sessions::revoked_at.is_null())
                .filter(identity_sessions::expires_at.gt(&now))
                .filter(identity_sessions::id.ne(&keep)),
        )
        .set(identity_sessions::revoked_at.eq(&now))
        .execute(c)
    })?;
    Ok(u64::try_from(revoked).unwrap_or(0))
}

/// Delete sessions revoked or expired more than [`RETENTION_DAYS`] ago; returns how many.
pub(super) async fn delete_stale(db: &DbPool) -> Result<usize> {
    let cutoff = crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::days(RETENTION_DAYS));
    Ok(db_interact!(db, |c| {
        diesel::delete(
            identity_sessions::table.filter(
                identity_sessions::revoked_at
                    .lt(&cutoff)
                    .or(identity_sessions::expires_at.lt(&cutoff)),
            ),
        )
        .execute(c)
    })?)
}

/// Logout token for `session_id`: a MAC only this deployment can mint.
pub(super) fn logout_token(key: &MacKey, session_id: &str) -> String {
    key.hex(&[session_id])
}

impl NativeBackend {
    fn session_lifespan(&self) -> chrono::Duration {
        chrono::Duration::hours(i64::from(self.settings.session_lifespan_hours))
    }

    /// The session cookie's value in a raw `Cookie` header, if present and non-empty.
    pub(super) fn session_token(&self, cookie_header: &str) -> Option<String> {
        crate::cookies::read_cookie_from(cookie_header, cookie_name(self.https))
            .filter(|t| !t.is_empty())
    }

    /// The live session the request's cookie carries.
    pub(super) async fn current_session(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<Option<SessionRow>> {
        match cookie_header.and_then(|h| self.session_token(h)) {
            Some(token) => find_live_by_token(&self.db, &token).await,
            None => Ok(None),
        }
    }

    /// Start a session with its first method; returns the id and the cookie value.
    pub(super) async fn issue_session(
        &self,
        identity_id: &str,
        method: &str,
        aal: Aal,
        device: Device<'_>,
    ) -> Result<Issued> {
        create(
            &self.db,
            identity_id,
            method,
            aal,
            self.session_lifespan(),
            device,
        )
        .await
    }

    /// `Set-Cookie` value for a session token.
    pub(super) fn session_set_cookie(&self, token: &str) -> String {
        set_cookie(token, self.https, self.session_lifespan())
    }

    /// Forseti's own logout URL for a session.
    pub(super) fn logout_url(&self, session_id: &str) -> String {
        format!(
            "/self-service/logout?token={}",
            logout_token(&self.keys.logout, session_id)
        )
    }

    /// The live session the cookie carries, when `token` is that session's logout token.
    pub(super) async fn verify_logout(
        &self,
        cookie_header: &str,
        token: &str,
    ) -> Result<Option<SessionRow>> {
        let Some(session) = self.current_session(Some(cookie_header)).await? else {
            return Ok(None);
        };
        Ok(self
            .keys
            .logout
            .matches_hex(&[&session.id], token)
            .then_some(session))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::IdentityState;
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

    async fn identity(db: &DbPool, email: &str) -> String {
        store::create(db, email, Some("Ada"), Some("L"), true)
            .await
            .unwrap()
            .unwrap()
            .id
    }

    async fn add_credential(db: &DbPool, identity_id: &str, kind: &'static str) {
        let identity_id = identity_id.to_string();
        let now = crate::db::now_rfc3339();
        sql(db, move |c| {
            diesel::insert_into(identity_credentials::table)
                .values((
                    identity_credentials::id.eq(uuid::Uuid::new_v4().to_string()),
                    identity_credentials::identity_id.eq(&identity_id),
                    identity_credentials::kind.eq(kind),
                    identity_credentials::config.eq("{}"),
                    identity_credentials::version.eq(0),
                    identity_credentials::created_at.eq(&now),
                    identity_credentials::updated_at.eq(&now),
                ))
                .execute(c)
        })
        .await;
    }

    const DEVICE: Device<'static> = Device {
        ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7))),
        user_agent: Some("Mozilla/5.0 test"),
    };

    async fn sign_in(backend: &NativeBackend, identity_id: &str) -> Issued {
        backend
            .issue_session(identity_id, "password", Aal::Aal1, DEVICE)
            .await
            .unwrap()
    }

    fn cookie(token: &str) -> String {
        format!("a=1; forseti_session={token}; b=2")
    }

    async fn set_column(db: &DbPool, id: &str, column: &'static str, value: &str) {
        let (id, value) = (id.to_string(), value.to_string());
        sql(db, move |c| {
            diesel::sql_query(format!(
                "UPDATE identity_sessions SET {column} = ? WHERE id = ?"
            ))
            .bind::<diesel::sql_types::Text, _>(value)
            .bind::<diesel::sql_types::Text, _>(id)
            .execute(c)
        })
        .await;
    }

    async fn whoami(backend: &NativeBackend, token: &str) -> WhoamiOutcome {
        backend.whoami(Some(&cookie(token))).await.unwrap()
    }

    fn session_of(outcome: WhoamiOutcome) -> Session {
        match outcome {
            WhoamiOutcome::Ok(s) => *s,
            other => panic!("expected a session, got {other:?}"),
        }
    }

    fn method_names(s: &Session) -> Vec<(String, Aal)> {
        s.authentication_methods
            .iter()
            .flatten()
            .map(|m| (m.method.clone().unwrap(), m.aal.unwrap()))
            .collect()
    }

    async fn setup() -> (DbPool, Arc<NativeBackend>) {
        let db = test_pool().await;
        let backend = NativeBackend::for_test(&db);
        (db, backend)
    }

    #[tokio::test]
    async fn whoami_returns_the_session_populated_like_kratos() {
        let (db, backend) = setup().await;
        let id = identity(&db, "w@x.test").await;
        let issued = sign_in(&backend, &id).await;
        let s = session_of(whoami(&backend, &issued.token).await);
        assert_eq!(s.id, issued.id);
        assert_eq!(s.active, Some(true));
        assert_eq!(s.authenticator_assurance_level, Some(Aal::Aal1));
        assert_eq!(method_names(&s), [("password".to_string(), Aal::Aal1)]);
        let issued_at = s.issued_at.as_deref().unwrap();
        assert_eq!(s.authenticated_at.as_deref(), Some(issued_at));
        assert_eq!(
            s.authentication_methods.as_ref().unwrap()[0]
                .completed_at
                .as_deref(),
            Some(issued_at)
        );
        let issued = crate::oauth::reauth::parse_rfc3339(issued_at).unwrap();
        let expires =
            crate::oauth::reauth::parse_rfc3339(s.expires_at.as_deref().unwrap()).unwrap();
        assert_eq!(expires - issued, chrono::Duration::hours(24));
        assert_eq!(
            s.devices,
            Some(vec![SessionDevice {
                ip_address: Some("192.0.2.7".into()),
                user_agent: Some("Mozilla/5.0 test".into()),
                location: None,
            }])
        );
        assert_eq!(s.principal(), (id, "w@x.test".to_string()));
        assert!(!s.needs_verification());
    }

    #[tokio::test]
    async fn whoami_is_none_without_a_usable_session() {
        let (db, backend) = setup().await;
        assert!(matches!(
            backend.whoami(None).await.unwrap(),
            WhoamiOutcome::None
        ));
        assert!(matches!(
            backend.whoami(Some("a=1; forseti_session=")).await.unwrap(),
            WhoamiOutcome::None
        ));
        assert!(matches!(
            whoami(&backend, "unknown").await,
            WhoamiOutcome::None
        ));

        let id = identity(&db, "n@x.test").await;
        let revoked = sign_in(&backend, &id).await;
        assert!(revoke(&db, &revoked.id, None).await.unwrap());
        assert!(matches!(
            whoami(&backend, &revoked.token).await,
            WhoamiOutcome::None
        ));

        let expired = sign_in(&backend, &id).await;
        set_column(
            &db,
            &expired.id,
            "expires_at",
            "2020-01-01T00:00:00.000000+00:00",
        )
        .await;
        assert!(matches!(
            whoami(&backend, &expired.token).await,
            WhoamiOutcome::None
        ));

        let live = sign_in(&backend, &id).await;
        assert!(matches!(
            whoami(&backend, &live.token).await,
            WhoamiOutcome::Ok(_)
        ));
        store::set_state(&db, &id, IdentityState::Inactive)
            .await
            .unwrap();
        assert!(matches!(
            whoami(&backend, &live.token).await,
            WhoamiOutcome::None
        ));
    }

    #[tokio::test]
    async fn the_cookie_name_follows_the_deployment_scheme() {
        let (db, backend) = setup().await;
        let id = identity(&db, "c@x.test").await;
        let issued = sign_in(&backend, &id).await;
        let host_prefixed = format!("__Host-forseti_session={}", issued.token);
        assert!(matches!(
            backend.whoami(Some(&host_prefixed)).await.unwrap(),
            WhoamiOutcome::None
        ));

        let mut cfg = crate::config::AppConfig::test_fixture();
        cfg.self_.url = "https://id.example.test".into();
        let https = NativeBackend::new(&cfg, &db, &[0x42; 32]);
        assert!(matches!(
            https.whoami(Some(&host_prefixed)).await.unwrap(),
            WhoamiOutcome::Ok(_)
        ));
        assert!(matches!(
            https.whoami(Some(&cookie(&issued.token))).await.unwrap(),
            WhoamiOutcome::None
        ));

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, host_prefixed.parse().unwrap());
        assert!(https.has_session_cookie(&headers));
        assert!(!backend.has_session_cookie(&headers));
        assert!(!https.has_session_cookie(&axum::http::HeaderMap::new()));
    }

    #[test]
    fn cookie_attributes() {
        let lifespan = chrono::Duration::hours(24);
        assert_eq!(
            set_cookie("tok", true, lifespan),
            "__Host-forseti_session=tok; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=86400"
        );
        assert_eq!(
            set_cookie("tok", false, lifespan),
            "forseti_session=tok; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400"
        );
        assert_eq!(
            clear_cookie(true),
            "__Host-forseti_session=; HttpOnly; SameSite=Lax; Secure; Path=/; \
             Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        );
        assert_eq!(
            clear_cookie(false),
            "forseti_session=; HttpOnly; SameSite=Lax; Path=/; \
             Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }

    #[tokio::test]
    async fn totp_makes_aal2_required_and_step_up_rotates_the_token() {
        let (db, backend) = setup().await;
        let id = identity(&db, "t@x.test").await;
        add_credential(&db, &id, "password").await;
        add_credential(&db, &id, "totp").await;
        let issued = sign_in(&backend, &id).await;
        assert!(matches!(
            whoami(&backend, &issued.token).await,
            WhoamiOutcome::InsufficientAal
        ));

        let row = find_live(&db, &issued.id).await.unwrap().unwrap();
        let StepUp::Rotated(rotated) = step_up(&db, &row, "totp", Aal::Aal2).await.unwrap() else {
            panic!("live session rotates");
        };
        assert_ne!(rotated, issued.token);
        assert!(matches!(
            whoami(&backend, &issued.token).await,
            WhoamiOutcome::None
        ));
        let s = session_of(whoami(&backend, &rotated).await);
        assert_eq!(s.id, issued.id);
        assert_eq!(s.authenticator_assurance_level, Some(Aal::Aal2));
        assert_eq!(
            method_names(&s),
            [
                ("password".to_string(), Aal::Aal1),
                ("totp".to_string(), Aal::Aal2)
            ]
        );
        let creds = s.identity.unwrap().credentials.unwrap();
        assert!(creds.contains_key("totp") && creds.contains_key("password"));

        assert!(revoke(&db, &issued.id, None).await.unwrap());
        let row = SessionRow {
            token_hash: codes::session_token_hash(&rotated),
            ..row
        };
        assert_eq!(
            step_up(&db, &row, "totp", Aal::Aal2).await.unwrap(),
            StepUp::NotLive
        );
    }

    #[tokio::test]
    async fn a_step_up_from_a_rotated_token_is_superseded_and_changes_nothing() {
        let (db, backend) = setup().await;
        let id = identity(&db, "sup@x.test").await;
        add_credential(&db, &id, "totp").await;
        let issued = sign_in(&backend, &id).await;
        let held = find_live(&db, &issued.id).await.unwrap().unwrap();

        let StepUp::Rotated(first) = step_up(&db, &held, "totp", Aal::Aal2).await.unwrap() else {
            panic!("first step-up rotates");
        };
        let before = find_live(&db, &issued.id).await.unwrap().unwrap();
        assert_eq!(
            step_up(&db, &held, "lookup_secret", Aal::Aal2)
                .await
                .unwrap(),
            StepUp::Superseded
        );
        let after = find_live(&db, &issued.id).await.unwrap().unwrap();
        assert_eq!(after.token_hash, before.token_hash);
        assert_eq!(after.methods, before.methods);
        let s = session_of(whoami(&backend, &first).await);
        assert_eq!(s.authenticator_assurance_level, Some(Aal::Aal2));
    }

    #[tokio::test]
    async fn unknown_stored_aal_values_are_errors_not_aal1() {
        let (db, backend) = setup().await;
        let id = identity(&db, "aal@x.test").await;
        for bad in [Aal::Aal0, Aal::Aal3] {
            assert!(
                create(
                    &db,
                    &id,
                    "password",
                    bad,
                    chrono::Duration::hours(1),
                    DEVICE
                )
                .await
                .is_err()
            );
        }
        let issued = sign_in(&backend, &id).await;
        assert!(
            refresh(&db, &issued.id, "password", Aal::Aal3)
                .await
                .is_err()
        );

        set_column(&db, &issued.id, "aal", "aal3").await;
        assert!(matches!(
            whoami(&backend, &issued.token).await,
            WhoamiOutcome::None
        ));
        assert!(get(&db, &issued.id).await.is_err());
        set_column(&db, &issued.id, "aal", "AAL2").await;
        assert!(matches!(
            whoami(&backend, &issued.token).await,
            WhoamiOutcome::None
        ));
        set_column(&db, &issued.id, "aal", "aal1").await;
        let healthy = sign_in(&backend, &id).await;
        set_column(
            &db,
            &issued.id,
            "methods",
            r#"[{"method":"password","aal":"aal9","completed_at":"2026-01-01T00:00:00.000000+00:00"}]"#,
        )
        .await;
        assert!(
            matches!(
                backend.whoami(Some(&cookie(&issued.token))).await.unwrap(),
                WhoamiOutcome::None
            ),
            "a bad method AAL signs the cookie out instead of failing every request"
        );
        let ids = |list: Vec<Session>| list.into_iter().map(|s| s.id).collect::<Vec<_>>();
        let only = std::slice::from_ref(&healthy.id);
        assert_eq!(ids(list_for_identity(&db, &id, None).await.unwrap()), only);
        assert_eq!(ids(live_for_identity(&db, &id, None).await.unwrap()), only);
        assert_eq!(ids(list_all(&db, 10, None, None).await.unwrap()), only);
    }

    #[tokio::test]
    async fn lookup_codes_alone_do_not_require_aal2() {
        let (db, backend) = setup().await;
        let id = identity(&db, "l@x.test").await;
        add_credential(&db, &id, "lookup_secret").await;
        let issued = sign_in(&backend, &id).await;
        assert!(matches!(
            whoami(&backend, &issued.token).await,
            WhoamiOutcome::Ok(_)
        ));
    }

    #[tokio::test]
    async fn refresh_advances_authenticated_at_and_keeps_the_aal() {
        let (db, backend) = setup().await;
        let id = identity(&db, "r@x.test").await;
        add_credential(&db, &id, "totp").await;
        let issued = sign_in(&backend, &id).await;
        let row = find_live(&db, &issued.id).await.unwrap().unwrap();
        let StepUp::Rotated(token) = step_up(&db, &row, "totp", Aal::Aal2).await.unwrap() else {
            panic!("live session rotates");
        };
        let old = "2026-01-01T00:00:00.000000+00:00";
        set_column(&db, &issued.id, "authenticated_at", old).await;

        assert!(
            refresh(&db, &issued.id, "password", Aal::Aal1)
                .await
                .unwrap()
        );
        let s = session_of(whoami(&backend, &token).await);
        assert_eq!(s.authenticator_assurance_level, Some(Aal::Aal2));
        assert!(s.authenticated_at.as_deref().unwrap() > old);
        assert_eq!(
            method_names(&s),
            [
                ("totp".to_string(), Aal::Aal2),
                ("password".to_string(), Aal::Aal1)
            ],
            "one entry per method, the newest last"
        );
        let newest = s.authentication_methods.as_ref().unwrap()[1]
            .completed_at
            .clone();
        assert_eq!(newest, s.authenticated_at);

        for _ in 0..20 {
            assert!(
                refresh(&db, &issued.id, "password", Aal::Aal1)
                    .await
                    .unwrap()
            );
        }
        let s = session_of(whoami(&backend, &token).await);
        assert_eq!(s.authentication_methods.as_ref().unwrap().len(), 2);
        let auth_time = crate::oauth::reauth::session_auth_time(&s);
        assert_eq!(
            auth_time.map(crate::db::rfc3339),
            s.authenticated_at.clone()
        );

        set_column(
            &db,
            &issued.id,
            "expires_at",
            "2020-01-01T00:00:00.000000+00:00",
        )
        .await;
        assert!(
            !refresh(&db, &issued.id, "password", Aal::Aal1)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn own_session_list_and_revocation() {
        let (db, backend) = setup().await;
        let id = identity(&db, "o@x.test").await;
        let other_identity = identity(&db, "p@x.test").await;
        let current = sign_in(&backend, &id).await;
        let second = sign_in(&backend, &id).await;
        let gone = sign_in(&backend, &id).await;
        let foreign = sign_in(&backend, &other_identity).await;
        assert!(revoke(&db, &gone.id, None).await.unwrap());
        let me = Some(cookie(&current.token));
        let me = me.as_deref();

        let listed: Vec<String> = backend
            .list_my_sessions(me)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(listed, std::slice::from_ref(&second.id));
        assert!(backend.list_my_sessions(None).await.is_err());

        assert!(backend.revoke_session(&current.id, me).await.is_err());
        assert!(backend.revoke_session(&foreign.id, me).await.is_err());
        assert!(backend.revoke_session("missing", me).await.is_err());
        assert!(backend.revoke_session(&second.id, None).await.is_err());
        assert!(matches!(
            whoami(&backend, &foreign.token).await,
            WhoamiOutcome::Ok(_)
        ));
        backend.revoke_session(&second.id, me).await.unwrap();
        assert!(matches!(
            whoami(&backend, &second.token).await,
            WhoamiOutcome::None
        ));
        assert!(matches!(
            whoami(&backend, &current.token).await,
            WhoamiOutcome::Ok(_)
        ));
    }

    #[tokio::test]
    async fn revoke_others_keeps_the_current_session() {
        let (db, backend) = setup().await;
        let id = identity(&db, "k@x.test").await;
        let other_identity = identity(&db, "q@x.test").await;
        let current = sign_in(&backend, &id).await;
        let a = sign_in(&backend, &id).await;
        let b = sign_in(&backend, &id).await;
        let expired = sign_in(&backend, &id).await;
        set_column(
            &db,
            &expired.id,
            "expires_at",
            "2020-01-01T00:00:00.000000+00:00",
        )
        .await;
        let foreign = sign_in(&backend, &other_identity).await;

        assert!(backend.revoke_other_sessions(None).await.is_err());
        let me = cookie(&current.token);
        assert_eq!(backend.revoke_other_sessions(Some(&me)).await.unwrap(), 2);
        for gone in [&a, &b] {
            assert!(matches!(
                whoami(&backend, &gone.token).await,
                WhoamiOutcome::None
            ));
        }
        assert!(matches!(
            whoami(&backend, &current.token).await,
            WhoamiOutcome::Ok(_)
        ));
        assert!(matches!(
            whoami(&backend, &foreign.token).await,
            WhoamiOutcome::Ok(_)
        ));
        assert_eq!(revoke_all(&db, &id, None).await.unwrap(), 1);
        assert!(matches!(
            whoami(&backend, &current.token).await,
            WhoamiOutcome::None
        ));
    }

    #[tokio::test]
    async fn active_sessions_exclude_revoked_and_expired() {
        let (db, backend) = setup().await;
        let id = identity(&db, "a@x.test").await;
        let live = sign_in(&backend, &id).await;
        let revoked = sign_in(&backend, &id).await;
        let expired = sign_in(&backend, &id).await;
        revoke(&db, &revoked.id, None).await.unwrap();
        set_column(
            &db,
            &expired.id,
            "expires_at",
            "2020-01-01T00:00:00.000000+00:00",
        )
        .await;

        let active = backend.active_session_ids(&id).await.unwrap();
        assert_eq!(active, [live.id.clone()].into_iter().collect());
        assert!(backend.is_session_active(&id, &live.id).await.unwrap());
        assert!(!backend.is_session_active(&id, &revoked.id).await.unwrap());
        assert!(!backend.is_session_active(&id, &expired.id).await.unwrap());
        assert!(!backend.is_session_active("other", &live.id).await.unwrap());

        let all = backend.list_identity_sessions(&id).await.unwrap();
        assert_eq!(all.len(), 3);
        let flags: HashMap<String, bool> = all
            .iter()
            .map(|s| (s.id.clone(), s.active.unwrap()))
            .collect();
        assert!(flags[&live.id]);
        assert!(!flags[&revoked.id]);
        assert!(!flags[&expired.id]);
        assert!(all.iter().all(|s| s.identity.is_none()));
        assert_eq!(backend.list_identity_sessions_all(&id).await.unwrap(), all);
    }

    #[tokio::test]
    async fn admin_get_and_revoke() {
        let (db, backend) = setup().await;
        let id = identity(&db, "g@x.test").await;
        let issued = sign_in(&backend, &id).await;
        let s = backend.admin_get_session(&issued.id).await.unwrap();
        assert_eq!(s.identity.map(|i| i.id), Some(id));
        assert!(backend.admin_get_session("missing").await.is_err());
        assert!(backend.admin_revoke_session("missing").await.is_err());
        backend.admin_revoke_session(&issued.id).await.unwrap();
        backend.admin_revoke_session(&issued.id).await.unwrap();
        let s = backend.admin_get_session(&issued.id).await.unwrap();
        assert_eq!(s.active, Some(false));
    }

    #[tokio::test]
    async fn admin_list_pages_by_issued_at_then_id() {
        let (db, backend) = setup().await;
        let first = identity(&db, "x1@x.test").await;
        let second = identity(&db, "x2@x.test").await;
        add_credential(&db, &first, "password").await;
        let mut tied = Vec::new();
        for owner in [&first, &second, &first] {
            let s = sign_in(&backend, owner).await;
            set_column(&db, &s.id, "issued_at", "2026-01-01T00:00:00.000000+00:00").await;
            tied.push(s.id);
        }
        tied.sort();
        tied.reverse();
        let newest = sign_in(&backend, &second).await;
        set_column(
            &db,
            &newest.id,
            "issued_at",
            "2026-01-02T00:00:00.000000+00:00",
        )
        .await;
        revoke(&db, &newest.id, None).await.unwrap();
        let mut expected = vec![newest.id.clone()];
        expected.extend(tied.clone());

        let mut seen = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = backend
                .admin_list_all_sessions(2, token.as_deref(), None)
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            for s in &page {
                let identity = s.identity.as_ref().expect("identity expanded");
                let creds = identity.credentials.as_ref();
                assert_eq!(
                    identity.id == first,
                    creds.is_some_and(|c| c.contains_key("password"))
                );
            }
            seen.extend(page.iter().map(|s| s.id.clone()));
            token = page.last().map(|s| s.id.clone());
        }
        assert_eq!(seen, expected);

        let active: Vec<String> = backend
            .admin_list_all_sessions(10, None, Some(true))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(active, tied);
        let inactive: Vec<String> = backend
            .admin_list_all_sessions(10, None, Some(false))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(inactive, [newest.id]);
        assert!(
            backend
                .admin_list_all_sessions(10, Some("missing"), None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn logout_token_is_bound_to_the_live_session() {
        let (db, backend) = setup().await;
        let id = identity(&db, "lo@x.test").await;
        let mine = sign_in(&backend, &id).await;
        let other = sign_in(&backend, &id).await;
        let me = cookie(&mine.token);

        assert_eq!(backend.fetch_logout_url("").await.unwrap(), None);
        assert_eq!(
            backend
                .fetch_logout_url("forseti_session=nope")
                .await
                .unwrap(),
            None
        );
        let url = backend.fetch_logout_url(&me).await.unwrap().unwrap();
        let token = url
            .strip_prefix("/self-service/logout?token=")
            .expect("relative logout URL");
        assert_eq!(token, logout_token(&backend.keys.logout, &mine.id));

        let verified = backend.verify_logout(&me, token).await.unwrap();
        assert_eq!(verified.map(|s| s.id), Some(mine.id.clone()));
        let other_token = logout_token(&backend.keys.logout, &other.id);
        assert!(
            backend
                .verify_logout(&me, &other_token)
                .await
                .unwrap()
                .is_none()
        );
        assert!(backend.verify_logout(&me, "").await.unwrap().is_none());
        assert!(backend.verify_logout("", token).await.unwrap().is_none());
        let foreign_key = MacKey::new([9; 32]);
        assert!(
            backend
                .verify_logout(&me, &logout_token(&foreign_key, &mine.id))
                .await
                .unwrap()
                .is_none()
        );

        revoke(&db, &mine.id, None).await.unwrap();
        assert!(backend.verify_logout(&me, token).await.unwrap().is_none());
        assert_eq!(backend.fetch_logout_url(&me).await.unwrap(), None);
    }

    #[tokio::test]
    async fn tear_down_revokes_the_cookie_session() {
        let (db, backend) = setup().await;
        let id = identity(&db, "td@x.test").await;
        let issued = sign_in(&backend, &id).await;
        backend.tear_down_session("").await;
        backend.tear_down_session(&cookie(&issued.token)).await;
        assert!(matches!(
            whoami(&backend, &issued.token).await,
            WhoamiOutcome::None
        ));
        assert!(!revoke_by_token(&db, &issued.token).await.unwrap());
    }

    #[tokio::test]
    async fn cleanup_deletes_only_rows_dead_for_30_days() {
        let (db, backend) = setup().await;
        let id = identity(&db, "cl@x.test").await;
        let live = sign_in(&backend, &id).await;
        let recently_revoked = sign_in(&backend, &id).await;
        revoke(&db, &recently_revoked.id, None).await.unwrap();
        let old_revoked = sign_in(&backend, &id).await;
        set_column(
            &db,
            &old_revoked.id,
            "revoked_at",
            "2020-01-01T00:00:00.000000+00:00",
        )
        .await;
        let recently_expired = sign_in(&backend, &id).await;
        let yesterday = crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::days(1));
        set_column(&db, &recently_expired.id, "expires_at", &yesterday).await;
        let old_expired = sign_in(&backend, &id).await;
        set_column(
            &db,
            &old_expired.id,
            "expires_at",
            "2020-01-01T00:00:00.000000+00:00",
        )
        .await;

        assert_eq!(delete_stale(&db).await.unwrap(), 2);
        let mut left: Vec<String> = list_for_identity(&db, &id, None)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        left.sort();
        let mut expected = vec![live.id, recently_revoked.id, recently_expired.id];
        expected.sort();
        assert_eq!(left, expected);
    }

    #[tokio::test]
    async fn user_agent_is_capped() {
        let (db, backend) = setup().await;
        let id = identity(&db, "ua@x.test").await;
        let long = "x".repeat(600);
        let issued = backend
            .issue_session(
                &id,
                "password",
                Aal::Aal1,
                Device {
                    ip: None,
                    user_agent: Some(&long),
                },
            )
            .await
            .unwrap();
        let s = session_of(whoami(&backend, &issued.token).await);
        let device = &s.devices.unwrap()[0];
        assert_eq!(device.user_agent.as_deref().map(str::len), Some(512));
        assert_eq!(device.ip_address, None);
        assert_eq!(
            backend.session_set_cookie(&issued.token),
            format!(
                "forseti_session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400",
                issued.token
            )
        );
    }
}
