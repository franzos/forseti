//! Authorization requests in `oauth_authorize_requests`: the login and consent challenges, the
//! resume verifier, the flow-binding cookie and the state machine between them.
//!
//! Every transition is a conditional `UPDATE ... WHERE state = <expected>`; its row count decides
//! the outcome, so of two concurrent accepts or resumes exactly one wins on either backend.

use anyhow::Result;
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::authorize::{AuthorizeRequest, Delivery, ResponseMode};
use super::grants::{self, CodeFor, GrantRow};
use super::response::Navigation;
use super::sessions::{self, LoginSession, SessionRow};
use super::{FLOW_TTL_SECS, NativeOAuth, clients, from_json, random_token, to_json, token_hash};
use crate::backend::oauth::{ConsentRequest, LoginRequest, OidcContext, RedirectTo};
use crate::db::{DbPool, rfc3339};
use crate::oauth::consent::GrantPath;
use crate::schema::{
    oauth_authorization_codes, oauth_authorize_requests, oauth_consent_grants, oauth_device_codes,
    oauth_login_sessions,
};
use crate::signed_cookie::{SignedCookie, unix_seconds_now};
use crate::{db_interact, serialized_txn};

/// The resume route; `{flow_id}` scopes the binding cookie to one request.
pub(super) const RESUME_ROUTE: &str = "/oauth2/auth/resume/{flow_id}";

const LOGIN: &str = "login";
const LOGIN_ACCEPTED: &str = "login_accepted";
const CONSENT: &str = "consent";
const CONSENT_ACCEPTED: &str = "consent_accepted";
const REJECTED: &str = "rejected";
const DONE: &str = "done";

const QUERY: &str = "query";
const FORM_POST: &str = "form_post";
/// The request of an accepted device user code; its result goes to the device row, not a client.
const DEVICE: &str = "device";

/// Where a finished device request sends the browser.
const DEVICE_DONE_PATH: &str = "/oauth/device/done";

/// Hydra's ceiling on the audience a client record may carry.
const MAX_GRANT_AUDIENCE: usize = 20;

const BINDING_COOKIE: &str = "forseti_flow";
const BINDING_COOKIE_LABEL: &[u8] = b"forseti::oauth::flow-binding::v1";

/// Why a challenge or verifier call was refused. Every variant leaves the request unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeError {
    /// No such challenge or verifier, or its request expired.
    Unknown,
    /// The challenge or verifier was already used.
    Used,
    /// The request was started in another browser.
    Unbound,
    EmptySubject,
    /// A remembered login accepted for another subject.
    SubjectMismatch,
    /// The `sid` belongs to another subject.
    SidTaken,
    /// The remembered login session ended during the request.
    SessionGone,
    ScopeNotRequested,
    OpenidRequired,
    AudienceTooLarge,
    /// A device request accepted without the consent screen.
    ConsentRequired,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "oauth challenge not found or expired",
            Self::Used => "oauth challenge already used",
            Self::Unbound => "oauth request belongs to another browser",
            Self::EmptySubject => "oauth login accepted without a subject",
            Self::SubjectMismatch => "remembered oauth login accepted for another subject",
            Self::SidTaken => "oauth login session belongs to another subject",
            Self::SessionGone => "remembered oauth login session ended",
            Self::ScopeNotRequested => "granted scope was not requested",
            Self::OpenidRequired => "requested openid scope was not granted",
            Self::AudienceTooLarge => "granted audience exceeds 20 entries",
            Self::ConsentRequired => "a device authorization needs the user's consent",
        })
    }
}

impl std::error::Error for ChallengeError {}

/// A transaction that stops on a refusal rolls back.
enum Abort {
    Refused(ChallengeError),
    Db(DieselError),
}

impl From<DieselError> for Abort {
    fn from(e: DieselError) -> Self {
        Self::Db(e)
    }
}

fn settle<T>(r: Result<T, Abort>) -> Result<T> {
    r.map_err(|e| match e {
        Abort::Refused(e) => e.into(),
        Abort::Db(e) => e.into(),
    })
}

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = oauth_authorize_requests)]
struct FlowRow {
    id: String,
    client_id: String,
    login_challenge_hash: String,
    consent_challenge_hash: Option<String>,
    verifier_hash: Option<String>,
    state: String,
    request_url: String,
    redirect_uri: String,
    response_mode: String,
    oauth_state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    requested_scope: String,
    requested_audience: String,
    /// RFC 8707 `resource` values; only the consent-skip check reads them.
    requested_resource: String,
    oidc_context: String,
    session_id: String,
    skip_login: i32,
    subject: Option<String>,
    skip_consent: Option<i32>,
    login_result: Option<String>,
    consent_result: Option<String>,
    error: Option<String>,
    created_at: String,
    expires_at: String,
}

impl FlowRow {
    fn is_device(&self) -> bool {
        self.response_mode == DEVICE
    }

    fn delivery(&self) -> Delivery {
        Delivery {
            redirect_uri: self.redirect_uri.clone(),
            mode: if self.response_mode == FORM_POST {
                ResponseMode::FormPost
            } else {
                ResponseMode::Query
            },
            state: self.oauth_state.clone(),
        }
    }

    fn oidc_context(&self) -> Result<OidcContext> {
        let s: StoredOidcContext = from_json(&self.oidc_context)?;
        Ok(OidcContext {
            acr_values: s.acr_values,
            login_hint: s.login_hint,
            ui_locales: s.ui_locales,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct StoredOidcContext {
    acr_values: Option<Vec<String>>,
    login_hint: Option<String>,
    ui_locales: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct LoginResult {
    remember: bool,
    /// The remember window in seconds, already capped.
    remember_for: i64,
    acr: Option<String>,
    amr: Vec<String>,
    auth_time: String,
}

#[derive(Serialize, Deserialize)]
struct ConsentResult {
    grant_scope: Vec<String>,
    grant_audience: Vec<String>,
    remember: bool,
}

#[derive(Serialize, Deserialize)]
struct FlowError {
    error: String,
    error_description: String,
}

/// Where a resumed request goes next.
#[derive(Debug)]
pub(super) enum Resumed {
    /// On to the consent handler. A fresh remembered login also sets `forseti_op`.
    Consent {
        challenge: String,
        remembered: Option<(String, i64)>,
    },
    Code {
        flow_id: String,
        delivery: Delivery,
        code: String,
    },
    Error {
        flow_id: String,
        delivery: Delivery,
        error: String,
        description: String,
        nav: Navigation,
    },
    /// A device request ended; the browser goes to [`device_done_url`].
    Device { approved: bool },
}

/// The page a finished device request shows, on `issuer`.
pub(super) fn device_done_url(issuer: &str, approved: bool) -> String {
    if approved {
        format!("{issuer}{DEVICE_DONE_PATH}")
    } else {
        format!("{issuer}{DEVICE_DONE_PATH}?error=1")
    }
}

/// The path of the resume route for the request `flow_id`.
pub(super) fn resume_path(flow_id: &str) -> String {
    RESUME_ROUTE.replace("{flow_id}", flow_id)
}

// The codec's MAC covers the cookie path, so the per-flow path binds the value to its flow.
fn binding_cookie(path: &str, secure: bool) -> SignedCookie<'_> {
    SignedCookie {
        name: BINDING_COOKIE,
        salt: BINDING_COOKIE_LABEL,
        ttl_secs: FLOW_TTL_SECS.unsigned_abs(),
        secure,
        path,
    }
}

/// The `Set-Cookie` that binds the request `flow_id` to this browser for the request's lifetime.
pub(super) fn bind(secret: &[u8], flow_id: &str, secure: bool) -> String {
    let path = resume_path(flow_id);
    let codec = binding_cookie(&path, secure);
    let value = codec.encode(secret, &[], unix_seconds_now());
    format!("{}; Max-Age={FLOW_TTL_SECS}", codec.set_header(&value))
}

/// Whether this browser holds a valid binding for `flow_id`. Any one of several same-named
/// cookies (another domain or path can add one) is enough.
pub(super) fn is_bound(secret: &[u8], headers: &HeaderMap, flow_id: &str) -> bool {
    let path = resume_path(flow_id);
    let codec = binding_cookie(&path, false);
    let now = unix_seconds_now();
    axum_extra::extract::cookie::Cookie::split_parse(crate::cookies::cookie_header(headers))
        .filter_map(Result::ok)
        .filter(|c| c.name() == BINDING_COOKIE)
        .any(|c| codec.verify(secret, c.value(), now).is_some())
}

/// The `Set-Cookie` that clears the binding of `flow_id`.
pub(super) fn unbind(flow_id: &str, secure: bool) -> String {
    binding_cookie(&resume_path(flow_id), secure).clear_header()
}

fn resume_url(issuer: &str, flow_id: &str, verifier: &str) -> String {
    format!(
        "{issuer}{}?verifier={}",
        resume_path(flow_id),
        crate::web::urlencode(verifier)
    )
}

/// Stores a validated request; `remembered` is the login session it skips under. Returns the
/// request id and its login challenge.
pub(super) async fn create(
    db: &DbPool,
    req: &AuthorizeRequest,
    request_url: String,
    remembered: Option<&LoginSession>,
) -> Result<(String, String)> {
    let now = Utc::now();
    let challenge = random_token();
    let oidc = req.oidc_context();
    let row = FlowRow {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: req.client_id.clone(),
        login_challenge_hash: token_hash(&challenge),
        consent_challenge_hash: None,
        verifier_hash: None,
        state: LOGIN.to_string(),
        request_url,
        redirect_uri: req.delivery.redirect_uri.clone(),
        response_mode: match req.delivery.mode {
            ResponseMode::Query => QUERY,
            ResponseMode::FormPost => FORM_POST,
        }
        .to_string(),
        oauth_state: req.delivery.state.clone(),
        nonce: req.nonce.clone(),
        code_challenge: req.code_challenge.clone(),
        requested_scope: to_json(&req.scope)?,
        requested_audience: to_json(&req.audience)?,
        requested_resource: to_json(&req.resource)?,
        oidc_context: to_json(&StoredOidcContext {
            acr_values: oidc.acr_values,
            login_hint: oidc.login_hint,
            ui_locales: oidc.ui_locales,
        })?,
        session_id: remembered.map_or_else(|| uuid::Uuid::new_v4().to_string(), |s| s.sid.clone()),
        skip_login: i32::from(remembered.is_some()),
        subject: remembered.map(|s| s.subject.clone()),
        skip_consent: None,
        login_result: None,
        consent_result: None,
        error: None,
        created_at: rfc3339(now),
        expires_at: rfc3339(now + chrono::Duration::seconds(FLOW_TTL_SECS)),
    };
    let id = row.id.clone();
    let now = rfc3339(now);
    db_interact!(db, |c| {
        diesel::delete(
            oauth_authorize_requests::table.filter(oauth_authorize_requests::expires_at.le(now)),
        )
        .execute(c)?;
        diesel::insert_into(oauth_authorize_requests::table)
            .values(&row)
            .execute(c)
    })?;
    Ok((id, challenge))
}

/// Moves the pending, unexpired device authorization with the stored-form `user_code` to
/// `accepted` and stores its authorization request, in one transaction: the flow expires with the
/// device code, has no redirect URI and never skips the login. Returns the login handler's URL.
pub(super) async fn accept_user_code(oauth: &NativeOAuth, user_code: &str) -> Result<RedirectTo> {
    use super::device::{ACCEPTED, PENDING};
    let now = Utc::now();
    let challenge = random_token();
    let template = FlowRow {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: String::new(),
        login_challenge_hash: token_hash(&challenge),
        consent_challenge_hash: None,
        verifier_hash: None,
        state: LOGIN.to_string(),
        request_url: format!("{}/oauth/device", oauth.issuer),
        redirect_uri: String::new(),
        response_mode: DEVICE.to_string(),
        oauth_state: None,
        nonce: None,
        code_challenge: None,
        requested_scope: String::new(),
        requested_audience: "[]".to_string(),
        requested_resource: "[]".to_string(),
        oidc_context: to_json(&StoredOidcContext {
            acr_values: None,
            login_hint: None,
            ui_locales: None,
        })?,
        session_id: uuid::Uuid::new_v4().to_string(),
        skip_login: 0,
        subject: None,
        skip_consent: None,
        login_result: None,
        consent_result: None,
        error: None,
        created_at: rfc3339(now),
        expires_at: rfc3339(now + chrono::Duration::seconds(FLOW_TTL_SECS)),
    };
    let (user_code, now) = (user_code.to_string(), rfc3339(now));
    settle(serialized_txn!(oauth.db, (), Abort, |c| {
        let device: Option<(String, String, String, String)> = oauth_device_codes::table
            .filter(oauth_device_codes::user_code.eq(&user_code))
            .filter(oauth_device_codes::status.eq(PENDING))
            .filter(oauth_device_codes::expires_at.gt(&now))
            .select((
                oauth_device_codes::device_code_hash,
                oauth_device_codes::client_id,
                oauth_device_codes::scope,
                oauth_device_codes::expires_at,
            ))
            .first(c)
            .optional()?;
        let Some((hash, client_id, scope, device_expires_at)) = device else {
            return Err(Abort::Refused(ChallengeError::Unknown));
        };
        let moved = diesel::update(
            oauth_device_codes::table
                .filter(oauth_device_codes::device_code_hash.eq(&hash))
                .filter(oauth_device_codes::status.eq(PENDING))
                .filter(oauth_device_codes::expires_at.gt(&now)),
        )
        .set((
            oauth_device_codes::status.eq(ACCEPTED),
            oauth_device_codes::flow_id.eq(Some(&template.id)),
        ))
        .execute(c)?;
        if moved == 0 {
            return Err(Abort::Refused(ChallengeError::Used));
        }
        diesel::delete(
            oauth_authorize_requests::table.filter(oauth_authorize_requests::expires_at.le(&now)),
        )
        .execute(c)?;
        let row = FlowRow {
            client_id,
            requested_scope: scope,
            expires_at: std::cmp::min(template.expires_at.clone(), device_expires_at),
            ..template.clone()
        };
        diesel::insert_into(oauth_authorize_requests::table)
            .values(&row)
            .execute(c)?;
        Ok(())
    }))?;
    Ok(RedirectTo {
        redirect_to: format!(
            "{}/oauth/login?login_challenge={}",
            oauth.issuer,
            crate::web::urlencode(&challenge)
        ),
    })
}

enum Lookup {
    Login(String),
    Consent(String),
    Verifier(String),
}

async fn find(db: &DbPool, by: Lookup) -> Result<Option<FlowRow>> {
    Ok(db_interact!(db, |c| {
        let q = oauth_authorize_requests::table
            .select(FlowRow::as_select())
            .into_boxed();
        let q = match by {
            Lookup::Login(h) => q.filter(oauth_authorize_requests::login_challenge_hash.eq(h)),
            Lookup::Consent(h) => q.filter(oauth_authorize_requests::consent_challenge_hash.eq(h)),
            Lookup::Verifier(h) => q.filter(oauth_authorize_requests::verifier_hash.eq(h)),
        };
        q.first(c).optional()
    })?)
}

fn is_live(row: &FlowRow, now: DateTime<Utc>) -> bool {
    row.expires_at > rfc3339(now)
}

/// The unexpired request whose challenge is in `state`.
async fn pending(db: &DbPool, by: Lookup, state: &str) -> Result<FlowRow> {
    match find(db, by).await? {
        Some(row) if !is_live(&row, Utc::now()) => Err(ChallengeError::Unknown.into()),
        Some(row) if row.state == state => Ok(row),
        Some(_) => Err(ChallengeError::Used.into()),
        None => Err(ChallengeError::Unknown.into()),
    }
}

pub(super) async fn get_login_request(db: &DbPool, challenge: &str) -> Result<LoginRequest> {
    let row = pending(db, Lookup::Login(token_hash(challenge)), LOGIN).await?;
    let client = clients::get(db, &row.client_id)
        .await?
        .ok_or(ChallengeError::Unknown)?;
    Ok(LoginRequest {
        client,
        oidc_context: Some(row.oidc_context()?),
        request_url: row.request_url.clone(),
        requested_scope: Some(from_json(&row.requested_scope)?),
        session_id: Some(row.session_id.clone()),
        skip: row.skip_login != 0,
        subject: row.subject.clone().unwrap_or_default(),
    })
}

pub(super) async fn accept_login(
    oauth: &NativeOAuth,
    challenge: &str,
    subject: &str,
    remember: bool,
    remember_for: i64,
    amr: Vec<String>,
    acr: Option<String>,
) -> Result<RedirectTo> {
    let db = &oauth.db;
    let row = pending(db, Lookup::Login(token_hash(challenge)), LOGIN).await?;
    let flow_id = row.id.clone();
    if subject.is_empty() {
        return Err(ChallengeError::EmptySubject.into());
    }
    let now = Utc::now();
    let skipped = row.skip_login != 0;
    let auth_time = if skipped {
        if row.subject.as_deref() != Some(subject) {
            return Err(ChallengeError::SubjectMismatch.into());
        }
        sessions::find(db, &row.session_id)
            .await?
            .filter(|s| s.subject == subject && s.expires_at > now)
            .ok_or(ChallengeError::SessionGone)?
            .auth_time
    } else {
        now
    };
    let window = sessions::remember_window(remember_for);
    let amr_json = to_json(&amr)?;
    let result = to_json(&LoginResult {
        remember,
        remember_for: window,
        acr: acr.clone(),
        amr,
        auth_time: rfc3339(auth_time),
    })?;
    let session = (!skipped).then(|| SessionRow {
        sid: row.session_id.clone(),
        subject: subject.to_string(),
        auth_time: rfc3339(now),
        acr,
        amr: amr_json,
        remember: i32::from(remember),
        created_at: rfc3339(now),
        expires_at: rfc3339(now + chrono::Duration::seconds(window)),
    });
    let verifier = random_token();
    let (id, verifier_hash, subject, now) = (
        row.id,
        token_hash(&verifier),
        subject.to_string(),
        rfc3339(now),
    );
    settle(serialized_txn!(db, (), Abort, |c| {
        let moved = diesel::update(
            oauth_authorize_requests::table
                .filter(oauth_authorize_requests::id.eq(&id))
                .filter(oauth_authorize_requests::state.eq(LOGIN))
                .filter(oauth_authorize_requests::expires_at.gt(&now)),
        )
        .set((
            oauth_authorize_requests::state.eq(LOGIN_ACCEPTED),
            oauth_authorize_requests::subject.eq(Some(&subject)),
            oauth_authorize_requests::login_result.eq(Some(&result)),
            oauth_authorize_requests::verifier_hash.eq(Some(&verifier_hash)),
        ))
        .execute(c)?;
        if moved == 0 {
            return Err(Abort::Refused(ChallengeError::Used));
        }
        if let Some(session) = &session {
            diesel::delete(
                oauth_login_sessions::table.filter(oauth_login_sessions::expires_at.le(&now)),
            )
            .execute(c)?;
            diesel::insert_into(oauth_login_sessions::table)
                .values(session)
                .on_conflict(oauth_login_sessions::sid)
                .do_nothing()
                .execute(c)?;
            let owner: String = oauth_login_sessions::table
                .find(&session.sid)
                .select(oauth_login_sessions::subject)
                .first(c)?;
            if owner != subject {
                return Err(Abort::Refused(ChallengeError::SidTaken));
            }
        }
        Ok(())
    }))?;
    Ok(RedirectTo {
        redirect_to: resume_url(&oauth.issuer, &flow_id, &verifier),
    })
}

/// Moves the request with challenge `by`, in `from`, to `rejected` with the handler's error.
async fn reject(
    oauth: &NativeOAuth,
    by: Lookup,
    from: &'static str,
    error: &str,
    error_description: &str,
) -> Result<RedirectTo> {
    let db = &oauth.db;
    let row = pending(db, by, from).await?;
    let flow_id = row.id.clone();
    let stored = to_json(&FlowError {
        error: error.to_string(),
        error_description: error_description.to_string(),
    })?;
    let verifier = random_token();
    let (id, verifier_hash, now) = (row.id, token_hash(&verifier), rfc3339(Utc::now()));
    let moved = db_interact!(db, |c| {
        diesel::update(
            oauth_authorize_requests::table
                .filter(oauth_authorize_requests::id.eq(id))
                .filter(oauth_authorize_requests::state.eq(from))
                .filter(oauth_authorize_requests::expires_at.gt(now)),
        )
        .set((
            oauth_authorize_requests::state.eq(REJECTED),
            oauth_authorize_requests::error.eq(Some(stored)),
            oauth_authorize_requests::verifier_hash.eq(Some(verifier_hash)),
        ))
        .execute(c)
    })?;
    if moved == 0 {
        return Err(ChallengeError::Used.into());
    }
    Ok(RedirectTo {
        redirect_to: resume_url(&oauth.issuer, &flow_id, &verifier),
    })
}

pub(super) async fn reject_login(
    oauth: &NativeOAuth,
    challenge: &str,
    error: &str,
    error_description: &str,
) -> Result<RedirectTo> {
    let by = Lookup::Login(token_hash(challenge));
    reject(oauth, by, LOGIN, error, error_description).await
}

pub(super) async fn get_consent_request(db: &DbPool, challenge: &str) -> Result<ConsentRequest> {
    let row = pending(db, Lookup::Consent(token_hash(challenge)), CONSENT).await?;
    let mut client = clients::get(db, &row.client_id)
        .await?
        .ok_or(ChallengeError::Unknown)?;
    // RFC 8628 section 5.4: the user sees what a device request authorizes, so the client's
    // `skip_consent` cannot take the handler's no-screen path.
    if row.is_device() {
        client.skip_consent = Some(false);
    }
    Ok(ConsentRequest {
        client: Some(client),
        consent_request_id: Some(row.id.clone()),
        login_session_id: Some(row.session_id.clone()),
        oidc_context: Some(row.oidc_context()?),
        request_url: Some(row.request_url.clone()),
        requested_access_token_audience: Some(from_json(&row.requested_audience)?),
        requested_scope: Some(from_json(&row.requested_scope)?),
        skip: Some(row.skip_consent.unwrap_or(0) != 0),
        subject: row.subject.clone(),
    })
}

/// `grant_scope` within the request, `openid` kept when requested, at most 20 audiences. Order
/// is kept; repeats go.
fn checked_grant(
    requested: &[String],
    grant_scope: Vec<String>,
    grant_audience: Vec<String>,
) -> Result<(Vec<String>, Vec<String>), ChallengeError> {
    let dedup = |items: Vec<String>| {
        let mut out: Vec<String> = Vec::with_capacity(items.len());
        for item in items {
            if !out.contains(&item) {
                out.push(item);
            }
        }
        out
    };
    let (scope, audience) = (dedup(grant_scope), dedup(grant_audience));
    if !scope.iter().all(|s| requested.contains(s)) {
        return Err(ChallengeError::ScopeNotRequested);
    }
    if requested.iter().any(|s| s == "openid") && !scope.iter().any(|s| s == "openid") {
        return Err(ChallengeError::OpenidRequired);
    }
    if audience.len() > MAX_GRANT_AUDIENCE {
        return Err(ChallengeError::AudienceTooLarge);
    }
    Ok((scope, audience))
}

pub(super) async fn accept_consent(
    oauth: &NativeOAuth,
    challenge: &str,
    grant_scope: Vec<String>,
    grant_audience: Vec<String>,
    path: GrantPath,
    id_token_session: Value,
    access_token_session: Map<String, Value>,
) -> Result<RedirectTo> {
    let db = &oauth.db;
    let row = pending(db, Lookup::Consent(token_hash(challenge)), CONSENT).await?;
    if row.is_device() && path == GrantPath::Auto {
        return Err(ChallengeError::ConsentRequired.into());
    }
    let flow_id = row.id.clone();
    let requested: Vec<String> = from_json(&row.requested_scope)?;
    let (scope, audience) = checked_grant(&requested, grant_scope, grant_audience)?;
    let remember = path.remember();
    let skipped = row.skip_consent.unwrap_or(0);
    // An automatic accept of a request reported as skipped builds on an earlier grant.
    let auto_granted = skipped == 0 && path == GrantPath::Auto;
    let now = rfc3339(Utc::now());
    let grant = GrantRow {
        id: row.id.clone(),
        client_id: row.client_id.clone(),
        subject: row.subject.clone().ok_or(ChallengeError::EmptySubject)?,
        session_id: row.session_id.clone(),
        scope: to_json(&scope)?,
        audience: to_json(&audience)?,
        id_token_claims: to_json(&id_token_session)?,
        access_token_claims: to_json(&access_token_session)?,
        remember: i32::from(remember),
        skipped,
        handled_at: now.clone(),
        auto_granted: i32::from(auto_granted),
        tokens_revoked_at: None,
    };
    let result = to_json(&ConsentResult {
        grant_scope: scope,
        grant_audience: audience,
        remember,
    })?;
    let verifier = random_token();
    let (id, verifier_hash) = (row.id, token_hash(&verifier));
    settle(serialized_txn!(db, (), Abort, |c| {
        let moved = diesel::update(
            oauth_authorize_requests::table
                .filter(oauth_authorize_requests::id.eq(&id))
                .filter(oauth_authorize_requests::state.eq(CONSENT))
                .filter(oauth_authorize_requests::expires_at.gt(&now)),
        )
        .set((
            oauth_authorize_requests::state.eq(CONSENT_ACCEPTED),
            oauth_authorize_requests::consent_result.eq(Some(&result)),
            oauth_authorize_requests::verifier_hash.eq(Some(&verifier_hash)),
        ))
        .execute(c)?;
        if moved == 0 {
            return Err(Abort::Refused(ChallengeError::Used));
        }
        diesel::insert_into(oauth_consent_grants::table)
            .values(&grant)
            .execute(c)
            .map_err(|e| match e {
                DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                    Abort::Refused(ChallengeError::Used)
                }
                other => Abort::Db(other),
            })?;
        Ok(())
    }))?;
    Ok(RedirectTo {
        redirect_to: resume_url(&oauth.issuer, &flow_id, &verifier),
    })
}

pub(super) async fn reject_consent(
    oauth: &NativeOAuth,
    challenge: &str,
    error: &str,
    error_description: &str,
) -> Result<RedirectTo> {
    let by = Lookup::Consent(token_hash(challenge));
    reject(oauth, by, CONSENT, error, error_description).await
}

/// Consumes `verifier` once, for the request `flow_id` (the resume path's) when `is_bound`
/// accepts its id. A refusal consumes nothing: an unbound verifier stays usable by the browser
/// that holds the binding. A stored device request is not asked about: it has no binding.
pub(super) async fn resume(
    db: &DbPool,
    flow_id: &str,
    verifier: &str,
    is_bound: impl FnOnce(&str) -> bool,
) -> Result<Resumed> {
    let verifier_hash = token_hash(verifier);
    let row = find(db, Lookup::Verifier(verifier_hash.clone()))
        .await?
        .ok_or(ChallengeError::Unknown)?;
    // The browser sent the binding of the path's flow, which proves nothing for another one.
    if row.id != flow_id || (!row.is_device() && !is_bound(&row.id)) {
        return Err(ChallengeError::Unbound.into());
    }
    let now = Utc::now();
    if !is_live(&row, now) {
        return Err(ChallengeError::Unknown.into());
    }
    match (row.state.as_str(), row.is_device()) {
        (LOGIN_ACCEPTED, _) => to_consent(db, row, verifier_hash).await,
        (CONSENT_ACCEPTED, false) => issue_code(db, row, verifier_hash, now).await,
        (CONSENT_ACCEPTED, true) => approve_device(db, row, verifier_hash, now).await,
        (REJECTED, false) => deliver_rejection(db, row, verifier_hash).await,
        (REJECTED, true) => deny_device(db, row, verifier_hash).await,
        _ => Err(ChallengeError::Used.into()),
    }
}

/// Consumes the verifier and moves the unexpired `row` from `from` to `to`, with `extra` set
/// alongside.
macro_rules! consume {
    ($c:ident, $row:expr, $verifier_hash:expr, $from:expr, $to:expr $(, $extra:expr)*) => {
        diesel::update(
            oauth_authorize_requests::table
                .filter(oauth_authorize_requests::id.eq(&$row.id))
                .filter(oauth_authorize_requests::verifier_hash.eq(&$verifier_hash))
                .filter(oauth_authorize_requests::state.eq($from))
                .filter(oauth_authorize_requests::expires_at.gt(crate::db::now_rfc3339())),
        )
        .set((
            oauth_authorize_requests::verifier_hash.eq(None::<String>),
            oauth_authorize_requests::state.eq($to),
            $($extra,)*
        ))
        .execute($c)
    };
}

async fn to_consent(db: &DbPool, row: FlowRow, verifier_hash: String) -> Result<Resumed> {
    let client = clients::get(db, &row.client_id)
        .await?
        .ok_or(ChallengeError::Unknown)?;
    let login: LoginResult = from_json(row.login_result.as_deref().unwrap_or("null"))?;
    let subject = row.subject.clone().ok_or(ChallengeError::EmptySubject)?;
    let prompt_consent = crate::oauth::login::request_url_param(&row.request_url, "prompt")
        .is_some_and(|p| p.split(' ').any(|v| v == "consent"));
    let mut required_audience: Vec<String> = from_json(&row.requested_audience)?;
    required_audience.extend(from_json::<Vec<String>>(&row.requested_resource)?);
    let skip = !row.is_device()
        && grants::consent_skip(
            db,
            &subject,
            &client,
            &row.redirect_uri,
            &from_json::<Vec<String>>(&row.requested_scope)?,
            &required_audience,
            prompt_consent,
        )
        .await?;
    let challenge = random_token();
    let challenge_hash = token_hash(&challenge);
    let moved = {
        let row = row.clone();
        db_interact!(db, |c| {
            consume!(
                c,
                row,
                verifier_hash,
                LOGIN_ACCEPTED,
                CONSENT,
                oauth_authorize_requests::consent_challenge_hash.eq(Some(&challenge_hash)),
                oauth_authorize_requests::skip_consent.eq(Some(i32::from(skip)))
            )
        })?
    };
    if moved == 0 {
        return Err(ChallengeError::Used.into());
    }
    // The browser holding a device request's verifier gets no cookie for the approver's session.
    let remembered = (login.remember && row.skip_login == 0 && !row.is_device())
        .then_some((row.session_id, login.remember_for));
    Ok(Resumed::Consent {
        challenge,
        remembered,
    })
}

async fn issue_code(
    db: &DbPool,
    row: FlowRow,
    verifier_hash: String,
    now: DateTime<Utc>,
) -> Result<Resumed> {
    let login: LoginResult = from_json(row.login_result.as_deref().unwrap_or("null"))?;
    let amr = to_json(&login.amr)?;
    let delivery = row.delivery();
    let flow_id = row.id.clone();
    let code = settle(serialized_txn!(db, Option<String>, Abort, |c| {
        if consume!(c, row, verifier_hash, CONSENT_ACCEPTED, DONE)? == 0 {
            return Err(Abort::Refused(ChallengeError::Used));
        }
        let Some(grant) = oauth_consent_grants::table
            .find(&row.id)
            .select(GrantRow::as_select())
            .first(c)
            .optional()?
        else {
            return Ok(None);
        };
        let (code, new_row) = grants::new_code(
            &CodeFor {
                grant: &grant,
                redirect_uri: &row.redirect_uri,
                code_challenge: row.code_challenge.as_deref(),
                nonce: row.nonce.as_deref(),
                auth_time: &login.auth_time,
                acr: login.acr.as_deref(),
                amr: &amr,
            },
            now,
        );
        diesel::insert_into(crate::schema::oauth_authorization_codes::table)
            .values(&new_row)
            .execute(c)?;
        Ok(Some(code))
    }))?;
    Ok(match code {
        Some(code) => Resumed::Code {
            flow_id,
            delivery,
            code,
        },
        None => Resumed::Error {
            flow_id,
            delivery,
            error: "access_denied".to_string(),
            description: "The consent was revoked.".to_string(),
            nav: Navigation::Redirect,
        },
    })
}

async fn deliver_rejection(db: &DbPool, row: FlowRow, verifier_hash: String) -> Result<Resumed> {
    let stored: FlowError = from_json(row.error.as_deref().unwrap_or("null"))?;
    let moved = {
        let row = row.clone();
        db_interact!(db, |c| { consume!(c, row, verifier_hash, REJECTED, DONE) })?
    };
    if moved == 0 {
        return Err(ChallengeError::Used.into());
    }
    // A rejected login can arrive inside the redirect chain of a sign-in form submission; a
    // document keeps the client's origin out of that chain's `form-action` check.
    let nav = if row.consent_challenge_hash.is_none() {
        Navigation::Document
    } else {
        Navigation::Redirect
    };
    Ok(Resumed::Error {
        delivery: row.delivery(),
        flow_id: row.id,
        error: stored.error,
        description: stored.error_description,
        nav,
    })
}

/// Moves the unexpired device row of request `flow_id` from `accepted` to `denied`.
macro_rules! deny_device_row {
    ($c:ident, $flow_id:expr, $now:expr) => {
        diesel::update(
            oauth_device_codes::table
                .filter(oauth_device_codes::flow_id.eq(Some($flow_id)))
                .filter(oauth_device_codes::status.eq(super::device::ACCEPTED))
                .filter(oauth_device_codes::expires_at.gt($now)),
        )
        .set(oauth_device_codes::status.eq(super::device::DENIED))
        .execute($c)
    };
}

/// Ends a consented device request: its code is stored under the device code's hash and the device
/// row moves from `accepted` to `approved`, with the verifier consumed, in one transaction. A
/// revoked grant, or a grant that does not match the device row, denies it instead; an expired
/// device row is left as it is.
async fn approve_device(
    db: &DbPool,
    row: FlowRow,
    verifier_hash: String,
    now: DateTime<Utc>,
) -> Result<Resumed> {
    use super::device::{ACCEPTED, APPROVED};
    let login: LoginResult = from_json(row.login_result.as_deref().unwrap_or("null"))?;
    let amr = to_json(&login.amr)?;
    let now_s = rfc3339(now);
    let approved = settle(serialized_txn!(db, bool, Abort, |c| {
        if consume!(c, row, verifier_hash, CONSENT_ACCEPTED, DONE)? == 0 {
            return Err(Abort::Refused(ChallengeError::Used));
        }
        let device: Option<(String, String, String, String)> = oauth_device_codes::table
            .filter(oauth_device_codes::flow_id.eq(Some(&row.id)))
            .filter(oauth_device_codes::status.eq(ACCEPTED))
            .filter(oauth_device_codes::expires_at.gt(&now_s))
            .select((
                oauth_device_codes::device_code_hash,
                oauth_device_codes::client_id,
                oauth_device_codes::scope,
                oauth_device_codes::expires_at,
            ))
            .first(c)
            .optional()?;
        let Some((hash, client_id, device_scope, device_expires_at)) = device else {
            return Ok(false);
        };
        let grant = oauth_consent_grants::table
            .find(&row.id)
            .select(GrantRow::as_select())
            .first(c)
            .optional()?;
        let within = |granted: &str| {
            let parse = |raw: &str| serde_json::from_str::<Vec<String>>(raw).ok();
            parse(granted)
                .zip(parse(&device_scope))
                .is_some_and(|(granted, allowed)| granted.iter().all(|s| allowed.contains(s)))
        };
        let Some(grant) = grant.filter(|g| g.client_id == client_id && within(&g.scope)) else {
            deny_device_row!(c, &row.id, &now_s)?;
            return Ok(false);
        };
        let (_, mut code) = grants::new_code(
            &CodeFor {
                grant: &grant,
                redirect_uri: "",
                code_challenge: None,
                nonce: None,
                auth_time: &login.auth_time,
                acr: login.acr.as_deref(),
                amr: &amr,
            },
            now,
        );
        code.code_hash = hash.clone();
        code.expires_at = std::cmp::min(code.expires_at, device_expires_at);
        diesel::insert_into(oauth_authorization_codes::table)
            .values(&code)
            .execute(c)?;
        let moved = diesel::update(
            oauth_device_codes::table
                .filter(oauth_device_codes::device_code_hash.eq(&hash))
                .filter(oauth_device_codes::status.eq(ACCEPTED))
                .filter(oauth_device_codes::expires_at.gt(&now_s)),
        )
        .set(oauth_device_codes::status.eq(APPROVED))
        .execute(c)?;
        if moved == 0 {
            return Err(Abort::Refused(ChallengeError::Used));
        }
        Ok(true)
    }))?;
    Ok(Resumed::Device { approved })
}

/// Ends a rejected device request: the device row moves from `accepted` to `denied`, with the
/// verifier consumed, in one transaction.
async fn deny_device(db: &DbPool, row: FlowRow, verifier_hash: String) -> Result<Resumed> {
    let now = crate::db::now_rfc3339();
    settle(serialized_txn!(db, (), Abort, |c| {
        if consume!(c, row, verifier_hash, REJECTED, DONE)? == 0 {
            return Err(Abort::Refused(ChallengeError::Used));
        }
        deny_device_row!(c, &row.id, &now)?;
        Ok(())
    }))?;
    Ok(Resumed::Device { approved: false })
}

#[cfg(test)]
mod tests;
