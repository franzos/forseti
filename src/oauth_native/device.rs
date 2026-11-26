//! The device authorization grant (RFC 8628) over `oauth_device_codes`: the device authorization
//! endpoint, polling at the token endpoint, and the in-process calls of the POSIX device login.
//! The code a poll redeems is the `oauth_authorization_codes` row stored under the device code's
//! hash once the user approves.

use anyhow::{Context as _, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde_json::{Value, json};

use super::authorize::space_list;
use super::clients::{self, ClientAuthError, ClientCredentials};
use super::jwt::Typ;
use super::token_endpoint::{
    self, REFRESH_TOKEN, authenticate_client, invalid_request, json_error, read_form, server_error,
};
use super::tokens::{self, Invalid, Issued};
use super::{ACCESS_TOKEN_TTL_SECS, NativeOAuth, parse_time, random_token, to_json, token_hash};
use crate::backend::oauth::{
    DeviceAuthorization, DeviceTokenOutcome, IdTokenClaims, OAuthClient, TokenSet,
};
use crate::db::{DbPool, rfc3339};
use crate::schema::oauth_device_codes;
use crate::state::AppState;
use crate::{db_interact, serialized_txn};

pub(super) const DEVICE_AUTHORIZATION_PATH: &str = "/oauth2/device/auth";
pub(super) const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Forseti's verification page, the `verification_uri` of every authorization.
const VERIFICATION_PATH: &str = "/oauth/device";

const DEVICE_CODE_TTL_SECS: i64 = 600;
const INTERVAL_SECS: i32 = 5;
/// RFC 8628 section 3.5: each `slow_down` raises the interval by this much for good.
const SLOW_DOWN_STEP_SECS: i32 = 5;
/// Unexpired authorizations still awaiting the user's decision, per client.
const MAX_UNDECIDED_PER_CLIENT: i64 = 1000;
/// RFC 8628 section 6.1: no vowels, so no words, and nothing that reads as a digit.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_ATTEMPTS: usize = 3;

pub(super) const PENDING: &str = "pending";
pub(super) const ACCEPTED: &str = "accepted";
pub(super) const APPROVED: &str = "approved";
pub(super) const DENIED: &str = "denied";

/// Why a device authorization request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    UnauthorizedClient,
    InvalidScope,
    TooManyPending,
}

impl Refused {
    fn response(self) -> Response {
        let (status, error, description) = match self {
            Self::UnauthorizedClient => (
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "the client is not registered for the device code grant",
            ),
            Self::InvalidScope => (
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "a requested scope is not allowed for this client",
            ),
            Self::TooManyPending => (
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "the client has too many pending device authorizations",
            ),
        };
        json_error(status, error, description)
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidScope => "invalid_scope",
            Self::TooManyPending => "too many pending device authorizations",
        })
    }
}

impl std::error::Error for Refused {}

#[derive(Insertable)]
#[diesel(table_name = oauth_device_codes)]
struct NewDevice {
    device_code_hash: String,
    user_code: String,
    client_id: String,
    scope: String,
    status: String,
    interval_secs: i32,
    created_at: String,
    expires_at: String,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = oauth_device_codes)]
struct DeviceRow {
    client_id: String,
    status: String,
    interval_secs: i32,
    last_polled_at: Option<String>,
    expires_at: String,
}

/// `XXXX-XXXX` from [`USER_CODE_ALPHABET`], about 34 bits.
fn user_code() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut code = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            code.push('-');
        }
        let pick = rng.random_range(0..USER_CODE_ALPHABET.len());
        code.push(char::from(USER_CODE_ALPHABET[pick]));
    }
    code
}

/// A user code as typed, in its stored form: case, spaces and dashes do not matter. `None` when
/// it cannot be one of ours.
pub(crate) fn normalize_user_code(raw: &str) -> Option<String> {
    let letters: Vec<u8> = raw
        .bytes()
        .filter(|b| *b != b'-' && !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if letters.len() != 8 || !letters.iter().all(|b| USER_CODE_ALPHABET.contains(b)) {
        return None;
    }
    let mut code: String = letters[..4].iter().map(|&b| char::from(b)).collect();
    code.push('-');
    code.extend(letters[4..].iter().map(|&b| char::from(b)));
    Some(code)
}

/// Accepts the pending device authorization of `user_code` as typed: its authorization request
/// goes to the login handler. A code that is not pending and unexpired is refused.
pub(super) async fn accept_user_code(
    oauth: &NativeOAuth,
    user_code: &str,
) -> Result<crate::backend::oauth::RedirectTo> {
    let user_code =
        normalize_user_code(user_code).ok_or(super::challenge::ChallengeError::Unknown)?;
    super::challenge::accept_user_code(oauth, &user_code).await
}

/// Stores `row` unless the client already has [`MAX_UNDECIDED_PER_CLIENT`] undecided
/// authorizations; `Ok(false)` when it has. A taken user code is the unique violation.
async fn insert(db: &DbPool, row: NewDevice, now: &str) -> Result<Result<bool, DieselError>> {
    let now = now.to_string();
    Ok(serialized_txn!(db, bool, DieselError, |c| {
        let undecided: i64 = oauth_device_codes::table
            .filter(oauth_device_codes::client_id.eq(&row.client_id))
            .filter(oauth_device_codes::status.eq_any([PENDING, ACCEPTED]))
            .filter(oauth_device_codes::expires_at.gt(&now))
            .count()
            .get_result(c)?;
        if undecided >= MAX_UNDECIDED_PER_CLIENT {
            return Ok(false);
        }
        diesel::insert_into(oauth_device_codes::table)
            .values(&row)
            .execute(c)?;
        Ok(true)
    }))
}

/// RFC 8628 section 3.1 for an authenticated `client`: the device grant registered, `scope`
/// within the client's, as at the authorization endpoint. A refusal is a [`Refused`].
pub(super) async fn create(
    db: &DbPool,
    issuer: &str,
    client: &OAuthClient,
    scope: &[String],
    now: DateTime<Utc>,
) -> Result<DeviceAuthorization> {
    let client_id = client
        .client_id
        .clone()
        .context("OAuth client without an id")?;
    if !token_endpoint::allows_grant(client, DEVICE_CODE_GRANT) {
        return Err(Refused::UnauthorizedClient.into());
    }
    let allowed = space_list(client.scope.as_deref());
    if !scope.iter().all(|s| allowed.contains(s)) {
        return Err(Refused::InvalidScope.into());
    }
    let device_code = random_token();
    let now_s = rfc3339(now);
    let verification_uri = format!("{issuer}{VERIFICATION_PATH}");
    for _ in 0..USER_CODE_ATTEMPTS {
        let user_code = user_code();
        let row = NewDevice {
            device_code_hash: token_hash(&device_code),
            user_code: user_code.clone(),
            client_id: client_id.clone(),
            scope: to_json(scope)?,
            status: PENDING.to_string(),
            interval_secs: INTERVAL_SECS,
            created_at: now_s.clone(),
            expires_at: rfc3339(now + chrono::Duration::seconds(DEVICE_CODE_TTL_SECS)),
        };
        match insert(db, row, &now_s).await? {
            Ok(true) => {
                return Ok(DeviceAuthorization {
                    device_code,
                    verification_uri_complete: Some(format!(
                        "{verification_uri}?user_code={user_code}"
                    )),
                    user_code,
                    verification_uri,
                    expires_in: DEVICE_CODE_TTL_SECS,
                    interval: i64::from(INTERVAL_SECS),
                });
            }
            Ok(false) => return Err(Refused::TooManyPending.into()),
            Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {}
            Err(e) => return Err(e).context("store a device authorization"),
        }
    }
    anyhow::bail!("no free user code in {USER_CODE_ATTEMPTS} attempts")
}

/// One poll of a device code (RFC 8628 section 3.5).
#[derive(Debug)]
pub(super) enum Polled {
    Pending,
    SlowDown,
    Expired,
    Denied,
    Issued(Box<Issued>),
}

impl Polled {
    /// The tokens to mint, or the RFC 8628 section 3.5 error code and description.
    pub(super) fn into_issued(self) -> Result<Issued, (&'static str, &'static str)> {
        match self {
            Self::Issued(issued) => Ok(*issued),
            Self::Pending => Err((
                "authorization_pending",
                "the user has not approved the request yet",
            )),
            Self::SlowDown => Err(("slow_down", "polling too fast; the interval was raised")),
            Self::Expired => Err(("expired_token", "the device code has expired")),
            Self::Denied => Err(("access_denied", "the user denied the request")),
        }
    }
}

/// Polls `device_code` for the authenticated `client`. An unknown or foreign code, or an approved
/// one whose code cannot be redeemed, is `invalid_grant` ([`Invalid`]). An undecided one polled
/// sooner than its interval after the previous poll answers `slow_down` and raises the interval.
pub(super) async fn poll(
    db: &DbPool,
    client: &OAuthClient,
    device_code: &str,
    resource: &[String],
    now: DateTime<Utc>,
) -> Result<Polled> {
    let client_id = client
        .client_id
        .as_deref()
        .context("OAuth client without an id")?;
    let hash = token_hash(device_code);
    let row = {
        let hash = hash.clone();
        db_interact!(db, |c| {
            oauth_device_codes::table
                .find(hash)
                .select(DeviceRow::as_select())
                .first(c)
                .optional()
        })?
    }
    .filter(|r| r.client_id == client_id)
    .ok_or(Invalid::Grant)?;
    if row.expires_at <= rfc3339(now) {
        return Ok(Polled::Expired);
    }
    match row.status.as_str() {
        DENIED => Ok(Polled::Denied),
        APPROVED => {
            let refresh_allowed = token_endpoint::allows_grant(client, REFRESH_TOKEN);
            let issued =
                tokens::redeem_device_code(db, client_id, &hash, resource, refresh_allowed, now)
                    .await?;
            Ok(Polled::Issued(Box::new(issued)))
        }
        PENDING | ACCEPTED => throttle(db, hash, row, now).await,
        _ => Err(Invalid::Grant.into()),
    }
}

/// Records the poll. One sooner than the interval after the last, or one racing another poll,
/// raises the interval and is `slow_down`.
async fn throttle(db: &DbPool, hash: String, row: DeviceRow, now: DateTime<Utc>) -> Result<Polled> {
    let interval = chrono::Duration::seconds(i64::from(row.interval_secs));
    let too_fast = match row.last_polled_at.as_deref() {
        Some(last) => now < parse_time(last)? + interval,
        None => false,
    };
    let now_s = rfc3339(now);
    if !too_fast {
        let (hash, now_s, last) = (hash.clone(), now_s.clone(), row.last_polled_at);
        let recorded = db_interact!(db, |c| {
            let target =
                oauth_device_codes::table.filter(oauth_device_codes::device_code_hash.eq(hash));
            match last {
                Some(last) => {
                    diesel::update(target.filter(oauth_device_codes::last_polled_at.eq(last)))
                        .set(oauth_device_codes::last_polled_at.eq(Some(now_s)))
                        .execute(c)
                }
                None => diesel::update(target.filter(oauth_device_codes::last_polled_at.is_null()))
                    .set(oauth_device_codes::last_polled_at.eq(Some(now_s)))
                    .execute(c),
            }
        })?;
        if recorded == 1 {
            return Ok(Polled::Pending);
        }
    }
    db_interact!(db, |c| {
        diesel::update(oauth_device_codes::table.find(hash))
            .set((
                oauth_device_codes::interval_secs
                    .eq(oauth_device_codes::interval_secs + SLOW_DOWN_STEP_SECS),
                oauth_device_codes::last_polled_at.eq(Some(now_s)),
            ))
            .execute(c)
    })?;
    Ok(Polled::SlowDown)
}

/// `POST /oauth2/device/auth` (RFC 8628 sections 3.1 and 3.2). A public client names itself with
/// `client_id`; a confidential one authenticates as at the token endpoint.
pub(super) async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let form = match read_form(&headers, body).await {
        Ok(form) => form,
        Err(why) => return invalid_request(why),
    };
    if form.repeated(&[]) {
        return invalid_request("a parameter is repeated");
    }
    let oauth = &state.oauth;
    let client = match authenticate_client(oauth, &headers, &form, false).await {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    let scope = space_list(form.get("scope"));
    let client_id = client.client_id.as_deref().unwrap_or_default();
    match create(&oauth.db, &oauth.issuer, &client, &scope, Utc::now()).await {
        Ok(a) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json!({
                "device_code": a.device_code,
                "user_code": a.user_code,
                "verification_uri": a.verification_uri,
                "verification_uri_complete": a.verification_uri_complete,
                "expires_in": a.expires_in,
                "interval": a.interval,
            })
            .to_string(),
        )
            .into_response(),
        Err(e) => match e.downcast_ref::<Refused>() {
            Some(r) => {
                tracing::info!(client_id, error = %r, "oauth device authorization refused");
                r.response()
            }
            None => {
                tracing::error!(error = ?e, client_id, "oauth device authorization failed");
                server_error()
            }
        },
    }
}

/// The client by `client_secret_basic`, the method the Ory backend uses for these calls.
async fn authenticate_basic(
    oauth: &NativeOAuth,
    client_id: &str,
    client_secret: &str,
) -> Result<OAuthClient, ClientAuthError> {
    let credentials = ClientCredentials::Basic {
        client_id,
        client_secret,
    };
    clients::authenticate(&oauth.db, &oauth.hash_permits, credentials).await
}

/// [`create`] in process; any refusal is an error, as a non-200 is on the Ory backend.
pub(super) async fn start(
    oauth: &NativeOAuth,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<DeviceAuthorization> {
    let client = authenticate_basic(oauth, client_id, client_secret).await?;
    let scope = space_list(Some(scope));
    create(&oauth.db, &oauth.issuer, &client, &scope, Utc::now()).await
}

/// [`poll`] in process, with the token response minted. A refused client, grant type or code is
/// `Expired`, as the Ory backend reads any error body other than the four RFC 8628 ones.
pub(super) async fn poll_token(
    oauth: &NativeOAuth,
    client_id: &str,
    client_secret: &str,
    device_code: &str,
) -> Result<DeviceTokenOutcome> {
    let client = match authenticate_basic(oauth, client_id, client_secret).await {
        Ok(client) => client,
        Err(ClientAuthError::InvalidClient) => return Ok(DeviceTokenOutcome::Expired),
        Err(e) => return Err(e.into()),
    };
    if !token_endpoint::allows_grant(&client, DEVICE_CODE_GRANT) {
        return Ok(DeviceTokenOutcome::Expired);
    }
    let now = Utc::now();
    let polled = match poll(&oauth.db, &client, device_code, &[], now).await {
        Ok(polled) => polled,
        Err(e) if e.downcast_ref::<Invalid>().is_some() => return Ok(DeviceTokenOutcome::Expired),
        Err(e) => return Err(e),
    };
    Ok(match polled {
        Polled::Pending => DeviceTokenOutcome::Pending,
        Polled::SlowDown => DeviceTokenOutcome::SlowDown,
        Polled::Expired => DeviceTokenOutcome::Expired,
        Polled::Denied => DeviceTokenOutcome::Denied,
        Polled::Issued(issued) => {
            let body = token_endpoint::mint(oauth, client_id, &issued, now).await?;
            DeviceTokenOutcome::Token(Box::new(TokenSet {
                access_token: body["access_token"]
                    .as_str()
                    .context("token response without an access token")?
                    .to_string(),
                id_token: body["id_token"].as_str().map(str::to_string),
                expires_in: ACCESS_TOKEN_TTL_SECS,
            }))
        }
    })
}

/// An ID token this server signed for `client_id`: [`NativeOAuth::verify_jwt`], `iss` equal to
/// `issuer`, `aud` exactly the client, and `iat` at most `iat_window_secs` old and at most 60 s
/// ahead. Native ID tokens carry no `azp`.
pub(super) async fn verify_id_token(
    oauth: &NativeOAuth,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    iat_window_secs: u64,
) -> Result<IdTokenClaims> {
    let claims = oauth
        .verify_jwt(id_token, Typ::IdToken, Some(client_id))
        .await?;
    if claims["iss"] != issuer {
        anyhow::bail!("id_token iss is not the expected issuer");
    }
    let only_client = match &claims["aud"] {
        Value::String(aud) => aud == client_id,
        Value::Array(aud) => aud.len() == 1 && aud[0] == client_id,
        _ => false,
    };
    if !only_client {
        anyhow::bail!("id_token aud must be exactly [{client_id}]");
    }
    let iat = claims["iat"].as_i64().context("id_token without iat")?;
    let now = Utc::now().timestamp();
    if iat > now.saturating_add(60) {
        anyhow::bail!("id_token iat is in the future");
    }
    let age = now.saturating_sub(iat);
    if age > i64::try_from(iat_window_secs).unwrap_or(i64::MAX) {
        anyhow::bail!("id_token iat is stale ({age}s > {iat_window_secs}s window)");
    }
    Ok(IdTokenClaims {
        sub: claims["sub"]
            .as_str()
            .context("id_token without sub")?
            .to_string(),
        acr: claims["acr"].as_str().map(str::to_string),
        amr: claims["amr"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        auth_time: claims["auth_time"].as_i64(),
    })
}

#[cfg(test)]
mod tests;
