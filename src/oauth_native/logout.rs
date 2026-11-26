//! RP-initiated logout (`/oauth2/sessions/logout`) with its challenge in `oauth_logout_requests`,
//! and back-channel logout when a login session ends by `sid`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use diesel::prelude::*;

use super::challenge::ChallengeError;
use super::keys::KeySet;
use super::{NativeOAuth, clients, jwt, random_token, sessions, token_hash};
use crate::audit::{self, AuditEvent, action, severity, target_kind};
use crate::backend::oauth::{LogoutRequest, RedirectTo};
use crate::db::{DbPool, rfc3339};
use crate::schema::{oauth_clients, oauth_consent_grants, oauth_logout_requests};
use crate::state::AppState;
use crate::{audit_metadata, db_interact};

pub(super) const LOGOUT_PATH: &str = "/oauth2/sessions/logout";

/// Time the user has to confirm on `/oauth/logout`.
const REQUEST_TTL_SECS: i64 = 30 * 60;
/// One back-channel POST, connect included.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);
/// A query or form body larger than any ID token this server issues.
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// `state` is stored with the request until the prune.
const MAX_STATE_BYTES: usize = 2048;

/// Why a logout request was answered with the error page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// The query or form body is over [`MAX_REQUEST_BYTES`].
    TooLarge,
    /// `state` is over [`MAX_STATE_BYTES`].
    StateTooLong,
    RepeatedParameter,
    InvalidHint,
    ClientMismatch,
    /// A `post_logout_redirect_uri` without an `id_token_hint`.
    RedirectWithoutHint,
    UnregisteredRedirect,
    /// A `post_logout_redirect_uri` that is not http or https, which `/oauth/logout` cannot
    /// continue to.
    RedirectScheme,
    /// No hint, and no `forseti_op` cookie naming a stored session.
    NoSession,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Params {
    id_token_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

impl Params {
    /// The RP-Initiated Logout 1.0 parameters of a query or form body; `logout_hint` and
    /// `ui_locales` are ignored. An empty value counts as absent (RFC 6749 section 3.1).
    pub(super) fn parse(raw: &[u8]) -> Result<Self, Refused> {
        if raw.len() > MAX_REQUEST_BYTES {
            return Err(Refused::TooLarge);
        }
        let mut seen = HashSet::new();
        let mut p = Self::default();
        for (k, v) in url::form_urlencoded::parse(raw) {
            if !seen.insert(k.clone()) {
                return Err(Refused::RepeatedParameter);
            }
            if v.is_empty() {
                continue;
            }
            let slot = match &*k {
                "id_token_hint" => &mut p.id_token_hint,
                "client_id" => &mut p.client_id,
                "post_logout_redirect_uri" => &mut p.post_logout_redirect_uri,
                "state" => &mut p.state,
                _ => continue,
            };
            *slot = Some(v.into_owned());
        }
        if p.state.as_ref().is_some_and(|s| s.len() > MAX_STATE_BYTES) {
            return Err(Refused::StateTooLong);
        }
        Ok(p)
    }
}

/// The only schemes the shared `/oauth/logout` handler continues to.
fn is_web_uri(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|u| matches!(u.scheme(), "http" | "https"))
}

pub(super) async fn get(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    respond(
        &state,
        raw.as_deref().unwrap_or_default().as_bytes(),
        &headers,
    )
    .await
}

pub(super) async fn post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    respond(&state, &body, &headers).await
}

/// A 303 to the confirmation page, or the error page; never a redirect to the client.
async fn respond(state: &AppState, raw: &[u8], headers: &HeaderMap) -> Response {
    let oauth = &state.oauth;
    let cookie_sid = sessions::read_op_cookie(&oauth.cookie_secret, headers);
    let opened = match Params::parse(raw) {
        Ok(params) => open(oauth, &params, cookie_sid.as_deref()).await,
        Err(refused) => Ok(Err(refused)),
    };
    match opened {
        Ok(Ok(challenge)) => Redirect::to(&format!(
            "{}/oauth/logout?logout_challenge={}",
            oauth.issuer,
            crate::web::urlencode(&challenge)
        ))
        .into_response(),
        Ok(Err(reason)) => {
            tracing::info!(?reason, "logout request refused");
            Redirect::to("/error").into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, "opening the logout request failed");
            Redirect::to("/error").into_response()
        }
    }
}

/// The client a verified hint was issued to: its single audience.
fn hint_audience(claims: &serde_json::Value) -> Option<&str> {
    match &claims["aud"] {
        serde_json::Value::String(aud) => Some(aud),
        serde_json::Value::Array(auds) if auds.len() == 1 => auds[0].as_str(),
        _ => None,
    }
}

/// Stores a logout request and returns its challenge. With a hint, the hint names the session and
/// the client, and a `forseti_op` cookie naming another session of the hint's subject is stored
/// as the browser's session; without one, the cookie's `sid` names the session.
pub(super) async fn open(
    oauth: &NativeOAuth,
    params: &Params,
    cookie_sid: Option<&str>,
) -> Result<Result<String, Refused>> {
    let (client_id, sid, browser_sid, subject, redirect) = match &params.id_token_hint {
        Some(hint) => {
            let Ok(claims) = oauth.verify_hint(hint).await else {
                return Ok(Err(Refused::InvalidHint));
            };
            let (Some(aud), Some(sid), Some(sub)) = (
                hint_audience(&claims),
                claims["sid"].as_str().filter(|s| !s.is_empty()),
                claims["sub"].as_str().filter(|s| !s.is_empty()),
            ) else {
                return Ok(Err(Refused::InvalidHint));
            };
            if params.client_id.as_deref().is_some_and(|c| c != aud) {
                return Ok(Err(Refused::ClientMismatch));
            }
            if let Some(uri) = &params.post_logout_redirect_uri {
                if !is_web_uri(uri) {
                    return Ok(Err(Refused::RedirectScheme));
                }
                let client = clients::get(&oauth.db, aud).await?;
                if !client.is_some_and(|c| is_registered(&c, uri)) {
                    return Ok(Err(Refused::UnregisteredRedirect));
                }
            }
            let redirect = params
                .post_logout_redirect_uri
                .clone()
                .map(|uri| (uri, params.state.clone()));
            let browser_sid = match cookie_sid.filter(|c| *c != sid) {
                Some(c) => sessions::find(&oauth.db, c)
                    .await?
                    .filter(|s| s.subject == sub)
                    .map(|s| s.sid),
                None => None,
            };
            (
                Some(aud.to_string()),
                sid.to_string(),
                browser_sid,
                sub.to_string(),
                redirect,
            )
        }
        None => {
            if params.post_logout_redirect_uri.is_some() {
                return Ok(Err(Refused::RedirectWithoutHint));
            }
            let session = match cookie_sid {
                Some(sid) => sessions::find(&oauth.db, sid).await?,
                None => None,
            };
            let Some(session) = session else {
                return Ok(Err(Refused::NoSession));
            };
            (None, session.sid, None, session.subject, None)
        }
    };
    let challenge = random_token();
    let now = Utc::now();
    let (post_logout_redirect_uri, oauth_state) = redirect.unzip();
    let row = LogoutRow {
        id: uuid::Uuid::new_v4().to_string(),
        challenge_hash: token_hash(&challenge),
        client_id,
        sid,
        browser_sid,
        subject,
        post_logout_redirect_uri,
        oauth_state: oauth_state.flatten(),
        accepted_at: None,
        created_at: rfc3339(now),
        expires_at: rfc3339(now + chrono::Duration::seconds(REQUEST_TTL_SECS)),
    };
    db_interact!(oauth.db, |c| {
        diesel::insert_into(oauth_logout_requests::table)
            .values(&row)
            .execute(c)
    })?;
    Ok(Ok(challenge))
}

fn is_registered(client: &crate::backend::oauth::OAuthClient, uri: &str) -> bool {
    client
        .post_logout_redirect_uris
        .iter()
        .flatten()
        .any(|registered| registered == uri)
}

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = oauth_logout_requests)]
struct LogoutRow {
    id: String,
    challenge_hash: String,
    client_id: Option<String>,
    sid: String,
    browser_sid: Option<String>,
    subject: String,
    post_logout_redirect_uri: Option<String>,
    oauth_state: Option<String>,
    accepted_at: Option<String>,
    created_at: String,
    expires_at: String,
}

/// The unexpired, unaccepted request of `challenge`.
async fn pending(db: &DbPool, challenge: &str) -> Result<LogoutRow> {
    let hash = token_hash(challenge);
    let row = db_interact!(db, |c| {
        oauth_logout_requests::table
            .filter(oauth_logout_requests::challenge_hash.eq(hash))
            .select(LogoutRow::as_select())
            .first(c)
            .optional()
    })?
    .ok_or(ChallengeError::Unknown)?;
    if row.accepted_at.is_some() {
        return Err(ChallengeError::Used.into());
    }
    if super::parse_time(&row.expires_at)? <= Utc::now() {
        return Err(ChallengeError::Unknown.into());
    }
    Ok(row)
}

/// What `/oauth/logout` shows: `rp_initiated` and `client` when an `id_token_hint` named the
/// client, as on Hydra.
pub(super) async fn get_logout_request(db: &DbPool, challenge: &str) -> Result<LogoutRequest> {
    let row = pending(db, challenge).await?;
    let client = match &row.client_id {
        Some(id) => clients::get(db, id).await?,
        None => None,
    };
    Ok(LogoutRequest {
        client,
        rp_initiated: Some(row.client_id.is_some()),
        sid: Some(row.sid),
        subject: Some(row.subject),
    })
}

/// Ends the request's login session, and the browser's session while it still belongs to the
/// request's subject, then consumes the request; of two concurrent accepts one succeeds. A failed
/// session end leaves the request usable. The redirect URI, with `state`, only while the client
/// still registers it; otherwise `/signed-out`. Grants stay.
pub(super) async fn accept_logout_request(
    oauth: &NativeOAuth,
    challenge: &str,
) -> Result<RedirectTo> {
    let row = pending(&oauth.db, challenge).await?;
    end_session(oauth, &row.sid).await?;
    if let Some(browser_sid) = &row.browser_sid
        && sessions::find(&oauth.db, browser_sid)
            .await?
            .is_some_and(|s| s.subject == row.subject)
    {
        end_session(oauth, browser_sid).await?;
    }
    let (id, now) = (row.id.clone(), rfc3339(Utc::now()));
    let consumed = db_interact!(oauth.db, |c| {
        diesel::update(
            oauth_logout_requests::table
                .filter(oauth_logout_requests::id.eq(id))
                .filter(oauth_logout_requests::accepted_at.is_null())
                .filter(oauth_logout_requests::expires_at.gt(&now)),
        )
        .set(oauth_logout_requests::accepted_at.eq(Some(&now)))
        .execute(c)
    })?;
    if consumed == 0 {
        return Err(ChallengeError::Used.into());
    }
    let redirect_to = match honoured_redirect(&oauth.db, &row).await {
        Ok(Some(uri)) => uri,
        Ok(None) => format!("{}/signed-out", oauth.issuer),
        Err(e) => {
            tracing::warn!(error = ?e, "oauth client lookup at logout accept failed");
            format!("{}/signed-out", oauth.issuer)
        }
    };
    Ok(RedirectTo { redirect_to })
}

async fn honoured_redirect(db: &DbPool, row: &LogoutRow) -> Result<Option<String>> {
    let (Some(client_id), Some(uri)) = (&row.client_id, &row.post_logout_redirect_uri) else {
        return Ok(None);
    };
    if !is_web_uri(uri) {
        return Ok(None);
    }
    if !clients::get(db, client_id)
        .await?
        .is_some_and(|c| is_registered(&c, uri))
    {
        return Ok(None);
    }
    let Some(state) = &row.oauth_state else {
        return Ok(Some(uri.clone()));
    };
    let Ok(mut url) = url::Url::parse(uri) else {
        return Ok(None);
    };
    url.query_pairs_mut().append_pair("state", state);
    Ok(Some(url.into()))
}

/// A client to notify: its id and `backchannel_logout_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Recipient {
    client_id: String,
    uri: String,
}

/// Clients with a grant under `sid` and a `backchannel_logout_uri`.
async fn recipients(db: &DbPool, sid: &str) -> Result<Vec<Recipient>> {
    let sid = sid.to_string();
    let rows = db_interact!(db, |c| {
        let granted: Vec<String> = oauth_consent_grants::table
            .filter(oauth_consent_grants::session_id.eq(&sid))
            .select(oauth_consent_grants::client_id)
            .distinct()
            .load(c)?;
        oauth_clients::table
            .filter(oauth_clients::client_id.eq_any(granted))
            .select((
                oauth_clients::client_id,
                oauth_clients::backchannel_logout_uri,
            ))
            .order(oauth_clients::client_id)
            .load::<(String, Option<String>)>(c)
    })?;
    Ok(rows
        .into_iter()
        .filter_map(|(client_id, uri)| {
            uri.filter(|u| !u.is_empty())
                .map(|uri| Recipient { client_id, uri })
        })
        .collect())
}

/// Deletes login session `sid` and its unredeemed codes. Only the call that deleted the row sends
/// back-channel logout, so a `sid` is announced at most once across retries and races. The
/// recipients are read first, while the grants under the `sid` still exist.
pub(super) async fn end_session(oauth: &NativeOAuth, sid: &str) -> Result<()> {
    let session = sessions::find(&oauth.db, sid).await?;
    let recipients = match &session {
        Some(_) => recipients(&oauth.db, sid).await?,
        None => Vec::new(),
    };
    let deleted = sessions::revoke_by_sid(&oauth.db, sid).await?;
    if let (true, Some(session)) = (deleted, session) {
        spawn_deliveries(oauth, &session.subject, sid, recipients);
    }
    Ok(())
}

/// Detached, so neither a dropped request nor a slow client holds up the caller.
fn spawn_deliveries(oauth: &NativeOAuth, subject: &str, sid: &str, recipients: Vec<Recipient>) {
    if recipients.is_empty() {
        return;
    }
    let keys = oauth.keys().ok();
    let mut set = oauth
        .deliveries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while set.try_join_next().is_some() {}
    for recipient in recipients {
        let delivery = Delivery {
            db: oauth.db.clone(),
            issuer: oauth.issuer.clone(),
            keys: keys.clone(),
            allow_private: oauth.allow_private_targets,
            subject: subject.to_string(),
            sid: sid.to_string(),
            recipient,
        };
        set.spawn(delivery.run());
    }
}

struct Delivery {
    db: DbPool,
    issuer: String,
    keys: Option<Arc<KeySet>>,
    allow_private: bool,
    subject: String,
    sid: String,
    recipient: Recipient,
}

impl Delivery {
    /// One POST; a failure is logged with the client id and host and audited, never retried.
    async fn run(self) {
        let Err(reason) = self.send().await else {
            return;
        };
        let host = url::Url::parse(&self.recipient.uri)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default();
        let client_id = self.recipient.client_id.as_str();
        tracing::warn!(client_id, host = %host, "oauth back-channel logout delivery failed");
        let event = AuditEvent::new(action::OAUTH_BACKCHANNEL_LOGOUT_FAILED)
            .actor_system("oauth")
            .target(target_kind::OAUTH_CLIENT, client_id)
            .severity(severity::WARNING)
            .metadata(audit_metadata!("client_id" => client_id, "host" => host))
            .failed(reason);
        if let Err(e) = audit::log(&self.db, event).await {
            tracing::warn!(error = %e, "audit write for a failed back-channel logout failed");
        }
    }

    /// `Err` is a fixed description that never carries the token or the URI.
    async fn send(&self) -> Result<(), String> {
        let url = url::Url::parse(&self.recipient.uri)
            .map_err(|_| "backchannel_logout_uri does not parse".to_string())?;
        crate::outbound::check_target(&url, self.allow_private)
            .map_err(|e| format!("backchannel_logout_uri {e}"))?;
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| "signing keys are not loaded".to_string())?;
        let claims = jwt::logout_token_claims(
            &self.issuer,
            &self.recipient.client_id,
            &self.subject,
            &self.sid,
            Utc::now().timestamp(),
        );
        let token = jwt::sign(keys, jwt::Typ::Logout, &claims)
            .map_err(|_| "logout token signing failed".to_string())?;
        let resp = crate::outbound::client(self.allow_private)
            .post(url)
            .timeout(DELIVERY_TIMEOUT)
            .form(&[("logout_token", token.as_str())])
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    "timed out".to_string()
                } else if e.is_connect() {
                    "connection failed".to_string()
                } else {
                    "request failed".to_string()
                }
            })?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("answered {}", status.as_u16()))
        }
    }
}

#[cfg(test)]
mod tests;
