//! The token endpoint (RFC 6749 section 3.2): client authentication, the `authorization_code`,
//! `refresh_token` and device code grants, and the tokens they mint.

use anyhow::Result;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::clients::{self, ClientAuthError, ClientCredentials};
use super::device::{self, DEVICE_CODE_GRANT};
use super::jwt::{self, AccessTokenFor, IdTokenFor, Typ};
use super::tokens::{self, CodeExchange, Invalid, Issued, RefreshExchange};
use super::{ACCESS_TOKEN_TTL_SECS, NativeOAuth, from_json};
use crate::backend::oauth::OAuthClient;
use crate::db::DbPool;
use crate::state::AppState;

pub(super) const TOKEN_PATH: &str = "/oauth2/token";
/// Form bodies of the token and userinfo endpoints.
pub(super) const MAX_BODY_BYTES: usize = 16 * 1024;

const AUTHORIZATION_CODE: &str = "authorization_code";
pub(super) const REFRESH_TOKEN: &str = "refresh_token";
const BASIC_CHALLENGE: &str = "Basic realm=\"oauth2\"";
/// The longest wait for an Argon2 permit, rounded up.
const BUSY_RETRY_AFTER_SECS: &str = "3";

/// An `application/x-www-form-urlencoded` body. Empty values count as omitted (RFC 6749 section
/// 3.2) but still count towards duplicates.
pub(super) struct Form {
    pairs: Vec<(String, String)>,
}

impl Form {
    fn parse(raw: &[u8]) -> Self {
        let pairs = url::form_urlencoded::parse(raw)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        Self { pairs }
    }

    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.pairs
            .iter()
            .filter(|(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Whether a parameter other than the `repeatable` ones appears twice.
    pub(super) fn repeated(&self, repeatable: &[&str]) -> bool {
        self.pairs.iter().enumerate().any(|(i, (k, _))| {
            !repeatable.contains(&k.as_str()) && self.pairs[..i].iter().any(|(p, _)| p == k)
        })
    }
}

/// The form body of a request, at most [`MAX_BODY_BYTES`]; the error is a fixed description.
pub(super) async fn read_form(headers: &HeaderMap, body: Body) -> Result<Form, &'static str> {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return Err("the body must be application/x-www-form-urlencoded");
    }
    axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map(|b| Form::parse(&b))
        .map_err(|_| "the request body is too large")
}

pub(super) fn json_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        json!({ "error": error, "error_description": description }).to_string(),
    )
        .into_response()
}

pub(super) fn invalid_request(description: &'static str) -> Response {
    json_error(StatusCode::BAD_REQUEST, "invalid_request", description)
}

/// RFC 6749 section 5.2: 401, with a `WWW-Authenticate` challenge when the client tried Basic.
fn invalid_client(basic: bool) -> Response {
    let mut resp = json_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "client authentication failed",
    );
    if basic {
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(BASIC_CHALLENGE),
        );
    }
    resp
}

pub(super) fn server_error() -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "the request could not be completed",
    )
}

fn busy() -> Response {
    let mut resp = json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the server is busy",
    );
    resp.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_static(BUSY_RETRY_AFTER_SECS),
    );
    resp
}

/// The JSON `429` of the token, revocation, introspection, userinfo and JWKS rate limits.
pub(super) fn rate_limited(err: tower_governor::GovernorError) -> Response {
    let retry = match &err {
        tower_governor::GovernorError::TooManyRequests { wait_time, .. } => Some(*wait_time),
        _ => None,
    };
    tracing::trace!(error = ?err, "oauth endpoint rate limit triggered");
    let mut resp = json_error(
        StatusCode::TOO_MANY_REQUESTS,
        "temporarily_unavailable",
        "too many requests",
    );
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(secs) = retry.and_then(|s| HeaderValue::from_str(&s.to_string()).ok()) {
        headers.insert(header::RETRY_AFTER, secs);
    }
    resp
}

/// Credentials by the one method the request used.
struct Presented {
    client_id: String,
    secret: Option<String>,
    basic: bool,
}

impl Presented {
    fn credentials(&self) -> ClientCredentials<'_> {
        match (&self.secret, self.basic) {
            (Some(client_secret), true) => ClientCredentials::Basic {
                client_id: &self.client_id,
                client_secret,
            },
            (Some(client_secret), false) => ClientCredentials::Post {
                client_id: &self.client_id,
                client_secret,
            },
            (None, _) => ClientCredentials::None {
                client_id: &self.client_id,
            },
        }
    }
}

/// RFC 6749 section 2.3.1: both halves are form-urlencoded before the Basic encoding.
fn form_decode(raw: &str) -> Option<String> {
    percent_encoding::percent_decode_str(&raw.replace('+', " "))
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// `None` without a Basic `Authorization` header; `Some(None)` for a malformed one.
fn basic_credentials(headers: &HeaderMap) -> Option<Option<(String, String)>> {
    let value = headers.get(header::AUTHORIZATION)?.as_bytes();
    let (scheme, rest) = value.split_at(value.iter().position(|b| *b == b' ')?);
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return None;
    }
    let decoded = STANDARD
        .decode(rest.trim_ascii())
        .ok()
        .and_then(|d| String::from_utf8(d).ok());
    Some(decoded.and_then(|d| {
        let (id, secret) = d.split_once(':')?;
        let id = form_decode(id).filter(|id| !id.is_empty())?;
        Some((id, form_decode(secret)?))
    }))
}

/// RFC 6749 section 2.3: one method per request; a body `client_id` next to Basic must agree.
fn presented(headers: &HeaderMap, form: &Form) -> Result<Presented, Response> {
    let (body_id, body_secret) = (form.get("client_id"), form.get("client_secret"));
    match basic_credentials(headers) {
        Some(Some((client_id, secret))) => {
            if body_secret.is_some() || body_id.is_some_and(|b| b != client_id) {
                return Err(invalid_request(
                    "the client used more than one authentication method",
                ));
            }
            Ok(Presented {
                client_id,
                secret: Some(secret),
                basic: true,
            })
        }
        Some(None) => Err(invalid_client(true)),
        None => match body_id {
            Some(client_id) => Ok(Presented {
                client_id: client_id.to_string(),
                secret: body_secret.map(str::to_string),
                basic: false,
            }),
            None => Err(invalid_client(false)),
        },
    }
}

/// RFC 6749 section 2.3 client authentication of a token, revocation or introspection request.
/// With `confidential`, a request without a secret is refused before any lookup. `Err` is the
/// response to send: 401 `invalid_client`, 400 for two methods at once, 503 for a busy hasher.
pub(super) async fn authenticate_client(
    oauth: &NativeOAuth,
    headers: &HeaderMap,
    form: &Form,
    confidential: bool,
) -> Result<OAuthClient, Response> {
    let presented = presented(headers, form)?;
    if confidential && presented.secret.is_none() {
        return Err(invalid_client(presented.basic));
    }
    match clients::authenticate(&oauth.db, &oauth.hash_permits, presented.credentials()).await {
        Ok(client) => Ok(client),
        Err(ClientAuthError::InvalidClient) => {
            tracing::info!("oauth client authentication failed");
            Err(invalid_client(presented.basic))
        }
        Err(ClientAuthError::Busy) => Err(busy()),
        Err(ClientAuthError::Failed(e)) => {
            tracing::error!(error = ?e, "oauth client authentication failed");
            Err(server_error())
        }
    }
}

/// An empty or missing `grant_types` stands for `authorization_code` alone, as fosite defaults it.
pub(super) fn allows_grant(client: &OAuthClient, grant_type: &str) -> bool {
    match client.grant_types.as_deref() {
        None | Some([]) => grant_type == AUTHORIZATION_CODE,
        Some(list) => list.iter().any(|g| g == grant_type),
    }
}

fn space_list(raw: &str) -> Vec<String> {
    raw.split(' ')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub(super) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let form = match read_form(&headers, body).await {
        Ok(form) => form,
        Err(why) => return invalid_request(why),
    };
    if form.repeated(&["resource"]) {
        return invalid_request("a parameter is repeated");
    }
    let grant_type = match form.get("grant_type") {
        Some(g @ (AUTHORIZATION_CODE | REFRESH_TOKEN | DEVICE_CODE_GRANT)) => g,
        Some(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "only authorization_code, refresh_token and the device code grant are supported",
            );
        }
        None => return invalid_request("grant_type is missing"),
    };
    let oauth = &state.oauth;
    let client = match authenticate_client(oauth, &headers, &form, false).await {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    let Some(client_id) = client.client_id.as_deref() else {
        return server_error();
    };
    if !allows_grant(&client, grant_type) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client is not registered for this grant type",
        );
    }

    let now = Utc::now();
    let resource = form.all("resource");
    let result = match grant_type {
        AUTHORIZATION_CODE => {
            let Some(code) = form.get("code") else {
                return invalid_request("code is missing");
            };
            let x = CodeExchange {
                client_id,
                code,
                redirect_uri: form.get("redirect_uri"),
                code_verifier: form.get("code_verifier"),
                resource: &resource,
                refresh_allowed: allows_grant(&client, REFRESH_TOKEN),
            };
            tokens::redeem_code(&oauth.db, &x, now).await
        }
        REFRESH_TOKEN => {
            let Some(refresh_token) = form.get("refresh_token") else {
                return invalid_request("refresh_token is missing");
            };
            let scope = form.get("scope").map(space_list);
            let x = RefreshExchange {
                client_id,
                refresh_token,
                scope: scope.as_deref(),
                resource: &resource,
            };
            tokens::refresh(&oauth.db, &x, now).await
        }
        _ => {
            let Some(device_code) = form.get("device_code") else {
                return invalid_request("device_code is missing");
            };
            match device::poll(&oauth.db, &client, device_code, &resource, now).await {
                Ok(polled) => match polled.into_issued() {
                    Ok(issued) => Ok(issued),
                    Err((error, description)) => {
                        return json_error(StatusCode::BAD_REQUEST, error, description);
                    }
                },
                Err(e) => Err(e),
            }
        }
    };
    let issued = match result {
        Ok(issued) => issued,
        Err(e) => {
            return match e.downcast_ref::<Invalid>() {
                Some(t) => {
                    tracing::info!(client_id, grant_type, error = %t, "oauth token request refused");
                    json_error(StatusCode::BAD_REQUEST, t.code(), t.description())
                }
                None => {
                    tracing::error!(error = ?e, client_id, grant_type, "oauth token request failed");
                    server_error()
                }
            };
        }
    };
    match mint(oauth, client_id, &issued, now).await {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = ?e, client_id, "minting oauth tokens failed");
            server_error()
        }
    }
}

/// Every claim name a registry row copies into access tokens. A failed read promotes none: the
/// claims stay under `ext`.
async fn promoted_claims(db: &DbPool) -> Vec<String> {
    match crate::resource_registry::list_enabled_claims(db).await {
        Ok(rows) => rows.into_iter().flat_map(|(_, claims)| claims).collect(),
        Err(e) => {
            tracing::error!(error = ?e, "resource registry claims read failed; promoting none");
            Vec::new()
        }
    }
}

/// The token response for `issued`; an ID token when this response's scope holds `openid`.
pub(super) async fn mint(
    oauth: &NativeOAuth,
    client_id: &str,
    issued: &Issued,
    now: DateTime<Utc>,
) -> Result<Value> {
    let keys = &oauth.keys()?;
    let promoted = promoted_claims(&oauth.db).await;
    let access_snapshot: Map<String, Value> = from_json(&issued.grant.access_token_claims)?;
    let id_snapshot = match from_json::<Value>(&issued.grant.id_token_claims)? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let now = now.timestamp();
    let access_claims = jwt::access_token_claims(&AccessTokenFor {
        issuer: &oauth.issuer,
        subject: &issued.grant.subject,
        client_id,
        audience: &issued.audience,
        scope: &issued.scope,
        acr: issued.acr.as_deref(),
        grant_id: &issued.grant.id,
        snapshot: &access_snapshot,
        promoted: &promoted,
        now,
    });
    let access_token = jwt::sign(keys, Typ::AccessToken, &access_claims)?;
    let mut body = json!({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECS,
        "scope": issued.scope.join(" "),
    });
    if issued.scope.iter().any(|s| s == "openid") {
        let id_claims = jwt::id_token_claims(&IdTokenFor {
            issuer: &oauth.issuer,
            subject: &issued.grant.subject,
            client_id,
            sid: &issued.session_id,
            auth_time: issued.auth_time.timestamp(),
            acr: issued.acr.as_deref(),
            amr: &issued.amr,
            nonce: issued.nonce.as_deref(),
            access_token: &access_token,
            snapshot: &id_snapshot,
            now,
        });
        body["id_token"] = json!(jwt::sign(keys, Typ::IdToken, &id_claims)?);
    }
    if let Some(refresh_token) = &issued.refresh_token {
        body["refresh_token"] = json!(refresh_token);
    }
    Ok(body)
}

#[cfg(test)]
mod tests;
