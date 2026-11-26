//! The userinfo endpoint (OIDC Core section 5.3): `sub` and the consent-time ID token claims of
//! the grant an access token names, unless the token was revoked. Bearer token use and errors
//! follow RFC 6750.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::jwt::Typ;
use super::token_endpoint::{json_error, read_form, server_error};
use super::{from_json, revocation};
use crate::state::AppState;

pub(super) const USERINFO_PATH: &str = "/userinfo";

/// RFC 6750 section 3: the error, if any, goes into the `Bearer` challenge as well.
fn bearer_error(status: StatusCode, error: Option<&str>, description: &str) -> Response {
    let challenge = match (error, status) {
        (Some(e), StatusCode::FORBIDDEN) => format!("Bearer error=\"{e}\", scope=\"openid\""),
        (Some(e), _) => format!("Bearer error=\"{e}\""),
        (None, _) => "Bearer".to_string(),
    };
    let mut resp = json_error(status, error.unwrap_or("invalid_token"), description);
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    resp
}

fn invalid_token() -> Response {
    bearer_error(
        StatusCode::UNAUTHORIZED,
        Some("invalid_token"),
        "the access token is invalid, expired or revoked",
    )
}

fn invalid_request(description: &str) -> Response {
    bearer_error(
        StatusCode::BAD_REQUEST,
        Some("invalid_request"),
        description,
    )
}

/// `None` without a Bearer `Authorization` header; `Some(None)` for an empty one.
fn bearer_header(headers: &HeaderMap) -> Option<Option<String>> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    Some((!token.is_empty()).then(|| token.to_string()))
}

pub(super) async fn get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match bearer_header(&headers) {
        Some(Some(token)) => answer(&state, &token).await,
        Some(None) => invalid_token(),
        None => missing_token(),
    }
}

/// RFC 6750 section 2.2: the token may also come as the `access_token` form field, never both.
pub(super) async fn post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let header_token = bearer_header(&headers);
    let body_token = if headers.contains_key(header::CONTENT_TYPE) {
        match read_form(&headers, body).await {
            Ok(form) if form.repeated(&[]) => {
                return invalid_request("a parameter is repeated");
            }
            Ok(form) => form.get("access_token").map(str::to_string),
            Err(_) if header_token.is_some() => None,
            Err(why) => return invalid_request(why),
        }
    } else {
        None
    };
    match (header_token, body_token) {
        (Some(_), Some(_)) => invalid_request("the access token was sent more than once"),
        (Some(Some(token)), None) | (None, Some(token)) => answer(&state, &token).await,
        (Some(None), None) => invalid_token(),
        (None, None) => missing_token(),
    }
}

fn missing_token() -> Response {
    bearer_error(
        StatusCode::UNAUTHORIZED,
        None,
        "an access token is required",
    )
}

async fn answer(state: &AppState, token: &str) -> Response {
    let oauth = &state.oauth;
    let Ok(claims) = oauth.verify_jwt(token, Typ::AccessToken, None).await else {
        return invalid_token();
    };
    let has_openid = claims["scope"]
        .as_str()
        .is_some_and(|s| s.split(' ').any(|v| v == "openid"));
    if !has_openid {
        return bearer_error(
            StatusCode::FORBIDDEN,
            Some("insufficient_scope"),
            "the access token lacks the openid scope",
        );
    }
    let grant = match revocation::live_grant(&oauth.db, &claims).await {
        Ok(Some(g)) => g,
        Ok(None) => return invalid_token(),
        Err(e) => {
            tracing::error!(error = ?e, "oauth grant lookup failed");
            return server_error();
        }
    };
    let mut info = match from_json::<Value>(&grant.id_token_claims) {
        Ok(Value::Object(m)) => m,
        Ok(_) => serde_json::Map::new(),
        Err(e) => {
            tracing::error!(error = ?e, "oauth grant claims unreadable");
            return server_error();
        }
    };
    info.insert("sub".to_string(), json!(grant.subject));
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Value::Object(info).to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
