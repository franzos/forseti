//! Token revocation (RFC 7009) and introspection (RFC 7662), the access token denylist in
//! `oauth_revoked_tokens` and the grant-wide revocation instant that userinfo honours as well.

use anyhow::Result;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde_json::{Map, Value, json};

use super::grants::{self, GrantRow};
use super::jwt::Typ;
use super::token_endpoint::{Form, authenticate_client, invalid_request, read_form, server_error};
use super::{NativeOAuth, from_json, parse_time, tokens};
use crate::db::{DbPool, rfc3339};
use crate::db_interact;
use crate::schema::oauth_revoked_tokens;
use crate::state::AppState;

pub(super) const REVOKE_PATH: &str = "/oauth2/revoke";
pub(super) const INTROSPECT_PATH: &str = "/oauth2/introspect";

/// The `jsonwebtoken` default leeway `jwt::verify` keeps: a token verifies this long past `exp`.
const VERIFY_LEEWAY_SECS: i64 = 60;

/// Access token claims RFC 7662 section 2.2 names, copied into an introspection response.
const INTROSPECTED_CLAIMS: [&str; 9] = [
    "scope",
    "client_id",
    "sub",
    "exp",
    "iat",
    "nbf",
    "aud",
    "iss",
    "jti",
];

/// The form of an authenticated revocation or introspection request and its `token`.
async fn authenticated_form(
    oauth: &NativeOAuth,
    headers: &HeaderMap,
    body: Body,
    confidential: bool,
) -> Result<(String, String), Response> {
    let form: Form = read_form(headers, body).await.map_err(invalid_request)?;
    if form.repeated(&[]) {
        return Err(invalid_request("a parameter is repeated"));
    }
    let client = authenticate_client(oauth, headers, &form, confidential).await?;
    let client_id = client.client_id.ok_or_else(server_error)?;
    let token = form
        .get("token")
        .ok_or_else(|| invalid_request("token is missing"))?;
    Ok((client_id, token.to_string()))
}

/// RFC 7009 section 2.2: 200 whether or not anything was revoked. `token_type_hint` is ignored.
pub(super) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let oauth = &state.oauth;
    let (client_id, token) = match authenticated_form(oauth, &headers, body, false).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match revoke_token(oauth, &client_id, &token, Utc::now()).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!(error = ?e, client_id = %client_id, "oauth token revocation failed");
            server_error()
        }
    }
}

/// An access token of `client_id` goes on the denylist; anything else is tried as a refresh token.
async fn revoke_token(
    oauth: &NativeOAuth,
    client_id: &str,
    token: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    if let Ok(claims) = oauth.verify_jwt(token, Typ::AccessToken, None).await {
        if claims["client_id"] == client_id {
            deny(&oauth.db, &claims).await?;
        }
        return Ok(());
    }
    tokens::revoke_refresh(&oauth.db, client_id, token, now).await?;
    Ok(())
}

/// Puts the token's `jti` on the denylist until it no longer verifies.
async fn deny(db: &DbPool, claims: &Value) -> Result<()> {
    let (Some(jti), Some(exp)) = (claims["jti"].as_str(), claims["exp"].as_i64()) else {
        return Ok(());
    };
    let until = exp
        .checked_add(VERIFY_LEEWAY_SECS)
        .and_then(|t| DateTime::from_timestamp(t, 0))
        .ok_or_else(|| anyhow::anyhow!("access token exp out of range"))?;
    let (jti, expires_at) = (jti.to_string(), rfc3339(until));
    db_interact!(db, |c| {
        diesel::insert_into(oauth_revoked_tokens::table)
            .values((
                oauth_revoked_tokens::jti.eq(jti),
                oauth_revoked_tokens::expires_at.eq(expires_at),
            ))
            .on_conflict_do_nothing()
            .execute(c)
    })?;
    Ok(())
}

async fn denied(db: &DbPool, jti: &str) -> Result<bool> {
    let jti = jti.to_string();
    let found = db_interact!(db, |c| {
        oauth_revoked_tokens::table
            .find(jti)
            .select(oauth_revoked_tokens::jti)
            .first::<String>(c)
            .optional()
    })?;
    Ok(found.is_some())
}

/// The grant of a verified access token while the token is in force: the grant exists for the
/// token's subject and client, its tokens were never revoked, and the token's `jti` is not denied.
pub(super) async fn live_grant(db: &DbPool, claims: &Value) -> Result<Option<GrantRow>> {
    let (Some(gid), Some(sub), Some(jti)) = (
        claims["gid"].as_str(),
        claims["sub"].as_str(),
        claims["jti"].as_str(),
    ) else {
        return Ok(None);
    };
    let Some(grant) = grants::find(db, gid)
        .await?
        .filter(|g| g.subject == sub && claims["client_id"] == g.client_id.as_str())
    else {
        return Ok(None);
    };
    // Nothing mints on a grant after a family revoke, so no clock comparison is needed.
    if grant.tokens_revoked_at.is_some() || denied(db, jti).await? {
        return Ok(None);
    }
    Ok(Some(grant))
}

/// RFC 7662 on the internal listener, for confidential clients only. Any of them may introspect
/// any token.
pub(super) async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let oauth = &state.oauth;
    let (client_id, token) = match authenticated_form(oauth, &headers, body, true).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match introspection(oauth, &token, Utc::now()).await {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = ?e, client_id = %client_id, "oauth token introspection failed");
            server_error()
        }
    }
}

/// RFC 7662 section 2.2. An access token is active while it verifies, `exp` is ahead of `now`
/// and [`live_grant`] holds; a refresh token while it is stored, unused and unexpired.
async fn introspection(oauth: &NativeOAuth, token: &str, now: DateTime<Utc>) -> Result<Value> {
    let inactive = json!({ "active": false });
    if let Ok(claims) = oauth.verify_jwt(token, Typ::AccessToken, None).await {
        let unexpired = claims["exp"]
            .as_i64()
            .is_some_and(|exp| exp > now.timestamp());
        if !unexpired || live_grant(&oauth.db, &claims).await?.is_none() {
            return Ok(inactive);
        }
        let mut out = Map::new();
        out.insert("active".into(), json!(true));
        for name in INTROSPECTED_CLAIMS {
            if let Some(v) = claims.get(name) {
                out.insert(name.into(), v.clone());
            }
        }
        out.insert("token_type".into(), json!("bearer"));
        return Ok(Value::Object(out));
    }
    let Some(row) = tokens::find_refresh(&oauth.db, token).await? else {
        return Ok(inactive);
    };
    if row.used_at.is_some() || row.expires_at <= rfc3339(now) {
        return Ok(inactive);
    }
    Ok(json!({
        "active": true,
        "scope": from_json::<Vec<String>>(&row.scope)?.join(" "),
        "client_id": row.client_id,
        "sub": row.subject,
        "exp": parse_time(&row.expires_at)?.timestamp(),
        "iat": parse_time(&row.created_at)?.timestamp(),
        "aud": from_json::<Vec<String>>(&row.audience)?,
        "iss": oauth.issuer,
    }))
}

#[cfg(test)]
mod tests;
