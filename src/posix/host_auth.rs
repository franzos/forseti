//! HTTP Basic authentication for enrolled hosts on the `/posix/v1/*`
//! resolver API. Credentials are `host_id:secret`; the secret is compared
//! against the stored SHA-256 hash in constant time so a probing client
//! can't time its way to a valid secret.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use subtle::ConstantTimeEq;

use crate::oauth::register::hash_token;
use crate::posix::db;
use crate::state::AppState;

/// An authenticated host enrollment, handed to resolver handlers as a typed
/// argument once HTTP Basic has validated the `host_id:secret` pair.
pub struct RequirePosixHost {
    pub host_id: String,
    pub allowed_gid: Option<u32>,
    pub force_mfa: bool,
}

/// Parse a `Basic <base64(host_id:secret)>` header into its credential pair.
/// Any deviation — wrong scheme, bad base64, non-utf8, no `:` — yields `None`.
fn parse_basic(header: &str) -> Option<(String, String)> {
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = BASE64.decode(encoded).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (id, secret) = creds.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic")],
        "",
    )
        .into_response()
}

impl<S> FromRequestParts<S> for RequirePosixHost
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = crate::extractors::app_state(parts, state).await;

        let Some((host_id, secret)) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_basic)
        else {
            return Err(unauthorized());
        };

        let row = match db::host_by_id(&app_state.db, &host_id).await {
            Ok(Some(row)) => row,
            // Unknown host and bad secret return the same 401 — never leak
            // which of the two it was.
            Ok(None) => return Err(unauthorized()),
            Err(e) => {
                tracing::error!(error = ?e, host_id, "posix host auth: db lookup failed");
                return Err(unauthorized());
            }
        };

        // Constant-time compare of the hex hashes so an attacker can't time
        // their way to a valid secret. ct_eq is false on length mismatch.
        let computed = hash_token(&secret);
        if !bool::from(row.secret_hash.as_bytes().ct_eq(computed.as_bytes())) {
            return Err(unauthorized());
        }

        // Throttle the last_seen write: skip it unless the row is stale
        // (>60s) so a busy resolver doesn't issue a write per lookup.
        // Best-effort — a failed touch must never fail the request.
        let now = Utc::now();
        let stale = row
            .last_seen_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|seen| (now - seen.with_timezone(&Utc)).num_seconds() > 60)
            .unwrap_or(true);
        if stale {
            if let Err(e) = db::touch_last_seen(&app_state.db, &host_id, &now.to_rfc3339()).await {
                tracing::warn!(error = ?e, host_id, "posix host auth: last_seen touch failed");
            }
        }

        Ok(RequirePosixHost {
            host_id,
            allowed_gid: row.allowed_gid.map(|g| g as u32),
            force_mfa: row.force_mfa != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_basic_header() {
        // base64("host-1:s3cret") = "aG9zdC0xOnMzY3JldA=="
        assert_eq!(
            parse_basic("Basic aG9zdC0xOnMzY3JldA=="),
            Some(("host-1".to_string(), "s3cret".to_string()))
        );
        assert_eq!(parse_basic("Bearer aG9zdC0xOnMzY3JldA=="), None);
        assert_eq!(parse_basic("Basic !!!notbase64"), None);
        assert_eq!(parse_basic("garbage"), None);
        // base64("host-1") = "aG9zdC0x" — no colon, so no credential pair.
        assert_eq!(parse_basic("Basic aG9zdC0x"), None);
        // base64("host-1:a:b") = "aG9zdC0xOmE6Yg==" — split on the first colon.
        assert_eq!(
            parse_basic("Basic aG9zdC0xOmE6Yg=="),
            Some(("host-1".to_string(), "a:b".to_string()))
        );
    }
}
