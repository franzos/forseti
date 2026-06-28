//! Server-side flash storage for one-shot reveals and short-lived redirect banners.
//!
//! 1. Secret reveal store ([`store_secret_reveal`] / [`take_secret_reveal`]): a Forseti-owned DB table keyed
//!    by an opaque token so secrets never ride the redirect URL (history/logs/CDN). Single-use; DB-backed so
//!    a multi-instance deployment can mint on one node and reveal on another.
//! 2. Flash cookie ([`store_flash`] / [`take_flash`]): a one-shot, HMAC-signed, path-scoped cookie the next
//!    render reads and clears. Tampering invalidates the HMAC and the cookie is dropped.
//!
//! The cookie HMAC key derives from `[security].cookie_secret` plus a per-cookie salt (see [`crate::signed_cookie`]).

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::secret_reveals;
use crate::signed_cookie::{unix_seconds_now, SignedCookie};

/// Revealed-secret payload, serialised as a `"kind"`-tagged JSON object in `secret_reveals.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretReveal {
    /// `/admin/clients` create: Hydra returns both the client secret AND
    /// a registration access token in one response. Either field may be
    /// empty when Hydra didn't mint one (e.g. public clients have no
    /// secret).
    ClientCreated {
        secret: String,
        registration_access_token: String,
        #[serde(default)]
        setup_note: String,
    },
    /// `/admin/clients/{id}/rotate-secret`: fresh client secret.
    ClientSecretRotated { secret: String },
    /// `/admin/identities/{id}/recovery`: Kratos recovery code + the matching recovery URL.
    RecoveryCode { code: String, link: String },
    /// `/admin/dcr-tokens` issue: raw Initial Access Token (shown once; only the hash is persisted).
    DcrInitialAccessToken { token: String },
    /// `/admin/hosts` enroll / rotate: `host_id` plus the raw host secret (shown once; only the hash is persisted).
    HostSecret { host_id: String, secret: String },
    /// `/claim-email` mint: 6-digit code + the target identity id the confirm step deletes on match.
    ClaimEmailCode { code: String, identity_id: String },
}

#[derive(Insertable)]
#[diesel(table_name = secret_reveals)]
struct NewReveal {
    token: String,
    payload: String,
    created_at: String,
}

// `Selectable` selects all columns; only `payload` is read back.
#[allow(dead_code)]
#[derive(Queryable, Selectable)]
#[diesel(table_name = secret_reveals)]
struct RevealRow {
    token: String,
    payload: String,
    created_at: String,
}

fn prune_cutoff(ttl_seconds: u64) -> String {
    (Utc::now() - chrono::Duration::seconds(ttl_seconds as i64)).to_rfc3339()
}

/// Store a reveal payload and return an opaque token to embed in the redirect URL (treat like a session id).
/// `reveal_ttl_seconds` drives best-effort pruning of stale rows on the same call.
pub async fn store_secret_reveal(
    db: &DbPool,
    reveal_ttl_seconds: u64,
    reveal: SecretReveal,
) -> anyhow::Result<String> {
    let token = random_token();
    let payload = serde_json::to_string(&reveal).map_err(|e| {
        tracing::error!(error = ?e, "secret_reveal: serialise failed");
        anyhow::anyhow!("serialise reveal payload: {e}")
    })?;
    let row = NewReveal {
        token: token.clone(),
        payload,
        created_at: Utc::now().to_rfc3339(),
    };
    let prune = prune_cutoff(reveal_ttl_seconds);
    let result: anyhow::Result<()> = async {
        db_interact!(db, |conn| {
            conn.transaction::<_, diesel::result::Error, _>(|c| {
                diesel::delete(secret_reveals::table.filter(secret_reveals::created_at.lt(&prune)))
                    .execute(c)?;
                diesel::insert_into(secret_reveals::table)
                    .values(&row)
                    .execute(c)?;
                Ok(())
            })
        })?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::error!(error = ?e, "secret_reveal: insert failed");
        return Err(e);
    }
    Ok(token)
}

/// Peek at the reveal for `token` without consuming it, returning the payload and current `attempts`.
/// For one-time-code flows: peek to compare, then [`take_secret_reveal`] on success or
/// [`bump_secret_reveal_attempts`] on failure. `None` for unknown / expired / failed tokens.
pub async fn peek_secret_reveal(
    db: &DbPool,
    reveal_ttl_seconds: u64,
    token: &str,
) -> Option<(SecretReveal, i32)> {
    let row = match peek_secret_reveal_inner(db, reveal_ttl_seconds, token).await {
        Ok(r) => r?,
        Err(e) => {
            tracing::error!(error = ?e, "secret_reveal: peek failed");
            return None;
        }
    };
    match serde_json::from_str::<SecretReveal>(&row.0) {
        Ok(r) => Some((r, row.1)),
        Err(e) => {
            tracing::error!(error = ?e, "secret_reveal: deserialise failed");
            None
        }
    }
}

async fn peek_secret_reveal_inner(
    db: &DbPool,
    reveal_ttl_seconds: u64,
    token: &str,
) -> anyhow::Result<Option<(String, i32)>> {
    let token = token.to_string();
    let prune = prune_cutoff(reveal_ttl_seconds);
    let result: Option<(String, i32)> = db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(secret_reveals::table.filter(secret_reveals::created_at.lt(&prune)))
                .execute(c)?;
            let row: Option<(String, i32)> = secret_reveals::table
                .filter(secret_reveals::token.eq(&token))
                .select((secret_reveals::payload, secret_reveals::attempts))
                .first(c)
                .optional()?;
            Ok(row)
        })
    })?;
    Ok(result)
}

/// Increment the per-row attempt counter, deleting the row at `>= max_attempts`. Returns `Ok(true)` when
/// exhausted (deleted), `Ok(false)` when still in budget. The atomic `SET attempts = attempts + 1` (not a
/// read-modify-write) takes a row lock so two concurrent wrong-code submissions can't both write `N+1` under
/// READ COMMITTED and double the grind budget.
pub async fn bump_secret_reveal_attempts(
    db: &DbPool,
    token: &str,
    max_attempts: i32,
) -> anyhow::Result<bool> {
    let token = token.to_string();
    let exhausted: bool = db_interact!(db, |conn| {
        conn.transaction::<bool, diesel::result::Error, _>(|c| {
            let updated =
                diesel::update(secret_reveals::table.filter(secret_reveals::token.eq(&token)))
                    .set(secret_reveals::attempts.eq(secret_reveals::attempts + 1))
                    .execute(c)?;
            if updated == 0 {
                return Ok(true);
            }
            let next: Option<i32> = secret_reveals::table
                .filter(secret_reveals::token.eq(&token))
                .select(secret_reveals::attempts)
                .first(c)
                .optional()?;
            let Some(next) = next else {
                return Ok(true);
            };
            if next >= max_attempts {
                diesel::delete(secret_reveals::table.filter(secret_reveals::token.eq(&token)))
                    .execute(c)?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    })?;
    Ok(exhausted)
}

/// Take the reveal for `token`, deleting it on success (single-use, enforced by SELECT + DELETE in one transaction).
/// `None` for unknown / expired / failed tokens.
pub async fn take_secret_reveal(
    db: &DbPool,
    reveal_ttl_seconds: u64,
    token: &str,
) -> Option<SecretReveal> {
    let payload = match take_secret_reveal_inner(db, reveal_ttl_seconds, token).await {
        Ok(p) => p?,
        Err(e) => {
            tracing::error!(error = ?e, "secret_reveal: take failed");
            return None;
        }
    };
    match serde_json::from_str::<SecretReveal>(&payload) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::error!(error = ?e, "secret_reveal: deserialise failed");
            None
        }
    }
}

async fn take_secret_reveal_inner(
    db: &DbPool,
    reveal_ttl_seconds: u64,
    token: &str,
) -> anyhow::Result<Option<String>> {
    let token = token.to_string();
    let prune = prune_cutoff(reveal_ttl_seconds);
    let payload: Option<String> = db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(secret_reveals::table.filter(secret_reveals::created_at.lt(&prune)))
                .execute(c)?;
            let row: Option<RevealRow> = secret_reveals::table
                .filter(secret_reveals::token.eq(&token))
                .select(RevealRow::as_select())
                .first(c)
                .optional()?;
            if row.is_some() {
                diesel::delete(secret_reveals::table.filter(secret_reveals::token.eq(&token)))
                    .execute(c)?;
            }
            Ok(row.map(|r| r.payload))
        })
    })?;
    Ok(payload)
}

fn random_token() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::rng().random();
    hex::encode(bytes)
}

// --- Flash cookie ---------------------------------------------------------

const FLASH_COOKIE_NAME: &str = "forseti_flash";
const FLASH_SALT: &[u8] = b"forseti::flash::v1";

fn flash_codec<'a>(path: &'a str, ttl_secs: u64, secure: bool) -> SignedCookie<'a> {
    SignedCookie {
        name: FLASH_COOKIE_NAME,
        salt: FLASH_SALT,
        ttl_secs,
        secure,
        path,
    }
}

/// Store a flash message to be displayed on the next page-load matching
/// `path`. Returns the `Set-Cookie` header value to append to the
/// redirect response.
pub fn store_flash(
    secret: &[u8],
    cookie_ttl_seconds: u64,
    path: &str,
    msg: &str,
    secure: bool,
) -> String {
    let codec = flash_codec(path, cookie_ttl_seconds, secure);
    let encoded = codec.encode(secret, msg.as_bytes(), unix_seconds_now());
    codec.set_header(&encoded)
}

/// Read and validate the flash cookie. Returns `(msg, clear_cookie_header)`:
///   * `msg` is the previously-stored flash text, if present and valid.
///   * `clear_cookie_header` is a `Set-Cookie: ...; Max-Age=0` directive
///     the caller should append to the response so the cookie is consumed
///     (one-shot semantics).
pub fn take_flash(
    headers: &HeaderMap,
    secret: &[u8],
    cookie_ttl_seconds: u64,
    path: &str,
    secure: bool,
) -> (String, Option<String>) {
    let codec = flash_codec(path, cookie_ttl_seconds, secure);
    let raw = crate::cookies::read_cookie(headers, FLASH_COOKIE_NAME);
    let Some(payload) = codec.decode(secret, headers, unix_seconds_now()) else {
        return (String::new(), raw.map(|_| codec.clear_header()));
    };
    let msg = String::from_utf8(payload).unwrap_or_default();
    (msg, Some(codec.clear_header()))
}

// --- Response helpers ----------------------------------------------------

/// 303 redirect to `target` carrying one `Set-Cookie` (typically from [`store_flash`]). A malformed cookie is dropped.
pub(crate) fn redirect_with_cookie(target: &str, cookie: &str) -> Response {
    let mut resp = Redirect::to(target).into_response();
    if let Ok(hv) = axum::http::HeaderValue::from_str(cookie) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, hv);
    }
    resp
}

/// Append an optional `Set-Cookie` (e.g. the flash-clear from [`take_flash`]) to a response. No-op on `None`.
pub(crate) fn attach_set_cookie(mut resp: Response, cookie: Option<String>) -> Response {
    crate::web::append_set_cookie(&mut resp, cookie);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;
    use axum::http::HeaderMap;

    const SECRET: &[u8] = b"flash-test-secret";
    const TTL: u64 = 60;

    fn cookie_value_from_set_cookie(sc: &str) -> String {
        let after_eq = sc.split_once('=').unwrap().1;
        after_eq.split(';').next().unwrap().to_string()
    }

    fn headers_with_flash(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            format!("{}={}", FLASH_COOKIE_NAME, value).parse().unwrap(),
        );
        h
    }

    #[test]
    fn flash_round_trip_returns_message() {
        let sc = store_flash(SECRET, TTL, "/admin", "Saved.", false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_flash(&value);
        let (msg, clear) = take_flash(&headers, SECRET, TTL, "/admin", false);
        assert_eq!(msg, "Saved.");
        assert!(clear.is_some());
        assert!(clear.unwrap().contains("Expires=Thu, 01 Jan 1970"));
    }

    #[test]
    fn flash_round_trip_survives_dots_in_payload() {
        let payload = "Saved profile. Welcome back.";
        let sc = store_flash(SECRET, TTL, "/admin", payload, false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_flash(&value);
        let (msg, _) = take_flash(&headers, SECRET, TTL, "/admin", false);
        assert_eq!(msg, payload);
    }

    #[test]
    fn flash_tampered_mac_fails() {
        let sc = store_flash(SECRET, TTL, "/admin", "Saved.", false);
        let value = cookie_value_from_set_cookie(&sc);
        let mut bytes: Vec<u8> = value.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(bytes).unwrap();
        let headers = headers_with_flash(&tampered);
        let (msg, clear) = take_flash(&headers, SECRET, TTL, "/admin", false);
        assert_eq!(msg, "");
        assert!(clear.is_some());
    }

    #[test]
    fn flash_missing_cookie_returns_empty() {
        let headers = HeaderMap::new();
        let (result, clear) = take_flash(&headers, SECRET, TTL, "/admin", false);
        assert_eq!(result, "");
        assert!(clear.is_none());
    }

    #[test]
    fn flash_cookie_secure_flag_respected() {
        let sc = store_flash(SECRET, TTL, "/admin", "Saved.", true);
        assert!(sc.contains("Secure"));
        let sc_plain = store_flash(SECRET, TTL, "/admin", "Saved.", false);
        assert!(!sc_plain.contains("Secure"));
    }

    #[test]
    fn flash_different_secret_rejects_signature() {
        let sc = store_flash(b"secret-a", TTL, "/admin", "Saved.", false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_flash(&value);
        let (msg, _) = take_flash(&headers, b"secret-b", TTL, "/admin", false);
        assert_eq!(msg, "");
    }
}
