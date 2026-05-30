//! Signed `app_referrer` cookie for RP-initiated account management.
//!
//! Set by the `/handoff` entry endpoint when an external OAuth client
//! deep-links a user into a Forseti settings surface. Drives the
//! "Continuing from <App>" banner rendered above the navigation.
//!
//! Backed by [`crate::signed_cookie`]; the salt is distinct from
//! flash / active_org so the three cookie types never share signing
//! material. The payload is JSON-serialised before the codec runs its
//! hex-encode + HMAC envelope.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::signed_cookie::{unix_seconds_now, SignedCookie};

const APP_REFERRER_COOKIE: &str = "forseti_app_referrer";
const APP_REFERRER_SALT: &[u8] = b"forseti::app_referrer::v1";

/// Decoded payload of the `forseti_app_referrer` cookie. Fields are what
/// the banner needs to render plus the URI the "Return to <App>" button
/// targets. `logo_uri` is optional because Hydra clients aren't required
/// to set one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReferrerPayload {
    pub client_id: String,
    pub client_name: String,
    pub logo_uri: Option<String>,
    pub referrer_uri: String,
}

fn codec<'a>(ttl_secs: u64, secure: bool) -> SignedCookie<'a> {
    SignedCookie {
        name: APP_REFERRER_COOKIE,
        salt: APP_REFERRER_SALT,
        ttl_secs,
        secure,
        path: "/",
    }
}

/// Read + verify the app-referrer cookie. Returns the decoded payload
/// when the cookie is present, well-formed, signed, and inside TTL. Any
/// failure → `None` (caller silently omits the banner).
pub fn read_referrer_cookie(
    headers: &HeaderMap,
    secret: &[u8],
    ttl_secs: u64,
) -> Option<ReferrerPayload> {
    let payload = codec(ttl_secs, false).decode(secret, headers, unix_seconds_now())?;
    serde_json::from_slice::<ReferrerPayload>(&payload).ok()
}

/// Build a `Set-Cookie` header value carrying the encoded referrer
/// payload. Path `/`, HttpOnly, SameSite=Lax, Secure when Forseti is
/// HTTPS.
pub fn set_referrer_cookie(
    secret: &[u8],
    ttl_secs: u64,
    payload: &ReferrerPayload,
    secure: bool,
) -> String {
    let c = codec(ttl_secs, secure);
    let json = serde_json::to_vec(payload).expect("ReferrerPayload always serialises");
    let encoded = c.encode(secret, &json, unix_seconds_now());
    c.set_header(&encoded)
}

/// Build a `Set-Cookie` header value that clears the app-referrer
/// cookie. Used by the dismiss + return endpoints.
pub fn clear_referrer_cookie(secure: bool) -> String {
    codec(0, secure).clear_header()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    const SECRET: &[u8] = b"app-referrer-test-secret";
    const TTL: u64 = 60 * 60;

    fn sample_payload() -> ReferrerPayload {
        ReferrerPayload {
            client_id: "bankapp".into(),
            client_name: "Bank".into(),
            logo_uri: Some("https://bank.app/logo.png".into()),
            referrer_uri: "https://bank.app/account".into(),
        }
    }

    fn cookie_value_from_set_cookie(sc: &str) -> String {
        let after_eq = sc.split_once('=').unwrap().1;
        after_eq.split(';').next().unwrap().to_string()
    }

    fn headers_with_app_referrer(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            format!("{}={}", APP_REFERRER_COOKIE, value)
                .parse()
                .unwrap(),
        );
        h
    }

    #[test]
    fn round_trip_returns_payload() {
        let payload = sample_payload();
        let sc = set_referrer_cookie(SECRET, TTL, &payload, false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_app_referrer(&value);
        assert_eq!(
            read_referrer_cookie(&headers, SECRET, TTL).as_ref(),
            Some(&payload),
        );
    }

    #[test]
    fn round_trip_without_logo_uri() {
        let mut payload = sample_payload();
        payload.logo_uri = None;
        let sc = set_referrer_cookie(SECRET, TTL, &payload, false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_app_referrer(&value);
        assert_eq!(
            read_referrer_cookie(&headers, SECRET, TTL).as_ref(),
            Some(&payload),
        );
    }

    #[test]
    fn tampered_mac_returns_none() {
        let sc = set_referrer_cookie(SECRET, TTL, &sample_payload(), false);
        let value = cookie_value_from_set_cookie(&sc);
        let mut bytes = value.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(bytes).unwrap();
        let headers = headers_with_app_referrer(&tampered);
        assert!(read_referrer_cookie(&headers, SECRET, TTL).is_none());
    }

    #[test]
    fn missing_cookie_returns_none() {
        let headers = HeaderMap::new();
        assert!(read_referrer_cookie(&headers, SECRET, TTL).is_none());
    }

    #[test]
    fn different_secret_rejects_signature() {
        let sc = set_referrer_cookie(b"secret-a", TTL, &sample_payload(), false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_app_referrer(&value);
        assert!(read_referrer_cookie(&headers, b"secret-b", TTL).is_none());
    }

    #[test]
    fn set_cookie_secure_flag_respected() {
        let sc_secure = set_referrer_cookie(SECRET, TTL, &sample_payload(), true);
        assert!(sc_secure.contains("Secure"));
        let sc_plain = set_referrer_cookie(SECRET, TTL, &sample_payload(), false);
        assert!(!sc_plain.contains("Secure"));
    }

    #[test]
    fn clear_cookie_emits_expired_directive() {
        let sc = clear_referrer_cookie(false);
        assert!(sc.contains(APP_REFERRER_COOKIE));
        assert!(sc.contains("Expires=Thu, 01 Jan 1970"));
    }
}
