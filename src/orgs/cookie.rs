//! Signed `active_org` cookie carrying the selected org id.
//!
//! Distinct salt so flash / active_org / app_referrer cookies never share
//! signing material. Not authoritative: handlers cross-check the value
//! against `organization_members`, so a forged cookie naming an org the
//! user isn't in falls back to the first membership.

use axum::http::HeaderMap;

use crate::signed_cookie::{unix_seconds_now, SignedCookie};

const ACTIVE_ORG_COOKIE: &str = "forseti_active_org";
const ACTIVE_ORG_SALT: &[u8] = b"forseti::active_org::v1";

fn codec<'a>(ttl_secs: u64, secure: bool) -> SignedCookie<'a> {
    SignedCookie {
        name: ACTIVE_ORG_COOKIE,
        salt: ACTIVE_ORG_SALT,
        ttl_secs,
        secure,
        path: "/",
    }
}

/// Read + verify the active-org cookie. `None` on any failure (caller falls
/// back to the first membership).
pub fn read_active_org_cookie(headers: &HeaderMap, secret: &[u8], ttl_secs: u64) -> Option<String> {
    let payload = codec(ttl_secs, false).decode(secret, headers, unix_seconds_now())?;
    String::from_utf8(payload).ok()
}

/// `Set-Cookie` line that clears the active-org pin.
pub fn clear_active_org_cookie(secure: bool) -> String {
    codec(0, secure).clear_header()
}

/// Build a `Set-Cookie` header value pinning `org_id` as the active org.
pub fn set_active_org_cookie(secret: &[u8], ttl_secs: u64, org_id: &str, secure: bool) -> String {
    let c = codec(ttl_secs, secure);
    let encoded = c.encode(secret, org_id.as_bytes(), unix_seconds_now());
    c.set_header(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    const SECRET: &[u8] = b"active-org-test-secret";
    const TTL: u64 = 60 * 60 * 24 * 30;

    fn cookie_value_from_set_cookie(sc: &str) -> String {
        let after_eq = sc.split_once('=').unwrap().1;
        after_eq.split(';').next().unwrap().to_string()
    }

    fn headers_with_active_org(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            format!("{}={}", ACTIVE_ORG_COOKIE, value).parse().unwrap(),
        );
        h
    }

    #[test]
    fn round_trip_returns_org_id() {
        let sc = set_active_org_cookie(SECRET, TTL, "org-abc-123", false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_active_org(&value);
        assert_eq!(
            read_active_org_cookie(&headers, SECRET, TTL).as_deref(),
            Some("org-abc-123"),
        );
    }

    #[test]
    fn tampered_mac_returns_none() {
        let sc = set_active_org_cookie(SECRET, TTL, "org-abc-123", false);
        let value = cookie_value_from_set_cookie(&sc);
        let mut bytes = value.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(bytes).unwrap();
        let headers = headers_with_active_org(&tampered);
        assert!(read_active_org_cookie(&headers, SECRET, TTL).is_none());
    }

    #[test]
    fn missing_cookie_returns_none() {
        let headers = HeaderMap::new();
        assert!(read_active_org_cookie(&headers, SECRET, TTL).is_none());
    }

    #[test]
    fn different_secret_rejects_signature() {
        let sc = set_active_org_cookie(b"secret-a", TTL, "org-abc", false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_active_org(&value);
        assert!(read_active_org_cookie(&headers, b"secret-b", TTL).is_none());
    }

    #[test]
    fn set_cookie_secure_flag_respected() {
        let sc = set_active_org_cookie(SECRET, TTL, "org-abc", true);
        assert!(sc.contains("Secure"));
        let sc_plain = set_active_org_cookie(SECRET, TTL, "org-abc", false);
        assert!(!sc_plain.contains("Secure"));
    }
}
