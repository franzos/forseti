//! Signed `forseti_brand_hint` cookie: display-only, never authoritative.

use axum::http::HeaderMap;

use crate::signed_cookie::{unix_seconds_now, SignedCookie};

const BRAND_HINT_COOKIE: &str = "forseti_brand_hint";
const BRAND_HINT_SALT: &[u8] = b"forseti::brand_hint::v1";
const BRAND_HINT_TTL_SECS: u64 = 600;

fn codec<'a>(secure: bool) -> SignedCookie<'a> {
    SignedCookie {
        name: BRAND_HINT_COOKIE,
        salt: BRAND_HINT_SALT,
        ttl_secs: BRAND_HINT_TTL_SECS,
        secure,
        path: "/registration",
    }
}

/// Build a `Set-Cookie` header value hinting `slug` as the org to theme registration for.
#[allow(dead_code)]
pub fn set_brand_hint(secret: &[u8], slug: &str, secure: bool) -> String {
    let c = codec(secure);
    let encoded = c.encode(secret, slug.as_bytes(), unix_seconds_now());
    c.set_header(&encoded)
}

/// Read + verify the brand-hint cookie. `None` on any failure.
pub fn read_brand_hint(headers: &HeaderMap, secret: &[u8]) -> Option<String> {
    let payload = codec(false).decode(secret, headers, unix_seconds_now())?;
    String::from_utf8(payload).ok()
}

/// `Set-Cookie` line that clears the brand-hint cookie.
#[allow(dead_code)]
pub fn clear_brand_hint(secure: bool) -> String {
    codec(secure).clear_header()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    const SECRET: &[u8] = b"brand-hint-test-secret";

    fn cookie_value_from_set_cookie(sc: &str) -> String {
        let after_eq = sc.split_once('=').unwrap().1;
        after_eq.split(';').next().unwrap().to_string()
    }

    fn headers_with_brand_hint(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            format!("{}={}", BRAND_HINT_COOKIE, value).parse().unwrap(),
        );
        h
    }

    #[test]
    fn round_trip_returns_slug() {
        let sc = set_brand_hint(SECRET, "acme-corp", false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_brand_hint(&value);
        assert_eq!(
            read_brand_hint(&headers, SECRET).as_deref(),
            Some("acme-corp")
        );
    }

    #[test]
    fn tampered_mac_returns_none() {
        let sc = set_brand_hint(SECRET, "acme-corp", false);
        let value = cookie_value_from_set_cookie(&sc);
        let mut bytes = value.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(bytes).unwrap();
        let headers = headers_with_brand_hint(&tampered);
        assert!(read_brand_hint(&headers, SECRET).is_none());
    }

    #[test]
    fn missing_cookie_returns_none() {
        let headers = HeaderMap::new();
        assert!(read_brand_hint(&headers, SECRET).is_none());
    }

    #[test]
    fn different_secret_rejects_signature() {
        let sc = set_brand_hint(b"secret-a", "acme-corp", false);
        let value = cookie_value_from_set_cookie(&sc);
        let headers = headers_with_brand_hint(&value);
        assert!(read_brand_hint(&headers, b"secret-b").is_none());
    }

    #[test]
    fn set_cookie_scoped_to_registration_path() {
        let sc = set_brand_hint(SECRET, "acme-corp", false);
        assert!(sc.contains("Path=/registration"));
    }

    #[test]
    fn set_cookie_secure_flag_respected() {
        let sc = set_brand_hint(SECRET, "acme-corp", true);
        assert!(sc.contains("Secure"));
        let sc_plain = set_brand_hint(SECRET, "acme-corp", false);
        assert!(!sc_plain.contains("Secure"));
    }
}
