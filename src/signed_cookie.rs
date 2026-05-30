//! HMAC-signed cookie codec shared by every Forseti-owned signed cookie
//! (flash banner, active-org, app-referrer).
//!
//! Cookie value format: `<unix_seconds>.<hex_payload>.<hex_mac>`.
//! Verification recomputes the MAC and rejects on TTL miss, malformed
//! parts, or signature mismatch.
//!
//! The HMAC key per cookie type is derived with HKDF-SHA256 (RFC 5869)
//! from the one operator secret, using the per-cookie `salt` as the
//! `info` context — independent keys per cookie type so compromising one
//! signing key never leaks another.

use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, SameSite};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::cookies::read_cookie;

type HmacSha256 = Hmac<Sha256>;

/// Per-cookie shape: name, key salt, TTL, and `Secure` attribute.
/// Construct one per cookie type and reuse for both encode/decode so the
/// signing and verification paths can never drift.
pub(crate) struct SignedCookie<'a> {
    pub name: &'a str,
    pub salt: &'a [u8],
    pub ttl_secs: u64,
    pub secure: bool,
    pub path: &'a str,
}

impl<'a> SignedCookie<'a> {
    // Per-cookie salt is HKDF `info` (context binding), not the salt input:
    // the operator secret is the only entropy source, so a non-secret
    // randomizing salt buys nothing while `info` is exactly the cookie-type
    // domain separation we want.
    fn derive_key(&self, secret: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, secret)
            .expand(self.salt, &mut key)
            .expect("HKDF expand of 32 bytes is within OKM length bound");
        key
    }

    /// Build the `<ts>.<hex_payload>.<hex_mac>` value (no cookie
    /// attributes — see [`Self::set_header`] for the full `Set-Cookie`
    /// line).
    pub(crate) fn encode(&self, secret: &[u8], payload: &[u8], now_secs: u64) -> String {
        let key = self.derive_key(secret);
        let payload_hex = hex::encode(payload);
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
        mac.update(format!("{now_secs}.{payload_hex}").as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{now_secs}.{payload_hex}.{}", hex::encode(tag))
    }

    /// Read + verify the cookie off `headers`. Returns the decoded
    /// payload bytes on success, `None` on any failure (missing cookie,
    /// malformed envelope, bad hex, TTL miss, signature mismatch).
    pub(crate) fn decode(
        &self,
        secret: &[u8],
        headers: &HeaderMap,
        now_secs: u64,
    ) -> Option<Vec<u8>> {
        let raw = read_cookie(headers, self.name)?;
        let parts: Vec<&str> = raw.splitn(3, '.').collect();
        if parts.len() != 3 {
            return None;
        }
        let ts = parts[0].parse::<u64>().ok()?;
        let payload = hex::decode(parts[1]).ok()?;
        let tag = hex::decode(parts[2]).ok()?;
        if now_secs.saturating_sub(ts) > self.ttl_secs {
            return None;
        }
        let key = self.derive_key(secret);
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        mac.verify_slice(&tag).ok()?;
        Some(payload)
    }

    /// Full `Set-Cookie` value carrying `encoded` (typically the output
    /// of [`Self::encode`]).
    pub(crate) fn set_header(&self, encoded: &str) -> String {
        Cookie::build((self.name.to_string(), encoded.to_string()))
            .path(self.path.to_string())
            .same_site(SameSite::Lax)
            .http_only(true)
            .secure(self.secure)
            .build()
            .to_string()
    }

    /// `Set-Cookie` line that clears the cookie on the browser. Emits an
    /// explicit RFC 1123 `Expires=` in the past so callers don't have to
    /// pull `time` in just for cookie-attribute construction.
    pub(crate) fn clear_header(&self) -> String {
        let mut s = Cookie::build((self.name.to_string(), String::new()))
            .path(self.path.to_string())
            .same_site(SameSite::Lax)
            .http_only(true)
            .secure(self.secure)
            .build()
            .to_string();
        s.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        s
    }
}

/// Seconds since the Unix epoch. Wall-clock; clamps to 0 on a
/// pre-epoch system clock (so the codec stays infallible).
pub(crate) fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    fn sc<'a>() -> SignedCookie<'a> {
        SignedCookie {
            name: "test_cookie",
            salt: b"forseti::test::v1",
            ttl_secs: 60,
            secure: false,
            path: "/",
        }
    }

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, format!("{name}={value}").parse().unwrap());
        h
    }

    #[test]
    fn round_trip_returns_payload() {
        let codec = sc();
        let secret = b"operator-secret-32-bytes-of-key!";
        let now = 1_700_000_000;
        let encoded = codec.encode(secret, b"hello", now);
        let headers = headers_with("test_cookie", &encoded);
        let got = codec.decode(secret, &headers, now);
        assert_eq!(got.as_deref(), Some(b"hello".as_slice()));
    }

    #[test]
    fn tampered_mac_returns_none() {
        let codec = sc();
        let secret = b"operator-secret";
        let now = 1_700_000_000;
        let encoded = codec.encode(secret, b"hello", now);
        let mut b = encoded.into_bytes();
        let last = b.len() - 1;
        b[last] = if b[last] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(b).unwrap();
        let headers = headers_with("test_cookie", &tampered);
        assert!(codec.decode(secret, &headers, now).is_none());
    }

    #[test]
    fn stale_returns_none() {
        let codec = sc();
        let secret = b"operator-secret";
        let encoded = codec.encode(secret, b"hello", 1_700_000_000);
        let headers = headers_with("test_cookie", &encoded);
        assert!(codec.decode(secret, &headers, 1_700_000_000 + 61).is_none());
    }

    #[test]
    fn wrong_secret_returns_none() {
        let codec = sc();
        let encoded = codec.encode(b"secret-a", b"hello", 1_700_000_000);
        let headers = headers_with("test_cookie", &encoded);
        assert!(codec.decode(b"secret-b", &headers, 1_700_000_000).is_none());
    }

    #[test]
    fn different_salt_yields_different_key() {
        let secret = b"shared-secret";
        let a = SignedCookie {
            name: "a",
            salt: b"forseti::a::v1",
            ttl_secs: 60,
            secure: false,
            path: "/",
        };
        let b = SignedCookie {
            name: "b",
            salt: b"forseti::b::v1",
            ttl_secs: 60,
            secure: false,
            path: "/",
        };
        let ka = a.derive_key(secret);
        let kb = b.derive_key(secret);
        assert_ne!(ka, kb);
    }

    #[test]
    fn missing_cookie_returns_none() {
        let codec = sc();
        let headers = HeaderMap::new();
        assert!(codec.decode(b"k", &headers, 0).is_none());
    }

    #[test]
    fn wrong_part_count_returns_none() {
        let codec = sc();
        let headers = headers_with("test_cookie", "only.two");
        assert!(codec.decode(b"k", &headers, 0).is_none());
    }

    #[test]
    fn mangled_hex_returns_none() {
        let codec = sc();
        let headers = headers_with("test_cookie", "1.nothex.deadbeef");
        assert!(codec.decode(b"k", &headers, 0).is_none());
    }

    #[test]
    fn set_header_carries_attributes() {
        let secure_codec = SignedCookie {
            name: "x",
            salt: b"s",
            ttl_secs: 60,
            secure: true,
            path: "/admin",
        };
        let line = secure_codec.set_header("payload");
        assert!(line.starts_with("x=payload"));
        assert!(line.contains("Secure"));
        assert!(line.contains("HttpOnly"));
        assert!(line.contains("Path=/admin"));
    }

    #[test]
    fn clear_header_emits_expired_directive() {
        let codec = sc();
        let line = codec.clear_header();
        assert!(line.contains("test_cookie="));
        assert!(line.contains("Expires=Thu, 01 Jan 1970"));
    }
}
