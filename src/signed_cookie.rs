//! HMAC-signed cookie codec shared by every Forseti-owned signed cookie (flash, active-org, app-referrer).
//!
//! Value format `<unix_seconds>.<hex_payload>.<hex_mac>`; verification rejects on TTL miss, malformed parts,
//! or signature mismatch. Per-cookie keys derive via HKDF-SHA256 from the one operator secret using the
//! per-cookie `salt` as `info`, so compromising one signing key never leaks another.

use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, SameSite};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::cookies::read_cookie;

type HmacSha256 = Hmac<Sha256>;

/// Per-cookie shape (name, key salt, TTL, `Secure`); reuse one for encode + decode so the paths can't drift.
pub(crate) struct SignedCookie<'a> {
    pub name: &'a str,
    pub salt: &'a [u8],
    pub ttl_secs: u64,
    pub secure: bool,
    pub path: &'a str,
}

impl<'a> SignedCookie<'a> {
    // Per-cookie salt is HKDF `info` (cookie-type domain separation), not the salt input: the operator secret is the only entropy source.
    fn derive_key(&self, secret: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, secret)
            .expand(self.salt, &mut key)
            .expect("HKDF expand of 32 bytes is within OKM length bound");
        key
    }

    /// The MAC input: the wire value, prefixed with the cookie's own name and
    /// path.
    ///
    /// Binding those in means a value minted for one cookie cannot be replayed
    /// as another even if the two ever shared a key, and a flash cookie scoped
    /// to one path cannot be lifted to a different one. The per-cookie HKDF
    /// salt already separates the keys; this makes the guarantee a property of
    /// the signature rather than of remembering to pick a distinct salt.
    fn mac_input(&self, now_secs: u64, payload_hex: &str) -> String {
        format!("{}|{}|{now_secs}.{payload_hex}", self.name, self.path)
    }

    /// Build the `<ts>.<hex_payload>.<hex_mac>` value (no cookie attributes; see [`Self::set_header`]).
    pub(crate) fn encode(&self, secret: &[u8], payload: &[u8], now_secs: u64) -> String {
        let key = self.derive_key(secret);
        let payload_hex = hex::encode(payload);
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
        mac.update(self.mac_input(now_secs, &payload_hex).as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{now_secs}.{payload_hex}.{}", hex::encode(tag))
    }

    /// Read + verify the cookie off `headers`; payload bytes on success, `None` on any failure.
    pub(crate) fn decode(
        &self,
        secret: &[u8],
        headers: &HeaderMap,
        now_secs: u64,
    ) -> Option<Vec<u8>> {
        self.decode_with_issued_at(secret, headers, now_secs)
            .map(|(_, payload)| payload)
    }

    /// [`Self::decode`] plus the second the value was minted, for callers that
    /// enforce a shorter window than the cookie's own TTL on some payloads.
    pub(crate) fn decode_with_issued_at(
        &self,
        secret: &[u8],
        headers: &HeaderMap,
        now_secs: u64,
    ) -> Option<(u64, Vec<u8>)> {
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
        mac.update(self.mac_input(ts, parts[1]).as_bytes());
        mac.verify_slice(&tag).ok()?;
        Some((ts, payload))
    }

    /// Full `Set-Cookie` value carrying `encoded` (typically from [`Self::encode`]).
    pub(crate) fn set_header(&self, encoded: &str) -> String {
        Cookie::build((self.name.to_string(), encoded.to_string()))
            .path(self.path.to_string())
            .same_site(SameSite::Lax)
            .http_only(true)
            .secure(self.secure)
            .build()
            .to_string()
    }

    /// `Set-Cookie` line that clears the cookie, with an explicit past `Expires=` (no `time` dependency).
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

/// Wall-clock seconds since the Unix epoch, clamped to 0 on a pre-epoch clock so the codec stays infallible.
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
    fn a_value_does_not_verify_under_a_different_cookie_name() {
        let secret = b"operator-secret-32-bytes-of-key!";
        let now = 1_700_000_000;
        let a = SignedCookie {
            name: "flash_a",
            salt: b"shared",
            ttl_secs: 60,
            secure: false,
            path: "/",
        };
        let b = SignedCookie {
            name: "flash_b",
            salt: b"shared",
            ttl_secs: 60,
            secure: false,
            path: "/",
        };
        // Same salt, so the same key — the NAME is what has to stop this.
        let encoded = a.encode(secret, b"payload", now);
        let headers = headers_with("flash_b", &encoded);
        assert!(
            b.decode(secret, &headers, now).is_none(),
            "a value minted as flash_a must not verify as flash_b"
        );
    }

    #[test]
    fn a_value_does_not_verify_under_a_different_path() {
        let secret = b"operator-secret-32-bytes-of-key!";
        let now = 1_700_000_000;
        let root = SignedCookie {
            name: "flash",
            salt: b"shared",
            ttl_secs: 60,
            secure: false,
            path: "/",
        };
        let scoped = SignedCookie {
            name: "flash",
            salt: b"shared",
            ttl_secs: 60,
            secure: false,
            path: "/settings",
        };
        let encoded = root.encode(secret, b"payload", now);
        let headers = headers_with("flash", &encoded);
        assert!(
            scoped.decode(secret, &headers, now).is_none(),
            "a value minted for / must not verify for /settings"
        );
        // ...and the matching pair still round-trips.
        assert_eq!(
            root.decode(secret, &headers, now).as_deref(),
            Some(b"payload".as_slice())
        );
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
