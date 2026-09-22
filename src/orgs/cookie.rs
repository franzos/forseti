//! Signed `active_org` cookie carrying the selected org id.
//!
//! Distinct salt so flash / active_org / app_referrer cookies never share
//! signing material. Not authoritative: handlers cross-check the value
//! against `organization_members`, so a forged cookie naming an org the
//! user isn't in falls back to the first membership.

use axum::http::HeaderMap;

use crate::signed_cookie::{SignedCookie, unix_seconds_now};

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

/// Payload marker for a pin set by an OAuth authorize link rather than by the
/// user's own org switcher.
const FLOW_PIN_PREFIX: &str = "flow:";

/// How long a flow-set pin stays honoured. A crafted `/oauth2/auth?organization_id=`
/// link rewrites the victim's active org as a side effect of them clicking it,
/// which used to stick for the cookie's full TTL (30 days by default) and
/// silently change which org's claims their next tokens carried. Bounded to
/// roughly one login flow instead.
const FLOW_PIN_TTL_SECS: u64 = 600;

/// Read + verify the active-org cookie. `None` on any failure (caller falls
/// back to the first membership).
///
/// A pin set by an authorize link is additionally held to
/// [`FLOW_PIN_TTL_SECS`], whatever the configured cookie TTL.
pub fn read_active_org_cookie(headers: &HeaderMap, secret: &[u8], ttl_secs: u64) -> Option<String> {
    let now = unix_seconds_now();
    let (issued_at, payload) =
        codec(ttl_secs, false).decode_with_issued_at(secret, headers, now)?;
    let value = String::from_utf8(payload).ok()?;
    match value.strip_prefix(FLOW_PIN_PREFIX) {
        Some(org_id) => {
            (now.saturating_sub(issued_at) <= FLOW_PIN_TTL_SECS).then(|| org_id.to_string())
        }
        None => Some(value),
    }
}

/// `Set-Cookie` line that clears the active-org pin.
pub fn clear_active_org_cookie(secure: bool) -> String {
    codec(0, secure).clear_header()
}

/// Build a `Set-Cookie` header value pinning `org_id` as the active org.
/// For the user's own, deliberate org switch: honoured for the full TTL.
pub fn set_active_org_cookie(secret: &[u8], ttl_secs: u64, org_id: &str, secure: bool) -> String {
    let c = codec(ttl_secs, secure);
    let encoded = c.encode(secret, org_id.as_bytes(), unix_seconds_now());
    c.set_header(&encoded)
}

/// Pin `org_id` for the duration of one OAuth flow. Same cookie, marked so
/// [`read_active_org_cookie`] holds it to [`FLOW_PIN_TTL_SECS`] — the caller
/// followed a link someone else composed, which is not the same thing as
/// choosing an org.
pub fn set_active_org_pin_for_flow(
    secret: &[u8],
    ttl_secs: u64,
    org_id: &str,
    secure: bool,
) -> String {
    let c = codec(ttl_secs, secure);
    let payload = format!("{FLOW_PIN_PREFIX}{org_id}");
    let encoded = c.encode(secret, payload.as_bytes(), unix_seconds_now());
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

#[cfg(test)]
mod flow_pin_tests {
    use super::*;
    use axum::http::header::COOKIE;

    const SECRET2: &[u8] = b"flow-pin-test-secret";
    const LONG_TTL: u64 = 60 * 60 * 24 * 30;

    fn headers_from(set_cookie: &str) -> HeaderMap {
        let value = set_cookie
            .split_once('=')
            .and_then(|(_, rest)| rest.split(';').next())
            .expect("Set-Cookie carries a value");
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            format!("{ACTIVE_ORG_COOKIE}={value}")
                .parse()
                .expect("cookie header parses"),
        );
        h
    }

    #[test]
    fn a_users_own_switch_is_honoured_for_the_full_ttl() {
        let sc = set_active_org_cookie(SECRET2, LONG_TTL, "acme-id", false);
        assert_eq!(
            read_active_org_cookie(&headers_from(&sc), SECRET2, LONG_TTL).as_deref(),
            Some("acme-id")
        );
    }

    #[test]
    fn a_flow_pin_reads_back_as_the_plain_org_id() {
        // The marker is an implementation detail; callers see an org id.
        let sc = set_active_org_pin_for_flow(SECRET2, LONG_TTL, "acme-id", false);
        assert_eq!(
            read_active_org_cookie(&headers_from(&sc), SECRET2, LONG_TTL).as_deref(),
            Some("acme-id")
        );
    }

    #[test]
    fn a_flow_pin_expires_on_its_own_short_window() {
        // Mint one as if it were issued well over the flow window ago; the
        // cookie's configured TTL (30 days) would still accept it.
        let c = codec(LONG_TTL, false);
        let stale = unix_seconds_now() - (FLOW_PIN_TTL_SECS + 60);
        let payload = format!("{FLOW_PIN_PREFIX}acme-id");
        let encoded = c.encode(SECRET2, payload.as_bytes(), stale);
        let headers = headers_from(&c.set_header(&encoded));
        assert_eq!(
            read_active_org_cookie(&headers, SECRET2, LONG_TTL),
            None,
            "a crafted authorize link must not rewrite the active org for 30 days"
        );

        // The same age on a user-chosen switch is still fine.
        let encoded = c.encode(SECRET2, b"acme-id", stale);
        let headers = headers_from(&c.set_header(&encoded));
        assert_eq!(
            read_active_org_cookie(&headers, SECRET2, LONG_TTL).as_deref(),
            Some("acme-id")
        );
    }
}
