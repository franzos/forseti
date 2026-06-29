//! Signed `forseti_known_accounts` cookie: a most-recently-used list of
//! identity UUIDs remembered on this device. Newline-separated payload,
//! deduped, capped. Not authoritative: handlers resolve labels server-side and
//! a forged/foreign id only seeds a prefill hint.

use axum::http::HeaderMap;

use crate::signed_cookie::{unix_seconds_now, SignedCookie};

const KNOWN_ACCOUNTS_COOKIE: &str = "forseti_known_accounts";
const KNOWN_ACCOUNTS_SALT: &[u8] = b"forseti::known_accounts::v1";
pub(crate) const KNOWN_ACCOUNTS_CAP: usize = 5;

fn codec<'a>(ttl_secs: u64, secure: bool) -> SignedCookie<'a> {
    SignedCookie {
        name: KNOWN_ACCOUNTS_COOKIE,
        salt: KNOWN_ACCOUNTS_SALT,
        ttl_secs,
        secure,
        path: "/",
    }
}

pub(crate) fn add_mru(ids: Vec<String>, id: &str, cap: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(ids.len() + 1);
    out.push(id.to_string());
    for existing in ids {
        if existing != id {
            out.push(existing);
        }
    }
    out.truncate(cap);
    out
}

pub(crate) fn remove(ids: Vec<String>, id: &str) -> Vec<String> {
    ids.into_iter().filter(|x| x != id).collect()
}

/// Read + verify the cookie into an ordered id list. Empty on any failure.
pub(crate) fn read_known_account_ids(
    headers: &HeaderMap,
    secret: &[u8],
    ttl_secs: u64,
) -> Vec<String> {
    let Some(payload) = codec(ttl_secs, false).decode(secret, headers, unix_seconds_now()) else {
        return Vec::new();
    };
    match String::from_utf8(payload) {
        Ok(s) => s.lines().filter(|l| !l.is_empty()).map(str::to_string).collect(),
        Err(_) => Vec::new(),
    }
}

/// Build the `Set-Cookie` header value for the given id list.
pub(crate) fn set_known_accounts_cookie(
    secret: &[u8],
    ttl_secs: u64,
    ids: &[String],
    secure: bool,
) -> String {
    let c = codec(ttl_secs, secure);
    let payload = ids.join("\n");
    let encoded = c.encode(secret, payload.as_bytes(), unix_seconds_now());
    c.set_header(&encoded)
}

/// `Set-Cookie` line that clears the cookie (forget-all).
pub(crate) fn clear_known_accounts_cookie(secure: bool) -> String {
    codec(0, secure).clear_header()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;
    use axum::http::HeaderMap;

    const SECRET: &[u8] = b"known-accounts-test-secret";
    const TTL: u64 = 60 * 60 * 24 * 90;

    #[test]
    fn add_mru_appends_new_to_front() {
        let out = add_mru(vec!["a".into(), "b".into()], "c", 5);
        assert_eq!(out, vec!["c", "a", "b"]);
    }

    #[test]
    fn add_mru_moves_existing_to_front_without_duplicate() {
        let out = add_mru(vec!["a".into(), "b".into(), "c".into()], "c", 5);
        assert_eq!(out, vec!["c", "a", "b"]);
    }

    #[test]
    fn add_mru_is_idempotent_on_head() {
        let out = add_mru(vec!["a".into(), "b".into()], "a", 5);
        assert_eq!(out, vec!["a", "b"]);
    }

    #[test]
    fn add_mru_evicts_past_cap() {
        let out = add_mru(
            vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            "f",
            5,
        );
        assert_eq!(out, vec!["f", "a", "b", "c", "d"]);
    }

    #[test]
    fn remove_drops_the_id() {
        let out = remove(vec!["a".into(), "b".into(), "c".into()], "b");
        assert_eq!(out, vec!["a", "c"]);
    }

    #[test]
    fn remove_absent_is_noop() {
        let out = remove(vec!["a".into(), "b".into()], "z");
        assert_eq!(out, vec!["a", "b"]);
    }

    fn cookie_value(set_cookie: &str) -> String {
        set_cookie.split_once('=').unwrap().1.split(';').next().unwrap().to_string()
    }

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, format!("{KNOWN_ACCOUNTS_COOKIE}={value}").parse().unwrap());
        h
    }

    #[test]
    fn round_trip_returns_ids_in_order() {
        let ids = vec!["11111111-1111-1111-1111-111111111111".to_string(), "22222222-2222-2222-2222-222222222222".to_string()];
        let sc = set_known_accounts_cookie(SECRET, TTL, &ids, false);
        let headers = headers_with(&cookie_value(&sc));
        assert_eq!(read_known_account_ids(&headers, SECRET, TTL), ids);
    }

    #[test]
    fn tampered_cookie_returns_empty() {
        let ids = vec!["11111111-1111-1111-1111-111111111111".to_string()];
        let sc = set_known_accounts_cookie(SECRET, TTL, &ids, false);
        let mut bytes = cookie_value(&sc).into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let headers = headers_with(&String::from_utf8(bytes).unwrap());
        assert!(read_known_account_ids(&headers, SECRET, TTL).is_empty());
    }

    #[test]
    fn missing_cookie_returns_empty() {
        assert!(read_known_account_ids(&HeaderMap::new(), SECRET, TTL).is_empty());
    }
}
