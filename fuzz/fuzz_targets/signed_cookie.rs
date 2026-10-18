#![no_main]

use axum::http::{HeaderMap, HeaderValue};
use forseti::fuzz_api::SignedCookie;
use libfuzzer_sys::fuzz_target;

const SECRET: &[u8] = b"fuzz-secret-0123456789abcdef0123456789";

fn cookie() -> SignedCookie<'static> {
    SignedCookie {
        name: "fz",
        salt: b"fuzz-salt",
        ttl_secs: 600,
        secure: true,
        path: "/",
    }
}

fuzz_target!(|input: (&[u8], &[u8], u64, u64)| {
    let (raw, payload, now, later) = input;
    let c = cookie();

    // Arbitrary cookie value: must never panic, and must never verify
    // unless it is exactly what encode() would have produced.
    let mut headers = HeaderMap::new();
    let value = format!("fz={}", String::from_utf8_lossy(raw));
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.insert("cookie", v);
        if let Some((ts, got)) = c.decode_with_issued_at(SECRET, &headers, now) {
            assert_eq!(c.encode(SECRET, &got, ts), String::from_utf8_lossy(raw));
        }
    }

    // Round trip: a freshly minted value decodes within its TTL.
    let encoded = c.encode(SECRET, payload, now);
    let mut headers = HeaderMap::new();
    headers.insert("cookie", HeaderValue::from_str(&format!("fz={encoded}")).unwrap());
    assert_eq!(c.decode(SECRET, &headers, now).as_deref(), Some(payload));
    let aged = c.decode(SECRET, &headers, later);
    let within = later.saturating_sub(now) <= 600 && now <= later.saturating_add(60);
    assert_eq!(aged.is_some(), within);
});
