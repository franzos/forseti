#![no_main]

use axum::http::{HeaderMap, HeaderValue};
use forseti::fuzz_api::forwarded_client_ip;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Vec<&[u8]>, u8)| {
    let (values, hops) = input;
    let mut headers = HeaderMap::new();
    for v in values.into_iter().take(8) {
        if let Ok(v) = HeaderValue::from_bytes(v) {
            headers.append("x-forwarded-for", v);
        }
    }
    let _ = forwarded_client_ip(&headers, hops);
});
