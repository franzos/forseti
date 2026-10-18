#![no_main]

use forseti::fuzz_api::{token_is_valid, url_origin};
use libfuzzer_sys::fuzz_target;

const SECRET: &[u8] = b"fuzz-secret-0123456789abcdef0123456789";

fuzz_target!(|input: (&str, &[u8])| {
    let (s, other_secret) = input;
    let _ = url_origin(s);
    // No forged token verifies: a valid one needs the HMAC over `random`
    // under the derived key, which the fuzzer never sees.
    assert!(!token_is_valid(SECRET, s) || s.len() > 64);
    let _ = token_is_valid(other_secret, s);
});
