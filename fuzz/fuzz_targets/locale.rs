#![no_main]

use forseti::fuzz_api::{from_accept_language, from_query_or_cookie};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = from_query_or_cookie(s);
    let _ = from_accept_language(Some(s));
    let _ = from_accept_language(None);
});
