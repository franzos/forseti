#![no_main]

use forseti::fuzz_api::{default_locale, humanise_timestamp, humanise_user_agent};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let locale = default_locale();
    let _ = humanise_user_agent(&locale, s);
    let _ = humanise_timestamp(&locale, s);
});
