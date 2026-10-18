#![no_main]

use forseti::fuzz_api::{safe_external_uri, safe_return_to_for_origin};
use libfuzzer_sys::fuzz_target;

const SELF_URL: &str = "https://forseti.example.com";

fuzz_target!(|raw: &str| {
    let out = safe_return_to_for_origin(SELF_URL, raw);
    // Either the untouched input or the fallback; anything else is a bug.
    assert!(out == "/" || out == raw);
    assert!(!out.bytes().any(|b| b < 0x20 || b == 0x7f));
    assert!(!out.starts_with("//") && !out.starts_with("/\\"));
    if out != "/" && !out.starts_with('/') {
        let parsed = url::Url::parse(out).expect("accepted absolute return_to must parse");
        assert_eq!(parsed.origin(), url::Url::parse(SELF_URL).unwrap().origin());
    }

    for allow_private in [false, true] {
        if let Some(uri) = safe_external_uri(raw, allow_private) {
            let parsed = url::Url::parse(&uri).expect("accepted external uri must parse");
            assert!(parsed.scheme() == "https" || (allow_private && parsed.scheme() == "http"));
            assert!(parsed.username().is_empty() && parsed.password().is_none());
        }
    }
});
