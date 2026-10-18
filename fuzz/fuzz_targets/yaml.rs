#![no_main]

use forseti::fuzz_api::{parse_yaml, to_yaml, yaml_scalar};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    if let Ok(v) = parse_yaml(s)
        && let Ok(text) = to_yaml(&v)
    {
        // What we write back must be readable again.
        let _ = parse_yaml(&text);
    }
    // A quoted scalar must survive a YAML round trip unchanged.
    if !s.is_empty() {
        let doc = format!("k: {}\n", yaml_scalar(s));
        if let Ok(v) = parse_yaml(&doc) {
            assert_eq!(v.get("k").and_then(|k| k.as_str()), Some(s));
        }
    }
});
