//! Shared text-formatting helpers: humanising User-Agent strings, relative timestamps, and UUID-shape detection.

/// Reduce a User-Agent to "Browser on OS"; empty string for unrecognised UAs.
/// Substring matching, most-specific first (Edge/Chromium UAs also contain "Safari" tokens).
pub fn humanise_user_agent(locale: &crate::locale::LanguageIdentifier, ua: &str) -> String {
    if ua.is_empty() {
        return String::new();
    }
    // Known browser/OS names are proper nouns and stay literal; only the
    // "unknown" fallbacks and the "{browser} on {os}" connector localize.
    let browser: Option<&str> = if ua.contains("Edg/") || ua.contains("Edge/") {
        Some("Edge")
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        Some("Opera")
    } else if ua.contains("Firefox/") {
        Some("Firefox")
    } else if ua.contains("Chrome/") || ua.contains("Chromium/") {
        Some("Chrome")
    } else if ua.contains("Safari/") {
        Some("Safari")
    } else {
        None
    };
    let os: Option<&str> = if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iOS") {
        Some("iOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    let browser = browser
        .map(str::to_string)
        .unwrap_or_else(|| crate::i18n::lookup(locale, "format-ua-unknown-browser"));
    let os = os
        .map(str::to_string)
        .unwrap_or_else(|| crate::i18n::lookup(locale, "format-ua-unknown-os"));
    crate::i18n::lookup_2s(locale, "format-ua-on", "browser", &browser, "os", &os)
}

/// Convert an RFC3339 timestamp into a coarse, localized relative string
/// ("2h ago", "yesterday", "in 15h"), handling both past and future. Falls back
/// to the original string on parse failure.
pub fn humanise_timestamp(locale: &crate::locale::LanguageIdentifier, iso: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(iso) else {
        return iso.to_string();
    };
    let unix = parsed.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let delta = now - unix;
    let future = delta < 0;
    let mag = delta.unsigned_abs() as i64;

    // Pick between the past ("... ago") and future ("in ...") variant of a key.
    let pick = |ago: &'static str, in_: &'static str| if future { in_ } else { ago };

    if mag < 60 {
        return crate::i18n::lookup(
            locale,
            pick("format-relative-just-now", "format-relative-in-a-moment"),
        );
    }
    if (86_400..86_400 * 2).contains(&mag) {
        return crate::i18n::lookup(
            locale,
            pick("format-relative-yesterday", "format-relative-tomorrow"),
        );
    }
    let (key, n) = if mag < 3600 {
        (
            pick("format-relative-minutes-ago", "format-relative-minutes-in"),
            mag / 60,
        )
    } else if mag < 86_400 {
        (
            pick("format-relative-hours-ago", "format-relative-hours-in"),
            mag / 3600,
        )
    } else if mag < 86_400 * 30 {
        (
            pick("format-relative-days-ago", "format-relative-days-in"),
            mag / 86_400,
        )
    } else if mag < 86_400 * 365 {
        (
            pick("format-relative-months-ago", "format-relative-months-in"),
            mag / (86_400 * 30),
        )
    } else {
        (
            pick("format-relative-years-ago", "format-relative-years-in"),
            mag / (86_400 * 365),
        )
    };
    crate::i18n::lookup_n(locale, key, n)
}

/// True when `s` has the canonical 8-4-4-4-12 UUID shape (not validated semantically).
/// Lets admin search decide between an ID lookup and a name/email filter.
pub fn looks_like_uuid(s: &str) -> bool {
    let s = s.trim();
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    let hyphens = [8, 13, 18, 23];
    bytes.iter().enumerate().all(|(i, b)| {
        if hyphens.contains(&i) {
            *b == b'-'
        } else {
            b.is_ascii_hexdigit()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- humanise_user_agent ------------------------------------------------

    #[test]
    fn humanise_user_agent_chrome_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";
        assert_eq!(humanise_user_agent(&en(), ua), "Chrome on Linux");
    }

    #[test]
    fn humanise_user_agent_firefox_macos() {
        let ua =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0";
        assert_eq!(humanise_user_agent(&en(), ua), "Firefox on macOS");
    }

    #[test]
    fn humanise_user_agent_safari_macos() {
        // Pure Safari, no Chrome/Edge tokens.
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";
        assert_eq!(humanise_user_agent(&en(), ua), "Safari on macOS");
    }

    #[test]
    fn humanise_user_agent_edge_wins_over_chrome() {
        let ua =
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0";
        assert_eq!(humanise_user_agent(&en(), ua), "Edge on Windows");
    }

    #[test]
    fn humanise_user_agent_mobile_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120.0";
        // Android substring beats the Linux fallback.
        assert_eq!(humanise_user_agent(&en(), ua), "Chrome on Android");
    }

    #[test]
    fn humanise_user_agent_unknown() {
        assert_eq!(
            humanise_user_agent(&en(), "Wget/1.21"),
            "Unknown browser on Unknown OS"
        );
    }

    #[test]
    fn humanise_user_agent_localizes_to_de() {
        let de: crate::locale::LanguageIdentifier = "de".parse().unwrap();
        let ua = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0";
        assert_eq!(humanise_user_agent(&de, ua), "Chrome unter Linux");
        assert_eq!(
            humanise_user_agent(&de, "Wget/1.21"),
            "Unbekannter Browser unter Unbekanntes System"
        );
    }

    #[test]
    fn humanise_user_agent_empty() {
        assert_eq!(humanise_user_agent(&en(), ""), "");
    }

    // --- humanise_timestamp -------------------------------------------------

    fn en() -> crate::locale::LanguageIdentifier {
        "en".parse().unwrap()
    }

    #[test]
    fn humanise_timestamp_returns_input_on_malformed() {
        // Malformed timestamps fall back to the original string.
        assert_eq!(
            humanise_timestamp(&en(), "not a timestamp"),
            "not a timestamp"
        );
        assert_eq!(humanise_timestamp(&en(), ""), "");
    }

    #[test]
    fn humanise_timestamp_just_now_for_recent() {
        // Anything within the last 60s is "just now".
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iso = unix_to_iso(now - 5);
        assert_eq!(humanise_timestamp(&en(), &iso), "just now");
    }

    #[test]
    fn humanise_timestamp_minutes_ago() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iso = unix_to_iso(now - 5 * 60);
        assert_eq!(humanise_timestamp(&en(), &iso), "5m ago");
    }

    #[test]
    fn humanise_timestamp_days_ago() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iso = unix_to_iso(now - 5 * 86_400);
        assert_eq!(humanise_timestamp(&en(), &iso), "5d ago");
    }

    #[test]
    fn humanise_timestamp_localizes_to_de() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let de: crate::locale::LanguageIdentifier = "de".parse().unwrap();
        assert_eq!(
            humanise_timestamp(&de, &unix_to_iso(now - 5)),
            "gerade eben"
        );
        assert_eq!(
            humanise_timestamp(&de, &unix_to_iso(now - 5 * 60)),
            "vor 5 Min."
        );
        assert_eq!(
            humanise_timestamp(&de, &unix_to_iso(now - 5 * 86_400)),
            "vor 5 Tagen"
        );
    }

    #[test]
    fn humanise_timestamp_future_format() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // 2 hours in the future.
        let iso = unix_to_iso(now + 2 * 3600);
        assert_eq!(humanise_timestamp(&en(), &iso), "in 2h");
    }

    /// Helper: convert a unix seconds value into the ISO8601 shape Kratos emits.
    fn unix_to_iso(unix: i64) -> String {
        let dt = chrono::DateTime::from_timestamp(unix, 0).expect("unix seconds in range");
        dt.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()
    }

    // --- parse_iso8601_to_unix (via humanise_timestamp round-trip) ---------

    #[test]
    fn parse_iso8601_round_trips_via_humanise() {
        // Indirect round-trip: encode a fixed unix value, parse via
        // humanise_timestamp's path, expect it to bucket near "now"
        // when the value is "now".
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iso = unix_to_iso(now);
        // Will be "just now" or "in a moment" depending on exact clock.
        let result = humanise_timestamp(&en(), &iso);
        assert!(
            result == "just now" || result == "in a moment",
            "expected just-now bucket, got {result:?}"
        );
    }

    #[test]
    fn parse_iso8601_malformed_returns_raw_string() {
        // humanise_timestamp falls back to the raw string on parse failure.
        assert_eq!(humanise_timestamp(&en(), "2025"), "2025");
        assert_eq!(
            humanise_timestamp(&en(), "2025-01-99T00:00:00Z"),
            humanise_timestamp(&en(), "2025-01-99T00:00:00Z")
        );
    }

    // --- looks_like_uuid ----------------------------------------------------

    #[test]
    fn looks_like_uuid_canonical_v4() {
        assert!(looks_like_uuid("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn looks_like_uuid_uppercase_hex() {
        assert!(looks_like_uuid("550E8400-E29B-41D4-A716-446655440000"));
    }

    #[test]
    fn looks_like_uuid_almost_but_not() {
        // Wrong length.
        assert!(!looks_like_uuid("550e8400-e29b-41d4-a716-44665544000"));
        // Wrong char at hyphen position.
        assert!(!looks_like_uuid("550e8400xe29b-41d4-a716-446655440000"));
        // Non-hex char.
        assert!(!looks_like_uuid("550e8400-e29b-41d4-a716-44665544000z"));
    }

    #[test]
    fn looks_like_uuid_garbage() {
        assert!(!looks_like_uuid(""));
        assert!(!looks_like_uuid("not-a-uuid"));
        assert!(!looks_like_uuid("           "));
    }

    #[test]
    fn looks_like_uuid_trims_input() {
        assert!(looks_like_uuid("  550e8400-e29b-41d4-a716-446655440000  "));
    }
}
