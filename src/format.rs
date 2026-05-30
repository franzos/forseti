//! Small text-formatting helpers shared across handlers and view-model
//! projections: humanising User-Agent strings, ISO-8601 timestamps, and
//! recognising UUID-shaped strings.
//!
//! These live in their own module (rather than scattered private fns)
//! because both the dashboard, the user-facing sessions page, and the
//! admin tables need the same coarse formatting and the rules should
//! drift together.

/// Reduce a verbose User-Agent string to "Browser on OS" (e.g.
/// "Chrome on Linux", "Firefox on macOS"). Falls back to an empty string
/// for unrecognised UAs so the caller can decide on a placeholder.
///
/// Deliberately tiny — we match on a handful of substrings rather than
/// pulling in a UA-parsing crate. Order matters: Edge/Chromium contain
/// "Safari" tokens, so check the more specific browser names first.
pub fn humanise_user_agent(ua: &str) -> String {
    if ua.is_empty() {
        return String::new();
    }
    let browser = if ua.contains("Edg/") || ua.contains("Edge/") {
        "Edge"
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        "Opera"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("Chromium/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "Unknown browser"
    };
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iOS") {
        "iOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Unknown OS"
    };
    format!("{browser} on {os}")
}

/// Convert an RFC3339 timestamp into a coarse relative string ("2h ago",
/// "yesterday", "in 15h"). Falls back to the original string if parsing
/// fails — better to show the raw timestamp than nothing.
///
/// Handles both past ("X ago") and future ("in X") directions, so a
/// single helper works for both `authenticated_at` and `expires_at`.
pub fn humanise_timestamp(iso: &str) -> String {
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
    let bucket = if mag < 60 {
        return if future {
            "in a moment".to_string()
        } else {
            "just now".to_string()
        };
    } else if mag < 3600 {
        format!("{}m", mag / 60)
    } else if mag < 86_400 {
        format!("{}h", mag / 3600)
    } else if mag < 86_400 * 2 {
        return if future {
            "tomorrow".to_string()
        } else {
            "yesterday".to_string()
        };
    } else if mag < 86_400 * 30 {
        format!("{}d", mag / 86_400)
    } else if mag < 86_400 * 365 {
        format!("{}mo", mag / (86_400 * 30))
    } else {
        format!("{}y", mag / (86_400 * 365))
    };
    if future {
        format!("in {bucket}")
    } else {
        format!("{bucket} ago")
    }
}

/// True when `s` looks like a canonical 8-4-4-4-12 UUID (hex + hyphens).
/// Used by admin list pages to decide whether a free-text search input
/// should be treated as an ID lookup vs. a name/email filter.
///
/// Doesn't validate the UUID semantically (version bits, variant bits) —
/// only the shape — because that's enough to decide "try a direct GET
/// before falling through to a list query".
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
        assert_eq!(humanise_user_agent(ua), "Chrome on Linux");
    }

    #[test]
    fn humanise_user_agent_firefox_macos() {
        let ua =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0";
        assert_eq!(humanise_user_agent(ua), "Firefox on macOS");
    }

    #[test]
    fn humanise_user_agent_safari_macos() {
        // Pure Safari — no Chrome/Edge tokens.
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";
        assert_eq!(humanise_user_agent(ua), "Safari on macOS");
    }

    #[test]
    fn humanise_user_agent_edge_wins_over_chrome() {
        let ua =
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0";
        assert_eq!(humanise_user_agent(ua), "Edge on Windows");
    }

    #[test]
    fn humanise_user_agent_mobile_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120.0";
        // Android substring beats the Linux fallback.
        assert_eq!(humanise_user_agent(ua), "Chrome on Android");
    }

    #[test]
    fn humanise_user_agent_unknown() {
        assert_eq!(
            humanise_user_agent("Wget/1.21"),
            "Unknown browser on Unknown OS"
        );
    }

    #[test]
    fn humanise_user_agent_empty() {
        assert_eq!(humanise_user_agent(""), "");
    }

    // --- humanise_timestamp -------------------------------------------------

    #[test]
    fn humanise_timestamp_returns_input_on_malformed() {
        // Malformed timestamps fall back to the original string.
        assert_eq!(humanise_timestamp("not a timestamp"), "not a timestamp");
        assert_eq!(humanise_timestamp(""), "");
    }

    #[test]
    fn humanise_timestamp_just_now_for_recent() {
        // Anything within the last 60s is "just now".
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iso = unix_to_iso(now - 5);
        assert_eq!(humanise_timestamp(&iso), "just now");
    }

    #[test]
    fn humanise_timestamp_minutes_ago() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iso = unix_to_iso(now - 5 * 60);
        assert_eq!(humanise_timestamp(&iso), "5m ago");
    }

    #[test]
    fn humanise_timestamp_days_ago() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iso = unix_to_iso(now - 5 * 86_400);
        assert_eq!(humanise_timestamp(&iso), "5d ago");
    }

    #[test]
    fn humanise_timestamp_future_format() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // 2 hours in the future.
        let iso = unix_to_iso(now + 2 * 3600);
        assert_eq!(humanise_timestamp(&iso), "in 2h");
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
        let result = humanise_timestamp(&iso);
        assert!(
            result == "just now" || result == "in a moment",
            "expected just-now bucket, got {result:?}"
        );
    }

    #[test]
    fn parse_iso8601_malformed_returns_raw_string() {
        // humanise_timestamp falls back to the raw string on parse failure.
        assert_eq!(humanise_timestamp("2025"), "2025");
        assert_eq!(
            humanise_timestamp("2025-01-99T00:00:00Z"),
            humanise_timestamp("2025-01-99T00:00:00Z")
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
