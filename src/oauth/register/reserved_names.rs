//! Reserved-name denylist + the Unicode normalisation pipeline that
//! folds spoof inputs (zero-width splits, fullwidth, NBSP separators,
//! combining marks, bidi controls, cross-script homoglyphs) down to the
//! ASCII shape the denylist checks against.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;
use unicode_security::skeleton;

/// Default `client_name` denylist. Case-insensitive substring match so a
/// self-registered client can't pose as e.g. "Microsoft Login" on the consent
/// screen. Operators replace it wholesale via `oauth.dcr_reserved_names`.
pub const RESERVED_NAMES_DEFAULT: &[&str] = &[
    "ory",
    "hydra",
    "kratos",
    "google",
    "apple",
    "microsoft",
    "github",
    "gitlab",
    "anthropic",
    "claude",
    "openai",
    "chatgpt",
    "okta",
    "auth0",
    "admin",
    "forseti",
    "portal",
    "system",
    "root",
];

/// Substring search for any reserved-name pattern in `client_name`, returning
/// the match (for logging only; the response doesn't echo it). Falls back to
/// [`RESERVED_NAMES_DEFAULT`] when unconfigured. Inputs are normalised first
/// (see [`normalise_for_reserved_check`]) so Unicode spoofs collapse to the
/// covered skeleton.
pub(super) fn reserved_name_hit(
    configured: &Option<Vec<String>>,
    client_name: &str,
) -> Option<String> {
    let needle = normalise_for_reserved_check(client_name);
    if needle.is_empty() {
        return None;
    }
    match configured {
        Some(list) => list
            .iter()
            .find(|p| !p.is_empty() && needle.contains(&normalise_for_reserved_check(p)))
            .cloned(),
        None => RESERVED_NAMES_DEFAULT
            .iter()
            .find(|p| needle.contains(&normalise_for_reserved_check(p)))
            .map(|p| (*p).to_string()),
    }
}

/// Fold a string into the canonical shape for reserved-name matching:
///
/// 1. NFKD: collapse compatibility forms (fullwidth, ligatures) and split
///    precomposed accents into base + combining mark.
/// 2. Strip combining marks (`"Göogle"` → `"Google"`).
/// 3. Strip zero-width and bidi controls (the step-6 skeleton does not).
/// 4. Collapse whitespace runs (incl. NBSP, ideographic space) to one space.
/// 5. Lowercase: the case-sensitive skeleton needs both sides lowered to
///    line up against the lowercase denylist.
/// 6. UTS 39 confusable skeleton: fold cross-script homoglyphs.
///
/// Order matters: the skeleton leaves invisible controls / whitespace alone
/// and doesn't case-fold, so steps 3-5 must precede it.
fn normalise_for_reserved_check(input: &str) -> String {
    // NFKD also splits precomposed accents, so the combining-mark strip below
    // catches both `"Go\u{0308}ogle"` and `"Göogle"`.
    let nfkd: String = input.nfkd().collect();
    let mut stripped = String::with_capacity(nfkd.len());
    let mut last_was_space = false;
    for c in nfkd.chars() {
        if is_combining_mark(c) || is_invisible_control(c) {
            continue;
        }
        if c.is_whitespace() {
            if !last_was_space {
                stripped.push(' ');
                last_was_space = true;
            }
            continue;
        }
        last_was_space = false;
        for lc in c.to_lowercase() {
            stripped.push(lc);
        }
    }
    skeleton(stripped.trim()).collect()
}

/// Zero-width and bidi-control characters that render as nothing (or flip
/// direction) and so could spoof a reserved name past a substring check.
fn is_invisible_control(c: char) -> bool {
    matches!(
        c as u32,
        0x200B..=0x200D   // ZWSP, ZWNJ, ZWJ
        | 0xFEFF          // BOM / zero-width no-break space
        | 0x202A..=0x202E // LRE, RLE, PDF, LRO, RLO
        | 0x2066..=0x2069 // LRI, RLI, FSI, PDI
    )
}

/// Clip a string to `max_chars` chars (not bytes) for safe audit-row inclusion.
pub(super) fn truncate_for_audit(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    //! Fast cargo-test feedback on the reserved-name normalisation pipeline;
    //! DB/HTTP paths are covered by the integration suite.
    use super::*;

    /// Self-test: a plain ASCII reserved name still trips after the
    /// normalisation pipeline. Guards against accidentally over-stripping.
    #[test]
    fn reserved_plain_ascii_still_matches() {
        let hit = reserved_name_hit(&None, "Google Login");
        assert_eq!(hit.as_deref(), Some("google"));
    }

    /// Zero-width space split: `"Goog\u{200B}le"` should fold to "google".
    #[test]
    fn reserved_zero_width_split_is_caught() {
        let hit = reserved_name_hit(&None, "Goog\u{200B}le Account");
        assert_eq!(hit.as_deref(), Some("google"));
    }

    /// Fullwidth spoof: NFKC maps `Ｇ` → `G`, etc.
    #[test]
    fn reserved_fullwidth_is_caught() {
        let hit = reserved_name_hit(&None, "ＧＯＯＧＬＥ Sign-In");
        assert_eq!(hit.as_deref(), Some("google"));
    }

    /// NBSP-separated reserved name: U+00A0 folds to a regular space without
    /// breaking the `"microsoft"` match.
    #[test]
    fn reserved_nbsp_separated_is_caught() {
        let hit = reserved_name_hit(&None, "Microsoft\u{00A0}Login");
        assert_eq!(hit.as_deref(), Some("microsoft"));
    }

    /// Combining mark spoof: `"Go\u{0308}ogle"` decomposes to base `o` +
    /// combining diaeresis; after stripping the mark, "google" remains.
    #[test]
    fn reserved_combining_mark_is_caught() {
        let hit = reserved_name_hit(&None, "Go\u{0308}ogle Drive");
        assert_eq!(hit.as_deref(), Some("google"));
    }

    /// Bidi-control wrap: U+202E (right-to-left override) used to break
    /// rendering. Should be stripped before the substring check.
    #[test]
    fn reserved_bidi_control_is_stripped() {
        let hit = reserved_name_hit(&None, "Goo\u{202E}gle\u{202C}");
        assert_eq!(hit.as_deref(), Some("google"));
    }

    /// Cyrillic-homoglyph spoof: `"Gооgle"` swaps the two ASCII `o`s for
    /// Cyrillic U+043E (`о`). NFKD/case-folding alone left these distinct;
    /// the UTS 39 skeleton folds both onto the same representative, so the
    /// candidate now collapses to the reserved-name skeleton.
    #[test]
    fn reserved_cyrillic_homoglyph_is_caught() {
        let hit = reserved_name_hit(&None, "G\u{043E}\u{043E}gle Sign-In");
        assert_eq!(hit.as_deref(), Some("google"));
    }

    /// Cyrillic-homoglyph spoof of a privilege name: `"аdmin"` leads with
    /// Cyrillic U+0430 (`а`) for ASCII `a`.
    #[test]
    fn reserved_cyrillic_admin_is_caught() {
        let hit = reserved_name_hit(&None, "\u{0430}dmin Console");
        assert_eq!(hit.as_deref(), Some("admin"));
    }

    /// Honest non-matching name passes through untouched.
    #[test]
    fn unreserved_name_does_not_match() {
        let hit = reserved_name_hit(&None, "Acme MCP Server");
        assert!(hit.is_none());
    }

    /// Empty / whitespace-only `client_name` short-circuits without a
    /// match — preserves the existing behaviour where an absent name
    /// isn't a reserved-name hit (Hydra rejects empties downstream).
    #[test]
    fn empty_name_does_not_match() {
        assert!(reserved_name_hit(&None, "").is_none());
        assert!(reserved_name_hit(&None, "   \u{00A0}\u{200B}  ").is_none());
    }
}
