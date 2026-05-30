//! Reserved-name denylist + the Unicode normalisation pipeline that
//! folds spoof inputs (zero-width splits, fullwidth, NBSP separators,
//! combining marks, bidi controls, cross-script homoglyphs) down to the
//! ASCII shape the denylist checks against.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;
use unicode_security::skeleton;

/// Default `client_name` denylist baked into the binary. Case-insensitive
/// substring match — any pattern occurring anywhere in `client_name` causes
/// the registration to be rejected. Covers our own brand, upstream Ory
/// brands, common consumer IDPs, AI vendors, and obvious privilege names so
/// a self-registered client can't pretend to be "Microsoft Login" or
/// "Forseti Admin" on the consent screen. Operators replace the list wholesale via
/// `oauth.dcr_reserved_names` in `config.toml`; there is intentionally no
/// merge-with-extras toggle.
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

/// Case-insensitive substring search for any reserved-name pattern in
/// `client_name`. Returns the matched pattern when a hit is found (for
/// logging only — the HTTP response intentionally does not echo it). When
/// the operator hasn't configured `oauth.dcr_reserved_names`, falls back
/// to [`RESERVED_NAMES_DEFAULT`].
///
/// Inputs are normalised before matching (see [`normalise_for_reserved_check`])
/// so spoofs like `"Goog\u{200B}le"` (zero-width split), fullwidth
/// `"ＧＯＯＧＬＥ"`, `"Microsoft\u{00A0}Login"` (NBSP), `"Gööogle"`
/// (combining diaereses), or `"Gооgle"` (Cyrillic `о` homoglyphs)
/// collapse to the same skeleton the denylist already covers.
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

/// Fold a string into the canonical shape used for reserved-name
/// matching:
///
/// 1. NFKD: collapses compatibility forms (fullwidth → ASCII,
///    ligatures → letters, etc) and splits precomposed accented
///    characters into base + combining mark.
/// 2. Strip combining marks: `"Göogle"` decomposes to `o` + U+0308
///    under NFKD; dropping the mark leaves `"Google"`.
/// 3. Strip zero-width and bidi-control characters so a caller can't
///    sneak `"Goog\u{200B}le"` past a substring check (the skeleton in
///    step 5 does NOT strip these).
/// 4. Collapse any whitespace run (incl. NBSP U+00A0, ideographic space
///    U+3000, etc) to a single ASCII space.
/// 5. Lowercase (Unicode-aware via `char::to_lowercase`): the skeleton
///    in step 6 is case-sensitive (it maps uppercase letters onto
///    uppercase representatives), so both sides must be lowercased first
///    for the substring compare to line up against the lowercase denylist.
/// 6. UTS 39 confusable skeleton (`unicode_security::skeleton`): folds
///    cross-script homoglyphs (Cyrillic `о`, Greek `ο`, …) onto a single
///    representative. The steps above feed it a pre-stripped, lowercased
///    string because the skeleton leaves invisible controls and
///    whitespace alone and does not case-fold.
///
/// Pure function, no allocations beyond the intermediate + output
/// `String`. Used by `reserved_name_hit` and exercised directly by the
/// unit tests below.
fn normalise_for_reserved_check(input: &str) -> String {
    // NFKD (compatibility decomposition) folds fullwidth / ligatures
    // into their base form AND splits precomposed accents into base +
    // combining mark — so the combining-mark strip below catches both
    // `"Go\u{0308}ogle"` (already-decomposed) and `"Göogle"`
    // (precomposed, which NFKC would keep as `ö`).
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
    // UTS 39 skeleton folds homoglyphs but is case-sensitive and leaves
    // whitespace / invisible controls alone — hence the pre-strip above.
    skeleton(stripped.trim()).collect()
}

/// Zero-width and bidi-control characters that render as nothing (or
/// flip rendering direction) and so let an attacker visually-spoof a
/// reserved name past a substring check. Includes the BOM (U+FEFF), the
/// zero-width joiner/non-joiner pair, the directional formatting set
/// (LRE/RLE/PDF/LRO/RLO), and the isolate set (LRI/RLI/FSI/PDI).
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
    //! Inline tests for the pure pieces of the DCR proxy. The DB- and
    //! HTTP-touching paths are covered by integration tests against the
    //! playground; what we want here is fast cargo-test feedback on the
    //! reserved-name normalisation pipeline (H2).
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

    /// NBSP-separated reserved name: U+00A0 is whitespace per Unicode.
    /// Strict ASCII `contains("microsoft")` would miss because the input
    /// folds to "microsoft login" (with a regular space), but it would
    /// have missed `"Microsoft\u{00A0}Login"` end-to-end because the
    /// substring `"microsoft"` is still present. We're really testing
    /// that the NBSP doesn't break anything else.
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
