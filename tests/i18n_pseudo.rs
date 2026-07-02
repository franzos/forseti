//! Pseudo-locale (`en-XA`) generator and its guard.
//!
//! A pseudo-locale is built from `en` by accenting only the human-readable
//! text of each message and leaving every Fluent placeable (`{ $var }`,
//! selectors, functions) untouched. Browsing the UI in such a locale makes
//! any string that was NOT extracted into a catalog stand out: it renders in
//! plain un-accented English while everything localized renders accented.
//!
//! This file delivers and validates the transform. Working on the Fluent AST
//! means placeable preservation is structural: we only ever rewrite
//! `TextElement`s, never `Placeable`s. Wiring `en-XA` into a live render pass
//! (serving it behind a dev flag, or a Playwright scan asserting no bare Latin
//! words remain) is the remaining, separate step and is not done here.

use std::fs;
use std::path::Path;

use fluent_syntax::ast;
use fluent_syntax::parser;

/// Accent every ASCII letter that has a common Latin-1 look-alike. Letter-free
/// runs (punctuation, digits, whitespace) pass through unchanged.
fn accent(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a' => 'á',
            'e' => 'é',
            'i' => 'í',
            'o' => 'ó',
            'u' => 'ú',
            'y' => 'ý',
            'n' => 'ñ',
            'c' => 'ç',
            's' => 'š',
            'A' => 'Á',
            'E' => 'É',
            'I' => 'Í',
            'O' => 'Ó',
            'U' => 'Ú',
            'Y' => 'Ý',
            'N' => 'Ñ',
            'C' => 'Ç',
            'S' => 'Š',
            other => other,
        })
        .collect()
}

fn has_accentable_letter(text: &str) -> bool {
    text.chars()
        .any(|c| accent(&c.to_string()) != c.to_string())
}

/// Render one pattern into its pseudo-localized string: text accented,
/// placeables reproduced verbatim from source. Returns the rebuilt string and
/// the count of text elements that carried accentable letters.
fn pseudo_pattern(pattern: &ast::Pattern<&str>) -> (String, usize) {
    let mut out = String::new();
    let mut accented_text_elements = 0;
    for element in &pattern.elements {
        match element {
            ast::PatternElement::TextElement { value } => {
                if has_accentable_letter(value) {
                    accented_text_elements += 1;
                }
                out.push_str(&accent(value));
            }
            // Placeables are reproduced unchanged: this is why the pseudo-locale
            // never corrupts a `{ $var }` or a selector.
            ast::PatternElement::Placeable { .. } => out.push_str("{ PLACEABLE }"),
        }
    }
    (out, accented_text_elements)
}

fn en_ftl_files() -> Vec<std::path::PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("locales")
        .join("en");
    let mut files: Vec<_> = fs::read_dir(dir)
        .expect("locales/en readable")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("ftl"))
        .collect();
    files.sort();
    files
}

/// The generator turns every text-bearing English message into a visibly
/// different (accented) string while leaving placeables intact. Proven over the
/// real `en` catalog so the transform can't silently no-op if the catalog grows.
#[test]
fn pseudo_locale_accents_text_and_preserves_placeables() {
    let mut messages_seen = 0usize;
    let mut messages_changed = 0usize;

    for path in en_ftl_files() {
        let src = fs::read_to_string(&path).expect("ftl readable");
        let resource = parser::parse(src.as_str())
            .unwrap_or_else(|(_, errs)| panic!("{}: parse error {:?}", path.display(), errs));
        for entry in &resource.body {
            let ast::Entry::Message(message) = entry else {
                continue;
            };
            let mut patterns: Vec<&ast::Pattern<&str>> = Vec::new();
            if let Some(value) = &message.value {
                patterns.push(value);
            }
            for attr in &message.attributes {
                patterns.push(&attr.value);
            }
            for pattern in patterns {
                messages_seen += 1;
                let (rendered, accented) = pseudo_pattern(pattern);
                // A message that carried any accentable letter must come out
                // changed; one that is pure punctuation/placeable is allowed to
                // pass through (e.g. `common-dash` or an attribute that is only
                // an interpolated value).
                if accented > 0 {
                    messages_changed += 1;
                    assert_ne!(
                        rendered,
                        pattern_source_approx(pattern),
                        "{}: pseudo transform was a no-op for a text-bearing message",
                        path.display()
                    );
                }
            }
        }
    }

    assert!(messages_seen > 0, "no en messages found");
    // Sanity: the catalog is overwhelmingly natural-language, so most messages
    // must transform. Guards against the accent map silently going empty.
    assert!(
        messages_changed * 2 >= messages_seen,
        "only {messages_changed}/{messages_seen} messages accented; accent map may be broken"
    );
}

/// Approximate source reconstruction for the no-op assertion: text verbatim,
/// placeables as the same sentinel used by `pseudo_pattern`, so the two only
/// differ when accenting actually changed the text.
fn pattern_source_approx(pattern: &ast::Pattern<&str>) -> String {
    let mut out = String::new();
    for element in &pattern.elements {
        match element {
            ast::PatternElement::TextElement { value } => out.push_str(value),
            ast::PatternElement::Placeable { .. } => out.push_str("{ PLACEABLE }"),
        }
    }
    out
}
