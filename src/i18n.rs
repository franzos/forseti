//! Process-wide Fluent loader plus raw lookup helpers. Bidi isolation
//! is disabled here; RTL isolation is done in HTML with `<bdi>` instead.

use std::borrow::Cow;
use std::collections::HashMap;

use fluent_templates::fluent_bundle::FluentValue;
use fluent_templates::{static_loader, Loader};

use crate::locale::LanguageIdentifier;

static_loader! {
    static LOADER = {
        locales: "./locales",
        fallback_language: "en",
        customise: |bundle| bundle.set_use_isolating(false),
    };
}

pub(crate) fn lookup(lang: &LanguageIdentifier, id: &str) -> String {
    LOADER.lookup(lang, id)
}

pub(crate) fn lookup_args(
    lang: &LanguageIdentifier,
    id: &str,
    args: &HashMap<Cow<'static, str>, FluentValue<'_>>,
) -> String {
    LOADER.lookup_with_args(lang, id, args)
}

/// Convenience for the common single-numeric-variable case (binds `$n`).
pub(crate) fn lookup_n(lang: &LanguageIdentifier, id: &str, n: i64) -> String {
    let mut args: HashMap<Cow<'static, str>, FluentValue<'_>> = HashMap::new();
    args.insert(Cow::Borrowed("n"), FluentValue::from(n));
    lookup_args(lang, id, &args)
}

/// Convenience for the two-string-variable case.
pub(crate) fn lookup_2s(
    lang: &LanguageIdentifier,
    id: &str,
    k1: &str,
    v1: &str,
    k2: &str,
    v2: &str,
) -> String {
    let mut args: HashMap<Cow<'static, str>, FluentValue<'_>> = HashMap::new();
    args.insert(
        Cow::Owned(k1.to_string()),
        FluentValue::from(v1.to_string()),
    );
    args.insert(
        Cow::Owned(k2.to_string()),
        FluentValue::from(v2.to_string()),
    );
    lookup_args(lang, id, &args)
}

pub(crate) fn try_lookup_args(
    lang: &LanguageIdentifier,
    id: &str,
    args: &HashMap<Cow<'static, str>, FluentValue<'_>>,
) -> Option<String> {
    LOADER.try_lookup_with_args(lang, id, args)
}

/// Translate a Kratos message by its stable numeric id, using `context` (the
/// JSON object Kratos attaches to every message) to build Fluent variables.
///
/// JSON object keys become Fluent variable names; numbers become numeric
/// `FluentValue`s (integers preferred), strings become string `FluentValue`s;
/// nested objects and arrays are skipped.
///
/// Falls back to `fallback_text` (Kratos's own English string) when the id
/// has no entry in `kratos.ftl` OR when Fluent formatting fails (e.g. a
/// required variable is absent from `context`). Emits a `tracing::warn` on
/// the fallback path so runtime drift is observable.
pub(crate) fn translate_ory(
    locale: &LanguageIdentifier,
    id: u64,
    context: &serde_json::Value,
    fallback_text: &str,
) -> String {
    let mut args: HashMap<Cow<'static, str>, FluentValue<'_>> = HashMap::new();
    if let Some(obj) = context.as_object() {
        for (k, v) in obj {
            let fv = match v {
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        FluentValue::from(i)
                    } else if let Some(f) = n.as_f64() {
                        FluentValue::from(f)
                    } else {
                        continue;
                    }
                }
                serde_json::Value::String(s) => FluentValue::from(s.clone()),
                _ => continue,
            };
            args.insert(Cow::Owned(k.clone()), fv);
        }
    }
    let key = format!("kratos-{id}");
    match try_lookup_args(locale, &key, &args) {
        Some(translated) => translated,
        None => {
            tracing::warn!(kratos_id = id, "unmapped/failed Kratos message id");
            fallback_text.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Literal that fluent-templates' infallible lookup emits on any failure.
    const MISSING_PREFIX: &str = "Unknown localization key:";

    #[test]
    fn looks_up_seed_key_per_locale() {
        let en: LanguageIdentifier = "en".parse().unwrap();
        let de: LanguageIdentifier = "de".parse().unwrap();
        assert_eq!(lookup(&en, "common-action-save"), "Save");
        assert_eq!(lookup(&de, "common-action-save"), "Speichern");
    }

    #[test]
    fn missing_key_returns_placeholder_not_panic() {
        let en: LanguageIdentifier = "en".parse().unwrap();
        assert!(lookup(&en, "does-not-exist").contains(MISSING_PREFIX));
    }

    #[test]
    fn missing_key_in_de_falls_back_to_en() {
        let de: LanguageIdentifier = "de".parse().unwrap();
        assert_eq!(lookup(&de, "nav-sign-out"), "Abmelden");
    }

    // --- translate_ory tests ------------------------------------------------

    #[test]
    fn translate_ory_string_context_provider() {
        let en: LanguageIdentifier = "en".parse().unwrap();
        let de: LanguageIdentifier = "de".parse().unwrap();
        let ctx = serde_json::json!({"provider": "Google"});
        // en: "Sign in with Google"
        assert_eq!(
            translate_ory(&en, 1010002, &ctx, "Sign in with Google"),
            "Sign in with Google"
        );
        // de: "Mit Google anmelden"
        assert_eq!(
            translate_ory(&de, 1010002, &ctx, "Sign in with Google"),
            "Mit Google anmelden"
        );
    }

    #[test]
    fn translate_ory_numeric_context_min_length() {
        let en: LanguageIdentifier = "en".parse().unwrap();
        let ctx = serde_json::json!({"min_length": 8, "actual_length": 3});
        let result = translate_ory(&en, 4000003, &ctx, "length must be >= 8, but got 3");
        assert_eq!(result, "length must be >= 8, but got 3");
    }

    #[test]
    fn translate_ory_unmapped_id_returns_fallback() {
        let en: LanguageIdentifier = "en".parse().unwrap();
        let result = translate_ory(&en, 9999999, &serde_json::Value::Null, "fallback text");
        assert_eq!(result, "fallback text");
    }

    #[test]
    fn translate_ory_interpolation_missing_returns_fallback() {
        // kratos-1010002 requires $provider; passing empty context means the
        // Fluent formatter encounters a missing variable, which fluent-templates
        // reports as a formatting error and returns None from try_lookup_with_args.
        let en: LanguageIdentifier = "en".parse().unwrap();
        let result = translate_ory(
            &en,
            1010002,
            &serde_json::Value::Null,
            "Sign in with GitHub",
        );
        assert_eq!(result, "Sign in with GitHub");
    }

    /// Version-pinned fixture: every mapped Kratos id that interpolates context
    /// is exercised with a realistic `context` shape in both locales. If a
    /// catalog message (en or de) references a variable the captured context no
    /// longer supplies (an Ory field rename like `provider` -> `provider_id`, or
    /// the length messages' `min_length`/`actual_length`), Fluent formatting
    /// fails, `translate_ory` returns the sentinel fallback, and this fails
    /// loudly instead of silently degrading a live error string.
    #[test]
    fn translate_ory_fixtures_resolve_in_every_locale() {
        const SENTINEL: &str = "\u{1}FALLBACK\u{1}";
        // (id, context) pairs captured from the pinned Kratos version.
        let fixtures: &[(u64, serde_json::Value)] = &[
            (1010002, serde_json::json!({ "provider": "Google" })),
            (1040002, serde_json::json!({ "provider": "GitHub" })),
            (1050002, serde_json::json!({ "provider": "GitLab" })),
            (1050003, serde_json::json!({ "provider": "GitLab" })),
            (1050018, serde_json::json!({ "display_name": "YubiKey 5" })),
            (
                1050020,
                serde_json::json!({ "display_name": "iCloud Passkey" }),
            ),
            (
                1060004,
                serde_json::json!({ "masked_address": "m****@example.com" }),
            ),
            (4000002, serde_json::json!({ "property": "email" })),
            (
                4000003,
                serde_json::json!({ "min_length": 8, "actual_length": 3 }),
            ),
            (4000005, serde_json::json!({ "reason": "it is too common" })),
            (
                4000032,
                serde_json::json!({ "min_length": 8, "actual_length": 3 }),
            ),
        ];
        for locale_tag in ["en", "de"] {
            let locale: LanguageIdentifier = locale_tag.parse().unwrap();
            for (id, ctx) in fixtures {
                let out = translate_ory(&locale, *id, ctx, SENTINEL);
                assert_ne!(
                    out, SENTINEL,
                    "kratos-{id} ({locale_tag}) fell back: context {ctx} does not satisfy the catalog message's variables"
                );
                assert!(
                    !out.contains("{ $") && !out.contains('\u{1}'),
                    "kratos-{id} ({locale_tag}) left an unresolved placeable: {out:?}"
                );
            }
        }
    }
}
