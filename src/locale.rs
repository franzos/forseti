//! Request-to-locale resolution and locale-derived presentation bits.
//! Modelled on `theme.rs`: a cookie reader plus small template-facing
//! helpers, kept free of the Fluent loader (that lives in `i18n.rs`).

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use unic_langid::langid;
pub(crate) use unic_langid::LanguageIdentifier;

use crate::state::AppState;

pub(crate) const LOCALE_COOKIE: &str = "forseti_locale";
pub(crate) const SUPPORTED: &[&str] = &["en", "de"];

pub(crate) fn default_locale() -> LanguageIdentifier {
    langid!("en")
}

fn supported_langids() -> Vec<LanguageIdentifier> {
    SUPPORTED
        .iter()
        .map(|s| s.parse().expect("SUPPORTED is valid"))
        .collect()
}

/// Best supported match for the requested list, else the default.
// `fluent_langneg::negotiate_languages` is not used here because fluent-langneg 0.14
// switched its LanguageIdentifier to icu_locid, which is incompatible with unic_langid.
// A language-subtag match is sufficient for our two-locale set.
pub(crate) fn negotiate(requested: &[LanguageIdentifier]) -> LanguageIdentifier {
    let available = supported_langids();
    for req in requested {
        if let Some(matched) = available.iter().find(|a| a.language == req.language) {
            return matched.clone();
        }
    }
    default_locale()
}

/// Parse a single tag (query/cookie); accept only if it negotiates to a
/// non-default supported locale or is itself the default.
pub(crate) fn from_query_or_cookie(value: &str) -> Option<LanguageIdentifier> {
    let parsed: LanguageIdentifier = value.parse().ok()?;
    // Accept only tags whose primary language subtag is supported; narrow
    // regional variants (de-AT) to the canonical supported locale.
    if SUPPORTED.contains(&parsed.language.as_str()) {
        Some(negotiate(&[parsed]))
    } else {
        None
    }
}

pub(crate) fn from_accept_language(header: Option<&str>) -> LanguageIdentifier {
    let Some(raw) = header else {
        return default_locale();
    };
    let requested: Vec<LanguageIdentifier> = raw
        .split(',')
        .filter_map(|part| part.split(';').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    negotiate(&requested)
}

pub(crate) fn read_locale_cookie(headers: &HeaderMap) -> Option<LanguageIdentifier> {
    crate::cookies::read_cookie(headers, LOCALE_COOKIE).and_then(|v| from_query_or_cookie(&v))
}

pub(crate) fn dir_for(lang: &LanguageIdentifier) -> &'static str {
    match lang.language.as_str() {
        "ar" | "he" | "fa" | "ur" => "rtl",
        _ => "ltr",
    }
}

/// Response middleware: if the request carries a supported `?lang=` query param,
/// persist it to the `forseti_locale` cookie so the preference survives navigation.
/// No-op when `lang` is absent or unsupported.
pub(crate) async fn persist_locale_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let lang_tag: Option<String> = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("lang="))
                .and_then(from_query_or_cookie)
        })
        .map(|lang| lang.language.as_str().to_string());

    let mut resp = next.run(req).await;

    if let Some(tag) = lang_tag {
        let secure = state.cfg.self_.is_https();
        crate::web::append_set_cookie(&mut resp, Some(build_locale_cookie(&tag, secure)));
    }

    resp
}

pub(crate) fn build_locale_cookie(tag: &str, secure: bool) -> String {
    format!(
        "{}={}; Path=/; SameSite=Lax; HttpOnly; Max-Age=31536000{}",
        LOCALE_COOKIE,
        tag,
        if secure { "; Secure" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_prefers_supported_then_falls_back() {
        let de: LanguageIdentifier = "de".parse().unwrap();
        assert_eq!(negotiate(&["de-AT".parse().unwrap()]), de);
        assert_eq!(negotiate(&["fr".parse().unwrap()]), default_locale());
        assert_eq!(negotiate(&[]), default_locale());
    }

    #[test]
    fn query_or_cookie_accepts_only_supported() {
        assert_eq!(from_query_or_cookie("de"), Some("de".parse().unwrap()));
        assert_eq!(from_query_or_cookie("fr"), None);
        assert_eq!(from_query_or_cookie("garbage!"), None);
    }

    #[test]
    fn accept_language_matches_supported() {
        assert_eq!(
            from_accept_language(Some("de-DE,de;q=0.9,en;q=0.8")),
            "de".parse::<LanguageIdentifier>().unwrap()
        );
        assert_eq!(from_accept_language(None), default_locale());
    }

    #[test]
    fn dir_is_rtl_for_rtl_scripts() {
        assert_eq!(dir_for(&langid!("ar")), "rtl");
        assert_eq!(dir_for(&langid!("en")), "ltr");
    }

    #[test]
    fn build_locale_cookie_http_attrs() {
        let s = build_locale_cookie("de", false);
        assert!(
            s.starts_with("forseti_locale=de;"),
            "cookie name=value: {s}"
        );
        assert!(s.contains("Path=/"), "Path: {s}");
        assert!(s.contains("SameSite=Lax"), "SameSite: {s}");
        assert!(s.contains("HttpOnly"), "HttpOnly: {s}");
        assert!(s.contains("Max-Age=31536000"), "Max-Age: {s}");
        assert!(!s.contains("Secure"), "no Secure on http: {s}");
    }

    #[test]
    fn build_locale_cookie_https_sets_secure() {
        let s = build_locale_cookie("en", true);
        assert!(s.contains("Secure"), "Secure on https: {s}");
    }

    #[test]
    fn build_locale_cookie_unsupported_lang_not_persisted() {
        // from_query_or_cookie rejects unsupported tags; verify the guard holds
        assert!(from_query_or_cookie("fr").is_none());
        assert!(from_query_or_cookie("garbage!").is_none());
    }
}
