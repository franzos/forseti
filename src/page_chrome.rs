//! Shared page-chrome view-model embedded in every template struct.
//!
//! `base.html`, `card.html`, and `admin/admin_shell.html` all consume the
//! same four fields (brand, version, user_email, csrf_token). Before this
//! struct existed each child template re-declared them as four flat
//! fields, so adding a new chrome field meant editing ~34 structs and
//! every constructor. The embedded-struct shape collapses that to one
//! place: add a field here, then read it from `chrome.<field>` in the
//! base template.

use std::borrow::Cow;
use std::collections::HashMap;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use fluent_templates::fluent_bundle::FluentValue;

use crate::config::BrandConfig;
use crate::extractors::{app_state, Csrf, OptionalSession};
use crate::locale::{dir_for, LanguageIdentifier};
use crate::state::AppState;
use crate::web::FORSETI_VERSION;

/// General locale precedence ladder: `?lang=` query param, then `forseti_locale`
/// cookie, then the `preferred_language` identity trait from the session,
/// then `Accept-Language`, then `en`. The `ui_locales` step for login/consent
/// lands in P2.
pub(crate) fn resolve_locale(parts: &Parts, session: &OptionalSession) -> LanguageIdentifier {
    if let Some(lang) = extract_query_lang(parts) {
        return lang;
    }
    if let Some(lang) = crate::locale::read_locale_cookie(&parts.headers) {
        return lang;
    }
    if let Some(lang) = session_preferred_language(session) {
        return lang;
    }
    let accept = parts
        .headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    crate::locale::from_accept_language(accept)
}

/// Locale resolution for OIDC login/consent surfaces. Adds a `ui_locales`
/// step between `?lang=` (highest) and the general cookie/trait/Accept-Language
/// ladder: D1 precedence is `?lang=` > `ui_locales` > cookie > trait > Accept-Language > en.
pub(crate) fn resolve_locale_for_flow(
    parts: &Parts,
    session: &OptionalSession,
    ui_locales: Option<&[String]>,
) -> LanguageIdentifier {
    if let Some(lang) = extract_query_lang(parts) {
        return lang;
    }
    if let Some(locs) = ui_locales {
        let parsed: Vec<LanguageIdentifier> = locs.iter().filter_map(|s| s.parse().ok()).collect();
        // Only accept the result when at least one requested tag's primary
        // language subtag is in SUPPORTED; otherwise fall through.
        let any_match = parsed
            .iter()
            .any(|p| crate::locale::SUPPORTED.contains(&p.language.as_str()));
        if any_match {
            return crate::locale::negotiate(&parsed);
        }
    }
    resolve_locale(parts, session)
}

/// Extract the explicit `?lang=<tag>` override from the request URI.
/// Shared by `resolve_locale` and `resolve_locale_for_flow` to avoid duplication.
fn extract_query_lang(parts: &Parts) -> Option<LanguageIdentifier> {
    parts
        .uri
        .query()?
        .split('&')
        .find_map(|kv| kv.strip_prefix("lang="))
        .and_then(crate::locale::from_query_or_cookie)
}

fn session_preferred_language(session: &OptionalSession) -> Option<LanguageIdentifier> {
    let s = session.ok()?;
    let tag = s
        .identity
        .as_ref()?
        .traits
        .as_ref()?
        .get("preferred_language")?
        .as_str()?;
    crate::locale::from_query_or_cookie(tag)
}

/// Extractor that resolves the request locale via the full precedence ladder
/// without requiring a separate `OptionalSession` in the handler signature.
pub(crate) struct ReqLocale(pub(crate) LanguageIdentifier);

impl<S> FromRequestParts<S> for ReqLocale
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = OptionalSession::from_request_parts(parts, state)
            .await
            .expect("OptionalSession extractor is infallible");
        Ok(ReqLocale(resolve_locale(parts, &session)))
    }
}

/// Page chrome shared by every template that extends `base.html` or
/// `card.html`. The four fields show up in the header (`user_email`,
/// `csrf_token` for the logout button) and footer (`version`,
/// `brand.name`).
pub(crate) struct PageChrome {
    pub(crate) brand: BrandConfig,
    pub(crate) version: &'static str,
    /// Empty string for anonymous pages — `base.html` hides the
    /// "Signed in as / Sign out" block when empty.
    pub(crate) user_email: String,
    /// Empty string for pages outside CSRF middleware. The logout button
    /// in `base.html` won't render usefully without it, but it stays
    /// hidden anyway when `user_email` is empty.
    pub(crate) csrf_token: String,
    /// True when `user_email` is in `[admin].allowed_emails`. Drives the
    /// "Admin" top-nav link in `base.html`.
    pub(crate) is_admin: bool,
    /// Appearance preference, read from the `forseti_theme` cookie by the
    /// `Chrome` extractor. Defaults to `System` for directly-constructed
    /// chrome (error boundary etc.) — the client script still applies it.
    pub(crate) theme_pref: crate::theme::ThemePref,
    /// Negotiated request locale. Drives `<html lang/dir>` and every
    /// `chrome.t(...)` lookup. Required at construction, never defaulted.
    pub(crate) locale: LanguageIdentifier,
}

impl PageChrome {
    /// Build from pre-extracted parts. `user_email` is the empty string
    /// for anonymous / error pages; `csrf_token` is the empty string
    /// outside CSRF middleware. `is_admin` is derived from the operator
    /// allowlist, so anonymous pages (empty email) never get the flag.
    pub(crate) fn from_parts(
        state: &AppState,
        user_email: String,
        csrf_token: String,
        locale: LanguageIdentifier,
    ) -> Self {
        let is_admin = state.cfg.admin.is_admin(&user_email);
        Self::from_brand_with_admin(
            state.cfg.brand.clone(),
            user_email,
            csrf_token,
            is_admin,
            locale,
        )
    }

    /// Assemble from an already-snapshotted brand plus an explicit admin
    /// verdict. The single place the chrome literal is built.
    pub(crate) fn from_brand_with_admin(
        brand: BrandConfig,
        user_email: String,
        csrf_token: String,
        is_admin: bool,
        locale: LanguageIdentifier,
    ) -> Self {
        Self {
            brand,
            version: FORSETI_VERSION,
            user_email,
            csrf_token,
            is_admin,
            theme_pref: crate::theme::ThemePref::System,
            locale,
        }
    }

    pub(crate) fn t(&self, id: &str) -> String {
        crate::i18n::lookup(&self.locale, id)
    }

    pub(crate) fn tv_count(&self, id: &str, count: &i64) -> String {
        let mut args: HashMap<Cow<'static, str>, FluentValue<'_>> = HashMap::new();
        args.insert(Cow::Borrowed("count"), FluentValue::from(*count));
        crate::i18n::lookup_args(&self.locale, id, &args)
    }

    pub(crate) fn tv1(&self, id: &str, name: &str, val: &str) -> String {
        let mut args: HashMap<Cow<'static, str>, FluentValue<'_>> = HashMap::new();
        args.insert(
            Cow::Owned(name.to_string()),
            FluentValue::from(val.to_string()),
        );
        crate::i18n::lookup_args(&self.locale, id, &args)
    }

    pub(crate) fn tv3(
        &self,
        id: &str,
        n1: &str,
        v1: &str,
        n2: &str,
        v2: &str,
        n3: &str,
        v3: &str,
    ) -> String {
        let mut args: HashMap<Cow<'static, str>, FluentValue<'_>> = HashMap::new();
        args.insert(
            Cow::Owned(n1.to_string()),
            FluentValue::from(v1.to_string()),
        );
        args.insert(
            Cow::Owned(n2.to_string()),
            FluentValue::from(v2.to_string()),
        );
        args.insert(
            Cow::Owned(n3.to_string()),
            FluentValue::from(v3.to_string()),
        );
        crate::i18n::lookup_args(&self.locale, id, &args)
    }

    pub(crate) fn is_locale(&self, tag: &str) -> bool {
        self.locale.language.as_str() == tag
    }

    pub(crate) fn dir(&self) -> &'static str {
        dir_for(&self.locale)
    }
}

/// Extractor that builds a [`PageChrome`] from the current request:
/// probes the session for the user email, reads the CSRF token from the
/// middleware-set extension, and snapshots the brand from state. Handlers
/// take this instead of plumbing `OptionalSession` + `Csrf` separately
/// when all they want is to render chrome.
pub(crate) struct Chrome(pub(crate) PageChrome);

impl<S> FromRequestParts<S> for Chrome
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = OptionalSession::from_request_parts(parts, state)
            .await
            .expect("OptionalSession extractor is infallible");
        let user_email = session.email().unwrap_or_default().to_string();
        let app_state = app_state(parts, state).await;
        let csrf = Csrf::from_request_parts(parts, state)
            .await
            .expect("Csrf extractor is infallible");
        let locale = resolve_locale(parts, &session);
        let mut chrome = PageChrome::from_parts(&app_state, user_email, csrf.0, locale);
        chrome.theme_pref = crate::theme::read_theme_cookie(&parts.headers);
        Ok(Chrome(chrome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrandConfig;
    use crate::extractors::OptionalSession;
    use axum::http::{HeaderMap, Request};

    fn chrome(locale: &str) -> PageChrome {
        PageChrome::from_brand_with_admin(
            BrandConfig {
                name: String::new(),
                support_email: None,
                logo_url: None,
                consent_intro: String::new(),
            },
            String::new(),
            String::new(),
            false,
            locale.parse().unwrap(),
        )
    }

    #[test]
    fn t_resolves_per_locale() {
        assert_eq!(chrome("en").t("common-action-save"), "Save");
        assert_eq!(chrome("de").t("common-action-save"), "Speichern");
    }

    #[test]
    fn tv_count_binds_count_variable() {
        assert_eq!(chrome("en").tv_count("test-count", &1), "1 item");
        assert_eq!(chrome("en").tv_count("test-count", &3), "3 items");
    }

    #[test]
    fn dir_defaults_ltr() {
        assert_eq!(chrome("en").dir(), "ltr");
    }

    fn parts_with(headers: HeaderMap, uri: &str) -> axum::http::request::Parts {
        let mut req = Request::builder().uri(uri).body(()).unwrap();
        *req.headers_mut() = headers;
        req.into_parts().0
    }

    #[test]
    fn resolve_prefers_query_then_cookie_then_accept_language() {
        // query wins
        let p = parts_with(HeaderMap::new(), "/?lang=de");
        assert_eq!(
            resolve_locale(&p, &OptionalSession::None).language.as_str(),
            "de"
        );

        // cookie next
        let mut h = HeaderMap::new();
        h.insert("cookie", "forseti_locale=de".parse().unwrap());
        let p = parts_with(h, "/");
        assert_eq!(
            resolve_locale(&p, &OptionalSession::None).language.as_str(),
            "de"
        );

        // accept-language fallback
        let mut h = HeaderMap::new();
        h.insert("accept-language", "de-DE,de;q=0.9".parse().unwrap());
        let p = parts_with(h, "/");
        assert_eq!(
            resolve_locale(&p, &OptionalSession::None).language.as_str(),
            "de"
        );

        // nothing -> en
        let p = parts_with(HeaderMap::new(), "/");
        assert_eq!(
            resolve_locale(&p, &OptionalSession::None).language.as_str(),
            "en"
        );
    }

    #[test]
    fn resolve_for_flow_query_wins_over_ui_locales() {
        // explicit ?lang=en beats ui_locales=["de"]
        let p = parts_with(HeaderMap::new(), "/?lang=en");
        let ui = vec!["de".to_string()];
        assert_eq!(
            resolve_locale_for_flow(&p, &OptionalSession::None, Some(&ui))
                .language
                .as_str(),
            "en"
        );
    }

    #[test]
    fn resolve_for_flow_ui_locales_wins_over_cookie() {
        // ui_locales=["de"] beats forseti_locale=en cookie
        let mut h = HeaderMap::new();
        h.insert("cookie", "forseti_locale=en".parse().unwrap());
        let p = parts_with(h, "/");
        let ui = vec!["de".to_string()];
        assert_eq!(
            resolve_locale_for_flow(&p, &OptionalSession::None, Some(&ui))
                .language
                .as_str(),
            "de"
        );
    }

    #[test]
    fn resolve_for_flow_unsupported_ui_locales_falls_through_to_cookie() {
        // ui_locales=["fr"] is unsupported; falls back to cookie "de"
        let mut h = HeaderMap::new();
        h.insert("cookie", "forseti_locale=de".parse().unwrap());
        let p = parts_with(h, "/");
        let ui = vec!["fr".to_string()];
        assert_eq!(
            resolve_locale_for_flow(&p, &OptionalSession::None, Some(&ui))
                .language
                .as_str(),
            "de"
        );
    }

    #[test]
    fn resolve_for_flow_none_ui_locales_equals_resolve_locale() {
        let mut h = HeaderMap::new();
        h.insert("cookie", "forseti_locale=de".parse().unwrap());
        let p = parts_with(h, "/");
        assert_eq!(
            resolve_locale_for_flow(&p, &OptionalSession::None, None),
            resolve_locale(&p, &OptionalSession::None),
        );

        let p2 = parts_with(HeaderMap::new(), "/");
        assert_eq!(
            resolve_locale_for_flow(&p2, &OptionalSession::None, None),
            resolve_locale(&p2, &OptionalSession::None),
        );
    }
}
