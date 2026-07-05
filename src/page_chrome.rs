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

/// Build the "<customer> · <email>" licensee watermark from the runtime
/// license, or `None` when unlicensed. Shared by `with_license_watermark`
/// (the `from_parts` path) and `AdminCtx` (which builds chrome via the
/// stateless `from_brand_with_admin`), so every admin surface shows the same
/// string regardless of which chrome path rendered it.
pub(crate) fn license_watermark(state: &AppState) -> Option<String> {
    match &*state.license.status() {
        crate::commercial::LicenseStatus::Active(l)
        | crate::commercial::LicenseStatus::Grace(l)
        | crate::commercial::LicenseStatus::Expired(l) => {
            Some(format!("{} · {}", l.customer, l.email))
        }
        crate::commercial::LicenseStatus::Unlicensed => None,
    }
}

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
    /// Pre-rendered `:root` CSS custom properties for the resolved theme.
    /// Defaults to the global (operator) theme; tenant pages override via
    /// [`PageChrome::with_theme`].
    pub(crate) theme_css_root: String,
    /// Pre-rendered `html.dark` CSS custom properties for the resolved
    /// theme's dark variant.
    pub(crate) theme_css_dark: String,
    /// `Some(slug)` when a tenant theme with an uploaded logo is active;
    /// the card icon then renders `/branding/{slug}/logo` instead of the
    /// operator default.
    pub(crate) logo_slug: Option<String>,
    /// `Some("<customer> · <email>")` when a commercial license is present
    /// (Active/Grace/Expired); the admin shell surfaces it so a leaked key
    /// advertises the buyer. `None` for unlicensed installs.
    pub(crate) license_watermark: Option<String>,
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
        .with_license_watermark(state)
    }

    /// Like [`Self::from_parts`] but themed by the caller's active org. The
    /// `memberships` slice is loaded once by the caller (or the [`ThemedChrome`]
    /// extractor) and reused for the nav switcher, so no extra query is issued.
    pub(crate) fn from_parts_themed(
        state: &AppState,
        memberships: &[crate::orgs::Membership],
        headers: &axum::http::HeaderMap,
        user_email: String,
        csrf_token: String,
        locale: LanguageIdentifier,
    ) -> Self {
        let chrome = Self::from_parts(state, user_email, csrf_token, locale);
        crate::theming::apply_active_org_theme(
            chrome,
            &state.cfg.brand,
            &state.cookie_secret,
            state.cfg.orgs.active_org_cookie_ttl_seconds,
            memberships,
            headers,
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
        let theme = crate::theming::resolve(
            &crate::theming::TokenOverrides::default(),
            &crate::theming::global_overrides(&brand),
        );
        Self {
            brand,
            version: FORSETI_VERSION,
            user_email,
            csrf_token,
            is_admin,
            theme_pref: crate::theme::ThemePref::System,
            locale,
            theme_css_root: theme.css_root(),
            theme_css_dark: theme.css_dark(),
            logo_slug: None,
            license_watermark: None,
        }
    }

    /// Override the chrome's theme, e.g. with a tenant-resolved theme
    /// instead of the global default set by [`Self::from_brand_with_admin`].
    pub(crate) fn with_theme(mut self, theme: crate::theming::ResolvedTheme) -> Self {
        self.theme_css_root = theme.css_root();
        self.theme_css_dark = theme.css_dark();
        self
    }

    /// Point the card icon at the tenant's uploaded logo instead of the
    /// operator default.
    pub(crate) fn with_logo_slug(mut self, slug: String) -> Self {
        self.logo_slug = Some(slug);
        self
    }

    /// Stamp the licensee identity from the runtime license handle so the
    /// admin shell can surface "Licensed to <customer> · <email>". `None`
    /// when unlicensed.
    pub(crate) fn with_license_watermark(mut self, state: &AppState) -> Self {
        self.license_watermark = license_watermark(state);
        self
    }

    /// Defence-in-depth: strip `\`/control chars so the operator brand name can't escape the CSS string quote.
    pub(crate) fn brand_name_css(&self) -> String {
        self.brand
            .name
            .chars()
            .filter(|c| *c != '\\' && !c.is_control())
            .take(128)
            .collect()
    }

    /// Defence-in-depth for the CSS `url("...")` sink in `base.html`: strip
    /// backslash, quotes, `}`/`;` and control chars so the logo URL can't
    /// escape the string or terminate the declaration.
    pub(crate) fn logo_url_css(&self) -> String {
        self.brand
            .logo_url
            .as_deref()
            .unwrap_or_default()
            .chars()
            .filter(|c| !matches!(c, '\\' | '"' | '\'' | '}' | ';') && !c.is_control())
            .take(2048)
            .collect()
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

    // i18n helper: id plus three name/value pairs; a struct would obscure the call site.
    #[allow(clippy::too_many_arguments)]
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

/// Themed counterpart of [`Chrome`] for authenticated app pages: loads the
/// caller's memberships once, themes the chrome by the active org, and hands
/// the same `memberships` back so a page rendering the org switcher can pass
/// them to `build_nav` instead of re-querying.
pub(crate) struct ThemedChrome {
    pub(crate) chrome: PageChrome,
    // Reused by `build_nav` on pages that also render the org switcher.
    #[allow(dead_code)]
    pub(crate) memberships: Vec<crate::orgs::Membership>,
}

impl<S> FromRequestParts<S> for ThemedChrome
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
        let memberships = match session.identity_id() {
            Some(id) => crate::orgs::list_memberships(&app_state.db, id)
                .await
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let mut chrome = PageChrome::from_parts_themed(
            &app_state,
            &memberships,
            &parts.headers,
            user_email,
            csrf.0,
            locale,
        );
        chrome.theme_pref = crate::theme::read_theme_cookie(&parts.headers);
        Ok(ThemedChrome {
            chrome,
            memberships,
        })
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
                theme_preset: None,
                brand_primary: None,
                brand_on_primary: None,
                brand_secondary: None,
                operator_trust_anchor: None,
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

    fn chrome_named(name: &str) -> PageChrome {
        PageChrome::from_brand_with_admin(
            BrandConfig {
                name: name.to_string(),
                support_email: None,
                logo_url: None,
                consent_intro: String::new(),
                theme_preset: None,
                brand_primary: None,
                brand_on_primary: None,
                brand_secondary: None,
                operator_trust_anchor: None,
            },
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        )
    }

    #[test]
    fn brand_name_css_strips_backslash() {
        assert_eq!(chrome_named("Acme\\").brand_name_css(), "Acme");
    }

    #[test]
    fn brand_name_css_strips_control_chars() {
        assert_eq!(chrome_named("Acme\nCorp\t!").brand_name_css(), "AcmeCorp!");
    }

    #[test]
    fn brand_name_css_clamps_to_128_chars() {
        let long_name = "A".repeat(500);
        assert_eq!(chrome_named(&long_name).brand_name_css().len(), 128);
    }

    fn chrome_with_logo(url: &str) -> PageChrome {
        let mut c = chrome("en");
        c.brand.logo_url = Some(url.to_string());
        c
    }

    #[test]
    fn logo_url_css_strips_string_and_declaration_breakers() {
        assert_eq!(
            chrome_with_logo("https://ex.com/a\\\"b'};.png\n").logo_url_css(),
            "https://ex.com/ab.png"
        );
    }

    #[test]
    fn logo_url_css_passes_plain_url_through() {
        assert_eq!(
            chrome_with_logo("https://example.com/logo.svg?v=2").logo_url_css(),
            "https://example.com/logo.svg?v=2"
        );
    }

    #[test]
    fn logo_url_css_empty_when_unset() {
        assert_eq!(chrome("en").logo_url_css(), "");
    }

    #[test]
    fn operator_trust_anchor_flows_onto_chrome_brand() {
        let brand = BrandConfig {
            operator_trust_anchor: Some("Secured by Acme Operator".to_string()),
            ..chrome("en").brand
        };
        let chrome = PageChrome::from_brand_with_admin(
            brand,
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        );
        assert_eq!(
            chrome.brand.operator_trust_anchor.as_deref(),
            Some("Secured by Acme Operator")
        );
    }

    #[test]
    fn operator_trust_anchor_survives_tenant_theme_override() {
        let brand = BrandConfig {
            operator_trust_anchor: Some("Secured by Acme Operator".to_string()),
            ..chrome("en").brand
        };
        let tenant_theme = crate::theming::resolve(
            &crate::theming::TokenOverrides::default(),
            &crate::theming::TokenOverrides::default(),
        );
        let chrome = PageChrome::from_brand_with_admin(
            brand,
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        )
        .with_theme(tenant_theme);
        assert_eq!(
            chrome.brand.operator_trust_anchor.as_deref(),
            Some("Secured by Acme Operator")
        );
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
        // ui_locales=["ja"] is unsupported; falls back to cookie "de"
        let mut h = HeaderMap::new();
        h.insert("cookie", "forseti_locale=de".parse().unwrap());
        let p = parts_with(h, "/");
        let ui = vec!["ja".to_string()];
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
