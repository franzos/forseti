//! Cross-cutting handler utilities used by more than one feature module
//! (version constant, return-to validation, `FlowQuery`, error-boundary template, cookie helpers).

use askama::Template;
use axum::response::Response;
use serde::Deserialize;

use crate::config::AppConfig;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

/// Package version surfaced in the layout footer, resolved at compile time from `Cargo.toml`.
pub(crate) const FORSETI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Validate a `?return_to=` before redirecting to it, guarding the post-login short-circuit
/// against open redirects (e.g. `/login?return_to=https://attacker.example/phish`).
/// Safe when path-only (`/` but not `//` or `/\`) or an absolute URL whose origin matches
/// `cfg.self_.url`; anything else falls back to `/` and logs a warn.
pub(crate) fn safe_return_to<'a>(cfg: &AppConfig, raw: &'a str) -> &'a str {
    if raw.is_empty() {
        return "/";
    }
    // Path-only: `/` but not `//` (scheme-relative) or `/\` (browsers may normalise backslash as slash).
    if let Some(rest) = raw.strip_prefix('/') {
        if rest.starts_with('/') || rest.starts_with('\\') {
            tracing::warn!(return_to = raw, "rejected open-redirect return_to");
            return "/";
        }
        return raw;
    }
    // Compare canonical origins; string-prefix matching would be fooled by `https://forseti.example.com.attacker.tld`.
    if let (Ok(forseti), Ok(candidate)) = (url::Url::parse(&cfg.self_.url), url::Url::parse(raw)) {
        if candidate.origin() == forseti.origin() {
            return raw;
        }
    }
    tracing::warn!(return_to = raw, "rejected open-redirect return_to");
    "/"
}

#[derive(Template)]
#[template(path = "error_boundary.html")]
pub(crate) struct ErrorBoundaryTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) error_title: String,
    pub(crate) error_body: String,
    pub(crate) cta_href: String,
    pub(crate) cta_label: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FlowQuery {
    pub(crate) flow: Option<String>,
    pub(crate) return_to: Option<String>,
    /// `aal=aal2` requests a step-up: login must not short-circuit on a valid `aal1` session
    /// but forward into a Kratos flow demanding the second factor.
    pub(crate) aal: Option<String>,
    /// `refresh=true` forces privileged-session re-auth: login must fall through to Kratos even when
    /// `whoami` returns a session, else the user livelocks at `privileged_session_max_age`.
    #[serde(default, deserialize_with = "deserialize_bool_str")]
    pub(crate) refresh: Option<bool>,
}

/// Coerce bare query strings (`true`/`1`/`yes`/`on`) to `Option<bool>`, since the default
/// deserializer expects JSON-ish tokens the browser doesn't send.
pub(crate) fn deserialize_bool_str<'de, D>(de: D) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(de)?;
    Ok(opt.map(|s| matches!(s.as_str(), "true" | "1" | "yes" | "on")))
}

/// Append (never replace) an optional `Set-Cookie` so it composes with any cookie the response
/// already carries. No-op on `None`; a malformed cookie string is dropped silently.
pub(crate) fn append_set_cookie(resp: &mut Response, cookie: Option<String>) {
    if let Some(value) = cookie {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut()
                .append(axum::http::header::SET_COOKIE, hv);
        }
    }
}

pub(crate) fn render_error_boundary(
    state: &AppState,
    locale: &crate::locale::LanguageIdentifier,
    title: &str,
    body: &str,
    cta_href: impl Into<String>,
    cta_label: impl Into<String>,
) -> Response {
    render(&ErrorBoundaryTemplate {
        chrome: PageChrome::from_parts(state, String::new(), String::new(), locale.clone()),
        error_title: title.to_string(),
        error_body: body.to_string(),
        cta_href: cta_href.into(),
        cta_label: cta_label.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn cfg_with_self_url(url: &str) -> AppConfig {
        let mut cfg = AppConfig::test_fixture();
        cfg.self_.url = url.into();
        cfg
    }

    #[test]
    fn safe_return_to_accepts_path() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, "/dashboard"), "/dashboard");
    }

    #[test]
    fn safe_return_to_accepts_path_with_query_and_fragment() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, "/foo?a=1&b=2"), "/foo?a=1&b=2");
        assert_eq!(safe_return_to(&cfg, "/foo#bar"), "/foo#bar");
    }

    #[test]
    fn safe_return_to_rejects_protocol_relative() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, "//evil.com"), "/");
        assert_eq!(safe_return_to(&cfg, "//evil.com/path"), "/");
    }

    #[test]
    fn safe_return_to_rejects_absolute_url_to_other_origin() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, "https://evil.example/x"), "/");
        assert_eq!(safe_return_to(&cfg, "http://forseti.example.com/x"), "/");
    }

    #[test]
    fn safe_return_to_rejects_javascript_scheme() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, "javascript:alert(1)"), "/");
    }

    #[test]
    fn safe_return_to_handles_empty() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, ""), "/");
    }

    #[test]
    fn safe_return_to_rejects_backslash_trickery() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        // Some browsers normalise `\` as `/` so `/\evil.com` could become
        // `//evil.com`, must be rejected.
        assert_eq!(safe_return_to(&cfg, "/\\evil.com"), "/");
    }

    #[test]
    fn safe_return_to_accepts_same_origin_absolute() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(
            safe_return_to(&cfg, "https://forseti.example.com/dashboard"),
            "https://forseti.example.com/dashboard"
        );
        // Trailing slash on Forseti url should not affect matching.
        let cfg2 = cfg_with_self_url("https://forseti.example.com/");
        assert_eq!(
            safe_return_to(&cfg2, "https://forseti.example.com/dashboard"),
            "https://forseti.example.com/dashboard"
        );
    }

    #[test]
    fn safe_return_to_rejects_prefix_collision() {
        // `forseti.example.com.evil.com` starts with `forseti.example.com` but
        // the next char is `.` (neither `/` nor `?`), so it must reject.
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(
            safe_return_to(&cfg, "https://forseti.example.com.evil.com/x"),
            "/"
        );
    }

    #[test]
    fn safe_return_to_accepts_just_root() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, "/"), "/");
    }
}
