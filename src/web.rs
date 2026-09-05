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
    // Control chars (e.g. CR/LF from a decoded `%0d%0a`) would panic `Redirect::to` when it
    // builds the `HeaderValue`; reject before either branch can hand `raw` back to a caller.
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        tracing::warn!("rejected return_to with control characters");
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
    if let (Ok(forseti), Ok(candidate)) = (url::Url::parse(&cfg.self_.url), url::Url::parse(raw))
        && candidate.origin() == forseti.origin()
    {
        return raw;
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
    /// Forwarded from `/oauth/login` (Hydra's `request_url`) so `/login` can
    /// theme itself from the org's public branding; ignored by every other
    /// consumer of `FlowQuery`.
    pub(crate) organization_id: Option<String>,
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
    if let Some(value) = cookie
        && let Ok(hv) = axum::http::HeaderValue::from_str(&value)
    {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, hv);
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

/// Gate for a client-supplied URL (`client_uri`, `logo_uri`) before it is
/// rendered as an `href` or `<img src>` on an authenticated page. Dynamic
/// and CIMD registration make these attacker-controllable, Askama escapes
/// quotes but not schemes, and the CSP carries no `script-src`, so an
/// unchecked value is a `javascript:` link or a tracking beacon. Requires
/// https, no userinfo, and a public-looking DNS name: IP-literal hosts and
/// obviously internal names are dropped. `allow_private` (the CIMD dev
/// hatch) additionally admits http and any host. `None` on any failure.
pub(crate) fn safe_external_uri(raw: &str, allow_private: bool) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => return None,
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host()?;
    if allow_private {
        return Some(raw.to_string());
    }
    let host = match host {
        url::Host::Domain(d) => d.trim_end_matches('.').to_ascii_lowercase(),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
    };
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || !host.contains('.')
    {
        return None;
    }
    Some(raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn safe(raw: &str) -> Option<String> {
        safe_external_uri(raw, false)
    }

    #[test]
    fn safe_external_uri_accepts_https_public_hosts() {
        assert_eq!(
            safe("https://cdn.bank.app/logo.png").as_deref(),
            Some("https://cdn.bank.app/logo.png")
        );
        assert_eq!(
            safe("https://bank.app:8443/logo.svg").as_deref(),
            Some("https://bank.app:8443/logo.svg")
        );
    }

    #[test]
    fn safe_external_uri_rejects_non_https_and_malformed() {
        assert!(safe("http://bank.app/logo.png").is_none());
        assert!(safe("javascript:alert(1)").is_none());
        assert!(safe("JavaScript:alert(1)").is_none());
        assert!(safe("data:text/html,<script>alert(1)</script>").is_none());
        assert!(safe("file:///etc/passwd").is_none());
        assert!(safe("/relative/logo.png").is_none());
        assert!(safe("").is_none());
    }

    #[test]
    fn safe_external_uri_rejects_ip_literal_hosts() {
        assert!(safe("https://127.0.0.1/logo.png").is_none());
        assert!(safe("https://10.0.0.1/logo.png").is_none());
        assert!(safe("https://169.254.169.254/latest/meta-data/").is_none());
        assert!(safe("https://8.8.8.8/logo.png").is_none());
        assert!(safe("https://[::1]/logo.png").is_none());
        assert!(safe("https://[fe80::1]/logo.png").is_none());
    }

    #[test]
    fn safe_external_uri_rejects_internal_names() {
        assert!(safe("https://localhost/logo.png").is_none());
        assert!(safe("https://LOCALHOST/logo.png").is_none());
        assert!(safe("https://foo.localhost/logo.png").is_none());
        assert!(safe("https://printer.local/logo.png").is_none());
        assert!(safe("https://vault.internal/logo.png").is_none());
        assert!(safe("https://intranet/logo.png").is_none());
        assert!(safe("https://localhost./logo.png").is_none());
    }

    #[test]
    fn safe_external_uri_rejects_userinfo() {
        assert!(safe("https://user:pass@bank.app/logo.png").is_none());
        assert!(safe("https://user@bank.app/logo.png").is_none());
    }

    #[test]
    fn safe_external_uri_private_hatch_admits_http_loopback_only_for_real_urls() {
        assert_eq!(
            safe_external_uri("http://localhost:8080/app", true).as_deref(),
            Some("http://localhost:8080/app")
        );
        assert_eq!(
            safe_external_uri("http://127.0.0.1/app", true).as_deref(),
            Some("http://127.0.0.1/app")
        );
        assert!(safe_external_uri("javascript:alert(1)", true).is_none());
        assert!(safe_external_uri("http://user:pw@localhost/app", true).is_none());
    }

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
    fn safe_return_to_rejects_control_chars() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        // A decoded `%0d%0a` reaching `Redirect::to` would panic on the invalid HeaderValue.
        assert_eq!(safe_return_to(&cfg, "/foo\r\nSet-Cookie: x=1"), "/");
        assert_eq!(safe_return_to(&cfg, "/foo\x00bar"), "/");
        assert_eq!(safe_return_to(&cfg, "/foo\x7f"), "/");
    }

    #[test]
    fn safe_return_to_accepts_just_root() {
        let cfg = cfg_with_self_url("https://forseti.example.com");
        assert_eq!(safe_return_to(&cfg, "/"), "/");
    }
}
