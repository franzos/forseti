//! Cross-cutting handler utilities: the Forseti version constant, return-to
//! validation, the shared `FlowQuery` extractor, the error-boundary template,
//! and the CSRF-cookie attachment shorthand.
//!
//! Anything here is used by more than one feature module. Items specific to a
//! single feature live alongside that feature's handler.

use askama::Template;
use axum::response::Response;
use serde::Deserialize;

use crate::config::AppConfig;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

/// Package version surfaced in the footer of every layout. Resolved at
/// compile time from `Cargo.toml`'s `version` so deployments always
/// advertise the binary they actually run.
pub(crate) const FORSETI_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) const AUTH_UNAVAILABLE_TITLE: &str = "Authentication unavailable";
pub(crate) const AUTH_UNAVAILABLE_BODY: &str =
    "We couldn't reach the authentication service. Please try again in a moment.";

/// Validate a `?return_to=` query parameter before short-circuiting a redirect
/// to it. Returns `"/"` whenever `raw` looks like an open-redirect attempt
/// (scheme-relative URL, embedded backslash, or an absolute URL whose origin
/// doesn't match Forseti's own external URL).
///
/// Why we need this: the `/login` and `/registration` handlers short-circuit
/// to `return_to` when the user already has a session. Without validation, a
/// crafted link like `/login?return_to=https://attacker.example/phish` would
/// hand the (authenticated) browser straight to an attacker-controlled page
/// after a normal-looking sign-in roundtrip.
///
/// A `return_to` is considered safe when:
///   * it starts with `/` and not `//` or `/\`
///     (path-only redirect on our own host), OR
///   * it parses as an absolute URL whose origin (scheme + host + port)
///     matches `cfg.self_.url`.
///
/// Anything else falls back to `/`. The caller renders no error — the
/// redirect just becomes a benign one. We log a `warn` so operators can see
/// rejected attempts in their pipeline.
pub(crate) fn safe_return_to<'a>(cfg: &AppConfig, raw: &'a str) -> &'a str {
    if raw.is_empty() {
        return "/";
    }
    // Path-only redirects: must start with `/` but not `//` (scheme-relative)
    // or `/\` (some browsers normalise backslash-as-slash).
    if let Some(rest) = raw.strip_prefix('/') {
        if rest.starts_with('/') || rest.starts_with('\\') {
            tracing::warn!(return_to = raw, "rejected open-redirect return_to");
            return "/";
        }
        return raw;
    }
    // Absolute URL: compare origins (scheme + host + port). String-prefix
    // matching can be fooled by `https://forseti.example.com.attacker.tld`
    // — `Url::origin` reduces the input to a canonical tuple so an
    // attacker-controlled host can't masquerade by sharing a prefix.
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
    /// `aal=aal2` requests an authentication step-up. The login handler must
    /// NOT short-circuit on a valid `aal1` session when this is set — instead
    /// it forwards the user into a Kratos flow that demands the second factor.
    /// Plumbed through to Kratos's browser-init URL.
    pub(crate) aal: Option<String>,
    /// `refresh=true` forces a privileged-session re-auth. Settings flows that
    /// hit `session_refresh_required` redirect through `/login?refresh=true`;
    /// the handler must fall through to Kratos even when `whoami` returns a
    /// session, otherwise the user livelocks at `privileged_session_max_age`.
    #[serde(default, deserialize_with = "deserialize_bool_str")]
    pub(crate) refresh: Option<bool>,
}

/// Accept `refresh=true`, `refresh=1`, etc. and coerce to `Option<bool>`. The
/// browser sends bare query strings, so the default `bool` deserializer (which
/// expects JSON-ish `true`/`false` tokens) fits, but being lenient here keeps
/// the handler robust against the operator-or-user-typed variants.
pub(crate) fn deserialize_bool_str<'de, D>(de: D) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(de)?;
    Ok(opt.map(|s| matches!(s.as_str(), "true" | "1" | "yes" | "on")))
}

/// Append an optional `Set-Cookie` header to an already-rendered response.
/// No-op when `cookie` is `None`. Appends (never replaces) so it composes with
/// any `Set-Cookie` the response already carries — e.g. attaching the
/// flash-clear cookie after the CSRF cookie has already been set. A malformed
/// cookie string is dropped silently.
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
    title: &str,
    body: &str,
    cta_href: impl Into<String>,
    cta_label: impl Into<String>,
) -> Response {
    render(&ErrorBoundaryTemplate {
        chrome: PageChrome::from_parts(state, String::new(), String::new()),
        error_title: title.to_string(),
        error_body: body.to_string(),
        cta_href: cta_href.into(),
        cta_label: cta_label.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, AuditConfig, BrandConfig, ClaimEmailConfig, DatabaseConfig,
        FlashConfig, HandoffConfig, HydraConfig, IdentityConfig, InternalConfig, KratosConfig,
        LicenseConfig, OAuthConfig, OrgsConfig, ProfilesConfig, ProxyConfig, SecurityConfig,
        SelfConfig, SmtpConfig, WebhookConfig,
    };

    fn cfg_with_self_url(url: &str) -> AppConfig {
        AppConfig {
            kratos: KratosConfig {
                public_url: "http://kratos:4433".into(),
                admin_url: "http://kratos:4434".into(),
            },
            hydra: HydraConfig {
                public_url: "http://hydra:4444".into(),
                admin_url: "http://hydra:4445".into(),
            },
            self_: SelfConfig { url: url.into() },
            brand: BrandConfig {
                name: "Test".into(),
                support_email: None,
                logo_url: None,
                consent_intro: String::new(),
            },
            apps: Vec::new(),
            oauth: OAuthConfig::default(),
            admin: AdminConfig::default(),
            database: DatabaseConfig::default(),
            audit: AuditConfig::default(),
            internal: InternalConfig::default(),
            license: LicenseConfig::default(),
            identity: IdentityConfig::default(),
            smtp: SmtpConfig::default(),
            profiles: ProfilesConfig::default(),
            webhook: WebhookConfig::default(),
            claim_email: ClaimEmailConfig::default(),
            handoff: HandoffConfig::default(),
            flash: FlashConfig::default(),
            orgs: OrgsConfig::default(),
            proxy: ProxyConfig::default(),
            security: SecurityConfig::default(),
        }
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
        // `//evil.com` — must be rejected.
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
