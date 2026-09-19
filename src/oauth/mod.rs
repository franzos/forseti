//! OAuth2/OIDC bridge handlers: Hydra's login / consent / logout redirect
//! targets. Forseti resolves the Kratos session, projects identity traits
//! into id_token claims, and accepts (or rejects) the Hydra challenge.

use axum::Router;
use axum::routing::{get, post};

use crate::config::{OAuthConfig, ProxyConfig};
use crate::rate_limit;
use crate::state::AppState;

pub(crate) mod cimd;
pub(crate) mod cimd_fetch;
pub(crate) mod consent;
pub(crate) mod continue_nav;
pub(crate) mod device;
pub(crate) mod device_verify;
pub(crate) mod login;
pub(crate) mod logout;

/// Consent-screen descriptions for built-in scopes (standard OIDC plus
/// Forseti's `groups`), used when the operator hasn't supplied one in
/// `[oauth.scope_descriptions]`.
pub(crate) fn default_scope_description(scope: &str) -> Option<&'static str> {
    Some(match scope {
        "openid" => "Confirm your identity",
        "profile" => "Your basic profile (name, picture, locale)",
        "email" => "Your email address",
        "offline_access" => "Stay signed in when you're not actively using the app",
        "address" => "Your postal address",
        "phone" => "Your phone number",
        "groups" => "Your team memberships (used to assign roles in the connected app)",
        "org" => "Your active organization and role",
        "orgs" => "Your organizations and your roles",
        _ => return None,
    })
}

/// Canonical form of an RFC 8707 resource identifier, used both to match
/// against `[oauth].allowed_resource_audiences` and as the value actually
/// granted or registered. Absolute URIs only; the fragment is dropped (RFC 8707
/// §2 forbids it) and the trailing slash is trimmed, so `https://host/mcp/` and
/// `https://host/mcp` are one resource. `None` when the input isn't a URI.
pub(crate) fn canonical_resource(raw: &str) -> Option<String> {
    let mut url = url::Url::parse(raw.trim()).ok()?;
    url.set_fragment(None);
    let canonical = url.as_str().trim_end_matches('/');
    (!canonical.is_empty()).then(|| canonical.to_string())
}

pub(crate) fn router(oauth_cfg: &OAuthConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    Router::new()
        .route("/oauth/login", get(login::oauth_login))
        .route(
            "/oauth/consent",
            get(consent::oauth_consent).post(consent::oauth_consent_submit),
        )
        .route("/oauth/consent/switch", post(consent::consent_switch))
        .route(
            "/oauth/logout",
            get(logout::oauth_logout).post(logout::oauth_logout_submit),
        )
        // RFC 8628 device-verification screen (Hydra's `verification_uri`),
        // session-gated and per-IP rate-limited (see `device_router`).
        .merge(device_router(oauth_cfg, proxy_cfg))
        .route("/oauth/device/done", get(device_verify::device_done))
}

/// Per-IP rate-limit defaults for `/oauth/device`, used when
/// `[oauth].device_verify_ip_rate_per_*` is unset. The verification screen is
/// already session-gated; these buckets are defence-in-depth against an
/// authenticated user grinding low-entropy RFC 8628 user codes. A legitimate
/// approval is one GET + one POST, so the caps are generous without being open.
const DEFAULT_DEVICE_VERIFY_RATE_PER_MINUTE: u32 = 20;
const DEFAULT_DEVICE_VERIFY_RATE_PER_HOUR: u32 = 120;

/// `/oauth/device` (GET + POST) under a paired per-IP rate limit. Split out so
/// the throttle wraps only this route, not the unthrottled `/oauth/device/done`
/// terminal page.
fn device_router(oauth_cfg: &OAuthConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    // `cancel` shares the bucket: it's another `user_code`-keyed action, so it
    // shouldn't hand out an unthrottled way to probe codes.
    let r = Router::new()
        .route(
            "/oauth/device",
            get(device_verify::device_verify).post(device_verify::device_verify_submit),
        )
        .route("/oauth/device/cancel", post(device_verify::device_cancel));

    let per_minute = oauth_cfg
        .device_verify_ip_rate_per_minute
        .unwrap_or(DEFAULT_DEVICE_VERIFY_RATE_PER_MINUTE);
    let per_hour = oauth_cfg
        .device_verify_ip_rate_per_hour
        .unwrap_or(DEFAULT_DEVICE_VERIFY_RATE_PER_HOUR);

    rate_limit::dual_window_with_backstop(
        r,
        proxy_cfg,
        per_minute,
        per_hour,
        rate_limit::plain_text_error("device_verify"),
    )
}

#[cfg(test)]
mod tests {
    use super::{canonical_resource, default_scope_description};

    #[test]
    fn default_scope_description_covers_standard_scopes() {
        for scope in [
            "openid",
            "profile",
            "email",
            "offline_access",
            "address",
            "phone",
            "groups",
            "org",
            "orgs",
        ] {
            assert!(
                default_scope_description(scope).is_some(),
                "expected built-in description for {scope}"
            );
        }
    }

    #[test]
    fn default_scope_description_none_for_custom() {
        assert!(default_scope_description("custom:thing").is_none());
    }

    #[test]
    fn canonical_resource_collapses_trailing_slash() {
        let expected = Some("https://stackpit.gofranz.com/mcp".to_string());
        assert_eq!(
            canonical_resource("https://stackpit.gofranz.com/mcp"),
            expected
        );
        assert_eq!(
            canonical_resource("https://stackpit.gofranz.com/mcp/"),
            expected
        );
        assert_eq!(
            canonical_resource("  https://stackpit.gofranz.com/mcp/  "),
            expected
        );
    }

    #[test]
    fn canonical_resource_drops_fragment() {
        assert_eq!(
            canonical_resource("https://api.example/mcp#frag"),
            Some("https://api.example/mcp".to_string())
        );
    }

    #[test]
    fn canonical_resource_rejects_non_absolute() {
        assert_eq!(canonical_resource("/mcp"), None);
        assert_eq!(canonical_resource(""), None);
        assert_eq!(canonical_resource("not a uri"), None);
    }

    #[test]
    fn canonical_resource_rejects_bare_audience_identifiers() {
        // Why `allowed_resource_audiences` can only ever hold RFC 8707 URIs,
        // and why a client's registered `audience` is compared verbatim
        // instead: Stackpit's web SSO names itself `stackpit-web` /
        // `stackpit.gofranz.com`, neither of which is an absolute URI.
        assert_eq!(canonical_resource("stackpit-web"), None);
        assert_eq!(canonical_resource("stackpit.gofranz.com"), None);
    }

    #[test]
    fn canonical_resource_preserves_case_sensitive_path() {
        // Host normalises to lowercase, the path must not: resource servers
        // compare `aud` byte-for-byte.
        assert_eq!(
            canonical_resource("https://Example.COM/MCP"),
            Some("https://example.com/MCP".to_string())
        );
    }
}
