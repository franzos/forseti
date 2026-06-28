//! OAuth2/OIDC bridge handlers: Hydra's login / consent / logout redirect
//! targets. Forseti resolves the Kratos session, projects identity traits
//! into id_token claims, and accepts (or rejects) the Hydra challenge.

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;

use crate::config::{OAuthConfig, ProxyConfig};
use crate::rate_limit;
use crate::state::AppState;

pub(crate) mod consent;
pub(crate) mod device;
pub(crate) mod device_verify;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod register;

/// Consent-screen descriptions for the standard OIDC scopes, used when the
/// operator hasn't supplied one in `[oauth.scope_descriptions]`.
pub(crate) fn default_scope_description(scope: &str) -> Option<&'static str> {
    Some(match scope {
        "openid" => "Confirm your identity",
        "profile" => "Your basic profile (name, picture, locale)",
        "email" => "Your email address",
        "offline_access" => "Stay signed in when you're not actively using the app",
        "address" => "Your postal address",
        "phone" => "Your phone number",
        _ => return None,
    })
}

/// Per-IP rate-limit defaults for `POST /oauth2/register`. 10/min guards
/// bursts, 100/hour slow-drip abuse; a request must satisfy both buckets.
const DEFAULT_DCR_IP_RATE_PER_MINUTE: u32 = 10;
const DEFAULT_DCR_IP_RATE_PER_HOUR: u32 = 100;

pub(crate) fn router(oauth_cfg: &OAuthConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    Router::new()
        .route("/oauth/login", get(login::oauth_login))
        .route(
            "/oauth/consent",
            get(consent::oauth_consent).post(consent::oauth_consent_submit),
        )
        .route(
            "/oauth/logout",
            get(logout::oauth_logout).post(logout::oauth_logout_submit),
        )
        // RFC 8628 device-verification screen (Hydra's `verification_uri`).
        .route(
            "/oauth/device",
            get(device_verify::device_verify).post(device_verify::device_verify_submit),
        )
        .route("/oauth/device/done", get(device_verify::device_done))
        // Forseti-fronted RFC 7591 DCR endpoint at the canonical
        // `/oauth2/register` path Hydra advertises in discovery. No CSRF (not
        // a browser form); rate-limited via the nested router below.
        .merge(register_router(oauth_cfg, proxy_cfg))
}

/// Per-request body cap for the DCR proxy. A valid RFC 7591 payload is a few
/// hundred bytes; 64 KiB leaves headroom for verbose `redirect_uris` without
/// giving abusers a multi-megabyte slot. Exceeding it yields a 413.
const DCR_BODY_LIMIT_BYTES: usize = 64 * 1024;

fn register_router(oauth_cfg: &OAuthConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    let r = Router::new()
        .route("/oauth2/register", post(register::register))
        .layer(DefaultBodyLimit::max(DCR_BODY_LIMIT_BYTES));

    let per_minute = oauth_cfg
        .dcr_ip_rate_per_minute
        .unwrap_or(DEFAULT_DCR_IP_RATE_PER_MINUTE);
    let per_hour = oauth_cfg
        .dcr_ip_rate_per_hour
        .unwrap_or(DEFAULT_DCR_IP_RATE_PER_HOUR);

    // Strict (peer-IP) mode requires
    // `into_make_service_with_connect_info::<SocketAddr>()` at the serve site
    // so `ConnectInfo` is in extensions; see `app::run`.
    rate_limit::dual_window(
        r,
        proxy_cfg.trust_forwarded_for,
        per_minute,
        per_hour,
        register::rate_limit_error_response,
    )
}

#[cfg(test)]
mod tests {
    use super::default_scope_description;

    #[test]
    fn default_scope_description_covers_standard_scopes() {
        for scope in [
            "openid",
            "profile",
            "email",
            "offline_access",
            "address",
            "phone",
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
}
