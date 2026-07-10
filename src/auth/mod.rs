//! Public Kratos self-service flow handlers: registration, login, recovery,
//! verification, logout, and the `/error` landing page.

use axum::routing::{get, post};
use axum::Router;

use crate::config::{AuthConfig, ProxyConfig};
use crate::rate_limit;
use crate::state::AppState;

pub(crate) mod error;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod recovery;
pub(crate) mod registration;
pub(crate) mod verification;

/// Per-IP rate-limit defaults for `GET /registration`, used when
/// `[auth].registration_ip_rate_per_*` is unset. This bounds signup-page
/// renders, not account creation (the browser POSTs straight to Kratos), so
/// the per-IP window has to tolerate many legitimate users sharing one egress
/// IP behind a corporate NAT / CGNAT; the global bucket below is the real
/// abuse backstop.
const DEFAULT_REGISTRATION_IP_RATE_PER_MINUTE: u32 = 30;
const DEFAULT_REGISTRATION_IP_RATE_PER_HOUR: u32 = 300;
/// Global (all-callers-share-one-bucket) defaults, bounding total traffic
/// regardless of claimed source IP.
const DEFAULT_REGISTRATION_GLOBAL_RATE_PER_MINUTE: u32 = 120;
const DEFAULT_REGISTRATION_GLOBAL_RATE_PER_HOUR: u32 = 1200;

pub(crate) fn router(proxy_cfg: &ProxyConfig, auth_cfg: &AuthConfig) -> Router<AppState> {
    Router::new()
        .route("/login", get(login::login))
        .merge(registration_router(proxy_cfg, auth_cfg))
        .route("/recovery", get(recovery::recovery))
        .route("/verification", get(verification::verification))
        .route("/error", get(error::error_page))
        .route("/logout", post(logout::logout))
}

/// `GET /registration` under a paired per-IP + global rate limit. The browser
/// POSTs registration straight to Kratos's own public endpoint (Forseti never
/// sees it), so this only bounds page renders — see the operator guide.
fn registration_router(proxy_cfg: &ProxyConfig, auth_cfg: &AuthConfig) -> Router<AppState> {
    let r = Router::new().route("/registration", get(registration::registration));

    let per_minute = auth_cfg
        .registration_ip_rate_per_minute
        .unwrap_or(DEFAULT_REGISTRATION_IP_RATE_PER_MINUTE);
    let per_hour = auth_cfg
        .registration_ip_rate_per_hour
        .unwrap_or(DEFAULT_REGISTRATION_IP_RATE_PER_HOUR);
    let global_per_minute = auth_cfg
        .registration_global_rate_per_minute
        .unwrap_or(DEFAULT_REGISTRATION_GLOBAL_RATE_PER_MINUTE);
    let global_per_hour = auth_cfg
        .registration_global_rate_per_hour
        .unwrap_or(DEFAULT_REGISTRATION_GLOBAL_RATE_PER_HOUR);

    rate_limit::dual_window_with_global(
        r,
        proxy_cfg.trust_forwarded_for,
        per_minute,
        per_hour,
        global_per_minute,
        global_per_hour,
        rate_limit::plain_text_error("registration"),
    )
}

/// Canonical `/login?aal=aal2&return_to=…` step-up URL.
pub(crate) fn aal2_step_up_url(return_to: &str) -> String {
    format!(
        "/login?aal=aal2&return_to={}",
        ory_client::apis::urlencode(return_to)
    )
}
