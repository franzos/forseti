//! Enterprise SAML SSO via a Jackson / Ory Polis bridge (commercial).
//!
//! Forseti is the OAuth2 client to Jackson; Jackson owns the SAML leg
//! (assertion validation, XML-DSIG, IdP quirks). Sessions are native
//! Kratos sessions established via admin-minted recovery links — OSS
//! Kratos has no admin session-creation API.

pub mod db;
pub mod flow;
pub mod jackson;

use axum::routing::get;
use axum::Router;

use crate::signed_cookie::SignedCookie;
use crate::state::AppState;

/// Mounted by `app::run` only when `[saml]` is configured.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sso/{slug}", get(flow::start))
        .route("/sso/callback", get(flow::callback))
}

/// CSRF/replay binding for the authorize round-trip. 10 minutes is
/// generous for an IdP login including a slow MFA prompt.
pub(crate) fn state_cookie(secure: bool) -> SignedCookie<'static> {
    SignedCookie {
        name: "forseti_saml_state",
        salt: b"forseti::saml_state::v1",
        ttl_secs: 600,
        secure,
        path: "/sso",
    }
}
