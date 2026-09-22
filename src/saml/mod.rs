//! Enterprise SAML SSO via a Jackson / Ory Polis bridge (commercial).
//!
//! Forseti is the OAuth2 client to Jackson; Jackson owns the SAML leg
//! (assertion validation, XML-DSIG, IdP quirks). Sessions are native
//! Kratos sessions established via admin-minted recovery links — OSS
//! Kratos has no admin session-creation API.

pub mod db;
pub mod flow;
pub mod jackson;

use axum::Router;
use axum::routing::get;

use crate::signed_cookie::SignedCookie;
use crate::state::AppState;

/// Mounted by `app::run` only when `[saml]` is configured.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sso/{slug}", get(flow::start))
        .route("/sso/callback", get(flow::callback))
        .route("/sso/confirm", get(flow::confirm))
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

/// Carries a pending link across the credential-confirmation bounce: the
/// assertion has been validated and resolved to an existing identity, but
/// nothing is written until the user proves they hold that identity. Same 10
/// minutes as the authorize round-trip, for the same reason (the user may be
/// walking through a password plus a second factor).
///
/// Path is `/` rather than `/sso`, because the bounce goes out to `/login` and
/// Kratos, and the cookie has to survive the round trip.
pub(crate) fn pending_link_cookie(secure: bool) -> SignedCookie<'static> {
    SignedCookie {
        name: "forseti_saml_pending",
        salt: b"forseti::saml_pending::v1",
        ttl_secs: 600,
        secure,
        path: "/",
    }
}
