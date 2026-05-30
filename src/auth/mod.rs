//! Public Kratos self-service flow handlers: registration, login, recovery,
//! verification, logout, and the `/error` landing page.
//!
//! Each submodule owns one route family. Templates and view-state for each
//! flow live alongside their handler so changes to a flow stay local.

use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

pub(crate) mod error;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod recovery;
pub(crate) mod registration;
pub(crate) mod verification;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/login", get(login::login))
        .route("/registration", get(registration::registration))
        .route("/recovery", get(recovery::recovery))
        .route("/verification", get(verification::verification))
        .route("/error", get(error::error_page))
        .route("/logout", post(logout::logout))
}

/// Canonical `/login?aal=aal2&return_to=…` step-up URL. Centralised so the
/// query-string shape (and its URL-encoding) lives in one place — every
/// caller (admin gate, registration, settings privileged-session, oauth
/// login ACR step-up) goes through here.
pub(crate) fn aal2_step_up_url(return_to: &str) -> String {
    format!(
        "/login?aal=aal2&return_to={}",
        ory_client::apis::urlencode(return_to)
    )
}
