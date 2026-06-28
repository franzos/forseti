//! Public Kratos self-service flow handlers: registration, login, recovery,
//! verification, logout, and the `/error` landing page.

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

/// Canonical `/login?aal=aal2&return_to=…` step-up URL.
pub(crate) fn aal2_step_up_url(return_to: &str) -> String {
    format!(
        "/login?aal=aal2&return_to={}",
        ory_client::apis::urlencode(return_to)
    )
}
