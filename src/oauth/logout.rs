//! `/oauth/logout` — Hydra's RP-initiated logout landing. The GET renders a
//! confirmation page; the POST performs the Kratos session tear-down and
//! accepts the Hydra logout challenge.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::csrf::CsrfForm;

use crate::cookies;
use crate::ory;
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthLogoutQuery {
    logout_challenge: String,
}

#[derive(Template)]
#[template(path = "oauth_logout_confirm.html")]
struct OAuthLogoutConfirmTemplate {
    chrome: PageChrome,
    logout_challenge: String,
}

/// `/oauth/logout?logout_challenge=...` — Hydra's RP-initiated logout
/// landing. Renders a confirmation page; the tear-down happens on POST so a
/// malicious link can't sign a user out without their consent.
pub(crate) async fn oauth_logout(
    State(state): State<AppState>,
    Query(query): Query<OAuthLogoutQuery>,
    Chrome(chrome): Chrome,
) -> Response {
    let challenge = query.logout_challenge;

    // Validate the challenge before rendering: there's no recovery from a
    // confirm-then-submit on a stale challenge.
    let logout_req = match ory::hydra::get_logout_request(&state.ory, &challenge).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "hydra get_logout_request failed");
            return Redirect::to("/error").into_response();
        }
    };

    let mut resp = render(&OAuthLogoutConfirmTemplate {
        chrome,
        logout_challenge: challenge,
    });
    // Same redirect-chain rule as consent: confirming logout ends at the RP's
    // registered `post_logout_redirect_uri`, so `form-action` has to allow it.
    if let Some(uris) = logout_req
        .client
        .as_ref()
        .and_then(|c| c.post_logout_redirect_uris.as_ref())
    {
        crate::app::allow_form_action_to(&mut resp, uris);
    }
    resp
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthLogoutForm {
    logout_challenge: String,
}

/// POST handler for the `/oauth/logout` confirmation page. Performs the
/// Kratos session tear-down + Hydra accept-logout.
pub(crate) async fn oauth_logout_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<OAuthLogoutForm>,
) -> Response {
    let challenge = form.logout_challenge;

    // Best-effort Kratos teardown; the user may already be signed out.
    let cookie = cookies::cookie_header(&headers);
    ory::kratos::tear_down_session(&state.ory, &cookie).await;

    match ory::hydra::accept_logout_request(&state.ory, &challenge).await {
        Ok(redirect) => Redirect::to(&redirect.redirect_to).into_response(),
        Err(e) => {
            tracing::error!(error = ?e, "hydra accept_logout_request failed");
            Redirect::to("/error").into_response()
        }
    }
}
