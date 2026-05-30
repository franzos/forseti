//! `/oauth/logout` — Hydra's RP-initiated logout landing. The GET renders a
//! confirmation page; the POST performs the Kratos session tear-down and
//! accepts the Hydra logout challenge.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

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
/// landing. We render a confirmation page; the actual tear-down happens on
/// POST (so a malicious link can't sign a user out without their consent —
/// previously this GET handler destroyed the session immediately).
pub(crate) async fn oauth_logout(
    State(state): State<AppState>,
    Query(query): Query<OAuthLogoutQuery>,
    Chrome(chrome): Chrome,
) -> Response {
    let challenge = query.logout_challenge;

    // Validate the challenge exists before we render the form. If Hydra
    // rejects it (expired/missing) bail early — there's no recovery from a
    // confirm-then-submit on a stale challenge.
    if let Err(e) = ory::hydra::get_logout_request(&state.ory, &challenge).await {
        tracing::error!(error = ?e, "hydra get_logout_request failed");
        return Redirect::to("/error").into_response();
    }

    render(&OAuthLogoutConfirmTemplate {
        chrome,
        logout_challenge: challenge,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthLogoutForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    logout_challenge: String,
}

/// POST handler for the `/oauth/logout` confirmation page. Performs the
/// actual Kratos session tear-down + Hydra accept-logout that the GET
/// handler used to do.
pub(crate) async fn oauth_logout_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<OAuthLogoutForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let challenge = form.logout_challenge;

    // Best-effort Kratos session teardown. The user might already be signed
    // out (no cookie), in which case we just accept the Hydra challenge.
    let cookie = cookies::cookie_header(&headers);
    if !cookie.is_empty() {
        if let Ok(Some(url)) = ory::kratos::fetch_logout_url(&state.ory, &cookie).await {
            // Fire-and-forget: hit the URL server-side to actually destroy
            // the session (we don't follow Kratos's post-logout redirect —
            // Hydra's redirect is authoritative for this flow).
            let _ = ory::kratos::hit_logout_url(&state.ory, &url, Some(&cookie)).await;
        }
    }

    match ory::hydra::accept_logout_request(&state.ory, &challenge).await {
        Ok(redirect) => Redirect::to(&redirect.redirect_to).into_response(),
        Err(e) => {
            tracing::error!(error = ?e, "hydra accept_logout_request failed");
            Redirect::to("/error").into_response()
        }
    }
}
