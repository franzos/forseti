//! `POST /logout` — verifies Forseti CSRF, fetches a Kratos logout URL, and
//! redirects the browser there so Kratos clears the session cookie.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::audit::{self, action, AuditCtx, AuditEvent};
use crate::cookies;
use crate::csrf;
use crate::extractors::OptionalSession;
use crate::ory;
use crate::state::AppState;
use crate::web::render_error_boundary;

#[derive(Debug, Deserialize)]
pub(crate) struct LogoutForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// `POST /logout` — POST-only on purpose: link prefetchers, scanners, and
/// pasted URLs must not be able to nuke a session. We verify Forseti's
/// own double-submit CSRF token, then fetch a fresh `logout_url` from Kratos
/// and redirect the browser to it (Kratos clears the session cookie and
/// 303s to `/login`).
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    session: OptionalSession,
    Form(form): Form<LogoutForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    let cookie = cookies::cookie_header(&headers);
    // Identify the actor before we hand off to Kratos — the session
    // cookie will be invalidated on the redirect, so this is the last
    // window to record who logged out. InsufficientAal sessions still
    // produce empty actor fields (the session JSON isn't surfaced on
    // that path), but the logout proceeds either way.
    let actor = session.identity_id().map(|id| {
        (
            id.to_string(),
            session.email().unwrap_or_default().to_string(),
        )
    });

    let secure = state.cfg.self_.is_https();
    match ory::kratos::fetch_logout_url(&state.ory, &cookie).await {
        Ok(Some(url)) => {
            if let Some((actor_id, actor_email)) = &actor {
                let _ = audit::log(
                    &state.db,
                    AuditEvent::new(action::AUTH_LOGOUT)
                        .actor_user(actor_id, actor_email)
                        .with_ctx(&actx),
                )
                .await;
            }
            csrf::attach_csrf(
                Redirect::to(&url).into_response(),
                Some(csrf::delete_csrf_cookie(secure)),
            )
        }
        Ok(None) => csrf::attach_csrf(
            Redirect::to("/login").into_response(),
            Some(csrf::delete_csrf_cookie(secure)),
        ),
        Err(e) => {
            tracing::error!(error = ?e, "logout: failed to fetch Kratos logout URL");
            // Silently redirecting to /login would land back on the dashboard:
            // the session cookie is still valid, so the user would think they
            // had logged out when they hadn't.
            render_error_boundary(
                &state,
                "Logout unavailable",
                "We couldn't complete your logout because the authentication service is unreachable. Your session is still active — please try again in a moment.",
                "/",
                "Back to dashboard",
            )
            .into_response()
        }
    }
}
