//! `POST /logout`: Forseti CSRF check, then redirect to a fresh Kratos
//! logout URL so Kratos clears the session cookie.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::{self, action, AuditCtx, AuditEvent};
use crate::cookies;
use crate::csrf;
use crate::extractors::OptionalSession;
use crate::ory;
use crate::state::AppState;
use crate::web::render_error_boundary;

/// POST-only on purpose: link prefetchers, scanners, and pasted URLs must not
/// be able to nuke a session.
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    session: OptionalSession,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    _: csrf::CsrfForm<csrf::NoPayload>,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    // Capture the actor before the redirect invalidates the session cookie:
    // this is the last window to record who logged out.
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
            // Redirecting to /login on failure would look like a successful
            // logout while the session cookie is still valid.
            render_error_boundary(
                &state,
                &locale,
                &crate::i18n::lookup(&locale, "error-boundary-logout-title"),
                &crate::i18n::lookup(&locale, "error-boundary-logout-body"),
                "/",
                crate::i18n::lookup(&locale, "error-boundary-cta-back-to-dashboard"),
            )
            .into_response()
        }
    }
}
