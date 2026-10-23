//! `POST /logout`: Forseti CSRF check, then redirect to a fresh Kratos
//! logout URL so Kratos clears the session cookie.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::{self, AuditCtx, AuditEvent, action};
use crate::cookies;
use crate::csrf;
use crate::extractors::OptionalSession;
use crate::ory;
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::web::render_error_boundary;
use askama::Template;

#[derive(Template)]
#[template(path = "signed_out.html")]
struct SignedOutTemplate {
    chrome: PageChrome,
}

/// `GET /signed-out`: the landing Hydra's `urls.post_logout_redirect` points
/// at, so an RP-initiated logout without a `post_logout_redirect_uri` ends on
/// a page that says so instead of the sign-in form.
pub(crate) async fn signed_out(Chrome(chrome): Chrome) -> Response {
    render(&SignedOutTemplate { chrome })
}

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
    let kratos_session_id = session.ok().map(|s| s.id.clone());

    let secure = state.cfg.self_.is_https();
    match ory::kratos::fetch_logout_url(&state.ory, &cookie).await {
        Ok(Some(url)) => {
            if let Some((actor_id, actor_email)) = &actor {
                if let Some(ksid) = &kratos_session_id {
                    crate::oauth::op_sessions::end_op_sessions_for_browser(
                        &state,
                        actor_id,
                        ksid,
                        crate::oauth::op_sessions::GrantRevocation::Keep,
                    )
                    .await;
                }
                crate::oauth::op_sessions::sweep_dead_browser_sessions(&state, actor_id).await;
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
