//! `/settings/sessions` — list and revoke the identity's active sessions.
//! Does not use a Kratos settings flow; reads directly from Kratos's session
//! APIs.

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::cookies;
use crate::csrf::CsrfForm;
use crate::extractors::Csrf;
use crate::flash;
use crate::flow_view::session_email;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::render_error_boundary;
use crate::state::AppState;

pub(crate) use crate::session_view::SessionView;

#[derive(Template)]
#[template(path = "settings_sessions.html")]
pub(crate) struct SettingsSessionsTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) sessions: Vec<SessionView>,
    pub(crate) has_other_sessions: bool,
    pub(crate) flash: String,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

pub(crate) async fn settings_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let session = sess.session;

    let other_sessions = match ory::kratos::list_my_sessions(
        &state.ory,
        (!cookie.is_empty()).then_some(cookie.as_str()),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = ?e, "list_my_sessions failed");
            return render_error_boundary(
                &state,
                "Sessions unavailable",
                "We couldn't list your active sessions. Please try again in a moment.",
                "/settings",
                "Back to settings",
            )
            .into_response();
        }
    };

    let mut rows: Vec<SessionView> = Vec::with_capacity(other_sessions.len() + 1);
    // Kratos's `/sessions` returns other sessions only; synthesize the current
    // one from `whoami` so the UI shows a complete picture.
    rows.push(SessionView::from_kratos(&session, true));
    for s in &other_sessions {
        rows.push(SessionView::from_kratos(s, false));
    }

    let has_other_sessions = !other_sessions.is_empty();

    let (flash_msg, clear_flash) = state.take_flash(&headers, "/settings/sessions");
    let body = render(&SettingsSessionsTemplate {
        chrome: PageChrome::from_parts(&state, session_email(&session), csrf.0),
        sessions: rows,
        has_other_sessions,
        flash: flash_msg,
        referrer_banner: banner.0,
    });
    flash::attach_set_cookie(body, clear_flash)
}

pub(crate) async fn settings_sessions_revoke(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let actor_id = sess.identity_id;
    let actor_email = sess.email;

    let (msg, ok) = match ory::kratos::revoke_session(
        &state.ory,
        &session_id,
        (!cookie.is_empty()).then_some(cookie.as_str()),
    )
    .await
    {
        Ok(()) => ("Session signed out.", true),
        Err(e) => {
            tracing::error!(error = ?e, session_id, "revoke_session failed");
            ("Could not sign out that session.", false)
        }
    };
    if ok {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::SESSION_REVOKED)
                .actor_user(&actor_id, &actor_email)
                .target(target_kind::SESSION, session_id.clone())
                .with_ctx(&actx),
        )
        .await;
    }
    state.flash_redirect("/settings/sessions", msg)
}

pub(crate) async fn settings_sessions_revoke_others(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let actor_id = sess.identity_id;
    let actor_email = sess.email;

    let msg = match ory::kratos::revoke_other_sessions(
        &state.ory,
        (!cookie.is_empty()).then_some(cookie.as_str()),
    )
    .await
    {
        Ok(n) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::SESSIONS_BULK_REVOKED)
                    .actor_user(&actor_id, &actor_email)
                    .with_ctx(&actx)
                    .metadata(audit_metadata!("count" => n)),
            )
            .await;
            format!(
                "Signed out {n} other session{}.",
                if n == 1 { "" } else { "s" }
            )
        }
        Err(e) => {
            tracing::error!(error = ?e, "revoke_other_sessions failed");
            "Could not sign out other sessions.".to_string()
        }
    };
    state.flash_redirect("/settings/sessions", &msg)
}
