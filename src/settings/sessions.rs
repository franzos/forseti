//! `/settings/sessions` — list and revoke the identity's active sessions.
//! Does not use a Kratos settings flow; reads directly from Kratos's session
//! APIs.

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::audit::{self, AuditCtx, AuditEvent, action, target_kind};
use crate::audit_metadata;
use crate::backend::IdentityBackend;
use crate::cookies;
use crate::csrf::CsrfForm;
use crate::flash;
use crate::page_chrome::{PageChrome, ThemedChrome};
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
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let session = sess.session;

    let other_sessions = match state
        .identity
        .list_my_sessions((!cookie.is_empty()).then_some(cookie.as_str()))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = ?e, "list_my_sessions failed");
            return render_error_boundary(
                &state,
                &locale,
                &crate::i18n::lookup(&locale, "error-boundary-sessions-title"),
                &crate::i18n::lookup(&locale, "error-boundary-sessions-body"),
                "/settings",
                crate::i18n::lookup(&locale, "error-boundary-cta-back-to-settings"),
            )
            .into_response();
        }
    };

    let mut rows: Vec<SessionView> = Vec::with_capacity(other_sessions.len() + 1);
    // Kratos's `/sessions` returns other sessions only; synthesize the current
    // one from `whoami` so the UI shows a complete picture.
    rows.push(SessionView::from_kratos(&locale, &session, true));
    for s in &other_sessions {
        rows.push(SessionView::from_kratos(&locale, s, false));
    }

    let has_other_sessions = !other_sessions.is_empty();

    let (flash_msg, clear_flash) = state.take_flash(&headers, "/settings/sessions");
    let body = render(&SettingsSessionsTemplate {
        chrome: themed.chrome,
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
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let actor_id = sess.identity_id;
    let actor_email = sess.email;

    // Kratos answers 204 for another identity's session id without revoking it.
    let owned = state
        .identity
        .is_session_active(&actor_id, &session_id)
        .await;
    let revoked = match owned {
        Ok(true) => {
            state
                .identity
                .revoke_session(&session_id, (!cookie.is_empty()).then_some(cookie.as_str()))
                .await
        }
        Ok(false) => Err(anyhow::anyhow!("session is not one of the actor's")),
        Err(e) => Err(e),
    };
    let (mut msg, ok) = match revoked {
        Ok(()) => (
            crate::i18n::lookup(&locale, "flash-session-signed-out"),
            true,
        ),
        Err(e) => {
            tracing::error!(error = ?e, session_id, "revoke_session failed");
            (
                crate::i18n::lookup(&locale, "flash-session-signout-failed"),
                false,
            )
        }
    };
    if ok {
        let ended = crate::oauth::op_sessions::end_op_sessions_for_browser(
            &state.db,
            &state.oauth,
            &actor_id,
            &session_id,
            crate::oauth::op_sessions::GrantRevocation::Revoke,
        )
        .await;
        let mut event = AuditEvent::new(action::SESSION_REVOKED)
            .actor_user(&actor_id, &actor_email)
            .target(target_kind::SESSION, session_id.clone())
            .with_ctx(&actx);
        if !ended {
            tracing::warn!(
                session_id,
                "session signed out, but its OAuth sessions and grants were not all ended"
            );
            event = event.merge_metadata(audit_metadata!("op_sessions_revoked" => false));
        }
        let _ = audit::log(&state.db, event).await;
        msg = crate::oauth::op_sessions::flash_with_partial_end(&locale, msg, ended);
    }
    state.flash_redirect("/settings/sessions", &msg)
}

pub(crate) async fn settings_sessions_revoke_others(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let actor_id = sess.identity_id;
    let actor_email = sess.email;

    let msg = match state
        .identity
        .revoke_other_sessions((!cookie.is_empty()).then_some(cookie.as_str()))
        .await
    {
        Ok(n) => {
            let ended = crate::oauth::op_sessions::end_op_sessions_for_subject(
                &state.db,
                &state.oauth,
                &actor_id,
                Some(&sess.session.id),
                crate::oauth::op_sessions::GrantRevocation::Revoke,
            )
            .await;
            let mut event = AuditEvent::new(action::SESSIONS_BULK_REVOKED)
                .actor_user(&actor_id, &actor_email)
                .with_ctx(&actx)
                .metadata(audit_metadata!("count" => n));
            if !ended {
                tracing::warn!(
                    identity_id = %actor_id,
                    "other sessions signed out, but their OAuth sessions and grants were not all ended"
                );
                event = event.merge_metadata(audit_metadata!("op_sessions_revoked" => false));
            }
            let _ = audit::log(&state.db, event).await;
            let mut args: std::collections::HashMap<
                std::borrow::Cow<'static, str>,
                fluent_templates::fluent_bundle::FluentValue,
            > = std::collections::HashMap::new();
            args.insert(std::borrow::Cow::Borrowed("count"), (n as i64).into());
            crate::oauth::op_sessions::flash_with_partial_end(
                &locale,
                crate::i18n::lookup_args(&locale, "flash-sessions-signed-out-others", &args),
                ended,
            )
        }
        Err(e) => {
            tracing::error!(error = ?e, "revoke_other_sessions failed");
            crate::i18n::lookup(&locale, "flash-sessions-signout-others-failed")
        }
    };
    state.flash_redirect("/settings/sessions", &msg)
}
