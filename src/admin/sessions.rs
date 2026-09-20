//! `/admin/sessions`: global session list + revoke.
//!
//! Kratos's admin API exposes every active session across all identities.
//! The list view paginates with an opaque `page_token`; revoking goes via
//! the typed `disable_session` admin call.
//!
//! Tier-1 only, for the same reason as `/admin/identities`: a Kratos session
//! belongs to a global identity, not to an org, so there is no honest
//! org-scoped view of one.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;

use crate::admin::{AdminSection, ConfirmForm, ConfirmTemplate, render_admin_error};
use crate::audit::{self, AuditCtx, action, target_kind};
use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, RequireAdmin};
use crate::flash;
use crate::format::{humanise_timestamp, humanise_user_agent};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

pub(crate) struct SessionRow {
    pub id: String,
    pub identity_id: String,
    pub identity_email: String,
    /// Raw ISO timestamps preserved for `title=` hover tooltips.
    pub authenticated_at: String,
    pub authenticated_at_pretty: String,
    pub expires_at: String,
    pub expires_at_pretty: String,
    /// Original UA preserved for `title=`; templates show the humanised form.
    pub user_agent: String,
    pub user_agent_pretty: String,
    pub ip_address: String,
}

#[derive(askama::Template)]
#[template(path = "admin/sessions_list.html")]
struct SessionsListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<SessionRow>,
    /// Echoed back into the "active only" toggle in the template.
    active_only: bool,
    /// Flash from a redirect after a successful revoke.
    flash: String,
    /// Opaque next-page token; empty when there's no next page.
    next_page_token: String,
    /// Kratos paginates with opaque tokens (no backward seek), so the only
    /// reliable back-step is "go to page 1".
    has_prev: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    active_only: Option<String>,
    #[serde(default)]
    page_token: Option<String>,
}

/// Page size, also the "is there more?" heuristic: a full page implies a next.
const SESSIONS_PAGE_SIZE: i64 = 100;

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
    admin: RequireAdmin,
    csrf: Csrf,
) -> Response {
    let RequireAdmin { ctx } = admin;

    let active_only = matches!(
        query.active_only.as_deref(),
        Some("1") | Some("true") | Some("on")
    );
    let page_token = query.page_token.as_deref().filter(|s| !s.is_empty());

    let sessions = match ory::kratos::admin_list_all_sessions(
        &state.ory,
        SESSIONS_PAGE_SIZE,
        page_token,
        if active_only { Some(true) } else { None },
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = ?e, "admin: list_sessions failed");
            return render_admin_error(
                &state,
                "Sessions unavailable",
                "We couldn't list active sessions. Please try again in a moment.",
            );
        }
    };

    let rows: Vec<SessionRow> = sessions
        .iter()
        .map(|s| {
            let identity = s.identity.as_ref();
            let identity_id = identity.map(|i| i.id.clone()).unwrap_or_default();
            let identity_email = identity
                .and_then(|i| i.traits.as_ref())
                .and_then(|t| t.get("email"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let device = s.devices.as_ref().and_then(|d| d.first()).cloned();
            let user_agent = device
                .clone()
                .and_then(|d| d.user_agent)
                .unwrap_or_default();
            let authenticated_at = s.authenticated_at.clone().unwrap_or_default();
            let expires_at = s.expires_at.clone().unwrap_or_default();
            SessionRow {
                id: s.id.clone(),
                identity_id,
                identity_email,
                authenticated_at_pretty: humanise_timestamp(&ctx.locale, &authenticated_at),
                authenticated_at,
                expires_at_pretty: humanise_timestamp(&ctx.locale, &expires_at),
                expires_at,
                user_agent_pretty: humanise_user_agent(&ctx.locale, &user_agent),
                user_agent,
                ip_address: device.and_then(|d| d.ip_address).unwrap_or_default(),
            }
        })
        .collect();

    // Next-page heuristic: the last row's session ID doubles as Kratos's
    // opaque token, since the typed SDK doesn't surface the Link header.
    let next_page_token = if rows.len() == SESSIONS_PAGE_SIZE as usize {
        rows.last().map(|r| r.id.clone()).unwrap_or_default()
    } else {
        String::new()
    };
    let has_prev = page_token.is_some();

    let (flash_msg, clear_flash) = state.take_flash(&headers, "/admin/sessions");

    tracing::info!(
        action = "admin.sessions.list",
        actor = %ctx.email,
        count = rows.len(),
        "admin action"
    );

    let chrome = ctx.chrome(&csrf);
    let resp = render(&SessionsListTemplate {
        chrome,
        admin_active: AdminSection::Sessions,
        rows,
        active_only,
        flash: flash_msg,
        next_page_token,
        has_prev,
    });
    flash::attach_set_cookie(resp, clear_flash)
}

pub async fn revoke_confirm(Path(id): Path<String>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let RequireAdmin { ctx } = admin;
    let action_url = format!(
        "/admin/sessions/{}/revoke",
        ory_client::apis::urlencode(&id)
    );
    let cancel_url = "/admin/sessions".to_string();
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Sessions,
        title: format!("Revoke session {id}?"),
        body: "The session will be terminated immediately. If this is your own session you'll be signed out.".to_string(),
        action_url,
        cancel_url,
        submit_label: "Revoke session",
    })
}

pub async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actx: AuditCtx,
    admin: RequireAdmin,
    CsrfForm(form): CsrfForm<ConfirmForm>,
) -> Response {
    let RequireAdmin { ctx } = admin;
    let redirect_to = "/admin/sessions".to_string();
    if let Some(r) = form.bounce_unless_confirmed(&redirect_to) {
        return r;
    }
    match ory::kratos::admin_revoke_session(&state.ory, &id).await {
        Ok(()) => {
            let _ = audit::log(
                &state.db,
                ctx.audit_event(action::ADMIN_SESSION_REVOKED, &actx)
                    .target(target_kind::SESSION, id.clone()),
            )
            .await;
            state.flash_redirect(
                &redirect_to,
                &crate::i18n::lookup(&ctx.locale, "flash-session-revoked"),
            )
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: revoke session failed");
            render_admin_error(
                &state,
                &crate::i18n::lookup(&ctx.locale, "dialog-revoke-failed-title"),
                &format!("Could not revoke session: {e}"),
            )
        }
    }
}
