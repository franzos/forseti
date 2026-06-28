//! `/admin/sessions`: global session list + revoke.
//!
//! Kratos's admin API exposes every active session across all identities.
//! The list view paginates with an opaque `page_token`; revoking goes via
//! the typed `disable_session` admin call.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;

use crate::admin::{render_admin_error, with_org, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx};
use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, RequireAdminScoped};
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

/// Page size for the org-scoped path; matches `admin/identities.rs` so the
/// surfaces page in lock-step.
const SESSIONS_ORG_PAGE_SIZE: i64 = 25;

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let active_only = matches!(
        query.active_only.as_deref(),
        Some("1") | Some("true") | Some("on")
    );
    let page_token = query.page_token.as_deref().filter(|s| !s.is_empty());

    // Org-scoped: fan out per-member session lookups, paginating with a numeric
    // member offset (matching `admin/identities.rs`). Forseti-wide passes the
    // opaque Kratos page_token through. `org_scoped_member_count` is Some only
    // on the org path and feeds the next-page heuristic; a full member page
    // implies more members.
    let (sessions, org_scoped_member_count): (Vec<_>, Option<i64>) = match scope.org_id() {
        Some(org_id) => {
            let offset: i64 = page_token
                .and_then(|t| t.parse::<i64>().ok())
                .filter(|n| *n >= 0)
                .unwrap_or(0);
            let members = match crate::orgs::list_members_paged(
                &state.db,
                org_id,
                SESSIONS_ORG_PAGE_SIZE,
                offset,
            )
            .await
            {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(error = ?e, "admin: org-scoped list_members_paged failed");
                    return render_admin_error(
                        &state,
                        "Sessions unavailable",
                        "We couldn't list org members. Please try again in a moment.",
                    );
                }
            };
            let member_count = members.len() as i64;
            // Bounded concurrency, else a 25-member org pays 25 serial Kratos
            // round-trips; cap matches `webhooks::resolve_client_names`.
            const MAX_CONCURRENT: usize = 8;
            let mut slots: Vec<Option<Vec<ory::Session>>> =
                (0..members.len()).map(|_| None).collect();
            let mut pending: Vec<(usize, String)> = members
                .iter()
                .enumerate()
                .map(|(i, m)| (i, m.identity_id.clone()))
                .rev()
                .collect();
            let mut set: tokio::task::JoinSet<(usize, String, anyhow::Result<Vec<ory::Session>>)> =
                tokio::task::JoinSet::new();
            let initial = MAX_CONCURRENT.min(pending.len());
            for _ in 0..initial {
                if let Some((idx, id)) = pending.pop() {
                    let ory = state.ory.clone();
                    set.spawn(async move {
                        let res = ory::kratos::list_identity_sessions(&ory, &id).await;
                        (idx, id, res)
                    });
                }
            }
            while let Some(joined) = set.join_next().await {
                let (idx, id, res) = match joined {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(error = ?e, "admin: per-identity session lookup task panicked");
                        if let Some((next_idx, next_id)) = pending.pop() {
                            let ory = state.ory.clone();
                            set.spawn(async move {
                                let res = ory::kratos::list_identity_sessions(&ory, &next_id).await;
                                (next_idx, next_id, res)
                            });
                        }
                        continue;
                    }
                };
                match res {
                    Ok(s) => slots[idx] = Some(s),
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            identity_id = %id,
                            "admin: per-identity session list failed; skipping member"
                        );
                        slots[idx] = Some(Vec::new());
                    }
                }
                if let Some((next_idx, next_id)) = pending.pop() {
                    let ory = state.ory.clone();
                    set.spawn(async move {
                        let res = ory::kratos::list_identity_sessions(&ory, &next_id).await;
                        (next_idx, next_id, res)
                    });
                }
            }
            let mut all: Vec<ory::Session> = slots
                .into_iter()
                .flat_map(|s| s.unwrap_or_default().into_iter())
                .collect();
            if active_only {
                all.retain(|s| s.active.unwrap_or(false));
            }
            (all, Some(member_count))
        }
        None => match ory::kratos::admin_list_all_sessions(
            &state.ory,
            SESSIONS_PAGE_SIZE,
            page_token,
            if active_only { Some(true) } else { None },
        )
        .await
        {
            Ok(s) => (s, None),
            Err(e) => {
                tracing::error!(error = ?e, "admin: list_sessions failed");
                return render_admin_error(
                    &state,
                    "Sessions unavailable",
                    "We couldn't list active sessions. Please try again in a moment.",
                );
            }
        },
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
                authenticated_at_pretty: humanise_timestamp(&authenticated_at),
                authenticated_at,
                expires_at_pretty: humanise_timestamp(&expires_at),
                expires_at,
                user_agent_pretty: humanise_user_agent(&user_agent),
                user_agent,
                ip_address: device.and_then(|d| d.ip_address).unwrap_or_default(),
            }
        })
        .collect();

    // Next-page heuristic, two schemes:
    //   * Forseti-wide: last row's session ID as Kratos's opaque token.
    //   * org-scoped: numeric member offset, advanced by a page when the
    //     member page came back full, so the next click advances over members.
    let next_page_token = match org_scoped_member_count {
        Some(member_count) if member_count == SESSIONS_ORG_PAGE_SIZE => {
            let current_offset: i64 = page_token
                .and_then(|t| t.parse::<i64>().ok())
                .filter(|n| *n >= 0)
                .unwrap_or(0);
            (current_offset + SESSIONS_ORG_PAGE_SIZE).to_string()
        }
        Some(_) => String::new(),
        None if rows.len() == SESSIONS_PAGE_SIZE as usize => {
            rows.last().map(|r| r.id.clone()).unwrap_or_default()
        }
        None => String::new(),
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

pub async fn revoke_confirm(
    State(state): State<AppState>,
    Path(id): Path<String>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    // Verify scope before rendering the confirm page so an org owner can't fish
    // for sessions outside their scope by URL-guessing.
    if let Err(resp) = require_session_in_scope(&state, &id, &scope).await {
        return resp;
    }
    let action_url = with_org(
        &format!(
            "/admin/sessions/{}/revoke",
            ory_client::apis::urlencode(&id)
        ),
        &scope,
    );
    let cancel_url = with_org("/admin/sessions", &scope);
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
    admin: RequireAdminScoped,
    CsrfForm(form): CsrfForm<ConfirmForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    let redirect_to = with_org("/admin/sessions", &scope);
    if let Some(r) = form.bounce_unless_confirmed(&redirect_to) {
        return r;
    }
    // Re-verify scope on the write path; don't trust the round-trip, since a
    // stale tab with a swapped `?org=` could otherwise revoke a foreign session.
    if let Err(resp) = require_session_in_scope(&state, &id, &scope).await {
        return resp;
    }
    match ory::kratos::admin_revoke_session(&state.ory, &id).await {
        Ok(()) => {
            let _ = audit::log(
                &state.db,
                ctx.audit_event(action::ADMIN_SESSION_REVOKED, &actx)
                    .target(target_kind::SESSION, id.clone()),
            )
            .await;
            state.flash_redirect(&redirect_to, "Session revoked.")
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: revoke session failed");
            render_admin_error(
                &state,
                "Revoke failed",
                &format!("Could not revoke session: {e}"),
            )
        }
    }
}

/// Reject the request unless the named session's identity is a member
/// of `scope`'s org. Forseti-wide scope is a no-op (admin sees all).
/// Treats Kratos lookup failure as `not found` to avoid leaking
/// session-existence cross-org via timing or error-shape probing.
async fn require_session_in_scope(
    state: &AppState,
    session_id: &str,
    scope: &crate::orgs::AdminScope,
) -> Result<(), Response> {
    let org_id = match scope.org_id() {
        Some(s) => s,
        None => return Ok(()),
    };
    let session = match ory::kratos::admin_get_session(&state.ory, session_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = ?e, session_id, "admin: get_session failed; rejecting as not-in-scope");
            return Err(render_admin_error(
                state,
                "Session not found",
                "We couldn't find a session with that ID in this organization.",
            ));
        }
    };
    let identity_id = session
        .identity
        .as_ref()
        .map(|i| i.id.clone())
        .unwrap_or_default();
    if identity_id.is_empty() {
        return Err(render_admin_error(
            state,
            "Session not found",
            "We couldn't find a session with that ID in this organization.",
        ));
    }
    if crate::orgs::is_member(&state.db, &identity_id, org_id).await {
        Ok(())
    } else {
        Err(render_admin_error(
            state,
            "Session not found",
            "We couldn't find a session with that ID in this organization.",
        ))
    }
}
