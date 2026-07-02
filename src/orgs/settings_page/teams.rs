//! Teams page — owner-facing team CRUD + membership management.
//!
//! Teams are commercial everywhere (unlike the OSS members page), so every
//! handler gates on `Feature::Orgs` explicitly: `require_org_owner_with_license`
//! skips the gate for the Default org.

use std::collections::HashSet;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::csrf::CsrfForm;
use crate::extractors::{gate_orgs_feature_or_upsell, Csrf, RequireSession};
use crate::orgs::{self, teams, Org};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::{build_nav, require_org_owner, resolve_org_or_404, settings_ctx, OrgSlug, SettingsCtx};

#[derive(Serialize, Clone)]
struct TeamRowView {
    id: String,
    name: String,
    member_count: i64,
}

#[derive(Serialize, Clone)]
struct RosterView {
    identity_id: String,
    email: String,
    display_name: String,
}

#[derive(Template)]
#[template(path = "orgs/teams.html")]
struct TeamsTemplate {
    chrome: PageChrome,
    org: Org,
    is_default: bool,
    nav: orgs::nav::OrgNav,
    teams: Vec<TeamRowView>,
    /// Present when `?team=<id>` selects a team; drives the membership panel.
    selected_team: Option<TeamRowView>,
    /// Members of the selected team.
    members: Vec<RosterView>,
    /// Org members not yet in the selected team (joinable).
    addable: Vec<RosterView>,
}

/// Owner + `Feature::Orgs` gate (explicit so the Default org isn't skipped).
/// Owner first, then license, so a non-owner sees 403 rather than the upsell.
#[allow(clippy::result_large_err)]
async fn require_team_admin(
    state: &AppState,
    csrf_token: &str,
    identity_id: &str,
    email: &str,
    org_id: &str,
) -> Result<(), Response> {
    require_org_owner(state, identity_id, org_id).await?;
    gate_orgs_feature_or_upsell(state, csrf_token, email)?;
    Ok(())
}

/// Optional `?team=<id>` selection driving the membership-manager panel.
#[derive(Deserialize)]
pub(super) struct TeamSelect {
    #[serde(default)]
    team: Option<String>,
}

pub(super) async fn teams(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    Query(sel): Query<TeamSelect>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    let ctx = settings_ctx(&sess, &csrf, locale);
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) = require_team_admin(
        &state,
        &ctx.csrf_token,
        &ctx.identity_id,
        &ctx.user_email,
        &target.org.id,
    )
    .await
    {
        return r;
    }
    render_teams(&state, &headers, &ctx, target.org, sel.team).await
}

async fn render_teams(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &SettingsCtx,
    org: Org,
    selected: Option<String>,
) -> Response {
    let org_id = &org.id;
    let counts = teams::list_teams_with_counts(&state.db, org_id)
        .await
        .unwrap_or_default();
    let team_rows: Vec<TeamRowView> = counts
        .iter()
        .map(|(t, n)| TeamRowView {
            id: t.id.clone(),
            name: t.name.clone(),
            member_count: *n,
        })
        .collect();

    let mut selected_team = None;
    let mut members = Vec::new();
    let mut addable = Vec::new();
    if let Some(sel) = selected {
        if let Some((team, n)) = counts.iter().find(|(t, _)| t.id == sel) {
            let roster = orgs::list_member_profiles(&state.db, &state.ory, org_id)
                .await
                .unwrap_or_default();
            let member_ids: HashSet<String> = teams::team_member_ids(&state.db, &team.id)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();
            for (m, email, display_name) in &roster {
                let view = RosterView {
                    identity_id: m.identity_id.clone(),
                    email: email.clone(),
                    display_name: display_name.clone(),
                };
                if member_ids.contains(&m.identity_id) {
                    members.push(view);
                } else {
                    addable.push(view);
                }
            }
            selected_team = Some(TeamRowView {
                id: team.id.clone(),
                name: team.name.clone(),
                member_count: *n,
            });
        }
    }

    let nav = build_nav(state, headers, &ctx.identity_id).await;
    let mut resp = render(&TeamsTemplate {
        chrome: PageChrome::from_parts(
            state,
            ctx.user_email.clone(),
            ctx.csrf_token.clone(),
            ctx.locale.clone(),
        ),
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        org,
        nav,
        teams: team_rows,
        selected_team,
        members,
        addable,
    });
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    resp
}

// --- route-derived path bundles ------------------------------------------

/// `slug` (`None` on the Default route) plus the team being acted on.
/// Deserialized from the route path; `slug` is absent on the singular route.
#[derive(Deserialize)]
pub(super) struct TeamTarget {
    #[serde(default)]
    pub(super) slug: Option<String>,
    pub(super) team_id: String,
}

/// `slug` + team + the identity being added/removed.
#[derive(Deserialize)]
pub(super) struct TeamMemberTarget {
    #[serde(default)]
    pub(super) slug: Option<String>,
    pub(super) team_id: String,
    pub(super) identity_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateForm {
    name: String,
}

pub(super) async fn teams_create(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<CreateForm>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) = require_team_admin(&state, &csrf.0, actor, actor_email, org_id).await {
        return r;
    }
    match teams::create_team(&state.db, org_id, form.name.trim(), Some(actor)).await {
        Ok(team) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ORG_TEAM_CREATED)
                    .actor_user(actor.as_str(), actor_email.as_str())
                    .target(target_kind::TEAM, team.id.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!(
                        "org_id" => org_id.as_str(),
                        "team_name" => team.name.as_str(),
                    )),
            )
            .await;
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("could not create team: {e}"),
            )
                .into_response();
        }
    }
    Redirect::to(&format!("{}/teams", target.base_path)).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct RenameForm {
    name: String,
}

pub(super) async fn teams_rename(
    State(state): State<AppState>,
    Path(TeamTarget { slug, team_id }): Path<TeamTarget>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<RenameForm>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) = require_team_admin(&state, &csrf.0, actor, actor_email, org_id).await {
        return r;
    }
    let name = form.name.trim();
    if let Err(e) = teams::rename_team(&state.db, &team_id, name).await {
        return (
            StatusCode::BAD_REQUEST,
            format!("could not rename team: {e}"),
        )
            .into_response();
    }
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_TEAM_RENAMED)
            .actor_user(actor.as_str(), actor_email.as_str())
            .target(target_kind::TEAM, team_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "org_id" => org_id.as_str(),
                "team_name" => name,
            )),
    )
    .await;
    Redirect::to(&format!("{}/teams", target.base_path)).into_response()
}

pub(super) async fn teams_delete(
    State(state): State<AppState>,
    Path(TeamTarget { slug, team_id }): Path<TeamTarget>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) = require_team_admin(&state, &csrf.0, actor, actor_email, org_id).await {
        return r;
    }
    if let Err(e) = teams::delete_team(&state.db, &team_id).await {
        tracing::error!(error = ?e, "teams_delete: delete_team failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response();
    }
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_TEAM_DELETED)
            .actor_user(actor.as_str(), actor_email.as_str())
            .target(target_kind::TEAM, team_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "org_id" => org_id.as_str(),
            )),
    )
    .await;
    Redirect::to(&format!("{}/teams", target.base_path)).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct MemberAddForm {
    identity_id: String,
}

pub(super) async fn teams_member_add(
    State(state): State<AppState>,
    Path(TeamTarget { slug, team_id }): Path<TeamTarget>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<MemberAddForm>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) = require_team_admin(&state, &csrf.0, actor, actor_email, org_id).await {
        return r;
    }
    let new_member = form.identity_id.trim();
    // Only org members may be added to a team.
    if orgs::org_role(&state.db, new_member, org_id)
        .await
        .is_none()
    {
        return (StatusCode::BAD_REQUEST, "not a member of this organization").into_response();
    }
    if let Err(e) = teams::add_member(&state.db, &team_id, new_member).await {
        tracing::error!(error = ?e, "teams_member_add: add_member failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "add failed").into_response();
    }
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_TEAM_MEMBER_ADDED)
            .actor_user(actor.as_str(), actor_email.as_str())
            .target(target_kind::IDENTITY, new_member.to_string())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "org_id" => org_id.as_str(),
                "team_id" => team_id.as_str(),
            )),
    )
    .await;
    Redirect::to(&format!("{}/teams?team={}", target.base_path, team_id)).into_response()
}

pub(super) async fn teams_member_remove(
    State(state): State<AppState>,
    Path(TeamMemberTarget {
        slug,
        team_id,
        identity_id,
    }): Path<TeamMemberTarget>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) = require_team_admin(&state, &csrf.0, actor, actor_email, org_id).await {
        return r;
    }
    if let Err(e) = teams::remove_member(&state.db, &team_id, &identity_id).await {
        tracing::error!(error = ?e, "teams_member_remove: remove_member failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "remove failed").into_response();
    }
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_TEAM_MEMBER_REMOVED)
            .actor_user(actor.as_str(), actor_email.as_str())
            .target(target_kind::IDENTITY, identity_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "org_id" => org_id.as_str(),
                "team_id" => team_id.as_str(),
            )),
    )
    .await;
    Redirect::to(&format!("{}/teams?team={}", target.base_path, team_id)).into_response()
}
