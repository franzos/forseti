//! Members page — list + role + remove. Includes pending-invites.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::{Deserialize, Serialize};

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::extractors::{Csrf, RequireSession};
use crate::orgs::{self, Org, Role};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::{
    build_nav, require_org_license, require_org_owner_with_license, resolve_org_or_404,
    settings_ctx, SettingsCtx,
};

#[derive(Serialize, Clone)]
struct MemberView {
    identity_id: String,
    email: String,
    /// "First Last" composite. Empty when no `traits.name`; template falls
    /// back to the email.
    display_name: String,
    role: String,
    /// Human-friendly relative timestamp.
    added_at: String,
    /// True for the viewing user's own row. Drives the "(you)" hint.
    is_self: bool,
    /// External avatar URL. Empty falls through to `identicon_svg`.
    avatar_url: String,
    /// Deterministic SVG identicon, inlined via `|safe`. Always present.
    identicon_svg: String,
    /// Member has opted out of the directory; shown to owners as a badge.
    hidden: bool,
}

#[derive(Serialize, Clone)]
struct InviteView {
    token: String,
    email: String,
    role: String,
    expires_at: String,
    invited_at: String,
}

#[derive(Template)]
#[template(path = "orgs/members.html")]
struct MembersTemplate {
    chrome: PageChrome,
    org: Org,
    members: Vec<MemberView>,
    invites: Vec<InviteView>,
    is_default: bool,
    is_owner: bool,
    /// Active directory-visibility policy; drives the policy statement shown
    /// to non-owners.
    visibility: String,
    /// Gates whether the name links to `/users/{id}`; avatar always renders.
    profiles_enabled: bool,
    nav: orgs::nav::OrgNav,
}

pub(super) async fn members(
    State(state): State<AppState>,
    slug: Option<String>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    let ctx = settings_ctx(&sess, &csrf);
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) = require_org_license(&state, &ctx.csrf_token, &ctx.user_email, &target.org.id) {
        return r;
    }
    let role = orgs::org_role(&state.db, &ctx.identity_id, &target.org.id).await;
    let admin_aal2 = state.cfg.admin.is_admin(&ctx.user_email)
        && crate::ory::kratos::session_satisfies_aal2(&sess.session);
    if role.is_none() && !admin_aal2 {
        return (StatusCode::NOT_FOUND, "unknown organization").into_response();
    }
    render_members(&state, &headers, &ctx, target.org, role, admin_aal2).await
}

async fn render_members(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &SettingsCtx,
    org: Org,
    role: Option<Role>,
    admin_aal2: bool,
) -> Response {
    let org_id = &org.id;
    let is_owner = role == Some(Role::Owner);
    let policy = crate::orgs::visibility::parse_visibility(&org.member_visibility);
    let co: std::collections::HashSet<String> =
        if policy == crate::orgs::visibility::MemberVisibility::SameGroup {
            crate::orgs::teams::co_team_member_ids(&state.db, &org.id, &ctx.identity_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect()
        } else {
            std::collections::HashSet::new()
        };
    let triples = orgs::list_member_profiles(&state.db, &state.ory, org_id)
        .await
        .unwrap_or_default();
    let profiles_enabled = state.cfg.profiles.enabled;
    // One query, skipped when profiles are off so OSS doesn't pay for it.
    let profiles_by_id = if profiles_enabled {
        let ids: Vec<&str> = triples
            .iter()
            .map(|(m, _, _)| m.identity_id.as_str())
            .collect();
        crate::profiles::fetch_many(&state.db, &ids)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };
    let mut members: Vec<MemberView> = Vec::with_capacity(triples.len());
    for (m, email, display_name) in triples {
        let is_self = m.identity_id == ctx.identity_id;
        let hidden = m.hidden_from_directory != 0;
        if !crate::orgs::visibility::visible(
            policy,
            is_self,
            is_owner,
            admin_aal2,
            hidden,
            co.contains(&m.identity_id),
        ) {
            continue;
        }
        let avatar_url = profiles_by_id
            .get(&m.identity_id)
            .and_then(|p| p.avatar_url.clone())
            .unwrap_or_default();
        let identicon_svg = crate::profiles::identicon::render(&m.identity_id);
        members.push(MemberView {
            is_self,
            identity_id: m.identity_id,
            email,
            display_name,
            role: m.role,
            added_at: crate::format::humanise_timestamp(&m.added_at),
            avatar_url,
            identicon_svg,
            hidden,
        });
    }
    // Pending invites are owner-only; non-owners get an empty list.
    let invites: Vec<InviteView> = if is_owner {
        orgs::list_org_invites(&state.db, org_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|i| InviteView {
                token: i.token,
                email: i.email,
                role: i.role,
                expires_at: crate::format::humanise_timestamp(&i.expires_at),
                invited_at: crate::format::humanise_timestamp(&i.created_at),
            })
            .collect()
    } else {
        Vec::new()
    };
    let nav = build_nav(state, headers, &ctx.identity_id).await;
    let visibility = policy.as_str().to_string();
    let mut resp = render(&MembersTemplate {
        chrome: PageChrome::from_parts(state, ctx.user_email.clone(), ctx.csrf_token.clone()),
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        org,
        members,
        invites,
        is_owner,
        visibility,
        profiles_enabled,
        nav,
    });
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    resp
}

#[derive(Debug, Deserialize)]
pub(super) struct RoleForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    role: String,
}

/// Org slug (`None` for Default) + the member identity being acted on, bundled
/// to keep the handlers under clippy's argument limit.
pub(super) struct MemberTarget {
    pub(super) slug: Option<String>,
    pub(super) identity_id: String,
}

pub(super) async fn members_role(
    State(state): State<AppState>,
    MemberTarget {
        slug,
        identity_id: target_identity,
    }: MemberTarget,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    Form(form): Form<RoleForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) =
        require_org_owner_with_license(&state, &csrf.0, actor, actor_email, org_id).await
    {
        return r;
    }
    let Ok(role) = form.role.parse::<Role>() else {
        return (StatusCode::BAD_REQUEST, "invalid role").into_response();
    };
    // Refuse to demote the sole owner: the org would lose every privileged
    // operation (rename, invite, manage roles) and become unrecoverable
    // through the UI.
    if role == Role::Member {
        let members = orgs::list_members(&state.db, org_id)
            .await
            .unwrap_or_default();
        let owners: Vec<_> = members
            .iter()
            .filter(|m| crate::orgs::is_owner_role(&m.role))
            .collect();
        if owners.len() == 1 && owners[0].identity_id == target_identity {
            return (StatusCode::CONFLICT, "cannot demote the last owner").into_response();
        }
    }
    if let Err(e) = orgs::update_role(&state.db, org_id, &target_identity, role).await {
        tracing::error!(error = ?e, "update_role failed");
    } else {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::ORG_MEMBER_ROLE_CHANGED)
                .actor_user(actor.as_str(), actor_email.as_str())
                .target(target_kind::IDENTITY, target_identity.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "org_id" => org_id.as_str(),
                    "new_role" => role.as_str(),
                )),
        )
        .await;
    }
    Redirect::to(&format!("{}/members", target.base_path)).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct VisibilityForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    visibility: String,
}

pub(super) async fn members_visibility(
    State(state): State<AppState>,
    slug: Option<String>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    Form(form): Form<VisibilityForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) =
        require_org_owner_with_license(&state, &csrf.0, actor, actor_email, org_id).await
    {
        return r;
    }
    let Ok(policy) = form
        .visibility
        .parse::<crate::orgs::visibility::MemberVisibility>()
    else {
        return (StatusCode::BAD_REQUEST, "invalid visibility").into_response();
    };
    // same_group only makes sense once at least one team exists; otherwise
    // it silently hides every peer from every non-owner (no team to share).
    if policy == crate::orgs::visibility::MemberVisibility::SameGroup
        && crate::orgs::teams::list_teams(&state.db, org_id)
            .await
            .unwrap_or_default()
            .is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            "create a team before restricting to same-group",
        )
            .into_response();
    }
    if let Err(e) = orgs::set_member_visibility(&state.db, org_id, policy).await {
        tracing::error!(error = ?e, "set_member_visibility failed");
    } else {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::ORG_VISIBILITY_CHANGED)
                .actor_user(actor.as_str(), actor_email.as_str())
                .target(target_kind::ORG, org_id.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "org_id" => org_id.as_str(),
                    "visibility" => policy.as_str(),
                )),
        )
        .await;
    }
    Redirect::to(&format!("{}/members", target.base_path)).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct HiddenForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    hidden: String,
}

pub(super) async fn members_hidden(
    State(state): State<AppState>,
    MemberTarget {
        slug,
        identity_id: target_identity,
    }: MemberTarget,
    headers: HeaderMap,
    sess: RequireSession,
    actx: AuditCtx,
    Form(form): Form<HiddenForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    // Owner may toggle anyone; a non-owner may only toggle their own row.
    let is_owner = orgs::org_role(&state.db, actor, org_id).await == Some(Role::Owner);
    if !is_owner && actor != &target_identity {
        return (StatusCode::FORBIDDEN, "owner role required").into_response();
    }
    let hidden = form.hidden == "true";
    if let Err(e) = orgs::set_member_hidden(&state.db, org_id, &target_identity, hidden).await {
        tracing::error!(error = ?e, "set_member_hidden failed");
    } else {
        let act = if hidden {
            action::ORG_MEMBER_DIRECTORY_HIDDEN
        } else {
            action::ORG_MEMBER_DIRECTORY_UNHIDDEN
        };
        let _ = audit::log(
            &state.db,
            AuditEvent::new(act)
                .actor_user(actor.as_str(), actor_email.as_str())
                .target(target_kind::IDENTITY, target_identity.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "org_id" => org_id.as_str(),
                )),
        )
        .await;
    }
    Redirect::to(&format!("{}/members", target.base_path)).into_response()
}

pub(super) async fn members_remove(
    State(state): State<AppState>,
    MemberTarget {
        slug,
        identity_id: target_identity,
    }: MemberTarget,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    Form(form): Form<crate::csrf::CsrfForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    let actor = &sess.identity_id;
    let actor_email = &sess.email;
    if let Err(r) =
        require_org_owner_with_license(&state, &csrf.0, actor, actor_email, org_id).await
    {
        return r;
    }
    // Refuse to remove the last owner: the org would become ungovernable.
    let members = orgs::list_members(&state.db, org_id)
        .await
        .unwrap_or_default();
    let owners: Vec<_> = members
        .iter()
        .filter(|m| crate::orgs::is_owner_role(&m.role))
        .collect();
    if owners.len() == 1 && owners[0].identity_id == target_identity {
        return (StatusCode::CONFLICT, "cannot remove the last owner").into_response();
    }
    if let Err(e) = orgs::remove_member(&state.db, org_id, &target_identity).await {
        tracing::error!(error = ?e, "remove_member failed");
    } else {
        // Cascade: drop the ex-member from the org's teams so a team-scoped
        // host stops resolving them. Best-effort; never abort.
        if let Err(e) =
            crate::orgs::teams::remove_identity_from_org_teams(&state.db, org_id, &target_identity)
                .await
        {
            tracing::error!(error = ?e, org_id = %org_id, identity_id = %target_identity, "failed to revoke team membership on org member removal");
        }
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::ORG_MEMBER_REMOVED)
                .actor_user(actor.as_str(), actor_email.as_str())
                .target(target_kind::IDENTITY, target_identity.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "org_id" => org_id.as_str(),
                )),
        )
        .await;
    }
    Redirect::to(&format!("{}/members", target.base_path)).into_response()
}
