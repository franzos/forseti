//! Overview page — rename + slug change. Default + named variants share
//! the same view-model and save worker.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, RequireSession};
use crate::orgs::{self, Org, Role};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::{
    build_nav, require_org_license, require_org_owner_with_license, resolve_org_or_404,
    settings_ctx, OrgSlug, SettingsCtx,
};

#[derive(Template)]
#[template(path = "orgs/overview.html")]
struct OverviewTemplate {
    chrome: PageChrome,
    org: Org,
    is_owner: bool,
    is_default: bool,
    member_count: usize,
    /// Read-only SSO status (operator-managed at `/admin/saml`). `None` when
    /// `[saml]` is unconfigured or the org has no connection.
    sso: Option<SsoStatus>,
    nav: orgs::nav::OrgNav,
}

struct SsoStatus {
    display_name: String,
    enabled: bool,
    sso_path: String,
}

/// SSO status shared by the owner + member overviews. `None` when `[saml]` is
/// unconfigured or there's no connection; a lookup failure logs and yields
/// `None` so a DB blip never breaks the page.
async fn sso_status(state: &AppState, org: &Org) -> Option<SsoStatus> {
    state.cfg.saml.as_ref()?;
    match crate::saml::db::get_connection(&state.db, &org.id).await {
        Ok(Some(conn)) => Some(SsoStatus {
            display_name: conn.display_name.clone(),
            enabled: conn.is_enabled(),
            sso_path: format!("/sso/{}", org.slug),
        }),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = ?e, org_id = %org.id, "org overview: saml connection lookup failed");
            None
        }
    }
}

pub(super) async fn overview(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
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
    // Non-Default orgs are license-gated for display too. Members still see
    // them if they were already members before the license lapsed.
    if let Err(r) = require_org_license(&state, &ctx.csrf_token, &ctx.user_email, &target.org.id) {
        return r;
    }
    // The management page is owner-only; non-owner members drop to the
    // read-only `/info` mirror rather than seeing edit forms they can't submit.
    if orgs::org_role(&state.db, &ctx.identity_id, &target.org.id).await != Some(Role::Owner) {
        return Redirect::to(&format!("{}/info", target.base_path)).into_response();
    }
    render_overview(&state, &headers, &ctx, &target.org).await
}

pub(super) async fn overview_info(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
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
    if let Err(r) = require_org_license(&state, &ctx.csrf_token, &ctx.user_email, &target.org.id) {
        return r;
    }
    render_overview_info(&state, &headers, &ctx, target.org).await
}

/// Read-only mirror of [`render_overview`]. Same data, no edit form,
/// no danger zone, no owner-only quick links. Surfaces the owner emails
/// so members know who manages the org.
async fn render_overview_info(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &SettingsCtx,
    org: Org,
) -> Response {
    let members = orgs::list_members(&state.db, &org.id)
        .await
        .unwrap_or_default();
    // One round-trip for all owner identities (avoids an N+1 per owner).
    let owner_ids: Vec<String> = members
        .iter()
        .filter(|m| crate::orgs::is_owner_role(&m.role))
        .map(|m| m.identity_id.clone())
        .collect();
    let mut owner_emails: Vec<String> = if owner_ids.is_empty() {
        Vec::new()
    } else {
        crate::ory::kratos::admin_list_identities_by_ids(&state.ory, owner_ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| {
                id.traits
                    .and_then(|t| t.get("email").and_then(|v| v.as_str().map(str::to_string)))
            })
            .collect()
    };
    owner_emails.sort();
    let sso = sso_status(state, &org).await;
    let nav = build_nav(state, headers, &ctx.identity_id).await;
    render(&OverviewInfoTemplate {
        chrome: PageChrome::from_parts(
            state,
            ctx.user_email.clone(),
            ctx.csrf_token.clone(),
            ctx.locale.clone(),
        ),
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        org,
        member_count: members.len(),
        owner_emails,
        sso,
        nav,
    })
}

#[derive(Template)]
#[template(path = "orgs/overview_info.html")]
struct OverviewInfoTemplate {
    chrome: PageChrome,
    org: Org,
    is_default: bool,
    member_count: usize,
    /// Sorted, unique. Lets members know who to contact without exposing the
    /// full roster.
    owner_emails: Vec<String>,
    /// Same SSO status the owner sees; members log in via `/sso/{slug}`.
    sso: Option<SsoStatus>,
    nav: orgs::nav::OrgNav,
}

async fn render_overview(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &SettingsCtx,
    org: &Org,
) -> Response {
    let is_owner = orgs::org_role(&state.db, &ctx.identity_id, &org.id).await == Some(Role::Owner);
    let members = orgs::list_members(&state.db, &org.id)
        .await
        .unwrap_or_default();
    let sso = sso_status(state, org).await;
    let nav = build_nav(state, headers, &ctx.identity_id).await;
    render(&OverviewTemplate {
        chrome: PageChrome::from_parts(
            state,
            ctx.user_email.clone(),
            ctx.csrf_token.clone(),
            ctx.locale.clone(),
        ),
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        org: org.clone(),
        is_owner,
        member_count: members.len(),
        sso,
        nav,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct OverviewForm {
    name: String,
    slug: String,
}

pub(super) async fn overview_save(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    sess: RequireSession,
    csrf: Csrf,
    CsrfForm(form): CsrfForm<OverviewForm>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = &target.org.id;
    if let Err(r) =
        require_org_owner_with_license(&state, &csrf.0, &sess.identity_id, &sess.email, org_id)
            .await
    {
        return r;
    }
    let new_slug = orgs::slugify(&form.slug);
    if new_slug != target.org.slug {
        // Second slug write-path (after create): guard here too so a rename
        // can't claim a route-shadowing slug the create path already refuses.
        if orgs::is_reserved_slug(&new_slug) {
            return (StatusCode::CONFLICT, "slug is reserved").into_response();
        }
        // Reject duplicates loudly (the database UNIQUE constraint would
        // also catch this, but a friendly error is nicer than a 500).
        if orgs::org_by_slug(&state.db, &new_slug)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return (StatusCode::CONFLICT, "slug already in use").into_response();
        }
    }
    if let Err(e) = orgs::update_branding(
        &state.db,
        org_id,
        form.name.trim(),
        &new_slug,
        target.org.logo_url.as_deref(),
        target.org.support_email.as_deref(),
    )
    .await
    {
        tracing::error!(error = ?e, "overview_save: update_branding failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "save failed").into_response();
    }
    // Named orgs land on the renamed slug; the Default route's slug is fixed.
    let redirect_to = match slug {
        Some(_) => format!("/settings/organizations/{new_slug}"),
        None => target.base_path,
    };
    Redirect::to(&redirect_to).into_response()
}

#[cfg(test)]
mod tests {
    use crate::orgs;

    /// The rename path slugifies the submitted slug then guards it, same as
    /// create. A submitted "admin" must resolve to a reserved slug and be
    /// rejected rather than shadowing `/admin` and friends.
    #[test]
    fn rename_to_reserved_word_is_flagged() {
        assert!(orgs::is_reserved_slug(&orgs::slugify("Admin")));
        assert!(orgs::is_reserved_slug(&orgs::slugify("login")));
        assert!(!orgs::is_reserved_slug(&orgs::slugify("Acme Corp")));
    }
}
