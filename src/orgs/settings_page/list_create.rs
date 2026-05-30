//! `/settings/organizations` list index + create POST + named-delete.
//! License-gated (commercial).

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::commercial::license::Feature;
use crate::commercial::upsell::render_upsell;
use crate::extractors::{gate_orgs_feature_or_upsell, Csrf, RequireSession};
use crate::orgs::{self, Membership, Role};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use crate::csrf::CsrfForm;

use super::{build_nav, require_org_owner, settings_ctx};

#[derive(Template)]
#[template(path = "orgs/list.html")]
struct OrgsListTemplate {
    chrome: PageChrome,
    memberships: Vec<Membership>,
    /// True when the operator's license covers the Orgs feature and
    /// they're under the quota — drives whether the "Create" form is
    /// shown or hidden behind an upsell card.
    can_create: bool,
    /// Pretty label for the upsell card (e.g. "Pro" or "Light").
    required_tier_label: String,
    /// True when at least one license is active (drives "Upgrade" vs
    /// "Get a license" CTA copy).
    has_license: bool,
    purchase_url: String,
    nav: orgs::nav::OrgNav,
}

pub(super) async fn orgs_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    let ctx = settings_ctx(&sess, &csrf);
    let memberships = orgs::list_memberships(&state.db, &ctx.identity_id)
        .await
        .unwrap_or_default();

    // License gate: can_create iff feature(Orgs) is Allowed AND we're
    // under max_orgs. We render the upsell card inline instead of a
    // hard 403 so the list page is always reachable.
    let feat = state.license.feature(Feature::Orgs);
    let max_orgs = state
        .license
        .status()
        .license()
        .map_or(Some(0), |l| l.max_orgs);
    let current = orgs::count_orgs(&state.db).await.unwrap_or(0);
    let can_create = matches!(feat, crate::commercial::FeatureStatus::Allowed)
        && crate::commercial::license::org_cap_allows(max_orgs, current);
    let nav = build_nav(&state, &headers, &ctx.identity_id).await;
    render(&OrgsListTemplate {
        chrome: PageChrome::from_parts(&state, ctx.user_email, ctx.csrf_token),
        memberships,
        can_create,
        required_tier_label: "Business".to_string(),
        has_license: state.license.status().license().is_some(),
        purchase_url: crate::commercial::upsell::effective_purchase_url(&state),
        nav,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateOrgForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    name: String,
    slug: Option<String>,
}

pub(super) async fn orgs_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    Form(form): Form<CreateOrgForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let identity_id = sess.identity_id;
    let email = sess.email;
    let actor_email = email.clone();

    // Gate rejected `Locked` already; refuse `GraceReadOnly` here
    // because create is a hard write (grace is read-only).
    let feat_status = match gate_orgs_feature_or_upsell(&state, &csrf.0, &email) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !matches!(feat_status, crate::commercial::FeatureStatus::Allowed) {
        return render_upsell(&state, &csrf.0, &email, Feature::Orgs);
    }
    let max_orgs = state
        .license
        .status()
        .license()
        .map_or(Some(0), |l| l.max_orgs);
    let current = orgs::count_orgs(&state.db).await.unwrap_or(0);
    if !crate::commercial::license::org_cap_allows(max_orgs, current) {
        return render_upsell(&state, &csrf.0, &email, Feature::Orgs);
    }

    let name = form.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name required").into_response();
    }
    let slug = match form
        .slug
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => orgs::slugify(s),
        None => match orgs::suggest_slug(&state.db, name).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "suggest_slug failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "slug suggestion failed")
                    .into_response();
            }
        },
    };
    if orgs::org_by_slug(&state.db, &slug)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return (StatusCode::CONFLICT, "slug already in use").into_response();
    }
    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = orgs::create_org(&state.db, &id, &slug, name, Some(&identity_id)).await {
        tracing::error!(error = ?e, "create_org failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
    }
    if let Err(e) = orgs::add_member(
        &state.db,
        &id,
        &identity_id,
        Role::Owner,
        Some(&identity_id),
    )
    .await
    {
        tracing::warn!(error = ?e, "add_member owner failed");
    } else {
        // Owner self-add on org creation. Membership mutations elsewhere
        // (role change, removal) are already audited at the handler
        // layer; this closes the gap on the create path so every
        // membership row written has a corresponding audit trail.
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::ORG_MEMBER_ADDED)
                .actor_user(identity_id.as_str(), actor_email.as_str())
                .target(target_kind::IDENTITY, identity_id.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "org_id" => id.as_str(),
                    "org_slug" => slug.as_str(),
                    "role" => "owner",
                    "source" => "org_create",
                )),
        )
        .await;
    }
    Redirect::to(&format!("/settings/organizations/{}", slug)).into_response()
}

pub(super) async fn named_delete(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    sess: RequireSession,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let identity_id = sess.identity_id;
    let Ok(Some(org)) = orgs::org_by_slug(&state.db, &slug).await else {
        return (StatusCode::NOT_FOUND, "unknown organization").into_response();
    };
    if org.id == orgs::DEFAULT_ORG_ID {
        return (StatusCode::CONFLICT, "Default org cannot be deleted").into_response();
    }
    if let Err(r) = require_org_owner(&state, &identity_id, &org.id).await {
        return r;
    }
    // Precondition: refuse delete while any oauth_client_metadata row
    // references this org. The Hydra-side client object itself is
    // owner-of-record for the oauth2 client; deleting the org without
    // moving its clients somewhere would orphan the rows.
    let pending = crate::oauth_client_metadata::count_for_org(&state.db, &org.id)
        .await
        .unwrap_or(0);
    if pending > 0 {
        return (
            StatusCode::CONFLICT,
            format!(
                "Cannot delete org: {pending} OAuth2 client(s) still reference it. Migrate or delete those clients first."
            ),
        )
            .into_response();
    }
    if let Err(e) = orgs::delete_org(&state.db, &org.id).await {
        tracing::error!(error = ?e, "delete_org failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response();
    }
    Redirect::to("/settings/organizations").into_response()
}
