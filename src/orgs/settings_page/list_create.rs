//! `/settings/organizations` list index + create POST + named-delete.
//! License-gated (commercial).

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::commercial::license::Feature;
use crate::commercial::upsell::render_upsell;
use crate::extractors::{gate_orgs_feature_or_upsell, Csrf, RequireSession};
use crate::orgs::{self, Membership, Role};
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::state::AppState;

use crate::csrf::CsrfForm;

use super::{build_nav, require_external_mode_writable, require_org_owner, settings_ctx};

#[derive(Template)]
#[template(path = "orgs/list.html")]
struct OrgsListTemplate {
    chrome: PageChrome,
    memberships: Vec<Membership>,
    /// License covers Orgs and under quota: shows the "Create" form vs an
    /// upsell card.
    can_create: bool,
    /// Pretty label for the upsell card (e.g. "Pro" or "Light").
    required_tier_label: String,
    /// A license is active (drives "Upgrade" vs "Get a license" CTA copy).
    has_license: bool,
    purchase_url: String,
    nav: orgs::nav::OrgNav,
}

pub(super) async fn orgs_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: RequireSession,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
) -> Response {
    let ctx = settings_ctx(&sess, &themed.chrome.csrf_token, locale);

    // Upsell card rendered inline (not a 403) so the list page stays reachable.
    let feat = state.license.feature(Feature::Orgs);
    let max_orgs = state
        .license
        .status()
        .license()
        .map_or(Some(0), |l| l.max_orgs);
    let current = orgs::count_orgs(&state.db).await.unwrap_or(0);
    let can_create = matches!(feat, crate::commercial::FeatureStatus::Allowed)
        && crate::commercial::license::org_cap_allows(max_orgs, current);
    let nav = build_nav(
        &state,
        &headers,
        &ctx.identity_id,
        Some(&themed.memberships),
    )
    .await;
    render(&OrgsListTemplate {
        chrome: themed.chrome,
        memberships: themed.memberships,
        can_create,
        required_tier_label: "Business".to_string(),
        has_license: state.license.status().license().is_some(),
        purchase_url: crate::commercial::upsell::effective_purchase_url(&state),
        nav,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateOrgForm {
    name: String,
    slug: Option<String>,
    access_mode: Option<String>,
}

/// Fail-closed like `orgs::parse_access_mode`: only the exact literal
/// "external" from the create-form radio requests external.
fn parse_create_mode_choice(raw: Option<&str>) -> orgs::AccessMode {
    match raw {
        Some("external") => orgs::AccessMode::External,
        _ => orgs::AccessMode::Internal,
    }
}

pub(super) async fn orgs_create(
    State(state): State<AppState>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<CreateOrgForm>,
) -> Response {
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
        return render_upsell(&state, &csrf.0, &email, Feature::Orgs, locale.clone());
    }
    let max_orgs = state
        .license
        .status()
        .license()
        .map_or(Some(0), |l| l.max_orgs);
    let current = orgs::count_orgs(&state.db).await.unwrap_or(0);
    if !crate::commercial::license::org_cap_allows(max_orgs, current) {
        return render_upsell(&state, &csrf.0, &email, Feature::Orgs, locale);
    }

    let name = form.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name required").into_response();
    }
    if crate::oauth::register::reserved_names::reserved_name_hit(
        &state.cfg.orgs.reserved_names,
        name,
    )
    .is_some()
    {
        return (StatusCode::CONFLICT, "that name is not allowed").into_response();
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
    if orgs::is_reserved_slug(&slug) {
        return (StatusCode::CONFLICT, "slug is reserved").into_response();
    }
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
    // Creator becomes owner of the new tenant org; drop their Default floor row
    // in the same txn unless they are an allowlisted operator (who keep Default).
    let drop_default = !state.cfg.admin.is_admin(&email);
    if let Err(e) =
        orgs::db::join_org_race_safe(&state.db, &identity_id, &id, Role::Owner, drop_default).await
    {
        tracing::warn!(error = ?e, "add_member owner failed");
    } else {
        // Audit the owner self-add so the create path matches the other
        // membership mutations' audit trail.
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
    let requested_mode = parse_create_mode_choice(form.access_mode.as_deref());
    if requested_mode.is_external() {
        if require_external_mode_writable(&state, &csrf.0, &identity_id, &email, &id)
            .await
            .is_ok()
        {
            if let Err(e) =
                orgs::db::set_access_mode(&state.db, &id, orgs::AccessMode::External).await
            {
                tracing::error!(error = ?e, "orgs_create: set_access_mode failed");
            } else if let Err(e) = orgs::db::apply_external_defaults(&state.db, &id).await {
                tracing::error!(error = ?e, "orgs_create: apply_external_defaults failed");
            } else {
                let _ = audit::log(
                    &state.db,
                    AuditEvent::new(action::ORG_ACCESS_MODE_CHANGED)
                        .actor_user(identity_id.as_str(), actor_email.as_str())
                        .target(target_kind::ORG, id.clone())
                        .with_ctx(&actx)
                        .metadata(audit_metadata!(
                            "org_id" => id.as_str(),
                            "org_slug" => slug.as_str(),
                            "from" => "internal",
                            "to" => "external",
                            "via" => "create",
                        )),
                )
                .await;
            }
        } else {
            tracing::warn!(org_id = %id, "orgs_create: external requested but not writable; stays internal");
        }
    }
    Redirect::to(&format!("/settings/organizations/{}", slug)).into_response()
}

pub(super) async fn named_delete(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    sess: RequireSession,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
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
    // Refuse delete while any oauth_client_metadata row references this org;
    // deleting it without migrating the clients would orphan the rows.
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
    if crate::posix::db::count_hosts_in_org(&state.db, &org.id)
        .await
        .unwrap_or(0)
        > 0
    {
        // Hosts are operator-tier; an owner can't destroy them by deleting the org.
        return (
            StatusCode::CONFLICT,
            "revoke this org's hosts before deleting it",
        )
            .into_response();
    }
    if let Err(e) = orgs::delete_org(&state.db, &org.id).await {
        tracing::error!(error = ?e, "delete_org failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response();
    }
    Redirect::to("/settings/organizations").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_mode_choice_defaults_internal() {
        assert_eq!(parse_create_mode_choice(None), orgs::AccessMode::Internal);
        assert_eq!(
            parse_create_mode_choice(Some("internal")),
            orgs::AccessMode::Internal
        );
        assert_eq!(
            parse_create_mode_choice(Some("bogus")),
            orgs::AccessMode::Internal
        );
    }

    #[test]
    fn create_mode_choice_external_only_on_exact_literal() {
        assert_eq!(
            parse_create_mode_choice(Some("external")),
            orgs::AccessMode::External
        );
        assert_eq!(
            parse_create_mode_choice(Some("External")),
            orgs::AccessMode::Internal
        );
    }
}
