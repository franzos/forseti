//! `/settings/organization*`: OSS Default + commercial-tier org pages.
//!
//! Two route shapes coexist:
//! 1. `/settings/organization/*`: singular, Default-org-only, no license gate.
//! 2. `/settings/organizations/{slug}/*`: plural, multi-org, gated on
//!    `feature(Orgs)`.

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::extractors::{gate_orgs_feature_or_upsell, Csrf, RequireSession};
use crate::orgs::{self, Org, Role};
use crate::state::AppState;

mod branding;
mod list_create;
mod members;
mod overview;
mod switch;
mod teams;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        // Singular (Default) and plural (`{slug}`) routes share handlers: an
        // absent `{slug}` extracts as `None`, selecting the Default org.
        .route(
            "/settings/organization",
            get(overview::overview).post(overview::overview_save),
        )
        .route("/settings/organization/info", get(overview::overview_info))
        .route(
            "/settings/organization/branding",
            get(branding::branding).post(branding::branding_save),
        )
        .route("/settings/organization/members", get(members::members))
        .route(
            "/settings/organization/members/visibility",
            post(members::members_visibility),
        )
        .route(
            "/settings/organization/members/{identity_id}/role",
            post(members::members_role),
        )
        .route(
            "/settings/organization/members/{identity_id}/hidden",
            post(members::members_hidden),
        )
        .route(
            "/settings/organization/members/{identity_id}/remove",
            post(members::members_remove),
        )
        // Teams (commercial everywhere) — Default-org singular routes.
        .route(
            "/settings/organization/teams",
            get(teams::teams).post(teams::teams_create),
        )
        .route(
            "/settings/organization/teams/{team_id}/rename",
            post(teams::teams_rename),
        )
        .route(
            "/settings/organization/teams/{team_id}/delete",
            post(teams::teams_delete),
        )
        .route(
            "/settings/organization/teams/{team_id}/members",
            post(teams::teams_member_add),
        )
        .route(
            "/settings/organization/teams/{team_id}/members/{identity_id}/remove",
            post(teams::teams_member_remove),
        )
        // Multi-org (commercial)
        .route("/settings/organizations", get(list_create::orgs_list))
        .route(
            "/settings/organizations/create",
            post(list_create::orgs_create),
        )
        .route(
            "/settings/organizations/{slug}",
            get(overview::overview).post(overview::overview_save),
        )
        .route(
            "/settings/organizations/{slug}/info",
            get(overview::overview_info),
        )
        .route(
            "/settings/organizations/{slug}/branding",
            get(branding::branding).post(branding::branding_save),
        )
        .route(
            "/settings/organizations/{slug}/members",
            get(members::members),
        )
        .route(
            "/settings/organizations/{slug}/members/visibility",
            post(members::members_visibility),
        )
        .route(
            "/settings/organizations/{slug}/members/{identity_id}/role",
            post(members::members_role),
        )
        .route(
            "/settings/organizations/{slug}/members/{identity_id}/hidden",
            post(members::members_hidden),
        )
        .route(
            "/settings/organizations/{slug}/members/{identity_id}/remove",
            post(members::members_remove),
        )
        // Teams (commercial) — multi-org plural twins.
        .route(
            "/settings/organizations/{slug}/teams",
            get(teams::teams).post(teams::teams_create),
        )
        .route(
            "/settings/organizations/{slug}/teams/{team_id}/rename",
            post(teams::teams_rename),
        )
        .route(
            "/settings/organizations/{slug}/teams/{team_id}/delete",
            post(teams::teams_delete),
        )
        .route(
            "/settings/organizations/{slug}/teams/{team_id}/members",
            post(teams::teams_member_add),
        )
        .route(
            "/settings/organizations/{slug}/teams/{team_id}/members/{identity_id}/remove",
            post(teams::teams_member_remove),
        )
        .route(
            "/settings/organizations/{slug}/delete",
            post(list_create::named_delete),
        )
        // Active-org switcher (top-nav dropdown POST target)
        .route("/orgs/switch", post(switch::switch_active_org))
}

// --- org-slug extractor, shared by the singular and plural routes ---------

/// Optional `slug` route segment. Singular routes (`/settings/organization/*`)
/// carry no `{slug}` and yield `None` (the Default org via `resolve_org_or_404`);
/// plural routes (`/settings/organizations/{slug}/*`) yield `Some`. The bundled
/// member/team path structs carry their own `slug` field, so they don't use this.
pub(super) struct OrgSlug(pub(super) Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for OrgSlug {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let slug = <Option<Path<String>>>::from_request_parts(parts, state)
            .await
            .unwrap_or_default()
            .map(|Path(s)| s);
        Ok(OrgSlug(slug))
    }
}

// --- shared session gate -------------------------------------------------

pub(super) struct SettingsCtx {
    pub(super) identity_id: String,
    pub(super) user_email: String,
    pub(super) csrf_token: String,
    pub(super) locale: crate::locale::LanguageIdentifier,
}

pub(super) fn settings_ctx(
    sess: &RequireSession,
    csrf: &Csrf,
    locale: crate::locale::LanguageIdentifier,
) -> SettingsCtx {
    SettingsCtx {
        identity_id: sess.identity_id.clone(),
        user_email: sess.email.clone(),
        csrf_token: csrf.0.clone(),
        locale,
    }
}

/// Resolved org for a settings sub-page plus the redirect/link prefix. The
/// only fork between singular and plural routes is org resolution and the
/// prefix; license gating stays data-driven off `org.id != DEFAULT_ORG_ID`.
pub(crate) struct OrgTarget {
    pub(crate) org: Org,
    /// `/settings/organization` or `/settings/organizations/{slug}`.
    pub(crate) base_path: String,
}

/// Resolve the target org for a settings sub-page: Default when `slug` is
/// `None`, else slug-lookup with a 404 on miss.
pub(crate) async fn resolve_org_or_404(
    state: &AppState,
    slug: Option<&str>,
) -> Result<OrgTarget, Response> {
    match slug {
        None => {
            let Ok(Some(org)) = orgs::org_by_id(&state.db, orgs::DEFAULT_ORG_ID).await else {
                return Err((StatusCode::NOT_FOUND, "unknown organization").into_response());
            };
            Ok(OrgTarget {
                org,
                base_path: "/settings/organization".to_string(),
            })
        }
        Some(slug) => {
            let Ok(Some(org)) = orgs::org_by_slug(&state.db, slug).await else {
                return Err((StatusCode::NOT_FOUND, "unknown organization").into_response());
            };
            let base_path = format!("/settings/organizations/{slug}");
            Ok(OrgTarget { org, base_path })
        }
    }
}

/// Verify the caller is an owner of `org_id` (otherwise 403).
pub(super) async fn require_org_owner(
    state: &AppState,
    identity_id: &str,
    org_id: &str,
) -> Result<(), Response> {
    if orgs::org_role(&state.db, identity_id, org_id).await != Some(Role::Owner) {
        return Err((StatusCode::FORBIDDEN, "owner role required").into_response());
    }
    Ok(())
}

/// Owner-check + license-gate for non-Default org write paths. Default org is
/// OSS; named orgs require `Feature::Orgs`. Locked licenses render the upsell
/// page rather than a hard 403. `email` feeds the upsell "signed in as" line.
pub(super) async fn require_org_owner_with_license(
    state: &AppState,
    csrf_token: &str,
    identity_id: &str,
    email: &str,
    org_id: &str,
) -> Result<(), Response> {
    require_org_owner(state, identity_id, org_id).await?;
    if org_id != orgs::DEFAULT_ORG_ID {
        gate_orgs_feature_or_upsell(state, csrf_token, email)?;
    }
    Ok(())
}

/// License-gate for non-Default org read paths visible to members.
///
/// Same upsell-on-locked behaviour as [`require_org_owner_with_license`]
/// minus the owner check, for GET handlers that members may view.
#[allow(clippy::result_large_err)]
pub(super) fn require_org_license(
    state: &AppState,
    csrf_token: &str,
    email: &str,
    org_id: &str,
) -> Result<(), Response> {
    if org_id != orgs::DEFAULT_ORG_ID {
        gate_orgs_feature_or_upsell(state, csrf_token, email)?;
    }
    Ok(())
}

pub(super) async fn build_nav(
    state: &AppState,
    headers: &HeaderMap,
    identity_id: &str,
) -> orgs::nav::OrgNav {
    let memberships = orgs::list_memberships(&state.db, identity_id)
        .await
        .unwrap_or_default();
    let active = orgs::active_org(
        &memberships,
        &state.cookie_secret,
        state.cfg.orgs.active_org_cookie_ttl_seconds,
        headers,
    );
    orgs::nav::OrgNav::from(active, memberships)
}
