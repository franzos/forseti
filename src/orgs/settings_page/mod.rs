//! `/settings/organization*` — OSS Default + commercial-tier org pages.
//!
//! Two route shapes coexist:
//!
//! 1. `/settings/organization/*` — singular, Default-org-only. Lives in
//!    OSS as the rebadged admin-management page that used to require
//!    editing `config.toml`. No license gate.
//! 2. `/settings/organizations/{slug}/*` — plural, multi-org. Commercial
//!    only. Each handler checks `feature(Orgs)` before rendering.
//!
//! Sub-pages: overview (rename), branding (logo + support email), members
//! (list + role + remove), pending-invites, create-new-org form.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::Form;

use crate::audit::AuditCtx;
use crate::extractors::{gate_orgs_feature_or_upsell, Csrf, RequireSession};
use crate::orgs::{self, Org, Role};
use crate::state::AppState;

mod branding;
mod list_create;
mod members;
mod overview;
mod switch;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        // OSS Default-org pages (singular, no slug) and the multi-org
        // (commercial, `{slug}`) twins target the same handlers — an absent
        // `{slug}` segment extracts as `None`, selecting the Default org.
        // Everything past resolution is shared, including the data-driven
        // license gate.
        .route("/settings/organization", get(overview).post(overview_save))
        .route("/settings/organization/info", get(overview_info))
        .route(
            "/settings/organization/branding",
            get(branding).post(branding_save),
        )
        .route("/settings/organization/members", get(members))
        .route(
            "/settings/organization/members/{identity_id}/role",
            post(members_role),
        )
        .route(
            "/settings/organization/members/{identity_id}/remove",
            post(members_remove),
        )
        // Multi-org (commercial)
        .route("/settings/organizations", get(list_create::orgs_list))
        .route(
            "/settings/organizations/create",
            post(list_create::orgs_create),
        )
        .route(
            "/settings/organizations/{slug}",
            get(overview).post(overview_save),
        )
        .route("/settings/organizations/{slug}/info", get(overview_info))
        .route(
            "/settings/organizations/{slug}/branding",
            get(branding).post(branding_save),
        )
        .route("/settings/organizations/{slug}/members", get(members))
        .route(
            "/settings/organizations/{slug}/members/{identity_id}/role",
            post(members_role),
        )
        .route(
            "/settings/organizations/{slug}/members/{identity_id}/remove",
            post(members_remove),
        )
        .route(
            "/settings/organizations/{slug}/delete",
            post(list_create::named_delete),
        )
        // Active-org switcher (top-nav dropdown POST target)
        .route("/orgs/switch", post(switch::switch_active_org))
}

// --- handlers: one fn per page, shared by the singular Default-org route
// (`slug` absent → `None`) and the plural multi-org route (`{slug}` → `Some`).

/// Pull the optional `slug` segment out of a path that may or may not carry
/// it. The singular `/settings/organization*` routes have no `{slug}`, so the
/// extractor yields `None` (the Default org); the plural routes carry it.
fn slug_of(path: Option<Path<String>>) -> Option<String> {
    path.map(|Path(s)| s)
}

async fn overview(
    state: State<AppState>,
    slug: Option<Path<String>>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    overview::overview(state, slug_of(slug), headers, sess, csrf).await
}

async fn overview_save(
    state: State<AppState>,
    slug: Option<Path<String>>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    form: Form<overview::OverviewForm>,
) -> Response {
    overview::overview_save(state, slug_of(slug), headers, sess, csrf, form).await
}

async fn overview_info(
    state: State<AppState>,
    slug: Option<Path<String>>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    overview::overview_info(state, slug_of(slug), headers, sess, csrf).await
}

async fn branding(
    state: State<AppState>,
    slug: Option<Path<String>>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    branding::branding(state, slug_of(slug), headers, sess, csrf).await
}

async fn branding_save(
    state: State<AppState>,
    slug: Option<Path<String>>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    form: Form<branding::BrandingForm>,
) -> Response {
    branding::branding_save(state, slug_of(slug), headers, sess, csrf, form).await
}

async fn members(
    state: State<AppState>,
    slug: Option<Path<String>>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    members::members(state, slug_of(slug), headers, sess, csrf).await
}

async fn members_role(
    state: State<AppState>,
    Path(params): Path<MemberPath>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    form: Form<members::RoleForm>,
) -> Response {
    members::members_role(state, params.into_target(), headers, sess, csrf, actx, form).await
}

async fn members_remove(
    state: State<AppState>,
    Path(params): Path<MemberPath>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    form: Form<crate::csrf::CsrfForm>,
) -> Response {
    members::members_remove(state, params.into_target(), headers, sess, csrf, actx, form).await
}

/// Path params for the member role/remove routes. `slug` is absent on the
/// singular Default-org route and present on the plural multi-org route;
/// `serde` fills it from whichever segments the matched route exposes.
#[derive(serde::Deserialize)]
struct MemberPath {
    #[serde(default)]
    slug: Option<String>,
    identity_id: String,
}

impl MemberPath {
    fn into_target(self) -> members::MemberTarget {
        members::MemberTarget {
            slug: self.slug,
            identity_id: self.identity_id,
        }
    }
}

// --- shared session gate -------------------------------------------------

pub(super) struct SettingsCtx {
    pub(super) identity_id: String,
    pub(super) user_email: String,
    pub(super) csrf_token: String,
}

pub(super) fn settings_ctx(sess: &RequireSession, csrf: &Csrf) -> SettingsCtx {
    SettingsCtx {
        identity_id: sess.identity_id.clone(),
        user_email: sess.email.clone(),
        csrf_token: csrf.0.clone(),
    }
}

/// Resolved org for a settings sub-page, plus the path prefix its
/// redirects/links hang off. `slug` is `None` on the OSS Default route
/// (`/settings/organization`) and `Some(_)` on the multi-org route
/// (`/settings/organizations/{slug}`); the only behavioural fork between
/// the two is org resolution and the redirect prefix — license gating
/// stays data-driven off `org.id != DEFAULT_ORG_ID` in the worker helpers.
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

/// Owner-check + license-gate for non-Default org write paths.
///
/// Default org stays OSS — no license check. Any named org (id !=
/// `DEFAULT_ORG_ID`) requires `Feature::Orgs` to be `Allowed`. Locked
/// licenses render the upsell page rather than a hard 403 so the user
/// understands what's blocking them.
///
/// Caller passes `email` for the upsell page's "signed in as" line.
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
