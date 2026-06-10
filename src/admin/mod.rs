//! Admin surface.
//!
//! Mounted under `/admin/*` from `main.rs::main`. Two-tier access model:
//!
//!   - [`require_admin`] — Tier 1, Forseti-wide. Session + AAL2 +
//!     `config.admin.allowed_emails`.
//!   - [`require_admin_with_scope`] — Tier 1 *or* Tier 2 routed by
//!     `?org=<slug>`. Tier 2 is session + AAL2 + org ownership (no
//!     allowlist check). See its docstring and `docs/operator-guide.md`
//!     ("Admin access model") for the full rationale.
//!
//! Why a config allowlist rather than a role on the identity (Tier 1):
//! keeps operator membership declarative and reviewable in the operator's
//! `config.toml`, and avoids carrying a custom trait through the Kratos
//! identity schema. The trade-off is that adding/removing a Forseti-wide
//! admin requires a config reload; for the small operator pool this is
//! aimed at, that's a feature.

use askama::Template;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;

use crate::config::BrandConfig;
use crate::cookies;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;
pub(crate) use crate::web::FORSETI_VERSION;

pub mod actions;
pub mod audit;
pub mod clients;
pub mod configuration;
pub mod dcr_tokens;
pub mod identities;
pub mod saml;
pub mod sessions;
pub mod status;
pub mod webhooks;

/// Build the admin sub-router. Mounted at the root in `main.rs`; every
/// route is path-prefixed `/admin/...` directly (rather than nested) so
/// `require_admin` sees the full request path for redirects.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(redirect_to_status))
        .route("/admin/status", get(status::show))
        .route("/admin/configuration", get(configuration::show))
        // Clients
        .route("/admin/clients", get(clients::list).post(clients::create))
        .route("/admin/clients/new", get(clients::new))
        .route(
            "/admin/clients/{id}",
            get(clients::show).post(clients::update),
        )
        .route(
            "/admin/clients/{id}/rotate-secret",
            get(clients::rotate_confirm).post(clients::rotate),
        )
        .route(
            "/admin/clients/{id}/delete",
            get(clients::delete_confirm).post(clients::delete),
        )
        .route("/admin/clients/{id}/verify", post(clients::verify))
        .route(
            "/admin/clients/{id}/unverify",
            get(clients::unverify_confirm).post(clients::unverify),
        )
        // Identities
        .route("/admin/identities", get(identities::list))
        .route("/admin/identities/{id}", get(identities::show))
        .route(
            "/admin/identities/{id}/recovery",
            post(identities::recovery),
        )
        .route(
            "/admin/identities/{id}/disable",
            get(identities::disable_confirm).post(identities::disable),
        )
        .route("/admin/identities/{id}/enable", post(identities::enable))
        .route(
            "/admin/identities/{id}/delete",
            get(identities::delete_confirm).post(identities::delete),
        )
        // Sessions
        .route("/admin/sessions", get(sessions::list))
        .route(
            "/admin/sessions/{id}/revoke",
            get(sessions::revoke_confirm).post(sessions::revoke),
        )
        // Audit (session-events stand-in)
        .route("/admin/audit", get(audit::show))
        .route("/admin/audit/{id}", get(audit::show_one))
        // Webhooks (Phase 1: dead-lettered account-deletion fan-out rows)
        .route("/admin/webhooks", get(webhooks::show))
        .route("/admin/webhooks/{id}", get(webhooks::show_one))
        .route("/admin/webhooks/{id}/requeue", post(webhooks::requeue))
        .route("/admin/webhooks/{id}/discard", post(webhooks::discard))
        // SAML SSO connections (commercial)
        .route("/admin/saml", get(saml::list))
        .route("/admin/saml/new", get(saml::new).post(saml::create))
        .route(
            "/admin/saml/{org_id}/delete",
            get(saml::delete_confirm).post(saml::delete),
        )
        .route("/admin/saml/{org_id}/toggle", post(saml::toggle))
        // DCR initial access tokens — gate for /oauth2/register
        .route("/admin/dcr-tokens", get(dcr_tokens::list))
        .route(
            "/admin/dcr-tokens/new",
            get(dcr_tokens::new).post(dcr_tokens::issue),
        )
        .route(
            "/admin/dcr-tokens/{id}/revoke",
            get(dcr_tokens::revoke_confirm).post(dcr_tokens::revoke),
        )
}

/// `/admin` → `/admin/status`. Saves operators a click on the bookmark.
async fn redirect_to_status() -> Response {
    Redirect::to("/admin/status").into_response()
}

/// Outcome of running the admin auth gate. On success, the caller gets
/// the admin's email + identity ID + a brand snapshot for templates. On
/// failure, the gate returns a `Response` (redirect or 403 page) that
/// the handler should return immediately.
pub struct AdminCtx {
    /// Admin's Kratos identity id — used as `actor_id` in audit logs.
    pub identity_id: String,
    /// Admin's session email — used as `actor_email` in audit logs and the
    /// `actor` chip in template chrome.
    pub email: String,
    /// Brand snapshot for templates that don't get one from state directly.
    pub brand: BrandConfig,
    /// True when the admin's email is in `[admin].allowed_emails` (Tier 1,
    /// Forseti-wide). False for org-scoped owners who reached an admin page
    /// without being on the operator allowlist — they don't get the
    /// Forseti-wide "Admin" top-nav link.
    pub is_forseti_admin: bool,
}

impl AdminCtx {
    /// Build a [`PageChrome`] from this admin context and a CSRF token.
    /// Used by admin template structs that embed `chrome: PageChrome`
    /// alongside their `admin_active: AdminSection` sibling field.
    pub(crate) fn chrome(&self, csrf: &crate::extractors::Csrf) -> PageChrome {
        PageChrome::from_brand_with_admin(
            self.brand.clone(),
            self.email.clone(),
            csrf.0.clone(),
            self.is_forseti_admin,
        )
    }
}

/// Shared session+AAL2 prefix for both admin entry points. Resolves the
/// Kratos session, pulls the (identity_id, email) principal, and gates on
/// AAL2 — returning all three so the caller can layer on the divergent
/// tail (email allowlist, or org-scope resolution).
async fn gate_admin_prefix(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<(ory::Session, String, String), Response> {
    use crate::extractors::{resolve_session, SessionFailure};
    let cookie = cookies::cookie_header(headers);
    let session = match resolve_session(state, &cookie, path).await {
        Ok(s) => *s,
        Err(SessionFailure::InsufficientAal(r)) | Err(SessionFailure::NoSession(r)) => {
            return Err(r.into_response());
        }
        Err(SessionFailure::KratosError(e)) => {
            tracing::error!(error = ?e, path, "admin gate: whoami failed");
            return Err(render_forbidden(
                state,
                crate::web::AUTH_UNAVAILABLE_TITLE,
                crate::web::AUTH_UNAVAILABLE_BODY,
            ));
        }
    };

    let (identity_id, email) = crate::flow_view::session_principal(&session);

    if !ory::kratos::session_satisfies_aal2(&session) {
        return Err(Redirect::to(&crate::auth::aal2_step_up_url(path)).into_response());
    }

    Ok((session, identity_id, email))
}

/// Like `require_admin` but with the `?org=<slug>` org-scoping convention
/// layered on top. This is the two-tier admin model:
///
/// - **Forseti-wide** (no `?org=`): operator surface. Gated by
///   `[admin].allowed_emails` *plus* session + AAL2. Touches every org and
///   every identity.
/// - **Org-scoped** (`?org=<slug>`): org-owner surface. Gated by org
///   ownership *plus* session + AAL2 — `[admin].allowed_emails` is **not**
///   checked, by design. Org owners need to manage members / branding /
///   invites for their own org without the operator having to allowlist
///   every customer email. Non-Default orgs additionally require the Orgs
///   license; locked → render the upsell page.
///
/// Documented for operators in `docs/operator-guide.md` ("Admin access
/// model"). If you change which tier requires what, update that section.
pub async fn require_admin_with_scope(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    org_slug: Option<&str>,
    csrf_token: &str,
) -> Result<(AdminCtx, crate::orgs::AdminScope), Response> {
    use crate::orgs::{AdminScope, AdminScopeOutcome};
    let (_session, identity_id, email) = gate_admin_prefix(state, headers, path).await?;

    let scope = crate::orgs::resolve_admin_scope(&state.db, &identity_id, org_slug).await;
    let scope = match scope {
        AdminScopeOutcome::Resolved(AdminScope::Forseti) => {
            if !state.cfg.admin.is_admin(&email) {
                return Err(render_forbidden(
                    state,
                    "Access denied",
                    "Your account isn't authorised to use the Forseti-wide admin tools.",
                ));
            }
            AdminScope::Forseti
        }
        AdminScopeOutcome::Resolved(other @ AdminScope::Org { .. }) => {
            // Non-Default orgs need the license. Default org's admin
            // surface stays OSS-tier.
            let org_id_str = other.org_id().unwrap_or("").to_string();
            if org_id_str != crate::orgs::DEFAULT_ORG_ID {
                crate::extractors::gate_orgs_feature_or_upsell(state, csrf_token, &email)?;
            }
            other
        }
        AdminScopeOutcome::UnknownOrg | AdminScopeOutcome::NotOwner => {
            return Err(render_forbidden(
                state,
                "Access denied",
                "You don't have admin access to that organization.",
            ));
        }
    };

    let is_forseti_admin = matches!(scope, AdminScope::Forseti);
    Ok((
        AdminCtx {
            identity_id,
            email,
            brand: state.cfg.brand.clone(),
            is_forseti_admin,
        },
        scope,
    ))
}

/// Gate every admin handler through these checks. On any failure, returns
/// `Err(Response)` carrying the redirect / forbidden page the caller
/// should hand back to axum.
///
/// The `path` argument is the request's pathname (e.g. `/admin/clients`),
/// used as the `return_to` for the `/login` redirects so the user lands
/// straight back on their target after re-authing.
pub async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<AdminCtx, Response> {
    let (_session, identity_id, email) = gate_admin_prefix(state, headers, path).await?;

    if !state.cfg.admin.is_admin(&email) {
        tracing::warn!(
            actor = %email,
            path,
            "admin gate: rejected non-admin"
        );
        return Err(render_forbidden(
            state,
            "Access denied",
            "Your account isn't authorised to use the admin tools.",
        ));
    }

    Ok(AdminCtx {
        identity_id,
        email,
        brand: state.cfg.brand.clone(),
        is_forseti_admin: true,
    })
}

/// Render the admin 403 page. Mirrors `main.rs::render_error_boundary` but
/// scoped to admin — uses the admin base layout so the "Admin" banner is
/// still visible (signals that the user *is* on the admin path, they're
/// just not allowed through).
fn render_forbidden(state: &AppState, title: &str, body: &str) -> Response {
    let tpl = AdminForbiddenTemplate {
        chrome: PageChrome::from_parts(state, String::new(), String::new()),
        title: title.to_string(),
        body: body.to_string(),
    };
    let mut resp = render(&tpl);
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp
}

#[derive(Template)]
#[template(path = "admin/forbidden.html")]
struct AdminForbiddenTemplate {
    chrome: PageChrome,
    title: String,
    body: String,
}

/// Shared confirmation form for destructive POST actions. Every confirm
/// page renders one of these and the action POST handler verifies the
/// CSRF + handles `confirm=yes`.
#[derive(Debug, Deserialize)]
pub struct ConfirmForm {
    #[serde(rename = "_csrf")]
    pub csrf: Option<String>,
    #[serde(default)]
    pub confirm: Option<String>,
}

impl ConfirmForm {
    pub fn confirmed(&self) -> bool {
        matches!(self.confirm.as_deref(), Some("yes"))
    }
}

/// Which admin section the sidebar should highlight. Replaces the
/// previous `admin_active: String` plumbing — handlers pass the variant
/// and the template calls `.as_slug()` to compare against link targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminSection {
    Status,
    Configuration,
    Clients,
    DcrTokens,
    Identities,
    Sessions,
    Audit,
    Webhooks,
    Saml,
    License,
}

impl AdminSection {
    pub(crate) fn as_slug(self) -> &'static str {
        match self {
            AdminSection::Status => "status",
            AdminSection::Configuration => "configuration",
            AdminSection::Clients => "clients",
            AdminSection::DcrTokens => "dcr-tokens",
            AdminSection::Identities => "identities",
            AdminSection::Sessions => "sessions",
            AdminSection::Audit => "audit",
            AdminSection::Webhooks => "webhooks",
            AdminSection::Saml => "saml",
            AdminSection::License => "license",
        }
    }
}

/// Shared destructive-action confirmation page. Used by clients (rotate
/// / delete), identities (disable / delete), sessions (revoke), and DCR
/// tokens (revoke). Every site renders the same HTML; only `title`,
/// `body`, and `submit_label` vary. The submit button is always rendered
/// in the destructive (red) style.
#[derive(askama::Template)]
#[template(path = "admin/confirm.html")]
pub(crate) struct ConfirmTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) admin_active: AdminSection,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) action_url: String,
    pub(crate) cancel_url: String,
    pub(crate) submit_label: &'static str,
}

/// Render a simple error response with a generic admin 500. Used by sub-
/// modules when an upstream call fails irrecoverably. Templates wrap this
/// via the shared `admin/error.html` layout.
pub fn render_admin_error(state: &AppState, title: &str, body: &str) -> Response {
    let tpl = AdminErrorTemplate {
        chrome: PageChrome::from_parts(state, String::new(), String::new()),
        title: title.to_string(),
        body: body.to_string(),
    };
    render(&tpl)
}

#[derive(Template)]
#[template(path = "admin/error.html")]
struct AdminErrorTemplate {
    chrome: PageChrome,
    title: String,
    body: String,
}

/// Append `?org=<slug>` (or `&org=<slug>` if a query string is already
/// present) to `url` when the request is org-scoped, so redirects thread the
/// active scope and an org-scoped admin doesn't bounce out of the surface
/// after a POST. Forseti-wide scope is a no-op.
pub(crate) fn with_org(url: &str, scope: &crate::orgs::AdminScope) -> String {
    let Some(slug) = scope.slug() else {
        return url.to_string();
    };
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}org={}", ory_client::apis::urlencode(slug))
}
