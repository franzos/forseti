//! Admin surface.
//!
//! Mounted under `/admin/*` from `main.rs::main`. Two-tier access model:
//!
//!   - [`require_admin`]: Tier 1, Forseti-wide. Session + AAL2 +
//!     `config.admin.allowed_emails`.
//!   - [`require_admin_with_scope`]: Tier 1 or Tier 2 routed by `?org=<slug>`.
//!     Tier 2 is session + AAL2 + org ownership (no allowlist check). See
//!     `docs/operator-guide.md` ("Admin access model") for the rationale.
//!
//! Tier 1 uses a config allowlist rather than a role on the identity so
//! operator membership stays declarative in `config.toml` and avoids a custom
//! trait in the Kratos schema; the cost is a config reload to change it.

use askama::Template;
use axum::{
    http::{request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;

use crate::audit::{AuditCtx, AuditEvent};
use crate::config::BrandConfig;
use crate::locale::LanguageIdentifier;
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
pub mod hosts;
pub mod identities;
pub mod posix;
pub mod saml;
pub mod sessions;
pub mod status;
pub mod webhooks;

/// Build the admin sub-router. Routes are path-prefixed `/admin/...` directly
/// (not nested) so `require_admin` sees the full request path for redirects.
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
        .route("/admin/identity-picker", get(identities::pick))
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
        // Audit
        .route("/admin/audit", get(audit::show))
        .route("/admin/audit/{id}", get(audit::show_one))
        // Webhooks
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
        // DCR initial access tokens
        .route("/admin/dcr-tokens", get(dcr_tokens::list))
        .route(
            "/admin/dcr-tokens/new",
            get(dcr_tokens::new).post(dcr_tokens::issue),
        )
        .route(
            "/admin/dcr-tokens/{id}/revoke",
            get(dcr_tokens::revoke_confirm).post(dcr_tokens::revoke),
        )
        // Linux host enrollment
        .route("/admin/hosts", get(hosts::list))
        .route("/admin/hosts/new", get(hosts::new).post(hosts::issue))
        .route(
            "/admin/hosts/{id}/edit",
            get(hosts::edit).post(hosts::update),
        )
        .route(
            "/admin/hosts/{id}/revoke",
            get(hosts::revoke_confirm).post(hosts::revoke),
        )
        .route(
            "/admin/hosts/{id}/rotate",
            get(hosts::rotate_confirm).post(hosts::rotate),
        )
        // POSIX accounts
        .route("/admin/posix", get(posix::list))
        .route("/admin/posix/new", get(posix::new).post(posix::provision))
        .route("/admin/posix/{id}", get(posix::account))
        .route("/admin/posix/{id}/keys", post(posix::add_key))
        .route(
            "/admin/posix/{id}/keys/{key_id}/delete",
            post(posix::remove_key),
        )
        .route("/admin/posix/{id}/disable", post(posix::disable))
        .route("/admin/posix/{id}/enable", post(posix::enable))
        .route(
            "/admin/posix/{id}/delete",
            get(posix::delete_confirm).post(posix::delete),
        )
        // License (commercial); handlers self-gate via RequireAdmin like the rest.
        .merge(crate::commercial::settings_page::router())
}

/// `/admin` → `/admin/status`. Saves operators a click on the bookmark.
async fn redirect_to_status() -> Response {
    Redirect::to("/admin/status").into_response()
}

/// Successful outcome of the admin auth gate.
pub struct AdminCtx {
    /// Admin's Kratos identity id; used as `actor_id` in audit logs.
    pub identity_id: String,
    /// Admin's session email; used as `actor_email` in audit logs.
    pub email: String,
    /// Brand snapshot for templates that don't get one from state directly.
    pub brand: BrandConfig,
    /// True when the email is in `[admin].allowed_emails` (Tier 1). False for
    /// org-scoped owners, who don't get the Forseti-wide "Admin" top-nav link.
    pub is_forseti_admin: bool,
    /// Negotiated request locale, resolved once by [`admin_success_locale`]
    /// after the auth gate passes.
    pub locale: LanguageIdentifier,
    /// Precomputed licensee watermark ("<customer> · <email>", or `None` when
    /// unlicensed), captured at gate time while `&AppState` is in scope so the
    /// stateless [`AdminCtx::chrome`] path can surface it on every admin page.
    pub(crate) license_watermark: Option<String>,
}

impl AdminCtx {
    /// Build a [`PageChrome`] from this admin context and a CSRF token.
    pub(crate) fn chrome(&self, csrf: &crate::extractors::Csrf) -> PageChrome {
        let mut chrome = PageChrome::from_brand_with_admin(
            self.brand.clone(),
            self.email.clone(),
            csrf.0.clone(),
            self.is_forseti_admin,
            self.locale.clone(),
        );
        chrome.license_watermark = self.license_watermark.clone();
        chrome
    }

    /// Open an audit event already attributed to this admin and stamped with
    /// the request context. Callers chain `.target(...)`, optional
    /// `.metadata(...)` / `.critical()`, then `audit::log`.
    pub(crate) fn audit_event(&self, action: &'static str, ctx: &AuditCtx) -> AuditEvent {
        AuditEvent::new(action)
            .actor_admin(&self.identity_id, &self.email)
            .with_ctx(ctx)
    }
}

/// Shared session+AAL2 prefix for both admin entry points. Returns the session
/// plus (identity_id, email) so the caller can layer on the divergent tail
/// (email allowlist, or org-scope resolution). Takes request `Parts` so the
/// middleware-cached whoami is reused instead of a second Kratos round-trip.
async fn gate_admin_prefix(
    state: &AppState,
    parts: &mut Parts,
    path: &str,
) -> Result<(ory::Session, String, String), Response> {
    use crate::extractors::{resolve_session_from_parts, SessionFailure};
    let session = match resolve_session_from_parts(state, parts, path).await {
        Ok(s) => *s,
        Err(SessionFailure::InsufficientAal(r)) | Err(SessionFailure::NoSession(r)) => {
            return Err(r.into_response());
        }
        Err(SessionFailure::KratosError(e)) => {
            tracing::error!(error = ?e, path, "admin gate: whoami failed");
            let locale = admin_gate_locale(&parts.headers);
            return Err(render_forbidden(
                state,
                &locale,
                &crate::i18n::lookup(&locale, "error-boundary-auth-unavailable-title"),
                &crate::i18n::lookup(&locale, "error-boundary-auth-unavailable-body"),
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
///   `[admin].allowed_emails` plus session + AAL2. Touches every org.
/// - **Org-scoped** (`?org=<slug>`): org-owner surface. Gated by org ownership
///   plus session + AAL2; `[admin].allowed_emails` is **not** checked, so
///   owners manage their own org without the operator allowlisting every
///   customer email. Non-Default orgs additionally require the Orgs license.
///
/// Documented for operators in `docs/operator-guide.md` ("Admin access
/// model"). If you change which tier requires what, update that section.
pub async fn require_admin_with_scope(
    state: &AppState,
    parts: &mut Parts,
    path: &str,
    org_slug: Option<&str>,
    csrf_token: &str,
) -> Result<(AdminCtx, crate::orgs::AdminScope), Response> {
    use crate::orgs::{AdminScope, AdminScopeOutcome};
    let (session, identity_id, email) = gate_admin_prefix(state, parts, path).await?;

    let scope = crate::orgs::resolve_admin_scope(&state.db, &identity_id, org_slug).await;
    let scope = match scope {
        AdminScopeOutcome::Resolved(AdminScope::Forseti) => {
            if !state.cfg.admin.is_admin(&email) {
                let locale = admin_gate_locale(&parts.headers);
                return Err(render_forbidden(
                    state,
                    &locale,
                    &crate::i18n::lookup(&locale, "error-admin-access-denied-title"),
                    &crate::i18n::lookup(&locale, "error-admin-access-denied-forseti-body"),
                ));
            }
            AdminScope::Forseti
        }
        AdminScopeOutcome::Resolved(other @ AdminScope::Org { .. }) => {
            // Non-Default orgs need the license; the Default org stays OSS-tier.
            let org_id_str = other.org_id().unwrap_or("").to_string();
            if org_id_str != crate::orgs::DEFAULT_ORG_ID {
                crate::extractors::gate_orgs_feature_or_upsell(state, csrf_token, &email)?;
            }
            other
        }
        AdminScopeOutcome::UnknownOrg | AdminScopeOutcome::NotOwner => {
            let locale = admin_gate_locale(&parts.headers);
            return Err(render_forbidden(
                state,
                &locale,
                &crate::i18n::lookup(&locale, "error-admin-access-denied-title"),
                &crate::i18n::lookup(&locale, "error-admin-access-denied-org-body"),
            ));
        }
    };

    let is_forseti_admin = matches!(scope, AdminScope::Forseti);
    let locale = admin_success_locale(parts, session, &identity_id, &email);
    Ok((
        AdminCtx {
            identity_id,
            email,
            brand: state.cfg.brand.clone(),
            is_forseti_admin,
            locale,
            license_watermark: crate::page_chrome::license_watermark(state),
        },
        scope,
    ))
}

/// Tier 1 admin gate. On failure returns the redirect / forbidden page to hand
/// back to axum. `path` is used as `return_to` so a `/login` redirect lands
/// back on the target after re-authing.
pub async fn require_admin(
    state: &AppState,
    parts: &mut Parts,
    path: &str,
) -> Result<AdminCtx, Response> {
    let (session, identity_id, email) = gate_admin_prefix(state, parts, path).await?;

    if !state.cfg.admin.is_admin(&email) {
        tracing::warn!(
            actor = %email,
            path,
            "admin gate: rejected non-admin"
        );
        let locale = admin_gate_locale(&parts.headers);
        return Err(render_forbidden(
            state,
            &locale,
            &crate::i18n::lookup(&locale, "error-admin-access-denied-title"),
            &crate::i18n::lookup(&locale, "error-admin-access-denied-body"),
        ));
    }

    let locale = admin_success_locale(parts, session, &identity_id, &email);
    Ok(AdminCtx {
        identity_id,
        email,
        brand: state.cfg.brand.clone(),
        is_forseti_admin: true,
        locale,
        license_watermark: crate::page_chrome::license_watermark(state),
    })
}

/// Render the admin 403 page using the admin base layout so the "Admin" banner
/// stays visible (the user is on the admin path, just not allowed through).
/// Best-effort locale for the admin gate's error/forbidden pages, which run
/// before any handler and have no request `Parts`. Cookie then Accept-Language;
/// `?lang=` and the session trait aren't consulted here.
fn admin_gate_locale(headers: &HeaderMap) -> crate::locale::LanguageIdentifier {
    crate::locale::read_locale_cookie(headers).unwrap_or_else(|| {
        let accept = headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok());
        crate::locale::from_accept_language(accept)
    })
}

/// Success-path locale for the admin surfaces, resolved once per request with
/// the same ladder as the page extractors: `?lang=` query, then the
/// `forseti_locale` cookie, then the `preferred_language` identity trait (off
/// the already resolved session, no extra Kratos call), then `Accept-Language`,
/// then `en`.
fn admin_success_locale(
    parts: &Parts,
    session: ory::Session,
    identity_id: &str,
    email: &str,
) -> LanguageIdentifier {
    let session = crate::extractors::OptionalSession::Ok {
        session: Box::new(session),
        identity_id: identity_id.to_string(),
        email: email.to_string(),
    };
    crate::page_chrome::resolve_locale(parts, &session)
}

fn render_forbidden(
    state: &AppState,
    locale: &crate::locale::LanguageIdentifier,
    title: &str,
    body: &str,
) -> Response {
    let tpl = AdminForbiddenTemplate {
        chrome: PageChrome::from_parts(state, String::new(), String::new(), locale.clone()),
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

/// Shared confirmation form for destructive POST actions.
#[derive(Debug, Deserialize)]
pub struct ConfirmForm {
    #[serde(default)]
    pub confirm: Option<String>,
}

impl ConfirmForm {
    pub fn confirmed(&self) -> bool {
        matches!(self.confirm.as_deref(), Some("yes"))
    }

    /// Bounce back to `redirect_to` when the form wasn't confirmed. Returns
    /// `Some(redirect)` to early-return, `None` to proceed with the action.
    pub fn bounce_unless_confirmed(&self, redirect_to: &str) -> Option<Response> {
        if self.confirmed() {
            None
        } else {
            Some(Redirect::to(redirect_to).into_response())
        }
    }
}

/// Which admin section the sidebar should highlight; the template calls
/// `.as_slug()` to compare against link targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminSection {
    Status,
    Configuration,
    Clients,
    DcrTokens,
    Hosts,
    Posix,
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
            AdminSection::Hosts => "hosts",
            AdminSection::Posix => "posix",
            AdminSection::Identities => "identities",
            AdminSection::Sessions => "sessions",
            AdminSection::Audit => "audit",
            AdminSection::Webhooks => "webhooks",
            AdminSection::Saml => "saml",
            AdminSection::License => "license",
        }
    }
}

/// Shared destructive-action confirmation page; only `title`, `body`, and
/// `submit_label` vary. The submit button is always destructive (red).
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

/// Render a generic admin error page for an irrecoverable upstream failure.
pub fn render_admin_error(state: &AppState, title: &str, body: &str) -> Response {
    let tpl = AdminErrorTemplate {
        // called from error paths throughout admin handlers without Parts; locale is inert here
        chrome: PageChrome::from_parts(
            state,
            String::new(),
            String::new(),
            crate::locale::default_locale(),
        ),
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

/// Append `?org=<slug>` to `url` when org-scoped, so redirects thread the
/// active scope and don't bounce an org-scoped admin out after a POST.
/// Forseti-wide scope is a no-op.
pub(crate) fn with_org(url: &str, scope: &crate::orgs::AdminScope) -> String {
    let Some(slug) = scope.slug() else {
        return url.to_string();
    };
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}org={}", ory_client::apis::urlencode(slug))
}
