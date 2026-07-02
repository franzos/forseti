//! `/admin/saml/*`: operator-managed SAML connections (commercial).
//!
//! IdP metadata and certificates live in Jackson; Forseti keeps the anchor row
//! (org-to-connection, enabled flag, display name) and drives Jackson's admin
//! API for create/delete. Forseti-tier only: connections cross org boundaries.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::admin::{render_admin_error, AdminCtx, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx};
use crate::audit_metadata;
use crate::commercial::license::{Feature, FeatureStatus};
use crate::commercial::upsell::render_upsell;
use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, RequireAdmin};
use crate::orgs;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::saml::{db, flow::http_client, jackson};
use crate::state::AppState;

struct ConnectionRow {
    org_id: String,
    org_name: String,
    display_name: String,
    enabled: bool,
    sso_url: String,
}

struct OrgOption {
    id: String,
    name: String,
    slug: String,
}

#[derive(askama::Template)]
#[template(path = "admin/saml_list.html")]
struct SamlListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    /// False when `[saml]` is absent from config; shows a guidance card.
    configured: bool,
    grace: bool,
    rows: Vec<ConnectionRow>,
    acs_url: String,
    entity_id: String,
}

#[derive(askama::Template)]
#[template(path = "admin/saml_new.html")]
struct SamlNewTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    error_message: String,
    orgs: Vec<OrgOption>,
    /// Echo the operator's input back so a validation failure doesn't
    /// wipe what they typed.
    org_id: String,
    display_name: String,
    metadata_url: String,
    metadata_xml: String,
}

/// Locked → upsell page; GraceReadOnly → `Ok(true)`; Allowed → `Ok(false)`.
#[allow(clippy::result_large_err)] // house pattern for sync Response-error gates
fn gate(state: &AppState, csrf: &Csrf, email: &str) -> Result<bool, Response> {
    match state.license.feature(Feature::Saml) {
        // no request context here; upsell locale is inert
        FeatureStatus::Locked => Err(render_upsell(
            state,
            &csrf.0,
            email,
            Feature::Saml,
            crate::locale::default_locale(),
        )),
        FeatureStatus::GraceReadOnly => Ok(true),
        FeatureStatus::Allowed => Ok(false),
    }
}

fn grace_read_only(state: &AppState) -> Response {
    render_admin_error(
        state,
        "Read-only",
        "License in grace period — SAML connections are read-only.",
    )
}

async fn load_org_options(state: &AppState) -> Result<Vec<OrgOption>, Response> {
    match orgs::db::list_orgs(&state.db).await {
        Ok(rows) => Ok(rows
            .into_iter()
            .map(|o| OrgOption {
                id: o.id,
                name: o.name,
                slug: o.slug,
            })
            .collect()),
        Err(e) => {
            tracing::error!(error = ?e, "admin/saml: list_orgs failed");
            Err(render_admin_error(
                state,
                "Organizations unavailable",
                "We couldn't list organizations. Please try again in a moment.",
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)] // form echo fields, not state
async fn render_new_page(
    state: &AppState,
    ctx: &AdminCtx,
    csrf: &Csrf,
    error_message: String,
    org_id: &str,
    display_name: &str,
    metadata_url: &str,
    metadata_xml: &str,
) -> Response {
    let orgs = match load_org_options(state).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    render(&SamlNewTemplate {
        chrome: ctx.chrome(csrf),
        admin_active: AdminSection::Saml,
        error_message,
        orgs,
        org_id: org_id.to_string(),
        display_name: display_name.to_string(),
        metadata_url: metadata_url.to_string(),
        metadata_xml: metadata_xml.to_string(),
    })
}

pub async fn list(State(state): State<AppState>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let grace = match gate(&state, &csrf, &ctx.email) {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let Some(cfg) = state.cfg.saml.as_ref() else {
        return render(&SamlListTemplate {
            chrome: ctx.chrome(&csrf),
            admin_active: AdminSection::Saml,
            configured: false,
            grace,
            rows: Vec::new(),
            acs_url: String::new(),
            entity_id: String::new(),
        });
    };

    let connections = match db::list_connections(&state.db).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "admin/saml: list_connections failed");
            return render_admin_error(
                &state,
                "SAML connections unavailable",
                "We couldn't list SAML connections. Please try again in a moment.",
            );
        }
    };

    let self_url = state.cfg.self_.url.trim_end_matches('/').to_string();
    let mut rows = Vec::with_capacity(connections.len());
    for c in connections {
        // Small N (one connection per org), so per-row lookups are fine.
        let (org_name, org_slug) = match orgs::db::org_by_id(&state.db, &c.org_id).await {
            Ok(Some(org)) => (org.name, org.slug),
            // Orphaned anchor row: show the raw id so the operator can clean up.
            Ok(None) => (c.org_id.clone(), String::new()),
            Err(e) => {
                tracing::error!(error = ?e, org_id = %c.org_id, "admin/saml: org lookup failed");
                return render_admin_error(
                    &state,
                    "SAML connections unavailable",
                    "We couldn't resolve an organization for a connection. Please try again in a moment.",
                );
            }
        };
        let sso_url = if org_slug.is_empty() {
            String::new()
        } else {
            format!("{self_url}/sso/{org_slug}")
        };
        rows.push(ConnectionRow {
            enabled: c.is_enabled(),
            org_id: c.org_id,
            org_name,
            display_name: c.display_name,
            sso_url,
        });
    }

    render(&SamlListTemplate {
        chrome: ctx.chrome(&csrf),
        admin_active: AdminSection::Saml,
        configured: true,
        grace,
        rows,
        acs_url: format!("{}/api/oauth/saml", cfg.jackson_url.trim_end_matches('/')),
        entity_id: cfg.sp_entity_id().to_string(),
    })
}

pub async fn new(State(state): State<AppState>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    if let Err(resp) = gate(&state, &csrf, &ctx.email) {
        return resp;
    }
    if state.cfg.saml.is_none() {
        return Redirect::to("/admin/saml").into_response();
    }
    render_new_page(&state, &ctx, &csrf, String::new(), "", "", "", "").await
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    org_id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    metadata_url: String,
    #[serde(default)]
    metadata_xml: String,
}

pub async fn create(
    State(state): State<AppState>,
    actx: AuditCtx,
    admin: RequireAdmin,
    csrf: Csrf,
    CsrfForm(form): CsrfForm<CreateForm>,
) -> Response {
    let ctx = admin.ctx;
    match gate(&state, &csrf, &ctx.email) {
        Ok(false) => {}
        Ok(true) => return grace_read_only(&state),
        Err(resp) => return resp,
    }
    let Some(cfg) = state.cfg.saml.as_ref() else {
        return Redirect::to("/admin/saml").into_response();
    };

    let org_id = form.org_id.trim().to_string();
    let display_name = form.display_name.trim().to_string();
    let metadata_url = form.metadata_url.trim().to_string();
    let metadata_xml = form.metadata_xml.trim().to_string();

    // async render_new_page can't be awaited from a closure, hence the macro.
    macro_rules! rerender {
        ($msg:expr) => {
            return render_new_page(
                &state,
                &ctx,
                &csrf,
                $msg.to_string(),
                &org_id,
                &display_name,
                &metadata_url,
                &metadata_xml,
            )
            .await
        };
    }

    if display_name.is_empty() {
        rerender!("Connection name is required.");
    }
    if metadata_url.is_empty() == metadata_xml.is_empty() {
        rerender!("Provide exactly one of metadata URL or metadata XML.");
    }
    match orgs::db::org_by_id(&state.db, &org_id).await {
        Ok(Some(_)) => {}
        Ok(None) => rerender!("That organization doesn't exist."),
        Err(e) => {
            tracing::error!(error = ?e, "admin/saml: org lookup failed");
            return render_admin_error(
                &state,
                "Create failed",
                "We couldn't verify the organization. Please try again in a moment.",
            );
        }
    }
    match db::get_connection(&state.db, &org_id).await {
        Ok(None) => {}
        Ok(Some(_)) => rerender!("That organization already has a connection."),
        Err(e) => {
            tracing::error!(error = ?e, "admin/saml: connection lookup failed");
            return render_admin_error(
                &state,
                "Create failed",
                "We couldn't check for an existing connection. Please try again in a moment.",
            );
        }
    }

    let (metadata, source) = if metadata_url.is_empty() {
        (jackson::MetadataInput::RawXml(metadata_xml.clone()), "xml")
    } else {
        (jackson::MetadataInput::Url(metadata_url.clone()), "url")
    };
    if let Err(e) = jackson::create_connection(
        cfg,
        http_client(),
        &state.cfg.self_.url,
        &org_id,
        &display_name,
        metadata,
    )
    .await
    {
        tracing::error!(error = ?e, org_id, "admin/saml: jackson create_connection failed");
        rerender!(format!("Jackson rejected the connection: {e}"));
    }

    if let Err(e) = db::insert_connection(&state.db, &org_id, &display_name, &ctx.identity_id).await
    {
        if matches!(
            e.downcast_ref::<diesel::result::Error>(),
            Some(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _
            ))
        ) {
            rerender!("That organization already has a SAML connection.");
        }
        tracing::error!(error = ?e, org_id, "admin/saml: insert_connection failed");
        return render_admin_error(
            &state,
            "Create failed",
            "The Jackson connection was created but the local record couldn't be written. \
             Delete the connection from this page after a refresh, or retry the create.",
        );
    }

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_SAML_CONNECTION_CREATED, &actx)
            .target(target_kind::SAML_CONNECTION, org_id.clone())
            .metadata(audit_metadata!(
                "org_id" => org_id.as_str(),
                "metadata_source" => source,
            )),
    )
    .await;

    Redirect::to("/admin/saml").into_response()
}

pub async fn toggle(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    actx: AuditCtx,
    admin: RequireAdmin,
    csrf: Csrf,
    _: CsrfForm<ConfirmForm>,
) -> Response {
    let ctx = admin.ctx;
    match gate(&state, &csrf, &ctx.email) {
        Ok(false) => {}
        Ok(true) => return grace_read_only(&state),
        Err(resp) => return resp,
    }
    if state.cfg.saml.is_none() {
        return Redirect::to("/admin/saml").into_response();
    }

    let conn = match db::get_connection(&state.db, &org_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return render_admin_error(
                &state,
                "Not found",
                "That SAML connection no longer exists.",
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, org_id, "admin/saml: connection lookup failed");
            return render_admin_error(
                &state,
                "Toggle failed",
                "We couldn't load that connection. Please try again in a moment.",
            );
        }
    };
    let enabled = !conn.is_enabled();
    if let Err(e) = db::set_enabled(&state.db, &org_id, enabled).await {
        tracing::error!(error = ?e, org_id, "admin/saml: set_enabled failed");
        return render_admin_error(
            &state,
            "Toggle failed",
            "We couldn't update that connection. Please try again in a moment.",
        );
    }

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_SAML_CONNECTION_TOGGLED, &actx)
            .target(target_kind::SAML_CONNECTION, org_id.clone())
            .metadata(audit_metadata!("enabled" => enabled)),
    )
    .await;

    Redirect::to("/admin/saml").into_response()
}

pub async fn delete_confirm(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    admin: RequireAdmin,
    csrf: Csrf,
) -> Response {
    let ctx = admin.ctx;
    if let Err(resp) = gate(&state, &csrf, &ctx.email) {
        return resp;
    }

    let conn = match db::get_connection(&state.db, &org_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return render_admin_error(
                &state,
                "Not found",
                "That SAML connection no longer exists.",
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, org_id, "admin/saml: connection lookup failed");
            return render_admin_error(
                &state,
                "SAML connections unavailable",
                "We couldn't load that connection. Please try again in a moment.",
            );
        }
    };
    let org_name = match orgs::db::org_by_id(&state.db, &org_id).await {
        Ok(Some(org)) => org.name,
        Ok(None) => org_id.clone(),
        Err(e) => {
            tracing::warn!(error = ?e, org_id, "admin/saml: org lookup failed in delete_confirm, falling back to raw id");
            org_id.clone()
        }
    };

    render(&ConfirmTemplate {
        chrome: ctx.chrome(&csrf),
        admin_active: AdminSection::Saml,
        title: "Delete SAML connection".to_string(),
        body: format!(
            "This removes \"{}\" for {org_name}. Members of that organization lose SSO sign-in \
             immediately, and the connection (IdP metadata included) is deleted from Jackson.",
            conn.display_name
        ),
        action_url: format!(
            "/admin/saml/{}/delete",
            ory_client::apis::urlencode(&org_id)
        ),
        cancel_url: "/admin/saml".to_string(),
        submit_label: "Delete connection",
    })
}

pub async fn delete(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    actx: AuditCtx,
    admin: RequireAdmin,
    csrf: Csrf,
    CsrfForm(form): CsrfForm<ConfirmForm>,
) -> Response {
    let ctx = admin.ctx;
    if let Some(r) = form.bounce_unless_confirmed("/admin/saml") {
        return r;
    }
    match gate(&state, &csrf, &ctx.email) {
        Ok(false) => {}
        Ok(true) => return grace_read_only(&state),
        Err(resp) => return resp,
    }
    let Some(cfg) = state.cfg.saml.as_ref() else {
        return Redirect::to("/admin/saml").into_response();
    };

    // Jackson first: a Forseti-only delete would orphan the Jackson connection
    // and keep the IdP round-trip alive.
    if let Err(e) = jackson::delete_connection(cfg, http_client(), &org_id).await {
        tracing::error!(error = ?e, org_id, "admin/saml: jackson delete_connection failed");
        return render_admin_error(
            &state,
            "Delete failed",
            &format!("Jackson refused to delete the connection: {e}. Nothing was changed locally."),
        );
    }
    if let Err(e) = db::delete_connection(&state.db, &org_id).await {
        tracing::error!(error = ?e, org_id, "admin/saml: delete_connection failed");
        return render_admin_error(
            &state,
            "Delete failed",
            "The Jackson connection was removed but the local record couldn't be deleted. \
             Retry the delete.",
        );
    }

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_SAML_CONNECTION_DELETED, &actx)
            .target(target_kind::SAML_CONNECTION, org_id.clone())
            .metadata(audit_metadata!("org_id" => org_id.as_str()))
            .critical(),
    )
    .await;

    Redirect::to("/admin/saml").into_response()
}
