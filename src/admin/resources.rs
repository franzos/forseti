//! `/admin/resources/*`: the resource registry (RFC 8707 audiences).
//!
//! Rows here are the consent-time audience allow-list
//! (`resource_registry::list_enabled` feeds `resolve_granted_audience`'s
//! `allowed` arm). Org-scoped like `/admin/clients`: a Forseti admin touches
//! any row and picks the target org at create time; an org-scoped admin
//! (`?org=<slug>`) sees only rows stamped with their org and may only create
//! resources whose host is a verified domain of that org (fail closed).
//!
//! Corroboration is the advisory RFC 9728 check (create + re-check button):
//! fetch `{resource-origin}/.well-known/oauth-protected-resource{path}`
//! through the same SSRF composition as the CIMD fetcher and compare the
//! document's `resource` + `authorization_servers` against the row and the
//! configured issuer. A badge, never a gate.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use url::Url;

use crate::admin::{
    AdminCtx, AdminSection, ConfirmForm, ConfirmTemplate, render_admin_error, with_org,
};
use crate::audit::{self, AuditCtx, action, target_kind};
use crate::audit_metadata;
use crate::csrf::{CsrfForm, NoPayload};
use crate::extractors::{Csrf, RequireAdminScoped};
use crate::format::humanise_timestamp;
use crate::orgs::AdminScope;
use crate::page_chrome::PageChrome;
use crate::protected_resource;
use crate::render::render;
use crate::resource_registry::{self, ClaimConflict, NewResource, SelfService, corroboration};
use crate::state::AppState;

/// One row on the list page; URLs are precomputed so the template doesn't
/// re-implement the `?org=` threading.
struct ResourceRow {
    resource: String,
    display_name: String,
    org_name: String,
    enabled: bool,
    corroboration: String,
    corroborated_at: String,
    created_at: String,
    created_at_pretty: String,
    created_by: String,
    /// Non-URI verbatim identifiers have nothing to fetch; hide the button.
    can_recheck: bool,
    /// Space-separated `metadata_admin` keys copied into the access token.
    access_token_claims: String,
    /// Empty when self-service is off.
    self_service_claim: String,
    /// Empty for org-scoped admins, who can't edit claims.
    claims_url: String,
    toggle_url: String,
    recheck_url: String,
    delete_url: String,
}

struct OrgOption {
    id: String,
    name: String,
    slug: String,
}

#[derive(askama::Template)]
#[template(path = "admin/resources_list.html")]
struct ResourcesListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<ResourceRow>,
    new_url: String,
}

#[derive(askama::Template)]
#[template(path = "admin/resource_new.html")]
struct ResourceNewTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    /// Inline error from the previous submission, if any.
    error_message: String,
    /// Echo the operator's input back so a validation failure doesn't
    /// wipe what they typed.
    resource: String,
    display_name: String,
    org_id: String,
    access_token_claims: String,
    /// Org selector options; empty (and unused) for org-scoped admins.
    orgs: Vec<OrgOption>,
    /// True for an org-scoped admin: no selector, pinned to their org.
    scoped: bool,
    scoped_org_name: String,
    form_action: String,
    cancel_url: String,
}

pub async fn list(
    State(state): State<AppState>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let mut rows = match resource_registry::list_all(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "admin: list resources failed");
            return render_admin_error(
                &state,
                "Resources unavailable",
                "We couldn't list registered resources. Please try again in a moment.",
            );
        }
    };
    // Org-scoped callers see only rows stamped with their org.
    if let AdminScope::Org { id: org_id, .. } = &scope {
        rows.retain(|r| &r.org_id == org_id);
    }

    let org_names: std::collections::HashMap<String, String> =
        match crate::orgs::db::list_orgs(&state.db).await {
            Ok(orgs) => orgs.into_iter().map(|o| (o.id, o.name)).collect(),
            Err(e) => {
                tracing::warn!(error = ?e, "admin: org name lookup for resource list failed");
                std::collections::HashMap::new()
            }
        };

    // Display only; DB timestamps go through crate::db::rfc3339.
    #[allow(clippy::disallowed_methods)]
    let rows = rows
        .into_iter()
        .map(|r| {
            let created_at = r.created_at.and_utc().to_rfc3339();
            ResourceRow {
                org_name: org_names.get(&r.org_id).cloned().unwrap_or(r.org_id),
                corroborated_at: r
                    .corroborated_at
                    .map(|t| t.and_utc().to_rfc3339())
                    .unwrap_or_default(),
                created_at_pretty: humanise_timestamp(&ctx.locale, &created_at),
                created_at,
                created_by: r.created_by.unwrap_or_default(),
                can_recheck: protected_resource::has_fetchable_host(&r.resource),
                claims_url: match scope {
                    AdminScope::Forseti => format!("/admin/resources/{}/claims", r.id),
                    AdminScope::Org { .. } => String::new(),
                },
                access_token_claims: r.access_token_claims.clone(),
                self_service_claim: r.self_service_claim.clone(),
                toggle_url: with_org(&format!("/admin/resources/{}/toggle", r.id), &scope),
                recheck_url: with_org(&format!("/admin/resources/{}/recheck", r.id), &scope),
                delete_url: with_org(&format!("/admin/resources/{}/delete", r.id), &scope),
                resource: r.resource,
                display_name: r.display_name,
                enabled: r.enabled,
                corroboration: r.corroboration,
            }
        })
        .collect();

    render(&ResourcesListTemplate {
        chrome: ctx.chrome(&csrf),
        admin_active: AdminSection::Resources,
        rows,
        new_url: with_org("/admin/resources/new", &scope),
    })
}

async fn load_org_options(state: &AppState) -> Result<Vec<OrgOption>, Response> {
    match crate::orgs::db::list_orgs(&state.db).await {
        Ok(rows) => Ok(rows
            .into_iter()
            .map(|o| OrgOption {
                id: o.id,
                name: o.name,
                slug: o.slug,
            })
            .collect()),
        Err(e) => {
            tracing::error!(error = ?e, "admin/resources: list_orgs failed");
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
    scope: &AdminScope,
    csrf: &Csrf,
    error_message: String,
    resource: &str,
    display_name: &str,
    org_id: &str,
    access_token_claims: &str,
) -> Response {
    let (orgs, scoped_org_name) = match scope {
        AdminScope::Org { id, .. } => {
            let name = match crate::orgs::db::org_by_id(&state.db, id).await {
                Ok(Some(org)) => org.name,
                _ => id.clone(),
            };
            (Vec::new(), name)
        }
        AdminScope::Forseti => match load_org_options(state).await {
            Ok(o) => (o, String::new()),
            Err(resp) => return resp,
        },
    };
    render(&ResourceNewTemplate {
        chrome: ctx.chrome(csrf),
        admin_active: AdminSection::Resources,
        error_message,
        resource: resource.to_string(),
        display_name: display_name.to_string(),
        org_id: org_id.to_string(),
        access_token_claims: access_token_claims.to_string(),
        orgs,
        scoped: matches!(scope, AdminScope::Org { .. }),
        scoped_org_name,
        form_action: with_org("/admin/resources/new", scope),
        cancel_url: with_org("/admin/resources", scope),
    })
}

pub async fn new(State(state): State<AppState>, admin: RequireAdminScoped, csrf: Csrf) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    render_new_page(&state, &ctx, &scope, &csrf, String::new(), "", "", "", "").await
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    resource: String,
    #[serde(default)]
    display_name: String,
    /// Only honored for Forseti-wide admins; org-scoped admins are pinned.
    #[serde(default)]
    org_id: String,
    /// Forseti-wide admins only: an org admin could otherwise route any
    /// user's operator-written metadata to their own resource server.
    #[serde(default)]
    access_token_claims: String,
}

pub async fn create(
    State(state): State<AppState>,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    csrf: Csrf,
    CsrfForm(form): CsrfForm<CreateForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let raw_resource = form.resource.trim().to_string();
    let display_name = form.display_name.trim().to_string();
    let form_org = form.org_id.trim().to_string();
    let raw_claims = form.access_token_claims.trim().to_string();

    // async render_new_page can't be awaited from a closure, hence the macro.
    macro_rules! rerender {
        ($msg:expr_2021) => {
            return render_new_page(
                &state,
                &ctx,
                &scope,
                &csrf,
                $msg.to_string(),
                &raw_resource,
                &display_name,
                &form_org,
                &raw_claims,
            )
            .await
        };
    }

    if raw_resource.is_empty() {
        rerender!("Resource is required.");
    }
    if matches!(scope, AdminScope::Org { .. }) && !raw_claims.is_empty() {
        rerender!("Only Forseti administrators can set access-token claims.");
    }
    let claims = match resource_registry::parse_access_token_claims(&raw_claims) {
        Ok(c) => c,
        Err(msg) => rerender!(msg),
    };
    // Dual matching, mirroring the consent resolver: canonicalizable URIs are
    // stored canonical, anything else is a verbatim opaque identifier.
    let stored =
        crate::oauth::canonical_resource(&raw_resource).unwrap_or_else(|| raw_resource.clone());
    if stored.chars().any(char::is_whitespace) {
        rerender!("Resource must be a single URI or identifier without whitespace.");
    }

    let org_id = match &scope {
        AdminScope::Org { id, .. } => {
            // Fail closed: org-scoped admins may only register resources whose
            // host is a verified domain of their org.
            let Some(host) = Url::parse(&stored)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
            else {
                rerender!(
                    "Organization admins can only register resources with a URI host \
                     on a verified domain of their organization."
                );
            };
            match crate::orgs::domains::get_domain(&state.db, id, &host).await {
                Ok(Some(d)) if d.verified_at.is_some() => {}
                Ok(_) => {
                    rerender!(format!(
                        "\"{host}\" is not a verified domain of your organization. \
                         Verify the domain first under organization settings."
                    ));
                }
                Err(e) => {
                    tracing::error!(error = ?e, host, "admin/resources: verified-domain lookup failed");
                    rerender!("We couldn't verify domain ownership. Please try again in a moment.");
                }
            }
            id.clone()
        }
        AdminScope::Forseti => {
            let target = if form_org.is_empty() {
                crate::orgs::DEFAULT_ORG_ID.to_string()
            } else {
                form_org.clone()
            };
            match crate::orgs::db::org_by_id(&state.db, &target).await {
                Ok(Some(_)) => target,
                Ok(None) => rerender!("That organization doesn't exist."),
                Err(e) => {
                    tracing::error!(error = ?e, "admin/resources: org lookup failed");
                    return render_admin_error(
                        &state,
                        "Create failed",
                        "We couldn't verify the organization. Please try again in a moment.",
                    );
                }
            }
        }
    };

    // The macro captures `display_name` for the re-render echo, so the
    // defaulted value gets its own binding.
    let effective_name = if display_name.is_empty() {
        stored.clone()
    } else {
        display_name.clone()
    };
    let insert_result = resource_registry::insert(
        &state.db,
        NewResource {
            resource: stored.clone(),
            display_name: effective_name.clone(),
            org_id: org_id.clone(),
            created_by: ctx.email.clone(),
        },
    )
    .await;
    if let Err(e) = insert_result {
        if matches!(
            e.downcast_ref::<diesel::result::Error>(),
            Some(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _
            ))
        ) {
            rerender!("That resource is already registered.");
        }
        tracing::error!(error = ?e, resource = %stored, "admin/resources: insert failed");
        return render_admin_error(
            &state,
            "Create failed",
            "We couldn't register the resource. Please try again in a moment.",
        );
    }

    if !claims.is_empty() {
        let set = match resource_registry::find_by_resource(&state.db, &stored).await {
            Ok(Some(row)) => resource_registry::set_access_token_claims(&state.db, row.id, &claims)
                .await
                .map_err(|e| (Some(row.id), e)),
            Ok(None) => Err((None, anyhow::anyhow!("row missing right after insert"))),
            Err(e) => Err((None, e)),
        };
        if let Err((id, e)) = set {
            if let (Some(id), Some(conflict)) = (id, e.downcast_ref::<ClaimConflict>()) {
                let msg = conflict.to_string();
                match resource_registry::delete(&state.db, id).await {
                    Ok(()) => rerender!(msg),
                    Err(e) => {
                        tracing::error!(error = ?e, resource = %stored, "admin/resources: removing row after claim conflict failed");
                    }
                }
            }
            tracing::error!(error = ?e, resource = %stored, "admin/resources: storing access-token claims failed");
            return render_admin_error(
                &state,
                "Claims not saved",
                "The resource was registered, but its access-token claims were not saved. \
                 Set them again from the resource list.",
            );
        }
    }

    // Advisory corroboration; a failure here never unwinds the row.
    let checked = match resource_registry::find_by_resource(&state.db, &stored).await {
        Ok(Some(row)) => match check_and_store(&state, &ctx, &actx, row.id, &stored).await {
            Ok(status) => status.unwrap_or(corroboration::UNCHECKED),
            Err(e) => {
                tracing::warn!(error = ?e, resource = %stored, "admin/resources: storing corroboration failed");
                corroboration::UNCHECKED
            }
        },
        other => {
            tracing::warn!(result = ?other.err(), resource = %stored, "admin/resources: re-read after insert failed");
            corroboration::UNCHECKED
        }
    };

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_RESOURCE_CREATED, &actx)
            .target(target_kind::RESOURCE, stored.clone())
            .metadata(audit_metadata!(
                "org_id" => org_id.as_str(),
                "display_name" => effective_name.as_str(),
                "corroboration" => checked,
                "claims" => claims.join(" "),
            )),
    )
    .await;

    Redirect::to(&with_org("/admin/resources", &scope)).into_response()
}

/// Fetch a row by path id and enforce the org scope: Forseti admins bypass;
/// org-scoped admins get the same "Not found" for a missing row and a
/// sibling-org row (no existence leak, mirroring `ensure_client_in_scope`).
async fn load_row_in_scope(
    state: &AppState,
    scope: &AdminScope,
    id: i64,
) -> Result<resource_registry::Row, Response> {
    let row = match resource_registry::get(&state.db, id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, id, "admin/resources: row lookup failed");
            return Err(render_admin_error(
                state,
                "Resource unavailable",
                "We couldn't load that resource. Please try again in a moment.",
            ));
        }
    };
    let not_found = || {
        render_admin_error(
            state,
            "Not found",
            "We couldn't find that resource in this organization.",
        )
    };
    let Some(row) = row else {
        return Err(not_found());
    };
    if let AdminScope::Org { id: org_id, .. } = scope
        && &row.org_id != org_id
    {
        return Err(not_found());
    }
    Ok(row)
}

pub async fn toggle(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    _: CsrfForm<NoPayload>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    let row = match load_row_in_scope(&state, &scope, id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let enabled = !row.enabled;
    if let Err(e) = resource_registry::set_enabled(&state.db, id, enabled).await {
        tracing::error!(error = ?e, id, "admin/resources: set_enabled failed");
        return render_admin_error(
            &state,
            "Toggle failed",
            "We couldn't update that resource. Please try again in a moment.",
        );
    }

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_RESOURCE_TOGGLED, &actx)
            .target(target_kind::RESOURCE, row.resource)
            .metadata(audit_metadata!("enabled" => enabled)),
    )
    .await;

    Redirect::to(&with_org("/admin/resources", &scope)).into_response()
}

#[derive(askama::Template)]
#[template(path = "admin/resource_claims.html")]
struct ResourceClaimsTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    error_message: String,
    resource: String,
    display_name: String,
    access_token_claims: String,
    self_service: SelfServiceFields,
    form_action: String,
    cancel_url: String,
}

/// The self-service inputs as entered (trimmed), for validation and echo.
#[derive(Debug, Default)]
struct SelfServiceFields {
    claim: String,
    issuer: String,
    client_id: String,
    template: String,
}

impl SelfServiceFields {
    fn from_row(row: &resource_registry::Row) -> Self {
        Self {
            claim: row.self_service_claim.clone(),
            issuer: row.self_service_issuer.clone(),
            client_id: row.self_service_client_id.clone(),
            template: row.self_service_template.clone(),
        }
    }

    fn from_form(form: &ClaimsForm) -> Self {
        Self {
            claim: form.self_service_claim.trim().to_string(),
            issuer: form.self_service_issuer.trim().to_string(),
            client_id: form.self_service_client_id.trim().to_string(),
            template: form.self_service_template.trim().to_string(),
        }
    }
}

/// All four fields empty turns self-service off; otherwise every field must
/// be valid. The issuer is kept as entered: discovery compares it verbatim to
/// the document's `issuer`.
fn validate_self_service(
    claims: &[String],
    fields: &SelfServiceFields,
    allow_private: bool,
) -> Result<Option<SelfService>, String> {
    let SelfServiceFields {
        claim,
        issuer,
        client_id,
        template,
    } = fields;
    if claim.is_empty() && issuer.is_empty() && client_id.is_empty() && template.is_empty() {
        return Ok(None);
    }
    if !claims.iter().any(|c| c == claim) {
        return Err("The self-service claim must be one of the access-token claims.".to_string());
    }
    if issuer.len() > 2048 {
        return Err("Issuer URL must be at most 2048 characters.".to_string());
    }
    let url = Url::parse(issuer).map_err(|_| "Issuer URL is not a valid URL.".to_string())?;
    crate::outbound::check_target(&url, allow_private).map_err(|e| format!("Issuer URL {e}."))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err("Issuer URL must not have a query or fragment.".to_string());
    }
    if client_id.is_empty()
        || client_id.len() > 255
        || !client_id.chars().all(|c| c.is_ascii_graphic())
    {
        return Err(
            "Client ID is required, at most 255 characters, printable ASCII without spaces."
                .to_string(),
        );
    }
    crate::claim_template::Template::parse(template).map_err(|e| format!("Value {e}."))?;
    Ok(Some(SelfService {
        claim: claim.clone(),
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        template: template.clone(),
    }))
}

/// Claims are Forseti-admin only, so an org-scoped admin gets the same
/// "Not found" as for a row outside their org.
async fn load_row_for_claims(
    state: &AppState,
    scope: &AdminScope,
    id: i64,
) -> Result<resource_registry::Row, Response> {
    if matches!(scope, AdminScope::Org { .. }) {
        return Err(render_admin_error(
            state,
            "Not found",
            "We couldn't find that resource in this organization.",
        ));
    }
    load_row_in_scope(state, scope, id).await
}

fn render_claims_page(
    ctx: &AdminCtx,
    csrf: &Csrf,
    row: &resource_registry::Row,
    access_token_claims: &str,
    self_service: SelfServiceFields,
    error_message: String,
) -> Response {
    render(&ResourceClaimsTemplate {
        chrome: ctx.chrome(csrf),
        admin_active: AdminSection::Resources,
        error_message,
        resource: row.resource.clone(),
        display_name: row.display_name.clone(),
        access_token_claims: access_token_claims.to_string(),
        self_service,
        form_action: format!("/admin/resources/{}/claims", row.id),
        cancel_url: "/admin/resources".to_string(),
    })
}

pub async fn claims_edit(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    let row = match load_row_for_claims(&state, &scope, id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    render_claims_page(
        &ctx,
        &csrf,
        &row,
        &row.access_token_claims,
        SelfServiceFields::from_row(&row),
        String::new(),
    )
}

#[derive(Debug, Deserialize)]
pub struct ClaimsForm {
    #[serde(default)]
    access_token_claims: String,
    #[serde(default)]
    self_service_claim: String,
    #[serde(default)]
    self_service_issuer: String,
    #[serde(default)]
    self_service_client_id: String,
    #[serde(default)]
    self_service_template: String,
}

pub async fn claims_update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    csrf: Csrf,
    CsrfForm(form): CsrfForm<ClaimsForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    let row = match load_row_for_claims(&state, &scope, id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let fields = SelfServiceFields::from_form(&form);
    let raw_claims = form.access_token_claims.trim();
    let rerender = |fields: SelfServiceFields, msg: String| {
        render_claims_page(&ctx, &csrf, &row, raw_claims, fields, msg)
    };
    let claims = match resource_registry::parse_access_token_claims(raw_claims) {
        Ok(c) => c,
        Err(msg) => return rerender(fields, msg),
    };
    let allow_private = state.cfg.oauth.cimd.allow_private_targets;
    let self_service = match validate_self_service(&claims, &fields, allow_private) {
        Ok(s) => s,
        Err(msg) => return rerender(fields, msg),
    };
    if let Err(e) = resource_registry::set_claims_and_self_service(
        &state.db,
        id,
        &claims,
        self_service.as_ref(),
    )
    .await
    {
        if let Some(conflict) = e.downcast_ref::<ClaimConflict>() {
            return rerender(fields, conflict.to_string());
        }
        tracing::error!(error = ?e, id, "admin/resources: set_claims_and_self_service failed");
        return render_admin_error(
            &state,
            "Update failed",
            "We couldn't update that resource. Please try again in a moment.",
        );
    }

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_RESOURCE_CLAIMS_UPDATED, &actx)
            .target(target_kind::RESOURCE, row.resource.clone())
            .metadata(audit_metadata!(
                "previous" => row.access_token_claims.as_str(),
                "claims" => claims.join(" "),
                "previous_self_service_claim" => row.self_service_claim.as_str(),
                "previous_self_service_issuer" => row.self_service_issuer.as_str(),
                "previous_self_service_client_id" => row.self_service_client_id.as_str(),
                "previous_self_service_template" => row.self_service_template.as_str(),
                "self_service_claim" => fields.claim,
                "self_service_issuer" => fields.issuer,
                "self_service_client_id" => fields.client_id,
                "self_service_template" => fields.template,
            ))
            .critical(),
    )
    .await;

    Redirect::to("/admin/resources").into_response()
}

pub async fn recheck(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    _: CsrfForm<NoPayload>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    let row = match load_row_in_scope(&state, &scope, id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Verbatim non-URI identifiers have nothing to fetch; stay `unchecked`.
    if let Err(e) = check_and_store(&state, &ctx, &actx, id, &row.resource).await {
        tracing::error!(error = ?e, id, "admin/resources: storing corroboration failed");
        return render_admin_error(
            &state,
            "Re-check failed",
            "We checked the resource but couldn't store the result. Please try again in a moment.",
        );
    }

    Redirect::to(&with_org("/admin/resources", &scope)).into_response()
}

pub async fn delete_confirm(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    let row = match load_row_in_scope(&state, &scope, id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    render(&ConfirmTemplate {
        chrome: ctx.chrome(&csrf),
        admin_active: AdminSection::Resources,
        title: format!("Delete resource {}?", row.resource),
        body: "After deletion this resource can no longer be granted as an access-token \
               audience; new consents requesting it will drop it. Already-issued tokens keep \
               their audience until they expire."
            .to_string(),
        action_url: with_org(&format!("/admin/resources/{id}/delete"), &scope),
        cancel_url: with_org("/admin/resources", &scope),
        submit_label: "Delete resource",
    })
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    CsrfForm(form): CsrfForm<ConfirmForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Some(r) = form.bounce_unless_confirmed(&with_org("/admin/resources", &scope)) {
        return r;
    }
    let row = match load_row_in_scope(&state, &scope, id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if let Err(e) = resource_registry::delete(&state.db, id).await {
        tracing::error!(error = ?e, id, "admin/resources: delete failed");
        return render_admin_error(
            &state,
            "Delete failed",
            "We couldn't delete that resource. Please try again in a moment.",
        );
    }

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_RESOURCE_DELETED, &actx)
            .target(target_kind::RESOURCE, row.resource)
            .metadata(audit_metadata!("org_id" => row.org_id.as_str()))
            .critical(),
    )
    .await;

    Redirect::to(&with_org("/admin/resources", &scope)).into_response()
}

/// Run the RFC 9728 check for a row and store the status and scopes. Returns
/// the status, or `None` when the resource has nothing to fetch; errs only
/// when storing the result fails.
async fn check_and_store(
    state: &AppState,
    ctx: &AdminCtx,
    actx: &AuditCtx,
    id: i64,
    resource: &str,
) -> Result<Option<&'static str>, anyhow::Error> {
    let Some(check) = protected_resource::check(
        resource,
        state.cfg.hydra.issuer_or_public(),
        state.cfg.oauth.cimd.allow_private_targets,
    )
    .await
    else {
        return Ok(None);
    };
    if let Some(reason) = &check.reason {
        tracing::info!(
            resource,
            status = check.status,
            reason,
            "admin/resources: RFC 9728 document did not corroborate"
        );
    }
    let diff =
        resource_registry::set_check_result(&state.db, id, check.status, check.scopes.as_deref())
            .await?;
    if let Some(diff) = diff {
        let _ = audit::log(
            &state.db,
            ctx.audit_event(action::RESOURCE_SCOPES_CHANGED, actx)
                .target(target_kind::RESOURCE, resource.to_string())
                .metadata(audit_metadata!(
                    "added" => diff.added.join(" "),
                    "removed" => diff.removed.join(" "),
                )),
        )
        .await;
        match resource_registry::load_registry_scopes(&state.db).await {
            Ok(reg) if reg.budget_cut => tracing::warn!(
                resource,
                budget = resource_registry::REGISTRY_SCOPE_BUDGET,
                "admin/resources: registry scopes exceed the budget; newer rows' scopes ignored"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = ?e, "admin/resources: registry scope reload failed"),
        }
    }
    Ok(Some(check.status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(claim: &str, issuer: &str, client_id: &str, template: &str) -> SelfServiceFields {
        SelfServiceFields {
            claim: claim.to_string(),
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            template: template.to_string(),
        }
    }

    #[test]
    fn validate_self_service_off_and_valid() {
        let claims = vec!["forgejo_aud".to_string(), "team".to_string()];
        assert_eq!(
            validate_self_service(&claims, &SelfServiceFields::default(), false),
            Ok(None)
        );
        let ok = fields(
            "forgejo_aud",
            "https://git.example.com/",
            "abc-123",
            "u:{sub}:{uuid}",
        );
        assert_eq!(
            validate_self_service(&claims, &ok, false),
            Ok(Some(SelfService {
                claim: "forgejo_aud".to_string(),
                issuer: "https://git.example.com/".to_string(),
                client_id: "abc-123".to_string(),
                template: "u:{sub}:{uuid}".to_string(),
            }))
        );
        let http = fields("forgejo_aud", "http://127.0.0.1:8092/default", "c", "{sub}");
        assert!(validate_self_service(&claims, &http, true).is_ok());
    }

    #[test]
    fn validate_self_service_refusals() {
        let claims = vec!["forgejo_aud".to_string()];
        let cases = [
            (
                fields("", "https://git.example.com/", "c", "{sub}"),
                "one of the access-token claims",
            ),
            (
                fields("other", "https://git.example.com/", "c", "{sub}"),
                "one of the access-token claims",
            ),
            (
                fields("forgejo_aud", "git.example.com", "c", "{sub}"),
                "not a valid URL",
            ),
            (
                fields("forgejo_aud", "http://git.example.com/", "c", "{sub}"),
                "must use https://",
            ),
            (
                fields("forgejo_aud", "https://127.0.0.1/", "c", "{sub}"),
                "private or special-use",
            ),
            (
                fields("forgejo_aud", "https://git.example.com/?a=b", "c", "{sub}"),
                "query or fragment",
            ),
            (
                fields("forgejo_aud", "https://git.example.com/#x", "c", "{sub}"),
                "query or fragment",
            ),
            (
                fields("forgejo_aud", "https://git.example.com/", "", "{sub}"),
                "Client ID",
            ),
            (
                fields("forgejo_aud", "https://git.example.com/", "a b", "{sub}"),
                "Client ID",
            ),
            (
                fields("forgejo_aud", "https://git.example.com/", "c", ""),
                "must contain {sub}",
            ),
            (
                fields("forgejo_aud", "https://git.example.com/", "c", "u|{sub}"),
                "template literals",
            ),
        ];
        for (input, want) in cases {
            let err = validate_self_service(&claims, &input, false)
                .expect_err(&format!("{input:?} must be refused"));
            assert!(err.contains(want), "{input:?}: {err}");
        }
    }
}
