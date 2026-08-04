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

use std::net::IpAddr;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use futures_util::StreamExt;
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
use crate::render::render;
use crate::resource_registry::{self, NewResource, corroboration};
use crate::state::AppState;

const CORROBORATION_TIMEOUT: Duration = Duration::from_secs(5);
const CORROBORATION_DOC_LIMIT_BYTES: usize = 64 * 1024;

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
                created_by: r.created_by,
                can_recheck: has_fetchable_host(&r.resource),
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
        orgs,
        scoped: matches!(scope, AdminScope::Org { .. }),
        scoped_org_name,
        form_action: with_org("/admin/resources/new", scope),
        cancel_url: with_org("/admin/resources", scope),
    })
}

pub async fn new(State(state): State<AppState>, admin: RequireAdminScoped, csrf: Csrf) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    render_new_page(&state, &ctx, &scope, &csrf, String::new(), "", "", "").await
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
            )
            .await
        };
    }

    if raw_resource.is_empty() {
        rerender!("Resource is required.");
    }
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

    // Advisory corroboration; a failure here never unwinds the row.
    let checked = match corroborate(&state, &stored).await {
        Some(status) => {
            match resource_registry::find_by_resource(&state.db, &stored).await {
                Ok(Some(row)) => {
                    if let Err(e) =
                        resource_registry::set_corroboration(&state.db, row.id, status).await
                    {
                        tracing::warn!(error = ?e, resource = %stored, "admin/resources: storing corroboration failed");
                    }
                }
                other => {
                    tracing::warn!(result = ?other.err(), resource = %stored, "admin/resources: re-read after insert failed");
                }
            }
            status
        }
        None => corroboration::UNCHECKED,
    };

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_RESOURCE_CREATED, &actx)
            .target(target_kind::RESOURCE, stored.clone())
            .metadata(audit_metadata!(
                "org_id" => org_id.as_str(),
                "display_name" => effective_name.as_str(),
                "corroboration" => checked,
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

pub async fn recheck(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    admin: RequireAdminScoped,
    _: CsrfForm<NoPayload>,
) -> Response {
    let RequireAdminScoped { scope, .. } = admin;
    let row = match load_row_in_scope(&state, &scope, id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Verbatim non-URI identifiers have nothing to fetch; stay `unchecked`.
    if let Some(status) = corroborate(&state, &row.resource).await
        && let Err(e) = resource_registry::set_corroboration(&state.db, id, status).await
    {
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

// --- RFC 9728 corroboration ----------------------------------------------

/// True when the stored resource is an http(s) URI with a host — i.e. the
/// corroboration fetch has somewhere to go.
fn has_fetchable_host(resource: &str) -> bool {
    Url::parse(resource)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .and_then(|u| u.host_str().map(str::to_string))
        .is_some()
}

/// RFC 9728 §3 well-known location, path-aware: the well-known prefix sits
/// between the origin and the resource's path component.
fn protected_resource_metadata_url(resource: &Url) -> Option<Url> {
    resource.host_str()?;
    let path = resource.path().trim_end_matches('/');
    let wk = if path.is_empty() {
        "/.well-known/oauth-protected-resource".to_string()
    } else {
        format!("/.well-known/oauth-protected-resource{path}")
    };
    let mut url = resource.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.set_path(&wk);
    Some(url)
}

/// Run the advisory check for `resource`. `None` = nothing to check (verbatim
/// non-URI identifier), the row stays `unchecked`. Never gates anything.
async fn corroborate(state: &AppState, resource: &str) -> Option<&'static str> {
    let url = Url::parse(resource)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))?;
    let wk = protected_resource_metadata_url(&url)?;
    let allow_private = state.cfg.oauth.cimd.allow_private_targets;
    let status = match fetch_metadata(&wk, allow_private).await {
        Ok(doc) => {
            let issuer = state.cfg.hydra.issuer_or_public();
            if resource_matches(&doc.resource, resource)
                && issuer_listed(&doc.authorization_servers, issuer)
            {
                corroboration::CORROBORATED
            } else {
                tracing::info!(
                    resource,
                    doc_resource = %doc.resource,
                    "admin/resources: RFC 9728 document fetched but did not corroborate"
                );
                corroboration::MISMATCH
            }
        }
        Err(e) => {
            tracing::info!(resource, error = %e, "admin/resources: RFC 9728 fetch failed");
            corroboration::UNREACHABLE
        }
    };
    Some(status)
}

/// The document's `resource` against the stored (canonical) row value, with
/// the same verbatim-then-canonical dual matching the consent resolver uses.
fn resource_matches(doc_resource: &str, stored: &str) -> bool {
    let doc_resource = doc_resource.trim();
    doc_resource == stored
        || crate::oauth::canonical_resource(doc_resource).is_some_and(|c| c == stored)
}

/// Trailing-slash-insensitive membership test for `authorization_servers`.
fn issuer_listed(servers: &[String], issuer: &str) -> bool {
    let want = issuer.trim_end_matches('/');
    servers
        .iter()
        .any(|s| s.trim().trim_end_matches('/') == want)
}

#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// SSRF-guarded GET of the metadata document: same composition as
/// `oauth::cimd_fetch` (scheme policy, blocked-IP literals, DNS-rebinding
/// guard via `webhook::guarded_resolver`, no redirects, 5 s / 64 KiB caps).
async fn fetch_metadata(
    url: &Url,
    allow_private: bool,
) -> Result<ProtectedResourceMetadata, String> {
    match url.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => return Err("metadata URL must use https://".to_string()),
    }
    match url.host() {
        None => return Err("metadata URL must include a host".to_string()),
        Some(_) if allow_private => {}
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            return Err("metadata host must not be a loopback address".to_string());
        }
        Some(url::Host::Ipv4(v4)) if crate::webhook::is_blocked_ip(IpAddr::V4(v4)) => {
            return Err("metadata host must not be a private or special-use IP".to_string());
        }
        Some(url::Host::Ipv6(v6)) if crate::webhook::is_blocked_ip(IpAddr::V6(v6)) => {
            return Err("metadata host must not be a private or special-use IP".to_string());
        }
        Some(_) => {}
    }

    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(CORROBORATION_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if !allow_private {
        builder = builder.dns_resolver(crate::webhook::guarded_resolver());
    }
    let client = builder.build().expect("static reqwest client config");

    let resp = client
        .get(url.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    if resp
        .content_length()
        .is_some_and(|l| l > CORROBORATION_DOC_LIMIT_BYTES as u64)
    {
        return Err("document too large".to_string());
    }
    // Chunked bodies carry no Content-Length; enforce the cap while reading.
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if buf.len() + chunk.len() > CORROBORATION_DOC_LIMIT_BYTES {
            return Err("document too large".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| format!("invalid document: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wk(raw: &str) -> String {
        protected_resource_metadata_url(&Url::parse(raw).unwrap())
            .expect("well-known URL")
            .to_string()
    }

    #[test]
    fn well_known_url_without_path() {
        assert_eq!(
            wk("https://mcp.example.com"),
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn well_known_url_inserts_before_path() {
        assert_eq!(
            wk("https://stackpit.gofranz.com/mcp"),
            "https://stackpit.gofranz.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn well_known_url_keeps_port_and_drops_query() {
        assert_eq!(
            wk("http://127.0.0.1:8890/mcp/v1?x=1"),
            "http://127.0.0.1:8890/.well-known/oauth-protected-resource/mcp/v1"
        );
    }

    #[test]
    fn resource_matches_verbatim_and_canonical() {
        let stored = "https://stackpit.gofranz.com/mcp";
        assert!(resource_matches(stored, stored));
        assert!(resource_matches(
            "https://stackpit.gofranz.com/mcp/",
            stored
        ));
        assert!(!resource_matches("https://other.example/mcp", stored));
        // Verbatim non-URI identifiers only ever match verbatim.
        assert!(resource_matches("stackpit-web", "stackpit-web"));
    }

    #[test]
    fn issuer_listed_is_trailing_slash_insensitive() {
        let servers = vec!["http://host.containers.internal:3000/hydra/".to_string()];
        assert!(issuer_listed(
            &servers,
            "http://host.containers.internal:3000/hydra"
        ));
        assert!(!issuer_listed(&servers, "https://other.issuer"));
    }

    #[test]
    fn has_fetchable_host_rejects_verbatim_identifiers() {
        assert!(has_fetchable_host("https://mcp.example.com/mcp"));
        assert!(!has_fetchable_host("stackpit-web"));
        assert!(!has_fetchable_host("stackpit.gofranz.com"));
        assert!(!has_fetchable_host("urn:example:resource"));
    }
}
