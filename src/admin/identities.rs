//! `/admin/identities/*`: Kratos identity browser.
//!
//! The typed `Identity` model doesn't suffer from the `ui.nodes` bug, so the
//! SDK types are usable directly here (unlike the raw-JSON Kratos flows).

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::admin::{render_admin_error, with_org, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::extractors::{Csrf, RequireAdminScoped};
use crate::flash::{
    self, attach_set_cookie as attach_cookie_if_some, redirect_with_cookie, SecretReveal,
};
use crate::format::{humanise_timestamp, looks_like_uuid};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

pub(crate) struct IdentityRow {
    pub id: String,
    pub email: String,
    pub state: String,
    /// Raw ISO timestamp kept for `title=` hover.
    pub created_at: String,
    pub created_at_pretty: String,
}

fn project_row(id: &ory::Identity) -> IdentityRow {
    let email = id
        .traits
        .as_ref()
        .and_then(|t| t.get("email"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // Kratos treats a missing `state` as `active`; mirror that so identities
    // created via APIs that omit the field don't render an empty red badge.
    let state = id
        .state
        .as_ref()
        .and_then(|s| {
            serde_json::to_value(s)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "active".to_string());
    let created_at = id.created_at.clone().unwrap_or_default();
    IdentityRow {
        id: id.id.clone(),
        email,
        state,
        created_at_pretty: humanise_timestamp(&created_at),
        created_at,
    }
}

pub(crate) struct CredentialView {
    pub method: String,
    pub identifiers: String,
}

pub(crate) struct AddressView {
    pub value: String,
    pub verified: bool,
}

pub(crate) use crate::session_view::SessionView as SessionRow;

#[derive(askama::Template)]
#[template(path = "admin/identities_list.html")]
struct IdentitiesListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<IdentityRow>,
    /// Current search input, echoed back into the textbox.
    filter_q: String,
    /// Opaque next-page token; empty when there's no next page.
    next_page_token: String,
    /// Kratos paginates with opaque tokens (no backward seek), so the only
    /// reliable back-step is "go to page 1".
    has_prev: bool,
}

#[derive(askama::Template)]
#[template(path = "admin/identity_show.html")]
struct IdentityShowTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    row: IdentityRow,
    traits_json: String,
    credentials: Vec<CredentialView>,
    addresses: Vec<AddressView>,
    sessions: Vec<SessionRow>,
    /// One-time recovery code shown after a successful `POST /recovery`.
    recovery_code: Option<String>,
    recovery_link: Option<String>,
    flash: String,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Matched against identity ID (UUID-shaped) else passed to Kratos as
    /// `credentials_identifier` (email).
    #[serde(default)]
    q: Option<String>,
    /// Legacy `?email=` alias; kept so old links don't 404.
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    page_token: Option<String>,
}

/// Page size, also the "is there more?" heuristic: a full page implies a next.
const IDENTITIES_PAGE_SIZE: i64 = 25;

pub(crate) struct IdentitySearch {
    pub rows: Vec<IdentityRow>,
    pub next_page_token: String,
    pub has_prev: bool,
}

/// Scope-aware identity search + pagination shared by the list page and the
/// picker. `filter_q` must already be trimmed. The Err variant carries a
/// ready-to-send admin-error Response (DB / Kratos failures).
pub(crate) async fn search_identities(
    state: &AppState,
    scope: &crate::orgs::AdminScope,
    filter_q: &str,
    page_token: Option<&str>,
) -> Result<IdentitySearch, axum::response::Response> {
    // Org-scoped: page the membership join in the DB first (so large orgs
    // don't issue one massive `?ids=...` to Kratos) then bulk-fetch the page.
    // `page_token` is a numeric offset here, not Kratos's opaque token. The
    // email filter runs after pagination, so a filtered page can be smaller
    // than `IDENTITIES_PAGE_SIZE`; SQL-side filtering would need the Kratos
    // identity store, which isn't visible from here.
    let scoped_offset: i64 = page_token
        .and_then(|t| t.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(0);
    let scoped_member_ids: Option<Vec<String>> = match scope.org_id() {
        Some(org_id) => match crate::orgs::list_members_paged(
            &state.db,
            org_id,
            IDENTITIES_PAGE_SIZE,
            scoped_offset,
        )
        .await
        {
            Ok(rows) => Some(rows.into_iter().map(|m| m.identity_id).collect()),
            Err(e) => {
                tracing::error!(error = ?e, "admin: org-scoped list_members_paged failed");
                return Err(render_admin_error(
                    state,
                    "Identities unavailable",
                    "We couldn't list org members. Please try again in a moment.",
                ));
            }
        },
        None => None,
    };

    // UUID-shaped query: single-identity admin GET, because Kratos's
    // `credentials_identifier` filter is name/email-only and won't match IDs.
    let identities = if looks_like_uuid(filter_q) {
        match ory::kratos::admin_get_identity_full(&state.ory, filter_q).await {
            Ok(id) => vec![id],
            // A 404 here is just an empty result, not a render error.
            Err(e) => {
                tracing::info!(error = ?e, "admin: identity ID lookup miss");
                Vec::new()
            }
        }
    } else if let Some(ref member_ids) = scoped_member_ids {
        // Org-scoped: bulk-load members via Kratos's `ids` filter in one
        // round-trip; email substring filter applied after the fact.
        let mut out =
            match ory::kratos::admin_list_identities_by_ids_full(&state.ory, member_ids.clone())
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = ?e, "admin: org-scoped bulk fetch failed");
                    Vec::new()
                }
            };
        if !filter_q.is_empty() {
            let needle = filter_q.to_lowercase();
            out.retain(|id| {
                id.traits
                    .as_ref()
                    .and_then(|t| t.get("email"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase().contains(&needle))
                    .unwrap_or(false)
            });
        }
        out
    } else {
        let email_filter = if filter_q.is_empty() {
            None
        } else {
            Some(filter_q)
        };
        match ory::kratos::list_identities(
            &state.ory,
            IDENTITIES_PAGE_SIZE,
            page_token,
            email_filter,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = ?e, "admin: list_identities failed");
                return Err(render_admin_error(
                    state,
                    "Identities unavailable",
                    "We couldn't list identities. Please try again in a moment.",
                ));
            }
        }
    };

    let rows: Vec<IdentityRow> = identities.iter().map(project_row).collect();
    // Next-page heuristic: a full page implies more. The typed SDK doesn't
    // surface the Link header, so the unscoped path uses the last row's ID as
    // the opaque token; the scoped path threads a numeric DB offset. The
    // scoped check keys off the pre-filter member-id count (filter runs
    // post-DB, so the filtered row count can't be trusted).
    let next_page_token = if looks_like_uuid(filter_q) {
        String::new()
    } else if let Some(ref member_ids) = scoped_member_ids {
        if member_ids.len() == IDENTITIES_PAGE_SIZE as usize {
            (scoped_offset + IDENTITIES_PAGE_SIZE).to_string()
        } else {
            String::new()
        }
    } else if rows.len() == IDENTITIES_PAGE_SIZE as usize {
        rows.last().map(|r| r.id.clone()).unwrap_or_default()
    } else {
        String::new()
    };
    let has_prev = page_token.is_some();

    Ok(IdentitySearch {
        rows,
        next_page_token,
        has_prev,
    })
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let filter_q = query
        .q
        .or(query.email)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let page_token = query.page_token.as_deref().filter(|s| !s.is_empty());

    let search = match search_identities(&state, &scope, &filter_q, page_token).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let IdentitySearch {
        rows,
        next_page_token,
        has_prev,
    } = search;

    tracing::info!(
        action = "admin.identities.list",
        actor = %ctx.email,
        count = rows.len(),
        "admin action"
    );

    let chrome = ctx.chrome(&csrf);
    render(&IdentitiesListTemplate {
        chrome,
        admin_active: AdminSection::Identities,
        rows,
        filter_q,
        next_page_token,
        has_prev,
    })
}

#[derive(Debug, Deserialize)]
pub struct PickQuery {
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    page_token: Option<String>,
}

struct PickerRow {
    email: String,
    id: String,
    state: String,
    created_at: String,
    created_at_pretty: String,
    select_url: String,
}

#[derive(askama::Template)]
#[template(path = "admin/identity_picker.html")]
struct IdentityPickerTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<PickerRow>,
    filter_q: String,
    return_to: String,
    org_slug: String,
    next_page_url: String,
    prev_url: String,
    invalid_return: bool,
}

fn append_query(url: &str, key: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{key}={}", ory_client::apis::urlencode(value))
}

pub async fn pick(
    State(state): State<AppState>,
    Query(query): Query<PickQuery>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    let raw_rt = query.return_to.as_deref().unwrap_or("").trim().to_string();
    let chrome = ctx.chrome(&csrf);

    // safe_return_to collapses bad input to "/"; treat a collapse (or any
    // fragment) as invalid rather than silently redirecting selections to "/".
    let safe = crate::web::safe_return_to(&state.cfg, &raw_rt);
    let invalid = raw_rt.is_empty() || raw_rt.contains('#') || safe != raw_rt;
    if invalid {
        return render(&IdentityPickerTemplate {
            chrome,
            admin_active: AdminSection::Identities,
            rows: Vec::new(),
            filter_q: String::new(),
            return_to: String::new(),
            org_slug: scope.slug().unwrap_or("").to_string(),
            next_page_url: String::new(),
            prev_url: String::new(),
            invalid_return: true,
        });
    }
    let return_to = safe.to_string();

    let filter_q = query.q.as_deref().unwrap_or("").trim().to_string();
    let page_token = query.page_token.as_deref().filter(|s| !s.is_empty());
    let search = match search_identities(&state, &scope, &filter_q, page_token).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let rows: Vec<PickerRow> = search
        .rows
        .into_iter()
        .map(|r| {
            let label = if r.email.is_empty() {
                r.id.clone()
            } else {
                r.email.clone()
            };
            PickerRow {
                select_url: append_query(&return_to, "identity_id", &r.id),
                email: label,
                id: r.id,
                state: r.state,
                created_at: r.created_at,
                created_at_pretty: r.created_at_pretty,
            }
        })
        .collect();

    let base = with_org("/admin/identity-picker", &scope);
    let mut next_page_url = String::new();
    if !search.next_page_token.is_empty() {
        let mut u = append_query(&base, "return_to", &return_to);
        u = append_query(&u, "page_token", &search.next_page_token);
        if !filter_q.is_empty() {
            u = append_query(&u, "q", &filter_q);
        }
        next_page_url = u;
    }
    let prev_url = if search.has_prev {
        let mut u = append_query(&base, "return_to", &return_to);
        if !filter_q.is_empty() {
            u = append_query(&u, "q", &filter_q);
        }
        u
    } else {
        String::new()
    };

    render(&IdentityPickerTemplate {
        chrome,
        admin_active: AdminSection::Identities,
        rows,
        filter_q,
        return_to,
        org_slug: scope.slug().unwrap_or("").to_string(),
        next_page_url,
        prev_url,
        invalid_return: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct ShowQuery {
    /// Opaque token for a one-shot recovery-code reveal (`take_secret_reveal`).
    #[serde(default)]
    reveal: Option<String>,
}

/// Reject unless `identity_id` is a member of `scope`'s org (Forseti-wide
/// scope is a no-op). Renders "not found" not "forbidden" so org-scoped
/// admins can't probe for identities outside their scope.
async fn require_identity_in_scope(
    state: &AppState,
    identity_id: &str,
    scope: &crate::orgs::AdminScope,
) -> Result<(), Response> {
    let Some(org_id) = scope.org_id() else {
        return Ok(());
    };
    if crate::orgs::is_member(&state.db, identity_id, org_id).await {
        Ok(())
    } else {
        Err(render_admin_error(
            state,
            "Identity not found",
            "We couldn't find an identity with that ID in this organization.",
        ))
    }
}

pub async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ShowQuery>,
    headers: HeaderMap,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Err(resp) = require_identity_in_scope(&state, &id, &scope).await {
        return resp;
    }

    let identity = match ory::kratos::admin_get_identity_full(&state.ory, &id).await {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: get_identity_full failed");
            return render_admin_error(
                &state,
                "Identity unavailable",
                "We couldn't load that identity. It may have been deleted.",
            );
        }
    };

    let row = project_row(&identity);
    let traits_json = identity
        .traits
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();

    let credentials: Vec<CredentialView> = identity
        .credentials
        .as_ref()
        .map(|map| {
            map.iter()
                .map(|(method, c)| CredentialView {
                    method: method.clone(),
                    identifiers: c.identifiers.clone().unwrap_or_default().join(", "),
                })
                .collect()
        })
        .unwrap_or_default();

    let addresses: Vec<AddressView> = identity
        .verifiable_addresses
        .as_ref()
        .map(|arr| {
            arr.iter()
                .map(|a| AddressView {
                    value: a.value.clone(),
                    verified: a.verified,
                })
                .collect()
        })
        .unwrap_or_default();

    let sessions: Vec<SessionRow> = match ory::kratos::list_identity_sessions(&state.ory, &id).await
    {
        Ok(s) => s
            .iter()
            .map(|s| SessionRow::from_kratos(s, false))
            .collect(),
        Err(e) => {
            tracing::warn!(
                identity_id = %id,
                error = %e,
                "admin: list_identity_sessions failed; rendering empty session list"
            );
            Vec::new()
        }
    };

    let reveal = match query.reveal.as_deref().filter(|s| !s.is_empty()) {
        Some(token) => {
            flash::take_secret_reveal(&state.db, state.cfg.flash.reveal_ttl_seconds, token).await
        }
        None => None,
    };
    let (recovery_code, recovery_link) = match reveal {
        Some(SecretReveal::RecoveryCode { code, link }) => (
            Some(code).filter(|s| !s.is_empty()),
            Some(link).filter(|s| !s.is_empty()),
        ),
        _ => (None, None),
    };

    let secure = state.cfg.self_.is_https();
    let path = format!("/admin/identities/{id}");
    let (flash_msg, clear_flash) = flash::take_flash(
        &headers,
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        &path,
        secure,
    );

    tracing::info!(
        action = "admin.identities.view",
        actor = %ctx.email,
        target = %id,
        "admin action"
    );
    let chrome = ctx.chrome(&csrf);
    let resp = render(&IdentityShowTemplate {
        chrome,
        admin_active: AdminSection::Identities,
        row,
        traits_json,
        credentials,
        addresses,
        sessions,
        recovery_code,
        recovery_link,
        flash: flash_msg,
    });
    attach_cookie_if_some(resp, clear_flash)
}

pub async fn recovery(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    Form(form): Form<crate::csrf::CsrfForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Err(resp) = require_identity_in_scope(&state, &id, &scope).await {
        return resp;
    }
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    match ory::kratos::admin_create_recovery_code(&state.ory, &id).await {
        Ok(code) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ADMIN_IDENTITY_RECOVERY_CODE_MINTED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::IDENTITY, id.clone())
                    .with_ctx(&actx)
                    .critical(),
            )
            .await;
            let reveal = SecretReveal::RecoveryCode {
                code: code.recovery_code.clone(),
                link: code.recovery_link.clone(),
            };
            let token = match flash::store_secret_reveal(
                &state.db,
                state.cfg.flash.reveal_ttl_seconds,
                reveal,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(error = ?e, id, "admin: recovery code reveal store failed");
                    return render_admin_error(
                        &state,
                        "Recovery code failed",
                        "We minted the recovery code but couldn't stage it for one-shot \
                         display. Generate a fresh code to retry.",
                    );
                }
            };
            // Reveal token + org slug ride the redirect so the show page lands
            // back inside the same org-scoped view.
            let base = format!(
                "/admin/identities/{}?reveal={}",
                ory_client::apis::urlencode(&id),
                ory_client::apis::urlencode(&token),
            );
            let url = match scope.slug() {
                Some(slug) if !slug.is_empty() => {
                    format!("{}&org={}", base, ory_client::apis::urlencode(slug))
                }
                _ => base,
            };
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: create_recovery_code failed");
            render_admin_error(
                &state,
                "Recovery code failed",
                &format!("Could not generate recovery code: {e}"),
            )
        }
    }
}

pub async fn disable_confirm(
    State(state): State<AppState>,
    Path(id): Path<String>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Err(resp) = require_identity_in_scope(&state, &id, &scope).await {
        return resp;
    }
    let action_url = with_org(
        &format!(
            "/admin/identities/{}/disable",
            ory_client::apis::urlencode(&id)
        ),
        &scope,
    );
    let cancel_url = with_org(
        &format!("/admin/identities/{}", ory_client::apis::urlencode(&id)),
        &scope,
    );
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Identities,
        title: format!("Disable identity {id}?"),
        body: "The identity will no longer be able to sign in. Existing sessions are not revoked — use the sessions admin to do that separately.".to_string(),
        action_url,
        cancel_url,
        submit_label: "Disable identity",
    })
}

pub async fn disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Err(resp) = require_identity_in_scope(&state, &id, &scope).await {
        return resp;
    }
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = with_org(
        &format!("/admin/identities/{}", ory_client::apis::urlencode(&id)),
        &scope,
    );
    if !form.confirmed() {
        return Redirect::to(&target).into_response();
    }
    match ory::kratos::admin_update_identity_state(
        &state.ory,
        &id,
        ory_client::models::update_identity_body::StateEnum::Inactive,
    )
    .await
    {
        Ok(_) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ADMIN_IDENTITY_DISABLED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::IDENTITY, id.clone())
                    .with_ctx(&actx),
            )
            .await;
            let cookie = flash::store_flash(
                &state.cookie_secret,
                state.cfg.flash.cookie_ttl_seconds,
                &target,
                "Identity disabled.",
                state.cfg.self_.is_https(),
            );
            redirect_with_cookie(&target, &cookie)
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: disable failed");
            render_admin_error(
                &state,
                "Disable failed",
                &format!("Could not disable identity: {e}"),
            )
        }
    }
}

pub async fn enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    Form(form): Form<crate::csrf::CsrfForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Err(resp) = require_identity_in_scope(&state, &id, &scope).await {
        return resp;
    }
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = with_org(
        &format!("/admin/identities/{}", ory_client::apis::urlencode(&id)),
        &scope,
    );
    match ory::kratos::admin_update_identity_state(
        &state.ory,
        &id,
        ory_client::models::update_identity_body::StateEnum::Active,
    )
    .await
    {
        Ok(_) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ADMIN_IDENTITY_ENABLED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::IDENTITY, id.clone())
                    .with_ctx(&actx),
            )
            .await;
            let cookie = flash::store_flash(
                &state.cookie_secret,
                state.cfg.flash.cookie_ttl_seconds,
                &target,
                "Identity enabled.",
                state.cfg.self_.is_https(),
            );
            redirect_with_cookie(&target, &cookie)
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: enable failed");
            render_admin_error(
                &state,
                "Enable failed",
                &format!("Could not enable identity: {e}"),
            )
        }
    }
}

pub async fn delete_confirm(
    State(state): State<AppState>,
    Path(id): Path<String>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Err(resp) = require_identity_in_scope(&state, &id, &scope).await {
        return resp;
    }
    let action_url = with_org(
        &format!(
            "/admin/identities/{}/delete",
            ory_client::apis::urlencode(&id)
        ),
        &scope,
    );
    let cancel_url = with_org(
        &format!("/admin/identities/{}", ory_client::apis::urlencode(&id)),
        &scope,
    );
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Identities,
        title: format!("Delete identity {id}?"),
        body: "This permanently removes the identity, its credentials, and all active sessions. The action cannot be undone.".to_string(),
        action_url,
        cancel_url,
        submit_label: "Delete identity",
    })
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Err(resp) = require_identity_in_scope(&state, &id, &scope).await {
        return resp;
    }
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let show_target = with_org(
        &format!("/admin/identities/{}", ory_client::apis::urlencode(&id)),
        &scope,
    );
    if !form.confirmed() {
        return Redirect::to(&show_target).into_response();
    }
    let list_target = with_org("/admin/identities", &scope);
    match crate::admin::actions::delete_identity_audited(
        &state,
        &id,
        crate::admin::actions::DeleteActor::Admin {
            identity_id: &ctx.identity_id,
            email: &ctx.email,
        },
        crate::admin::actions::DeleteReason::AdminInitiated,
        crate::audit::SafeMetadata::empty(),
        Some(&actx),
    )
    .await
    {
        Ok(()) => Redirect::to(&list_target).into_response(),
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: delete failed");
            render_admin_error(
                &state,
                "Delete failed",
                &format!("Could not delete identity: {e}"),
            )
        }
    }
}
