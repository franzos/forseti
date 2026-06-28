//! `GET /admin/clients` — the list/index page.

use axum::{
    extract::{Query, State},
    response::Response,
};
use serde::Deserialize;

use crate::admin::{render_admin_error, AdminSection};
use crate::extractors::Csrf;
use crate::format::looks_like_uuid;
use crate::oauth_client_metadata;
use crate::orgs::AdminScope;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use crate::admin::clients::presets::picker_cards;
use crate::admin::clients::projection::{project_row, ClientRow};

#[derive(askama::Template)]
#[template(path = "admin/clients_list.html")]
struct ClientsListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<ClientRow>,
    /// Current search input — echoed back into the textbox. Matched
    /// against client name AND (when shaped like a UUID) client ID.
    filter_q: String,
    /// Currently selected preset slug for the type filter, or empty
    /// for "all".
    filter_type: String,
    /// Currently selected verification filter — `"verified"`,
    /// `"unverified"`, or empty (for "all"). Applied client-side after
    /// Hydra returns the page; mirrors the type filter.
    filter_verification: String,
    /// Options for the type-filter `<select>`. Each is `(slug, label)`.
    type_options: Vec<(&'static str, &'static str)>,
    next_page_token: String,
    /// True when this request carries a `page_token` — surfaces the
    /// "Back to start" link.
    has_prev: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Search input — matched against client name and (when shaped
    /// like a UUID) client ID.
    #[serde(default)]
    q: Option<String>,
    /// Legacy alias for `?q=` — earlier versions of the page used
    /// `?name=`. Kept so saved links don't 404.
    #[serde(default)]
    name: Option<String>,
    /// Preset filter — matches `metadata.forseti.client_type`. Applied
    /// client-side after Hydra returns the page; Hydra has no native
    /// metadata filter.
    #[serde(rename = "type", default)]
    type_: Option<String>,
    /// Verification filter — `"verified"` / `"unverified"`. Empty = all.
    /// Applied client-side after merging in `oauth_client_metadata`
    /// rows for the visible page. A missing metadata row counts as
    /// "verified" (legacy fallback — see `oauth_client_metadata`).
    #[serde(default)]
    verification: Option<String>,
    #[serde(default)]
    page_token: Option<String>,
}

const CLIENTS_PAGE_SIZE: i64 = 25;

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    admin: crate::extractors::RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let crate::extractors::RequireAdminScoped { ctx, scope } = admin;

    let filter_q = query
        .q
        .or(query.name)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let filter_type = query
        .type_
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let filter_verification = query
        .verification
        .map(|s| s.trim().to_string())
        .filter(|s| matches!(s.as_str(), "verified" | "unverified"))
        .unwrap_or_default();
    let page_token = query.page_token.as_deref().filter(|s| !s.is_empty());

    // UUID-shaped query: short-circuit through `get_client` so admins
    // can paste a client ID directly into the search box. Hydra's
    // `list_o_auth2_clients` `client_name` filter doesn't match IDs,
    // so without this branch a paste-the-ID lookup returns empty.
    let clients = if looks_like_uuid(&filter_q) {
        match ory::hydra::get_client(&state.ory, &filter_q).await {
            Ok(c) => vec![c],
            Err(e) => {
                tracing::info!(error = ?e, "admin: client ID lookup miss");
                Vec::new()
            }
        }
    } else {
        let name_filter = if filter_q.is_empty() {
            None
        } else {
            Some(filter_q.as_str())
        };
        match ory::hydra::list_clients(&state.ory, CLIENTS_PAGE_SIZE, page_token, name_filter).await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = ?e, "admin: list_clients failed");
                return render_admin_error(
                    &state,
                    "Clients unavailable",
                    "We couldn't list OAuth2 clients. Please try again in a moment.",
                );
            }
        }
    };

    // Hydra owns the clients table, Forseti owns `oauth_client_metadata`, and
    // they live in separate databases/schemas, so no SQL JOIN. Merge in memory
    // via a single bulk lookup bounded by `CLIENTS_PAGE_SIZE`.
    let client_ids: Vec<String> = clients.iter().filter_map(|c| c.client_id.clone()).collect();
    let meta_rows = match oauth_client_metadata::get_many(&state.db, &client_ids).await {
        Ok(rows) => rows,
        Err(e) => {
            // Don't take /admin/clients down on a metadata lookup miss; render
            // with legacy defaults (every row verified, none self_registered).
            tracing::error!(error = ?e, "admin: oauth_client_metadata bulk lookup failed; rendering with legacy defaults");
            Vec::new()
        }
    };
    let meta_by_id: std::collections::HashMap<String, &oauth_client_metadata::Row> =
        meta_rows.iter().map(|m| (m.client_id.clone(), m)).collect();
    let mut rows: Vec<ClientRow> = clients
        .iter()
        .map(|c| {
            let id = c.client_id.clone().unwrap_or_default();
            let meta = meta_by_id.get(&id).copied();
            project_row(c, meta)
        })
        .collect();

    // The SDK exposes no next-page token; on a full page use the last row's ID
    // (Hydra accepts client_id there). Compute before any client-side filter so
    // later pages don't skip Hydra rows filtered out on this page.
    let next_page_token = if rows.len() == CLIENTS_PAGE_SIZE as usize && !looks_like_uuid(&filter_q)
    {
        rows.last().map(|r| r.id.clone()).unwrap_or_default()
    } else {
        String::new()
    };

    // Org-scoped callers see only clients whose `oauth_client_metadata.org_id`
    // matches; orphan rows stay invisible (only Forseti admins triage them).
    // Post-filtering shrinks the page below `CLIENTS_PAGE_SIZE`, so a sparse
    // org may need several "Next page" clicks; a Forseti-owned mirror would fix it.
    if let AdminScope::Org { id: org_id, .. } = &scope {
        rows.retain(|r| {
            meta_by_id
                .get(&r.id)
                .map(|m| &m.org_id == org_id)
                .unwrap_or(false)
        });
    }
    let has_prev = page_token.is_some();
    // Hydra has no metadata search, so type/verification filter after the
    // fact. Cost bounded by `CLIENTS_PAGE_SIZE`.
    if !filter_type.is_empty() {
        rows.retain(|r| r.client_type == filter_type);
    }
    if !filter_verification.is_empty() {
        let want_verified = filter_verification == "verified";
        rows.retain(|r| r.verified == want_verified);
    }

    tracing::info!(
        action = "admin.clients.list",
        actor = %ctx.email,
        count = rows.len(),
        "admin action"
    );

    let chrome = ctx.chrome(&csrf);
    render(&ClientsListTemplate {
        chrome,
        admin_active: AdminSection::Clients,
        rows,
        filter_q,
        filter_type,
        filter_verification,
        type_options: picker_cards().iter().map(|c| (c.slug, c.label)).collect(),
        next_page_token,
        has_prev,
    })
}
