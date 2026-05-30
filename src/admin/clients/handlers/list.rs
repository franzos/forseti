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

    // Fetch Forseti-side metadata for the visible page in one round-trip,
    // then merge into the rows in memory. Hydra owns the clients table
    // and Forseti owns `oauth_client_metadata` — they live in
    // separate databases for sqlite deployments and separate schemas
    // for postgres ones, so a real SQL JOIN isn't on the table. The
    // bulk lookup is bounded by `CLIENTS_PAGE_SIZE`, so it's a single
    // small `IN (?, ?, ...)` query.
    let client_ids: Vec<String> = clients.iter().filter_map(|c| c.client_id.clone()).collect();
    let meta_rows = match oauth_client_metadata::get_many(&state.db, &client_ids).await {
        Ok(rows) => rows,
        Err(e) => {
            // Don't fail the page on a metadata lookup miss — render
            // the list with legacy defaults (every row "verified",
            // none "self_registered") and log loudly. Beats taking
            // /admin/clients down because one row in our table is
            // corrupt.
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

    // Hydra doesn't expose a next-page token in the SDK return; if we
    // got a full page, surface the last row's ID as the continuation
    // token (Hydra accepts client_id values there). UUID searches and
    // empty results never advertise a next page. Compute *before* any
    // client-side filter (org / type / verification) so subsequent
    // pages don't skip Hydra rows that happen to be filtered out on
    // the current page.
    let next_page_token = if rows.len() == CLIENTS_PAGE_SIZE as usize && !looks_like_uuid(&filter_q)
    {
        rows.last().map(|r| r.id.clone()).unwrap_or_default()
    } else {
        String::new()
    };

    // Org-scope filter. Forseti scope sees every client; an org-scoped
    // caller sees only clients whose `oauth_client_metadata.org_id`
    // matches their org. Orphan rows (no metadata at all) belong to no
    // org and stay invisible to org-scoped views — only Forseti admins
    // can triage them. v1 shortcut: post-filtering shrinks the page
    // below `CLIENTS_PAGE_SIZE`, so an org with sparse clients spread
    // across Hydra's ordering may need multiple "Next page" clicks to
    // reach all its rows. A Forseti-owned client mirror would lift this.
    if let AdminScope::Org { id: org_id, .. } = &scope {
        rows.retain(|r| {
            meta_by_id
                .get(&r.id)
                .map(|m| &m.org_id == org_id)
                .unwrap_or(false)
        });
    }
    let has_prev = page_token.is_some();
    // Client-side type filter. Hydra has no metadata search, so we filter
    // after the fact. Cost is bounded by `CLIENTS_PAGE_SIZE`. If list
    // sizes grow past a few hundred we'd need a Forseti-owned mirror —
    // out of scope for now.
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
