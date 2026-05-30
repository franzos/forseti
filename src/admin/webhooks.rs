//! `/admin/webhooks` — surfaces dead-lettered outbox rows so an operator
//! can either retry delivery (rare; usually the receiver fixed something)
//! or discard if delivery is genuinely no longer possible.
//!
//! Healthy rows never appear here; the worker drains them silently. A
//! count of `state=DEAD` rows surfaces on `/admin/status` so operators
//! notice even if they don't open this page directly.
//!
//! The page is master/detail: the summary table at `/admin/webhooks` is
//! scan-friendly (client name + age + attempts, with a single "View"
//! action), and `/admin/webhooks/{id}` carries the full URL, full
//! `last_error`, the signed payload, and both Requeue / Discard buttons.
//! Discard only lives on the detail page because it's irreversible and
//! we want the operator one extra click away from a fat-finger.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;

use crate::admin::{render_admin_error, with_org, AdminSection, ConfirmForm};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::extractors::{Csrf, RequireAdminScoped};
use crate::format::humanise_timestamp;
use crate::oauth_client_metadata;
use crate::orgs::AdminScope;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;
use crate::webhook;

/// Look up the Forseti-side metadata row for `client_id` and decide
/// whether it lives in `scope`. Orphans (no metadata row) default to
/// the Default org per the `oauth_client_metadata` convention, so an
/// org-scoped admin never sees an orphan row from another org. Forseti
/// scope is a no-op. Returns `Ok(false)` for "in scope, hide row"
/// rather than an error so the caller can quietly filter the list.
async fn webhook_row_in_scope(state: &AppState, scope: &AdminScope, client_id: &str) -> bool {
    let AdminScope::Org { id: scope_org, .. } = scope else {
        return true;
    };
    let row = match oauth_client_metadata::get(&state.db, client_id).await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(error = ?e, client_id, "admin/webhooks: scope check failed to fetch client metadata");
            return false;
        }
    };
    let client_org = row
        .map(|r| r.org_id)
        .unwrap_or_else(|| crate::orgs::DEFAULT_ORG_ID.to_string());
    &client_org == scope_org
}

/// One row in the dead-letter summary table.
pub(crate) struct DeadRow {
    pub id: String,
    /// Short prefix of the event UUID; the full id sits in the `title`
    /// attribute (hover tooltip) and on the detail page.
    pub event_id_short: String,
    pub event_id: String,
    pub client_id: String,
    /// Resolved via `hydra::get_client`; falls back to `client_id` if the
    /// client was deleted between the dead-letter being created and the
    /// admin opening this page.
    pub client_name: String,
    pub client_exists: bool,
    pub attempts: i32,
    pub created_at_pretty: String,
}

/// Full record for the detail page.
pub(crate) struct DeadDetail {
    pub id: String,
    pub event_id: String,
    pub client_id: String,
    pub client_name: String,
    pub client_exists: bool,
    pub url: String,
    pub attempts: i32,
    pub last_error: String,
    pub created_at: String,
    pub created_at_pretty: String,
    pub next_attempt_at: String,
    pub state: String,
    /// Pretty-printed JSON, or the raw payload if it didn't parse as JSON
    /// (defensive — we always write JSON, but reading back from storage
    /// shouldn't crash if the row was hand-edited).
    pub payload_pretty: String,
}

#[derive(askama::Template)]
#[template(path = "admin/webhooks.html")]
struct WebhooksTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<DeadRow>,
}

#[derive(askama::Template)]
#[template(path = "admin/webhook_show.html")]
struct WebhookShowTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    row: DeadDetail,
}

pub async fn show(
    State(state): State<AppState>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let mut outbox_rows = match webhook::list_dead(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "admin: list_dead failed");
            return render_admin_error(
                &state,
                "Webhooks unavailable",
                "We couldn't list dead-lettered webhook rows. Please try again in a moment.",
            );
        }
    };

    // Org-scoped: keep only rows owned by clients in the active org.
    // Filtering in Rust after a single SELECT is acceptable for a
    // dead-letter list (small N); a SQL-side join would require
    // introducing a foreign-key view across Forseti-owned and
    // webhook-owned tables that don't otherwise reference each other.
    if scope.org_id().is_some() {
        let mut keep = Vec::with_capacity(outbox_rows.len());
        for r in outbox_rows.into_iter() {
            if webhook_row_in_scope(&state, &scope, &r.client_id).await {
                keep.push(r);
            }
        }
        outbox_rows = keep;
    }

    let client_names = resolve_client_names(
        &state,
        outbox_rows
            .iter()
            .map(|r| r.client_id.as_str())
            .collect::<HashSet<_>>(),
    )
    .await;

    let rows: Vec<DeadRow> = outbox_rows
        .into_iter()
        .map(|r| {
            let (client_name, client_exists) = client_label(&client_names, &r.client_id);
            DeadRow {
                event_id_short: short_id(&r.event_id),
                created_at_pretty: humanise_timestamp(&r.created_at),
                id: r.id,
                event_id: r.event_id,
                client_id: r.client_id,
                client_name,
                client_exists,
                attempts: r.attempts,
            }
        })
        .collect();

    tracing::info!(
        action = "admin.webhooks.list",
        actor = %ctx.email,
        count = rows.len(),
        "admin action"
    );

    let chrome = ctx.chrome(&csrf);
    render(&WebhooksTemplate {
        chrome,
        admin_active: AdminSection::Webhooks,
        rows,
    })
}

pub async fn show_one(
    State(state): State<AppState>,
    Path(row_id): Path<String>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let outbox = match webhook::find_by_id(&state.db, &row_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return render_admin_error(
                &state,
                "Not found",
                "That webhook row no longer exists. It may have been requeued or discarded.",
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, row_id, "admin: find_by_id failed");
            return render_admin_error(
                &state,
                "Webhooks unavailable",
                "We couldn't load that webhook row. Please try again in a moment.",
            );
        }
    };

    if !webhook_row_in_scope(&state, &scope, &outbox.client_id).await {
        // 404-shape so an org-scoped admin can't probe for sibling-org
        // row IDs by URL-guessing.
        return render_admin_error(
            &state,
            "Not found",
            "That webhook row no longer exists. It may have been requeued or discarded.",
        );
    }

    let client_names = resolve_client_names(
        &state,
        std::iter::once(outbox.client_id.as_str()).collect::<HashSet<_>>(),
    )
    .await;
    let (client_name, client_exists) = client_label(&client_names, &outbox.client_id);

    let payload_pretty = match serde_json::from_str::<serde_json::Value>(&outbox.payload) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| outbox.payload.clone()),
        Err(_) => outbox.payload.clone(),
    };

    let row = DeadDetail {
        created_at_pretty: humanise_timestamp(&outbox.created_at),
        id: outbox.id,
        event_id: outbox.event_id,
        client_id: outbox.client_id,
        client_name,
        client_exists,
        url: outbox.url,
        attempts: outbox.attempts,
        last_error: outbox.last_error.unwrap_or_default(),
        created_at: outbox.created_at,
        next_attempt_at: outbox.next_attempt_at,
        state: outbox.state,
        payload_pretty,
    };

    let chrome = ctx.chrome(&csrf);
    render(&WebhookShowTemplate {
        chrome,
        admin_active: AdminSection::Webhooks,
        row,
    })
}

pub async fn requeue(
    State(state): State<AppState>,
    Path(row_id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    if let Err(resp) = enforce_row_scope(&state, &scope, &row_id).await {
        return resp;
    }
    let redirect = with_org("/admin/webhooks", &scope);
    match webhook::requeue_dead(&state.db, &row_id).await {
        Ok(true) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ADMIN_WEBHOOK_REQUEUED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::WEBHOOK_OUTBOX, row_id.clone())
                    .with_ctx(&actx),
            )
            .await;
        }
        Ok(false) => {
            tracing::warn!(actor = %ctx.email, row_id, "admin.webhooks.requeue: row not found / not DEAD");
        }
        Err(e) => {
            tracing::error!(error = ?e, row_id, "admin: requeue failed");
            return render_admin_error(
                &state,
                "Requeue failed",
                "We couldn't requeue that row. Please try again.",
            );
        }
    }
    Redirect::to(&redirect).into_response()
}

pub async fn discard(
    State(state): State<AppState>,
    Path(row_id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdminScoped,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    if let Err(resp) = enforce_row_scope(&state, &scope, &row_id).await {
        return resp;
    }
    let redirect = with_org("/admin/webhooks", &scope);
    match webhook::discard_dead(&state.db, &row_id).await {
        Ok(true) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ADMIN_WEBHOOK_DISCARDED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::WEBHOOK_OUTBOX, row_id.clone())
                    .with_ctx(&actx),
            )
            .await;
        }
        Ok(false) => {
            tracing::warn!(actor = %ctx.email, row_id, "admin.webhooks.discard: row not found / not DEAD");
        }
        Err(e) => {
            tracing::error!(error = ?e, row_id, "admin: discard failed");
            return render_admin_error(
                &state,
                "Discard failed",
                "We couldn't discard that row. Please try again.",
            );
        }
    }
    Redirect::to(&redirect).into_response()
}

/// Look up the outbox row, then verify its client belongs to the
/// active scope. Rendered as 404-shape rather than 403 so an
/// org-scoped caller can't enumerate sibling-org row IDs by probing
/// for the difference between "wrong scope" and "doesn't exist".
async fn enforce_row_scope(
    state: &AppState,
    scope: &AdminScope,
    row_id: &str,
) -> Result<(), Response> {
    if scope.org_id().is_none() {
        return Ok(());
    }
    let outbox = match webhook::find_by_id(&state.db, row_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(render_admin_error(
                state,
                "Not found",
                "That webhook row no longer exists. It may have been requeued or discarded.",
            ));
        }
        Err(e) => {
            tracing::error!(error = ?e, row_id, "admin: find_by_id failed during scope check");
            return Err(render_admin_error(
                state,
                "Webhooks unavailable",
                "We couldn't verify access to that webhook row. Please try again in a moment.",
            ));
        }
    };
    if webhook_row_in_scope(state, scope, &outbox.client_id).await {
        Ok(())
    } else {
        Err(render_admin_error(
            state,
            "Not found",
            "That webhook row no longer exists. It may have been requeued or discarded.",
        ))
    }
}

/// Resolve client names for the given client_ids. Returns
/// `Some(name)` when Hydra returned a client (name may be empty if the
/// operator never set one), `None` when the client no longer exists
/// (deleted between dead-letter creation and operator opening this page).
///
/// Fans out up to `MAX_CONCURRENT` lookups concurrently via
/// `tokio::task::JoinSet` so the page renders in roughly one Hydra
/// round-trip rather than N. Bounded so a large dead-letter table can't
/// stampede Hydra.
async fn resolve_client_names(
    state: &AppState,
    client_ids: HashSet<&str>,
) -> HashMap<String, Option<String>> {
    const MAX_CONCURRENT: usize = 8;
    let mut out = HashMap::with_capacity(client_ids.len());
    let mut pending: Vec<String> = client_ids.into_iter().map(|s| s.to_string()).collect();
    let mut set: tokio::task::JoinSet<(String, anyhow::Result<ory::OAuth2Client>)> =
        tokio::task::JoinSet::new();

    let initial = MAX_CONCURRENT.min(pending.len());
    for _ in 0..initial {
        if let Some(cid) = pending.pop() {
            let ory = state.ory.clone();
            set.spawn(async move {
                let res = ory::hydra::get_client(&ory, &cid).await;
                (cid, res)
            });
        }
    }
    while let Some(joined) = set.join_next().await {
        let (cid, res) = match joined {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = ?e, "admin: hydra client lookup task panicked");
                continue;
            }
        };
        match res {
            Ok(c) => {
                out.insert(cid, Some(c.client_name.unwrap_or_default()));
            }
            Err(_) => {
                out.insert(cid, None);
            }
        }
        if let Some(next) = pending.pop() {
            let ory = state.ory.clone();
            set.spawn(async move {
                let res = ory::hydra::get_client(&ory, &next).await;
                (next, res)
            });
        }
    }
    out
}

/// Pull the resolved label out of [`resolve_client_names`]. Returns
/// `(label, exists)` — when the client is gone we still show the raw
/// UUID (so the operator can match it back against logs) but the
/// template renders it as plain text rather than a link.
fn client_label(names: &HashMap<String, Option<String>>, client_id: &str) -> (String, bool) {
    match names.get(client_id) {
        Some(Some(name)) if !name.is_empty() => (name.clone(), true),
        Some(Some(_)) => (client_id.to_string(), true), // exists but unnamed
        Some(None) | None => (client_id.to_string(), false), // deleted / unresolvable
    }
}

/// First eight chars of a UUID. Enough to disambiguate in a small
/// dead-letter list; the full id remains in the row's `title` attribute
/// and on the detail page.
fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}
