//! `/admin/audit`: append-only audit event browser over `audit_events`.
//!
//! Master/detail. List filters via query string:
//!
//! - `email`: substring match against `actor_email`
//! - `action`: substring match against `action` (`LIKE %x%`)
//! - `severity`: exact match (`info` / `warning` / `error` / `critical`)
//! - `since`: RFC3339 / `datetime-local`; older rows filtered out

use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use serde::Deserialize;

use crate::admin::{render_admin_error, AdminSection};
use crate::audit;
use crate::extractors::{Csrf, RequireAdminScoped};
use crate::format::humanise_timestamp;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

/// One row in the audit summary table.
pub(crate) struct AuditRow {
    pub id: String,
    pub when: String,
    pub when_pretty: String,
    pub severity: String,
    pub success: bool,
    pub action: String,
    /// Empty if not a user/admin actor (e.g. system, webhook).
    pub actor_email: String,
    pub actor_id: String,
    /// Empty when the event has no target (e.g. logout).
    pub target_kind: String,
    pub target_id: String,
    /// Eight-char prefix for display; full id in the `title` tooltip.
    pub target_id_short: String,
    /// URL to the target's own admin page; empty when none (e.g. sessions).
    pub target_link: String,
}

/// Full record for the audit detail page.
pub(crate) struct AuditDetail {
    pub id: String,
    pub when: String,
    pub when_pretty: String,
    pub severity: String,
    pub success: bool,
    pub action: String,
    pub actor_kind: String,
    pub actor_email: String,
    pub actor_id: String,
    pub target_kind: String,
    pub target_id: String,
    /// Resolved label (identity email / client name); falls back to `target_id`
    /// when unresolvable (deleted, or a kind we don't look up like `session`).
    pub target_label: String,
    /// True when the target's own admin page is still reachable.
    pub target_exists: bool,
    pub target_link: String,
    pub org_id: String,
    pub ip_hash: String,
    pub user_agent: String,
    pub request_id: String,
    /// JSON pretty-printed; empty when the row has no metadata.
    pub metadata_pretty: String,
}

#[derive(askama::Template)]
#[template(path = "admin/audit.html")]
struct AuditTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<AuditRow>,
    total: i64,
    filter_email: String,
    filter_action: String,
    filter_severity: String,
    filter_since: String,
    /// Inline parse error for `since`; when non-empty the filter is ignored.
    filter_error: String,
    /// 1-indexed page currently rendered.
    page: i64,
    /// Current page's offset (`(page-1) * page_size`).
    offset: i64,
    has_prev: bool,
    has_next: bool,
    /// Pre-rendered query strings for the prev/next links, with every filter.
    prev_query: String,
    next_query: String,
}

#[derive(askama::Template)]
#[template(path = "admin/audit_show.html")]
struct AuditShowTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    row: AuditDetail,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    since: Option<String>,
    /// 1-indexed page; missing / `<1` falls back to page 1. The table is
    /// sorted newest-first, so an offset-based pager drifts when rows are
    /// appended; acceptable since operators usually filter before paging.
    #[serde(default)]
    page: Option<i64>,
}

const AUDIT_PAGE_SIZE: i64 = 200;

pub async fn show(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let filter_email = query.email.unwrap_or_default();
    let filter_action = query.action.unwrap_or_default();
    let filter_severity = query.severity.unwrap_or_default();
    let filter_since = query.since.unwrap_or_default();
    let page = query.page.unwrap_or(1).max(1);
    let offset = page.saturating_sub(1).saturating_mul(AUDIT_PAGE_SIZE);

    let (since_dt, filter_error) = if filter_since.is_empty() {
        (None, String::new())
    } else {
        match parse_since(&filter_since) {
            Ok(dt) => (Some(dt), String::new()),
            Err(_) => (
                None,
                format!(
                    "Couldn't parse \"{filter_since}\" as a timestamp. Expected RFC3339, e.g. 2025-01-01T00:00:00Z."
                ),
            ),
        }
    };

    // `actor_email_contains` is pushed into SQL so pagination doesn't silently
    // drop matches past the LIMIT.
    let filter = audit::AuditFilter {
        actor_email_contains: if filter_email.trim().is_empty() {
            None
        } else {
            Some(filter_email.clone())
        },
        action_prefix: if filter_action.is_empty() {
            None
        } else {
            Some(filter_action.clone())
        },
        severity: if filter_severity.is_empty() {
            None
        } else {
            Some(filter_severity.clone())
        },
        since: since_dt,
        // Org-scoped: restrict to rows tagged with that org's id.
        org_id: scope.org_id().map(str::to_string),
        limit: AUDIT_PAGE_SIZE,
        offset,
        ..Default::default()
    };

    let (raw_rows, total) = match audit::query(&state.db, filter).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "admin: audit query failed");
            return render_admin_error(
                &state,
                "Audit unavailable",
                "We couldn't load audit events. Please try again in a moment.",
            );
        }
    };

    let rows: Vec<AuditRow> = raw_rows.into_iter().map(project_summary_row).collect();

    let has_prev = page > 1;
    let has_next = offset + (rows.len() as i64) < total;
    let filters_qs = filter_query_string(
        &filter_email,
        &filter_action,
        &filter_severity,
        &filter_since,
        scope.org_id(),
    );
    let prev_query = page_query_string(page - 1, &filters_qs);
    let next_query = page_query_string(page + 1, &filters_qs);

    let chrome = ctx.chrome(&csrf);
    render(&AuditTemplate {
        chrome,
        admin_active: AdminSection::Audit,
        rows,
        total,
        filter_email,
        filter_action,
        filter_severity,
        filter_error,
        filter_since,
        page,
        offset,
        has_prev,
        has_next,
        prev_query,
        next_query,
    })
}

/// Build the filter part of the URL (everything except `page`). Empty filters
/// are dropped.
fn filter_query_string(
    email: &str,
    action: &str,
    severity: &str,
    since: &str,
    org: Option<&str>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    let push = |parts: &mut Vec<String>, k: &str, v: &str| {
        if !v.is_empty() {
            parts.push(format!(
                "{}={}",
                ory_client::apis::urlencode(k),
                ory_client::apis::urlencode(v)
            ));
        }
    };
    push(&mut parts, "email", email);
    push(&mut parts, "action", action);
    push(&mut parts, "severity", severity);
    push(&mut parts, "since", since);
    if let Some(org) = org {
        push(&mut parts, "org", org);
    }
    parts.join("&")
}

fn page_query_string(page: i64, filters_qs: &str) -> String {
    let page = page.max(1);
    if filters_qs.is_empty() {
        format!("?page={page}")
    } else {
        format!("?{filters_qs}&page={page}")
    }
}

pub async fn show_one(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
    admin: RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let RequireAdminScoped { ctx, scope } = admin;

    let raw = match audit::find_by_id(&state.db, &event_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return render_admin_error(
                &state,
                "Not found",
                "That audit event doesn't exist. It may have been pruned by `forseti audit-prune`.",
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, event_id, "admin: audit find_by_id failed");
            return render_admin_error(
                &state,
                "Audit unavailable",
                "We couldn't load that audit event. Please try again in a moment.",
            );
        }
    };

    // Org-scoped: 404-shape on a foreign-org row so an org-scoped admin can't
    // probe for the existence of sibling-org audit IDs.
    if let Some(scope_org) = scope.org_id() {
        let row_org = raw.org_id.as_deref().unwrap_or("");
        if row_org != scope_org {
            return render_admin_error(
                &state,
                "Not found",
                "That audit event doesn't exist. It may have been pruned by `forseti audit-prune`.",
            );
        }
    }

    let row = project_detail_row(&state, raw).await;

    let chrome = ctx.chrome(&csrf);
    render(&AuditShowTemplate {
        chrome,
        admin_active: AdminSection::Audit,
        row,
    })
}

/// Project one DB row into the summary view-model. No external lookups: those
/// would be O(N) Hydra/Kratos calls per page. The detail view resolves labels.
fn project_summary_row(r: audit::AuditRow) -> AuditRow {
    let success = r.succeeded();
    let target_kind = r.target_kind.clone().unwrap_or_default();
    let target_id = r.target_id.clone().unwrap_or_default();
    let target_link = target_admin_link(&target_kind, &target_id);
    let target_id_short = short_id(&target_id);
    AuditRow {
        when_pretty: humanise_timestamp(&r.created_at),
        when: r.created_at,
        severity: r.severity,
        success,
        action: r.action,
        actor_email: r.actor_email.unwrap_or_default(),
        actor_id: r.actor_id.unwrap_or_default(),
        target_kind,
        target_id,
        target_id_short,
        target_link,
        id: r.id,
    }
}

/// Detail-row projection. Resolves the target label via Hydra/Kratos (e.g. a
/// client name instead of a bare UUID), falling back to the raw id if deleted.
async fn project_detail_row(state: &AppState, r: audit::AuditRow) -> AuditDetail {
    let target_kind = r.target_kind.clone().unwrap_or_default();
    let target_id = r.target_id.clone().unwrap_or_default();
    let target_link = target_admin_link(&target_kind, &target_id);

    let (target_label, target_exists) = resolve_target_label(state, &target_kind, &target_id).await;

    let success = r.succeeded();
    let metadata_pretty = if r.metadata.is_empty() || r.metadata == "{}" {
        String::new()
    } else {
        let raw = r.metadata.clone();
        match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => serde_json::to_string_pretty(&v).unwrap_or(raw),
            Err(_) => raw,
        }
    };

    AuditDetail {
        when_pretty: humanise_timestamp(&r.created_at),
        when: r.created_at,
        severity: r.severity,
        success,
        action: r.action,
        actor_kind: r.actor_kind,
        actor_email: r.actor_email.unwrap_or_default(),
        actor_id: r.actor_id.unwrap_or_default(),
        target_kind,
        target_id,
        target_label,
        target_exists,
        target_link,
        org_id: r.org_id.unwrap_or_default(),
        ip_hash: r.ip_hash.unwrap_or_default(),
        user_agent: r.user_agent.unwrap_or_default(),
        request_id: r.request_id.unwrap_or_default(),
        metadata_pretty,
        id: r.id,
    }
}

/// Resolve a friendly label for the event's target. At most one Hydra or Kratos
/// admin call per render. Returns `(label, exists)`.
async fn resolve_target_label(
    state: &AppState,
    target_kind: &str,
    target_id: &str,
) -> (String, bool) {
    if target_id.is_empty() {
        return (String::new(), false);
    }
    match target_kind {
        audit::target_kind::OAUTH_CLIENT => {
            match ory::hydra::get_client(&state.ory, target_id).await {
                Ok(c) => {
                    let name = c.client_name.unwrap_or_default();
                    if name.is_empty() {
                        (target_id.to_string(), true)
                    } else {
                        (name, true)
                    }
                }
                Err(_) => (target_id.to_string(), false),
            }
        }
        audit::target_kind::IDENTITY => {
            match ory::kratos::admin_get_identity(&state.ory, target_id).await {
                Ok(ident) => {
                    let email = ident
                        .traits
                        .as_ref()
                        .and_then(|t| t.get("email"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if email.is_empty() {
                        (target_id.to_string(), true)
                    } else {
                        (email, true)
                    }
                }
                Err(_) => (target_id.to_string(), false),
            }
        }
        // Sessions/webhook rows have no label to resolve; raw id is fine.
        _ => (target_id.to_string(), true),
    }
}

/// URL of the target's own admin detail page; empty when none exists.
fn target_admin_link(target_kind: &str, target_id: &str) -> String {
    if target_id.is_empty() {
        return String::new();
    }
    match target_kind {
        audit::target_kind::IDENTITY => format!("/admin/identities/{target_id}"),
        audit::target_kind::OAUTH_CLIENT => format!("/admin/clients/{target_id}"),
        audit::target_kind::WEBHOOK_OUTBOX => format!("/admin/webhooks/{target_id}"),
        // sessions/system have no detail page
        _ => String::new(),
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Parse the `since` shapes (`datetime-local` with/without seconds, RFC3339)
/// into a typed UTC timestamp. Parsing here (rather than passing a string to
/// SQL) stops a non-RFC3339 input from reaching the comparison and silently
/// returning a lexicographically-wrong row set.
fn parse_since(s: &str) -> Result<chrono::DateTime<chrono::Utc>, chrono::ParseError> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    let padded = if s.len() == 16 && s.chars().nth(13) == Some(':') {
        format!("{s}:00Z")
    } else if s.len() == 19 && !s.ends_with('Z') {
        format!("{s}Z")
    } else {
        s.to_string()
    };
    chrono::DateTime::parse_from_rfc3339(&padded).map(|dt| dt.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_accepts_rfc3339() {
        let dt = parse_since("2025-01-01T12:30:00Z").unwrap();
        assert_eq!(
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "2025-01-01T12:30:00Z"
        );
    }

    #[test]
    fn parse_since_pads_datetime_local_without_seconds() {
        let dt = parse_since("2025-01-01T12:30").unwrap();
        assert_eq!(dt.format("%H:%M:%S").to_string(), "12:30:00");
    }

    #[test]
    fn parse_since_pads_datetime_local_with_seconds() {
        let dt = parse_since("2025-01-01T12:30:45").unwrap();
        assert_eq!(dt.format("%H:%M:%S").to_string(), "12:30:45");
    }

    #[test]
    fn parse_since_rejects_garbage() {
        assert!(parse_since("not a timestamp").is_err());
        assert!(parse_since("").is_err());
        assert!(parse_since("2025-13-01T00:00:00Z").is_err());
    }

    #[test]
    fn target_admin_link_identity() {
        let url = target_admin_link(audit::target_kind::IDENTITY, "abc-123");
        assert_eq!(url, "/admin/identities/abc-123");
    }

    #[test]
    fn target_admin_link_oauth_client() {
        let url = target_admin_link(audit::target_kind::OAUTH_CLIENT, "client-id");
        assert_eq!(url, "/admin/clients/client-id");
    }

    #[test]
    fn target_admin_link_webhook_outbox() {
        let url = target_admin_link(audit::target_kind::WEBHOOK_OUTBOX, "wh-1");
        assert_eq!(url, "/admin/webhooks/wh-1");
    }

    #[test]
    fn target_admin_link_session_has_no_page() {
        assert_eq!(target_admin_link(audit::target_kind::SESSION, "sess-1"), "");
    }

    #[test]
    fn target_admin_link_empty_id() {
        assert_eq!(target_admin_link(audit::target_kind::IDENTITY, ""), "");
    }

    #[test]
    fn short_id_truncates_to_eight() {
        assert_eq!(short_id("abcdefghijklmnop"), "abcdefgh");
    }

    #[test]
    fn short_id_passes_through_shorter() {
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id(""), "");
    }
}
