//! Org-scope helpers specific to `/admin/clients/*` handlers.
//!
//! See [`crate::orgs::AdminScope`] for the precedence rules; this file
//! exposes the client-specific glue (scope-belongs check, create-time
//! target resolution). Generic query-string threading lives in
//! [`crate::admin::with_org`].

use axum::extract::{FromRef, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::response::Response;

use crate::admin::{render_admin_error, AdminCtx};
use crate::extractors::RequireAdminScoped;
use crate::oauth_client_metadata;
use crate::orgs::AdminScope;
use crate::state::AppState;

/// Enforce that `client_id` belongs to the org named by `scope`. Forseti
/// admins bypass entirely; org-scoped admins get a 404 (rather than 403
/// — we prefer to expose nothing about the existence of sibling-org
/// clients to an org-scoped caller). An orphan row (no Forseti metadata)
/// is treated as Default and is therefore invisible to non-Default
/// org-scoped views; see the module doc on `oauth_client_metadata` for
/// why orphans default to Default.
pub(super) async fn ensure_client_in_scope(
    state: &AppState,
    scope: &AdminScope,
    client_id: &str,
) -> Result<(), Response> {
    let AdminScope::Org { id: scope_org, .. } = scope else {
        return Ok(());
    };
    let row = match oauth_client_metadata::get(&state.db, client_id).await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(error = ?e, client_id, "admin: org-scope check failed to fetch metadata");
            return Err(render_admin_error(
                state,
                "Client unavailable",
                "We couldn't verify access to that client. Please try again in a moment.",
            ));
        }
    };
    let client_org = row
        .map(|r| r.org_id)
        .unwrap_or_else(|| crate::orgs::DEFAULT_ORG_ID.to_string());
    if &client_org != scope_org {
        return Err(render_admin_error(
            state,
            "Not found",
            "We couldn't find that client in this organization.",
        ));
    }
    Ok(())
}

/// Org-scoped admin gate + path-id + scope-belongs check rolled into one
/// extractor. Collapses the `RequireAdminScoped` + `Path(id)` +
/// `ensure_client_in_scope` triad that fronted every `/admin/clients/{id}/*`
/// handler. Only gates — handlers still call their own `get_client` loader
/// because callers vary in what they need (include-secret, audit-only name
/// lookup, etc.).
pub(crate) struct RequireClientInScope {
    pub(crate) id: String,
    pub(crate) ctx: AdminCtx,
    pub(crate) scope: AdminScope,
}

impl<S> FromRequestParts<S> for RequireClientInScope
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let State(app_state) = State::<AppState>::from_request_parts(parts, state)
            .await
            .expect("AppState extractor is infallible");
        let RequireAdminScoped { ctx, scope } =
            RequireAdminScoped::from_request_parts(parts, state).await?;
        let Path(id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(axum::response::IntoResponse::into_response)?;
        ensure_client_in_scope(&app_state, &scope, &id).await?;
        Ok(RequireClientInScope { id, ctx, scope })
    }
}

/// Pick the `org_id` to stamp on a newly-created client's Forseti
/// metadata row. The non-obvious bit is the Forseti-scope license re-check
/// that defends against a Forseti admin whose `active_org` cookie targets
/// a non-Default org which the current license no longer covers.
pub(super) async fn resolve_create_target_org(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &crate::admin::AdminCtx,
    scope: &AdminScope,
) -> String {
    if let AdminScope::Org { id, .. } = scope {
        return id.clone();
    }
    let memberships = crate::orgs::list_memberships(&state.db, &ctx.identity_id)
        .await
        .unwrap_or_default();
    let active = crate::orgs::active_org(
        &memberships,
        &state.cookie_secret,
        state.cfg.orgs.active_org_cookie_ttl_seconds,
        headers,
    )
    .map(|m| m.org_id);
    match active {
        Some(org_id) if org_id != crate::orgs::DEFAULT_ORG_ID => {
            // Re-gate non-Default targets on the Orgs license. A Forseti
            // admin can still create clients without an active license,
            // but they land in Default rather than in a locked org.
            // TODO(extractor sweep): stays inline because Locked here
            // logs + falls back to Default rather than rendering upsell —
            // distinct from `gate_orgs_feature_or_upsell`'s semantics.
            let feat = state
                .license
                .feature(crate::commercial::license::Feature::Orgs);
            if matches!(feat, crate::commercial::FeatureStatus::Locked) {
                tracing::warn!(
                    target_org = %org_id,
                    "admin: create_client active-org cookie names a non-Default org but Orgs feature is locked; falling back to Default",
                );
                crate::orgs::DEFAULT_ORG_ID.to_string()
            } else {
                org_id
            }
        }
        Some(org_id) => org_id,
        None => crate::orgs::DEFAULT_ORG_ID.to_string(),
    }
}
