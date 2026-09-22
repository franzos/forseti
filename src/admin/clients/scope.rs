//! Org-scope helpers specific to `/admin/clients/*` handlers.
//!
//! See [`crate::orgs::AdminScope`] for the precedence rules; this file
//! exposes the client-specific glue (scope-belongs check, create-time
//! target resolution). Generic query-string threading lives in
//! [`crate::admin::with_org`].

use axum::extract::{FromRef, FromRequestParts, Path, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::response::Response;

use crate::admin::{AdminCtx, render_admin_error};
use crate::extractors::RequireAdminScoped;
use crate::oauth_client_metadata;
use crate::orgs::AdminScope;
use crate::ory;
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

/// Constrain a client payload to what an org owner may ask for; Forseti-wide
/// scope is a no-op. An org owner is not an operator, so two things are theirs
/// to keep and Forseti's to refuse:
///
///   * `skip_consent` - a silent-grant client would issue tokens for any user
///     who follows an authorize link, without a consent screen.
///   * `audience` - an entry is only allowed when it is an enabled resource
///     registered to this same org, so a client can't be pointed at another
///     tenant's resource server.
///
/// The Err variant is the message to show on the re-rendered form.
pub(super) async fn constrain_org_scoped_client(
    state: &AppState,
    scope: &AdminScope,
    payload: &mut ory::OAuth2Client,
) -> Result<(), String> {
    let AdminScope::Org { id: org_id, .. } = scope else {
        return Ok(());
    };
    payload.skip_consent = Some(false);

    for raw in payload.audience.as_deref().unwrap_or_default() {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let canonical =
            crate::oauth::canonical_resource(entry).unwrap_or_else(|| entry.to_string());
        let row = crate::resource_registry::find_by_resource(&state.db, &canonical)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, resource = %canonical, "admin/clients: audience lookup failed");
                "We couldn't check the audience against the resource registry. \
                 Please try again in a moment."
                    .to_string()
            })?;
        match row {
            Some(r) if r.enabled && r.org_id == *org_id => {}
            _ => {
                return Err(format!(
                    "\"{entry}\" is not an enabled resource of your organization. \
                     Register it under Resources first."
                ));
            }
        }
    }
    // Hydra fetches these itself on logout, from inside the deployment, so an
    // org owner supplying an internal URL turns Hydra into an SSRF proxy they
    // do not otherwise reach. Same guard the webhook targets get.
    for (field, raw) in [
        (
            "Back-channel logout URI",
            payload.backchannel_logout_uri.as_deref(),
        ),
        (
            "Front-channel logout URI",
            payload.frontchannel_logout_uri.as_deref(),
        ),
    ] {
        let Some(uri) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        if let Err(e) = crate::webhook::validate_webhook_url(uri) {
            return Err(format!("{field}: {e}"));
        }
    }

    Ok(())
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
