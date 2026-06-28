//! Client verification toggle: `verify`, `unverify_confirm`, `unverify`.

use axum::{extract::State, http::HeaderMap, response::Response};
use axum_extra::extract::Form;

use crate::admin::with_org;
use crate::admin::{render_admin_error, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::extractors::Csrf;
use crate::flash::{self, redirect_with_cookie};
use crate::oauth_client_metadata;
use crate::orgs::AdminScope;
use crate::ory;
use crate::render::render;
use crate::state::AppState;

use crate::admin::clients::scope::RequireClientInScope;

/// `POST /admin/clients/{id}/verify` — admin vouches for the client. Writes
/// the `oauth_client_metadata` row (lazy-creating for legacy clients). No
/// interstitial: verification is a non-destructive upgrade.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    client_in_scope: RequireClientInScope,
    actx: AuditCtx,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let RequireClientInScope { id, ctx, scope } = client_in_scope;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    set_verification(
        &state,
        &id,
        &ctx.identity_id,
        &ctx.email,
        &actx,
        true,
        &scope,
    )
    .await
}

/// `GET /admin/clients/{id}/unverify` — interstitial confirm for the
/// destructive side. Mirrors `delete_confirm` / `rotate_confirm`.
pub async fn unverify_confirm(client_in_scope: RequireClientInScope, csrf: Csrf) -> Response {
    let RequireClientInScope { id, ctx, .. } = client_in_scope;
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Clients,
        title: format!("Revoke verification for {id}?"),
        body: "End-users will see a caution banner on the consent screen for this client until it is verified again.".to_string(),
        action_url: format!("/admin/clients/{}/unverify", ory_client::apis::urlencode(&id)),
        cancel_url: format!("/admin/clients/{}", ory_client::apis::urlencode(&id)),
        submit_label: "Revoke verification",
    })
}

/// `POST /admin/clients/{id}/unverify` — admin revokes a prior vouch. This
/// is the destructive side; emits a CRITICAL audit row so revocation
/// surfaces alongside delete / rotate-secret in `/admin/audit?severity=critical`.
pub async fn unverify(
    State(state): State<AppState>,
    headers: HeaderMap,
    client_in_scope: RequireClientInScope,
    actx: AuditCtx,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let RequireClientInScope { id, ctx, scope } = client_in_scope;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    set_verification(
        &state,
        &id,
        &ctx.identity_id,
        &ctx.email,
        &actx,
        false,
        &scope,
    )
    .await
}

/// Shared body for [`verify`] / [`unverify`]. Touches the Forseti-owned
/// `oauth_client_metadata` table only — the Hydra client is read solely
/// for the `client_name` audit field. Emits the appropriate audit row
/// and redirects to the show page with a flash banner.
async fn set_verification(
    state: &AppState,
    id: &str,
    admin_id: &str,
    admin_email: &str,
    actx: &AuditCtx,
    verify_now: bool,
    scope: &AdminScope,
) -> Response {
    // Best-effort client_name lookup for the audit row. Don't fail the
    // verification if Hydra is temporarily unreachable — the trust
    // state lives Forseti-side now, and the audit row's `target_id`
    // still resolves later via the same `get_client` call.
    let client_name = match ory::hydra::get_client(&state.ory, id).await {
        Ok(c) => c.client_name.clone().unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = ?e, id, "admin: get_client for verify audit failed; proceeding with empty client_name");
            String::new()
        }
    };

    let prior = if verify_now {
        match oauth_client_metadata::mark_verified(&state.db, id, admin_email).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = ?e, id, "admin: mark_verified failed");
                return render_admin_error(
                    state,
                    "Verification update failed",
                    &format!("Could not update client verification: {e}"),
                );
            }
        }
    } else {
        match oauth_client_metadata::mark_unverified(&state.db, id, admin_email).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = ?e, id, "admin: mark_unverified failed");
                return render_admin_error(
                    state,
                    "Verification update failed",
                    &format!("Could not update client verification: {e}"),
                );
            }
        }
    };

    let event = if verify_now {
        AuditEvent::new(action::ADMIN_CLIENT_VERIFIED)
            .actor_admin(admin_id, admin_email)
            .target(target_kind::OAUTH_CLIENT, id.to_string())
            .with_ctx(actx)
            .metadata(audit_metadata!(
                "client_name" => client_name,
                "previous_state" => prior,
            ))
    } else {
        AuditEvent::new(action::ADMIN_CLIENT_UNVERIFIED)
            .actor_admin(admin_id, admin_email)
            .target(target_kind::OAUTH_CLIENT, id.to_string())
            .with_ctx(actx)
            .metadata(audit_metadata!(
                "client_name" => client_name,
                "previous_state" => prior,
            ))
            .critical()
    };
    let _ = audit::log(&state.db, event).await;

    let target = with_org(
        &format!("/admin/clients/{}", ory_client::apis::urlencode(id)),
        scope,
    );
    let msg = if verify_now {
        "Client verified."
    } else {
        "Client verification revoked."
    };
    let cookie = flash::store_flash(
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        &target,
        msg,
        state.cfg.self_.is_https(),
    );
    redirect_with_cookie(&target, &cookie)
}
