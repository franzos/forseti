//! `GET /admin/clients/{id}/delete` (confirm) and `POST` (delete).

use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
};

use crate::admin::with_org;
use crate::admin::{render_admin_error, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx};
use crate::csrf::CsrfForm;
use crate::extractors::Csrf;
use crate::ory;
use crate::render::render;
use crate::state::AppState;

use crate::admin::clients::scope::RequireClientInScope;

pub async fn delete_confirm(client_in_scope: RequireClientInScope, csrf: Csrf) -> Response {
    let RequireClientInScope { id, ctx, .. } = client_in_scope;
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Clients,
        title: format!("Delete client {id}?"),
        body: "This permanently removes the OAuth2 client. Existing tokens issued by Hydra remain valid until their expiry — Hydra does not invalidate them on client deletion.".to_string(),
        action_url: format!("/admin/clients/{}/delete", ory_client::apis::urlencode(&id)),
        cancel_url: format!("/admin/clients/{}", ory_client::apis::urlencode(&id)),
        submit_label: "Delete client",
    })
}

pub async fn delete(
    State(state): State<AppState>,
    client_in_scope: RequireClientInScope,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<ConfirmForm>,
) -> Response {
    let RequireClientInScope { id, ctx, scope } = client_in_scope;
    if let Some(r) = form.bounce_unless_confirmed(&with_org(
        &format!("/admin/clients/{}", ory_client::apis::urlencode(&id)),
        &scope,
    )) {
        return r;
    }
    match ory::hydra::delete_client(&state.ory, &id).await {
        Ok(()) => {
            let _ = audit::log(
                &state.db,
                ctx.audit_event(action::ADMIN_CLIENT_DELETED, &actx)
                    .target(target_kind::OAUTH_CLIENT, id.clone())
                    .critical(),
            )
            .await;
            Redirect::to(&with_org("/admin/clients", &scope)).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: delete_client failed");
            render_admin_error(
                &state,
                "Delete failed",
                &format!("Could not delete client: {e}"),
            )
        }
    }
}
