//! `GET /admin/clients/{id}/rotate-secret` (confirm) and `POST` (rotate).

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::Form;

use crate::admin::with_org;
use crate::admin::{render_admin_error, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::extractors::Csrf;
use crate::flash::{self, SecretReveal};
use crate::ory;
use crate::render::render;
use crate::state::AppState;

use crate::admin::clients::scope::RequireClientInScope;

pub async fn rotate_confirm(client_in_scope: RequireClientInScope, csrf: Csrf) -> Response {
    let RequireClientInScope { id, ctx, .. } = client_in_scope;
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Clients,
        title: format!("Rotate client secret for {id}?"),
        body: "The current secret will stop working immediately. Any deployments using it will need the new secret.".to_string(),
        action_url: format!("/admin/clients/{}/rotate-secret", ory_client::apis::urlencode(&id)),
        cancel_url: format!("/admin/clients/{}", ory_client::apis::urlencode(&id)),
        submit_label: "Rotate secret",
    })
}

pub async fn rotate(
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
    if !form.confirmed() {
        return Redirect::to(&with_org(
            &format!("/admin/clients/{}", ory_client::apis::urlencode(&id)),
            &scope,
        ))
        .into_response();
    }
    match ory::hydra::rotate_client_secret(&state.ory, &id).await {
        Ok(updated) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ADMIN_CLIENT_SECRET_ROTATED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::OAUTH_CLIENT, id.clone())
                    .with_ctx(&actx)
                    .critical(),
            )
            .await;
            let reveal = SecretReveal::ClientSecretRotated {
                secret: updated.client_secret.clone().unwrap_or_default(),
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
                    tracing::error!(error = ?e, id, "admin: secret rotation reveal store failed");
                    return render_admin_error(
                        &state,
                        "Secret rotated — reveal failed",
                        "The secret was rotated, but we couldn't stage it for one-shot \
                         display. Rotate again to retrieve a fresh value.",
                    );
                }
            };
            Redirect::to(&with_org(
                &format!(
                    "/admin/clients/{}?reveal={}",
                    ory_client::apis::urlencode(&id),
                    ory_client::apis::urlencode(&token),
                ),
                &scope,
            ))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: rotate_client_secret failed");
            render_admin_error(
                &state,
                "Rotate failed",
                &format!("Could not rotate client secret: {e}"),
            )
        }
    }
}
