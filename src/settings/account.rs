//! `/settings/account` — danger zone (account self-deletion).
//!
//! The deletion itself is `identity::delete::delete_identity`; this module
//! owns the confirm page, the typed-email check and the error rendering.
//!
//! Privileged-session enforcement reuses the `?refresh=true` gate from
//! `/settings/password` (a Kratos settings flow as a "is this session
//! privileged?" probe), because Kratos's admin delete doesn't enforce re-auth.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Deserialize;

use crate::FlowQuery;
use crate::audit::{AuditCtx, SafeMetadata};
use crate::csrf;
use crate::flow_view::session_email;
use crate::identity::delete::{
    CollectStep, DeleteActor, DeleteEnv, DeleteError, DeleteReason, DeleteRequest, delete_identity,
    notified_clients,
};
use crate::locale::LanguageIdentifier;
use crate::ory;
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::state::AppState;

use super::{SettingsSection, fetch_settings_subpage};

/// One app shown on the delete-confirm card as a notification target.
#[derive(Debug, Clone)]
pub(crate) struct NotifiedApp {
    pub(crate) name: String,
}

#[derive(Template)]
#[template(path = "settings_account.html")]
struct SettingsAccountTemplate {
    chrome: PageChrome,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

#[derive(Template)]
#[template(path = "settings_account_delete_confirm.html")]
struct SettingsAccountDeleteConfirmTemplate {
    chrome: PageChrome,
    notified_apps: Vec<NotifiedApp>,
    /// Threaded through the form action so the POST re-runs the same
    /// privileged-session check; without it the POST bounces through a fresh
    /// Kratos init and loses the form body.
    flow_id: String,
    /// `[audit].audit_retention_days`, shown on the "what we keep" card.
    retention_days: String,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

/// Danger-zone landing page; the privileged-session check is deferred to the
/// confirm page.
pub(crate) async fn settings_account(
    _sess: crate::extractors::RequireSession,
    banner: crate::handoff::ReferrerBanner,
    themed: ThemedChrome,
) -> Response {
    render(&SettingsAccountTemplate {
        chrome: themed.chrome,
        referrer_banner: banner.0,
    })
}

/// Delete-confirm page; gated behind the privileged-session refresh window.
pub(crate) async fn settings_account_delete(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
) -> Response {
    let (session, flow) = match fetch_settings_subpage(
        &state,
        &headers,
        &query,
        SettingsSection::Account,
        &sess,
        &locale,
    )
    .await
    {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let user_id = session
        .identity
        .as_ref()
        .map(|i| i.id.clone())
        .unwrap_or_default();
    let notified_apps = list_apps_to_notify(&state, &user_id).await;
    let flow_id = flow
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    render(&SettingsAccountDeleteConfirmTemplate {
        chrome: themed.chrome,
        notified_apps,
        flow_id,
        retention_days: state.cfg.audit.audit_retention_days.to_string(),
        referrer_banner: banner.0,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteForm {
    /// Typed-email confirmation so a stray click can't trigger the delete.
    #[serde(default)]
    pub(crate) confirm_email: String,
}

/// `POST /settings/account/delete` — runs the outbox saga.
pub(crate) async fn settings_account_delete_submit(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    csrf::CsrfForm(form): csrf::CsrfForm<DeleteForm>,
) -> Response {
    // Re-run the privileged gate in case the window lapsed between confirm and
    // submit.
    let session = match fetch_settings_subpage(
        &state,
        &headers,
        &query,
        SettingsSection::Account,
        &sess,
        &locale,
    )
    .await
    {
        Ok((session, _)) => session,
        Err(resp) => return resp,
    };

    // Typed-email confirm must match the session's email.
    let session_email_str = session_email(&session);
    if !form
        .confirm_email
        .trim()
        .eq_ignore_ascii_case(&session_email_str)
    {
        tracing::warn!(
            actor = %session_email_str,
            "account.self_delete rejected: confirm_email mismatch"
        );
        return Redirect::to("/settings/account/delete").into_response();
    }

    run_delete_saga(&state, &session, &actx, &locale).await
}

async fn run_delete_saga(
    state: &AppState,
    session: &ory::Session,
    actx: &AuditCtx,
    locale: &LanguageIdentifier,
) -> Response {
    let Some(identity) = session.identity.as_ref() else {
        tracing::error!("session has no identity; refusing self-delete");
        return render_delete_failure(
            state,
            locale,
            &crate::i18n::lookup(locale, "error-boundary-account-delete-bad-session"),
        );
    };
    let user_id = identity.id.clone();
    let actor_email = session_email(session);

    let env = DeleteEnv::from_state(state);
    let req = DeleteRequest {
        identity_id: user_id.clone(),
        reason: DeleteReason::SelfService,
        actor: DeleteActor::User {
            id: user_id.clone(),
            email: actor_email.clone(),
        },
        force: false,
        ctx: Some(actx.clone()),
        metadata: SafeMetadata::empty(),
    };
    let failure_key = match delete_identity(&env, req).await {
        Ok(_) => {
            // Clear the now-stale Kratos session cookie the browser still
            // holds, so it isn't carried back to a surface that hasn't yet
            // observed the 401.
            let mut response = Redirect::to("/login?msg=account_deleted").into_response();
            let secure = state.cfg.self_.is_https();
            if let Ok(hv) = axum::http::HeaderValue::from_str(&clear_kratos_session_cookie(secure))
            {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, hv);
            }
            if let Ok(hv) = axum::http::HeaderValue::from_str(&csrf::delete_csrf_cookie(secure)) {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, hv);
            }
            return response;
        }
        Err(DeleteError::SoleOwner(names)) => {
            let names = names.join(", ");
            tracing::warn!(
                actor = %actor_email,
                user_id = %user_id,
                orgs = %names,
                "account self-delete blocked: sole owner of org(s) with other members"
            );
            let mut args: std::collections::HashMap<
                std::borrow::Cow<'static, str>,
                fluent_templates::fluent_bundle::FluentValue,
            > = std::collections::HashMap::new();
            args.insert(std::borrow::Cow::Borrowed("names"), names.into());
            return render_delete_failure(
                state,
                locale,
                &crate::i18n::lookup_args(
                    locale,
                    "error-boundary-account-delete-sole-owner",
                    &args,
                ),
            );
        }
        Err(e @ DeleteError::Guard(_)) => {
            tracing::error!(error = %e, user_id = %user_id, "self-delete aborted before destructive call");
            "error-boundary-account-delete-ownership-check-failed"
        }
        Err(e @ DeleteError::Collect(CollectStep::Consents, _)) => {
            tracing::error!(error = %e, user_id = %user_id, "self-delete aborted before destructive call");
            "error-boundary-account-delete-consent-unreachable"
        }
        Err(e @ DeleteError::Collect(CollectStep::Identity, _)) => {
            tracing::error!(error = %e, user_id = %user_id, "self-delete aborted before destructive call");
            "error-boundary-account-delete-failed"
        }
        Err(e @ DeleteError::Outbox(_)) => {
            tracing::error!(error = %e, user_id = %user_id, "self-delete aborted before destructive call");
            "error-boundary-account-delete-notifications-failed"
        }
        Err(e @ DeleteError::Kratos(_)) => {
            tracing::error!(error = %e, actor = %actor_email, user_id = %user_id, "kratos admin delete failed");
            "error-boundary-account-delete-failed"
        }
    };
    render_delete_failure(state, locale, &crate::i18n::lookup(locale, failure_key))
}

/// For the confirm-page card list (names only). A Hydra failure yields an
/// empty list here; the write path refuses instead.
async fn list_apps_to_notify(state: &AppState, user_id: &str) -> Vec<NotifiedApp> {
    match notified_clients(&state.ory, user_id).await {
        Ok(clients) => clients
            .into_iter()
            .map(|c| NotifiedApp { name: c.name })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, user_id, "could not list consent sessions");
            Vec::new()
        }
    }
}

fn render_delete_failure(state: &AppState, locale: &LanguageIdentifier, body: &str) -> Response {
    crate::web::render_error_boundary(
        state,
        locale,
        &crate::i18n::lookup(locale, "error-boundary-account-deletion-title"),
        body,
        "/settings/account",
        crate::i18n::lookup(locale, "error-boundary-cta-back-to-account"),
    )
    .into_response()
}

/// Clear the `ory_kratos_session` cookie. Attributes match what Kratos emits
/// in the path-prefixed single-host topology so the browser overwrites it.
///
/// In a split-origin deployment (Kratos on a separate host/subdomain) the
/// browser scopes Kratos's cookie to Kratos's origin, so this is a no-op until
/// the next request to Kratos returns 401. Documented limitation of the proxy
/// shape.
fn clear_kratos_session_cookie(secure: bool) -> String {
    let mut s = Cookie::build(("ory_kratos_session", ""))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .build()
        .to_string();
    // Fixed epoch `Expires` (not `Max-Age=0`) to avoid a time-formatting dep,
    // matching `clear_flash_cookie`.
    s.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    s
}
