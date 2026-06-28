//! `POST /accounts/switch` — tear down the current Kratos session, verify it
//! is gone, clear the active-org pin, audit, and redirect to a fresh login
//! prefilled for the target identity.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::Router;
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::cookies;
use crate::csrf::CsrfForm;
use crate::orgs;
use crate::ory;
use crate::ory::kratos::WhoamiOutcome;
use crate::state::AppState;
use crate::web::append_set_cookie;

#[derive(Debug, Deserialize)]
pub(crate) struct SwitchForm {
    /// Kratos identity UUID to prefill on the login page after teardown.
    #[serde(default)]
    target_id: String,
    #[serde(default)]
    return_to: Option<String>,
}

/// `POST /accounts/switch` — log the current session out server-side, confirm
/// it is gone, clear the active-org pin, audit the switch, and redirect to
/// `/login` with a `login_hint` seeded from `target_id`.
pub(crate) async fn switch(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<SwitchForm>,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let secure = state.cfg.self_.is_https();

    // Capture the actor's identity before teardown so the audit row records who
    // initiated the switch even after the session is gone.
    let actor_id = match ory::kratos::whoami(&state.ory, Some(&cookie)).await {
        Ok(WhoamiOutcome::Ok(session)) => session
            .identity
            .as_ref()
            .map(|i| i.id.clone())
            .unwrap_or_default(),
        _ => String::new(),
    };

    ory::kratos::tear_down_session(&state.ory, &cookie).await;

    // Security gate: re-check whoami after teardown. If the session is still
    // live, something is wrong on the Kratos side; do NOT redirect to login
    // (that would re-grant the old account). Abort to /error instead.
    match ory::kratos::whoami(&state.ory, Some(&cookie)).await {
        Ok(WhoamiOutcome::None) | Ok(WhoamiOutcome::InsufficientAal) => {}
        Ok(WhoamiOutcome::Ok(_)) => {
            tracing::error!(
                actor_id = %actor_id,
                "account switch: session still live after teardown; aborting"
            );
            return Redirect::to("/error").into_response();
        }
        Err(e) => {
            tracing::error!(error = ?e, "account switch: post-teardown whoami check failed");
            return Redirect::to("/error").into_response();
        }
    }

    // Session is confirmed gone; clear the active-org pin on the success path only.
    let clear_org = orgs::cookie::clear_active_org_cookie(secure);

    let mut resp = build_login_redirect(&state, &form.target_id, form.return_to.as_deref());
    append_set_cookie(&mut resp, Some(clear_org));

    let ev = AuditEvent::new(action::ACCOUNT_SWITCHED)
        .actor_user(&actor_id, "")
        .target(target_kind::IDENTITY, &form.target_id)
        .with_ctx(&actx);
    let _ = audit::log(&state.db, ev).await;

    resp
}

/// Build a `/login` redirect with optional `return_to` (validated) and
/// `login_hint` (the target identity id, URL-encoded).
fn build_login_redirect(state: &AppState, target_id: &str, return_to: Option<&str>) -> Response {
    let mut qs = String::new();

    let rt = return_to
        .filter(|r| !r.is_empty())
        .map(|r| crate::safe_return_to(&state.cfg, r));
    if let Some(rt) = rt {
        qs.push_str("?return_to=");
        qs.push_str(&ory_client::apis::urlencode(rt));
    }

    if !target_id.is_empty() {
        if qs.is_empty() {
            qs.push('?');
        } else {
            qs.push('&');
        }
        qs.push_str("login_hint=");
        qs.push_str(&ory_client::apis::urlencode(target_id));
    }

    Redirect::to(&format!("/login{qs}")).into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct ForgetForm {
    identity_id: String,
    return_to: Option<String>,
}

/// Remove one remembered account (or all, when `identity_id == "*"`) from this
/// device's chooser list.
pub(crate) async fn forget(
    State(state): State<AppState>,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<ForgetForm>,
) -> Response {
    let secure = state.cfg.self_.is_https();
    let ttl = state.cfg.accounts.known_accounts_cookie_ttl_seconds;
    let dest = crate::safe_return_to(&state.cfg, form.return_to.as_deref().unwrap_or("/")).to_string();

    let set_cookie = if form.identity_id == "*" {
        crate::accounts::cookie::clear_known_accounts_cookie(secure)
    } else {
        let ids = crate::accounts::cookie::read_known_account_ids(&headers, &state.cookie_secret, ttl);
        let next = crate::accounts::cookie::remove(ids, &form.identity_id);
        crate::accounts::cookie::set_known_accounts_cookie(&state.cookie_secret, ttl, &next, secure)
    };

    let mut resp = Redirect::to(&dest).into_response();
    crate::web::append_set_cookie(&mut resp, Some(set_cookie));
    resp
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/accounts/switch", post(switch))
        .route("/accounts/forget", post(forget))
}
