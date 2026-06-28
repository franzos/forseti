//! Kratos registration flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::cookies;
use crate::csrf;
use crate::extractors::OptionalSession;
use crate::flow_view::*;
use crate::ory::kratos::FlowOutcome;
use crate::ory::{self, FlowKind};
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, safe_return_to, FlowQuery};

#[derive(Debug, Deserialize)]
pub(crate) struct PrefillQuery {
    pub(crate) prefill_email: Option<String>,
}

#[derive(Template)]
#[template(path = "registration.html")]
struct RegistrationTemplate {
    chrome: PageChrome,
    form: FlowFormView,
    /// WebAuthn / passkey helper script; without it the passkey enrollment
    /// button's `window.oryPasskeyRegistration` is undefined.
    webauthn_scripts: Vec<ScriptView>,
}

pub(crate) async fn registration(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    Query(prefill): Query<PrefillQuery>,
    headers: HeaderMap,
    session: OptionalSession,
    Chrome(chrome): Chrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    // Explicit ?prefill_email= wins over the one-shot cookie dropped by
    // /claim-email/confirm, which we clear on render.
    let prefill_email = prefill
        .prefill_email
        .or_else(|| cookies::read_cookie(&headers, "forseti_prefill_email"));

    // Already-authenticated sessions skip /registration. An InsufficientAal
    // session routes through /login?aal=aal2 instead of landing on a protected
    // page (e.g. /admin/*) with an AAL1 session.
    match session {
        OptionalSession::Ok { .. } => {
            let target = safe_return_to(&state.cfg, query.return_to.as_deref().unwrap_or("/"));
            return Redirect::to(target).into_response();
        }
        OptionalSession::InsufficientAal => {
            let target = safe_return_to(&state.cfg, query.return_to.as_deref().unwrap_or("/"));
            return Redirect::to(&crate::auth::aal2_step_up_url(target)).into_response();
        }
        OptionalSession::None => {}
    }

    let flow_id = query.flow.as_deref();
    let init_url = || {
        ory::kratos::browser_init_url(
            FlowKind::Registration,
            &state.cfg.kratos.public_url,
            query.return_to.as_deref(),
        )
    };

    match ory::kratos::resolve_flow(&state.ory, FlowKind::Registration, flow_id, &cookie).await {
        FlowOutcome::Init => {
            let secure = state.cfg.self_.is_https();
            csrf::attach_csrf(
                Redirect::to(&init_url()).into_response(),
                Some(csrf::delete_csrf_cookie(secure)),
            )
        }
        FlowOutcome::Ready(flow) => {
            let mut resp = render_registration(
                chrome,
                &flow,
                query.return_to.as_deref(),
                prefill_email.as_deref(),
            );
            if prefill_email.is_some() {
                attach_prefill_clear_cookie(&mut resp, state.cfg.self_.is_https());
            }
            resp
        }
        FlowOutcome::Reinit | FlowOutcome::Privileged(_) => {
            Redirect::to(&init_url()).into_response()
        }
        FlowOutcome::Error(e) => {
            tracing::error!(error = ?e, ?flow_id, "failed to fetch Kratos registration flow");
            render_error_boundary(
                &state,
                "Sign-up unavailable",
                crate::web::AUTH_UNAVAILABLE_BODY,
                "/registration",
                "Try again",
            )
            .into_response()
        }
    }
}

/// Clear the one-shot prefill cookie from `/claim-email/confirm`.
fn attach_prefill_clear_cookie(resp: &mut Response, secure: bool) {
    let secure_attr = if secure { "; Secure" } else { "" };
    let header = format!(
        "forseti_prefill_email=; Path=/registration; Max-Age=0; HttpOnly; SameSite=Lax{secure_attr}"
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&header) {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
}

fn render_registration(
    chrome: PageChrome,
    flow: &serde_json::Value,
    return_to: Option<&str>,
    prefill_email: Option<&str>,
) -> Response {
    let mut form = FlowFormView::from_flow(flow, FlowKind::Registration, return_to);
    // Overwrite the empty `traits.email` Kratos persists on flow init rather
    // than re-initialising the flow. Only mutates `value`, so the already-computed
    // `has_visible_default` (keyed on `input_type`) is unaffected.
    if let Some(email) = prefill_email.filter(|s| !s.is_empty()) {
        for group in [
            &mut form.groups.profile,
            &mut form.groups.password,
            &mut form.groups.default,
        ] {
            for node in group.iter_mut() {
                if node.name == "traits.email" && node.value.is_empty() {
                    node.value = email.to_string();
                }
            }
        }
    }
    let webauthn_scripts = collect_webauthn_scripts(flow);

    render(&RegistrationTemplate {
        chrome,
        form,
        webauthn_scripts,
    })
}
