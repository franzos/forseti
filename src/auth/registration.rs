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
use crate::ory::{self, FlowFetch, FlowKind};
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
    form_action: String,
    form_method: String,
    flow_messages: Vec<MessageView>,
    groups: GroupedNodes,
    has_visible_default: bool,
    return_to_qs: String,
    /// Same WebAuthn / passkey helper script that login + settings emit.
    /// Required when the registration flow includes a passkey enrollment
    /// button, otherwise `window.oryPasskeyRegistration` is undefined.
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
    // Pre-fill source: explicit ?prefill_email= wins over the cookie
    // dropped by /claim-email/confirm. Either way, when present we'll
    // also emit a Set-Cookie to clear the cookie one-shot.
    let prefill_email = prefill
        .prefill_email
        .or_else(|| cookies::read_cookie(&headers, "forseti_prefill_email"));

    // An existing session means "you don't need /registration". We split
    // the two non-None outcomes apart: a fully-authenticated session goes
    // straight to `return_to`, but an `InsufficientAal` session must be
    // routed through `/login?aal=aal2` so the user gets an AAL2 step-up
    // rather than landing on a protected page (e.g. `/admin/*`) with an
    // AAL1 session.
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

    let Some(flow_id) = query.flow.as_deref() else {
        let url = ory::kratos::browser_init_url(
            FlowKind::Registration,
            &state.cfg.kratos.public_url,
            query.return_to.as_deref(),
        );
        let secure = state.cfg.self_.is_https();
        return csrf::attach_csrf(
            Redirect::to(&url).into_response(),
            Some(csrf::delete_csrf_cookie(secure)),
        );
    };

    match ory::kratos::get_flow(&state.ory, FlowKind::Registration, flow_id, &cookie).await {
        Ok(FlowFetch::Ok(flow)) => {
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
        Ok(FlowFetch::Gone) | Ok(FlowFetch::PrivilegedRequired(_)) => {
            let url = ory::kratos::browser_init_url(
                FlowKind::Registration,
                &state.cfg.kratos.public_url,
                query.return_to.as_deref(),
            );
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, flow_id, "failed to fetch Kratos registration flow");
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

/// Append a `Set-Cookie: forseti_prefill_email=; Max-Age=0` directive
/// so the one-shot prefill cookie from `/claim-email/confirm` is
/// consumed on the next render.
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
    let (form_action, form_method) = form_target(flow);
    let mut groups = group_nodes(flow);
    mark_primary_submits(&mut groups, FlowKind::Registration);
    // Pre-populate the `traits.email` input when the caller landed here
    // from a flow that already proved ownership of the address (currently
    // `/claim-email/confirm`). The value Kratos persists on flow init is
    // empty; we overwrite it here rather than re-initialising the flow.
    if let Some(email) = prefill_email.filter(|s| !s.is_empty()) {
        for group in [
            &mut groups.profile,
            &mut groups.password,
            &mut groups.default,
        ] {
            for node in group.iter_mut() {
                if node.name == "traits.email" && node.value.is_empty() {
                    node.value = email.to_string();
                }
            }
        }
    }
    let has_visible_default = has_visible_default_inputs(&groups);
    let webauthn_scripts = collect_webauthn_scripts(flow);

    render(&RegistrationTemplate {
        chrome,
        form_action,
        form_method,
        flow_messages: flow_messages(flow),
        groups,
        has_visible_default,
        return_to_qs: return_to_qs(return_to.or_else(|| flow_return_to(flow))),
        webauthn_scripts,
    })
}
