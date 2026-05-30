//! Kratos login flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::cookies;
use crate::csrf;
use crate::extractors::OptionalSession;
use crate::flow_view::*;
use crate::ory::{self, FlowFetch, FlowKind};
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, safe_return_to, FlowQuery};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    chrome: PageChrome,
    form_action: String,
    form_method: String,
    flow_messages: Vec<MessageView>,
    groups: GroupedNodes,
    has_visible_default: bool,
    return_to_qs: String,
    /// `script` nodes from the webauthn / passkey groups. Kratos serves a
    /// helper at `/.well-known/ory/webauthn.js` that registers
    /// `window.oryWebAuthnLogin`, `window.oryPasskeyLogin`, etc. — those
    /// functions are what the trigger buttons' `onclick` calls. Without the
    /// `<script>` tag in the rendered page, the functions don't exist and
    /// clicking a webauthn/passkey button throws "is not a function".
    webauthn_scripts: Vec<ScriptView>,
    /// True when this flow is asking for AAL2 but the identity has no second
    /// factor enrolled — Kratos returns a flow with the "complete the second
    /// authentication challenge" message but no input nodes to satisfy it,
    /// leaving the user stuck. The template detects this and shows an
    /// explanatory CTA pointing at `/settings/2fa` instead.
    aal2_unavailable: bool,
}

pub(crate) async fn login(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    session: OptionalSession,
    Chrome(chrome): Chrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let requested_aal = query.aal.as_deref().filter(|s| !s.is_empty());
    let refresh = matches!(query.refresh, Some(true));

    // 1. Already signed in? Normally bounce to `return_to` or `/`.
    //
    // Two carve-outs short-circuit the short-circuit:
    //   * `aal` requested AND the session's current AAL doesn't satisfy it
    //     (step-up flow — e.g. an OAuth client demands `acr_values=aal2`
    //     and the user is at aal1). Without this, the user loops between
    //     `/oauth/login` (sees aal1, redirects to /login?aal=aal2) and
    //     `/login` (sees a valid session, redirects back to /oauth/login).
    //   * `refresh=true` (privileged-session re-auth — e.g. /settings/password
    //     hit `session_refresh_required` and bounced through here). Without
    //     this the user livelocks at `privileged_session_max_age` because
    //     the session is technically valid and the handler keeps bouncing
    //     them off.
    //
    // In both cases we fall through to the Kratos init redirect with the
    // `aal` / `refresh` parameters preserved; Kratos then demands the
    // appropriate credential and issues a stronger / refreshed session.
    if let Some(session) = session.ok() {
        let session_aal = ory::kratos::session_aal_string(session);
        let aal_mismatch = requested_aal.map(|a| a != session_aal).unwrap_or(false);
        // Also skip the short-circuit when a flow ID is present — Kratos
        // bakes `refresh=true` into the flow's server-side context after a
        // `session_refresh_required` bounce, so we won't see it in the URL.
        // Always render the flow when one was passed in.
        if !refresh && !aal_mismatch && query.flow.is_none() {
            let target = safe_return_to(&state.cfg, query.return_to.as_deref().unwrap_or("/"));
            return Redirect::to(target).into_response();
        }
    }

    // 2. No flow yet — kick off a Kratos browser flow with the requested
    //    `aal` / `refresh` parameters preserved.
    let Some(flow_id) = query.flow.as_deref() else {
        let url = ory::kratos::browser_init_url_with(
            FlowKind::Login,
            &state.cfg.kratos.public_url,
            query.return_to.as_deref(),
            requested_aal,
            query.refresh,
        );
        let secure = state.cfg.self_.is_https();
        return csrf::attach_csrf(
            Redirect::to(&url).into_response(),
            Some(csrf::delete_csrf_cookie(secure)),
        );
    };

    // 3. Flow ID present — fetch it, render it.
    match ory::kratos::get_flow(&state.ory, FlowKind::Login, flow_id, &cookie).await {
        Ok(FlowFetch::Ok(flow)) => render_login(chrome, &flow, query.return_to.as_deref()),
        Ok(FlowFetch::Gone) | Ok(FlowFetch::PrivilegedRequired(_)) => {
            let url = ory::kratos::browser_init_url_with(
                FlowKind::Login,
                &state.cfg.kratos.public_url,
                query.return_to.as_deref(),
                requested_aal,
                query.refresh,
            );
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, flow_id, "failed to fetch Kratos login flow");
            render_error_boundary(
                &state,
                "Sign-in unavailable",
                crate::web::AUTH_UNAVAILABLE_BODY,
                "/login",
                "Try again",
            )
            .into_response()
        }
    }
}

fn render_login(chrome: PageChrome, flow: &serde_json::Value, return_to: Option<&str>) -> Response {
    let (form_action, form_method) = form_target(flow);
    let mut groups = group_nodes(flow);
    mark_primary_submits(&mut groups, FlowKind::Login);
    let has_visible_default = has_visible_default_inputs(&groups);
    let webauthn_scripts = collect_webauthn_scripts(flow);

    // AAL2 step-up requested but no second factor available. Detect by:
    //   1. flow.requested_aal == "aal2"
    //   2. no method group has any non-hidden actionable input
    // Kratos still emits the "complete the second authentication challenge"
    // message in this case, but provides no way to actually do so — so we
    // surface a CTA to enrol 2FA instead of leaving the user staring at a
    // blank form.
    let requested_aal2 = flow
        .get("requested_aal")
        .and_then(|v| v.as_str())
        .map(|s| s == "aal2")
        .unwrap_or(false);
    let any_actionable_method = !groups.oidc.is_empty()
        || !groups.code.is_empty()
        || !groups.password.is_empty()
        || groups
            .other
            .iter()
            .any(|n| n.input_type != "hidden" && n.name != "method");
    let aal2_unavailable = requested_aal2 && !any_actionable_method;

    render(&LoginTemplate {
        chrome,
        form_action,
        form_method,
        flow_messages: flow_messages(flow),
        groups,
        has_visible_default,
        return_to_qs: return_to_qs(return_to.or_else(|| flow_return_to(flow))),
        webauthn_scripts,
        aal2_unavailable,
    })
}
