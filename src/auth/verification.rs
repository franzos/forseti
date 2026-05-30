//! Kratos email-verification flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::cookies;
use crate::extractors::OptionalSession;
use crate::flow_view::*;
use crate::ory::{self, FlowFetch, FlowKind};
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, FlowQuery};

#[derive(Template)]
#[template(path = "verification.html")]
struct VerificationTemplate {
    chrome: PageChrome,
    form_action: String,
    form_method: String,
    flow_messages: Vec<MessageView>,
    groups: GroupedNodes,
    has_visible_default: bool,
    state: String,
    return_to_qs: String,
    /// `true` when the request carries a valid Kratos session — drives the
    /// footer's "Back to dashboard" vs "Back to sign in" branch.
    is_logged_in: bool,
}

pub(crate) async fn verification(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    session: OptionalSession,
    Chrome(chrome): Chrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);

    // Verification must work both for anonymous post-registration users
    // and for logged-in users who already know their email. The latter
    // case enables the auto-send short-circuit below (skip "type your
    // email" and go straight to code entry).
    let session_opt = session.ok();
    let is_logged_in = session_opt.is_some();

    let Some(flow_id) = query.flow.as_deref() else {
        let url = ory::kratos::browser_init_url(
            FlowKind::Verification,
            &state.cfg.kratos.public_url,
            query.return_to.as_deref(),
        );
        return Redirect::to(&url).into_response();
    };

    match ory::kratos::get_flow(&state.ory, FlowKind::Verification, flow_id, &cookie).await {
        Ok(FlowFetch::Ok(flow)) => {
            // If the user is logged in and the flow is sitting at
            // `choose_method` (the "type your email" step), Forseti
            // already knows the only address Kratos can legitimately
            // verify against this identity. Auto-submit it server-side
            // and bounce the browser to the same flow — which by then
            // will have transitioned to `sent_email`, dropping the user
            // straight into the code-entry screen. Any failure here
            // falls through to render the original form unchanged.
            if let Some(session) = session_opt {
                if flow_state(&flow) == "choose_method" && session_needs_verification(session) {
                    let email = session_email(session);
                    if !email.is_empty()
                        && submit_email_method(&state, &flow, &email, &cookie)
                            .await
                            .is_ok()
                    {
                        return Redirect::to(&format!(
                            "/verification?flow={}",
                            ory_client::apis::urlencode(flow_id)
                        ))
                        .into_response();
                    }
                }
            }
            render_verification(chrome, &flow, query.return_to.as_deref(), is_logged_in)
        }
        Ok(FlowFetch::Gone) | Ok(FlowFetch::PrivilegedRequired(_)) => {
            let url = ory::kratos::browser_init_url(
                FlowKind::Verification,
                &state.cfg.kratos.public_url,
                query.return_to.as_deref(),
            );
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, flow_id, "failed to fetch Kratos verification flow");
            render_error_boundary(
                &state,
                "Verification unavailable",
                crate::web::AUTH_UNAVAILABLE_BODY,
                "/login",
                "Sign in",
            )
            .into_response()
        }
    }
}

fn render_verification(
    chrome: PageChrome,
    flow: &serde_json::Value,
    return_to: Option<&str>,
    is_logged_in: bool,
) -> Response {
    let (form_action, form_method) = form_target(flow);
    let mut groups = group_nodes(flow);
    mark_primary_submits(&mut groups, FlowKind::Verification);
    let has_visible_default = has_visible_default_inputs(&groups);

    render(&VerificationTemplate {
        chrome,
        form_action,
        form_method,
        flow_messages: flow_messages(flow),
        groups,
        has_visible_default,
        state: flow_state(flow).to_string(),
        return_to_qs: return_to_qs(return_to.or_else(|| flow_return_to(flow))),
        is_logged_in,
    })
}

/// POST `email=<email>&method=code&csrf_token=<token>` to the flow's
/// `ui.action` URL, server-side, forwarding the user's cookies. Used to
/// skip the manual "type your email" step when we already know the
/// address from the session.
///
/// Returns `Ok(())` only on a successful state transition; any non-2xx
/// (CSRF mismatch, address not on identity, transport error, etc.) is
/// surfaced as `Err` so the caller can fall through to the regular
/// template render.
async fn submit_email_method(
    state: &AppState,
    flow: &serde_json::Value,
    email: &str,
    cookie: &str,
) -> anyhow::Result<()> {
    let action = flow
        .pointer("/ui/action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("verification flow missing ui.action"))?;
    let csrf = flow
        .pointer("/ui/nodes")
        .and_then(|n| n.as_array())
        .and_then(|nodes| {
            nodes.iter().find_map(|node| {
                if node.pointer("/attributes/name")?.as_str()? == "csrf_token" {
                    node.pointer("/attributes/value")?
                        .as_str()
                        .map(str::to_string)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| anyhow::anyhow!("verification flow missing csrf_token node"))?;

    let body = serde_json::json!({
        "method": "code",
        "email": email,
        "csrf_token": csrf,
    });

    let resp = state
        .ory
        .kratos_public
        .client
        .post(action)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::COOKIE, cookie)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos verification submit transport error: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "kratos verification submit returned {status}: {body}"
        ));
    }
    Ok(())
}
