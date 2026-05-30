//! Kratos account-recovery flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::cookies;
use crate::flow_view::*;
use crate::ory::{self, FlowFetch, FlowKind};
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, FlowQuery};

#[derive(Template)]
#[template(path = "recovery.html")]
struct RecoveryTemplate {
    chrome: PageChrome,
    form_action: String,
    form_method: String,
    flow_messages: Vec<MessageView>,
    groups: GroupedNodes,
    has_visible_default: bool,
    state: String,
    return_to_qs: String,
}

pub(crate) async fn recovery(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    Chrome(chrome): Chrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);

    let Some(flow_id) = query.flow.as_deref() else {
        let url = ory::kratos::browser_init_url(
            FlowKind::Recovery,
            &state.cfg.kratos.public_url,
            query.return_to.as_deref(),
        );
        return Redirect::to(&url).into_response();
    };

    match ory::kratos::get_flow(&state.ory, FlowKind::Recovery, flow_id, &cookie).await {
        Ok(FlowFetch::Ok(flow)) => render_recovery(chrome, &flow, query.return_to.as_deref()),
        Ok(FlowFetch::Gone) | Ok(FlowFetch::PrivilegedRequired(_)) => {
            let url = ory::kratos::browser_init_url(
                FlowKind::Recovery,
                &state.cfg.kratos.public_url,
                query.return_to.as_deref(),
            );
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, flow_id, "failed to fetch Kratos recovery flow");
            render_error_boundary(
                &state,
                "Recovery unavailable",
                crate::web::AUTH_UNAVAILABLE_BODY,
                "/login",
                "Sign in",
            )
            .into_response()
        }
    }
}

fn render_recovery(
    chrome: PageChrome,
    flow: &serde_json::Value,
    return_to: Option<&str>,
) -> Response {
    let (form_action, form_method) = form_target(flow);
    let mut groups = group_nodes(flow);
    mark_primary_submits(&mut groups, FlowKind::Recovery);
    let has_visible_default = has_visible_default_inputs(&groups);

    render(&RecoveryTemplate {
        chrome,
        form_action,
        form_method,
        flow_messages: flow_messages(flow),
        groups,
        has_visible_default,
        state: flow_state(flow).to_string(),
        return_to_qs: return_to_qs(return_to.or_else(|| flow_return_to(flow))),
    })
}
