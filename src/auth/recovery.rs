//! Kratos account-recovery flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::cookies;
use crate::flow_view::*;
use crate::ory::kratos::FlowOutcome;
use crate::ory::{self, FlowKind};
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, FlowQuery};

#[derive(Template)]
#[template(path = "recovery.html")]
struct RecoveryTemplate {
    chrome: PageChrome,
    form: FlowFormView,
    state: String,
}

pub(crate) async fn recovery(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    Chrome(chrome): Chrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let flow_id = query.flow.as_deref();
    let init_url = || {
        ory::kratos::browser_init_url(
            FlowKind::Recovery,
            &state.cfg.kratos.public_url,
            query.return_to.as_deref(),
        )
    };

    match ory::kratos::resolve_flow(&state.ory, FlowKind::Recovery, flow_id, &cookie).await {
        FlowOutcome::Init | FlowOutcome::Reinit | FlowOutcome::Privileged(_) => {
            Redirect::to(&init_url()).into_response()
        }
        FlowOutcome::Ready(flow) => render_recovery(chrome, &flow, query.return_to.as_deref()),
        FlowOutcome::Error(e) => {
            tracing::error!(error = ?e, ?flow_id, "failed to fetch Kratos recovery flow");
            render_error_boundary(
                &state,
                &chrome.locale,
                &crate::i18n::lookup(&chrome.locale, "error-boundary-recovery-title"),
                &crate::i18n::lookup(&chrome.locale, "error-boundary-auth-unavailable-body"),
                "/login",
                crate::i18n::lookup(&chrome.locale, "error-boundary-cta-sign-in"),
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
    let form = FlowFormView::from_flow(flow, FlowKind::Recovery, return_to, &chrome.locale);
    render(&RecoveryTemplate {
        chrome,
        form,
        state: flow_state(flow).to_string(),
    })
}
