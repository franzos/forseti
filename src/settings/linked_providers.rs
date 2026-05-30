//! `/settings/linked-providers` — link / unlink upstream OIDC providers.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::flow_view::{
    collect_default_hidden, collect_input_nodes, flow_messages, form_target, session_email,
    InputView, MessageView,
};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;
use crate::FlowQuery;

use super::{fetch_settings_subpage, SettingsSection};

#[derive(Template)]
#[template(path = "settings_linked_providers.html")]
pub(crate) struct SettingsLinkedProvidersTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    /// CSRF / method hiddens forwarded from the flow's `default` group.
    pub(crate) hidden_defaults: Vec<InputView>,
    /// OIDC-group nodes — one submit button per provider (link / unlink).
    pub(crate) oidc_nodes: Vec<InputView>,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

pub(crate) async fn settings_linked_providers(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: crate::extractors::Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    match fetch_settings_subpage(
        &state,
        &headers,
        &query,
        SettingsSection::LinkedProviders,
        &sess,
    )
    .await
    {
        Ok((session, flow)) => render_linked_providers(&state, &csrf.0, &session, &flow, banner.0),
        Err(resp) => resp,
    }
}

fn render_linked_providers(
    state: &AppState,
    csrf_token: &str,
    session: &ory::Session,
    flow: &serde_json::Value,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
) -> Response {
    let (form_action, form_method) = form_target(flow);
    let hidden_defaults = collect_default_hidden(flow);
    let mut oidc_nodes = collect_input_nodes(flow, "oidc");
    // Every provider button should look the same — render them as secondary
    // (outline) buttons rather than promoting one to primary.
    for n in oidc_nodes.iter_mut() {
        n.is_primary = false;
    }

    render(&SettingsLinkedProvidersTemplate {
        chrome: PageChrome::from_parts(state, session_email(session), csrf_token.to_string()),
        form_action,
        form_method,
        flow_messages: flow_messages(flow),
        hidden_defaults,
        oidc_nodes,
        referrer_banner,
    })
}
