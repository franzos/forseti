//! `/settings/linked-providers` — link / unlink upstream OIDC providers.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::flow_view::{
    collect_default_hidden, collect_input_nodes, flow_messages, form_target, session_email,
    translate_inputs, translate_messages, InputView, MessageView,
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
    pub(crate) hidden_defaults: Vec<InputView>,
    /// OIDC-group nodes: one submit button per provider (link / unlink).
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
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    match fetch_settings_subpage(
        &state,
        &headers,
        &query,
        SettingsSection::LinkedProviders,
        &sess,
        &locale,
    )
    .await
    {
        Ok((session, flow)) => {
            render_linked_providers(&state, &csrf.0, &session, &flow, banner.0, locale)
        }
        Err(resp) => resp,
    }
}

fn render_linked_providers(
    state: &AppState,
    csrf_token: &str,
    session: &ory::Session,
    flow: &serde_json::Value,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
    locale: crate::locale::LanguageIdentifier,
) -> Response {
    let (form_action, form_method) = form_target(flow);
    let mut hidden_defaults = collect_default_hidden(flow);
    let mut oidc_nodes = collect_input_nodes(flow, "oidc");
    translate_inputs(&mut hidden_defaults, &locale);
    translate_inputs(&mut oidc_nodes, &locale);
    let mut msgs = flow_messages(flow);
    translate_messages(&mut msgs, &locale);
    // Render every provider button as secondary; none is promoted to primary.
    for n in oidc_nodes.iter_mut() {
        n.is_primary = false;
    }

    render(&SettingsLinkedProvidersTemplate {
        chrome: PageChrome::from_parts(
            state,
            session_email(session),
            csrf_token.to_string(),
            locale,
        ),
        form_action,
        form_method,
        flow_messages: msgs,
        hidden_defaults,
        oidc_nodes,
        referrer_banner,
    })
}
