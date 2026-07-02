//! `/settings/password` — change the account's password. Also serves the
//! focused recovery hand-off variant when Kratos's
//! `recovery.after.password` hook issues a fresh settings flow.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::flow_view::{GroupedNodes, MessageView};
use crate::page_chrome::PageChrome;
use crate::state::AppState;
use crate::FlowQuery;

use super::{settings_subpage, InlineRenderSection};

#[derive(Template)]
#[template(path = "settings_password.html")]
pub(crate) struct SettingsPasswordTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    pub(crate) groups: GroupedNodes,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

/// Focused-mode template for the `recovery.after.password` hand-off: strips
/// chrome so the user can only finish the password change or sign out.
#[derive(Template)]
#[template(path = "settings_password_handoff.html")]
pub(crate) struct SettingsPasswordHandoffTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    pub(crate) groups: GroupedNodes,
    /// RFC3339 deadline for the privileged session. The page's JS counts
    /// down to this. `None` when we couldn't parse `flow.issued_at` — the
    /// page falls back to a static "15 minutes" hint.
    pub(crate) privileged_deadline: Option<String>,
}

pub(crate) async fn settings_password(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: crate::extractors::Csrf,
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    // SSO arrivals get dumped here by the recovery redemption; the
    // breadcrumb marks them for a bounce to the dashboard instead.
    if crate::cookies::read_cookie(&headers, "forseti_sso_arrival").is_some() {
        let secure = if state.cfg.self_.is_https() {
            "; Secure"
        } else {
            ""
        };
        let mut resp = Redirect::to("/").into_response();
        crate::web::append_set_cookie(
            &mut resp,
            Some(format!(
                "forseti_sso_arrival=; Path=/settings; Max-Age=0; HttpOnly; SameSite=Lax{secure}"
            )),
        );
        return resp;
    }
    settings_subpage(
        &state,
        &headers,
        &csrf.0,
        &query,
        InlineRenderSection::Password,
        &sess,
        banner,
        false,
        locale,
    )
    .await
}
