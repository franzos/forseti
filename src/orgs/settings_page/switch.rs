//! `/orgs/switch` — active-org cookie POST. Sets the `active_org` cookie
//! after verifying the caller is a member of the target org.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::csrf::CsrfForm;
use crate::extractors::RequireSession;
use crate::orgs;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(super) struct SwitchForm {
    org_id: String,
    #[serde(default)]
    return_to: Option<String>,
}

pub(super) async fn switch_active_org(
    State(state): State<AppState>,
    sess: RequireSession,
    CsrfForm(form): CsrfForm<SwitchForm>,
) -> Response {
    let identity_id = sess.identity_id;
    if !orgs::is_member(&state.db, &identity_id, &form.org_id).await {
        return (StatusCode::FORBIDDEN, "not a member of that org").into_response();
    }
    let secure = state.cfg.self_.is_https();
    let set_cookie = orgs::cookie::set_active_org_cookie(
        &state.cookie_secret,
        state.cfg.orgs.active_org_cookie_ttl_seconds,
        &form.org_id,
        secure,
    );
    let target = crate::web::safe_return_to(&state.cfg, form.return_to.as_deref().unwrap_or("/"))
        .to_string();
    let mut resp = Redirect::to(&target).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&set_cookie) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
    resp
}
