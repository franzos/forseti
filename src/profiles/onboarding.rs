//! Post-signup "choose a username" step. `/oauth/login` sends a new account
//! here once, before accepting, when the app asked for `profile` and no handle
//! is set: an app that provisions local accounts from `preferred_username`
//! (Forgejo, Gitea) otherwise asks the user for one itself.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::AuditCtx;
use crate::csrf::CsrfForm;
use crate::extractors::RequireSession;
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;

/// Marker `/oauth/login` reads to skip the step for the rest of this flow.
const SKIP_PARAM: &str = "skip_username";

#[derive(Template)]
#[template(path = "onboarding_username.html")]
struct UsernameStepTemplate {
    chrome: PageChrome,
    return_to: String,
    skip_href: String,
    value: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UsernameStepQuery {
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UsernameStepForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    return_to: String,
}

pub(crate) async fn username_step_get(
    State(state): State<AppState>,
    sess: RequireSession,
    Chrome(chrome): Chrome,
    Query(q): Query<UsernameStepQuery>,
) -> Response {
    let target = continue_target(&state.cfg, q.return_to.as_deref());
    let has_handle = crate::profiles::fetch(&state.db, &sess.identity_id)
        .await
        .ok()
        .and_then(|p| p.username)
        .is_some();
    if has_handle {
        return Redirect::to(&target).into_response();
    }
    render_step(chrome, &target, String::new(), None)
}

pub(crate) async fn username_step_post(
    State(state): State<AppState>,
    sess: RequireSession,
    actx: AuditCtx,
    Chrome(chrome): Chrome,
    CsrfForm(form): CsrfForm<UsernameStepForm>,
) -> Response {
    let target = continue_target(&state.cfg, Some(&form.return_to));
    if form.username.trim().is_empty() {
        return Redirect::to(&skip_target(&target)).into_response();
    }
    match crate::settings::profile::save_username(
        &state,
        &sess.identity_id,
        &sess.email,
        &actx,
        &form.username,
    )
    .await
    {
        Ok(()) => Redirect::to(&target).into_response(),
        Err(e) => {
            let msg = chrome.t(e.message_key());
            render_step(chrome, &target, form.username, Some(msg))
        }
    }
}

fn render_step(chrome: PageChrome, target: &str, value: String, error: Option<String>) -> Response {
    render(&UsernameStepTemplate {
        chrome,
        return_to: target.to_string(),
        skip_href: skip_target(target),
        value,
        error,
    })
}

/// Sanitized `return_to`, or the dashboard.
fn continue_target(cfg: &crate::config::AppConfig, return_to: Option<&str>) -> String {
    match return_to.filter(|s| !s.is_empty()) {
        Some(rt) => crate::web::safe_return_to(cfg, rt).to_string(),
        None => "/".to_string(),
    }
}

/// The continue target with the skip marker, so `/oauth/login` doesn't ask again.
fn skip_target(target: &str) -> String {
    if target == "/" {
        return target.to_string();
    }
    let sep = if target.contains('?') { '&' } else { '?' };
    format!("{target}{sep}{SKIP_PARAM}=1")
}

#[cfg(test)]
mod tests {
    use super::{continue_target, skip_target};

    #[test]
    fn continues_only_to_same_origin_targets() {
        let cfg = crate::config::AppConfig::test_fixture();
        assert_eq!(
            continue_target(&cfg, Some("/oauth/login?login_challenge=x")),
            "/oauth/login?login_challenge=x"
        );
        assert_eq!(continue_target(&cfg, Some("https://evil.example/")), "/");
        assert_eq!(continue_target(&cfg, None), "/");
    }

    #[test]
    fn skip_appends_the_marker() {
        assert_eq!(
            skip_target("/oauth/login?login_challenge=x"),
            "/oauth/login?login_challenge=x&skip_username=1"
        );
        assert_eq!(skip_target("/"), "/");
    }
}
