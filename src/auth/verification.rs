//! Kratos email-verification flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::backend::IdentityBackend;
use crate::backend::identity::FlowInit;
use crate::backend::identity::FlowKind;
use crate::backend::identity::FlowOutcome;
use crate::cookies;
use crate::extractors::OptionalSession;
use crate::flow_view::*;
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{FlowQuery, render_error_boundary};

#[derive(Template)]
#[template(path = "verification.html")]
struct VerificationTemplate {
    chrome: PageChrome,
    form: FlowFormView,
    state: String,
    is_logged_in: bool,
    /// Where the flow was headed before verification (an OAuth login, an
    /// invite), offered once the challenge has passed.
    continue_href: Option<String>,
}

pub(crate) async fn verification(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    session: OptionalSession,
    Chrome(chrome): Chrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);

    let session_opt = session.ok();
    let is_logged_in = session_opt.is_some();
    let flow_id = query.flow.as_deref();
    let init_url = || {
        state.identity.flow_init_url(
            FlowKind::Verification,
            FlowInit {
                return_to: query.return_to.as_deref(),
                ..Default::default()
            },
        )
    };

    match state
        .identity
        .resolve_flow(FlowKind::Verification, flow_id, &cookie)
        .await
    {
        FlowOutcome::Ready(flow) => {
            // Logged-in user at `choose_method`: auto-submit the known address
            // server-side so the browser lands straight on code entry. Any
            // failure falls through to render the original form unchanged.
            if let Some(session) = session_opt
                && flow.state == "choose_method"
                && session.needs_verification()
            {
                let email = session.email();
                if !email.is_empty()
                    && state
                        .identity
                        .verify_known_email(&flow, &email, &cookie)
                        .await
                        .is_ok()
                {
                    return Redirect::to(&format!(
                        "/verification?flow={}",
                        crate::web::urlencode(flow_id.unwrap_or_default())
                    ))
                    .into_response();
                }
            }
            render_verification(
                &state.cfg,
                chrome,
                &flow,
                query.return_to.as_deref(),
                is_logged_in,
            )
        }
        FlowOutcome::Init | FlowOutcome::Reinit | FlowOutcome::Privileged(_) => {
            Redirect::to(&init_url()).into_response()
        }
        FlowOutcome::Error(e) => {
            tracing::error!(error = ?e, ?flow_id, "failed to fetch Kratos verification flow");
            render_error_boundary(
                &state,
                &chrome.locale,
                &crate::i18n::lookup(&chrome.locale, "error-boundary-verification-title"),
                &crate::i18n::lookup(&chrome.locale, "error-boundary-auth-unavailable-body"),
                "/login",
                crate::i18n::lookup(&chrome.locale, "error-boundary-cta-sign-in"),
            )
            .into_response()
        }
    }
}

fn render_verification(
    cfg: &crate::config::AppConfig,
    chrome: PageChrome,
    flow: &Flow,
    return_to: Option<&str>,
    is_logged_in: bool,
) -> Response {
    let form = FlowFormView::from_flow(flow, FlowKind::Verification, return_to, &chrome.locale);
    let state = flow.state.clone();
    let continue_href = continue_href(cfg, &state, return_to.or(flow.return_to.as_deref()));
    render(&VerificationTemplate {
        chrome,
        form,
        state,
        is_logged_in,
        continue_href,
    })
}

/// The post-verification destination, when there is one worth offering over
/// the dashboard. Kratos already checked the flow's `return_to` against
/// `allowed_return_urls`; `safe_return_to` additionally pins it to Forseti's
/// own origin, since every legitimate destination is a Forseti route.
fn continue_href(
    cfg: &crate::config::AppConfig,
    state: &str,
    return_to: Option<&str>,
) -> Option<String> {
    if state != "passed_challenge" {
        return None;
    }
    let href = crate::web::safe_return_to(cfg, return_to?);
    (href != "/").then(|| href.to_string())
}

#[cfg(test)]
mod tests {
    use super::continue_href;
    use crate::config::AppConfig;

    fn cfg() -> AppConfig {
        let mut cfg = AppConfig::test_fixture();
        cfg.self_.url = "https://id.example.com".into();
        cfg
    }

    #[test]
    fn offers_the_oauth_login_once_verified() {
        let rt = "https://id.example.com/oauth/login?login_challenge=abc";
        assert_eq!(
            continue_href(&cfg(), "passed_challenge", Some(rt)).as_deref(),
            Some(rt)
        );
    }

    #[test]
    fn offers_the_invite_once_verified() {
        let rt = "https://id.example.com/invite/finalize?token=t";
        assert_eq!(
            continue_href(&cfg(), "passed_challenge", Some(rt)).as_deref(),
            Some(rt)
        );
    }

    #[test]
    fn nothing_before_the_challenge_passes() {
        let rt = "https://id.example.com/oauth/login?login_challenge=abc";
        assert_eq!(continue_href(&cfg(), "sent_email", Some(rt)), None);
        assert_eq!(continue_href(&cfg(), "choose_method", Some(rt)), None);
    }

    #[test]
    fn nothing_for_foreign_origins_or_no_destination() {
        assert_eq!(
            continue_href(&cfg(), "passed_challenge", Some("https://evil.example/x")),
            None
        );
        assert_eq!(
            continue_href(&cfg(), "passed_challenge", Some("//evil.example")),
            None
        );
        assert_eq!(continue_href(&cfg(), "passed_challenge", None), None);
        assert_eq!(continue_href(&cfg(), "passed_challenge", Some("/")), None);
    }
}
