//! `/error?id=<error_id>` — landing page for Kratos self-service errors that
//! have no flow context (stale links, already-consumed flows, etc.).

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use crate::ory;
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    chrome: PageChrome,
    error_title: String,
    error_message: String,
    error_reason: String,
    error_id: String,
    cta_href: String,
    cta_label: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorQuery {
    id: Option<String>,
}

pub(crate) async fn error_page(
    State(state): State<AppState>,
    Query(query): Query<ErrorQuery>,
    Chrome(chrome): Chrome,
) -> Response {
    let error_id = query.id.unwrap_or_default();
    let locale = &chrome.locale;
    let (title, message, reason) = if error_id.is_empty() {
        (
            crate::i18n::lookup(locale, "error-page-generic-title"),
            crate::i18n::lookup(locale, "error-page-generic-body"),
            String::new(),
        )
    } else {
        match ory::kratos::get_self_service_error(&state.ory, &error_id).await {
            Ok(Some(body)) => extract_error_strings(&body, locale),
            Ok(None) => (
                crate::i18n::lookup(locale, "error-page-link-expired-title"),
                crate::i18n::lookup(locale, "error-page-link-expired-body"),
                String::new(),
            ),
            Err(e) => {
                tracing::error!(error = ?e, error_id, "failed to fetch Kratos self-service error");
                (
                    crate::i18n::lookup(locale, "error-page-generic-title"),
                    crate::i18n::lookup(locale, "error-boundary-auth-unavailable-body"),
                    String::new(),
                )
            }
        }
    };

    let cta_label = chrome.t("error-cta-back-to-sign-in");
    render(&ErrorTemplate {
        chrome,
        error_title: title,
        error_message: message,
        error_reason: reason,
        error_id,
        cta_href: "/login".to_string(),
        cta_label,
    })
}

/// Older Kratos versions put the error at the top level, newer ones wrap it
/// under `error.{id,message,reason,...}`. Handle both.
fn extract_error_strings(
    body: &serde_json::Value,
    locale: &crate::locale::LanguageIdentifier,
) -> (String, String, String) {
    let inner = body.get("error").unwrap_or(body);
    let title_key = inner
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "self_service_flow_expired" => "error-page-link-expired-title",
            "security_csrf_violation" => "error-page-security-title",
            "session_already_available" => "error-page-already-signed-in-title",
            _ => "error-page-generic-title",
        })
        .unwrap_or("error-page-generic-title");
    let title = crate::i18n::lookup(locale, title_key);
    // `message` is Kratos's own localized error text; only the absent case
    // falls back to a Forseti string.
    let message = inner
        .get("message")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| crate::i18n::lookup(locale, "error-page-default-message"));
    let reason = inner
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (title, message, reason)
}
