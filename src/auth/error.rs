//! `/error?id=<error_id>` — landing page for Kratos self-service errors that
//! have no flow context (stale links, already-consumed flows, etc.). Also
//! Hydra's `urls.error` (`?error=&error_description=`), for OAuth errors it
//! can't redirect back to the client.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use crate::backend::IdentityBackend;
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
    error: Option<String>,
    error_description: Option<String>,
}

pub(crate) async fn error_page(
    State(state): State<AppState>,
    Query(query): Query<ErrorQuery>,
    Chrome(chrome): Chrome,
) -> Response {
    if let Some(code) = query.error.filter(|s| !s.is_empty()) {
        let title = chrome.t("error-page-oauth-title");
        let cta_label = chrome.t("error-boundary-cta-back-to-dashboard");
        let message = query
            .error_description
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| chrome.t("error-page-default-message"));
        return render(&ErrorTemplate {
            chrome,
            error_title: title,
            error_message: message,
            error_reason: code,
            error_id: String::new(),
            cta_href: "/".to_string(),
            cta_label,
        });
    }
    let error_id = query.id.unwrap_or_default();
    let locale = &chrome.locale;
    let (title, message, reason) = if error_id.is_empty() {
        (
            crate::i18n::lookup(locale, "error-page-generic-title"),
            crate::i18n::lookup(locale, "error-page-generic-body"),
            String::new(),
        )
    } else {
        match state.identity.get_self_service_error(&error_id).await {
            Ok(Some(err)) => error_strings(&err, locale),
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

fn error_strings(
    err: &crate::backend::identity::SelfServiceError,
    locale: &crate::locale::LanguageIdentifier,
) -> (String, String, String) {
    let title_key = match err.id.as_deref() {
        Some("self_service_flow_expired") => "error-page-link-expired-title",
        Some("security_csrf_violation") => "error-page-security-title",
        Some("session_already_available") => "error-page-already-signed-in-title",
        _ => "error-page-generic-title",
    };
    let title = crate::i18n::lookup(locale, title_key);
    // `message` is Kratos's own localized error text; only the absent case
    // falls back to a Forseti string.
    let message = err
        .message
        .clone()
        .unwrap_or_else(|| crate::i18n::lookup(locale, "error-page-default-message"));
    let reason = err.reason.clone().unwrap_or_default();
    (title, message, reason)
}
