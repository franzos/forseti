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

/// `/error?id=<error_id>` — Kratos's `flows.error.ui_url` lands here whenever
/// a self-service flow terminates with an error that has no flow context
/// (e.g. a stale link that's already been consumed).
pub(crate) async fn error_page(
    State(state): State<AppState>,
    Query(query): Query<ErrorQuery>,
    Chrome(chrome): Chrome,
) -> Response {
    let error_id = query.id.unwrap_or_default();
    let (title, message, reason) = if error_id.is_empty() {
        (
            "Something went wrong".to_string(),
            "We couldn't load the requested page. The link may have expired or been used already."
                .to_string(),
            String::new(),
        )
    } else {
        match ory::kratos::get_self_service_error(&state.ory, &error_id).await {
            Ok(Some(body)) => extract_error_strings(&body),
            Ok(None) => (
                "Link expired".to_string(),
                "This link is no longer valid. Please start again from sign-in.".to_string(),
                String::new(),
            ),
            Err(e) => {
                tracing::error!(error = ?e, error_id, "failed to fetch Kratos self-service error");
                (
                    "Something went wrong".to_string(),
                    crate::web::AUTH_UNAVAILABLE_BODY.to_string(),
                    String::new(),
                )
            }
        }
    };

    render(&ErrorTemplate {
        chrome,
        error_title: title,
        error_message: message,
        error_reason: reason,
        error_id,
        cta_href: "/login".to_string(),
        cta_label: "Back to sign in".to_string(),
    })
}

/// Pull `(title, message, reason)` out of Kratos's self-service error envelope.
/// Kratos wraps the actual error under `error.{id,message,reason,...}`; older
/// versions use the top-level fields directly. Handle both.
fn extract_error_strings(body: &serde_json::Value) -> (String, String, String) {
    let inner = body.get("error").unwrap_or(body);
    let title = inner
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "self_service_flow_expired" => "Link expired",
            "security_csrf_violation" => "Security check failed",
            "session_already_available" => "Already signed in",
            _ => "Something went wrong",
        })
        .unwrap_or("Something went wrong")
        .to_string();
    let message = inner
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("We couldn't complete that request.")
        .to_string();
    let reason = inner
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (title, message, reason)
}
