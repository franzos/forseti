//! Forseti-owned discovery document at `/.well-known/forseti-configuration`, advertising the Forseti-specific,
//! non-OIDC surfaces (account-management URI, handoff deep-links, webhook JWKS + supported RISC events).
//! Kept separate from Hydra's OIDC discovery so Forseti's discoverability isn't tied to Hydra's response shape.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::json;

use crate::handoff::HANDOFF_ACTIONS;
use crate::state::AppState;
use crate::web::FORSETI_VERSION;
use crate::webhook::event_type::ACCOUNT_PURGED;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/.well-known/forseti-configuration", get(configuration))
}

async fn configuration(State(state): State<AppState>) -> Response {
    let base = state.cfg.self_.url.trim_end_matches('/');
    let body = json!({
        "issuer": base,
        "forseti_version": FORSETI_VERSION,
        "account_management_uri": format!("{base}/settings"),
        "handoff_endpoint": format!("{base}/handoff"),
        "handoff_actions_supported": HANDOFF_ACTIONS,
        "webhook_jwks_uri": format!("{base}/.well-known/webhook-jwks.json"),
        "webhook_events_supported": [ACCOUNT_PURGED],
    });

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "max-age=3600, public"),
        ],
        body.to_string(),
    )
        .into_response()
}
