//! Forseti-owned discovery document — `/.well-known/forseti-configuration`.
//!
//! Hydra advertises the OAuth/OIDC machine surfaces (auth, token, jwks,
//! end_session, registration_endpoint) on its own
//! `/.well-known/openid-configuration`. This document covers everything
//! that's Forseti-specific and *not* OIDC-shaped:
//!
//! - `account_management_uri` — the `/settings` hub.
//! - `handoff_endpoint` + `handoff_actions_supported` — the deep-link
//!   contract documented in `docs/integration-guide.md#account-self-service-deep-links`.
//! - `webhook_jwks_uri` — the JWKS receivers use to verify outbound
//!   RFC 8417 SETs (account-purged, future RISC events).
//! - `webhook_events_supported` — the RISC event URIs Forseti
//!   currently emits.
//!
//! Not spliced into Hydra's OIDC discovery doc deliberately — mixing the
//! two muddles the contract and ties Forseti's discoverability to
//! Hydra's response shape. RPs fetch this doc by URL convention.

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
