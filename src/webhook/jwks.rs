//! Public JWKS endpoint for SET signature verification.

use serde_json::json;

/// `GET /.well-known/webhook-jwks.json` — public JWKS for receivers to
/// verify SET signatures. Distinct from Hydra's `/.well-known/jwks.json`
/// (id_token signing) so a receiver can pin them separately if they want.
///
/// Cached for a day at the receiver — `kid` is deterministic across
/// Forseti restarts (SHA-256 of the public DER), so cache hits survive
/// rolling restarts.
pub async fn jwks_endpoint(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    let body = json!({ "keys": [state.signing_key.jwk.clone()] });
    (
        axum::http::StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "max-age=86400, public"),
        ],
        body.to_string(),
    )
        .into_response()
}
