//! Funnel every askama `Template` through one `Response`-returning chokepoint.
//!
//! Collapsing handlers to a single `Response` return type (render to `String`, wrap in `Html`) bounds the
//! per-route `IntoResponse` trait inference cost under axum 0.8, keeping `cargo check` tractable. Render
//! failures (vanishingly rare; askama catches most at compile time) log the template type name and 500.

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

/// Render an askama template to a `Response`. Errors fall through to a 500
/// with a generic body; the underlying error is logged with full context.
pub fn render<T: askama::Template>(tpl: &T) -> Response {
    match tpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            tracing::error!(
                error = ?err,
                template = std::any::type_name::<T>(),
                "template render failed"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "render error").into_response()
        }
    }
}
