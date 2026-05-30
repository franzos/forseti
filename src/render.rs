//! Tiny helper that funnels every askama `Template` through a single
//! `Response`-returning chokepoint.
//!
//! Why this exists: under axum 0.8, returning a distinct template struct from
//! every handler forces the `Handler` trait machinery to verify a fresh
//! `IntoResponse` impl per route. With askama 0.15 (no more `askama_axum`),
//! the natural alternative is to render to a `String` in the handler and wrap
//! it in `Html(...)` — collapsing every template into a single `Response`
//! return type. That bounds the trait inference cost and keeps `cargo check`
//! tractable as the admin surface grows.
//!
//! Failures are logged with the template's type name (`std::any::type_name`)
//! and surfaced as a plain 500. They're vanishingly rare in practice — askama
//! catches most issues at compile time — but we still want a breadcrumb when
//! one does slip through.

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

/// Render an askama template to a `Response`. Errors fall through to a 500
/// with a generic body — the underlying error is logged with full context.
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
