//! Forward the user's `Cookie` header to Kratos and read individual cookie values from it.
//! Forseti never interprets Kratos's continuity/session cookies; it forwards them as-is.

use axum::http::HeaderMap;

/// Raw `Cookie` header value, or empty string when absent (the shape `ory_client`'s wrappers expect when unauthenticated).
pub(crate) fn cookie_header(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Read a single cookie's raw value (no URL-decoding) from the inbound `Cookie` header; first match wins.
/// `None` when the header is absent, not UTF-8, or has no cookie named `name`.
pub(crate) fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    // `split_parse` (not `split_parse_encoded`) leaves values opaque, matching prior no-decode semantics.
    axum_extra::extract::cookie::Cookie::split_parse(raw.to_string())
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .map(|c| c.value().to_string())
}
