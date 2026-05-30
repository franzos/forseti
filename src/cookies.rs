//! Helpers for forwarding the user's `Cookie` header to Kratos, and for
//! reading individual cookie values out of the inbound `Cookie` header.
//!
//! Kratos's browser flow stores the continuity cookie (`csrf_token_*`,
//! `ory_kratos_continuity`) and, post-login, the session cookie
//! (`ory_kratos_session`) under the same origin as Kratos. Forseti never
//! reads those cookies — it just forwards them as-is on the upstream call.

use axum::http::HeaderMap;

/// Extract the raw `Cookie` header value from an incoming request.
///
/// Returns an empty string when no `Cookie` header is present, which is the
/// shape `ory_client`'s `to_session` / `get_flow` wrappers expect when
/// the user is unauthenticated.
pub(crate) fn cookie_header(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Read a single cookie's raw value from the inbound `Cookie` header.
///
/// Returns the value as-is (no URL-decoding — Forseti's own cookies don't carry
/// URL-encoded values, and Kratos's continuity cookies are opaque tokens that
/// don't need decoding either). Returns `None` when no `Cookie` header is
/// present, when the header isn't valid UTF-8, or when no cookie with `name`
/// is found. The first match wins.
pub(crate) fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    // `split_parse` (not `split_parse_encoded`) leaves values opaque — no
    // percent-decoding — matching the no-decode semantics every prior copy of
    // this scanner relied on.
    axum_extra::extract::cookie::Cookie::split_parse(raw.to_string())
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .map(|c| c.value().to_string())
}
