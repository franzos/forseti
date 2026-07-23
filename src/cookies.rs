//! Forward the user's `Cookie` header to Kratos and read individual cookie values from it.
//! Forseti never interprets Kratos's continuity/session cookies; it forwards them as-is.

use axum::http::HeaderMap;

/// Raw `Cookie` header value, or empty string when absent (the shape `ory_client`'s wrappers expect when unauthenticated).
/// HTTP/2 (RFC 9113 §8.2.3) lets a client split the cookies across multiple field lines; join them back with `"; "`.
pub(crate) fn cookie_header(headers: &HeaderMap) -> String {
    join_cookie_lines(headers)
}

/// Read a single cookie's raw value (no URL-decoding) from the inbound `Cookie` header; first match wins.
/// `None` when the header is absent, not UTF-8, or has no cookie named `name`.
pub(crate) fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = join_cookie_lines(headers);
    if raw.is_empty() {
        return None;
    }
    // `split_parse` (not `split_parse_encoded`) leaves values opaque, matching prior no-decode semantics.
    axum_extra::extract::cookie::Cookie::split_parse(raw)
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .map(|c| c.value().to_string())
}

/// Concatenate every `Cookie` field line with `"; "`, skipping non-UTF-8 lines.
fn join_cookie_lines(headers: &HeaderMap) -> String {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    #[test]
    fn read_cookie_spans_split_header_lines() {
        // RFC 9113 §8.2.3: an h2 client may split the cookies across field lines.
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, "a=1".parse().unwrap());
        headers.append(COOKIE, "ory_session=xyz".parse().unwrap());
        assert_eq!(read_cookie(&headers, "ory_session").as_deref(), Some("xyz"));
        assert_eq!(cookie_header(&headers), "a=1; ory_session=xyz");
    }

    #[test]
    fn read_cookie_absent_is_none() {
        let headers = HeaderMap::new();
        assert_eq!(read_cookie(&headers, "x"), None);
        assert_eq!(cookie_header(&headers), "");
    }
}
