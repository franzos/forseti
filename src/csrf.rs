//! Forseti-issued CSRF protection for POST endpoints not backed by a Kratos flow
//! (`/logout`, `/oauth/consent`), via a stateless double-submit cookie.
//!
//! GET renders mint a random `forseti_csrf` cookie ([`ensure_csrf_cookie`]) and embed the same value in a
//! hidden `_csrf` input; the POST handler compares them ([`verify_csrf`]), 403 on mismatch. The cookie is
//! `SameSite=Lax; HttpOnly` (the token is rendered server-side, so no JS read is needed). The [`middleware`]
//! mints/stashes the token in request extensions, read via the [`crate::extractors::Csrf`] extractor.

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::cookie::{Cookie, SameSite};
use rand::distr::Alphanumeric;
use rand::Rng;

use crate::state::AppState;

/// Name of the Forseti-issued CSRF cookie. Kept distinct from Kratos's
/// `csrf_token_*` cookies so the two strategies don't collide.
pub const CSRF_COOKIE_NAME: &str = "forseti_csrf";

/// Read the existing CSRF cookie value, if any.
pub(crate) fn read_csrf_cookie(headers: &HeaderMap) -> Option<String> {
    crate::cookies::read_cookie(headers, CSRF_COOKIE_NAME)
}

/// Verify that the form's `_csrf` value matches the request's `forseti_csrf` cookie.
/// Both must be present and non-empty for the request to pass.
pub fn verify_csrf(headers: &HeaderMap, form_token: &str) -> bool {
    let Some(cookie_token) = read_csrf_cookie(headers) else {
        return false;
    };
    if cookie_token.is_empty() || form_token.is_empty() {
        return false;
    }
    // Plain compare: the token is a fresh random value, not a server-held secret, so timing leakage is irrelevant.
    cookie_token == form_token
}

/// Return the CSRF token for a GET-rendered form, minting + setting a cookie when none is present.
/// `secure` (Forseti's URL is HTTPS) sets the `Secure` attribute. Returns `(token, Some(set_cookie))`
/// when a new cookie must be sent, or `(token, None)` when reusing the existing one.
pub fn ensure_csrf_cookie(headers: &HeaderMap, secure: bool) -> (String, Option<String>) {
    if let Some(existing) = read_csrf_cookie(headers) {
        if !existing.is_empty() {
            return (existing, None);
        }
    }
    let token = mint_token();
    let cookie = build_csrf_cookie(&token, secure);
    (token, Some(cookie))
}

fn mint_token() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn build_csrf_cookie(value: &str, secure: bool) -> String {
    Cookie::build((CSRF_COOKIE_NAME, value.to_string()))
        .path("/")
        .same_site(SameSite::Lax)
        // HttpOnly removes XSS as a read channel; the token is rendered server-side, so no JS access is needed.
        .http_only(true)
        .secure(secure)
        .build()
        .to_string()
}

/// Clear the `forseti_csrf` cookie on session-boundary transitions (logout, redirect-to-Kratos, self-delete)
/// so a stale token from a previous principal can't survive into the next form render.
pub fn delete_csrf_cookie(secure: bool) -> String {
    let mut s = Cookie::build((CSRF_COOKIE_NAME, ""))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .build()
        .to_string();
    s.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    s
}

/// Append the optional `Set-Cookie` from [`ensure_csrf_cookie`] to a response. No-op when `None`.
pub fn attach_csrf(mut resp: Response, set_cookie: Option<String>) -> Response {
    crate::web::append_set_cookie(&mut resp, set_cookie);
    resp
}

/// CSRF token threaded through request extensions by [`middleware`]. Handlers
/// pull this via the [`crate::extractors::Csrf`] extractor.
#[derive(Clone, Debug)]
pub(crate) struct CsrfToken(pub(crate) String);

/// `Form<T>` body for POST handlers whose only field is the double-submit
/// `_csrf` token. Verified via [`crate::extractors::verify_csrf_or_forbid`].
#[derive(Debug, serde::Deserialize)]
pub(crate) struct CsrfForm {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: Option<String>,
}

/// Ensure every covered request has a `forseti_csrf` cookie and a token in request extensions.
pub async fn middleware(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let secure = state.cfg.self_.is_https();

    let (token, set_cookie) = ensure_csrf_cookie(req.headers(), secure);

    req.extensions_mut().insert(CsrfToken(token));

    let mut resp = next.run(req).await;
    crate::web::append_set_cookie(&mut resp, set_cookie);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;
    use axum::http::HeaderMap;

    fn headers_with_csrf(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            format!("{}={}", CSRF_COOKIE_NAME, token).parse().unwrap(),
        );
        h
    }

    #[test]
    fn verify_csrf_matches() {
        let headers = headers_with_csrf("abc123");
        assert!(verify_csrf(&headers, "abc123"));
    }

    #[test]
    fn verify_csrf_rejects_mismatch() {
        let headers = headers_with_csrf("abc123");
        assert!(!verify_csrf(&headers, "different"));
    }

    #[test]
    fn verify_csrf_rejects_empty_form_token() {
        let headers = headers_with_csrf("abc123");
        assert!(!verify_csrf(&headers, ""));
    }

    #[test]
    fn verify_csrf_rejects_missing_cookie() {
        let headers = HeaderMap::new();
        assert!(!verify_csrf(&headers, "abc123"));
    }

    #[test]
    fn verify_csrf_rejects_empty_cookie() {
        let headers = headers_with_csrf("");
        assert!(!verify_csrf(&headers, "abc123"));
    }

    #[test]
    fn ensure_csrf_cookie_mints_when_absent() {
        let headers = HeaderMap::new();
        let (token, set_cookie) = ensure_csrf_cookie(&headers, false);
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(set_cookie.is_some());
        let sc = set_cookie.unwrap();
        assert!(sc.contains(CSRF_COOKIE_NAME));
        assert!(sc.contains(&token));
        assert!(sc.contains("HttpOnly"));
    }

    #[test]
    fn ensure_csrf_cookie_reuses_existing() {
        let headers = headers_with_csrf("existing-token-value");
        let (token, set_cookie) = ensure_csrf_cookie(&headers, false);
        assert_eq!(token, "existing-token-value");
        assert!(set_cookie.is_none());
    }

    #[test]
    fn ensure_csrf_cookie_secure_flag_when_https() {
        let headers = HeaderMap::new();
        let (_, set_cookie) = ensure_csrf_cookie(&headers, true);
        let sc = set_cookie.unwrap();
        assert!(sc.contains("Secure"));
    }

    #[test]
    fn ensure_csrf_cookie_no_secure_flag_when_http() {
        let headers = HeaderMap::new();
        let (_, set_cookie) = ensure_csrf_cookie(&headers, false);
        let sc = set_cookie.unwrap();
        assert!(!sc.contains("Secure"));
    }

    #[test]
    fn delete_csrf_cookie_emits_expired_directive() {
        let sc = delete_csrf_cookie(true);
        assert!(sc.contains(CSRF_COOKIE_NAME));
        assert!(sc.contains("Path=/"));
        assert!(sc.contains("HttpOnly"));
        assert!(sc.contains("Secure"));
        assert!(sc.contains("SameSite=Lax"));
        assert!(sc.contains("Expires=Thu, 01 Jan 1970"));
    }
}
