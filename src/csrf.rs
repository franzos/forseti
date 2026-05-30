//! Forseti-issued CSRF protection for forms not backed by a Kratos flow.
//!
//! This module also exposes a tower middleware ([`middleware`]) that mints
//! the cookie on the request side and stashes the token in request
//! extensions, then attaches the `Set-Cookie` on the response side. Routes
//! covered by the middleware can use the [`crate::extractors::Csrf`]
//! extractor to read the token without re-touching the headers.
//!
//! Kratos's own forms (login, registration, recovery, verification, settings)
//! carry a `csrf_token` node inside the flow's UI; Forseti just forwards it
//! unchanged. But Forseti also exposes its own POST endpoints — `/logout`,
//! `/oauth/consent` — whose targets are *not* Kratos, so a Kratos-issued token
//! wouldn't help. For those we ship a small double-submit cookie strategy:
//!
//! 1. Every GET that renders one of our forms calls [`ensure_csrf_cookie`] to
//!    set a random `forseti_csrf` cookie (if one isn't already present) and
//!    expose the token to the template.
//! 2. The template embeds the same token in a hidden `_csrf` input.
//! 3. Matching POST handlers call [`verify_csrf`], which checks that the form
//!    value matches the cookie value. Mismatch → 403.
//!
//! Why double-submit (rather than a server-side session table or signed
//! token): Forseti is stateless and we don't want to lean on Kratos's
//! storage for our own forms. The cookie is `SameSite=Lax; HttpOnly=true` —
//! the server renders the same token into the form's hidden `_csrf` input,
//! so no JS read is needed and removing the XSS read channel is free.
//! This is good enough for now; if we ever need a stronger guarantee (token
//! rotation per request, per-form binding) we can swap the strategy without
//! changing call sites.

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
    // Plain compare: the double-submit token is a freshly-minted random value,
    // not a server-held secret, so timing leakage buys an attacker nothing.
    cookie_token == form_token
}

/// Return the CSRF token for a GET-rendered form, minting + setting a cookie
/// when none is present. `secure` controls the `Secure` cookie attribute and
/// should be `true` whenever Forseti's external URL is HTTPS — handlers
/// derive that from `cfg.self_.url.starts_with("https://")` so the playground
/// over plain HTTP keeps working while production deployments harden the
/// cookie. Returns `(token, Some(set_cookie_header))` when a new cookie must
/// be sent on the response, or `(token, None)` when the existing cookie is
/// reused.
///
/// The [`middleware`] uses this on every covered request; it's also available
/// for ad-hoc handler use.
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
        // HttpOnly=true: the double-submit strategy works either way (server
        // compares the form-field copy against the cookie copy; neither side
        // needs JS access). Making the cookie HttpOnly removes XSS as a
        // read channel for the token without losing any functionality —
        // the template renders the token into the hidden `_csrf` input
        // server-side, and the browser sends both back on POST.
        .http_only(true)
        .secure(secure)
        .build()
        .to_string()
}

/// Build a `Set-Cookie` header value that clears the `forseti_csrf` cookie.
/// Wrap a handler response via [`attach_csrf`] on session-boundary transitions
/// (logout, login/registration redirect-to-Kratos, self-delete) so a stale
/// token from a previous principal can't survive into the next form render.
/// The middleware mints a fresh token on the following request automatically.
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

/// Append the optional `Set-Cookie` header produced by [`ensure_csrf_cookie`]
/// to an already-rendered response. No-op when `set_cookie` is `None` (i.e.
/// the cookie was already present on the request — no need to re-set it).
///
/// Hoisted here so the six handlers across `main.rs` and `admin/*.rs` that
/// need to attach the cookie don't each carry their own private copy.
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

/// Axum middleware: ensure every request covered by it has a `forseti_csrf`
/// cookie and that handlers can read the token via request extensions.
///
/// Wired in `app::run` via `route_layer` on the Forseti-owned routes that
/// actually render CSRF-protected forms. The Kratos webhook and `/healthz`
/// /`/readyz` stay outside the layer — they don't render forms and don't
/// want a stray `Set-Cookie` either.
pub async fn middleware(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let secure = state.cfg.self_.is_https();

    let (token, set_cookie) = ensure_csrf_cookie(req.headers(), secure);

    // The token is stashed in request extensions so handlers / render
    // helpers read it via the `Csrf` extractor. The inbound `Cookie:`
    // header is left untouched — anything that re-reads it (logging,
    // audit, downstream middleware) sees exactly what the browser sent.
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
