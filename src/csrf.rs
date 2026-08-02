//! Forseti-issued CSRF protection for POST endpoints not backed by a Kratos flow
//! (`/logout`, `/oauth/consent`), via a stateless signed double-submit cookie.
//!
//! GET renders mint a `forseti_csrf` cookie ([`ensure_csrf_cookie`]) carrying `<random>.<hex hmac>`
//! (HMAC-SHA256 over the random part, key HKDF-derived from the operator cookie secret with a
//! CSRF-specific info string) and embed the same value in a hidden `_csrf` input; the POST handler
//! compares them ([`verify_csrf`]), 403 on mismatch. The signature alone does NOT block cookie
//! tossing — Forseti hands a validly signed token to any anonymous GET, so a sibling subdomain can
//! replay one it was given rather than forge one. Two things in [`middleware`] block it instead:
//! state-changing requests whose `Origin` (or, absent that, `Sec-Fetch-Site`) says they aren't
//! same-origin are rejected, and every CSRF cookie whose name isn't the one this deployment mints
//! is dropped off the request, so a `Domain=`-scoped `forseti_csrf` can never stand in for the
//! `__Host-` cookie. The same pass drops unsigned/forged values, so [`verify_csrf`]'s plain equality
//! only ever sees tokens Forseti minted — every verifying route must stay behind the middleware.
//! Tokens are session-unbound on purpose: login/registration forms need CSRF before any session exists.
//!
//! On HTTPS deployments the cookie is named `__Host-forseti_csrf` (prefix pins Secure + Path=/ +
//! no Domain in the browser); plain-http keeps `forseti_csrf`. The cookie is `SameSite=Lax;
//! HttpOnly` (the token is rendered server-side, so no JS read is needed). The [`middleware`]
//! mints/stashes the token in request extensions, read via the [`crate::extractors::Csrf`] extractor.

use axum::RequestExt;
use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, RawForm, Request, State};
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN};
use axum::http::{HeaderMap, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::{Cookie, SameSite};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use rand::distr::Alphanumeric;
use serde::de::DeserializeOwned;
use sha2::Sha256;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Name of the Forseti-issued CSRF cookie on plain-http deployments. Kept
/// distinct from Kratos's `csrf_token_*` cookies so the two strategies don't collide.
pub const CSRF_COOKIE_NAME: &str = "forseti_csrf";

/// Cookie name on HTTPS deployments; `__Host-` requires Secure, Path=/, no Domain.
pub const CSRF_COOKIE_NAME_SECURE: &str = "__Host-forseti_csrf";

/// HKDF info string, domain-separating the CSRF key from the signed-cookie keys.
const CSRF_KEY_INFO: &[u8] = b"forseti::csrf::v1";

/// Not in `axum::http::header`; browsers send it on navigations alongside `Origin`.
const SEC_FETCH_SITE: &str = "sec-fetch-site";

/// The cookie name minted for this deployment mode. The only name that survives
/// [`middleware`]: the other one is stripped off the request.
pub(crate) fn csrf_cookie_name(secure: bool) -> &'static str {
    if secure {
        CSRF_COOKIE_NAME_SECURE
    } else {
        CSRF_COOKIE_NAME
    }
}

/// Read the existing CSRF cookie value, if any. Both names are accepted here because
/// [`middleware`] has already dropped whichever one this deployment doesn't mint, so
/// on HTTPS only the `__Host-` cookie can reach a handler.
pub(crate) fn read_csrf_cookie(headers: &HeaderMap) -> Option<String> {
    crate::cookies::read_cookie(headers, CSRF_COOKIE_NAME_SECURE)
        .or_else(|| crate::cookies::read_cookie(headers, CSRF_COOKIE_NAME))
}

/// Reduce a URL to its `scheme://host[:port]` origin with default ports elided, matching
/// how browsers serialize `Origin`. `None` for relative, malformed, or opaque-origin input.
pub(crate) fn url_origin(url: &str) -> Option<String> {
    let origin = url::Url::parse(url).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

fn derive_key(secret: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(CSRF_KEY_INFO, &mut key)
        .expect("HKDF expand of 32 bytes is within OKM length bound");
    key
}

fn sign_random(secret: &[u8], random: &str) -> String {
    let key = derive_key(secret);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
    mac.update(random.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// True when `token` is `<random>.<hex hmac>` with a valid signature under this
/// deployment's derived CSRF key.
pub(crate) fn token_is_valid(secret: &[u8], token: &str) -> bool {
    let Some((random, tag_hex)) = token.split_once('.') else {
        return false;
    };
    if random.is_empty() {
        return false;
    }
    let Ok(tag) = hex::decode(tag_hex) else {
        return false;
    };
    let key = derive_key(secret);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
    mac.update(random.as_bytes());
    mac.verify_slice(&tag).is_ok()
}

/// Verify that the form's `_csrf` value matches the request's CSRF cookie.
/// Both must be present and non-empty for the request to pass. Signature
/// validity is enforced upstream: [`middleware`] drops CSRF cookies that fail
/// [`token_is_valid`], so equality here implies a Forseti-signed token.
pub fn verify_csrf(headers: &HeaderMap, form_token: &str) -> bool {
    let Some(cookie_token) = read_csrf_cookie(headers) else {
        return false;
    };
    if cookie_token.is_empty() || form_token.is_empty() {
        return false;
    }
    // Plain compare: both values travel with the request, so timing leakage is irrelevant.
    cookie_token == form_token
}

/// Return the CSRF token for a GET-rendered form, minting + setting a cookie when no validly
/// signed one is present. `secure` (Forseti's URL is HTTPS) selects the `__Host-` name and the
/// `Secure` attribute. Returns `(token, Some(set_cookie))` when a new cookie must be sent, or
/// `(token, None)` when reusing the existing one.
pub fn ensure_csrf_cookie(
    headers: &HeaderMap,
    secret: &[u8],
    secure: bool,
) -> (String, Option<String>) {
    let name = csrf_cookie_name(secure);
    if let Some(existing) = crate::cookies::read_cookie(headers, name)
        && token_is_valid(secret, &existing)
    {
        return (existing, None);
    }
    let token = mint_token(secret);
    let cookie = build_csrf_cookie(name, &token, secure);
    (token, Some(cookie))
}

fn mint_token(secret: &[u8]) -> String {
    let random: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let tag = sign_random(secret, &random);
    format!("{random}.{tag}")
}

fn build_csrf_cookie(name: &str, value: &str, secure: bool) -> String {
    Cookie::build((name.to_string(), value.to_string()))
        .path("/")
        .same_site(SameSite::Lax)
        // HttpOnly removes XSS as a read channel; the token is rendered server-side, so no JS access is needed.
        .http_only(true)
        .secure(secure)
        .build()
        .to_string()
}

/// Clear the CSRF cookie on session-boundary transitions (logout, redirect-to-Kratos, self-delete)
/// so a stale token from a previous principal can't survive into the next form render.
pub fn delete_csrf_cookie(secure: bool) -> String {
    let mut s = Cookie::build((csrf_cookie_name(secure), ""))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .build()
        .to_string();
    s.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    s
}

/// RFC 9110 safe methods. Everything else counts as state-changing and goes through
/// [`origin_allowed`], so an unknown method fails closed rather than skipping the gate.
fn is_safe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Same-origin gate for state-changing requests, layered under the double-submit check: it is what
/// stops a sibling subdomain from replaying a token Forseti minted for it.
///
/// `Sec-Fetch-Site` decides whenever the browser sent it: it is a forbidden header (page JS cannot
/// set it) and it distinguishes `same-origin` from the `same-site` sibling-subdomain case, which is
/// exactly the threat here. It is also the only signal that survives our own `Referrer-Policy:
/// no-referrer` — per Fetch, a non-CORS request under that policy serializes its `Origin` as the
/// literal `null`, so every form POST from a Forseti page arrives with `Origin: null` and comparing
/// that against `[self].url` would 403 the entire write surface.
///
/// `Origin` is only the fallback for clients that send it without `Sec-Fetch-Site`, and the opaque
/// `null` is treated as absent rather than as a mismatch. Neither header present passes —
/// non-browser clients send neither, and the double-submit token still gates them.
fn origin_allowed(headers: &HeaderMap, self_origin: Option<&str>) -> bool {
    if let Some(site) = headers.get(SEC_FETCH_SITE).and_then(|v| v.to_str().ok()) {
        return matches!(site, "same-origin" | "none");
    }
    match (
        headers.get(ORIGIN).and_then(|v| v.to_str().ok()),
        self_origin,
    ) {
        (Some(origin), Some(expected)) if origin != "null" => origin.eq_ignore_ascii_case(expected),
        _ => true,
    }
}

/// Drop CSRF cookies this deployment didn't mint from the request's `Cookie` header, so downstream
/// reads (equality in [`verify_csrf`], the [`crate::extractors::Csrf`] fallback) never see a
/// tossed/forged value. Two rules: the name must be exactly [`csrf_cookie_name`] for the current
/// scheme, since a sibling subdomain can plant a `Domain=`-scoped `forseti_csrf` but not a
/// `__Host-` cookie; and the value must verify under this deployment's key. Non-CSRF cookies pass
/// through untouched.
fn strip_invalid_csrf_cookies(headers: &mut HeaderMap, secret: &[u8], secure: bool) {
    let minted = csrf_cookie_name(secure);
    let lines: Vec<String> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    if lines.is_empty() {
        return;
    }
    let mut changed = false;
    let kept: Vec<String> = lines
        .iter()
        .flat_map(|line| Cookie::split_parse(line.clone()).filter_map(Result::ok))
        .filter(|c| {
            let is_csrf = c.name() == CSRF_COOKIE_NAME || c.name() == CSRF_COOKIE_NAME_SECURE;
            if is_csrf && (c.name() != minted || !token_is_valid(secret, c.value())) {
                changed = true;
                return false;
            }
            true
        })
        .map(|c| format!("{}={}", c.name(), c.value()))
        .collect();
    if !changed {
        return;
    }
    headers.remove(COOKIE);
    if !kept.is_empty()
        && let Ok(v) = HeaderValue::from_str(&kept.join("; "))
    {
        headers.insert(COOKIE, v);
    }
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

/// Empty form payload for POST handlers whose body carries only the
/// double-submit `_csrf` token. Pair with [`CsrfForm`] (`CsrfForm<NoPayload>`)
/// to verify CSRF without any other fields.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct NoPayload {}

/// Hidden `_csrf` field, deserialized out of the form body alongside the
/// handler's real payload.
#[derive(serde::Deserialize)]
struct CsrfField {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

/// Body extractor for Forseti-owned POST forms: deserializes the inner `T`
/// exactly like [`axum_extra::extract::Form`] (so repeated keys / `Vec` fields
/// parse identically) and verifies the double-submit `_csrf` token as a side
/// effect. On mismatch it returns the same 403 as
/// [`crate::extractors::verify_csrf_or_forbid`]; handlers bind
/// `CsrfForm(payload): CsrfForm<T>`. Sites that also need the token (re-render)
/// keep a [`crate::extractors::Csrf`] param.
pub(crate) struct CsrfForm<T>(pub(crate) T);

impl<T, S> FromRequest<S> for CsrfForm<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let headers = req.headers().clone();
        let RawForm(bytes) = req.extract().await.map_err(IntoResponse::into_response)?;

        // Parse the real payload first so a malformed body yields the same
        // axum_extra::Form rejection (422) it would today, before the CSRF
        // check (403) runs, preserving the prior extractor-then-handler order.
        let value = form_from_bytes::<T, S>(bytes.clone(), state).await?;
        let field = form_from_bytes::<CsrfField, S>(bytes, state).await?;
        if let Some(resp) =
            crate::extractors::verify_csrf_or_forbid(&headers, field.csrf.as_deref())
        {
            return Err(resp);
        }
        Ok(CsrfForm(value))
    }
}

/// Deserialize `T` from a urlencoded body via the exact [`axum_extra::extract::Form`]
/// path (`serde_html_form`), so multi-value keys and rejections match. The
/// rebuilt request is POST with the urlencoded content-type so `RawForm` reads
/// the body (not the query) and surfaces the same rejection variant as today.
async fn form_from_bytes<T, S>(bytes: Bytes, state: &S) -> Result<T, Response>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    let mut req = Request::new(Body::from(bytes));
    *req.method_mut() = Method::POST;
    req.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    axum_extra::extract::Form::<T>::from_request(req, state)
        .await
        .map(|axum_extra::extract::Form(value)| value)
        .map_err(IntoResponse::into_response)
}

/// Ensure every covered request has a validly signed CSRF cookie and a token in request extensions.
pub async fn middleware(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let secure = state.cfg.self_.is_https();

    if !is_safe_method(req.method()) {
        let self_origin = url_origin(&state.cfg.self_.url);
        if !origin_allowed(req.headers(), self_origin.as_deref()) {
            tracing::warn!(
                path = %req.uri().path(),
                origin = ?req.headers().get(ORIGIN),
                sec_fetch_site = ?req.headers().get(SEC_FETCH_SITE),
                expected = ?self_origin,
                "rejected cross-origin state-changing request"
            );
            return crate::extractors::forbid_response();
        }
    }

    strip_invalid_csrf_cookies(req.headers_mut(), &state.cookie_secret, secure);
    let (token, set_cookie) = ensure_csrf_cookie(req.headers(), &state.cookie_secret, secure);

    req.extensions_mut().insert(CsrfToken(token));

    let mut resp = next.run(req).await;
    crate::web::append_set_cookie(&mut resp, set_cookie);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::http::header::COOKIE;

    const SECRET: &[u8] = b"csrf-test-operator-secret";

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
        let (token, set_cookie) = ensure_csrf_cookie(&headers, SECRET, false);
        let (random, tag) = token.split_once('.').expect("token is random.tag");
        assert_eq!(random.len(), 32);
        assert!(random.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(tag.len(), 64);
        assert!(token_is_valid(SECRET, &token));
        assert!(set_cookie.is_some());
        let sc = set_cookie.unwrap();
        assert!(sc.starts_with(&format!("{}=", CSRF_COOKIE_NAME)));
        assert!(sc.contains(&token));
        assert!(sc.contains("HttpOnly"));
    }

    #[test]
    fn ensure_csrf_cookie_reuses_existing_signed_token() {
        let existing = mint_token(SECRET);
        let headers = headers_with_csrf(&existing);
        let (token, set_cookie) = ensure_csrf_cookie(&headers, SECRET, false);
        assert_eq!(token, existing);
        assert!(set_cookie.is_none());
    }

    #[test]
    fn ensure_csrf_cookie_replaces_unsigned_token() {
        let headers = headers_with_csrf("tossed-unsigned-value");
        let (token, set_cookie) = ensure_csrf_cookie(&headers, SECRET, false);
        assert_ne!(token, "tossed-unsigned-value");
        assert!(token_is_valid(SECRET, &token));
        assert!(set_cookie.is_some());
    }

    #[test]
    fn ensure_csrf_cookie_replaces_token_signed_with_other_secret() {
        let foreign = mint_token(b"some-other-secret");
        let headers = headers_with_csrf(&foreign);
        let (token, set_cookie) = ensure_csrf_cookie(&headers, SECRET, false);
        assert_ne!(token, foreign);
        assert!(set_cookie.is_some());
    }

    #[test]
    fn ensure_csrf_cookie_secure_uses_host_prefix() {
        let headers = HeaderMap::new();
        let (_, set_cookie) = ensure_csrf_cookie(&headers, SECRET, true);
        let sc = set_cookie.unwrap();
        assert!(sc.starts_with(&format!("{}=", CSRF_COOKIE_NAME_SECURE)));
        assert!(sc.contains("Secure"));
        assert!(sc.contains("Path=/"));
        assert!(!sc.contains("Domain="));
    }

    #[test]
    fn ensure_csrf_cookie_http_keeps_unprefixed_name() {
        let headers = HeaderMap::new();
        let (_, set_cookie) = ensure_csrf_cookie(&headers, SECRET, false);
        let sc = set_cookie.unwrap();
        assert!(sc.starts_with(&format!("{}=", CSRF_COOKIE_NAME)));
        assert!(!sc.contains("Secure"));
    }

    #[test]
    fn verify_csrf_accepts_host_prefixed_cookie() {
        let token = mint_token(SECRET);
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{}={}", CSRF_COOKIE_NAME_SECURE, token)
                .parse()
                .unwrap(),
        );
        assert!(verify_csrf(&headers, &token));
    }

    #[test]
    fn token_is_valid_rejects_malformed_and_forged() {
        assert!(!token_is_valid(SECRET, ""));
        assert!(!token_is_valid(SECRET, "no-dot-at-all"));
        assert!(!token_is_valid(SECRET, ".deadbeef"));
        assert!(!token_is_valid(SECRET, "random.nothex"));
        let token = mint_token(SECRET);
        assert!(token_is_valid(SECRET, &token));
        assert!(!token_is_valid(b"different-secret", &token));
    }

    #[test]
    fn strip_invalid_csrf_cookies_drops_tossed_value_keeps_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("other=1; {}=tossed; session=abc", CSRF_COOKIE_NAME)
                .parse()
                .unwrap(),
        );
        strip_invalid_csrf_cookies(&mut headers, SECRET, false);
        let raw = headers.get(COOKIE).unwrap().to_str().unwrap();
        assert!(!raw.contains("tossed"));
        assert!(raw.contains("other=1"));
        assert!(raw.contains("session=abc"));
        assert!(read_csrf_cookie(&headers).is_none());
    }

    #[test]
    fn strip_invalid_csrf_cookies_keeps_signed_value() {
        let token = mint_token(SECRET);
        let mut headers = headers_with_csrf(&token);
        strip_invalid_csrf_cookies(&mut headers, SECRET, false);
        assert_eq!(read_csrf_cookie(&headers).as_deref(), Some(token.as_str()));
    }

    #[test]
    fn strip_invalid_csrf_cookies_removes_header_when_only_cookie_was_forged() {
        let mut headers = headers_with_csrf("tossed");
        strip_invalid_csrf_cookies(&mut headers, SECRET, false);
        assert!(headers.get(COOKIE).is_none());
    }

    #[test]
    fn strip_invalid_csrf_cookies_drops_signed_unprefixed_cookie_on_https() {
        // Cookie tossing: a sibling subdomain plants a validly signed, Domain-scoped `forseti_csrf`.
        let tossed = mint_token(SECRET);
        let mut headers = headers_with_csrf(&tossed);
        strip_invalid_csrf_cookies(&mut headers, SECRET, true);
        assert!(read_csrf_cookie(&headers).is_none());
        assert!(!verify_csrf(&headers, &tossed));
    }

    #[test]
    fn strip_invalid_csrf_cookies_prefers_host_prefixed_over_tossed_sibling_cookie() {
        let ours = mint_token(SECRET);
        let tossed = mint_token(SECRET);
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{CSRF_COOKIE_NAME}={tossed}; {CSRF_COOKIE_NAME_SECURE}={ours}")
                .parse()
                .unwrap(),
        );
        strip_invalid_csrf_cookies(&mut headers, SECRET, true);
        assert_eq!(read_csrf_cookie(&headers).as_deref(), Some(ours.as_str()));
    }

    #[test]
    fn strip_invalid_csrf_cookies_drops_host_prefixed_cookie_on_http() {
        let token = mint_token(SECRET);
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{CSRF_COOKIE_NAME_SECURE}={token}")
                .parse()
                .unwrap(),
        );
        strip_invalid_csrf_cookies(&mut headers, SECRET, false);
        assert!(read_csrf_cookie(&headers).is_none());
    }

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, value.parse().unwrap());
        h
    }

    fn headers_of(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.insert(*name, value.parse().unwrap());
        }
        h
    }

    #[test]
    fn origin_allowed_matches_self_origin() {
        let expected = Some("https://id.example.com");
        assert!(origin_allowed(
            &headers_with("origin", "https://id.example.com"),
            expected
        ));
        assert!(!origin_allowed(
            &headers_with("origin", "https://evil.example.com"),
            expected
        ));
    }

    /// What Chrome actually sends for a same-origin form POST from a Forseti page: our own
    /// `Referrer-Policy: no-referrer` makes Fetch serialize `Origin` as the opaque `null`, so the
    /// gate has to read `Sec-Fetch-Site` or it 403s every form in the app.
    #[test]
    fn origin_allowed_accepts_null_origin_when_sec_fetch_site_is_same_origin() {
        assert!(origin_allowed(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "same-origin")]),
            Some("http://localhost:3000")
        ));
    }

    /// The sibling-subdomain cookie-tossing case still loses: `Origin: null` hides the attacker's
    /// host, but `Sec-Fetch-Site` reports `same-site` and decides.
    #[test]
    fn origin_allowed_rejects_null_origin_when_sec_fetch_site_is_same_site() {
        assert!(!origin_allowed(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "same-site")]),
            Some("https://id.example.com")
        ));
        assert!(!origin_allowed(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "cross-site")]),
            Some("https://id.example.com")
        ));
    }

    /// `Sec-Fetch-Site` is a forbidden header, so when the browser sent it, it outranks an `Origin`
    /// the page could have influenced.
    #[test]
    fn origin_allowed_prefers_sec_fetch_site_over_origin() {
        assert!(!origin_allowed(
            &headers_of(&[
                ("origin", "https://id.example.com"),
                ("sec-fetch-site", "cross-site"),
            ]),
            Some("https://id.example.com")
        ));
    }

    #[test]
    fn origin_allowed_falls_back_to_sec_fetch_site() {
        let expected = Some("https://id.example.com");
        assert!(origin_allowed(
            &headers_with("sec-fetch-site", "same-origin"),
            expected
        ));
        assert!(origin_allowed(
            &headers_with("sec-fetch-site", "none"),
            expected
        ));
        assert!(!origin_allowed(
            &headers_with("sec-fetch-site", "same-site"),
            expected
        ));
        assert!(!origin_allowed(
            &headers_with("sec-fetch-site", "cross-site"),
            expected
        ));
    }

    #[test]
    fn origin_allowed_passes_when_neither_header_present() {
        assert!(origin_allowed(
            &HeaderMap::new(),
            Some("https://id.example.com")
        ));
    }

    #[test]
    fn origin_allowed_without_self_origin_still_rejects_cross_site() {
        assert!(origin_allowed(
            &headers_with("origin", "https://evil.example.com"),
            None
        ));
        assert!(!origin_allowed(
            &headers_with("sec-fetch-site", "cross-site"),
            None
        ));
    }

    #[test]
    fn url_origin_elides_default_ports_and_paths() {
        assert_eq!(
            url_origin("https://id.example.com/login?x=1").as_deref(),
            Some("https://id.example.com")
        );
        assert_eq!(
            url_origin("https://id.example.com:443/").as_deref(),
            Some("https://id.example.com")
        );
        assert_eq!(
            url_origin("http://127.0.0.1:4433").as_deref(),
            Some("http://127.0.0.1:4433")
        );
        assert!(url_origin("/relative").is_none());
        assert!(url_origin("not a url").is_none());
    }

    #[test]
    fn safe_methods_skip_the_origin_gate() {
        assert!(is_safe_method(&Method::GET));
        assert!(is_safe_method(&Method::HEAD));
        assert!(!is_safe_method(&Method::POST));
        assert!(!is_safe_method(&Method::DELETE));
    }

    #[test]
    fn delete_csrf_cookie_emits_expired_directive() {
        let sc = delete_csrf_cookie(true);
        assert!(sc.starts_with(&format!("{}=", CSRF_COOKIE_NAME_SECURE)));
        assert!(sc.contains("Path=/"));
        assert!(sc.contains("HttpOnly"));
        assert!(sc.contains("Secure"));
        assert!(sc.contains("SameSite=Lax"));
        assert!(sc.contains("Expires=Thu, 01 Jan 1970"));
        let sc_http = delete_csrf_cookie(false);
        assert!(sc_http.starts_with(&format!("{}=", CSRF_COOKIE_NAME)));
        assert!(sc_http.contains("Expires=Thu, 01 Jan 1970"));
    }
}
