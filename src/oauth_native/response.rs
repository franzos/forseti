//! Authorization response delivery (RFC 6749 section 4.1.2, OAuth 2.0 Form Post Response Mode,
//! RFC 9207 `iss`).

use askama::Template;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};

use super::authorize::{Delivery, ResponseMode};
use super::clients::REFUSED_SCHEMES;
use crate::locale::LanguageIdentifier;
use crate::render::render;

/// How a `query` response leaves Forseti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Navigation {
    /// A 303, for a response to a GET.
    Redirect,
    /// A [`crate::oauth::continue_nav`] document, for a response to a form POST, so the
    /// client's origin never joins a `form-action` checked redirect chain. A refused scheme ends
    /// on `/error`.
    Document,
}

#[derive(Template)]
#[template(path = "oauth/form_post.html")]
struct FormPostTemplate<'a> {
    lang: String,
    dir: &'static str,
    action: &'a str,
    fields: Vec<(&'a str, &'a str)>,
    heading: String,
    continue_label: String,
}

/// The authorization code for `delivery`.
pub(crate) fn success(
    delivery: &Delivery,
    issuer: &str,
    code: &str,
    nav: Navigation,
    locale: &LanguageIdentifier,
) -> Response {
    let mut params = vec![("code", code)];
    if let Some(state) = delivery.state.as_deref() {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    deliver(delivery, &params, nav, locale)
}

/// An error for `delivery`. `description` is fixed ASCII text.
pub(crate) fn error(
    delivery: &Delivery,
    issuer: &str,
    error: &str,
    description: &str,
    nav: Navigation,
    locale: &LanguageIdentifier,
) -> Response {
    let mut params = vec![("error", error), ("error_description", description)];
    if let Some(state) = delivery.state.as_deref() {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    deliver(delivery, &params, nav, locale)
}

fn deliver(
    delivery: &Delivery,
    params: &[(&str, &str)],
    nav: Navigation,
    locale: &LanguageIdentifier,
) -> Response {
    let mut resp = match delivery.mode {
        ResponseMode::Query => {
            let location = query_location(&delivery.redirect_uri, params);
            match nav {
                Navigation::Redirect => Redirect::to(&location).into_response(),
                Navigation::Document => document(&location, locale),
            }
        }
        ResponseMode::FormPost => form_post(&delivery.redirect_uri, params, locale),
    };
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `continue_to` logs a target it refuses, so only http(s) goes there; nothing here logs
/// `location`, which carries the code.
fn document(location: &str, locale: &LanguageIdentifier) -> Response {
    let scheme = url::Url::parse(location).map(|u| u.scheme().to_string());
    match scheme.as_deref() {
        Ok("http" | "https") => crate::oauth::continue_nav::continue_to(location, locale),
        Ok(s) if !REFUSED_SCHEMES.contains(&s) => {
            crate::oauth::continue_nav::continue_to_app(location, locale)
        }
        _ => Redirect::to("/error").into_response(),
    }
}

/// `redirect_uri` with `params` appended to the query it was registered with.
pub(crate) fn query_location(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    let separator = match redirect_uri.find('?') {
        None => "?",
        Some(i) if i + 1 == redirect_uri.len() || redirect_uri.ends_with('&') => "",
        Some(_) => "&",
    };
    format!("{redirect_uri}{separator}{encoded}")
}

fn form_post(redirect_uri: &str, params: &[(&str, &str)], locale: &LanguageIdentifier) -> Response {
    let mut resp = render(&FormPostTemplate {
        lang: locale.to_string(),
        dir: crate::locale::dir_for(locale),
        action: redirect_uri,
        fields: params.to_vec(),
        heading: crate::i18n::lookup(locale, "oauth-continue-heading"),
        continue_label: crate::i18n::lookup(locale, "common-action-continue"),
    });
    crate::app::allow_form_action_to(&mut resp, &[redirect_uri.to_string()]);
    resp
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    use super::*;
    use crate::app::ExtraFormAction;

    const ISSUER: &str = "https://id.example.com";

    fn en() -> LanguageIdentifier {
        crate::locale::default_locale()
    }

    fn delivery(uri: &str, mode: ResponseMode, state: Option<&str>) -> Delivery {
        Delivery {
            redirect_uri: uri.to_string(),
            mode,
            state: state.map(str::to_string),
        }
    }

    fn location(resp: &Response) -> &str {
        resp.headers()[header::LOCATION].to_str().unwrap()
    }

    async fn body_of(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn query_keeps_the_registered_query_and_encodes_values() {
        let d = delivery(
            "https://app.example/cb?tenant=a%20b&x=1",
            ResponseMode::Query,
            Some("s t&u=v#w"),
        );
        let resp = success(&d, ISSUER, "c/1+2", Navigation::Redirect, &en());
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            location(&resp),
            "https://app.example/cb?tenant=a%20b&x=1&code=c%2F1%2B2&state=s+t%26u%3Dv%23w\
             &iss=https%3A%2F%2Fid.example.com"
        );

        for (uri, sep) in [
            ("https://app.example/cb", "?"),
            ("https://app.example/cb?", ""),
            ("https://app.example/cb?x=1&", ""),
            ("http://127.0.0.1:5000/cb?x=1", "&"),
        ] {
            assert_eq!(
                query_location(uri, &[("code", "c")]),
                format!("{uri}{sep}code=c"),
                "{uri}"
            );
        }
    }

    #[test]
    fn error_carries_state_only_when_given() {
        let with = error(
            &delivery("https://app.example/cb", ResponseMode::Query, Some("xyz")),
            ISSUER,
            "invalid_scope",
            "a requested scope is not allowed for this client",
            Navigation::Redirect,
            &en(),
        );
        assert_eq!(
            location(&with),
            "https://app.example/cb?error=invalid_scope\
             &error_description=a+requested+scope+is+not+allowed+for+this+client\
             &state=xyz&iss=https%3A%2F%2Fid.example.com"
        );
        let without = error(
            &delivery("https://app.example/cb", ResponseMode::Query, None),
            ISSUER,
            "login_required",
            "the user is not signed in",
            Navigation::Redirect,
            &en(),
        );
        assert!(
            !location(&without).contains("state="),
            "{}",
            location(&without)
        );
        assert!(location(&without).contains("error=login_required"));
    }

    #[tokio::test]
    async fn document_navigation_answers_with_a_page() {
        let resp = success(
            &delivery("https://app.example/cb", ResponseMode::Query, None),
            ISSUER,
            "c",
            Navigation::Document,
            &en(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::LOCATION).is_none());
        let body = body_of(resp).await;
        assert!(body.contains(r#"http-equiv="refresh""#));
        assert!(body.contains("https://app.example/cb?code=c&#38;iss="));
    }

    #[tokio::test]
    async fn document_navigation_reaches_private_use_schemes() {
        for uri in ["com.example.app:/oauth", "myapp:/cb", "myapp://cb"] {
            let resp = success(
                &delivery(uri, ResponseMode::Query, Some("s")),
                ISSUER,
                "c",
                Navigation::Document,
                &en(),
            );
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            let body = body_of(resp).await;
            let target = format!("{uri}?code=c&#38;state=s&#38;iss=");
            assert_eq!(body.matches(&target).count(), 2, "refresh and link: {body}");
            assert!(body.contains(r#"http-equiv="refresh""#));
            assert!(!body.contains("<script"));
        }
    }

    #[tokio::test]
    async fn document_navigation_refuses_script_and_local_schemes() {
        for uri in [
            "javascript:alert(1)//",
            "JavaScript:alert(1)//",
            "data:text/html,x",
            "vbscript:x",
            "file:///etc/passwd",
            "blob:https://app.example/1",
            "not a url",
        ] {
            let resp = success(
                &delivery(uri, ResponseMode::Query, None),
                ISSUER,
                "c",
                Navigation::Document,
                &en(),
            );
            assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{uri}");
            assert_eq!(location(&resp), "/error", "{uri}");
        }
    }

    /// The code-bearing location must never reach a log line.
    #[test]
    fn private_use_delivery_does_not_log() {
        fn body_of_fn<'a>(src: &'a str, signature: &str) -> &'a str {
            let start = src.find(signature).unwrap();
            let len = src[start..].find("\n}\n").unwrap();
            &src[start..start + len]
        }
        let nav = include_str!("../oauth/continue_nav.rs");
        let native = body_of_fn(nav, "pub(crate) fn continue_to_app(");
        assert!(!native.contains("tracing"), "{native}");
        let own = include_str!("response.rs");
        let doc = body_of_fn(own, "\nfn document(");
        assert!(!doc.contains("tracing"), "{doc}");
    }

    #[tokio::test]
    async fn every_mode_is_no_store() {
        let cases = [
            (
                "https://app.example/cb",
                ResponseMode::Query,
                Navigation::Redirect,
            ),
            (
                "https://app.example/cb",
                ResponseMode::Query,
                Navigation::Document,
            ),
            ("myapp:/cb", ResponseMode::Query, Navigation::Document),
            ("javascript:x", ResponseMode::Query, Navigation::Document),
            (
                "https://app.example/cb",
                ResponseMode::FormPost,
                Navigation::Redirect,
            ),
        ];
        for (uri, mode, nav) in cases {
            let d = delivery(uri, mode, None);
            for resp in [
                success(&d, ISSUER, "c", nav, &en()),
                error(&d, ISSUER, "access_denied", "denied", nav, &en()),
            ] {
                assert_eq!(
                    resp.headers()[header::CACHE_CONTROL],
                    "no-store",
                    "{uri} {mode:?} {nav:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn form_post_escapes_values_and_widens_form_action() {
        let uri = "https://app.example/cb?a=1&b=\"2'<x>";
        let resp = success(
            &delivery(uri, ResponseMode::FormPost, Some("\"'<script>&amp;")),
            ISSUER,
            "code-1",
            Navigation::Redirect,
            &en(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let extra = resp.extensions().get::<ExtraFormAction>().unwrap();
        assert_eq!(extra.0, ["https://app.example"]);

        let body = body_of(resp).await;
        assert!(body.contains(r#"method="post""#));
        assert!(
            body.contains(r#"action="https://app.example/cb?a=1&#38;b=&#34;2&#39;&#60;x&#62;""#),
            "{body}"
        );
        assert!(
            body.contains(r#"name="state" value="&#34;&#39;&#60;script&#62;&#38;amp;""#),
            "{body}"
        );
        assert!(body.contains(r#"name="code" value="code-1""#));
        assert!(body.contains(r#"name="iss" value="https://id.example.com""#));
        assert!(!body.contains("<script>&"), "{body}");
        assert!(!body.contains("<noscript>"));
        assert!(body.contains(r#"<button type="submit">Continue</button>"#));
    }

    /// The auto-submit is an inline script, which holds only while the CSP sets neither
    /// `script-src` nor `default-src`.
    #[tokio::test]
    async fn form_post_auto_submit_fits_the_csp() {
        let csp = crate::app::build_csp("'self'", "'self'");
        assert!(!csp.contains("script-src"), "{csp}");
        assert!(!csp.contains("default-src"), "{csp}");
        let resp = error(
            &delivery("https://app.example/cb", ResponseMode::FormPost, None),
            ISSUER,
            "access_denied",
            "the user denied the request",
            Navigation::Redirect,
            &en(),
        );
        let body = body_of(resp).await;
        assert_eq!(body.matches("<script").count(), 1);
        assert!(body.contains("<script>document.forms[0].submit();</script>"));
        assert!(!body.contains(r#"name="state""#));
        assert!(body.contains(r#"name="error" value="access_denied""#));
    }
}
