//! Terminate a form-submission navigation before handing back to Hydra.
//!
//! `form-action` is checked only on navigations of type `form-submission`
//! (CSP3 §6.4.1.1), but Chrome and Safari apply that check to every hop of the
//! submission's redirect chain — Firefox to none (w3c/webappsec-csp#8, open
//! since 2015). A consent grant used to 303 straight into Hydra, so the chain
//! ran on to the client's `redirect_uri` and to wherever the client bounced
//! next, and Forseti had to name all of it in the header. It can't: a client's
//! post-callback hosts aren't in its metadata, and CSP3 §2.4.1 reports only
//! the pre-redirect URL, so a blocked hop never names itself. Tailscale takes
//! its callback on `login.tailscale.com` and then bounces to
//! `console.tailscale.com`; the user landed on a dead page while the server
//! logged a completed flow.
//!
//! Answering the POST with a document instead of a 303 ends the submission
//! navigation on Forseti's own origin. The continuation is a declarative
//! refresh — navigation type "other", which no browser checks against
//! `form-action`, and which the HTML spec performs with `historyHandling:
//! "replace"`, so the back button doesn't land on a spent challenge. No script
//! is involved; the link is there for a client that strips the refresh.

use askama::Template;
use axum::response::{IntoResponse, Redirect, Response};

use crate::locale::LanguageIdentifier;
use crate::render::render;

#[derive(Template)]
#[template(path = "oauth/continue.html")]
struct ContinueTemplate {
    lang: String,
    dir: &'static str,
    target: String,
    heading: String,
    continue_label: String,
}

/// Continue a flow at `target` from a fresh navigation.
///
/// `target` is Hydra's `redirect_to`. Non-HTTP(S) can't reach here — Hydra
/// mints it — but the fallback link would honour a `javascript:` URL that the
/// declarative refresh itself refuses, so the scheme is checked rather than
/// assumed.
pub(crate) fn continue_to(target: &str, locale: &LanguageIdentifier) -> Response {
    if !is_http_url(target) {
        tracing::error!(target, "refusing to continue to a non-HTTP(S) target");
        return Redirect::to("/error").into_response();
    }
    render(&ContinueTemplate {
        lang: locale.to_string(),
        dir: crate::locale::dir_for(locale),
        target: target.to_string(),
        heading: crate::i18n::lookup(locale, "oauth-continue-heading"),
        continue_label: crate::i18n::lookup(locale, "common-action-continue"),
    })
}

fn is_http_url(raw: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|u| matches!(u.scheme(), "http" | "https"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    fn en() -> LanguageIdentifier {
        crate::locale::default_locale()
    }

    async fn body_of(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn continues_with_a_document_not_a_redirect() {
        let resp = continue_to("https://hydra.example.com/oauth2/auth?x=1", &en());
        // A 3xx here would put the hop back inside the form submission and
        // re-open the blocked-navigation bug.
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        assert!(body.contains(r#"http-equiv="refresh""#));
        assert!(body.contains("https://hydra.example.com/oauth2/auth?x=1"));
    }

    /// Hydra's `redirect_to` always carries a query string, so an unescaped
    /// `&` or `"` would either truncate the target or break out of the
    /// attribute.
    #[tokio::test]
    async fn escapes_the_target_in_both_the_refresh_and_the_link() {
        let resp = continue_to("https://app.example.com/cb?code=a&state=b\"c", &en());
        let body = body_of(resp).await;
        assert!(
            !body.contains("state=b\"c"),
            "raw quote escaped the attribute"
        );
        assert_eq!(
            body.matches("code=a&#38;state=b&#34;c").count(),
            2,
            "both the refresh and the link carry the escaped target"
        );
    }

    #[tokio::test]
    async fn refuses_a_non_http_target() {
        for raw in ["javascript:alert(1)", "data:text/html,x", "not a url"] {
            let resp = continue_to(raw, &en());
            assert_eq!(
                resp.status(),
                StatusCode::SEE_OTHER,
                "{raw} should not be rendered into the page"
            );
        }
    }
}
