//! `idp_hint`: an RP names the upstream provider on the authorization request,
//! and an anonymous user goes straight to it instead of Forseti's chooser.

use askama::Template;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;

use crate::page_chrome::PageChrome;

/// One-shot cookie carrying the hint across Kratos's flow-init hop.
pub(crate) const COOKIE: &str = "forseti_idp_hint";

const MAX_LEN: usize = 64;

/// A syntactically valid provider id: `[A-Za-z0-9._-]{1,64}`.
pub(crate) fn parse(raw: &str) -> Option<&str> {
    let ok = (1..=MAX_LEN).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then_some(raw)
}

/// The hint a [`COOKIE`] carried, decoded and re-validated.
pub(crate) fn decode_cookie(raw: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()?;
    parse(&decoded).map(str::to_string)
}

/// `Set-Cookie` carrying the query's `idp_hint` across the Kratos init hop
/// at `path`. Without a usable hint (none, or a step-up `aal` or re-auth
/// `refresh`, which keep their own pages) a leftover cookie is cleared, so it
/// can't hand off a flow the user started without one.
pub(crate) fn init_cookie(
    query: &crate::FlowQuery,
    headers: &HeaderMap,
    path: &str,
    secure: bool,
) -> Option<String> {
    let step_up_or_reauth =
        query.aal.as_deref().is_some_and(|a| !a.is_empty()) || query.refresh == Some(true);
    match query.idp_hint.as_deref().and_then(parse) {
        Some(hint) if !step_up_or_reauth => {
            Some(crate::auth::hint_cookie(COOKIE, path, Some(hint), secure))
        }
        _ => crate::cookies::read_cookie(headers, COOKIE)
            .map(|_| crate::auth::hint_cookie(COOKIE, path, None, secure)),
    }
}

/// The hint this render acts on: the query's, else the one the init-hop
/// cookie carried. `cookie_present` says whether the cookie needs clearing.
pub(crate) struct Requested {
    pub(crate) hint: Option<String>,
    cookie_present: bool,
}

impl Requested {
    pub(crate) fn from_request(headers: &HeaderMap, query_hint: Option<&str>) -> Self {
        let cookie = crate::cookies::read_cookie(headers, COOKIE);
        let hint = query_hint
            .and_then(parse)
            .map(str::to_string)
            .or_else(|| cookie.as_deref().and_then(decode_cookie));
        Self {
            hint,
            cookie_present: cookie.is_some(),
        }
    }

    /// Clears the one-shot cookie, so a failed provider round-trip lands on
    /// the normal page instead of looping.
    pub(crate) fn clear_cookie(&self, resp: &mut Response, path: &str, secure: bool) {
        if self.cookie_present {
            crate::web::append_set_cookie(
                resp,
                Some(crate::auth::hint_cookie(COOKIE, path, None, secure)),
            );
        }
    }
}

/// The provider to hand off to: `hint`, when this flow offers it. Never for
/// an AAL2 step-up or a refresh, whose known user must not be sent upstream.
pub(crate) fn matching_provider(flow: &serde_json::Value, hint: Option<&str>) -> Option<String> {
    let hint = hint?;
    let step_up = flow.get("requested_aal").and_then(|v| v.as_str()) == Some("aal2");
    let refresh = flow.get("refresh").and_then(|v| v.as_bool()) == Some(true);
    if step_up || refresh {
        return None;
    }
    if crate::flow_view::oidc_provider_ids(flow)
        .iter()
        .any(|id| id == hint)
    {
        Some(hint.to_string())
    } else {
        tracing::warn!(hint, "idp_hint not offered by this flow; showing sign-in");
        None
    }
}

#[derive(Template)]
#[template(path = "idp_handoff.html")]
struct HandoffTemplate {
    chrome: PageChrome,
    form_action: String,
    form_method: String,
    /// The flow's hidden inputs (`csrf_token` among them).
    hidden: Vec<(String, String)>,
    provider_id: String,
    provider_name: String,
}

/// Auto-submitting page that POSTs the flow's OIDC form for `provider`
/// straight at Kratos.
pub(crate) fn render_handoff(
    chrome: PageChrome,
    flow: &serde_json::Value,
    provider: &str,
) -> Response {
    let (form_action, form_method) = crate::flow_view::form_target(flow);
    let hidden = ["default", "oidc"]
        .into_iter()
        .flat_map(|group| crate::flow_view::collect_input_nodes(flow, group))
        .filter(|n| n.input_type == "hidden" && !matches!(n.name.as_str(), "method" | "provider"))
        .map(|n| (n.name, n.value))
        .collect();
    let mut resp = crate::render::render(&HandoffTemplate {
        chrome,
        form_action,
        form_method,
        hidden,
        provider_id: provider.to_string(),
        provider_name: crate::oidc_providers::display_name(provider),
    });
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

#[cfg(test)]
mod tests {
    use super::{Requested, decode_cookie, init_cookie, matching_provider, parse, render_handoff};

    fn query(idp_hint: Option<&str>, aal: Option<&str>, refresh: Option<bool>) -> crate::FlowQuery {
        crate::FlowQuery {
            flow: None,
            return_to: None,
            aal: aal.map(str::to_string),
            refresh,
            organization_id: None,
            login_hint: None,
            idp_hint: idp_hint.map(str::to_string),
        }
    }

    #[test]
    fn init_cookie_carries_a_valid_hint() {
        let none = axum::http::HeaderMap::new();
        let set = init_cookie(
            &query(Some("playground"), None, None),
            &none,
            "/login",
            true,
        )
        .unwrap();
        assert!(set.starts_with("forseti_idp_hint=playground; Path=/login; Max-Age=600; HttpOnly"));
        let set = init_cookie(
            &query(Some("playground"), Some(""), Some(false)),
            &none,
            "/registration",
            false,
        );
        assert!(set.unwrap().contains("Path=/registration"));
    }

    #[test]
    fn init_cookie_skips_step_up_reauth_and_bad_hints() {
        let none = axum::http::HeaderMap::new();
        for q in [
            query(Some("playground"), Some("aal2"), None),
            query(Some("playground"), None, Some(true)),
            query(Some("git hub"), None, None),
            query(None, None, None),
        ] {
            assert_eq!(init_cookie(&q, &none, "/login", true), None);
        }
    }

    #[test]
    fn init_cookie_clears_a_leftover_cookie_without_a_usable_hint() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "forseti_idp_hint=github".parse().unwrap(),
        );
        for q in [
            query(None, None, None),
            query(Some("playground"), Some("aal2"), None),
        ] {
            let set = init_cookie(&q, &headers, "/login", true).unwrap();
            assert!(
                set.starts_with("forseti_idp_hint=; Path=/login; Max-Age=0"),
                "{set}"
            );
        }
        let set = init_cookie(
            &query(Some("playground"), None, None),
            &headers,
            "/login",
            true,
        );
        assert!(set.unwrap().starts_with("forseti_idp_hint=playground;"));
    }

    #[test]
    fn parse_accepts_provider_ids() {
        for id in ["github", "playground", "a.b_c-1", "G", &"x".repeat(64)] {
            assert_eq!(parse(id), Some(id));
        }
    }

    #[test]
    fn parse_rejects_bad_ids() {
        for id in ["", &"x".repeat(65), "git hub", "a/b", "é", "a;b", "a%20"] {
            assert_eq!(parse(id), None, "{id:?}");
        }
    }

    #[test]
    fn decode_cookie_roundtrips_and_revalidates() {
        let set = crate::auth::hint_cookie(super::COOKIE, "/login", Some("a.b_c-1"), true);
        let value = set
            .strip_prefix("forseti_idp_hint=")
            .and_then(|s| s.split(';').next())
            .unwrap();
        assert_eq!(decode_cookie(value).as_deref(), Some("a.b_c-1"));
        assert_eq!(decode_cookie("git%20hub"), None);
        assert_eq!(decode_cookie("%FF%FE"), None);
        assert_eq!(decode_cookie(""), None);
    }

    fn flow(requested_aal: &str, refresh: bool) -> serde_json::Value {
        let input = |group: &str, name: &str, ty: &str, value: &str| {
            serde_json::json!({
                "type": "input",
                "group": group,
                "attributes": { "name": name, "type": ty, "value": value },
            })
        };
        serde_json::json!({
            "requested_aal": requested_aal,
            "refresh": refresh,
            "ui": {
                "action": "http://kratos.test/self-service/login?flow=f1",
                "method": "POST",
                "nodes": [
                    input("default", "csrf_token", "hidden", "tok<&>"),
                    input("default", "identifier", "text", ""),
                    input("oidc", "provider", "submit", "playground"),
                    input("oidc", "provider", "submit", "github"),
                ],
            },
        })
    }

    fn chrome() -> crate::page_chrome::PageChrome {
        let brand = crate::config::BrandConfig {
            name: "Forseti".into(),
            support_email: None,
            logo_url: None,
            consent_intro: String::new(),
            theme_preset: None,
            brand_primary: None,
            brand_on_primary: None,
            brand_secondary: None,
            operator_trust_anchor: None,
        };
        crate::page_chrome::PageChrome::from_brand_with_admin(
            brand,
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        )
    }

    #[test]
    fn matching_provider_hits_and_misses() {
        let f = flow("aal1", false);
        assert_eq!(
            matching_provider(&f, Some("playground")).as_deref(),
            Some("playground")
        );
        assert_eq!(matching_provider(&f, Some("nope")), None);
        assert_eq!(matching_provider(&f, None), None);
    }

    #[test]
    fn stale_hint_on_step_up_or_refresh_shows_the_normal_page() {
        assert_eq!(
            matching_provider(&flow("aal2", false), Some("playground")),
            None
        );
        assert_eq!(
            matching_provider(&flow("aal1", true), Some("playground")),
            None
        );
    }

    #[tokio::test]
    async fn handoff_renders_the_kratos_form() {
        let resp = render_handoff(chrome(), &flow("aal1", false), "playground");
        assert_eq!(
            resp.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains(r#"<form id="idp-handoff""#));
        assert!(html.contains(r#"action="http://kratos.test/self-service/login?flow=f1""#));
        assert!(
            html.contains(r#"<input type="hidden" name="csrf_token" value="tok&#60;&#38;&#62;">"#),
            "{html}"
        );
        assert!(html.contains(r#"<input type="hidden" name="method" value="oidc">"#));
        assert!(html.contains(r#"<input type="hidden" name="provider" value="playground">"#));
        assert!(!html.contains(r#"name="identifier""#));
        assert!(html.contains("Continuing to Playground"));
        assert!(html.contains("document.getElementById('idp-handoff').submit()"));
    }

    #[test]
    fn requested_prefers_the_query_and_clears_only_a_present_cookie() {
        let mut headers = axum::http::HeaderMap::new();
        let r = Requested::from_request(&headers, Some("playground"));
        assert_eq!(r.hint.as_deref(), Some("playground"));
        let mut resp = axum::response::Response::new(axum::body::Body::empty());
        r.clear_cookie(&mut resp, "/login", true);
        assert!(resp.headers().get(axum::http::header::SET_COOKIE).is_none());

        headers.insert(
            axum::http::header::COOKIE,
            "forseti_idp_hint=github".parse().unwrap(),
        );
        let r = Requested::from_request(&headers, None);
        assert_eq!(r.hint.as_deref(), Some("github"));
        r.clear_cookie(&mut resp, "/login", true);
        let set = resp.headers()[axum::http::header::SET_COOKIE]
            .to_str()
            .unwrap();
        assert!(set.starts_with("forseti_idp_hint=; Path=/login; Max-Age=0"));
    }
}
