//! Config-gated reverse proxy fronting Hydra's public API (`/hydra/{*rest}`),
//! plus the always-mounted RFC 8414 / OIDC path-insertion discovery routes
//! serving Hydra's discovery document augmented for CIMD (Design A of the
//! MCP CIMD design). Bodies are buffered under a 2 MiB cap by design:
//! Hydra's public endpoints only ever carry small payloads, so streaming
//! buys nothing here. The discovery document comes from the shared
//! [`crate::state::DiscoveryCache`], not a per-request fetch.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::config::HydraConfig;
use crate::state::AppState;

/// Buffered request-body cap for the passthrough; Hydra's endpoints never need more.
const PROXY_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// Response headers worth forwarding back from Hydra.
const PROXIED_RESPONSE_HEADERS: [&str; 5] = [
    "content-type",
    "location",
    "www-authenticate",
    "cache-control",
    "vary",
];

/// `[hydra].front_proxy`-gated passthrough. Mounted on the public listener
/// outside the CSRF layer (Hydra does its own request validation).
pub(crate) fn router(hydra_cfg: &HydraConfig) -> Router<AppState> {
    if !hydra_cfg.front_proxy {
        return Router::new();
    }
    Router::new()
        .route("/hydra/{*rest}", get(passthrough).post(passthrough))
        .layer(DefaultBodyLimit::max(PROXY_BODY_LIMIT_BYTES))
}

/// RFC 8414 / OIDC path-insertion discovery for the configured issuer path
/// (prod haproxy routes these to Forseti already). A path-less issuer has no
/// insertion form, so nothing mounts.
pub(crate) fn well_known_router(hydra_cfg: &HydraConfig) -> Router<AppState> {
    let Some(path) = hydra_cfg.issuer_path() else {
        return Router::new();
    };
    Router::new()
        .route(
            &format!("/.well-known/oauth-authorization-server/{path}"),
            get(augmented_discovery_route),
        )
        .route(
            &format!("/.well-known/openid-configuration/{path}"),
            get(augmented_discovery_route),
        )
}

async fn passthrough(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    method: Method,
    RawQuery(query): RawQuery,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The AS discovery endpoints must carry the CIMD augmentation, so they never proxy verbatim.
    if method == Method::GET
        && matches!(
            rest.as_str(),
            ".well-known/openid-configuration" | ".well-known/oauth-authorization-server"
        )
    {
        return augmented_discovery(&state).await;
    }

    let Ok(url) = upstream_url(&state.cfg.hydra.public_url, &rest, query.as_deref()) else {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    };

    // A proxy must hand Hydra's redirects to the browser, never follow them itself.
    static NO_REDIRECT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = NO_REDIRECT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("reqwest client")
    });
    let mut req = if method == Method::POST {
        client.post(url)
    } else {
        client.get(url)
    };
    for name in [
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::AUTHORIZATION,
        header::COOKIE,
    ] {
        if let Some(v) = headers.get(&name)
            && let Ok(s) = v.to_str()
        {
            req = req.header(name.as_str(), s);
        }
    }
    // The caller's own `x-forwarded-*` are dropped rather than passed on.
    // Forseti is the hop Hydra sees, so it states what it actually resolved;
    // relaying the inbound copies would let any caller tell Hydra whatever
    // client address and scheme it liked.
    if let Some(ip) = crate::client_ip::client_ip(&headers, &state.cfg.proxy, Some(peer_addr.ip()))
    {
        req = req.header("x-forwarded-for", ip.to_string());
    }
    req = req.header(
        "x-forwarded-proto",
        if state.cfg.self_.is_https() {
            "https"
        } else {
            "http"
        },
    );
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "hydra front proxy: upstream unreachable");
            return (StatusCode::BAD_GATEWAY, "hydra upstream unreachable").into_response();
        }
    };
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut out_headers = HeaderMap::new();
    for name in PROXIED_RESPONSE_HEADERS {
        if let Some(v) = resp.headers().get(name)
            && let Ok(hv) = HeaderValue::from_bytes(v.as_bytes())
        {
            out_headers.insert(HeaderName::from_static(name), hv);
        }
    }
    // Set-Cookie is multi-valued (Hydra's CSRF cookies) — append every instance.
    for v in resp.headers().get_all(header::SET_COOKIE) {
        if let Ok(hv) = HeaderValue::from_bytes(v.as_bytes()) {
            out_headers.append(header::SET_COOKIE, hv);
        }
    }
    match crate::outbound::read_capped(resp, PROXY_BODY_LIMIT_BYTES).await {
        Ok(b) => (status, out_headers, b).into_response(),
        Err(e) => {
            tracing::warn!(error = ?e, "hydra front proxy: upstream body read failed");
            (StatusCode::BAD_GATEWAY, "hydra upstream read failed").into_response()
        }
    }
}

/// `base` with the decoded wildcard appended segment by segment, so `?`, `#`
/// and `%` stay in the path. `Err` on a `.` or `..` segment or a control character.
fn upstream_url(base: &str, rest: &str, query: Option<&str>) -> Result<url::Url, ()> {
    // `url` strips tab, CR and LF from a segment, which would turn `.\t.` into `..`.
    if rest.chars().any(|c| c.is_control()) || rest.split('/').any(|s| s == "." || s == "..") {
        return Err(());
    }
    let mut url = url::Url::parse(base.trim_end_matches('/')).map_err(|_| ())?;
    url.path_segments_mut()?
        .pop_if_empty()
        .extend(rest.split('/'));
    url.set_query(query);
    Ok(url)
}

async fn augmented_discovery_route(State(state): State<AppState>) -> Response {
    augmented_discovery(&state).await
}

/// Hydra's discovery document (via the shared cache) as adjusted by
/// [`augment_discovery_doc`].
pub(crate) async fn augmented_discovery(state: &AppState) -> Response {
    let Some(raw) = state.openid_configuration_raw().await else {
        return (StatusCode::BAD_GATEWAY, "hydra discovery unavailable").into_response();
    };
    let providers = state.idp_provider_ids().await;
    let Some(doc) = augment_discovery_doc(&raw, state.cfg.hydra.issuer_path(), &providers) else {
        return (StatusCode::BAD_GATEWAY, "hydra discovery unavailable").into_response();
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        doc.to_string(),
    )
        .into_response()
}

/// Hydra's raw discovery doc, adjusted to what Forseti actually serves:
/// advertise CIMD support, point `authorization_endpoint` at the Forseti
/// shim, drop `registration_endpoint` (no anonymous registration surface),
/// advertise only the code flow, S256 and signed tokens, and add the
/// `prompt`/`acr` values Forseti handles, and list the upstream providers an
/// `idp_hint` can name. `issuer` and the remaining endpoints pass through
/// untouched. `None` when the doc is not a JSON object.
fn augment_discovery_doc(
    raw: &serde_json::Value,
    issuer_path: Option<&str>,
    idp_provider_ids: &[String],
) -> Option<serde_json::Value> {
    let mut doc = raw.as_object()?.clone();
    doc.insert(
        "client_id_metadata_document_supported".to_string(),
        serde_json::Value::Bool(true),
    );
    // The shim lives at the issuer's origin base (issuer minus its configured path suffix).
    if let Some(issuer) = doc.get("issuer").and_then(serde_json::Value::as_str) {
        let issuer = issuer.trim_end_matches('/');
        let origin_base = match issuer_path {
            Some(p) => issuer.strip_suffix(&format!("/{p}")).unwrap_or(issuer),
            None => issuer,
        };
        doc.insert(
            "authorization_endpoint".to_string(),
            serde_json::Value::String(format!("{origin_base}/oauth2/authorize")),
        );
    }
    doc.remove("registration_endpoint");
    doc.retain(|k, _| !k.starts_with("credentials_"));
    doc.insert(
        "response_types_supported".to_string(),
        serde_json::json!(["code"]),
    );
    doc.insert(
        "code_challenge_methods_supported".to_string(),
        serde_json::json!(["S256"]),
    );
    for (key, value) in doc.iter_mut() {
        if key.ends_with("_signing_alg_values_supported")
            && let Some(algs) = value.as_array_mut()
        {
            algs.retain(|a| a.as_str() != Some("none"));
        }
    }
    doc.insert(
        "prompt_values_supported".to_string(),
        serde_json::json!(["none", "login", "consent", "create"]),
    );
    doc.insert(
        "acr_values_supported".to_string(),
        serde_json::json!(["aal1", "aal2"]),
    );
    if let Some(hints) = crate::oidc_providers::idp_hints_supported(idp_provider_ids) {
        doc.insert("idp_hints_supported".to_string(), hints);
    }
    Some(serde_json::Value::Object(doc))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
    use tower::ServiceExt;

    use super::{PROXY_BODY_LIMIT_BYTES, augment_discovery_doc, router, upstream_url};
    use crate::config::AppConfig;
    use crate::state::AppState;

    #[test]
    fn augmentation_trims_to_supported_features_and_keeps_the_rest() {
        let raw = serde_json::json!({
            "issuer": "http://host.containers.internal:3000/hydra",
            "authorization_endpoint": "http://host.containers.internal:3000/hydra/oauth2/auth",
            "token_endpoint": "http://host.containers.internal:3000/hydra/oauth2/token",
            "jwks_uri": "http://host.containers.internal:3000/hydra/.well-known/jwks.json",
            "registration_endpoint": "http://host.containers.internal:3000/hydra/oauth2/register",
            "scopes_supported": ["openid", "offline", "offline_access"],
            "response_types_supported": ["code", "id_token", "code id_token", "token"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_signing_alg_values_supported": ["none", "RS256"],
            "request_object_signing_alg_values_supported": ["none", "RS256", "ES256"],
            "credentials_endpoint_draft_00": "http://host.containers.internal:3000/hydra/credentials",
            "credentials_supported_draft_00": [{"format": "jwt_vc_json"}],
        });
        let out = augment_discovery_doc(&raw, Some("hydra"), &[]).expect("object doc");

        assert_eq!(out["client_id_metadata_document_supported"], true);
        assert_eq!(
            out["authorization_endpoint"],
            "http://host.containers.internal:3000/oauth2/authorize"
        );
        assert!(out.get("registration_endpoint").is_none());
        assert!(out.get("credentials_endpoint_draft_00").is_none());
        assert!(out.get("credentials_supported_draft_00").is_none());
        assert_eq!(out["response_types_supported"], serde_json::json!(["code"]));
        assert_eq!(
            out["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            out["userinfo_signing_alg_values_supported"],
            serde_json::json!(["RS256"])
        );
        assert_eq!(
            out["request_object_signing_alg_values_supported"],
            serde_json::json!(["RS256", "ES256"])
        );
        assert_eq!(
            out["prompt_values_supported"],
            serde_json::json!(["none", "login", "consent", "create"])
        );
        assert_eq!(
            out["acr_values_supported"],
            serde_json::json!(["aal1", "aal2"])
        );

        // Every untouched key survives byte-identical — the issuer above all,
        // since it is the `iss` in every token.
        let rewritten = [
            "authorization_endpoint",
            "registration_endpoint",
            "response_types_supported",
            "code_challenge_methods_supported",
            "userinfo_signing_alg_values_supported",
            "request_object_signing_alg_values_supported",
            "credentials_endpoint_draft_00",
            "credentials_supported_draft_00",
        ];
        assert!(out.get("idp_hints_supported").is_none());
        let (raw, out) = (raw.as_object().unwrap(), out.as_object().unwrap());
        for (key, value) in raw {
            if rewritten.contains(&key.as_str()) {
                continue;
            }
            assert_eq!(
                serde_json::to_string(&out[key]).unwrap(),
                serde_json::to_string(value).unwrap(),
                "key {key} must pass through verbatim"
            );
        }
    }

    #[test]
    fn augmentation_without_issuer_path_uses_issuer_origin() {
        let raw = serde_json::json!({ "issuer": "http://localhost:4444" });
        let out = augment_discovery_doc(&raw, None, &[]).expect("object doc");
        assert_eq!(
            out["authorization_endpoint"],
            "http://localhost:4444/oauth2/authorize"
        );
        assert_eq!(out["issuer"], "http://localhost:4444");
    }

    #[test]
    fn augmentation_lists_idp_hints_and_keeps_other_keys() {
        let raw = serde_json::json!({
            "issuer": "http://localhost:4444",
            "scopes_supported": ["openid"],
        });
        let ids = ["github".to_string(), "playground".to_string()];
        let out = augment_discovery_doc(&raw, None, &ids).expect("object doc");
        assert_eq!(
            out["idp_hints_supported"],
            serde_json::json!([
                { "id": "github", "name": "GitHub" },
                { "id": "playground", "name": "Playground" },
            ])
        );
        let without = augment_discovery_doc(&raw, None, &[]).expect("object doc");
        let mut with = out.as_object().unwrap().clone();
        with.remove("idp_hints_supported");
        assert_eq!(&with, without.as_object().unwrap());
    }

    #[test]
    fn augmentation_rejects_non_object_doc() {
        assert!(augment_discovery_doc(&serde_json::json!([1, 2]), Some("hydra"), &[]).is_none());
    }

    const BASE: &str = "http://hydra:4444";

    #[test]
    fn upstream_url_rejects_dot_segments() {
        for rest in [
            ".", "..", "../x", "a/../b", "a/./b", "a/.", "a/..", "a/.\t./x", "a/\n./x", "a/..\r/x",
        ] {
            assert!(upstream_url(BASE, rest, None).is_err(), "{rest}");
        }
        for rest in [".well-known/jwks.json", "...", ".x/..y", "a./b"] {
            assert!(upstream_url(BASE, rest, None).is_ok(), "{rest}");
        }
    }

    #[test]
    fn upstream_url_encodes_query_and_fragment_chars_in_path() {
        let url = upstream_url(BASE, "a?b#c/100%/x y", None).unwrap();
        assert_eq!(url.as_str(), "http://hydra:4444/a%3Fb%23c/100%25/x%20y");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn upstream_url_keeps_trailing_and_double_slashes() {
        assert_eq!(
            upstream_url(BASE, "oauth2/token/", None).unwrap().as_str(),
            "http://hydra:4444/oauth2/token/"
        );
        assert_eq!(
            upstream_url(BASE, "a//b", None).unwrap().as_str(),
            "http://hydra:4444/a//b"
        );
    }

    #[test]
    fn upstream_url_keeps_base_path_prefix() {
        for base in ["http://hydra:4444/prefix", "http://hydra:4444/prefix/"] {
            assert_eq!(
                upstream_url(base, "oauth2/auth", None).unwrap().as_str(),
                "http://hydra:4444/prefix/oauth2/auth"
            );
        }
        assert_eq!(
            upstream_url("http://hydra:4444/", "userinfo", None)
                .unwrap()
                .as_str(),
            "http://hydra:4444/userinfo"
        );
    }

    #[test]
    fn upstream_url_forwards_query_verbatim() {
        assert_eq!(
            upstream_url(BASE, "userinfo", None).unwrap().as_str(),
            "http://hydra:4444/userinfo"
        );
        assert_eq!(
            upstream_url(BASE, "userinfo", Some("")).unwrap().as_str(),
            "http://hydra:4444/userinfo?"
        );
        let raw = "scope=openid+email&state=a%20b&redirect_uri=https%3A%2F%2Fapp%2Fcb\
                   &resource=https://api.example/x&a=1&a=2&empty=&flag";
        assert_eq!(
            upstream_url(BASE, "oauth2/auth", Some(raw))
                .unwrap()
                .as_str(),
            format!("http://hydra:4444/oauth2/auth?{raw}")
        );
        // Same URL as parsing the interpolated string, for every endpoint shape the consumers use.
        for rest in [
            "oauth2/auth",
            "oauth2/token",
            "oauth2/revoke",
            "oauth2/device/auth",
            "oauth2/device/verify",
            "oauth2/register/0b8c4f2e-1d7a-4c5e-9f3a-2b6d8e1c7a90",
            "oauth2/sessions/logout",
            "userinfo",
            ".well-known/jwks.json",
        ] {
            for query in [None, Some(""), Some(raw), Some("q='\"<x> y")] {
                let mut old = format!("{BASE}/{rest}");
                if let Some(q) = query {
                    old.push('?');
                    old.push_str(q);
                }
                assert_eq!(
                    upstream_url(BASE, rest, query).unwrap(),
                    url::Url::parse(&old).unwrap(),
                    "{old}"
                );
            }
        }
    }

    type Seen = Arc<Mutex<Vec<(Method, String, Option<String>, Option<String>, Vec<u8>)>>>;

    /// Stub Hydra recording method, raw path and query, `Authorization`,
    /// and body; replies with `body`.
    async fn stub_upstream(body: Vec<u8>) -> (String, Seen) {
        let seen = Seen::default();
        let recorder = seen.clone();
        let app = Router::new().fallback(
            move |method: Method, uri: Uri, headers: HeaderMap, req_body: Bytes| {
                let recorder = recorder.clone();
                let body = body.clone();
                async move {
                    recorder.lock().unwrap().push((
                        method,
                        uri.path().to_string(),
                        uri.query().map(str::to_string),
                        headers
                            .get(header::AUTHORIZATION)
                            .map(|v| v.to_str().unwrap().to_string()),
                        req_body.to_vec(),
                    ));
                    let mut out = HeaderMap::new();
                    out.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
                    out.append(header::SET_COOKIE, "a=1".parse().unwrap());
                    out.append(header::SET_COOKIE, "b=2".parse().unwrap());
                    out.insert("x-not-forwarded", "1".parse().unwrap());
                    (StatusCode::CREATED, out, body)
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    async fn proxy_app(upstream: &str) -> Router {
        let mut cfg = AppConfig::test_fixture();
        cfg.hydra.public_url = upstream.to_string();
        cfg.hydra.front_proxy = true;
        let db = crate::db::test_pool().await;
        let identity = crate::backend::build_identity(&cfg, &db, &[0x42; 32]);
        let router = router(&cfg.hydra);
        router
            .with_state(AppState::for_test(cfg, db, identity, &[0x42; 32]))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9))))
    }

    #[tokio::test]
    async fn passthrough_forwards_normal_response() {
        let (upstream, seen) = stub_upstream(b"{\"ok\":true}".to_vec()).await;
        let app = proxy_app(&upstream).await;

        let query = "a=1+2&b=%20x&c=http%3A%2F%2Fx%2Fy&a=3&d=&redirect_uri=https%3A%2F%2Fapp%2Fcb";
        let form = b"grant_type=authorization_code&code=abc+d%2Fe".to_vec();
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/hydra/oauth2/token?{query}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::AUTHORIZATION, "Basic Y2xpZW50OnNlY3JldA==")
                    .body(Body::from(form.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        let cookies: Vec<_> = resp.headers().get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(cookies, ["a=1", "b=2"]);
        assert!(resp.headers().get("x-not-forwarded").is_none());
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"{\"ok\":true}");

        let resp = app
            .oneshot(Request::get("/hydra/userinfo").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let (method, path, q, auth, body) = &seen[0];
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/oauth2/token");
        assert_eq!(q.as_deref(), Some(query));
        assert_eq!(auth.as_deref(), Some("Basic Y2xpZW50OnNlY3JldA=="));
        assert_eq!(body, &form);
        let (method, path, q, auth, body) = &seen[1];
        assert_eq!(method, Method::GET);
        assert_eq!(path, "/userinfo");
        assert_eq!(q, &None);
        assert_eq!(auth, &None);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn passthrough_caps_the_response_body() {
        let (upstream, seen) = stub_upstream(vec![b'x'; PROXY_BODY_LIMIT_BYTES + 1]).await;
        let app = proxy_app(&upstream).await;
        let resp = app
            .clone()
            .oneshot(
                Request::get("/hydra/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = app
            .oneshot(
                Request::get("/hydra/a/%2e%2e/b")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
