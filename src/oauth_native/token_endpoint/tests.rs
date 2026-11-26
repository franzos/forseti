use axum::http::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

use super::*;
use crate::backend::OAuthBackend;
use crate::oauth_native::test_support::*;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

async fn app() -> (axum::Router, AppState) {
    token_app().await
}

fn basic_header(id: &str, secret: &str) -> String {
    let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", encode(id), encode(secret)))
    )
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn send(app: &axum::Router, req: Request<Body>) -> Answer {
    let resp = app.clone().oneshot(with_peer(req)).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    Answer {
        status,
        headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

async fn post_token(app: &axum::Router, body: &str, basic: Option<(&str, &str)>) -> Answer {
    let mut req =
        Request::post(TOKEN_PATH).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some((id, secret)) = basic {
        req = req.header(header::AUTHORIZATION, basic_header(id, secret));
    }
    send(app, req.body(Body::from(body.to_string())).unwrap()).await
}

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn code_form(code: &str, extra: &[(&str, &str)]) -> String {
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT),
    ];
    pairs.extend_from_slice(extra);
    form(&pairs)
}

fn assert_no_store(a: &Answer) {
    assert_eq!(a.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(a.headers[header::PRAGMA], "no-cache");
    assert_eq!(a.headers[header::CONTENT_TYPE], "application/json");
}

fn assert_error(a: &Answer, status: StatusCode, error: &str) {
    assert_eq!(a.status, status, "{}", a.body);
    assert_eq!(a.body["error"], error, "{}", a.body);
    let description = a.body["error_description"].as_str().unwrap();
    assert!(description.is_ascii() && !description.is_empty());
    assert_no_store(a);
}

async fn code_for(state: &AppState, client_id: &str, extra: &str) -> String {
    code_with(&state.oauth, client_id, "alice", OFFLINE, &[API], extra)
        .await
        .1
}

#[tokio::test]
async fn each_auth_method_exchanges_a_code() {
    let (app, state) = app().await;
    let keys = &state.oauth.keys().unwrap();
    let pkce = format!(
        "&nonce=n-1&code_challenge={}&code_challenge_method=S256",
        URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
    );
    for client_id in ["basic", "post", "pub"] {
        let code = code_for(&state, client_id, &pkce).await;
        let secret = format!("{client_id}-secret");
        let mut extra = vec![("code_verifier", VERIFIER)];
        let basic = match client_id {
            "basic" => Some((client_id, secret.as_str())),
            "post" => {
                extra.extend([("client_id", client_id), ("client_secret", &secret)]);
                None
            }
            _ => {
                extra.push(("client_id", client_id));
                None
            }
        };
        let a = post_token(&app, &code_form(&code, &extra), basic).await;
        assert_eq!(a.status, StatusCode::OK, "{client_id}: {}", a.body);
        assert_no_store(&a);
        let mut members: Vec<&String> = a.body.as_object().unwrap().keys().collect();
        members.sort();
        assert_eq!(
            members,
            [
                "access_token",
                "expires_in",
                "id_token",
                "refresh_token",
                "scope",
                "token_type"
            ]
        );
        assert_eq!(a.body["token_type"], "bearer");
        assert_eq!(a.body["expires_in"], 300);
        assert_eq!(a.body["scope"], "openid email offline_access");
        assert_eq!(a.body["refresh_token"].as_str().unwrap().len(), 43);

        let access = a.body["access_token"].as_str().unwrap();
        let at = jwt::verify(keys, ISSUER, access, Typ::AccessToken, Some(API)).unwrap();
        assert_eq!(at["client_id"], client_id);
        assert_eq!(at["sub"], "alice");
        assert_eq!(at["ext"], json!({"tenant": "t1"}));
        assert!(at.get("tenant").is_none());
        let id = a.body["id_token"].as_str().unwrap();
        let claims = jwt::verify(keys, ISSUER, id, Typ::IdToken, Some(client_id)).unwrap();
        assert_eq!(claims["nonce"], "n-1");
        assert_eq!(claims["at_hash"], jwt::at_hash(access));
        assert_eq!(claims["email"], "alice@example.com");
        assert_eq!(claims["aud"], json!([client_id]));
    }
}

#[tokio::test]
async fn registry_claims_are_promoted_to_the_top_level() {
    let (app, state) = app().await;
    use crate::resource_registry as registry;
    registry::insert(
        &state.db,
        registry::NewResource {
            resource: API.to_string(),
            display_name: "API".to_string(),
            org_id: crate::orgs::DEFAULT_ORG_ID.to_string(),
            created_by: "test@example.com".to_string(),
        },
    )
    .await
    .unwrap();
    let row = registry::find_by_resource(&state.db, API)
        .await
        .unwrap()
        .unwrap();
    registry::set_access_token_claims(&state.db, row.id, &strings(&["tenant"]))
        .await
        .unwrap();
    let code = code_for(&state, "basic", "").await;
    let a = post_token(
        &app,
        &code_form(&code, &[]),
        Some(("basic", "basic-secret")),
    )
    .await;
    let keys = &state.oauth.keys().unwrap();
    let access = a.body["access_token"].as_str().unwrap();
    let at = jwt::verify(keys, ISSUER, access, Typ::AccessToken, None).unwrap();
    assert_eq!(at["tenant"], "t1");
    assert_eq!(at["ext"]["tenant"], "t1");
}

#[tokio::test]
async fn client_authentication_failures_are_401() {
    let (app, state) = app().await;
    let code = code_for(&state, "basic", "").await;
    let body = code_form(&code, &[]);

    let a = post_token(&app, &body, Some(("basic", "wrong"))).await;
    assert_error(&a, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(
        a.headers[header::WWW_AUTHENTICATE],
        "Basic realm=\"oauth2\""
    );

    for malformed in ["Basic !!!", "Basic Zm9v", "basic "] {
        let req = Request::post(TOKEN_PATH)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, malformed)
            .body(Body::from(body.clone()))
            .unwrap();
        let a = send(&app, req).await;
        assert_error(&a, StatusCode::UNAUTHORIZED, "invalid_client");
        assert!(
            a.headers.contains_key(header::WWW_AUTHENTICATE),
            "{malformed}"
        );
    }

    for extra in [
        vec![("client_id", "post"), ("client_secret", "wrong")],
        vec![("client_id", "basic"), ("client_secret", "basic-secret")],
        vec![("client_id", "ghost"), ("client_secret", "x")],
        vec![("client_id", "ghost")],
        vec![("client_id", "basic")],
        vec![],
    ] {
        let a = post_token(&app, &code_form(&code, &extra), None).await;
        assert_error(&a, StatusCode::UNAUTHORIZED, "invalid_client");
        assert!(
            !a.headers.contains_key(header::WWW_AUTHENTICATE),
            "{extra:?}"
        );
    }

    let a = post_token(&app, &body, Some(("ghost", "x"))).await;
    assert_error(&a, StatusCode::UNAUTHORIZED, "invalid_client");

    // The code was never touched.
    let a = post_token(&app, &body, Some(("basic", "basic-secret"))).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
}

#[tokio::test]
async fn protocol_errors_are_400() {
    let (app, state) = app().await;
    let basic = Some(("basic", "basic-secret"));
    let a = post_token(&app, &code_form("unknown", &[]), basic).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
    assert!(!a.headers.contains_key(header::WWW_AUTHENTICATE));

    let a = post_token(&app, &form(&[("grant_type", "authorization_code")]), basic).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");
    let a = post_token(&app, &form(&[("grant_type", "refresh_token")]), basic).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");
    let a = post_token(&app, &form(&[("code", "x")]), basic).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");

    let code = code_for(&state, "basic", "").await;
    let a = post_token(
        &app,
        &code_form(&code, &[("resource", "https://other.example")]),
        basic,
    )
    .await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_target");

    let req = Request::post(TOKEN_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, basic_header("basic", "basic-secret"))
        .body(Body::from("{}"))
        .unwrap();
    assert_error(
        &send(&app, req).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );

    let a = post_token(&app, &code_form(&code, &[("resource", API)]), basic).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
}

#[tokio::test]
async fn two_auth_methods_at_once_are_refused() {
    let (app, state) = app().await;
    let code = code_for(&state, "basic", "").await;
    let basic = Some(("basic", "basic-secret"));
    for extra in [
        vec![("client_secret", "basic-secret")],
        vec![("client_id", "post")],
        vec![("client_id", "basic"), ("client_secret", "basic-secret")],
    ] {
        let a = post_token(&app, &code_form(&code, &extra), basic).await;
        assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");
    }
    // A matching body client_id next to Basic is one method.
    let a = post_token(&app, &code_form(&code, &[("client_id", "basic")]), basic).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
}

#[tokio::test]
async fn a_code_redeemed_by_another_client_is_refused() {
    let (app, state) = app().await;
    let code = code_for(&state, "basic", "").await;
    let a = post_token(
        &app,
        &code_form(
            &code,
            &[("client_id", "post"), ("client_secret", "post-secret")],
        ),
        None,
    )
    .await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
    let a = post_token(
        &app,
        &code_form(&code, &[]),
        Some(("basic", "basic-secret")),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let a = post_token(
        &app,
        &code_form(&code, &[]),
        Some(("basic", "basic-secret")),
    )
    .await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
}

#[tokio::test]
async fn grant_types_are_enforced() {
    let (app, state) = app().await;
    let mut code_only = client("code-only");
    code_only.client_secret = Some("code-only-secret".to_string());
    state.oauth.create_client(code_only).await.unwrap();
    let mut refresh_only = offline_client("refresh-only");
    refresh_only.grant_types = Some(strings(&["refresh_token"]));
    refresh_only.client_secret = Some("refresh-only-secret".to_string());
    state.oauth.create_client(refresh_only).await.unwrap();

    let refresh = form(&[("grant_type", "refresh_token"), ("refresh_token", "x")]);
    let a = post_token(&app, &refresh, Some(("code-only", "code-only-secret"))).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "unauthorized_client");
    let a = post_token(
        &app,
        &code_form("x", &[]),
        Some(("refresh-only", "refresh-only-secret")),
    )
    .await;
    assert_error(&a, StatusCode::BAD_REQUEST, "unauthorized_client");

    // Without the refresh_token grant type there is no refresh token.
    let code = code_with(&state.oauth, "code-only", "alice", OFFLINE, &[], "")
        .await
        .1;
    let a = post_token(
        &app,
        &code_form(&code, &[]),
        Some(("code-only", "code-only-secret")),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert!(a.body.get("refresh_token").is_none());

    for grant_type in ["password", "client_credentials"] {
        let a = post_token(
            &app,
            &form(&[("grant_type", grant_type)]),
            Some(("basic", "basic-secret")),
        )
        .await;
        assert_error(&a, StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let device = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", "x"),
    ]);
    let a = post_token(&app, &device, Some(("basic", "basic-secret"))).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "unauthorized_client");
}

#[tokio::test]
async fn duplicate_parameters_are_refused() {
    let (app, state) = app().await;
    let code = code_for(&state, "basic", "").await;
    let basic = Some(("basic", "basic-secret"));
    for dup in [
        ("code", code.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", ""),
    ] {
        let a = post_token(&app, &code_form(&code, &[dup]), basic).await;
        assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");
    }
    let a = post_token(
        &app,
        &code_form(&code, &[("resource", API), ("resource", API)]),
        basic,
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
}

#[tokio::test]
async fn a_body_over_16_kib_is_refused() {
    let (app, state) = app().await;
    let code = code_for(&state, "basic", "").await;
    let padding = "x".repeat(MAX_BODY_BYTES);
    let body = code_form(&code, &[("padding", &padding)]);
    let a = post_token(&app, &body, Some(("basic", "basic-secret"))).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");
    let a = post_token(
        &app,
        &code_form(&code, &[]),
        Some(("basic", "basic-secret")),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
}

#[tokio::test]
async fn busy_hashing_is_503() {
    let (app, state) = app().await;
    let permits = state.oauth.hash_permits.clone();
    let held = permits
        .clone()
        .acquire_many_owned(u32::try_from(permits.available_permits()).unwrap())
        .await
        .unwrap();
    let a = post_token(&app, &code_form("x", &[]), Some(("basic", "basic-secret"))).await;
    assert_error(
        &a,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    );
    assert_eq!(a.headers[header::RETRY_AFTER], "3");
    drop(held);
}

#[tokio::test]
async fn refresh_returns_new_tokens_and_an_id_token_without_nonce() {
    let (app, state) = app().await;
    let keys = &state.oauth.keys().unwrap();
    let code = code_for(&state, "basic", "&nonce=n-1").await;
    let basic = Some(("basic", "basic-secret"));
    let first = post_token(&app, &code_form(&code, &[]), basic).await;
    let first_id = jwt::verify(
        keys,
        ISSUER,
        first.body["id_token"].as_str().unwrap(),
        Typ::IdToken,
        Some("basic"),
    )
    .unwrap();
    let refresh_token = first.body["refresh_token"].as_str().unwrap();

    let a = post_token(
        &app,
        &form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", "openid"),
        ]),
        basic,
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_no_store(&a);
    assert_eq!(a.body["scope"], "openid");
    let next = a.body["refresh_token"].as_str().unwrap();
    assert_ne!(next, refresh_token);
    let access = a.body["access_token"].as_str().unwrap();
    let id = jwt::verify(
        keys,
        ISSUER,
        a.body["id_token"].as_str().unwrap(),
        Typ::IdToken,
        Some("basic"),
    )
    .unwrap();
    assert!(id.get("nonce").is_none());
    assert_eq!(id["auth_time"], first_id["auth_time"]);
    assert_eq!(id["sid"], first_id["sid"]);
    assert_eq!(id["at_hash"], jwt::at_hash(access));
    let at = jwt::verify(keys, ISSUER, access, Typ::AccessToken, None).unwrap();
    assert_eq!(at["scp"], json!(["openid"]));

    let replay = form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ]);
    assert_error(
        &post_token(&app, &replay, basic).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    );
    let newest = form(&[("grant_type", "refresh_token"), ("refresh_token", next)]);
    assert_error(
        &post_token(&app, &newest, basic).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    );
}
