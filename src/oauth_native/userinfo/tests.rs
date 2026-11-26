use axum::http::Request;
use tower::ServiceExt;

use super::*;
use crate::backend::OAuthBackend;
use crate::oauth_native::jwt;
use crate::oauth_native::test_support::*;

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

/// The token response for a fresh code of `basic` with `scope`, and the grant id.
async fn tokens(app: &axum::Router, state: &AppState, scope: &[&str]) -> (Value, String) {
    let (grant_id, code) = code_with(&state.oauth, "basic", "alice", scope, &[API], "").await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("client_id", "basic"),
        ])
        .finish();
    let req = Request::post("/oauth2/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    "basic:basic-secret"
                )
            ),
        )
        .body(Body::from(body))
        .unwrap();
    let a = send(app, req).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    (a.body, grant_id)
}

fn get_with(token: &str) -> Request<Body> {
    Request::get(USERINFO_PATH)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_form(body: String, bearer: Option<&str>) -> Request<Body> {
    let mut req = Request::post(USERINFO_PATH)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(token) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    req.body(Body::from(body)).unwrap()
}

fn assert_bearer_error(a: &Answer, status: StatusCode, challenge: &str) {
    assert_eq!(a.status, status, "{}", a.body);
    assert_eq!(a.headers[header::WWW_AUTHENTICATE], challenge);
    assert_eq!(a.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(a.headers[header::CONTENT_TYPE], "application/json");
    assert!(a.body["error"].is_string(), "{}", a.body);
}

const INVALID_TOKEN: &str = "Bearer error=\"invalid_token\"";

#[tokio::test]
async fn a_valid_token_returns_sub_and_the_snapshot() {
    let (app, state) = token_app().await;
    let (t, _) = tokens(&app, &state, &["openid", "email"]).await;
    let access = t["access_token"].as_str().unwrap();
    let want = json!({"sub": "alice", "email": "alice@example.com"});

    let a = send(&app, get_with(access)).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(a.headers[header::CONTENT_TYPE], "application/json");
    assert!(a.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert_eq!(a.body, want);

    let req = Request::get(USERINFO_PATH)
        .header(header::AUTHORIZATION, format!("bearer {access}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.body, want);

    let a = send(&app, post_form(format!("access_token={access}"), None)).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body, want);
    let a = send(&app, post_form(String::new(), Some(access))).await;
    assert_eq!(a.body, want);
}

#[tokio::test]
async fn an_id_token_is_not_an_access_token() {
    let (app, state) = token_app().await;
    let (t, _) = tokens(&app, &state, &["openid"]).await;
    let a = send(&app, get_with(t["id_token"].as_str().unwrap())).await;
    assert_bearer_error(&a, StatusCode::UNAUTHORIZED, INVALID_TOKEN);
    let a = send(&app, get_with("not-a-jwt")).await;
    assert_bearer_error(&a, StatusCode::UNAUTHORIZED, INVALID_TOKEN);
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let (app, state) = token_app().await;
    let (t, _) = tokens(&app, &state, &["openid"]).await;
    let keys = state.oauth.keys().unwrap();
    let mut claims = jwt::verify(
        &keys,
        ISSUER,
        t["access_token"].as_str().unwrap(),
        Typ::AccessToken,
        None,
    )
    .unwrap();
    let past = i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap() - 3600;
    claims["iat"] = json!(past - 300);
    claims["nbf"] = json!(past - 300);
    claims["exp"] = json!(past);
    let expired = jwt::sign(&keys, Typ::AccessToken, &claims).unwrap();
    let a = send(&app, get_with(&expired)).await;
    assert_bearer_error(&a, StatusCode::UNAUTHORIZED, INVALID_TOKEN);
}

#[tokio::test]
async fn a_token_without_openid_has_insufficient_scope() {
    let (app, state) = token_app().await;
    let (t, _) = tokens(&app, &state, &["email"]).await;
    assert!(t.get("id_token").is_none());
    let a = send(&app, get_with(t["access_token"].as_str().unwrap())).await;
    assert_bearer_error(
        &a,
        StatusCode::FORBIDDEN,
        "Bearer error=\"insufficient_scope\", scope=\"openid\"",
    );
    assert_eq!(a.body["error"], "insufficient_scope");
}

#[tokio::test]
async fn a_revoked_grant_refuses_its_tokens() {
    let (app, state) = token_app().await;
    let (t, grant_id) = tokens(&app, &state, &["openid", "email"]).await;
    state
        .oauth
        .revoke_consent_sessions_by_request_id(&grant_id)
        .await
        .unwrap();
    let a = send(&app, get_with(t["access_token"].as_str().unwrap())).await;
    assert_bearer_error(&a, StatusCode::UNAUTHORIZED, INVALID_TOKEN);
}

#[tokio::test]
async fn the_query_string_is_never_read() {
    let (app, state) = token_app().await;
    let (t, _) = tokens(&app, &state, &["openid"]).await;
    let access = t["access_token"].as_str().unwrap();
    let req = Request::get(format!("{USERINFO_PATH}?access_token={access}"))
        .body(Body::empty())
        .unwrap();
    let a = send(&app, req).await;
    assert_bearer_error(&a, StatusCode::UNAUTHORIZED, "Bearer");
    let req = Request::post(format!("{USERINFO_PATH}?access_token={access}"))
        .body(Body::empty())
        .unwrap();
    assert_bearer_error(&send(&app, req).await, StatusCode::UNAUTHORIZED, "Bearer");
}

#[tokio::test]
async fn one_token_per_request() {
    let (app, state) = token_app().await;
    let (t, _) = tokens(&app, &state, &["openid"]).await;
    let access = t["access_token"].as_str().unwrap();
    let invalid_request = "Bearer error=\"invalid_request\"";
    let a = send(
        &app,
        post_form(format!("access_token={access}"), Some(access)),
    )
    .await;
    assert_bearer_error(&a, StatusCode::BAD_REQUEST, invalid_request);
    let a = send(
        &app,
        post_form(format!("access_token={access}&access_token={access}"), None),
    )
    .await;
    assert_bearer_error(&a, StatusCode::BAD_REQUEST, invalid_request);
    let req = Request::get(USERINFO_PATH)
        .header(header::AUTHORIZATION, "Bearer ")
        .body(Body::empty())
        .unwrap();
    assert_bearer_error(
        &send(&app, req).await,
        StatusCode::UNAUTHORIZED,
        INVALID_TOKEN,
    );
}

#[tokio::test]
async fn a_token_signed_after_a_rotation_elsewhere_is_accepted() {
    let (app, state) = token_app().await;
    let (t, _) = tokens(&app, &state, &["openid", "email"]).await;
    let old = &state.oauth.keys().unwrap();
    let claims = jwt::verify(
        old,
        ISSUER,
        t["access_token"].as_str().unwrap(),
        Typ::AccessToken,
        None,
    )
    .unwrap();

    let elsewhere = crate::oauth_native::NativeOAuth::new(&state.cfg, &state.db, &[0x42; 32]);
    let rotated = elsewhere.rotate_key().await.unwrap();
    elsewhere.init().await.unwrap();
    let new = &elsewhere.keys().unwrap();
    assert_eq!(new.signing().kid, rotated.active);
    let token = jwt::sign(new, Typ::AccessToken, &claims).unwrap();

    let a = send(&app, get_with(&token)).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["sub"], "alice");
    assert_eq!(state.oauth.keys().unwrap().signing().kid, rotated.active);
    let a = send(&app, get_with(t["access_token"].as_str().unwrap())).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
}
