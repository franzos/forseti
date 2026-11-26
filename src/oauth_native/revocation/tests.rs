use axum::http::Request;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::Digest as _;
use tower::ServiceExt;

use super::*;
use crate::oauth_native::jwt;
use crate::oauth_native::test_support::*;
use crate::schema::{oauth_consent_grants, oauth_refresh_tokens};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Apps {
    public: axum::Router,
    internal: axum::Router,
    state: AppState,
}

async fn apps() -> Apps {
    let (public, state) = token_app().await;
    let internal = axum::Router::new()
        .merge(crate::oauth_native::routes::internal_router(&state.cfg))
        .with_state(state.clone());
    Apps {
        public,
        internal,
        state,
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    raw: String,
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
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// How a request authenticates: Basic, the body, or nothing.
#[derive(Clone, Copy)]
enum By<'a> {
    Basic(&'a str, &'a str),
    Post(&'a str, &'a str),
    Public(&'a str),
    Nobody,
}

const BASIC: By<'static> = By::Basic("basic", "basic-secret");
const POST: By<'static> = By::Post("post", "post-secret");
const PUBLIC: By<'static> = By::Public("pub");

async fn post(app: &axum::Router, path: &str, by: By<'_>, pairs: &[(&str, &str)]) -> Answer {
    let mut pairs = pairs.to_vec();
    let mut req =
        Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    match by {
        By::Basic(id, secret) => {
            req = req.header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            );
        }
        By::Post(id, secret) => pairs.extend([("client_id", id), ("client_secret", secret)]),
        By::Public(id) => pairs.push(("client_id", id)),
        By::Nobody => {}
    }
    send(app, req.body(Body::from(form(&pairs))).unwrap()).await
}

async fn revoke_by(a: &Apps, by: By<'_>, token: &str) -> Answer {
    post(&a.public, REVOKE_PATH, by, &[("token", token)]).await
}

async fn introspect_by(a: &Apps, by: By<'_>, token: &str) -> Value {
    let r = post(&a.internal, INTROSPECT_PATH, by, &[("token", token)]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
    r.body
}

async fn active(a: &Apps, token: &str) -> bool {
    introspect_by(a, POST, token).await["active"] == true
}

async fn userinfo_status(a: &Apps, token: &str) -> StatusCode {
    let req = Request::get("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    send(&a.public, req).await.status
}

struct Tokens {
    grant_id: String,
    access: String,
    refresh: String,
    id_token: String,
}

/// A code of `client` exchanged for tokens; `by` authenticates as that client.
async fn tokens_for(a: &Apps, client: &str, by: By<'_>) -> Tokens {
    let pkce = format!(
        "&code_challenge={}&code_challenge_method=S256",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(VERIFIER.as_bytes()))
    );
    let (grant_id, code) = code_with(&a.state.oauth, client, "alice", OFFLINE, &[API], &pkce).await;
    let r = post(
        &a.public,
        "/oauth2/token",
        by,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    Tokens {
        grant_id,
        access: r.body["access_token"].as_str().unwrap().to_string(),
        refresh: r.body["refresh_token"].as_str().unwrap().to_string(),
        id_token: r.body["id_token"].as_str().unwrap().to_string(),
    }
}

/// The access and refresh token of one rotation of `refresh`.
async fn rotated(a: &Apps, by: By<'_>, refresh: &str) -> (String, String) {
    let r = post(
        &a.public,
        "/oauth2/token",
        by,
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    (
        r.body["access_token"].as_str().unwrap().to_string(),
        r.body["refresh_token"].as_str().unwrap().to_string(),
    )
}

async fn refresh_rows_of(db: &DbPool, grant_id: &str) -> i64 {
    let grant_id = grant_id.to_string();
    let r: Result<i64> = async {
        Ok(db_interact!(db, |c| {
            oauth_refresh_tokens::table
                .filter(oauth_refresh_tokens::grant_id.eq(grant_id))
                .count()
                .get_result(c)
        })?)
    }
    .await;
    r.unwrap()
}

async fn revoked_at(db: &DbPool, grant_id: &str) -> Option<String> {
    grants::find(db, grant_id)
        .await
        .unwrap()
        .unwrap()
        .tokens_revoked_at
}

async fn denylist(db: &DbPool) -> Vec<(String, String)> {
    let r: Result<Vec<(String, String)>> = async {
        Ok(db_interact!(db, |c| {
            oauth_revoked_tokens::table
                .order(oauth_revoked_tokens::jti)
                .select((oauth_revoked_tokens::jti, oauth_revoked_tokens::expires_at))
                .load(c)
        })?)
    }
    .await;
    r.unwrap()
}

fn claims_of(a: &Apps, access: &str) -> Value {
    let keys = a.state.oauth.keys().unwrap();
    jwt::verify(&keys, ISSUER, access, Typ::AccessToken, None).unwrap()
}

fn assert_ok_empty(r: &Answer) {
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert!(r.raw.is_empty(), "{}", r.raw);
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
}

fn assert_error(r: &Answer, status: StatusCode, error: &str) {
    assert_eq!(r.status, status, "{}", r.raw);
    assert_eq!(r.body["error"], error, "{}", r.raw);
}

#[tokio::test]
async fn the_migration_adds_the_denylist_and_the_grant_column() {
    let db = crate::db::test_pool().await;
    let r: Result<(Vec<String>, Vec<Option<String>>)> = async {
        Ok(db_interact!(db, |c| {
            let jtis = oauth_revoked_tokens::table
                .select(oauth_revoked_tokens::jti)
                .load::<String>(c)?;
            let at = oauth_consent_grants::table
                .select(oauth_consent_grants::tokens_revoked_at)
                .load::<Option<String>>(c)?;
            Ok::<_, diesel::result::Error>((jtis, at))
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), (vec![], vec![]));
}

#[tokio::test]
async fn a_token_issued_after_the_recorded_revoke_instant_is_still_inactive() {
    let a = apps().await;
    let db = &a.state.db;
    let t = tokens_for(&a, "basic", BASIC).await;
    let iat = claims_of(&a, &t.access)["iat"].as_i64().unwrap();
    let earlier = DateTime::from_timestamp(iat - 3600, 0).unwrap();
    let (grant_id, at) = (t.grant_id.clone(), rfc3339(earlier));
    let r: Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(oauth_consent_grants::table.find(grant_id))
                .set(oauth_consent_grants::tokens_revoked_at.eq(Some(at)))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
    assert_eq!(
        introspect_by(&a, POST, &t.access).await,
        json!({"active": false})
    );
    assert_eq!(
        userinfo_status(&a, &t.access).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn revoking_a_refresh_token_ends_its_family_and_the_grants_access_tokens() {
    let a = apps().await;
    let db = &a.state.db;
    let t = tokens_for(&a, "basic", BASIC).await;
    let (sibling, newest) = rotated(&a, BASIC, &t.refresh).await;
    assert_eq!(refresh_rows_of(db, &t.grant_id).await, 2);
    assert!(active(&a, &t.access).await);
    assert!(active(&a, &sibling).await);

    assert_ok_empty(&revoke_by(&a, BASIC, &newest).await);

    assert_eq!(refresh_rows_of(db, &t.grant_id).await, 0);
    assert!(revoked_at(db, &t.grant_id).await.is_some());
    assert!(denylist(db).await.is_empty());
    for access in [&t.access, &sibling] {
        assert_eq!(
            introspect_by(&a, POST, access).await,
            json!({"active": false})
        );
        assert_eq!(userinfo_status(&a, access).await, StatusCode::UNAUTHORIZED);
    }
    assert!(!active(&a, &newest).await);
    let r = post(
        &a.public,
        "/oauth2/token",
        BASIC,
        &[("grant_type", "refresh_token"), ("refresh_token", &newest)],
    )
    .await;
    assert_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");

    // A new authorization is a new grant and is not affected.
    let fresh = tokens_for(&a, "basic", BASIC).await;
    assert_ne!(fresh.grant_id, t.grant_id);
    assert!(active(&a, &fresh.access).await);
    assert!(active(&a, &fresh.refresh).await);
    assert_eq!(userinfo_status(&a, &fresh.access).await, StatusCode::OK);
}

#[tokio::test]
async fn revoking_a_used_refresh_token_also_ends_the_family() {
    let a = apps().await;
    let t = tokens_for(&a, "basic", BASIC).await;
    let (_, newest) = rotated(&a, BASIC, &t.refresh).await;
    assert_ok_empty(&revoke_by(&a, BASIC, &t.refresh).await);
    assert_eq!(refresh_rows_of(&a.state.db, &t.grant_id).await, 0);
    assert!(!active(&a, &newest).await);
    assert!(!active(&a, &t.access).await);
}

#[tokio::test]
async fn revoking_an_access_token_denies_its_jti_until_exp_plus_the_leeway() {
    let a = apps().await;
    let db = &a.state.db;
    let t = tokens_for(&a, "basic", BASIC).await;
    let claims = claims_of(&a, &t.access);

    assert_ok_empty(&revoke_by(&a, BASIC, &t.access).await);
    assert_ok_empty(&revoke_by(&a, BASIC, &t.access).await);

    let until = DateTime::from_timestamp(claims["exp"].as_i64().unwrap() + 60, 0).unwrap();
    assert_eq!(
        denylist(db).await,
        [(claims["jti"].as_str().unwrap().to_string(), rfc3339(until))]
    );
    assert_eq!(
        introspect_by(&a, POST, &t.access).await,
        json!({"active": false})
    );
    assert_eq!(
        userinfo_status(&a, &t.access).await,
        StatusCode::UNAUTHORIZED
    );

    // The grant and its refresh token stay.
    assert!(revoked_at(db, &t.grant_id).await.is_none());
    assert!(active(&a, &t.refresh).await);
    let (next, _) = rotated(&a, BASIC, &t.refresh).await;
    assert!(active(&a, &next).await);
    assert_eq!(userinfo_status(&a, &next).await, StatusCode::OK);
}

#[tokio::test]
async fn foreign_unknown_malformed_and_expired_tokens_answer_200_and_change_nothing() {
    let a = apps().await;
    let db = &a.state.db;
    let t = tokens_for(&a, "basic", BASIC).await;

    for token in [
        t.access.as_str(),
        t.refresh.as_str(),
        "unknown",
        "a.b.c",
        "eyJhbGciOiJub25lIn0.e30.",
        t.id_token.as_str(),
    ] {
        assert_ok_empty(&revoke_by(&a, POST, token).await);
        assert_ok_empty(&revoke_by(&a, PUBLIC, token).await);
    }
    for token in ["unknown", "a.b.c", t.id_token.as_str()] {
        assert_ok_empty(&revoke_by(&a, BASIC, token).await);
    }
    assert!(denylist(db).await.is_empty());
    assert_eq!(refresh_rows_of(db, &t.grant_id).await, 1);
    assert!(revoked_at(db, &t.grant_id).await.is_none());
    assert!(active(&a, &t.access).await);
    assert!(active(&a, &t.refresh).await);

    let (hash, past) = (
        crate::oauth_native::token_hash(&t.refresh),
        rfc3339(Utc::now() - chrono::Duration::seconds(1)),
    );
    let r: Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(
                oauth_refresh_tokens::table.filter(oauth_refresh_tokens::token_hash.eq(hash)),
            )
            .set(oauth_refresh_tokens::expires_at.eq(past))
            .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
    assert_ok_empty(&revoke_by(&a, BASIC, &t.refresh).await);
    assert_eq!(refresh_rows_of(db, &t.grant_id).await, 1);
    assert!(revoked_at(db, &t.grant_id).await.is_none());
    assert!(active(&a, &t.access).await);
}

#[tokio::test]
async fn a_public_client_revokes_its_own_tokens() {
    let a = apps().await;
    let db = &a.state.db;
    let first = tokens_for(&a, "pub", PUBLIC).await;
    assert_ok_empty(&revoke_by(&a, PUBLIC, &first.access).await);
    assert_eq!(denylist(db).await.len(), 1);
    assert!(!active(&a, &first.access).await);

    let second = tokens_for(&a, "pub", PUBLIC).await;
    assert_ok_empty(&revoke_by(&a, PUBLIC, &second.refresh).await);
    assert_eq!(refresh_rows_of(db, &second.grant_id).await, 0);
    assert!(!active(&a, &second.access).await);
}

#[tokio::test]
async fn request_errors_at_revocation() {
    let a = apps().await;
    let t = tokens_for(&a, "basic", BASIC).await;

    for pairs in [
        vec![],
        vec![("token", "")],
        vec![("token_type_hint", "refresh_token")],
    ] {
        let r = post(&a.public, REVOKE_PATH, BASIC, &pairs).await;
        assert_error(&r, StatusCode::BAD_REQUEST, "invalid_request");
    }
    let r = post(
        &a.public,
        REVOKE_PATH,
        BASIC,
        &[("token", &t.access), ("token", &t.access)],
    )
    .await;
    assert_error(&r, StatusCode::BAD_REQUEST, "invalid_request");

    let r = revoke_by(&a, By::Basic("basic", "wrong"), &t.access).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(
        r.headers[header::WWW_AUTHENTICATE],
        "Basic realm=\"oauth2\""
    );
    for by in [
        By::Post("post", "wrong"),
        By::Post("ghost", "x"),
        By::Public("ghost"),
        By::Public("basic"),
        By::Nobody,
    ] {
        let r = revoke_by(&a, by, &t.access).await;
        assert_error(&r, StatusCode::UNAUTHORIZED, "invalid_client");
        assert!(!r.headers.contains_key(header::WWW_AUTHENTICATE));
    }
    assert!(denylist(&a.state.db).await.is_empty());

    // The hint is accepted and ignored.
    let r = post(
        &a.public,
        REVOKE_PATH,
        BASIC,
        &[("token", &t.access), ("token_type_hint", "refresh_token")],
    )
    .await;
    assert_ok_empty(&r);
    assert!(!active(&a, &t.access).await);
}

#[tokio::test]
async fn busy_hashing_at_revocation_is_503() {
    let a = apps().await;
    let permits = a.state.oauth.hash_permits.clone();
    let held = permits
        .clone()
        .acquire_many_owned(u32::try_from(permits.available_permits()).unwrap())
        .await
        .unwrap();
    let r = revoke_by(&a, BASIC, "x").await;
    assert_error(
        &r,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    );
    assert_eq!(r.headers[header::RETRY_AFTER], "3");
    drop(held);
}

#[tokio::test]
async fn introspection_of_an_access_token() {
    let a = apps().await;
    let t = tokens_for(&a, "basic", BASIC).await;
    let claims = claims_of(&a, &t.access);
    let want = json!({
        "active": true,
        "scope": "openid email offline_access",
        "client_id": "basic",
        "sub": "alice",
        "exp": claims["exp"],
        "iat": claims["iat"],
        "nbf": claims["nbf"],
        "aud": [API],
        "iss": ISSUER,
        "jti": claims["jti"],
        "token_type": "bearer",
    });
    assert_eq!(introspect_by(&a, POST, &t.access).await, want);
    assert_eq!(introspect_by(&a, BASIC, &t.access).await, want);
    assert_eq!(
        introspect_by(&a, POST, &t.id_token).await,
        json!({"active": false})
    );
    assert_eq!(
        introspect_by(&a, POST, "unknown").await,
        json!({"active": false})
    );
}

#[tokio::test]
async fn introspection_of_a_refresh_token() {
    let a = apps().await;
    let t = tokens_for(&a, "basic", BASIC).await;
    let got = introspect_by(&a, POST, &t.refresh).await;
    let mut keys: Vec<&String> = got.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "active",
            "aud",
            "client_id",
            "exp",
            "iat",
            "iss",
            "scope",
            "sub"
        ]
    );
    assert_eq!(got["active"], true);
    assert_eq!(got["scope"], "openid email offline_access");
    assert_eq!(got["client_id"], "basic");
    assert_eq!(got["sub"], "alice");
    assert_eq!(got["aud"], json!([API]));
    assert_eq!(got["iss"], ISSUER);
    let ttl = got["exp"].as_i64().unwrap() - got["iat"].as_i64().unwrap();
    assert_eq!(ttl, crate::oauth_native::REFRESH_TOKEN_TTL_SECS);

    let (_, newest) = rotated(&a, BASIC, &t.refresh).await;
    assert_eq!(
        introspect_by(&a, POST, &t.refresh).await,
        json!({"active": false})
    );
    assert!(active(&a, &newest).await);
}

#[tokio::test]
async fn an_expired_access_token_is_inactive() {
    let a = apps().await;
    let t = tokens_for(&a, "basic", BASIC).await;
    let keys = a.state.oauth.keys().unwrap();
    let now = Utc::now().timestamp();
    for exp in [now - 10, now - 3600] {
        let mut claims = claims_of(&a, &t.access);
        claims["iat"] = json!(exp - 300);
        claims["nbf"] = json!(exp - 300);
        claims["exp"] = json!(exp);
        let expired = jwt::sign(&keys, Typ::AccessToken, &claims).unwrap();
        assert_eq!(
            introspect_by(&a, POST, &expired).await,
            json!({"active": false})
        );
    }
}

#[tokio::test]
async fn introspection_needs_a_confidential_client() {
    let a = apps().await;
    let t = tokens_for(&a, "basic", BASIC).await;
    for by in [
        PUBLIC,
        By::Basic("pub", "pub-secret"),
        By::Basic("basic", "wrong"),
        By::Post("ghost", "x"),
        By::Nobody,
    ] {
        let r = post(&a.internal, INTROSPECT_PATH, by, &[("token", &t.access)]).await;
        assert_error(&r, StatusCode::UNAUTHORIZED, "invalid_client");
        assert!(r.body.get("active").is_none(), "{}", r.raw);
    }
    let r = post(&a.internal, INTROSPECT_PATH, POST, &[]).await;
    assert_error(&r, StatusCode::BAD_REQUEST, "invalid_request");
}

#[tokio::test]
async fn introspection_is_not_on_the_public_router() {
    let a = apps().await;
    let r = post(&a.public, INTROSPECT_PATH, POST, &[("token", "x")]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = post(&a.internal, REVOKE_PATH, POST, &[("token", "x")]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}
