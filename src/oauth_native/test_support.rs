//! Fixtures shared by the challenge, session and grant tests.

use std::sync::Arc;

use diesel::prelude::*;
use serde_json::{Map, json};

use super::authorize::{self, AuthorizeQuery};
use super::challenge::{self, ChallengeError, Resumed};
use super::sessions::LoginSession;
use super::{NativeOAuth, clients};
use crate::backend::OAuthBackend;
use crate::backend::oauth::{OAuthClient, RedirectTo};
use crate::config::AppConfig;
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{
    oauth_authorization_codes, oauth_authorize_requests, oauth_consent_grants, oauth_login_sessions,
};

pub(super) const REDIRECT: &str = "https://app.example/cb";
pub(super) const API: &str = "https://api.example";

pub(super) async fn backend_on(db: &DbPool) -> Arc<NativeOAuth> {
    NativeOAuth::new(&AppConfig::test_fixture(), db, &[0x42; 32])
}

pub(super) async fn backend() -> Arc<NativeOAuth> {
    backend_on(&crate::db::test_pool().await).await
}

pub(super) fn client(id: &str) -> OAuthClient {
    OAuthClient {
        client_id: Some(id.to_string()),
        client_name: Some(format!("App {id}")),
        redirect_uris: Some(vec![REDIRECT.to_string()]),
        scope: Some("openid email profile offline_access".to_string()),
        audience: Some(vec![API.to_string()]),
        token_endpoint_auth_method: Some("client_secret_basic".to_string()),
        metadata: Some(json!({"forseti": {"client_type": "web_app"}})),
        ..OAuthClient::default()
    }
}

pub(super) async fn register(o: &NativeOAuth, id: &str) -> OAuthClient {
    o.create_client(client(id)).await.unwrap()
}

pub(super) fn raw_query(client_id: &str, extra: &str) -> String {
    format!(
        "client_id={}&redirect_uri={}&response_type=code&scope=openid+email&state=xyz{extra}",
        crate::web::urlencode(client_id),
        crate::web::urlencode(REDIRECT),
    )
}

pub(super) struct Started {
    pub(super) id: String,
    pub(super) challenge: String,
}

/// Validates and stores a request with the raw query `raw`.
pub(super) async fn start_raw(
    o: &NativeOAuth,
    raw: &str,
    remembered: Option<&LoginSession>,
) -> Started {
    let query = AuthorizeQuery::parse(raw);
    let client = clients::get(&o.db, query.client_id().unwrap())
        .await
        .unwrap();
    let req = authorize::validate(&query, client.as_ref()).unwrap();
    let url = authorize::request_url(&o.issuer, raw);
    let (id, challenge) = challenge::create(&o.db, &req, url, remembered)
        .await
        .unwrap();
    Started { id, challenge }
}

pub(super) async fn start(o: &NativeOAuth, client_id: &str, extra: &str) -> Started {
    start_raw(o, &raw_query(client_id, extra), None).await
}

/// The request id in the path of a resume URL.
pub(super) fn flow_of(r: &RedirectTo) -> String {
    let url = url::Url::parse(&r.redirect_to).unwrap();
    let id = url.path().rsplit('/').next().unwrap().to_string();
    assert_eq!(url.path(), challenge::resume_path(&id), "{}", r.redirect_to);
    id
}

pub(super) fn verifier_of(r: &RedirectTo) -> String {
    flow_of(r);
    url::Url::parse(&r.redirect_to)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "verifier")
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

pub(super) async fn resume(
    o: &NativeOAuth,
    s: &Started,
    r: &RedirectTo,
) -> anyhow::Result<Resumed> {
    challenge::resume(&o.db, &flow_of(r), &verifier_of(r), |id| id == s.id).await
}

pub(super) async fn accept_login(
    o: &NativeOAuth,
    s: &Started,
    subject: &str,
    remember: bool,
) -> anyhow::Result<RedirectTo> {
    o.accept_login_request(
        &s.challenge,
        subject,
        remember,
        86_400,
        vec!["pwd".to_string()],
        Some("aal1".to_string()),
    )
    .await
}

/// Login accepted and resumed: the consent challenge.
pub(super) async fn to_consent(
    o: &NativeOAuth,
    s: &Started,
    subject: &str,
    remember: bool,
) -> String {
    let r = accept_login(o, s, subject, remember).await.unwrap();
    match resume(o, s, &r).await.unwrap() {
        Resumed::Consent { challenge, .. } => challenge,
        other => panic!("expected consent, got {other:?}"),
    }
}

pub(super) async fn accept_consent(
    o: &NativeOAuth,
    consent: &str,
    scope: &[&str],
    audience: &[&str],
    remember: bool,
) -> anyhow::Result<RedirectTo> {
    let mut access = Map::new();
    access.insert("tenant".to_string(), json!("t1"));
    o.accept_consent_request(
        consent,
        scope.iter().map(|s| (*s).to_string()).collect(),
        audience.iter().map(|a| (*a).to_string()).collect(),
        remember,
        json!({"email": "alice@example.com"}),
        access,
    )
    .await
}

/// A finished request for `subject`: the request id (also the grant id) and the code.
pub(super) async fn finish(
    o: &NativeOAuth,
    client_id: &str,
    subject: &str,
    remember_consent: bool,
) -> (String, String) {
    let s = start(o, client_id, "").await;
    let consent = to_consent(o, &s, subject, true).await;
    let r = accept_consent(o, &consent, &["openid", "email"], &[API], remember_consent)
        .await
        .unwrap();
    match resume(o, &s, &r).await.unwrap() {
        Resumed::Code { code, .. } => (s.id, code),
        other => panic!("expected a code, got {other:?}"),
    }
}

/// [`client`] registered for the `refresh_token` grant as well.
pub(super) fn offline_client(id: &str) -> OAuthClient {
    OAuthClient {
        grant_types: Some(strings(&["authorization_code", "refresh_token"])),
        ..client(id)
    }
}

/// A code for `subject`, `scope` requested and granted with `audience`; `extra` goes on the
/// authorize query. The grant id and the code.
pub(super) async fn code_with(
    o: &NativeOAuth,
    client_id: &str,
    subject: &str,
    scope: &[&str],
    audience: &[&str],
    extra: &str,
) -> (String, String) {
    let raw = format!(
        "client_id={}&redirect_uri={}&response_type=code&scope={}&state=xyz{extra}",
        crate::web::urlencode(client_id),
        crate::web::urlencode(REDIRECT),
        scope.join("+"),
    );
    let s = start_raw(o, &raw, None).await;
    let consent = to_consent(o, &s, subject, true).await;
    let r = accept_consent(o, &consent, scope, audience, true)
        .await
        .unwrap();
    match resume(o, &s, &r).await.unwrap() {
        Resumed::Code { code, .. } => (s.id, code),
        other => panic!("expected a code, got {other:?}"),
    }
}

pub(super) const ISSUER: &str = "https://id.example.com";
pub(super) const OFFLINE: &[&str] = &["openid", "email", "offline_access"];

/// The native routes on a fresh state at [`ISSUER`], with the offline clients `basic`, `post` and
/// `pub` registered by those auth methods; each confidential one's secret is `<id>-secret`.
pub(super) async fn token_app() -> (axum::Router, crate::state::AppState) {
    let mut cfg = AppConfig::test_fixture();
    cfg.self_.url = format!("{ISSUER}/");
    // Refused at once, so the provider probe does not wait on DNS.
    #[cfg(feature = "identity-ory")]
    {
        cfg.kratos.public_url = "http://127.0.0.1:1".to_string();
    }
    let db = crate::db::test_pool().await;
    let identity = crate::backend::build_identity(&cfg, &db, &[0x42; 32]);
    let state = crate::state::AppState::for_test(cfg, db, identity, &[0x42; 32]);
    state.oauth.init().await.unwrap();
    let app = axum::Router::new()
        .merge(super::routes::router(&state.cfg))
        .with_state(state.clone());
    for (id, method) in [
        ("basic", clients::AUTH_BASIC),
        ("post", clients::AUTH_POST),
        ("pub", clients::AUTH_NONE),
    ] {
        state
            .oauth
            .create_client(OAuthClient {
                token_endpoint_auth_method: Some(method.to_string()),
                client_secret: Some(format!("{id}-secret")),
                ..offline_client(id)
            })
            .await
            .unwrap();
    }
    (app, state)
}

/// `req` from a fixed peer address, which the per-IP rate limits key on.
pub(super) fn with_peer(
    mut req: axum::http::Request<axum::body::Body>,
) -> axum::http::Request<axum::body::Body> {
    let addr: std::net::SocketAddr = "192.0.2.7:443".parse().unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    req
}

pub(super) fn refusal(e: &anyhow::Error) -> Option<ChallengeError> {
    e.downcast_ref::<ChallengeError>().copied()
}

/// `(state, verifier_hash, consent_challenge_hash)` of request `id`.
pub(super) async fn flow_state(db: &DbPool, id: &str) -> (String, Option<String>, Option<String>) {
    let id = id.to_string();
    let r: anyhow::Result<_> = async {
        Ok(db_interact!(db, |c| {
            oauth_authorize_requests::table
                .find(id)
                .select((
                    oauth_authorize_requests::state,
                    oauth_authorize_requests::verifier_hash,
                    oauth_authorize_requests::consent_challenge_hash,
                ))
                .first::<(String, Option<String>, Option<String>)>(c)
        })?)
    }
    .await;
    r.unwrap()
}

/// The `sid` of request `id`.
pub(super) async fn sid_of(db: &DbPool, id: &str) -> String {
    let id = id.to_string();
    let r: anyhow::Result<String> = async {
        Ok(db_interact!(db, |c| {
            oauth_authorize_requests::table
                .find(id)
                .select(oauth_authorize_requests::session_id)
                .first(c)
        })?)
    }
    .await;
    r.unwrap()
}

pub(super) async fn flow_count(db: &DbPool, client_id: &str) -> i64 {
    let client_id = client_id.to_string();
    let r: anyhow::Result<i64> = async {
        Ok(db_interact!(db, |c| {
            oauth_authorize_requests::table
                .filter(oauth_authorize_requests::client_id.eq(client_id))
                .count()
                .get_result(c)
        })?)
    }
    .await;
    r.unwrap()
}

pub(super) async fn grant_count(db: &DbPool, subject: &str) -> i64 {
    let subject = subject.to_string();
    let r: anyhow::Result<i64> = async {
        Ok(db_interact!(db, |c| {
            oauth_consent_grants::table
                .filter(oauth_consent_grants::subject.eq(subject))
                .count()
                .get_result(c)
        })?)
    }
    .await;
    r.unwrap()
}

/// The code row's `(grant_id, auth_time, scope, audience, family_id, expires_at)`, by code.
pub(super) async fn code_row(
    db: &DbPool,
    code: &str,
) -> Option<(String, String, String, String, String, String)> {
    let hash = super::token_hash(code);
    let r: anyhow::Result<_> = async {
        Ok(db_interact!(db, |c| {
            oauth_authorization_codes::table
                .find(hash)
                .select((
                    oauth_authorization_codes::grant_id,
                    oauth_authorization_codes::auth_time,
                    oauth_authorization_codes::scope,
                    oauth_authorization_codes::audience,
                    oauth_authorization_codes::family_id,
                    oauth_authorization_codes::expires_at,
                ))
                .first(c)
                .optional()
        })?)
    }
    .await;
    r.unwrap()
}

pub(super) async fn code_count(db: &DbPool) -> i64 {
    let r: anyhow::Result<i64> = async {
        Ok(db_interact!(db, |c| {
            oauth_authorization_codes::table.count().get_result(c)
        })?)
    }
    .await;
    r.unwrap()
}

pub(super) async fn expire_flow(db: &DbPool, id: &str) {
    let (id, past) = (
        id.to_string(),
        crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::seconds(1)),
    );
    let r: anyhow::Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(oauth_authorize_requests::table.find(id))
                .set(oauth_authorize_requests::expires_at.eq(past))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
}

pub(super) async fn set_flow_sid(db: &DbPool, id: &str, sid: &str) {
    let (id, sid) = (id.to_string(), sid.to_string());
    let r: anyhow::Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(oauth_authorize_requests::table.find(id))
                .set(oauth_authorize_requests::session_id.eq(sid))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
}

pub(super) async fn expire_session(db: &DbPool, sid: &str) {
    let (sid, past) = (
        sid.to_string(),
        crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::seconds(1)),
    );
    let r: anyhow::Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(oauth_login_sessions::table.find(sid))
                .set(oauth_login_sessions::expires_at.eq(past))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
}

/// Accepts `consent` as the consent handler's automatic path does.
pub(super) async fn accept_auto(o: &NativeOAuth, consent: &str) -> RedirectTo {
    o.accept_consent_on(
        crate::oauth::consent::GrantPath::Auto,
        consent,
        strings(&["openid", "email"]),
        strings(&[API]),
        json!({"email": "alice@example.com"}),
        Map::new(),
    )
    .await
    .unwrap()
}

/// A request of `client_id` for `subject` accepted automatically; the grant id.
pub(super) async fn finish_auto(o: &NativeOAuth, client_id: &str, subject: &str) -> String {
    let s = start(o, client_id, "").await;
    let consent = to_consent(o, &s, subject, true).await;
    let r = accept_auto(o, &consent).await;
    assert!(matches!(
        resume(o, &s, &r).await.unwrap(),
        Resumed::Code { .. }
    ));
    s.id
}

pub(super) async fn set_skip_consent(o: &NativeOAuth, id: &str, on: bool) {
    let current = clients::get(&o.db, id).await.unwrap().unwrap();
    o.update_client(
        id,
        OAuthClient {
            skip_consent: Some(on),
            ..current
        },
    )
    .await
    .unwrap();
}

/// `(remember, skipped, auto_granted)` of grant `id`.
pub(super) async fn grant_flags(db: &DbPool, id: &str) -> (i32, i32, i32) {
    let id = id.to_string();
    let r: anyhow::Result<_> = async {
        Ok(db_interact!(db, |c| {
            oauth_consent_grants::table
                .find(id)
                .select((
                    oauth_consent_grants::remember,
                    oauth_consent_grants::skipped,
                    oauth_consent_grants::auto_granted,
                ))
                .first::<(i32, i32, i32)>(c)
        })?)
    }
    .await;
    r.unwrap()
}

/// The rows an approval of `device_code` leaves: a grant of `scope` to `subject`, its code stored
/// under the device code's hash without a redirect URI, and the device row `approved` naming the
/// grant's request. The grant id.
pub(super) async fn approve_device(
    o: &NativeOAuth,
    device_code: &str,
    subject: &str,
    scope: &[&str],
) -> String {
    use super::grants::{self, CodeFor, GrantRow};
    use crate::schema::oauth_device_codes;
    let hash = super::token_hash(device_code);
    let now = chrono::Utc::now();
    let id = uuid::Uuid::new_v4().to_string();
    let client_id: String = {
        let hash = hash.clone();
        let r: anyhow::Result<String> = async {
            Ok(db_interact!(o.db, |c| {
                oauth_device_codes::table
                    .find(hash)
                    .select(oauth_device_codes::client_id)
                    .first(c)
            })?)
        }
        .await;
        r.unwrap()
    };
    let grant = GrantRow {
        id: id.clone(),
        client_id,
        subject: subject.to_string(),
        session_id: format!("sid-{id}"),
        scope: super::to_json(&strings(scope)).unwrap(),
        audience: "[]".to_string(),
        id_token_claims: json!({"email": "alice@example.com"}).to_string(),
        access_token_claims: "{}".to_string(),
        remember: 0,
        skipped: 0,
        handled_at: crate::db::rfc3339(now),
        auto_granted: 0,
        tokens_revoked_at: None,
    };
    let auth_time = crate::db::rfc3339(now);
    let (_, mut code) = grants::new_code(
        &CodeFor {
            grant: &grant,
            redirect_uri: "",
            code_challenge: None,
            nonce: None,
            auth_time: &auth_time,
            acr: Some("aal1"),
            amr: r#"["pwd"]"#,
        },
        now,
    );
    code.code_hash = hash.clone();
    let r: anyhow::Result<usize> = async {
        Ok(db_interact!(o.db, |c| {
            diesel::insert_into(oauth_consent_grants::table)
                .values(&grant)
                .execute(c)?;
            diesel::insert_into(oauth_authorization_codes::table)
                .values(&code)
                .execute(c)?;
            diesel::update(oauth_device_codes::table.find(&hash))
                .set((
                    oauth_device_codes::status.eq("approved"),
                    oauth_device_codes::flow_id.eq(Some(&grant.id)),
                ))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
    id
}

/// A client of the device and refresh grants authenticating by `method`; its secret is
/// `<id>-secret`.
pub(super) fn device_client(id: &str, method: &str) -> OAuthClient {
    OAuthClient {
        grant_types: Some(strings(&[
            super::device::DEVICE_CODE_GRANT,
            super::token_endpoint::REFRESH_TOKEN,
        ])),
        redirect_uris: None,
        token_endpoint_auth_method: Some(method.to_string()),
        client_secret: Some(format!("{id}-secret")),
        ..client(id)
    }
}

/// A pending device authorization of `client_id` for `scope`.
pub(super) async fn start_device(
    o: &NativeOAuth,
    client_id: &str,
    scope: &[&str],
) -> crate::backend::oauth::DeviceAuthorization {
    let client = clients::get(&o.db, client_id).await.unwrap().unwrap();
    super::device::create(
        &o.db,
        &o.issuer,
        &client,
        &strings(scope),
        chrono::Utc::now(),
    )
    .await
    .unwrap()
}

/// Accepts `user_code` as typed: the request it started, by the device row's `flow_id`.
pub(super) async fn accept_device(o: &NativeOAuth, user_code: &str) -> anyhow::Result<Started> {
    let r = o.accept_user_code_request("", user_code).await?;
    let prefix = format!("{}/oauth/login?login_challenge=", o.issuer);
    let challenge = url::Url::parse(&r.redirect_to)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "login_challenge")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    assert!(r.redirect_to.starts_with(&prefix), "{}", r.redirect_to);
    let normalized = super::device::normalize_user_code(user_code).unwrap();
    let r: anyhow::Result<Option<String>> = async {
        Ok(db_interact!(o.db, |c| {
            crate::schema::oauth_device_codes::table
                .filter(crate::schema::oauth_device_codes::user_code.eq(normalized))
                .select(crate::schema::oauth_device_codes::flow_id)
                .first(c)
        })?)
    }
    .await;
    Ok(Started {
        id: r.unwrap().unwrap(),
        challenge,
    })
}

/// `(status, flow_id, expires_at)` of the device row of `device_code`.
pub(super) async fn device_row(db: &DbPool, device_code: &str) -> (String, Option<String>, String) {
    use crate::schema::oauth_device_codes;
    let hash = super::token_hash(device_code);
    let r: anyhow::Result<_> = async {
        Ok(db_interact!(db, |c| {
            oauth_device_codes::table
                .find(hash)
                .select((
                    oauth_device_codes::status,
                    oauth_device_codes::flow_id,
                    oauth_device_codes::expires_at,
                ))
                .first::<(String, Option<String>, String)>(c)
        })?)
    }
    .await;
    r.unwrap()
}

pub(super) async fn expire_device(db: &DbPool, device_code: &str) {
    use crate::schema::oauth_device_codes;
    let (hash, past) = (
        super::token_hash(device_code),
        crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::seconds(1)),
    );
    let r: anyhow::Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(oauth_device_codes::table.find(hash))
                .set(oauth_device_codes::expires_at.eq(past))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
}

/// The code row stored under a device code's hash.
#[derive(Queryable, Debug)]
pub(super) struct DeviceCodeRow {
    pub(super) grant_id: String,
    pub(super) client_id: String,
    pub(super) subject: String,
    pub(super) session_id: String,
    pub(super) redirect_uri: String,
    pub(super) code_challenge: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) scope: String,
    pub(super) expires_at: String,
}

pub(super) async fn device_code_row(db: &DbPool, device_code: &str) -> Option<DeviceCodeRow> {
    let hash = super::token_hash(device_code);
    let r: anyhow::Result<_> = async {
        Ok(db_interact!(db, |c| {
            oauth_authorization_codes::table
                .find(hash)
                .select((
                    oauth_authorization_codes::grant_id,
                    oauth_authorization_codes::client_id,
                    oauth_authorization_codes::subject,
                    oauth_authorization_codes::session_id,
                    oauth_authorization_codes::redirect_uri,
                    oauth_authorization_codes::code_challenge,
                    oauth_authorization_codes::nonce,
                    oauth_authorization_codes::scope,
                    oauth_authorization_codes::expires_at,
                ))
                .first::<DeviceCodeRow>(c)
                .optional()
        })?)
    }
    .await;
    r.unwrap()
}

pub(super) fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}
