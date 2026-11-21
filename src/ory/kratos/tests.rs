use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::http::Uri;
use serde_json::{Value, json};

use super::*;
use crate::backend::identity::{
    Aal, AuthMethod, Credential, RecoveryAddress, SessionDevice, VerifiableAddress,
};

const IDENTITY: &str = include_str!("../fixtures/kratos/identity.json");
const IDENTITY_CREDENTIALS: &str = include_str!("../fixtures/kratos/identity_credentials.json");
const IDENTITIES_PAGE: &str = include_str!("../fixtures/kratos/identities_page.json");
const SESSION_AAL1: &str = include_str!("../fixtures/kratos/session_aal1.json");
const SESSION_AAL2: &str = include_str!("../fixtures/kratos/session_aal2.json");
const MY_SESSIONS: &str = include_str!("../fixtures/kratos/my_sessions.json");
const IDENTITY_SESSIONS: &str = include_str!("../fixtures/kratos/identity_sessions.json");
const SESSIONS_PAGE: &str = include_str!("../fixtures/kratos/sessions_page.json");
const ADMIN_SESSION: &str = include_str!("../fixtures/kratos/admin_session.json");
const DELETE_COUNT: &str = include_str!("../fixtures/kratos/delete_my_sessions_count.json");
const RECOVERY_CODE: &str = include_str!("../fixtures/kratos/recovery_code.json");
const RECOVERY_LINK: &str = include_str!("../fixtures/kratos/recovery_link.json");
const COURIER_MESSAGES: &str = include_str!("../fixtures/kratos/courier_messages.json");
const IDENTITY_SCHEMAS: &str = include_str!("../fixtures/kratos/identity_schemas.json");
const VERSION: &str = include_str!("../fixtures/kratos/version.json");
const HEALTH_ALIVE: &str = include_str!("../fixtures/kratos/health_alive.json");
const SELF_SERVICE_ERROR: &str = include_str!("../fixtures/kratos/self_service_error.json");
const LOGIN_FLOW_API: &str = include_str!("../fixtures/kratos/login_flow_api.json");
const ERROR_UNAUTHORIZED: &str = include_str!("../fixtures/kratos/error_whoami_unauthorized.json");
const ERROR_AAL2_REQUIRED: &str =
    include_str!("../fixtures/kratos/error_whoami_aal2_required.json");
const ERROR_NOT_FOUND: &str = include_str!("../fixtures/kratos/error_identity_not_found.json");
const ERROR_CONFLICT: &str = include_str!("../fixtures/kratos/error_identity_conflict.json");

/// The `Link` header Kratos sent with `identities_page.json` (`page_size=2`).
const IDENTITIES_PAGE_LINK: &str = "</admin/identities?page_size=2&page_token=00000000-0000-0000-0000-000000000000>; rel=\"first\",</admin/identities?page_size=2&page_token=79a2099c-af9b-4cd9-941b-2aeca5187330>; rel=\"next\"";
/// The `Link` header Kratos sent for `/admin/identities/{id}/sessions?page_size=1`.
const IDENTITY_SESSIONS_LINK: &str = "</admin/identities/79a2099c-af9b-4cd9-941b-2aeca5187330/sessions?page=1&page_size=1&page_token=eyJvZmZzZXQiOiIxIiwidiI6Mn0&per_page=1>; rel=\"next\",</admin/identities/79a2099c-af9b-4cd9-941b-2aeca5187330/sessions?page=3&page_size=1&page_token=eyJvZmZzZXQiOiIzIiwidiI6Mn0&per_page=1>; rel=\"last\"";

// --- recording stub ---------------------------------------------------

/// One request as the stub received it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: Option<String>,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn assert(&self, method: &str, path: &str, query: Option<&str>) {
        assert_eq!(
            (
                self.method.as_str(),
                self.path.as_str(),
                self.query.as_deref()
            ),
            (method, path, query),
            "{self:#?}"
        );
    }

    fn assert_cookie(&self, cookie: Option<&str>) {
        assert_eq!(self.header("cookie"), cookie, "{self:#?}");
        assert_eq!(self.header("x-session-token"), None);
    }

    /// The body as sent, byte for byte.
    fn assert_json(&self, want: &str) {
        assert_eq!(self.header("content-type"), Some("application/json"));
        assert_eq!(std::str::from_utf8(&self.body).unwrap(), want);
    }

    fn assert_no_body(&self) {
        assert!(self.body.is_empty(), "{self:#?}");
        assert_eq!(self.header("content-type"), None);
    }
}

struct Reply {
    status: u16,
    content_type: Option<&'static str>,
    link: Option<&'static str>,
    location: Option<String>,
    body: String,
}

fn reply(status: u16, body: &str) -> Reply {
    Reply {
        status,
        content_type: Some("application/json; charset=utf-8"),
        link: None,
        location: None,
        body: body.to_string(),
    }
}

fn ok(body: &str) -> Reply {
    reply(200, body)
}

fn no_content() -> Reply {
    Reply {
        status: 204,
        content_type: None,
        link: None,
        location: None,
        body: String::new(),
    }
}

/// An HTTP server that records every request and answers with `replies` in order.
/// The public endpoint is mounted at `/pub`, the admin one at `/adm`.
struct Stub {
    base: String,
    clients: KratosClients,
    seen: Arc<Mutex<Vec<Seen>>>,
    queue: Arc<Mutex<VecDeque<Reply>>>,
}

impl Stub {
    async fn new(replies: Vec<Reply>) -> Stub {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(replies)));
        let replies = queue.clone();
        let log = seen.clone();
        let app = axum::Router::new().fallback(
            move |method: axum::http::Method,
                  uri: Uri,
                  headers: axum::http::HeaderMap,
                  body: Bytes| {
                let log = log.clone();
                let queue = queue.clone();
                async move {
                    log.lock().unwrap().push(Seen {
                        method: method.to_string(),
                        path: uri.path().to_string(),
                        query: uri.query().map(str::to_string),
                        headers,
                        body: body.to_vec(),
                    });
                    let r = queue.lock().unwrap().pop_front().expect("a canned reply");
                    let mut resp = axum::http::Response::builder().status(r.status);
                    if let Some(ct) = r.content_type {
                        resp = resp.header("content-type", ct);
                    }
                    if let Some(link) = r.link {
                        resp = resp.header("link", link);
                    }
                    if let Some(location) = r.location {
                        resp = resp.header("location", location);
                    }
                    resp.body(Body::from(r.body)).unwrap()
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Stub {
            clients: KratosClients::new(&format!("{base}/pub"), &format!("{base}/adm")),
            base,
            seen,
            queue: replies,
        }
    }

    /// Queue more replies, for bodies that name the stub's own address.
    fn push(&self, replies: Vec<Reply>) {
        self.queue.lock().unwrap().extend(replies);
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn only(&self) -> Seen {
        let seen = self.seen();
        assert_eq!(seen.len(), 1, "{seen:#?}");
        seen.into_iter().next().unwrap()
    }
}

// --- metadata_admin patch -------------------------------------------------

fn ops(current: Option<Value>, key: &str, value: Option<&str>) -> Vec<Value> {
    metadata_admin_patch(current.as_ref(), key, value)
        .expect("patch")
        .iter()
        .map(|op| serde_json::to_value(op).unwrap())
        .collect()
}

#[test]
fn self_service_error_reads_wrapped_and_top_level_shapes() {
    let wrapped = json!({"id": "e1", "error": {
        "id": "self_service_flow_expired", "message": "expired", "reason": "too old"
    }});
    assert_eq!(
        self_service_error(&wrapped),
        SelfServiceError {
            id: Some("self_service_flow_expired".into()),
            message: Some("expired".into()),
            reason: Some("too old".into()),
        }
    );
    let top = json!({"id": "security_csrf_violation", "message": 5});
    assert_eq!(
        self_service_error(&top),
        SelfServiceError {
            id: Some("security_csrf_violation".into()),
            ..Default::default()
        }
    );
}

#[test]
fn set_on_absent_or_null_adds_the_object() {
    let want = vec![json!({"op": "add", "path": "/metadata_admin", "value": {"aud": "u:1:x"}})];
    assert_eq!(ops(None, "aud", Some("u:1:x")), want);
    assert_eq!(ops(Some(json!(null)), "aud", Some("u:1:x")), want);
}

#[test]
fn set_on_object_adds_only_the_key() {
    let current = json!({"other": "keep", "aud": "old"});
    assert_eq!(
        ops(Some(current.clone()), "aud", Some("new")),
        vec![json!({"op": "add", "path": "/metadata_admin/aud", "value": "new"})]
    );
    assert_eq!(
        ops(Some(json!({})), "aud", Some("v")),
        vec![json!({"op": "add", "path": "/metadata_admin/aud", "value": "v"})]
    );
}

#[test]
fn non_object_is_refused() {
    for current in [json!(["aud"]), json!("aud"), json!(1), json!(true)] {
        assert!(metadata_admin_patch(Some(&current), "aud", Some("v")).is_err());
        assert!(metadata_admin_patch(Some(&current), "aud", None).is_err());
    }
}

#[test]
fn remove_present_key() {
    let patch = metadata_admin_patch(Some(&json!({"aud": "v", "x": 1})), "aud", None).unwrap();
    assert_eq!(patch.len(), 1);
    assert_eq!(patch[0].op, "remove");
    assert_eq!(patch[0].path, "/metadata_admin/aud");
    assert_eq!(
        serde_json::to_string(&patch[0]).unwrap(),
        r#"{"op":"remove","path":"/metadata_admin/aud"}"#
    );
}

#[test]
fn remove_absent_is_no_op() {
    assert!(ops(None, "aud", None).is_empty());
    assert!(ops(Some(json!(null)), "aud", None).is_empty());
    assert!(ops(Some(json!({"other": 1})), "aud", None).is_empty());
}

#[test]
fn pointer_escapes_tilde_before_slash() {
    let current = json!({"a/b~c": "v"});
    assert_eq!(
        ops(Some(current.clone()), "a/b~c", Some("w")),
        vec![json!({"op": "add", "path": "/metadata_admin/a~1b~0c", "value": "w"})]
    );
    assert_eq!(
        ops(Some(current), "a/b~c", None),
        vec![json!({"op": "remove", "path": "/metadata_admin/a~1b~0c"})]
    );
    assert_eq!(
        ops(Some(json!({})), "~1", Some("w"))[0]["path"],
        "/metadata_admin/~01"
    );
}

#[test]
fn set_on_null_keeps_the_raw_key() {
    assert_eq!(ops(None, "a/b", Some("v"))[0]["value"], json!({"a/b": "v"}));
}

#[test]
fn has_key_ignores_null_and_absent() {
    let mut identity = Identity::default();
    assert!(!identity.metadata_admin_has_key("aud"));
    identity.metadata_admin = Some(json!(null));
    assert!(!identity.metadata_admin_has_key("aud"));
    identity.metadata_admin = Some(json!({"aud": null}));
    assert!(!identity.metadata_admin_has_key("aud"));
    identity.metadata_admin = Some(json!(["aud"]));
    assert!(!identity.metadata_admin_has_key("aud"));
    identity.metadata_admin = Some(json!({"aud": "v"}));
    assert!(identity.metadata_admin_has_key("aud"));
}

// --- fixture expectations ---------------------------------------------------

const FULL_ID: &str = "79a2099c-af9b-4cd9-941b-2aeca5187330";
const PLAIN_ID: &str = "bcf0f3aa-eaf2-48ac-a34b-795b67c31a25";
const OTHER_ID: &str = "69e3c312-e9b1-4788-9516-0737fa56bfe8";

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_string()).collect()
}

fn credential(identifier: &str, version: i64, at: &str, config: Option<Value>) -> Credential {
    Credential {
        identifiers: Some(strings(&[identifier])),
        config,
        created_at: s(at),
        updated_at: s(at),
        version: Some(version),
    }
}

/// `identity.json`, or `identity_credentials.json` with `configs`.
fn fixture_identity(configs: bool) -> Identity {
    let cfg = |v: Value| configs.then_some(v);
    let email = "fixture-full@example.test";
    Identity {
        id: FULL_ID.into(),
        schema_id: "default".into(),
        traits: Some(json!({
            "name": {"last": "Person", "first": "Fixture"},
            "email": email,
            "preferred_language": "de",
        })),
        state: Some(IdentityState::Active),
        state_changed_at: s("2026-11-20T21:08:30.655997Z"),
        created_at: s("2026-11-20T21:08:30.657411Z"),
        updated_at: s("2026-11-20T21:09:11.859719Z"),
        external_id: s("fixture-external-1"),
        organization_id: None,
        metadata_public: Some(json!({"plan": "pro"})),
        metadata_admin: Some(json!({"aud": "u:1:fixture", "note": null})),
        verifiable_addresses: Some(vec![VerifiableAddress {
            id: s("e735db35-1aab-46c2-bca2-2790e3461457"),
            value: email.into(),
            via: "email".into(),
            status: "completed".into(),
            verified: true,
            verified_at: s("2026-11-20T21:08:30.658455Z"),
            created_at: s("2026-11-20T21:08:30.65851Z"),
            updated_at: s("2026-11-20T21:08:30.65851Z"),
        }]),
        recovery_addresses: Some(vec![RecoveryAddress {
            id: s("3a61f2e5-d303-4b06-ad5f-1bfae57121d1"),
            value: email.into(),
            via: "email".into(),
            created_at: s("2026-11-20T21:08:30.659096Z"),
            updated_at: s("2026-11-20T21:08:30.659096Z"),
        }]),
        credentials: Some(HashMap::from([
            (
                "code".to_string(),
                credential(email, 1, "2026-11-20T21:08:30.659508Z", None),
            ),
            (
                "oidc".to_string(),
                credential(
                    "github:fixture-gh-subject",
                    0,
                    "2026-11-20T21:08:30.659514Z",
                    cfg(json!({"providers": [{
                        "initial_id_token": "",
                        "initial_access_token": "",
                        "initial_refresh_token": "",
                        "subject": "fixture-gh-subject",
                        "provider": "github",
                    }]})),
                ),
            ),
            (
                "password".to_string(),
                credential(
                    email,
                    0,
                    "2026-11-20T21:08:30.659512Z",
                    cfg(json!({"hashed_password": "fixture-password-hash"})),
                ),
            ),
            (
                "totp".to_string(),
                credential(
                    FULL_ID,
                    0,
                    "2026-11-20T21:08:38.808951Z",
                    cfg(json!({"totp_url": "fixture-totp-url"})),
                ),
            ),
            (
                "webauthn".to_string(),
                credential(
                    email,
                    1,
                    "2026-11-20T21:08:30.659516Z",
                    cfg(json!({"user_handle": "eaIJnK+bTNmUGyrspRhzMA=="})),
                ),
            ),
        ])),
        sole_sign_in_is_oidc: None,
    }
}

fn plain_identity() -> Identity {
    let email = "fixture-plain@example.test";
    Identity {
        id: PLAIN_ID.into(),
        schema_id: "default".into(),
        traits: Some(json!({"email": email})),
        state: Some(IdentityState::Active),
        state_changed_at: s("2026-11-20T21:09:11.559037Z"),
        created_at: s("2026-11-20T21:09:11.56049Z"),
        updated_at: s("2026-11-20T21:09:11.56049Z"),
        verifiable_addresses: Some(vec![VerifiableAddress {
            id: s("516bd787-5002-4b66-8475-3d4b375cdfd1"),
            value: email.into(),
            via: "email".into(),
            status: "completed".into(),
            verified: true,
            verified_at: s("2026-11-20T21:09:11.56127Z"),
            created_at: s("2026-11-20T21:09:11.561311Z"),
            updated_at: s("2026-11-20T21:09:11.561311Z"),
        }]),
        recovery_addresses: Some(vec![RecoveryAddress {
            id: s("fdc067bb-3a5f-4ffa-89fa-b92099250a2f"),
            value: email.into(),
            via: "email".into(),
            created_at: s("2026-11-20T21:09:11.561897Z"),
            updated_at: s("2026-11-20T21:09:11.561897Z"),
        }]),
        ..Identity::default()
    }
}

fn method(name: &str, aal: Aal, at: &str) -> AuthMethod {
    AuthMethod {
        aal: Some(aal),
        completed_at: s(at),
        method: s(name),
        ..AuthMethod::default()
    }
}

fn device(ip: &str) -> SessionDevice {
    SessionDevice {
        ip_address: s(ip),
        user_agent: s("Python-urllib/3.12"),
        location: s(""),
    }
}

/// `session_aal1.json`: a password session of the identity without a second factor.
fn session_aal1() -> Session {
    Session {
        id: "34efe5df-a64a-4944-be35-c2ca714ed411".into(),
        active: Some(true),
        issued_at: s("2026-11-20T21:09:17.07837Z"),
        authenticated_at: s("2026-11-20T21:09:17.07837Z"),
        expires_at: s("2026-11-21T21:09:17.07837Z"),
        authenticator_assurance_level: Some(Aal::Aal1),
        authentication_methods: Some(vec![method(
            "password",
            Aal::Aal1,
            "2026-11-20T21:09:17.078249393Z",
        )]),
        devices: Some(vec![device("10.89.12.11:54470")]),
        identity: Some(Box::new(plain_identity())),
    }
}

fn decode<T: serde::de::DeserializeOwned>(raw: &str) -> T {
    serde_json::from_str(raw).unwrap()
}

// --- fixture decoding ---------------------------------------------------------

#[test]
fn identity_fixtures_decode() {
    assert_eq!(
        Identity::from(decode::<wire::Identity>(IDENTITY)),
        fixture_identity(false)
    );
    assert_eq!(
        Identity::from(decode::<wire::Identity>(IDENTITY_CREDENTIALS)),
        fixture_identity(true)
    );
    let raw: wire::Identity = decode(IDENTITY);
    assert_eq!(
        raw.metadata_admin,
        Some(Some(json!({"aud": "u:1:fixture", "note": null})))
    );
}

#[test]
fn session_fixtures_decode() {
    assert_eq!(
        Session::from(decode::<wire::Session>(SESSION_AAL1)),
        session_aal1()
    );
    let aal2 = Session::from(decode::<wire::Session>(SESSION_AAL2));
    let mut identity = fixture_identity(false);
    identity.metadata_admin = None;
    identity.credentials = None;
    assert_eq!(
        aal2,
        Session {
            id: "9f32043a-c310-42e2-83de-6cc7ba9485e8".into(),
            active: Some(true),
            issued_at: s("2026-11-20T21:09:17.142195Z"),
            authenticated_at: s("2026-11-20T21:09:17.170056Z"),
            expires_at: s("2026-11-21T21:09:17.170056Z"),
            authenticator_assurance_level: Some(Aal::Aal2),
            authentication_methods: Some(vec![
                method("password", Aal::Aal1, "2026-11-20T21:09:17.142136078Z"),
                method("totp", Aal::Aal2, "2026-11-20T21:09:17.170049358Z"),
            ]),
            devices: Some(vec![device("10.89.12.11:54496")]),
            identity: Some(Box::new(identity)),
        }
    );
    assert!(aal2.satisfies_aal2());
    assert_eq!(
        serde_json::to_string(aal2.authentication_methods.as_ref().unwrap()).unwrap(),
        r#"[{"aal":"aal1","completed_at":"2026-11-20T21:09:17.142136078Z","method":"password"},{"aal":"aal2","completed_at":"2026-11-20T21:09:17.170049358Z","method":"totp"}]"#
    );
    let admin = Session::from(decode::<wire::Session>(ADMIN_SESSION));
    assert_eq!(
        admin,
        Session {
            devices: Some(vec![]),
            ..session_aal1()
        }
    );
}

#[test]
fn identity_and_session_decoding_follows_the_spec() {
    let base = || -> Value { decode(IDENTITY) };
    let decodes = |v: &Value| serde_json::from_value::<wire::Identity>(v.clone()).is_ok();
    for (key, value, ok) in [
        ("schema_url", None, false),
        ("traits", None, false),
        ("traits", Some(Value::Null), true),
        ("state", Some(json!("deleted")), false),
        ("state", Some(Value::Null), true),
        ("region", Some(json!("eu-central")), true),
        ("region", Some(json!("mars")), false),
        ("organization_id", Some(json!(5)), false),
        ("external_id", Some(Value::Null), true),
        ("unknown_field", Some(json!(1)), true),
    ] {
        let mut v = base();
        match value {
            Some(x) => v[key] = x,
            None => {
                v.as_object_mut().unwrap().remove(key);
            }
        }
        assert_eq!(decodes(&v), ok, "{key}");
    }
    let mut v = base();
    v["verifiable_addresses"][0]["via"] = json!("pigeon");
    assert!(!decodes(&v));
    let mut v = base();
    v["credentials"]["code"]["type"] = json!("magic");
    assert!(!decodes(&v));

    let session = |f: &dyn Fn(&mut Value)| {
        let mut v: Value = decode(SESSION_AAL1);
        f(&mut v);
        serde_json::from_value::<wire::Session>(v).is_ok()
    };
    assert!(!session(
        &|v| v["authenticator_assurance_level"] = json!("aal9")
    ));
    assert!(!session(
        &|v| v["authentication_methods"][0]["method"] = json!("magic")
    ));
    assert!(!session(&|v| {
        v["devices"][0].as_object_mut().unwrap().remove("id");
    }));
    assert!(!session(&|v| v["tokenized"] = json!(1)));
    assert!(session(&|v| {
        let m = v.as_object_mut().unwrap();
        m.remove("identity");
        m.remove("devices");
        m.remove("authentication_methods");
    }));
}

// --- whoami and the self-service flows ----------------------------------------

#[tokio::test]
async fn whoami_forwards_the_cookie_and_maps_statuses() {
    let stub = Stub::new(vec![
        ok(SESSION_AAL1),
        reply(401, ERROR_UNAUTHORIZED),
        reply(403, ERROR_AAL2_REQUIRED),
        reply(500, "{}"),
        Reply {
            content_type: Some("text/html"),
            ..ok("{}")
        },
    ])
    .await;
    let cookie = "ory_kratos_session=abc; other=1";
    let WhoamiOutcome::Ok(session) = whoami(&stub.clients, Some(cookie)).await.unwrap() else {
        panic!("a session");
    };
    assert_eq!(*session, session_aal1());
    assert!(matches!(
        whoami(&stub.clients, None).await.unwrap(),
        WhoamiOutcome::None
    ));
    assert!(matches!(
        whoami(&stub.clients, Some("")).await.unwrap(),
        WhoamiOutcome::InsufficientAal
    ));
    let err = whoami(&stub.clients, None).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos whoami failed: error in response: status code 500 Internal Server Error"
    );
    let err = whoami(&stub.clients, None).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos whoami failed: error in serde: Received `text/html` content type response that cannot be converted to JSON"
    );
    let seen = stub.seen();
    for s in &seen {
        s.assert("GET", "/pub/sessions/whoami", None);
        s.assert_no_body();
    }
    seen[0].assert_cookie(Some(cookie));
    seen[1].assert_cookie(None);
    seen[2].assert_cookie(Some(""));
}

#[tokio::test]
async fn get_flow_maps_statuses_per_kind() {
    let refresh = r#"{"error":{"id":"session_refresh_required"}}"#;
    let stub = Stub::new(vec![
        ok(LOGIN_FLOW_API),
        reply(404, "{}"),
        reply(410, "{}"),
        reply(403, ERROR_AAL2_REQUIRED),
        reply(403, refresh),
        reply(403, ERROR_AAL2_REQUIRED),
        reply(500, "boom"),
    ])
    .await;
    let c = &stub.clients;
    assert!(matches!(
        resolve_flow(c, FlowKind::Login, None, "c=1").await,
        FlowOutcome::Init
    ));
    let FlowOutcome::Ready(flow) = resolve_flow(c, FlowKind::Login, Some("f 1"), "c=1").await
    else {
        panic!("a flow");
    };
    assert_eq!(
        flow.form_action,
        "http://localhost:4433/self-service/login?flow=2ccf97f7-9c86-4349-bb57-c7b380bcca84"
    );
    assert!(matches!(
        resolve_flow(c, FlowKind::Login, Some("f"), "").await,
        FlowOutcome::Reinit
    ));
    assert!(matches!(
        resolve_flow(c, FlowKind::Recovery, Some("f"), "").await,
        FlowOutcome::Reinit
    ));
    assert!(matches!(
        resolve_flow(c, FlowKind::Settings, Some("f"), "").await,
        FlowOutcome::Privileged(PrivilegedReason::Aal2Required)
    ));
    assert!(matches!(
        resolve_flow(c, FlowKind::Settings, Some("f"), "").await,
        FlowOutcome::Privileged(PrivilegedReason::SessionRefresh)
    ));
    assert!(matches!(
        resolve_flow(c, FlowKind::Login, Some("f"), "").await,
        FlowOutcome::Reinit
    ));
    let FlowOutcome::Error(e) = resolve_flow(c, FlowKind::Verification, Some("f"), "").await else {
        panic!("an error");
    };
    assert_eq!(
        e.to_string(),
        "kratos get_flow (verification) returned 500 Internal Server Error: boom"
    );
    let seen = stub.seen();
    assert_eq!(seen.len(), 7);
    seen[0].assert("GET", "/pub/self-service/login/flows", Some("id=f+1"));
    seen[0].assert_cookie(Some("c=1"));
    seen[1].assert_cookie(None);
    seen[3].assert("GET", "/pub/self-service/settings/flows", Some("id=f"));
    seen[6].assert("GET", "/pub/self-service/verification/flows", Some("id=f"));
}

#[tokio::test]
async fn probe_oidc_provider_ids_reads_a_fresh_api_flow() {
    let stub = Stub::new(vec![ok(LOGIN_FLOW_API), reply(500, "{}")]).await;
    assert_eq!(
        probe_oidc_provider_ids(&stub.clients).await.unwrap(),
        ["playground"]
    );
    let err = probe_oidc_provider_ids(&stub.clients).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos provider probe returned 500 Internal Server Error"
    );
    for s in stub.seen() {
        s.assert("GET", "/pub/self-service/login/api", None);
        s.assert_cookie(None);
    }
}

#[tokio::test]
async fn verify_known_email_posts_to_the_form_action() {
    let stub = Stub::new(vec![ok("{}"), reply(400, "{\"e\":1}")]).await;
    let mut flow: Flow = crate::flow_json::project(&decode(LOGIN_FLOW_API));
    flow.form_action = format!("{}/pub/self-service/verification?flow=v1", stub.base);
    flow.csrf_token = Some("csrf-1".into());
    verify_known_email(&stub.clients, &flow, "a@b.c", "c=1")
        .await
        .unwrap();
    let err = verify_known_email(&stub.clients, &flow, "a@b.c", "c=1")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos submit_flow returned 400 Bad Request: {\"e\":1}"
    );
    let seen = stub.seen();
    seen[0].assert("POST", "/pub/self-service/verification", Some("flow=v1"));
    seen[0].assert_cookie(Some("c=1"));
    assert_eq!(seen[0].header("accept"), Some("application/json"));
    seen[0].assert_json(r#"{"method":"code","email":"a@b.c","csrf_token":"csrf-1"}"#);
    flow.csrf_token = None;
    assert!(
        verify_known_email(&stub.clients, &flow, "a@b.c", "c=1")
            .await
            .is_err()
    );
    assert_eq!(stub.seen().len(), 2);
}

#[tokio::test]
async fn get_self_service_error_maps_gone_to_none() {
    let stub = Stub::new(vec![
        ok(SELF_SERVICE_ERROR),
        reply(410, "{}"),
        reply(500, "x"),
    ])
    .await;
    assert_eq!(
        get_self_service_error(&stub.clients, "stub:500")
            .await
            .unwrap(),
        Some(SelfServiceError {
            id: None,
            message: s(
                "An internal server error occurred, please contact the system administrator"
            ),
            reason: s("This is a stub error."),
        })
    );
    assert_eq!(
        get_self_service_error(&stub.clients, "x").await.unwrap(),
        None
    );
    assert!(get_self_service_error(&stub.clients, "x").await.is_err());
    stub.seen()[0].assert("GET", "/pub/self-service/errors", Some("id=stub%3A500"));
}

#[tokio::test]
async fn logout_fetches_the_url_and_hits_it_with_the_cookie() {
    let stub = Stub::new(vec![]).await;
    let logout = format!("{}/pub/self-service/logout?token=t", stub.base);
    stub.push(vec![
        ok(&json!({"logout_url": logout, "logout_token": "t"}).to_string()),
        Reply {
            status: 303,
            content_type: None,
            link: None,
            location: Some("/pub/login".into()),
            body: String::new(),
        },
        ok("{}"),
        reply(401, ERROR_UNAUTHORIZED),
        reply(500, "x"),
    ]);
    tear_down_session(&stub.clients, "").await;
    tear_down_session(&stub.clients, "c=1").await;
    assert_eq!(fetch_logout_url(&stub.clients, "c=1").await.unwrap(), None);
    assert_eq!(fetch_logout_url(&stub.clients, "").await.unwrap(), None);
    assert!(fetch_logout_url(&stub.clients, "c=1").await.is_err());
    let seen = stub.seen();
    assert_eq!(seen.len(), 5);
    seen[0].assert("GET", "/pub/self-service/logout/browser", None);
    assert_eq!(seen[0].header("accept"), Some("application/json"));
    seen[0].assert_cookie(Some("c=1"));
    seen[1].assert("GET", "/pub/self-service/logout", Some("token=t"));
    seen[1].assert_cookie(Some("c=1"));
    // The post-logout redirect is followed.
    seen[2].assert("GET", "/pub/login", None);
}

// --- sessions -----------------------------------------------------------------

#[tokio::test]
async fn my_sessions_list_and_revoke_forward_the_cookie() {
    let stub = Stub::new(vec![
        ok(MY_SESSIONS),
        no_content(),
        reply(400, "{}"),
        ok(DELETE_COUNT),
        ok("{}"),
        ok(r#"{"count":-3}"#),
    ])
    .await;
    let c = &stub.clients;
    let mine = list_my_sessions(c, Some("c=1")).await.unwrap();
    assert_eq!(
        mine.iter()
            .map(|s| (s.id.as_str(), s.authenticator_assurance_level))
            .collect::<Vec<_>>(),
        [
            ("682ef623-7845-4e74-a777-5e971b6d1cf1", Some(Aal::Aal1)),
            ("126ccd9f-0822-4572-8d08-ed40c487954c", Some(Aal::Aal1)),
            ("bfc45c96-ce3c-4180-bd75-e5b6544f4622", Some(Aal::Aal2)),
        ]
    );
    assert!(mine.iter().all(|s| s.principal().0 == FULL_ID));
    revoke_session(c, "a b/c", Some("c=1")).await.unwrap();
    let err = revoke_session(c, "s", None).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos disable_my_session failed: error in response: status code 400 Bad Request"
    );
    assert_eq!(revoke_other_sessions(c, Some("c=1")).await.unwrap(), 3);
    assert_eq!(revoke_other_sessions(c, None).await.unwrap(), 0);
    assert_eq!(revoke_other_sessions(c, None).await.unwrap(), 0);
    let seen = stub.seen();
    seen[0].assert("GET", "/pub/sessions", None);
    seen[0].assert_cookie(Some("c=1"));
    seen[1].assert("DELETE", "/pub/sessions/a+b%2Fc", None);
    seen[1].assert_cookie(Some("c=1"));
    seen[1].assert_no_body();
    seen[2].assert_cookie(None);
    seen[3].assert("DELETE", "/pub/sessions", None);
    seen[3].assert_cookie(Some("c=1"));
}

#[tokio::test]
async fn identity_sessions_and_active_ids() {
    let stub = Stub::new(vec![
        ok(IDENTITY_SESSIONS),
        ok(IDENTITY_SESSIONS),
        ok(IDENTITY_SESSIONS),
        reply(404, ERROR_NOT_FOUND),
    ])
    .await;
    let c = &stub.clients;
    assert_eq!(list_identity_sessions(c, "i d/1").await.unwrap().len(), 4);
    let ids = active_session_ids(c, "i/1").await.unwrap();
    assert_eq!(ids.len(), 4);
    assert!(
        is_session_active(c, "i", "bfc45c96-ce3c-4180-bd75-e5b6544f4622")
            .await
            .unwrap()
    );
    let err = is_session_active(c, "i", "x").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos admin list_identity_sessions failed: error in response: status code 404 Not Found"
    );
    let seen = stub.seen();
    seen[0].assert("GET", "/adm/admin/identities/i+d%2F1/sessions", None);
    seen[1].assert(
        "GET",
        "/adm/admin/identities/i%2F1/sessions",
        Some("page_size=1000&active=true"),
    );
}

#[tokio::test]
async fn list_identity_sessions_all_follows_absolute_next_links() {
    let next = Reply {
        link: Some(
            "<http://kratos.test/admin/identities/i/sessions?page_size=250&page_token=p%2F2>; rel=\"next\"",
        ),
        ..ok(IDENTITY_SESSIONS)
    };
    let relative = Reply {
        link: Some(IDENTITY_SESSIONS_LINK),
        ..ok(IDENTITY_SESSIONS)
    };
    let empty_with_next = Reply {
        link: Some("<http://kratos.test/x?page_token=p3>; rel=\"next\""),
        ..ok("[]")
    };
    let stub = Stub::new(vec![
        next,
        ok(IDENTITY_SESSIONS),
        relative,
        empty_with_next,
        reply(500, "boom"),
    ])
    .await;
    let c = &stub.clients;
    assert_eq!(list_identity_sessions_all(c, "i/1").await.unwrap().len(), 8);
    // Kratos sends relative `Link` URLs, which end the walk after one page.
    assert_eq!(list_identity_sessions_all(c, "i").await.unwrap().len(), 4);
    assert!(list_identity_sessions_all(c, "i").await.unwrap().is_empty());
    let err = list_identity_sessions_all(c, "i").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos list_identity_sessions returned 500 Internal Server Error: boom"
    );
    let seen = stub.seen();
    seen[0].assert(
        "GET",
        "/adm/admin/identities/i%2F1/sessions",
        Some("page_size=250"),
    );
    seen[1].assert(
        "GET",
        "/adm/admin/identities/i%2F1/sessions",
        Some("page_size=250&page_token=p%2F2"),
    );
    assert_eq!(seen.len(), 5);
}

#[tokio::test]
async fn admin_sessions_get_list_and_revoke() {
    let stub = Stub::new(vec![
        ok(ADMIN_SESSION),
        reply(404, ERROR_NOT_FOUND),
        ok(SESSIONS_PAGE),
        ok("[]"),
        ok("[]"),
        no_content(),
        reply(404, ERROR_NOT_FOUND),
    ])
    .await;
    let c = &stub.clients;
    assert_eq!(
        admin_get_session(c, "s/1").await.unwrap().principal().0,
        PLAIN_ID
    );
    let err = admin_get_session(c, "s").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos admin get_session failed: error in response: status code 404 Not Found"
    );
    let page = admin_list_all_sessions(c, 2, None, None).await.unwrap();
    assert_eq!(
        page.iter()
            .map(|s| (s.email(), s.devices.as_ref().map(Vec::len)))
            .collect::<Vec<_>>(),
        [
            ("fixture-full@example.test".to_string(), Some(1)),
            ("fixture-full@example.test".to_string(), Some(1)),
        ]
    );
    admin_list_all_sessions(c, 5, Some("t/1"), Some(true))
        .await
        .unwrap();
    admin_list_all_sessions(c, 5, None, Some(false))
        .await
        .unwrap();
    admin_revoke_session(c, "s b").await.unwrap();
    let err = admin_revoke_session(c, "s").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos admin disable_session failed: error in response: status code 404 Not Found"
    );
    let seen = stub.seen();
    seen[0].assert("GET", "/adm/admin/sessions/s%2F1", Some("expand=identity"));
    seen[2].assert(
        "GET",
        "/adm/admin/sessions",
        Some("page_size=2&expand=identity&expand=devices"),
    );
    seen[3].assert(
        "GET",
        "/adm/admin/sessions",
        Some("page_size=5&page_token=t%2F1&active=true&expand=identity&expand=devices"),
    );
    seen[4].assert(
        "GET",
        "/adm/admin/sessions",
        Some("page_size=5&active=false&expand=identity&expand=devices"),
    );
    seen[5].assert("DELETE", "/adm/admin/sessions/s+b", None);
    seen[5].assert_no_body();
}

// --- identities -----------------------------------------------------------------

#[tokio::test]
async fn admin_get_identity_variants_map_404() {
    let stub = Stub::new(vec![
        ok(IDENTITY),
        reply(404, ERROR_NOT_FOUND),
        ok(IDENTITY),
        reply(404, ERROR_NOT_FOUND),
        reply(500, "{}"),
        ok(IDENTITY_CREDENTIALS),
        reply(404, ERROR_NOT_FOUND),
        ok(IDENTITY_CREDENTIALS),
        reply(404, ERROR_NOT_FOUND),
    ])
    .await;
    let c = &stub.clients;
    assert_eq!(
        admin_get_identity(c, "a b").await.unwrap(),
        fixture_identity(false)
    );
    assert_eq!(
        admin_get_identity(c, "x").await.unwrap_err().to_string(),
        "kratos admin get_identity failed: error in response: status code 404 Not Found"
    );
    assert_eq!(
        admin_get_identity_optional(c, "x").await.unwrap(),
        Some(fixture_identity(false))
    );
    assert_eq!(admin_get_identity_optional(c, "x").await.unwrap(), None);
    assert!(admin_get_identity_optional(c, "x").await.is_err());
    assert_eq!(
        admin_get_identity_full(c, "x").await.unwrap(),
        fixture_identity(true)
    );
    assert_eq!(
        admin_get_identity_full(c, "x")
            .await
            .unwrap_err()
            .to_string(),
        "kratos admin get_identity_full failed: error in response: status code 404 Not Found"
    );
    assert_eq!(
        admin_get_identity_full_optional(c, "x").await.unwrap(),
        Some(fixture_identity(true))
    );
    assert_eq!(
        admin_get_identity_full_optional(c, "x").await.unwrap(),
        None
    );
    let seen = stub.seen();
    seen[0].assert("GET", "/adm/admin/identities/a+b", None);
    seen[0].assert_no_body();
    let full = Some(
        "include_credential=password&include_credential=totp&include_credential=webauthn&include_credential=lookup_secret&include_credential=oidc",
    );
    seen[5].assert("GET", "/adm/admin/identities/x", full);
    seen[8].assert("GET", "/adm/admin/identities/x", full);
}

#[tokio::test]
async fn list_identities_sends_paging_and_filters() {
    let stub = Stub::new(vec![
        Reply {
            link: Some(IDENTITIES_PAGE_LINK),
            ..ok(IDENTITIES_PAGE)
        },
        ok("[]"),
        ok(IDENTITIES_PAGE),
        ok(IDENTITIES_PAGE),
        ok(IDENTITIES_PAGE),
    ])
    .await;
    let c = &stub.clients;
    let page = list_identities(c, 2, None, None).await.unwrap();
    assert_eq!(
        page.iter()
            .map(|i| (i.id.as_str(), i.addresses().map(|a| a[0].verified)))
            .collect::<Vec<_>>(),
        [(OTHER_ID, Some(false)), (FULL_ID, Some(true))]
    );
    list_identities(c, 50, Some("tok/1"), Some("a+b@x.y"))
        .await
        .unwrap();
    let found = admin_find_identity_by_email(c, "FIXTURE-OTHER@example.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((found.0.id.as_str(), found.1), (OTHER_ID, false));
    assert_eq!(
        admin_find_identity_by_email(c, "nobody@x.y").await.unwrap(),
        None
    );
    let by_ids = admin_list_identities_by_ids(c, strings(&["a", "b c/d"]))
        .await
        .unwrap();
    assert_eq!(by_ids.len(), 2);
    assert!(
        admin_list_identities_by_ids(c, vec![])
            .await
            .unwrap()
            .is_empty()
    );
    let seen = stub.seen();
    assert_eq!(seen.len(), 5);
    seen[0].assert("GET", "/adm/admin/identities", Some("page_size=2"));
    seen[1].assert(
        "GET",
        "/adm/admin/identities",
        Some("page_size=50&page_token=tok%2F1&credentials_identifier=a%2Bb%40x.y"),
    );
    seen[2].assert(
        "GET",
        "/adm/admin/identities",
        Some("page_size=10&credentials_identifier=FIXTURE-OTHER%40example.test"),
    );
    seen[4].assert(
        "GET",
        "/adm/admin/identities",
        Some("per_page=2&ids=a&ids=b+c%2Fd"),
    );
}

/// The `PUT` body that writes `identity.json` back with `state` and `traits`.
fn put_body(state: &str, traits: &str) -> String {
    format!(
        r#"{{"external_id":"fixture-external-1","metadata_admin":{{"aud":"u:1:fixture","note":null}},"metadata_public":{{"plan":"pro"}},"schema_id":"default","state":"{state}","traits":{traits}}}"#
    )
}

#[tokio::test]
async fn identity_updates_round_trip_what_was_read() {
    let bare =
        r#"{"id":"i","schema_id":"default","schema_url":"","traits":null,"metadata_public":null}"#;
    let stub = Stub::new(vec![
        ok(IDENTITY),
        ok(IDENTITY),
        ok(IDENTITY),
        ok(IDENTITY),
        ok(bare),
        ok(IDENTITY),
        ok(bare),
        ok(IDENTITY),
        ok(IDENTITY),
        reply(400, "{}"),
    ])
    .await;
    let c = &stub.clients;
    assert_eq!(
        admin_set_identity_language(c, "a/b", "th").await.unwrap(),
        fixture_identity(false)
    );
    admin_update_identity_state(c, "a", IdentityState::Inactive)
        .await
        .unwrap();
    admin_set_identity_language(c, "i", "en").await.unwrap();
    admin_update_identity_state(c, "i", IdentityState::Active)
        .await
        .unwrap();
    let err = admin_update_identity_state(c, "a", IdentityState::Active)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "kratos admin update_identity (state) failed: error in response: status code 400 Bad Request"
    );
    let seen = stub.seen();
    seen[0].assert("GET", "/adm/admin/identities/a%2Fb", None);
    seen[1].assert("PUT", "/adm/admin/identities/a%2Fb", None);
    seen[1].assert_json(&put_body(
        "active",
        r#"{"name":{"last":"Person","first":"Fixture"},"email":"fixture-full@example.test","preferred_language":"th"}"#,
    ));
    seen[3].assert_json(&put_body(
        "inactive",
        r#"{"name":{"last":"Person","first":"Fixture"},"email":"fixture-full@example.test","preferred_language":"de"}"#,
    ));
    // Absent metadata stays absent, `null` stays `null`, null traits become an object for the language.
    seen[5].assert_json(
        r#"{"metadata_public":null,"schema_id":"default","state":"active","traits":{"preferred_language":"en"}}"#,
    );
    seen[7].assert_json(
        r#"{"metadata_public":null,"schema_id":"default","state":"active","traits":null}"#,
    );
}

#[tokio::test]
async fn metadata_admin_keys_are_patched() {
    let stub = Stub::new(vec![
        ok(IDENTITY),
        ok(IDENTITY),
        ok(IDENTITY),
        ok(IDENTITY),
        ok(IDENTITY),
        ok(IDENTITY),
        ok(IDENTITY),
        ok("{}"),
    ])
    .await;
    let c = &stub.clients;
    admin_set_metadata_admin_key(c, "a/b", "aud", "u:2")
        .await
        .unwrap();
    assert!(
        admin_remove_metadata_admin_key(c, "a", "aud")
            .await
            .unwrap()
    );
    // `note` is null: removed from the object, but it held no value.
    assert!(
        !admin_remove_metadata_admin_key(c, "a", "note")
            .await
            .unwrap()
    );
    let err = admin_set_metadata_admin_key(c, "a", "k", "v")
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("kratos admin patch_identity (metadata_admin) failed: error in serde: missing field `id`"),
        "{err}"
    );
    let seen = stub.seen();
    assert_eq!(seen.len(), 8);
    seen[1].assert("PATCH", "/adm/admin/identities/a%2Fb", None);
    seen[1].assert_json(r#"[{"op":"add","path":"/metadata_admin/aud","value":"u:2"}]"#);
    seen[3].assert_json(r#"[{"op":"remove","path":"/metadata_admin/aud"}]"#);
    seen[5].assert_json(r#"[{"op":"remove","path":"/metadata_admin/note"}]"#);
}

#[tokio::test]
async fn removing_an_absent_metadata_key_sends_no_patch() {
    let stub = Stub::new(vec![ok(SESSION_AAL1_IDENTITY)]).await;
    assert!(
        !admin_remove_metadata_admin_key(&stub.clients, "i", "aud")
            .await
            .unwrap()
    );
    stub.only().assert("GET", "/adm/admin/identities/i", None);
}

const SESSION_AAL1_IDENTITY: &str =
    r#"{"id":"i","schema_id":"default","schema_url":"","traits":{}}"#;

#[tokio::test]
async fn delete_identity_and_create_identity() {
    let stub = Stub::new(vec![
        no_content(),
        reply(404, ERROR_NOT_FOUND),
        reply(201, IDENTITY),
        reply(409, ERROR_CONFLICT),
        reply(400, "{}"),
        reply(201, IDENTITY),
    ])
    .await;
    let c = &stub.clients;
    admin_delete_identity(c, "a b").await.unwrap();
    assert_eq!(
        admin_delete_identity(c, "x").await.unwrap_err().to_string(),
        "kratos admin delete_identity failed: error in response: status code 404 Not Found"
    );
    assert_eq!(
        admin_create_identity_verified(c, "default", "a@b.c", "Ä", "\"q\"")
            .await
            .unwrap(),
        Some(fixture_identity(false))
    );
    assert_eq!(
        admin_create_identity_verified(c, "default", "a@b.c", "A", "B")
            .await
            .unwrap(),
        None
    );
    assert!(
        admin_create_identity_verified(c, "default", "a@b.c", "A", "B")
            .await
            .is_err()
    );
    let backend = crate::ory::KratosBackend {
        clients: Arc::new(KratosClients::new(
            &stub.clients.kratos_public.base,
            &stub.clients.kratos_admin.base,
        )),
        https: false,
    };
    assert_eq!(
        crate::ory::create_unverified_test_identity(&backend, "p@x.y")
            .await
            .unwrap(),
        FULL_ID
    );
    let seen = stub.seen();
    seen[0].assert("DELETE", "/adm/admin/identities/a+b", None);
    seen[0].assert_no_body();
    seen[2].assert("POST", "/adm/admin/identities", None);
    seen[2].assert_json(
        r#"{"schema_id":"default","traits":{"email":"a@b.c","name":{"first":"Ä","last":"\"q\""}},"verifiable_addresses":[{"status":"completed","value":"a@b.c","verified":true,"via":"email"}]}"#,
    );
    seen[5].assert_json(
        r#"{"schema_id":"default","traits":{"email":"p@x.y","name":{"first":"Prune","last":"Test"}}}"#,
    );
}

#[tokio::test]
async fn recovery_code_and_link() {
    let stub = Stub::new(vec![
        reply(201, RECOVERY_CODE),
        reply(404, ERROR_NOT_FOUND),
        ok(RECOVERY_LINK),
        ok(RECOVERY_LINK),
    ])
    .await;
    let c = &stub.clients;
    assert_eq!(
        admin_create_recovery_code(c, "i/1").await.unwrap(),
        RecoveryCode {
            recovery_code: "fixture-recovery-code".into(),
            recovery_link:
                "http://localhost:3000/recovery?flow=8b22a405-995d-4bb1-83a7-540f8c55baa0".into(),
        }
    );
    assert_eq!(
        admin_create_recovery_code(c, "i")
            .await
            .unwrap_err()
            .to_string(),
        "kratos admin create_recovery_code failed: error in response: status code 404 Not Found"
    );
    let link = "http://localhost:4433/self-service/recovery?flow=61b1e11e-d92d-46c2-9ec1-99352d07e85a&token=fixture-recovery-token";
    assert_eq!(
        admin_create_recovery_link(c, "i/1", "1m", Some("/settings?a=b c"))
            .await
            .unwrap(),
        link
    );
    assert_eq!(
        admin_create_recovery_link(c, "i", "15m", None)
            .await
            .unwrap(),
        link
    );
    let seen = stub.seen();
    seen[0].assert("POST", "/adm/admin/recovery/code", None);
    seen[0].assert_json(r#"{"identity_id":"i/1"}"#);
    seen[2].assert(
        "POST",
        "/adm/admin/recovery/link",
        Some("return_to=%2Fsettings%3Fa%3Db+c"),
    );
    seen[2].assert_json(r#"{"expires_in":"1m","identity_id":"i/1"}"#);
    seen[3].assert("POST", "/adm/admin/recovery/link", None);
    seen[3].assert_json(r#"{"expires_in":"15m","identity_id":"i"}"#);
}

// --- status page ----------------------------------------------------------------

#[tokio::test]
async fn schemas_follow_the_admin_redirect() {
    let stub = Stub::new(vec![
        Reply {
            status: 307,
            content_type: Some("text/html; charset=utf-8"),
            link: None,
            location: Some("/pub/schemas".into()),
            body: String::new(),
        },
        ok(IDENTITY_SCHEMAS),
        ok(r#"[{"id":"x"}]"#),
    ])
    .await;
    assert_eq!(
        list_identity_schemas(&stub.clients).await.unwrap(),
        ["default"]
    );
    let err = list_identity_schemas(&stub.clients).await.unwrap_err();
    assert!(
        err.to_string().starts_with(
            "kratos list_identity_schemas failed: error in serde: missing field `schema`"
        ),
        "{err}"
    );
    let seen = stub.seen();
    seen[0].assert("GET", "/adm/schemas", None);
    seen[1].assert("GET", "/pub/schemas", None);
}

#[tokio::test]
async fn courier_backlog_counts_the_first_page() {
    let unknown = COURIER_MESSAGES.replace("verification_code_valid", "brand_new");
    let stub = Stub::new(vec![ok(COURIER_MESSAGES), ok("[]"), ok(&unknown)]).await;
    let c = &stub.clients;
    assert_eq!(
        courier_backlog(c, CourierStatus::Queued, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        courier_backlog(c, CourierStatus::Abandoned, 5)
            .await
            .unwrap(),
        0
    );
    assert!(courier_backlog(c, CourierStatus::Queued, 1).await.is_err());
    let seen = stub.seen();
    seen[0].assert(
        "GET",
        "/adm/admin/courier/messages",
        Some("page_size=100&status=queued"),
    );
    seen[1].assert(
        "GET",
        "/adm/admin/courier/messages",
        Some("page_size=5&status=abandoned"),
    );
}

#[tokio::test]
async fn health_and_version() {
    let down = Reply {
        content_type: Some("text/plain"),
        ..reply(503, "down")
    };
    let stub = Stub::new(vec![ok(HEALTH_ALIVE), down, ok(VERSION), ok("{}")]).await;
    let c = &stub.clients;
    health_alive(c).await.unwrap();
    assert_eq!(
        health_ready(c).await.unwrap_err().to_string(),
        "health probe /health/ready returned 503 Service Unavailable: down"
    );
    assert_eq!(version(c).await.unwrap(), "v26.2.0");
    assert!(
        version(c)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("kratos get_version failed: error in serde: missing field `version`")
    );
    let seen = stub.seen();
    seen[0].assert("GET", "/adm/health/alive", None);
    seen[1].assert("GET", "/adm/health/ready", None);
    seen[2].assert("GET", "/adm/version", None);
}

#[test]
fn error_fixtures_are_kratos_error_bodies() {
    for (raw, code) in [
        (ERROR_UNAUTHORIZED, 401),
        (ERROR_AAL2_REQUIRED, 403),
        (ERROR_NOT_FOUND, 404),
        (ERROR_CONFLICT, 409),
    ] {
        assert_eq!(decode::<Value>(raw)["error"]["code"], code);
    }
    assert_eq!(
        decode::<Value>(ERROR_AAL2_REQUIRED)["error"]["id"],
        "session_aal2_required"
    );
}
