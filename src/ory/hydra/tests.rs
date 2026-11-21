use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::http::Uri;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::json;

use super::*;
use crate::backend::oauth::{DeviceTokenOutcome, IdTokenClaims, OidcContext};

const CLIENT: &str = include_str!("../fixtures/hydra/client.json");
const CLIENT_CREATED: &str = include_str!("../fixtures/hydra/client_created.json");
const LOGIN_REQUEST: &str = include_str!("../fixtures/hydra/login_request.json");
const LOGIN_REQUEST_SKIP: &str = include_str!("../fixtures/hydra/login_request_skip.json");
const CONSENT_REQUEST: &str = include_str!("../fixtures/hydra/consent_request.json");
const CONSENT_REQUEST_SKIP: &str = include_str!("../fixtures/hydra/consent_request_skip.json");
const CONSENT_SESSIONS: &str = include_str!("../fixtures/hydra/consent_sessions.json");
const LOGOUT_REQUEST: &str = include_str!("../fixtures/hydra/logout_request.json");
const REDIRECT_TO: &str = include_str!("../fixtures/hydra/redirect_to.json");
const DEVICE_AUTHORIZATION: &str = include_str!("../fixtures/hydra/device_authorization.json");
const TOKEN_RESPONSE: &str = include_str!("../fixtures/hydra/token_response.json");
const JWKS: &str = include_str!("../fixtures/hydra/jwks.json");
const DISCOVERY: &str = include_str!("../fixtures/hydra/discovery.json");
const VERSION: &str = include_str!("../fixtures/hydra/version.json");
const ERROR_NOT_FOUND: &str = include_str!("../fixtures/hydra/error_not_found.json");

// --- device-token error mapping --------------------------------------

#[test]
fn maps_device_token_errors() {
    assert!(matches!(
        map_device_token_error("authorization_pending"),
        DeviceTokenOutcome::Pending
    ));
    assert!(matches!(
        map_device_token_error("slow_down"),
        DeviceTokenOutcome::SlowDown
    ));
    assert!(matches!(
        map_device_token_error("expired_token"),
        DeviceTokenOutcome::Expired
    ));
    assert!(matches!(
        map_device_token_error("access_denied"),
        DeviceTokenOutcome::Denied
    ));
    // Unknown / consumed-grant codes collapse to a dead flow.
    assert!(matches!(
        map_device_token_error("invalid_grant"),
        DeviceTokenOutcome::Expired
    ));
}

// --- id_token validation ---------------------------------------------

const TEST_ISS: &str = "http://hydra.test:4444";
const TEST_CLIENT: &str = "forseti-linux-pam";

// PKCS#8 RSA-2048 private key used only to mint test id_tokens.
const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwVqAC9L0r0uJ2\n\
JDPk9e2axX7YSYYfc7SxW85iWv9XpBDHuzZ9vMsl532kQY5PT7f4FpdZSrPL1QLm\n\
+9EFh2VYBm17qbFwFAbEvvymBZ8f4NNQI/xXpCRX/X4E7Di0U3IdZsyJlAqLQD8a\n\
hUWRdG1gAOhwe1OyersaRE6QoH4Arce4oY9pAtduKbio6VZSsItNZJWJ7yISGlnS\n\
xK0kU7M01lvnXWAFfNhDo6E9QBtHuprfiAUqiqfMHd0tDvy01t4+ytSY6l/INHW/\n\
Td4JsjWSc+10AJxFGYU/GrYGF9NENmZIPxIYH5kxsVUEOI3gjGfp+x9eDjRjtJ/+\n\
vAmlXx2XAgMBAAECggEAH0Zl39BXYtfmuWxnVdL2Xs5rVmIH6zki0ZgGTTR1eC5N\n\
mZcPLZLX9vONOZ405sUtTE95bWlN5Td06dG8uz3N0CRns5ifs1Ch+LAk8C8sD0PZ\n\
RqvzO/oNRhvcB3R8BCOOqD9MxJPgoNz2tDXx5j/fjDjtANImwI968sgtpQIKBwV/\n\
qrhBEJ4vVLqDiSTNtdFsS73evgFYylVUfigFTd4xDqPc6LBMd1DscLL1jTSjiX03\n\
VmWMUVt4LWhuE89GzuXVZehx1nO6HRqLNpSPjoxX+3d+1+aw/QkFhj5R4qBXd2XV\n\
gjFD4bMslO6tLKXqicBCg9eGf3ixKpNHZdFCYMHHYQKBgQDoqPoyA+LKjhVuacSY\n\
8/vXKH4XLfvpIUZs74VRgqnvp7854F1MxudPsXoy/GxmUzyTCMQpR4E2hoUPsTT2\n\
q8pEcNZoh9jEhmKOwuoEV6Yfm2OmPucqBp+SK5/l/wrPuJC/Ao/UCxb3YaeXqdLt\n\
qEF5SJ6Th+L28tEXYsdMloWl4QKBgQDCBzsvm/XXfX2dmvdwWR6pCk1kRiqCDr7J\n\
KhxLyZUVrDDEp2vK+BNaWaN5G4vslfJ8+RINOTY6bETvLP8nbnI5wxQFi61IvFDd\n\
nJ9E3+Sg5hr20iHZ2kPu+UYxkES+kiuyFehfNZcfl2K/q2aJKB7KHJkM9yVsK7Yn\n\
LrCUcdtCdwKBgQDAdnhyQ3Cq6xqjee9eMAcXF7Im7q1DT3l4yDNbGGIHlJbGA+pq\n\
huf2rvRNlS7+/sBPSaMsGrCzMFiGgKs1myr5rvZPBoG1IQ4K1wbLjM4pu1uVvNdx\n\
loUOX/QoSPDioOVsfWwJlxrqjegbuCp62wM+l2pG1NRWQMvjMp13p9TrQQKBgQCB\n\
D6BN3dbcXOvWjwLyJ0WeuWybO5UA59/+HVWvD8psHRpfZOHto6/z1FZJs4oSd/dR\n\
K7fXNewdVnFQCsU6LFwskddajPtZu3Gqx4ilnqwMXqMm9MVxjJ7NceBADa+8d6w7\n\
DBmCYzo/2EnmJpPQvfAlDnq7xhWNa1IBpCvuwgFPpwKBgBeqbZPSX+H7OQZwK9uo\n\
tMT4rTN4iCzBd3OQryd+UVF5dlGZSM/ahPo0sVEoIc5Do6qKB+hs92alKJsr97b+\n\
SRZ/w8gQ2ALLGaApskC1zn5ojdqqjTvXWmW9bccCeGYJ8yOu4oWP/QLkNzM4WVKA\n\
3SmfuVDc+5r3d6JFhgQeOMb1\n\
-----END PRIVATE KEY-----\n";

// base64url RSA modulus/exponent for the key above (the JWKS Hydra would publish for it).
const TEST_N: &str = "sFagAvS9K9LidiQz5PXtmsV-2EmGH3O0sVvOYlr_V6QQx7s2fbzLJed9pEGOT0-3-BaXWUqzy9UC5vvRBYdlWAZte6mxcBQGxL78pgWfH-DTUCP8V6QkV_1-BOw4tFNyHWbMiZQKi0A_GoVFkXRtYADocHtTsnq7GkROkKB-AK3HuKGPaQLXbim4qOlWUrCLTWSVie8iEhpZ0sStJFOzNNZb511gBXzYQ6OhPUAbR7qa34gFKoqnzB3dLQ78tNbePsrUmOpfyDR1v03eCbI1knPtdACcRRmFPxq2BhfTRDZmSD8SGB-ZMbFVBDiN4Ixn6fsfXg40Y7Sf_rwJpV8dlw";
const TEST_E: &str = "AQAB";
const TEST_KID: &str = "test-kid";

fn test_jwks_json() -> Value {
    json!({"keys": [{
        "alg": "RS256",
        "kid": TEST_KID,
        "kty": "RSA",
        "use": "sig",
        "n": TEST_N,
        "e": TEST_E,
    }]})
}

fn test_jwks() -> JsonWebKeySet {
    serde_json::from_value(test_jwks_json()).unwrap()
}

#[derive(serde::Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    azp: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    amr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
}

impl Default for TestClaims {
    fn default() -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            sub: "ident-123".into(),
            iss: TEST_ISS.into(),
            aud: TEST_CLIENT.into(),
            azp: TEST_CLIENT.into(),
            exp: now + 300,
            iat: now,
            acr: Some("aal2".into()),
            amr: vec!["pwd".into(), "totp".into()],
            auth_time: Some(now),
        }
    }
}

fn mint(claims: &TestClaims, alg: jsonwebtoken::Algorithm) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(alg);
    header.kid = Some(TEST_KID.into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, claims, &key).unwrap()
}

fn verify(token: &str) -> Result<IdTokenClaims> {
    verify_id_token_with_jwks(token, &test_jwks(), TEST_ISS, TEST_CLIENT, 120)
}

#[test]
fn id_token_valid_passes() {
    let claims = TestClaims::default();
    let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
    let out = verify(&tok).expect("valid token");
    assert_eq!(out.sub, "ident-123");
    assert_eq!(out.acr.as_deref(), Some("aal2"));
    assert_eq!(out.amr, vec!["pwd".to_string(), "totp".to_string()]);
    assert!(out.auth_time.is_some());
}

#[test]
fn id_token_alg_none_rejected() {
    // A `none`-alg token (unsigned). jsonwebtoken won't mint `none`, so
    // hand-build the compact form.
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let header = b64(br#"{"alg":"none","kid":"test-kid","typ":"JWT"}"#);
    let claims = TestClaims::default();
    let payload = b64(serde_json::to_vec(&claims).unwrap().as_slice());
    let tok = format!("{header}.{payload}.");
    let err = verify(&tok).unwrap_err().to_string();
    assert!(err.contains("alg") || err.contains("RS256"), "got: {err}");
}

#[test]
fn id_token_wrong_aud_rejected() {
    let claims = TestClaims {
        aud: "some-other-client".into(),
        ..TestClaims::default()
    };
    let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
    assert!(verify(&tok).is_err());
}

#[test]
fn id_token_extra_aud_rejected() {
    // aud contains our client plus another party. jsonwebtoken accepts the
    // membership, but the exact-aud pin must reject the multi-audience token.
    #[derive(serde::Serialize)]
    struct MultiAud {
        sub: String,
        iss: String,
        aud: Vec<String>,
        azp: String,
        exp: i64,
        iat: i64,
    }
    use jsonwebtoken::{EncodingKey, Header, encode};
    let now = chrono::Utc::now().timestamp();
    let claims = MultiAud {
        sub: "ident-123".into(),
        iss: TEST_ISS.into(),
        aud: vec![TEST_CLIENT.into(), "other-rp".into()],
        azp: TEST_CLIENT.into(),
        exp: now + 300,
        iat: now,
    };
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(TEST_KID.into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    let tok = encode(&header, &claims, &key).unwrap();
    let err = verify(&tok).unwrap_err().to_string();
    assert!(err.contains("aud"), "got: {err}");
}

#[test]
fn id_token_wrong_azp_rejected() {
    // aud correct (our client) but azp points elsewhere; the authorized-party pin must still reject.
    let claims = TestClaims {
        azp: "evil-client".into(),
        ..TestClaims::default()
    };
    let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
    let err = verify(&tok).unwrap_err().to_string();
    assert!(err.contains("azp"), "got: {err}");
}

#[test]
fn id_token_wrong_iss_rejected() {
    let claims = TestClaims {
        iss: "http://evil.test".into(),
        ..TestClaims::default()
    };
    let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
    assert!(verify(&tok).is_err());
}

#[test]
fn id_token_expired_rejected() {
    let now = chrono::Utc::now().timestamp();
    // Past exp, beyond jsonwebtoken's 60s leeway.
    let claims = TestClaims {
        exp: now - 600,
        iat: now - 900,
        ..TestClaims::default()
    };
    let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
    assert!(verify(&tok).is_err());
}

#[test]
fn id_token_stale_iat_rejected() {
    let now = chrono::Utc::now().timestamp();
    // Still inside exp, but iat is older than the 120s window.
    let claims = TestClaims {
        iat: now - 300,
        exp: now + 300,
        ..TestClaims::default()
    };
    let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
    let err = verify(&tok).unwrap_err().to_string();
    assert!(err.contains("stale") || err.contains("iat"), "got: {err}");
}

#[test]
fn id_token_unknown_kid_rejected() {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("not-in-jwks".into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    let tok = encode(&header, &TestClaims::default(), &key).unwrap();
    let err = verify(&tok).unwrap_err().to_string();
    assert!(err.contains("kid"), "got: {err}");
}

#[test]
fn next_link_extracts_page_token() {
    let mut h = HeaderMap::new();
    h.insert(
        "link",
        HeaderValue::from_static(
            "<https://hydra/admin/oauth2/auth/sessions/consent?page_token=abc123&page_size=250>; rel=\"next\"",
        ),
    );
    assert_eq!(next_link(&h).as_deref(), Some("abc123"));
}

#[test]
fn next_link_handles_multiple_relations() {
    let mut h = HeaderMap::new();
    h.insert(
        "link",
        HeaderValue::from_static(
            "<https://hydra/prev?page_token=xyz>; rel=\"prev\", <https://hydra/next?page_token=def>; rel=\"next\"",
        ),
    );
    assert_eq!(next_link(&h).as_deref(), Some("def"));
}

#[test]
fn next_link_skips_bare_part_before_next() {
    let mut h = HeaderMap::new();
    h.insert(
        "link",
        HeaderValue::from_static(
            "<https://hydra/first?page_token=xyz>, <https://hydra/next?page_token=def>; rel=\"next\"",
        ),
    );
    assert_eq!(next_link(&h).as_deref(), Some("def"));
}

#[test]
fn next_link_returns_none_when_only_prev() {
    let mut h = HeaderMap::new();
    h.insert(
        "link",
        HeaderValue::from_static("<https://hydra/prev?page_token=xyz>; rel=\"prev\""),
    );
    assert_eq!(next_link(&h), None);
}

#[test]
fn next_link_missing_header() {
    let h = HeaderMap::new();
    assert_eq!(next_link(&h), None);
}

// --- client audience patch --------------------------------------------

const MCP: &str = "https://stackpit.gofranz.com/mcp";

fn owned(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

/// The audience values a patch would append, in order.
fn appended(patch: &[JsonPatchOp]) -> Vec<String> {
    patch
        .iter()
        .map(|p| {
            assert_eq!((p.op, p.path), ("add", "/audience/-"));
            p.value.as_str().expect("patch value").to_string()
        })
        .collect()
}

#[test]
fn audience_patch_appends_a_resource_the_record_lacks() {
    let patch = audience_patch("c", &[], &owned(&[MCP]));
    assert_eq!(appended(&patch), vec![MCP.to_string()]);
}

#[test]
fn second_consent_for_the_same_resource_emits_no_patch() {
    // The bug: an empty `on_record` made every consent re-append, so one
    // client's record grew an identical entry per grant, unbounded.
    assert!(audience_patch("c", &owned(&[MCP]), &owned(&[MCP])).is_empty());
}

#[test]
fn audience_patch_dedups_against_a_self_written_record() {
    // Whoever wrote the entry, it is already there — a CIMD client's own
    // `audience` still suppresses the write.
    let self_written = "http://127.0.0.1:3333/mcp";
    assert!(audience_patch("c", &owned(&[self_written]), &owned(&[self_written])).is_empty());
}

#[test]
fn audience_patch_dedups_a_record_that_already_repeats() {
    // The bloated records the bug left behind must not keep growing.
    assert!(audience_patch("c", &owned(&[MCP, MCP, MCP]), &owned(&[MCP])).is_empty());
}

#[test]
fn audience_patch_appends_each_resource_once() {
    let patch = audience_patch(
        "c",
        &owned(&[MCP]),
        &owned(&[MCP, "https://a.test", "https://a.test"]),
    );
    assert_eq!(appended(&patch), vec!["https://a.test".to_string()]);
}

#[test]
fn audience_patch_stops_at_the_cap() {
    let full: Vec<String> = (0..CLIENT_AUDIENCE_CAP)
        .map(|i| format!("https://r{i}.test"))
        .collect();
    assert!(audience_patch("c", &full, &owned(&["https://new.test"])).is_empty());
    // One slot left: the first granted resource lands, the rest don't.
    let patch = audience_patch(
        "c",
        &full[..CLIENT_AUDIENCE_CAP - 1],
        &owned(&["https://a.test", "https://b.test"]),
    );
    assert_eq!(appended(&patch), vec!["https://a.test".to_string()]);
}

// --- recording stub ---------------------------------------------------

/// One request as the stub received it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: Option<String>,
    content_type: Option<String>,
    authorization: Option<String>,
    body: Vec<u8>,
}

impl Seen {
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

    fn assert_json(&self, want: Value) {
        assert_eq!(self.content_type.as_deref(), Some("application/json"));
        let got: Value = serde_json::from_slice(&self.body).expect("JSON request body");
        assert_eq!(got, want);
    }

    fn assert_no_body(&self) {
        assert!(self.body.is_empty(), "{self:#?}");
        assert_eq!(self.content_type, None);
    }

    fn assert_form(&self, want: &str) {
        assert_eq!(
            self.content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(std::str::from_utf8(&self.body).unwrap(), want);
    }
}

struct Reply {
    status: u16,
    content_type: Option<&'static str>,
    link: Option<&'static str>,
    body: String,
}

fn reply(status: u16, body: &str) -> Reply {
    Reply {
        status,
        content_type: Some("application/json; charset=utf-8"),
        link: None,
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
        body: String::new(),
    }
}

fn not_found() -> Reply {
    reply(404, ERROR_NOT_FOUND)
}

/// An HTTP server that records every request and answers with `replies` in order.
/// The public endpoint is mounted at `/pub`, the admin one at `/adm`.
struct Stub {
    hydra: HydraBackend,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Stub {
    async fn new(replies: Vec<Reply>) -> Stub {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(replies)));
        let log = seen.clone();
        let app = axum::Router::new().fallback(
            move |method: axum::http::Method,
                  uri: Uri,
                  headers: axum::http::HeaderMap,
                  body: Bytes| {
                let log = log.clone();
                let queue = queue.clone();
                async move {
                    let header = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string)
                    };
                    log.lock().unwrap().push(Seen {
                        method: method.to_string(),
                        path: uri.path().to_string(),
                        query: uri.query().map(str::to_string),
                        content_type: header("content-type"),
                        authorization: header("authorization"),
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
                    resp.body(Body::from(r.body)).unwrap()
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Stub {
            hydra: HydraBackend {
                clients: Arc::new(OryClients::new(
                    &format!("{base}/pub"),
                    &format!("{base}/adm"),
                )),
            },
            seen,
        }
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

// --- fixture expectations ----------------------------------------------

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

fn object(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => panic!("not an object"),
    }
}

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
}

/// `request_url` as the fixture carries it.
fn request_url(v: &Value) -> String {
    v["request_url"].as_str().unwrap().to_string()
}

/// `client.json` as Forseti reads it: `skip_logout_consent: null` is dropped, the null lifespans stay.
fn fixture_client() -> OAuthClient {
    OAuthClient {
        audience: Some(strings(&["https://api.fixture.test"])),
        backchannel_logout_session_required: None,
        backchannel_logout_uri: Some("http://127.0.0.1:9999/bcl".into()),
        client_id: Some("forseti-fixture-client".into()),
        client_name: Some("Fixture App".into()),
        client_secret: None,
        client_uri: Some(String::new()),
        created_at: Some("2026-11-20T19:44:40Z".into()),
        frontchannel_logout_session_required: None,
        frontchannel_logout_uri: None,
        grant_types: Some(strings(&[
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ])),
        logo_uri: Some(String::new()),
        metadata: Some(json!({"forseti": {"client_type": "web_app"}})),
        post_logout_redirect_uris: Some(strings(&["http://127.0.0.1:9999/bye"])),
        redirect_uris: Some(strings(&["http://127.0.0.1:9999/cb"])),
        registration_access_token: None,
        response_types: Some(strings(&["code"])),
        scope: Some("openid offline_access email".into()),
        skip_consent: Some(false),
        token_endpoint_auth_method: Some("client_secret_basic".into()),
        extra: object(json!({
            "allowed_cors_origins": [],
            "authorization_code_grant_access_token_lifespan": null,
            "authorization_code_grant_id_token_lifespan": "1h0m0s",
            "authorization_code_grant_refresh_token_lifespan": null,
            "client_credentials_grant_access_token_lifespan": null,
            "client_secret_expires_at": 0,
            "contacts": [],
            "device_authorization_grant_access_token_lifespan": null,
            "device_authorization_grant_id_token_lifespan": null,
            "device_authorization_grant_refresh_token_lifespan": null,
            "implicit_grant_access_token_lifespan": null,
            "implicit_grant_id_token_lifespan": null,
            "jwks": {},
            "jwt_bearer_grant_access_token_lifespan": null,
            "owner": "",
            "policy_uri": "",
            "refresh_token_grant_access_token_lifespan": null,
            "refresh_token_grant_id_token_lifespan": null,
            "refresh_token_grant_refresh_token_lifespan": null,
            "subject_type": "public",
            "tos_uri": "",
            "updated_at": "2026-11-20T19:44:39.838666Z",
            "userinfo_signed_response_alg": "none",
        })),
    }
}

/// `client.json` as Forseti writes it back.
fn fixture_client_wire() -> Value {
    let mut v = fixture(CLIENT);
    v.as_object_mut().unwrap().remove("skip_logout_consent");
    v
}

fn fixture_oidc_context() -> OidcContext {
    OidcContext {
        acr_values: Some(strings(&["aal2"])),
        login_hint: Some("alice@example.com".into()),
        ui_locales: Some(strings(&["de", "en"])),
    }
}

const SID: &str = "0c555428-144b-4e2a-950d-b28f1e9f2184";
const SUBJECT: &str = "fixture-subject-1";
const CONSENT_REQUEST_ID: &str = "2179363104f34015946962bee0c27d56";

/// Every client field the spec names, all set, in wire order.
fn full_client_json() -> Value {
    serde_json::from_str(
        r#"{
            "access_token_strategy": "jwt",
            "allowed_cors_origins": ["https://cors.example"],
            "audience": ["https://api.example"],
            "authorization_code_grant_access_token_lifespan": null,
            "authorization_code_grant_id_token_lifespan": "1h",
            "authorization_code_grant_refresh_token_lifespan": "720h",
            "backchannel_logout_session_required": true,
            "backchannel_logout_uri": "https://app.example/bcl",
            "client_credentials_grant_access_token_lifespan": null,
            "client_id": "client-1",
            "client_name": "App",
            "client_secret": "secret",
            "client_secret_expires_at": 1900000000,
            "client_uri": "https://app.example",
            "contacts": ["ops@app.example"],
            "created_at": "2026-01-01T00:00:00Z",
            "device_authorization_grant_access_token_lifespan": "2h",
            "device_authorization_grant_id_token_lifespan": null,
            "device_authorization_grant_refresh_token_lifespan": "3h",
            "frontchannel_logout_session_required": true,
            "frontchannel_logout_uri": "https://app.example/fcl",
            "grant_types": ["authorization_code", "refresh_token"],
            "implicit_grant_access_token_lifespan": "4h",
            "implicit_grant_id_token_lifespan": null,
            "jwks": {"keys": [{
                "alg": "RS256", "crv": "P-256", "d": "d", "dp": "dp", "dq": "dq", "e": "AQAB",
                "k": "k", "kid": "kid-1", "kty": "RSA", "n": "n", "p": "p", "q": "q", "qi": "qi",
                "use": "sig", "x": "x", "x5c": ["cert"], "y": "y"
            }]},
            "jwks_uri": "https://app.example/jwks.json",
            "jwt_bearer_grant_access_token_lifespan": "5h",
            "logo_uri": "https://app.example/logo.png",
            "metadata": {"forseti": {"client_type": "web_app", "require_pkce": true}},
            "owner": "owner",
            "policy_uri": "https://app.example/policy",
            "post_logout_redirect_uris": ["https://app.example/bye"],
            "redirect_uris": ["https://app.example/cb"],
            "refresh_token_grant_access_token_lifespan": null,
            "refresh_token_grant_id_token_lifespan": "6h",
            "refresh_token_grant_refresh_token_lifespan": "7h",
            "registration_access_token": "rat",
            "registration_client_uri": "https://hydra.example/oauth2/register/client-1",
            "request_object_signing_alg": "RS256",
            "request_uris": ["https://app.example/req"],
            "response_types": ["code"],
            "scope": "openid offline_access",
            "sector_identifier_uri": "https://app.example/sector.json",
            "skip_consent": true,
            "skip_logout_consent": true,
            "subject_type": "public",
            "token_endpoint_auth_method": "client_secret_basic",
            "token_endpoint_auth_signing_alg": "RS256",
            "tos_uri": "https://app.example/tos",
            "updated_at": "2026-02-01T00:00:00Z",
            "userinfo_signed_response_alg": "none"
        }"#,
    )
    .unwrap()
}

// --- client wire shape -------------------------------------------------

#[test]
fn client_round_trips_through_the_wire_shape() {
    for x in [full_client_json(), json!({})] {
        let back = client_to_wire(client_from_wire(x.clone()).unwrap()).unwrap();
        assert_eq!(back, x);
        assert_eq!(back.to_string(), x.to_string(), "key order");
    }
    assert_eq!(
        serde_json::to_value(client_from_wire(json!({})).unwrap()).unwrap(),
        json!({})
    );
}

#[test]
fn client_names_app_fields_and_carries_the_rest() {
    let x = full_client_json();
    let mut d = client_from_wire(x.clone()).unwrap();
    assert_eq!(d.client_name.as_deref(), Some("App"));
    assert_eq!(d.metadata, Some(x["metadata"].clone()));
    assert_eq!(
        d.extra["authorization_code_grant_access_token_lifespan"],
        Value::Null
    );
    assert_eq!(d.extra["jwks"], x["jwks"]);
    let mut extra: Vec<&str> = d.extra.keys().map(String::as_str).collect();
    extra.sort_unstable();
    assert_eq!(
        extra,
        [
            "access_token_strategy",
            "allowed_cors_origins",
            "authorization_code_grant_access_token_lifespan",
            "authorization_code_grant_id_token_lifespan",
            "authorization_code_grant_refresh_token_lifespan",
            "client_credentials_grant_access_token_lifespan",
            "client_secret_expires_at",
            "contacts",
            "device_authorization_grant_access_token_lifespan",
            "device_authorization_grant_id_token_lifespan",
            "device_authorization_grant_refresh_token_lifespan",
            "implicit_grant_access_token_lifespan",
            "implicit_grant_id_token_lifespan",
            "jwks",
            "jwks_uri",
            "jwt_bearer_grant_access_token_lifespan",
            "owner",
            "policy_uri",
            "refresh_token_grant_access_token_lifespan",
            "refresh_token_grant_id_token_lifespan",
            "refresh_token_grant_refresh_token_lifespan",
            "registration_client_uri",
            "request_object_signing_alg",
            "request_uris",
            "sector_identifier_uri",
            "skip_logout_consent",
            "subject_type",
            "token_endpoint_auth_signing_alg",
            "tos_uri",
            "updated_at",
            "userinfo_signed_response_alg",
        ]
    );

    d.client_name = Some("Renamed".to_string());
    d.backchannel_logout_uri = None;
    let back = client_to_wire(d).unwrap();
    let mut expected = x;
    expected["client_name"] = json!("Renamed");
    expected
        .as_object_mut()
        .unwrap()
        .remove("backchannel_logout_uri");
    assert_eq!(back, expected);
}

#[test]
fn client_wire_shape_drops_unknown_fields_and_plain_nulls() {
    let raw = json!({
        "client_id": "c",
        "not_in_the_spec": 1,
        "contacts": null,
        "metadata": null,
        "skip_logout_consent": null,
        "implicit_grant_id_token_lifespan": null,
        "jwks": {"keys": [{"kid": "k", "use": "sig", "x5c": null, "extra": 1}], "other": 2},
    });
    let want = json!({
        "client_id": "c",
        "implicit_grant_id_token_lifespan": null,
        "jwks": {"keys": [{"kid": "k", "use": "sig"}]},
    });
    let c = client_from_wire(raw.clone()).unwrap();
    assert_eq!(c.metadata, None);
    assert_eq!(client_to_wire(c).unwrap(), want);

    let c = OAuthClient {
        extra: object(raw),
        ..Default::default()
    };
    assert_eq!(client_to_wire(c).unwrap(), want);

    for (jwks, want) in [(json!({"keys": null}), json!({})), (json!({}), json!({}))] {
        let mut v = json!({"jwks": jwks});
        wire_client(&mut v);
        assert_eq!(v, json!({"jwks": want}));
    }
}

#[test]
fn client_fixture_decodes() {
    assert_eq!(client_from_wire(fixture(CLIENT)).unwrap(), fixture_client());
}

#[test]
fn consent_session_defaults_when_empty() {
    let sessions: Vec<ConsentSession> = with_nested_clients(json!([{}])).unwrap();
    assert_eq!(sessions, [ConsentSession::default()]);
}

// --- login, consent, logout --------------------------------------------

#[tokio::test]
async fn get_login_request_sends_the_challenge_and_decodes() {
    let stub = Stub::new(vec![ok(LOGIN_REQUEST)]).await;
    let got = stub.hydra.get_login_request("a b/c+d").await.unwrap();
    let seen = stub.only();
    seen.assert(
        "GET",
        "/adm/admin/oauth2/auth/requests/login",
        Some("login_challenge=a+b%2Fc%2Bd"),
    );
    seen.assert_no_body();
    assert_eq!(
        got,
        LoginRequest {
            client: fixture_client(),
            oidc_context: Some(fixture_oidc_context()),
            request_url: request_url(&fixture(LOGIN_REQUEST)),
            requested_scope: Some(strings(&["openid", "offline_access", "email"])),
            session_id: Some(SID.into()),
            skip: false,
            subject: String::new(),
        }
    );
    assert!(got.request_url.starts_with(
        "http://host.containers.internal:3000/hydra/oauth2/auth?client_id=forseti-fixture-client&"
    ));
}

#[tokio::test]
async fn get_login_request_decodes_a_remembered_login() {
    let stub = Stub::new(vec![ok(LOGIN_REQUEST_SKIP)]).await;
    let got = stub.hydra.get_login_request("c").await.unwrap();
    assert_eq!(
        got,
        LoginRequest {
            client: fixture_client(),
            oidc_context: Some(OidcContext::default()),
            request_url: request_url(&fixture(LOGIN_REQUEST_SKIP)),
            requested_scope: Some(strings(&["openid", "offline_access", "email"])),
            session_id: Some(SID.into()),
            skip: true,
            subject: SUBJECT.into(),
        }
    );
}

#[tokio::test]
async fn get_login_request_maps_status_and_content_type_errors() {
    let text = Reply {
        status: 200,
        content_type: Some("text/plain"),
        link: None,
        body: "{}".into(),
    };
    let stub = Stub::new(vec![not_found(), text]).await;
    let err = stub.hydra.get_login_request("gone").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra get_login_request failed: error in response: status code 404 Not Found"
    );
    let err = stub.hydra.get_login_request("c").await.unwrap_err();
    assert!(
        err.to_string()
            .starts_with("hydra get_login_request failed: error in serde: Received `text/plain`"),
        "{err}"
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let redirect = Reply {
        status: 302,
        content_type: None,
        link: None,
        body: String::new(),
    };
    let stub = Stub::new(vec![redirect]).await;
    assert!(stub.hydra.get_login_request("c").await.is_err());
    assert_eq!(stub.seen().len(), 1);
}

#[tokio::test]
async fn accept_login_request_sends_the_body() {
    let stub = Stub::new(vec![ok(REDIRECT_TO), ok(REDIRECT_TO)]).await;
    let got = stub
        .hydra
        .accept_login_request(
            "ch",
            "subject-1",
            true,
            3600,
            strings(&["pwd", "totp"]),
            Some("aal2".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        got.redirect_to,
        fixture(REDIRECT_TO)["redirect_to"].as_str().unwrap()
    );
    stub.hydra
        .accept_login_request("ch", "subject-1", false, 0, vec![], None)
        .await
        .unwrap();
    let seen = stub.seen();
    for s in &seen {
        s.assert(
            "PUT",
            "/adm/admin/oauth2/auth/requests/login/accept",
            Some("login_challenge=ch"),
        );
    }
    seen[0].assert_json(json!({
        "acr": "aal2",
        "amr": ["pwd", "totp"],
        "remember": true,
        "remember_for": 3600,
        "subject": "subject-1",
    }));
    seen[1].assert_json(json!({"remember": false, "remember_for": 0, "subject": "subject-1"}));
}

#[tokio::test]
async fn reject_login_request_sends_no_status_code() {
    let stub = Stub::new(vec![ok(REDIRECT_TO)]).await;
    stub.hydra
        .reject_login_request("ch", "login_required", "no session")
        .await
        .unwrap();
    let seen = stub.only();
    seen.assert(
        "PUT",
        "/adm/admin/oauth2/auth/requests/login/reject",
        Some("login_challenge=ch"),
    );
    seen.assert_json(json!({"error": "login_required", "error_description": "no session"}));
}

#[tokio::test]
async fn get_consent_request_sends_the_challenge_and_decodes() {
    let stub = Stub::new(vec![ok(CONSENT_REQUEST), ok(CONSENT_REQUEST_SKIP)]).await;
    let got = stub.hydra.get_consent_request("ch").await.unwrap();
    assert_eq!(
        got,
        ConsentRequest {
            client: Some(fixture_client()),
            consent_request_id: Some(CONSENT_REQUEST_ID.into()),
            login_session_id: Some(SID.into()),
            oidc_context: Some(fixture_oidc_context()),
            request_url: Some(request_url(&fixture(CONSENT_REQUEST))),
            requested_access_token_audience: Some(strings(&["https://api.fixture.test"])),
            requested_scope: Some(strings(&["openid", "offline_access", "email"])),
            skip: Some(false),
            subject: Some(SUBJECT.into()),
        }
    );
    let skip = stub.hydra.get_consent_request("ch2").await.unwrap();
    assert_eq!(
        skip,
        ConsentRequest {
            client: Some(fixture_client()),
            consent_request_id: Some("129ba72b5f594756ad60079335802a71".into()),
            login_session_id: Some(SID.into()),
            oidc_context: Some(OidcContext::default()),
            request_url: Some(request_url(&fixture(CONSENT_REQUEST_SKIP))),
            requested_access_token_audience: Some(strings(&["https://api.fixture.test"])),
            requested_scope: Some(strings(&["openid", "offline_access", "email"])),
            skip: Some(true),
            subject: Some(SUBJECT.into()),
        }
    );
    let seen = stub.seen();
    seen[0].assert(
        "GET",
        "/adm/admin/oauth2/auth/requests/consent",
        Some("consent_challenge=ch"),
    );
    seen[0].assert_no_body();
    seen[1].assert(
        "GET",
        "/adm/admin/oauth2/auth/requests/consent",
        Some("consent_challenge=ch2"),
    );
}

#[tokio::test]
async fn accept_consent_request_sends_the_body() {
    let stub = Stub::new(vec![ok(REDIRECT_TO), ok(REDIRECT_TO)]).await;
    stub.hydra
        .accept_consent_request(
            "ch",
            strings(&["openid", "email"]),
            strings(&["https://api.test"]),
            true,
            json!({"email": "a@example.com"}),
            Map::new(),
        )
        .await
        .unwrap();
    stub.hydra
        .accept_consent_request(
            "ch",
            vec![],
            vec![],
            false,
            Value::Null,
            object(json!({"org": "o"})),
        )
        .await
        .unwrap();
    let seen = stub.seen();
    for s in &seen {
        s.assert(
            "PUT",
            "/adm/admin/oauth2/auth/requests/consent/accept",
            Some("consent_challenge=ch"),
        );
    }
    seen[0].assert_json(json!({
        "grant_access_token_audience": ["https://api.test"],
        "grant_scope": ["openid", "email"],
        "remember": true,
        "remember_for": 0,
        "session": {"id_token": {"email": "a@example.com"}},
    }));
    seen[1].assert_json(json!({
        "grant_access_token_audience": [],
        "grant_scope": [],
        "remember": false,
        "remember_for": 0,
        "session": {"access_token": {"org": "o"}, "id_token": null},
    }));
}

#[tokio::test]
async fn reject_consent_request_sends_status_403() {
    let stub = Stub::new(vec![ok(REDIRECT_TO)]).await;
    stub.hydra
        .reject_consent_request("ch", "access_denied", "denied")
        .await
        .unwrap();
    let seen = stub.only();
    seen.assert(
        "PUT",
        "/adm/admin/oauth2/auth/requests/consent/reject",
        Some("consent_challenge=ch"),
    );
    seen.assert_json(json!({
        "error": "access_denied",
        "error_description": "denied",
        "status_code": 403,
    }));
}

#[tokio::test]
async fn get_logout_request_sends_the_challenge_and_decodes() {
    let stub = Stub::new(vec![ok(LOGOUT_REQUEST)]).await;
    let got = stub.hydra.get_logout_request("lo").await.unwrap();
    let seen = stub.only();
    seen.assert(
        "GET",
        "/adm/admin/oauth2/auth/requests/logout",
        Some("logout_challenge=lo"),
    );
    seen.assert_no_body();
    assert_eq!(
        got,
        LogoutRequest {
            client: Some(fixture_client()),
            rp_initiated: Some(true),
            sid: Some(SID.into()),
            subject: Some(SUBJECT.into()),
        }
    );
}

#[tokio::test]
async fn accept_logout_request_sends_no_body() {
    let stub = Stub::new(vec![ok(REDIRECT_TO)]).await;
    stub.hydra.accept_logout_request("lo").await.unwrap();
    let seen = stub.only();
    seen.assert(
        "PUT",
        "/adm/admin/oauth2/auth/requests/logout/accept",
        Some("logout_challenge=lo"),
    );
    seen.assert_no_body();
}

// --- device grant ------------------------------------------------------

fn basic(id: &str, secret: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

#[tokio::test]
async fn device_authorization_posts_the_form_with_basic_auth() {
    let stub = Stub::new(vec![ok(DEVICE_AUTHORIZATION)]).await;
    let got = stub
        .hydra
        .device_authorization("pam client", "s3cret", "openid offline")
        .await
        .unwrap();
    let seen = stub.only();
    seen.assert("POST", "/pub/oauth2/device/auth", None);
    assert_eq!(
        seen.authorization.as_deref(),
        Some(basic("pam client", "s3cret").as_str())
    );
    seen.assert_form("client_id=pam+client&scope=openid+offline");
    assert_eq!(got.device_code, "fixture-device-code");
    assert_eq!(got.user_code, "fixtureUC");
    assert_eq!(
        got.verification_uri,
        "http://host.containers.internal:3000/hydra/oauth2/device/verify"
    );
    assert_eq!(
        got.verification_uri_complete.as_deref(),
        Some("http://host.containers.internal:3000/hydra/oauth2/device/verify?user_code=fixtureUC")
    );
    assert_eq!((got.expires_in, got.interval), (599, 5));
}

#[tokio::test]
async fn device_authorization_defaults_and_required_fields() {
    let stub = Stub::new(vec![
        ok(r#"{"device_code":"d","user_code":"u","verification_uri":"v"}"#),
        ok("{}"),
        reply(401, r#"{"error":"invalid_client"}"#),
    ])
    .await;
    let got = stub
        .hydra
        .device_authorization("c", "s", "openid")
        .await
        .unwrap();
    assert_eq!((got.expires_in, got.interval), (600, 5));
    assert_eq!(got.verification_uri_complete, None);
    let err = stub
        .hydra
        .device_authorization("c", "s", "openid")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "device_authorization: missing device_code");
    let err = stub
        .hydra
        .device_authorization("c", "s", "openid")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        r#"hydra device_authorization returned 401 Unauthorized: {"error":"invalid_client"}"#
    );
}

#[tokio::test]
async fn poll_device_token_posts_the_grant_and_maps_outcomes() {
    let stub = Stub::new(vec![
        ok(TOKEN_RESPONSE),
        reply(400, r#"{"error":"authorization_pending"}"#),
        reply(401, "not json"),
    ])
    .await;
    let got = stub
        .hydra
        .poll_device_token("c", "s", "dc-1")
        .await
        .unwrap();
    let DeviceTokenOutcome::Token(tok) = got else {
        panic!("a token set");
    };
    assert_eq!(tok.access_token, "fixture-access-token");
    assert_eq!(tok.id_token.as_deref(), Some("fixture-id-token"));
    assert_eq!(tok.expires_in, 299);
    assert!(matches!(
        stub.hydra
            .poll_device_token("c", "s", "dc-1")
            .await
            .unwrap(),
        DeviceTokenOutcome::Pending
    ));
    let err = stub
        .hydra
        .poll_device_token("c", "s", "dc-1")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra poll_device_token returned 401 Unauthorized"
    );
    for s in stub.seen() {
        s.assert("POST", "/pub/oauth2/token", None);
        assert_eq!(s.authorization.as_deref(), Some(basic("c", "s").as_str()));
        s.assert_form(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=dc-1",
        );
    }
}

#[tokio::test]
async fn accept_user_code_request_sends_the_code() {
    let stub = Stub::new(vec![ok(REDIRECT_TO)]).await;
    stub.hydra
        .accept_user_code_request("dch", "ABCD-EFGH")
        .await
        .unwrap();
    let seen = stub.only();
    seen.assert(
        "PUT",
        "/adm/admin/oauth2/auth/requests/device/accept",
        Some("device_challenge=dch"),
    );
    seen.assert_json(json!({"user_code": "ABCD-EFGH"}));
}

#[tokio::test]
async fn verify_id_token_fetches_the_public_jwks() {
    let stub = Stub::new(vec![ok(&test_jwks_json().to_string())]).await;
    let tok = mint(&TestClaims::default(), jsonwebtoken::Algorithm::RS256);
    let claims = stub
        .hydra
        .verify_id_token(&tok, TEST_ISS, TEST_CLIENT, 120)
        .await
        .unwrap();
    assert_eq!(claims.sub, "ident-123");
    let seen = stub.only();
    seen.assert("GET", "/pub/.well-known/jwks.json", None);
    seen.assert_no_body();
}

// --- clients -------------------------------------------------------------

#[tokio::test]
async fn list_clients_sends_paging_and_name_filter() {
    let list = format!("[{CLIENT}]");
    let stub = Stub::new(vec![ok(&list), ok("[]")]).await;
    let got = stub
        .hydra
        .list_clients(50, Some("tok/1"), Some("Fixture App"))
        .await
        .unwrap();
    assert_eq!(got, [fixture_client()]);
    assert!(
        stub.hydra
            .list_clients(10, None, None)
            .await
            .unwrap()
            .is_empty()
    );
    let seen = stub.seen();
    seen[0].assert(
        "GET",
        "/adm/admin/clients",
        Some("page_size=50&page_token=tok%2F1&client_name=Fixture+App"),
    );
    seen[1].assert("GET", "/adm/admin/clients", Some("page_size=10"));
}

#[tokio::test]
async fn get_client_urlencodes_the_id() {
    let stub = Stub::new(vec![ok(CLIENT)]).await;
    assert_eq!(
        stub.hydra.get_client("a/b c").await.unwrap(),
        fixture_client()
    );
    let seen = stub.only();
    seen.assert("GET", "/adm/admin/clients/a%2Fb+c", None);
    seen.assert_no_body();
}

#[tokio::test]
async fn get_client_opt_maps_404_to_none() {
    let stub = Stub::new(vec![ok(CLIENT), not_found(), reply(500, "{}")]).await;
    assert_eq!(
        stub.hydra.get_client_opt("c").await.unwrap(),
        Some(fixture_client())
    );
    assert_eq!(stub.hydra.get_client_opt("c").await.unwrap(), None);
    let err = stub.hydra.get_client_opt("c").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra get_client failed: error in response: status code 500 Internal Server Error"
    );
    for s in stub.seen() {
        s.assert("GET", "/adm/admin/clients/c", None);
    }
}

#[tokio::test]
async fn create_client_sends_the_wire_shape() {
    let stub = Stub::new(vec![ok(CLIENT_CREATED)]).await;
    let mut input = fixture_client();
    input
        .extra
        .insert("skip_logout_consent".into(), Value::Null);
    input.extra.insert("not_in_the_spec".into(), json!("x"));
    let got = stub.hydra.create_client(input).await.unwrap();
    let seen = stub.only();
    seen.assert("POST", "/adm/admin/clients", None);
    seen.assert_json(fixture_client_wire());
    assert_eq!(got.client_secret.as_deref(), Some("fixture-client-secret"));
    assert_eq!(
        got.registration_access_token.as_deref(),
        Some("fixture-registration-access-token")
    );
    assert_eq!(
        got.extra["registration_client_uri"],
        "http://host.containers.internal:3000/hydra/oauth2/register/forseti-fixture-client"
    );
    assert!(!got.extra.contains_key("contacts"));
}

#[tokio::test]
async fn update_client_puts_the_round_tripped_record() {
    let stub = Stub::new(vec![ok(CLIENT), ok(CLIENT)]).await;
    let mut c = stub
        .hydra
        .get_client("forseti-fixture-client")
        .await
        .unwrap();
    c.client_name = Some("Renamed".into());
    stub.hydra
        .update_client("forseti-fixture-client", c)
        .await
        .unwrap();
    let seen = stub.seen();
    seen[1].assert("PUT", "/adm/admin/clients/forseti-fixture-client", None);
    let mut want = fixture_client_wire();
    want["client_name"] = json!("Renamed");
    seen[1].assert_json(want);
}

#[tokio::test]
async fn delete_client_sends_delete() {
    let stub = Stub::new(vec![no_content()]).await;
    stub.hydra.delete_client("a b").await.unwrap();
    let seen = stub.only();
    seen.assert("DELETE", "/adm/admin/clients/a+b", None);
    seen.assert_no_body();
}

#[tokio::test]
async fn add_client_audiences_patches_only_new_entries() {
    let stub = Stub::new(vec![ok(CLIENT)]).await;
    let on_record = strings(&["https://a.test"]);
    stub.hydra
        .add_client_audiences("c", &on_record, &on_record)
        .await
        .unwrap();
    assert!(stub.seen().is_empty());
    stub.hydra
        .add_client_audiences(
            "c",
            &on_record,
            &strings(&["https://a.test", "https://b.test"]),
        )
        .await
        .unwrap();
    let seen = stub.only();
    seen.assert("PATCH", "/adm/admin/clients/c", None);
    seen.assert_json(json!([{"op": "add", "path": "/audience/-", "value": "https://b.test"}]));
}

#[tokio::test]
async fn rotate_client_secret_patches_a_fresh_secret() {
    let stub = Stub::new(vec![ok(CLIENT_CREATED)]).await;
    let got = stub.hydra.rotate_client_secret("c").await.unwrap();
    assert_eq!(got.client_secret.as_deref(), Some("fixture-client-secret"));
    let seen = stub.only();
    seen.assert("PATCH", "/adm/admin/clients/c", None);
    assert_eq!(seen.content_type.as_deref(), Some("application/json"));
    let body: Value = serde_json::from_slice(&seen.body).unwrap();
    let secret = body[0]["value"].as_str().unwrap().to_string();
    assert_eq!(secret.len(), 40);
    assert!(secret.chars().all(|c| c.is_ascii_alphanumeric()));
    assert_eq!(
        body,
        json!([{"op": "replace", "path": "/client_secret", "value": secret}])
    );
}

// --- consent and login sessions ------------------------------------------

fn fixture_consent_session() -> ConsentSession {
    let raw = fixture(CONSENT_SESSIONS);
    ConsentSession {
        consent_request: Some(ConsentRequest {
            client: Some(fixture_client()),
            consent_request_id: Some(CONSENT_REQUEST_ID.into()),
            login_session_id: Some(SID.into()),
            oidc_context: Some(fixture_oidc_context()),
            request_url: Some(request_url(&raw[0]["consent_request"])),
            requested_access_token_audience: Some(strings(&["https://api.fixture.test"])),
            requested_scope: Some(strings(&["openid", "offline_access", "email"])),
            skip: Some(false),
            subject: Some(SUBJECT.into()),
        }),
        consent_request_id: Some(CONSENT_REQUEST_ID.into()),
        grant_access_token_audience: Some(strings(&["https://api.fixture.test"])),
        grant_scope: Some(strings(&["openid", "offline_access", "email"])),
        handled_at: Some("2026-11-20T19:44:40.00246Z".into()),
        remember: Some(true),
        remember_for: Some(0),
    }
}

#[tokio::test]
async fn list_consent_sessions_by_subject_follows_link_pages() {
    let first = Reply {
        link: Some(
            "<http://hydra.test/admin/oauth2/auth/sessions/consent?page_size=250&page_token=p%2F2&subject=s>; rel=\"next\"",
        ),
        ..ok(CONSENT_SESSIONS)
    };
    let stub = Stub::new(vec![first, ok(CONSENT_SESSIONS)]).await;
    let got = stub
        .hydra
        .list_consent_sessions_by_subject(SUBJECT)
        .await
        .unwrap();
    assert_eq!(got, [fixture_consent_session(), fixture_consent_session()]);
    let seen = stub.seen();
    assert_eq!(seen.len(), 2);
    seen[0].assert(
        "GET",
        "/adm/admin/oauth2/auth/sessions/consent",
        Some("subject=fixture-subject-1&page_size=250"),
    );
    seen[1].assert(
        "GET",
        "/adm/admin/oauth2/auth/sessions/consent",
        Some("subject=fixture-subject-1&page_size=250&page_token=p%2F2"),
    );
    seen[0].assert_no_body();
}

#[tokio::test]
async fn list_consent_sessions_by_subject_stops_on_an_empty_page() {
    let first = Reply {
        link: Some("<http://hydra.test/x?page_token=p2>; rel=\"next\""),
        ..ok("[]")
    };
    let stub = Stub::new(vec![first, reply(500, "boom")]).await;
    assert!(
        stub.hydra
            .list_consent_sessions_by_subject("s")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(stub.seen().len(), 1);
    let err = stub
        .hydra
        .list_consent_sessions_by_subject("s")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra list_consent_sessions returned 500 Internal Server Error: boom"
    );
}

#[tokio::test]
async fn list_consent_sessions_by_login_session_sends_the_sid() {
    let stub = Stub::new(vec![ok(CONSENT_SESSIONS)]).await;
    let got = stub
        .hydra
        .list_consent_sessions_by_login_session("s", "sid-1")
        .await
        .unwrap();
    assert_eq!(got, [fixture_consent_session()]);
    stub.only().assert(
        "GET",
        "/adm/admin/oauth2/auth/sessions/consent",
        Some("page_size=250&subject=s&login_session_id=sid-1"),
    );
}

#[tokio::test]
async fn revoke_consent_sessions_send_their_queries() {
    let stub = Stub::new(vec![no_content(), no_content(), no_content()]).await;
    stub.hydra
        .revoke_consent_sessions_for_subject("s a")
        .await
        .unwrap();
    stub.hydra
        .revoke_consent_sessions_for_client("s", "c/1")
        .await
        .unwrap();
    stub.hydra
        .revoke_consent_sessions_by_request_id("crid")
        .await
        .unwrap();
    let seen = stub.seen();
    let path = "/adm/admin/oauth2/auth/sessions/consent";
    seen[0].assert("DELETE", path, Some("subject=s+a&all=true"));
    seen[1].assert("DELETE", path, Some("subject=s&client=c%2F1"));
    seen[2].assert("DELETE", path, Some("consent_request_id=crid"));
    for s in &seen {
        s.assert_no_body();
    }
}

#[tokio::test]
async fn revoke_consent_by_request_id_maps_404_to_revoked() {
    let stub = Stub::new(vec![not_found(), reply(500, "{}"), not_found()]).await;
    stub.hydra
        .revoke_consent_sessions_by_request_id("crid")
        .await
        .unwrap();
    let err = stub
        .hydra
        .revoke_consent_sessions_by_request_id("crid")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra revoke_consent_sessions by request id failed: error in response: status code 500 Internal Server Error"
    );
    let err = stub
        .hydra
        .revoke_consent_sessions_for_subject("s")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra revoke_consent_sessions failed: error in response: status code 404 Not Found"
    );
}

#[tokio::test]
async fn revoke_login_sessions_send_their_queries() {
    let stub = Stub::new(vec![no_content(), no_content()]).await;
    stub.hydra
        .revoke_login_sessions_for_subject("s")
        .await
        .unwrap();
    stub.hydra
        .revoke_login_session_by_sid("sid-1")
        .await
        .unwrap();
    let seen = stub.seen();
    let path = "/adm/admin/oauth2/auth/sessions/login";
    seen[0].assert("DELETE", path, Some("subject=s"));
    seen[1].assert("DELETE", path, Some("sid=sid-1"));
}

#[tokio::test]
async fn revoke_login_session_by_sid_maps_404_to_revoked() {
    let stub = Stub::new(vec![not_found(), reply(500, "{}"), not_found()]).await;
    stub.hydra
        .revoke_login_session_by_sid("sid-1")
        .await
        .unwrap();
    let err = stub
        .hydra
        .revoke_login_session_by_sid("sid-1")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra revoke_login_session_by_sid failed: error in response: status code 500 Internal Server Error"
    );
    let err = stub
        .hydra
        .revoke_login_sessions_for_subject("s")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "hydra revoke_login_sessions failed: error in response: status code 404 Not Found"
    );
}

// --- metadata ------------------------------------------------------------

#[tokio::test]
async fn health_version_and_signing_keys() {
    let down = Reply {
        content_type: Some("text/plain"),
        ..reply(503, "down")
    };
    let stub = Stub::new(vec![ok(r#"{"status":"ok"}"#), down, ok(VERSION), ok(JWKS)]).await;
    stub.hydra.health_alive().await.unwrap();
    let err = stub.hydra.health_ready().await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "health probe /health/ready returned 503 Service Unavailable: down"
    );
    assert_eq!(stub.hydra.version().await.unwrap(), "v26.2.0");
    let keys = stub.hydra.signing_keys().await.unwrap();
    let keys: Vec<(&str, &str, &str, &str)> = keys
        .iter()
        .map(|k| {
            (
                k.kid.as_str(),
                k.alg.as_str(),
                k.kty.as_str(),
                k.use_.as_str(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        [
            (
                "ceba0165-5a39-4964-b3ff-ebba5503a83b",
                "RS256",
                "RSA",
                "sig"
            ),
            (
                "e65ffa7c-4819-44cd-a95c-3e1b6b1b9bc1",
                "RS256",
                "RSA",
                "sig"
            ),
        ]
    );
    let seen = stub.seen();
    seen[0].assert("GET", "/adm/health/alive", None);
    seen[1].assert("GET", "/adm/health/ready", None);
    seen[2].assert("GET", "/adm/version", None);
    seen[3].assert("GET", "/pub/.well-known/jwks.json", None);
}

#[tokio::test]
async fn discovery_fetches_and_decodes() {
    let stub = Stub::new(vec![ok(DISCOVERY)]).await;
    let (doc, raw) = stub.hydra.fetch_discovery().await.unwrap();
    stub.only()
        .assert("GET", "/pub/.well-known/openid-configuration", None);
    assert_eq!(raw, fixture(DISCOVERY));
    let base = "http://host.containers.internal:3000/hydra";
    assert_eq!(doc.issuer, base);
    assert_eq!(doc.authorization_endpoint, format!("{base}/oauth2/auth"));
    assert_eq!(doc.token_endpoint, format!("{base}/oauth2/token"));
    assert_eq!(doc.userinfo_endpoint, format!("{base}/userinfo"));
    assert_eq!(doc.jwks_uri, format!("{base}/.well-known/jwks.json"));
    assert_eq!(
        doc.end_session_endpoint,
        format!("{base}/oauth2/sessions/logout")
    );
    assert_eq!(doc.revocation_endpoint, format!("{base}/oauth2/revoke"));
    assert_eq!(doc.registration_endpoint, "");
    assert!(doc.scopes_supported.contains(&"openid".to_string()));
    assert_eq!(doc.code_challenge_methods_supported, ["plain", "S256"]);
    assert_eq!(doc.id_token_signing_alg_values_supported, ["RS256"]);
    assert_eq!(doc.subject_types_supported, ["public"]);
    assert!(
        doc.grant_types_supported
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string())
    );
    assert_eq!(doc.response_types_supported.len(), 6);
    assert_eq!(doc.token_endpoint_auth_methods_supported.len(), 4);
    assert!(doc.backchannel_logout_supported && doc.frontchannel_logout_supported);
}
