//! Unit-test support: identities with a password, TOTP credentials and lookup codes written
//! straight to the store, a browser that starts and submits flows, and in-process OIDC and
//! GitHub provider stubs.

use std::sync::Arc;

use tokio::sync::{OnceCell, Semaphore};

use super::NativeBackend;
use super::flows::{Dispatch, Form, InitOutcome, InitParams, SubmitOutcome, Submitted};
use super::lookup;
use super::password::{self, PasswordConfig};
use super::session::Device;
use super::store;
use super::totp::{self, TotpConfig};
use crate::backend::identity::FlowKind;
use crate::db::DbPool;

/// The password every [`identity_with_password`] identity has.
pub(super) const PASSWORD: &str = "correct horse battery";

/// One Argon2 hash of [`PASSWORD`] per test process.
async fn password_phc() -> &'static str {
    static PHC: OnceCell<String> = OnceCell::const_new();
    PHC.get_or_init(|| async {
        password::hash(&Arc::new(Semaphore::new(1)), PASSWORD.to_string())
            .await
            .expect("hash the test password")
    })
    .await
}

/// An active identity with [`PASSWORD`]; returns its id.
pub(super) async fn identity_with_password(db: &DbPool, email: &str, verified: bool) -> String {
    let identity = store::create(db, email, Some("Ann"), Some("Lee"), verified)
        .await
        .unwrap()
        .expect("address is free");
    plant_password(db, &identity.id).await;
    identity.id
}

pub(super) async fn plant_password(db: &DbPool, identity_id: &str) {
    let config = PasswordConfig {
        hashed_password: password_phc().await.to_string(),
    };
    let config = serde_json::to_string(&config).unwrap();
    assert!(
        store::insert_credential(db, identity_id, "password", &config)
            .await
            .unwrap()
    );
}

/// A TOTP credential with a fresh secret; returns the secret.
pub(super) async fn plant_totp(backend: &NativeBackend, identity_id: &str) -> Vec<u8> {
    let secret = totp::new_secret().to_vec();
    let config = TotpConfig::new(&backend.keys.seal, identity_id, &secret);
    let config = serde_json::to_string(&config).unwrap();
    assert!(
        store::insert_credential(&backend.db, identity_id, "totp", &config)
            .await
            .unwrap()
    );
    secret
}

/// Fresh lookup codes, stored as MACs; returns them in display form.
pub(super) async fn plant_lookup_codes(backend: &NativeBackend, identity_id: &str) -> Vec<String> {
    let codes = lookup::generate();
    let config = lookup::config_for(&backend.keys.lookup_mac, identity_id, &codes);
    let config = serde_json::to_string(&config).unwrap();
    assert!(
        store::insert_credential(&backend.db, identity_id, "lookup_secret", &config)
            .await
            .unwrap()
    );
    codes
}

/// The TOTP code for `secret` at `unix` seconds, computed by `totp-lite`.
pub(super) fn totp_code(secret: &[u8], unix: u64) -> String {
    totp_lite::totp_custom::<totp_lite::Sha1>(totp::STEP_SECS, 6, secret, unix)
}

pub(super) const DEVICE: Device<'static> = Device {
    ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))),
    user_agent: Some("Mozilla/5.0 test"),
};

/// A browser: its CSRF token and, once signed in, its session token.
#[derive(Clone)]
pub(super) struct Browser {
    pub(super) csrf: String,
    pub(super) session: Option<String>,
}

impl Browser {
    pub(super) fn new() -> Self {
        Self {
            csrf: uuid::Uuid::new_v4().to_string(),
            session: None,
        }
    }

    pub(super) fn cookie(&self) -> String {
        match &self.session {
            Some(s) => format!("forseti_csrf={}; forseti_session={s}", self.csrf),
            None => format!("forseti_csrf={}", self.csrf),
        }
    }
}

/// A new flow of `kind` for `browser`.
pub(super) async fn start(
    backend: &NativeBackend,
    browser: &Browser,
    kind: FlowKind,
    params: InitParams<'_>,
) -> String {
    match backend
        .init_flow(kind, params, &browser.csrf, &browser.cookie())
        .await
        .unwrap()
    {
        InitOutcome::Created(id) => id,
        InitOutcome::Redirect(to) => panic!("no flow, redirected to {to}"),
    }
}

/// Submit `fields` to the flow as `browser`, with a valid CSRF field.
pub(super) async fn submit(
    backend: &NativeBackend,
    browser: &Browser,
    kind: FlowKind,
    id: &str,
    fields: &[(&str, &str)],
) -> Submitted {
    let form = Form(
        fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    );
    match backend
        .submit_flow(kind, id, &form, &browser.cookie(), true, DEVICE)
        .await
        .unwrap()
    {
        Dispatch::Done(done) => done,
        other => panic!("submit not handled: {other:?}"),
    }
}

/// The session token a submit sets.
pub(super) fn session_cookie(done: &Submitted) -> Option<String> {
    let SubmitOutcome::Redirect { set_cookies, .. } = &done.outcome else {
        return None;
    };
    set_cookies.iter().find_map(|c| {
        c.strip_prefix("forseti_session=")
            .map(|rest| rest.split(';').next().unwrap().to_string())
    })
}

/// Flow-level and node message ids saved on the flow.
pub(super) async fn messages(backend: &NativeBackend, id: &str) -> (Vec<u64>, Vec<(String, u64)>) {
    let rec = backend.load_flow(id).await.unwrap().unwrap();
    (
        rec.ctx.messages.iter().map(|m| m.id).collect(),
        rec.ctx
            .node_messages
            .iter()
            .map(|n| (n.node.clone(), n.message.id))
            .collect(),
    )
}

/// The audit actions of a submit, in `Debug` form.
pub(super) fn audit_lines(done: &Submitted) -> Vec<String> {
    done.audit.iter().map(|e| format!("{e:?}")).collect()
}

/// Run `f` on the test pool's one sqlite connection.
pub(super) async fn sql<T: Send + 'static>(
    db: &DbPool,
    f: impl FnOnce(&mut diesel::sqlite::SqliteConnection) -> diesel::QueryResult<T> + Send + 'static,
) -> T {
    let DbPool::Sqlite(pool) = db else {
        unreachable!("test_pool is sqlite")
    };
    pool.get()
        .await
        .unwrap()
        .interact(f)
        .await
        .unwrap()
        .unwrap()
}

pub(super) use stubs::{GithubAccount, GithubAddress, GithubStub, OidcStub, StubKey, upstream};

mod stubs {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use base64::{
        Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use url::Url;

    use super::super::upstream::{GithubUrls, Upstream};
    use crate::config::{OidcProviderConfig, OidcProviderKind};
    use crate::oidc_rp::id_token::tests as keys;

    const STUB_CLIENT_ID: &str = "forseti";
    const STUB_CLIENT_SECRET: &str = "stub-secret";

    /// An [`Upstream`] for `providers` with `[self].url` of [`crate::config::AppConfig::test_fixture`],
    /// private targets allowed, and GitHub pointed at `github`.
    pub(in super::super) fn upstream(
        providers: &[OidcProviderConfig],
        github: Option<&GithubStub>,
    ) -> Upstream {
        let upstream = Upstream::from_config(providers, "http://localhost:3000", true)
            .expect("stub provider config is valid");
        match github {
            Some(stub) => upstream.with_github_urls(stub.urls()),
            None => upstream,
        }
    }

    fn provider_config(
        id: &str,
        kind: OidcProviderKind,
        issuer: Option<String>,
    ) -> OidcProviderConfig {
        OidcProviderConfig {
            id: id.into(),
            kind,
            issuer,
            client_id: STUB_CLIENT_ID.into(),
            client_secret: Some(STUB_CLIENT_SECRET.into()),
            client_secret_env: None,
            scopes: None,
        }
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn query(url: &Url) -> HashMap<String, String> {
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn form(body: &[u8]) -> HashMap<String, String> {
        url::form_urlencoded::parse(body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn s256(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn json_response(status: StatusCode, body: Value) -> Response {
        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response()
    }

    fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
        headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// RFC 6749 2.3.1: the id and secret are form-urlencoded inside the Basic credentials.
    fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
        let encoded = header_str(headers, header::AUTHORIZATION)?.strip_prefix("Basic ")?;
        let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
        let (id, secret) = decoded.split_once(':')?;
        let dec = |s: &str| {
            percent_encoding::percent_decode_str(&s.replace('+', " "))
                .decode_utf8()
                .ok()
                .map(|c| c.into_owned())
        };
        Some((dec(id)?, dec(secret)?))
    }

    /// A signing key of the OIDC stub; both come from the `id_token` test keys.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in super::super) enum StubKey {
        Rsa,
        Ec,
    }

    impl StubKey {
        fn jwk(self) -> Value {
            match self {
                Self::Rsa => {
                    json!({"kty": "RSA", "kid": "stub-rsa", "use": "sig", "alg": "RS256", "n": keys::RSA_N, "e": keys::RSA_E})
                }
                Self::Ec => {
                    json!({"kty": "EC", "kid": "stub-ec", "crv": "P-256", "x": keys::EC_X, "y": keys::EC_Y})
                }
            }
        }

        fn sign(self, claims: &Value) -> String {
            let (alg, kid, key) = match self {
                Self::Rsa => (
                    "RS256",
                    "stub-rsa",
                    EncodingKey::from_rsa_pem(keys::RSA_PEM.as_bytes()),
                ),
                Self::Ec => (
                    "ES256",
                    "stub-ec",
                    EncodingKey::from_ec_pem(keys::EC_PEM.as_bytes()),
                ),
            };
            let mut header = Header::new(if alg == "RS256" {
                Algorithm::RS256
            } else {
                Algorithm::ES256
            });
            header.kid = Some(kid.into());
            jsonwebtoken::encode(&header, claims, &key.unwrap()).unwrap()
        }
    }

    struct OidcGrant {
        redirect_uri: String,
        challenge: String,
        nonce: Option<String>,
        claims: Value,
    }

    struct OidcState {
        issuer: String,
        auth_methods: Option<Vec<String>>,
        iss_parameter: bool,
        signing: StubKey,
        published: Vec<StubKey>,
        jwks_fails: bool,
        discovery_fails: bool,
        discovery_fetches: usize,
        jwks_fetches: usize,
        grants: HashMap<String, OidcGrant>,
        client_auth: Vec<&'static str>,
    }

    /// An OIDC provider on a loopback port: discovery, token endpoint (confidential client,
    /// PKCE S256) and JWKS. Codes come from [`OidcStub::issue`], which plays the browser hop.
    #[derive(Clone)]
    pub(in super::super) struct OidcStub {
        pub(in super::super) issuer: String,
        state: Arc<Mutex<OidcState>>,
    }

    impl OidcStub {
        /// Signs with [`StubKey::Rsa`], advertises no auth methods (so Basic) and no `iss`.
        pub(in super::super) async fn start() -> Self {
            let state = Arc::new(Mutex::new(OidcState {
                issuer: String::new(),
                auth_methods: None,
                iss_parameter: false,
                signing: StubKey::Rsa,
                published: vec![StubKey::Rsa],
                jwks_fails: false,
                discovery_fails: false,
                discovery_fetches: 0,
                jwks_fetches: 0,
                grants: HashMap::new(),
                client_auth: Vec::new(),
            }));
            let app = Router::new()
                .route("/.well-known/openid-configuration", get(oidc_discovery))
                .route("/token", post(oidc_token))
                .route("/jwks", get(oidc_jwks))
                .with_state(state.clone());
            let issuer = serve(app).await;
            state.lock().unwrap().issuer.clone_from(&issuer);
            Self { issuer, state }
        }

        pub(in super::super) fn provider_config(&self, id: &str) -> OidcProviderConfig {
            provider_config(id, OidcProviderKind::Oidc, Some(self.issuer.clone()))
        }

        /// A code for the authorization request at `authorize_url`. The ID token carries
        /// `iss`, `aud`, `exp`, `iat`, `nonce` and `sub = "stub-subject"`, then `claims` on top;
        /// a `null` in `claims` removes the claim.
        pub(in super::super) fn issue(&self, authorize_url: &Url, claims: Value) -> String {
            let q = query(authorize_url);
            assert_eq!(q.get("client_id").map(String::as_str), Some(STUB_CLIENT_ID));
            let code = uuid::Uuid::new_v4().to_string();
            self.state.lock().unwrap().grants.insert(
                code.clone(),
                OidcGrant {
                    redirect_uri: q["redirect_uri"].clone(),
                    challenge: q["code_challenge"].clone(),
                    nonce: q.get("nonce").cloned(),
                    claims,
                },
            );
            code
        }

        /// Sign with `key` and publish only it.
        pub(in super::super) fn rotate(&self, key: StubKey) {
            let mut s = self.state.lock().unwrap();
            s.signing = key;
            s.published = vec![key];
        }

        pub(in super::super) fn set_jwks_failing(&self, failing: bool) {
            self.state.lock().unwrap().jwks_fails = failing;
        }

        pub(in super::super) fn set_discovery_failing(&self, failing: bool) {
            self.state.lock().unwrap().discovery_fails = failing;
        }

        /// `token_endpoint_auth_methods_supported`; `None` leaves the member out.
        pub(in super::super) fn set_auth_methods(&self, methods: Option<&[&str]>) {
            self.state.lock().unwrap().auth_methods =
                methods.map(|m| m.iter().map(|s| (*s).to_string()).collect());
        }

        pub(in super::super) fn set_iss_parameter(&self, supported: bool) {
            self.state.lock().unwrap().iss_parameter = supported;
        }

        pub(in super::super) fn jwks_fetches(&self) -> usize {
            self.state.lock().unwrap().jwks_fetches
        }

        pub(in super::super) fn discovery_fetches(&self) -> usize {
            self.state.lock().unwrap().discovery_fetches
        }

        /// `"basic"` or `"post"` per token request that authenticated.
        pub(in super::super) fn client_auth(&self) -> Vec<&'static str> {
            self.state.lock().unwrap().client_auth.clone()
        }
    }

    async fn oidc_discovery(State(state): State<Arc<Mutex<OidcState>>>) -> Response {
        let mut s = state.lock().unwrap();
        s.discovery_fetches += 1;
        if s.discovery_fails {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let issuer = &s.issuer;
        let mut doc = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "code_challenge_methods_supported": ["S256"],
        });
        if let Some(methods) = &s.auth_methods {
            doc["token_endpoint_auth_methods_supported"] = json!(methods);
        }
        if s.iss_parameter {
            doc["authorization_response_iss_parameter_supported"] = json!(true);
        }
        json_response(StatusCode::OK, doc)
    }

    async fn oidc_jwks(State(state): State<Arc<Mutex<OidcState>>>) -> Response {
        let mut s = state.lock().unwrap();
        s.jwks_fetches += 1;
        if s.jwks_fails {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let keys: Vec<Value> = s.published.iter().map(|k| k.jwk()).collect();
        json_response(StatusCode::OK, json!({ "keys": keys }))
    }

    async fn oidc_token(
        State(state): State<Arc<Mutex<OidcState>>>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Response {
        let invalid =
            |error: &str| json_response(StatusCode::BAD_REQUEST, json!({ "error": error }));
        let f = form(&body);
        let field = |name: &str| f.get(name).map(String::as_str);
        let (client, method) = match (basic_credentials(&headers), field("client_secret")) {
            (Some(creds), None) => (creds, "basic"),
            (None, Some(secret)) => (
                (
                    field("client_id").unwrap_or_default().to_string(),
                    secret.to_string(),
                ),
                "post",
            ),
            _ => return invalid("invalid_client"),
        };
        if client.0 != STUB_CLIENT_ID || client.1 != STUB_CLIENT_SECRET {
            return invalid("invalid_client");
        }
        let mut s = state.lock().unwrap();
        s.client_auth.push(method);
        if field("grant_type") != Some("authorization_code") {
            return invalid("unsupported_grant_type");
        }
        let Some(grant) = field("code").and_then(|c| s.grants.remove(c)) else {
            return invalid("invalid_grant");
        };
        if field("redirect_uri") != Some(grant.redirect_uri.as_str())
            || field("code_verifier").map(s256).as_deref() != Some(grant.challenge.as_str())
        {
            return invalid("invalid_grant");
        }
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": s.issuer,
            "aud": STUB_CLIENT_ID,
            "sub": "stub-subject",
            "exp": now + 300,
            "iat": now,
        });
        if let Some(nonce) = grant.nonce {
            claims["nonce"] = json!(nonce);
        }
        for (k, v) in grant.claims.as_object().into_iter().flatten() {
            if v.is_null() {
                claims.as_object_mut().unwrap().remove(k);
            } else {
                claims[k] = v.clone();
            }
        }
        json_response(
            StatusCode::OK,
            json!({
                "access_token": "stub-access-token",
                "token_type": "Bearer",
                "id_token": s.signing.sign(&claims),
            }),
        )
    }

    /// One address on a [`GithubAccount`].
    #[derive(Debug, Clone)]
    pub(in super::super) struct GithubAddress {
        pub(in super::super) email: String,
        pub(in super::super) primary: bool,
        pub(in super::super) verified: bool,
    }

    /// The account a GitHub stub code signs in.
    #[derive(Debug, Clone)]
    pub(in super::super) struct GithubAccount {
        pub(in super::super) id: u64,
        pub(in super::super) name: Option<String>,
        pub(in super::super) emails: Vec<GithubAddress>,
    }

    struct GithubGrant {
        redirect_uri: String,
        challenge: String,
        account: GithubAccount,
    }

    #[derive(Default)]
    struct GithubState {
        grants: HashMap<String, GithubGrant>,
        tokens: HashMap<String, GithubAccount>,
        refused_without_agent: usize,
    }

    /// GitHub's OAuth token endpoint and the `/user` and `/user/emails` API on a loopback port.
    /// Token errors answer HTTP 200 with an `error` body, as GitHub does; a request without
    /// `User-Agent` gets 403.
    #[derive(Clone)]
    pub(in super::super) struct GithubStub {
        base: String,
        state: Arc<Mutex<GithubState>>,
    }

    impl GithubStub {
        pub(in super::super) async fn start() -> Self {
            let state = Arc::new(Mutex::new(GithubState::default()));
            let app = Router::new()
                .route("/login/oauth/access_token", post(github_token))
                .route("/user", get(github_user))
                .route("/user/emails", get(github_emails))
                .with_state(state.clone());
            Self {
                base: serve(app).await,
                state,
            }
        }

        pub(in super::super) fn urls(&self) -> GithubUrls {
            let url = |path: &str| Url::parse(&format!("{}{path}", self.base)).unwrap();
            GithubUrls {
                authorize: url("/login/oauth/authorize"),
                token: url("/login/oauth/access_token"),
                user: url("/user"),
                emails: url("/user/emails"),
            }
        }

        pub(in super::super) fn provider_config(&self, id: &str) -> OidcProviderConfig {
            provider_config(id, OidcProviderKind::Github, None)
        }

        /// A code for the authorization request at `authorize_url` that signs in `account`.
        pub(in super::super) fn issue(
            &self,
            authorize_url: &Url,
            account: GithubAccount,
        ) -> String {
            let q = query(authorize_url);
            assert_eq!(q.get("client_id").map(String::as_str), Some(STUB_CLIENT_ID));
            let code = uuid::Uuid::new_v4().simple().to_string();
            self.state.lock().unwrap().grants.insert(
                code.clone(),
                GithubGrant {
                    redirect_uri: q["redirect_uri"].clone(),
                    challenge: q["code_challenge"].clone(),
                    account,
                },
            );
            code
        }

        /// Requests refused for a missing `User-Agent`.
        pub(in super::super) fn refused_without_agent(&self) -> usize {
            self.state.lock().unwrap().refused_without_agent
        }
    }

    fn github_agent_missing(state: &Mutex<GithubState>, headers: &HeaderMap) -> Option<Response> {
        if header_str(headers, header::USER_AGENT).is_some_and(|ua| !ua.is_empty()) {
            return None;
        }
        state.lock().unwrap().refused_without_agent += 1;
        Some(
            (
                StatusCode::FORBIDDEN,
                "Request forbidden by administrative rules. Please make sure your request has a User-Agent header",
            )
                .into_response(),
        )
    }

    async fn github_token(
        State(state): State<Arc<Mutex<GithubState>>>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Response {
        if let Some(refused) = github_agent_missing(&state, &headers) {
            return refused;
        }
        let error = |e: &str| {
            json_response(
                StatusCode::OK,
                json!({ "error": e, "error_description": "stub" }),
            )
        };
        let f = form(&body);
        let field = |name: &str| f.get(name).map(String::as_str);
        if field("client_id") != Some(STUB_CLIENT_ID)
            || field("client_secret") != Some(STUB_CLIENT_SECRET)
        {
            return error("incorrect_client_credentials");
        }
        let mut s = state.lock().unwrap();
        let Some(grant) = field("code").and_then(|c| s.grants.remove(c)) else {
            return error("bad_verification_code");
        };
        if field("redirect_uri") != Some(grant.redirect_uri.as_str()) {
            return error("redirect_uri_mismatch");
        }
        if field("code_verifier").map(s256).as_deref() != Some(grant.challenge.as_str()) {
            return error("bad_verification_code");
        }
        let token = format!("gho_{}", uuid::Uuid::new_v4().simple());
        s.tokens.insert(token.clone(), grant.account);
        json_response(
            StatusCode::OK,
            json!({ "access_token": token, "token_type": "bearer", "scope": "read:user,user:email" }),
        )
    }

    fn github_account(
        state: &Mutex<GithubState>,
        headers: &HeaderMap,
    ) -> Result<GithubAccount, Response> {
        if let Some(refused) = github_agent_missing(state, headers) {
            return Err(refused);
        }
        if header_str(headers, header::ACCEPT) != Some("application/vnd.github+json")
            || header_str(
                headers,
                header::HeaderName::from_static("x-github-api-version"),
            ) != Some("2022-11-28")
        {
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
        header_str(headers, header::AUTHORIZATION)
            .and_then(|a| a.strip_prefix("Bearer "))
            .and_then(|t| state.lock().unwrap().tokens.get(t).cloned())
            .ok_or_else(|| {
                json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({ "message": "Bad credentials" }),
                )
            })
    }

    async fn github_user(
        State(state): State<Arc<Mutex<GithubState>>>,
        headers: HeaderMap,
    ) -> Response {
        match github_account(&state, &headers) {
            Ok(a) => json_response(
                StatusCode::OK,
                json!({ "id": a.id, "login": format!("user{}", a.id), "name": a.name }),
            ),
            Err(r) => r,
        }
    }

    async fn github_emails(
        State(state): State<Arc<Mutex<GithubState>>>,
        headers: HeaderMap,
    ) -> Response {
        match github_account(&state, &headers) {
            Ok(a) => {
                let list: Vec<Value> = a
                    .emails
                    .iter()
                    .map(|e| json!({ "email": e.email, "primary": e.primary, "verified": e.verified, "visibility": null }))
                    .collect();
                json_response(StatusCode::OK, json!(list))
            }
            Err(r) => r,
        }
    }
}
