//! Public routes of the native authorization server. Mounted outside the CSRF layer.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::Utc;
use serde::Deserialize;
use tower_http::set_header::SetResponseHeaderLayer;

use super::authorize::{self, AUTHORIZE_PATH, AuthorizeError, AuthorizeQuery, LoginStep};
use super::challenge::{self, RESUME_ROUTE, Resumed};
use super::device::{self, DEVICE_AUTHORIZATION_PATH};
use super::logout::{self, LOGOUT_PATH};
use super::response::{self, Navigation};
use super::revocation::{self, INTROSPECT_PATH, REVOKE_PATH};
use super::token_endpoint::{self, TOKEN_PATH};
use super::userinfo::{self, USERINFO_PATH};
use super::{clients, sessions};
use crate::audit::AuditCtx;
use crate::config::{AppConfig, CimdConfig};
use crate::locale::LanguageIdentifier;
use crate::oauth::cimd;
use crate::page_chrome::ReqLocale;
use crate::rate_limit::{self, KeyedQuota};
use crate::state::AppState;

/// Per-IP limits shared by the authorization and resume endpoints, and separately of logout.
const AUTHORIZE_RATE_PER_MINUTE: u32 = 120;
const AUTHORIZE_RATE_PER_HOUR: u32 = 1200;
/// Per-IP limits of the token endpoint, and separately of device authorization, revocation,
/// introspection, userinfo and the JWKS.
const TOKEN_RATE_PER_MINUTE: u32 = 300;
const TOKEN_RATE_PER_HOUR: u32 = 3000;

/// Keys each CIMD window tracks at most; see [`KeyedQuota::bounded`] for a full map.
const CIMD_LIMITER_MAX_KEYS: usize = 10_000;

/// Per-IP limit on authorization requests that name a CIMD client, from
/// `[oauth.cimd].ip_rate_per_*`. A zero window is off.
struct CimdIpLimit {
    minute: KeyedQuota,
    hour: KeyedQuota,
    enabled: bool,
}

impl CimdIpLimit {
    fn new(cfg: &CimdConfig) -> Self {
        let per_minute = cfg
            .ip_rate_per_minute
            .unwrap_or(cimd::DEFAULT_CIMD_IP_RATE_PER_MINUTE);
        let per_hour = cfg
            .ip_rate_per_hour
            .unwrap_or(cimd::DEFAULT_CIMD_IP_RATE_PER_HOUR);
        let quota = |secs, limit: u32| {
            KeyedQuota::bounded(
                std::time::Duration::from_secs(secs),
                limit as usize,
                CIMD_LIMITER_MAX_KEYS,
            )
        };
        Self {
            minute: quota(60, per_minute),
            hour: quota(3600, per_hour),
            enabled: per_minute > 0 || per_hour > 0,
        }
    }

    /// `Err` is the 429. Without a client address the request is refused, as the governor
    /// layers refuse a request whose key cannot be extracted.
    fn admit(&self, ip: Option<IpAddr>) -> Result<(), Response> {
        if !self.enabled {
            return Ok(());
        }
        let Some(ip) = ip else {
            return Err(rate_limit::too_many_requests(None));
        };
        let key = crate::client_ip::limiter_key(ip).to_string();
        self.minute
            .try_admit(&key)
            .and_then(|()| self.hour.try_admit(&key))
            .map_err(|wait| {
                tracing::trace!("cimd: per-IP authorization limit triggered");
                rate_limit::too_many_requests(Some(rate_limit::retry_after_secs(wait)))
            })
    }
}

fn no_store() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
}

fn no_cache() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(header::PRAGMA, HeaderValue::from_static("no-cache"))
}

pub(crate) fn router(cfg: &AppConfig) -> Router<AppState> {
    // RFC 6749 section 5.1.
    let token = Router::new()
        .route(TOKEN_PATH, post(token_endpoint::token))
        .route_layer(no_store())
        .route_layer(no_cache());
    let device_authorization = Router::new()
        .route(DEVICE_AUTHORIZATION_PATH, post(device::authorize))
        .route_layer(no_store())
        .route_layer(no_cache());
    let revoke = Router::new()
        .route(REVOKE_PATH, post(revocation::revoke))
        .route_layer(no_store());
    let userinfo = Router::new()
        .route(USERINFO_PATH, get(userinfo::get).post(userinfo::post))
        .route_layer(no_store());
    let key_set = Router::new().route("/.well-known/jwks.json", get(jwks));
    let rate_limited = |r: Router<AppState>| {
        rate_limit::route_dual_window(
            r,
            &cfg.proxy,
            TOKEN_RATE_PER_MINUTE,
            TOKEN_RATE_PER_HOUR,
            token_endpoint::rate_limited,
        )
    };
    let flow = Router::new()
        .route("/oauth2/auth", get(authorize_get).post(authorize_post))
        .route(AUTHORIZE_PATH, get(authorize_get).post(authorize_post))
        .route(RESUME_ROUTE, get(resume))
        .route_layer(no_store())
        .layer(Extension(Arc::new(CimdIpLimit::new(&cfg.oauth.cimd))));
    let end_session = Router::new()
        .route(LOGOUT_PATH, get(logout::get).post(logout::post))
        .route_layer(no_store());
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .merge(rate_limit::route_dual_window(
            flow,
            &cfg.proxy,
            AUTHORIZE_RATE_PER_MINUTE,
            AUTHORIZE_RATE_PER_HOUR,
            rate_limit::plain_text_error("authorization"),
        ))
        .merge(rate_limit::route_dual_window(
            end_session,
            &cfg.proxy,
            AUTHORIZE_RATE_PER_MINUTE,
            AUTHORIZE_RATE_PER_HOUR,
            rate_limit::plain_text_error("logout"),
        ))
        .merge(rate_limited(token))
        .merge(rate_limited(device_authorization))
        .merge(rate_limited(revoke))
        .merge(rate_limited(userinfo))
        .merge(rate_limited(key_set))
}

/// Routes of the internal listener: introspection, at the token endpoint's per-IP limits.
pub(crate) fn internal_router(cfg: &AppConfig) -> Router<AppState> {
    let introspect = Router::new()
        .route(INTROSPECT_PATH, post(revocation::introspect))
        .route_layer(no_store());
    rate_limit::route_dual_window(
        introspect,
        &cfg.internal_proxy(),
        TOKEN_RATE_PER_MINUTE,
        TOKEN_RATE_PER_HOUR,
        token_endpoint::rate_limited,
    )
}

fn error_page() -> Response {
    Redirect::to("/error").into_response()
}

async fn authorize_get(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Extension(cimd_limit): Extension<Arc<CimdIpLimit>>,
    actx: AuditCtx,
    ReqLocale(locale): ReqLocale,
) -> Response {
    let raw = raw.as_deref().unwrap_or_default();
    let query = AuthorizeQuery::parse(raw);
    let peer = peer.map(|Extension(ConnectInfo(addr))| addr.ip());
    let ip = crate::client_ip::client_ip(&headers, &state.cfg.proxy, peer);
    if let Err(resp) = resolve_cimd(&state, &actx, &query, &cimd_limit, ip).await {
        return resp;
    }
    authorize_request(&state, raw, &query, &headers, &locale).await
}

/// Registers or refreshes a URL-shaped `client_id` from its metadata document; `Err` is the
/// response to send instead. A request with a repeated parameter is left to validation.
async fn resolve_cimd(
    state: &AppState,
    actx: &AuditCtx,
    query: &AuthorizeQuery,
    limit: &CimdIpLimit,
    ip: Option<IpAddr>,
) -> Result<(), Response> {
    let allow_private = state.cfg.oauth.cimd.allow_private_targets;
    if query.has_duplicate() || !cimd::client_id_is_cimd(query.client_id(), allow_private) {
        return Ok(());
    }
    limit.admit(ip)?;
    cimd::resolve(state, actx, query.pairs()).await
}

/// The body alone is the request; it is answered with the same request as a GET.
async fn authorize_post(State(state): State<AppState>, body: Bytes) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(url::form_urlencoded::parse(&body))
        .finish();
    Redirect::to(&authorize::request_url(&state.oauth.issuer, &query)).into_response()
}

async fn authorize_request(
    state: &AppState,
    raw_query: &str,
    query: &AuthorizeQuery,
    headers: &HeaderMap,
    locale: &LanguageIdentifier,
) -> Response {
    let oauth = &state.oauth;
    let issuer = oauth.issuer.as_str();
    let client = match query.client_id() {
        Some(id) => match clients::get(&oauth.db, id).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = ?e, "oauth client lookup failed");
                return error_page();
            }
        },
        None => None,
    };
    let req = match authorize::validate(query, client.as_ref()) {
        Ok(req) => req,
        Err(AuthorizeError::Page(reason)) => {
            tracing::info!(?reason, "authorization request refused");
            return error_page();
        }
        Err(AuthorizeError::Redirect(e)) => {
            return response::error(
                &e.delivery,
                issuer,
                e.error.as_str(),
                e.description,
                Navigation::Redirect,
                locale,
            );
        }
    };

    let secure = state.cfg.self_.is_https();
    let now = Utc::now();
    let named = sessions::read_op_cookie(&oauth.cookie_secret, headers);
    let remembered = match &named {
        Some(sid) => match sessions::find(&oauth.db, sid).await {
            Ok(s) => s.filter(|s| s.expires_at > now),
            Err(e) => {
                tracing::error!(error = ?e, "oauth login session lookup failed");
                return error_page();
            }
        },
        None => None,
    };
    let clear_op =
        (named.is_some() && remembered.is_none()).then(|| sessions::clear_op_cookie(secure));

    let snapshot = remembered.as_ref().map(sessions::LoginSession::snapshot);
    let (skip, page) = match authorize::login_step(&req.prompt, req.max_age, now, snapshot.as_ref())
    {
        LoginStep::LoginRequired => {
            let mut resp = response::error(
                &req.delivery,
                issuer,
                authorize::ErrorCode::LoginRequired.as_str(),
                "the user is not signed in",
                Navigation::Redirect,
                locale,
            );
            crate::web::append_set_cookie(&mut resp, clear_op);
            return resp;
        }
        LoginStep::Skip { .. } => (remembered.as_ref(), "/oauth/login"),
        LoginStep::ShowLogin => (None, "/oauth/login"),
        LoginStep::Register => (None, "/oauth/register"),
    };
    let request_url = authorize::request_url(issuer, raw_query);
    let (flow_id, login_challenge) =
        match challenge::create(&oauth.db, &req, request_url, skip).await {
            Ok(created) => created,
            Err(e) => {
                tracing::error!(error = ?e, "storing the authorization request failed");
                return error_page();
            }
        };
    let mut resp = Redirect::to(&format!(
        "{issuer}{page}?login_challenge={}",
        crate::web::urlencode(&login_challenge)
    ))
    .into_response();
    let binding = challenge::bind(&oauth.cookie_secret, &flow_id, secure);
    crate::web::append_set_cookie(&mut resp, Some(binding));
    crate::web::append_set_cookie(&mut resp, clear_op);
    resp
}

#[derive(Deserialize)]
struct ResumeQuery {
    verifier: Option<String>,
}

/// The login and consent handlers come back here; consent results and errors reach it from a
/// [`crate::oauth::continue_nav`] document, never from a form submission.
async fn resume(
    State(state): State<AppState>,
    Path(flow_id): Path<String>,
    Query(query): Query<ResumeQuery>,
    headers: HeaderMap,
    ReqLocale(locale): ReqLocale,
) -> Response {
    let Some(verifier) = query.verifier.filter(|v| !v.is_empty()) else {
        return error_page();
    };
    let oauth = &state.oauth;
    let issuer = oauth.issuer.as_str();
    let secure = state.cfg.self_.is_https();
    let is_bound = |id: &str| challenge::is_bound(&oauth.cookie_secret, &headers, id);
    match challenge::resume(&oauth.db, &flow_id, &verifier, is_bound).await {
        Ok(Resumed::Consent {
            challenge,
            remembered,
        }) => {
            let mut resp = Redirect::to(&format!(
                "{issuer}/oauth/consent?consent_challenge={}",
                crate::web::urlencode(&challenge)
            ))
            .into_response();
            if let Some((sid, max_age)) = remembered {
                let cookie = sessions::set_op_cookie(&oauth.cookie_secret, &sid, max_age, secure);
                crate::web::append_set_cookie(&mut resp, Some(cookie));
            }
            resp
        }
        Ok(Resumed::Code {
            flow_id,
            delivery,
            code,
        }) => {
            let mut resp =
                response::success(&delivery, issuer, &code, Navigation::Redirect, &locale);
            crate::web::append_set_cookie(&mut resp, Some(challenge::unbind(&flow_id, secure)));
            resp
        }
        Ok(Resumed::Error {
            flow_id,
            delivery,
            error,
            description,
            nav,
        }) => {
            let mut resp = response::error(&delivery, issuer, &error, &description, nav, &locale);
            crate::web::append_set_cookie(&mut resp, Some(challenge::unbind(&flow_id, secure)));
            resp
        }
        Ok(Resumed::Device { approved }) => {
            Redirect::to(&challenge::device_done_url(issuer, approved)).into_response()
        }
        Err(e) => {
            tracing::info!(error = %e, "authorization resume refused");
            error_page()
        }
    }
}

async fn discovery(State(state): State<AppState>) -> Response {
    let providers = state.idp_provider_ids().await;
    let doc = super::discovery::document(&state.oauth.issuer, &providers);
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

async fn jwks(State(state): State<AppState>) -> Response {
    let keys = match state.oauth.published_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = ?e, "oauth signing keys unavailable");
            return (StatusCode::SERVICE_UNAVAILABLE, "signing keys unavailable").into_response();
        }
    };
    let body = serde_json::json!({ "keys": keys.public_jwks() });
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            // Same as Hydra's JWKS through the front proxy: a rotation is visible at once.
            (
                header::CACHE_CONTROL,
                "private, no-cache, no-store, must-revalidate",
            ),
        ],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use crate::backend::OAuthBackend;
    use crate::config::AppConfig;
    use crate::state::AppState;

    async fn app() -> (axum::Router, AppState) {
        app_at("https://id.example.com/").await
    }

    async fn app_at(self_url: &str) -> (axum::Router, AppState) {
        app_with(|cfg| cfg.self_.url = self_url.to_string()).await
    }

    async fn app_with(configure: impl FnOnce(&mut AppConfig)) -> (axum::Router, AppState) {
        let mut cfg = AppConfig::test_fixture();
        cfg.self_.url = "https://id.example.com/".to_string();
        configure(&mut cfg);
        // Refused at once, so the provider probe does not wait on DNS.
        #[cfg(feature = "identity-ory")]
        {
            cfg.kratos.public_url = "http://127.0.0.1:1".to_string();
        }
        let db = crate::db::test_pool().await;
        let identity = crate::backend::build_identity(&cfg, &db, &[0x42; 32]);
        let state = AppState::for_test(cfg, db, identity, &[0x42; 32]);
        state.oauth.init().await.unwrap();
        let app = axum::Router::new()
            .merge(super::router(&state.cfg))
            .with_state(state.clone());
        (app, state)
    }

    async fn get(app: &axum::Router, path: &str) -> (axum::http::HeaderMap, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(crate::oauth_native::test_support::with_peer(
                Request::get(path).body(Body::empty()).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let headers = resp.headers().clone();
        assert_eq!(headers[header::CONTENT_TYPE], "application/json", "{path}");
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*", "{path}");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (headers, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn well_known_routes_serve_discovery_and_the_active_key() {
        let (app, state) = app().await;

        let (_, oidc) = get(&app, "/.well-known/openid-configuration").await;
        let (_, oauth) = get(&app, "/.well-known/oauth-authorization-server").await;
        assert_eq!(oidc, oauth);
        assert_eq!(oidc["issuer"], "https://id.example.com");
        let (_, raw) = state.oauth.fetch_discovery().await.unwrap();
        assert_eq!(oidc, raw);

        let (_, jwks) = get(&app, "/.well-known/jwks.json").await;
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let mut members: Vec<_> = keys[0].as_object().unwrap().keys().cloned().collect();
        members.sort();
        assert_eq!(members, ["alg", "e", "kid", "kty", "n", "use"]);
        let signing = state.oauth.keys().unwrap().signing().kid.clone();
        assert_eq!(keys[0]["kid"], signing.as_str());
    }

    #[tokio::test]
    async fn the_jwks_route_serves_a_key_rotated_by_another_instance() {
        let (app, state) = app().await;
        let elsewhere = crate::oauth_native::NativeOAuth::new(&state.cfg, &state.db, &[0x42; 32]);
        let rotated = elsewhere.rotate_key().await.unwrap();
        let (_, jwks) = get(&app, "/.well-known/jwks.json").await;
        let mut kids: Vec<&str> = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        kids.sort_unstable();
        let mut want = vec![rotated.active.as_str(), rotated.retired.as_str()];
        want.sort_unstable();
        assert_eq!(kids, want);
    }

    #[tokio::test]
    async fn the_jwks_route_is_rate_limited() {
        let (app, _) = app().await;
        let send = || async {
            app.clone()
                .oneshot(crate::oauth_native::test_support::with_peer(
                    Request::get("/.well-known/jwks.json")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap()
        };
        // The bucket refills while a slow run works through it, so the refusal can come late.
        let mut refused = None;
        for sent in 0..super::TOKEN_RATE_PER_MINUTE * 2 {
            let resp = send().await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                refused = Some((sent, resp));
                break;
            }
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let (sent, resp) = refused.expect("the limiter refuses within twice its burst");
        assert!(sent >= super::TOKEN_RATE_PER_MINUTE);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
    }

    const REDIRECT: &str = "https://app.example/cb";

    fn client(id: &str) -> crate::backend::oauth::OAuthClient {
        crate::backend::oauth::OAuthClient {
            client_id: Some(id.to_string()),
            redirect_uris: Some(vec![REDIRECT.to_string()]),
            scope: Some("openid email".to_string()),
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            ..Default::default()
        }
    }

    fn authorize_query(extra: &str) -> String {
        format!(
            "/oauth2/authorize?client_id=app&redirect_uri={}&response_type=code&scope=openid&state=xyz{extra}",
            crate::web::urlencode(REDIRECT)
        )
    }

    /// One browser: its cookie jar, keyed by name and `Path`, and the requests it sends.
    #[derive(Default, Clone)]
    struct Browser {
        cookies: std::collections::BTreeMap<(String, String), String>,
        /// The `Cookie` header of the last request.
        sent: String,
    }

    /// RFC 6265 section 5.1.4.
    fn path_matches(cookie_path: &str, request_path: &str) -> bool {
        request_path == cookie_path
            || (request_path.starts_with(cookie_path)
                && (cookie_path.ends_with('/')
                    || request_path[cookie_path.len()..].starts_with('/')))
    }

    impl Browser {
        async fn send(
            &mut self,
            app: &axum::Router,
            req: Request<Body>,
        ) -> axum::response::Response {
            let (mut parts, body) = req.into_parts();
            let path = parts.uri.path().to_string();
            let mut matching: Vec<_> = self
                .cookies
                .iter()
                .filter(|((_, p), _)| path_matches(p, &path))
                .collect();
            matching.sort_by_key(|((_, p), _)| std::cmp::Reverse(p.len()));
            let jar: Vec<String> = matching
                .into_iter()
                .map(|((k, _), v)| format!("{k}={v}"))
                .collect();
            self.sent = jar.join("; ");
            if !jar.is_empty() {
                parts
                    .headers
                    .insert(header::COOKIE, self.sent.parse().unwrap());
            }
            let addr: std::net::SocketAddr = "192.0.2.7:443".parse().unwrap();
            parts.extensions.insert(axum::extract::ConnectInfo(addr));
            let resp = app
                .clone()
                .oneshot(Request::from_parts(parts, body))
                .await
                .unwrap();
            for line in resp.headers().get_all(header::SET_COOKIE) {
                let line = line.to_str().unwrap();
                let (name, rest) = line.split_once('=').unwrap();
                let value = rest.split(';').next().unwrap();
                let cookie_path = line
                    .split("; ")
                    .find_map(|a| a.strip_prefix("Path="))
                    .unwrap_or("/");
                let key = (name.to_string(), cookie_path.to_string());
                if value.is_empty() || line.contains("Expires=Thu, 01 Jan 1970") {
                    self.cookies.remove(&key);
                } else {
                    self.cookies.insert(key, value.to_string());
                }
            }
            resp
        }

        async fn get(&mut self, app: &axum::Router, uri: &str) -> axum::response::Response {
            self.send(app, Request::get(uri).body(Body::empty()).unwrap())
                .await
        }

        fn has(&self, name: &str) -> bool {
            self.cookies.keys().any(|(n, _)| n == name)
        }

        /// The paths of the flow bindings this browser holds.
        fn binding_paths(&self) -> Vec<String> {
            self.cookies
                .keys()
                .filter(|(n, _)| n == "forseti_flow")
                .map(|(_, p)| p.clone())
                .collect()
        }
    }

    fn location(resp: &axum::response::Response) -> String {
        resp.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }

    fn set_cookie<'a>(resp: &'a axum::response::Response, name: &str) -> Option<&'a str> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|v| v.starts_with(&format!("{name}=")))
    }

    /// The flow-binding `Set-Cookie` a response mints.
    fn binding_set(resp: &axum::response::Response) -> Option<&str> {
        set_cookie(resp, "forseti_flow").filter(|v| !v.contains("Expires=Thu, 01 Jan 1970"))
    }

    fn param(url: &str, name: &str) -> Option<String> {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    /// Path and query of an absolute `url`, for sending it to the router.
    fn local(url: &str) -> String {
        let u = url::Url::parse(url).unwrap();
        format!("{}?{}", u.path(), u.query().unwrap_or_default())
    }

    async fn flow_app() -> (axum::Router, AppState) {
        let (app, state) = app().await;
        state.oauth.create_client(client("app")).await.unwrap();
        (app, state)
    }

    /// Authorize in `browser`: the login challenge.
    async fn authorize(app: &axum::Router, browser: &mut Browser, extra: &str) -> String {
        let resp = browser.get(app, &authorize_query(extra)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let to = location(&resp);
        assert!(
            to.starts_with("https://id.example.com/oauth/login?login_challenge="),
            "{to}"
        );
        param(&to, "login_challenge").unwrap()
    }

    async fn accept_login(state: &AppState, challenge: &str) -> String {
        state
            .oauth
            .accept_login_request(challenge, "alice", true, 86_400, vec![], None)
            .await
            .unwrap()
            .redirect_to
    }

    #[tokio::test]
    async fn authorize_sends_the_browser_to_the_login_handler_and_binds_the_request() {
        let (app, _) = flow_app().await;
        let mut browser = Browser::default();
        let resp = browser.get(&app, &authorize_query("")).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let binding = binding_set(&resp).unwrap();
        for attr in ["HttpOnly", "SameSite=Lax", "Secure", "Max-Age=1800"] {
            assert!(binding.contains(attr), "{attr}: {binding}");
        }
        let [path] = <[String; 1]>::try_from(browser.binding_paths()).unwrap();
        let flow_id = path.strip_prefix("/oauth2/auth/resume/").unwrap();
        assert!(uuid::Uuid::try_parse(flow_id).is_ok(), "{binding}");
        assert!(
            binding.split("; ").any(|a| a == format!("Path={path}")),
            "{binding}"
        );
        let to = location(&resp);
        let challenge = param(&to, "login_challenge").unwrap();
        assert_eq!(challenge.len(), 43);

        // The alias path serves the same endpoint; neither path receives the binding.
        let resp = browser
            .get(
                &app,
                &authorize_query("").replace("/oauth2/authorize", "/oauth2/auth"),
            )
            .await;
        assert!(location(&resp).contains("/oauth/login?login_challenge="));
        assert!(!browser.sent.contains("forseti_flow"), "{}", browser.sent);
        browser.get(&app, &authorize_query("")).await;
        assert!(!browser.sent.contains("forseti_flow"), "{}", browser.sent);
        assert_eq!(browser.binding_paths().len(), 3);
    }

    #[tokio::test]
    async fn authorize_errors_go_to_the_error_page_or_the_client() {
        let (app, _) = flow_app().await;
        let mut browser = Browser::default();
        let resp = browser
            .get(
                &app,
                &authorize_query("").replace("client_id=app", "client_id=ghost"),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/error");
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        assert!(binding_set(&resp).is_none());

        let resp = browser
            .get(
                &app,
                &authorize_query("").replace("scope=openid", "scope=openid+admin"),
            )
            .await;
        let to = location(&resp);
        assert!(to.starts_with(REDIRECT), "{to}");
        assert_eq!(param(&to, "error").as_deref(), Some("invalid_scope"));
        assert_eq!(param(&to, "state").as_deref(), Some("xyz"));
        assert_eq!(param(&to, "iss").as_deref(), Some("https://id.example.com"));
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn a_post_is_answered_with_its_body_as_a_get() {
        let (app, _) = flow_app().await;
        let body = "client_id=app&scope=openid%20email&state=a+b";
        let req = Request::post("/oauth2/authorize?client_id=ignored&prompt=none")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = Browser::default().send(&app, req).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            location(&resp),
            "https://id.example.com/oauth2/authorize?client_id=app&scope=openid+email&state=a+b"
        );
    }

    #[tokio::test]
    async fn resume_without_the_binding_cookie_consumes_nothing() {
        let (app, state) = flow_app().await;
        let mut attacker = Browser::default();
        let challenge = authorize(&app, &mut attacker, "").await;
        let resume = accept_login(&state, &challenge).await;

        let mut victim = Browser::default();
        let resp = victim.get(&app, &local(&resume)).await;
        assert_eq!(location(&resp), "/error");
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        assert!(set_cookie(&resp, "forseti_op").is_none());

        // The verifier is untouched: only the browser holding the binding can still use it.
        let resp = attacker.get(&app, &local(&resume)).await;
        assert!(
            location(&resp).starts_with("https://id.example.com/oauth/consent?consent_challenge=")
        );
        let resp = attacker.get(&app, &local(&resume)).await;
        assert_eq!(location(&resp), "/error");
    }

    #[tokio::test]
    async fn the_whole_flow_ends_at_the_client_with_a_code() {
        let (app, state) = flow_app().await;
        let mut browser = Browser::default();
        let challenge = authorize(&app, &mut browser, "").await;
        let login = state.oauth.get_login_request(&challenge).await.unwrap();
        assert!(!login.skip);
        let resume = accept_login(&state, &challenge).await;

        let resp = browser.get(&app, &local(&resume)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let op = set_cookie(&resp, "forseti_op").unwrap();
        for attr in [
            "HttpOnly",
            "SameSite=Lax",
            "Path=/oauth2",
            "Max-Age=86400",
            "Secure",
        ] {
            assert!(op.contains(attr), "{attr}: {op}");
        }
        let consent = param(&location(&resp), "consent_challenge").unwrap();
        let req = state.oauth.get_consent_request(&consent).await.unwrap();
        assert_eq!(req.login_session_id, login.session_id);
        let resume = state
            .oauth
            .accept_consent_request(
                &consent,
                vec!["openid".to_string()],
                vec![],
                true,
                serde_json::json!({}),
                serde_json::Map::new(),
            )
            .await
            .unwrap()
            .redirect_to;

        let resp = browser.get(&app, &local(&resume)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let to = location(&resp);
        assert!(to.starts_with(&format!("{REDIRECT}?code=")), "{to}");
        let code = param(&to, "code").unwrap();
        assert_eq!(param(&to, "state").as_deref(), Some("xyz"));
        assert_eq!(param(&to, "iss").as_deref(), Some("https://id.example.com"));
        let hash = super::super::token_hash(&code);
        let found: anyhow::Result<i64> = async {
            use diesel::prelude::*;
            Ok(crate::db_interact!(state.db, |c| {
                crate::schema::oauth_authorization_codes::table
                    .filter(crate::schema::oauth_authorization_codes::code_hash.eq(hash))
                    .count()
                    .get_result(c)
            })?)
        }
        .await;
        assert_eq!(found.unwrap(), 1);
    }

    /// Signs `browser` in with a remembered login: the `sid`.
    async fn remembered_login(
        app: &axum::Router,
        state: &AppState,
        browser: &mut Browser,
    ) -> String {
        let challenge = authorize(app, browser, "").await;
        let sid = state
            .oauth
            .get_login_request(&challenge)
            .await
            .unwrap()
            .session_id
            .unwrap();
        let resume = accept_login(state, &challenge).await;
        browser.get(app, &local(&resume)).await;
        assert!(browser.has("forseti_op"));
        sid
    }

    #[tokio::test]
    async fn a_remembered_login_is_skipped_unless_the_client_asks_for_a_login() {
        let (app, state) = flow_app().await;
        let mut browser = Browser::default();
        let sid = remembered_login(&app, &state, &mut browser).await;

        let challenge = authorize(&app, &mut browser, "").await;
        let req = state.oauth.get_login_request(&challenge).await.unwrap();
        assert!(req.skip);
        assert_eq!(req.subject, "alice");
        assert_eq!(req.session_id.as_deref(), Some(sid.as_str()));

        let challenge = authorize(&app, &mut browser, "&prompt=login").await;
        let req = state.oauth.get_login_request(&challenge).await.unwrap();
        assert!(!req.skip);
        assert_eq!(req.subject, "");
        assert_ne!(req.session_id.as_deref(), Some(sid.as_str()));

        let challenge = authorize(&app, &mut browser, "&prompt=none").await;
        assert!(
            state
                .oauth
                .get_login_request(&challenge)
                .await
                .unwrap()
                .skip
        );
    }

    #[tokio::test]
    async fn a_revoked_session_clears_the_cookie() {
        let (app, state) = flow_app().await;
        let mut browser = Browser::default();
        let sid = remembered_login(&app, &state, &mut browser).await;
        state.oauth.revoke_login_session_by_sid(&sid).await.unwrap();

        let resp = browser.get(&app, &authorize_query("")).await;
        let cleared = set_cookie(&resp, "forseti_op").unwrap();
        assert!(cleared.contains("Expires=Thu, 01 Jan 1970"), "{cleared}");
        let challenge = param(&location(&resp), "login_challenge").unwrap();
        assert!(
            !state
                .oauth
                .get_login_request(&challenge)
                .await
                .unwrap()
                .skip
        );
    }

    #[tokio::test]
    async fn prompt_none_without_a_session_answers_login_required() {
        let (app, _) = flow_app().await;
        let resp = Browser::default()
            .get(&app, &authorize_query("&prompt=none"))
            .await;
        let to = location(&resp);
        assert!(to.starts_with(REDIRECT), "{to}");
        assert_eq!(param(&to, "error").as_deref(), Some("login_required"));
        assert_eq!(param(&to, "state").as_deref(), Some("xyz"));
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn prompt_create_goes_to_registration() {
        let (app, state) = flow_app().await;
        let resp = Browser::default()
            .get(&app, &authorize_query("&prompt=create"))
            .await;
        let to = location(&resp);
        assert!(
            to.starts_with("https://id.example.com/oauth/register?login_challenge="),
            "{to}"
        );
        let challenge = param(&to, "login_challenge").unwrap();
        let req = state.oauth.get_login_request(&challenge).await.unwrap();
        assert!(!req.skip);
        assert!(req.request_url.contains("prompt=create"));
    }

    #[tokio::test]
    async fn cookies_are_secure_only_on_https() {
        let (app, state) = app_at("http://id.example.com/").await;
        state.oauth.create_client(client("app")).await.unwrap();
        let mut browser = Browser::default();
        let resp = browser.get(&app, &authorize_query("")).await;
        let binding = binding_set(&resp).unwrap();
        assert!(!binding.contains("Secure"), "{binding}");
        let challenge = param(&location(&resp), "login_challenge").unwrap();
        let resume = accept_login(&state, &challenge).await;
        let resp = browser.get(&app, &local(&resume)).await;
        let op = set_cookie(&resp, "forseti_op").unwrap();
        assert!(!op.contains("Secure"), "{op}");
        assert!(
            op.contains("HttpOnly") && op.contains("Path=/oauth2"),
            "{op}"
        );
    }

    /// Accepts the login of `challenge` and follows the browser to the consent handler: the
    /// consent challenge.
    async fn to_consent(
        app: &axum::Router,
        state: &AppState,
        browser: &mut Browser,
        challenge: &str,
    ) -> String {
        let resume = accept_login(state, challenge).await;
        let resp = browser.get(app, &local(&resume)).await;
        let to = location(&resp);
        assert!(
            to.starts_with("https://id.example.com/oauth/consent?consent_challenge="),
            "{to}"
        );
        assert!(
            !resp
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().starts_with("forseti_flow=")),
            "the hop to consent keeps the binding"
        );
        param(&to, "consent_challenge").unwrap()
    }

    /// Accepts the consent and follows the browser back: the final response.
    async fn to_code(
        app: &axum::Router,
        state: &AppState,
        browser: &mut Browser,
        consent: &str,
    ) -> axum::response::Response {
        let resume = state
            .oauth
            .accept_consent_request(
                consent,
                vec!["openid".to_string()],
                vec![],
                false,
                serde_json::json!({}),
                serde_json::Map::new(),
            )
            .await
            .unwrap()
            .redirect_to;
        browser.get(app, &local(&resume)).await
    }

    /// Whether `resp` clears the binding on `path`.
    fn cleared(resp: &axum::response::Response, path: &str) -> bool {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .any(|c| {
                c.starts_with("forseti_flow=;")
                    && c.contains("Expires=Thu, 01 Jan 1970")
                    && c.split("; ").any(|a| a == format!("Path={path}"))
            })
    }

    fn code_of(resp: &axum::response::Response) -> String {
        let to = location(resp);
        assert!(to.starts_with(&format!("{REDIRECT}?code=")), "{to}");
        param(&to, "code").unwrap()
    }

    fn only_binding(browser: &Browser) -> String {
        let [path] = <[String; 1]>::try_from(browser.binding_paths()).unwrap();
        path
    }

    #[tokio::test]
    async fn the_binding_survives_the_hop_to_consent_and_goes_with_the_code() {
        let (app, state) = flow_app().await;
        let mut browser = Browser::default();
        let challenge = authorize(&app, &mut browser, "").await;
        let path = only_binding(&browser);
        let consent = to_consent(&app, &state, &mut browser, &challenge).await;
        assert!(
            browser.sent.contains("forseti_flow="),
            "the resume carried it"
        );
        assert_eq!(browser.binding_paths(), std::slice::from_ref(&path));

        let resp = to_code(&app, &state, &mut browser, &consent).await;
        code_of(&resp);
        assert!(cleared(&resp, &path));
        assert!(browser.binding_paths().is_empty());
    }

    #[tokio::test]
    async fn error_responses_clear_the_binding() {
        let (app, state) = flow_app().await;
        let mut browser = Browser::default();

        let challenge = authorize(&app, &mut browser, "").await;
        let path = only_binding(&browser);
        let resume = state
            .oauth
            .reject_login_request(&challenge, "login_required", "x")
            .await
            .unwrap()
            .redirect_to;
        let resp = browser.get(&app, &local(&resume)).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a login rejection is a document"
        );
        assert!(cleared(&resp, &path));

        let challenge = authorize(&app, &mut browser, "").await;
        let path = only_binding(&browser);
        let consent = to_consent(&app, &state, &mut browser, &challenge).await;
        let resume = state
            .oauth
            .reject_consent_request(&consent, "access_denied", "x")
            .await
            .unwrap()
            .redirect_to;
        let resp = browser.get(&app, &local(&resume)).await;
        assert_eq!(
            param(&location(&resp), "error").as_deref(),
            Some("access_denied")
        );
        assert!(cleared(&resp, &path));
        assert!(browser.binding_paths().is_empty());
    }

    #[tokio::test]
    async fn two_concurrent_authorizes_in_one_browser_both_stay_bound_and_complete() {
        let (app, state) = flow_app().await;
        let mut first = Browser::default();
        // Two tabs send from the same jar before either response lands.
        let mut second = first.clone();
        let (a, b) = tokio::join!(
            authorize(&app, &mut first, ""),
            authorize(&app, &mut second, "")
        );
        first.cookies.extend(second.cookies);
        assert_eq!(first.binding_paths().len(), 2);

        let consent_a = to_consent(&app, &state, &mut first, &a).await;
        let consent_b = to_consent(&app, &state, &mut first, &b).await;
        let code_a = code_of(&to_code(&app, &state, &mut first, &consent_a).await);
        let code_b = code_of(&to_code(&app, &state, &mut first, &consent_b).await);
        assert_ne!(code_a, code_b);
        assert!(first.binding_paths().is_empty());
    }

    #[tokio::test]
    async fn eight_pending_flows_all_stay_bound() {
        let (app, state) = flow_app().await;
        let mut browser = Browser::default();
        let mut challenges = Vec::new();
        for _ in 0..8 {
            challenges.push(authorize(&app, &mut browser, "").await);
        }
        assert_eq!(browser.binding_paths().len(), 8);
        for challenge in &challenges {
            to_consent(&app, &state, &mut browser, challenge).await;
            assert_eq!(
                browser.sent.matches("forseti_flow=").count(),
                1,
                "a resume carries only its own binding"
            );
        }
        assert_eq!(browser.binding_paths().len(), 8);
    }

    #[tokio::test]
    async fn another_flows_binding_on_this_flows_path_is_refused() {
        let (app, state) = flow_app().await;
        let mut owner = Browser::default();
        let challenge = authorize(&app, &mut owner, "").await;
        let resume = accept_login(&state, &challenge).await;
        let owner_path = only_binding(&owner);

        let mut attacker = Browser::default();
        authorize(&app, &mut attacker, "").await;
        let own = ("forseti_flow".to_string(), only_binding(&attacker));
        let value = attacker.cookies.remove(&own).unwrap();
        attacker
            .cookies
            .insert(("forseti_flow".to_string(), owner_path), value);

        let resp = attacker.get(&app, &local(&resume)).await;
        assert!(attacker.sent.contains("forseti_flow="));
        assert_eq!(location(&resp), "/error");
        assert!(set_cookie(&resp, "forseti_op").is_none());

        let resp = owner.get(&app, &local(&resume)).await;
        assert!(
            location(&resp).starts_with("https://id.example.com/oauth/consent?consent_challenge=")
        );
    }

    #[tokio::test]
    async fn a_resume_path_naming_another_flow_is_refused() {
        let (app, state) = flow_app().await;
        let mut owner = Browser::default();
        let challenge = authorize(&app, &mut owner, "").await;
        let resume = accept_login(&state, &challenge).await;
        let owner_path = only_binding(&owner);

        // The attacker's own, valid binding, presented with the owner's verifier.
        let mut attacker = Browser::default();
        authorize(&app, &mut attacker, "").await;
        let attacker_path = only_binding(&attacker);
        let swapped = local(&resume).replace(&owner_path, &attacker_path);
        let resp = attacker.get(&app, &swapped).await;
        assert!(attacker.sent.contains("forseti_flow="));
        assert_eq!(location(&resp), "/error");
        assert!(set_cookie(&resp, "forseti_op").is_none());
        assert!(set_cookie(&resp, "forseti_flow").is_none());

        // The same within one browser holding both bindings.
        let other = authorize(&app, &mut owner, "").await;
        let other_path = owner
            .binding_paths()
            .into_iter()
            .find(|p| *p != owner_path)
            .unwrap();
        let resp = owner
            .get(&app, &local(&resume).replace(&owner_path, &other_path))
            .await;
        assert_eq!(location(&resp), "/error");

        let resp = owner.get(&app, &local(&resume)).await;
        assert!(
            location(&resp).starts_with("https://id.example.com/oauth/consent?consent_challenge=")
        );
        assert!(state.oauth.get_login_request(&other).await.is_ok());
    }

    // --- CIMD -------------------------------------------------------------------

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    /// Refuses connections, so a CIMD fetch of it fails.
    const DEAD_DOC: &str = "http://127.0.0.1:1/doc";

    async fn cimd_app(ip_rate_per_minute: Option<u32>) -> (axum::Router, AppState) {
        let (app, state) = app_with(|cfg| {
            cfg.oauth.cimd.allow_private_targets = true;
            cfg.oauth.cimd.ip_rate_per_minute = ip_rate_per_minute;
        })
        .await;
        state.oauth.create_client(client("app")).await.unwrap();
        (app, state)
    }

    async fn serve_cimd_doc() -> String {
        serve_cimd_doc_with_logo("https://cimd.example/logo.png").await
    }

    /// Serves a CIMD document on a loopback port; its URL is the client_id.
    async fn serve_cimd_doc_with_logo(logo_uri: &str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/doc", listener.local_addr().unwrap());
        let body = serde_json::json!({
            "client_id": url,
            "client_name": "cimd-fixture",
            "client_uri": "https://cimd.example/",
            "logo_uri": logo_uri,
            "redirect_uris": ["http://127.0.0.1/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })
        .to_string();
        let doc = axum::Router::new().route(
            "/doc",
            axum::routing::get(move || {
                let body = body.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], body) }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, doc).await.unwrap() });
        url
    }

    fn cimd_query(client_id: &str, redirect_uri: &str, extra: &str) -> String {
        format!(
            "/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid\
             &state=xyz&code_challenge={CHALLENGE}&code_challenge_method=S256{extra}",
            crate::web::urlencode(client_id),
            crate::web::urlencode(redirect_uri)
        )
    }

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn is_login_page(resp: &axum::response::Response) -> bool {
        resp.status() == StatusCode::SEE_OTHER
            && location(resp).starts_with("https://id.example.com/oauth/login?login_challenge=")
    }

    #[tokio::test]
    async fn a_cimd_client_id_is_registered_before_the_client_lookup() {
        let (app, state) = cimd_app(None).await;
        let url = serve_cimd_doc().await;
        let resp = Browser::default()
            .get(
                &app,
                &cimd_query(&url, "http://127.0.0.1:43210/callback", ""),
            )
            .await;
        assert!(is_login_page(&resp), "{:?}", resp.headers());

        let registered = state.oauth.get_client(&url).await.unwrap();
        assert_eq!(
            registered.token_endpoint_auth_method.as_deref(),
            Some("none")
        );
        assert_eq!(
            registered.redirect_uris.unwrap(),
            ["http://127.0.0.1/callback"],
            "no loopback literal is stored"
        );
        assert_eq!(
            registered.client_uri.as_deref(),
            Some("https://cimd.example/")
        );
        assert_eq!(
            registered.logo_uri.as_deref(),
            Some("https://cimd.example/logo.png")
        );
        let meta = crate::oauth_client_metadata::get(&state.db, &url)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.source, crate::oauth_client_metadata::source::CIMD);
    }

    #[tokio::test]
    async fn a_cimd_logo_the_store_refuses_is_dropped_and_the_client_registers() {
        let (app, state) = cimd_app(None).await;
        let url = serve_cimd_doc_with_logo("https://cimd.example/logo.png#frag").await;
        let resp = Browser::default()
            .get(&app, &cimd_query(&url, "http://127.0.0.1/callback", ""))
            .await;
        assert!(is_login_page(&resp), "{:?}", resp.headers());
        let registered = state.oauth.get_client(&url).await.unwrap();
        assert_eq!(registered.logo_uri, None);
        assert_eq!(
            registered.client_uri.as_deref(),
            Some("https://cimd.example/")
        );
    }

    #[tokio::test]
    async fn a_failing_cimd_document_is_a_plain_400() {
        let (app, state) = cimd_app(None).await;
        let resp = Browser::default()
            .get(&app, &cimd_query(DEAD_DOC, "http://127.0.0.1/callback", ""))
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.starts_with("cimd: "));
        assert!(
            state
                .oauth
                .get_client_opt(DEAD_DOC)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_cimd_limit_refuses_once_spent_and_leaves_other_clients_alone() {
        let (app, _) = cimd_app(Some(1)).await;
        let mut browser = Browser::default();
        let query = cimd_query(DEAD_DOC, "http://127.0.0.1/callback", "");
        let resp = browser.get(&app, &query).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = browser.get(&app, &query).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));

        let resp = browser.get(&app, &authorize_query("")).await;
        assert!(is_login_page(&resp), "{:?}", resp.headers());
    }

    #[test]
    fn the_cimd_limit_refuses_a_request_without_an_address() {
        let limit = super::CimdIpLimit::new(&crate::config::CimdConfig::default());
        let refused = limit.admit(None).unwrap_err();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limit.admit(Some("192.0.2.7".parse().unwrap())).is_ok());

        let off = super::CimdIpLimit::new(&crate::config::CimdConfig {
            ip_rate_per_minute: Some(0),
            ip_rate_per_hour: Some(0),
            ..Default::default()
        });
        assert!(off.admit(None).is_ok());
    }

    #[tokio::test]
    async fn a_repeated_parameter_skips_cimd_and_fails_validation() {
        let (app, _) = cimd_app(Some(1)).await;
        let mut browser = Browser::default();
        let resp = browser
            .get(
                &app,
                &cimd_query(DEAD_DOC, "http://127.0.0.1/callback", "&state=again"),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/error");

        // The skipped request spent nothing from the CIMD limit.
        let resp = browser
            .get(&app, &cimd_query(DEAD_DOC, "http://127.0.0.1/callback", ""))
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_cold_path_keeps_only_the_documents_redirect_uris() {
        let (app, state) = cimd_app(None).await;
        let url = serve_cimd_doc().await;
        let mut browser = Browser::default();
        let query = cimd_query(&url, "http://127.0.0.1:43210/callback", "");
        assert!(is_login_page(&browser.get(&app, &query).await));

        // The row as an earlier document left it: one more URI and another hash.
        let mut row = state.oauth.get_client(&url).await.unwrap();
        row.redirect_uris = Some(vec![
            "http://127.0.0.1/callback".to_string(),
            "https://dropped.example/cb".to_string(),
        ]);
        state.oauth.update_client(&url, row).await.unwrap();
        crate::oauth_client_metadata::set_cimd_doc_hash(&state.db, &url, "earlier")
            .await
            .unwrap();

        assert!(is_login_page(&browser.get(&app, &query).await));
        let row = state.oauth.get_client(&url).await.unwrap();
        assert_eq!(row.redirect_uris.unwrap(), ["http://127.0.0.1/callback"]);
    }

    #[tokio::test]
    async fn another_loopback_port_takes_the_warm_path() {
        let (app, state) = cimd_app(None).await;
        let url = serve_cimd_doc().await;
        let mut browser = Browser::default();
        let resp = browser
            .get(
                &app,
                &cimd_query(&url, "http://127.0.0.1:43210/callback", ""),
            )
            .await;
        assert!(is_login_page(&resp), "{:?}", resp.headers());

        // A cold-path upsert would reset the name from the document.
        let mut row = state.oauth.get_client(&url).await.unwrap();
        row.client_name = Some("warm-canary".to_string());
        state.oauth.update_client(&url, row).await.unwrap();

        let resp = browser
            .get(
                &app,
                &cimd_query(&url, "http://127.0.0.1:43211/callback", ""),
            )
            .await;
        assert!(is_login_page(&resp), "{:?}", resp.headers());
        let row = state.oauth.get_client(&url).await.unwrap();
        assert_eq!(row.client_name.as_deref(), Some("warm-canary"));
        assert_eq!(row.redirect_uris.unwrap(), ["http://127.0.0.1/callback"]);
    }
}
