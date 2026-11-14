//! `/self-service/*`: flow init, form submits, the verification mail link, the admin recovery
//! link and logout.

use std::net::SocketAddr;

use axum::Extension;
use axum::Router;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::errors;
use super::flows::{
    AfterEffect, Dispatch, Form, InitOutcome, InitParams, Logout, SubmitOutcome, kind_from_segment,
};
use super::session::{self, Device};
use crate::audit::AuditCtx;
use crate::backend::identity::FlowKind;
use crate::config::AppConfig;
use crate::extractors::Csrf;
use crate::page_chrome::ReqLocale;
use crate::rate_limit;
use crate::state::AppState;

/// Per-IP limits on flow init for every kind but registration, which follows `GET /registration`
/// and shares its `[auth].registration_*` values.
const INIT_IP_RATE_PER_MINUTE: u32 = 60;
const INIT_IP_RATE_PER_HOUR: u32 = 600;

/// Per-IP limits on verification and recovery submits.
const CODE_IP_RATE_PER_MINUTE: u32 = 5;
const CODE_IP_RATE_PER_HOUR: u32 = 30;

/// Per-IP limits on settings submits.
const SETTINGS_IP_RATE_PER_MINUTE: u32 = 30;
const SETTINGS_IP_RATE_PER_HOUR: u32 = 300;

/// Longest `return_to` a flow keeps; a longer one is dropped.
const RETURN_TO_MAX_BYTES: usize = 2048;

pub(crate) fn router(cfg: &AppConfig) -> Router<AppState> {
    let per_ip = |r: Router<AppState>, per_minute: u32, per_hour: u32, context: &'static str| {
        rate_limit::route_dual_window(
            r,
            &cfg.proxy,
            per_minute,
            per_hour,
            rate_limit::plain_text_error(context),
        )
    };
    let limits = crate::auth::registration_limits(&cfg.auth);
    let registration = |r: Router<AppState>| {
        rate_limit::route_dual_window_then_global(
            r,
            &cfg.proxy,
            limits.ip_per_minute,
            limits.ip_per_hour,
            limits.global_per_minute,
            limits.global_per_hour,
            rate_limit::plain_text_error("registration"),
        )
    };
    // Literal paths only: routing matches the raw path, so a `{kind}` route would also take a
    // percent-encoded kind and skip that kind's buckets. Anything else is a 404.
    Router::new()
        .route("/self-service/logout", get(link))
        .merge(per_ip(
            Router::new().route("/self-service/settings", post(submit)),
            SETTINGS_IP_RATE_PER_MINUTE,
            SETTINGS_IP_RATE_PER_HOUR,
            "settings",
        ))
        .merge(per_ip(
            Router::new()
                .route("/self-service/login/browser", get(init))
                .route("/self-service/recovery/browser", get(init))
                .route("/self-service/verification/browser", get(init))
                .route("/self-service/settings/browser", get(init)),
            INIT_IP_RATE_PER_MINUTE,
            INIT_IP_RATE_PER_HOUR,
            "flow init",
        ))
        .merge(registration(
            Router::new().route("/self-service/registration/browser", get(init)),
        ))
        .merge(registration(
            Router::new().route("/self-service/registration", post(submit)),
        ))
        .merge(per_ip(
            Router::new().route("/self-service/login", post(submit)),
            cfg.identity.login_ip_rate_per_minute,
            cfg.identity.login_ip_rate_per_hour,
            "login",
        ))
        .merge(per_ip(
            Router::new()
                .route("/self-service/verification", post(submit))
                .route("/self-service/recovery", post(submit)),
            CODE_IP_RATE_PER_MINUTE,
            CODE_IP_RATE_PER_HOUR,
            "verification and recovery",
        ))
        .route("/self-service/verification", get(link))
        .route("/self-service/recovery", get(link))
}

/// `<segment>` of `/self-service/<segment>[/browser]`.
fn segment(uri: &Uri) -> &str {
    let rest = uri
        .path()
        .strip_prefix("/self-service/")
        .unwrap_or_default();
    rest.strip_suffix("/browser").unwrap_or(rest)
}

#[derive(Deserialize)]
struct InitQuery {
    return_to: Option<String>,
    aal: Option<String>,
    #[serde(default, deserialize_with = "crate::web::deserialize_bool_str")]
    refresh: Option<bool>,
}

#[derive(Deserialize)]
struct LinkQuery {
    flow: Option<String>,
    code: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct SubmitQuery {
    flow: Option<String>,
}

fn page_url(kind: FlowKind, id: &str) -> String {
    format!(
        "/{}?flow={}",
        kind.path_segment(),
        crate::web::urlencode(id)
    )
}

fn failure(
    state: &AppState,
    locale: &crate::locale::LanguageIdentifier,
    e: &anyhow::Error,
) -> Response {
    tracing::error!(error = ?e, "native self-service request failed");
    let mut resp = crate::web::render_error_boundary(
        state,
        locale,
        &crate::i18n::lookup(locale, "error-page-generic-title"),
        &crate::i18n::lookup(locale, "error-boundary-auth-unavailable-body"),
        "/",
        crate::i18n::lookup(locale, "error-boundary-cta-try-again"),
    );
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

/// `GET /self-service/{kind}/browser`: create a flow bound to this browser and send it to the page.
async fn init(
    State(state): State<AppState>,
    uri: Uri,
    Query(query): Query<InitQuery>,
    headers: HeaderMap,
    Csrf(csrf_token): Csrf,
    ReqLocale(locale): ReqLocale,
) -> Response {
    let Some(kind) = kind_from_segment(segment(&uri)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // An off-site or oversized target is dropped rather than replaced, so the flow keeps no `return_to`.
    let return_to = query.return_to.as_deref().filter(|rt| {
        rt.len() <= RETURN_TO_MAX_BYTES && crate::web::safe_return_to(&state.cfg, rt) == *rt
    });
    let params = InitParams {
        return_to,
        aal2: query.aal.as_deref() == Some("aal2"),
        refresh: query.refresh.unwrap_or_default(),
    };
    let cookie = crate::cookies::cookie_header(&headers);
    match state
        .identity
        .init_flow(kind, params, &csrf_token, &cookie)
        .await
    {
        Ok(InitOutcome::Created(id)) => Redirect::to(&page_url(kind, &id)).into_response(),
        Ok(InitOutcome::Redirect(to)) => Redirect::to(&to).into_response(),
        Err(e) => failure(&state, &locale, &e),
    }
}

/// `GET /self-service/verification?flow=&code=` (mail link), `GET /self-service/recovery?flow=`
/// (admin recovery link) and `GET /self-service/logout?token=`.
async fn link(
    State(state): State<AppState>,
    uri: Uri,
    Query(query): Query<LinkQuery>,
    headers: HeaderMap,
    Csrf(csrf_token): Csrf,
    ReqLocale(locale): ReqLocale,
) -> Response {
    let cookie = crate::cookies::cookie_header(&headers);
    match segment(&uri) {
        "verification" => {
            let Some(flow) = query.flow.as_deref().filter(|f| !f.is_empty()) else {
                return Redirect::to("/verification").into_response();
            };
            let code = query.code.as_deref().unwrap_or_default();
            if let Err(e) = state
                .identity
                .prefill_verification_code(flow, code, &csrf_token)
                .await
            {
                return failure(&state, &locale, &e);
            }
            let mut to = page_url(FlowKind::Verification, flow);
            if !code.is_empty() {
                to.push_str(&format!("&code={}", crate::web::urlencode(code)));
            }
            Redirect::to(&to).into_response()
        }
        // The link an admin hands out with a recovery code. Taking the `Csrf` extractor sets the
        // CSRF cookie on this response, so the page's first submit can bind the flow.
        "recovery" => match query.flow.as_deref().filter(|f| !f.is_empty()) {
            Some(flow) => Redirect::to(&page_url(FlowKind::Recovery, flow)).into_response(),
            None => Redirect::to("/recovery").into_response(),
        },
        "logout" => {
            let token = query.token.as_deref().unwrap_or_default();
            match state.identity.logout(&cookie, token).await {
                Ok(Logout::SignedOut | Logout::NoSession) => {
                    let mut resp = Redirect::to("/login").into_response();
                    crate::web::append_set_cookie(
                        &mut resp,
                        Some(session::clear_cookie(state.cfg.self_.is_https())),
                    );
                    resp
                }
                Ok(Logout::BadToken) => {
                    Redirect::to(&errors::url(errors::CSRF_VIOLATION)).into_response()
                }
                Err(e) => failure(&state, &locale, &e),
            }
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The response for a handled submit.
fn respond(kind: FlowKind, id: &str, outcome: SubmitOutcome) -> Response {
    match outcome {
        SubmitOutcome::Page => Redirect::to(&page_url(kind, id)).into_response(),
        SubmitOutcome::Redirect {
            location,
            set_cookies,
        } => {
            let mut resp = Redirect::to(&location).into_response();
            for c in set_cookies {
                crate::web::append_set_cookie(&mut resp, Some(c));
            }
            resp
        }
    }
}

/// `POST /self-service/{kind}?flow=<id>`.
#[allow(clippy::too_many_arguments)]
async fn submit(
    State(state): State<AppState>,
    uri: Uri,
    Query(query): Query<SubmitQuery>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    ReqLocale(locale): ReqLocale,
    audit: AuditCtx,
    axum::Form(fields): axum::Form<Vec<(String, String)>>,
) -> Response {
    let Some(kind) = kind_from_segment(segment(&uri)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(id) = query.flow.filter(|f| !f.is_empty()) else {
        return Redirect::to(&errors::url(errors::FLOW_EXPIRED)).into_response();
    };
    let form = Form(fields);
    let csrf_valid = crate::csrf::verify_csrf(&headers, form.get("csrf_token").unwrap_or_default());
    let cookie = crate::cookies::cookie_header(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let peer = peer.map(|Extension(ConnectInfo(addr))| addr.ip());
    let device = Device {
        ip: crate::client_ip::client_ip(&headers, &state.cfg.proxy, peer),
        user_agent,
    };
    match state
        .identity
        .submit_flow(kind, &id, &form, &cookie, csrf_valid, device)
        .await
    {
        Ok(Dispatch::Done(done)) => {
            for event in done.audit {
                let _ = crate::audit::log(&state.db, event.with_ctx(&audit)).await;
            }
            if let Some(AfterEffect::PasswordChanged {
                identity_id,
                session_id,
            }) = &done.after
            {
                crate::oauth::op_sessions::end_op_sessions_for_subject(
                    &state.db,
                    &state.oauth,
                    identity_id,
                    Some(session_id),
                    crate::oauth::op_sessions::GrantRevocation::Revoke,
                )
                .await;
            }
            respond(kind, &id, done.outcome)
        }
        Ok(Dispatch::Expired) => Redirect::to(&errors::url(errors::FLOW_EXPIRED)).into_response(),
        Ok(Dispatch::Forged) => Redirect::to(&errors::url(errors::CSRF_VIOLATION)).into_response(),
        Ok(Dispatch::SignIn(to)) => Redirect::to(&to).into_response(),
        Err(e) => failure(&state, &locale, &e),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use diesel::prelude::*;
    use tower::ServiceExt as _;

    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::{Aal, FlowFetch, FlowOutcome, PrivilegedReason, WhoamiOutcome};
    use crate::config::AppConfig;
    use crate::db::{DbPool, test_pool};
    use crate::flow_view::Flow;
    use crate::identity_native::{NativeBackend, store};
    use crate::schema::{identity_credentials, identity_flows};

    const SECRET: &[u8] = &[0x42; 32];
    const PEER: &str = "192.0.2.10";

    struct App {
        router: Router,
        db: DbPool,
        backend: Arc<NativeBackend>,
    }

    async fn app() -> App {
        app_with(AppConfig::test_fixture()).await
    }

    async fn app_with(cfg: AppConfig) -> App {
        let db = test_pool().await;
        let backend = NativeBackend::new(&cfg, &db, SECRET);
        let router = super::router(&cfg).merge(crate::auth::router(&cfg.proxy, &cfg.auth));
        let state = AppState::for_test(cfg, db.clone(), backend.clone(), SECRET);
        let router = router
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::csrf::middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::audit::middleware,
            ))
            .with_state(state);
        App {
            router,
            db,
            backend,
        }
    }

    impl App {
        async fn get(&self, uri: &str, cookie: &str) -> Response {
            self.get_from(PEER, uri, cookie).await
        }

        async fn get_from(&self, peer: &str, uri: &str, cookie: &str) -> Response {
            let mut req = Request::get(uri);
            if !cookie.is_empty() {
                req = req.header(header::COOKIE, cookie);
            }
            let mut req = req.body(Body::empty()).unwrap();
            let addr: SocketAddr = format!("{peer}:443").parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            self.send(req).await
        }

        async fn post(&self, uri: &str, cookie: &str, body: &str) -> Response {
            self.post_from(PEER, uri, cookie, body).await
        }

        /// A form POST from the client at `peer`, as the server's connect info reports it.
        async fn post_from(&self, peer: &str, uri: &str, cookie: &str, body: &str) -> Response {
            let mut req = Request::post(uri)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::USER_AGENT, "Mozilla/5.0 test")
                .body(Body::from(body.to_string()))
                .unwrap();
            let addr: SocketAddr = format!("{peer}:443").parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            self.send(req).await
        }

        async fn send(&self, req: Request<Body>) -> Response {
            self.router.clone().oneshot(req).await.unwrap()
        }

        /// Start a flow in a fresh browser: (flow id, the browser's cookie header, its CSRF token).
        async fn start(&self, kind: &str, query: &str) -> (String, String, String) {
            let resp = self
                .get(&format!("/self-service/{kind}/browser{query}"), "")
                .await;
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let token = csrf_cookie(&resp).expect("the init response mints a CSRF cookie");
            let id = location(&resp)
                .strip_prefix(&format!("/{kind}?flow="))
                .expect("redirect to the flow page")
                .to_string();
            (id, format!("forseti_csrf={token}"), token)
        }

        async fn fetch(&self, kind: FlowKind, id: &str, cookie: &str) -> FlowFetch {
            self.backend.get_flow(kind, id, cookie).await.unwrap()
        }

        async fn flow(&self, kind: FlowKind, id: &str, cookie: &str) -> Flow {
            match self.fetch(kind, id, cookie).await {
                FlowFetch::Ok(flow) => *flow,
                _ => panic!("flow {id} is not readable"),
            }
        }

        async fn row(&self, id: &str) -> super::super::flows::FlowRow {
            self.backend.load_flow(id).await.unwrap().unwrap().row
        }

        async fn user(&self, email: &str) -> String {
            store::create(&self.db, email, Some("Ann"), Some("Lee"), true)
                .await
                .unwrap()
                .unwrap()
                .id
        }

        /// A signed-in browser: (session id, cookie header with session and CSRF cookies, CSRF token).
        async fn signed_in(&self, identity_id: &str) -> (String, String, String) {
            let issued = self
                .backend
                .issue_session(identity_id, "password", Aal::Aal1, Device::default())
                .await
                .unwrap();
            let resp = self.get("/self-service/logout", "").await;
            let token = csrf_cookie(&resp).unwrap();
            (
                issued.id,
                format!("forseti_session={}; forseti_csrf={token}", issued.token),
                token,
            )
        }

        async fn add_totp(&self, identity_id: &str) {
            insert_totp(&self.db, identity_id).await.unwrap();
        }

        async fn expire(&self, id: &str) {
            expire_flow(&self.db, id).await.unwrap();
        }
    }

    async fn insert_totp(db: &DbPool, identity_id: &str) -> anyhow::Result<()> {
        let identity_id = identity_id.to_string();
        let now = crate::db::now_rfc3339();
        crate::db_interact!(db, |c| {
            diesel::insert_into(identity_credentials::table)
                .values((
                    identity_credentials::id.eq(uuid::Uuid::new_v4().to_string()),
                    identity_credentials::identity_id.eq(&identity_id),
                    identity_credentials::kind.eq("totp"),
                    identity_credentials::config.eq("{}"),
                    identity_credentials::version.eq(0),
                    identity_credentials::created_at.eq(&now),
                    identity_credentials::updated_at.eq(&now),
                ))
                .execute(c)
        })?;
        Ok(())
    }

    async fn expire_flow(db: &DbPool, id: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        crate::db_interact!(db, |c| {
            diesel::update(identity_flows::table.find(&id))
                .set(identity_flows::expires_at.eq("2020-01-01T00:00:00.000000+00:00"))
                .execute(c)
        })?;
        Ok(())
    }

    fn location(resp: &Response) -> String {
        resp.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }

    fn set_cookies(resp: &Response) -> Vec<String> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn csrf_cookie(resp: &Response) -> Option<String> {
        set_cookies(resp).iter().find_map(|c| {
            c.strip_prefix("forseti_csrf=")
                .map(|rest| rest.split(';').next().unwrap().to_string())
                .filter(|v| !v.is_empty())
        })
    }

    fn sha256_hex(s: &str) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(s.as_bytes()))
    }

    #[tokio::test]
    async fn init_creates_a_flow_bound_to_the_browser_for_each_kind() {
        let app = app().await;
        for (segment, kind) in [
            ("login", FlowKind::Login),
            ("registration", FlowKind::Registration),
            ("recovery", FlowKind::Recovery),
            ("verification", FlowKind::Verification),
        ] {
            let (id, cookie, token) = app.start(segment, "").await;
            let row = app.row(&id).await;
            assert_eq!(row.kind, segment);
            assert_eq!(row.binding.as_deref(), Some(sha256_hex(&token).as_str()));
            assert_eq!(
                row.request_url,
                format!("http://localhost:3000/self-service/{segment}/browser")
            );
            let issued = chrono::DateTime::parse_from_rfc3339(&row.issued_at).unwrap();
            let expires = chrono::DateTime::parse_from_rfc3339(&row.expires_at).unwrap();
            let minutes = if matches!(kind, FlowKind::Login | FlowKind::Registration) {
                10
            } else {
                15
            };
            assert_eq!(
                expires - issued,
                chrono::Duration::minutes(minutes),
                "{segment}"
            );

            let flow = app.flow(kind, &id, &cookie).await;
            assert_eq!(flow.id, id);
            assert_eq!(flow.state, "choose_method");
            assert_eq!(flow.csrf_token.as_deref(), Some(token.as_str()));
            assert_eq!(
                flow.form_action,
                format!("/self-service/{segment}?flow={id}")
            );
        }
        let resp = app.get("/self-service/settings/browser", "").await;
        assert_eq!(location(&resp), "/login?return_to=%2Fsettings");
        assert_eq!(
            app.get("/self-service/nothing/browser", "").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn init_keeps_a_same_origin_return_to_and_drops_an_off_site_one() {
        let app = app().await;
        for (return_to, kept) in [
            ("/settings/profile", true),
            ("http://localhost:3000/oauth/login?login_challenge=c", true),
            ("https://evil.example/x", false),
            ("//evil.example/x", false),
        ] {
            let query = format!("?return_to={}", crate::web::urlencode(return_to));
            let (id, cookie, _) = app.start("login", &query).await;
            let row = app.row(&id).await;
            assert_eq!(
                row.return_to.as_deref(),
                kept.then_some(return_to),
                "{return_to}"
            );
            assert_eq!(row.request_url.contains("return_to="), kept, "{return_to}");
            let flow = app.flow(FlowKind::Login, &id, &cookie).await;
            assert_eq!(flow.return_to.as_deref(), kept.then_some(return_to));
        }
    }

    #[tokio::test]
    async fn another_browser_cannot_read_or_submit_the_flow() {
        let app = app().await;
        let (id, cookie, token) = app.start("login", "").await;
        let (_, other_cookie, other_token) = app.start("login", "").await;

        assert!(matches!(
            app.fetch(FlowKind::Login, &id, &other_cookie).await,
            FlowFetch::Gone
        ));
        assert!(matches!(
            app.fetch(FlowKind::Login, &id, "").await,
            FlowFetch::Gone
        ));
        assert!(matches!(
            app.backend
                .resolve_flow(FlowKind::Login, Some(&id), &other_cookie)
                .await,
            FlowOutcome::Reinit
        ));
        assert!(matches!(
            app.fetch(FlowKind::Registration, &id, &cookie).await,
            FlowFetch::Gone
        ));

        let uri = format!("/self-service/login?flow={id}");
        let forged = app
            .post(&uri, &other_cookie, &format!("csrf_token={other_token}"))
            .await;
        assert_eq!(location(&forged), "/error?id=security_csrf_violation");
        let wrong_field = app.post(&uri, &cookie, "csrf_token=nope").await;
        assert_eq!(location(&wrong_field), "/error?id=security_csrf_violation");
        let no_field = app.post(&uri, &cookie, "identifier=a").await;
        assert_eq!(location(&no_field), "/error?id=security_csrf_violation");

        let own = app
            .post(&uri, &cookie, &format!("csrf_token={token}&identifier=a"))
            .await;
        assert_eq!(own.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&own), format!("/login?flow={id}"));
        let flow = app.flow(FlowKind::Login, &id, &cookie).await;
        let ids: Vec<u64> = flow.messages.iter().map(|m| m.id).collect();
        assert_eq!(ids, [4_010_002], "a submit without a method is no attempt");
    }

    #[tokio::test]
    async fn an_expired_or_unknown_flow_is_gone() {
        let app = app().await;
        let (id, cookie, token) = app.start("recovery", "").await;
        app.expire(&id).await;
        assert!(matches!(
            app.fetch(FlowKind::Recovery, &id, &cookie).await,
            FlowFetch::Gone
        ));
        assert!(matches!(
            app.backend
                .resolve_flow(FlowKind::Recovery, Some(&id), &cookie)
                .await,
            FlowOutcome::Reinit
        ));
        assert!(matches!(
            app.backend
                .resolve_flow(FlowKind::Recovery, None, &cookie)
                .await,
            FlowOutcome::Init
        ));
        let body = format!("csrf_token={token}");
        for uri in [
            format!("/self-service/recovery?flow={id}"),
            "/self-service/recovery?flow=00000000-0000-4000-8000-000000000000".to_string(),
            "/self-service/recovery".to_string(),
            format!("/self-service/login?flow={id}"),
        ] {
            let resp = app.post(&uri, &cookie, &body).await;
            assert_eq!(
                location(&resp),
                "/error?id=self_service_flow_expired",
                "{uri}"
            );
        }
        let resp = app
            .post(&format!("/self-service/nothing?flow={id}"), &cookie, &body)
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_verification_mail_link_prefills_the_code_for_the_browser_that_followed_it() {
        let app = app().await;
        let (id, cookie, _) = app.start("verification", "").await;
        let mut rec = app.backend.load_flow(&id).await.unwrap().unwrap();
        rec.ctx.email = Some("ann@example.com".into());
        rec.set_state("sent_email");
        assert_eq!(
            rec.save(&app.db).await.unwrap(),
            super::super::flows::Saved::Done
        );
        let code_in = |flow: &Flow| {
            flow.inputs("code")
                .find(|i| i.name == "code")
                .unwrap()
                .value
                .clone()
        };

        // Opened in a different browser, as mail links often are.
        let (_, elsewhere, _) = app.start("login", "").await;
        let resp = app
            .get(
                &format!("/self-service/verification?flow={id}&code=123456"),
                &elsewhere,
            )
            .await;
        assert_eq!(
            location(&resp),
            format!("/verification?flow={id}&code=123456")
        );
        let row = app.row(&id).await;
        assert_eq!(row.state, "sent_email", "the link verifies nothing");
        assert!(!row.context.contains("123456"), "the code is sealed");
        assert_eq!(
            code_in(&app.flow(FlowKind::Verification, &id, &elsewhere).await),
            "123456"
        );
        assert_eq!(
            code_in(&app.flow(FlowKind::Verification, &id, &cookie).await),
            "",
            "the browser that started the flow does not see the code"
        );

        // A second follow replaces code and browser.
        app.get(
            &format!("/self-service/verification?flow={id}&code=654321"),
            &cookie,
        )
        .await;
        assert_eq!(
            code_in(&app.flow(FlowKind::Verification, &id, &cookie).await),
            "654321"
        );
        assert_eq!(
            code_in(&app.flow(FlowKind::Verification, &id, &elsewhere).await),
            ""
        );

        // A browser without a CSRF cookie gets one minted with the redirect, bound to the code.
        let resp = app
            .get(
                &format!("/self-service/verification?flow={id}&code=111111"),
                "",
            )
            .await;
        let fresh = format!("forseti_csrf={}", csrf_cookie(&resp).unwrap());
        assert_eq!(
            code_in(&app.flow(FlowKind::Verification, &id, &fresh).await),
            "111111"
        );
        assert_eq!(app.row(&id).await.state, "sent_email");

        let (other, _, _) = app.start("verification", "").await;
        app.get(
            &format!("/self-service/verification?flow={other}&code=12ab56"),
            "",
        )
        .await;
        assert!(
            app.backend
                .load_flow(&other)
                .await
                .unwrap()
                .unwrap()
                .ctx
                .prefill_code
                .is_none()
        );
        let resp = app.get("/self-service/verification", "").await;
        assert_eq!(location(&resp), "/verification");
        assert_eq!(
            app.get("/self-service/registration?flow=x", "")
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            app.get("/self-service/settings?flow=x", "").await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[tokio::test]
    async fn a_percent_encoded_kind_reaches_no_handler() {
        let app = app().await;
        let (id, cookie, token) = app.start("login", "").await;
        let flows = || async {
            crate::identity_native::test_support::sql(&app.db, |c| {
                identity_flows::table.count().get_result::<i64>(c)
            })
            .await
        };
        let before = flows().await;
        let body = format!("csrf_token={token}&method=password&identifier=a&password=b");
        for encoded in [
            "%6Cogin",
            "%72egistration",
            "%76erification",
            "%72ecovery",
            "%73ettings",
            "logi%6E",
        ] {
            let resp = app
                .post(
                    &format!("/self-service/{encoded}?flow={id}"),
                    &cookie,
                    &body,
                )
                .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "submit {encoded}");
            let resp = app
                .get(&format!("/self-service/{encoded}/browser"), "")
                .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "init {encoded}");
        }
        assert_eq!(flows().await, before, "no flow was started");
        let row = app.row(&id).await;
        assert_eq!(
            (row.state.as_str(), row.version),
            ("choose_method", 0),
            "no submit landed"
        );
    }

    /// A signed-in browser at AAL2 with TOTP: (cookie header, CSRF token, TOTP secret).
    async fn enrolled_browser(app: &App, email: &str) -> (String, String, Vec<u8>) {
        use crate::identity_native::test_support::{identity_with_password, plant_totp};
        let identity = identity_with_password(&app.db, email, true).await;
        let secret = plant_totp(&app.backend, &identity).await;
        let (session_id, _, token) = app.signed_in(&identity).await;
        let held = session::find_live(&app.db, &session_id)
            .await
            .unwrap()
            .unwrap();
        let session::StepUp::Rotated(session) = session::step_up(&app.db, &held, "totp", Aal::Aal2)
            .await
            .unwrap()
        else {
            panic!("live session rotates");
        };
        (
            format!("forseti_session={session}; forseti_csrf={token}"),
            token,
            secret,
        )
    }

    async fn settings_flow(app: &App, cookie: &str, page: &str) -> String {
        let back = crate::web::urlencode(format!("http://localhost:3000{page}"));
        let resp = app
            .get(
                &format!("/self-service/settings/browser?return_to={back}"),
                cookie,
            )
            .await;
        location(&resp)
            .strip_prefix("/settings?flow=")
            .expect("a settings flow")
            .to_string()
    }

    #[tokio::test]
    async fn a_lapsed_sign_in_is_sent_to_a_refresh_login_that_returns_to_the_page() {
        let app = app().await;
        let (cookie, token, _) = enrolled_browser(&app, "lapse@x.test").await;
        let id = settings_flow(&app, &cookie, "/settings/password").await;
        let WhoamiOutcome::Ok(session) = app.backend.whoami(Some(&cookie)).await.unwrap() else {
            panic!("live");
        };
        crate::identity_native::test_support::sql(&app.db, move |c| {
            use crate::schema::identity_sessions;
            diesel::update(identity_sessions::table.find(&session.id))
                .set(identity_sessions::authenticated_at.eq("2026-01-01T00:00:00.000000+00:00"))
                .execute(c)
        })
        .await;
        let resp = app
            .post(
                &format!("/self-service/settings?flow={id}"),
                &cookie,
                &format!("csrf_token={token}&method=password&password=violet+staircase+42"),
            )
            .await;
        assert_eq!(
            location(&resp),
            "/login?refresh=true&return_to=http%3A%2F%2Flocalhost%3A3000%2Fsettings%2Fpassword"
        );
        assert!(audit_rows(&app.db).await.unwrap().is_empty());

        let resp = app.get(&location(&resp), &cookie).await;
        let init = location(&resp);
        assert!(init.starts_with("/self-service/login/browser?"), "{init}");
        assert!(init.contains("refresh=true"));
        let resp = app.get(&init, &cookie).await;
        let login = location(&resp)
            .strip_prefix("/login?flow=")
            .expect("a refresh login flow")
            .to_string();
        let row = app.row(&login).await;
        assert_eq!(row.refresh, 1);
        assert_eq!(
            row.return_to.as_deref(),
            Some("http://localhost:3000/settings/password")
        );
    }

    /// A Hydra admin API that accepts every revoke and lists no consent sessions; returns its
    /// base URL and the requests it saw.
    async fn fake_hydra_admin() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let hydra = Router::new().fallback(move |method: axum::http::Method, uri: Uri| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push(format!("{method} {uri}"));
                if method == axum::http::Method::DELETE {
                    StatusCode::NO_CONTENT.into_response()
                } else {
                    axum::Json(serde_json::json!([])).into_response()
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, hydra).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    fn signed_in_session(outcome: WhoamiOutcome) -> crate::backend::identity::Session {
        match outcome {
            WhoamiOutcome::Ok(session) => *session,
            _ => panic!("the browser is signed in"),
        }
    }

    #[tokio::test]
    async fn a_password_change_over_http_audits_with_the_request_and_keeps_the_browser_signed_in() {
        let (hydra, seen) = fake_hydra_admin().await;
        let mut cfg = AppConfig::test_fixture();
        cfg.hydra.admin_url = hydra;
        let app = app_with(cfg).await;
        let (cookie, token, _) = enrolled_browser(&app, "http@x.test").await;
        let current = signed_in_session(app.backend.whoami(Some(&cookie)).await.unwrap());
        let identity = current.identity.as_ref().unwrap().id.clone();
        let (elsewhere, _, _) = app.signed_in(&identity).await;
        use crate::oauth::op_sessions;
        op_sessions::record(&app.db, "sid-here", &identity, &current.id, 86400)
            .await
            .unwrap();
        op_sessions::record(&app.db, "sid-elsewhere", &identity, &elsewhere, 86400)
            .await
            .unwrap();
        let id = settings_flow(&app, &cookie, "/settings/password").await;
        let resp = app
            .post(
                &format!("/self-service/settings?flow={id}"),
                &cookie,
                &format!("csrf_token={token}&method=password&password=violet+staircase+42"),
            )
            .await;
        assert_eq!(location(&resp), "http://localhost:3000/settings/password");
        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "password.changed");
        assert_eq!(rows[0].user_agent.as_deref(), Some("Mozilla/5.0 test"));
        assert!(!format!("{:?}", rows[0]).contains("violet"));
        assert!(matches!(
            app.backend.whoami(Some(&cookie)).await.unwrap(),
            WhoamiOutcome::Ok(_)
        ));
        let flow = app.flow(FlowKind::Settings, &id, &cookie).await;
        assert_eq!(flow.state, "success");

        let left: Vec<String> = op_sessions::rows_for_subject(&app.db, &identity)
            .await
            .unwrap()
            .login_sessions
            .into_iter()
            .map(|r| r.sid)
            .collect();
        assert_eq!(left, ["sid-here"], "the other browser's OP session ended");
        let seen = seen.lock().unwrap().clone();
        let revokes: Vec<&String> = seen.iter().filter(|r| r.starts_with("DELETE")).collect();
        assert_eq!(revokes.len(), 1, "{seen:?}");
        assert!(revokes[0].contains("sid=sid-elsewhere"), "{seen:?}");
        assert!(
            session::find_live(&app.db, &elsewhere)
                .await
                .unwrap()
                .is_some(),
            "identity sessions stay"
        );
    }

    #[tokio::test]
    async fn a_settings_submit_needs_a_live_session_of_an_active_identity() {
        let app = app().await;
        let body = |token: &str| {
            format!("csrf_token={token}&method=password&password=violet+staircase+42")
        };
        for revoke in [true, false] {
            let email = if revoke { "rev@x.test" } else { "off@x.test" };
            let (cookie, token, _) = enrolled_browser(&app, email).await;
            let session = signed_in_session(app.backend.whoami(Some(&cookie)).await.unwrap());
            let identity = session.identity.as_ref().unwrap().id.clone();
            let id = settings_flow(&app, &cookie, "/settings/password").await;
            if revoke {
                session::revoke(&app.db, &session.id, None).await.unwrap();
            } else {
                store::set_state(
                    &app.db,
                    &identity,
                    crate::backend::identity::IdentityState::Inactive,
                )
                .await
                .unwrap();
            }
            let before = store::credential(&app.db, &identity, "password")
                .await
                .unwrap()
                .unwrap();
            let resp = app
                .post(
                    &format!("/self-service/settings?flow={id}"),
                    &cookie,
                    &body(&token),
                )
                .await;
            assert_eq!(location(&resp), "/login?return_to=%2Fsettings", "{email}");
            let after = store::credential(&app.db, &identity, "password")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.version, before.version, "{email}");
        }
        assert!(audit_rows(&app.db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn settings_submits_over_the_per_ip_limit_get_a_plain_429() {
        let app = app().await;
        let uri = "/self-service/settings?flow=unknown";
        for _ in 0..SETTINGS_IP_RATE_PER_MINUTE {
            assert_eq!(app.post(uri, "", "").await.status(), StatusCode::SEE_OTHER);
        }
        let limited = app.post(uri, "", "").await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key("retry-after"));
        let elsewhere = app.post_from("198.51.100.4", uri, "", "").await;
        assert_eq!(elsewhere.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn totp_enrolment_over_http_sets_the_raised_session_cookie() {
        use crate::identity_native::test_support::{identity_with_password, totp_code};
        let app = app().await;
        let identity = identity_with_password(&app.db, "enrol@x.test", true).await;
        let (_, cookie, token) = app.signed_in(&identity).await;
        let id = settings_flow(&app, &cookie, "/settings/2fa").await;
        let flow = app.flow(FlowKind::Settings, &id, &cookie).await;
        let secret = base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            flow.totp_secret.as_deref().unwrap(),
        )
        .unwrap();
        let code = totp_code(&secret, crate::identity_native::totp::unix_now());
        let resp = app
            .post(
                &format!("/self-service/settings?flow={id}"),
                &cookie,
                &format!("csrf_token={token}&totp_code={code}&method=totp"),
            )
            .await;
        assert_eq!(location(&resp), "http://localhost:3000/settings/2fa");
        let raised = format!(
            "forseti_session={}; forseti_csrf={token}",
            session_cookie(&resp).expect("a new session cookie")
        );
        let WhoamiOutcome::Ok(session) = app.backend.whoami(Some(&raised)).await.unwrap() else {
            panic!("the raised session is live");
        };
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal2));
        assert!(matches!(
            app.backend.whoami(Some(&cookie)).await.unwrap(),
            WhoamiOutcome::None
        ));
        let actions: Vec<String> = audit_rows(&app.db)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert_eq!(actions, ["mfa.totp.enrolled"]);
    }

    #[tokio::test]
    async fn logout_needs_the_session_logout_token() {
        let app = app().await;
        let identity = app.user("out@example.com").await;
        let (session_id, cookie, _) = app.signed_in(&identity).await;
        let url = app
            .backend
            .fetch_logout_url(&cookie)
            .await
            .unwrap()
            .unwrap();

        let bad = app.get("/self-service/logout?token=00ff", &cookie).await;
        assert_eq!(location(&bad), "/error?id=security_csrf_violation");
        assert!(
            set_cookies(&bad)
                .iter()
                .all(|c| !c.starts_with("forseti_session="))
        );
        assert!(matches!(
            app.backend.whoami(Some(&cookie)).await.unwrap(),
            WhoamiOutcome::Ok(_)
        ));

        let good = app.get(&url, &cookie).await;
        assert_eq!(location(&good), "/login");
        assert!(
            set_cookies(&good)
                .iter()
                .any(|c| c.starts_with("forseti_session=;") && c.contains("1970"))
        );
        assert!(matches!(
            app.backend.whoami(Some(&cookie)).await.unwrap(),
            WhoamiOutcome::None
        ));
        let session = app.backend.admin_get_session(&session_id).await.unwrap();
        assert_eq!(session.active, Some(false));

        let again = app.get(&url, &cookie).await;
        assert_eq!(location(&again), "/login", "already signed out");
    }

    #[tokio::test]
    async fn login_init_with_a_session_follows_refresh_and_aal() {
        let app = app().await;
        let identity = app.user("in@example.com").await;
        let (session_id, cookie, _) = app.signed_in(&identity).await;

        let resp = app
            .get("/self-service/login/browser?return_to=%2Fsettings", &cookie)
            .await;
        assert_eq!(location(&resp), "/settings", "already signed in");
        let resp = app.get("/self-service/registration/browser", &cookie).await;
        assert_eq!(location(&resp), "/");
        let resp = app.get("/self-service/recovery/browser", &cookie).await;
        assert_eq!(location(&resp), "/");

        let resp = app
            .get("/self-service/login/browser?refresh=true", &cookie)
            .await;
        let id = location(&resp)
            .strip_prefix("/login?flow=")
            .unwrap()
            .to_string();
        let row = app.row(&id).await;
        assert_eq!(row.identity_id.as_deref(), Some(identity.as_str()));
        assert_eq!(row.session_id.as_deref(), Some(session_id.as_str()));
        let flow = app.flow(FlowKind::Login, &id, &cookie).await;
        assert!(flow.refresh);
        assert_eq!(flow.requested_aal.as_deref(), Some("aal1"));
        let identifier = flow
            .inputs("default")
            .find(|i| i.name == "identifier")
            .unwrap();
        assert_eq!(
            (identifier.input_type.as_str(), identifier.value.as_str()),
            ("hidden", "in@example.com")
        );

        let resp = app
            .get("/self-service/login/browser?aal=aal2", &cookie)
            .await;
        let id = location(&resp)
            .strip_prefix("/login?flow=")
            .unwrap()
            .to_string();
        let flow = app.flow(FlowKind::Login, &id, &cookie).await;
        assert_eq!(flow.requested_aal.as_deref(), Some("aal2"));
        let names: Vec<&str> = flow.inputs.iter().map(|(_, i)| i.name.as_str()).collect();
        assert_eq!(names, ["csrf_token"], "no second factor to offer");
        assert_eq!(flow.messages[0].id, 1_010_004);

        app.add_totp(&identity).await;
        let flow = {
            let resp = app
                .get("/self-service/login/browser?aal=aal2", &cookie)
                .await;
            let id = location(&resp)
                .strip_prefix("/login?flow=")
                .unwrap()
                .to_string();
            app.flow(FlowKind::Login, &id, &cookie).await
        };
        assert!(flow.inputs("totp").any(|i| i.name == "totp_code"));

        let anonymous = app
            .get("/self-service/login/browser?aal=aal2&refresh=true", "")
            .await;
        let id = location(&anonymous)
            .strip_prefix("/login?flow=")
            .unwrap()
            .to_string();
        let row = app.row(&id).await;
        assert_eq!(
            (row.requested_aal.as_deref(), row.refresh),
            (Some("aal1"), 0)
        );
    }

    #[tokio::test]
    async fn settings_flows_belong_to_one_session_and_need_aal2_with_totp() {
        let app = app().await;
        let identity = app.user("set@example.com").await;
        let (session_id, cookie, _) = app.signed_in(&identity).await;
        let (_, other_session, _) = app.signed_in(&identity).await;

        let resp = app
            .get(
                "/self-service/settings/browser?return_to=http%3A%2F%2Flocalhost%3A3000%2Fsettings%2F2fa",
                &cookie,
            )
            .await;
        let id = location(&resp)
            .strip_prefix("/settings?flow=")
            .unwrap()
            .to_string();
        let row = app.row(&id).await;
        assert_eq!(row.session_id.as_deref(), Some(session_id.as_str()));
        assert_eq!(row.binding, None);
        assert!(row.context.contains("pending_totp"));

        let flow = app.flow(FlowKind::Settings, &id, &cookie).await;
        assert_eq!(flow.request_return_to, "http://localhost:3000/settings/2fa");
        assert_eq!(flow.state, "show_form");
        assert!(
            flow.totp_qr
                .as_deref()
                .unwrap()
                .starts_with("data:image/svg+xml;base64,")
        );
        let secret = flow.totp_secret.clone().unwrap();
        assert_eq!(secret.len(), 32);
        assert!(
            !row.context.contains(&secret),
            "the pending secret is sealed"
        );
        let again = app.flow(FlowKind::Settings, &id, &cookie).await;
        assert_eq!(again.totp_secret, Some(secret), "stable across renders");
        assert!(!flow.has_node("lookup_secret", "lookup_secret"));
        let profile: Vec<(&str, &str)> = flow
            .inputs("profile")
            .map(|i| (i.name.as_str(), i.value.as_str()))
            .collect();
        assert!(profile.contains(&("traits.email", "set@example.com")));
        assert!(profile.contains(&("traits.name.first", "Ann")));
        let creds = app
            .backend
            .admin_get_identity(&identity)
            .await
            .unwrap()
            .credentials;
        assert!(
            creds.is_none(),
            "enrolment stores nothing in identity_credentials"
        );

        assert!(matches!(
            app.fetch(FlowKind::Settings, &id, &other_session).await,
            FlowFetch::Gone
        ));
        assert!(matches!(
            app.fetch(FlowKind::Settings, &id, "").await,
            FlowFetch::Gone
        ));

        app.add_totp(&identity).await;
        assert!(matches!(
            app.fetch(FlowKind::Settings, &id, &cookie).await,
            FlowFetch::PrivilegedRequired(PrivilegedReason::Aal2Required)
        ));
        let resp = app.get("/self-service/settings/browser", &cookie).await;
        assert_eq!(location(&resp), "/login?aal=aal2&return_to=%2Fsettings");
        let post = app
            .post(&format!("/self-service/settings?flow={id}"), &cookie, "")
            .await;
        assert_eq!(location(&post), "/login?aal=aal2&return_to=%2Fsettings");

        let held = session::find_live(&app.db, &session_id)
            .await
            .unwrap()
            .unwrap();
        let session::StepUp::Rotated(token) = session::step_up(&app.db, &held, "totp", Aal::Aal2)
            .await
            .unwrap()
        else {
            panic!("live session rotates");
        };
        let csrf = cookie.split("forseti_csrf=").nth(1).unwrap();
        let stepped = format!("forseti_session={token}; forseti_csrf={csrf}");
        let flow = app.flow(FlowKind::Settings, &id, &stepped).await;
        assert!(flow.has_node("totp", "totp_unlink"));
        assert!(flow.totp_qr.is_none());
        assert!(flow.has_node("lookup_secret", "lookup_secret_regenerate"));

        let post = app
            .post(
                &format!("/self-service/settings?flow={id}"),
                &stepped,
                &format!("csrf_token={csrf}"),
            )
            .await;
        assert_eq!(location(&post), format!("/settings?flow={id}"));
        let post = app
            .post(&format!("/self-service/settings?flow={id}"), "", "")
            .await;
        assert_eq!(location(&post), "/login?return_to=%2Fsettings");
    }

    fn session_cookie(resp: &Response) -> Option<String> {
        set_cookies(resp).iter().find_map(|c| {
            c.strip_prefix("forseti_session=")
                .map(|rest| rest.split(';').next().unwrap().to_string())
                .filter(|v| !v.is_empty())
        })
    }

    async fn audit_rows(db: &DbPool) -> anyhow::Result<Vec<crate::audit::AuditRow>> {
        use crate::schema::audit_events;
        Ok(crate::db_interact!(db, |c| {
            audit_events::table
                .select(crate::audit::AuditRow::as_select())
                .order(audit_events::created_at)
                .load(c)
        })?)
    }

    fn password_body(token: &str, identifier: &str, password: &str) -> String {
        format!(
            "csrf_token={token}&method=password&identifier={}&password={}",
            crate::web::urlencode(identifier),
            crate::web::urlencode(password)
        )
    }

    #[tokio::test]
    async fn a_password_sign_in_returns_to_the_oauth_challenge_with_a_session_and_an_audit_row() {
        use crate::identity_native::test_support::{PASSWORD, identity_with_password};
        let app = app().await;
        let identity = identity_with_password(&app.db, "router@x.test", true).await;
        let target = "http://localhost:3000/oauth/login?login_challenge=abc";
        let query = format!("?return_to={}", crate::web::urlencode(target));
        let (id, cookie, token) = app.start("login", &query).await;
        let resp = app
            .post(
                &format!("/self-service/login?flow={id}"),
                &cookie,
                &password_body(&token, "router@x.test", PASSWORD),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), target);
        let session = session_cookie(&resp).expect("session cookie");
        assert!(set_cookies(&resp).iter().any(|c| c.contains("HttpOnly")));
        let signed_in = format!("{cookie}; forseti_session={session}");
        assert!(matches!(
            app.backend.whoami(Some(&signed_in)).await.unwrap(),
            WhoamiOutcome::Ok(_)
        ));

        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.action, "auth.login");
        assert!(row.succeeded());
        assert_eq!(row.actor_id.as_deref(), Some(identity.as_str()));
        assert_eq!(row.actor_email.as_deref(), Some("router@x.test"));
        assert_eq!(row.user_agent.as_deref(), Some("Mozilla/5.0 test"));
        assert!(row.ip_hash.is_some());
        let meta: serde_json::Value = serde_json::from_str(&row.metadata).unwrap();
        assert_eq!(meta["flow_id"], id.as_str());
        assert_eq!(meta["method"], "password");
        let whole = format!("{row:?}");
        assert!(!whole.contains(PASSWORD) && !whole.contains(&session));
    }

    #[tokio::test]
    async fn unknown_and_wrong_password_answers_match_over_http() {
        use crate::identity_native::test_support::{PASSWORD, identity_with_password};
        let app = app().await;
        identity_with_password(&app.db, "real@x.test", true).await;
        let mut answers = Vec::new();
        for (identifier, password) in [
            ("ghost@x.test", PASSWORD),
            ("real@x.test", "wrong horse battery"),
        ] {
            let (id, cookie, token) = app.start("login", "").await;
            let resp = app
                .post(
                    &format!("/self-service/login?flow={id}"),
                    &cookie,
                    &password_body(&token, identifier, password),
                )
                .await;
            assert!(session_cookie(&resp).is_none());
            let flow = app.flow(FlowKind::Login, &id, &cookie).await;
            let messages: Vec<(u64, String)> = flow
                .messages
                .iter()
                .map(|m| (m.id, m.text.clone()))
                .collect();
            answers.push((
                resp.status(),
                location(&resp).replace(&id, "<flow>"),
                messages,
            ));
        }
        assert_eq!(answers[0], answers[1]);
        assert_eq!(answers[0].2[0].0, 4_000_006);

        let rows = audit_rows(&app.db).await.unwrap();
        let failed: Vec<_> = rows
            .iter()
            .filter(|r| r.action == "auth.login_failed")
            .collect();
        assert_eq!(failed.len(), 2);
        for row in failed {
            assert!(!row.succeeded());
            let whole = format!("{row:?}");
            assert!(!whole.contains(PASSWORD) && !whole.contains("wrong horse"));
            assert!(!whole.contains("ghost@x.test"), "no typed identifier");
        }
    }

    #[tokio::test]
    async fn login_submits_over_the_per_ip_limit_get_a_plain_429() {
        let mut cfg = AppConfig::test_fixture();
        cfg.identity.login_ip_rate_per_minute = 2;
        let app = app_with(cfg).await;
        let (id, cookie, token) = app.start("login", "").await;
        let uri = format!("/self-service/login?flow={id}");
        let body = format!("csrf_token={token}&method=password&identifier=a&password=b");
        for _ in 0..2 {
            let resp = app.post(&uri, &cookie, &body).await;
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        }
        let limited = app.post(&uri, &cookie, &body).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key("retry-after"));
        let elsewhere = app.post_from("198.51.100.4", &uri, &cookie, &body).await;
        assert_eq!(elsewhere.status(), StatusCode::SEE_OTHER);

        let (other, cookie, token) = app.start("recovery", "").await;
        let resp = app
            .post(
                &format!("/self-service/recovery?flow={other}"),
                &cookie,
                &format!("csrf_token={token}"),
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "only login is limited"
        );
    }

    #[tokio::test]
    async fn a_totp_step_up_over_http_moves_the_browser_to_a_new_cookie() {
        use crate::identity_native::test_support::{
            PASSWORD, identity_with_password, plant_totp, totp_code,
        };
        let app = app().await;
        let identity = identity_with_password(&app.db, "step@x.test", true).await;
        let secret = plant_totp(&app.backend, &identity).await;
        let (id, cookie, token) = app.start("login", "?return_to=%2Fsettings").await;
        let resp = app
            .post(
                &format!("/self-service/login?flow={id}"),
                &cookie,
                &password_body(&token, "step@x.test", PASSWORD),
            )
            .await;
        assert_eq!(location(&resp), "/settings");
        let aal1 = format!(
            "{cookie}; forseti_session={}",
            session_cookie(&resp).unwrap()
        );
        assert!(matches!(
            app.backend.whoami(Some(&aal1)).await.unwrap(),
            WhoamiOutcome::InsufficientAal
        ));

        let resp = app
            .get(
                "/self-service/login/browser?aal=aal2&return_to=%2Fsettings",
                &aal1,
            )
            .await;
        let id = location(&resp)
            .strip_prefix("/login?flow=")
            .expect("a second-factor flow")
            .to_string();
        let code = totp_code(&secret, crate::identity_native::totp::unix_now());
        let resp = app
            .post(
                &format!("/self-service/login?flow={id}"),
                &aal1,
                &format!("csrf_token={token}&method=totp&totp_code={code}"),
            )
            .await;
        assert_eq!(location(&resp), "/settings");
        let aal2 = format!(
            "{cookie}; forseti_session={}",
            session_cookie(&resp).unwrap()
        );
        assert!(matches!(
            app.backend.whoami(Some(&aal1)).await.unwrap(),
            WhoamiOutcome::None
        ));
        let WhoamiOutcome::Ok(session) = app.backend.whoami(Some(&aal2)).await.unwrap() else {
            panic!("the new cookie carries the session");
        };
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal2));
        let actions: Vec<String> = audit_rows(&app.db)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert_eq!(actions, ["auth.login"]);
    }

    #[test]
    fn a_redirect_outcome_sets_its_cookies() {
        let resp = respond(
            FlowKind::Login,
            "f",
            SubmitOutcome::Redirect {
                location: "/next".into(),
                set_cookies: vec!["a=1; Path=/".into(), "b=2; Path=/".into()],
            },
        );
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/next");
        assert_eq!(set_cookies(&resp), ["a=1; Path=/", "b=2; Path=/"]);
        let page = respond(FlowKind::Settings, "f 1", SubmitOutcome::Page);
        assert_eq!(location(&page), "/settings?flow=f+1");
    }

    #[tokio::test]
    async fn the_error_table_answers_the_error_page() {
        let app = app().await;
        let e = app
            .backend
            .get_self_service_error("security_csrf_violation")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e.id.as_deref(), Some("security_csrf_violation"));
        assert!(
            app.backend
                .get_self_service_error("other")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn init_is_limited_per_ip_and_registration_init_follows_the_registration_limits() {
        let mut cfg = AppConfig::test_fixture();
        cfg.auth.registration_ip_rate_per_minute = Some(2);
        let app = app_with(cfg).await;
        for _ in 0..2 {
            let resp = app.get("/self-service/registration/browser", "").await;
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        }
        let limited = app.get("/self-service/registration/browser", "").await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        for _ in 0..INIT_IP_RATE_PER_MINUTE {
            let resp = app.get("/self-service/login/browser", "").await;
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        }
        let limited = app.get("/self-service/recovery/browser", "").await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key("retry-after"));
        let elsewhere = app
            .get_from("198.51.100.4", "/self-service/login/browser", "")
            .await;
        assert_eq!(elsewhere.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn init_drops_an_oversized_return_to() {
        let app = app().await;
        let path = format!("/settings/{}", "a".repeat(RETURN_TO_MAX_BYTES));
        let query = format!("?return_to={}", crate::web::urlencode(&path));
        let (id, _, _) = app.start("login", &query).await;
        assert_eq!(app.row(&id).await.return_to, None);
        let fits = format!("/settings/{}", "a".repeat(RETURN_TO_MAX_BYTES - 10));
        let query = format!("?return_to={}", crate::web::urlencode(&fits));
        let (id, _, _) = app.start("login", &query).await;
        assert_eq!(app.row(&id).await.return_to, Some(fits));
    }

    #[tokio::test]
    async fn code_submits_over_the_per_ip_limit_get_a_plain_429() {
        let app = app().await;
        let (id, cookie, token) = app.start("verification", "").await;
        let uri = format!("/self-service/verification?flow={id}");
        let body = format!("csrf_token={token}&method=code&email=x%40x.test");
        for _ in 0..CODE_IP_RATE_PER_MINUTE {
            assert_eq!(
                app.post(&uri, &cookie, &body).await.status(),
                StatusCode::SEE_OTHER
            );
        }
        let limited = app.post(&uri, &cookie, &body).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let (recovery, cookie, token) = app.start("recovery", "").await;
        let limited = app
            .post(
                &format!("/self-service/recovery?flow={recovery}"),
                &cookie,
                &format!("csrf_token={token}"),
            )
            .await;
        assert_eq!(
            limited.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "verification and recovery share the buckets"
        );
        let elsewhere = app.post_from("198.51.100.4", &uri, &cookie, &body).await;
        assert_eq!(elsewhere.status(), StatusCode::SEE_OTHER);
        let link = app
            .get(
                &format!("/self-service/verification?flow={id}&code=123456"),
                "",
            )
            .await;
        assert_eq!(
            link.status(),
            StatusCode::SEE_OTHER,
            "the mail link is not limited"
        );
    }

    #[tokio::test]
    async fn a_submit_the_minute_bucket_refuses_keeps_its_hour_token() {
        let app = app().await;
        let (id, cookie, token) = app.start("verification", "").await;
        let uri = format!("/self-service/verification?flow={id}");
        let body = format!("csrf_token={token}&method=code&email=x%40x.test");
        let mut last = None;
        for _ in 0..=CODE_IP_RATE_PER_HOUR {
            last = Some(app.post(&uri, &cookie, &body).await);
        }
        let last = last.unwrap();
        assert_eq!(last.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = last.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            retry <= 60 / u64::from(CODE_IP_RATE_PER_MINUTE),
            "refused by the minute bucket, the hour bucket still has tokens: {retry}"
        );
    }

    #[tokio::test]
    async fn an_unmatched_path_is_a_404_and_spends_no_budget() {
        let app = app().await;
        // The auth router merged into the test app still counts its fallback against its 30/min.
        for _ in 0..=CODE_IP_RATE_PER_MINUTE {
            for uri in ["/self-service/nothing", "/self-service/recovery/nothing"] {
                assert_eq!(app.post(uri, "", "").await.status(), StatusCode::NOT_FOUND);
                assert_eq!(app.get(uri, "").await.status(), StatusCode::NOT_FOUND);
            }
        }
        let (id, cookie, token) = app.start("verification", "").await;
        let uri = format!("/self-service/verification?flow={id}");
        let body = format!("csrf_token={token}&method=code&email=x%40x.test");
        for _ in 0..CODE_IP_RATE_PER_MINUTE {
            assert_eq!(
                app.post(&uri, &cookie, &body).await.status(),
                StatusCode::SEE_OTHER
            );
        }
        assert_eq!(
            app.post(&uri, &cookie, &body).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            app.post("/self-service/nothing", "", "").await.status(),
            StatusCode::NOT_FOUND,
            "an unmatched path is not limited either"
        );
    }

    #[tokio::test]
    async fn a_client_over_its_registration_limit_does_not_drain_the_global_one() {
        let mut cfg = AppConfig::test_fixture();
        cfg.auth.registration_ip_rate_per_minute = Some(2);
        cfg.auth.registration_global_rate_per_minute = Some(3);
        let app = app_with(cfg).await;
        let init = "/self-service/registration/browser";
        let noisy = "198.51.100.7";
        for expected in [
            StatusCode::SEE_OTHER,
            StatusCode::SEE_OTHER,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert_eq!(app.get_from(noisy, init, "").await.status(), expected);
        }
        assert_eq!(
            app.get_from("198.51.100.8", init, "").await.status(),
            StatusCode::SEE_OTHER,
            "the refused requests left the global bucket alone"
        );
        assert_eq!(
            app.get_from("198.51.100.9", init, "").await.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the global bucket still caps the total"
        );
    }

    #[tokio::test]
    async fn registration_submits_follow_the_registration_limits() {
        let mut cfg = AppConfig::test_fixture();
        cfg.auth.registration_ip_rate_per_minute = Some(3);
        let app = app_with(cfg).await;
        let (id, cookie, token) = app.start("registration", "").await;
        let uri = format!("/self-service/registration?flow={id}");
        let body = format!("csrf_token={token}&method=profile&traits.email=");
        for _ in 0..3 {
            assert_eq!(
                app.post(&uri, &cookie, &body).await.status(),
                StatusCode::SEE_OTHER
            );
        }
        let limited = app.post(&uri, &cookie, &body).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn opening_login_in_a_second_tab_keeps_the_first_tabs_flow() {
        let app = app().await;
        let (first, cookie, token) = app.start("login", "").await;
        let resp = app.get("/login", &cookie).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/self-service/login/browser");
        assert!(
            set_cookies(&resp)
                .iter()
                .all(|c| !c.starts_with("forseti_csrf=")),
            "the CSRF cookie is kept"
        );
        let resp = app.get(&location(&resp), &cookie).await;
        let second = location(&resp)
            .strip_prefix("/login?flow=")
            .unwrap()
            .to_string();
        assert_ne!(first, second);
        for id in [&first, &second] {
            let flow = app.flow(FlowKind::Login, id, &cookie).await;
            assert_eq!(flow.csrf_token.as_deref(), Some(token.as_str()));
        }
        let resp = app.get("/registration", &cookie).await;
        assert!(
            set_cookies(&resp)
                .iter()
                .all(|c| !c.starts_with("forseti_csrf="))
        );
    }

    #[tokio::test]
    async fn a_registration_over_http_signs_in_mails_a_code_and_verifies() {
        let app = app().await;
        let (id, cookie, token) = app.start("registration", "?return_to=%2Fsettings").await;
        let uri = format!("/self-service/registration?flow={id}");
        let resp = app
            .post(
                &uri,
                &cookie,
                &format!(
                    "csrf_token={token}&method=profile&traits.email=web%40x.test&traits.name.first=Web&traits.name.last=User"
                ),
            )
            .await;
        assert_eq!(location(&resp), format!("/registration?flow={id}"));
        let resp = app
            .post(
                &uri,
                &cookie,
                &format!(
                    "csrf_token={token}&method=password&password=violet+staircase+42&traits.email=web%40x.test"
                ),
            )
            .await;
        let verification = location(&resp)
            .strip_prefix("/verification?flow=")
            .expect("to the verification screen")
            .to_string();
        let session = session_cookie(&resp).expect("signed in");
        let signed_in = format!("{cookie}; forseti_session={session}");
        let WhoamiOutcome::Ok(who) = app.backend.whoami(Some(&signed_in)).await.unwrap() else {
            panic!("the session is live");
        };

        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "identity.created");
        assert_eq!(rows[0].actor_email.as_deref(), Some("web@x.test"));
        assert_eq!(rows[0].user_agent.as_deref(), Some("Mozilla/5.0 test"));
        let meta: serde_json::Value = serde_json::from_str(&rows[0].metadata).unwrap();
        assert_eq!(meta["kratos_session_id"], who.id.as_str());
        assert!(!format!("{:?}", rows[0]).contains("violet"));

        let mail = app.backend.mailed("web@x.test").await;
        assert_eq!(mail.len(), 1);
        let code = mail[0].code.clone();
        let link = mail[0].body.lines().nth(2).unwrap().to_string();
        let path = link.strip_prefix("http://localhost:3000").unwrap();
        let resp = app.get(path, &signed_in).await;
        assert_eq!(
            location(&resp),
            format!("/verification?flow={verification}&code={code}")
        );
        let flow = app
            .flow(FlowKind::Verification, &verification, &signed_in)
            .await;
        assert_eq!(flow.state, "sent_email");
        let prefilled = flow.inputs("code").find(|i| i.name == "code").unwrap();
        assert_eq!(prefilled.value, code);

        let resp = app
            .post(
                &format!("/self-service/verification?flow={verification}"),
                &signed_in,
                &format!("csrf_token={token}&method=code&code={code}"),
            )
            .await;
        assert_eq!(
            location(&resp),
            format!("/verification?flow={verification}")
        );
        let flow = app
            .flow(FlowKind::Verification, &verification, &signed_in)
            .await;
        assert_eq!(flow.state, "passed_challenge");
        assert_eq!(flow.return_to.as_deref(), Some("/settings"));
        let actions: Vec<String> = audit_rows(&app.db)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert_eq!(actions, ["identity.created", "verification.completed"]);
    }

    #[tokio::test]
    async fn a_recovery_over_http_signs_in_and_lands_on_the_password_page() {
        use crate::identity_native::test_support::identity_with_password;
        let app = app().await;
        identity_with_password(&app.db, "web-lost@x.test", true).await;
        let (id, cookie, token) = app.start("recovery", "").await;
        let uri = format!("/self-service/recovery?flow={id}");
        let resp = app
            .post(
                &uri,
                &cookie,
                &format!("csrf_token={token}&method=code&email=web-lost%40x.test"),
            )
            .await;
        assert_eq!(location(&resp), format!("/recovery?flow={id}"));
        let code = app.backend.mailed("web-lost@x.test").await[0].code.clone();
        let body = format!("csrf_token={token}&method=code&code={code}");
        let resp = app.post(&uri, &cookie, &body).await;
        let settings = location(&resp)
            .strip_prefix("/settings?flow=")
            .expect("to the settings handoff")
            .to_string();
        let session = session_cookie(&resp).expect("signed in");
        let signed_in = format!("{cookie}; forseti_session={session}");
        let flow = app.flow(FlowKind::Settings, &settings, &signed_in).await;
        assert!(flow.recovery_handoff);

        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "password.recovered");
        assert_eq!(rows[0].actor_email.as_deref(), Some("web-lost@x.test"));
        assert_eq!(rows[0].user_agent.as_deref(), Some("Mozilla/5.0 test"));
        let whole = format!("{:?}", rows[0]);
        assert!(!whole.contains(&code) && !whole.contains(&session));

        let again = app.post(&uri, &cookie, &body).await;
        assert_eq!(location(&again), "/error?id=self_service_flow_expired");
    }

    #[tokio::test]
    async fn the_admin_recovery_link_survives_a_link_preview_and_binds_on_the_first_submit() {
        use crate::identity_native::test_support::identity_with_password;
        let app = app().await;
        let identity = identity_with_password(&app.db, "helped@x.test", true).await;
        let minted = app
            .backend
            .admin_create_recovery_code(&identity)
            .await
            .unwrap();
        let link = minted
            .recovery_link
            .strip_prefix("http://localhost:3000")
            .unwrap()
            .to_string();
        let id = link.rsplit("flow=").next().unwrap().to_string();
        let page = format!("/self-service/recovery?flow={id}");

        // A chat unfurler or mail scanner: no cookies, follows the hop and reads the page.
        let preview = app.get(&link, "").await;
        assert_eq!(location(&preview), format!("/recovery?flow={id}"));
        let scanned = app.flow(FlowKind::Recovery, &id, "").await;
        assert_eq!(scanned.state, "sent_email");
        for (_, input) in &scanned.inputs {
            assert!(
                !input.value.contains("helped"),
                "an unbound flow shows no identity data: {} = {}",
                input.name,
                input.value
            );
        }
        assert!(
            scanned
                .inputs
                .iter()
                .any(|(_, i)| i.name == "email" && i.input_type == "submit")
        );
        assert_eq!(app.row(&id).await.binding, None, "a GET never binds");

        // The user's browser: the hop mints its CSRF cookie.
        let resp = app.get(&link, "").await;
        assert_eq!(location(&resp), format!("/recovery?flow={id}"));
        let token = csrf_cookie(&resp).expect("a CSRF cookie for the new browser");
        let cookie = format!("forseti_csrf={token}");
        assert_eq!(
            app.flow(FlowKind::Recovery, &id, &cookie).await.state,
            "sent_email"
        );
        let (_, elsewhere, other_token) = app.start("login", "").await;
        assert_eq!(
            app.flow(FlowKind::Recovery, &id, &elsewhere).await.state,
            "sent_email"
        );

        // A submit without a valid CSRF token binds nothing.
        let forged = app
            .post(
                &page,
                &elsewhere,
                "csrf_token=wrong&method=code&code=000000",
            )
            .await;
        assert_eq!(location(&forged), "/error?id=security_csrf_violation");
        assert_eq!(app.row(&id).await.binding, None);

        let wrong = format!(
            "{:06}",
            (minted.recovery_code.parse::<u32>().unwrap() + 1) % 1_000_000
        );
        let resp = app
            .post(
                &page,
                &cookie,
                &format!("csrf_token={token}&method=code&code={wrong}"),
            )
            .await;
        assert_eq!(location(&resp), format!("/recovery?flow={id}"));
        assert_eq!(
            app.row(&id).await.binding.as_deref(),
            Some(sha256_hex(&token).as_str()),
            "the first submit binds the flow"
        );

        let late = app
            .post(
                &page,
                &elsewhere,
                &format!(
                    "csrf_token={other_token}&method=code&code={}",
                    minted.recovery_code
                ),
            )
            .await;
        assert_eq!(location(&late), "/error?id=self_service_flow_expired");
        assert!(session_cookie(&late).is_none());
        assert!(matches!(
            app.fetch(FlowKind::Recovery, &id, &elsewhere).await,
            FlowFetch::Gone
        ));

        let resp = app
            .post(
                &page,
                &cookie,
                &format!(
                    "csrf_token={token}&method=code&code={}",
                    minted.recovery_code
                ),
            )
            .await;
        assert!(location(&resp).starts_with("/settings?flow="));
        assert!(session_cookie(&resp).is_some());
        assert!(app.backend.mailed("helped@x.test").await.is_empty());

        assert!(matches!(
            app.fetch(FlowKind::Recovery, &id, &cookie).await,
            FlowFetch::Gone
        ));
        assert_eq!(
            location(&app.get("/self-service/recovery", "").await),
            "/recovery"
        );
    }
}
