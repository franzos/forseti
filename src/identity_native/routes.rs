//! `/self-service/*`: flow init, form submits, the provider callback, the verification mail link,
//! the admin recovery link and logout.

use std::net::SocketAddr;

use axum::Extension;
use axum::Router;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::errors;
use super::flows::{
    AfterEffect, CallbackQuery, Dispatch, Form, InitOutcome, InitParams, Logout, SubmitOutcome,
    clear_state_cookie, kind_from_segment, page_url,
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
    // A provider sign-up creates an identity from the callback, so it spends the registration
    // submit buckets.
    let (registration_submit, creation) =
        registration(Router::new().route("/self-service/registration", post(submit)));
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
        .merge(per_ip(
            Router::new()
                .route(
                    "/self-service/methods/oidc/callback/{provider}",
                    get(callback),
                )
                .route_layer(Extension(creation)),
            INIT_IP_RATE_PER_MINUTE,
            INIT_IP_RATE_PER_HOUR,
            "provider callback",
        ))
        .merge(registration(Router::new().route("/self-service/registration/browser", get(init))).0)
        .merge(registration_submit)
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
            // The prefilled code is sealed on the flow for this browser, so it survives the
            // sign-in or second factor without riding on the return URL.
            match state.identity.address_change_detour(flow, &cookie).await {
                Ok(Some(detour)) => return Redirect::to(&detour).into_response(),
                Ok(None) => {}
                Err(e) => return failure(&state, &locale, &e),
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

/// The device a request comes from, as sessions record it.
fn device_of<'a>(
    state: &AppState,
    headers: &'a HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Device<'a> {
    let peer = peer.map(|Extension(ConnectInfo(addr))| addr.ip());
    Device {
        ip: crate::client_ip::client_ip(headers, &state.cfg.proxy, peer),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    }
}

/// `GET /self-service/methods/oidc/callback/{provider}`: the provider's redirect back. An answer
/// clears the state cookie once the cookie and `state` verified (RFC 9700 4.2.4); a request that
/// fails before that leaves it for the genuine callback.
#[allow(clippy::too_many_arguments)]
async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    query: Result<Query<CallbackQuery>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Extension(creation): Extension<rate_limit::SharedBuckets>,
    ReqLocale(locale): ReqLocale,
    audit: AuditCtx,
) -> Response {
    let query = query.map(|Query(q)| q).unwrap_or_default();
    let device = device_of(&state, &headers, peer);
    let answer = state
        .identity
        .upstream_callback(&provider, &query, &headers, device, &creation)
        .await;
    let Some(answer) = answer.transpose() else {
        return Redirect::to(&errors::url(errors::CSRF_VIOLATION)).into_response();
    };
    let mut resp = match answer {
        Ok(Dispatch::Done(done)) => {
            for event in done.audit {
                let _ = crate::audit::log(&state.db, event.with_ctx(&audit)).await;
            }
            match done.outcome {
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
                SubmitOutcome::Page => {
                    Redirect::to(&errors::url(errors::FLOW_EXPIRED)).into_response()
                }
            }
        }
        Ok(Dispatch::Expired) => Redirect::to(&errors::url(errors::FLOW_EXPIRED)).into_response(),
        Ok(Dispatch::Forged) => Redirect::to(&errors::url(errors::CSRF_VIOLATION)).into_response(),
        Ok(Dispatch::SignIn(to)) => Redirect::to(&to).into_response(),
        Ok(Dispatch::TooManyRequests(retry_after)) => rate_limit::too_many_requests(retry_after),
        Err(e) => failure(&state, &locale, &e),
    };
    crate::web::append_set_cookie(
        &mut resp,
        Some(clear_state_cookie(state.cfg.self_.is_https())),
    );
    resp
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
    let device = device_of(&state, &headers, peer);
    match state
        .identity
        .submit_flow(kind, &id, &form, &cookie, csrf_valid, device)
        .await
    {
        Ok(Dispatch::Done(done)) => {
            for event in done.audit {
                let _ = crate::audit::log(&state.db, event.with_ctx(&audit)).await;
            }
            let ended = match &done.after {
                Some(AfterEffect::PasswordChanged {
                    identity_id,
                    session_id,
                }) => Some((identity_id, Some(session_id.as_str()))),
                Some(AfterEffect::AccountReset { identity_id }) => Some((identity_id, None)),
                None => None,
            };
            if let Some((identity_id, kept)) = ended {
                let all = crate::oauth::op_sessions::end_op_sessions_for_subject(
                    &state.db,
                    &state.oauth,
                    identity_id,
                    kept,
                    crate::oauth::op_sessions::GrantRevocation::Revoke,
                )
                .await;
                // A later recovery is no reset, so nothing retries this.
                if !all && kept.is_none() {
                    tracing::error!(identity_id = %identity_id, "OAuth sessions and grants of a reset identity not fully ended");
                } else if !all {
                    tracing::warn!(identity_id = %identity_id, "password changed, but the other browsers' OAuth sessions and grants were not all ended");
                }
                if !all {
                    let event =
                        crate::audit::AuditEvent::new(crate::audit::action::SESSIONS_BULK_REVOKED)
                            .target(crate::audit::target_kind::IDENTITY, identity_id.as_str())
                            .with_ctx(&audit)
                            .metadata(crate::audit_metadata!("op_sessions_revoked" => false))
                            .failed("OAuth sessions and grants not all ended");
                    let _ = crate::audit::log(&state.db, event).await;
                }
            }
            respond(kind, &id, done.outcome)
        }
        Ok(Dispatch::Expired) => Redirect::to(&errors::url(errors::FLOW_EXPIRED)).into_response(),
        Ok(Dispatch::Forged) => Redirect::to(&errors::url(errors::CSRF_VIOLATION)).into_response(),
        Ok(Dispatch::SignIn(to)) => Redirect::to(&to).into_response(),
        Ok(Dispatch::TooManyRequests(retry_after)) => rate_limit::too_many_requests(retry_after),
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
        app_with_github(cfg, None).await
    }

    /// An app whose GitHub providers talk to `github`.
    async fn app_with_github(
        cfg: AppConfig,
        github: Option<&crate::identity_native::test_support::GithubStub>,
    ) -> App {
        let db = test_pool().await;
        let backend = match github {
            Some(stub) => NativeBackend::with_github(&cfg, &db, SECRET, stub.urls()),
            None => NativeBackend::new(&cfg, &db, SECRET),
        };
        let router = super::router(&cfg)
            .merge(crate::auth::router(&cfg.proxy, &cfg.auth))
            .merge(crate::settings::router(&cfg))
            .merge(crate::admin::router());
        let csp = crate::app::CspSources {
            frame_ancestors: cfg.security.frame_ancestors.clone(),
            form_action: "'self'".to_string(),
        };
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
            .layer(axum::middleware::from_fn_with_state(
                csp,
                crate::app::strict_frame_for_sensitive,
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
            self.signed_in_by(identity_id, "password", None).await
        }

        /// [`signed_in`](Self::signed_in) with a session completed by `method` through `provider`.
        async fn signed_in_by(
            &self,
            identity_id: &str,
            method: &str,
            provider: Option<&str>,
        ) -> (String, String, String) {
            let issued = self
                .backend
                .issue_session(identity_id, method, provider, Aal::Aal1, Device::default())
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
        let session::StepUp::Rotated(session) =
            session::step_up(&app.db, &held, "totp", None, Aal::Aal2)
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

    #[cfg(feature = "oauth-ory")]
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
    async fn an_address_change_mail_link_sends_a_signed_out_browser_to_sign_in_first() {
        use crate::identity_native::codes::Purpose;
        let app = app().await;
        let identity = app.user("before@x.test").await;
        let (session, signed_in_cookie, _) = app.signed_in(&identity).await;
        let flow = app.backend.address_change_flow("after@x.test", &identity);
        let code = app.backend.mailed_code(
            &flow.row.id,
            Purpose::Verification,
            &identity,
            "after@x.test",
        );
        let writer = store::Writer {
            identity_id: &identity,
            session_id: &session,
            verified_only: false,
        };
        let change = store::AddressChange {
            email: "after@x.test".to_string(),
            verification: flow.row.clone(),
            code,
        };
        assert_eq!(
            store::update_profile(&app.db, writer, None, None, Some(change))
                .await
                .unwrap(),
            store::ProfileSaved::Saved
        );
        let mail = app.backend.mailed("after@x.test").await;
        let body = &mail[0].body;
        let at = body
            .find("/self-service/verification?flow=")
            .expect("a link");
        let link: String = body[at..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();

        let resp = app.get(&link, "").await;
        let page = format!("/verification?flow={}", flow.row.id);
        assert_eq!(
            location(&resp),
            format!("/login?return_to={}", crate::web::urlencode(&page))
        );
        assert!(
            !location(&resp).contains(&mail[0].code),
            "the code stays off the URL"
        );
        let rec = app.backend.load_flow(&flow.row.id).await.unwrap().unwrap();
        assert!(
            rec.ctx.prefill_code.is_some(),
            "the code waits on the flow for this browser"
        );

        let resp = app.get(&link, &signed_in_cookie).await;
        assert!(location(&resp).starts_with(&page), "{}", location(&resp));
        assert_eq!(
            store::row_by_id(&app.db, &identity)
                .await
                .unwrap()
                .unwrap()
                .email,
            "before@x.test",
            "following the link changes nothing"
        );
    }

    #[tokio::test]
    async fn an_address_change_of_a_totp_identity_steps_up_back_to_its_flow() {
        use crate::identity_native::codes::Purpose;
        let app = app().await;
        let identity = app.user("totp-before@x.test").await;
        app.add_totp(&identity).await;
        let (session, aal1_cookie, token) = app.signed_in(&identity).await;
        let flow = app
            .backend
            .address_change_flow("totp-after@x.test", &identity);
        let code = app.backend.mailed_code(
            &flow.row.id,
            Purpose::Verification,
            &identity,
            "totp-after@x.test",
        );
        let writer = store::Writer {
            identity_id: &identity,
            session_id: &session,
            verified_only: false,
        };
        let change = store::AddressChange {
            email: "totp-after@x.test".to_string(),
            verification: flow.row.clone(),
            code,
        };
        assert_eq!(
            store::update_profile(&app.db, writer, None, None, Some(change))
                .await
                .unwrap(),
            store::ProfileSaved::Saved
        );
        let mail = app.backend.mailed("totp-after@x.test").await;
        let body = &mail[0].body;
        let at = body
            .find("/self-service/verification?flow=")
            .expect("a link");
        let link: String = body[at..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        let step_up = crate::auth::aal2_step_up_url(&format!("/verification?flow={}", flow.row.id));

        let resp = app.get(&link, &aal1_cookie).await;
        assert_eq!(location(&resp), step_up);
        let submit_uri = format!("/self-service/verification?flow={}", flow.row.id);
        let body = format!("csrf_token={token}&method=code&code={}", mail[0].code);
        let resp = app.post(&submit_uri, &aal1_cookie, &body).await;
        assert_eq!(location(&resp), step_up);
        assert_eq!(
            store::row_by_id(&app.db, &identity)
                .await
                .unwrap()
                .unwrap()
                .email,
            "totp-before@x.test"
        );

        let held = session::find_live(&app.db, &session)
            .await
            .unwrap()
            .unwrap();
        let session::StepUp::Rotated(aal2) =
            session::step_up(&app.db, &held, "totp", None, Aal::Aal2)
                .await
                .unwrap()
        else {
            panic!("a live session rotates");
        };
        let aal2_cookie = format!("forseti_session={aal2}; forseti_csrf={token}");
        let rec = app.backend.load_flow(&flow.row.id).await.unwrap().unwrap();
        assert!(
            rec.ctx.prefill_code.is_some(),
            "the code waited on the flow"
        );
        let resp = app.post(&submit_uri, &aal2_cookie, &body).await;
        assert_eq!(
            location(&resp),
            format!("/verification?flow={}", flow.row.id)
        );
        let row = store::row_by_id(&app.db, &identity).await.unwrap().unwrap();
        assert_eq!(row.email, "totp-after@x.test");
        assert!(row.email_verified_at.is_some());
    }

    #[cfg(feature = "oauth-ory")]
    #[tokio::test]
    async fn a_recovery_reset_over_http_ends_every_op_session_and_grant() {
        use crate::identity_native::test_support::identity_with_password;
        use crate::oauth::op_sessions;
        let (hydra, seen) = fake_hydra_admin().await;
        let mut cfg = AppConfig::test_fixture();
        cfg.hydra.admin_url = hydra;
        let app = app_with(cfg).await;
        let identity = identity_with_password(&app.db, "squat@x.test", false).await;
        let (squatter, _, _) = app.signed_in(&identity).await;
        op_sessions::record(&app.db, "sid-squatter", &identity, &squatter, 86400)
            .await
            .unwrap();
        let (id, cookie, token) = app.start("recovery", "").await;
        let uri = format!("/self-service/recovery?flow={id}");
        let body = format!("csrf_token={token}&method=code&email=squat%40x.test");
        app.post(&uri, &cookie, &body).await;
        let code = app.backend.mailed("squat@x.test").await[0].code.clone();
        let body = format!("csrf_token={token}&method=code&code={code}");
        let resp = app.post(&uri, &cookie, &body).await;
        assert!(
            location(&resp).starts_with("/settings?flow="),
            "{}",
            location(&resp)
        );
        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "password.recovered");

        let left = op_sessions::rows_for_subject(&app.db, &identity)
            .await
            .unwrap()
            .login_sessions;
        assert!(left.is_empty(), "{left:?}");
        let seen = seen.lock().unwrap().clone();
        let revokes: Vec<&String> = seen.iter().filter(|r| r.starts_with("DELETE")).collect();
        assert!(
            revokes.iter().any(|r| r.contains("sid=sid-squatter")),
            "{seen:?}"
        );
        for kind in ["login", "consent"] {
            assert!(
                revokes
                    .iter()
                    .any(|r| r.contains(kind) && r.contains(&format!("subject={identity}"))),
                "{kind}: {seen:?}"
            );
        }
    }

    #[cfg(feature = "oauth-ory")]
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
        let session::StepUp::Rotated(token) =
            session::step_up(&app.db, &held, "totp", None, Aal::Aal2)
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

    const ISSUER: &str = "https://idp.example.com/realms/x";

    /// An app with an `oidc` provider `playground` at [`ISSUER`] and a GitHub provider `gh`.
    async fn app_with_providers() -> App {
        use crate::config::{OidcProviderConfig, OidcProviderKind};
        let provider = |id: &str, kind, issuer: Option<&str>| OidcProviderConfig {
            id: id.into(),
            kind,
            issuer: issuer.map(str::to_string),
            client_id: "forseti".into(),
            client_secret: Some("secret".into()),
            client_secret_env: None,
            scopes: None,
        };
        let mut cfg = AppConfig::test_fixture();
        cfg.identity.oidc_providers = vec![
            provider("playground", OidcProviderKind::Oidc, Some(ISSUER)),
            provider("gh", OidcProviderKind::Github, None),
        ];
        app_with(cfg).await
    }

    async fn body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn oidc_inputs(flow: &Flow) -> Vec<(String, String)> {
        flow.inputs("oidc")
            .map(|i| (i.name.clone(), i.value.clone()))
            .collect()
    }

    fn named(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[tokio::test]
    async fn sign_in_and_sign_up_offer_the_configured_providers_and_csp_allows_them() {
        let app = app_with_providers().await;
        assert_eq!(
            app.backend.probe_oidc_provider_ids().await.unwrap(),
            ["playground", "gh"]
        );
        for kind in ["login", "registration"] {
            let (id, cookie, _) = app.start(kind, "").await;
            let resp = app.get(&format!("/{kind}?flow={id}"), &cookie).await;
            assert_eq!(resp.status(), StatusCode::OK, "{kind}");
            let csp = resp.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .to_string();
            assert!(
                csp.ends_with("form-action 'self' https://idp.example.com https://github.com"),
                "{kind}: {csp}"
            );
            let html = body(resp).await;
            assert!(html.contains(r#"name="provider""#), "{kind}");
            assert!(html.contains(r#"value="playground""#), "{kind}");
            assert!(html.contains(r#"value="gh""#), "{kind}");
        }
        let (id, cookie, _) = app.start("login", "").await;
        assert_eq!(
            oidc_inputs(&app.flow(FlowKind::Login, &id, &cookie).await),
            [named("provider", "playground"), named("provider", "gh")]
        );
    }

    #[tokio::test]
    async fn without_providers_the_csp_gains_nothing() {
        let app = app().await;
        let (id, cookie, _) = app.start("login", "").await;
        let resp = app.get(&format!("/login?flow={id}"), &cookie).await;
        assert!(
            resp.headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_none()
        );
        assert!(
            app.backend
                .probe_oidc_provider_ids()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_refresh_login_offers_only_the_configured_oidc_providers_the_identity_is_linked_to() {
        let app = app_with_providers().await;
        let identity = app.user("refresh@x.test").await;
        for (provider, subject) in [("playground", "0"), ("gh", "1"), ("gone", "2")] {
            store::insert_link(&app.db, &identity, provider, subject)
                .await
                .unwrap();
        }
        let (_, cookie, _) = app.signed_in(&identity).await;
        let resp = app
            .get("/self-service/login/browser?refresh=true", &cookie)
            .await;
        let id = location(&resp)
            .strip_prefix("/login?flow=")
            .expect("a refresh login flow")
            .to_string();
        assert_eq!(app.row(&id).await.refresh, 1);
        assert_eq!(
            oidc_inputs(&app.flow(FlowKind::Login, &id, &cookie).await),
            [named("provider", "playground")]
        );
    }

    #[tokio::test]
    async fn the_email_needed_screen_asks_for_an_address_and_continues_with_the_provider() {
        let app = app_with_providers().await;
        let (id, cookie, _) = app.start("registration", "").await;
        let mut rec = app.backend.load_flow(&id).await.unwrap().unwrap();
        rec.ctx.email_needed = Some("playground".into());
        rec.ctx.traits = Some(super::super::flows::PendingTraits {
            email: "typed@x.test".into(),
            first: String::new(),
            last: String::new(),
        });
        assert_eq!(
            rec.save(&app.db).await.unwrap(),
            super::super::flows::Saved::Done
        );
        let flow = app.flow(FlowKind::Registration, &id, &cookie).await;
        assert_eq!(oidc_inputs(&flow), [named("provider", "playground")]);

        let html = body(app.get(&format!("/registration?flow={id}"), &cookie).await).await;
        assert!(html.contains("share a verified email address"), "{html}");
        assert!(html.contains(r#"name="traits.email""#));
        assert!(html.contains(r#"value="typed@x.test""#));
        assert!(!html.contains(r#"name="password""#));
    }

    /// The linked-providers page for `identity`, rendered from a fresh settings flow.
    async fn linked_providers_page(app: &App, identity: &str) -> String {
        let (_, cookie, _) = app.signed_in(identity).await;
        let id = settings_flow(app, &cookie, "/settings/linked-providers").await;
        let resp = app
            .get(&format!("/settings/linked-providers?flow={id}"), &cookie)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let csp = resp
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let html = body(resp).await;
        for (provider, origin) in [
            ("playground", "https://idp.example.com"),
            ("gh", "https://github.com"),
        ] {
            assert_eq!(
                csp.contains(origin),
                action(&html, "link", provider),
                "only a link hop leaves for the provider: {csp}"
            );
        }
        html
    }

    fn action(html: &str, name: &str, provider: &str) -> bool {
        let html = html.split_whitespace().collect::<Vec<_>>().join(" ");
        html.contains(&format!(r#"name="{name}" value="{provider}""#))
    }

    const BLOCKED: &str = "This is your only sign-in method.";

    #[tokio::test]
    async fn linked_providers_page_offers_link_unlink_or_the_blocked_note() {
        use crate::identity_native::test_support::{identity_with_password, plant_password};
        let app = app_with_providers().await;

        let fresh = identity_with_password(&app.db, "fresh@x.test", true).await;
        let html = linked_providers_page(&app, &fresh).await;
        assert!(action(&html, "link", "playground"));
        assert!(action(&html, "link", "gh"));
        assert!(!html.contains(BLOCKED));

        let sole = app.user("sole@x.test").await;
        store::insert_link(&app.db, &sole, "playground", "s1")
            .await
            .unwrap();
        let html = linked_providers_page(&app, &sole).await;
        assert!(!action(&html, "unlink", "playground"));
        assert!(html.contains(BLOCKED), "{html}");
        assert!(action(&html, "link", "gh"));

        plant_password(&app.db, &sole).await;
        let html = linked_providers_page(&app, &sole).await;
        assert!(action(&html, "unlink", "playground"));
        assert!(!html.contains(BLOCKED));

        let two = app.user("two@x.test").await;
        for (provider, subject) in [("playground", "t1"), ("gh", "t2")] {
            store::insert_link(&app.db, &two, provider, subject)
                .await
                .unwrap();
        }
        let html = linked_providers_page(&app, &two).await;
        assert!(action(&html, "unlink", "playground"));
        assert!(action(&html, "unlink", "gh"));
        assert!(!html.contains(BLOCKED));
    }

    #[tokio::test]
    async fn the_sole_sign_in_fact_counts_only_configured_links_and_a_password() {
        use crate::identity_native::test_support::plant_password;
        let app = app_with_providers().await;
        let fact = |links: &'static [&'static str], password: bool| {
            let app = &app;
            async move {
                let id = app
                    .user(&format!("u{}@x.test", uuid::Uuid::new_v4().simple()))
                    .await;
                for provider in links {
                    let inserted = store::insert_link(&app.db, &id, provider, &id)
                        .await
                        .unwrap();
                    assert_eq!(inserted, store::LinkInserted::Linked);
                }
                if password {
                    plant_password(&app.db, &id).await;
                }
                app.backend
                    .admin_get_identity_full(&id)
                    .await
                    .unwrap()
                    .sole_sign_in_is_oidc
            }
        };
        assert_eq!(fact(&[], false).await, Some(false));
        assert_eq!(fact(&["gh"], false).await, Some(true));
        assert_eq!(fact(&["gone"], false).await, Some(true));
        assert_eq!(fact(&["gh", "gone"], false).await, Some(true));
        assert_eq!(fact(&["gh", "playground"], false).await, Some(false));
        assert_eq!(fact(&["gh"], true).await, Some(false));
    }

    use crate::identity_native::test_support::OidcStub;

    const STATE_COOKIE: &str = "forseti_upstream_state";

    /// An app whose providers are `stub` (and `other`, when `two`) at the OIDC stub.
    async fn stub_app(stub: &OidcStub, two: bool) -> App {
        let mut cfg = AppConfig::test_fixture();
        cfg.oauth.cimd.allow_private_targets = true;
        cfg.identity.oidc_providers = vec![stub.provider_config("stub")];
        if two {
            cfg.identity
                .oidc_providers
                .push(stub.provider_config("other"));
        }
        app_with(cfg).await
    }

    /// A provider hop started from a fresh flow.
    struct Hop {
        flow: String,
        provider: String,
        /// The browser's cookie header, the state cookie included.
        cookie: String,
        authorize: url::Url,
        /// The `Set-Cookie` line of the state cookie.
        set_cookie: String,
    }

    impl Hop {
        fn state(&self) -> String {
            self.authorize
                .query_pairs()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.into_owned())
                .unwrap()
        }

        /// The callback URI for `provider` with `query` appended to `state`.
        fn callback_at(&self, provider: &str, query: &str) -> String {
            format!(
                "/self-service/methods/oidc/callback/{provider}?state={}{query}",
                crate::web::urlencode(self.state())
            )
        }

        fn callback(&self, query: &str) -> String {
            self.callback_at(&self.provider, query)
        }
    }

    /// Start a `kind` flow (`query` on its init) and press the `provider` button.
    async fn start_hop(app: &App, kind: &str, query: &str, provider: &str) -> Hop {
        let (flow, cookie, token) = app.start(kind, query).await;
        let body = format!("csrf_token={token}&provider={provider}");
        press(app, kind, &flow, &cookie, &body, provider).await
    }

    /// Post `body` on the `kind` flow in the browser holding `cookie`: the provider hop it answers.
    async fn press(
        app: &App,
        kind: &str,
        flow: &str,
        cookie: &str,
        body: &str,
        provider: &str,
    ) -> Hop {
        let resp = app
            .post(&format!("/self-service/{kind}?flow={flow}"), cookie, body)
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let flow = flow.to_string();
        let authorize = url::Url::parse(&location(&resp)).expect("a redirect to the provider");
        let set_cookie = set_cookies(&resp)
            .into_iter()
            .find(|c| c.starts_with(&format!("{STATE_COOKIE}=")))
            .expect("the state cookie");
        let value = set_cookie.split(';').next().unwrap().to_string();
        Hop {
            flow,
            provider: provider.to_string(),
            cookie: format!("{cookie}; {value}"),
            authorize,
            set_cookie,
        }
    }

    /// The callback for a code the stub issues for `claims`.
    async fn stub_callback(
        app: &App,
        stub: &OidcStub,
        hop: &Hop,
        claims: serde_json::Value,
    ) -> Response {
        let code = stub.issue(&hop.authorize, claims);
        app.get(&hop.callback(&format!("&code={code}")), &hop.cookie)
            .await
    }

    fn clears_state_cookie(resp: &Response) -> bool {
        set_cookies(resp).iter().any(|c| {
            c.starts_with(&format!("{STATE_COOKIE}=;"))
                && c.contains("Path=/self-service/methods/oidc/callback")
                && c.contains("Expires=Thu, 01 Jan 1970")
        })
    }

    async fn flow_messages(app: &App, id: &str) -> Vec<u64> {
        let rec = app.backend.load_flow(id).await.unwrap().unwrap();
        rec.ctx.messages.iter().map(|m| m.id).collect()
    }

    /// A verified identity linked to the stub's default subject at `stub`.
    async fn linked_user(app: &App, email: &str, verified: bool) -> String {
        let id = store::create(&app.db, email, Some("Ann"), Some("Lee"), verified)
            .await
            .unwrap()
            .unwrap()
            .id;
        store::insert_link(&app.db, &id, "stub", "stub-subject")
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn a_linked_provider_account_signs_in_through_the_callback() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let identity = linked_user(&app, "linked@x.test", true).await;
        let hop = start_hop(&app, "login", "?return_to=%2Fsettings", "stub").await;
        assert!(
            hop.authorize
                .as_str()
                .starts_with(&format!("{}/authorize?", stub.issuer))
        );
        for attr in [
            "Path=/self-service/methods/oidc/callback",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=600",
        ] {
            assert!(hop.set_cookie.contains(attr), "{attr}: {}", hop.set_cookie);
        }
        assert!(!hop.set_cookie.contains("Secure"), "http self URL");
        let stored = app.backend.load_flow(&hop.flow).await.unwrap().unwrap();
        assert_eq!(stored.ctx.oidc_state.as_deref(), Some(hop.state().as_str()));

        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(location(&resp), "/settings");
        assert!(clears_state_cookie(&resp));
        let token = session_cookie(&resp).expect("a session cookie");
        let WhoamiOutcome::Ok(session) = app
            .backend
            .whoami(Some(&format!("forseti_session={token}")))
            .await
            .unwrap()
        else {
            panic!("the session is live");
        };
        assert_eq!(session.identity.unwrap().id, identity);
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal1));
        let methods = session.authentication_methods.unwrap();
        assert_eq!(methods[0].method.as_deref(), Some("oidc"));
        assert_eq!(methods[0].provider.as_deref(), Some("stub"));
        let row = app.row(&hop.flow).await;
        assert_eq!(row.state, "passed_challenge", "the flow is spent");

        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "auth.login");
        assert_eq!(rows[0].actor_id.as_deref(), Some(identity.as_str()));
        let meta: serde_json::Value = serde_json::from_str(&rows[0].metadata).unwrap();
        assert_eq!(meta["method"], "oidc");
        assert_eq!(meta["provider"], "stub");
        let whole = format!("{:?}", rows[0]);
        assert!(!whole.contains("stub-subject") && !whole.contains(&hop.state()));
        assert!(!whole.contains(&token));

        let hop = start_hop(&app, "registration", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(
            location(&resp),
            "/",
            "a registration flow signs the linked account in"
        );
        assert!(session_cookie(&resp).is_some());

        app.add_totp(&identity).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        let token = session_cookie(&resp).unwrap();
        assert!(
            matches!(
                app.backend
                    .whoami(Some(&format!("forseti_session={token}")))
                    .await
                    .unwrap(),
                WhoamiOutcome::InsufficientAal
            ),
            "TOTP still demands the second factor"
        );
    }

    #[tokio::test]
    async fn a_tampered_or_missing_state_cookie_is_a_csrf_violation() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        linked_user(&app, "tamper@x.test", true).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let code = stub.issue(&hop.authorize, serde_json::json!({}));
        let uri = hop.callback(&format!("&code={code}"));
        let mut tampered = hop.cookie.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(tampered).unwrap();
        let without = hop
            .cookie
            .split("; forseti_upstream")
            .next()
            .unwrap()
            .to_string();
        for cookie in [&tampered, &without] {
            let resp = app.get(&uri, cookie).await;
            assert_eq!(location(&resp), "/error?id=security_csrf_violation");
            assert!(
                no_state_cookie(&resp),
                "an unverified request leaves the cookie"
            );
            assert!(session_cookie(&resp).is_none());
        }
        assert!(
            stub.client_auth().is_empty(),
            "no exchange reached the provider"
        );
        let resp = app.get(&uri, &hop.cookie).await;
        assert_eq!(location(&resp), "/", "the genuine callback still works");
        assert!(clears_state_cookie(&resp));

        let hop = start_hop(&app, "login", "", "stub").await;
        app.expire(&hop.flow).await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(location(&resp), "/error?id=self_service_flow_expired");
        assert!(clears_state_cookie(&resp));
    }

    #[tokio::test]
    async fn a_callback_for_another_provider_or_state_is_refused() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, true).await;
        linked_user(&app, "paths@x.test", true).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let code = stub.issue(&hop.authorize, serde_json::json!({}));
        let code_q = format!("&code={code}");
        for uri in [
            hop.callback_at("other", &code_q),
            hop.callback_at("nope", &code_q),
            format!("/self-service/methods/oidc/callback/stub?state=other{code_q}"),
            format!("/self-service/methods/oidc/callback/stub?code={code}"),
        ] {
            let resp = app.get(&uri, &hop.cookie).await;
            assert_eq!(
                location(&resp),
                "/error?id=security_csrf_violation",
                "{uri}"
            );
            assert!(no_state_cookie(&resp), "{uri}");
        }
        assert!(stub.client_auth().is_empty());
        let resp = app.get(&hop.callback(&code_q), &hop.cookie).await;
        assert_eq!(location(&resp), "/");
        assert!(clears_state_cookie(&resp));

        let (_, foreign, _) = app.start("login", "").await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let state_cookie = hop.cookie.split("; ").last().unwrap();
        let resp = app
            .get(
                &hop.callback("&code=x"),
                &format!("{foreign}; {state_cookie}"),
            )
            .await;
        assert_eq!(
            location(&resp),
            "/error?id=security_csrf_violation",
            "another browser's flow"
        );
        assert!(
            clears_state_cookie(&resp),
            "the cookie and state verified before the flow check"
        );
    }

    #[tokio::test]
    async fn a_replayed_callback_never_reaches_the_provider() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(
            &app,
            &stub,
            &hop,
            serde_json::json!({"aud": "someone-else"}),
        )
        .await;
        assert_eq!(
            location(&resp),
            format!("/login?flow={}", hop.flow),
            "the flow stays usable"
        );
        assert_eq!(stub.client_auth().len(), 1);
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(location(&resp), "/error?id=security_csrf_violation");
        assert!(clears_state_cookie(&resp));
        assert_eq!(stub.client_auth().len(), 1, "the replay was not exchanged");

        linked_user(&app, "replay@x.test", true).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let code = stub.issue(&hop.authorize, serde_json::json!({}));
        let uri = hop.callback(&format!("&code={code}"));
        let resp = app.get(&uri, &hop.cookie).await;
        assert!(session_cookie(&resp).is_some());
        let again = app.get(&uri, &hop.cookie).await;
        assert_eq!(location(&again), "/error?id=self_service_flow_expired");
        assert!(session_cookie(&again).is_none());
        assert_eq!(stub.client_auth().len(), 2);
    }

    #[tokio::test]
    async fn the_iss_parameter_must_name_the_configured_issuer() {
        let stub = OidcStub::start().await;
        stub.set_iss_parameter(true);
        let app = stub_app(&stub, false).await;
        linked_user(&app, "iss@x.test", true).await;
        let iss = format!("&iss={}", crate::web::urlencode(&stub.issuer));
        for (extra, signed_in) in [
            (String::new(), false),
            ("&iss=https%3A%2F%2Fevil.example".to_string(), false),
            (iss, true),
        ] {
            let hop = start_hop(&app, "login", "", "stub").await;
            let before = stub.client_auth().len();
            let code = stub.issue(&hop.authorize, serde_json::json!({}));
            let resp = app
                .get(&hop.callback(&format!("&code={code}{extra}")), &hop.cookie)
                .await;
            assert!(clears_state_cookie(&resp));
            assert_eq!(session_cookie(&resp).is_some(), signed_in, "{extra}");
            if !signed_in {
                assert_eq!(location(&resp), format!("/login?flow={}", hop.flow));
                assert_eq!(flow_messages(&app, &hop.flow).await, [9_000_002], "{extra}");
                assert_eq!(stub.client_auth().len(), before, "no exchange: {extra}");
            }
        }

        let plain = OidcStub::start().await;
        let app = stub_app(&plain, false).await;
        linked_user(&app, "iss2@x.test", true).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let code = plain.issue(&hop.authorize, serde_json::json!({}));
        let resp = app
            .get(
                &hop.callback(&format!("&code={code}&iss=https%3A%2F%2Fevil.example")),
                &hop.cookie,
            )
            .await;
        assert_eq!(
            flow_messages(&app, &hop.flow).await,
            [9_000_002],
            "a present iss is checked"
        );
        assert!(session_cookie(&resp).is_none());
    }

    #[tokio::test]
    async fn a_provider_error_is_shown_on_the_flow_and_audited() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = app
            .get(
                &hop.callback("&error=access_denied&error_description=%3Cb%3Eno%3C%2Fb%3E"),
                &hop.cookie,
            )
            .await;
        assert_eq!(location(&resp), format!("/login?flow={}", hop.flow));
        assert!(clears_state_cookie(&resp));
        assert!(stub.client_auth().is_empty());
        let flow = app.flow(FlowKind::Login, &hop.flow, &hop.cookie).await;
        assert_eq!(flow.messages.len(), 1);
        assert_eq!(flow.messages[0].id, 9_000_002);
        assert!(
            !flow.messages[0].text.contains("<b>"),
            "the provider's text is not shown"
        );
        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "auth.login_failed");
        assert!(!rows[0].succeeded());
        let meta: serde_json::Value = serde_json::from_str(&rows[0].metadata).unwrap();
        assert_eq!(
            (meta["method"].as_str(), meta["provider"].as_str()),
            (Some("oidc"), Some("stub"))
        );

        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = app
            .get(&hop.callback("&code=not-issued"), &hop.cookie)
            .await;
        assert_eq!(location(&resp), format!("/login?flow={}", hop.flow));
        assert_eq!(
            flow_messages(&app, &hop.flow).await,
            [9_000_002],
            "a failed exchange"
        );
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(
            &app,
            &stub,
            &hop,
            serde_json::json!({"aud": "someone-else"}),
        )
        .await;
        assert_eq!(location(&resp), format!("/login?flow={}", hop.flow));
        assert_eq!(
            flow_messages(&app, &hop.flow).await,
            [9_000_002],
            "an invalid ID token"
        );
    }

    #[tokio::test]
    async fn a_never_verified_or_inactive_identity_is_not_signed_in() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let identity = linked_user(&app, "pending@x.test", false).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(location(&resp), format!("/login?flow={}", hop.flow));
        assert!(session_cookie(&resp).is_none());
        assert_eq!(flow_messages(&app, &hop.flow).await, [4_000_010]);
        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows[0].action, "auth.login_failed");
        assert_eq!(rows[0].actor_id.as_deref(), Some(identity.as_str()));

        store::mark_verified(&app.db, &identity, "pending@x.test")
            .await
            .unwrap();
        store::set_state(
            &app.db,
            &identity,
            crate::backend::identity::IdentityState::Inactive,
        )
        .await
        .unwrap();
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert!(session_cookie(&resp).is_none());
        assert_eq!(flow_messages(&app, &hop.flow).await, [4_000_006]);
        assert_eq!(
            app.row(&hop.flow).await.state,
            "choose_method",
            "the flow is not spent"
        );
    }

    #[tokio::test]
    async fn a_start_for_an_unknown_provider_sets_no_cookie() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let (id, cookie, token) = app.start("login", "").await;
        let resp = app
            .post(
                &format!("/self-service/login?flow={id}"),
                &cookie,
                &format!("csrf_token={token}&provider=nope"),
            )
            .await;
        assert_eq!(location(&resp), format!("/login?flow={id}"));
        assert!(
            set_cookies(&resp)
                .iter()
                .all(|c| !c.starts_with(STATE_COOKIE))
        );
        assert_eq!(flow_messages(&app, &id).await, [9_000_002]);
        assert_eq!(stub.discovery_fetches(), 0);
        assert!(
            app.backend
                .load_flow(&id)
                .await
                .unwrap()
                .unwrap()
                .ctx
                .oidc_state
                .is_none()
        );
    }

    #[tokio::test]
    async fn provider_callbacks_are_limited_per_ip() {
        let app = app().await;
        let uri = "/self-service/methods/oidc/callback/stub?state=x";
        for _ in 0..INIT_IP_RATE_PER_MINUTE {
            let resp = app.get(uri, "").await;
            assert_eq!(location(&resp), "/error?id=security_csrf_violation");
        }
        let limited = app.get(uri, "").await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let elsewhere = app.get_from("198.51.100.4", uri, "").await;
        assert_eq!(elsewhere.status(), StatusCode::SEE_OTHER);
    }

    /// Identities and provider links stored.
    async fn identity_and_link_counts(db: &DbPool) -> (i64, i64) {
        use crate::schema::{identities, identity_oidc_links};
        let run = async {
            Ok::<_, anyhow::Error>(crate::db_interact!(db, |c| {
                Ok::<_, diesel::result::Error>((
                    identities::table.count().get_result::<i64>(c)?,
                    identity_oidc_links::table.count().get_result::<i64>(c)?,
                ))
            })?)
        };
        run.await.unwrap()
    }

    fn verified(email: &str) -> serde_json::Value {
        serde_json::json!({"email": email, "email_verified": true})
    }

    /// The registration flow a callback sent the browser to.
    fn registration_flow(resp: &Response) -> String {
        location(resp)
            .strip_prefix("/registration?flow=")
            .expect("a new registration flow")
            .to_string()
    }

    async fn whoami_of(app: &App, token: &str) -> crate::backend::identity::Session {
        match app
            .backend
            .whoami(Some(&format!("forseti_session={token}")))
            .await
            .unwrap()
        {
            WhoamiOutcome::Ok(session) => *session,
            _ => panic!("the session is live"),
        }
    }

    #[tokio::test]
    async fn a_verified_provider_address_signs_up_a_linked_verified_identity() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let hop = start_hop(&app, "login", "?return_to=%2Fsettings", "stub").await;
        let long = "L".repeat(store::NAME_MAX_CHARS + 40);
        let claims = serde_json::json!({
            "email": "New@X.test",
            "email_verified": true,
            "given_name": " <b>Ada</b> ",
            "family_name": long,
        });
        let resp = stub_callback(&app, &stub, &hop, claims).await;
        assert_eq!(location(&resp), "/settings");
        assert!(clears_state_cookie(&resp));
        let token = session_cookie(&resp).expect("signed in");
        let session = whoami_of(&app, &token).await;
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal1));
        let methods = session.authentication_methods.unwrap();
        assert_eq!(methods[0].method.as_deref(), Some("oidc"));
        assert_eq!(methods[0].provider.as_deref(), Some("stub"));
        let identity = session.identity.unwrap();
        let traits = identity.traits.as_ref().unwrap();
        assert_eq!(traits["email"], "New@X.test");
        assert_eq!(traits["name"]["first"], "<b>Ada</b>");
        assert_eq!(
            traits["name"]["last"].as_str().unwrap().chars().count(),
            store::NAME_MAX_CHARS,
            "a long name is cut, not refused"
        );
        assert!(identity.verifiable_addresses.as_ref().unwrap()[0].verified);
        let row = store::row_by_id(&app.db, &identity.id)
            .await
            .unwrap()
            .unwrap();
        assert!(row.first_verified_at.is_some() && row.email_verified_at.is_some());
        assert_eq!(
            store::link_owner(&app.db, "stub", "stub-subject")
                .await
                .unwrap()
                .as_deref(),
            Some(identity.id.as_str())
        );
        assert_eq!(app.row(&hop.flow).await.state, "passed_challenge");
        assert!(
            app.backend.mailed("New@X.test").await.is_empty(),
            "no verification mail"
        );

        let rows = audit_rows(&app.db).await.unwrap();
        let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(actions, ["identity.created", "auth.login"]);
        for row in &rows {
            assert_eq!(row.actor_id.as_deref(), Some(identity.id.as_str()));
            let meta: serde_json::Value = serde_json::from_str(&row.metadata).unwrap();
            assert_eq!(
                (meta["method"].as_str(), meta["provider"].as_str()),
                (Some("oidc"), Some("stub"))
            );
            let whole = format!("{row:?}");
            assert!(!whole.contains("stub-subject") && !whole.contains(&hop.state()));
            assert!(!whole.contains(&token));
        }

        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, verified("other@x.test")).await;
        assert_eq!(
            location(&resp),
            "/",
            "the next callback signs the linked identity in"
        );
        let again = whoami_of(&app, &session_cookie(&resp).unwrap()).await;
        assert_eq!(again.identity.unwrap().id, identity.id);
        assert_eq!(identity_and_link_counts(&app.db).await, (1, 1));
    }

    #[tokio::test]
    async fn a_taken_provider_address_is_refused_on_a_new_registration_flow() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let existing = identity_with_password(&app.db, "taken@x.test", true).await;
        let before = store::row_by_id(&app.db, &existing).await.unwrap().unwrap();
        for kind in ["login", "registration"] {
            let hop = start_hop(&app, kind, "?return_to=%2Fsettings", "stub").await;
            let resp = stub_callback(&app, &stub, &hop, verified("TAKEN@x.test")).await;
            assert!(session_cookie(&resp).is_none(), "{kind}");
            assert!(clears_state_cookie(&resp));
            let next = registration_flow(&resp);
            assert_ne!(next, hop.flow);
            assert_eq!(flow_messages(&app, &next).await, [4_000_007], "{kind}");
            let (old, new) = (app.row(&hop.flow).await, app.row(&next).await);
            assert_eq!(old.state, "passed_challenge", "the original flow is spent");
            assert_eq!(new.binding, old.binding);
            assert_eq!(new.return_to.as_deref(), Some("/settings"));
            assert_eq!(new.identity_id, None);
            let ctx = app.backend.load_flow(&next).await.unwrap().unwrap().ctx;
            assert_eq!(
                (ctx.email_needed, ctx.upstream, ctx.traits),
                (None, None, None)
            );
            let flow = app.flow(FlowKind::Registration, &next, &hop.cookie).await;
            assert_eq!(flow.messages[0].id, 4_000_007);
        }
        assert_eq!(identity_and_link_counts(&app.db).await, (1, 0));
        assert!(
            store::links_of(&app.db, &existing)
                .await
                .unwrap()
                .is_empty()
        );
        let after = store::row_by_id(&app.db, &existing).await.unwrap().unwrap();
        assert_eq!(
            (after.email, after.first_name, after.updated_at),
            (before.email, before.first_name, before.updated_at)
        );
        let rows = audit_rows(&app.db).await.unwrap();
        assert!(
            rows.iter()
                .all(|r| r.action == "auth.login_failed" && r.actor_id.is_none())
        );
    }

    #[tokio::test]
    async fn an_admin_allowlisted_provider_address_creates_nothing() {
        let stub = OidcStub::start().await;
        let mut cfg = AppConfig::test_fixture();
        cfg.oauth.cimd.allow_private_targets = true;
        cfg.identity.oidc_providers = vec![stub.provider_config("stub")];
        cfg.admin.allowed_emails = vec!["Root@X.test".into()];
        let app = app_with(cfg).await;
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, verified("root@x.TEST")).await;
        assert!(session_cookie(&resp).is_none());
        assert_eq!(
            flow_messages(&app, &registration_flow(&resp)).await,
            [4_000_007]
        );
        assert_eq!(identity_and_link_counts(&app.db).await, (0, 0));
        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].metadata.contains("admin_allowlisted_email"),
            "{}",
            rows[0].metadata
        );
    }

    #[tokio::test]
    async fn a_provider_sign_up_spends_the_registration_buckets_and_a_sign_in_does_not() {
        let stub = OidcStub::start().await;
        let mut cfg = AppConfig::test_fixture();
        cfg.oauth.cimd.allow_private_targets = true;
        cfg.identity.oidc_providers = vec![stub.provider_config("stub")];
        cfg.auth.registration_ip_rate_per_minute = Some(1);
        let app = app_with(cfg).await;
        linked_user(&app, "linked@x.test", true).await;
        for _ in 0..3 {
            let hop = start_hop(&app, "login", "", "stub").await;
            let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
            assert!(session_cookie(&resp).is_some(), "a sign-in is not counted");
        }

        let signed_up = |sub: &str, email: &str| serde_json::json!({"sub": sub, "email": email, "email_verified": true});
        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, signed_up("first", "first@x.test")).await;
        assert!(
            session_cookie(&resp).is_some(),
            "the one sign-up the bucket holds"
        );
        assert_eq!(identity_and_link_counts(&app.db).await, (2, 2));

        let hop = start_hop(&app, "login", "", "stub").await;
        let resp = stub_callback(&app, &stub, &hop, signed_up("second", "second@x.test")).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key("retry-after"));
        assert!(session_cookie(&resp).is_none());
        assert!(clears_state_cookie(&resp));
        assert_eq!(
            identity_and_link_counts(&app.db).await,
            (2, 2),
            "nothing created"
        );
        assert_ne!(app.row(&hop.flow).await.state, "passed_challenge");

        let (id, cookie, token) = app.start("registration", "").await;
        let limited = app
            .post(
                &format!("/self-service/registration?flow={id}"),
                &cookie,
                &format!("csrf_token={token}&method=profile&traits.email="),
            )
            .await;
        assert_eq!(
            limited.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the registration submit shares the bucket"
        );
    }

    impl Hop {
        fn csrf(&self) -> &str {
            self.cookie
                .split("; ")
                .find_map(|c| c.strip_prefix("forseti_csrf="))
                .unwrap()
        }
    }

    /// A callback without a verified address: the email-needed registration flow it opened.
    async fn email_needed_flow(
        app: &App,
        stub: &OidcStub,
        claims: serde_json::Value,
    ) -> (Hop, String) {
        let hop = start_hop(app, "login", "?return_to=%2Fsettings", "stub").await;
        let resp = stub_callback(app, stub, &hop, claims).await;
        assert!(session_cookie(&resp).is_none());
        let next = registration_flow(&resp);
        (hop, next)
    }

    async fn submit_address(
        app: &App,
        hop: &Hop,
        flow: &str,
        email: &str,
        provider: &str,
    ) -> Response {
        app.post(
            &format!("/self-service/registration?flow={flow}"),
            &hop.cookie,
            &format!(
                "csrf_token={}&traits.email={}&provider={provider}",
                hop.csrf(),
                crate::web::urlencode(email)
            ),
        )
        .await
    }

    #[tokio::test]
    async fn without_a_verified_address_the_account_waits_sealed_on_an_email_needed_flow() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        for claims in [
            serde_json::json!({"email": "u@x.test", "email_verified": false, "given_name": "Grace"}),
            serde_json::json!({"email": "u@x.test", "given_name": "Grace"}),
            serde_json::json!({"given_name": "Grace"}),
        ] {
            let (hop, next) = email_needed_flow(&app, &stub, claims.clone()).await;
            let (old, new) = (app.row(&hop.flow).await, app.row(&next).await);
            assert_eq!(old.state, "passed_challenge");
            assert_eq!(new.binding, old.binding);
            assert_eq!(new.return_to.as_deref(), Some("/settings"));
            assert!(
                !new.context.contains("stub-subject") && !new.context.contains("Grace"),
                "{}",
                new.context
            );
            let ctx = app.backend.load_flow(&next).await.unwrap().unwrap().ctx;
            assert_eq!(ctx.email_needed.as_deref(), Some("stub"));
            assert!(ctx.upstream.is_some(), "{claims}");
            assert_eq!(ctx.traits, None, "an unverified address is not echoed");

            let resp = app
                .get(&format!("/registration?flow={next}"), &hop.cookie)
                .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let html = body(resp).await;
            assert!(html.contains("share a verified email address"));
            assert!(!html.contains("stub-subject") && !html.contains("Grace"));
        }
        assert_eq!(identity_and_link_counts(&app.db).await, (0, 0));
        assert!(app.backend.mailed("u@x.test").await.is_empty());
        assert!(audit_rows(&app.db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_email_needed_submit_refuses_a_taken_address_without_a_new_hop() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, true).await;
        identity_with_password(&app.db, "taken@x.test", true).await;
        let (hop, flow) = email_needed_flow(&app, &stub, serde_json::json!({})).await;
        let page = format!("/registration?flow={flow}");
        for (email, provider) in [("Taken@x.test", "stub"), ("TAKEN@x.test", "other")] {
            let resp = submit_address(&app, &hop, &flow, email, provider).await;
            assert_eq!(location(&resp), page, "{email}: no provider hop");
            assert!(
                set_cookies(&resp)
                    .iter()
                    .all(|c| !c.starts_with(STATE_COOKIE))
            );
            assert_eq!(flow_messages(&app, &flow).await, [4_000_007], "{email}");
            let ctx = app.backend.load_flow(&flow).await.unwrap().unwrap().ctx;
            assert_eq!(
                ctx.email_needed.as_deref(),
                Some("stub"),
                "the form's provider is ignored"
            );
            assert_eq!(ctx.oidc_state, None);
            assert_eq!(
                ctx.traits.unwrap().email,
                email,
                "the typed address is echoed"
            );
        }
        let resp = submit_address(&app, &hop, &flow, "not-an-address", "stub").await;
        assert_eq!(location(&resp), page);
        assert_eq!(
            messages_of(&app, &flow).await,
            [("traits.email".to_string(), 4_000_001)]
        );
        assert_eq!(identity_and_link_counts(&app.db).await, (1, 0));
        assert!(app.backend.mailed("taken@x.test").await.is_empty());
    }

    #[tokio::test]
    async fn an_allowlisted_address_on_the_email_needed_screen_is_refused_at_the_code() {
        let stub = OidcStub::start().await;
        let mut cfg = AppConfig::test_fixture();
        cfg.oauth.cimd.allow_private_targets = true;
        cfg.identity.oidc_providers = vec![stub.provider_config("stub")];
        cfg.admin.allowed_emails = vec!["root@x.test".into()];
        let app = app_with(cfg).await;
        let (hop, flow) = email_needed_flow(&app, &stub, serde_json::json!({})).await;
        let verification = signup_verification(&app, &hop, &flow, "ROOT@x.test").await;
        assert!(
            flow_messages(&app, &flow).await.is_empty(),
            "answered as a free address"
        );
        let code = app.backend.mailed("ROOT@x.test").await[0].code.clone();
        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert!(session_cookie(&resp).is_none());
        assert_eq!(flow_messages(&app, &verification).await, [4_000_007]);
        assert_eq!(identity_and_link_counts(&app.db).await, (0, 0));
        let rows = audit_rows(&app.db).await.unwrap();
        assert!(
            rows.iter()
                .any(|r| r.metadata.contains("admin_allowlisted_email")),
            "{rows:?}"
        );
    }

    async fn messages_of(app: &App, id: &str) -> Vec<(String, u64)> {
        let rec = app.backend.load_flow(id).await.unwrap().unwrap();
        rec.ctx
            .node_messages
            .iter()
            .map(|n| (n.node.clone(), n.message.id))
            .collect()
    }

    #[tokio::test]
    async fn a_sealed_provider_account_does_not_open_on_another_flow() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        identity_with_password(&app.db, "taken@x.test", true).await;
        let (_, first) = email_needed_flow(&app, &stub, serde_json::json!({"sub": "first"})).await;
        let (hop, second) =
            email_needed_flow(&app, &stub, serde_json::json!({"sub": "second"})).await;
        let sealed = app
            .backend
            .load_flow(&first)
            .await
            .unwrap()
            .unwrap()
            .ctx
            .upstream;
        let mut rec = app.backend.load_flow(&second).await.unwrap().unwrap();
        assert_ne!(rec.ctx.upstream, sealed);
        rec.ctx.upstream = sealed;
        assert_eq!(
            rec.save(&app.db).await.unwrap(),
            super::super::flows::Saved::Done
        );

        submit_address(&app, &hop, &second, "taken@x.test", "stub").await;
        assert_eq!(
            flow_messages(&app, &second).await,
            [9_000_002],
            "the copied account does not open, so the address is not even looked at"
        );
        assert_eq!(identity_and_link_counts(&app.db).await, (1, 0));
    }

    /// The callbacks of two hops, each with its code, run concurrently.
    async fn race(app: &App, hops: &[(Hop, String)]) -> (Response, Response) {
        let uris: Vec<String> = hops
            .iter()
            .map(|(hop, code)| hop.callback(&format!("&code={code}")))
            .collect();
        tokio::join!(
            app.get(&uris[0], &hops[0].0.cookie),
            app.get(&uris[1], &hops[1].0.cookie),
        )
    }

    #[tokio::test]
    async fn two_callbacks_racing_for_one_address_create_one_identity() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let mut codes = Vec::new();
        for subject in ["racer-a", "racer-b"] {
            let hop = start_hop(&app, "login", "", "stub").await;
            let claims =
                serde_json::json!({"sub": subject, "email": "race@x.test", "email_verified": true});
            let code = stub.issue(&hop.authorize, claims);
            codes.push((hop, code));
        }
        let (a, b) = race(&app, &codes).await;
        let (won, lost) = if session_cookie(&a).is_some() {
            (a, b)
        } else {
            (b, a)
        };
        assert!(session_cookie(&won).is_some());
        assert!(session_cookie(&lost).is_none(), "one sign-up only");
        assert_eq!(
            flow_messages(&app, &registration_flow(&lost)).await,
            [4_000_007]
        );
        assert_eq!(identity_and_link_counts(&app.db).await, (1, 1));
    }

    #[tokio::test]
    async fn two_callbacks_racing_for_one_provider_account_create_one_identity_and_link() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let mut codes = Vec::new();
        for email in ["one@x.test", "two@x.test"] {
            let hop = start_hop(&app, "login", "", "stub").await;
            let code = stub.issue(&hop.authorize, verified(email));
            codes.push((hop, code));
        }
        let (a, b) = race(&app, &codes).await;
        assert_eq!(identity_and_link_counts(&app.db).await, (1, 1));
        let owner = store::link_owner(&app.db, "stub", "stub-subject")
            .await
            .unwrap()
            .unwrap();
        for resp in [a, b] {
            if let Some(token) = session_cookie(&resp) {
                assert_eq!(whoami_of(&app, &token).await.identity.unwrap().id, owner);
            }
        }
    }

    /// Submit the free `email` on the email-needed flow: the sign-up's verification flow.
    async fn signup_verification(app: &App, hop: &Hop, flow: &str, email: &str) -> String {
        let resp = submit_address(app, hop, flow, email, "stub").await;
        assert!(session_cookie(&resp).is_none());
        location(&resp)
            .strip_prefix("/verification?flow=")
            .expect("the sign-up's verification flow")
            .to_string()
    }

    async fn enter_code(app: &App, cookie: &str, token: &str, flow: &str, code: &str) -> Response {
        app.post(
            &format!("/self-service/verification?flow={flow}"),
            cookie,
            &format!("csrf_token={token}&method=code&code={code}"),
        )
        .await
    }

    #[tokio::test]
    async fn a_typed_address_creates_the_identity_only_when_its_code_comes_from_the_starting_browser()
     {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let claims = serde_json::json!({"given_name": "Grace", "family_name": "Hopper"});
        let (hop, flow) = email_needed_flow(&app, &stub, claims).await;
        let verification = signup_verification(&app, &hop, &flow, "Typed@X.test").await;
        assert_eq!(
            identity_and_link_counts(&app.db).await,
            (0, 0),
            "nothing before the code"
        );
        assert_eq!(app.row(&flow).await.state, "passed_challenge");
        let (registration, row) = (
            app.backend.load_flow(&flow).await.unwrap().unwrap(),
            app.row(&verification).await,
        );
        assert_eq!(row.binding, registration.row.binding);
        assert_eq!(row.return_to.as_deref(), Some("/settings"));
        let ctx = app
            .backend
            .load_flow(&verification)
            .await
            .unwrap()
            .unwrap()
            .ctx;
        assert!(
            ctx.upstream.is_some() && ctx.upstream != registration.ctx.upstream,
            "sealed again"
        );
        assert!(!row.context.contains("stub-subject") && !row.context.contains("Grace"));
        let outbox = app.backend.outbox_for("Typed@X.test").await.unwrap();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].identity_id, None);
        let code = app.backend.mailed("Typed@X.test").await[0].code.clone();

        let (_, other, other_token) = app.start("login", "").await;
        let resp = enter_code(&app, &other, &other_token, &verification, &code).await;
        assert_eq!(location(&resp), "/error?id=security_csrf_violation");
        assert!(matches!(
            app.fetch(FlowKind::Verification, &verification, &other)
                .await,
            FlowFetch::Gone
        ));
        let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &wrong).await;
        assert!(session_cookie(&resp).is_none());
        assert_eq!(flow_messages(&app, &verification).await, [4_070_006]);
        assert_eq!(identity_and_link_counts(&app.db).await, (0, 0));

        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert_eq!(location(&resp), "/settings");
        let session = whoami_of(&app, &session_cookie(&resp).expect("signed in")).await;
        let methods = session.authentication_methods.unwrap();
        assert_eq!(
            (methods[0].method.as_deref(), methods[0].provider.as_deref()),
            (Some("oidc"), Some("stub"))
        );
        let identity = session.identity.unwrap();
        let traits = identity.traits.as_ref().unwrap();
        assert_eq!(traits["email"], "Typed@X.test");
        assert_eq!(
            (
                traits["name"]["first"].as_str(),
                traits["name"]["last"].as_str()
            ),
            (Some("Grace"), Some("Hopper"))
        );
        let stored = store::row_by_id(&app.db, &identity.id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.first_verified_at.is_some() && stored.email_verified_at.is_some());
        assert_eq!(
            store::link_owner(&app.db, "stub", "stub-subject")
                .await
                .unwrap()
                .as_deref(),
            Some(identity.id.as_str())
        );
        let rows = audit_rows(&app.db).await.unwrap();
        let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(actions, ["identity.created", "auth.login"]);
        for row in &rows {
            let whole = format!("{row:?}");
            assert!(!whole.contains("stub-subject") && !whole.contains(&code));
            assert!(
                row.metadata.contains(r#""provider":"stub""#),
                "{}",
                row.metadata
            );
        }
        let again = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert!(session_cookie(&again).is_none());
        assert_eq!(identity_and_link_counts(&app.db).await, (1, 1));
    }

    #[tokio::test]
    async fn the_sign_up_code_is_checked_again_when_it_is_entered() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;

        let (hop, flow) = email_needed_flow(&app, &stub, serde_json::json!({})).await;
        let verification = signup_verification(&app, &hop, &flow, "late@x.test").await;
        let code = app.backend.mailed("late@x.test").await[0].code.clone();
        let taken = identity_with_password(&app.db, "LATE@x.test", false).await;
        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert!(session_cookie(&resp).is_none());
        assert_eq!(flow_messages(&app, &verification).await, [4_000_007]);
        assert!(store::links_of(&app.db, &taken).await.unwrap().is_empty());
        assert!(
            store::row_by_id(&app.db, &taken)
                .await
                .unwrap()
                .unwrap()
                .email_verified_at
                .is_none()
        );

        let (hop, flow) = email_needed_flow(&app, &stub, serde_json::json!({"sub": "raced"})).await;
        let verification = signup_verification(&app, &hop, &flow, "mine@x.test").await;
        let code = app.backend.mailed("mine@x.test").await[0].code.clone();
        store::create_with_link(&app.db, "first@x.test", None, None, "stub", "raced")
            .await
            .unwrap();
        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert!(session_cookie(&resp).is_none());
        assert_eq!(flow_messages(&app, &verification).await, [9_000_002]);
        assert!(
            store::row_by_email(&app.db, "mine@x.test")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(identity_and_link_counts(&app.db).await, (2, 1));
    }

    #[tokio::test]
    async fn sign_up_codes_and_identity_codes_never_stand_in_for_each_other() {
        use crate::identity_native::codes::{CODE_ATTEMPTS, Purpose};
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let pending = identity_with_password(&app.db, "pending@x.test", false).await;

        let (id, cookie, token) = app.start("verification", "").await;
        app.backend
            .send_signup_code(&id, "pending@x.test")
            .await
            .unwrap();
        let code = app.backend.mailed("pending@x.test").await[0].code.clone();
        enter_code(&app, &cookie, &token, &id, &code).await;
        assert_eq!(
            flow_messages(&app, &id).await,
            [4_070_006],
            "an ordinary flow refuses it"
        );
        assert!(
            store::row_by_id(&app.db, &pending)
                .await
                .unwrap()
                .unwrap()
                .email_verified_at
                .is_none()
        );

        let (hop, flow) = email_needed_flow(&app, &stub, serde_json::json!({})).await;
        let verification = signup_verification(&app, &hop, &flow, "fresh@x.test").await;
        let free = identity_with_password(&app.db, "other@x.test", false).await;
        app.backend
            .send_code(&verification, Purpose::Verification, &free, "fresh@x.test")
            .await
            .unwrap();
        let code = app
            .backend
            .mailed("fresh@x.test")
            .await
            .last()
            .unwrap()
            .code
            .clone();
        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert!(session_cookie(&resp).is_none());
        assert_eq!(
            flow_messages(&app, &verification).await,
            [4_070_006],
            "a sign-up flow refuses it"
        );

        let resp = app
            .post(
                &format!("/self-service/verification?flow={verification}"),
                &hop.cookie,
                &format!(
                    "csrf_token={}&method=code&email=victim%40x.test",
                    hop.csrf()
                ),
            )
            .await;
        assert!(session_cookie(&resp).is_none());
        assert!(
            app.backend.mailed("victim@x.test").await.is_empty(),
            "a resend goes to the flow's address"
        );
        let code = app
            .backend
            .mailed("fresh@x.test")
            .await
            .last()
            .unwrap()
            .code
            .clone();
        let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
        for _ in 0..CODE_ATTEMPTS {
            enter_code(&app, &hop.cookie, hop.csrf(), &verification, &wrong).await;
        }
        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert!(session_cookie(&resp).is_none(), "the attempt limit applies");
        assert_eq!(identity_and_link_counts(&app.db).await, (2, 0));
    }

    use crate::identity_native::test_support::{GithubAccount, GithubAddress, GithubStub};

    async fn github_app(github: &GithubStub) -> App {
        let mut cfg = AppConfig::test_fixture();
        cfg.oauth.cimd.allow_private_targets = true;
        cfg.identity.oidc_providers = vec![github.provider_config("gh")];
        app_with_github(cfg, Some(github)).await
    }

    fn github_account(id: u64, emails: &[(&str, bool, bool)]) -> GithubAccount {
        GithubAccount {
            id,
            name: Some("Grace Brewster Hopper".into()),
            emails: emails
                .iter()
                .map(|(email, primary, verified)| GithubAddress {
                    email: (*email).into(),
                    primary: *primary,
                    verified: *verified,
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn a_github_account_with_a_primary_verified_address_signs_up() {
        let github = GithubStub::start().await;
        let app = github_app(&github).await;
        let hop = start_hop(&app, "registration", "", "gh").await;
        let account = github_account(
            4242,
            &[("other@x.test", false, true), ("grace@x.test", true, true)],
        );
        let code = github.issue(&hop.authorize, account);
        let resp = app
            .get(&hop.callback(&format!("&code={code}")), &hop.cookie)
            .await;
        assert_eq!(location(&resp), "/");
        let session = whoami_of(&app, &session_cookie(&resp).expect("signed in")).await;
        assert_eq!(
            session.authentication_methods.unwrap()[0]
                .provider
                .as_deref(),
            Some("gh")
        );
        let identity = session.identity.unwrap();
        let traits = identity.traits.as_ref().unwrap();
        assert_eq!(traits["email"], "grace@x.test");
        assert_eq!(traits["name"]["first"], "Grace");
        assert_eq!(traits["name"]["last"], "Brewster Hopper");
        assert!(identity.verifiable_addresses.as_ref().unwrap()[0].verified);
        assert_eq!(
            store::link_owner(&app.db, "gh", "4242")
                .await
                .unwrap()
                .as_deref(),
            Some(identity.id.as_str())
        );
        assert_eq!(github.refused_without_agent(), 0);
    }

    #[tokio::test]
    async fn a_github_account_without_a_primary_verified_address_needs_an_email() {
        let github = GithubStub::start().await;
        let app = github_app(&github).await;
        let hop = start_hop(&app, "login", "", "gh").await;
        let account = github_account(
            7,
            &[("grace@x.test", true, false), ("old@x.test", false, true)],
        );
        let code = github.issue(&hop.authorize, account);
        let resp = app
            .get(&hop.callback(&format!("&code={code}")), &hop.cookie)
            .await;
        assert!(session_cookie(&resp).is_none());
        let next = registration_flow(&resp);
        let ctx = app.backend.load_flow(&next).await.unwrap().unwrap().ctx;
        assert_eq!(ctx.email_needed.as_deref(), Some("gh"));
        assert!(ctx.upstream.is_some());
        let html = body(
            app.get(&format!("/registration?flow={next}"), &hop.cookie)
                .await,
        )
        .await;
        assert!(html.contains("share a verified email address"));
        assert_eq!(identity_and_link_counts(&app.db).await, (0, 0));

        let verification = signup_verification(&app, &hop, &next, "grace@x.test").await;
        let code = app.backend.mailed("grace@x.test").await[0].code.clone();
        let resp = enter_code(&app, &hop.cookie, hop.csrf(), &verification, &code).await;
        assert_eq!(location(&resp), "/");
        let session = whoami_of(&app, &session_cookie(&resp).expect("signed in")).await;
        assert_eq!(
            session.authentication_methods.unwrap()[0]
                .provider
                .as_deref(),
            Some("gh")
        );
        let identity = session.identity.unwrap();
        assert_eq!(
            identity.traits.as_ref().unwrap()["name"]["last"],
            "Brewster Hopper"
        );
        assert_eq!(
            store::link_owner(&app.db, "gh", "7")
                .await
                .unwrap()
                .as_deref(),
            Some(identity.id.as_str())
        );
    }

    const LINKED_PAGE: &str = "http://localhost:3000/settings/linked-providers";

    /// A signed-in browser on a settings flow for `identity`: (flow id, cookie header, CSRF
    /// token, session id).
    async fn settings_browser(app: &App, identity: &str) -> (String, String, String, String) {
        let (session, cookie, token) = app.signed_in(identity).await;
        let flow = settings_flow(app, &cookie, "/settings/linked-providers").await;
        (flow, cookie, token, session)
    }

    async fn settings_post(app: &App, flow: &str, cookie: &str, body: &str) -> Response {
        app.post(&format!("/self-service/settings?flow={flow}"), cookie, body)
            .await
    }

    /// Move the session's sign-in outside the privileged window.
    async fn lapse_session(app: &App, session_id: &str) {
        let id = session_id.to_string();
        crate::identity_native::test_support::sql(&app.db, move |c| {
            use crate::schema::identity_sessions;
            diesel::update(identity_sessions::table.find(&id))
                .set(identity_sessions::authenticated_at.eq("2026-01-01T00:00:00.000000+00:00"))
                .execute(c)
        })
        .await;
    }

    fn param(url: &url::Url, name: &str) -> Option<String> {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    async fn provider_links(app: &App, identity: &str) -> Vec<(String, String)> {
        store::links_of(&app.db, identity)
            .await
            .unwrap()
            .into_iter()
            .map(|l| (l.provider, l.subject))
            .collect()
    }

    fn pair(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    async fn flow_texts(app: &App, id: &str) -> Vec<(u64, String)> {
        let rec = app.backend.load_flow(id).await.unwrap().unwrap();
        rec.ctx
            .messages
            .iter()
            .map(|m| (m.id, m.text.clone()))
            .collect()
    }

    fn no_state_cookie(resp: &Response) -> bool {
        set_cookies(resp)
            .iter()
            .all(|c| !c.starts_with(STATE_COOKIE))
    }

    #[tokio::test]
    async fn a_settings_link_joins_the_provider_account_to_the_signed_in_identity() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let identity = identity_with_password(&app.db, "link@x.test", true).await;
        let (flow, cookie, token, _) = settings_browser(&app, &identity).await;
        let form = format!("csrf_token={token}&link=stub");
        let hop = press(&app, "settings", &flow, &cookie, &form, "stub").await;
        assert_eq!(param(&hop.authorize, "max_age"), None);
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(location(&resp), LINKED_PAGE);
        assert!(clears_state_cookie(&resp));
        assert!(session_cookie(&resp).is_none(), "a link issues no session");
        assert_eq!(
            provider_links(&app, &identity).await,
            [pair("stub", "stub-subject")]
        );
        assert_eq!(app.row(&flow).await.state, "success");
        let page = app.flow(FlowKind::Settings, &flow, &cookie).await;
        assert_eq!(
            page.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            [1_050_001]
        );

        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "identity.oidc.linked");
        assert_eq!(rows[0].actor_id.as_deref(), Some(identity.as_str()));
        let meta: serde_json::Value = serde_json::from_str(&rows[0].metadata).unwrap();
        assert_eq!(meta["provider"], "stub");
        let whole = format!("{:?}", rows[0]);
        assert!(!whole.contains("stub-subject") && !whole.contains(&hop.state()));

        let resp = app
            .get(&format!("/settings/linked-providers?flow={flow}"), &cookie)
            .await;
        let html = body(resp).await;
        assert!(action(&html, "unlink", "stub"), "{html}");
        assert!(!action(&html, "link", "stub"));
    }

    #[tokio::test]
    async fn a_lapsed_window_sends_link_and_unlink_where_a_password_change_goes() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, true).await;
        let identity = identity_with_password(&app.db, "lapse@x.test", true).await;
        store::insert_link(&app.db, &identity, "stub", "s-lapse")
            .await
            .unwrap();
        let (flow, cookie, token, session) = settings_browser(&app, &identity).await;
        lapse_session(&app, &session).await;
        let expected = format!(
            "/login?refresh=true&return_to={}",
            crate::web::urlencode(LINKED_PAGE)
        );
        for body in [
            "method=password&password=violet+staircase+42",
            "link=other",
            "unlink=stub",
        ] {
            let resp =
                settings_post(&app, &flow, &cookie, &format!("csrf_token={token}&{body}")).await;
            assert_eq!(location(&resp), expected, "{body}");
            assert!(no_state_cookie(&resp), "{body}");
        }
        assert_eq!(
            app.backend
                .load_flow(&flow)
                .await
                .unwrap()
                .unwrap()
                .ctx
                .oidc_state,
            None
        );
        assert_eq!(stub.discovery_fetches(), 0, "no provider hop");
        assert_eq!(
            provider_links(&app, &identity).await,
            [pair("stub", "s-lapse")]
        );

        let (flow, cookie, token, session) = settings_browser(&app, &identity).await;
        let body = format!("csrf_token={token}&link=other");
        let hop = press(&app, "settings", &flow, &cookie, &body, "other").await;
        lapse_session(&app, &session).await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({"sub": "late"})).await;
        assert_eq!(location(&resp), expected, "a window lapsed during the hop");
        assert!(clears_state_cookie(&resp));
        assert_eq!(
            store::link_owner(&app.db, "other", "late").await.unwrap(),
            None
        );
        assert!(audit_rows(&app.db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_settings_link_refuses_an_account_linked_elsewhere_and_a_second_link_to_the_provider()
    {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let owner = linked_user(&app, "owner@x.test", true).await;
        let me = identity_with_password(&app.db, "me@x.test", true).await;
        let (flow, cookie, token, _) = settings_browser(&app, &me).await;
        let link = format!("csrf_token={token}&link=stub");
        let page = format!("/settings?flow={flow}");

        let hop = press(&app, "settings", &flow, &cookie, &link, "stub").await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(location(&resp), page);
        assert_eq!(flow_messages(&app, &flow).await, [4_000_007]);
        assert_eq!(
            store::link_owner(&app.db, "stub", "stub-subject")
                .await
                .unwrap()
                .as_deref(),
            Some(owner.as_str())
        );
        assert!(provider_links(&app, &me).await.is_empty());

        store::insert_link(&app.db, &me, "stub", "mine")
            .await
            .unwrap();
        let hop = press(&app, "settings", &flow, &cookie, &link, "stub").await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({"sub": "another"})).await;
        assert_eq!(location(&resp), page);
        assert_eq!(flow_messages(&app, &flow).await, [4_000_007]);
        assert_eq!(provider_links(&app, &me).await, [pair("stub", "mine")]);
        assert_eq!(
            store::link_owner(&app.db, "stub", "another").await.unwrap(),
            None
        );
        assert!(audit_rows(&app.db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_never_verified_identity_links_no_provider() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let pending = identity_with_password(&app.db, "pending@x.test", false).await;
        let (flow, cookie, token, _) = settings_browser(&app, &pending).await;
        let resp = settings_post(
            &app,
            &flow,
            &cookie,
            &format!("csrf_token={token}&link=stub"),
        )
        .await;
        assert_eq!(location(&resp), format!("/settings?flow={flow}"));
        assert!(no_state_cookie(&resp));
        assert_eq!(flow_messages(&app, &flow).await, [4_000_010]);
        assert_eq!(stub.discovery_fetches(), 0);

        let verified = identity_with_password(&app.db, "verified@x.test", true).await;
        let (flow, cookie, token, _) = settings_browser(&app, &verified).await;
        let body = format!("csrf_token={token}&link=stub");
        let hop = press(&app, "settings", &flow, &cookie, &body, "stub").await;
        let id = verified.clone();
        crate::identity_native::test_support::sql(&app.db, move |c| {
            use crate::schema::identities;
            diesel::update(identities::table.find(&id))
                .set(identities::first_verified_at.eq(None::<String>))
                .execute(c)
        })
        .await;
        let resp = stub_callback(&app, &stub, &hop, serde_json::json!({})).await;
        assert_eq!(location(&resp), format!("/settings?flow={flow}"));
        assert_eq!(
            flow_messages(&app, &flow).await,
            [4_000_010],
            "checked again at the callback"
        );
        assert_eq!(identity_and_link_counts(&app.db).await, (2, 0));
    }

    #[tokio::test]
    async fn a_link_callback_in_another_identitys_browser_links_nothing() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let attacker = identity_with_password(&app.db, "attacker@x.test", true).await;
        let victim = identity_with_password(&app.db, "victim@x.test", true).await;
        let (flow, cookie, token, _) = settings_browser(&app, &attacker).await;
        let body = format!("csrf_token={token}&link=stub");
        let hop = press(&app, "settings", &flow, &cookie, &body, "stub").await;
        let code = stub.issue(&hop.authorize, serde_json::json!({"sub": "attacker-sub"}));
        let uri = hop.callback(&format!("&code={code}"));
        let (_, victim_cookie, _) = app.signed_in(&victim).await;
        let state_cookie = hop.cookie.split("; ").last().unwrap();
        for (cookie, verified) in [
            (victim_cookie.clone(), false),
            (format!("{victim_cookie}; {state_cookie}"), true),
        ] {
            let resp = app.get(&uri, &cookie).await;
            assert_eq!(
                location(&resp),
                "/error?id=security_csrf_violation",
                "{cookie}"
            );
            assert_eq!(clears_state_cookie(&resp), verified, "{cookie}");
            assert_eq!(no_state_cookie(&resp), !verified, "{cookie}");
            assert!(session_cookie(&resp).is_none());
        }
        assert!(stub.client_auth().is_empty(), "nothing was exchanged");
        assert!(provider_links(&app, &victim).await.is_empty());
        assert_eq!(
            store::link_owner(&app.db, "stub", "attacker-sub")
                .await
                .unwrap(),
            None
        );

        let resp = app.get(&uri, &hop.cookie).await;
        assert_eq!(
            location(&resp),
            LINKED_PAGE,
            "the starting browser still completes it"
        );
        assert_eq!(
            store::link_owner(&app.db, "stub", "attacker-sub")
                .await
                .unwrap()
                .as_deref(),
            Some(attacker.as_str())
        );
        assert!(provider_links(&app, &victim).await.is_empty());
    }

    #[tokio::test]
    async fn an_unlink_removes_the_link_and_its_first_seen_date_and_keeps_the_session() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, true).await;
        let identity = identity_with_password(&app.db, "unlink@x.test", true).await;
        for (provider, subject) in [("stub", "hidden-subject-1"), ("other", "hidden-subject-2")] {
            store::insert_link(&app.db, &identity, provider, subject)
                .await
                .unwrap();
            crate::settings::oidc_links_db::upsert_seen(&app.db, &identity, provider)
                .await
                .unwrap();
        }
        let (session, cookie, token) = app.signed_in_by(&identity, "oidc", Some("stub")).await;
        let flow = settings_flow(&app, &cookie, "/settings/linked-providers").await;
        let resp = settings_post(
            &app,
            &flow,
            &cookie,
            &format!("csrf_token={token}&unlink=stub"),
        )
        .await;
        assert_eq!(location(&resp), LINKED_PAGE);
        assert!(no_state_cookie(&resp));
        assert_eq!(
            stub.discovery_fetches(),
            0,
            "an unlink never leaves for the provider"
        );
        assert_eq!(
            provider_links(&app, &identity).await,
            [pair("other", "hidden-subject-2")]
        );
        let seen = crate::settings::oidc_links_db::list_for_identity(&app.db, &identity)
            .await
            .unwrap();
        assert_eq!(
            seen.into_iter().map(|(p, _)| p).collect::<Vec<_>>(),
            ["other"]
        );
        let page = app.flow(FlowKind::Settings, &flow, &cookie).await;
        assert_eq!(
            page.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            [1_050_001]
        );

        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "identity.oidc.unlinked");
        assert_eq!(rows[0].actor_id.as_deref(), Some(identity.as_str()));
        let meta: serde_json::Value = serde_json::from_str(&rows[0].metadata).unwrap();
        assert_eq!(meta["provider"], "stub");
        assert!(!format!("{:?}", rows[0]).contains("hidden-subject"));
        let WhoamiOutcome::Ok(live) = app.backend.whoami(Some(&cookie)).await.unwrap() else {
            panic!("the session signed in through the unlinked provider stays live");
        };
        assert_eq!(live.id, session);
    }

    #[tokio::test]
    async fn a_forged_unlink_of_the_last_usable_method_changes_nothing() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let sole = app.user("sole@x.test").await;
        for (provider, subject) in [("stub", "s1"), ("gone", "g1")] {
            store::insert_link(&app.db, &sole, provider, subject)
                .await
                .unwrap();
        }
        let (flow, cookie, token, _) = settings_browser(&app, &sole).await;
        let resp = settings_post(
            &app,
            &flow,
            &cookie,
            &format!("csrf_token={token}&unlink=stub"),
        )
        .await;
        assert_eq!(location(&resp), format!("/settings?flow={flow}"));
        assert_eq!(
            flow_texts(&app, &flow).await,
            [(
                4_000_001,
                "Unable to remove the last sign-in method.".to_string()
            )]
        );
        assert_eq!(
            provider_links(&app, &sole).await,
            [pair("gone", "g1"), pair("stub", "s1")]
        );
        assert!(audit_rows(&app.db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unlink_of_a_provider_not_linked_or_not_configured_changes_nothing() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, true).await;
        let identity = identity_with_password(&app.db, "forged@x.test", true).await;
        for (provider, subject) in [("stub", "s1"), ("gone", "g1")] {
            store::insert_link(&app.db, &identity, provider, subject)
                .await
                .unwrap();
        }
        let (flow, cookie, token, _) = settings_browser(&app, &identity).await;
        for provider in ["other", "gone", "nope"] {
            let resp = settings_post(
                &app,
                &flow,
                &cookie,
                &format!("csrf_token={token}&unlink={provider}"),
            )
            .await;
            assert_eq!(
                location(&resp),
                format!("/settings?flow={flow}"),
                "{provider}"
            );
            let texts = flow_texts(&app, &flow).await;
            assert_eq!(texts.len(), 1, "{provider}");
            assert_eq!(texts[0].0, 4_000_001, "{provider}");
            assert!(
                texts[0].1.starts_with("Could not find a strategy"),
                "{provider}"
            );
        }
        assert_eq!(
            provider_links(&app, &identity).await,
            [pair("gone", "g1"), pair("stub", "s1")]
        );
        assert!(audit_rows(&app.db).await.unwrap().is_empty());
    }

    /// A browser signed in to `identity` (raised to AAL2 when `aal2`) whose sign-in lies outside
    /// the privileged window: (session id, cookie header, CSRF token).
    async fn refresh_browser(app: &App, identity: &str, aal2: bool) -> (String, String, String) {
        let (session, mut cookie, token) = app.signed_in(identity).await;
        if aal2 {
            let held = session::find_live(&app.db, &session)
                .await
                .unwrap()
                .unwrap();
            let session::StepUp::Rotated(raised) =
                session::step_up(&app.db, &held, "totp", None, Aal::Aal2)
                    .await
                    .unwrap()
            else {
                panic!("a live session rotates");
            };
            cookie = format!("forseti_session={raised}; forseti_csrf={token}");
        }
        lapse_session(app, &session).await;
        (session, cookie, token)
    }

    /// A refresh login flow returning to `/settings`, in the browser holding `cookie`.
    async fn refresh_flow(app: &App, cookie: &str) -> String {
        let resp = app
            .get(
                "/self-service/login/browser?refresh=true&return_to=%2Fsettings",
                cookie,
            )
            .await;
        location(&resp)
            .strip_prefix("/login?flow=")
            .expect("a refresh login flow")
            .to_string()
    }

    async fn refresh_hop(app: &App, cookie: &str, token: &str, provider: &str) -> Hop {
        let flow = refresh_flow(app, cookie).await;
        let body = format!("csrf_token={token}&provider={provider}");
        press(app, "login", &flow, cookie, &body, provider).await
    }

    /// The hop start time the flow of `hop` stored with its `state`.
    async fn hop_started_at(app: &App, hop: &Hop) -> i64 {
        let rec = app.backend.load_flow(&hop.flow).await.unwrap().unwrap();
        rec.ctx.oidc_started_at.expect("stored with the state")
    }

    /// (aal, authenticated_at, methods, token hash) of the session.
    async fn session_state(app: &App, id: &str) -> (String, String, String, String) {
        let row = session::find_live(&app.db, id).await.unwrap().unwrap();
        (row.aal, row.authenticated_at, row.methods, row.token_hash)
    }

    fn oidc_method(methods: &str) -> serde_json::Value {
        let methods: serde_json::Value = serde_json::from_str(methods).unwrap();
        methods
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["method"] == "oidc")
            .cloned()
            .expect("an oidc method")
    }

    #[tokio::test]
    async fn a_refresh_through_an_oidc_provider_keeps_the_aal_and_advances_authenticated_at() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let identity = linked_user(&app, "refresh@x.test", true).await;
        let mut sessions = Vec::new();
        for aal2 in [true, false] {
            let (session, cookie, token) = refresh_browser(&app, &identity, aal2).await;
            let before = session_state(&app, &session).await;
            let hop = refresh_hop(&app, &cookie, &token, "stub").await;
            assert_eq!(param(&hop.authorize, "max_age").as_deref(), Some("0"));
            let started = hop_started_at(&app, &hop).await;
            let resp =
                stub_callback(&app, &stub, &hop, serde_json::json!({"auth_time": started})).await;
            assert_eq!(location(&resp), "/settings");
            assert!(clears_state_cookie(&resp));
            assert!(
                session_cookie(&resp).is_none(),
                "the session keeps its token"
            );
            let after = session_state(&app, &session).await;
            assert_eq!(after.0, if aal2 { "aal2" } else { "aal1" });
            assert_eq!(after.3, before.3);
            assert!(after.1 > before.1, "{} > {}", after.1, before.1);
            assert_eq!(oidc_method(&after.2)["provider"], "stub");
            assert_eq!(app.row(&hop.flow).await.state, "passed_challenge");
            sessions.push(session);
        }

        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 2);
        for (row, session) in rows.iter().zip(&sessions) {
            assert_eq!(row.action, "auth.login");
            assert_eq!(row.actor_id.as_deref(), Some(identity.as_str()));
            let meta: serde_json::Value = serde_json::from_str(&row.metadata).unwrap();
            assert_eq!(meta["method"], "oidc");
            assert_eq!(meta["provider"], "stub");
            assert_eq!(meta["refresh"], true);
            assert_eq!(meta["kratos_session_id"], session.as_str());
            assert!(!format!("{row:?}").contains("stub-subject"));
        }
    }

    #[tokio::test]
    async fn a_refresh_without_a_fresh_auth_time_changes_nothing() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let identity = linked_user(&app, "stale@x.test", true).await;
        let (session, cookie, token) = refresh_browser(&app, &identity, true).await;
        let before = session_state(&app, &session).await;
        let skew = 60;
        for case in ["missing", "before the hop", "ahead"] {
            let hop = refresh_hop(&app, &cookie, &token, "stub").await;
            let started = hop_started_at(&app, &hop).await;
            let claims = match case {
                "missing" => serde_json::json!({}),
                "before the hop" => serde_json::json!({"auth_time": started - skew - 30}),
                _ => serde_json::json!({"auth_time": started + 600}),
            };
            let resp = stub_callback(&app, &stub, &hop, claims.clone()).await;
            assert_eq!(
                location(&resp),
                format!("/login?flow={}", hop.flow),
                "{claims}"
            );
            assert!(session_cookie(&resp).is_none());
            assert_eq!(
                flow_messages(&app, &hop.flow).await,
                [4_000_006],
                "{claims}"
            );
            assert_eq!(app.row(&hop.flow).await.state, "choose_method");
            assert_eq!(session_state(&app, &session).await, before, "{claims}");
        }
        let rows = audit_rows(&app.db).await.unwrap();
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(row.action, "auth.login_failed");
            assert!(
                row.metadata.contains("stale_authentication"),
                "{}",
                row.metadata
            );
        }
    }

    #[tokio::test]
    async fn a_refresh_start_for_a_provider_not_linked_to_the_session_identity_never_hops() {
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, true).await;
        let identity = linked_user(&app, "unlinked@x.test", true).await;
        store::insert_link(&app.db, &identity, "gone", "g1")
            .await
            .unwrap();
        let (_, cookie, token) = refresh_browser(&app, &identity, false).await;
        let flow = refresh_flow(&app, &cookie).await;
        for provider in ["other", "gone", "nope"] {
            let resp = app
                .post(
                    &format!("/self-service/login?flow={flow}"),
                    &cookie,
                    &format!("csrf_token={token}&provider={provider}"),
                )
                .await;
            assert_eq!(location(&resp), format!("/login?flow={flow}"), "{provider}");
            assert!(no_state_cookie(&resp), "{provider}");
            assert_eq!(flow_messages(&app, &flow).await, [4_000_006], "{provider}");
        }
        assert_eq!(
            app.backend
                .load_flow(&flow)
                .await
                .unwrap()
                .unwrap()
                .ctx
                .oidc_state,
            None
        );
        assert_eq!(stub.discovery_fetches(), 0);
    }

    #[tokio::test]
    async fn a_refresh_callback_for_another_or_no_identitys_account_changes_nothing() {
        use crate::identity_native::test_support::identity_with_password;
        let stub = OidcStub::start().await;
        let app = stub_app(&stub, false).await;
        let me = linked_user(&app, "me@x.test", true).await;
        let other = identity_with_password(&app.db, "else@x.test", true).await;
        store::insert_link(&app.db, &other, "stub", "else-sub")
            .await
            .unwrap();
        let (session, cookie, token) = refresh_browser(&app, &me, false).await;
        let before = session_state(&app, &session).await;
        let now = chrono::Utc::now().timestamp();
        for sub in ["else-sub", "nobody"] {
            let hop = refresh_hop(&app, &cookie, &token, "stub").await;
            let claims = serde_json::json!({
                "sub": sub,
                "auth_time": now,
                "email": "new@x.test",
                "email_verified": true,
            });
            let resp = stub_callback(&app, &stub, &hop, claims).await;
            assert_eq!(
                location(&resp),
                format!("/login?flow={}", hop.flow),
                "{sub}"
            );
            assert!(session_cookie(&resp).is_none(), "{sub}");
            assert_eq!(flow_messages(&app, &hop.flow).await, [4_000_006], "{sub}");
            assert_eq!(session_state(&app, &session).await, before, "{sub}");
        }
        assert_eq!(identity_and_link_counts(&app.db).await, (2, 2));
        assert!(
            store::row_by_email(&app.db, "new@x.test")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn github_is_neither_offered_nor_accepted_for_a_refresh() {
        let stub = OidcStub::start().await;
        let github = GithubStub::start().await;
        let mut cfg = AppConfig::test_fixture();
        cfg.oauth.cimd.allow_private_targets = true;
        cfg.identity.oidc_providers =
            vec![stub.provider_config("stub"), github.provider_config("gh")];
        let app = app_with_github(cfg, Some(&github)).await;
        let both = linked_user(&app, "both@x.test", true).await;
        store::insert_link(&app.db, &both, "gh", "4242")
            .await
            .unwrap();
        let (session, cookie, token) = refresh_browser(&app, &both, false).await;
        let before = session_state(&app, &session).await;
        let flow = refresh_flow(&app, &cookie).await;
        assert_eq!(
            oidc_inputs(&app.flow(FlowKind::Login, &flow, &cookie).await),
            [named("provider", "stub")]
        );
        let resp = app
            .post(
                &format!("/self-service/login?flow={flow}"),
                &cookie,
                &format!("csrf_token={token}&provider=gh"),
            )
            .await;
        assert_eq!(location(&resp), format!("/login?flow={flow}"));
        assert!(no_state_cookie(&resp));
        assert_eq!(flow_messages(&app, &flow).await, [4_000_006]);
        let rec = app.backend.load_flow(&flow).await.unwrap().unwrap();
        assert_eq!((rec.ctx.oidc_state, rec.ctx.oidc_started_at), (None, None));
        assert_eq!(session_state(&app, &session).await, before);

        let gh_only = app.user("gh@x.test").await;
        store::insert_link(&app.db, &gh_only, "gh", "4243")
            .await
            .unwrap();
        let (_, cookie, _) = refresh_browser(&app, &gh_only, false).await;
        let flow = refresh_flow(&app, &cookie).await;
        assert!(oidc_inputs(&app.flow(FlowKind::Login, &flow, &cookie).await).is_empty());
    }

    #[cfg(feature = "oauth-ory")]
    /// An app with `root@x.test` allowlisted as admin and Hydra's admin API stubbed, and that
    /// admin's AAL2 browser: (admin id, cookie header, CSRF token).
    async fn admin_app() -> (App, String, String, String) {
        let (hydra, _) = fake_hydra_admin().await;
        let mut cfg = AppConfig::test_fixture();
        cfg.hydra.admin_url = hydra;
        cfg.admin.allowed_emails = vec!["root@x.test".into()];
        let app = app_with(cfg).await;
        let admin = app.user("root@x.test").await;
        let (cookie, token) = browser_at(&app, &admin, Aal::Aal2).await;
        (app, admin, cookie, token)
    }

    #[cfg(feature = "oauth-ory")]
    /// A browser holding a session of `identity_id` at `aal`: (cookie header, CSRF token).
    async fn browser_at(app: &App, identity_id: &str, aal: Aal) -> (String, String) {
        let issued = app
            .backend
            .issue_session(identity_id, "password", None, aal, Device::default())
            .await
            .unwrap();
        let token = csrf_cookie(&app.get("/self-service/logout", "").await).unwrap();
        let cookie = format!("forseti_session={}; forseti_csrf={token}", issued.token);
        (cookie, token)
    }

    #[cfg(feature = "oauth-ory")]
    /// The identity page as `cookie` sees it right after `redirect`, with its flash cookie.
    async fn page_after(app: &App, redirect: &Response, cookie: &str) -> String {
        let flash = set_cookies(redirect)
            .first()
            .map(|c| c.split(';').next().unwrap().to_string())
            .unwrap();
        let page = app
            .get(&location(redirect), &format!("{cookie}; {flash}"))
            .await;
        assert_eq!(page.status(), StatusCode::OK);
        body(page).await
    }

    #[cfg(feature = "oauth-ory")]
    #[tokio::test]
    async fn admin_second_factor_reset_keeps_passkeys_and_sessions_and_is_audited() {
        use store::keys::{self, KeyKind};
        let (app, admin, cookie, csrf) = admin_app().await;
        let target = app.user("t@x.test").await;
        crate::identity_native::test_support::plant_password(&app.db, &target).await;
        app.add_totp(&target).await;
        crate::identity_native::test_support::plant_lookup_codes(&app.backend, &target).await;
        keys::plant(&app.db, &target, KeyKind::Webauthn).await;
        keys::plant(&app.db, &target, KeyKind::Passkey).await;
        let (aal1_session, _, _) = app.signed_in(&target).await;
        let show = format!("/admin/identities/{target}");
        let uri = format!("{show}/reset-2fa");

        assert!(body(app.get(&show, &cookie).await).await.contains(&uri));
        let confirm = app.get(&uri, &cookie).await;
        assert_eq!(confirm.status(), StatusCode::OK);
        assert!(body(confirm).await.contains(&format!("action=\"{uri}\"")));

        let forged = app.post(&uri, &cookie, "confirm=yes").await;
        assert_eq!(forged.status(), StatusCode::FORBIDDEN);
        let unconfirmed = app.post(&uri, &cookie, &format!("_csrf={csrf}")).await;
        assert_eq!(location(&unconfirmed), show);
        assert!(keys::has_second_factor(&app.db, &target).await.unwrap());

        let done = app
            .post(&uri, &cookie, &format!("_csrf={csrf}&confirm=yes"))
            .await;
        assert_eq!(location(&done), show);
        let page = page_after(&app, &done, &cookie).await;
        assert!(page.contains("2FA reset."));
        assert!(!page.contains(&uri));

        let identity = store::get(&app.db, &target).await.unwrap().unwrap();
        let mut kinds: Vec<String> = identity.credentials.unwrap().into_keys().collect();
        kinds.sort();
        assert_eq!(kinds, ["passkey", "password"]);
        assert_eq!(identity.has_second_factor, Some(false));
        assert!(
            session::find_live(&app.db, &aal1_session)
                .await
                .unwrap()
                .is_some()
        );

        let resets = |rows: Vec<crate::audit::AuditRow>| {
            rows.into_iter()
                .filter(|r| r.action == crate::audit::action::ADMIN_IDENTITY_SECOND_FACTORS_RESET)
                .collect::<Vec<_>>()
        };
        let rows = resets(audit_rows(&app.db).await.unwrap());
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.severity, "critical");
        assert_eq!(row.actor_kind, "admin");
        assert_eq!(row.actor_id.as_deref(), Some(admin.as_str()));
        assert_eq!(
            (row.target_kind.as_deref(), row.target_id.as_deref()),
            (Some("identity"), Some(target.as_str()))
        );
        let metadata: serde_json::Value = serde_json::from_str(&row.metadata).unwrap();
        assert_eq!(
            metadata,
            serde_json::json!({"removed": ["totp", "lookup_secret", "webauthn"], "security_keys": 1})
        );

        let again = app
            .post(&uri, &cookie, &format!("_csrf={csrf}&confirm=yes"))
            .await;
        assert_eq!(location(&again), show);
        assert!(
            page_after(&app, &again, &cookie)
                .await
                .contains("This identity has no 2FA to reset.")
        );
        assert_eq!(resets(audit_rows(&app.db).await.unwrap()).len(), 1);
    }

    #[cfg(feature = "oauth-ory")]
    #[tokio::test]
    async fn admin_second_factor_reset_needs_an_aal2_admin() {
        let (app, admin, _, _) = admin_app().await;
        let target = app.user("t@x.test").await;
        app.add_totp(&target).await;
        let uri = format!("/admin/identities/{target}/reset-2fa");

        let (cookie, token) = browser_at(&app, &admin, Aal::Aal1).await;
        let resp = app
            .post(&uri, &cookie, &format!("_csrf={token}&confirm=yes"))
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(location(&resp).contains("aal=aal2"), "{}", location(&resp));

        let user = app.user("user@x.test").await;
        let (cookie, token) = browser_at(&app, &user, Aal::Aal2).await;
        let resp = app
            .post(&uri, &cookie, &format!("_csrf={token}&confirm=yes"))
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        assert!(
            store::keys::has_second_factor(&app.db, &target)
                .await
                .unwrap()
        );
    }

    #[cfg(feature = "oauth-ory")]
    #[tokio::test]
    async fn admin_disable_revokes_sessions_and_enable_brings_none_back() {
        let (app, _, cookie, csrf) = admin_app().await;
        let target = app.user("t@x.test").await;
        let (held, _, _) = app.signed_in(&target).await;
        let show = format!("/admin/identities/{target}");

        let confirm = body(app.get(&format!("{show}/disable"), &cookie).await).await;
        assert!(confirm.contains("Forseti browser sessions are revoked"));
        let done = app
            .post(
                &format!("{show}/disable"),
                &cookie,
                &format!("_csrf={csrf}&confirm=yes"),
            )
            .await;
        assert_eq!(location(&done), show);
        assert!(session::find_live(&app.db, &held).await.unwrap().is_none());
        assert!(!app.backend.is_session_active(&target, &held).await.unwrap());

        let enabled = app
            .post(&format!("{show}/enable"), &cookie, &format!("_csrf={csrf}"))
            .await;
        assert_eq!(location(&enabled), show);
        assert!(!app.backend.is_session_active(&target, &held).await.unwrap());
        assert!(
            app.backend
                .active_session_ids(&target)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
