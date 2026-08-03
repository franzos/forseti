//! Bootstrap + router composition. [`run`] is the single entry point invoked from `main`.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use tokio_util::sync::CancellationToken;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::audit;
use crate::commercial::{self, LicenseHandle};
use crate::config::{AppConfig, DatabaseBackend, DatabaseConfig};
use crate::db::DbPool;
use crate::discovery;
use crate::handoff;
use crate::identity;
use crate::orgs;
use crate::ory::OryClients;
use crate::profiles;
use crate::state::AppState;
use crate::static_assets;
use crate::webhook;
use crate::{accounts, admin, auth, dashboard, oauth, settings};

pub(crate) async fn healthz() -> &'static str {
    "ok"
}

/// A stale webhook worker is reported as degraded info in the body but stays
/// 200: page serving is unaffected, so it must not 503 the whole instance.
/// The threshold scales with the operator-configured poll interval (4x
/// `[webhook].tick_seconds`, floor 20s) so a slow tick can't trip a false stale.
pub(crate) async fn readyz(State(state): State<AppState>) -> Response {
    let threshold = worker_stale_threshold_secs(state.cfg.webhook.tick_seconds);
    let stale = state.webhook_worker.seconds_since_last_tick();
    if stale > threshold {
        return format!("ready (degraded: webhook worker stale, {stale}s since last tick)")
            .into_response();
    }
    "ready".into_response()
}

fn worker_stale_threshold_secs(tick_seconds: u64) -> i64 {
    i64::try_from(tick_seconds.saturating_mul(4).max(20)).unwrap_or(i64::MAX)
}

pub(crate) async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .init();

    let cfg = AppConfig::load()?;

    // Unset (empty string or empty list) means the audit webhook endpoint boots silently closed; always a deployment bug.
    if cfg.audit.webhook_token.is_unset() {
        eprintln!(
            "config error: audit.webhook_token must be set; the audit webhook endpoint \
             requires bearer authentication. Set it in config.toml (or via \
             FORSETI_AUDIT__WEBHOOK_TOKEN env var) and restart."
        );
        std::process::exit(1);
    }
    if let Err(msg) = cfg.audit.webhook_token.validate() {
        eprintln!("config error: {msg}");
        std::process::exit(1);
    }

    // Reject overlapping posix uid/gid bands at boot before a team gid can collide with a user gid on a host.
    cfg.posix.validate_bands()?;

    let ory = OryClients::from_config(&cfg);

    // Refuse to serve POSIX device auth against a PAM client Hydra reports as
    // public: Forseti holds the `device_code` on every host's behalf, so a
    // credential-less token endpoint hands that grant to anyone. Only fires
    // when device auth is actually configured and Hydra positively answers.
    if cfg.posix.pam_client_secret.is_some()
        && crate::oauth::device::pam_client_is_public(&ory, &cfg.posix).await
    {
        eprintln!(
            "config error: OAuth client '{}' has token_endpoint_auth_method = none. \
             POSIX device auth requires a confidential client; reset it to \
             client_secret_basic in Hydra and restart.",
            cfg.posix.pam_client_id
        );
        std::process::exit(1);
    }

    let db = DbPool::init(&cfg.database)?;
    db.ping().await?;
    maybe_run_migrations(&db, &cfg.database).await?;
    warn_if_sqlite_in_production(&db, &cfg.self_.url);

    // Load before the worker spins up so the JWKS endpoint is queryable by the first delivery.
    let signing_key =
        webhook::SigningKey::load_or_generate(std::path::Path::new(&cfg.webhook.signing_key_path))?;

    // One Ctrl+C / SIGTERM fans out to the HTTP listeners and the webhook background tasks.
    let shutdown = CancellationToken::new();

    let cookie_secret =
        resolve_cookie_secret(cfg.security.cookie_secret.as_deref(), &cfg.self_.url);

    if cfg.audit.ip_salt.as_deref().is_none_or(str::is_empty) {
        tracing::warn!(
            "[audit].ip_salt not configured; the audit IP-pseudonymization salt is derived \
             from [security].cookie_secret. Setting a dedicated [audit].ip_salt is recommended \
             (e.g. `openssl rand -hex 32`); note rotating the cookie secret rotates audit \
             ip_hash values as a side-effect."
        );
    }

    // Reconcile PENDING rows stranded by a crash between writing the rows and the Kratos delete, then drain CONFIRMED rows.
    if let Err(e) = webhook::reconcile_pending(&db, &ory).await {
        tracing::warn!(error = %e, "webhook reconcile_pending failed at startup");
    }
    let webhook_worker = webhook::spawn_worker(db.clone(), cfg.webhook.clone(), shutdown.clone());
    // Periodic reconcile (every 60s, rows older than 5 minutes) so stuck PENDING rows don't wait for the next restart.
    webhook::spawn_reconcile(db.clone(), ory.clone(), shutdown.clone());

    // `store::load` falls back to `Unlicensed` on missing row or verification failure, so OSS and stale-key deployments boot cleanly.
    let grace_days = commercial::GRACE_DAYS;
    let initial_status = commercial::store::load(&db, grace_days).await;
    let license = LicenseHandle::new(initial_status, grace_days);
    // Status is otherwise only recomputed at boot / activate, so a license that booted Active never crosses into grace.
    commercial::spawn_reclassify(license.clone(), shutdown.clone());

    // Hourly POSIX reconcile for identities deleted out-of-band via the Kratos admin API; never purges on a Kratos lookup error.
    crate::posix::spawn_reconcile(db.clone(), ory.clone(), shutdown.clone());

    // Sweeps stale per-IP entries out of every keyed rate limiter built below.
    crate::rate_limit::spawn_retention(shutdown.clone());

    let cfg_public_bind = cfg.self_.bind.clone();
    let cfg_internal_bind = cfg.internal.bind.clone();
    let metrics_handle = crate::metrics::install_metrics_recorder();
    let ip_salt: Arc<str> = crate::audit::ip_salt(&cfg, &cookie_secret).into();

    let state = AppState {
        cfg: Arc::new(cfg),
        ory,
        db,
        webhook_worker,
        signing_key,
        license,
        cookie_secret,
        ip_salt,
        discovery: crate::state::DiscoveryCache::default(),
        logo_cache: Arc::new(tokio::sync::Mutex::new(
            crate::logo_cache::LogoCache::default(),
        )),
        metrics_handle,
    };

    // Forseti-owned CSRF-protected forms/POSTs. The middleware mints `forseti_csrf` and appends `Set-Cookie`;
    // `/healthz`, `/readyz`, the kratos webhook, and static assets stay outside the layer (no forms).
    let csrf_routes = Router::new()
        .route("/", get(dashboard::root))
        .merge(auth::router(&state.cfg.proxy, &state.cfg.auth))
        .merge(settings::router())
        .merge(orgs::settings_page::router())
        .merge(orgs::invite::router())
        .merge(orgs::join::router())
        .merge(orgs::domain_prompt::router())
        .merge(identity::claim_email::router(
            &state.cfg.proxy,
            &state.cfg.claim_email,
        ))
        .merge(profiles::router())
        .merge(oauth::router(&state.cfg.oauth, &state.cfg.proxy))
        .merge(accounts::router())
        .merge(handoff::router(&state.cfg.proxy, &state.cfg.handoff))
        .merge(admin::router())
        // One-shot secret reveals (client secrets, recovery codes, DCR + registration access
        // tokens, POSIX host secrets) render on these routes; none of them may reach a disk
        // cache or an intermediary.
        .route_layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::csrf::middleware,
        ))
        // Lazy auto-join into the Default org; cheap-skips when no Kratos session cookie is present.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::orgs::middleware::auto_join_default_org,
        ))
        // Persist a supported ?lang= query param to forseti_locale cookie so the
        // language switcher survives navigation without relying on Accept-Language.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::locale::persist_locale_middleware,
        ));

    let mut public_app = Router::new()
        .merge(csrf_routes)
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(orgs::public_landing::router(
            &state.cfg.orgs,
            &state.cfg.proxy,
        ))
        .merge(crate::legal::router(&state.cfg.proxy))
        .merge(orgs::logo::router(&state.cfg.orgs, &state.cfg.proxy))
        .merge(crate::client_logo::router(
            &state.cfg.orgs,
            &state.cfg.proxy,
        ))
        // Public JWKS for outbound webhook signature verification (RFC 8417 SETs); outside the CSRF layer.
        .route(
            "/.well-known/webhook-jwks.json",
            get(webhook::jwks_endpoint),
        )
        .merge(discovery::router());
    // SSO routes mount only when [saml] is configured; outside CSRF (Jackson's callback is a cross-site GET).
    if state.cfg.saml.is_some() {
        public_app = public_app.merge(crate::saml::router());
    }
    // Falls back to `[hydra].public_url` the same way the device id_token's
    // issuer check does, so a deployment where the two match needs no extra config.
    let hydra_issuer = state
        .cfg
        .posix
        .hydra_issuer
        .clone()
        .unwrap_or_else(|| state.cfg.hydra.public_url.clone());
    let form_action = csp_form_action(
        &state.cfg.kratos.public_url,
        &state.cfg.hydra.public_url,
        &hydra_issuer,
        &state.cfg.security.extra_form_action,
    );
    let csp_value = axum::http::HeaderValue::from_str(&build_csp(
        &state.cfg.security.frame_ancestors,
        &form_action,
    ))
    .unwrap_or_else(|e| {
        eprintln!(
            "config error: [security].frame_ancestors {:?} is not a valid header value: {e}",
            state.cfg.security.frame_ancestors
        );
        std::process::exit(1);
    });

    let mut public_app = public_app
        .merge(static_assets::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit::middleware,
        ))
        .layer(axum::middleware::from_fn(
            crate::metrics::track_http_metrics,
        ))
        // No page here needs to leak its URL (often carrying tokens/state params) to a
        // third-party Location header via the Referer request header on outbound links.
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CONTENT_SECURITY_POLICY,
            csp_value,
        ));
    if state.cfg.security.x_frame_options {
        public_app = public_app.layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("SAMEORIGIN"),
        ));
    }
    // `/join/confirm` and `/oauth/consent` must always be unframable (CSRF POST), overriding global config.
    let csp_sources = CspSources {
        frame_ancestors: state.cfg.security.frame_ancestors.clone(),
        form_action,
    };
    let public_app = public_app
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            csp_sources,
            strict_frame_for_sensitive,
        ))
        .with_state(state.clone());

    // Internal listener: machine-to-machine endpoints only. No CSRF, no readiness probes (those stay on the public listener).
    // `/metrics` is added AFTER the metrics/audit layers so scrapes aren't self-counted and don't generate audit noise.
    let internal_app = Router::new()
        .merge(audit::kratos_webhook::router())
        .merge(crate::posix::router(state.clone()))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit::middleware,
        ))
        .layer(axum::middleware::from_fn(
            crate::metrics::track_http_metrics,
        ))
        .layer(TraceLayer::new_for_http())
        .route(
            "/metrics",
            axum::routing::get(crate::metrics::metrics_handler),
        )
        .with_state(state);

    let public_addr: SocketAddr = cfg_public_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid [self].bind value '{cfg_public_bind}': {e}"))?;
    let internal_addr: SocketAddr = cfg_internal_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid [internal].bind value '{cfg_internal_bind}': {e}"))?;
    tracing::info!("public listener on {public_addr}");
    tracing::info!("internal listener on {internal_addr}");

    let public_listener = tokio::net::TcpListener::bind(public_addr).await?;
    let internal_listener = tokio::net::TcpListener::bind(internal_addr).await?;

    let public_shutdown = shutdown.clone();
    let internal_shutdown = shutdown.clone();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signal_shutdown.cancel();
    });

    // `into_make_service_with_connect_info` puts the TCP peer `SocketAddr` into request extensions so
    // tower_governor's `PeerIpKeyExtractor` can see it when `proxy.trust_forwarded_for = false`.
    let public_fut = axum::serve(
        public_listener,
        public_app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        public_shutdown.cancelled().await;
    })
    .into_future();

    let internal_fut = axum::serve(
        internal_listener,
        internal_app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        internal_shutdown.cancelled().await;
    })
    .into_future();

    tokio::try_join!(public_fut, internal_fut)?;

    Ok(())
}

/// Run embedded migrations on startup unless `[database].skip_migrations` opts out
/// (for deploys that gate schema changes through a pipeline).
async fn maybe_run_migrations(db: &DbPool, cfg: &DatabaseConfig) -> anyhow::Result<()> {
    if cfg.skip_migrations {
        tracing::info!("database migrations skipped (skip_migrations = true)");
        return Ok(());
    }
    tracing::info!(backend = ?db.backend(), "running database migrations");
    db.run_migrations().await?;
    Ok(())
}

/// Sqlite + a production-shaped Forseti URL is a multi-instance corruption footgun.
/// We can only see deployment shape from here, so we warn (and also surface it on `/admin/status`).
fn warn_if_sqlite_in_production(db: &DbPool, self_url: &str) {
    if db.backend() != DatabaseBackend::Sqlite {
        return;
    }
    if !DatabaseConfig::looks_like_production(self_url) {
        return;
    }
    tracing::warn!(
        self_url = %self_url,
        "sqlite + production-looking deployment; multi-instance setups will corrupt the database. Switch to Postgres for HA."
    );
}

/// Materialise the master cookie-signing secret. Hex string preferred (`openssl rand -hex 32`);
/// a 64-char value that isn't valid hex hard-fails boot (typo guard), other lengths fall back
/// to raw UTF-8 bytes; under 32 bytes hard-fails boot. Missing config falls back to 32
/// per-process random bytes with a warning (cookies won't survive restart) on dev URLs, but
/// hard-fails on a production-shaped URL: a per-process key silently rejects peers' cookies
/// across an HA fleet.
fn resolve_cookie_secret(configured: Option<&str>, self_url: &str) -> Arc<[u8]> {
    if let Some(raw) = configured.map(str::trim).filter(|s| !s.is_empty()) {
        let key: Box<[u8]> = match hex::decode(raw) {
            Ok(bytes) => bytes.into_boxed_slice(),
            // 64 chars is the `openssl rand -hex 32` shape; a silent raw-bytes
            // fallback would yield a different key than intended (HA cookie mismatch).
            Err(_) if raw.len() == 64 => {
                eprintln!(
                    "config error: [security].cookie_secret is 64 characters but is not valid \
                     hex. A 64-char secret is always treated as hex (`openssl rand -hex 32`); \
                     fix the typo (only 0-9a-f allowed), or use a different length to opt into \
                     raw-byte interpretation, and restart."
                );
                std::process::exit(1);
            }
            Err(_) => {
                static RAW_BYTES_WARN: std::sync::Once = std::sync::Once::new();
                RAW_BYTES_WARN.call_once(|| {
                    tracing::warn!(
                        "[security].cookie_secret is not hex; interpreting it as raw UTF-8 \
                         bytes. Prefer a hex secret from `openssl rand -hex 32`."
                    );
                });
                raw.as_bytes().to_vec().into_boxed_slice()
            }
        };
        if key.len() < 32 {
            eprintln!(
                "config error: [security].cookie_secret decodes to {} bytes; a minimum of 32 \
                 bytes is required for a strong HMAC key. Generate one with `openssl rand -hex \
                 32` (or via FORSETI_SECURITY__COOKIE_SECRET) and restart.",
                key.len()
            );
            std::process::exit(1);
        }
        return Arc::from(key);
    }
    if DatabaseConfig::looks_like_production(self_url) {
        eprintln!(
            "config error: [security].cookie_secret is unset on a production-looking deployment \
             ({self_url}). A per-process ephemeral key silently rejects peers' signed cookies \
             across a multi-instance fleet. Generate one with `openssl rand -hex 32` (or via \
             FORSETI_SECURITY__COOKIE_SECRET) and restart."
        );
        std::process::exit(1);
    }
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    tracing::warn!(
        "[security].cookie_secret not configured; generated ephemeral 32-byte key. \
         Flash, active-org, and app-referrer cookies will not survive restart. \
         Set [security].cookie_secret in production (e.g. `openssl rand -hex 32`)."
    );
    Arc::from(bytes.to_vec().into_boxed_slice())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

// omits default-src/script-src/style-src/img-src: those break WebAuthn/QR/Shape-2 forms
fn build_csp(frame_ancestors: &str, form_action: &str) -> String {
    format!(
        "object-src 'none'; base-uri 'self'; frame-ancestors {frame_ancestors}; \
         form-action {form_action}"
    )
}

/// `form-action` sources: `'self'` plus every origin a form POST is legitimately allowed to end
/// up at.
///
/// Kratos, because the login, registration, recovery, verification and settings forms take their
/// `action` verbatim from the Kratos flow JSON, which points at Kratos's own origin.
///
/// Hydra, because `form-action` is enforced across redirects, not just on the form's `action`:
/// consent, logout and device approval all POST to the portal and answer with a 303 into Hydra.
/// Leave Hydra out and the browser silently blocks that navigation — the server logs a clean 303
/// and the user sits on an unchanged page.
///
/// Hydra's browser-facing origin is its `urls.self.issuer`, which can differ from
/// `[hydra].public_url` (a container-reachable hostname vs `localhost`), so both are listed when
/// they differ. Origin only (scheme+host+port); CSP source expressions with a path would not match
/// the flow's action URL anyway.
fn csp_form_action(
    kratos_public_url: &str,
    hydra_public_url: &str,
    hydra_issuer: &str,
    extra: &[String],
) -> String {
    let mut sources = vec!["'self'".to_string()];
    for url in [kratos_public_url, hydra_public_url, hydra_issuer]
        .into_iter()
        .chain(extra.iter().map(String::as_str))
    {
        if let Some(origin) = csp_origin_source(url)
            && !sources.contains(&origin)
        {
            sources.push(origin);
        }
    }
    sources.join(" ")
}

/// `url`'s origin as a CSP source expression, or `None` if it isn't a plain
/// `scheme://host[:port]`.
///
/// A `;` is legal in a host and survives origin serialization — Hydra accepts
/// `https://a;sandbox/cb` as a redirect URI — while in a CSP header a `;` ends
/// the directive. Without this filter, registering that URI appends an
/// attacker-chosen directive (`sandbox`, say, which neuters the page) to the
/// header of whichever page allowlists that client.
fn csp_origin_source(url: &str) -> Option<String> {
    let origin = crate::csrf::url_origin(url)?;
    origin
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | '[' | ']'))
        .then_some(origin)
}

/// Base CSP inputs the response-time middleware needs to rebuild the header for
/// a single response.
#[derive(Clone)]
struct CspSources {
    frame_ancestors: String,
    form_action: String,
}

/// Extra `form-action` origins for one response, attached by a handler that
/// knows where its form is allowed to end up.
///
/// An authorization server can't express this statically: after consent the
/// browser has to reach the client's registered `redirect_uri`, which differs
/// per client. Handlers that render such a form attach the origins Hydra
/// already validated for that client, so the allowlist stays exact instead of
/// being widened for everyone.
#[derive(Clone)]
pub(crate) struct ExtraFormAction(pub(crate) Vec<String>);

/// Ceiling on per-response extra origins. A client registers a handful of
/// redirect URIs in practice; the registration endpoint accepts far more, and
/// an unbounded list turns into a header big enough for a reverse proxy to
/// refuse the response.
const MAX_EXTRA_FORM_ACTION: usize = 16;

/// Attach the distinct origins of `uris` to `resp` as extra `form-action`
/// sources. Entries that aren't a plain `scheme://host[:port]` are skipped; a
/// client with none usable simply adds nothing. Additive: a page whose form can
/// reach both an OAuth client and an upstream IdP calls this once per set.
pub(crate) fn allow_form_action_to(resp: &mut Response, uris: &[String]) {
    let mut origins: Vec<String> = resp
        .extensions()
        .get::<ExtraFormAction>()
        .map(|e| e.0.clone())
        .unwrap_or_default();
    let before = origins.len();
    for uri in uris {
        if origins.len() >= MAX_EXTRA_FORM_ACTION {
            tracing::debug!(
                cap = MAX_EXTRA_FORM_ACTION,
                "form-action: extra origins capped; the rest are not allowlisted"
            );
            break;
        }
        if let Some(origin) = csp_origin_source(uri)
            && !origins.contains(&origin)
        {
            origins.push(origin);
        }
    }
    if origins.len() > before {
        resp.extensions_mut().insert(ExtraFormAction(origins));
    }
}

/// Forces `frame-ancestors 'none'` + `X-Frame-Options: DENY` on sensitive, state-changing pages,
/// overriding global config, and folds in any per-response [`ExtraFormAction`].
async fn strict_frame_for_sensitive(
    State(sources): State<CspSources>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let sensitive = matches!(req.uri().path(), "/join/confirm" | "/oauth/consent");
    let mut resp = next.run(req).await;
    let extra = resp.extensions().get::<ExtraFormAction>().cloned();

    if sensitive || extra.is_some() {
        let frame_ancestors = if sensitive {
            "'none'"
        } else {
            sources.frame_ancestors.as_str()
        };
        let form_action = match extra {
            Some(ExtraFormAction(origins)) if !origins.is_empty() => {
                format!("{} {}", sources.form_action, origins.join(" "))
            }
            _ => sources.form_action.clone(),
        };
        // A bad origin can only come from client metadata, so drop the addition
        // rather than the whole header if it won't serialise.
        if let Ok(v) = axum::http::HeaderValue::from_str(&build_csp(frame_ancestors, &form_action))
        {
            resp.headers_mut()
                .insert(axum::http::header::CONTENT_SECURITY_POLICY, v);
        }
    }
    if sensitive {
        resp.headers_mut().insert(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        );
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::{
        ExtraFormAction, MAX_EXTRA_FORM_ACTION, allow_form_action_to, build_csp, csp_form_action,
        csp_origin_source, resolve_cookie_secret, worker_stale_threshold_secs,
    };

    #[test]
    fn worker_stale_threshold_scales_with_tick_and_floors_at_20() {
        assert_eq!(worker_stale_threshold_secs(1), 20);
        assert_eq!(worker_stale_threshold_secs(5), 20);
        assert_eq!(worker_stale_threshold_secs(6), 24);
        assert_eq!(worker_stale_threshold_secs(60), 240);
        assert_eq!(worker_stale_threshold_secs(u64::MAX), i64::MAX);
    }

    #[test]
    fn cookie_secret_64_char_hex_decodes_to_32_bytes() {
        let hex64 = "ab".repeat(32);
        let key = resolve_cookie_secret(Some(&hex64), "http://localhost:3000");
        assert_eq!(key.len(), 32);
        assert!(key.iter().all(|b| *b == 0xab));
    }

    #[test]
    fn cookie_secret_non_hex_other_length_uses_raw_bytes() {
        let raw = "x".repeat(40);
        let key = resolve_cookie_secret(Some(&raw), "http://localhost:3000");
        assert_eq!(&*key, raw.as_bytes());
    }

    #[test]
    fn cookie_secret_unset_on_dev_url_is_ephemeral_32_bytes() {
        let key = resolve_cookie_secret(None, "http://localhost:3000");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn csp_contains_safe_directives() {
        let csp = build_csp("'self'", "'self'");
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("base-uri 'self'"));
        assert!(csp.contains("frame-ancestors 'self'"));
        assert!(csp.contains("form-action 'self'"));
    }

    /// `form-action` is enforced across redirects, so leaving Hydra out silently
    /// breaks consent, logout and device approval: the POST lands, the server
    /// answers 303, and the browser refuses to follow it.
    #[test]
    fn form_action_allows_hydra_as_well_as_kratos() {
        let csp = csp_form_action(
            "http://localhost:4433",
            "http://localhost:4444",
            "http://localhost:4444",
            &[],
        );
        assert!(csp.contains("http://localhost:4433"), "kratos: {csp}");
        assert!(csp.contains("http://localhost:4444"), "hydra: {csp}");
        // public_url == issuer must not be listed twice.
        assert_eq!(csp.matches("http://localhost:4444").count(), 1, "{csp}");
    }

    /// Hydra's browser-facing origin is its issuer, which in the playground is a
    /// container-reachable hostname while `[hydra].public_url` stays localhost.
    /// Both have to be allowed.
    #[test]
    fn form_action_covers_an_issuer_that_differs_from_public_url() {
        let csp = csp_form_action(
            "http://localhost:4433",
            "http://localhost:4444",
            "http://host.containers.internal:4444",
            &[],
        );
        assert!(csp.contains("http://localhost:4444"), "{csp}");
        assert!(
            csp.contains("http://host.containers.internal:4444"),
            "{csp}"
        );
    }

    /// Escape hatch for an upstream Forseti can't derive (a provider added to
    /// kratos.yml by hand, or a host one of the built-ins bounces through).
    #[test]
    fn form_action_appends_operator_supplied_origins() {
        let csp = csp_form_action(
            "http://localhost:4433",
            "http://localhost:4444",
            "http://localhost:4444",
            &["https://idp.example.com/authorize".to_string()],
        );
        assert!(csp.ends_with("https://idp.example.com"), "{csp}");
    }

    /// A `;` in a host ends the CSP directive, so a redirect URI like
    /// `https://a;sandbox/cb` — which Hydra accepts — would otherwise append a
    /// `sandbox` directive to the page that allowlists that client.
    #[test]
    fn csp_origin_source_rejects_directive_separators() {
        assert_eq!(csp_origin_source("https://a;sandbox/cb"), None);
        assert_eq!(
            csp_origin_source("https://ok.example.com/cb").as_deref(),
            Some("https://ok.example.com")
        );
        assert_eq!(
            csp_origin_source("http://[::1]:4444/cb").as_deref(),
            Some("http://[::1]:4444")
        );
        // Opaque origins (custom schemes) carry no host to allow.
        assert_eq!(csp_origin_source("myapp://cb"), None);
    }

    #[test]
    fn form_action_drops_an_origin_carrying_a_separator() {
        let csp = csp_form_action(
            "http://localhost:4433",
            "",
            "",
            &["https://a;sandbox".to_string()],
        );
        assert!(!csp.contains("sandbox"), "{csp}");
    }

    #[test]
    fn extra_form_action_is_capped() {
        let uris: Vec<String> = (0..40)
            .map(|i| format!("https://c{i}.example.com/cb"))
            .collect();
        let mut resp = axum::response::Response::new(axum::body::Body::empty());
        allow_form_action_to(&mut resp, &uris);
        let extra = resp
            .extensions()
            .get::<ExtraFormAction>()
            .expect("extra set");
        assert_eq!(extra.0.len(), MAX_EXTRA_FORM_ACTION);
    }

    #[test]
    fn form_action_falls_back_to_self_on_unparseable_urls() {
        assert_eq!(csp_form_action("", "", "", &[]), "'self'");
    }

    #[test]
    fn csp_omits_breaking_directives() {
        let csp = build_csp("'self'", "'self'");
        assert!(!csp.contains("default-src"));
        assert!(!csp.contains("script-src"));
        assert!(!csp.contains("style-src"));
        assert!(!csp.contains("img-src"));
    }

    #[test]
    fn csp_uses_configured_frame_ancestors() {
        let csp = build_csp("https://example.com", "'self'");
        assert!(csp.contains("frame-ancestors https://example.com"));
    }

    #[test]
    fn csp_form_action_allows_self_and_kratos_origin() {
        // Kratos renders its flow forms' action; a bare 'self' would break every login POST.
        assert_eq!(
            csp_form_action("http://127.0.0.1:4433/", "", "", &[]),
            "'self' http://127.0.0.1:4433"
        );
        assert_eq!(
            csp_form_action("https://auth.example.com/self-service/login", "", "", &[]),
            "'self' https://auth.example.com"
        );
    }

    #[test]
    fn csp_form_action_falls_back_to_self_on_unparseable_kratos_url() {
        assert_eq!(csp_form_action("not a url", "", "", &[]), "'self'");
    }

    #[test]
    fn csp_form_action_lands_in_the_header() {
        let csp = build_csp(
            "'none'",
            &csp_form_action("https://auth.example.com", "", "", &[]),
        );
        assert!(csp.contains("form-action 'self' https://auth.example.com"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    /// The per-response hook is what makes an allowlisted `form-action` workable
    /// for an authorization server: the client's registered redirect URIs are
    /// only knowable per request.
    #[test]
    fn extra_form_action_carries_distinct_client_origins() {
        let mut resp = axum::response::IntoResponse::into_response("ok");
        allow_form_action_to(
            &mut resp,
            &[
                "https://app.example.com/cb".to_string(),
                "https://app.example.com/other".to_string(),
                "https://other.example.com/cb".to_string(),
                "not a url".to_string(),
            ],
        );
        let extra = resp
            .extensions()
            .get::<ExtraFormAction>()
            .expect("origins attached");
        assert_eq!(
            extra.0,
            vec!["https://app.example.com", "https://other.example.com"]
        );
    }

    #[test]
    fn extra_form_action_absent_when_no_origin_is_usable() {
        let mut resp = axum::response::IntoResponse::into_response("ok");
        allow_form_action_to(&mut resp, &["not a url".to_string()]);
        assert!(resp.extensions().get::<ExtraFormAction>().is_none());
    }
}
