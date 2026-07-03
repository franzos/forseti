//! Bootstrap + router composition. [`run`] is the single entry point invoked from `main`.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
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

/// Returns 503 when the background webhook worker has been silent too long. The
/// threshold is generous (4x the 5-second tick) so a slow Postgres / paused VM
/// doesn't trip a false unready.
pub(crate) async fn readyz(State(state): State<AppState>) -> Response {
    const WORKER_STALE_SECS: i64 = 20;
    let stale = state.webhook_worker.seconds_since_last_tick();
    if stale > WORKER_STALE_SECS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("webhook worker stale: {stale}s since last tick"),
        )
            .into_response();
    }
    "ready".into_response()
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

    // Empty token means the audit webhook endpoint boots silently closed; always a deployment bug.
    if cfg.audit.webhook_token.is_empty() {
        eprintln!(
            "config error: audit.webhook_token must be set; the audit webhook endpoint \
             requires bearer authentication. Set it in config.toml (or via \
             FORSETI_AUDIT__WEBHOOK_TOKEN env var) and restart."
        );
        std::process::exit(1);
    }

    // Reject overlapping posix uid/gid bands at boot before a team gid can collide with a user gid on a host.
    cfg.posix.validate_bands()?;

    let ory = OryClients::from_config(&cfg);

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

    let cfg_internal_bind = cfg.internal.bind.clone();

    let state = AppState {
        cfg: Arc::new(cfg),
        ory,
        db,
        webhook_worker,
        signing_key,
        license,
        cookie_secret,
        discovery: crate::state::DiscoveryCache::default(),
    };

    // Forseti-owned CSRF-protected forms/POSTs. The middleware mints `forseti_csrf` and appends `Set-Cookie`;
    // `/healthz`, `/readyz`, the kratos webhook, and static assets stay outside the layer (no forms).
    let csrf_routes = Router::new()
        .route("/", get(dashboard::root))
        .merge(auth::router())
        .merge(settings::router())
        .merge(orgs::settings_page::router())
        .merge(orgs::invite::router())
        .merge(identity::claim_email::router(
            &state.cfg.proxy,
            &state.cfg.claim_email,
        ))
        .merge(profiles::router())
        .merge(oauth::router(&state.cfg.oauth, &state.cfg.proxy))
        .merge(accounts::router())
        .merge(handoff::router(&state.cfg.proxy, &state.cfg.handoff))
        .merge(admin::router())
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
        .route("/o/{slug}", get(orgs::public_landing::landing))
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
    let public_app = public_app
        .merge(static_assets::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit::middleware,
        ))
        // No page here needs to leak its URL (often carrying tokens/state params) to a
        // third-party Location header via the Referer request header on outbound links.
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // Internal listener: machine-to-machine endpoints only. No CSRF, no readiness probes (those stay on the public listener).
    let internal_app = Router::new()
        .merge(audit::kratos_webhook::router())
        .merge(crate::posix::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit::middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let public_addr: SocketAddr = "0.0.0.0:3000".parse()?;
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

/// Materialise the master cookie-signing secret. Hex string preferred (`openssl rand -hex 32`),
/// otherwise raw UTF-8 bytes; under 32 bytes hard-fails boot. Missing config falls back to 32
/// per-process random bytes with a warning (cookies won't survive restart) on dev URLs, but
/// hard-fails on a production-shaped URL: a per-process key silently rejects peers' cookies
/// across an HA fleet.
fn resolve_cookie_secret(configured: Option<&str>, self_url: &str) -> Arc<[u8]> {
    if let Some(raw) = configured.map(str::trim).filter(|s| !s.is_empty()) {
        let key: Box<[u8]> = match hex::decode(raw) {
            Ok(bytes) => bytes.into_boxed_slice(),
            Err(_) => raw.as_bytes().to_vec().into_boxed_slice(),
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
    use rand::Rng;
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
