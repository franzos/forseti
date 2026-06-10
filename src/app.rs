//! Bootstrap + router composition.
//!
//! [`run`] wires tracing, config, the Ory client bundle, and the merged
//! feature routers into an `axum::serve` call with graceful shutdown. It is
//! the single entry point invoked from `main`.

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
use tower_http::{services::ServeDir, trace::TraceLayer};

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
use crate::webhook;
use crate::{admin, auth, dashboard, oauth, settings};

pub(crate) async fn healthz() -> &'static str {
    "ok"
}

/// Liveness gate consulted by orchestrators. Returns 503 when the
/// background webhook worker is silent for too long — a stuck or dead
/// worker that liveness wouldn't otherwise notice. The threshold is
/// generous (4× the 5-second tick) so a slow Postgres / paused VM
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

    // Fail loudly when the audit webhook bearer is missing rather than
    // letting Forseti boot with the webhook endpoint silently closed.
    // The endpoint is the only documented path for Kratos audit events, so
    // an empty token here is always a deployment bug.
    if cfg.audit.webhook_token.is_empty() {
        eprintln!(
            "config error: audit.webhook_token must be set; the audit webhook endpoint \
             requires bearer authentication. Set it in config.toml (or via \
             FORSETI_AUDIT__WEBHOOK_TOKEN env var) and restart."
        );
        std::process::exit(1);
    }

    let ory = OryClients::from_config(&cfg);

    let db = DbPool::init(&cfg.database)?;
    db.ping().await?;
    maybe_run_migrations(&db, &cfg.database).await?;
    warn_if_sqlite_in_production(&db, &cfg.self_.url);

    // Load (or generate) the RSA key the outbound webhooks sign with.
    // Done before the worker spins up so the JWKS endpoint is queryable
    // by the time the first delivery lands on a receiver.
    let signing_key =
        webhook::SigningKey::load_or_generate(std::path::Path::new(&cfg.webhook.signing_key_path))?;

    // Shared shutdown token: one Ctrl+C / SIGTERM fans out to the HTTP
    // listeners *and* the webhook background tasks so the runtime can
    // wind down cleanly. `CancellationToken` is the idiomatic tokio
    // primitive for this — every clone observes the same one-shot
    // cancellation, with no broadcast-channel capacity or Lagged
    // semantics to worry about.
    let shutdown = CancellationToken::new();

    // Resolve the master cookie-signing secret. Hex-decoded when
    // possible (operators paste `openssl rand -hex 32`); raw bytes
    // otherwise. Falls back to a per-boot ephemeral 32-byte key with a
    // loud warning — fine for dev (cookies dropped on restart) but a
    // misconfiguration in production.
    let cookie_secret = resolve_cookie_secret(cfg.security.cookie_secret.as_deref());

    // Phase 1: account-deletion outbox. Reconcile any PENDING rows that
    // were stranded by a prior crash (between writing the rows and the
    // Kratos delete), then spin up the worker that drains CONFIRMED rows.
    if let Err(e) = webhook::reconcile_pending(&db, &ory).await {
        tracing::warn!(error = %e, "webhook reconcile_pending failed at startup");
    }
    let webhook_worker = webhook::spawn_worker(db.clone(), cfg.webhook.clone(), shutdown.clone());
    // Periodic reconcile so stuck PENDING rows don't sit until the
    // next Forseti restart. Runs every 60s; bounded to rows older than
    // 5 minutes so it can't interfere with in-flight sagas.
    webhook::spawn_reconcile(db.clone(), ory.clone(), shutdown.clone());

    // Boot the license gate. `commercial::store::load` falls back to
    // `Unlicensed` on missing row or verification failure, so Forseti
    // boots cleanly on both OSS deployments and stale-key scenarios.
    let grace_days = commercial::GRACE_DAYS;
    let initial_status = commercial::store::load(&db, grace_days).await;
    let license = LicenseHandle::new(initial_status, grace_days);

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

    // Forseti-owned routes that render CSRF-protected forms or handle
    // CSRF-protected POSTs. The CSRF middleware mints `forseti_csrf` on the
    // way in and appends `Set-Cookie` on the way out; handlers read the
    // token via the `Csrf` extractor instead of re-fetching the cookie.
    // `/healthz`, `/readyz`, the kratos webhook, and the static asset
    // service stay outside the layer — they don't render forms and would
    // only pollute responses with an unused Set-Cookie.
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
        .merge(commercial::router())
        .merge(oauth::router(&state.cfg.oauth, &state.cfg.proxy))
        .merge(handoff::router(&state.cfg.proxy, &state.cfg.handoff))
        .merge(admin::router())
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::csrf::middleware,
        ))
        // Lazy auto-join into the Default org. Cheap-skips when no Kratos
        // session cookie is present, so unauthenticated routes inside this
        // bundle (login, registration, claim-email, etc.) pay nothing.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::orgs::middleware::auto_join_default_org,
        ));

    let mut public_app = Router::new()
        .merge(csrf_routes)
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Public JWKS for outbound webhook signature verification (RFC 8417
        // SETs). Sits alongside `/healthz` / `/readyz` so it stays outside
        // the CSRF layer — no cookies, no forms.
        .route(
            "/.well-known/webhook-jwks.json",
            get(webhook::jwks_endpoint),
        )
        .merge(discovery::router());
    // SSO routes mount only when [saml] is configured; inside the audit
    // layer, outside CSRF (Jackson's callback is a cross-site GET).
    if state.cfg.saml.is_some() {
        public_app = public_app.merge(crate::saml::router());
    }
    let public_app = public_app
        .nest_service("/static", ServeDir::new("./static"))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit::middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // Internal listener: machine-to-machine endpoints only. No CSRF layer
    // (no cookies, no forms), no readiness probes (those stay on the
    // public listener so k8s / load-balancer probes don't have to know
    // about a second port). Today this only carries the audit webhook;
    // future internal endpoints land here too.
    let internal_app = Router::new()
        .merge(audit::kratos_webhook::router())
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

    // Hand each listener its own clone of the shutdown token (the
    // webhook background tasks are already holding clones). One
    // Ctrl+C / SIGTERM fires `cancel()` once and every clone observes
    // it.
    let public_shutdown = shutdown.clone();
    let internal_shutdown = shutdown.clone();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signal_shutdown.cancel();
    });

    // `into_make_service_with_connect_info` puts the TCP peer
    // `SocketAddr` into request extensions so tower_governor's
    // `PeerIpKeyExtractor` (used by the per-IP rate limiters when
    // `proxy.trust_forwarded_for = false`) can see it. Harmless for
    // every other handler — extensions are pull-based.
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

/// Run embedded migrations on startup unless the operator has opted out via
/// `FORSETI_DATABASE__SKIP_MIGRATIONS=1` / `[database].skip_migrations = true`.
/// Default-on is the self-hoster ergonomics call from `TODO.md` §0; the
/// opt-out exists for deploys that gate schema changes through a pipeline.
async fn maybe_run_migrations(db: &DbPool, cfg: &DatabaseConfig) -> anyhow::Result<()> {
    if cfg.skip_migrations {
        tracing::info!("database migrations skipped (skip_migrations = true)");
        return Ok(());
    }
    tracing::info!(backend = ?db.backend(), "running database migrations");
    db.run_migrations().await?;
    Ok(())
}

/// Sqlite + a production-shaped Forseti URL is the multi-instance corruption
/// footgun called out in `TODO.md` §0. We can't see other instances from
/// here, only deployment shape — so we log a warn and (separately) surface
/// the same fact on `/admin/status`.
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

/// Materialise the master cookie-signing secret. Hex string preferred
/// (operators paste `openssl rand -hex 32`); a string that fails hex
/// decode is treated as raw UTF-8 bytes. Missing config → 32 random
/// bytes for this process only, with a loud warning so the operator
/// knows cookies won't survive restart.
fn resolve_cookie_secret(configured: Option<&str>) -> Arc<[u8]> {
    if let Some(raw) = configured.map(str::trim).filter(|s| !s.is_empty()) {
        let key: Box<[u8]> = match hex::decode(raw) {
            Ok(bytes) => bytes.into_boxed_slice(),
            Err(_) => raw.as_bytes().to_vec().into_boxed_slice(),
        };
        if key.len() < 32 {
            tracing::warn!(
                len = key.len(),
                "[security].cookie_secret is shorter than 32 bytes; this is a weak HMAC key. \
                 Use `openssl rand -hex 32` to generate a strong secret."
            );
        }
        return Arc::from(key);
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
