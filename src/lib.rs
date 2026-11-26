#[cfg(all(feature = "identity-ory", feature = "identity-native"))]
compile_error!("features `identity-ory` and `identity-native` are mutually exclusive");
#[cfg(not(any(feature = "identity-ory", feature = "identity-native")))]
compile_error!("enable exactly one identity backend: `identity-ory` or `identity-native`");
#[cfg(all(feature = "oauth-ory", feature = "oauth-native"))]
compile_error!("features `oauth-ory` and `oauth-native` are mutually exclusive");
#[cfg(not(any(feature = "oauth-ory", feature = "oauth-native")))]
compile_error!(
    "enable exactly one OAuth backend: `oauth-ory` or `oauth-native`; valid builds are `--features identity-ory,oauth-ory` (the default), `identity-native,oauth-ory`, `identity-ory,oauth-native` and `identity-native,oauth-native`"
);

mod accounts;
mod admin;
mod app;
mod audit;
mod auth;
mod backend;
mod claim_template;
mod cli;
mod client_ip;
mod client_logo;
mod commercial;
mod config;
mod cookies;
mod csrf;
mod dashboard;
mod db;
mod discovery;
mod extractors;
mod flash;
mod flow_json;
mod flow_view;
mod format;
mod handoff;
#[cfg(feature = "oauth-ory")]
mod hydra_front;
mod i18n;
mod identity;
#[cfg(feature = "identity-native")]
mod identity_native;
mod legal;
mod locale;
mod logo_cache;
mod mailer;
mod metrics;
mod oauth;
mod oauth_client_metadata;
#[cfg(feature = "oauth-native")]
mod oauth_native;
mod oidc_providers;
mod oidc_rp;
mod orgs;
#[cfg(any(feature = "identity-ory", feature = "oauth-ory"))]
mod ory;
mod outbound;
mod page_chrome;
mod posix;
mod profiles;
mod protected_resource;
mod rate_limit;
mod render;
mod resource_registry;
mod saml;
mod schema;
#[cfg(any(feature = "identity-native", feature = "oauth-native"))]
mod seal;
mod session_view;
mod settings;
mod signed_cookie;
mod state;
mod static_assets;
mod theme;
mod theming;
mod web;
mod webhook;

pub mod fuzz_api;
#[cfg(any(feature = "identity-native", feature = "oauth-native"))]
pub mod native_test_support;

pub(crate) use web::{FlowQuery, render_error_boundary, safe_return_to};

#[cfg(feature = "oauth-native")]
use backend::OAuthBackend;
use clap::Parser as _;
use cli::{Cli, Cmd};

/// Process entry point: parse the CLI and run the server or a subcommand.
pub async fn run_cli() -> anyhow::Result<()> {
    let cmd = Cli::parse().cmd;
    if cmd.is_some() {
        init_cli_tracing();
    }
    match cmd {
        None => app::run().await,
        Some(Cmd::AuditPrune) => {
            let cfg = config::AppConfig::load()?;
            let db = bootstrap_db(&cfg).await?;
            let code = audit::prune_cli(&cfg, &db).await;
            std::process::exit(code);
        }
        Some(Cmd::UnverifiedPrune) => {
            let cfg = config::AppConfig::load()?;
            // Deletes go through Kratos's admin API but cascade to the local POSIX tables, so the pool is needed.
            let db = bootstrap_db(&cfg).await?;
            let identity_backend = cli_identity(&cfg, &db);
            let oauth_backend = cli_oauth(&cfg, &db);
            #[cfg(feature = "oauth-native")]
            cli_load_signing_keys(&oauth_backend).await;
            let code =
                identity::prune_unverified_cli(&cfg, &db, &identity_backend, &oauth_backend).await;
            #[cfg(feature = "oauth-native")]
            oauth_backend
                .drain_deliveries(oauth_native::DELIVERY_DRAIN)
                .await;
            std::process::exit(code);
        }
        Some(Cmd::DeleteIdentity { id, yes, force }) => {
            let cfg = config::AppConfig::load()?;
            let db = bootstrap_db(&cfg).await?;
            let identity_backend = cli_identity(&cfg, &db);
            let oauth_backend = cli_oauth(&cfg, &db);
            #[cfg(feature = "oauth-native")]
            cli_load_signing_keys(&oauth_backend).await;
            let code = identity::delete_identity_cli(
                &cfg,
                &db,
                &identity_backend,
                &oauth_backend,
                &id,
                yes,
                force,
            )
            .await;
            #[cfg(feature = "oauth-native")]
            oauth_backend
                .drain_deliveries(oauth_native::DELIVERY_DRAIN)
                .await;
            std::process::exit(code);
        }
        Some(Cmd::PosixReconcile) => {
            let cfg = config::AppConfig::load()?;
            let db = bootstrap_db(&cfg).await?;
            let identity_backend = cli_identity(&cfg, &db);
            match posix::reconcile_orphans(&db, &identity_backend).await {
                Ok(n) => {
                    println!("posix-reconcile: removed {n} orphaned posix account(s)");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("posix-reconcile: {e:?}");
                    std::process::exit(1);
                }
            }
        }
        Some(Cmd::PosixInitClient) => {
            let cfg = config::AppConfig::load()?;
            // Hydra needs no pool, so this verb works on a host without `forseti.db`.
            #[cfg(feature = "oauth-ory")]
            let oauth_backend = backend::HydraBackend::from_config(&cfg);
            #[cfg(feature = "oauth-native")]
            let oauth_backend = cli_oauth(&cfg, &bootstrap_db(&cfg).await?);
            match oauth::device::ensure_pam_client(&oauth_backend, &cfg.posix).await {
                Ok(oauth::device::EnsureOutcome::AlreadyExists) => {
                    println!(
                        "posix-init-client: client '{}' already exists — left untouched",
                        cfg.posix.pam_client_id
                    );
                    std::process::exit(0);
                }
                Ok(oauth::device::EnsureOutcome::Created { secret }) => {
                    println!(
                        "posix-init-client: created confidential client '{}'",
                        cfg.posix.pam_client_id
                    );
                    if secret.is_empty() {
                        println!(
                            "  using the operator-supplied [posix].pam_client_secret from config"
                        );
                    } else {
                        // One-shot reveal: Hydra won't show the plaintext again.
                        println!(
                            "  client_secret (shown ONCE — store it in [posix].pam_client_secret):"
                        );
                        println!("    {secret}");
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("posix-init-client: {e:?}");
                    std::process::exit(1);
                }
            }
        }
        #[cfg(feature = "oauth-native")]
        Some(Cmd::RotateOauthKey) => {
            let cfg = config::AppConfig::load()?;
            let oauth_backend = cli_oauth(&cfg, &bootstrap_db(&cfg).await?);
            match oauth_backend.rotate_key().await {
                Ok(rotated) => {
                    println!(
                        "rotate-oauth-key: retired {}, active {}",
                        rotated.retired, rotated.active
                    );
                    println!(
                        "  running instances sign with the new key after their next key reload, within an hour"
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("rotate-oauth-key: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Some(Cmd::ReconcileClientMetadata) => {
            let cfg = config::AppConfig::load()?;
            let db = bootstrap_db(&cfg).await?;
            let oauth_backend = cli_oauth(&cfg, &db);
            match reconcile_client_metadata(&db, &oauth_backend).await {
                Ok((stamped, seen)) => {
                    println!(
                        "reconcile-client-metadata: stamped {stamped} of {seen} Hydra client(s) as source=admin, verification=verified"
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("reconcile-client-metadata: {e:?}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Subcommands don't go through `app::run`'s JSON subscriber, so warnings from
/// `AppConfig::load` would otherwise be dropped. Stderr keeps stdout parseable.
fn init_cli_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .compact()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();
}

#[cfg(feature = "oauth-ory")]
fn cli_oauth(cfg: &config::AppConfig, db: &db::DbPool) -> std::sync::Arc<backend::OAuthImpl> {
    backend::build_oauth(cfg, db, &[])
}

#[cfg(feature = "oauth-native")]
fn cli_oauth(cfg: &config::AppConfig, db: &db::DbPool) -> std::sync::Arc<backend::OAuthImpl> {
    let cookie_secret = app::native_cookie_secret(cfg);
    if let Err(msg) = app::check_native_oauth(cfg) {
        eprintln!("config error: {msg}");
        std::process::exit(1);
    }
    backend::build_oauth(cfg, db, &cookie_secret)
}

/// The logout tokens of the sessions a verb ends are signed with these keys.
#[cfg(feature = "oauth-native")]
async fn cli_load_signing_keys(oauth: &backend::OAuthImpl) {
    if let Err(e) = oauth.init().await {
        tracing::warn!(
            error = format!("{e:#}"),
            "oauth signing keys did not load; back-channel logout will fail"
        );
    }
}

// Kratos ignores the cookie secret; resolving it here would add the server's boot checks to the CLI.
#[cfg(feature = "identity-ory")]
fn cli_identity(cfg: &config::AppConfig, db: &db::DbPool) -> std::sync::Arc<backend::IdentityImpl> {
    backend::build_identity(cfg, db, &[])
}

#[cfg(feature = "identity-native")]
fn cli_identity(cfg: &config::AppConfig, db: &db::DbPool) -> std::sync::Arc<backend::IdentityImpl> {
    let cookie_secret = app::native_cookie_secret(cfg);
    if let Err(msg) = app::check_native_identity(cfg) {
        eprintln!("config error: {msg}");
        std::process::exit(1);
    }
    backend::build_identity(cfg, db, &cookie_secret)
}

/// Shared DB prologue for the DB-touching subcommands: pool init + ping, then migrations unless skipped.
/// Migrations land tables a fresh DB lacks (e.g. audit_events + the sqlite trigger's `_forseti_meta` sentinel).
async fn bootstrap_db(cfg: &config::AppConfig) -> anyhow::Result<db::DbPool> {
    let db = db::DbPool::init_existing(&cfg.database)?;
    db.ping().await?;
    if !cfg.database.skip_migrations {
        db.run_migrations().await?;
    }
    Ok(db)
}

/// Back the consent badge's rowless-is-unverified inversion: walk the clients
/// Hydra knows and write an `oauth_client_metadata` row for the ones Forseti
/// has none for, marking them operator-created and verified.
///
/// A deploy step, not a boot task. Forseti's database and Hydra's are separate
/// servers, so no migration can enumerate Hydra's clients; and a half-finished
/// best-effort run at boot would transiently render legacy operator clients
/// unverified on the consent screen. Returns `(stamped, seen)`.
///
/// One page, deliberately. `list_clients` doesn't return Hydra's `Link: rel="next"`
/// cursor, so there is no honest way to follow the cursor from here — a full page means
/// the caller is told to re-run rather than being handed a silently short
/// answer.
async fn reconcile_client_metadata(
    db: &db::DbPool,
    oauth: &backend::OAuthImpl,
) -> anyhow::Result<(usize, usize)> {
    const PAGE: i64 = 500;
    let clients = oauth.list_clients(PAGE, None, None).await?;
    if clients.len() as i64 >= PAGE {
        eprintln!(
            "reconcile-client-metadata: WARNING — Hydra returned a full page of {PAGE} clients, \
             so there may be more. Re-run after confirming; clients already stamped are skipped."
        );
    }
    let (mut stamped, mut seen) = (0usize, 0usize);
    for client in &clients {
        let Some(client_id) = client.client_id.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        seen += 1;
        if oauth_client_metadata::backfill_legacy_admin(db, client_id).await? {
            stamped += 1;
            println!("  stamped {client_id}");
        }
    }
    Ok((stamped, seen))
}
