mod accounts;
mod admin;
mod app;
mod audit;
mod auth;
mod cli;
mod client_ip;
mod client_logo;
mod commercial;
mod config;
mod config_cli;
mod cookies;
mod csrf;
mod dashboard;
mod db;
mod discovery;
mod extractors;
mod flash;
mod flow_view;
mod format;
mod handoff;
mod hydra_front;
mod i18n;
mod identity;
mod legal;
mod locale;
mod logo_cache;
mod mailer;
mod metrics;
mod oauth;
mod oauth_client_metadata;
mod oidc_providers;
mod orgs;
mod ory;
mod outbound;
mod page_chrome;
mod posix;
mod profiles;
mod rate_limit;
mod render;
mod resource_registry;
mod saml;
mod schema;
mod session_view;
mod settings;
mod signed_cookie;
mod state;
mod static_assets;
mod theme;
mod theming;
mod web;
mod webhook;

pub(crate) use web::{FlowQuery, render_error_boundary, safe_return_to};

use clap::Parser as _;
use cli::{Cli, Cmd, ConfigCmd, PruneCmd, RotateCmd};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
            let ory = ory::OryClients::from_config(&cfg);
            let db = bootstrap_db(&cfg).await?;
            let code = identity::prune_unverified_cli(&cfg, &db, &ory).await;
            std::process::exit(code);
        }
        Some(Cmd::PosixReconcile) => {
            let cfg = config::AppConfig::load()?;
            let db = bootstrap_db(&cfg).await?;
            let ory = ory::OryClients::from_config(&cfg);
            match posix::reconcile_orphans(&db, &ory).await {
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
            let ory = ory::OryClients::from_config(&cfg);
            match oauth::device::ensure_pam_client(&ory, &cfg.posix).await {
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
        Some(Cmd::ReconcileClientMetadata) => {
            let cfg = config::AppConfig::load()?;
            let ory = ory::OryClients::from_config(&cfg);
            let db = bootstrap_db(&cfg).await?;
            match reconcile_client_metadata(&db, &ory).await {
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
        // Pure file operations: Forseti can't read Kratos's live config via API, so these lint/generate the files.
        Some(Cmd::ConfigCheckAlias(args)) => std::process::exit(config_cli::check(&args)),
        Some(Cmd::ConfigInitAlias(args)) => std::process::exit(config_cli::init(&args)),
        Some(Cmd::Config(args)) => std::process::exit(dispatch_config(args).await),
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

/// `config` subcommand dispatch. Bare `forseti config` (`cmd: None`) drops
/// into the interactive menu when stdin is a TTY; otherwise it prints the
/// same clap help it always did and exits 2.
async fn dispatch_config(args: cli::ConfigArgs) -> i32 {
    use clap::CommandFactory;
    use std::io::{IsTerminal as _, Write};

    let cli::ConfigArgs { cmd, paths } = args;
    match cmd {
        Some(ConfigCmd::Check(args)) => config_cli::check(&args),
        Some(ConfigCmd::Init(args)) => config_cli::init(&args),
        Some(ConfigCmd::Status { json }) => config_cli::status(&paths, json),
        Some(ConfigCmd::Oidc { cmd }) => config_cli::run_oidc(cmd, &paths).await,
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::WebhookToken,
        }) => config_cli::run_rotate_webhook_token(&paths),
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::KratosSecrets { cookie, cipher },
        }) => config_cli::run_rotate_kratos_secrets(&paths, cookie, cipher),
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::HydraSystem,
        }) => config_cli::run_rotate_hydra_system(&paths),
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::PairwiseSalt { confirmed },
        }) => config_cli::run_rotate_pairwise_salt(&paths, confirmed).await,
        Some(ConfigCmd::Prune {
            cmd: PruneCmd::WebhookToken,
        }) => config_cli::run_prune_webhook_token(&paths),
        Some(ConfigCmd::Prune {
            cmd: PruneCmd::KratosSecrets { cookie, cipher },
        }) => config_cli::run_prune_kratos_secrets(&paths, cookie, cipher),
        Some(ConfigCmd::Prune {
            cmd: PruneCmd::HydraSystem,
        }) => config_cli::run_prune_hydra_system(&paths),
        Some(ConfigCmd::Restore { from }) => config_cli::run_restore(&paths, from),
        Some(ConfigCmd::Smtp { cmd }) => config_cli::run_smtp(cmd, &paths),
        None if std::io::stdin().is_terminal() => {
            use std::cell::RefCell;
            use std::rc::Rc;
            let input: Rc<RefCell<dyn config_cli::LineSource>> =
                Rc::new(RefCell::new(config_cli::StdinLines));
            let output: Rc<RefCell<dyn std::io::Write>> =
                Rc::new(RefCell::new(config_cli::RealStdout));
            let mut io = config_cli::MenuIo::new(input, output, true);
            config_cli::run_menu(&mut io, &paths)
        }
        None => {
            // Not a TTY (script/CI context): print clap-generated help instead.
            let mut config_cmd = Cli::command()
                .find_subcommand("config")
                .expect("config subcommand not found")
                .clone();
            let _ = writeln!(std::io::stderr(), "{}", config_cmd.render_help());
            2
        }
    }
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
/// One page, deliberately. The SDK drops Hydra's `Link: rel="next"` header, so
/// there is no honest way to follow the cursor from here — a full page means
/// the caller is told to re-run rather than being handed a silently short
/// answer.
async fn reconcile_client_metadata(
    db: &db::DbPool,
    ory: &ory::OryClients,
) -> anyhow::Result<(usize, usize)> {
    const PAGE: i64 = 500;
    let clients = ory::hydra::list_clients(ory, PAGE, None, None).await?;
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
