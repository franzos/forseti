mod accounts;
mod admin;
mod app;
mod audit;
mod auth;
mod cli;
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
mod page_chrome;
mod posix;
mod profiles;
mod rate_limit;
mod render;
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

pub(crate) use web::{render_error_boundary, safe_return_to, FlowQuery};

use clap::Parser as _;
use cli::{Cli, Cmd, ConfigCmd, PruneCmd, RotateCmd};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
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
        // Pure file operations: Forseti can't read Kratos's live config via API, so these lint/generate the files.
        Some(Cmd::ConfigCheckAlias(args)) => std::process::exit(config_cli::check(&args)),
        Some(Cmd::ConfigInitAlias(args)) => std::process::exit(config_cli::init(&args)),
        Some(Cmd::Config(args)) => std::process::exit(dispatch_config(args).await),
    }
}

/// `config` subcommand dispatch. Variants beyond `check`/`init`/`status`
/// (and the bare interactive menu) land in later tasks; until then they're a
/// stub.
async fn dispatch_config(args: cli::ConfigArgs) -> i32 {
    use clap::CommandFactory;
    use std::io::Write;

    let cli::ConfigArgs { cmd, paths } = args;
    match cmd {
        Some(ConfigCmd::Check(args)) => config_cli::check(&args),
        Some(ConfigCmd::Init(args)) => config_cli::init(&args),
        Some(ConfigCmd::Status { json }) => config_cli::status(&paths, json),
        Some(ConfigCmd::Oidc { cmd }) => config_cli::run_oidc(cmd, &paths).await,
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::WebhookToken,
        }) => config_cli::run_rotate_webhook_token(&paths),
        Some(ConfigCmd::Prune {
            cmd: PruneCmd::WebhookToken,
        }) => config_cli::run_prune_webhook_token(&paths),
        None => {
            // Print clap-generated help for the config subcommand to stderr.
            let mut config_cmd = Cli::command()
                .find_subcommand("config")
                .expect("config subcommand not found")
                .clone();
            let _ = writeln!(std::io::stderr(), "{}", config_cmd.render_help());
            2
        }
        _ => {
            eprintln!("not implemented yet");
            2
        }
    }
}

/// Shared DB prologue for the DB-touching subcommands: pool init + ping, then migrations unless skipped.
/// Migrations land tables a fresh DB lacks (e.g. audit_events + the sqlite trigger's `_forseti_meta` sentinel).
async fn bootstrap_db(cfg: &config::AppConfig) -> anyhow::Result<db::DbPool> {
    let db = db::DbPool::init(&cfg.database)?;
    db.ping().await?;
    if !cfg.database.skip_migrations {
        db.run_migrations().await?;
    }
    Ok(db)
}
