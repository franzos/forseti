mod admin;
mod app;
mod audit;
mod auth;
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
mod identity;
mod mailer;
mod oauth;
mod oauth_client_metadata;
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
mod web;
mod webhook;

pub(crate) use web::{render_error_boundary, safe_return_to, FlowQuery};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // One verb doesn't justify a CLI framework; unrecognised tokens fall through to the HTTP server.
    match std::env::args().nth(1).as_deref() {
        Some("--help" | "-h" | "help") => {
            print_top_help();
            std::process::exit(0);
        }
        Some("audit-prune") => {
            let cfg = config::AppConfig::load()?;
            let db = db::DbPool::init(&cfg.database)?;
            db.ping().await?;
            // Migrations land the audit_events table + the sqlite trigger's `_forseti_meta` sentinel row; without them a fresh-db prune hits "no such table".
            if !cfg.database.skip_migrations {
                db.run_migrations().await?;
            }
            let code = audit::prune_cli(&cfg, &db).await;
            std::process::exit(code);
        }
        Some("unverified-prune") => {
            let cfg = config::AppConfig::load()?;
            // Deletes go through Kratos's admin API but cascade to the local POSIX tables, so the pool is needed.
            let ory = ory::OryClients::from_config(&cfg);
            let db = db::DbPool::init(&cfg.database)?;
            db.ping().await?;
            if !cfg.database.skip_migrations {
                db.run_migrations().await?;
            }
            let code = identity::prune_unverified_cli(&cfg, &db, &ory).await;
            std::process::exit(code);
        }
        Some("posix-reconcile") => {
            let cfg = config::AppConfig::load()?;
            let db = db::DbPool::init(&cfg.database)?;
            db.ping().await?;
            if !cfg.database.skip_migrations {
                db.run_migrations().await?;
            }
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
        Some("posix-init-client") => {
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
        Some("config-check") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            std::process::exit(config_cli::check(&args));
        }
        Some("config-init") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            std::process::exit(config_cli::init(&args));
        }
        // A flag-shaped token is almost certainly a typo; show help rather than silently booting the server. A bare `forseti` still runs it.
        Some(tok) if tok.starts_with('-') => {
            print_top_help();
            std::process::exit(0);
        }
        _ => app::run().await,
    }
}

fn print_top_help() {
    println!(
        "forseti {version} — identity + OAuth2/OIDC frontend for Ory Kratos & Hydra

USAGE: forseti [SUBCOMMAND]

With no subcommand, forseti runs the HTTP server.

SUBCOMMANDS:
  config-check       lint Kratos + Hydra config files against Forseti's recommendations
  config-init        generate a recommended Kratos + Hydra config pair
  audit-prune        delete audit_events older than [audit].retention_days
  unverified-prune   delete Kratos identities with unverified addresses past their TTL
  posix-reconcile    purge POSIX rows whose Kratos identity no longer exists
  posix-init-client  create the forseti-linux-pam confidential OAuth client (device grant)
  help               print this help

Run `forseti <SUBCOMMAND> --help` for flags.",
        version = web::FORSETI_VERSION,
    );
}
