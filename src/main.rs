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
    // Hand-rolled subcommand dispatch — one verb doesn't justify a CLI
    // framework. Anything other than a recognised subcommand falls
    // through to the HTTP server.
    match std::env::args().nth(1).as_deref() {
        Some("--help" | "-h" | "help") => {
            print_top_help();
            std::process::exit(0);
        }
        Some("audit-prune") => {
            let cfg = config::AppConfig::load()?;
            let db = db::DbPool::init(&cfg.database)?;
            db.ping().await?;
            // Migrations land the audit_events table + the `_forseti_meta`
            // sentinel row the sqlite trigger reads. Without this the prune
            // command on a fresh database errors with "no such table".
            if !cfg.database.skip_migrations {
                db.run_migrations().await?;
            }
            let code = audit::prune_cli(&cfg, &db).await;
            std::process::exit(code);
        }
        Some("unverified-prune") => {
            let cfg = config::AppConfig::load()?;
            // No DB-touching here; reads + deletes go through Kratos's
            // admin API. We still build OryClients from config.
            let ory = ory::OryClients::from_config(&cfg);
            let code = identity::prune_unverified_cli(&cfg, &ory).await;
            std::process::exit(code);
        }
        // Pure file operations — no DB, no Ory clients. Forseti can't read
        // Kratos's live config via API, so these lint/generate the files.
        Some("config-check") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            std::process::exit(config_cli::check(&args));
        }
        Some("config-init") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            std::process::exit(config_cli::init(&args));
        }
        // An unrecognised token that looks like a flag is almost certainly a
        // typo or a misplaced server flag — show help rather than silently
        // booting the server. A bare `forseti` (no args) still runs the server.
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
  help               print this help

Run `forseti <SUBCOMMAND> --help` for flags.",
        version = web::FORSETI_VERSION,
    );
}
