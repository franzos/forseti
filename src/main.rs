mod admin;
mod app;
mod audit;
mod auth;
mod commercial;
mod config;
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
        _ => app::run().await,
    }
}
