//! `/admin/status` — system health dashboard.
//!
//! Pulls a small snapshot from Kratos + Hydra: alive/ready health,
//! courier message backlog (pending + failed counts), and build versions
//! including Forseti's own. Every probe is best-effort; one upstream
//! failure renders that row as "down" without aborting the page.

use axum::{extract::State, response::Response};

use crate::admin::{AdminSection, FORSETI_VERSION};
use crate::config::{DatabaseBackend, DatabaseConfig};
use crate::extractors::RequireAdmin;
use crate::format::humanise_timestamp;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

#[derive(askama::Template)]
#[template(path = "admin/status.html")]
struct StatusTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    /// One row per probed service.
    services: Vec<ServiceStatus>,
    /// Courier queue snapshot. None entries collapse to "—" in the template.
    courier_pending: Option<u64>,
    courier_failed: Option<u64>,
    /// Build versions for the three components in the stack.
    forseti_version: &'static str,
    kratos_version: String,
    hydra_version: String,
    /// Database backend label ("sqlite" / "postgres") shown alongside the
    /// build versions.
    database_backend: &'static str,
    /// Set when Forseti is on sqlite *and* the deployment shape looks
    /// like production. Drives the warning banner. Can't auto-detect actual
    /// instance count, only shape — see `db.rs` / `TODO.md` §0.
    sqlite_prod_warning: bool,
    /// Number of webhook outbox rows that exhausted retries. >0 drives a
    /// banner linking to `/admin/webhooks`. Phase 1.
    dead_webhook_count: i64,
    /// Humanised "received N ago" string for the most recent Kratos-sourced
    /// audit event (`actor_kind = "webhook"`). `None` when no such row
    /// exists yet — the template renders "never" in that case, which is
    /// itself the signal that the receiver path may be broken.
    last_kratos_webhook_pretty: Option<String>,
    /// Raw RFC3339 of the same timestamp, attached as a `title=` tooltip so
    /// the precise value is one hover away from the relative label.
    last_kratos_webhook_full: Option<String>,
    /// In-process counter of audit rows that failed to land in the DB
    /// since the last Forseti restart. >0 means the `audit_fallback`
    /// stderr lines should be inspected — the row data is still
    /// recoverable from logs.
    audit_write_failures: u64,
    /// One-word license state: "Unlicensed" / "Active" / "Grace" /
    /// "Expired". Drives the badge colour in the template.
    license_state: &'static str,
    /// Tier + customer label rendered next to the license badge when a
    /// license is present. `None` for the OSS-tier deployment.
    license_detail: Option<String>,
}

/// One row in the services-health table.
pub(crate) struct ServiceStatus {
    pub name: &'static str,
    /// `"up"` / `"down"` — drives the badge colour in the template.
    pub state: &'static str,
    /// Free-form detail (URL, error message). Truncated at the template.
    pub detail: String,
}

pub async fn show(State(state): State<AppState>, admin: RequireAdmin) -> Response {
    let ctx = admin.ctx;

    let mut services = Vec::with_capacity(4);
    services.push(probe(
        "Kratos (alive)",
        &state.cfg.kratos.admin_url,
        ory::kratos::health_alive(&state.ory).await,
    ));
    services.push(probe(
        "Kratos (ready)",
        &state.cfg.kratos.admin_url,
        ory::kratos::health_ready(&state.ory).await,
    ));
    services.push(probe(
        "Hydra (alive)",
        &state.cfg.hydra.admin_url,
        ory::hydra::health_alive(&state.ory).await,
    ));
    services.push(probe(
        "Hydra (ready)",
        &state.cfg.hydra.admin_url,
        ory::hydra::health_ready(&state.ory).await,
    ));

    let courier_pending = count_courier(
        ory::kratos::list_courier_messages(
            &state.ory,
            100,
            Some(ory::CourierMessageStatus::Queued),
        )
        .await,
    );
    let courier_failed = count_courier(
        ory::kratos::list_courier_messages(
            &state.ory,
            100,
            Some(ory::CourierMessageStatus::Abandoned),
        )
        .await,
    );

    let kratos_version = ory::kratos::version(&state.ory).await.unwrap_or_else(|e| {
        tracing::warn!(error = ?e, "kratos version probe failed");
        "—".to_string()
    });
    let hydra_version = ory::hydra::version(&state.ory).await.unwrap_or_else(|e| {
        tracing::warn!(error = ?e, "hydra version probe failed");
        "—".to_string()
    });

    tracing::info!(
        action = "admin.status.view",
        actor = %ctx.email,
        "admin action"
    );

    let db_backend = state.db.backend();
    let database_backend = match db_backend {
        DatabaseBackend::Sqlite => "sqlite",
        DatabaseBackend::Postgres => "postgres",
    };
    let sqlite_prod_warning = db_backend == DatabaseBackend::Sqlite
        && DatabaseConfig::looks_like_production(&state.cfg.self_.url);

    let dead_webhook_count = match crate::webhook::dead_letter_count(&state.db).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "dead_letter_count probe failed");
            0
        }
    };

    let last_kratos_webhook_full = crate::audit::last_kratos_webhook_epoch().map(|secs| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
            .map(|ts| ts.to_rfc3339())
            .unwrap_or_else(|| format!("epoch:{secs}"))
    });
    let last_kratos_webhook_pretty = last_kratos_webhook_full.as_deref().map(humanise_timestamp);

    let audit_write_failures = crate::audit::audit_write_failures_total();

    let (license_state, license_detail) = match &*state.license.status() {
        crate::commercial::LicenseStatus::Unlicensed => ("Unlicensed", None),
        crate::commercial::LicenseStatus::Active(l) => {
            ("Active", Some(format!("Business · {}", l.customer)))
        }
        crate::commercial::LicenseStatus::Grace(l) => (
            "Grace",
            Some(format!("Business · {} (expired, in grace)", l.customer)),
        ),
        crate::commercial::LicenseStatus::Expired(l) => {
            ("Expired", Some(format!("Business · {}", l.customer)))
        }
    };

    render(&StatusTemplate {
        chrome: PageChrome::from_parts(&state, ctx.email, String::new()),
        admin_active: AdminSection::Status,
        services,
        courier_pending,
        courier_failed,
        forseti_version: FORSETI_VERSION,
        kratos_version,
        hydra_version,
        database_backend,
        sqlite_prod_warning,
        dead_webhook_count,
        last_kratos_webhook_pretty,
        last_kratos_webhook_full,
        audit_write_failures,
        license_state,
        license_detail,
    })
}

fn probe(name: &'static str, base: &str, result: anyhow::Result<()>) -> ServiceStatus {
    match result {
        Ok(()) => ServiceStatus {
            name,
            state: "up",
            detail: base.to_string(),
        },
        Err(e) => ServiceStatus {
            name,
            state: "down",
            detail: format!("{base} · {e}"),
        },
    }
}

fn count_courier(result: anyhow::Result<Vec<ory::Message>>) -> Option<u64> {
    match result {
        Ok(msgs) => Some(msgs.len() as u64),
        Err(e) => {
            tracing::warn!(error = ?e, "courier list failed");
            None
        }
    }
}
