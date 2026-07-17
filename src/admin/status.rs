//! `/admin/status`: system health dashboard.
//!
//! Pulls a snapshot from Kratos + Hydra: alive/ready health, courier backlog,
//! and build versions. Every probe is best-effort; one upstream failure renders
//! that row as "down" without aborting the page.

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
    /// Courier queue snapshot; None entries collapse to a dash in the template.
    courier_pending: Option<u64>,
    courier_failed: Option<u64>,
    /// Build versions for the three components in the stack.
    forseti_version: &'static str,
    kratos_version: String,
    hydra_version: String,
    /// Database backend label ("sqlite" / "postgres").
    database_backend: &'static str,
    /// Set when on sqlite and the deployment shape looks like production; only
    /// the shape is detectable, not the actual instance count.
    sqlite_prod_warning: bool,
    /// Webhook outbox rows that exhausted retries; >0 drives a banner.
    dead_webhook_count: i64,
    /// "received N ago" for the most recent Kratos-sourced audit event. `None`
    /// renders "never", itself a signal that the receiver path may be broken.
    last_kratos_webhook_pretty: Option<String>,
    /// Raw RFC3339 of the same timestamp, attached as a `title=` tooltip.
    last_kratos_webhook_full: Option<String>,
    /// Audit rows that failed to land in the DB since restart; >0 means the
    /// `audit_fallback` stderr lines should be inspected.
    audit_write_failures: u64,
    /// Kratos-webhook payloads rejected since boot; >0 means a hook/config
    /// mismatch (check the `kratos audit webhook` warn logs).
    audit_webhook_rejected: u64,
    /// Kratos-webhook rows flagged stale/future since boot; usually a slow flow
    /// or clock skew.
    audit_webhook_freshness_anomalies: u64,
    /// `[audit].webhook_token` accept-list size; >1 means a rotation is in
    /// flight (see `WebhookTokens` in `config.rs`).
    audit_webhook_accept_list_len: usize,
    /// Index of the accept-list entry that last authenticated a request;
    /// `None` renders "none since boot".
    audit_webhook_last_matched: Option<usize>,
    /// One-word license state: "Unlicensed" / "Active" / "Grace" / "Expired".
    license_state: &'static str,
    /// Tier + customer label when a license is present; `None` for OSS-tier.
    license_detail: Option<String>,
    /// OIDC issuer from Hydra's discovery doc; empty when unknown.
    issuer: String,
    /// Whether the discovery fetch succeeded; gates the teaser line.
    discovery_ok: bool,
}

/// One row in the services-health table.
pub(crate) struct ServiceStatus {
    pub name: &'static str,
    /// `"up"` / `"down"`; drives the badge colour.
    pub state: &'static str,
    /// Free-form detail (URL, error message). Truncated at the template.
    pub detail: String,
}

pub async fn show(State(state): State<AppState>, admin: RequireAdmin) -> Response {
    let ctx = admin.ctx;

    // Independent upstream probes run concurrently; sequentially each carries
    // its own 10s timeout, so a down Kratos/Hydra would stall the page.
    let (
        kratos_alive,
        kratos_ready,
        hydra_alive,
        hydra_ready,
        courier_queued,
        courier_abandoned,
        kratos_version_res,
        hydra_version_res,
        (disc, discovery_ok),
    ) = tokio::join!(
        ory::kratos::health_alive(&state.ory),
        ory::kratos::health_ready(&state.ory),
        ory::hydra::health_alive(&state.ory),
        ory::hydra::health_ready(&state.ory),
        ory::kratos::list_courier_messages(
            &state.ory,
            100,
            Some(ory::CourierMessageStatus::Queued)
        ),
        ory::kratos::list_courier_messages(
            &state.ory,
            100,
            Some(ory::CourierMessageStatus::Abandoned)
        ),
        ory::kratos::version(&state.ory),
        ory::hydra::version(&state.ory),
        state.openid_configuration(),
    );

    let services = vec![
        probe("Kratos (alive)", &state.cfg.kratos.admin_url, kratos_alive),
        probe("Kratos (ready)", &state.cfg.kratos.admin_url, kratos_ready),
        probe("Hydra (alive)", &state.cfg.hydra.admin_url, hydra_alive),
        probe("Hydra (ready)", &state.cfg.hydra.admin_url, hydra_ready),
    ];

    let courier_pending = count_courier(courier_queued);
    let courier_failed = count_courier(courier_abandoned);

    let kratos_version = kratos_version_res.unwrap_or_else(|e| {
        tracing::warn!(error = ?e, "kratos version probe failed");
        "—".to_string()
    });
    let hydra_version = hydra_version_res.unwrap_or_else(|e| {
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
    let last_kratos_webhook_pretty = last_kratos_webhook_full
        .as_deref()
        .map(|ts| humanise_timestamp(&ctx.locale, ts));

    let audit_write_failures = crate::audit::audit_write_failures_total();
    let audit_webhook_rejected = crate::audit::kratos_webhook_rejected_total();
    let audit_webhook_freshness_anomalies =
        crate::audit::kratos_webhook_freshness_anomalies_total();
    let audit_webhook_accept_list_len = state.cfg.audit.webhook_token.entries().len();
    let audit_webhook_last_matched = crate::audit::kratos_webhook_last_matched_index();

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
        chrome: PageChrome::from_parts(&state, ctx.email, String::new(), ctx.locale.clone()),
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
        audit_webhook_rejected,
        audit_webhook_freshness_anomalies,
        audit_webhook_accept_list_len,
        audit_webhook_last_matched,
        license_state,
        license_detail,
        issuer: disc.issuer,
        discovery_ok,
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
