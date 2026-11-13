//! Ory implementation of the backend traits: [`KratosBackend`] and [`HydraBackend`] delegate to the private
//! `ory_client` wrappers in `kratos`, `hydra` and `discovery`, which convert to `crate::backend` types via `convert`.
//! Forseti talks to Kratos via its public API (forwarding the user's `Cookie`) and Hydra via its admin API.
//! Kratos flows are fetched as raw JSON and projected by [`flow_json`] because the SDK's `ui.nodes` deserializer is
//! broken (see `kratos::get_flow`).

use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use anyhow::Result;

use ory_client::models::{
    CreateIdentityBody, CreateRecoveryCodeForIdentityBody, CreateRecoveryLinkForIdentityBody,
    UpdateIdentityBody,
};

use crate::backend::identity::{FlowFetch, FlowKind, Identity, PrivilegedReason, Session};

mod backend;
mod convert;
mod discovery;
pub(crate) mod flow_json;
mod hydra;
mod kratos;

pub(crate) use backend::backends;
pub use backend::{HydraBackend, KratosBackend};
#[cfg(test)]
pub(crate) use backend::{create_unverified_test_identity, test_backends};

/// Shared HTTP/SDK clients pinned at startup, held behind `Arc` by both backends.
struct OryClients {
    /// Browser-facing Kratos public API (used with forwarded cookies).
    kratos_public: ory_client::apis::configuration::Configuration,
    /// Server-only Kratos admin API.
    kratos_admin: ory_client::apis::configuration::Configuration,
    /// Browser-facing Hydra OAuth2 public endpoint.
    hydra_public: ory_client::apis::configuration::Configuration,
    /// Server-only Hydra admin API (login/consent/logout challenges).
    hydra_admin: ory_client::apis::configuration::Configuration,
}

impl OryClients {
    fn from_config(cfg: &AppConfig) -> Arc<OryClients> {
        // One shared HTTP client (one pool, one timeout) across all four configs; without a timeout a wedged Kratos hangs every page (each calls `whoami`).
        // `ory_reqwest` is the renamed reqwest 0.12 the SDK pins, distinct from the codebase's 0.13, so the `Client` type matches `Configuration.client`.
        let http = ory_reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client builds");
        let mk = |base_path: &str| ory_client::apis::configuration::Configuration {
            base_path: base_path.to_string(),
            client: http.clone(),
            ..Default::default()
        };
        Arc::new(OryClients {
            kratos_public: mk(&cfg.kratos.public_url),
            kratos_admin: mk(&cfg.kratos.admin_url),
            hydra_public: mk(&cfg.hydra.public_url),
            hydra_admin: mk(&cfg.hydra.admin_url),
        })
    }
}

/// URL path segment Kratos uses for this flow kind.
fn path_segment(kind: FlowKind) -> &'static str {
    match kind {
        FlowKind::Login => "login",
        FlowKind::Registration => "registration",
        FlowKind::Recovery => "recovery",
        FlowKind::Verification => "verification",
        FlowKind::Settings => "settings",
    }
}

/// Shared low-level GET against a `/health/*` endpoint: 2xx is Ok, else Err with status + truncated body.
async fn probe_health(
    cfg: &ory_client::apis::configuration::Configuration,
    path: &str,
) -> Result<()> {
    let url = format!("{}{}", cfg.base_path.trim_end_matches('/'), path);
    let resp = cfg
        .client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("health probe transport error ({path}): {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Err(anyhow::anyhow!(
        "health probe {path} returned {status}: {}",
        body.chars().take(200).collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_urlencode_matches_the_sdk() {
        for s in [
            "",
            "a b",
            "a+b",
            "a/b?c=d&e",
            "ünï©ödé 日本",
            "~-_.*",
            "%20",
        ] {
            assert_eq!(
                crate::web::urlencode(s),
                ory_client::apis::urlencode(s),
                "input {s:?}"
            );
        }
    }
}
