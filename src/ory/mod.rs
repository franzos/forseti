//! Ory implementation of the backend traits: [`KratosBackend`] and [`HydraBackend`] delegate to the private
//! `ory_client` wrappers in `kratos`, `hydra` and `discovery`, which convert to `crate::backend` types via
//! `convert_identity` and `convert`. Forseti talks to Kratos via its public API (forwarding the user's `Cookie`)
//! and Hydra via its admin API. Kratos flows are fetched as raw JSON and projected by [`crate::flow_json`]
//! because the SDK's `ui.nodes` deserializer is broken (see `kratos::get_flow`).

use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use anyhow::Result;

mod convert;
#[cfg(feature = "identity-ory")]
mod convert_identity;
mod discovery;
mod hydra;
mod hydra_backend;
#[cfg(feature = "identity-ory")]
mod kratos;
#[cfg(feature = "identity-ory")]
mod kratos_backend;

pub use hydra_backend::HydraBackend;
#[cfg(feature = "identity-ory")]
pub use kratos_backend::KratosBackend;
#[cfg(all(test, feature = "identity-ory"))]
pub(crate) use kratos_backend::create_unverified_test_identity;

/// Hydra HTTP/SDK clients pinned at startup, held behind `Arc` by [`HydraBackend`].
struct OryClients {
    /// Browser-facing Hydra OAuth2 public endpoint.
    hydra_public: ory_client::apis::configuration::Configuration,
    /// Server-only Hydra admin API (login/consent/logout challenges).
    hydra_admin: ory_client::apis::configuration::Configuration,
}

impl OryClients {
    fn from_config(cfg: &AppConfig) -> Arc<OryClients> {
        let mk = sdk_configs();
        Arc::new(OryClients {
            hydra_public: mk(&cfg.hydra.public_url),
            hydra_admin: mk(&cfg.hydra.admin_url),
        })
    }
}

/// Kratos HTTP/SDK clients pinned at startup, held behind `Arc` by [`KratosBackend`].
#[cfg(feature = "identity-ory")]
struct KratosClients {
    /// Browser-facing Kratos public API (used with forwarded cookies).
    kratos_public: ory_client::apis::configuration::Configuration,
    /// Server-only Kratos admin API.
    kratos_admin: ory_client::apis::configuration::Configuration,
}

#[cfg(feature = "identity-ory")]
impl KratosClients {
    fn from_config(cfg: &AppConfig) -> Arc<KratosClients> {
        let mk = sdk_configs();
        Arc::new(KratosClients {
            kratos_public: mk(&cfg.kratos.public_url),
            kratos_admin: mk(&cfg.kratos.admin_url),
        })
    }
}

/// SDK configurations sharing one HTTP client, built per base URL.
fn sdk_configs() -> impl Fn(&str) -> ory_client::apis::configuration::Configuration {
    // One HTTP client (one pool, one timeout) per backend; without a timeout a wedged Kratos hangs every page (each calls `whoami`).
    // `ory_reqwest` is the renamed reqwest 0.12 the SDK pins, distinct from the codebase's 0.13, so the `Client` type matches `Configuration.client`.
    let http = ory_reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client builds");
    move |base_path: &str| ory_client::apis::configuration::Configuration {
        base_path: base_path.to_string(),
        client: http.clone(),
        ..Default::default()
    }
}

/// Both backends over clients pointed at the given base URLs, for tests without an `AppConfig`.
#[cfg(all(test, feature = "identity-ory"))]
pub(crate) fn test_backends(
    kratos_public: &str,
    kratos_admin: &str,
    hydra_public: &str,
    hydra_admin: &str,
) -> (Arc<KratosBackend>, Arc<HydraBackend>) {
    let mk = |base_path: &str| ory_client::apis::configuration::Configuration {
        base_path: base_path.to_string(),
        ..Default::default()
    };
    (
        Arc::new(KratosBackend {
            clients: Arc::new(KratosClients {
                kratos_public: mk(kratos_public),
                kratos_admin: mk(kratos_admin),
            }),
        }),
        Arc::new(HydraBackend {
            clients: Arc::new(OryClients {
                hydra_public: mk(hydra_public),
                hydra_admin: mk(hydra_admin),
            }),
        }),
    )
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
