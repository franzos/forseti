//! Thin app-typed wrappers around `ory_client`, so handlers don't drag the full `ory_client::apis::*` paths around.
//! Forseti talks to Kratos via its public API (forwarding the user's `Cookie`) and Hydra via its admin API.
//! Hydra wrappers return SDK models directly; Kratos flow fetches go through [`FlowFetch`] / raw JSON because the
//! SDK's `ui.nodes` deserializer is broken (see below).

use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use anyhow::Result;

// Re-export the `ory_client` models the rest of the app deals with.
#[allow(unused_imports)]
pub use ory_client::models::{
    AcceptOAuth2ConsentRequest, AcceptOAuth2ConsentRequestSession, AcceptOAuth2LoginRequest,
    AuthenticatorAssuranceLevel, CourierMessageStatus, CreateIdentityBody,
    CreateRecoveryCodeForIdentityBody, CreateRecoveryLinkForIdentityBody, Identity, LoginFlow,
    Message, OAuth2Client, OAuth2ConsentRequest, OAuth2ConsentSession, OAuth2LoginRequest,
    OAuth2LogoutRequest, OAuth2RedirectTo, RecoveryCodeForIdentity, RecoveryFlow, RegistrationFlow,
    RejectOAuth2Request, Session, SettingsFlow, UpdateIdentityBody, VerifiableIdentityAddress,
    VerificationFlow,
};

pub mod discovery;
pub mod hydra;
pub mod kratos;

/// Shared HTTP/SDK clients pinned at startup, held behind `Arc` so `State<AppState>` clones cheaply.
pub struct OryClients {
    /// Browser-facing Kratos public API (used with forwarded cookies).
    pub kratos_public: ory_client::apis::configuration::Configuration,
    /// Server-only Kratos admin API.
    pub kratos_admin: ory_client::apis::configuration::Configuration,
    /// Browser-facing Hydra OAuth2 public endpoint.
    pub hydra_public: ory_client::apis::configuration::Configuration,
    /// Server-only Hydra admin API (login/consent/logout challenges).
    pub hydra_admin: ory_client::apis::configuration::Configuration,
}

impl OryClients {
    pub fn from_config(cfg: &AppConfig) -> Arc<OryClients> {
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

/// Kind of Kratos self-service flow. Used by the generic fetch/init helpers to
/// build the right URL path segment (`login`, `registration`, …).
#[derive(Debug, Clone, Copy)]
pub enum FlowKind {
    Login,
    Registration,
    Recovery,
    Verification,
    Settings,
}

impl FlowKind {
    /// URL path segment Kratos uses for this flow kind.
    fn path_segment(self) -> &'static str {
        match self {
            FlowKind::Login => "login",
            FlowKind::Registration => "registration",
            FlowKind::Recovery => "recovery",
            FlowKind::Verification => "verification",
            FlowKind::Settings => "settings",
        }
    }
}

/// Why a privileged-session error was raised on a settings flow, parsed from Kratos's `error.id`.
/// Both resolve to a `/login` redirect with different params (`aal=aal2` vs `refresh=true`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedReason {
    /// `session_refresh_required`: session older than `privileged_session_max_age`.
    SessionRefresh,
    /// `session_aal2_required`: settings group needs AAL2 but the session is AAL1.
    Aal2Required,
}

/// Outcome of fetching a Kratos self-service flow, surfacing 404/410 (missing/expired) and the settings-flow
/// 403 as plain variants. Hands back raw JSON, not the typed `LoginFlow`/etc, because the SDK's
/// `UiNodeAttributes` deserializer is broken for the real Kratos wire shape (see `get_flow`).
#[derive(Debug)]
pub enum FlowFetch {
    Ok(Box<serde_json::Value>),
    /// The flow ID is unknown or expired; restart the flow.
    Gone,
    /// Settings-flow 403; the variant says whether to redirect with `refresh=true` or `aal=aal2`.
    PrivilegedRequired(PrivilegedReason),
}

/// Shared low-level GET against a `/health/*` endpoint: 2xx is Ok, else Err with status + truncated body.
pub(crate) async fn probe_health(
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
