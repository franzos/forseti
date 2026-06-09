//! Thin app-typed wrappers around `ory_client`.
//!
//! Forseti speaks to Kratos via its public API on behalf of the browser
//! (forwarding the user's `Cookie` header) and to Hydra via its admin API
//! (server-only). The wrappers here exist so handlers don't have to drag the
//! full `ory_client::apis::*` paths and error types around.
//!
//! Hydra admin responses are typed (the `ory_client` deserialization bug
//! described below only affects Kratos's `ui.nodes`, which Hydra never emits),
//! so the Hydra wrappers return SDK models directly. Kratos flow fetches go
//! through [`FlowFetch`] / raw JSON.

use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use anyhow::Result;

// Re-export the `ory_client` models the rest of the app deals with.
#[allow(unused_imports)]
pub use ory_client::models::{
    AcceptOAuth2ConsentRequest, AcceptOAuth2ConsentRequestSession, AcceptOAuth2LoginRequest,
    AuthenticatorAssuranceLevel, CourierMessageStatus, CreateRecoveryCodeForIdentityBody, Identity,
    LoginFlow, Message, OAuth2Client, OAuth2ConsentRequest, OAuth2ConsentSession,
    OAuth2LoginRequest, OAuth2LogoutRequest, OAuth2RedirectTo, RecoveryCodeForIdentity,
    RecoveryFlow, RegistrationFlow, RejectOAuth2Request, Session, SettingsFlow, UpdateIdentityBody,
    VerifiableIdentityAddress, VerificationFlow,
};

pub mod discovery;
pub mod hydra;
pub mod kratos;

/// Shared HTTP/SDK clients pinned at startup.
///
/// Held behind an `Arc` in `AppState` so every `State<AppState>` extraction
/// clones cheaply — the four `Configuration` structs each carry a
/// `reqwest::Client` handle. `Arc`'s own `Deref` keeps field access
/// (`state.ory.kratos_public`) working.
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
        // One shared HTTP client across all four SDK configurations: one
        // connection pool, one set of timeouts. Without a timeout a wedged
        // Kratos can hang every request Forseti serves (every page
        // calls `whoami`).
        //
        // `ory_client` 1.22 pulls reqwest 0.12, the rest of the codebase
        // is on 0.13 — see Cargo.toml. We use the renamed `ory_reqwest`
        // 0.12 dep here so the `Client` type matches the SDK's
        // `Configuration.client` field.
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

/// Why a privileged-session error was raised on a settings flow.
///
/// Parsed at the [`FlowFetch`] boundary from Kratos's `error.id` so
/// handlers can pattern-match without poking at raw JSON. Both reasons
/// resolve to a `/login` redirect; the parameters differ:
///   * [`PrivilegedReason::Aal2Required`] → `/login?aal=aal2&return_to=...`
///   * [`PrivilegedReason::SessionRefresh`] → `/login?refresh=true&return_to=...`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedReason {
    /// `session_refresh_required` — session older than
    /// `privileged_session_max_age`. Refresh re-proves "still you".
    SessionRefresh,
    /// `session_aal2_required` — settings group needs AAL2 and the
    /// session is AAL1. Step up via the second factor.
    Aal2Required,
}

/// Outcome of fetching a self-service flow from Kratos.
///
/// Kratos returns 404/410 when a flow is missing or expired; rather than make
/// every handler match on `ory_client`'s untagged error enums, surface those
/// states as plain variants the handler can `match` on.
///
/// `PrivilegedRequired` is the settings-flow-specific 403 signal that the
/// user's session is too old to mutate credentials — handlers redirect to
/// `/login?refresh=true&return_to=...` so Kratos can re-auth and return.
///
/// We hand back the raw JSON rather than the typed `LoginFlow` / `RegistrationFlow` /
/// etc. because the SDK's `UiNodeAttributes` tagged-enum deserializer is broken
/// for the real Kratos wire shape (see `get_flow` for details). Handlers do
/// their own light projection into view-models, which is cheap and lets us
/// decouple from the SDK's shape drift entirely.
#[derive(Debug)]
pub enum FlowFetch {
    Ok(Box<serde_json::Value>),
    /// The flow ID is unknown or expired — the handler should restart the flow.
    Gone,
    /// 403 with `session_refresh_required` or `session_aal2_required` on a
    /// settings flow. The variant carries which one so handlers can pick
    /// the right `/login` redirect without re-parsing JSON.
    PrivilegedRequired(PrivilegedReason),
}

/// Shared low-level GET against an `/health/*` endpoint. 2xx → Ok, anything
/// else → Err with the status and (truncated) body. Used by both Kratos and
/// Hydra health probes — the endpoints are identical in shape.
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
