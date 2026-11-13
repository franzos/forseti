//! Backend-neutral domain types the app works with; the Ory implementation converts at its boundary.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use axum::http::HeaderMap;
use serde_json::{Map, Value};

use crate::config::AppConfig;
use crate::flow_view::Flow;

use identity::{
    CourierStatus, FlowFetch, FlowInit, FlowKind, FlowOutcome, Identity, IdentityState,
    RecoveryCode, SelfServiceError, Session, WhoamiOutcome,
};
use oauth::{
    ConsentRequest, ConsentSession, DeviceAuthorization, DeviceTokenOutcome, IdTokenClaims,
    JwkSummary, LoginRequest, LogoutRequest, OAuthClient, OidcDiscovery, RedirectTo,
};

pub mod identity;
pub mod oauth;

pub use crate::ory::{HydraBackend, KratosBackend};

pub type IdentityImpl = KratosBackend;
pub type OAuthImpl = HydraBackend;

/// Build both backends over one shared set of upstream clients.
pub fn build(cfg: &AppConfig) -> (Arc<IdentityImpl>, Arc<OAuthImpl>) {
    crate::ory::backends(cfg)
}

/// Identities, sessions and self-service flows.
#[allow(async_fn_in_trait)]
pub trait IdentityBackend: Send + Sync + 'static {
    async fn whoami(&self, cookie: Option<&str>) -> Result<WhoamiOutcome>;
    fn has_session_cookie(&self, headers: &HeaderMap) -> bool;
    fn clear_session_cookie(&self, secure: bool) -> String;
    async fn tear_down_session(&self, cookie: &str);
    async fn fetch_logout_url(&self, cookie: &str) -> Result<Option<String>>;

    fn flow_init_url(&self, kind: FlowKind, init: FlowInit<'_>) -> String;
    async fn get_flow(&self, kind: FlowKind, flow_id: &str, cookie: &str) -> Result<FlowFetch>;
    async fn resolve_flow(
        &self,
        kind: FlowKind,
        flow_id: Option<&str>,
        cookie: &str,
    ) -> FlowOutcome;
    async fn verify_known_email(&self, flow: &Flow, email: &str, cookie: &str) -> Result<()>;
    async fn get_self_service_error(&self, error_id: &str) -> Result<Option<SelfServiceError>>;
    async fn probe_oidc_provider_ids(&self) -> Result<Vec<String>>;

    async fn list_my_sessions(&self, cookie: Option<&str>) -> Result<Vec<Session>>;
    async fn revoke_session(&self, id: &str, cookie: Option<&str>) -> Result<()>;
    async fn revoke_other_sessions(&self, cookie: Option<&str>) -> Result<u64>;
    async fn list_identity_sessions(&self, identity_id: &str) -> Result<Vec<Session>>;
    async fn list_identity_sessions_all(&self, identity_id: &str) -> Result<Vec<Session>>;
    async fn active_session_ids(&self, identity_id: &str) -> Result<HashSet<String>>;
    async fn is_session_active(&self, identity_id: &str, kratos_session_id: &str) -> Result<bool>;
    async fn admin_get_session(&self, id: &str) -> Result<Session>;
    async fn admin_list_all_sessions(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        active: Option<bool>,
    ) -> Result<Vec<Session>>;
    async fn admin_revoke_session(&self, id: &str) -> Result<()>;

    async fn admin_get_identity(&self, id: &str) -> Result<Identity>;
    async fn admin_get_identity_optional(&self, id: &str) -> Result<Option<Identity>>;
    async fn admin_get_identity_full(&self, id: &str) -> Result<Identity>;
    async fn admin_get_identity_full_optional(&self, id: &str) -> Result<Option<Identity>>;
    async fn list_identities(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        credentials_identifier: Option<&str>,
    ) -> Result<Vec<Identity>>;
    async fn admin_list_identities_by_ids(&self, ids: Vec<String>) -> Result<Vec<Identity>>;
    async fn admin_find_identity_by_email(&self, email: &str) -> Result<Option<(Identity, bool)>>;
    async fn admin_create_identity_verified(
        &self,
        schema_id: &str,
        email: &str,
        first: &str,
        last: &str,
    ) -> Result<Option<Identity>>;
    async fn admin_set_identity_language(&self, id: &str, lang: &str) -> Result<Identity>;
    async fn admin_update_identity_state(&self, id: &str, state: IdentityState)
    -> Result<Identity>;
    async fn admin_set_metadata_admin_key(&self, id: &str, key: &str, value: &str) -> Result<()>;
    async fn admin_remove_metadata_admin_key(&self, id: &str, key: &str) -> Result<bool>;
    async fn admin_delete_identity(&self, id: &str) -> Result<()>;
    async fn admin_create_recovery_code(&self, identity_id: &str) -> Result<RecoveryCode>;
    async fn admin_create_recovery_link(
        &self,
        identity_id: &str,
        expires_in: &str,
        return_to: Option<&str>,
    ) -> Result<String>;
    async fn list_identity_schemas(&self) -> Result<Vec<String>>;

    async fn courier_backlog(&self, status: CourierStatus, page_size: i64) -> Result<u64>;
    async fn health_alive(&self) -> Result<()>;
    async fn health_ready(&self) -> Result<()>;
    async fn version(&self) -> Result<String>;
}

/// OAuth 2.0 / OIDC provider: login, consent and logout challenges, clients, grants.
#[allow(async_fn_in_trait)]
pub trait OAuthBackend: Send + Sync + 'static {
    async fn get_login_request(&self, challenge: &str) -> Result<LoginRequest>;
    async fn accept_login_request(
        &self,
        challenge: &str,
        subject: &str,
        remember: bool,
        remember_for: i64,
        amr: Vec<String>,
        acr: Option<String>,
    ) -> Result<RedirectTo>;
    async fn reject_login_request(
        &self,
        challenge: &str,
        error: &str,
        error_description: &str,
    ) -> Result<RedirectTo>;
    async fn get_consent_request(&self, challenge: &str) -> Result<ConsentRequest>;
    async fn accept_consent_request(
        &self,
        challenge: &str,
        grant_scope: Vec<String>,
        grant_audience: Vec<String>,
        remember: bool,
        id_token_session: Value,
        access_token_session: Map<String, Value>,
    ) -> Result<RedirectTo>;
    async fn reject_consent_request(
        &self,
        challenge: &str,
        error: &str,
        error_description: &str,
    ) -> Result<RedirectTo>;
    async fn get_logout_request(&self, challenge: &str) -> Result<LogoutRequest>;
    async fn accept_logout_request(&self, challenge: &str) -> Result<RedirectTo>;

    async fn device_authorization(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: &str,
    ) -> Result<DeviceAuthorization>;
    async fn poll_device_token(
        &self,
        client_id: &str,
        client_secret: &str,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome>;
    async fn accept_user_code_request(
        &self,
        device_challenge: &str,
        user_code: &str,
    ) -> Result<RedirectTo>;
    async fn verify_id_token(
        &self,
        id_token: &str,
        issuer: &str,
        client_id: &str,
        iat_window_secs: u64,
    ) -> Result<IdTokenClaims>;

    async fn list_clients(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        client_name: Option<&str>,
    ) -> Result<Vec<OAuthClient>>;
    async fn get_client(&self, id: &str) -> Result<OAuthClient>;
    async fn get_client_opt(&self, id: &str) -> Result<Option<OAuthClient>>;
    async fn create_client(&self, client: OAuthClient) -> Result<OAuthClient>;
    async fn update_client(&self, id: &str, client: OAuthClient) -> Result<OAuthClient>;
    async fn delete_client(&self, id: &str) -> Result<()>;
    async fn add_client_audiences(
        &self,
        client_id: &str,
        on_record: &[String],
        granted: &[String],
    ) -> Result<()>;
    async fn rotate_client_secret(&self, id: &str) -> Result<OAuthClient>;

    async fn list_consent_sessions_by_subject(&self, subject: &str) -> Result<Vec<ConsentSession>>;
    async fn list_consent_sessions_by_login_session(
        &self,
        subject: &str,
        sid: &str,
    ) -> Result<Vec<ConsentSession>>;
    async fn revoke_consent_sessions_for_subject(&self, subject: &str) -> Result<()>;
    async fn revoke_consent_sessions_by_request_id(&self, consent_request_id: &str) -> Result<()>;
    async fn revoke_consent_sessions_for_client(
        &self,
        subject: &str,
        client_id: &str,
    ) -> Result<()>;
    async fn revoke_login_sessions_for_subject(&self, subject: &str) -> Result<()>;
    async fn revoke_login_session_by_sid(&self, sid: &str) -> Result<()>;

    /// The OIDC discovery document, typed and as served.
    async fn fetch_discovery(&self) -> Result<(OidcDiscovery, Value)>;
    async fn signing_keys(&self) -> Result<Vec<JwkSummary>>;
    async fn health_alive(&self) -> Result<()>;
    async fn health_ready(&self) -> Result<()>;
    async fn version(&self) -> Result<String>;
}

// Handlers, `tokio::spawn` and `JoinSet` need the futures `Send`; this fails to compile if one is not.
const _: fn(&IdentityImpl, &OAuthImpl) = |identity, oauth| {
    fn require_send<T: Send>(_: T) {}
    require_send(identity.whoami(None));
    require_send(identity.resolve_flow(FlowKind::Login, None, ""));
    require_send(oauth.get_login_request(""));
    require_send(oauth.fetch_discovery());
};
