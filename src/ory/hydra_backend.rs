//! Hydra implementation of [`OAuthBackend`], delegating to the free functions.

use std::sync::Arc;

use serde_json::{Map, Value};

use super::{OryClients, Result, discovery, hydra};
use crate::backend::OAuthBackend;
use crate::backend::oauth::{
    ConsentRequest, ConsentSession, DeviceAuthorization, DeviceTokenOutcome, IdTokenClaims,
    JwkSummary, LoginRequest, LogoutRequest, OAuthClient, OidcDiscovery, RedirectTo,
};
use crate::config::AppConfig;

pub struct HydraBackend {
    pub(super) clients: Arc<OryClients>,
}

impl HydraBackend {
    pub(crate) fn from_config(cfg: &AppConfig) -> Arc<HydraBackend> {
        Arc::new(HydraBackend {
            clients: OryClients::from_config(cfg),
        })
    }
}

impl OAuthBackend for HydraBackend {
    async fn get_login_request(&self, challenge: &str) -> Result<LoginRequest> {
        hydra::get_login_request(&self.clients, challenge).await
    }

    async fn accept_login_request(
        &self,
        challenge: &str,
        subject: &str,
        remember: bool,
        remember_for: i64,
        amr: Vec<String>,
        acr: Option<String>,
    ) -> Result<RedirectTo> {
        hydra::accept_login_request(
            &self.clients,
            challenge,
            subject,
            remember,
            remember_for,
            amr,
            acr,
        )
        .await
    }

    async fn reject_login_request(
        &self,
        challenge: &str,
        error: &str,
        error_description: &str,
    ) -> Result<RedirectTo> {
        hydra::reject_login_request(&self.clients, challenge, error, error_description).await
    }

    async fn get_consent_request(&self, challenge: &str) -> Result<ConsentRequest> {
        hydra::get_consent_request(&self.clients, challenge).await
    }

    async fn accept_consent_request(
        &self,
        challenge: &str,
        grant_scope: Vec<String>,
        grant_audience: Vec<String>,
        remember: bool,
        id_token_session: Value,
        access_token_session: Map<String, Value>,
    ) -> Result<RedirectTo> {
        hydra::accept_consent_request(
            &self.clients,
            challenge,
            grant_scope,
            grant_audience,
            remember,
            id_token_session,
            access_token_session,
        )
        .await
    }

    async fn reject_consent_request(
        &self,
        challenge: &str,
        error: &str,
        error_description: &str,
    ) -> Result<RedirectTo> {
        hydra::reject_consent_request(&self.clients, challenge, error, error_description).await
    }

    async fn get_logout_request(&self, challenge: &str) -> Result<LogoutRequest> {
        hydra::get_logout_request(&self.clients, challenge).await
    }

    async fn accept_logout_request(&self, challenge: &str) -> Result<RedirectTo> {
        hydra::accept_logout_request(&self.clients, challenge).await
    }

    async fn device_authorization(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: &str,
    ) -> Result<DeviceAuthorization> {
        hydra::device_authorization(&self.clients, client_id, client_secret, scope).await
    }

    async fn poll_device_token(
        &self,
        client_id: &str,
        client_secret: &str,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome> {
        hydra::poll_device_token(&self.clients, client_id, client_secret, device_code).await
    }

    async fn accept_user_code_request(
        &self,
        device_challenge: &str,
        user_code: &str,
    ) -> Result<RedirectTo> {
        hydra::accept_user_code_request(&self.clients, device_challenge, user_code).await
    }

    async fn verify_id_token(
        &self,
        id_token: &str,
        issuer: &str,
        client_id: &str,
        iat_window_secs: u64,
    ) -> Result<IdTokenClaims> {
        hydra::verify_id_token(&self.clients, id_token, issuer, client_id, iat_window_secs).await
    }

    async fn list_clients(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        client_name: Option<&str>,
    ) -> Result<Vec<OAuthClient>> {
        hydra::list_clients(&self.clients, page_size, page_token, client_name).await
    }

    async fn get_client(&self, id: &str) -> Result<OAuthClient> {
        hydra::get_client(&self.clients, id).await
    }

    async fn get_client_opt(&self, id: &str) -> Result<Option<OAuthClient>> {
        hydra::get_client_opt(&self.clients, id).await
    }

    async fn create_client(&self, client: OAuthClient) -> Result<OAuthClient> {
        hydra::create_client(&self.clients, client).await
    }

    async fn update_client(&self, id: &str, client: OAuthClient) -> Result<OAuthClient> {
        hydra::update_client(&self.clients, id, client).await
    }

    async fn delete_client(&self, id: &str) -> Result<()> {
        hydra::delete_client(&self.clients, id).await
    }

    async fn add_client_audiences(
        &self,
        client_id: &str,
        on_record: &[String],
        granted: &[String],
    ) -> Result<()> {
        hydra::add_client_audiences(&self.clients, client_id, on_record, granted).await
    }

    async fn rotate_client_secret(&self, id: &str) -> Result<OAuthClient> {
        hydra::rotate_client_secret(&self.clients, id).await
    }

    async fn list_consent_sessions_by_subject(&self, subject: &str) -> Result<Vec<ConsentSession>> {
        hydra::list_consent_sessions_by_subject(&self.clients, subject).await
    }

    async fn list_consent_sessions_by_login_session(
        &self,
        subject: &str,
        sid: &str,
    ) -> Result<Vec<ConsentSession>> {
        hydra::list_consent_sessions_by_login_session(&self.clients, subject, sid).await
    }

    async fn revoke_consent_sessions_for_subject(&self, subject: &str) -> Result<()> {
        hydra::revoke_consent_sessions_for_subject(&self.clients, subject).await
    }

    async fn revoke_consent_sessions_by_request_id(&self, consent_request_id: &str) -> Result<()> {
        hydra::revoke_consent_sessions_by_request_id(&self.clients, consent_request_id).await
    }

    async fn revoke_consent_sessions_for_client(
        &self,
        subject: &str,
        client_id: &str,
    ) -> Result<()> {
        hydra::revoke_consent_sessions_for_client(&self.clients, subject, client_id).await
    }

    async fn revoke_login_sessions_for_subject(&self, subject: &str) -> Result<()> {
        hydra::revoke_login_sessions_for_subject(&self.clients, subject).await
    }

    async fn revoke_login_session_by_sid(&self, sid: &str) -> Result<()> {
        hydra::revoke_login_session_by_sid(&self.clients, sid).await
    }

    async fn fetch_discovery(&self) -> Result<(OidcDiscovery, Value)> {
        discovery::fetch(&self.clients, &self.clients.hydra_public.base_path).await
    }

    async fn signing_keys(&self) -> Result<Vec<JwkSummary>> {
        hydra::signing_keys(&self.clients).await
    }

    async fn health_alive(&self) -> Result<()> {
        hydra::health_alive(&self.clients).await
    }

    async fn health_ready(&self) -> Result<()> {
        hydra::health_ready(&self.clients).await
    }

    async fn version(&self) -> Result<String> {
        hydra::version(&self.clients).await
    }
}
