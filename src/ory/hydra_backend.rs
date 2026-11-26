//! Hydra implementation of [`OAuthBackend`], delegating to the inherent methods of [`HydraBackend`].

use serde_json::{Map, Value};

use super::{HydraBackend, Result};
use crate::backend::OAuthBackend;
use crate::backend::oauth::{
    ConsentRequest, ConsentSession, DeviceAuthorization, DeviceTokenOutcome, IdTokenClaims,
    JwkSummary, LoginRequest, LogoutRequest, OAuthClient, OidcDiscovery, RedirectTo,
};

// `HydraBackend::name` resolves to the inherent method, which takes precedence over the trait's.
impl OAuthBackend for HydraBackend {
    async fn get_login_request(&self, challenge: &str) -> Result<LoginRequest> {
        HydraBackend::get_login_request(self, challenge).await
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
        HydraBackend::accept_login_request(
            self,
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
        HydraBackend::reject_login_request(self, challenge, error, error_description).await
    }

    async fn get_consent_request(&self, challenge: &str) -> Result<ConsentRequest> {
        HydraBackend::get_consent_request(self, challenge).await
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
        HydraBackend::accept_consent_request(
            self,
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
        HydraBackend::reject_consent_request(self, challenge, error, error_description).await
    }

    async fn get_logout_request(&self, challenge: &str) -> Result<LogoutRequest> {
        HydraBackend::get_logout_request(self, challenge).await
    }

    async fn accept_logout_request(&self, challenge: &str) -> Result<RedirectTo> {
        HydraBackend::accept_logout_request(self, challenge).await
    }

    async fn device_authorization(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: &str,
    ) -> Result<DeviceAuthorization> {
        HydraBackend::device_authorization(self, client_id, client_secret, scope).await
    }

    async fn poll_device_token(
        &self,
        client_id: &str,
        client_secret: &str,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome> {
        HydraBackend::poll_device_token(self, client_id, client_secret, device_code).await
    }

    async fn accept_user_code_request(
        &self,
        device_challenge: &str,
        user_code: &str,
    ) -> Result<RedirectTo> {
        HydraBackend::accept_user_code_request(self, device_challenge, user_code).await
    }

    async fn verify_id_token(
        &self,
        id_token: &str,
        issuer: &str,
        client_id: &str,
        iat_window_secs: u64,
    ) -> Result<IdTokenClaims> {
        HydraBackend::verify_id_token(self, id_token, issuer, client_id, iat_window_secs).await
    }

    async fn list_clients(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        client_name: Option<&str>,
    ) -> Result<Vec<OAuthClient>> {
        HydraBackend::list_clients(self, page_size, page_token, client_name).await
    }

    async fn get_client(&self, id: &str) -> Result<OAuthClient> {
        HydraBackend::get_client(self, id).await
    }

    async fn get_client_opt(&self, id: &str) -> Result<Option<OAuthClient>> {
        HydraBackend::get_client_opt(self, id).await
    }

    async fn create_client(&self, client: OAuthClient) -> Result<OAuthClient> {
        HydraBackend::create_client(self, client).await
    }

    async fn update_client(&self, id: &str, client: OAuthClient) -> Result<OAuthClient> {
        HydraBackend::update_client(self, id, client).await
    }

    async fn delete_client(&self, id: &str) -> Result<()> {
        HydraBackend::delete_client(self, id).await
    }

    async fn add_client_audiences(
        &self,
        client_id: &str,
        on_record: &[String],
        granted: &[String],
    ) -> Result<()> {
        HydraBackend::add_client_audiences(self, client_id, on_record, granted).await
    }

    async fn rotate_client_secret(&self, id: &str) -> Result<OAuthClient> {
        HydraBackend::rotate_client_secret(self, id).await
    }

    async fn list_consent_sessions_by_subject(&self, subject: &str) -> Result<Vec<ConsentSession>> {
        HydraBackend::list_consent_sessions_by_subject(self, subject).await
    }

    async fn revoke_consent_sessions_for_subject(&self, subject: &str) -> Result<()> {
        HydraBackend::revoke_consent_sessions_for_subject(self, subject).await
    }

    async fn revoke_consent_sessions_by_request_id(&self, consent_request_id: &str) -> Result<()> {
        HydraBackend::revoke_consent_sessions_by_request_id(self, consent_request_id).await
    }

    async fn list_consent_sessions_by_login_session(
        &self,
        subject: &str,
        sid: &str,
    ) -> Result<Vec<ConsentSession>> {
        HydraBackend::list_consent_sessions_by_login_session(self, subject, sid).await
    }

    async fn revoke_consent_sessions_for_client(
        &self,
        subject: &str,
        client_id: &str,
    ) -> Result<()> {
        HydraBackend::revoke_consent_sessions_for_client(self, subject, client_id).await
    }

    async fn revoke_login_sessions_for_subject(&self, subject: &str) -> Result<()> {
        HydraBackend::revoke_login_sessions_for_subject(self, subject).await
    }

    async fn revoke_login_session_by_sid(&self, sid: &str) -> Result<()> {
        HydraBackend::revoke_login_session_by_sid(self, sid).await
    }

    async fn health_alive(&self) -> Result<()> {
        HydraBackend::health_alive(self).await
    }

    async fn health_ready(&self) -> Result<()> {
        HydraBackend::health_ready(self).await
    }

    async fn version(&self) -> Result<String> {
        HydraBackend::version(self).await
    }

    async fn signing_keys(&self) -> Result<Vec<JwkSummary>> {
        HydraBackend::signing_keys(self).await
    }

    async fn fetch_discovery(&self) -> Result<(OidcDiscovery, Value)> {
        HydraBackend::fetch_discovery(self).await
    }

    fn issuer(&self) -> &str {
        &self.clients.issuer
    }

    fn form_action_origins(&self) -> Vec<String> {
        self.clients.form_action_origins.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use axum::http::header::CONTENT_TYPE;
    use axum::routing::{delete, get};

    use super::super::OryClients;
    use super::*;

    const CLIENT: &str = include_str!("fixtures/hydra/client.json");
    const LOGIN_REQUEST: &str = include_str!("fixtures/hydra/login_request.json");

    fn json(body: &'static str) -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
        ([(CONTENT_TYPE, "application/json")], body)
    }

    #[tokio::test]
    async fn trait_methods_reach_hydra() {
        let app = axum::Router::new()
            .route(
                "/adm/admin/oauth2/auth/requests/login",
                get(|| async { json(LOGIN_REQUEST) }),
            )
            .route(
                "/adm/admin/clients/forseti-fixture-client",
                get(|| async { json(CLIENT) }),
            )
            .route(
                "/adm/admin/oauth2/auth/sessions/login",
                delete(|| async { StatusCode::NO_CONTENT }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let hydra = HydraBackend {
            clients: Arc::new(OryClients::new(
                &format!("{base}/pub"),
                &format!("{base}/adm"),
            )),
        };

        let login = OAuthBackend::get_login_request(&hydra, "c").await.unwrap();
        assert_eq!(
            login.client.client_id.as_deref(),
            Some("forseti-fixture-client")
        );
        let client = OAuthBackend::get_client(&hydra, "forseti-fixture-client")
            .await
            .unwrap();
        assert_eq!(client.client_id.as_deref(), Some("forseti-fixture-client"));
        OAuthBackend::revoke_login_session_by_sid(&hydra, "sid-1")
            .await
            .unwrap();

        assert_eq!(OAuthBackend::issuer(&hydra), format!("{base}/pub"));
        assert_eq!(OAuthBackend::form_action_origins(&hydra), vec![base]);
    }
}
