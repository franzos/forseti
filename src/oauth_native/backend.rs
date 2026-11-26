use anyhow::Result;
use serde_json::{Map, Value};

use super::{NativeOAuth, challenge, clients, device, discovery, grants, logout, sessions};
use crate::backend::OAuthBackend;
use crate::backend::oauth::{
    ConsentRequest, ConsentSession, DeviceAuthorization, DeviceTokenOutcome, IdTokenClaims,
    JwkSummary, LoginRequest, LogoutRequest, OAuthClient, OidcDiscovery, RedirectTo,
};

impl OAuthBackend for NativeOAuth {
    async fn get_login_request(&self, challenge: &str) -> Result<LoginRequest> {
        challenge::get_login_request(&self.db, challenge).await
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
        challenge::accept_login(self, challenge, subject, remember, remember_for, amr, acr).await
    }

    async fn reject_login_request(
        &self,
        challenge: &str,
        error: &str,
        error_description: &str,
    ) -> Result<RedirectTo> {
        challenge::reject_login(self, challenge, error, error_description).await
    }

    async fn get_consent_request(&self, challenge: &str) -> Result<ConsentRequest> {
        challenge::get_consent_request(&self.db, challenge).await
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
        challenge::accept_consent(
            self,
            challenge,
            grant_scope,
            grant_audience,
            crate::oauth::consent::GrantPath::Interactive { remember },
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
        challenge::reject_consent(self, challenge, error, error_description).await
    }

    async fn get_logout_request(&self, challenge: &str) -> Result<LogoutRequest> {
        logout::get_logout_request(&self.db, challenge).await
    }

    async fn accept_logout_request(&self, challenge: &str) -> Result<RedirectTo> {
        logout::accept_logout_request(self, challenge).await
    }

    async fn device_authorization(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: &str,
    ) -> Result<DeviceAuthorization> {
        device::start(self, client_id, client_secret, scope).await
    }

    async fn poll_device_token(
        &self,
        client_id: &str,
        client_secret: &str,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome> {
        device::poll_token(self, client_id, client_secret, device_code).await
    }

    async fn accept_user_code_request(
        &self,
        _device_challenge: &str,
        user_code: &str,
    ) -> Result<RedirectTo> {
        device::accept_user_code(self, user_code).await
    }

    async fn verify_id_token(
        &self,
        id_token: &str,
        issuer: &str,
        client_id: &str,
        iat_window_secs: u64,
    ) -> Result<IdTokenClaims> {
        device::verify_id_token(self, id_token, issuer, client_id, iat_window_secs).await
    }

    async fn list_clients(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        client_name: Option<&str>,
    ) -> Result<Vec<OAuthClient>> {
        clients::list(&self.db, page_size, page_token, client_name).await
    }

    async fn get_client(&self, id: &str) -> Result<OAuthClient> {
        clients::get(&self.db, id)
            .await?
            .ok_or_else(|| clients::ClientError::NotFound.into())
    }

    async fn get_client_opt(&self, id: &str) -> Result<Option<OAuthClient>> {
        clients::get(&self.db, id).await
    }

    async fn create_client(&self, client: OAuthClient) -> Result<OAuthClient> {
        clients::create(&self.db, &self.hash_permits, client).await
    }

    async fn update_client(&self, id: &str, client: OAuthClient) -> Result<OAuthClient> {
        clients::update(&self.db, &self.hash_permits, id, client).await
    }

    async fn delete_client(&self, id: &str) -> Result<()> {
        clients::delete(&self.db, id).await
    }

    /// The granted audience is stored with the grant, not on the client.
    async fn add_client_audiences(
        &self,
        _client_id: &str,
        _on_record: &[String],
        _granted: &[String],
    ) -> Result<()> {
        Ok(())
    }

    async fn rotate_client_secret(&self, id: &str) -> Result<OAuthClient> {
        clients::rotate_secret(&self.db, &self.hash_permits, id).await
    }

    async fn list_consent_sessions_by_subject(&self, subject: &str) -> Result<Vec<ConsentSession>> {
        grants::list_by_subject(&self.db, subject).await
    }

    async fn revoke_consent_sessions_for_subject(&self, subject: &str) -> Result<()> {
        grants::revoke_for_subject(&self.db, subject).await
    }

    async fn revoke_consent_sessions_by_request_id(&self, consent_request_id: &str) -> Result<()> {
        grants::revoke_by_id(&self.db, consent_request_id).await
    }

    async fn list_consent_sessions_by_login_session(
        &self,
        subject: &str,
        sid: &str,
    ) -> Result<Vec<ConsentSession>> {
        grants::list_by_login_session(&self.db, subject, sid).await
    }

    async fn revoke_consent_sessions_for_client(
        &self,
        subject: &str,
        client_id: &str,
    ) -> Result<()> {
        grants::revoke_for_client(&self.db, subject, client_id).await
    }

    /// No back-channel logout is sent.
    async fn revoke_login_sessions_for_subject(&self, subject: &str) -> Result<()> {
        sessions::revoke_for_subject(&self.db, subject).await
    }

    /// Sends back-channel logout to the clients with a grant under `sid`; an unknown `sid` counts
    /// as revoked.
    async fn revoke_login_session_by_sid(&self, sid: &str) -> Result<()> {
        logout::end_session(self, sid).await
    }

    async fn health_alive(&self) -> Result<()> {
        Ok(())
    }

    async fn health_ready(&self) -> Result<()> {
        self.db.ping().await?;
        if self.keys.load().is_none() {
            anyhow::bail!("signing keys not loaded");
        }
        Ok(())
    }

    async fn version(&self) -> Result<String> {
        Ok(format!("native {}", crate::web::FORSETI_VERSION))
    }

    async fn signing_keys(&self) -> Result<Vec<JwkSummary>> {
        Ok(self.keys()?.summaries())
    }

    /// Without `idp_hints_supported`: the providers come from the identity backend, which the
    /// discovery route adds.
    async fn fetch_discovery(&self) -> Result<(OidcDiscovery, Value)> {
        let raw = discovery::document(&self.issuer, &[]);
        Ok((serde_json::from_value(raw.clone())?, raw))
    }

    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn form_action_origins(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    #[tokio::test]
    async fn ready_once_keys_are_loaded_and_lists_the_active_kid() {
        let db = crate::db::test_pool().await;
        let oauth = NativeOAuth::new(&AppConfig::test_fixture(), &db, &[0x42; 32]);
        assert!(oauth.health_alive().await.is_ok());
        assert!(oauth.health_ready().await.is_err());
        oauth.init().await.unwrap();
        assert!(oauth.health_ready().await.is_ok());
        let active = oauth.keys().unwrap().signing().kid.clone();
        let keys = oauth.signing_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, active);
        assert_eq!(
            (keys[0].alg.as_str(), keys[0].kty.as_str()),
            ("RS256", "RSA")
        );
    }
}
