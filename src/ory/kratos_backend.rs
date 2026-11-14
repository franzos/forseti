//! Kratos implementation of [`IdentityBackend`], delegating to the free functions.

use std::collections::HashSet;
use std::sync::Arc;

use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, SameSite};

use super::{KratosClients, Result, kratos};
use crate::backend::IdentityBackend;
use crate::backend::identity::{
    CourierStatus, FlowFetch, FlowInit, FlowKind, FlowOutcome, Identity, IdentityState,
    RecoveryCode, SelfServiceError, Session, WhoamiOutcome, browser_init_url,
};
use crate::config::AppConfig;
use crate::flow_view::Flow;

const SESSION_COOKIE: &str = "ory_kratos_session";

pub struct KratosBackend {
    pub(super) clients: Arc<KratosClients>,
}

impl KratosBackend {
    pub(crate) fn from_config(cfg: &AppConfig) -> Arc<KratosBackend> {
        Arc::new(KratosBackend {
            clients: KratosClients::from_config(cfg),
        })
    }
}

/// Create an identity with an unverified `email` through the admin API; returns its id.
#[cfg(test)]
pub(crate) async fn create_unverified_test_identity(
    identity: &KratosBackend,
    email: &str,
) -> Result<String> {
    let body = ory_client::models::CreateIdentityBody::new(
        "default".to_string(),
        serde_json::json!({ "email": email, "name": { "first": "Prune", "last": "Test" } }),
    );
    let created =
        ory_client::apis::identity_api::create_identity(&identity.clients.kratos_admin, Some(body))
            .await
            .map_err(|e| anyhow::anyhow!("kratos admin create_identity failed: {e}"))?;
    Ok(created.id)
}

impl IdentityBackend for KratosBackend {
    async fn whoami(&self, cookie: Option<&str>) -> Result<WhoamiOutcome> {
        kratos::whoami(&self.clients, cookie).await
    }

    fn has_session_cookie(&self, headers: &HeaderMap) -> bool {
        crate::cookies::read_cookie(headers, SESSION_COOKIE).is_some()
    }

    // Attributes match what Kratos emits in the single-host topology; a no-op when Kratos is on another origin.
    fn clear_session_cookie(&self, secure: bool) -> String {
        let mut s = Cookie::build((SESSION_COOKIE, ""))
            .path("/")
            .same_site(SameSite::Lax)
            .http_only(true)
            .secure(secure)
            .build()
            .to_string();
        s.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        s
    }

    async fn tear_down_session(&self, cookie: &str) {
        kratos::tear_down_session(&self.clients, cookie).await;
    }

    async fn fetch_logout_url(&self, cookie: &str) -> Result<Option<String>> {
        kratos::fetch_logout_url(&self.clients, cookie).await
    }

    fn flow_init_url(&self, kind: FlowKind, init: FlowInit<'_>) -> String {
        browser_init_url(&self.clients.kratos_public.base_path, kind, init)
    }

    async fn get_flow(&self, kind: FlowKind, flow_id: &str, cookie: &str) -> Result<FlowFetch> {
        kratos::get_flow(&self.clients, kind, flow_id, cookie).await
    }

    async fn resolve_flow(
        &self,
        kind: FlowKind,
        flow_id: Option<&str>,
        cookie: &str,
    ) -> FlowOutcome {
        kratos::resolve_flow(&self.clients, kind, flow_id, cookie).await
    }

    async fn verify_known_email(&self, flow: &Flow, email: &str, cookie: &str) -> Result<()> {
        kratos::verify_known_email(&self.clients, flow, email, cookie).await
    }

    async fn get_self_service_error(&self, error_id: &str) -> Result<Option<SelfServiceError>> {
        kratos::get_self_service_error(&self.clients, error_id).await
    }

    async fn probe_oidc_provider_ids(&self) -> Result<Vec<String>> {
        kratos::probe_oidc_provider_ids(&self.clients).await
    }

    async fn list_my_sessions(&self, cookie: Option<&str>) -> Result<Vec<Session>> {
        kratos::list_my_sessions(&self.clients, cookie).await
    }

    async fn revoke_session(&self, id: &str, cookie: Option<&str>) -> Result<()> {
        kratos::revoke_session(&self.clients, id, cookie).await
    }

    async fn revoke_other_sessions(&self, cookie: Option<&str>) -> Result<u64> {
        kratos::revoke_other_sessions(&self.clients, cookie).await
    }

    async fn list_identity_sessions(&self, identity_id: &str) -> Result<Vec<Session>> {
        kratos::list_identity_sessions(&self.clients, identity_id).await
    }

    async fn list_identity_sessions_all(&self, identity_id: &str) -> Result<Vec<Session>> {
        kratos::list_identity_sessions_all(&self.clients, identity_id).await
    }

    async fn active_session_ids(&self, identity_id: &str) -> Result<HashSet<String>> {
        kratos::active_session_ids(&self.clients, identity_id).await
    }

    async fn is_session_active(&self, identity_id: &str, kratos_session_id: &str) -> Result<bool> {
        kratos::is_session_active(&self.clients, identity_id, kratos_session_id).await
    }

    async fn admin_get_session(&self, id: &str) -> Result<Session> {
        kratos::admin_get_session(&self.clients, id).await
    }

    async fn admin_list_all_sessions(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        active: Option<bool>,
    ) -> Result<Vec<Session>> {
        kratos::admin_list_all_sessions(&self.clients, page_size, page_token, active).await
    }

    async fn admin_revoke_session(&self, id: &str) -> Result<()> {
        kratos::admin_revoke_session(&self.clients, id).await
    }

    async fn admin_get_identity(&self, id: &str) -> Result<Identity> {
        kratos::admin_get_identity(&self.clients, id).await
    }

    async fn admin_get_identity_optional(&self, id: &str) -> Result<Option<Identity>> {
        kratos::admin_get_identity_optional(&self.clients, id).await
    }

    async fn admin_get_identity_full(&self, id: &str) -> Result<Identity> {
        kratos::admin_get_identity_full(&self.clients, id).await
    }

    async fn admin_get_identity_full_optional(&self, id: &str) -> Result<Option<Identity>> {
        kratos::admin_get_identity_full_optional(&self.clients, id).await
    }

    async fn list_identities(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        credentials_identifier: Option<&str>,
    ) -> Result<Vec<Identity>> {
        kratos::list_identities(&self.clients, page_size, page_token, credentials_identifier).await
    }

    async fn admin_list_identities_by_ids(&self, ids: Vec<String>) -> Result<Vec<Identity>> {
        kratos::admin_list_identities_by_ids(&self.clients, ids).await
    }

    async fn admin_find_identity_by_email(&self, email: &str) -> Result<Option<(Identity, bool)>> {
        kratos::admin_find_identity_by_email(&self.clients, email).await
    }

    async fn admin_create_identity_verified(
        &self,
        schema_id: &str,
        email: &str,
        first: &str,
        last: &str,
    ) -> Result<Option<Identity>> {
        kratos::admin_create_identity_verified(&self.clients, schema_id, email, first, last).await
    }

    async fn admin_set_identity_language(&self, id: &str, lang: &str) -> Result<Identity> {
        kratos::admin_set_identity_language(&self.clients, id, lang).await
    }

    async fn admin_update_identity_state(
        &self,
        id: &str,
        state: IdentityState,
    ) -> Result<Identity> {
        kratos::admin_update_identity_state(&self.clients, id, state).await
    }

    async fn admin_set_metadata_admin_key(&self, id: &str, key: &str, value: &str) -> Result<()> {
        kratos::admin_set_metadata_admin_key(&self.clients, id, key, value).await
    }

    async fn admin_remove_metadata_admin_key(&self, id: &str, key: &str) -> Result<bool> {
        kratos::admin_remove_metadata_admin_key(&self.clients, id, key).await
    }

    async fn admin_delete_identity(&self, id: &str) -> Result<()> {
        kratos::admin_delete_identity(&self.clients, id).await
    }

    async fn admin_create_recovery_code(&self, identity_id: &str) -> Result<RecoveryCode> {
        kratos::admin_create_recovery_code(&self.clients, identity_id).await
    }

    async fn admin_create_recovery_link(
        &self,
        identity_id: &str,
        expires_in: &str,
        return_to: Option<&str>,
    ) -> Result<String> {
        kratos::admin_create_recovery_link(&self.clients, identity_id, expires_in, return_to).await
    }

    async fn list_identity_schemas(&self) -> Result<Vec<String>> {
        kratos::list_identity_schemas(&self.clients).await
    }

    async fn courier_backlog(&self, status: CourierStatus, page_size: i64) -> Result<u64> {
        kratos::courier_backlog(&self.clients, status, page_size).await
    }

    async fn health_alive(&self) -> Result<()> {
        kratos::health_alive(&self.clients).await
    }

    async fn health_ready(&self) -> Result<()> {
        kratos::health_ready(&self.clients).await
    }

    async fn version(&self) -> Result<String> {
        kratos::version(&self.clients).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    const KRATOS: &str = "http://kratos:4433/";

    fn kratos() -> Arc<KratosBackend> {
        crate::ory::test_backends(
            KRATOS,
            "http://kratos:4434",
            "http://hydra:4444",
            "http://hydra:4445",
        )
        .0
    }

    #[test]
    fn flow_init_url_per_kind() {
        let backend = kratos();
        for (kind, segment) in [
            (FlowKind::Login, "login"),
            (FlowKind::Registration, "registration"),
            (FlowKind::Recovery, "recovery"),
            (FlowKind::Verification, "verification"),
            (FlowKind::Settings, "settings"),
        ] {
            let base = format!("http://kratos:4433/self-service/{segment}/browser");
            for return_to in [None, Some("")] {
                let init = FlowInit {
                    return_to,
                    ..FlowInit::default()
                };
                assert_eq!(
                    backend.flow_init_url(kind, init),
                    base,
                    "{kind:?} {return_to:?}"
                );
            }
            let init = FlowInit {
                return_to: Some("https://app.example/settings?a=b c&x=ü"),
                ..FlowInit::default()
            };
            assert_eq!(
                backend.flow_init_url(kind, init),
                format!(
                    "{base}?return_to=https%3A%2F%2Fapp.example%2Fsettings%3Fa%3Db+c%26x%3D%C3%BC"
                ),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn flow_init_url_aal_and_refresh() {
        let backend = kratos();
        let base = "http://kratos:4433/self-service/login/browser";
        let cases = [
            (None, None, false, String::new()),
            (Some(""), Some(""), false, String::new()),
            (None, Some("aal2"), false, "?aal=aal2".to_string()),
            (None, None, true, "?refresh=true".to_string()),
            (
                Some("/join/confirm?token=a+b/c"),
                Some("aal2"),
                true,
                "?return_to=%2Fjoin%2Fconfirm%3Ftoken%3Da%2Bb%2Fc&aal=aal2&refresh=true"
                    .to_string(),
            ),
            (
                Some("/settings"),
                Some(""),
                true,
                "?return_to=%2Fsettings&refresh=true".to_string(),
            ),
        ];
        for (return_to, aal, refresh, query) in cases {
            let init = FlowInit {
                return_to,
                aal,
                refresh,
            };
            assert_eq!(
                backend.flow_init_url(FlowKind::Login, init),
                format!("{base}{query}"),
                "{return_to:?} {aal:?} {refresh:?}"
            );
        }
    }

    #[test]
    fn has_session_cookie_matches_read_cookie() {
        let backend = kratos();
        let cases: [&[&str]; 6] = [
            &[],
            &["ory_kratos_session=abc"],
            &["a=1; ory_kratos_session=abc; b=2"],
            &["a=1", "ory_kratos_session=abc"],
            &["ory_kratos_session_x=abc; ory_session=1"],
            &["ory_kratos_session="],
        ];
        for lines in cases {
            let mut headers = HeaderMap::new();
            for line in lines {
                headers.append(COOKIE, line.parse().unwrap());
            }
            assert_eq!(
                backend.has_session_cookie(&headers),
                crate::cookies::read_cookie(&headers, "ory_kratos_session").is_some(),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn clear_session_cookie_attributes() {
        let backend = kratos();
        assert_eq!(
            backend.clear_session_cookie(true),
            "ory_kratos_session=; HttpOnly; SameSite=Lax; Secure; Path=/; \
             Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        );
        assert_eq!(
            backend.clear_session_cookie(false),
            "ory_kratos_session=; HttpOnly; SameSite=Lax; Path=/; \
             Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }
}
