use std::collections::HashSet;

use anyhow::Result;
use axum::http::HeaderMap;

use super::flows::Found;
use super::{NativeBackend, errors, mail, session, store};
use crate::backend::IdentityBackend;
use crate::backend::identity::{
    CourierStatus, FlowFetch, FlowInit, FlowKind, FlowOutcome, Identity, IdentityState,
    PrivilegedReason, RecoveryCode, SelfServiceError, Session, WhoamiOutcome, browser_init_url,
};
use crate::flow_view::Flow;

fn not_found(id: &str) -> anyhow::Error {
    anyhow::anyhow!("identity {id} not found")
}

fn no_session() -> anyhow::Error {
    anyhow::anyhow!("no live session cookie")
}

impl IdentityBackend for NativeBackend {
    async fn whoami(&self, cookie: Option<&str>) -> Result<WhoamiOutcome> {
        match cookie.and_then(|c| self.session_token(c)) {
            Some(token) => session::whoami(&self.db, &token).await,
            None => Ok(WhoamiOutcome::None),
        }
    }

    fn has_session_cookie(&self, headers: &HeaderMap) -> bool {
        crate::cookies::read_cookie(headers, session::cookie_name(self.https)).is_some()
    }

    fn clear_session_cookie(&self, secure: bool) -> String {
        session::clear_cookie(secure)
    }

    async fn tear_down_session(&self, cookie: &str) {
        let Some(token) = self.session_token(cookie) else {
            return;
        };
        if let Err(e) = session::revoke_by_token(&self.db, &token).await {
            tracing::warn!(error = ?e, "native session teardown failed");
        }
    }

    async fn fetch_logout_url(&self, cookie: &str) -> Result<Option<String>> {
        Ok(self
            .current_session(Some(cookie))
            .await?
            .map(|s| self.logout_url(&s.id)))
    }

    // Flows are served by Forseti itself, so the init URL is relative.
    fn flow_init_url(&self, kind: FlowKind, init: FlowInit<'_>) -> String {
        browser_init_url("", kind, init)
    }

    async fn get_flow(&self, kind: FlowKind, flow_id: &str, cookie: &str) -> Result<FlowFetch> {
        Ok(match self.browser_flow(kind, flow_id, cookie).await? {
            Found::Ready(mut rec) => {
                let doc = self.flow_document(&mut rec, cookie).await?;
                FlowFetch::Ok(Box::new(crate::flow_json::project(&doc)))
            }
            Found::Gone => FlowFetch::Gone,
            Found::Aal2Required => FlowFetch::PrivilegedRequired(PrivilegedReason::Aal2Required),
        })
    }

    async fn resolve_flow(
        &self,
        kind: FlowKind,
        flow_id: Option<&str>,
        cookie: &str,
    ) -> FlowOutcome {
        let Some(flow_id) = flow_id else {
            return FlowOutcome::Init;
        };
        match self.get_flow(kind, flow_id, cookie).await {
            Ok(FlowFetch::Ok(flow)) => FlowOutcome::Ready(flow),
            Ok(FlowFetch::Gone) => FlowOutcome::Reinit,
            Ok(FlowFetch::PrivilegedRequired(reason)) => FlowOutcome::Privileged(reason),
            Err(e) => FlowOutcome::Error(e),
        }
    }

    async fn verify_known_email(&self, flow: &Flow, email: &str, _cookie: &str) -> Result<()> {
        self.request_verification_for_known(&flow.id, email).await
    }

    async fn get_self_service_error(&self, error_id: &str) -> Result<Option<SelfServiceError>> {
        Ok(errors::lookup(error_id))
    }

    async fn probe_oidc_provider_ids(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn list_my_sessions(&self, cookie: Option<&str>) -> Result<Vec<Session>> {
        let current = self.current_session(cookie).await?.ok_or_else(no_session)?;
        session::live_for_identity(&self.db, &current.identity_id, Some(&current.id)).await
    }

    async fn revoke_session(&self, id: &str, cookie: Option<&str>) -> Result<()> {
        let current = self.current_session(cookie).await?.ok_or_else(no_session)?;
        if current.id == id {
            anyhow::bail!("the current session cannot be revoked here; sign out instead");
        }
        if !session::revoke(&self.db, id, Some(&current.identity_id)).await? {
            anyhow::bail!("session {id} is not one of the caller's sessions");
        }
        Ok(())
    }

    async fn revoke_other_sessions(&self, cookie: Option<&str>) -> Result<u64> {
        let current = self.current_session(cookie).await?.ok_or_else(no_session)?;
        session::revoke_all(&self.db, &current.identity_id, Some(&current.id)).await
    }

    async fn list_identity_sessions(&self, identity_id: &str) -> Result<Vec<Session>> {
        session::list_page_for_identity(&self.db, identity_id).await
    }

    async fn list_identity_sessions_all(&self, identity_id: &str) -> Result<Vec<Session>> {
        session::list_for_identity(&self.db, identity_id, None).await
    }

    async fn active_session_ids(&self, identity_id: &str) -> Result<HashSet<String>> {
        Ok(session::live_for_identity(&self.db, identity_id, None)
            .await?
            .into_iter()
            .map(|s| s.id)
            .collect())
    }

    async fn is_session_active(&self, identity_id: &str, kratos_session_id: &str) -> Result<bool> {
        session::is_live_for(&self.db, identity_id, kratos_session_id).await
    }

    async fn admin_get_session(&self, id: &str) -> Result<Session> {
        session::get(&self.db, id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("session {id} not found"))
    }

    async fn admin_list_all_sessions(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        active: Option<bool>,
    ) -> Result<Vec<Session>> {
        session::list_all(&self.db, page_size, page_token, active).await
    }

    async fn admin_revoke_session(&self, id: &str) -> Result<()> {
        if session::revoke(&self.db, id, None).await? {
            Ok(())
        } else {
            Err(anyhow::anyhow!("session {id} not found"))
        }
    }

    async fn admin_get_identity(&self, id: &str) -> Result<Identity> {
        self.admin_get_identity_optional(id)
            .await?
            .ok_or_else(|| not_found(id))
    }

    async fn admin_get_identity_optional(&self, id: &str) -> Result<Option<Identity>> {
        store::get(&self.db, id).await
    }

    // Credential configs hold secrets and are never handed out, so "full" is the same view.
    async fn admin_get_identity_full(&self, id: &str) -> Result<Identity> {
        self.admin_get_identity(id).await
    }

    async fn admin_get_identity_full_optional(&self, id: &str) -> Result<Option<Identity>> {
        self.admin_get_identity_optional(id).await
    }

    async fn list_identities(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        credentials_identifier: Option<&str>,
    ) -> Result<Vec<Identity>> {
        store::list(&self.db, page_size, page_token, credentials_identifier).await
    }

    async fn admin_list_identities_by_ids(&self, ids: Vec<String>) -> Result<Vec<Identity>> {
        store::list_by_ids(&self.db, ids).await
    }

    async fn admin_find_identity_by_email(&self, email: &str) -> Result<Option<(Identity, bool)>> {
        store::find_by_email(&self.db, email).await
    }

    async fn admin_create_identity_verified(
        &self,
        _schema_id: &str,
        email: &str,
        first: &str,
        last: &str,
    ) -> Result<Option<Identity>> {
        store::create(&self.db, email, Some(first), Some(last), true).await
    }

    async fn admin_set_identity_language(&self, id: &str, lang: &str) -> Result<Identity> {
        if !store::set_language(&self.db, id, lang).await? {
            return Err(not_found(id));
        }
        self.admin_get_identity(id).await
    }

    async fn admin_update_identity_state(
        &self,
        id: &str,
        state: IdentityState,
    ) -> Result<Identity> {
        store::set_state(&self.db, id, state).await?;
        self.admin_get_identity(id).await
    }

    async fn admin_set_metadata_admin_key(&self, id: &str, key: &str, value: &str) -> Result<()> {
        store::patch_metadata_admin(&self.db, id, key, Some(value))
            .await?
            .ok_or_else(|| not_found(id))
            .map(|_| ())
    }

    async fn admin_remove_metadata_admin_key(&self, id: &str, key: &str) -> Result<bool> {
        store::patch_metadata_admin(&self.db, id, key, None)
            .await?
            .ok_or_else(|| not_found(id))
    }

    async fn admin_delete_identity(&self, id: &str) -> Result<()> {
        if store::delete(&self.db, id).await? {
            Ok(())
        } else {
            Err(not_found(id))
        }
    }

    async fn admin_create_recovery_code(&self, identity_id: &str) -> Result<RecoveryCode> {
        self.admin_recovery_code(identity_id).await
    }

    // Only the SAML bridge mints recovery links, and it is not mounted on this backend.
    async fn admin_create_recovery_link(
        &self,
        _identity_id: &str,
        _expires_in: &str,
        _return_to: Option<&str>,
    ) -> Result<String> {
        anyhow::bail!("recovery links are not supported by the native identity backend")
    }

    async fn list_identity_schemas(&self) -> Result<Vec<String>> {
        Ok(vec!["default".to_string()])
    }

    // Capped at `page_size` like Kratos's first-page count.
    async fn courier_backlog(&self, status: CourierStatus, page_size: i64) -> Result<u64> {
        let state = match status {
            CourierStatus::Queued => mail::state::QUEUED,
            CourierStatus::Abandoned => mail::state::ABANDONED,
        };
        self.count_mail(state, page_size).await
    }

    async fn health_alive(&self) -> Result<()> {
        Ok(())
    }

    async fn health_ready(&self) -> Result<()> {
        self.db.ping().await
    }

    async fn version(&self) -> Result<String> {
        Ok(format!("native {}", crate::web::FORSETI_VERSION))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn answers_the_methods_without_storage() {
        let backend = NativeBackend::for_test(&crate::db::test_pool().await);
        backend.health_alive().await.expect("alive");
        backend.health_ready().await.expect("ready");
        assert!(backend.version().await.unwrap().starts_with("native "));
        assert_eq!(backend.list_identity_schemas().await.unwrap(), ["default"]);
        assert!(backend.probe_oidc_provider_ids().await.unwrap().is_empty());
        assert!(
            backend
                .admin_create_recovery_link("id", "1h", None)
                .await
                .is_err()
        );
        assert_eq!(
            backend.flow_init_url(
                FlowKind::Login,
                FlowInit {
                    aal: Some("aal2"),
                    ..Default::default()
                }
            ),
            "/self-service/login/browser?aal=aal2"
        );
    }

    #[tokio::test]
    async fn missing_identity_is_none_for_optional_lookups_and_err_elsewhere() {
        let backend = NativeBackend::for_test(&crate::db::test_pool().await);
        let id = "00000000-0000-4000-8000-000000000000";
        assert!(
            backend
                .admin_get_identity_optional(id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .admin_get_identity_full_optional(id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .admin_find_identity_by_email("x@x.test")
                .await
                .unwrap()
                .is_none()
        );
        assert!(backend.admin_get_identity(id).await.is_err());
        assert!(backend.admin_get_identity_full(id).await.is_err());
        assert!(backend.admin_set_identity_language(id, "de").await.is_err());
        assert!(
            backend
                .admin_update_identity_state(id, IdentityState::Inactive)
                .await
                .is_err()
        );
        assert!(
            backend
                .admin_set_metadata_admin_key(id, "k", "v")
                .await
                .is_err()
        );
        assert!(
            backend
                .admin_remove_metadata_admin_key(id, "k")
                .await
                .is_err()
        );
        assert!(backend.admin_delete_identity(id).await.is_err());
    }

    #[tokio::test]
    async fn find_by_email_reports_the_verified_flag() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let verified = store::create(&db, "V@x.test", None, None, true)
            .await
            .unwrap()
            .unwrap();
        store::create(&db, "u@x.test", None, None, false)
            .await
            .unwrap()
            .unwrap();
        let (found, is_verified) = backend
            .admin_find_identity_by_email("v@X.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((found.id, is_verified), (verified.id, true));
        let (_, is_verified) = backend
            .admin_find_identity_by_email("u@x.test")
            .await
            .unwrap()
            .unwrap();
        assert!(!is_verified);
    }

    #[tokio::test]
    async fn find_by_email_reports_a_non_ascii_address_verified_in_any_case() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let created = store::create(&db, "Ärger@Ü.test", None, None, true)
            .await
            .unwrap()
            .unwrap();
        let (found, is_verified) = backend
            .admin_find_identity_by_email("ärger@ü.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((found.id, is_verified), (created.id, true));
    }

    #[tokio::test]
    async fn state_change_returns_the_updated_identity() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let created = store::create(&db, "s@x.test", None, None, true)
            .await
            .unwrap()
            .unwrap();
        let disabled = backend
            .admin_update_identity_state(&created.id, IdentityState::Inactive)
            .await
            .unwrap();
        assert_eq!(disabled.state, Some(IdentityState::Inactive));
        let lang = backend
            .admin_set_identity_language(&created.id, "th")
            .await
            .unwrap();
        assert_eq!(lang.state, Some(IdentityState::Inactive));
        assert_eq!(lang.traits.unwrap()["preferred_language"], "th");
    }
}
