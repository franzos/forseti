use std::collections::HashSet;

use anyhow::Result;
use axum::http::HeaderMap;

use super::flows::Found;
use super::{NativeBackend, errors, mail, session, store};
use crate::backend::IdentityBackend;
use crate::backend::identity::{
    Aal, BrowserSession, CourierStatus, FlowFetch, FlowInit, FlowKind, FlowOutcome, Identity,
    IdentityState, PrivilegedReason, RecoveryCode, SelfServiceError, Session, SessionOrigin,
    WhoamiOutcome, browser_init_url,
};
use crate::flow_view::Flow;

fn not_found(id: &str) -> anyhow::Error {
    anyhow::anyhow!("identity {id} not found")
}

fn no_session() -> anyhow::Error {
    anyhow::anyhow!("no live session cookie")
}

impl NativeBackend {
    /// Sets [`Identity::sole_sign_in_is_oidc`]: linked, no password, and at most one link to a
    /// configured provider. Links to providers removed from config are no way in.
    fn with_sign_in_fact(&self, mut identity: Identity) -> Identity {
        let links = crate::settings::linked_providers::linked_provider_ids(&identity);
        let has_password = identity
            .credentials
            .as_ref()
            .is_some_and(|c| c.contains_key("password"));
        let usable = self.upstream.ids().filter(|p| links.contains(*p)).count();
        identity.sole_sign_in_is_oidc = Some(!links.is_empty() && !has_password && usable <= 1);
        identity
    }
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
        Ok(self.upstream.ids().map(str::to_string).collect())
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
        Ok(store::get(&self.db, id)
            .await?
            .map(|i| self.with_sign_in_fact(i)))
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
        let found = store::list(&self.db, page_size, page_token, credentials_identifier).await?;
        Ok(found
            .into_iter()
            .map(|i| self.with_sign_in_fact(i))
            .collect())
    }

    async fn admin_list_identities_by_ids(&self, ids: Vec<String>) -> Result<Vec<Identity>> {
        let found = store::list_by_ids(&self.db, ids).await?;
        Ok(found
            .into_iter()
            .map(|i| self.with_sign_in_fact(i))
            .collect())
    }

    async fn admin_find_identity_by_email(&self, email: &str) -> Result<Option<(Identity, bool)>> {
        Ok(store::find_by_email(&self.db, email)
            .await?
            .map(|(i, verified)| (self.with_sign_in_fact(i), verified)))
    }

    async fn admin_create_identity_verified(
        &self,
        _schema_id: &str,
        email: &str,
        first: &str,
        last: &str,
    ) -> Result<Option<Identity>> {
        let max = store::NAME_MAX_CHARS;
        if first.chars().count() > max || last.chars().count() > max {
            anyhow::bail!("name longer than {max} characters");
        }
        Ok(
            store::create(&self.db, email, Some(first), Some(last), true)
                .await?
                .map(|i| self.with_sign_in_fact(i)),
        )
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

    // AAL1 like a password sign-in: whoami still asks an identity with TOTP for its second factor.
    // A never-verified identity gets none, as on the provider path.
    async fn establish_browser_session(
        &self,
        identity_id: &str,
        return_to: &str,
        origin: SessionOrigin<'_>,
    ) -> Result<BrowserSession> {
        if !store::row_by_id(&self.db, identity_id)
            .await?
            .is_some_and(|row| store::is_active(&row) && row.first_verified_at.is_some())
        {
            anyhow::bail!("identity {identity_id} is missing, inactive or never verified");
        }
        let device = session::Device {
            ip: origin.ip,
            user_agent: origin.user_agent,
        };
        let issued = self
            .issue_session(identity_id, origin.method, None, Aal::Aal1, device)
            .await?;
        Ok(BrowserSession {
            location: return_to.to_string(),
            set_cookies: vec![self.session_set_cookie(&issued.token)],
        })
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

    const ORIGIN: SessionOrigin<'static> = SessionOrigin {
        method: "saml",
        ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))),
        user_agent: Some("Mozilla/5.0 sso"),
    };

    fn cookie_header(set_cookie: &str) -> String {
        set_cookie.split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn an_established_browser_session_is_an_aal1_session_cookie_for_return_to() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let id = store::create(&db, "sso@x.test", None, None, true)
            .await
            .unwrap()
            .unwrap()
            .id;
        let established = backend
            .establish_browser_session(&id, "/", ORIGIN)
            .await
            .unwrap();
        assert_eq!(established.location, "/");
        let [set_cookie] = established.set_cookies.as_slice() else {
            panic!("one cookie expected: {:?}", established.set_cookies);
        };
        let token = cookie_header(set_cookie)
            .strip_prefix("forseti_session=")
            .unwrap()
            .to_string();
        assert_eq!(set_cookie, &backend.session_set_cookie(&token));
        let WhoamiOutcome::Ok(s) = backend
            .whoami(Some(&cookie_header(set_cookie)))
            .await
            .unwrap()
        else {
            panic!("the cookie carries a session");
        };
        assert_eq!(s.authenticator_assurance_level, Some(Aal::Aal1));
        let [method] = s.authentication_methods.as_deref().unwrap() else {
            panic!("one method expected");
        };
        assert_eq!(method.method.as_deref(), Some("saml"));
        assert_eq!(method.provider, None);
        let device = &s.devices.as_deref().unwrap()[0];
        assert_eq!(device.ip_address.as_deref(), Some("192.0.2.9"));
        assert_eq!(device.user_agent.as_deref(), Some("Mozilla/5.0 sso"));

        super::super::test_support::plant_totp(&backend, &id).await;
        assert!(matches!(
            backend
                .whoami(Some(&cookie_header(set_cookie)))
                .await
                .unwrap(),
            WhoamiOutcome::InsufficientAal
        ));
    }

    #[tokio::test]
    async fn no_browser_session_for_a_missing_inactive_or_never_verified_identity() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let missing = "00000000-0000-4000-8000-000000000000";
        assert!(
            backend
                .establish_browser_session(missing, "/", ORIGIN)
                .await
                .is_err()
        );
        let id = store::create(&db, "off@x.test", None, None, true)
            .await
            .unwrap()
            .unwrap()
            .id;
        store::set_state(&db, &id, IdentityState::Inactive)
            .await
            .unwrap();
        assert!(
            backend
                .establish_browser_session(&id, "/", ORIGIN)
                .await
                .is_err()
        );
        let never_verified = store::create(&db, "new@x.test", None, None, false)
            .await
            .unwrap()
            .unwrap()
            .id;
        assert!(
            backend
                .establish_browser_session(&never_verified, "/", ORIGIN)
                .await
                .is_err()
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
