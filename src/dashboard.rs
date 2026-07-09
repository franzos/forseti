//! `/` handler: the post-login landing page (Recent Activity sidebar +
//! Account health tile). Both side-panels are best-effort; upstream failures
//! fold to safe defaults so the page always renders.

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};

use crate::config::AppEntry;
use crate::cookies;
use crate::extractors::RequireSession;
use crate::flow_view::session_needs_verification;
use crate::format::{humanise_timestamp, humanise_user_agent};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::page_chrome::{ReqLocale, ThemedChrome};
use crate::render::render;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    chrome: PageChrome,
    needs_verification: bool,
    apps: Vec<AppEntry>,
    /// Recent sign-in events, newest first, from Kratos's session history.
    /// Empty when the admin API call fails.
    activity: Vec<ActivityEvent>,
    health: AccountHealth,
    /// `Some` when a verified-domain address resolves to a proven `auto_join`
    /// org the caller isn't a member of: renders the explicit join prompt.
    domain_prompt: Option<crate::orgs::domain_prompt::ProvenJoin>,
}

struct ActivityEvent {
    title: String,
    detail: String,
    when: String,
    /// Full ISO timestamp shown on hover, preserved when `when` is humanised.
    when_full: String,
    /// Full user-agent shown on hover; `detail` shows the parsed form.
    ua_full: String,
}

struct AccountHealth {
    email_verified: bool,
    two_factor_enabled: bool,
    /// Device factor enrolled but no recovery codes: losing the device means
    /// permanent lockout. Drives a backstop notice.
    two_factor_without_recovery_codes: bool,
    active_sessions: usize,
    linked_providers: usize,
}

pub(crate) async fn root(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: RequireSession,
    ReqLocale(locale): ReqLocale,
    themed: ThemedChrome,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let session = sess.session;
    let identity_id = sess.identity_id;
    let email = sess.email;

    let (activity, health, domain_prompt) = tokio::join!(
        build_activity_feed(&state, &session, &locale),
        build_account_health(&state, &session, &cookie),
        crate::orgs::domain_prompt::resolve_prompt(&state.db, &session, &identity_id, &email),
    );

    render(&DashboardTemplate {
        chrome: themed.chrome,
        needs_verification: session_needs_verification(&session),
        apps: state.cfg.apps.clone(),
        activity,
        health,
        domain_prompt,
    })
}

/// "Recent Activity" payload from Kratos's session history (most recent 5).
/// Failures are non-fatal: log and return empty.
async fn build_activity_feed(
    state: &AppState,
    session: &ory::Session,
    locale: &crate::locale::LanguageIdentifier,
) -> Vec<ActivityEvent> {
    let Some(identity_id) = session.identity.as_ref().map(|id| id.id.clone()) else {
        return Vec::new();
    };
    let sessions = match ory::kratos::list_identity_sessions(&state.ory, &identity_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = ?e, identity_id, "list_identity_sessions failed; activity feed empty");
            return Vec::new();
        }
    };
    let mut sorted = sessions;
    // Newest first by authenticated_at; sessions without that field fall to the bottom.
    sorted.sort_by(|a, b| b.authenticated_at.cmp(&a.authenticated_at));
    sorted
        .into_iter()
        .take(5)
        .map(|s| {
            let device = s
                .devices
                .as_ref()
                .and_then(|d| d.first())
                .cloned()
                .unwrap_or_default();
            let ua_full = device.user_agent.unwrap_or_default();
            let ip = device.ip_address.unwrap_or_default();
            let ua_pretty = humanise_user_agent(locale, &ua_full);
            let detail = match (ua_pretty.is_empty(), ip.is_empty()) {
                (false, false) => format!("{ua_pretty} \u{00b7} {ip}"),
                (false, true) => ua_pretty,
                (true, false) => ip,
                (true, true) => crate::i18n::lookup(locale, "format-device-unknown"),
            };
            let when_full = s.authenticated_at.unwrap_or_else(|| "—".to_string());
            let when = humanise_timestamp(locale, &when_full);
            ActivityEvent {
                title: crate::i18n::lookup(locale, "dashboard-activity-signin-title"),
                detail,
                when,
                when_full,
                ua_full,
            }
        })
        .collect()
}

/// "Account health" tile from the session, admin identity (credentials), and
/// the user's sessions. Best-effort: failures fold to `false` / `0`.
async fn build_account_health(
    state: &AppState,
    session: &ory::Session,
    cookie: &str,
) -> AccountHealth {
    let email_verified = !session_needs_verification(session);

    let identity_id = session.identity.as_ref().map(|id| id.id.clone());

    // Public sessions (user's cookie) plus the admin "full" identity, whose
    // credentials reveal 2FA factors and linked OIDC providers.
    let (sessions_res, identity_res) = tokio::join!(
        ory::kratos::list_my_sessions(&state.ory, (!cookie.is_empty()).then_some(cookie)),
        async {
            match identity_id.as_deref() {
                Some(id) => ory::kratos::admin_get_identity_full(&state.ory, id).await,
                None => Err(anyhow::anyhow!("session has no identity id")),
            }
        }
    );

    let active_sessions = match sessions_res {
        // Kratos /sessions excludes the current session; count it.
        Ok(s) => s.len() + 1,
        Err(e) => {
            tracing::warn!(error = ?e, "list_my_sessions failed; health.active_sessions=0");
            0
        }
    };

    let (two_factor_enabled, two_factor_without_recovery_codes, linked_providers) =
        match identity_res {
            Ok(identity) => {
                let creds = identity.credentials.unwrap_or_default();
                let two_factor = creds_indicate_second_factor(&creds);
                let without_codes = two_factor_without_recovery_codes(&creds);
                let oidc_count = creds
                    .get("oidc")
                    .and_then(|c| c.identifiers.as_ref().map(|ids| ids.len()))
                    .unwrap_or(0);
                (two_factor, without_codes, oidc_count)
            }
            Err(e) => {
                tracing::warn!(error = ?e, "admin_get_identity_full failed; health 2FA/oidc=0");
                (false, false, 0)
            }
        };

    AccountHealth {
        email_verified,
        two_factor_enabled,
        two_factor_without_recovery_codes,
        active_sessions,
        linked_providers,
    }
}

/// True when a second factor is enrolled. Kratos seeds `webauthn.identifiers`
/// on every password identity (not enrolment), so test `config.credentials`.
fn creds_indicate_second_factor(
    creds: &std::collections::HashMap<String, ory_client::models::IdentityCredentials>,
) -> bool {
    if creds.contains_key("totp") || creds.contains_key("lookup_secret") {
        return true;
    }
    ["webauthn", "passkey"].iter().any(|k| {
        creds
            .get(*k)
            .and_then(|c| c.config.as_ref())
            .and_then(|cfg| cfg.get("credentials"))
            .and_then(|v| v.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false)
    })
}

/// A device second factor (TOTP/WebAuthn) with no `lookup_secret` is the
/// self-lockout trap; `lookup_secret` present clears it, no factor clears it.
fn two_factor_without_recovery_codes(
    creds: &std::collections::HashMap<String, ory_client::models::IdentityCredentials>,
) -> bool {
    creds_indicate_second_factor(creds) && !creds.contains_key("lookup_secret")
}

#[cfg(test)]
mod tests {
    //! Locks the "2FA enabled" badge helper against the WebAuthn pre-stub
    //! false-positive: Kratos seeds `credentials.webauthn.identifiers` with the
    //! user's email on every password identity, so an `identifiers.is_empty()`
    //! check flips the badge on for users who never enrolled.
    use super::{creds_indicate_second_factor, two_factor_without_recovery_codes};
    use ory_client::models::IdentityCredentials;
    use std::collections::HashMap;

    fn empty_cred() -> IdentityCredentials {
        IdentityCredentials::new()
    }

    /// Pre-stub: `identifiers` seeded but `config` carries no `credentials`
    /// array, so 2FA is off.
    fn webauthn_pre_stub() -> IdentityCredentials {
        let mut c = IdentityCredentials::new();
        c.identifiers = Some(vec!["user@example.com".to_string()]);
        c.config = Some(serde_json::json!({ "user_handle": "abc=" }));
        c
    }

    /// Attested credential: non-empty `config.credentials` array.
    fn webauthn_enrolled() -> IdentityCredentials {
        let mut c = IdentityCredentials::new();
        c.config = Some(serde_json::json!({
            "user_handle": "abc=",
            "credentials": [{ "id": "..." }],
        }));
        c
    }

    #[test]
    fn password_only_is_not_second_factor() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), empty_cred());
        assert!(!creds_indicate_second_factor(&creds));
    }

    #[test]
    fn password_plus_webauthn_pre_stub_is_not_second_factor() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), empty_cred());
        creds.insert("webauthn".to_string(), webauthn_pre_stub());
        assert!(
            !creds_indicate_second_factor(&creds),
            "webauthn pre-stub (config.user_handle only) must NOT count as 2FA"
        );
    }

    #[test]
    fn totp_enrolled_is_second_factor() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), empty_cred());
        creds.insert("totp".to_string(), empty_cred());
        assert!(creds_indicate_second_factor(&creds));
    }

    #[test]
    fn password_plus_lookup_secret_is_second_factor() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), empty_cred());
        creds.insert("lookup_secret".to_string(), empty_cred());
        assert!(creds_indicate_second_factor(&creds));
    }

    #[test]
    fn webauthn_with_attested_credentials_is_second_factor() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), empty_cred());
        creds.insert("webauthn".to_string(), webauthn_enrolled());
        assert!(creds_indicate_second_factor(&creds));
    }

    #[test]
    fn device_factor_without_lookup_needs_recovery_codes() {
        let mut creds = HashMap::new();
        creds.insert("totp".to_string(), empty_cred());
        assert!(two_factor_without_recovery_codes(&creds));
    }

    #[test]
    fn lookup_secret_present_clears_recovery_warning() {
        let mut creds = HashMap::new();
        creds.insert("totp".to_string(), empty_cred());
        creds.insert("lookup_secret".to_string(), empty_cred());
        assert!(!two_factor_without_recovery_codes(&creds));
    }

    #[test]
    fn no_second_factor_does_not_need_recovery_codes() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), empty_cred());
        assert!(!two_factor_without_recovery_codes(&creds));
    }
}
