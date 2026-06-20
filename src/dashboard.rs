//! `/` handler: the post-login landing page.
//!
//! Renders the dashboard template, including the "Recent Activity" sidebar
//! (derived from Kratos's identity session history) and the "Account health"
//! tile (verified email, 2FA enrolment, active sessions, linked OIDC
//! providers). Both side-panels are best-effort — upstream failures fold to
//! safe defaults so the page itself never fails to render.

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};

use crate::config::AppEntry;
use crate::cookies;
use crate::extractors::{Csrf, RequireSession};
use crate::flow_view::{session_email, session_needs_verification};
use crate::format::{humanise_timestamp, humanise_user_agent};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    chrome: PageChrome,
    needs_verification: bool,
    apps: Vec<AppEntry>,
    /// Recent sign-in events, newest first. Stand-in for a full audit log;
    /// derived from Kratos's identity session history. Empty when the admin
    /// API call fails — the template handles the empty case gracefully.
    activity: Vec<ActivityEvent>,
    /// At-a-glance account status (verified email, 2FA, session/provider counts).
    health: AccountHealth,
}

/// One row in the dashboard's "Recent Activity" sidebar.
struct ActivityEvent {
    title: String,
    detail: String,
    when: String,
    /// Full ISO timestamp surfaced on hover via `title=` so the precise
    /// authenticated_at is preserved even when `when` is humanised.
    when_full: String,
    /// Full user-agent string preserved on hover via `title=`; the visible
    /// `detail` shows the parsed "Chrome on Linux" form.
    ua_full: String,
}

/// Dashboard "Account health" tile — a 4-row at-a-glance status panel.
///
/// Each row reflects one signal sourced from the session/identity:
/// email verification, 2FA enrolment, active session count, linked
/// upstream OIDC providers. Failures upstream collapse to safe defaults
/// (counts of 0, booleans false) so the card always renders.
struct AccountHealth {
    email_verified: bool,
    two_factor_enabled: bool,
    active_sessions: usize,
    linked_providers: usize,
}

pub(crate) async fn root(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    let cookie = cookies::cookie_header(&headers);
    let session = sess.session;

    let (activity, health) = tokio::join!(
        build_activity_feed(&state, &session),
        build_account_health(&state, &session, &cookie)
    );

    render(&DashboardTemplate {
        chrome: PageChrome::from_parts(&state, session_email(&session), csrf.0),
        needs_verification: session_needs_verification(&session),
        apps: state.cfg.apps.clone(),
        activity,
        health,
    })
}

/// Build the "Recent Activity" sidebar payload from Kratos's identity session
/// history. Each `Session` row becomes one "Successful sign-in" event. We
/// truncate to the most recent 5 to keep the sidebar tight.
///
/// Failures are non-fatal — the dashboard is the post-login landing page, and
/// a missing audit feed shouldn't make the page itself fail. We log and
/// return an empty list (the template renders an "no recent activity"
/// fallback).
async fn build_activity_feed(state: &AppState, session: &ory::Session) -> Vec<ActivityEvent> {
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
            let ua_pretty = humanise_user_agent(&ua_full);
            let detail = match (ua_pretty.is_empty(), ip.is_empty()) {
                (false, false) => format!("{ua_pretty} \u{00b7} {ip}"),
                (false, true) => ua_pretty,
                (true, false) => ip,
                (true, true) => "Unknown device".to_string(),
            };
            let when_full = s.authenticated_at.unwrap_or_else(|| "—".to_string());
            let when = humanise_timestamp(&when_full);
            ActivityEvent {
                title: "Successful sign-in".to_string(),
                detail,
                when,
                when_full,
                ua_full,
            }
        })
        .collect()
}

/// Compute the dashboard's "Account health" tile from the session + admin
/// identity (for credentials) + the user's own sessions list.
///
/// Both upstream calls are best-effort: any failure folds to a neutral
/// default (`false` / `0`) so the dashboard still renders. The function
/// never returns `Result` for that reason.
async fn build_account_health(
    state: &AppState,
    session: &ory::Session,
    cookie: &str,
) -> AccountHealth {
    let email_verified = !session_needs_verification(session);

    let identity_id = session.identity.as_ref().map(|id| id.id.clone());

    // Pull active sessions via the public API (uses the user's cookie) and
    // the admin "full" identity (to read credentials → which 2FA factors
    // and which OIDC providers are linked).
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

    let (two_factor_enabled, linked_providers) = match identity_res {
        Ok(identity) => {
            let creds = identity.credentials.unwrap_or_default();
            let two_factor = creds_indicate_second_factor(&creds);
            let oidc_count = creds
                .get("oidc")
                .and_then(|c| c.identifiers.as_ref().map(|ids| ids.len()))
                .unwrap_or(0);
            (two_factor, oidc_count)
        }
        Err(e) => {
            tracing::warn!(error = ?e, "admin_get_identity_full failed; health 2FA/oidc=0");
            (false, 0)
        }
    };

    AccountHealth {
        email_verified,
        two_factor_enabled,
        active_sessions,
        linked_providers,
    }
}

/// True when the identity has enrolled a second-factor (or passkey)
/// credential. Kratos pre-populates `credentials.webauthn.identifiers`
/// with the user's email on every password identity so WebAuthn can be
/// offered as a step-up method — that pre-allocation is NOT enrolment, so
/// `identifiers.is_empty()` is the wrong test. The real signals: `totp`
/// only appears when the user completes TOTP enrolment, `lookup_secret`
/// only appears once backup codes are generated, and webauthn/passkey
/// have a `config.credentials` array that's only populated post-attest.
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

#[cfg(test)]
mod tests {
    //! Locks the helper that drives the dashboard "2FA enabled" badge.
    //! See the commit that fixed the false-positive WebAuthn pre-stub —
    //! Kratos seeds `credentials.webauthn.identifiers` with the user's
    //! email on every password identity, and the old `identifiers.is_empty()`
    //! check flipped the badge on for users who never actually enrolled.
    use super::creds_indicate_second_factor;
    use ory_client::models::IdentityCredentials;
    use std::collections::HashMap;

    fn empty_cred() -> IdentityCredentials {
        IdentityCredentials::new()
    }

    /// `webauthn` pre-stub: Kratos seeds the `identifiers` field with
    /// the user's email even when no authenticator has been registered.
    /// The `config.credentials` array is the real signal — if it's empty
    /// (or `config` is just `{ "user_handle": "..." }`), 2FA is OFF.
    fn webauthn_pre_stub() -> IdentityCredentials {
        let mut c = IdentityCredentials::new();
        c.identifiers = Some(vec!["user@example.com".to_string()]);
        c.config = Some(serde_json::json!({ "user_handle": "abc=" }));
        c
    }

    /// `webauthn` with an actual attested credential — `config.credentials`
    /// is a non-empty array.
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
}
