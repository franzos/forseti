//! Identity and session types.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

use crate::flow_view::Flow;

/// Authenticator assurance level; serialises as `aal0` .. `aal3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Aal {
    #[serde(rename = "aal0")]
    Aal0,
    #[serde(rename = "aal1")]
    Aal1,
    #[serde(rename = "aal2")]
    Aal2,
    #[serde(rename = "aal3")]
    Aal3,
}

impl Aal {
    pub fn as_str(self) -> &'static str {
        match self {
            Aal::Aal0 => "aal0",
            Aal::Aal1 => "aal1",
            Aal::Aal2 => "aal2",
            Aal::Aal3 => "aal3",
        }
    }
}

impl std::fmt::Display for Aal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identity state; serialises as `active` / `inactive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum IdentityState {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
}

/// One completed authentication step of a session. Field order and
/// `skip_serializing_if` are part of the account export format.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct AuthMethod {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aal: Option<Aal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Wire name of the method (`password`, `oidc`, `totp`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_amr: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SessionDevice {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub location: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Session {
    pub id: String,
    pub active: Option<bool>,
    pub issued_at: Option<String>,
    pub authenticated_at: Option<String>,
    pub expires_at: Option<String>,
    pub authenticator_assurance_level: Option<Aal>,
    pub authentication_methods: Option<Vec<AuthMethod>>,
    pub devices: Option<Vec<SessionDevice>>,
    pub identity: Option<Box<Identity>>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VerifiableAddress {
    pub id: Option<String>,
    pub value: String,
    /// `email` or `sms`.
    pub via: String,
    pub status: String,
    pub verified: bool,
    pub verified_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RecoveryAddress {
    pub id: Option<String>,
    pub value: String,
    pub via: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Credential {
    pub identifiers: Option<Vec<String>>,
    pub config: Option<Value>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub version: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Identity {
    pub id: String,
    pub schema_id: String,
    pub traits: Option<Value>,
    pub state: Option<IdentityState>,
    pub state_changed_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub external_id: Option<String>,
    pub organization_id: Option<String>,
    pub metadata_public: Option<Value>,
    pub metadata_admin: Option<Value>,
    pub verifiable_addresses: Option<Vec<VerifiableAddress>>,
    pub recovery_addresses: Option<Vec<RecoveryAddress>>,
    /// Keyed by credential type (`password`, `oidc`, ...).
    pub credentials: Option<HashMap<String, Credential>>,
}

/// One-shot admin-minted recovery code and the link that redeems it.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryCode {
    pub recovery_code: String,
    pub recovery_link: String,
}

/// Courier message status the admin status page counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CourierStatus {
    Queued,
    Abandoned,
}

/// A self-service error the `/error?id=` page explains.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SelfServiceError {
    pub id: Option<String>,
    /// The backend's own localized error text.
    pub message: Option<String>,
    pub reason: Option<String>,
}

/// Optional parameters for starting a browser self-service flow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowInit<'a> {
    /// Where the browser lands after the flow; ignored when empty.
    pub return_to: Option<&'a str>,
    /// Requested authenticator assurance level (login step-up); ignored when empty.
    pub aal: Option<&'a str>,
    /// Force re-authentication of an existing session.
    pub refresh: bool,
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

/// Why a privileged-session error was raised on a settings flow, parsed from Kratos's `error.id`.
/// Both resolve to a `/login` redirect with different params (`aal=aal2` vs `refresh=true`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedReason {
    /// `session_refresh_required`: session older than `privileged_session_max_age`.
    SessionRefresh,
    /// `session_aal2_required`: settings group needs AAL2 but the session is AAL1.
    Aal2Required,
}

/// Outcome of fetching a Kratos self-service flow, surfacing 404/410 (missing/expired) and the settings-flow
/// 403 as plain variants. The flow is projected from raw JSON by `ory::flow_json::project`, not the typed
/// `LoginFlow`/etc, because the SDK's `UiNodeAttributes` deserializer is broken for the real Kratos wire
/// shape (see `get_flow`).
pub enum FlowFetch {
    Ok(Box<Flow>),
    /// The flow ID is unknown or expired; restart the flow.
    Gone,
    /// Settings-flow 403; the variant says whether to redirect with `refresh=true` or `aal=aal2`.
    PrivilegedRequired(PrivilegedReason),
}

/// Classified result of resolving a self-service flow from the request's
/// `?flow=` id. Lets the four self-service handlers (login, registration,
/// recovery, verification) and the settings sub-page gate share the
/// fetch + 404/410/403 mapping while each keeps its own redirects: callers
/// build the (CSRF-attaching, param-carrying, settings-specific) responses
/// themselves, which differ enough that folding them in here would change
/// behaviour (e.g. login attaches a CSRF cookie on `Init` but not `Reinit`).
pub enum FlowOutcome {
    /// No flow id present: start a fresh browser flow.
    Init,
    /// Flow fetched; render it.
    Ready(Box<Flow>),
    /// Flow unknown/expired (404/410): re-init the browser flow.
    Reinit,
    /// Settings-flow 403: privileged step-up required (see [`PrivilegedReason`]).
    Privileged(PrivilegedReason),
    /// Transport/upstream failure: render an error boundary.
    Error(anyhow::Error),
}

/// Outcome of resolving the current session. Keeps "no session" and "session below required AAL" distinct
/// so callers route the step-up case to `/login?aal=aal2`; collapsing both livelocks AAL2-enrolled users.
#[derive(Clone, Debug)]
pub enum WhoamiOutcome {
    /// No session at all; send to /login.
    None,
    /// Session exists but doesn't satisfy the required AAL; send to `/login?aal=aal2&return_to=...`.
    InsufficientAal,
    /// Valid session satisfying the whoami AAL requirement.
    Ok(Box<Session>),
}

/// True iff `email` matches a `verified` entry of `addrs` (ASCII
/// case-insensitive). `None`/empty addresses are never verified.
pub(crate) fn address_is_verified(addrs: Option<&[VerifiableAddress]>, email: &str) -> bool {
    if email.is_empty() {
        return false;
    }
    addrs.is_some_and(|addrs| {
        addrs
            .iter()
            .any(|a| a.value.eq_ignore_ascii_case(email) && a.verified)
    })
}

/// True when `metadata` is an object carrying a non-null `key`.
pub(crate) fn metadata_has_key(metadata: Option<&Value>, key: &str) -> bool {
    metadata
        .and_then(|m| m.get(key))
        .is_some_and(|v| !v.is_null())
}

impl Identity {
    /// The identity's verifiable addresses, for [`address_is_verified`].
    pub(crate) fn addresses(&self) -> Option<&[VerifiableAddress]> {
        self.verifiable_addresses.as_deref()
    }

    /// True when `metadata_admin` carries a non-null `key`, the same rule consent
    /// applies when copying claims.
    pub(crate) fn metadata_admin_has_key(&self, key: &str) -> bool {
        metadata_has_key(self.metadata_admin.as_ref(), key)
    }
}

impl Session {
    /// The display email from the identity traits; empty when the trait or
    /// identity is missing.
    pub(crate) fn email(&self) -> String {
        self.identity
            .as_ref()
            .and_then(|id| id.traits.as_ref())
            .and_then(|t| t.get("email"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    /// The (identity_id, email) pair; both default to empty strings.
    pub(crate) fn principal(&self) -> (String, String) {
        let identity_id = self
            .identity
            .as_ref()
            .map(|id| id.id.clone())
            .unwrap_or_default();
        (identity_id, self.email())
    }

    /// Identity created within the last hour: a sign-up that is still in its
    /// first visit, greeted rather than welcomed "back" and offered a handle.
    pub(crate) fn is_new_account(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.identity
            .as_ref()
            .and_then(|i| i.created_at.as_deref())
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .is_some_and(|created| now.signed_duration_since(created) < chrono::Duration::hours(1))
    }

    /// True when the identity has at least one verifiable address still
    /// pending verification; drives the dashboard verify banner.
    pub(crate) fn needs_verification(&self) -> bool {
        self.identity
            .as_ref()
            .and_then(|id| id.verifiable_addresses.as_ref())
            .is_some_and(|addrs| addrs.iter().any(|a| !a.verified))
    }

    /// The session identity's verifiable addresses, for [`address_is_verified`].
    pub(crate) fn addresses(&self) -> Option<&[VerifiableAddress]> {
        self.identity.as_ref().and_then(|i| i.addresses())
    }

    /// `true` iff the AAL is `aal2`; a missing AAL is treated as AAL1 (fails closed).
    pub(crate) fn satisfies_aal2(&self) -> bool {
        matches!(self.authenticator_assurance_level, Some(Aal::Aal2))
    }

    /// The AAL as a string, defaulting to `"aal1"` when omitted (fails closed). Use when comparing
    /// against a requested `aal`; prefer [`Session::satisfies_aal2`] for a plain check.
    pub(crate) fn aal_string(&self) -> String {
        self.authenticator_assurance_level
            .map_or_else(|| "aal1".to_string(), |aal| aal.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_created(at: &str) -> Session {
        let identity = Identity {
            id: "id".into(),
            schema_id: "default".into(),
            created_at: Some(at.into()),
            ..Default::default()
        };
        Session {
            id: "sid".into(),
            identity: Some(Box::new(identity)),
            ..Default::default()
        }
    }

    #[test]
    fn greets_an_account_created_in_the_last_hour() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(session_created("2026-09-29T11:30:00Z").is_new_account(now));
        assert!(!session_created("2026-09-29T10:00:00Z").is_new_account(now));
    }
}
