//! OAuth client, request, session and discovery types.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// An OAuth 2.0 client registration. Field names and JSON shape follow the
/// Hydra admin API.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OAuthClient {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_consent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// Every other client field, kept verbatim (explicit `null`s included) so
    /// a get-then-put round trip leaves it unchanged.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The OIDC parameters of an authorization request.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OidcContext {
    pub acr_values: Option<Vec<String>>,
    pub login_hint: Option<String>,
    pub ui_locales: Option<Vec<String>>,
}

/// A pending login challenge.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LoginRequest {
    pub client: OAuthClient,
    pub oidc_context: Option<OidcContext>,
    /// The authorization request URL as the client sent it.
    pub request_url: String,
    pub requested_scope: Option<Vec<String>>,
    /// The OP login session (`sid`).
    pub session_id: Option<String>,
    /// The subject is remembered and needs no authentication.
    pub skip: bool,
    pub subject: String,
}

/// A pending consent challenge, or the request a consent session was granted on.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConsentRequest {
    pub client: Option<OAuthClient>,
    pub consent_request_id: Option<String>,
    pub login_session_id: Option<String>,
    pub oidc_context: Option<OidcContext>,
    pub request_url: Option<String>,
    pub requested_access_token_audience: Option<Vec<String>>,
    pub requested_scope: Option<Vec<String>>,
    /// A remembered consent covers the request.
    pub skip: Option<bool>,
    pub subject: Option<String>,
}

/// A pending logout challenge.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogoutRequest {
    pub client: Option<OAuthClient>,
    pub rp_initiated: Option<bool>,
    pub sid: Option<String>,
    pub subject: Option<String>,
}

/// A granted consent.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConsentSession {
    pub consent_request: Option<ConsentRequest>,
    pub consent_request_id: Option<String>,
    pub grant_access_token_audience: Option<Vec<String>>,
    pub grant_scope: Option<Vec<String>>,
    pub handled_at: Option<String>,
    pub remember: Option<bool>,
    pub remember_for: Option<i64>,
}

/// Where to send the browser after a challenge is accepted or rejected.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RedirectTo {
    pub redirect_to: String,
}

/// Projected device-authz response (RFC 8628 §3.2). All fields are
/// required on a real Hydra response; we surface concrete types so the
/// device endpoints don't carry `Option`s the protocol guarantees.
#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    /// Minimum poll interval Hydra asks for; RFC 8628 default 5s.
    pub interval: i64,
}

/// The token set returned once a device flow is approved. `id_token` is
/// always present for the `openid` scope; the access token is carried for
/// completeness but the device path validates-and-discards the id_token
/// and never persists either (R3 / R10).
#[derive(Debug, Clone)]
pub struct TokenSet {
    // Carried for protocol completeness; the device path binds on `id_token`
    // only and never introspects (R10), so these two are intentionally unread.
    #[allow(dead_code)]
    pub access_token: String,
    pub id_token: Option<String>,
    #[allow(dead_code)]
    pub expires_in: i64,
}

/// Outcome of one device-code token poll (RFC 8628 §3.5). The error
/// strings Hydra returns at `/oauth2/token` map onto these so callers
/// pattern-match instead of string-sniffing.
#[derive(Debug, Clone)]
pub enum DeviceTokenOutcome {
    /// `authorization_pending`: keep polling at the current interval.
    Pending,
    /// `slow_down`: Hydra wants a longer interval; back off (+5s per RFC).
    SlowDown,
    /// Approved: the token set is ready.
    Token(Box<TokenSet>),
    /// `expired_token`: the device_code is dead; restart the flow.
    Expired,
    /// `access_denied`: the user rejected the request.
    Denied,
}

/// The subset of OIDC id_token claims the device path binds against. The
/// token is validated then discarded; these are read once at poll time and never persisted (R3).
#[derive(Debug, Clone)]
pub struct IdTokenClaims {
    pub sub: String,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    /// Hydra stamps this when Forseti accepts the login request, so it is
    /// not a freshness signal for the PAM `force_mfa` window — that reads
    /// the second factor's `completed_at` off Kratos instead
    /// (`posix::device::newest_second_factor_at`).
    #[allow(dead_code)]
    pub auth_time: Option<i64>,
}

/// One row of the configuration page's JWKS table: the public signing keys Hydra advertises at its `jwks_uri`.
pub struct JwkSummary {
    pub kid: String,
    pub alg: String,
    pub kty: String,
    pub use_: String,
}

/// The subset of OIDC discovery fields the admin UI surfaces.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OidcDiscovery {
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: String,
    #[serde(default)]
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: String,
    #[serde(default)]
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    #[serde(default)]
    pub registration_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: String,
    #[serde(default)]
    pub backchannel_logout_supported: bool,
    #[serde(default)]
    pub frontchannel_logout_supported: bool,
}
