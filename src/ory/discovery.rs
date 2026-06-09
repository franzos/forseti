//! Hydra's OIDC discovery document (`/.well-known/openid-configuration`).

use anyhow::Result;
use serde::Deserialize;

use super::OryClients;

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

/// Fetch Hydra's discovery doc over its public base URL.
///
/// Written to match `probe_health` / `list_consent_sessions_by_subject` in
/// this module: the SDK's `reqwest` is the renamed `ory_reqwest` 0.12 dep,
/// so we capture the response and check `.status()` rather than chaining
/// `.error_for_status()` (which would cross the 0.12/0.13 type boundary).
pub async fn fetch(clients: &OryClients, public_url: &str) -> Result<OidcDiscovery> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        public_url.trim_end_matches('/')
    );
    let resp = clients
        .hydra_public
        .client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("hydra discovery transport: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("hydra discovery returned {status}: {body}"));
    }
    resp.json::<OidcDiscovery>()
        .await
        .map_err(|e| anyhow::anyhow!("hydra discovery decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_partial_doc() {
        let json = r#"{"issuer":"https://i","token_endpoint":"https://i/oauth2/token"}"#;
        let d: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert_eq!(d.issuer, "https://i");
        assert_eq!(d.userinfo_endpoint, ""); // missing → default
    }

    #[test]
    fn default_doc_is_all_empty() {
        let d = OidcDiscovery::default();
        assert!(d.issuer.is_empty() && d.token_endpoint.is_empty());
        assert!(d.scopes_supported.is_empty());
        assert!(!d.backchannel_logout_supported);
    }

    #[test]
    fn deserializes_capability_fields() {
        let json = r#"{
            "issuer":"https://i",
            "scopes_supported":["openid","offline","email"],
            "grant_types_supported":["authorization_code","refresh_token"],
            "response_types_supported":["code"],
            "token_endpoint_auth_methods_supported":["client_secret_basic","none"],
            "code_challenge_methods_supported":["S256"],
            "id_token_signing_alg_values_supported":["RS256"],
            "subject_types_supported":["public"],
            "registration_endpoint":"https://i/oauth2/register",
            "revocation_endpoint":"https://i/oauth2/revoke",
            "backchannel_logout_supported":true,
            "frontchannel_logout_supported":true
        }"#;
        let d: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert_eq!(d.scopes_supported, ["openid", "offline", "email"]);
        assert_eq!(d.code_challenge_methods_supported, ["S256"]);
        assert_eq!(d.registration_endpoint, "https://i/oauth2/register");
        assert_eq!(d.revocation_endpoint, "https://i/oauth2/revoke");
        assert!(d.backchannel_logout_supported);
        assert!(d.frontchannel_logout_supported);
    }

    #[test]
    fn capability_fields_default_when_missing() {
        let json = r#"{"issuer":"https://i"}"#;
        let d: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert!(d.grant_types_supported.is_empty());
        assert!(d.subject_types_supported.is_empty());
        assert!(d.registration_endpoint.is_empty());
        assert!(!d.frontchannel_logout_supported);
    }
}
