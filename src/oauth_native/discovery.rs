//! The OpenID Provider / RFC 8414 metadata document, served at both well-known paths.

use forseti_common::{SUPPORTED_CLAIMS, SUPPORTED_SCOPES};
use serde_json::{Value, json};

use super::authorize::AUTHORIZE_PATH;
use super::device::{DEVICE_AUTHORIZATION_PATH, DEVICE_CODE_GRANT};
use super::keys::ALG;
use super::logout::LOGOUT_PATH;

/// Scopes the token endpoint understands on its own, ahead of the ones the ID token builder adds.
const BASE_SCOPES: [&str; 3] = ["offline_access", "offline", "openid"];

/// The document for `issuer` (no trailing slash). Lists only what this build serves.
pub(crate) fn document(issuer: &str, idp_provider_ids: &[String]) -> Value {
    let scopes: Vec<&str> = BASE_SCOPES
        .iter()
        .chain(&SUPPORTED_SCOPES)
        .copied()
        .collect();
    let mut doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}{AUTHORIZE_PATH}"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "device_authorization_endpoint": format!("{issuer}{DEVICE_AUTHORIZATION_PATH}"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "end_session_endpoint": format!("{issuer}{LOGOUT_PATH}"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "scopes_supported": scopes,
        "claims_supported": SUPPORTED_CLAIMS,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token", DEVICE_CODE_GRANT],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALG],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "prompt_values_supported": ["none", "login", "consent", "create"],
        "acr_values_supported": ["aal1", "aal2"],
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": true,
    });
    if let Some(hints) = crate::oidc_providers::idp_hints_supported(idp_provider_ids)
        && let Some(map) = doc.as_object_mut()
    {
        map.insert("idp_hints_supported".to_string(), hints);
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::OAuthBackend;
    use crate::config::AppConfig;
    use crate::oauth_native::NativeOAuth;

    const ISSUER: &str = "https://id.example.com";

    #[test]
    fn golden_document() {
        assert_eq!(
            document(ISSUER, &[]),
            json!({
                "issuer": "https://id.example.com",
                "authorization_endpoint": "https://id.example.com/oauth2/authorize",
                "token_endpoint": "https://id.example.com/oauth2/token",
                "revocation_endpoint": "https://id.example.com/oauth2/revoke",
                "device_authorization_endpoint": "https://id.example.com/oauth2/device/auth",
                "userinfo_endpoint": "https://id.example.com/userinfo",
                "end_session_endpoint": "https://id.example.com/oauth2/sessions/logout",
                "jwks_uri": "https://id.example.com/.well-known/jwks.json",
                "scopes_supported": [
                    "offline_access", "offline", "openid", "email", "profile", "org", "orgs",
                    "groups", "extended_profile"
                ],
                "claims_supported": [
                    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid",
                    "email", "email_verified", "name", "given_name", "family_name", "picture",
                    "website", "preferred_username", "locale", "updated_at", "org", "orgs",
                    "groups", "bio", "pronouns", "links"
                ],
                "response_types_supported": ["code"],
                "response_modes_supported": ["query", "form_post"],
                "grant_types_supported": [
                    "authorization_code", "refresh_token",
                    "urn:ietf:params:oauth:grant-type:device_code"
                ],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": [
                    "none", "client_secret_basic", "client_secret_post"
                ],
                "code_challenge_methods_supported": ["S256"],
                "request_parameter_supported": false,
                "request_uri_parameter_supported": false,
                "backchannel_logout_supported": true,
                "backchannel_logout_session_supported": true,
                "prompt_values_supported": ["none", "login", "consent", "create"],
                "acr_values_supported": ["aal1", "aal2"],
                "authorization_response_iss_parameter_supported": true,
                "client_id_metadata_document_supported": true,
            })
        );
    }

    #[test]
    fn advertises_only_served_endpoints() {
        let doc = document(ISSUER, &["github".to_string()]);
        let doc = doc.as_object().unwrap();
        let served = [
            "authorization_endpoint",
            "token_endpoint",
            "revocation_endpoint",
            "device_authorization_endpoint",
            "userinfo_endpoint",
            "end_session_endpoint",
            "jwks_uri",
        ];
        for key in doc.keys() {
            if key.ends_with("_endpoint") || key.ends_with("_uri") {
                assert!(served.contains(&key.as_str()), "{key} is not served");
            }
        }
        for key in served {
            assert!(doc.contains_key(key), "{key}");
        }
        for key in [
            "introspection_endpoint",
            "registration_endpoint",
            "frontchannel_logout_supported",
            "frontchannel_logout_session_supported",
            "check_session_iframe",
        ] {
            assert!(!doc.contains_key(key), "{key}");
        }
        assert_eq!(doc["backchannel_logout_supported"], true);
        assert_eq!(doc["backchannel_logout_session_supported"], true);
        assert_eq!(doc["client_id_metadata_document_supported"], true);
        assert!(
            doc["grant_types_supported"]
                .as_array()
                .unwrap()
                .contains(&json!(DEVICE_CODE_GRANT))
        );
    }

    #[tokio::test]
    async fn trailing_slash_in_self_url_yields_the_same_document() {
        let db = crate::db::test_pool().await;
        let mut docs = Vec::new();
        for url in [ISSUER, "https://id.example.com/"] {
            let mut cfg = AppConfig::test_fixture();
            cfg.self_.url = url.to_string();
            let (_, raw) = NativeOAuth::new(&cfg, &db, &[0x42; 32])
                .fetch_discovery()
                .await
                .unwrap();
            docs.push(raw);
        }
        assert_eq!(docs[0], docs[1]);
        assert_eq!(docs[0], document(ISSUER, &[]));
    }

    #[test]
    fn lists_idp_hints_as_the_ory_build_does() {
        let ids = ["github".to_string(), "playground".to_string()];
        let out = document(ISSUER, &ids);
        assert_eq!(
            out["idp_hints_supported"],
            json!([
                { "id": "github", "name": "GitHub" },
                { "id": "playground", "name": "Playground" },
            ])
        );
        let mut with = out.as_object().unwrap().clone();
        with.remove("idp_hints_supported");
        assert_eq!(&with, document(ISSUER, &[]).as_object().unwrap());
    }
}
