//! Hydra SDK model to domain type conversions. OAuth clients convert both ways
//! through JSON, with unnamed fields carried in `OAuthClient::extra`. OAuth
//! requests and consent sessions convert one way; Hydra accept/reject bodies
//! are built from SDK models in `hydra`.

use ory_client::models as sdk;

use crate::backend::oauth::{
    ConsentRequest, ConsentSession, LoginRequest, LogoutRequest, OAuthClient, OidcContext,
    RedirectTo,
};

pub(super) fn client_from_sdk(c: sdk::OAuth2Client) -> anyhow::Result<OAuthClient> {
    serde_json::from_value(serde_json::to_value(c)?)
        .map_err(|e| anyhow::anyhow!("oauth client from sdk: {e}"))
}

pub(super) fn client_to_sdk(c: OAuthClient) -> anyhow::Result<sdk::OAuth2Client> {
    serde_json::from_value(serde_json::to_value(c)?)
        .map_err(|e| anyhow::anyhow!("oauth client to sdk: {e}"))
}

impl From<sdk::OAuth2ConsentRequestOpenIdConnectContext> for OidcContext {
    fn from(c: sdk::OAuth2ConsentRequestOpenIdConnectContext) -> Self {
        OidcContext {
            acr_values: c.acr_values,
            login_hint: c.login_hint,
            ui_locales: c.ui_locales,
        }
    }
}

impl From<sdk::OAuth2RedirectTo> for RedirectTo {
    fn from(r: sdk::OAuth2RedirectTo) -> Self {
        RedirectTo {
            redirect_to: r.redirect_to,
        }
    }
}

pub(super) fn login_request_from_sdk(r: sdk::OAuth2LoginRequest) -> anyhow::Result<LoginRequest> {
    Ok(LoginRequest {
        client: client_from_sdk(*r.client)?,
        oidc_context: r.oidc_context.map(|c| OidcContext::from(*c)),
        request_url: r.request_url,
        requested_scope: r.requested_scope,
        session_id: r.session_id,
        skip: r.skip,
        subject: r.subject,
    })
}

pub(super) fn consent_request_from_sdk(
    r: sdk::OAuth2ConsentRequest,
) -> anyhow::Result<ConsentRequest> {
    Ok(ConsentRequest {
        client: r.client.map(|c| client_from_sdk(*c)).transpose()?,
        consent_request_id: r.consent_request_id,
        login_session_id: r.login_session_id,
        oidc_context: r.oidc_context.map(|c| OidcContext::from(*c)),
        request_url: r.request_url,
        requested_access_token_audience: r.requested_access_token_audience,
        requested_scope: r.requested_scope,
        skip: r.skip,
        subject: r.subject,
    })
}

pub(super) fn logout_request_from_sdk(
    r: sdk::OAuth2LogoutRequest,
) -> anyhow::Result<LogoutRequest> {
    Ok(LogoutRequest {
        client: r.client.map(|c| client_from_sdk(*c)).transpose()?,
        rp_initiated: r.rp_initiated,
        sid: r.sid,
        subject: r.subject,
    })
}

pub(super) fn consent_session_from_sdk(
    s: sdk::OAuth2ConsentSession,
) -> anyhow::Result<ConsentSession> {
    Ok(ConsentSession {
        consent_request: s
            .consent_request
            .map(|r| consent_request_from_sdk(*r))
            .transpose()?,
        consent_request_id: s.consent_request_id,
        grant_access_token_audience: s.grant_access_token_audience,
        grant_scope: s.grant_scope,
        handled_at: s.handled_at,
        remember: s.remember,
        remember_for: s.remember_for,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_sdk_client() -> sdk::OAuth2Client {
        let s = |v: &str| Some(v.to_string());
        let list = |v: &[&str]| Some(v.iter().map(|x| (*x).to_string()).collect::<Vec<_>>());
        let mut key =
            sdk::JsonWebKey::new("RS256".into(), "kid-1".into(), "RSA".into(), "sig".into());
        key.crv = s("P-256");
        key.d = s("d");
        key.dp = s("dp");
        key.dq = s("dq");
        key.e = s("AQAB");
        key.k = s("k");
        key.n = s("n");
        key.p = s("p");
        key.q = s("q");
        key.qi = s("qi");
        key.x = s("x");
        key.x5c = list(&["cert"]);
        key.y = s("y");
        sdk::OAuth2Client {
            access_token_strategy: s("jwt"),
            allowed_cors_origins: list(&["https://cors.example"]),
            audience: list(&["https://api.example"]),
            authorization_code_grant_access_token_lifespan: Some(None),
            authorization_code_grant_id_token_lifespan: Some(s("1h")),
            authorization_code_grant_refresh_token_lifespan: Some(s("720h")),
            backchannel_logout_session_required: Some(true),
            backchannel_logout_uri: s("https://app.example/bcl"),
            client_credentials_grant_access_token_lifespan: Some(None),
            client_id: s("client-1"),
            client_name: s("App"),
            client_secret: s("secret"),
            client_secret_expires_at: Some(1_900_000_000),
            client_uri: s("https://app.example"),
            contacts: list(&["ops@app.example"]),
            created_at: s("2026-01-01T00:00:00Z"),
            device_authorization_grant_access_token_lifespan: Some(s("2h")),
            device_authorization_grant_id_token_lifespan: Some(None),
            device_authorization_grant_refresh_token_lifespan: Some(s("3h")),
            frontchannel_logout_session_required: Some(true),
            frontchannel_logout_uri: s("https://app.example/fcl"),
            grant_types: list(&["authorization_code", "refresh_token"]),
            implicit_grant_access_token_lifespan: Some(s("4h")),
            implicit_grant_id_token_lifespan: Some(None),
            jwks: Some(Box::new(sdk::JsonWebKeySet {
                keys: Some(vec![key]),
            })),
            jwks_uri: s("https://app.example/jwks.json"),
            jwt_bearer_grant_access_token_lifespan: Some(s("5h")),
            logo_uri: s("https://app.example/logo.png"),
            metadata: Some(json!({"forseti": {"client_type": "web_app", "require_pkce": true}})),
            owner: s("owner"),
            policy_uri: s("https://app.example/policy"),
            post_logout_redirect_uris: list(&["https://app.example/bye"]),
            redirect_uris: list(&["https://app.example/cb"]),
            refresh_token_grant_access_token_lifespan: Some(None),
            refresh_token_grant_id_token_lifespan: Some(s("6h")),
            refresh_token_grant_refresh_token_lifespan: Some(s("7h")),
            registration_access_token: s("rat"),
            registration_client_uri: s("https://hydra.example/oauth2/register/client-1"),
            request_object_signing_alg: s("RS256"),
            request_uris: list(&["https://app.example/req"]),
            response_types: list(&["code"]),
            scope: s("openid offline_access"),
            sector_identifier_uri: s("https://app.example/sector.json"),
            skip_consent: Some(true),
            skip_logout_consent: Some(true),
            subject_type: s("public"),
            token_endpoint_auth_method: s("client_secret_basic"),
            token_endpoint_auth_signing_alg: s("RS256"),
            tos_uri: s("https://app.example/tos"),
            updated_at: s("2026-02-01T00:00:00Z"),
            userinfo_signed_response_alg: s("none"),
        }
    }

    #[test]
    fn oauth_client_round_trips_through_the_sdk() {
        for x in [full_sdk_client(), sdk::OAuth2Client::new()] {
            let back = client_to_sdk(client_from_sdk(x.clone()).unwrap()).unwrap();
            assert_eq!(back, x);
            assert_eq!(
                serde_json::to_value(&back).unwrap(),
                serde_json::to_value(&x).unwrap()
            );
        }
        assert_eq!(
            serde_json::to_value(client_from_sdk(sdk::OAuth2Client::new()).unwrap()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn oauth_client_names_app_fields_and_carries_the_rest() {
        let x = full_sdk_client();
        let mut d = client_from_sdk(x.clone()).unwrap();
        assert_eq!(d.client_name, x.client_name);
        assert_eq!(d.metadata, x.metadata);
        assert_eq!(
            d.extra["authorization_code_grant_access_token_lifespan"],
            serde_json::Value::Null
        );
        assert_eq!(d.extra["jwks"], json!(x.jwks));
        let mut extra: Vec<&str> = d.extra.keys().map(String::as_str).collect();
        extra.sort_unstable();
        assert_eq!(
            extra,
            [
                "access_token_strategy",
                "allowed_cors_origins",
                "authorization_code_grant_access_token_lifespan",
                "authorization_code_grant_id_token_lifespan",
                "authorization_code_grant_refresh_token_lifespan",
                "client_credentials_grant_access_token_lifespan",
                "client_secret_expires_at",
                "contacts",
                "device_authorization_grant_access_token_lifespan",
                "device_authorization_grant_id_token_lifespan",
                "device_authorization_grant_refresh_token_lifespan",
                "implicit_grant_access_token_lifespan",
                "implicit_grant_id_token_lifespan",
                "jwks",
                "jwks_uri",
                "jwt_bearer_grant_access_token_lifespan",
                "owner",
                "policy_uri",
                "refresh_token_grant_access_token_lifespan",
                "refresh_token_grant_id_token_lifespan",
                "refresh_token_grant_refresh_token_lifespan",
                "registration_client_uri",
                "request_object_signing_alg",
                "request_uris",
                "sector_identifier_uri",
                "skip_logout_consent",
                "subject_type",
                "token_endpoint_auth_signing_alg",
                "tos_uri",
                "updated_at",
                "userinfo_signed_response_alg",
            ]
        );

        d.client_name = Some("Renamed".to_string());
        d.backchannel_logout_uri = None;
        let back = client_to_sdk(d).unwrap();
        let mut expected = x;
        expected.client_name = Some("Renamed".to_string());
        expected.backchannel_logout_uri = None;
        assert_eq!(back, expected);
    }

    #[test]
    fn consent_session_carries_its_request_and_client() {
        let mut ctx = sdk::OAuth2ConsentRequestOpenIdConnectContext::new();
        ctx.ui_locales = Some(vec!["de".to_string()]);
        let mut req = sdk::OAuth2ConsentRequest::new("challenge".to_string());
        req.client = Some(Box::new(full_sdk_client()));
        req.login_session_id = Some("sid".to_string());
        req.oidc_context = Some(Box::new(ctx));
        let mut s = sdk::OAuth2ConsentSession::new();
        s.consent_request = Some(Box::new(req));
        s.consent_request_id = Some("crid".to_string());
        s.remember_for = Some(0);
        let d = consent_session_from_sdk(s).unwrap();
        let r = d.consent_request.unwrap();
        assert_eq!(r.client, Some(client_from_sdk(full_sdk_client()).unwrap()));
        assert_eq!(r.login_session_id.as_deref(), Some("sid"));
        assert_eq!(
            r.oidc_context.unwrap().ui_locales,
            Some(vec!["de".to_string()])
        );
        assert_eq!(d.consent_request_id.as_deref(), Some("crid"));
        assert_eq!(d.remember_for, Some(0));
        assert_eq!(
            consent_session_from_sdk(sdk::OAuth2ConsentSession::new()).unwrap(),
            ConsentSession::default()
        );
    }
}
