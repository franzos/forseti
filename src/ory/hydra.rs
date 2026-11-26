//! Hydra admin and public API calls over plain HTTP.
//!
//! Responses deserialize into `crate::backend::oauth` types; request bodies
//! are private wire structs. Paths, methods and query names follow Hydra's
//! OpenAPI spec (`/admin/...` on the admin endpoint, `/oauth2/...` and
//! `/.well-known/...` on the public one). Failures read
//! `hydra <operation> failed: error in <reqwest|serde|response>: ...`.

use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::*;
use crate::backend::oauth::JwkSummary;
use crate::backend::oauth::{
    ConsentRequest, ConsentSession, LoginRequest, LogoutRequest, OAuthClient, RedirectTo,
};
use crate::web::urlencode;

fn decode<T: DeserializeOwned>(v: Value) -> Result<T, CallError> {
    serde_json::from_value(v).map_err(|e| CallError::Decode(e.to_string()))
}

// --- OAuth client wire shape ---------------------------------------------

/// Every OAuth2 client field in Hydra's OpenAPI spec, sorted.
const CLIENT_FIELDS: &[&str] = &[
    "access_token_strategy",
    "allowed_cors_origins",
    "audience",
    "authorization_code_grant_access_token_lifespan",
    "authorization_code_grant_id_token_lifespan",
    "authorization_code_grant_refresh_token_lifespan",
    "backchannel_logout_session_required",
    "backchannel_logout_uri",
    "client_credentials_grant_access_token_lifespan",
    "client_id",
    "client_name",
    "client_secret",
    "client_secret_expires_at",
    "client_uri",
    "contacts",
    "created_at",
    "device_authorization_grant_access_token_lifespan",
    "device_authorization_grant_id_token_lifespan",
    "device_authorization_grant_refresh_token_lifespan",
    "frontchannel_logout_session_required",
    "frontchannel_logout_uri",
    "grant_types",
    "implicit_grant_access_token_lifespan",
    "implicit_grant_id_token_lifespan",
    "jwks",
    "jwks_uri",
    "jwt_bearer_grant_access_token_lifespan",
    "logo_uri",
    "metadata",
    "owner",
    "policy_uri",
    "post_logout_redirect_uris",
    "redirect_uris",
    "refresh_token_grant_access_token_lifespan",
    "refresh_token_grant_id_token_lifespan",
    "refresh_token_grant_refresh_token_lifespan",
    "registration_access_token",
    "registration_client_uri",
    "request_object_signing_alg",
    "request_uris",
    "response_types",
    "scope",
    "sector_identifier_uri",
    "skip_consent",
    "skip_logout_consent",
    "subject_type",
    "token_endpoint_auth_method",
    "token_endpoint_auth_signing_alg",
    "tos_uri",
    "updated_at",
    "userinfo_signed_response_alg",
];

/// The client fields the spec marks nullable: an explicit `null` survives, on every other field it is dropped.
const CLIENT_NULLABLE_FIELDS: &[&str] = &[
    "authorization_code_grant_access_token_lifespan",
    "authorization_code_grant_id_token_lifespan",
    "authorization_code_grant_refresh_token_lifespan",
    "client_credentials_grant_access_token_lifespan",
    "device_authorization_grant_access_token_lifespan",
    "device_authorization_grant_id_token_lifespan",
    "device_authorization_grant_refresh_token_lifespan",
    "implicit_grant_access_token_lifespan",
    "implicit_grant_id_token_lifespan",
    "jwt_bearer_grant_access_token_lifespan",
    "refresh_token_grant_access_token_lifespan",
    "refresh_token_grant_id_token_lifespan",
    "refresh_token_grant_refresh_token_lifespan",
];

/// JSON Web Key fields in Hydra's OpenAPI spec, sorted.
const JWK_FIELDS: &[&str] = &[
    "alg", "crv", "d", "dp", "dq", "e", "k", "kid", "kty", "n", "p", "q", "qi", "use", "x", "x5c",
    "y",
];

/// Keep only `fields` (in that order) and drop `null`s outside `nullable`.
fn retain_fields(map: &mut Map<String, Value>, fields: &[&str], nullable: &[&str]) {
    let mut src = std::mem::take(map);
    for &k in fields {
        if let Some(v) = src.remove(k)
            && (!v.is_null() || nullable.contains(&k))
        {
            map.insert(k.to_string(), v);
        }
    }
}

/// Reduce a client object to the spec's fields, so a get-then-put round
/// trip sends Hydra only fields it documents and `null` only where it is
/// meaningful. Applied to every client read and written.
fn wire_client(v: &mut Value) {
    let Value::Object(map) = v else { return };
    retain_fields(map, CLIENT_FIELDS, CLIENT_NULLABLE_FIELDS);
    if let Some(Value::Object(jwks)) = map.get_mut("jwks") {
        let keys = jwks.remove("keys");
        jwks.clear();
        if let Some(mut keys) = keys.filter(|k| !k.is_null()) {
            if let Value::Array(items) = &mut keys {
                for key in items {
                    if let Value::Object(key) = key {
                        retain_fields(key, JWK_FIELDS, &[]);
                    }
                }
            }
            jwks.insert("keys".to_string(), keys);
        }
    }
}

/// [`wire_client`] on the `client` of a login/consent/logout request, and
/// on the request inside a consent session.
fn wire_nested_clients(v: &mut Value) {
    match v {
        Value::Array(items) => items.iter_mut().for_each(wire_nested_clients),
        Value::Object(map) => {
            if let Some(c) = map.get_mut("client") {
                wire_client(c);
            }
            if let Some(r) = map.get_mut("consent_request") {
                wire_nested_clients(r);
            }
        }
        _ => {}
    }
}

fn client_from_wire(mut v: Value) -> Result<OAuthClient, CallError> {
    wire_client(&mut v);
    decode(v)
}

fn client_to_wire(c: OAuthClient) -> Result<Value> {
    let mut v = serde_json::to_value(c)?;
    wire_client(&mut v);
    Ok(v)
}

fn with_nested_clients<T: DeserializeOwned>(mut v: Value) -> Result<T, CallError> {
    wire_nested_clients(&mut v);
    decode(v)
}

// --- Request bodies -----------------------------------------------------

#[derive(Serialize)]
struct AcceptLoginBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    amr: Vec<String>,
    remember: bool,
    remember_for: i64,
    subject: &'a str,
}

#[derive(Serialize)]
struct RejectBody<'a> {
    error: &'a str,
    error_description: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<i64>,
}

#[derive(Serialize)]
struct AcceptConsentBody {
    grant_access_token_audience: Vec<String>,
    grant_scope: Vec<String>,
    remember: bool,
    remember_for: i64,
    session: ConsentClaims,
}

/// Hydra's `session.access_token` / `session.id_token` claim payloads.
#[derive(Serialize)]
struct ConsentClaims {
    #[serde(skip_serializing_if = "Map::is_empty")]
    access_token: Map<String, Value>,
    id_token: Value,
}

#[derive(Serialize)]
struct AcceptUserCodeBody<'a> {
    user_code: &'a str,
}

/// One RFC 6902 operation.
#[derive(Serialize)]
struct JsonPatchOp {
    op: &'static str,
    path: &'static str,
    value: Value,
}

// --- Response bodies ----------------------------------------------------

#[derive(serde::Deserialize)]
struct VersionBody {
    version: String,
}

/// Hydra's JWKS. `alg`, `kid`, `kty` and `use` are required by its spec.
#[derive(serde::Deserialize)]
struct JsonWebKeySet {
    keys: Option<Vec<JsonWebKey>>,
}

#[derive(serde::Deserialize)]
struct JsonWebKey {
    alg: String,
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    use_: String,
    n: Option<String>,
    e: Option<String>,
}

pub struct HydraBackend {
    pub(super) clients: Arc<OryClients>,
}

// --- Login, consent, logout ---------------------------------------------

impl HydraBackend {
    pub(crate) fn from_config(cfg: &AppConfig) -> Arc<HydraBackend> {
        Arc::new(HydraBackend {
            clients: OryClients::from_config(cfg),
        })
    }

    pub async fn get_login_request(&self, challenge: &str) -> Result<LoginRequest> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::GET, "/admin/oauth2/auth/requests/login")
            .query(&[("login_challenge", challenge)]);
        send_json(req)
            .await
            .and_then(with_nested_clients)
            .map_err(|e| anyhow::anyhow!("hydra get_login_request failed: {e}"))
    }

    /// Accept a Hydra login challenge for a Kratos subject. `amr`/`acr` mirror the OIDC claims RPs see;
    /// `remember` extends Hydra's login session so subsequent SSO hits skip re-prompting Kratos, for
    /// `remember_for` seconds (`0` = Hydra's maximum duration).
    pub async fn accept_login_request(
        &self,
        challenge: &str,
        subject: &str,
        remember: bool,
        remember_for: i64,
        amr: Vec<String>,
        acr: Option<String>,
    ) -> Result<RedirectTo> {
        let body = AcceptLoginBody {
            acr,
            amr,
            remember,
            remember_for,
            subject,
        };
        let req = self
            .clients
            .hydra_admin
            .request(Method::PUT, "/admin/oauth2/auth/requests/login/accept")
            .query(&[("login_challenge", challenge)])
            .json(&body);
        send_json(req)
            .await
            .map_err(|e| anyhow::anyhow!("hydra accept_login_request failed: {e}"))
    }

    /// Reject a login challenge, sending the OAuth2 `error` / `error_description`
    /// back to the relying party (`login_required`, `interaction_required`, ...).
    pub async fn reject_login_request(
        &self,
        challenge: &str,
        error: &str,
        error_description: &str,
    ) -> Result<RedirectTo> {
        let body = RejectBody {
            error,
            error_description,
            status_code: None,
        };
        let req = self
            .clients
            .hydra_admin
            .request(Method::PUT, "/admin/oauth2/auth/requests/login/reject")
            .query(&[("login_challenge", challenge)])
            .json(&body);
        send_json(req)
            .await
            .map_err(|e| anyhow::anyhow!("hydra reject_login_request failed: {e}"))
    }

    pub async fn get_consent_request(&self, challenge: &str) -> Result<ConsentRequest> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::GET, "/admin/oauth2/auth/requests/consent")
            .query(&[("consent_challenge", challenge)]);
        send_json(req)
            .await
            .and_then(with_nested_clients)
            .map_err(|e| anyhow::anyhow!("hydra get_consent_request failed: {e}"))
    }

    /// Accept a Hydra consent challenge with the granted scopes and the id_token and access-token claim payloads (Hydra's `session.id_token` / `session.access_token`).
    /// A remembered consent (`remember == true`) persists indefinitely, until the user revokes it from Authorized apps.
    pub async fn accept_consent_request(
        &self,
        challenge: &str,
        grant_scope: Vec<String>,
        grant_audience: Vec<String>,
        remember: bool,
        id_token_session: Value,
        access_token_session: Map<String, Value>,
    ) -> Result<RedirectTo> {
        let body = AcceptConsentBody {
            grant_access_token_audience: grant_audience,
            grant_scope,
            remember,
            remember_for: 0,
            session: ConsentClaims {
                access_token: access_token_session,
                id_token: id_token_session,
            },
        };
        let req = self
            .clients
            .hydra_admin
            .request(Method::PUT, "/admin/oauth2/auth/requests/consent/accept")
            .query(&[("consent_challenge", challenge)])
            .json(&body);
        send_json(req)
            .await
            .map_err(|e| anyhow::anyhow!("hydra accept_consent_request failed: {e}"))
    }

    /// Reject a consent challenge, propagating an OAuth2 `error` / `error_description`
    /// back to the relying party.
    pub async fn reject_consent_request(
        &self,
        challenge: &str,
        error: &str,
        error_description: &str,
    ) -> Result<RedirectTo> {
        let body = RejectBody {
            error,
            error_description,
            status_code: Some(403),
        };
        let req = self
            .clients
            .hydra_admin
            .request(Method::PUT, "/admin/oauth2/auth/requests/consent/reject")
            .query(&[("consent_challenge", challenge)])
            .json(&body);
        send_json(req)
            .await
            .map_err(|e| anyhow::anyhow!("hydra reject_consent_request failed: {e}"))
    }

    pub async fn get_logout_request(&self, challenge: &str) -> Result<LogoutRequest> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::GET, "/admin/oauth2/auth/requests/logout")
            .query(&[("logout_challenge", challenge)]);
        send_json(req)
            .await
            .and_then(with_nested_clients)
            .map_err(|e| anyhow::anyhow!("hydra get_logout_request failed: {e}"))
    }

    pub async fn accept_logout_request(&self, challenge: &str) -> Result<RedirectTo> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::PUT, "/admin/oauth2/auth/requests/logout/accept")
            .query(&[("logout_challenge", challenge)]);
        send_json(req)
            .await
            .map_err(|e| anyhow::anyhow!("hydra accept_logout_request failed: {e}"))
    }
}

// --- Device Authorization Grant (RFC 8628) ---------------------------
//
// Wrappers driven by the Part-B device endpoints (`src/posix/device.rs`)
// and the browser verification UI (`src/oauth/device_verify.rs`).
mod device_grant {
    use super::{
        AcceptUserCodeBody, HydraBackend, JsonWebKeySet, Method, RedirectTo, Result, send_json,
    };
    use crate::backend::oauth::{DeviceAuthorization, DeviceTokenOutcome, IdTokenClaims, TokenSet};

    /// Hydra's `/oauth2/device/auth` success body (RFC 8628 §3.2).
    #[derive(serde::Deserialize)]
    struct DeviceAuthorizationBody {
        device_code: Option<String>,
        user_code: Option<String>,
        verification_uri: Option<String>,
        verification_uri_complete: Option<String>,
        expires_in: Option<i64>,
        interval: Option<i64>,
    }

    /// Hydra's `/oauth2/token` error body shape (RFC 6749 §5.2).
    #[derive(serde::Deserialize)]
    struct TokenError {
        error: String,
    }

    /// Hydra's `/oauth2/token` success body for the device grant.
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
        #[serde(default)]
        id_token: Option<String>,
        #[serde(default)]
        expires_in: i64,
    }

    const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

    // --- id_token verification -------------------------------------------

    /// Raw id_token claim shape for deserialization. `aud` is string-or-array
    /// in OIDC; jsonwebtoken checks membership for us, but we keep the field so
    /// we can assert it's EXACTLY our client (the PAM client is single-audience
    /// by construction) and cross-check `azp`.
    #[derive(serde::Deserialize)]
    struct RawIdClaims {
        sub: String,
        aud: Audience,
        #[serde(default)]
        azp: Option<String>,
        #[serde(default)]
        acr: Option<String>,
        #[serde(default)]
        amr: Vec<String>,
        #[serde(default)]
        auth_time: Option<i64>,
    }

    /// `aud` is a single string or an array of strings in OIDC.
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    impl Audience {
        fn as_slice(&self) -> &[String] {
            match self {
                Audience::One(s) => std::slice::from_ref(s),
                Audience::Many(v) => v,
            }
        }
    }

    impl HydraBackend {
        /// Start the device grant against Hydra's public `/oauth2/device/auth` with HTTP Basic client auth:
        /// the confidential client must authenticate.
        pub async fn device_authorization(
            &self,
            client_id: &str,
            client_secret: &str,
            scope: &str,
        ) -> Result<DeviceAuthorization> {
            let ep = &self.clients.hydra_public;
            let url = format!("{}/oauth2/device/auth", ep.base.trim_end_matches('/'));
            let resp = ep
                .http
                .post(&url)
                .basic_auth(client_id, Some(client_secret))
                // RFC 8628 §3.1 requires `client_id` in the body; Hydra cross-checks
                // it against the Basic-auth client and 400s on a mismatch (incl. an
                // absent body client_id), so send it in both.
                .form(&[("client_id", client_id), ("scope", scope)])
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("hydra device_authorization transport: {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "hydra device_authorization returned {status}: {body}"
                ));
            }
            let raw: DeviceAuthorizationBody = resp
                .json()
                .await
                .map_err(|e| anyhow::anyhow!("hydra device_authorization decode: {e}"))?;
            Ok(DeviceAuthorization {
                device_code: raw
                    .device_code
                    .ok_or_else(|| anyhow::anyhow!("device_authorization: missing device_code"))?,
                user_code: raw
                    .user_code
                    .ok_or_else(|| anyhow::anyhow!("device_authorization: missing user_code"))?,
                verification_uri: raw.verification_uri.ok_or_else(|| {
                    anyhow::anyhow!("device_authorization: missing verification_uri")
                })?,
                verification_uri_complete: raw.verification_uri_complete,
                expires_in: raw.expires_in.unwrap_or(600),
                interval: raw.interval.unwrap_or(5),
            })
        }

        /// Poll Hydra's public token endpoint for a device_code (RFC 8628 §3.4).
        /// Client-authenticated (`client_secret_basic`): the confidential client means this leg can't be driven
        /// without Forseti's credential. NEVER log `device_code` or the returned tokens.
        pub async fn poll_device_token(
            &self,
            client_id: &str,
            client_secret: &str,
            device_code: &str,
        ) -> Result<DeviceTokenOutcome> {
            let ep = &self.clients.hydra_public;
            let url = format!("{}/oauth2/token", ep.base.trim_end_matches('/'));
            let resp = ep
                .http
                .post(&url)
                .basic_auth(client_id, Some(client_secret))
                .form(&[
                    ("grant_type", DEVICE_CODE_GRANT),
                    ("device_code", device_code),
                ])
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("hydra poll_device_token transport: {e}"))?;

            let status = resp.status();
            let body = resp
                .text()
                .await
                .map_err(|e| anyhow::anyhow!("hydra poll_device_token body: {e}"))?;

            if status.is_success() {
                let tok: TokenResponse = serde_json::from_str(&body)
                    .map_err(|e| anyhow::anyhow!("hydra poll_device_token decode: {e}"))?;
                return Ok(DeviceTokenOutcome::Token(Box::new(TokenSet {
                    access_token: tok.access_token,
                    id_token: tok.id_token,
                    expires_in: tok.expires_in,
                })));
            }

            // 4xx with an RFC 6749 `error` body. Map the device-grant error codes;
            // anything else is a genuine failure (bad client auth, misconfig).
            let parsed: TokenError = serde_json::from_str(&body)
                .map_err(|_| anyhow::anyhow!("hydra poll_device_token returned {status}"))?;
            Ok(map_device_token_error(&parsed.error))
        }

        /// Accept a device user-code verification challenge (Part B entry point).
        /// `PUT /admin/oauth2/auth/requests/device/accept`. Forseti calls this
        /// from the `device_verify` page after the user types a valid `user_code`; Hydra then drives login + consent.
        pub async fn accept_user_code_request(
            &self,
            device_challenge: &str,
            user_code: &str,
        ) -> Result<RedirectTo> {
            let req = self
                .clients
                .hydra_admin
                .request(Method::PUT, "/admin/oauth2/auth/requests/device/accept")
                .query(&[("device_challenge", device_challenge)])
                .json(&AcceptUserCodeBody { user_code });
            send_json(req)
                .await
                .map_err(|e| anyhow::anyhow!("hydra accept_user_code_request failed: {e}"))
        }

        /// Verify a device id_token against Hydra's JWKS and the configured
        /// security set. Pins **RS256** (rejects `none` and every other alg),
        /// validates `iss`/`aud`/`exp` via jsonwebtoken, then cross-checks
        /// `azp == client_id` and a tight `iat` freshness window on top of `exp`.
        ///
        /// Validate-and-discard: the returned claims carry only what the binding
        /// needs (`sub`/`acr`/`amr`/`auth_time`); the token itself is never logged
        /// or persisted (R3 / R10, no introspection).
        pub async fn verify_id_token(
            &self,
            id_token: &str,
            issuer: &str,
            client_id: &str,
            iat_window_secs: u64,
        ) -> Result<IdTokenClaims> {
            let jwks = self.fetch_jwks().await?;
            verify_id_token_with_jwks(id_token, &jwks, issuer, client_id, iat_window_secs)
        }
    }

    /// Map an RFC 6749 / RFC 8628 token-endpoint `error` code to an outcome.
    /// Unknown codes surface as an `Err` from the caller; the four spec codes
    /// are the only non-terminal/terminal device states.
    pub(super) fn map_device_token_error(error: &str) -> DeviceTokenOutcome {
        match error {
            "authorization_pending" => DeviceTokenOutcome::Pending,
            "slow_down" => DeviceTokenOutcome::SlowDown,
            "expired_token" => DeviceTokenOutcome::Expired,
            "access_denied" => DeviceTokenOutcome::Denied,
            // Treat any other error (e.g. invalid_grant once consumed) as a
            // dead flow rather than retrying forever.
            _ => DeviceTokenOutcome::Expired,
        }
    }

    /// Pure validation core, split out so it's unit-testable with a crafted
    /// JWKS + minted tokens (no network). See the test module.
    pub(super) fn verify_id_token_with_jwks(
        id_token: &str,
        jwks: &JsonWebKeySet,
        issuer: &str,
        client_id: &str,
        iat_window_secs: u64,
    ) -> Result<IdTokenClaims> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

        // Pin the alg from our side BEFORE trusting the header's. We still read
        // the header's `kid` to select the key, but reject anything whose
        // declared alg isn't RS256 (defeats the `alg: none` / alg-confusion
        // family; the header can't downgrade us).
        let header =
            decode_header(id_token).map_err(|e| anyhow::anyhow!("id_token header decode: {e}"))?;
        if header.alg != Algorithm::RS256 {
            return Err(anyhow::anyhow!(
                "id_token alg {:?} rejected (only RS256 accepted)",
                header.alg
            ));
        }
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("id_token header missing kid"))?;

        let jwk = jwks
            .keys
            .as_ref()
            .and_then(|ks| ks.iter().find(|k| k.kid == kid))
            .ok_or_else(|| anyhow::anyhow!("id_token kid {kid} not in Hydra JWKS"))?;
        if jwk.kty != "RSA" {
            return Err(anyhow::anyhow!(
                "id_token signing key kty {} not RSA",
                jwk.kty
            ));
        }
        let n = jwk
            .n
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("JWKS RSA key missing modulus"))?;
        let e = jwk
            .e
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("JWKS RSA key missing exponent"))?;
        let key = DecodingKey::from_rsa_components(n, e)
            .map_err(|e| anyhow::anyhow!("JWKS RSA key invalid: {e}"))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        // jsonwebtoken's default 60s leeway on exp/nbf is fine; iat freshness is
        // enforced separately below with the configured tight window.
        validation.validate_exp = true;

        let data = decode::<RawIdClaims>(id_token, &key, &validation)
            .map_err(|e| anyhow::anyhow!("id_token validation failed: {e}"))?;
        let claims = data.claims;

        // Self-defending aud pin: the PAM client is single-audience by
        // construction, so require `aud` to be EXACTLY our client. jsonwebtoken
        // only checks membership, which would accept a token whose `aud` also
        // names other parties; reject those here regardless of Hydra config.
        match claims.aud.as_slice() {
            [only] if only == client_id => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "id_token aud must be exactly [{client_id}]"
                ));
            }
        }

        // azp pin: per OIDC Core §3.1.3.7, `azp` is OPTIONAL and only present
        // when `aud` has multiple values (or differs from the authorized party).
        // Hydra omits it for a single-audience token, so a missing `azp` is
        // valid, since `aud` is already pinned to our client via set_audience. When
        // `azp` IS present it must be our client.
        match claims.azp.as_deref() {
            Some(azp) if azp == client_id => {}
            Some(other) => {
                return Err(anyhow::anyhow!(
                    "id_token azp {other} != expected client {client_id}"
                ));
            }
            None => {}
        }

        // Tight iat freshness on top of exp, a replay guard. jsonwebtoken
        // doesn't expose iat-max-age, so check it by hand against the claim.
        let iat = extract_iat(id_token)?;
        let now = chrono::Utc::now().timestamp();
        if iat > now.saturating_add(60) {
            return Err(anyhow::anyhow!("id_token iat is in the future"));
        }
        let age = now.saturating_sub(iat);
        if age > iat_window_secs as i64 {
            return Err(anyhow::anyhow!(
                "id_token iat is stale ({age}s > {iat_window_secs}s window)"
            ));
        }

        Ok(IdTokenClaims {
            sub: claims.sub,
            acr: claims.acr,
            amr: claims.amr,
            auth_time: claims.auth_time,
        })
    }

    /// Pull `iat` out of the (already signature-verified) payload. We decode
    /// the middle segment ourselves because `Validation` doesn't surface a
    /// max-iat-age knob.
    fn extract_iat(id_token: &str) -> Result<i64> {
        use base64::Engine;
        let payload_b64 = id_token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("id_token not a JWT"))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| anyhow::anyhow!("id_token payload base64: {e}"))?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("id_token payload json: {e}"))?;
        v.get("iat")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow::anyhow!("id_token missing iat"))
    }
} // mod device_grant

#[cfg(test)]
use device_grant::{map_device_token_error, verify_id_token_with_jwks};

// --- Admin surface ---------------------------------------------------

fn client_path(id: &str) -> String {
    format!("/admin/clients/{}", urlencode(id))
}

/// Ceiling on how many audiences consent may accumulate on one client record.
const CLIENT_AUDIENCE_CAP: usize = 20;

/// The append-only patch that brings the client's `audience` up to `granted`.
///
/// `on_record` must be the `audience` array as Hydra stores it now, whoever
/// wrote it — it is both the dedup set and the cap accounting. Handing this a
/// source-filtered view (say, only what an operator wrote) makes every entry
/// look new, so the same resource is re-appended on every consent and the cap
/// never binds.
fn audience_patch(client_id: &str, on_record: &[String], granted: &[String]) -> Vec<JsonPatchOp> {
    let mut have: Vec<&str> = on_record.iter().map(String::as_str).collect();
    let mut patch = Vec::new();
    for resource in granted {
        if have.contains(&resource.as_str()) {
            continue;
        }
        if have.len() >= CLIENT_AUDIENCE_CAP {
            tracing::warn!(
                client_id,
                resource = %resource,
                "hydra: client audience cap reached; not registering",
            );
            break;
        }
        have.push(resource);
        patch.push(JsonPatchOp {
            op: "add",
            path: "/audience/-",
            value: Value::String(resource.clone()),
        });
    }
    patch
}

const CONSENT_LIST_PAGE_SIZE: i64 = 250;
const CONSENT_LIST_MAX_PAGES: usize = 50; // 12,500 grants per subject, well past any realistic case.

fn consent_sessions_from_wire(sessions: Vec<Value>) -> Result<Vec<ConsentSession>> {
    with_nested_clients(Value::Array(sessions))
        .map_err(|e| anyhow::anyhow!("hydra list_consent_sessions decode: {e}"))
}

/// Generate a random client secret. 40 alphanumerics is about 238 bits of entropy, well above the OAuth2 spec's recommendation.
fn generate_client_secret() -> String {
    use rand::RngExt;
    use rand::distr::Alphanumeric;
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect()
}

impl HydraBackend {
    /// Paginated client list. `page_token` comes from the previous page's `Link: rel="next"` header.
    pub async fn list_clients(
        &self,
        page_size: i64,
        page_token: Option<&str>,
        client_name: Option<&str>,
    ) -> Result<Vec<OAuthClient>> {
        let mut req = self
            .clients
            .hydra_admin
            .request(Method::GET, "/admin/clients")
            .query(&[("page_size", page_size.to_string())]);
        if let Some(tok) = page_token {
            req = req.query(&[("page_token", tok)]);
        }
        if let Some(name) = client_name {
            req = req.query(&[("client_name", name)]);
        }
        send_json::<Vec<Value>>(req)
            .await
            .and_then(|list| list.into_iter().map(client_from_wire).collect())
            .map_err(|e| anyhow::anyhow!("hydra list_clients failed: {e}"))
    }

    async fn fetch_client(&self, id: &str) -> Result<OAuthClient, CallError> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::GET, &client_path(id));
        client_from_wire(send_json(req).await?)
    }

    pub async fn get_client(&self, id: &str) -> Result<OAuthClient> {
        self.fetch_client(id)
            .await
            .map_err(|e| anyhow::anyhow!("hydra get_client failed: {e}"))
    }

    /// [`get_client`] with Hydra's 404 mapped to `None`, so upsert callers can branch on existence.
    pub async fn get_client_opt(&self, id: &str) -> Result<Option<OAuthClient>> {
        match self.fetch_client(id).await {
            Ok(c) => Ok(Some(c)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(anyhow::anyhow!("hydra get_client failed: {e}")),
        }
    }

    pub async fn create_client(&self, client: OAuthClient) -> Result<OAuthClient> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::POST, "/admin/clients")
            .json(&client_to_wire(client)?);
        send_json(req)
            .await
            .and_then(client_from_wire)
            .map_err(|e| anyhow::anyhow!("hydra create_client failed: {e}"))
    }

    /// Replace a client. Hydra's `PUT /admin/clients/{id}` fully overrides the stored client,
    /// so callers should round-trip via `get_client` first to preserve unrelated fields.
    pub async fn update_client(&self, id: &str, client: OAuthClient) -> Result<OAuthClient> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::PUT, &client_path(id))
            .json(&client_to_wire(client)?);
        send_json(req)
            .await
            .and_then(client_from_wire)
            .map_err(|e| anyhow::anyhow!("hydra update_client failed: {e}"))
    }

    pub async fn delete_client(&self, id: &str) -> Result<()> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::DELETE, &client_path(id));
        send(req)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("hydra delete_client failed: {e}"))
    }

    async fn patch_client(
        &self,
        id: &str,
        patch: &[JsonPatchOp],
    ) -> Result<OAuthClient, CallError> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::PATCH, &client_path(id))
            .json(patch);
        client_from_wire(send_json(req).await?)
    }

    /// Add `granted` to the client's registered `audience` allow-list, skipping
    /// whatever `on_record` (the record as the caller just read it) already
    /// covers. fosite re-validates the granted audience against the client record
    /// on the refresh grant (`handler/oauth2/flow_refresh.go`) but not on the code
    /// exchange, so a granted resource that never lands here buys the client one
    /// working access token and then permanent refresh failures. Idempotent, and
    /// capped so a client can't grow the record without bound.
    pub async fn add_client_audiences(
        &self,
        client_id: &str,
        on_record: &[String],
        granted: &[String],
    ) -> Result<()> {
        let patch = audience_patch(client_id, on_record, granted);
        if patch.is_empty() {
            return Ok(());
        }
        self.patch_client(client_id, &patch)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("hydra add_client_audiences failed: {e}"))
    }

    /// Rotate a client's secret. Hydra has no dedicated rotate endpoint, so we PATCH a JSON Patch asking it to
    /// replace `client_secret`. The response carries the new plaintext secret (the admin UI shows it once).
    pub async fn rotate_client_secret(&self, id: &str) -> Result<OAuthClient> {
        let patch = [JsonPatchOp {
            op: "replace",
            path: "/client_secret",
            value: Value::String(generate_client_secret()),
        }];
        self.patch_client(id, &patch)
            .await
            .map_err(|e| anyhow::anyhow!("hydra rotate_client_secret failed: {e}"))
    }

    /// Enumerate Hydra consent sessions with an active grant for `subject`, paging the `Link: rel="next"` header
    /// until exhausted (drives the account-deletion webhook fan-out, so the list must not be silently capped).
    /// Bounded by [`CONSENT_LIST_MAX_PAGES`].
    pub async fn list_consent_sessions_by_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<ConsentSession>> {
        let ep = &self.clients.hydra_admin;
        let base = format!(
            "{}/admin/oauth2/auth/sessions/consent",
            ep.base.trim_end_matches('/')
        );

        let mut out: Vec<Value> = Vec::new();
        let mut page_token: Option<String> = None;
        for page in 0..CONSENT_LIST_MAX_PAGES {
            let mut req = ep.http.get(&base).query(&[
                ("subject", subject.to_string()),
                ("page_size", CONSENT_LIST_PAGE_SIZE.to_string()),
            ]);
            if let Some(tok) = page_token.as_deref() {
                req = req.query(&[("page_token", tok)]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("hydra list_consent_sessions transport: {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "hydra list_consent_sessions returned {status}: {body}"
                ));
            }

            let next = next_link(resp.headers());
            let batch: Vec<Value> = resp
                .json()
                .await
                .map_err(|e| anyhow::anyhow!("hydra list_consent_sessions decode: {e}"))?;
            let batch_empty = batch.is_empty();
            out.extend(batch);
            match next {
                Some(tok) if !batch_empty => page_token = Some(tok),
                _ => return consent_sessions_from_wire(out),
            }
            if page + 1 == CONSENT_LIST_MAX_PAGES {
                tracing::error!(
                    subject,
                    pages = CONSENT_LIST_MAX_PAGES,
                    "hydra consent-session pagination hit safety cap — webhook fanout may be incomplete",
                );
            }
        }
        consent_sessions_from_wire(out)
    }

    /// `DELETE /admin/oauth2/auth/sessions/consent` with the given query.
    async fn revoke_consent_sessions(&self, query: &[(&str, &str)]) -> Result<(), CallError> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::DELETE, "/admin/oauth2/auth/sessions/consent")
            .query(query);
        send(req).await.map(|_| ())
    }

    /// Revoke every consent grant for `subject` and invalidate associated
    /// OAuth2 access tokens. Best-effort during account deletion: failures log and the flow proceeds (the
    /// source-of-truth Kratos identity determines whether the user can sign back in).
    pub async fn revoke_consent_sessions_for_subject(&self, subject: &str) -> Result<()> {
        self.revoke_consent_sessions(&[("subject", subject), ("all", "true")])
            .await
            .map_err(|e| anyhow::anyhow!("hydra revoke_consent_sessions failed: {e}"))
    }

    /// Revoke one consent grant by its consent request id, which Hydra documents
    /// as revoking the token chains derived from it. Hydra takes the id alone;
    /// adding `subject` is a 400. A grant Hydra no longer knows counts as revoked.
    pub async fn revoke_consent_sessions_by_request_id(
        &self,
        consent_request_id: &str,
    ) -> Result<()> {
        match self
            .revoke_consent_sessions(&[("consent_request_id", consent_request_id)])
            .await
        {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "hydra revoke_consent_sessions by request id failed: {e}"
            )),
        }
    }

    /// One page of a subject's consent sessions granted under one Hydra login
    /// session. Lists only consents Hydra remembered, never skipped ones.
    pub async fn list_consent_sessions_by_login_session(
        &self,
        subject: &str,
        sid: &str,
    ) -> Result<Vec<ConsentSession>> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::GET, "/admin/oauth2/auth/sessions/consent")
            .query(&[("page_size", CONSENT_LIST_PAGE_SIZE.to_string())])
            .query(&[("subject", subject), ("login_session_id", sid)]);
        send_json(req)
            .await
            .and_then(with_nested_clients)
            .map_err(|e| {
                anyhow::anyhow!("hydra list_consent_sessions by login session failed: {e}")
            })
    }

    /// Revoke all consent grants for a single (subject, client) pair.
    /// Powers the per-app "Revoke access" action on `/settings/authorized-apps`.
    /// Hydra has no per-scope revocation; reducing a grant needs the user to re-consent with a narrower scope set.
    pub async fn revoke_consent_sessions_for_client(
        &self,
        subject: &str,
        client_id: &str,
    ) -> Result<()> {
        // `client` and `all` are mutually exclusive in Hydra v2 (passing both is a 400); with a client named, leave `all` unset.
        self.revoke_consent_sessions(&[("subject", subject), ("client", client_id)])
            .await
            .map_err(|e| anyhow::anyhow!("hydra revoke_consent_sessions_for_client failed: {e}"))
    }

    /// `DELETE /admin/oauth2/auth/sessions/login` with the given query.
    async fn revoke_login_sessions(&self, query: &[(&str, &str)]) -> Result<(), CallError> {
        let req = self
            .clients
            .hydra_admin
            .request(Method::DELETE, "/admin/oauth2/auth/sessions/login")
            .query(query);
        send(req).await.map(|_| ())
    }

    /// Revoke every Hydra login session (the OP skip/remember state) for a subject.
    /// Subject-keyed revocation fires no front/back-channel logout; pair it with
    /// `revoke_consent_sessions_for_subject` to invalidate the RPs' grants.
    pub async fn revoke_login_sessions_for_subject(&self, subject: &str) -> Result<()> {
        self.revoke_login_sessions(&[("subject", subject)])
            .await
            .map_err(|e| anyhow::anyhow!("hydra revoke_login_sessions failed: {e}"))
    }

    /// Revoke one Hydra login session by `sid`. Unlike the subject-keyed revoke,
    /// this sends back-channel logout to every client the session signed in to.
    /// A session Hydra no longer knows counts as revoked.
    pub async fn revoke_login_session_by_sid(&self, sid: &str) -> Result<()> {
        match self.revoke_login_sessions(&[("sid", sid)]).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "hydra revoke_login_session_by_sid failed: {e}"
            )),
        }
    }

    /// Health probes, same shape as Kratos.
    pub async fn health_alive(&self) -> Result<()> {
        self.clients.hydra_admin.probe_health("/health/alive").await
    }

    pub async fn health_ready(&self) -> Result<()> {
        self.clients.hydra_admin.probe_health("/health/ready").await
    }

    /// Fetch the Hydra build version.
    pub async fn version(&self) -> Result<String> {
        let req = self.clients.hydra_admin.request(Method::GET, "/version");
        let v: VersionBody = send_json(req)
            .await
            .map_err(|e| anyhow::anyhow!("hydra get_version failed: {e}"))?;
        Ok(v.version)
    }

    /// Hydra's JWKS, fetched fresh from the public `/.well-known/jwks.json`.
    async fn fetch_jwks(&self) -> Result<JsonWebKeySet> {
        let req = self
            .clients
            .hydra_public
            .request(Method::GET, "/.well-known/jwks.json");
        send_json(req)
            .await
            .map_err(|e| anyhow::anyhow!("hydra discover_json_web_keys failed: {e}"))
    }

    /// Fetch Hydra's public signing keys (the `jwks_uri` contents) and project
    /// each down to the fields the admin UI shows. Order is whatever Hydra
    /// returns.
    pub async fn signing_keys(&self) -> Result<Vec<JwkSummary>> {
        let set = self.fetch_jwks().await?;
        Ok(set
            .keys
            .unwrap_or_default()
            .into_iter()
            .map(|k| JwkSummary {
                kid: k.kid,
                alg: k.alg,
                kty: k.kty,
                use_: k.use_,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
