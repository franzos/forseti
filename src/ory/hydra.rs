//! Hydra OAuth2 bridge wrappers (admin-API operations).
//!
//! Hydra's admin API does not produce the broken `ui.nodes` shape that the
//! Kratos flow models do, so the SDK types are usable directly here.

use super::*;
use ory_client::apis::o_auth2_api;

pub async fn get_login_request(
    clients: &OryClients,
    challenge: &str,
) -> Result<OAuth2LoginRequest> {
    o_auth2_api::get_o_auth2_login_request(&clients.hydra_admin, challenge)
        .await
        .map_err(|e| anyhow::anyhow!("hydra get_login_request failed: {e}"))
}

/// Accept a Hydra login challenge for a Kratos subject. `amr`/`acr` mirror the OIDC claims RPs see;
/// `remember` extends Hydra's login session so subsequent SSO hits skip re-prompting Kratos.
pub async fn accept_login_request(
    clients: &OryClients,
    challenge: &str,
    subject: &str,
    remember: bool,
    amr: Vec<String>,
    acr: Option<String>,
) -> Result<OAuth2RedirectTo> {
    let mut body = AcceptOAuth2LoginRequest::new(subject.to_string());
    body.remember = Some(remember);
    body.remember_for = Some(3600);
    if !amr.is_empty() {
        body.amr = Some(amr);
    }
    body.acr = acr;
    o_auth2_api::accept_o_auth2_login_request(&clients.hydra_admin, challenge, Some(body))
        .await
        .map_err(|e| anyhow::anyhow!("hydra accept_login_request failed: {e}"))
}

pub async fn get_consent_request(
    clients: &OryClients,
    challenge: &str,
) -> Result<OAuth2ConsentRequest> {
    o_auth2_api::get_o_auth2_consent_request(&clients.hydra_admin, challenge)
        .await
        .map_err(|e| anyhow::anyhow!("hydra get_consent_request failed: {e}"))
}

/// Accept a Hydra consent challenge with the granted scopes and id_token claim payload (folded into Hydra's `session.id_token`).
pub async fn accept_consent_request(
    clients: &OryClients,
    challenge: &str,
    grant_scope: Vec<String>,
    grant_audience: Vec<String>,
    remember: bool,
    id_token_session: serde_json::Value,
) -> Result<OAuth2RedirectTo> {
    let mut session = AcceptOAuth2ConsentRequestSession::new();
    // `Option<Option<Value>>` mirrors openapi-generator's "nullable optional"
    // shape; the outer `Some` says "field present", the inner `Some` says
    // "value non-null".
    session.id_token = Some(Some(id_token_session));

    let mut body = AcceptOAuth2ConsentRequest::new();
    body.grant_scope = Some(grant_scope);
    body.grant_access_token_audience = Some(grant_audience);
    body.remember = Some(remember);
    body.remember_for = Some(3600);
    body.session = Some(Box::new(session));

    o_auth2_api::accept_o_auth2_consent_request(&clients.hydra_admin, challenge, Some(body))
        .await
        .map_err(|e| anyhow::anyhow!("hydra accept_consent_request failed: {e}"))
}

/// Reject a consent challenge, propagating an OAuth2 `error` / `error_description`
/// back to the relying party.
pub async fn reject_consent_request(
    clients: &OryClients,
    challenge: &str,
    error: &str,
    error_description: &str,
) -> Result<OAuth2RedirectTo> {
    let body = RejectOAuth2Request {
        error: Some(error.to_string()),
        error_debug: None,
        error_description: Some(error_description.to_string()),
        error_hint: None,
        status_code: Some(403),
    };
    o_auth2_api::reject_o_auth2_consent_request(&clients.hydra_admin, challenge, Some(body))
        .await
        .map_err(|e| anyhow::anyhow!("hydra reject_consent_request failed: {e}"))
}

pub async fn get_logout_request(
    clients: &OryClients,
    challenge: &str,
) -> Result<OAuth2LogoutRequest> {
    o_auth2_api::get_o_auth2_logout_request(&clients.hydra_admin, challenge)
        .await
        .map_err(|e| anyhow::anyhow!("hydra get_logout_request failed: {e}"))
}

pub async fn accept_logout_request(
    clients: &OryClients,
    challenge: &str,
) -> Result<OAuth2RedirectTo> {
    o_auth2_api::accept_o_auth2_logout_request(&clients.hydra_admin, challenge)
        .await
        .map_err(|e| anyhow::anyhow!("hydra accept_logout_request failed: {e}"))
}

// --- Device Authorization Grant (RFC 8628) ---------------------------
//
// Wrappers driven by the Part-B device endpoints (`src/posix/device.rs`)
// and the browser verification UI (`src/oauth/device_verify.rs`).
mod device_grant {
    use super::{o_auth2_api, OAuth2RedirectTo, OryClients, Result};

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

    /// Start the device grant against Hydra's public `/oauth2/device/auth`. POSTs directly with HTTP Basic
    /// client auth because the SDK's `o_auth2_device_flow` sends none, and the confidential client must authenticate.
    pub async fn device_authorization(
        clients: &OryClients,
        client_id: &str,
        client_secret: &str,
        scope: &str,
    ) -> Result<DeviceAuthorization> {
        let cfg = &clients.hydra_public;
        let url = format!("{}/oauth2/device/auth", cfg.base_path.trim_end_matches('/'));
        let resp = cfg
            .client
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
        let raw: ory_client::models::DeviceAuthorization = resp
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
            verification_uri: raw
                .verification_uri
                .ok_or_else(|| anyhow::anyhow!("device_authorization: missing verification_uri"))?,
            verification_uri_complete: raw.verification_uri_complete,
            expires_in: raw.expires_in.unwrap_or(600),
            interval: raw.interval.unwrap_or(5),
        })
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

    /// Poll Hydra's public token endpoint for a device_code (RFC 8628 §3.4).
    /// Client-authenticated (`client_secret_basic`): the confidential client means this leg can't be driven
    /// without Forseti's credential. NEVER log `device_code` or the returned tokens.
    pub async fn poll_device_token(
        clients: &OryClients,
        client_id: &str,
        client_secret: &str,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome> {
        let cfg = &clients.hydra_public;
        let url = format!("{}/oauth2/token", cfg.base_path.trim_end_matches('/'));
        let resp = cfg
            .client
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

    /// Accept a device user-code verification challenge (Part B entry point).
    /// `PUT /admin/oauth2/auth/requests/device/accept`. Forseti calls this
    /// from the `device_verify` page after the user types a valid `user_code`; Hydra then drives login + consent.
    pub async fn accept_user_code_request(
        clients: &OryClients,
        device_challenge: &str,
        user_code: &str,
    ) -> Result<OAuth2RedirectTo> {
        let body = ory_client::models::AcceptDeviceUserCodeRequest {
            user_code: Some(user_code.to_string()),
        };
        o_auth2_api::accept_user_code_request(&clients.hydra_admin, device_challenge, Some(body))
            .await
            .map_err(|e| anyhow::anyhow!("hydra accept_user_code_request failed: {e}"))
    }

    // --- id_token verification -------------------------------------------

    /// The subset of OIDC id_token claims the device path binds against. The
    /// token is validated then discarded; these are read once at poll time and never persisted (R3).
    #[derive(Debug, Clone)]
    pub struct IdTokenClaims {
        pub sub: String,
        pub acr: Option<String>,
        pub amr: Vec<String>,
        pub auth_time: Option<i64>,
    }

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

    /// Verify a device id_token against Hydra's JWKS and the configured
    /// security set. Pins **RS256** (rejects `none` and every other alg),
    /// validates `iss`/`aud`/`exp` via jsonwebtoken, then cross-checks
    /// `azp == client_id` and a tight `iat` freshness window on top of `exp`.
    ///
    /// Validate-and-discard: the returned claims carry only what the binding
    /// needs (`sub`/`acr`/`amr`/`auth_time`); the token itself is never logged
    /// or persisted (R3 / R10, no introspection).
    pub async fn verify_id_token(
        clients: &OryClients,
        id_token: &str,
        issuer: &str,
        client_id: &str,
        iat_window_secs: u64,
    ) -> Result<IdTokenClaims> {
        let jwks = fetch_jwks(clients).await?;
        verify_id_token_with_jwks(id_token, &jwks, issuer, client_id, iat_window_secs)
    }

    /// Hydra's JWKS, fetched fresh from the public `jwks_uri`. Reuses the SDK
    /// helper already used by [`signing_keys`].
    async fn fetch_jwks(clients: &OryClients) -> Result<ory_client::models::JsonWebKeySet> {
        ory_client::apis::wellknown_api::discover_json_web_keys(&clients.hydra_public)
            .await
            .map_err(|e| anyhow::anyhow!("hydra discover_json_web_keys failed: {e}"))
    }

    /// Pure validation core, split out so it's unit-testable with a crafted
    /// JWKS + minted tokens (no network). See the test module.
    pub(super) fn verify_id_token_with_jwks(
        id_token: &str,
        jwks: &ory_client::models::JsonWebKeySet,
        issuer: &str,
        client_id: &str,
        iat_window_secs: u64,
    ) -> Result<IdTokenClaims> {
        use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

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
                ))
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
                ))
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

pub use device_grant::{
    accept_user_code_request, device_authorization, poll_device_token, verify_id_token,
    DeviceTokenOutcome, TokenSet,
};
#[cfg(test)]
use device_grant::{map_device_token_error, verify_id_token_with_jwks, IdTokenClaims};

// --- Admin surface ---------------------------------------------------

/// Paginated client list. `page_token` comes from the previous page's `Link: rel="next"` header.
pub async fn list_clients(
    clients: &OryClients,
    page_size: i64,
    page_token: Option<&str>,
    client_name: Option<&str>,
) -> Result<Vec<OAuth2Client>> {
    o_auth2_api::list_o_auth2_clients(
        &clients.hydra_admin,
        Some(page_size),
        page_token,
        client_name,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("hydra list_clients failed: {e}"))
}

pub async fn get_client(clients: &OryClients, id: &str) -> Result<OAuth2Client> {
    o_auth2_api::get_o_auth2_client(&clients.hydra_admin, id)
        .await
        .map_err(|e| anyhow::anyhow!("hydra get_client failed: {e}"))
}

pub async fn create_client(clients: &OryClients, client: OAuth2Client) -> Result<OAuth2Client> {
    o_auth2_api::create_o_auth2_client(&clients.hydra_admin, client)
        .await
        .map_err(|e| anyhow::anyhow!("hydra create_client failed: {e}"))
}

/// Replace a client. Hydra's `set_o_auth2_client` is PUT-shaped (the body fully overrides the stored client),
/// so callers should round-trip via `get_client` first to preserve unrelated fields.
pub async fn update_client(
    clients: &OryClients,
    id: &str,
    client: OAuth2Client,
) -> Result<OAuth2Client> {
    o_auth2_api::set_o_auth2_client(&clients.hydra_admin, id, client)
        .await
        .map_err(|e| anyhow::anyhow!("hydra update_client failed: {e}"))
}

pub async fn delete_client(clients: &OryClients, id: &str) -> Result<()> {
    o_auth2_api::delete_o_auth2_client(&clients.hydra_admin, id)
        .await
        .map_err(|e| anyhow::anyhow!("hydra delete_client failed: {e}"))
}

/// Rotate a client's secret. Hydra has no dedicated rotate endpoint, so we POST a JSON Patch asking it to
/// regenerate `client_secret`. The response carries the new plaintext secret (the admin UI shows it once).
pub async fn rotate_client_secret(clients: &OryClients, id: &str) -> Result<OAuth2Client> {
    let patch = vec![ory_client::models::JsonPatch {
        from: None,
        op: ory_client::models::json_patch::OpEnum::Replace,
        path: "/client_secret".to_string(),
        value: Some(Some(serde_json::Value::String(generate_client_secret()))),
    }];
    o_auth2_api::patch_o_auth2_client(&clients.hydra_admin, id, patch)
        .await
        .map_err(|e| anyhow::anyhow!("hydra rotate_client_secret failed: {e}"))
}

/// Enumerate Hydra consent sessions with an active grant for `subject`, paging the `Link: rel="next"` header
/// until exhausted (drives the account-deletion webhook fan-out, so the list must not be silently capped).
/// Driven via the raw client because the SDK helper drops the Link header; bounded by [`CONSENT_LIST_MAX_PAGES`].
const CONSENT_LIST_PAGE_SIZE: i64 = 250;
const CONSENT_LIST_MAX_PAGES: usize = 50; // 12,500 grants per subject, well past any realistic case.

pub async fn list_consent_sessions_by_subject(
    clients: &OryClients,
    subject: &str,
) -> Result<Vec<OAuth2ConsentSession>> {
    let cfg = &clients.hydra_admin;
    let base = format!(
        "{}/admin/oauth2/auth/sessions/consent",
        cfg.base_path.trim_end_matches('/')
    );

    let mut out: Vec<OAuth2ConsentSession> = Vec::new();
    let mut page_token: Option<String> = None;
    for page in 0..CONSENT_LIST_MAX_PAGES {
        let mut req = cfg.client.get(&base).query(&[
            ("subject", subject.to_string()),
            ("page_size", CONSENT_LIST_PAGE_SIZE.to_string()),
        ]);
        if let Some(tok) = page_token.as_deref() {
            req = req.query(&[("page_token", tok)]);
        }
        if let Some(token) = cfg.bearer_access_token.as_ref() {
            req = req.bearer_auth(token);
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
        let batch: Vec<OAuth2ConsentSession> = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("hydra list_consent_sessions decode: {e}"))?;
        let batch_empty = batch.is_empty();
        out.extend(batch);
        match next {
            Some(tok) if !batch_empty => page_token = Some(tok),
            _ => return Ok(out),
        }
        if page + 1 == CONSENT_LIST_MAX_PAGES {
            tracing::error!(
                subject,
                pages = CONSENT_LIST_MAX_PAGES,
                "hydra consent-session pagination hit safety cap — webhook fanout may be incomplete",
            );
        }
    }
    Ok(out)
}

/// Parse `Link: <…?page_token=XYZ&…>; rel="next"` and return the
/// `page_token` value. Hydra emits the standard RFC 5988 shape; we
/// only care about the `next` relation.
fn next_link(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let raw = headers.get("link").and_then(|v| v.to_str().ok())?;
    for part in raw.split(',') {
        let part = part.trim();
        // Skip malformed parts; aborting with None would read as end-of-pagination.
        let Some((url_part, params)) = part.split_once(';') else {
            continue;
        };
        if !params.contains("rel=\"next\"") && !params.contains("rel=next") {
            continue;
        }
        let url_str = url_part
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>');
        let url = url::Url::parse(url_str).ok()?;
        return url
            .query_pairs()
            .find(|(k, _)| k == "page_token")
            .map(|(_, v)| v.into_owned());
    }
    None
}

/// Revoke every consent grant for `subject` and invalidate associated
/// OAuth2 access tokens. Best-effort during account deletion: failures log and the flow proceeds (the
/// source-of-truth Kratos identity determines whether the user can sign back in).
pub async fn revoke_consent_sessions_for_subject(
    clients: &OryClients,
    subject: &str,
) -> Result<()> {
    o_auth2_api::revoke_o_auth2_consent_sessions(
        &clients.hydra_admin,
        Some(subject),
        None,
        None,
        Some(true),
    )
    .await
    .map_err(|e| anyhow::anyhow!("hydra revoke_consent_sessions failed: {e}"))
}

/// Revoke all consent grants for a single (subject, client) pair.
/// Powers the per-app "Revoke access" action on `/settings/authorized-apps`.
/// Hydra has no per-scope revocation; reducing a grant needs the user to re-consent with a narrower scope set.
pub async fn revoke_consent_sessions_for_client(
    clients: &OryClients,
    subject: &str,
    client_id: &str,
) -> Result<()> {
    // `client` and `all` are mutually exclusive in Hydra v2 (passing both is a 400); with a client named, leave `all` unset.
    o_auth2_api::revoke_o_auth2_consent_sessions(
        &clients.hydra_admin,
        Some(subject),
        Some(client_id),
        None,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("hydra revoke_consent_sessions_for_client failed: {e}"))
}

/// Health probes, same shape as Kratos.
pub async fn health_alive(clients: &OryClients) -> Result<()> {
    super::probe_health(&clients.hydra_admin, "/health/alive").await
}

pub async fn health_ready(clients: &OryClients) -> Result<()> {
    super::probe_health(&clients.hydra_admin, "/health/ready").await
}

/// Fetch the Hydra build version.
pub async fn version(clients: &OryClients) -> Result<String> {
    let v = ory_client::apis::metadata_api::get_version(&clients.hydra_admin)
        .await
        .map_err(|e| anyhow::anyhow!("hydra get_version failed: {e}"))?;
    Ok(v.version)
}

/// One row of the configuration page's JWKS table: the public signing keys Hydra advertises at its `jwks_uri`.
pub struct JwkSummary {
    pub kid: String,
    pub alg: String,
    pub kty: String,
    pub use_: String,
}

/// Fetch Hydra's public signing keys (the `jwks_uri` contents) and project
/// each down to the fields the admin UI shows. Order is whatever Hydra
/// returns.
pub async fn signing_keys(clients: &OryClients) -> Result<Vec<JwkSummary>> {
    let set = ory_client::apis::wellknown_api::discover_json_web_keys(&clients.hydra_public)
        .await
        .map_err(|e| anyhow::anyhow!("hydra discover_json_web_keys failed: {e}"))?;
    Ok(set
        .keys
        .unwrap_or_default()
        .into_iter()
        .map(|k| JwkSummary {
            kid: k.kid,
            alg: k.alg,
            kty: k.kty,
            use_: k.r#use,
        })
        .collect())
}

/// Generate a random client secret. 40 alphanumerics is about 238 bits of entropy, well above the OAuth2 spec's recommendation.
fn generate_client_secret() -> String {
    use rand::distr::Alphanumeric;
    use rand::Rng;
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    // --- device-token error mapping --------------------------------------

    #[test]
    fn maps_device_token_errors() {
        assert!(matches!(
            map_device_token_error("authorization_pending"),
            DeviceTokenOutcome::Pending
        ));
        assert!(matches!(
            map_device_token_error("slow_down"),
            DeviceTokenOutcome::SlowDown
        ));
        assert!(matches!(
            map_device_token_error("expired_token"),
            DeviceTokenOutcome::Expired
        ));
        assert!(matches!(
            map_device_token_error("access_denied"),
            DeviceTokenOutcome::Denied
        ));
        // Unknown / consumed-grant codes collapse to a dead flow.
        assert!(matches!(
            map_device_token_error("invalid_grant"),
            DeviceTokenOutcome::Expired
        ));
    }

    // --- id_token validation ---------------------------------------------

    const TEST_ISS: &str = "http://hydra.test:4444";
    const TEST_CLIENT: &str = "forseti-linux-pam";

    // PKCS#8 RSA-2048 private key used only to mint test id_tokens.
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwVqAC9L0r0uJ2\n\
JDPk9e2axX7YSYYfc7SxW85iWv9XpBDHuzZ9vMsl532kQY5PT7f4FpdZSrPL1QLm\n\
+9EFh2VYBm17qbFwFAbEvvymBZ8f4NNQI/xXpCRX/X4E7Di0U3IdZsyJlAqLQD8a\n\
hUWRdG1gAOhwe1OyersaRE6QoH4Arce4oY9pAtduKbio6VZSsItNZJWJ7yISGlnS\n\
xK0kU7M01lvnXWAFfNhDo6E9QBtHuprfiAUqiqfMHd0tDvy01t4+ytSY6l/INHW/\n\
Td4JsjWSc+10AJxFGYU/GrYGF9NENmZIPxIYH5kxsVUEOI3gjGfp+x9eDjRjtJ/+\n\
vAmlXx2XAgMBAAECggEAH0Zl39BXYtfmuWxnVdL2Xs5rVmIH6zki0ZgGTTR1eC5N\n\
mZcPLZLX9vONOZ405sUtTE95bWlN5Td06dG8uz3N0CRns5ifs1Ch+LAk8C8sD0PZ\n\
RqvzO/oNRhvcB3R8BCOOqD9MxJPgoNz2tDXx5j/fjDjtANImwI968sgtpQIKBwV/\n\
qrhBEJ4vVLqDiSTNtdFsS73evgFYylVUfigFTd4xDqPc6LBMd1DscLL1jTSjiX03\n\
VmWMUVt4LWhuE89GzuXVZehx1nO6HRqLNpSPjoxX+3d+1+aw/QkFhj5R4qBXd2XV\n\
gjFD4bMslO6tLKXqicBCg9eGf3ixKpNHZdFCYMHHYQKBgQDoqPoyA+LKjhVuacSY\n\
8/vXKH4XLfvpIUZs74VRgqnvp7854F1MxudPsXoy/GxmUzyTCMQpR4E2hoUPsTT2\n\
q8pEcNZoh9jEhmKOwuoEV6Yfm2OmPucqBp+SK5/l/wrPuJC/Ao/UCxb3YaeXqdLt\n\
qEF5SJ6Th+L28tEXYsdMloWl4QKBgQDCBzsvm/XXfX2dmvdwWR6pCk1kRiqCDr7J\n\
KhxLyZUVrDDEp2vK+BNaWaN5G4vslfJ8+RINOTY6bETvLP8nbnI5wxQFi61IvFDd\n\
nJ9E3+Sg5hr20iHZ2kPu+UYxkES+kiuyFehfNZcfl2K/q2aJKB7KHJkM9yVsK7Yn\n\
LrCUcdtCdwKBgQDAdnhyQ3Cq6xqjee9eMAcXF7Im7q1DT3l4yDNbGGIHlJbGA+pq\n\
huf2rvRNlS7+/sBPSaMsGrCzMFiGgKs1myr5rvZPBoG1IQ4K1wbLjM4pu1uVvNdx\n\
loUOX/QoSPDioOVsfWwJlxrqjegbuCp62wM+l2pG1NRWQMvjMp13p9TrQQKBgQCB\n\
D6BN3dbcXOvWjwLyJ0WeuWybO5UA59/+HVWvD8psHRpfZOHto6/z1FZJs4oSd/dR\n\
K7fXNewdVnFQCsU6LFwskddajPtZu3Gqx4ilnqwMXqMm9MVxjJ7NceBADa+8d6w7\n\
DBmCYzo/2EnmJpPQvfAlDnq7xhWNa1IBpCvuwgFPpwKBgBeqbZPSX+H7OQZwK9uo\n\
tMT4rTN4iCzBd3OQryd+UVF5dlGZSM/ahPo0sVEoIc5Do6qKB+hs92alKJsr97b+\n\
SRZ/w8gQ2ALLGaApskC1zn5ojdqqjTvXWmW9bccCeGYJ8yOu4oWP/QLkNzM4WVKA\n\
3SmfuVDc+5r3d6JFhgQeOMb1\n\
-----END PRIVATE KEY-----\n";

    // base64url RSA modulus/exponent for the key above (the JWKS Hydra would publish for it).
    const TEST_N: &str = "sFagAvS9K9LidiQz5PXtmsV-2EmGH3O0sVvOYlr_V6QQx7s2fbzLJed9pEGOT0-3-BaXWUqzy9UC5vvRBYdlWAZte6mxcBQGxL78pgWfH-DTUCP8V6QkV_1-BOw4tFNyHWbMiZQKi0A_GoVFkXRtYADocHtTsnq7GkROkKB-AK3HuKGPaQLXbim4qOlWUrCLTWSVie8iEhpZ0sStJFOzNNZb511gBXzYQ6OhPUAbR7qa34gFKoqnzB3dLQ78tNbePsrUmOpfyDR1v03eCbI1knPtdACcRRmFPxq2BhfTRDZmSD8SGB-ZMbFVBDiN4Ixn6fsfXg40Y7Sf_rwJpV8dlw";
    const TEST_E: &str = "AQAB";
    const TEST_KID: &str = "test-kid";

    fn test_jwks() -> ory_client::models::JsonWebKeySet {
        let mut k = ory_client::models::JsonWebKey::new(
            "RS256".into(),
            TEST_KID.into(),
            "RSA".into(),
            "sig".into(),
        );
        k.n = Some(TEST_N.into());
        k.e = Some(TEST_E.into());
        ory_client::models::JsonWebKeySet {
            keys: Some(vec![k]),
        }
    }

    #[derive(serde::Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        azp: String,
        exp: i64,
        iat: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        acr: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        amr: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_time: Option<i64>,
    }

    impl Default for TestClaims {
        fn default() -> Self {
            let now = chrono::Utc::now().timestamp();
            Self {
                sub: "ident-123".into(),
                iss: TEST_ISS.into(),
                aud: TEST_CLIENT.into(),
                azp: TEST_CLIENT.into(),
                exp: now + 300,
                iat: now,
                acr: Some("aal2".into()),
                amr: vec!["pwd".into(), "totp".into()],
                auth_time: Some(now),
            }
        }
    }

    fn mint(claims: &TestClaims, alg: jsonwebtoken::Algorithm) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let mut header = Header::new(alg);
        header.kid = Some(TEST_KID.into());
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        encode(&header, claims, &key).unwrap()
    }

    fn verify(token: &str) -> Result<IdTokenClaims> {
        verify_id_token_with_jwks(token, &test_jwks(), TEST_ISS, TEST_CLIENT, 120)
    }

    #[test]
    fn id_token_valid_passes() {
        let claims = TestClaims::default();
        let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
        let out = verify(&tok).expect("valid token");
        assert_eq!(out.sub, "ident-123");
        assert_eq!(out.acr.as_deref(), Some("aal2"));
        assert_eq!(out.amr, vec!["pwd".to_string(), "totp".to_string()]);
        assert!(out.auth_time.is_some());
    }

    #[test]
    fn id_token_alg_none_rejected() {
        // A `none`-alg token (unsigned). jsonwebtoken won't mint `none`, so
        // hand-build the compact form.
        use base64::Engine;
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header = b64(br#"{"alg":"none","kid":"test-kid","typ":"JWT"}"#);
        let claims = TestClaims::default();
        let payload = b64(serde_json::to_vec(&claims).unwrap().as_slice());
        let tok = format!("{header}.{payload}.");
        let err = verify(&tok).unwrap_err().to_string();
        assert!(err.contains("alg") || err.contains("RS256"), "got: {err}");
    }

    #[test]
    fn id_token_wrong_aud_rejected() {
        let claims = TestClaims {
            aud: "some-other-client".into(),
            ..TestClaims::default()
        };
        let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
        assert!(verify(&tok).is_err());
    }

    #[test]
    fn id_token_extra_aud_rejected() {
        // aud contains our client plus another party. jsonwebtoken accepts the
        // membership, but the exact-aud pin must reject the multi-audience token.
        #[derive(serde::Serialize)]
        struct MultiAud {
            sub: String,
            iss: String,
            aud: Vec<String>,
            azp: String,
            exp: i64,
            iat: i64,
        }
        use jsonwebtoken::{encode, EncodingKey, Header};
        let now = chrono::Utc::now().timestamp();
        let claims = MultiAud {
            sub: "ident-123".into(),
            iss: TEST_ISS.into(),
            aud: vec![TEST_CLIENT.into(), "other-rp".into()],
            azp: TEST_CLIENT.into(),
            exp: now + 300,
            iat: now,
        };
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.into());
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        let tok = encode(&header, &claims, &key).unwrap();
        let err = verify(&tok).unwrap_err().to_string();
        assert!(err.contains("aud"), "got: {err}");
    }

    #[test]
    fn id_token_wrong_azp_rejected() {
        // aud correct (our client) but azp points elsewhere; the authorized-party pin must still reject.
        let claims = TestClaims {
            azp: "evil-client".into(),
            ..TestClaims::default()
        };
        let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
        let err = verify(&tok).unwrap_err().to_string();
        assert!(err.contains("azp"), "got: {err}");
    }

    #[test]
    fn id_token_wrong_iss_rejected() {
        let claims = TestClaims {
            iss: "http://evil.test".into(),
            ..TestClaims::default()
        };
        let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
        assert!(verify(&tok).is_err());
    }

    #[test]
    fn id_token_expired_rejected() {
        let now = chrono::Utc::now().timestamp();
        // Past exp, beyond jsonwebtoken's 60s leeway.
        let claims = TestClaims {
            exp: now - 600,
            iat: now - 900,
            ..TestClaims::default()
        };
        let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
        assert!(verify(&tok).is_err());
    }

    #[test]
    fn id_token_stale_iat_rejected() {
        let now = chrono::Utc::now().timestamp();
        // Still inside exp, but iat is older than the 120s window.
        let claims = TestClaims {
            iat: now - 300,
            exp: now + 300,
            ..TestClaims::default()
        };
        let tok = mint(&claims, jsonwebtoken::Algorithm::RS256);
        let err = verify(&tok).unwrap_err().to_string();
        assert!(err.contains("stale") || err.contains("iat"), "got: {err}");
    }

    #[test]
    fn id_token_unknown_kid_rejected() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("not-in-jwks".into());
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        let tok = encode(&header, &TestClaims::default(), &key).unwrap();
        let err = verify(&tok).unwrap_err().to_string();
        assert!(err.contains("kid"), "got: {err}");
    }

    #[test]
    fn next_link_extracts_page_token() {
        let mut h = HeaderMap::new();
        h.insert(
            "link",
            HeaderValue::from_static(
                "<https://hydra/admin/oauth2/auth/sessions/consent?page_token=abc123&page_size=250>; rel=\"next\"",
            ),
        );
        assert_eq!(next_link(&h).as_deref(), Some("abc123"));
    }

    #[test]
    fn next_link_handles_multiple_relations() {
        let mut h = HeaderMap::new();
        h.insert(
            "link",
            HeaderValue::from_static(
                "<https://hydra/prev?page_token=xyz>; rel=\"prev\", <https://hydra/next?page_token=def>; rel=\"next\"",
            ),
        );
        assert_eq!(next_link(&h).as_deref(), Some("def"));
    }

    #[test]
    fn next_link_skips_bare_part_before_next() {
        let mut h = HeaderMap::new();
        h.insert(
            "link",
            HeaderValue::from_static(
                "<https://hydra/first?page_token=xyz>, <https://hydra/next?page_token=def>; rel=\"next\"",
            ),
        );
        assert_eq!(next_link(&h).as_deref(), Some("def"));
    }

    #[test]
    fn next_link_returns_none_when_only_prev() {
        let mut h = HeaderMap::new();
        h.insert(
            "link",
            HeaderValue::from_static("<https://hydra/prev?page_token=xyz>; rel=\"prev\""),
        );
        assert_eq!(next_link(&h), None);
    }

    #[test]
    fn next_link_missing_header() {
        let h = HeaderMap::new();
        assert_eq!(next_link(&h), None);
    }
}
