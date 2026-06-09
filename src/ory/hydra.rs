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

/// Accept a Hydra login challenge for the given Kratos subject (identity ID).
/// `amr` / `acr` mirror the OIDC claims downstream relying parties see;
/// `remember` extends the Hydra login session cookie so subsequent SSO
/// hits go through without re-prompting Kratos.
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

/// Accept a Hydra consent challenge with the user's chosen scope grant and
/// id_token claim payload. The `id_token_session` JSON is folded directly
/// into Hydra's `session.id_token`; callers compose it based on which
/// scopes were granted (e.g. `email`, `name`).
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

// --- Admin surface ---------------------------------------------------

/// Paginated client list. `page_token` comes from the previous page's
/// `Link: rel="next"` header. We don't surface paging metadata in the
/// SDK return; the admin UI keeps things simple (page-size only).
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

/// Replace a client. Hydra's `set_o_auth2_client` is PUT-shaped — the
/// provided body fully overrides the stored client, so callers should
/// round-trip via `get_client` first to preserve unrelated fields.
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

/// Rotate a client's secret. Hydra has no dedicated rotate endpoint —
/// we fetch the client, clear the `client_secret` field, and POST a
/// JSON Patch that asks Hydra to regenerate it. The response carries
/// the new plaintext secret (which the admin UI shows once).
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

/// Enumerate Hydra consent sessions that have an active grant for
/// `subject`. Forseti uses this during account self-deletion to drive
/// the webhook fan-out; silently capping the list would leave some
/// downstream apps unaware of the deletion. Pages via Hydra's
/// `Link: <...>; rel="next"` header until exhausted.
///
/// The SDK helper throws away both the Link header and the raw response
/// body shape, so we drive the request via the SDK's configured
/// `reqwest::Client` directly. Bounded by [`CONSENT_LIST_MAX_PAGES`] as
/// a runaway-loop guard — Hydra would have to lie about there being
/// more pages for this cap to bite.
const CONSENT_LIST_PAGE_SIZE: i64 = 250;
const CONSENT_LIST_MAX_PAGES: usize = 50; // 12,500 grants per subject — well past any realistic case.

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
        let (url_part, params) = part.split_once(';')?;
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
/// OAuth2 access tokens. Best-effort during account deletion — failures
/// log and the flow proceeds (the source-of-truth Kratos identity is
/// what really determines whether the user can sign back in).
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
/// Hydra has no per-scope revocation — the user would need to re-consent
/// with a narrower scope set to reduce a grant.
pub async fn revoke_consent_sessions_for_client(
    clients: &OryClients,
    subject: &str,
    client_id: &str,
) -> Result<()> {
    o_auth2_api::revoke_o_auth2_consent_sessions(
        &clients.hydra_admin,
        Some(subject),
        Some(client_id),
        None,
        Some(true),
    )
    .await
    .map_err(|e| anyhow::anyhow!("hydra revoke_consent_sessions_for_client failed: {e}"))
}

/// Health probes — same shape as Kratos.
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

/// One row of the configuration page's JWKS table — the public signing
/// keys Hydra advertises at its `jwks_uri`.
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

/// Generate a random client secret. 40 alphanumerics ≈ 238 bits of
/// entropy — comfortably above the OAuth2 spec's recommendation.
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
