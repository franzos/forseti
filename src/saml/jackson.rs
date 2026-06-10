//! Thin client for the Jackson / Ory Polis bridge: the OAuth2 leg the
//! SSO flow drives, plus connection CRUD against Jackson's admin API.
//! <https://www.ory.com/docs/polis/sso-flow>

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Deserialize;

use crate::config::SamlConfig;

pub const PRODUCT: &str = "forseti";

/// Jackson's dynamic-client convention: tenant/product encoded into the
/// client_id, paired with the instance-wide secret verifier.
pub fn dyn_client_id(org_id: &str) -> String {
    format!("tenant={org_id}&product={PRODUCT}")
}

pub fn redirect_uri(self_url: &str) -> String {
    format!("{}/sso/callback", self_url.trim_end_matches('/'))
}

/// Browser-facing authorize URL (`jackson_url`, not the internal override).
pub fn authorize_url(cfg: &SamlConfig, self_url: &str, org_id: &str, state: &str) -> String {
    // No PKCE: the token endpoint is an internal server-to-server call bound
    // by the shared client_secret_verifier, not a public client.
    let base = cfg.jackson_url.trim_end_matches('/');
    format!(
        "{base}/api/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&state={}",
        ory_client::apis::urlencode(dyn_client_id(org_id)),
        ory_client::apis::urlencode(redirect_uri(self_url)),
        ory_client::apis::urlencode(state),
    )
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Bounded snippet of an upstream error body — a misbehaving bridge must not flood the logs.
async fn error_body(resp: reqwest::Response) -> String {
    resp.text()
        .await
        .unwrap_or_default()
        .chars()
        .take(500)
        .collect()
}

/// Profile shape returned by Jackson's userinfo endpoint.
#[derive(Debug, Deserialize)]
pub struct JacksonProfile {
    #[serde(default)]
    /// SAML subject (NameID) — the durable, email-independent link key.
    pub id: String,
    pub email: String,
    #[serde(default, rename = "firstName")]
    pub first_name: String,
    #[serde(default, rename = "lastName")]
    pub last_name: String,
}

pub async fn exchange_code(
    cfg: &SamlConfig,
    client: &reqwest::Client,
    self_url: &str,
    org_id: &str,
    code: &str,
) -> anyhow::Result<String> {
    let url = format!(
        "{}/api/oauth/token",
        cfg.internal_url().trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", dyn_client_id(org_id).as_str()),
            ("client_secret", &*cfg.client_secret_verifier),
            ("redirect_uri", redirect_uri(self_url).as_str()),
            ("code", code),
        ])
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("jackson token exchange transport error: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = error_body(resp).await;
        return Err(anyhow::anyhow!(
            "jackson token exchange returned {status}: {body}"
        ));
    }
    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("jackson token response decode failed: {e}"))?;
    Ok(token.access_token)
}

pub async fn userinfo(
    cfg: &SamlConfig,
    client: &reqwest::Client,
    access_token: &str,
) -> anyhow::Result<JacksonProfile> {
    let url = format!(
        "{}/api/oauth/userinfo",
        cfg.internal_url().trim_end_matches('/')
    );
    let resp = client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("jackson userinfo transport error: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = error_body(resp).await;
        return Err(anyhow::anyhow!(
            "jackson userinfo returned {status}: {body}"
        ));
    }
    resp.json()
        .await
        .map_err(|e| anyhow::anyhow!("jackson userinfo decode failed: {e}"))
}

/// IdP metadata input for connection creation: raw XML (base64-encoded on
/// the wire as `encodedRawMetadata`) or a URL Jackson fetches itself.
#[derive(Debug)]
pub enum MetadataInput {
    RawXml(String),
    Url(String),
}

pub async fn create_connection(
    cfg: &SamlConfig,
    client: &reqwest::Client,
    self_url: &str,
    org_id: &str,
    name: &str,
    metadata: MetadataInput,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/v1/connections",
        cfg.internal_url().trim_end_matches('/')
    );
    let callback = redirect_uri(self_url);
    let mut body = serde_json::json!({
        "tenant": org_id,
        "product": PRODUCT,
        "name": name,
        "defaultRedirectUrl": callback,
        "redirectUrl": [callback],
    });
    match metadata {
        MetadataInput::RawXml(xml) => {
            body["encodedRawMetadata"] = BASE64.encode(xml).into();
        }
        MetadataInput::Url(u) => {
            body["metadataUrl"] = u.into();
        }
    }
    let resp = client
        .post(&url)
        .header(
            "Authorization",
            format!("Api-Key {}", &*cfg.jackson_api_key),
        )
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("jackson create_connection transport error: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = error_body(resp).await;
        return Err(anyhow::anyhow!(
            "jackson create_connection returned {status}: {body}"
        ));
    }
    Ok(())
}

pub async fn delete_connection(
    cfg: &SamlConfig,
    client: &reqwest::Client,
    org_id: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/v1/connections?tenant={}&product={PRODUCT}",
        cfg.internal_url().trim_end_matches('/'),
        ory_client::apis::urlencode(org_id),
    );
    let resp = client
        .delete(&url)
        .header(
            "Authorization",
            format!("Api-Key {}", &*cfg.jackson_api_key),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("jackson delete_connection transport error: {e}"))?;
    let status = resp.status();
    // 404 = already gone; deletion is idempotent.
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    if !status.is_success() {
        let body = error_body(resp).await;
        return Err(anyhow::anyhow!(
            "jackson delete_connection returned {status}: {body}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Redacted;

    fn cfg(internal: Option<&str>) -> SamlConfig {
        SamlConfig {
            jackson_url: "http://127.0.0.1:5225".to_string(),
            jackson_internal_url: internal.map(str::to_string),
            jackson_api_key: Redacted("api-key".to_string()),
            client_secret_verifier: Redacted("verifier".to_string()),
            identity_schema_id: "default".to_string(),
            sp_entity_id: None,
        }
    }

    #[test]
    fn dyn_client_id_raw_format() {
        assert_eq!(dyn_client_id("acme"), "tenant=acme&product=forseti");
    }

    #[test]
    fn redirect_uri_trims_trailing_slash() {
        assert_eq!(
            redirect_uri("https://id.example.com/"),
            "https://id.example.com/sso/callback"
        );
        assert_eq!(
            redirect_uri("https://id.example.com"),
            "https://id.example.com/sso/callback"
        );
    }

    #[test]
    fn authorize_url_encodes_components() {
        let url = authorize_url(&cfg(None), "https://id.example.com", "acme", "st4te");
        assert!(url.starts_with("http://127.0.0.1:5225/api/oauth/authorize?response_type=code"));
        assert!(url.contains("client_id=tenant%3Dacme%26product%3Dforseti"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fid.example.com%2Fsso%2Fcallback"));
        assert!(url.contains("state=st4te"));
    }

    #[test]
    fn internal_url_falls_back_to_jackson_url() {
        assert_eq!(cfg(None).internal_url(), "http://127.0.0.1:5225");
        assert_eq!(
            cfg(Some("http://jackson:5225")).internal_url(),
            "http://jackson:5225"
        );
    }
}
