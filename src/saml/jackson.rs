//! Thin client for the Jackson / Ory Polis bridge: the OAuth2 leg the
//! SSO flow drives, plus connection CRUD against Jackson's admin API.
//! <https://www.ory.com/docs/polis/sso-flow>

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;

use crate::config::SamlConfig;
use crate::outbound::{self, FetchError};

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
        crate::web::urlencode(dyn_client_id(org_id)),
        crate::web::urlencode(redirect_uri(self_url)),
        crate::web::urlencode(state),
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

const METADATA_LIMIT: usize = 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(10);

/// GET IdP metadata XML from an operator-supplied URL through the SSRF-guarded
/// outbound client. Errors read as a sentence fragment for the form.
pub async fn fetch_metadata(url: &str, allow_private: bool) -> Result<String, String> {
    let parsed = url::Url::parse(url).map_err(|_| "metadata URL is not a valid URL".to_string())?;
    outbound::check_target(&parsed, allow_private).map_err(|e| format!("metadata URL {e}"))?;
    let fetch_err = |e: FetchError| match e {
        FetchError::Transport(e) => format!("metadata fetch failed: {e}"),
        FetchError::Status(s) => format!("metadata URL returned HTTP {s}"),
        FetchError::TooLarge => "metadata document exceeds 1 MiB".to_string(),
    };
    let resp = outbound::get_ok(
        outbound::client(allow_private),
        parsed.as_str(),
        None,
        METADATA_TIMEOUT,
    )
    .await
    .map_err(fetch_err)?;
    let body = outbound::read_capped(resp, METADATA_LIMIT)
        .await
        .map_err(fetch_err)?;
    String::from_utf8(body).map_err(|_| "metadata document is not UTF-8".to_string())
}

pub async fn create_connection(
    cfg: &SamlConfig,
    client: &reqwest::Client,
    self_url: &str,
    org_id: &str,
    name: &str,
    metadata_xml: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/v1/connections",
        cfg.internal_url().trim_end_matches('/')
    );
    let callback = redirect_uri(self_url);
    let body = serde_json::json!({
        "tenant": org_id,
        "product": PRODUCT,
        "name": name,
        "defaultRedirectUrl": callback,
        "redirectUrl": [callback],
        "encodedRawMetadata": BASE64.encode(metadata_xml),
    });
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
        crate::web::urlencode(org_id),
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

    async fn serve_metadata(body: Vec<u8>) -> String {
        let app = axum::Router::new().route(
            "/metadata",
            axum::routing::get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/metadata")
    }

    #[tokio::test]
    async fn fetch_metadata_refuses_loopback_when_guarded() {
        for raw in [
            "https://127.0.0.1:9/metadata",
            "https://localhost/metadata",
            "https://[::1]/metadata",
            "https://10.0.0.1/metadata",
        ] {
            let err = fetch_metadata(raw, false).await.unwrap_err();
            assert!(
                err.starts_with("metadata URL ") && !err.contains("returned HTTP"),
                "{raw} got: {err}"
            );
        }
        let url = serve_metadata(b"<EntityDescriptor/>".to_vec()).await;
        assert!(fetch_metadata(&url, false).await.is_err());
    }

    #[tokio::test]
    async fn fetch_metadata_rejects_oversize_body() {
        let url = serve_metadata(vec![b'a'; METADATA_LIMIT + 1]).await;
        assert_eq!(
            fetch_metadata(&url, true).await.unwrap_err(),
            "metadata document exceeds 1 MiB"
        );
    }

    #[tokio::test]
    async fn fetch_metadata_returns_xml_from_stub() {
        let xml = "<EntityDescriptor entityID=\"https://idp.example\"/>";
        let url = serve_metadata(xml.as_bytes().to_vec()).await;
        assert_eq!(fetch_metadata(&url, true).await.unwrap(), xml);
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
