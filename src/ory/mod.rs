//! Ory backends: [`KratosBackend`] implements `IdentityBackend` over the private wrappers in `kratos`;
//! [`HydraBackend`] carries its calls as inherent methods in `hydra` and `discovery`. Both are called over
//! plain HTTP with the workspace `reqwest`: Hydra responses deserialize straight into `crate::backend` types,
//! Kratos bodies into the private structs in `kratos_wire`, converted by `convert_identity`. Forseti talks to
//! Kratos via its public API (forwarding the user's `Cookie`) and its admin API, and to Hydra via its admin
//! API. Kratos flows are fetched as raw JSON and projected by [`crate::flow_json`].

use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use anyhow::Result;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;

#[cfg(feature = "identity-ory")]
mod convert_identity;
mod discovery;
mod hydra;
#[cfg(feature = "identity-ory")]
mod kratos;
#[cfg(feature = "identity-ory")]
mod kratos_backend;
#[cfg(feature = "identity-ory")]
mod kratos_wire;

pub use hydra::HydraBackend;
#[cfg(feature = "identity-ory")]
pub use kratos_backend::KratosBackend;
#[cfg(all(test, feature = "identity-ory"))]
pub(crate) use kratos_backend::create_unverified_test_identity;

/// One base URL plus the HTTP client used to reach it.
struct Endpoint {
    base: String,
    http: reqwest::Client,
}

impl Endpoint {
    /// A request to `base` + `path`, concatenated as given.
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http.request(method, format!("{}{path}", self.base))
    }

    /// GET against a `/health/*` endpoint: 2xx is Ok, else Err with status + truncated body.
    async fn probe_health(&self, path: &str) -> Result<()> {
        let url = format!("{}{}", self.base.trim_end_matches('/'), path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("health probe transport error ({path}): {e}"))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(anyhow::anyhow!(
            "health probe {path} returned {status}: {}",
            body.chars().take(200).collect::<String>()
        ))
    }
}

/// A failed Ory call. A 4xx/5xx is `Status`, so callers can map one code to an outcome.
#[derive(Debug)]
enum CallError {
    Transport(reqwest::Error),
    Decode(String),
    Status(StatusCode),
}

impl CallError {
    fn is_not_found(&self) -> bool {
        matches!(self, CallError::Status(s) if *s == StatusCode::NOT_FOUND)
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Transport(e) => write!(f, "error in reqwest: {e}"),
            CallError::Decode(e) => write!(f, "error in serde: {e}"),
            CallError::Status(s) => write!(f, "error in response: status code {s}"),
        }
    }
}

/// Send `req`; anything but a 4xx/5xx counts as success.
async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response, CallError> {
    let resp = req.send().await.map_err(CallError::Transport)?;
    let status = resp.status();
    if status.is_client_error() || status.is_server_error() {
        resp.text().await.map_err(CallError::Transport)?;
        return Err(CallError::Status(status));
    }
    Ok(resp)
}

/// [`send`], then decode a JSON body. A non-JSON `Content-Type` is a decode error.
async fn send_json<T: DeserializeOwned>(req: reqwest::RequestBuilder) -> Result<T, CallError> {
    let resp = send(req).await?;
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = resp.text().await.map_err(CallError::Transport)?;
    if !(content_type.starts_with("application") && content_type.contains("json")) {
        return Err(CallError::Decode(format!(
            "Received `{content_type}` content type response that cannot be converted to JSON"
        )));
    }
    serde_json::from_str(&body).map_err(|e| CallError::Decode(e.to_string()))
}

/// Hydra endpoints pinned at startup, held behind `Arc` by [`HydraBackend`].
struct OryClients {
    /// Browser-facing Hydra OAuth2 public endpoint.
    hydra_public: Endpoint,
    /// Server-only Hydra admin API (login/consent/logout challenges).
    hydra_admin: Endpoint,
}

impl OryClients {
    fn from_config(cfg: &AppConfig) -> Arc<OryClients> {
        Arc::new(OryClients::new(&cfg.hydra.public_url, &cfg.hydra.admin_url))
    }

    fn new(public: &str, admin: &str) -> OryClients {
        let http = hydra_http();
        OryClients {
            hydra_public: Endpoint {
                base: public.to_string(),
                http: http.clone(),
            },
            hydra_admin: Endpoint {
                base: admin.to_string(),
                http,
            },
        }
    }
}

/// One client (one pool, one timeout) for both Hydra endpoints. Both are operator-configured,
/// so this is not the SSRF-guarded `outbound` client.
fn hydra_http() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client builds")
}

/// Kratos endpoints pinned at startup, held behind `Arc` by [`KratosBackend`].
#[cfg(feature = "identity-ory")]
struct KratosClients {
    /// Browser-facing Kratos public API (used with forwarded cookies).
    kratos_public: Endpoint,
    /// Server-only Kratos admin API.
    kratos_admin: Endpoint,
}

#[cfg(feature = "identity-ory")]
impl KratosClients {
    fn from_config(cfg: &AppConfig) -> Arc<KratosClients> {
        Arc::new(KratosClients::new(
            &cfg.kratos.public_url,
            &cfg.kratos.admin_url,
        ))
    }

    fn new(public: &str, admin: &str) -> KratosClients {
        let http = kratos_http();
        KratosClients {
            kratos_public: Endpoint {
                base: public.to_string(),
                http: http.clone(),
            },
            kratos_admin: Endpoint {
                base: admin.to_string(),
                http,
            },
        }
    }
}

/// One client (one pool, one timeout) for both Kratos endpoints; every page calls `whoami`.
#[cfg(feature = "identity-ory")]
fn kratos_http() -> reqwest::Client {
    // Redirects are followed: the admin `/schemas` 307s to the public endpoint.
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client builds")
}

/// Both backends over clients pointed at the given base URLs, for tests without an `AppConfig`.
#[cfg(all(test, feature = "identity-ory"))]
pub(crate) fn test_backends(
    kratos_public: &str,
    kratos_admin: &str,
    hydra_public: &str,
    hydra_admin: &str,
) -> (Arc<KratosBackend>, Arc<HydraBackend>) {
    (
        Arc::new(KratosBackend {
            clients: Arc::new(KratosClients::new(kratos_public, kratos_admin)),
            https: false,
        }),
        Arc::new(HydraBackend {
            clients: Arc::new(OryClients::new(hydra_public, hydra_admin)),
        }),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn urlencode_form_encodes_path_segments() {
        for (input, want) in [
            ("", ""),
            ("a b", "a+b"),
            ("a+b", "a%2Bb"),
            ("a/b?c=d&e", "a%2Fb%3Fc%3Dd%26e"),
            (
                "ünï©ödé 日本",
                "%C3%BCn%C3%AF%C2%A9%C3%B6d%C3%A9+%E6%97%A5%E6%9C%AC",
            ),
            ("~-_.*", "%7E-_.*"),
            ("%20", "%2520"),
        ] {
            assert_eq!(crate::web::urlencode(input), want, "input {input:?}");
        }
    }
}
