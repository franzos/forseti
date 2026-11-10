//! Upstream issuer discovery (OIDC Discovery 1.0), code exchange and JWKS
//! fetch. Every request goes through [`crate::outbound::client`]; parsing and
//! validation are pure functions.

use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::outbound::{self, FetchError};

const TIMEOUT: Duration = Duration::from_secs(10);
const BODY_LIMIT: usize = 64 * 1024;

/// The endpoints of an issuer whose discovery document passed validation.
#[derive(Debug, Clone)]
pub(crate) struct Provider {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
}

#[derive(Deserialize)]
struct Document {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
}

/// A JSON Web Key Set (RFC 7517), keeping only the members ID token
/// validation reads.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// `<issuer>/.well-known/openid-configuration`, appended to the issuer's path
/// (OIDC Discovery 4).
fn discovery_url(issuer: &Url) -> Url {
    let mut url = issuer.clone();
    let path = format!(
        "{}/.well-known/openid-configuration",
        issuer.path().trim_end_matches('/')
    );
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn endpoint(raw: &str, issuer: &Url, allow_private: bool) -> Result<Url, &'static str> {
    let url = Url::parse(raw).map_err(|_| "discovery endpoint is not a URL")?;
    outbound::check_target(&url, allow_private).map_err(|_| "discovery endpoint not allowed")?;
    if url.origin() != issuer.origin() {
        return Err("discovery endpoint is not on the issuer's origin");
    }
    Ok(url)
}

/// Validate a discovery document fetched for `issuer`: `issuer` must match
/// exactly (OIDC Discovery 4.3), every endpoint must pass the outbound check
/// and share the issuer's origin, and advertised PKCE methods must include
/// `S256`.
fn parse_document(
    issuer: &Url,
    configured: &str,
    body: &[u8],
    allow_private: bool,
) -> Result<Provider, &'static str> {
    let doc: Document =
        serde_json::from_slice(body).map_err(|_| "discovery document is malformed")?;
    if doc.issuer != configured {
        return Err("discovery issuer does not match");
    }
    if doc
        .code_challenge_methods_supported
        .is_some_and(|m| !m.iter().any(|m| m == "S256"))
    {
        return Err("issuer does not support PKCE S256");
    }
    Ok(Provider {
        issuer: doc.issuer,
        authorization_endpoint: endpoint(&doc.authorization_endpoint, issuer, allow_private)?,
        token_endpoint: endpoint(&doc.token_endpoint, issuer, allow_private)?,
        jwks_uri: endpoint(&doc.jwks_uri, issuer, allow_private)?,
    })
}

fn parse_token_response(body: &[u8]) -> Result<String, &'static str> {
    let resp: TokenResponse =
        serde_json::from_slice(body).map_err(|_| "token response has no id_token")?;
    if resp.id_token.is_empty() {
        return Err("token response has no id_token");
    }
    Ok(resp.id_token)
}

fn reason(url: &Url, e: FetchError) -> &'static str {
    match e {
        FetchError::Transport(m) => {
            tracing::warn!(url = %url, error = %m, "oidc_rp: upstream request failed");
            "upstream request failed"
        }
        FetchError::Status(_) => "upstream returned an error status",
        FetchError::TooLarge => "upstream response too large",
    }
}

async fn get_json(url: &Url, allow_private: bool) -> Result<Vec<u8>, &'static str> {
    outbound::check_target(url, allow_private).map_err(|_| "upstream URL not allowed")?;
    let client = outbound::client(allow_private);
    let resp = outbound::get_ok(client, url.as_str(), Some("application/json"), TIMEOUT)
        .await
        .map_err(|e| reason(url, e))?;
    outbound::read_capped(resp, BODY_LIMIT)
        .await
        .map_err(|e| reason(url, e))
}

/// Fetch and validate the discovery document of `issuer` (the configured
/// string, compared verbatim).
pub(crate) async fn discover(issuer: &str, allow_private: bool) -> Result<Provider, &'static str> {
    let issuer_url = Url::parse(issuer).map_err(|_| "issuer is not a URL")?;
    let body = get_json(&discovery_url(&issuer_url), allow_private).await?;
    parse_document(&issuer_url, issuer, &body, allow_private)
}

/// Redeem `code` at the token endpoint as a public client (RFC 6749 4.1.3,
/// RFC 7636 4.5) and return the `id_token`; nothing else in the response is
/// read. Error bodies are never surfaced.
pub(crate) async fn exchange_code(
    provider: &Provider,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
    allow_private: bool,
) -> Result<String, &'static str> {
    let url = &provider.token_endpoint;
    outbound::check_target(url, allow_private).map_err(|_| "upstream URL not allowed")?;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    let (status, body) = outbound::post_form(
        outbound::client(allow_private),
        url.as_str(),
        &form,
        TIMEOUT,
        BODY_LIMIT,
    )
    .await
    .map_err(|e| reason(url, e))?;
    if !(200..300).contains(&status) {
        return Err("token endpoint refused the code");
    }
    parse_token_response(&body)
}

/// The issuer's current key set, fetched on every call.
pub(crate) async fn fetch_jwks(jwks_uri: &Url, allow_private: bool) -> Result<Jwks, &'static str> {
    let body = get_json(jwks_uri, allow_private).await?;
    serde_json::from_slice(&body).map_err(|_| "JWKS is malformed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://git.example.com/";

    fn doc(overrides: serde_json::Value) -> Vec<u8> {
        let mut d = json!({
            "issuer": ISSUER,
            "authorization_endpoint": "https://git.example.com/login/oauth/authorize",
            "token_endpoint": "https://git.example.com/login/oauth/access_token",
            "jwks_uri": "https://git.example.com/login/oauth/keys",
            "code_challenge_methods_supported": ["plain", "S256"],
        });
        for (k, v) in overrides.as_object().unwrap() {
            if v.is_null() {
                d.as_object_mut().unwrap().remove(k);
            } else {
                d[k] = v.clone();
            }
        }
        serde_json::to_vec(&d).unwrap()
    }

    fn parse(issuer: &str, body: &[u8], allow_private: bool) -> Result<Provider, &'static str> {
        parse_document(&Url::parse(issuer).unwrap(), issuer, body, allow_private)
    }

    #[test]
    fn discovery_url_appends_to_issuer_path() {
        let wk = |raw: &str| discovery_url(&Url::parse(raw).unwrap()).to_string();
        assert_eq!(
            wk("https://git.example.com"),
            "https://git.example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            wk("https://git.example.com/"),
            "https://git.example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            wk("http://host:8092/default"),
            "http://host:8092/default/.well-known/openid-configuration"
        );
        assert_eq!(
            wk("https://id.example.com/realms/a/"),
            "https://id.example.com/realms/a/.well-known/openid-configuration"
        );
    }

    #[test]
    fn valid_document_parses() {
        let p = parse(ISSUER, &doc(json!({})), false).expect("valid");
        assert_eq!(p.issuer, ISSUER);
        assert_eq!(p.token_endpoint.path(), "/login/oauth/access_token");
        assert_eq!(p.jwks_uri.path(), "/login/oauth/keys");
    }

    #[test]
    fn issuer_must_match_exactly() {
        for other in [
            "https://git.example.com",
            "https://evil.example.com/",
            "https://git.example.com/x",
        ] {
            assert_eq!(
                parse(ISSUER, &doc(json!({"issuer": other})), false).unwrap_err(),
                "discovery issuer does not match",
                "{other}"
            );
        }
    }

    #[test]
    fn cross_origin_endpoint_refused() {
        for (field, url) in [
            (
                "authorization_endpoint",
                "https://evil.example.com/authorize",
            ),
            ("token_endpoint", "https://git.example.com:8443/token"),
            ("jwks_uri", "http://git.example.com/keys"),
        ] {
            assert!(
                parse(ISSUER, &doc(json!({ field: url })), true).is_err(),
                "{field} {url}"
            );
        }
    }

    #[test]
    fn endpoint_must_pass_outbound_check() {
        let issuer = "https://10.0.0.5/";
        let body = doc(json!({
            "issuer": issuer,
            "authorization_endpoint": "https://10.0.0.5/a",
            "token_endpoint": "https://10.0.0.5/t",
            "jwks_uri": "https://10.0.0.5/k",
        }));
        assert_eq!(
            parse(issuer, &body, false).unwrap_err(),
            "discovery endpoint not allowed"
        );
        assert!(parse(issuer, &body, true).is_ok());
    }

    #[test]
    fn s256_required_when_methods_advertised() {
        assert_eq!(
            parse(
                ISSUER,
                &doc(json!({"code_challenge_methods_supported": ["plain"]})),
                false
            )
            .unwrap_err(),
            "issuer does not support PKCE S256"
        );
        assert!(
            parse(
                ISSUER,
                &doc(json!({"code_challenge_methods_supported": []})),
                false
            )
            .is_err()
        );
        assert!(
            parse(
                ISSUER,
                &doc(json!({"code_challenge_methods_supported": null})),
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn missing_endpoint_is_malformed() {
        assert_eq!(
            parse(ISSUER, &doc(json!({"jwks_uri": null})), false).unwrap_err(),
            "discovery document is malformed"
        );
    }

    #[test]
    fn token_response_reads_only_id_token() {
        let body = json!({"access_token": "a", "token_type": "bearer", "id_token": "x.y.z"});
        assert_eq!(
            parse_token_response(&serde_json::to_vec(&body).unwrap()).unwrap(),
            "x.y.z"
        );
        assert!(parse_token_response(br#"{"access_token":"a"}"#).is_err());
        assert!(parse_token_response(br#"{"id_token":""}"#).is_err());
    }

    #[test]
    fn jwks_keeps_unknown_key_types() {
        let jwks: Jwks = serde_json::from_value(json!({"keys": [
            {"kty": "RSA", "kid": "r", "use": "sig", "n": "AQ", "e": "AQAB"},
            {"kty": "OKP", "crv": "Ed25519", "x": "AA"},
        ]}))
        .unwrap();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].use_.as_deref(), Some("sig"));
        assert!(jwks.keys[1].kid.is_none());
    }
}
