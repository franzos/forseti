//! Upstream issuer discovery (OIDC Discovery 1.0), code exchange and JWKS
//! fetch. Every request goes through [`crate::outbound::client`]; parsing and
//! validation are pure functions.

use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::outbound::{self, FetchError};

/// Per-request timeout for upstream calls; three of them fit a callback
/// inside the 30 s request timeout.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 64 * 1024;

/// The endpoints of an issuer whose discovery document passed validation.
#[derive(Debug, Clone)]
pub(crate) struct Provider {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
    /// `None` when the document does not advertise the member.
    #[cfg(feature = "identity-native")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// RFC 9207: the issuer sends `iss` with every authorization response.
    #[cfg(feature = "identity-native")]
    pub authorization_response_iss_parameter_supported: bool,
}

#[derive(Deserialize)]
struct Document {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
    // Untyped so a malformed optional member does not fail the whole document.
    #[cfg(feature = "identity-native")]
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<serde_json::Value>,
    #[cfg(feature = "identity-native")]
    #[serde(default)]
    authorization_response_iss_parameter_supported: Option<serde_json::Value>,
}

/// Which endpoints a discovery document may name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origins {
    /// Every endpoint on the issuer's origin.
    Issuer,
    /// Any origin that passes the outbound check (operator-configured issuer).
    #[cfg(feature = "identity-native")]
    Any,
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

fn endpoint(
    raw: &str,
    issuer: &Url,
    origins: Origins,
    allow_private: bool,
) -> Result<Url, &'static str> {
    let url = Url::parse(raw).map_err(|_| "discovery endpoint is not a URL")?;
    outbound::check_target(&url, allow_private).map_err(|_| "discovery endpoint not allowed")?;
    if origins == Origins::Issuer && url.origin() != issuer.origin() {
        return Err("discovery endpoint is not on the issuer's origin");
    }
    Ok(url)
}

/// Validate a discovery document fetched for `issuer`: `issuer` must match
/// exactly (OIDC Discovery 4.3), every endpoint must pass the outbound check
/// and sit where `origins` allows, and advertised PKCE methods must include
/// `S256`.
fn parse_document(
    issuer: &Url,
    configured: &str,
    body: &[u8],
    origins: Origins,
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
    let at = |raw: &str| endpoint(raw, issuer, origins, allow_private);
    Ok(Provider {
        authorization_endpoint: at(&doc.authorization_endpoint)?,
        token_endpoint: at(&doc.token_endpoint)?,
        jwks_uri: at(&doc.jwks_uri)?,
        issuer: doc.issuer,
        #[cfg(feature = "identity-native")]
        token_endpoint_auth_methods_supported: doc
            .token_endpoint_auth_methods_supported
            .and_then(|v| serde_json::from_value(v).ok()),
        #[cfg(feature = "identity-native")]
        authorization_response_iss_parameter_supported: doc
            .authorization_response_iss_parameter_supported
            .is_some_and(|v| v == serde_json::Value::Bool(true)),
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
    discover_within(issuer, Origins::Issuer, allow_private).await
}

/// [`discover`] for an operator-configured issuer: endpoints may sit on any
/// origin that passes the outbound check, as Google's token and JWKS hosts do.
#[cfg(feature = "identity-native")]
pub(crate) async fn discover_configured(
    issuer: &str,
    allow_private: bool,
) -> Result<Provider, &'static str> {
    discover_within(issuer, Origins::Any, allow_private).await
}

async fn discover_within(
    issuer: &str,
    origins: Origins,
    allow_private: bool,
) -> Result<Provider, &'static str> {
    let issuer_url = Url::parse(issuer).map_err(|_| "issuer is not a URL")?;
    let body = get_json(&discovery_url(&issuer_url), allow_private).await?;
    parse_document(&issuer_url, issuer, &body, origins, allow_private)
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
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    redeem(provider, &form, None, allow_private).await
}

/// Client authentication with a secret at the token endpoint (RFC 6749
/// 2.3.1).
#[cfg(feature = "identity-native")]
#[derive(Clone, Copy)]
pub(crate) enum ClientAuth<'a> {
    /// `client_secret_basic`: HTTP Basic with the form-encoded id and secret.
    Basic(&'a str),
    /// `client_secret_post`: `client_id` and `client_secret` in the form.
    Post(&'a str),
}

#[cfg(feature = "identity-native")]
impl<'a> ClientAuth<'a> {
    /// Basic when `provider` advertises `client_secret_basic` or advertises
    /// no methods (its default, OIDC Discovery 3), else post.
    pub(crate) fn for_provider(provider: &Provider, secret: &'a str) -> Self {
        if uses_basic(provider.token_endpoint_auth_methods_supported.as_deref()) {
            Self::Basic(secret)
        } else {
            Self::Post(secret)
        }
    }
}

#[cfg(feature = "identity-native")]
fn uses_basic(methods: Option<&[String]>) -> bool {
    methods.is_none_or(|m| m.iter().any(|m| m == "client_secret_basic"))
}

/// `Authorization` value for `client_secret_basic`: id and secret each
/// form-urlencoded, joined with `:`, base64 (RFC 6749 2.3.1).
#[cfg(feature = "identity-native")]
fn basic_authorization(client_id: &str, secret: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", enc(client_id), enc(secret)))
    )
}

/// [`exchange_code`] as a confidential client authenticating with `auth`.
#[cfg(feature = "identity-native")]
pub(crate) async fn exchange_code_with(
    provider: &Provider,
    client_id: &str,
    auth: ClientAuth<'_>,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
    allow_private: bool,
) -> Result<String, &'static str> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];
    let authorization = match auth {
        ClientAuth::Basic(secret) => Some(basic_authorization(client_id, secret)),
        ClientAuth::Post(secret) => {
            form.push(("client_id", client_id));
            form.push(("client_secret", secret));
            None
        }
    };
    redeem(provider, &form, authorization.as_deref(), allow_private).await
}

async fn redeem(
    provider: &Provider,
    form: &[(&str, &str)],
    authorization: Option<&str>,
    allow_private: bool,
) -> Result<String, &'static str> {
    let url = &provider.token_endpoint;
    outbound::check_target(url, allow_private).map_err(|_| "upstream URL not allowed")?;
    let headers: &[(reqwest::header::HeaderName, &str)] = match authorization {
        Some(a) => &[(reqwest::header::AUTHORIZATION, a)],
        None => &[],
    };
    let (status, body) = outbound::post_form(
        outbound::client(allow_private),
        url.as_str(),
        form,
        headers,
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
        parse_document(
            &Url::parse(issuer).unwrap(),
            issuer,
            body,
            Origins::Issuer,
            allow_private,
        )
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

    #[cfg(feature = "identity-native")]
    mod configured {
        use super::*;

        const GOOGLE: &str = "https://accounts.google.com";

        fn google() -> Vec<u8> {
            serde_json::to_vec(&json!({
                "issuer": GOOGLE,
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "code_challenge_methods_supported": ["plain", "S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            }))
            .unwrap()
        }

        fn parse_any(
            issuer: &str,
            body: &[u8],
            allow_private: bool,
        ) -> Result<Provider, &'static str> {
            parse_document(
                &Url::parse(issuer).unwrap(),
                issuer,
                body,
                Origins::Any,
                allow_private,
            )
        }

        #[test]
        fn cross_origin_endpoints_accepted_only_when_configured() {
            assert_eq!(
                parse(GOOGLE, &google(), false).unwrap_err(),
                "discovery endpoint is not on the issuer's origin"
            );
            let p = parse_any(GOOGLE, &google(), false).expect("configured");
            assert_eq!(p.token_endpoint.host_str(), Some("oauth2.googleapis.com"));
            assert_eq!(p.jwks_uri.host_str(), Some("www.googleapis.com"));
            assert_eq!(
                p.token_endpoint_auth_methods_supported.as_deref(),
                Some(
                    &[
                        "client_secret_post".to_string(),
                        "client_secret_basic".to_string()
                    ][..]
                )
            );
            assert!(!p.authorization_response_iss_parameter_supported);
        }

        #[test]
        fn configured_keeps_outbound_check_and_issuer_match() {
            let body = doc(json!({"token_endpoint": "https://10.0.0.5/t"}));
            assert_eq!(
                parse_any(ISSUER, &body, false).unwrap_err(),
                "discovery endpoint not allowed"
            );
            let body = doc(json!({"jwks_uri": "http://keys.example.com/k"}));
            assert_eq!(
                parse_any(ISSUER, &body, false).unwrap_err(),
                "discovery endpoint not allowed"
            );
            assert_eq!(
                parse_any(
                    ISSUER,
                    &doc(json!({"issuer": "https://evil.example.com/"})),
                    false
                )
                .unwrap_err(),
                "discovery issuer does not match"
            );
        }

        #[test]
        fn optional_members_are_lenient() {
            let p = parse(
                ISSUER,
                &doc(json!({
                    "token_endpoint_auth_methods_supported": "client_secret_basic",
                    "authorization_response_iss_parameter_supported": "true",
                })),
                false,
            )
            .expect("malformed optional members do not fail the document");
            assert!(p.token_endpoint_auth_methods_supported.is_none());
            assert!(!p.authorization_response_iss_parameter_supported);
            let p = parse(
                ISSUER,
                &doc(json!({"authorization_response_iss_parameter_supported": true})),
                false,
            )
            .unwrap();
            assert!(p.authorization_response_iss_parameter_supported);
        }

        #[test]
        fn auth_method_pick() {
            let methods = |m: &[&str]| m.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
            assert!(uses_basic(None));
            assert!(uses_basic(Some(&methods(&["client_secret_basic"]))));
            assert!(uses_basic(Some(&methods(&[
                "client_secret_post",
                "client_secret_basic"
            ]))));
            assert!(!uses_basic(Some(&methods(&["client_secret_post"]))));
            assert!(!uses_basic(Some(&methods(&["private_key_jwt"]))));
            assert!(!uses_basic(Some(&[])));

            let mut p = parse(ISSUER, &doc(json!({})), false).unwrap();
            assert!(matches!(
                ClientAuth::for_provider(&p, "s"),
                ClientAuth::Basic("s")
            ));
            p.token_endpoint_auth_methods_supported = Some(methods(&["client_secret_post"]));
            assert!(matches!(
                ClientAuth::for_provider(&p, "s"),
                ClientAuth::Post("s")
            ));
        }

        #[test]
        fn basic_header_form_encodes_before_base64() {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let decode = |h: String| {
                String::from_utf8(STANDARD.decode(h.strip_prefix("Basic ").unwrap()).unwrap())
                    .unwrap()
            };
            assert_eq!(
                basic_authorization("forseti", "s3cret"),
                "Basic Zm9yc2V0aTpzM2NyZXQ="
            );
            assert_eq!(
                decode(basic_authorization("my client:1", "p@ss w/rd+&=%")),
                "my+client%3A1:p%40ss+w%2Frd%2B%26%3D%25"
            );
            assert_eq!(decode(basic_authorization("ü", "")), "%C3%BC:");
        }
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
