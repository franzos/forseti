//! RFC 9728 protected-resource metadata: fetch a resource's well-known
//! document through the guarded outbound client and corroborate it against
//! the stored resource and Forseti's issuer.

use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::resource_registry::{corroboration, parse_scopes_supported};

const TIMEOUT: Duration = Duration::from_secs(5);
const DOC_LIMIT_BYTES: usize = 64 * 1024;

/// Outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// A [`corroboration`] value.
    pub status: &'static str,
    /// The document's valid `scopes_supported` when corroborated and present
    /// as an array; `None` keeps the stored list.
    pub scopes: Option<Vec<String>>,
    /// Why the document didn't corroborate, for the caller's log line.
    pub reason: Option<String>,
}

/// True when the stored resource is an http(s) URI with a host, i.e. the
/// fetch has somewhere to go.
pub fn has_fetchable_host(resource: &str) -> bool {
    Url::parse(resource)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .and_then(|u| u.host_str().map(str::to_string))
        .is_some()
}

/// RFC 9728 §3 well-known location, path-aware: the well-known prefix sits
/// between the origin and the resource's path component.
fn protected_resource_metadata_url(resource: &Url) -> Option<Url> {
    resource.host_str()?;
    let path = resource.path().trim_end_matches('/');
    let wk = if path.is_empty() {
        "/.well-known/oauth-protected-resource".to_string()
    } else {
        format!("/.well-known/oauth-protected-resource{path}")
    };
    let mut url = resource.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.set_path(&wk);
    Some(url)
}

/// Fetch and evaluate `resource`'s document. `None` = nothing to fetch
/// (verbatim non-URI identifier).
pub async fn check(resource: &str, issuer: &str, allow_private: bool) -> Option<Check> {
    let url = Url::parse(resource)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))?;
    let wk = protected_resource_metadata_url(&url)?;
    Some(match fetch_metadata(&wk, allow_private).await {
        Ok(doc) => evaluate(&doc, resource, issuer),
        Err(e) => Check {
            status: corroboration::UNREACHABLE,
            scopes: None,
            reason: Some(e),
        },
    })
}

fn evaluate(doc: &ProtectedResourceMetadata, resource: &str, issuer: &str) -> Check {
    if !resource_matches(&doc.resource, resource) {
        return Check {
            status: corroboration::MISMATCH,
            scopes: None,
            reason: Some(format!("document resource {:?}", doc.resource)),
        };
    }
    if !issuer_listed(&doc.authorization_servers, issuer) {
        return Check {
            status: corroboration::MISMATCH,
            scopes: None,
            reason: Some("authorization_servers does not list the issuer".to_string()),
        };
    }
    let scopes = doc.scopes_supported.as_array().map(|items| {
        let names: Vec<String> = items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        parse_scopes_supported(&names)
    });
    Check {
        status: corroboration::CORROBORATED,
        scopes,
        reason: None,
    }
}

/// The document's `resource` against the stored (canonical) row value, with
/// the same verbatim-then-canonical dual matching the consent resolver uses.
fn resource_matches(doc_resource: &str, stored: &str) -> bool {
    let doc_resource = doc_resource.trim();
    doc_resource == stored
        || crate::oauth::canonical_resource(doc_resource).is_some_and(|c| c == stored)
}

/// Trailing-slash-insensitive membership test for `authorization_servers`.
fn issuer_listed(servers: &[String], issuer: &str) -> bool {
    let want = issuer.trim_end_matches('/');
    servers
        .iter()
        .any(|s| s.trim().trim_end_matches('/') == want)
}

#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
    /// Read leniently: anything but an array of strings yields no scopes.
    #[serde(default)]
    scopes_supported: serde_json::Value,
}

/// SSRF-guarded GET of the metadata document: `outbound::check_target`, then
/// the shared guarded `outbound` client with no redirects, 5 s / 64 KiB caps.
async fn fetch_metadata(
    url: &Url,
    allow_private: bool,
) -> Result<ProtectedResourceMetadata, String> {
    crate::outbound::check_target(url, allow_private).map_err(|e| format!("metadata URL {e}"))?;

    use crate::outbound::FetchError;
    let describe = |e: FetchError| match e {
        FetchError::Transport(m) => m,
        FetchError::Status(s) => format!("HTTP {s}"),
        FetchError::TooLarge => "document too large".to_string(),
    };
    let client = crate::outbound::client(allow_private);
    let resp = crate::outbound::get_ok(client, url.as_str(), Some("application/json"), TIMEOUT)
        .await
        .map_err(describe)?;
    let buf = crate::outbound::read_capped(resp, DOC_LIMIT_BYTES)
        .await
        .map_err(describe)?;
    serde_json::from_slice(&buf).map_err(|e| format!("invalid document: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wk(raw: &str) -> String {
        protected_resource_metadata_url(&Url::parse(raw).unwrap())
            .expect("well-known URL")
            .to_string()
    }

    #[test]
    fn well_known_url_without_path() {
        assert_eq!(
            wk("https://mcp.example.com"),
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn well_known_url_inserts_before_path() {
        assert_eq!(
            wk("https://stackpit.gofranz.com/mcp"),
            "https://stackpit.gofranz.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn well_known_url_keeps_port_and_drops_query() {
        assert_eq!(
            wk("http://127.0.0.1:8890/mcp/v1?x=1"),
            "http://127.0.0.1:8890/.well-known/oauth-protected-resource/mcp/v1"
        );
    }

    #[test]
    fn resource_matches_verbatim_and_canonical() {
        let stored = "https://stackpit.gofranz.com/mcp";
        assert!(resource_matches(stored, stored));
        assert!(resource_matches(
            "https://stackpit.gofranz.com/mcp/",
            stored
        ));
        assert!(!resource_matches("https://other.example/mcp", stored));
        // Verbatim non-URI identifiers only ever match verbatim.
        assert!(resource_matches("stackpit-web", "stackpit-web"));
    }

    #[test]
    fn issuer_listed_is_trailing_slash_insensitive() {
        let servers = vec!["http://host.containers.internal:3000/hydra/".to_string()];
        assert!(issuer_listed(
            &servers,
            "http://host.containers.internal:3000/hydra"
        ));
        assert!(!issuer_listed(&servers, "https://other.issuer"));
    }

    #[test]
    fn has_fetchable_host_rejects_verbatim_identifiers() {
        assert!(has_fetchable_host("https://mcp.example.com/mcp"));
        assert!(!has_fetchable_host("stackpit-web"));
        assert!(!has_fetchable_host("stackpit.gofranz.com"));
        assert!(!has_fetchable_host("urn:example:resource"));
    }

    const RES: &str = "https://mcp.example.com/mcp";
    const ISS: &str = "https://id.example.com/hydra";

    fn doc(json: serde_json::Value) -> ProtectedResourceMetadata {
        serde_json::from_value(json).expect("document")
    }

    #[test]
    fn evaluate_corroborated_reads_scopes_leniently() {
        let check = evaluate(
            &doc(serde_json::json!({
                "resource": RES,
                "authorization_servers": [ISS],
                "scopes_supported": ["a:read", 7, "bad scope", null, "b:write"],
            })),
            RES,
            ISS,
        );
        assert_eq!(check.status, corroboration::CORROBORATED);
        assert_eq!(
            check.scopes,
            Some(vec!["a:read".to_string(), "b:write".to_string()])
        );

        let empty = evaluate(
            &doc(serde_json::json!({
                "resource": RES, "authorization_servers": [ISS], "scopes_supported": [],
            })),
            RES,
            ISS,
        );
        assert_eq!(empty.status, corroboration::CORROBORATED);
        assert_eq!(empty.scopes, Some(vec![]));

        for value in [serde_json::json!(null), serde_json::json!("a:read b:write")] {
            let check = evaluate(
                &doc(serde_json::json!({
                    "resource": RES, "authorization_servers": [ISS], "scopes_supported": value,
                })),
                RES,
                ISS,
            );
            assert_eq!(check.status, corroboration::CORROBORATED);
            assert_eq!(check.scopes, None, "{value}");
        }
        let missing = evaluate(
            &doc(serde_json::json!({"resource": RES, "authorization_servers": [ISS]})),
            RES,
            ISS,
        );
        assert_eq!(missing.scopes, None);
    }

    #[test]
    fn evaluate_mismatch_yields_no_scopes() {
        let wrong_resource = evaluate(
            &doc(serde_json::json!({
                "resource": "https://other.example.com/mcp",
                "authorization_servers": [ISS],
                "scopes_supported": ["a:read"],
            })),
            RES,
            ISS,
        );
        assert_eq!(wrong_resource.status, corroboration::MISMATCH);
        assert_eq!(wrong_resource.scopes, None);
        assert!(wrong_resource.reason.is_some());

        let no_issuer = evaluate(
            &doc(serde_json::json!({
                "resource": RES,
                "authorization_servers": ["https://elsewhere.example.com"],
                "scopes_supported": ["a:read"],
            })),
            RES,
            ISS,
        );
        assert_eq!(no_issuer.status, corroboration::MISMATCH);
        assert_eq!(no_issuer.scopes, None);
    }
}
