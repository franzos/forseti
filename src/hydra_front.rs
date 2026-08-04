//! Config-gated reverse proxy fronting Hydra's public API (`/hydra/{*rest}`),
//! plus the always-mounted RFC 8414 / OIDC path-insertion discovery routes
//! serving Hydra's discovery document augmented for CIMD (Design A of the
//! MCP CIMD design). Bodies are buffered under a 2 MiB cap by design:
//! Hydra's public endpoints only ever carry small payloads, so streaming
//! buys nothing here. The discovery document comes from the shared
//! [`crate::state::DiscoveryCache`], not a per-request fetch.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::config::HydraConfig;
use crate::state::AppState;

/// Buffered request-body cap for the passthrough; Hydra's endpoints never need more.
const PROXY_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// Response headers worth forwarding back from Hydra.
const PROXIED_RESPONSE_HEADERS: [&str; 5] = [
    "content-type",
    "location",
    "www-authenticate",
    "cache-control",
    "vary",
];

/// `[hydra].front_proxy`-gated passthrough. Mounted on the public listener
/// outside the CSRF layer (Hydra does its own request validation).
pub(crate) fn router(hydra_cfg: &HydraConfig) -> Router<AppState> {
    if !hydra_cfg.front_proxy {
        return Router::new();
    }
    Router::new()
        .route("/hydra/{*rest}", get(passthrough).post(passthrough))
        .layer(DefaultBodyLimit::max(PROXY_BODY_LIMIT_BYTES))
}

/// RFC 8414 / OIDC path-insertion discovery for the configured issuer path
/// (prod haproxy routes these to Forseti already). A path-less issuer has no
/// insertion form, so nothing mounts.
pub(crate) fn well_known_router(hydra_cfg: &HydraConfig) -> Router<AppState> {
    let Some(path) = hydra_cfg.issuer_path() else {
        return Router::new();
    };
    Router::new()
        .route(
            &format!("/.well-known/oauth-authorization-server/{path}"),
            get(augmented_discovery_route),
        )
        .route(
            &format!("/.well-known/openid-configuration/{path}"),
            get(augmented_discovery_route),
        )
}

async fn passthrough(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The AS discovery endpoints must carry the CIMD augmentation, so they never proxy verbatim.
    if method == Method::GET
        && matches!(
            rest.as_str(),
            ".well-known/openid-configuration" | ".well-known/oauth-authorization-server"
        )
    {
        return augmented_discovery(&state).await;
    }

    let base = state.cfg.hydra.public_url.trim_end_matches('/');
    let mut url = format!("{base}/{rest}");
    if let Some(q) = query.as_deref() {
        url.push('?');
        url.push_str(q);
    }

    // A proxy must hand Hydra's redirects to the browser, never follow them itself.
    static NO_REDIRECT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = NO_REDIRECT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("reqwest client")
    });
    let mut req = if method == Method::POST {
        client.post(&url)
    } else {
        client.get(&url)
    };
    for name in [
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::AUTHORIZATION,
        header::COOKIE,
    ] {
        if let Some(v) = headers.get(&name)
            && let Ok(s) = v.to_str()
        {
            req = req.header(name.as_str(), s);
        }
    }
    for (name, v) in headers.iter() {
        if name.as_str().starts_with("x-forwarded-")
            && let Ok(s) = v.to_str()
        {
            req = req.header(name.as_str(), s);
        }
    }
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "hydra front proxy: upstream unreachable");
            return (StatusCode::BAD_GATEWAY, "hydra upstream unreachable").into_response();
        }
    };
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut out_headers = HeaderMap::new();
    for name in PROXIED_RESPONSE_HEADERS {
        if let Some(v) = resp.headers().get(name)
            && let Ok(hv) = HeaderValue::from_bytes(v.as_bytes())
        {
            out_headers.insert(HeaderName::from_static(name), hv);
        }
    }
    // Set-Cookie is multi-valued (Hydra's CSRF cookies) — append every instance.
    for v in resp.headers().get_all(header::SET_COOKIE) {
        if let Ok(hv) = HeaderValue::from_bytes(v.as_bytes()) {
            out_headers.append(header::SET_COOKIE, hv);
        }
    }
    match resp.bytes().await {
        Ok(b) => (status, out_headers, b.to_vec()).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "hydra front proxy: upstream body read failed");
            (StatusCode::BAD_GATEWAY, "hydra upstream read failed").into_response()
        }
    }
}

async fn augmented_discovery_route(State(state): State<AppState>) -> Response {
    augmented_discovery(&state).await
}

/// Hydra's discovery document (via the shared cache) with the three CIMD
/// mutations applied by [`augment_discovery_doc`].
pub(crate) async fn augmented_discovery(state: &AppState) -> Response {
    let Some(raw) = state.openid_configuration_raw().await else {
        return (StatusCode::BAD_GATEWAY, "hydra discovery unavailable").into_response();
    };
    let Some(doc) = augment_discovery_doc(&raw, state.cfg.hydra.issuer_path()) else {
        return (StatusCode::BAD_GATEWAY, "hydra discovery unavailable").into_response();
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        doc.to_string(),
    )
        .into_response()
}

/// The three CIMD mutations over Hydra's raw discovery doc: advertise CIMD
/// support, point `authorization_endpoint` at the Forseti shim, and drop
/// `registration_endpoint` (no anonymous registration surface). Everything
/// else — `issuer` above all — passes through untouched. `None` when the doc
/// is not a JSON object.
fn augment_discovery_doc(
    raw: &serde_json::Value,
    issuer_path: Option<&str>,
) -> Option<serde_json::Value> {
    let mut doc = raw.as_object()?.clone();
    doc.insert(
        "client_id_metadata_document_supported".to_string(),
        serde_json::Value::Bool(true),
    );
    // The shim lives at the issuer's origin base (issuer minus its configured path suffix).
    if let Some(issuer) = doc.get("issuer").and_then(serde_json::Value::as_str) {
        let issuer = issuer.trim_end_matches('/');
        let origin_base = match issuer_path {
            Some(p) => issuer.strip_suffix(&format!("/{p}")).unwrap_or(issuer),
            None => issuer,
        };
        doc.insert(
            "authorization_endpoint".to_string(),
            serde_json::Value::String(format!("{origin_base}/oauth2/authorize")),
        );
    }
    doc.remove("registration_endpoint");
    Some(serde_json::Value::Object(doc))
}

#[cfg(test)]
mod tests {
    use super::augment_discovery_doc;

    #[test]
    fn augmentation_mutates_three_keys_and_nothing_else() {
        let raw = serde_json::json!({
            "issuer": "http://host.containers.internal:3000/hydra",
            "authorization_endpoint": "http://host.containers.internal:3000/hydra/oauth2/auth",
            "token_endpoint": "http://host.containers.internal:3000/hydra/oauth2/token",
            "jwks_uri": "http://host.containers.internal:3000/hydra/.well-known/jwks.json",
            "registration_endpoint": "http://host.containers.internal:3000/hydra/oauth2/register",
            "scopes_supported": ["openid", "offline", "offline_access"],
            "response_types_supported": ["code", "id_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "subject_types_supported": ["public"],
        });
        let out = augment_discovery_doc(&raw, Some("hydra")).expect("object doc");

        assert_eq!(out["client_id_metadata_document_supported"], true);
        assert_eq!(
            out["authorization_endpoint"],
            "http://host.containers.internal:3000/oauth2/authorize"
        );
        assert!(out.get("registration_endpoint").is_none());

        // Every untouched key survives byte-identical — the issuer above all,
        // since it is the `iss` in every token.
        let (raw, out) = (raw.as_object().unwrap(), out.as_object().unwrap());
        for (key, value) in raw {
            if matches!(
                key.as_str(),
                "authorization_endpoint" | "registration_endpoint"
            ) {
                continue;
            }
            assert_eq!(
                serde_json::to_string(&out[key]).unwrap(),
                serde_json::to_string(value).unwrap(),
                "key {key} must pass through verbatim"
            );
        }
        assert_eq!(out.len(), raw.len()); // -registration_endpoint +cimd_supported
    }

    #[test]
    fn augmentation_without_issuer_path_uses_issuer_origin() {
        let raw = serde_json::json!({ "issuer": "http://localhost:4444" });
        let out = augment_discovery_doc(&raw, None).expect("object doc");
        assert_eq!(
            out["authorization_endpoint"],
            "http://localhost:4444/oauth2/authorize"
        );
        assert_eq!(out["issuer"], "http://localhost:4444");
    }

    #[test]
    fn augmentation_rejects_non_object_doc() {
        assert!(augment_discovery_doc(&serde_json::json!([1, 2]), Some("hydra")).is_none());
    }
}
