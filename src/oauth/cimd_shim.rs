//! Forseti's authorization endpoint (`/oauth2/authorize`) in front of Hydra's
//! `/oauth2/auth`. URL-shaped client_ids are resolved by [`cimd::resolve`]
//! (rate-limited per IP); every other client_id passes straight through,
//! unlimited. A POST (OIDC Core 3.1.2.1) becomes a GET with a 303, since Hydra
//! resumes a flow from the request URL, and `prompt=create` (Initiating User
//! Registration 1.0) becomes Hydra's `prompt=registration`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::cimd::{self, client_id_is_cimd};
use crate::audit::AuditCtx;
use crate::config::{HydraConfig, OAuthConfig, ProxyConfig};
use crate::rate_limit;
use crate::state::AppState;

/// Cap on a POSTed authorization request; the parameters fit a URL anyway.
const AUTHORIZE_FORM_LIMIT: usize = 16 * 1024;

pub(crate) fn router(
    oauth_cfg: &OAuthConfig,
    proxy_cfg: &ProxyConfig,
    hydra_cfg: &HydraConfig,
) -> Router<AppState> {
    let r = Router::new().route("/oauth2/authorize", get(authorize).post(authorize_post));
    let cimd = &oauth_cfg.cimd;
    // Outermost, so only a CIMD-shaped request reaches the limiter below.
    let allow_private = cimd.allow_private_targets;
    let hydra_cfg = hydra_cfg.clone();
    let passthrough = axum::middleware::from_fn(move |req: Request, next: Next| {
        let hydra_cfg = hydra_cfg.clone();
        async move {
            if req.method() == Method::POST {
                let (parts, body) = req.into_parts();
                let body = match axum::body::to_bytes(body, AUTHORIZE_FORM_LIMIT).await {
                    Ok(b) => b,
                    Err(_) => {
                        return (StatusCode::PAYLOAD_TOO_LARGE, "authorize: form too large")
                            .into_response();
                    }
                };
                if !client_id_is_cimd(form_param(&body, "client_id").as_deref(), allow_private) {
                    return redirect_post_to_hydra(&hydra_cfg, &body);
                }
                return next
                    .run(Request::from_parts(parts, axum::body::Body::from(body)))
                    .await;
            }
            let raw_query = req.uri().query().unwrap_or_default().to_string();
            if !is_cimd_request(&raw_query, allow_private) {
                return redirect_to_hydra(&hydra_cfg, &raw_query);
            }
            next.run(req).await
        }
    });
    let limited = rate_limit::dual_window(
        r,
        proxy_cfg,
        cimd.ip_rate_per_minute
            .unwrap_or(cimd::DEFAULT_CIMD_IP_RATE_PER_MINUTE),
        cimd.ip_rate_per_hour
            .unwrap_or(cimd::DEFAULT_CIMD_IP_RATE_PER_HOUR),
        rate_limit::plain_text_error("cimd_authorize"),
    );
    limited.layer(passthrough)
}

fn form_param(form: &[u8], name: &str) -> Option<String> {
    url::form_urlencoded::parse(form)
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn is_cimd_request(raw_query: &str, allow_private: bool) -> bool {
    client_id_is_cimd(
        form_param(raw_query.as_bytes(), "client_id").as_deref(),
        allow_private,
    )
}

/// Where the authorization request goes on to Hydra.
enum AuthorizeOrigin<'a> {
    /// A GET; its query is forwarded.
    Get(&'a str),
    /// A POST; its form body is re-sent by the browser.
    Post(&'a [u8]),
}

async fn authorize(
    State(state): State<AppState>,
    actx: AuditCtx,
    RawQuery(query): RawQuery,
) -> Response {
    let raw_query = query.unwrap_or_default();
    authorize_core(
        &state,
        &actx,
        raw_query.as_bytes(),
        AuthorizeOrigin::Get(&raw_query),
    )
    .await
}

/// A CIMD-shaped POST, replayed here by the passthrough layer.
async fn authorize_post(State(state): State<AppState>, actx: AuditCtx, body: Bytes) -> Response {
    authorize_core(&state, &actx, &body, AuthorizeOrigin::Post(&body)).await
}

/// Resolve a CIMD client from the request's parameters, then send the request
/// on to Hydra the way it came.
async fn authorize_core(
    state: &AppState,
    actx: &AuditCtx,
    form: &[u8],
    origin: AuthorizeOrigin<'_>,
) -> Response {
    let params: Vec<(String, String)> = url::form_urlencoded::parse(form).into_owned().collect();
    if let Err(resp) = cimd::resolve(state, actx, &params).await {
        return resp;
    }
    match origin {
        AuthorizeOrigin::Get(q) => redirect_to_hydra(&state.cfg.hydra, q),
        AuthorizeOrigin::Post(b) => redirect_post_to_hydra(&state.cfg.hydra, b),
    }
}

/// The query for Hydra: byte-identical, unless `prompt` carries `create`,
/// which Hydra v26 knows as `registration`.
fn hydra_query(raw_query: &str) -> std::borrow::Cow<'_, str> {
    let has_create = url::form_urlencoded::parse(raw_query.as_bytes())
        .any(|(k, v)| k == "prompt" && v.split_whitespace().any(|p| p == "create"));
    if !has_create {
        return std::borrow::Cow::Borrowed(raw_query);
    }
    let pairs = url::form_urlencoded::parse(raw_query.as_bytes()).map(|(k, v)| {
        if k == "prompt" {
            let v = v
                .split_whitespace()
                .map(|p| if p == "create" { "registration" } else { p })
                .collect::<Vec<_>>()
                .join(" ");
            (k.into_owned(), v)
        } else {
            (k.into_owned(), v.into_owned())
        }
    });
    std::borrow::Cow::Owned(
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish(),
    )
}

/// Hydra's authorize endpoint. Relative when the issuer carries a path: the
/// browser must stay on the issuer origin it arrived on (Hydra's CSRF cookies
/// are host-scoped), and `/{issuer_path}/oauth2/auth` resolves to the front
/// proxy here and to haproxy's Hydra route in prod. Path-less issuer =
/// front-proxy-less deployment: go absolute.
fn hydra_auth_endpoint(hydra_cfg: &HydraConfig) -> String {
    let base = match hydra_cfg.issuer_path() {
        Some(p) => format!("/{p}"),
        None => hydra_cfg.public_url.trim_end_matches('/').to_string(),
    };
    format!("{base}/oauth2/auth")
}

/// 302 into Hydra's authorize endpoint (query per [`hydra_query`]).
fn redirect_to_hydra(hydra_cfg: &HydraConfig, raw_query: &str) -> Response {
    redirect_with_query(hydra_cfg, raw_query, StatusCode::FOUND)
}

/// 303 into Hydra's authorize endpoint with the POSTed form as the query
/// (RFC 9110 §15.4.4). Hydra resumes a flow from the stored request URL, so a
/// body re-sent with a 307 loses its parameters once login or consent runs.
fn redirect_post_to_hydra(hydra_cfg: &HydraConfig, body: &[u8]) -> Response {
    let Ok(form) = std::str::from_utf8(body) else {
        return (StatusCode::BAD_REQUEST, "authorize: malformed form body").into_response();
    };
    redirect_with_query(hydra_cfg, form, StatusCode::SEE_OTHER)
}

fn redirect_with_query(hydra_cfg: &HydraConfig, raw_query: &str, status: StatusCode) -> Response {
    let raw_query = hydra_query(raw_query);
    let endpoint = hydra_auth_endpoint(hydra_cfg);
    let target = if raw_query.is_empty() {
        endpoint
    } else {
        format!("{endpoint}?{raw_query}")
    };
    match axum::http::HeaderValue::from_str(&target) {
        Ok(loc) => (status, [(header::LOCATION, loc)]).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "cimd: malformed query").into_response(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_url_shaped_client_ids_count_as_cimd() {
        use super::is_cimd_request;
        assert!(is_cimd_request(
            "client_id=https%3A%2F%2Fapp.example%2Fc.json",
            false
        ));
        assert!(!is_cimd_request("client_id=forgejo&scope=openid", false));
        assert!(!is_cimd_request(
            "client_id=http%3A%2F%2F127.0.0.1%2Fc",
            false
        ));
        assert!(is_cimd_request(
            "client_id=http%3A%2F%2F127.0.0.1%2Fc",
            true
        ));
        assert!(!is_cimd_request("", false));
    }

    #[test]
    fn prompt_create_becomes_registration_and_nothing_else_changes() {
        use super::hydra_query;
        let untouched = "client_id=x&scope=openid+email&prompt=login";
        assert_eq!(hydra_query(untouched), untouched);
        let out = hydra_query("client_id=x&prompt=create&state=s%20t");
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(out.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("client_id".to_string(), "x".to_string()),
                ("prompt".to_string(), "registration".to_string()),
                ("state".to_string(), "s t".to_string()),
            ]
        );
    }
}
