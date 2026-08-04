//! CIMD authorization shim (`GET /oauth2/authorize`): resolves URL-shaped
//! client_ids per draft-ietf-oauth-client-id-metadata-document, upserts the
//! matching Hydra client, then 302s into Hydra's real `/oauth2/auth` with the
//! query untouched. Non-URL client_ids pass straight through. Fetching and
//! caching live in [`cimd_fetch`].

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::cimd_fetch::{self, CimdDocument};
use crate::audit::{self, AuditCtx, AuditEvent, action};
use crate::audit_metadata;
use crate::config::{OAuthConfig, ProxyConfig};
use crate::oauth_client_metadata::{self, source};
use crate::ory::OAuth2Client;
use crate::ory::hydra;
use crate::rate_limit;
use crate::state::AppState;

/// Base scopes every CIMD client's Hydra row carries; the request's `scope`
/// values, `[oauth.cimd].client_scope_extra` and the document's own `scope`
/// union in on top. A ceiling, never a grant — consent stays the authorization.
const CIMD_BASE_SCOPES: &[&str] = &["openid", "offline", "offline_access"];
/// Cap on scope entries kept on the Hydra row (existing entries survive first).
const MAX_SCOPE_ENTRIES: usize = 30;
/// Cap on non-document loopback redirect literals kept on the Hydra row (oldest evicted).
const MAX_LOOPBACK_LITERALS: usize = 5;

/// Rate-limit defaults for `GET /oauth2/authorize`, mirroring the DCR proxy's:
/// per-IP 10/min + 100/hour, global 40/min + 400/hour.
const DEFAULT_CIMD_IP_RATE_PER_MINUTE: u32 = 10;
const DEFAULT_CIMD_IP_RATE_PER_HOUR: u32 = 100;
const DEFAULT_CIMD_GLOBAL_RATE_PER_MINUTE: u32 = 40;
const DEFAULT_CIMD_GLOBAL_RATE_PER_HOUR: u32 = 400;

pub(crate) fn router(oauth_cfg: &OAuthConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    let r = Router::new().route("/oauth2/authorize", get(authorize));
    let cimd = &oauth_cfg.cimd;
    rate_limit::dual_window_with_global(
        r,
        proxy_cfg.trust_forwarded_for,
        cimd.ip_rate_per_minute
            .unwrap_or(DEFAULT_CIMD_IP_RATE_PER_MINUTE),
        cimd.ip_rate_per_hour
            .unwrap_or(DEFAULT_CIMD_IP_RATE_PER_HOUR),
        cimd.global_rate_per_minute
            .unwrap_or(DEFAULT_CIMD_GLOBAL_RATE_PER_MINUTE),
        cimd.global_rate_per_hour
            .unwrap_or(DEFAULT_CIMD_GLOBAL_RATE_PER_HOUR),
        rate_limit::plain_text_error("cimd_authorize"),
    )
}

async fn authorize(
    State(state): State<AppState>,
    actx: AuditCtx,
    RawQuery(query): RawQuery,
) -> Response {
    let raw_query = query.unwrap_or_default();
    let params: Vec<(String, String)> = url::form_urlencoded::parse(raw_query.as_bytes())
        .into_owned()
        .collect();
    let param = |k: &str| {
        params
            .iter()
            .find(|(pk, _)| pk == k)
            .map(|(_, v)| v.as_str())
    };

    // Pre-registered (non-CIMD) clients pass through untouched; http:// ids
    // count as CIMD only under the [oauth.cimd].allow_private_targets hatch
    // (loopback fixture servers) — in production they pass through as before.
    let allow_private = state.cfg.oauth.cimd.allow_private_targets;
    let Some(client_id) = param("client_id")
        .filter(|c| c.starts_with("https://") || (allow_private && c.starts_with("http://")))
    else {
        return redirect_to_hydra(&state.cfg.hydra, &raw_query);
    };
    let client_id = client_id.to_string();
    let request_redirect_uri = param("redirect_uri").unwrap_or("").to_string();
    let requested_scope = param("scope").unwrap_or("").to_string();

    // Guard before any Hydra write: a CIMD flow must never mutate an admin/DCR client.
    let meta_row = match oauth_client_metadata::get(&state.db, &client_id).await {
        Ok(Some(row)) if row.source != source::CIMD => {
            return reject(
                &state,
                &actx,
                &client_id,
                "client_id collides with an existing non-CIMD client",
            )
            .await;
        }
        Ok(row) => row,
        Err(e) => {
            tracing::error!(error = ?e, "cimd: client metadata lookup failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "cimd: metadata lookup unavailable",
            )
                .into_response();
        }
    };

    let Ok(doc_url) = url::Url::parse(&client_id) else {
        return reject(&state, &actx, &client_id, "client_id is not a valid URL").await;
    };
    if let Some(reason) =
        host_policy_violation(&doc_url, &state.cfg.oauth.cimd.allowed_client_hosts)
    {
        return reject(&state, &actx, &client_id, &reason).await;
    }
    let doc = match cimd_fetch::fetch_document(&state, &doc_url).await {
        Ok(d) => d,
        Err(e) => return reject(&state, &actx, &client_id, &e.to_string()).await,
    };
    if let Err(reason) = validate_doc(&doc, &client_id) {
        return reject(&state, &actx, &client_id, &reason).await;
    }
    let matched = match match_redirect_uri(&request_redirect_uri, &doc.redirect_uris) {
        Some(m) => m,
        None => {
            return reject(
                &state,
                &actx,
                &client_id,
                "redirect_uri does not match the client metadata document",
            )
            .await;
        }
    };

    // One Hydra read per authorize, shared by the warm-path check and the
    // upsert. Trade-off: the warm path could avoid it by also persisting the
    // known redirect set Forseti-side, but a second copy would drift.
    let existing = match hydra::get_client_opt(&state.ory, &client_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(client_id, error = %e, "cimd: hydra client lookup failed");
            return (
                StatusCode::BAD_GATEWAY,
                "cimd: client registration unavailable",
            )
                .into_response();
        }
    };

    // Warm path: unchanged document + already-registered redirect_uri means
    // the Hydra row and metadata row are both current — skip every write.
    let doc_hash = hex::encode(doc.raw_hash);
    let warm = meta_row
        .as_ref()
        .is_some_and(|r| r.cimd_doc_hash.as_deref() == Some(doc_hash.as_str()))
        && existing
            .as_ref()
            .and_then(|c| c.redirect_uris.as_ref())
            .is_some_and(|uris| uris.iter().any(|u| u == &request_redirect_uri));

    if !warm {
        if let Err(reason) = upsert_hydra_client(
            &state,
            &client_id,
            &doc,
            existing,
            &requested_scope,
            (matched == RedirectMatch::LoopbackPort).then_some(request_redirect_uri.as_str()),
        )
        .await
        {
            tracing::error!(client_id, error = %reason, "cimd: hydra client upsert failed");
            return (
                StatusCode::BAD_GATEWAY,
                "cimd: client registration unavailable",
            )
                .into_response();
        }

        if let Err(e) =
            oauth_client_metadata::insert_or_get_cimd(&state.db, &client_id, chrono::Utc::now())
                .await
        {
            tracing::error!(error = ?e, "cimd: metadata row insert failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "cimd: metadata write unavailable",
            )
                .into_response();
        }
        if let Err(e) =
            oauth_client_metadata::set_cimd_doc_hash(&state.db, &client_id, &doc_hash).await
        {
            // Non-fatal: the flow is complete; the next visit just takes the cold path.
            tracing::warn!(error = ?e, client_id, "cimd: doc hash store failed");
        }
    }

    let ev = AuditEvent::new(action::OAUTH_CIMD_CLIENT_SEEN)
        .with_ctx(&actx)
        .target(audit::target_kind::OAUTH_CLIENT, client_id.clone())
        .metadata(audit_metadata!("client_id" => client_id));
    let _ = audit::log(&state.db, ev).await;

    redirect_to_hydra(&state.cfg.hydra, &raw_query)
}

/// 302 into Hydra's authorize endpoint with the query string byte-identical.
fn redirect_to_hydra(hydra_cfg: &crate::config::HydraConfig, raw_query: &str) -> Response {
    // Relative redirect when the issuer carries a path: the browser must stay on the
    // issuer origin it arrived on (Hydra's CSRF cookies are host-scoped), and
    // `/{issuer_path}/oauth2/auth` resolves to the front proxy here and to haproxy's
    // Hydra route in prod. Path-less issuer = front-proxy-less deployment: go absolute.
    let base = match hydra_cfg.issuer_path() {
        Some(p) => format!("/{p}"),
        None => hydra_cfg.public_url.trim_end_matches('/').to_string(),
    };
    let target = if raw_query.is_empty() {
        format!("{base}/oauth2/auth")
    } else {
        format!("{base}/oauth2/auth?{raw_query}")
    };
    match axum::http::HeaderValue::from_str(&target) {
        Ok(loc) => (StatusCode::FOUND, [(header::LOCATION, loc)]).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "cimd: malformed query").into_response(),
    }
}

/// Plain 400; never a redirect — the redirect_uri is not yet trusted here.
async fn reject(state: &AppState, actx: &AuditCtx, client_id: &str, reason: &str) -> Response {
    tracing::warn!(client_id, reason, "cimd: authorization rejected");
    let ev = AuditEvent::new(action::OAUTH_CIMD_CLIENT_REJECTED)
        .with_ctx(actx)
        .severity(audit::severity::WARNING)
        .metadata(audit_metadata!("client_id" => client_id, "reason" => reason));
    let _ = audit::log(&state.db, ev).await;
    (StatusCode::BAD_REQUEST, format!("cimd: {reason}")).into_response()
}

/// `Some(reason)` when `[oauth.cimd].allowed_client_hosts` is non-empty and
/// the client_id URL's host is not on it (exact, case-insensitive). Empty
/// list = open (any host, consent-gated).
fn host_policy_violation(url: &url::Url, allowed: &[String]) -> Option<String> {
    if allowed.is_empty() {
        return None;
    }
    let host = url.host_str().unwrap_or("");
    if allowed.iter().any(|a| a.eq_ignore_ascii_case(host)) {
        return None;
    }
    Some(format!(
        "client_id host {host:?} is not allowed by this server's [oauth.cimd].allowed_client_hosts policy"
    ))
}

/// Validate the parsed document per the CIMD draft's public-client subset.
fn validate_doc(doc: &CimdDocument, url: &str) -> Result<(), String> {
    // Byte equality per the draft: the document must claim exactly the URL it was fetched from.
    if doc.client_id != url {
        return Err("document client_id does not equal the fetched URL".to_string());
    }
    if doc.token_endpoint_auth_method != "none" {
        return Err("only token_endpoint_auth_method \"none\" is supported".to_string());
    }
    let grants_ok = !doc.grant_types.is_empty()
        && doc
            .grant_types
            .iter()
            .all(|g| matches!(g.as_str(), "authorization_code" | "refresh_token"));
    if !grants_ok {
        return Err("grant_types must be a subset of authorization_code/refresh_token".to_string());
    }
    if !(doc.response_types.len() == 1 && doc.response_types[0] == "code") {
        return Err("response_types must be exactly [\"code\"]".to_string());
    }
    if doc.redirect_uris.is_empty() {
        return Err("redirect_uris must be a non-empty array of strings".to_string());
    }
    for u in &doc.redirect_uris {
        if !is_acceptable_redirect_entry(u) {
            return Err(format!(
                "redirect_uri entry not https or loopback http: {u}"
            ));
        }
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn is_acceptable_redirect_entry(uri: &str) -> bool {
    let Ok(u) = url::Url::parse(uri) else {
        return false;
    };
    match u.scheme() {
        "https" => true,
        "http" => u.host_str().is_some_and(is_loopback_host),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectMatch {
    Exact,
    /// Matched a loopback document entry ignoring the port (RFC 8252 §7.3);
    /// the literal must be upserted onto the Hydra row (Hydra only port-matches IP literals).
    LoopbackPort,
}

fn match_redirect_uri(request_uri: &str, doc_uris: &[String]) -> Option<RedirectMatch> {
    if doc_uris.iter().any(|d| d == request_uri) {
        return Some(RedirectMatch::Exact);
    }
    let req = url::Url::parse(request_uri).ok()?;
    if req.scheme() != "http" || !req.host_str().is_some_and(is_loopback_host) {
        return None;
    }
    for d in doc_uris {
        let Ok(doc) = url::Url::parse(d) else {
            continue;
        };
        if doc.scheme() == "http"
            && doc.host_str() == req.host_str()
            && doc.path() == req.path()
            && (doc.port().is_none() || doc.port() == req.port())
        {
            return Some(RedirectMatch::LoopbackPort);
        }
    }
    None
}

/// The Hydra row's `scope` ceiling: existing entries (never shrink), then the
/// base scopes, the request's `scope` values, `client_scope_extra` and the
/// document's `scope`, deduplicated in that order and capped at
/// [`MAX_SCOPE_ENTRIES`]. Returns the joined string and whether the cap cut
/// anything off.
fn scope_union(
    existing: Option<&str>,
    requested: &str,
    doc_scope: Option<&str>,
    extra: &[String],
) -> (String, bool) {
    let mut entries: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        if !s.is_empty() && !entries.iter().any(|e| e == s) {
            entries.push(s.to_string());
        }
    };
    for s in existing.unwrap_or_default().split_whitespace() {
        push(s);
    }
    for s in CIMD_BASE_SCOPES {
        push(s);
    }
    for s in requested.split_whitespace() {
        push(s);
    }
    for e in extra {
        for s in e.split_whitespace() {
            push(s);
        }
    }
    for s in doc_scope.unwrap_or_default().split_whitespace() {
        push(s);
    }
    let truncated = entries.len() > MAX_SCOPE_ENTRIES;
    entries.truncate(MAX_SCOPE_ENTRIES);
    (entries.join(" "), truncated)
}

/// Create or PUT-update the Hydra client for this CIMD URL. Updates start
/// from the existing record so unrelated fields — notably the `audience`
/// array the consent-time heal writes — survive Hydra's PUT-override.
async fn upsert_hydra_client(
    state: &AppState,
    client_id: &str,
    doc: &CimdDocument,
    existing: Option<OAuth2Client>,
    requested_scope: &str,
    loopback_literal: Option<&str>,
) -> anyhow::Result<()> {
    let doc_uris = &doc.redirect_uris;

    // Doc URIs first, then surviving non-doc loopback literals (oldest-first order preserved).
    let mut extras: Vec<String> = existing
        .as_ref()
        .and_then(|c| c.redirect_uris.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|u| !doc_uris.contains(u))
        .collect();
    if let Some(lit) = loopback_literal
        && !extras.iter().any(|e| e == lit)
    {
        extras.push(lit.to_string());
    }
    while extras.len() > MAX_LOOPBACK_LITERALS {
        extras.remove(0);
    }
    let mut redirect_uris = doc_uris.clone();
    redirect_uris.extend(extras);

    let (scope, truncated) = scope_union(
        existing.as_ref().and_then(|c| c.scope.as_deref()),
        requested_scope,
        doc.scope.as_deref(),
        &state.cfg.oauth.cimd.client_scope_extra,
    );
    if truncated {
        tracing::warn!(
            client_id,
            cap = MAX_SCOPE_ENTRIES,
            "cimd: scope union exceeded the entry cap; truncated"
        );
    }

    let is_update = existing.is_some();
    let mut c = existing.unwrap_or_default();
    c.client_id = Some(client_id.to_string());
    c.client_name = doc.client_name.clone();
    c.client_uri = doc.client_uri.clone();
    c.logo_uri = doc.logo_uri.clone();
    c.token_endpoint_auth_method = Some("none".to_string());
    c.grant_types = Some(doc.grant_types.clone());
    c.response_types = Some(doc.response_types.clone());
    c.scope = Some(scope);
    c.redirect_uris = Some(redirect_uris);
    if !is_update {
        c.skip_consent = Some(false);
    }

    if is_update {
        hydra::update_client(&state.ory, client_id, c).await?;
    } else {
        hydra::create_client(&state.ory, c).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CimdDocument, MAX_SCOPE_ENTRIES, RedirectMatch, host_policy_violation,
        is_acceptable_redirect_entry, match_redirect_uri, scope_union, validate_doc,
    };

    const DOC_URL: &str = "https://claude.ai/oauth/claude-code-client-metadata";

    fn base_doc() -> CimdDocument {
        CimdDocument {
            raw_hash: [0u8; 32],
            client_id: DOC_URL.to_string(),
            client_name: None,
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec![
                "http://localhost/callback".to_string(),
                "http://127.0.0.1/callback".to_string(),
            ],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            scope: None,
        }
    }

    #[test]
    fn valid_claude_shaped_doc_passes() {
        validate_doc(&base_doc(), DOC_URL).expect("valid doc");
    }

    #[test]
    fn client_id_mismatch_rejected() {
        assert!(validate_doc(&base_doc(), "https://claude.ai/other").is_err());
    }

    #[test]
    fn confidential_doc_rejected() {
        let mut d = base_doc();
        d.token_endpoint_auth_method = "client_secret_basic".to_string();
        assert!(validate_doc(&d, DOC_URL).is_err());
    }

    #[test]
    fn foreign_grant_type_rejected() {
        let mut d = base_doc();
        d.grant_types = vec!["client_credentials".to_string()];
        assert!(validate_doc(&d, DOC_URL).is_err());
    }

    #[test]
    fn non_loopback_http_redirect_rejected() {
        assert!(!is_acceptable_redirect_entry("http://evil.example/cb"));
        assert!(is_acceptable_redirect_entry("https://app.example/cb"));
        assert!(is_acceptable_redirect_entry("http://[::1]:9999/cb"));
    }

    #[test]
    fn loopback_port_variant_matches() {
        let doc_uris = vec!["http://localhost/callback".to_string()];
        assert_eq!(
            match_redirect_uri("http://localhost:54321/callback", &doc_uris),
            Some(RedirectMatch::LoopbackPort)
        );
        assert_eq!(
            match_redirect_uri("http://localhost/callback", &doc_uris),
            Some(RedirectMatch::Exact)
        );
        // The port exception never applies off-loopback or across paths.
        assert_eq!(
            match_redirect_uri("http://localhost:1/other", &doc_uris),
            None
        );
        assert_eq!(
            match_redirect_uri(
                "http://evil.example:80/callback",
                &["http://evil.example/callback".to_string()]
            ),
            None
        );
    }

    // --- host policy --------------------------------------------------------

    #[test]
    fn host_policy_open_when_list_empty() {
        let url = url::Url::parse("https://anything.example/doc").unwrap();
        assert_eq!(host_policy_violation(&url, &[]), None);
    }

    #[test]
    fn host_policy_matches_exact_host_case_insensitively() {
        let allowed = vec!["claude.ai".to_string()];
        let ok = url::Url::parse("https://claude.ai/oauth/meta").unwrap();
        assert_eq!(host_policy_violation(&ok, &allowed), None);
        // url normalises hosts to lowercase; a mixed-case config entry still matches.
        let mixed = vec!["Claude.AI".to_string()];
        assert_eq!(host_policy_violation(&ok, &mixed), None);
    }

    #[test]
    fn host_policy_rejects_unlisted_and_sub_hosts() {
        let allowed = vec!["claude.ai".to_string()];
        for raw in [
            "https://evil.example/doc",
            "https://sub.claude.ai/doc",
            "https://claude.ai.evil.example/doc",
        ] {
            let url = url::Url::parse(raw).unwrap();
            let reason = host_policy_violation(&url, &allowed).expect(raw);
            assert!(
                reason.contains("allowed_client_hosts"),
                "reason must name the policy: {reason}"
            );
        }
    }

    // --- scope union --------------------------------------------------------

    #[test]
    fn scope_union_bases_plus_requested_extra_and_doc_deduped() {
        let extra = vec!["app:admin".to_string()];
        let (scope, truncated) =
            scope_union(None, "openid app:read app:read", Some("app:doc"), &extra);
        assert_eq!(
            scope,
            "openid offline offline_access app:read app:admin app:doc"
        );
        assert!(!truncated);
    }

    #[test]
    fn scope_union_never_shrinks_existing_row_scope() {
        let (scope, _) = scope_union(Some("app:legacy openid"), "app:new", None, &[]);
        // Existing entries first, so a later cap can't evict them.
        assert_eq!(scope, "app:legacy openid offline offline_access app:new");
    }

    #[test]
    fn scope_union_caps_at_thirty_entries() {
        let requested: String = (0..40)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let (scope, truncated) = scope_union(None, &requested, None, &[]);
        assert_eq!(scope.split_whitespace().count(), MAX_SCOPE_ENTRIES);
        assert!(truncated);
        // The base scopes come before the flood, so they survive the cap.
        assert!(scope.starts_with("openid offline offline_access"));
    }
}
