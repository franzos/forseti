//! RP-initiated account management — the `/handoff` entry endpoint.
//!
//! External OAuth/OIDC apps (Hydra clients) deep-link their users into
//! Forseti's settings surface with a short URL of the shape:
//!
//! ```text
//! GET /handoff?referrer=<client_id>&referrer_uri=<absolute_url>&action=<verb>
//! ```
//!
//! The handler validates the client against Hydra, origin-matches the
//! `referrer_uri` against the client's registered `redirect_uris` (plus
//! `client_uri`), sets the signed `forseti_app_referrer` cookie that drives
//! the "Continuing from <App>" banner, then 302s to the per-action target.
//!
//! ## Trust model
//!
//! `referrer_uri` must share its origin with one of the client's registered
//! URIs; without that gate anyone who can mint a client could phish (point
//! the "Return to <App>" banner at an attacker-chosen URL). Banner data
//! (`client_name`, `logo_uri`) is read from Hydra, not the URL, so the
//! referrer URL can't become a brand-spoofing vector. `logo_uri` is still
//! client-controlled (dynamic registration), so [`safe_logo_uri`] gates it
//! before it reaches the cookie and the banner `<img>`.
//!
//! ## Sibling endpoints
//!
//! - `GET /handoff/return` — clear cookie, 302 to the stored `referrer_uri`.
//! - `POST /handoff/dismiss` (CSRF-protected) — clear cookie, redirect back.
//!
//! The action whitelist is a stability contract: external apps reference
//! verbs (`2fa`, `password`) not internal paths, so renaming routes doesn't
//! break callers. Destructive actions (account deletion) are omitted.

pub mod cookie;

use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::config::{HandoffConfig, ProxyConfig};
use crate::csrf::CsrfForm;
use crate::flash::redirect_with_cookie;
use crate::ory;
use crate::rate_limit;
use crate::state::AppState;

use cookie::{clear_referrer_cookie, read_referrer_cookie, set_referrer_cookie, ReferrerPayload};

/// View-model for the "Continuing from <App>" banner, built from a verified
/// [`ReferrerPayload`].
#[derive(Debug, Clone)]
pub struct ReferrerBannerView {
    pub client_name: String,
    pub logo_uri: Option<String>,
}

impl From<ReferrerPayload> for ReferrerBannerView {
    fn from(p: ReferrerPayload) -> Self {
        Self {
            client_name: p.client_name,
            logo_uri: p.logo_uri,
        }
    }
}

/// Extractor reading the verified app-referrer cookie, or `None` when it's
/// absent / expired / tampered. Infallible so handlers stay readable.
pub struct ReferrerBanner(pub Option<ReferrerBannerView>);

impl<S> FromRequestParts<S> for ReferrerBanner
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let payload = read_referrer_cookie(
            &parts.headers,
            &app_state.cookie_secret,
            app_state.cfg.handoff.referrer_cookie_ttl_seconds,
        );
        Ok(ReferrerBanner(payload.map(ReferrerBannerView::from)))
    }
}

pub(crate) fn router(proxy_cfg: &ProxyConfig, handoff_cfg: &HandoffConfig) -> Router<AppState> {
    let r = Router::new()
        .route("/handoff", get(handoff_enter))
        .route("/handoff/return", get(handoff_return))
        .route("/handoff/dismiss", post(handoff_dismiss));

    rate_limit::dual_window(
        r,
        proxy_cfg.trust_forwarded_for,
        handoff_cfg.rate_limit_per_minute,
        handoff_cfg.rate_limit_per_hour,
        rate_limit_error_response,
    )
}

fn rate_limit_error_response(err: tower_governor::GovernorError) -> Response {
    use tower_governor::GovernorError;
    let retry = match &err {
        GovernorError::TooManyRequests { wait_time, .. } => Some(*wait_time),
        _ => None,
    };
    let mut builder = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "text/plain; charset=utf-8");
    if let Some(s) = retry {
        builder = builder.header("retry-after", s.to_string());
    }
    builder
        .body(axum::body::Body::from("Too many requests."))
        .expect("static response is well-formed")
}

#[derive(Debug, Deserialize)]
pub(crate) struct HandoffQuery {
    referrer: Option<String>,
    referrer_uri: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DismissForm {
    /// Path to redirect back to after clearing. Defaults to the
    /// referrer-target the user was on. Path-only — `safe_return_to`
    /// rules apply.
    return_to: Option<String>,
}

/// `GET /handoff?referrer=<client_id>&referrer_uri=<url>&action=<verb>`
///
/// Public entry point external apps use to deep-link their users into
/// account self-service. Validates the client + URI, sets the cookie,
/// 302s to the per-action target.
pub(crate) async fn handoff_enter(
    State(state): State<AppState>,
    Query(q): Query<HandoffQuery>,
    actx: AuditCtx,
) -> Response {
    let target = action_target(q.action.as_deref());

    // Both referrer params are required together. Neither set is a stable
    // deep-link (no banner, no audit): just land on the target.
    let (referrer_id, referrer_uri) = match (q.referrer.as_deref(), q.referrer_uri.as_deref()) {
        (None, None) | (None, Some(_)) => return Redirect::to(target).into_response(),
        (Some(_), None) => return invalid_referrer(),
        (Some(id), Some(uri)) => (id, uri),
    };

    let client = match ory::hydra::get_client(&state.ory, referrer_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = ?e, referrer = referrer_id, "handoff: unknown referrer client");
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::APP_REFERRER_ENTERED)
                    .target(target_kind::OAUTH_CLIENT, referrer_id.to_string())
                    .with_ctx(&actx)
                    .severity(audit::severity::WARNING)
                    .failed("client_not_found"),
            )
            .await;
            return invalid_referrer();
        }
    };

    if !client_origin_matches(&client, referrer_uri) {
        tracing::warn!(
            referrer = referrer_id,
            referrer_uri = %referrer_uri,
            "handoff: referrer_uri origin not in client's registered URIs",
        );
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::APP_REFERRER_ENTERED)
                .target(target_kind::OAUTH_CLIENT, referrer_id.to_string())
                .with_ctx(&actx)
                .severity(audit::severity::WARNING)
                .failed("referrer_uri_origin_mismatch"),
        )
        .await;
        return invalid_referrer();
    }

    let client_name = client
        .client_name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| referrer_id.to_string());
    let logo_uri = client.logo_uri.as_deref().and_then(safe_logo_uri);

    let payload = ReferrerPayload {
        client_id: referrer_id.to_string(),
        client_name: client_name.clone(),
        logo_uri,
        referrer_uri: referrer_uri.to_string(),
    };
    let secure = state.cfg.self_.is_https();
    let set_cookie = set_referrer_cookie(
        &state.cookie_secret,
        state.cfg.handoff.referrer_cookie_ttl_seconds,
        &payload,
        secure,
    );

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::APP_REFERRER_ENTERED)
            .target(target_kind::OAUTH_CLIENT, referrer_id.to_string())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "client_name" => client_name,
                "action" => q.action.clone().unwrap_or_default(),
            )),
    )
    .await;

    redirect_with_cookie(target, &set_cookie)
}

/// `GET /handoff/return` — the "Return to <App>" banner button. Clears the
/// cookie and 302s to the stored `referrer_uri`. Idempotent; a GET so it's a
/// plain anchor.
pub(crate) async fn handoff_return(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
) -> Response {
    let payload = read_referrer_cookie(
        &headers,
        &state.cookie_secret,
        state.cfg.handoff.referrer_cookie_ttl_seconds,
    );

    // Re-validate against the client's current Hydra config: the ~1h cookie
    // TTL leaves a window where URIs could be narrowed. Fall back to `/` if it
    // no longer origin-matches.
    let target = match &payload {
        Some(p) => match ory::hydra::get_client(&state.ory, &p.client_id).await {
            Ok(client) if client_origin_matches(&client, &p.referrer_uri) => p.referrer_uri.clone(),
            _ => "/".to_string(),
        },
        None => "/".to_string(),
    };

    let secure = state.cfg.self_.is_https();
    let clear = clear_referrer_cookie(secure);

    // No CSRF token: the banner anchor only clears a self-scoped UX cookie and
    // redirects to an origin-revalidated target (idempotent, non-destructive).
    if let Some(p) = payload {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::APP_REFERRER_RETURNED)
                .target(target_kind::OAUTH_CLIENT, p.client_id.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!("client_name" => p.client_name)),
        )
        .await;
    }
    redirect_with_cookie(&target, &clear)
}

/// `POST /handoff/dismiss` — the banner "×". Clears the cookie and redirects
/// back. CSRF-protected because it has a server-side side-effect.
pub(crate) async fn handoff_dismiss(
    State(state): State<AppState>,
    CsrfForm(form): CsrfForm<DismissForm>,
) -> Response {
    let secure = state.cfg.self_.is_https();
    let clear = clear_referrer_cookie(secure);
    let back = match form.return_to.as_deref() {
        Some(raw) if !raw.is_empty() => crate::web::safe_return_to(&state.cfg, raw),
        _ => "/settings",
    };
    redirect_with_cookie(back, &clear)
}

/// Canonical action verbs advertised on `/.well-known/forseti-configuration`
/// as `handoff_actions_supported`. Aliases accepted by [`action_target`]
/// aren't listed; the canonical form is the integration contract.
/// Destructive actions (account deletion) are absent.
pub(crate) const HANDOFF_ACTIONS: &[&str] = &[
    "2fa",
    "password",
    "profile",
    "sessions",
    "linked-providers",
    "authorized-apps",
];

/// Public action verb → Forseti-internal path. The stability boundary for the
/// integration contract: rename `/settings/2fa` and only this table changes.
/// Destructive actions are absent (see module docs).
fn action_target(action: Option<&str>) -> &'static str {
    match action.unwrap_or("").trim() {
        "2fa" | "totp" | "mfa" => "/settings/2fa",
        "password" => "/settings/password",
        "profile" => "/settings/profile",
        "sessions" => "/settings/sessions",
        "linked_providers" | "linked-providers" => "/settings/linked-providers",
        "authorized_apps" | "authorized-apps" => "/settings/authorized-apps",
        _ => "/settings",
    }
}

/// True when `candidate_uri`'s origin (scheme+host+port) appears among the
/// client's `redirect_uris` (and `client_uri`). Origin comparison rather than
/// full-URL: it gives the same trust guarantee as redirect-URI matching
/// without forcing the integrator to enumerate every page.
fn client_origin_matches(client: &ory_client::models::OAuth2Client, candidate_uri: &str) -> bool {
    let Some(candidate) = parse_origin(candidate_uri) else {
        return false;
    };
    let mut registered: Vec<String> = client
        .redirect_uris
        .as_ref()
        .map(|v| v.iter().filter_map(|u| parse_origin(u)).collect())
        .unwrap_or_default();
    if let Some(c_uri) = client.client_uri.as_deref() {
        if let Some(o) = parse_origin(c_uri) {
            registered.push(o);
        }
    }
    registered.iter().any(|o| o == &candidate)
}

/// Reduce a URL to its origin (`scheme://host[:port]`). Returns `None`
/// for relative or malformed inputs. URLs with non-default ports keep
/// the port; default-port URLs canonicalise to the no-port form so
/// `https://x.com` and `https://x.com:443` compare equal.
fn parse_origin(url_str: &str) -> Option<String> {
    let u = url::Url::parse(url_str).ok()?;
    let host = u.host_str()?;
    let scheme = u.scheme();
    let default_port = matches!(
        (scheme, u.port()),
        ("https", None) | ("https", Some(443)) | ("http", None) | ("http", Some(80))
    );
    if default_port {
        Some(format!("{}://{}", scheme, host))
    } else {
        Some(format!("{}://{}:{}", scheme, host, u.port().unwrap_or(0)))
    }
}

/// Static safety gate for the client-controlled `logo_uri` before it lands in
/// the signed cookie and the banner's `<img src>`. Anonymous dynamic client
/// registration makes it attacker-controllable, and the CSP has no `img-src`,
/// so an unchecked URL is a tracking beacon / internal-host probe on an
/// authenticated page. Requires https, no userinfo, and a public-looking
/// DNS name: IP-literal hosts and obviously internal names (the same spirit
/// as the webhook SSRF blocklist, without DNS resolution) are dropped.
/// Returns `None` on any failure — the banner falls back to text-only.
fn safe_logo_uri(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = match parsed.host()? {
        url::Host::Domain(d) => d.trim_end_matches('.').to_ascii_lowercase(),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
    };
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || !host.contains('.')
    {
        return None;
    }
    Some(raw.to_string())
}

/// Uniform 400 for every `/handoff` validation failure. One body for all
/// branches keeps the endpoint from being a client-id existence oracle.
fn invalid_referrer() -> Response {
    (StatusCode::BAD_REQUEST, "invalid referrer parameters").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ory_client::models::OAuth2Client;

    fn client_with(redirect_uris: Vec<&str>, client_uri: Option<&str>) -> OAuth2Client {
        OAuth2Client {
            redirect_uris: Some(redirect_uris.into_iter().map(String::from).collect()),
            client_uri: client_uri.map(String::from),
            ..OAuth2Client::new()
        }
    }

    #[test]
    fn action_target_maps_known_verbs() {
        assert_eq!(action_target(Some("2fa")), "/settings/2fa");
        assert_eq!(action_target(Some("totp")), "/settings/2fa");
        assert_eq!(action_target(Some("password")), "/settings/password");
        assert_eq!(action_target(Some("profile")), "/settings/profile");
        assert_eq!(action_target(Some("sessions")), "/settings/sessions");
        assert_eq!(
            action_target(Some("linked-providers")),
            "/settings/linked-providers"
        );
        assert_eq!(
            action_target(Some("linked_providers")),
            "/settings/linked-providers"
        );
        assert_eq!(
            action_target(Some("authorized-apps")),
            "/settings/authorized-apps"
        );
    }

    #[test]
    fn handoff_actions_constant_resolves_to_non_hub_routes() {
        // Every advertised verb must resolve off the hub; catches a route
        // removed without dropping the verb from the discovery doc.
        for verb in HANDOFF_ACTIONS {
            assert_ne!(
                action_target(Some(verb)),
                "/settings",
                "advertised verb `{}` falls back to the hub",
                verb,
            );
        }
    }

    #[test]
    fn action_target_falls_back_to_hub() {
        assert_eq!(action_target(None), "/settings");
        assert_eq!(action_target(Some("")), "/settings");
        assert_eq!(action_target(Some("nonsense")), "/settings");
        // Destructive actions intentionally not in the whitelist.
        assert_eq!(action_target(Some("account")), "/settings");
        assert_eq!(action_target(Some("delete")), "/settings");
    }

    #[test]
    fn parse_origin_canonicalises_default_ports() {
        assert_eq!(
            parse_origin("https://x.com/foo?bar=1").as_deref(),
            Some("https://x.com")
        );
        assert_eq!(
            parse_origin("https://x.com:443/").as_deref(),
            Some("https://x.com")
        );
        assert_eq!(
            parse_origin("http://x.com:80").as_deref(),
            Some("http://x.com")
        );
    }

    #[test]
    fn parse_origin_keeps_explicit_nondefault_port() {
        assert_eq!(
            parse_origin("https://x.com:8443/foo").as_deref(),
            Some("https://x.com:8443")
        );
    }

    #[test]
    fn parse_origin_rejects_relative_or_malformed() {
        assert!(parse_origin("/relative").is_none());
        assert!(parse_origin("not a url").is_none());
        assert!(parse_origin("").is_none());
    }

    #[test]
    fn origin_match_against_registered_redirect_uri() {
        let c = client_with(vec!["https://bank.app/oauth/callback"], None);
        assert!(client_origin_matches(&c, "https://bank.app/account"));
    }

    #[test]
    fn origin_match_against_client_uri() {
        let c = client_with(vec![], Some("https://bank.app/"));
        assert!(client_origin_matches(&c, "https://bank.app/account"));
    }

    #[test]
    fn origin_match_rejects_different_origin() {
        let c = client_with(vec!["https://bank.app/oauth/callback"], None);
        assert!(!client_origin_matches(&c, "https://attacker.com/account"));
    }

    #[test]
    fn origin_match_rejects_scheme_mismatch() {
        let c = client_with(vec!["https://bank.app/oauth/callback"], None);
        assert!(!client_origin_matches(&c, "http://bank.app/account"));
    }

    #[test]
    fn origin_match_rejects_port_mismatch() {
        let c = client_with(vec!["https://bank.app:8443/oauth/callback"], None);
        assert!(!client_origin_matches(&c, "https://bank.app/account"));
    }

    #[test]
    fn origin_match_rejects_subdomain() {
        let c = client_with(vec!["https://bank.app/oauth/callback"], None);
        assert!(!client_origin_matches(&c, "https://evil.bank.app/account"));
    }

    #[test]
    fn origin_match_rejects_empty_client() {
        let c = client_with(vec![], None);
        assert!(!client_origin_matches(&c, "https://bank.app/account"));
    }

    #[test]
    fn safe_logo_uri_accepts_https_public_hosts() {
        assert_eq!(
            safe_logo_uri("https://cdn.bank.app/logo.png").as_deref(),
            Some("https://cdn.bank.app/logo.png")
        );
        assert_eq!(
            safe_logo_uri("https://bank.app:8443/logo.svg").as_deref(),
            Some("https://bank.app:8443/logo.svg")
        );
    }

    #[test]
    fn safe_logo_uri_rejects_non_https_and_malformed() {
        assert!(safe_logo_uri("http://bank.app/logo.png").is_none());
        assert!(safe_logo_uri("javascript:alert(1)").is_none());
        assert!(safe_logo_uri("file:///etc/passwd").is_none());
        assert!(safe_logo_uri("/relative/logo.png").is_none());
        assert!(safe_logo_uri("").is_none());
    }

    #[test]
    fn safe_logo_uri_rejects_ip_literal_hosts() {
        assert!(safe_logo_uri("https://127.0.0.1/logo.png").is_none());
        assert!(safe_logo_uri("https://10.0.0.1/logo.png").is_none());
        assert!(safe_logo_uri("https://169.254.169.254/latest/meta-data/").is_none());
        assert!(safe_logo_uri("https://8.8.8.8/logo.png").is_none());
        assert!(safe_logo_uri("https://[::1]/logo.png").is_none());
        assert!(safe_logo_uri("https://[fe80::1]/logo.png").is_none());
    }

    #[test]
    fn safe_logo_uri_rejects_internal_names() {
        assert!(safe_logo_uri("https://localhost/logo.png").is_none());
        assert!(safe_logo_uri("https://LOCALHOST/logo.png").is_none());
        assert!(safe_logo_uri("https://foo.localhost/logo.png").is_none());
        assert!(safe_logo_uri("https://printer.local/logo.png").is_none());
        assert!(safe_logo_uri("https://vault.internal/logo.png").is_none());
        assert!(safe_logo_uri("https://intranet/logo.png").is_none());
        assert!(safe_logo_uri("https://localhost./logo.png").is_none());
    }

    #[test]
    fn safe_logo_uri_rejects_userinfo() {
        assert!(safe_logo_uri("https://user:pass@bank.app/logo.png").is_none());
        assert!(safe_logo_uri("https://user@bank.app/logo.png").is_none());
    }

    #[test]
    fn origin_match_skips_malformed_registered_uris() {
        // A junk entry in redirect_uris doesn't poison the comparison.
        let c = client_with(vec!["not a url", "https://bank.app/oauth/callback"], None);
        assert!(client_origin_matches(&c, "https://bank.app/account"));
    }
}
