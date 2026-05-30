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
//! `client_uri`), then sets the signed `forseti_app_referrer` cookie that
//! drives the "Continuing from <App>" banner on subsequent settings
//! pages. After validation it 302s the user to the per-action target
//! (e.g. `2fa` → `/settings/2fa`).
//!
//! ## Trust model
//!
//! `client_id` must resolve to a real Hydra client. `referrer_uri` must
//! share its origin with one of the client's registered URIs — without
//! this gate, anyone who can mint a client could phish: register
//! `redirect_uris=["https://attacker.com/x"]`, send users to
//! `/handoff?referrer=mine&referrer_uri=https://attacker.com/y` and the
//! banner ("Return to Mine") would point at a URL the attacker chose
//! at link time. Origin-binding confines the spoof to URIs the client
//! legitimately controls.
//!
//! The banner data (`client_name`, `logo_uri`) is read from Hydra at
//! entry, not taken from the URL — otherwise the referrer URL becomes
//! a brand-spoofing vector ("Return to PayPal" with a non-PayPal URI).
//!
//! ## Sibling endpoints
//!
//! - `GET /handoff/return` — clear cookie, 302 to the stored
//!   `referrer_uri`. The "Return to <App>" banner button's target.
//! - `POST /handoff/dismiss` (CSRF-protected) — clear cookie, redirect
//!   to the current page. The dismiss "×" on the banner.
//!
//! The action whitelist is a deliberate stability contract: external
//! apps reference verbs like `2fa` and `password`, not Forseti-internal
//! paths like `/settings/2fa`. Renaming the routes doesn't break
//! callers; adding a new surface requires a new entry here. Destructive
//! actions (account deletion) are intentionally omitted — users
//! navigate there from Forseti's own nav, in a context they chose.

pub mod cookie;

use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::config::{HandoffConfig, ProxyConfig};
use crate::flash::redirect_with_cookie;
use crate::ory;
use crate::rate_limit;
use crate::state::AppState;

use cookie::{clear_referrer_cookie, read_referrer_cookie, set_referrer_cookie, ReferrerPayload};

/// View-model handed to Askama for rendering the "Continuing from
/// <App>" banner. Constructed from a verified [`ReferrerPayload`]; the
/// fields are exactly what `_referrer_banner.html` reads, no more.
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

/// Axum extractor that reads the verified app-referrer cookie off the
/// request, or `None` when the cookie is absent / expired / tampered.
/// Settings handlers consume it and thread the value into their
/// template structs as `referrer_banner: Option<ReferrerBannerView>`.
///
/// Infallible — handlers stay readable (`banner: ReferrerBanner` in
/// the argument list, not `Result<ReferrerBanner, _>`).
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
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
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

    // Both referrer params are required together — one without the other
    // doesn't make sense. If neither is set, this is a "stable deep-link"
    // request (no banner, no audit): land on the target and we're done.
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
    let logo_uri = client.logo_uri.clone().filter(|u| !u.is_empty());

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

/// `GET /handoff/return` — the "Return to <App>" banner button.
/// Clears the cookie and 302s to the stored `referrer_uri`. Idempotent
/// (clears regardless of whether a cookie was present) — a GET so it's
/// a plain anchor in the banner partial.
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

    // Re-validate the stored URI against the client's *current* Hydra config:
    // the cookie's ~1h TTL leaves a window where the client could be deleted
    // or have its registered URIs narrowed. Fall back to `/` if it no longer
    // origin-matches.
    let target = match &payload {
        Some(p) => match ory::hydra::get_client(&state.ory, &p.client_id).await {
            Ok(client) if client_origin_matches(&client, &p.referrer_uri) => p.referrer_uri.clone(),
            _ => "/".to_string(),
        },
        None => "/".to_string(),
    };

    let secure = state.cfg.self_.is_https();
    let clear = clear_referrer_cookie(secure);

    // No CSRF token: the banner's "Return to <app>" must stay a plain anchor,
    // and the only effect is clearing a self-scoped UX cookie then redirecting
    // to an origin-revalidated target — idempotent and non-destructive.
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

/// `POST /handoff/dismiss` — the "×" on the banner. Clears the cookie
/// globally (so the banner stays gone across pages) and redirects back
/// to wherever the user was. CSRF-protected because it has a server-
/// side side-effect (cookie clear).
pub(crate) async fn handoff_dismiss(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DismissForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let secure = state.cfg.self_.is_https();
    let clear = clear_referrer_cookie(secure);
    let back = match form.return_to.as_deref() {
        Some(raw) if !raw.is_empty() => crate::web::safe_return_to(&state.cfg, raw),
        _ => "/settings",
    };
    redirect_with_cookie(back, &clear)
}

/// Canonical action verbs advertised on `/.well-known/forseti-configuration`
/// as `handoff_actions_supported`. One entry per logical surface —
/// aliases (`totp`, `mfa`, `linked_providers`) accepted by
/// [`action_target`] are not listed here; the canonical form is the
/// integration contract.
///
/// Destructive actions (account deletion) are intentionally absent.
pub(crate) const HANDOFF_ACTIONS: &[&str] = &[
    "2fa",
    "password",
    "profile",
    "sessions",
    "linked-providers",
    "authorized-apps",
];

/// Mapping from public action verb → Forseti-internal path. Source of
/// stability for the external integration contract: rename
/// `/settings/2fa` and only this table changes, the public verb
/// `?action=2fa` stays the same.
///
/// Destructive actions (account deletion) are intentionally absent —
/// see module docs.
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

/// True when `candidate_uri`'s origin (scheme+host+port) appears among
/// the client's `redirect_uris` (and `client_uri`). Empty / un-parseable
/// inputs return false. Origin comparison is intentional: registering
/// every conceivable "return URL" is impractical, and origin-binding
/// gives us the same trust guarantee as OAuth2's redirect-URI matching
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

/// Uniform 400 response for every `/handoff` validation failure
/// (missing `referrer_uri`, unknown `client_id`, origin mismatch).
/// Returning the same body for all branches keeps the endpoint from
/// being a client-id existence oracle: an attacker can't distinguish
/// "no such client" from "client exists but origin doesn't match".
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
        // Every advertised verb must resolve somewhere meaningful —
        // catches the drift where someone removes a route but forgets
        // to drop the verb from the discovery doc.
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
    fn origin_match_skips_malformed_registered_uris() {
        // A junk entry in redirect_uris doesn't poison the comparison.
        let c = client_with(vec!["not a url", "https://bank.app/oauth/callback"], None);
        assert!(client_origin_matches(&c, "https://bank.app/account"));
    }
}
