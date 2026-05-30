//! `POST /oauth2/register` DCR proxy handler — Hydra forward, audit
//! emission, response normalisation, error rendering.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde_json::json;

use crate::audit::{self, action, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::oauth_client_metadata;
use crate::state::AppState;

use super::iat::hash_token;
use super::iat::{
    consume_iat, lookup_iat, parse_authorization, AuthOutcome, IatCheck, IatConsume, IatRow,
    DEFAULT_IAT_DAILY_LIMIT,
};
use super::reserved_names::{reserved_name_hit, truncate_for_audit};

pub(crate) async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    actx: AuditCtx,
    body: Bytes,
) -> Response {
    // Anonymous DCR is the default. An `Authorization` header is optional
    // — but if present, it must parse to a valid IAT; a malformed or
    // unknown bearer is rejected with 401 rather than silently falling
    // through to the anonymous path, so an attacker can't probe IATs
    // without leaving an audit trail.
    let iat_row: Option<IatRow> = match parse_authorization(&headers) {
        AuthOutcome::None => None,
        AuthOutcome::Malformed => {
            tracing::info!("dcr: rejected request with malformed Authorization header");
            let ev = AuditEvent::new(action::OAUTH_CLIENT_DCR_REJECTED)
                .with_ctx(&actx)
                .severity(audit::severity::WARNING)
                .metadata(audit_metadata!("reason" => "auth_header_malformed"));
            let _ = audit::log(&state.db, ev).await;
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The Authorization header is malformed. Either omit it (for anonymous DCR) or send `Authorization: Bearer <initial_access_token>`.",
            );
        }
        AuthOutcome::Token(token) => match lookup_iat(&state.db, &token).await {
            IatCheck::Ok(row) => Some(row),
            IatCheck::Invalid => {
                // Audit the no-row case at WARNING so probing for valid IATs
                // leaves a trail. Never log the raw bearer — record only a
                // short prefix of its SHA-256 to help an operator correlate
                // bursts ("the same wrong token tried 200 times").
                let hash_prefix = hash_token(&token).chars().take(8).collect::<String>();
                tracing::info!(hash_prefix = %hash_prefix, "dcr: unknown initial access token");
                let ev = AuditEvent::new(action::OAUTH_CLIENT_DCR_REJECTED)
                    .with_ctx(&actx)
                    .severity(audit::severity::WARNING)
                    .metadata(audit_metadata!(
                        "reason" => "iat_invalid",
                        "hash_prefix" => hash_prefix,
                    ));
                let _ = audit::log(&state.db, ev).await;
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "The provided initial access token is not recognised.",
                );
            }
            IatCheck::Exhausted { iat_id } => {
                tracing::info!(iat_id = %iat_id, "dcr: initial access token revoked / expired / exhausted");
                let ev = AuditEvent::new(action::OAUTH_CLIENT_DCR_REJECTED)
                    .actor_dcr_iat(&iat_id)
                    .with_ctx(&actx)
                    .severity(audit::severity::WARNING)
                    .target(crate::audit::target_kind::DCR_IAT, iat_id.clone())
                    .metadata(audit_metadata!(
                        "reason" => "iat_exhausted",
                        "iat_id" => iat_id,
                    ));
                let _ = audit::log(&state.db, ev).await;
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "The provided initial access token is revoked, expired, or has no remaining uses.",
                );
            }
            IatCheck::DatabaseError => {
                // The lookup itself failed (DB blip). Don't pretend the
                // token is invalid — return 503 so well-behaved callers
                // back off and retry instead of rotating credentials.
                // No audit row: we can't trust the DB to record one.
                tracing::error!("dcr: IAT lookup unavailable; returning 503");
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Token validation is temporarily unavailable. Retry shortly.",
                );
            }
        },
    };

    // Parse the body as JSON so we can sanitise it. Anything that isn't a
    // JSON object is rejected with `invalid_client_metadata` per RFC 7591.
    let mut payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(serde_json::Value::Object(m)) => serde_json::Value::Object(m),
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Request body must be a JSON object.",
            )
        }
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("Request body is not valid JSON: {e}"),
            )
        }
    };

    // Strip `metadata.forseti.*` from the incoming body. Trust-boundary
    // fields (`verification`, `source`, `dcr_iat_id`, ...) live in the
    // Forseti-owned `oauth_client_metadata` table — we never let a DCR
    // caller seed them onto the Hydra client, because RFC 7592 PUT
    // (handled directly by Hydra, not Forseti) would then let the
    // client modify its own trust state via the RAT.
    strip_forseti_metadata(&mut payload);

    // Snapshot the caller-declared `audience` array before Hydra eats
    // it. Space-joined to match how `scope` is stored — keeps the
    // diesel column shape uniform and lets the admin UI render the
    // list with the same splitter. Stays `None` (NULL column) when the
    // caller didn't declare an audience; the lazy `resource_url`
    // capture on first consent picks up that case.
    let posted_audience = payload
        .get("audience")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .map(|v| v.join(" "));

    let posted_name_raw = payload
        .get("client_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // Reserved-name check applies to every path (anonymous + IAT). For
    // the IAT path it runs after IAT validation but before the IAT use is
    // decremented, so a bad actor can't burn through someone else's
    // single-use IAT by probing names.
    if let Some(pattern) = reserved_name_hit(&state.cfg.oauth.dcr_reserved_names, &posted_name_raw)
    {
        tracing::info!(
            iat_id = iat_row.as_ref().map(|r| r.id.as_str()).unwrap_or("-"),
            pattern,
            "dcr: rejected registration — client_name matches reserved pattern"
        );
        let truncated = truncate_for_audit(&posted_name_raw, 100);
        let mut ev = AuditEvent::new(action::OAUTH_CLIENT_DCR_REJECTED)
            .with_ctx(&actx)
            .severity(audit::severity::WARNING);
        ev = match iat_row.as_ref() {
            Some(row) => ev
                .actor_dcr_iat(&row.id)
                .target(crate::audit::target_kind::DCR_IAT, row.id.clone())
                .metadata(audit_metadata!(
                    "reason" => "reserved_name",
                    "iat_id" => row.id.clone(),
                    "client_name_attempted" => truncated,
                )),
            None => ev.metadata(audit_metadata!(
                "reason" => "reserved_name",
                "client_name_attempted" => truncated,
            )),
        };
        let _ = audit::log(&state.db, ev).await;
        // Note: response intentionally does not echo the matched pattern —
        // gives an attacker less feedback for probing the denylist.
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "client_name is reserved",
        );
    }

    // Decrement only after all validations pass to prevent name-probing
    // draining the IAT. The daily counter + uses_remaining only exist on
    // an IAT row, so the anonymous path skips this entirely; per-IP rate
    // limiting (tower_governor, upstream of this handler) is the
    // anonymous-path equivalent.
    if let Some(row) = iat_row.as_ref() {
        let daily_limit = state
            .cfg
            .oauth
            .dcr_iat_daily_limit
            .unwrap_or(DEFAULT_IAT_DAILY_LIMIT);
        match consume_iat(&state.db, row, daily_limit).await {
            IatConsume::Ok => {}
            IatConsume::Exhausted => {
                tracing::info!(iat_id = %row.id, "dcr: IAT exhausted between lookup and consume");
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "The provided initial access token is revoked, expired, or has no remaining uses.",
                );
            }
            IatConsume::DailyLimit { count } => {
                tracing::warn!(
                    iat_id = %row.id,
                    daily_use_count = count,
                    daily_limit,
                    "dcr: IAT daily limit exceeded"
                );
                let ev = AuditEvent::new(action::OAUTH_CLIENT_DCR_RATE_LIMITED)
                    .actor_dcr_iat(&row.id)
                    .with_ctx(&actx)
                    .severity(audit::severity::WARNING)
                    .target(crate::audit::target_kind::DCR_IAT, row.id.clone())
                    .metadata(audit_metadata!(
                        "iat_id" => row.id.clone(),
                        "reason" => "iat_daily_limit",
                        "daily_use_count" => count,
                    ));
                let _ = audit::log(&state.db, ev).await;
                return rate_limited_response(
                    "iat daily limit exceeded",
                    // Retry-After is the time until the current window
                    // rolls over. We don't have the exact `started_at`
                    // here without another fetch; 1 hour is a reasonable
                    // backoff hint without leaking the window's age.
                    Some(3600),
                );
            }
        }
    }

    // Snapshot the remaining audit bits before we hand the JSON over to
    // Hydra (which echoes everything back, but reading from the request
    // body is cheaper than re-parsing the response).
    let posted_name = posted_name_raw;
    let posted_scope = payload
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let redirect_uri_count = payload
        .get("redirect_uris")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as i64)
        .unwrap_or(0);

    let upstream = format!(
        "{}/oauth2/register",
        state.ory.hydra_public.base_path.trim_end_matches('/')
    );
    let body_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            // Should never happen — we built `payload` from a parsed
            // `Value`. If it does, falling through to Hydra with an empty
            // body would write a broken audit row and produce a confusing
            // 400 from Hydra; surface as 500 instead.
            tracing::error!(error = ?e, "dcr: failed to serialise forward payload");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to prepare the registration request.",
            );
        }
    };
    let resp = match state
        .ory
        .hydra_public
        .client
        .post(&upstream)
        .header("content-type", "application/json")
        .body(body_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "dcr: hydra forward transport error");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "Failed to reach the authorization server.",
            );
        }
    };

    let status = resp.status();
    let status_code =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let upstream_body = resp.bytes().await.unwrap_or_default();

    if !status.is_success() {
        // Hand Hydra's error body back verbatim — RFC 7591 says the AS
        // returns a JSON error with `error` / `error_description`, and
        // Hydra already does that. Rewriting it would only introduce
        // drift.
        return (
            status_code,
            [("content-type", "application/json")],
            upstream_body,
        )
            .into_response();
    }

    // Parse the success response so we can both pick up `client_id` for
    // the audit row + Forseti-side insert AND normalize the body before
    // returning it. Hydra emits zero-value strings ("") for unset URL
    // fields (`client_uri`, `policy_uri`, `tos_uri`, `logo_uri`,
    // `jwks_uri`) and `null` for unset arrays (`contacts`). RFC 7591
    // §3.2.1 says optional fields can be omitted; strict client SDKs
    // (Claude's, for one) reject empty-string-as-URL and null-as-array
    // outright. Dropping those keys is RFC-compliant and keeps the
    // proxy usable from those clients.
    let (normalized_body, returned_client_id) =
        match serde_json::from_slice::<serde_json::Value>(&upstream_body) {
            Ok(mut v) => {
                if let Some(obj) = v.as_object_mut() {
                    obj.retain(|_, val| match val {
                        serde_json::Value::Null => false,
                        serde_json::Value::String(s) if s.is_empty() => false,
                        _ => true,
                    });
                }
                let id = v
                    .get("client_id")
                    .and_then(|c| c.as_str())
                    .map(str::to_string)
                    .unwrap_or_default();
                let body = serde_json::to_vec(&v)
                    .map(Bytes::from)
                    .unwrap_or(upstream_body.clone());
                (body, id)
            }
            Err(_) => (upstream_body.clone(), String::new()),
        };

    // Stamp the Forseti-owned metadata row BEFORE returning. If Hydra has
    // already committed the registration but our INSERT fails, log
    // loudly and still return success — undoing the Hydra-side create
    // by hand would require a Hydra DELETE call with no idempotency
    // guarantees, and would leave the caller's `registration_access_token`
    // in a torn state. The audit row below captures the gap so an
    // operator triaging "client present in Hydra, no Forseti row" can
    // see what happened.
    //
    // Missing `client_id` in the response is unexpected (Hydra always
    // returns one on 2xx), but we still log + skip rather than
    // panicking.
    let iat_id_for_log = iat_row.as_ref().map(|r| r.id.as_str()).unwrap_or("-");
    if !returned_client_id.is_empty() {
        // DCR is typically un-authed (Claude / Code can't carry a Forseti
        // session cookie). When a session *is* present — operator
        // shelling a curl from inside the browser, scripted dev flow —
        // we attribute the new client to the caller's active org. The
        // common path (no cookie / unknown identity) falls through to
        // the Default org.
        let target_org = resolve_dcr_target_org(&state, &headers, &extensions).await;
        if let Err(e) = oauth_client_metadata::insert_dcr(
            &state.db,
            &returned_client_id,
            iat_row.as_ref().map(|r| r.id.as_str()),
            posted_audience.as_deref(),
            &target_org,
            Utc::now(),
        )
        .await
        {
            tracing::error!(
                error = ?e,
                client_id = %returned_client_id,
                iat_id = %iat_id_for_log,
                "dcr: hydra committed registration but Forseti metadata INSERT failed — \
                 client will be treated as legacy (verified) until reconciled",
            );
        }
    } else {
        tracing::error!(
            iat_id = %iat_id_for_log,
            "dcr: hydra success response missing client_id — skipping Forseti metadata INSERT",
        );
    }

    // Actor is the IAT itself when one was presented, otherwise `system`
    // — the DCR proxy is unauthenticated browser-wise. Surfacing the IAT
    // id as the actor lets an operator triaging suspicious registrations
    // find every event back to a single issued token; anonymous
    // registrations are still surfaced via the `source = dcr` metadata
    // row and the per-IP rate-limit trace.
    let mut ev = AuditEvent::new(action::OAUTH_CLIENT_DCR_REGISTERED)
        .with_ctx(&actx)
        .metadata(match iat_row.as_ref() {
            Some(row) => audit_metadata!(
                "iat_id" => row.id.clone(),
                "client_name" => posted_name,
                "scope" => posted_scope,
                "redirect_uri_count" => redirect_uri_count,
            ),
            None => audit_metadata!(
                "client_name" => posted_name,
                "scope" => posted_scope,
                "redirect_uri_count" => redirect_uri_count,
                "anonymous" => true,
            ),
        });
    ev = match iat_row.as_ref() {
        Some(row) => ev.actor_dcr_iat(&row.id),
        None => ev,
    };
    if !returned_client_id.is_empty() {
        ev = ev.target(crate::audit::target_kind::OAUTH_CLIENT, returned_client_id);
    }
    let _ = audit::log(&state.db, ev).await;

    (
        status_code,
        [("content-type", "application/json")],
        normalized_body,
    )
        .into_response()
}

/// Remove `metadata.forseti` from the incoming registration body. Trust-
/// boundary fields (`verification`, `source`, `dcr_iat_id`,
/// `dcr_registered_at`, `verified_by`, ...) live in the Forseti-owned
/// `oauth_client_metadata` table, not on the Hydra client. Letting a
/// DCR caller seed them on the Hydra side would defeat the whole point
/// — RFC 7592 PUT (handled directly by Hydra) replaces the full client
/// representation including `metadata`, so any Forseti-scoped trust
/// state on the Hydra client is mutable by the RAT-bearer.
///
/// Non-Forseti metadata keys (anything outside the `forseti` sub-object)
/// are passed through untouched — operators can still attach arbitrary
/// app-specific data to clients via DCR.
fn strip_forseti_metadata(payload: &mut serde_json::Value) {
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    let Some(metadata) = obj.get_mut("metadata") else {
        return;
    };
    let Some(metadata_obj) = metadata.as_object_mut() else {
        return;
    };
    metadata_obj.remove("forseti");
}

/// Realm advertised in `WWW-Authenticate: Bearer` on 401 responses.
/// Stable string so a client implementing per-realm token storage can
/// key off it. Per RFC 6750 §3, the realm is operator-chosen; the
/// Forseti's identifier is fine.
const DCR_BEARER_REALM: &str = "forseti-dcr";

/// RFC 7591 §3.2.2 error response shape: JSON body with `error` and
/// optional `error_description`. The status code carries the HTTP-level
/// failure category (401 for token problems, 400 for body problems).
///
/// On 401 we additionally emit `WWW-Authenticate: Bearer realm=…,
/// error=…, error_description=…` per RFC 6750 §3 — Hydra-fronting
/// proxies + spec-strict clients use this header to distinguish "you
/// need a token" from "your token is bad".
fn error_response(status: StatusCode, error: &str, description: &str) -> Response {
    let body = json!({
        "error": error,
        "error_description": description,
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED {
        // Quote-escape per RFC 6750 §3 (`quoted-string`). Description
        // is operator-trusted (we built it), but the quote on the
        // description still gets the same treatment defensively.
        let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let header_value = format!(
            r#"Bearer realm="{}", error="{}", error_description="{}""#,
            escape(DCR_BEARER_REALM),
            escape(error),
            escape(description),
        );
        return (
            status,
            [
                ("content-type", "application/json"),
                ("www-authenticate", header_value.as_str()),
            ],
            bytes,
        )
            .into_response();
    }
    (status, [("content-type", "application/json")], bytes).into_response()
}

/// 429 response in the RFC 7591 shape (`temporarily_unavailable`) plus a
/// `Retry-After: <seconds>` header. Used by both layers — per-IAT
/// (folded into the handler) and per-IP (the `tower_governor` error
/// handler, see [`rate_limit_error_response`]).
fn rate_limited_response(description: &str, retry_after_seconds: Option<u64>) -> Response {
    let body = json!({
        "error": "temporarily_unavailable",
        "error_description": description,
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mut builder = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json");
    if let Some(s) = retry_after_seconds {
        builder = builder.header("retry-after", s.to_string());
    }
    builder
        .body(axum::body::Body::from(bytes))
        .expect("static response is well-formed")
}

/// Error handler used by the per-IP `tower_governor` layer. Exposed so
/// `oauth::router` can wire it into the `GovernorLayer`.
pub(crate) fn rate_limit_error_response(err: tower_governor::GovernorError) -> Response {
    use tower_governor::GovernorError;
    let retry = match &err {
        GovernorError::TooManyRequests { wait_time, .. } => Some(*wait_time),
        _ => None,
    };
    // Per spec: no audit event for per-IP hits — too noisy. Trace-level
    // log only.
    tracing::trace!(error = ?err, "dcr: per-IP rate limit triggered");
    rate_limited_response("rate limit exceeded", retry)
}

/// Best-effort resolve the org to attribute a DCR-registered client to.
/// Returns the caller's active org when a session cookie is present and
/// resolves to a known identity; falls back to the Default org id in
/// every other case. Never errors — the registration has already been
/// committed Hydra-side by the time we get here.
async fn resolve_dcr_target_org(
    state: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> String {
    let session = crate::extractors::optional_session(state, headers, extensions).await;
    let Some(identity_id) = session.identity_id() else {
        return crate::orgs::DEFAULT_ORG_ID.to_string();
    };
    let identity_id = identity_id.to_string();
    let memberships = crate::orgs::list_memberships(&state.db, &identity_id)
        .await
        .unwrap_or_default();
    crate::orgs::active_org(
        &memberships,
        &state.cookie_secret,
        state.cfg.orgs.active_org_cookie_ttl_seconds,
        headers,
    )
    .map(|m| m.org_id)
    .unwrap_or_else(|| crate::orgs::DEFAULT_ORG_ID.to_string())
}
