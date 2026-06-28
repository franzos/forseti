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
    // Anonymous DCR is the default; a present `Authorization` header must
    // parse to a valid IAT or get rejected with 401 (no silent fall-through,
    // so attackers can't probe IATs without an audit trail).
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
                // Never log the raw bearer; a SHA-256 prefix lets an operator
                // correlate bursts of the same wrong token.
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
                // Don't pretend the token is invalid on a DB blip; 503 makes
                // callers back off instead of rotating credentials. No audit
                // row: we can't trust the DB to record one.
                tracing::error!("dcr: IAT lookup unavailable; returning 503");
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Token validation is temporarily unavailable. Retry shortly.",
                );
            }
        },
    };

    // Non-object bodies are rejected with `invalid_client_metadata` per
    // RFC 7591.
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

    strip_forseti_metadata(&mut payload);

    // Snapshot the caller-declared `audience` before Hydra eats it.
    // Space-joined to match how `scope` is stored. `None` when undeclared;
    // the lazy `resource_url` capture on first consent covers that case.
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

    // Runs before the IAT is decremented so probing names can't burn through
    // someone else's single-use IAT.
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
        // Response intentionally doesn't echo the matched pattern.
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "client_name is reserved",
        );
    }

    // Decrement only after all validations pass so name-probing can't drain
    // the IAT. Anonymous path skips this; per-IP rate limiting upstream is
    // its equivalent.
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
                    // 1h backoff hint; we don't have `started_at` here and
                    // don't want to leak the window's age anyway.
                    Some(3600),
                );
            }
        }
    }

    // Snapshot the remaining audit bits before handing the JSON to Hydra.
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
            // Shouldn't happen (payload is a parsed `Value`); surface as 500
            // rather than forwarding an empty body to Hydra.
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
        // Hand Hydra's error body back verbatim; it already matches RFC 7591.
        return (
            status_code,
            [("content-type", "application/json")],
            upstream_body,
        )
            .into_response();
    }

    // Parse the success response to pick up `client_id` and normalize the
    // body. Hydra emits "" for unset URL fields and `null` for unset arrays;
    // strict client SDKs reject those, and RFC 7591 §3.2.1 lets optional
    // fields be omitted, so dropping the empty keys keeps the proxy usable.
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

    // Stamp the Forseti metadata row before returning. If Hydra committed but
    // the INSERT fails, log loudly and still return success: undoing the
    // Hydra create would tear the caller's `registration_access_token`, and
    // the audit row below captures the gap for reconciliation.
    let iat_id_for_log = iat_row.as_ref().map(|r| r.id.as_str()).unwrap_or("-");
    if !returned_client_id.is_empty() {
        // Attribute to the caller's active org when a session is present
        // (operator curl, scripted dev flow); otherwise the Default org.
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

    // Actor is the IAT when one was presented, else `system`. Surfacing the
    // IAT id lets an operator trace every event back to a single token.
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

/// Remove `metadata.forseti` from the incoming body so a DCR caller can't
/// seed trust-boundary fields onto the Hydra client: RFC 7592 PUT (Hydra-
/// handled) replaces the full `metadata`, so any Forseti trust state on the
/// Hydra client would be RAT-mutable. Other metadata keys pass through.
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

/// Realm advertised in `WWW-Authenticate: Bearer` on 401s. Stable so a client
/// keying per-realm token storage can rely on it (RFC 6750 §3).
const DCR_BEARER_REALM: &str = "forseti-dcr";

/// RFC 7591 §3.2.2 error response: JSON `error` + optional `error_description`.
/// On 401 it also emits `WWW-Authenticate: Bearer` per RFC 6750 §3 so clients
/// can distinguish "need a token" from "token is bad".
fn error_response(status: StatusCode, error: &str, description: &str) -> Response {
    let body = json!({
        "error": error,
        "error_description": description,
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED {
        // Quote-escape per RFC 6750 §3 (`quoted-string`).
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

/// 429 in the RFC 7591 shape (`temporarily_unavailable`) plus `Retry-After`.
/// Used by both the per-IAT and per-IP rate-limit paths.
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
    // No audit event for per-IP hits (too noisy); trace only.
    tracing::trace!(error = ?err, "dcr: per-IP rate limit triggered");
    rate_limited_response("rate limit exceeded", retry)
}

/// Best-effort org to attribute a DCR-registered client to: the caller's
/// active org when a session resolves, else the Default org. Never errors.
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
