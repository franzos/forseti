//! The `/posix/v1/*` resolver HTTP API consumed by enrolled hosts' NSS/SSH
//! integration. Mounted on the INTERNAL listener; every handler is gated by
//! the [`RequirePosixHost`] Basic-auth extractor.
//!
//! Access control hinges on `host.allowed_gid`:
//! - `None` (unscoped): single lookups resolve any account/group, but
//!   enumeration returns empty so a host can't slurp the whole directory.
//! - `Some(gid)` (scoped): everything is restricted to enabled members of
//!   the named org group, which is re-asserted to be `kind = "org"` per
//!   request (defense in depth — never trust the stored allowed_gid alone).

use axum::extract::{Json as JsonBody, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::audit::{self, action, target_kind, AuditEvent, SafeMetadata};
use crate::posix::db;
use crate::posix::host_auth::RequirePosixHost;
use crate::posix::offline::{OfflineVerifier, OfflineVerifiersResponse};
use crate::posix::scope;
use crate::rate_limit;
use crate::state::AppState;

#[derive(serde::Serialize)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

#[derive(serde::Serialize)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

impl From<db::PosixAccount> for PasswdEntry {
    fn from(a: db::PosixAccount) -> Self {
        PasswdEntry {
            name: a.username,
            uid: a.uid as u32,
            gid: a.gid as u32,
            gecos: a.gecos,
            dir: a.home_dir,
            shell: a.shell,
        }
    }
}

/// Per-IP rate limit for the resolver. Coarse on purpose: keyed by source IP,
/// so hosts behind one NAT share a bucket. A host-keyed extractor would be a
/// future hardening (rate_limit.rs has no host-id extractor yet).
const RESOLVER_RATE_PER_MINUTE: u32 = 600;

/// Tiny empty 429 for machine clients — no HTML page, no JSON envelope.
fn rate_limit_error(_err: tower_governor::GovernorError) -> Response {
    StatusCode::TOO_MANY_REQUESTS.into_response()
}

pub fn router() -> Router<AppState> {
    let r = Router::new()
        .route("/posix/v1/passwd", get(passwd_all))
        .route("/posix/v1/passwd/name/{name}", get(passwd_by_name))
        .route("/posix/v1/passwd/uid/{uid}", get(passwd_by_uid))
        .route("/posix/v1/group", get(group_all))
        .route("/posix/v1/group/name/{name}", get(group_by_name))
        .route("/posix/v1/group/gid/{gid}", get(group_by_gid))
        .route("/posix/v1/authorized_keys/{name}", get(authorized_keys))
        .route("/posix/v1/offline_verifiers", get(offline_verifiers))
        .route("/posix/v1/offline_audit", post(offline_audit));

    rate_limit::apply(
        r,
        tower_governor::key_extractor::SmartIpKeyExtractor,
        60_000,
        RESOLVER_RATE_PER_MINUTE,
        rate_limit_error,
    )
}

/// 500 helper: a db error must not look like a NOTFOUND to the daemon.
fn db_error(e: anyhow::Error, ctx: &str) -> Response {
    tracing::error!(error = ?e, "posix resolver: {ctx}");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// Resolve `host.allowed_gid` into a concrete scope. Returns:
/// - `Ok(None)` — unscoped host.
/// - `Ok(Some(gid))` — scoped host, `gid` confirmed to be an org group.
/// - `Err(response)` — misconfigured scoped host (gid missing or not org);
///   the caller serves the supplied empty/not-found `response`.
async fn resolve_scope(
    state: &AppState,
    host: &RequirePosixHost,
    misconfigured: Response,
) -> Result<Option<u32>, Response> {
    let Some(gid) = host.allowed_gid else {
        return Ok(None);
    };
    match db::group_by_gid(&state.db, gid).await {
        Ok(Some(g)) if g.kind == "org" => Ok(Some(gid)),
        Ok(_) => {
            tracing::warn!(
                host_id = %host.host_id,
                gid,
                "posix resolver: host's allowed_gid is missing or not an org group; serving empty"
            );
            Err(misconfigured)
        }
        Err(e) => Err(db_error(e, "scope re-assert failed")),
    }
}

async fn passwd_all(State(state): State<AppState>, host: RequirePosixHost) -> Response {
    let scope = match resolve_scope(&state, &host, Json(Vec::<PasswdEntry>::new()).into_response())
        .await
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    match scope {
        // Unscoped hosts never enumerate the directory.
        None => Json(Vec::<PasswdEntry>::new()).into_response(),
        Some(gid) => match db::accounts_in_gid(&state.db, gid).await {
            Ok(rows) => {
                let out: Vec<PasswdEntry> = rows.into_iter().map(PasswdEntry::from).collect();
                Json(out).into_response()
            }
            Err(e) => db_error(e, "passwd_all scoped query failed"),
        },
    }
}

async fn passwd_by_name(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(name): Path<String>,
) -> Response {
    let account = match db::account_by_username(&state.db, &name).await {
        Ok(Some(a)) if a.enabled == 1 => a,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return db_error(e, "passwd_by_name lookup failed"),
    };
    serve_account_scoped(&state, &host, account).await
}

async fn passwd_by_uid(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(uid): Path<u32>,
) -> Response {
    let account = match db::account_by_uid(&state.db, uid).await {
        Ok(Some(a)) if a.enabled == 1 => a,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return db_error(e, "passwd_by_uid lookup failed"),
    };
    serve_account_scoped(&state, &host, account).await
}

/// Return the account as a passwd entry, enforcing the shared host-scope
/// decision: an unscoped host gets it outright; a scoped host gets it only if
/// the account is visible under [`scope::account_visible_on_host`].
async fn serve_account_scoped(
    state: &AppState,
    host: &RequirePosixHost,
    account: db::PosixAccount,
) -> Response {
    match scope::account_visible_on_host(&state.db, host, &account).await {
        Ok(true) => Json(PasswdEntry::from(account)).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => db_error(e, "account scope check failed"),
    }
}

async fn group_all(State(state): State<AppState>, host: RequirePosixHost) -> Response {
    let scope = match resolve_scope(&state, &host, Json(Vec::<GroupEntry>::new()).into_response())
        .await
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    match scope {
        None => Json(Vec::<GroupEntry>::new()).into_response(),
        // Scoped hosts see exactly their one org group (sufficient for M1).
        Some(gid) => match group_entry(&state, gid).await {
            Ok(Some(g)) => Json(vec![g]).into_response(),
            Ok(None) => Json(Vec::<GroupEntry>::new()).into_response(),
            Err(e) => db_error(e, "group_all scoped query failed"),
        },
    }
}

async fn group_by_name(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(name): Path<String>,
) -> Response {
    let scope = match resolve_scope(&state, &host, StatusCode::NOT_FOUND.into_response()).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let group = match db::group_by_name(&state.db, &name).await {
        Ok(Some(g)) => g,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return db_error(e, "group_by_name lookup failed"),
    };
    serve_group_scoped(&state, scope, group).await
}

async fn group_by_gid(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(gid): Path<u32>,
) -> Response {
    let scope = match resolve_scope(&state, &host, StatusCode::NOT_FOUND.into_response()).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let group = match db::group_by_gid(&state.db, gid).await {
        Ok(Some(g)) => g,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return db_error(e, "group_by_gid lookup failed"),
    };
    serve_group_scoped(&state, scope, group).await
}

/// Return the group with its members, enforcing scope: an unscoped host gets
/// any group; a scoped host gets the group ONLY if it is the allowed gid.
async fn serve_group_scoped(
    state: &AppState,
    scope: Option<u32>,
    group: db::PosixGroup,
) -> Response {
    if let Some(allowed) = scope {
        if group.gid as u32 != allowed {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    match db::group_member_usernames(&state.db, group.gid as u32).await {
        Ok(members) => Json(GroupEntry {
            name: group.name,
            gid: group.gid as u32,
            members,
        })
        .into_response(),
        Err(e) => db_error(e, "group member lookup failed"),
    }
}

/// Build a `GroupEntry` for `gid` (the group row + its members), or `None`
/// when the group doesn't exist.
async fn group_entry(state: &AppState, gid: u32) -> anyhow::Result<Option<GroupEntry>> {
    let Some(group) = db::group_by_gid(&state.db, gid).await? else {
        return Ok(None);
    };
    let members = db::group_member_usernames(&state.db, gid).await?;
    Ok(Some(GroupEntry {
        name: group.name,
        gid: group.gid as u32,
        members,
    }))
}

async fn authorized_keys(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(name): Path<String>,
) -> Response {
    // Empty body is the "no keys" answer sshd expects; reuse it for every
    // miss (misconfigured host, unknown/disabled account, out-of-scope).
    let account = match db::account_by_username(&state.db, &name).await {
        Ok(Some(a)) if a.enabled == 1 => a,
        Ok(_) => return text_plain(String::new()),
        Err(e) => return db_error(e, "authorized_keys account lookup failed"),
    };
    match scope::account_visible_on_host(&state.db, &host, &account).await {
        Ok(true) => {}
        Ok(false) => return text_plain(String::new()),
        Err(e) => return db_error(e, "authorized_keys scope check failed"),
    }
    let keys = match db::authorized_keys_for(&state.db, &account.identity_id).await {
        Ok(k) => k,
        Err(e) => return db_error(e, "authorized_keys query failed"),
    };
    let now = chrono::Utc::now();
    let body = keys
        .into_iter()
        // Serve-time expiry: drop any key whose expires_at is past.
        .filter(|k| {
            k.expires_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .is_none_or(|exp| exp.with_timezone(&chrono::Utc) > now)
        })
        .map(|k| k.public_key)
        .collect::<Vec<_>>()
        .join("\n");
    text_plain(body)
}

fn text_plain(body: String) -> Response {
    ([(axum::http::header::CONTENT_TYPE, "text/plain")], body).into_response()
}

// --- offline auth (M3a) --------------------------------------------------

/// The complete current set of offline verifiers this host may verify against
/// while partitioned. The host wholesale-replaces its keystore from the result,
/// so withdrawal (disable / de-scope / clear / force_mfa-flip) is just absence
/// from the next pull.
///
/// force_mfa hosts get an **empty** set unconditionally: an MFA host requires
/// network for login, closing the AAL2-downgrade where going offline would skip
/// the second factor. This check precedes any DB work.
async fn offline_verifiers(State(state): State<AppState>, host: RequirePosixHost) -> Response {
    if !state.cfg.posix.offline_auth_enabled || host.force_mfa {
        return Json(OfflineVerifiersResponse { verifiers: vec![] }).into_response();
    }

    // Candidate accounts = the accounts visible on this host: scoped hosts see
    // their org-group members, unscoped hosts see every enabled account. (Unlike
    // `passwd_all`, an unscoped host DOES get the offline set — it can already
    // resolve+authenticate these users online.) `accounts_in_gid` and
    // `list_enabled_accounts` both filter `enabled = 1` already.
    let scope = match resolve_scope(
        &state,
        &host,
        Json(OfflineVerifiersResponse { verifiers: vec![] }).into_response(),
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    let candidates = match scope {
        None => match db::list_enabled_accounts(&state.db).await {
            Ok(rows) => rows,
            Err(e) => return db_error(e, "offline_verifiers unscoped account query failed"),
        },
        Some(gid) => match db::accounts_in_gid(&state.db, gid).await {
            Ok(rows) => rows,
            Err(e) => return db_error(e, "offline_verifiers scoped account query failed"),
        },
    };

    let ids: Vec<String> = candidates.iter().map(|a| a.identity_id.clone()).collect();
    let secrets = match db::offline_secrets_for_identities(&state.db, ids).await {
        Ok(rows) => rows,
        Err(e) => return db_error(e, "offline_verifiers secret lookup failed"),
    };
    let by_id: std::collections::HashMap<String, (String, i32)> = secrets
        .into_iter()
        .map(|(id, verifier, algo)| (id, (verifier, algo)))
        .collect();

    let ttl_secs = state.cfg.posix.offline_ttl_hours.saturating_mul(3600) as i64;
    let verifiers: Vec<OfflineVerifier> = candidates
        .into_iter()
        .filter_map(|a| {
            let (verifier, algo_version) = by_id.get(&a.identity_id).cloned()?;
            Some(OfflineVerifier {
                username: a.username,
                verifier,
                ttl_secs,
                algo_version,
            })
        })
        .collect();

    Json(OfflineVerifiersResponse { verifiers }).into_response()
}

/// Hard cap on a single offline-audit batch. A host queues offline-auth events
/// while partitioned and flushes them on reconnect; bound the batch so a
/// compromised or buggy host can't flood the audit table in one request.
const OFFLINE_AUDIT_MAX_BATCH: usize = 256;

#[derive(serde::Deserialize)]
struct OfflineAuditBatch {
    events: Vec<OfflineAuditEvent>,
}

#[derive(serde::Deserialize)]
struct OfflineAuditEvent {
    username: String,
    /// `"success"` → succeeded action; anything else → failed.
    result: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    occurred_at: String,
}

/// Ingest a host's queued offline-auth events into the server audit log. Each
/// event lands as a `posix.offline.auth_{succeeded,failed}` row carrying only
/// host_id + username + a coarse reason (the SafeMetadata deny-list blocks the
/// passphrase/verifier regardless). Malformed entries are skipped; an oversized
/// batch is rejected outright.
async fn offline_audit(
    State(state): State<AppState>,
    host: RequirePosixHost,
    JsonBody(batch): JsonBody<OfflineAuditBatch>,
) -> Response {
    if batch.events.len() > OFFLINE_AUDIT_MAX_BATCH {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    let mut written = 0usize;
    for ev in batch.events {
        // Skip garbage: an event with no username carries nothing auditable.
        if ev.username.trim().is_empty() {
            continue;
        }
        let success = ev.result == "success";
        let action = if success {
            action::POSIX_OFFLINE_AUTH_SUCCEEDED
        } else {
            action::POSIX_OFFLINE_AUTH_FAILED
        };
        // Coarse reason only; truncate so a hostile host can't bloat the row.
        let reason: String = ev.reason.chars().take(128).collect();
        let occurred: String = ev.occurred_at.chars().take(64).collect();
        let meta = SafeMetadata::from_pairs(&[
            ("host_id", serde_json::Value::String(host.host_id.clone())),
            ("username", serde_json::Value::String(ev.username.clone())),
            ("reason", serde_json::Value::String(reason)),
            ("occurred_at", serde_json::Value::String(occurred)),
        ]);
        let mut event = AuditEvent::new(action)
            .target(target_kind::HOST, host.host_id.clone())
            .metadata(meta);
        if !success {
            event = event.failed("offline auth failed");
        }
        let _ = audit::log(&state.db, event).await;
        written += 1;
    }

    Json(serde_json::json!({ "accepted": written })).into_response()
}
