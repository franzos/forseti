//! The `/posix/v1/*` resolver HTTP API consumed by enrolled hosts' NSS/SSH
//! integration. Every handler is gated by the [`RequirePosixHost`] Basic-auth
//! extractor.
//!
//! Access control hinges on the host's org/team scope (see [`scope`]):
//! - whole-org (no allowed teams): resolves provisioned members of the host's
//!   org; `group` enumeration emits each org team that has a gid.
//! - team-scoped (one or more allowed teams): restricted to provisioned members
//!   of those teams (any-of-N); `group` enumeration emits only those teams. Each
//!   team's org is asserted == the host's org in the db layer, so a cross-org
//!   team can never widen visibility.
//!
//! Group lookups also resolve user-private groups (UPG): a gid/name mapping to a
//! `kind = "user"` group is served single-member, but only when its owning
//! account is visible on the host. UPGs are never enumerated.

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

/// Coarse per-source-IP resolver rate limit; hosts behind one NAT share a bucket.
const RESOLVER_RATE_PER_MINUTE: u32 = 600;

fn rate_limit_error(_err: tower_governor::GovernorError) -> Response {
    StatusCode::TOO_MANY_REQUESTS.into_response()
}

pub fn router(state: AppState) -> Router<AppState> {
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

    // Resolution is never license-gated: the free tier resolves up to
    // `free_seats` accounts, and an already-provisioned account keeps resolving
    // whatever the license state. `Feature::LinuxAuth` only caps *provisioning*
    // (src/admin/posix.rs), never reads.
    rate_limit::single_window(
        r,
        state.cfg.proxy.trust_forwarded_for,
        60_000,
        RESOLVER_RATE_PER_MINUTE,
        rate_limit_error,
    )
}

/// 500, not 404: a db error must not look like a miss to the daemon.
fn db_error(e: anyhow::Error, ctx: &str) -> Response {
    tracing::error!(error = ?e, "posix resolver: {ctx}");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// A host's resolved scope. Always carries the host's org.
enum HostScope {
    /// Empty allowed-team set: any provisioned member of the org may log in;
    /// no org-level group is emitted.
    WholeOrg(String),
    /// Restricted to these team uuids (any-of-N), all within the org.
    Teams(String, Vec<String>),
}

async fn resolve_scope(state: &AppState, host: &RequirePosixHost) -> Result<HostScope, Response> {
    let team_ids = match db::host_allowed_team_ids(&state.db, &host.host_id).await {
        Ok(t) => t,
        Err(e) => return Err(db_error(e, "scope load failed")),
    };
    if team_ids.is_empty() {
        Ok(HostScope::WholeOrg(host.org_id.clone()))
    } else {
        Ok(HostScope::Teams(host.org_id.clone(), team_ids))
    }
}

async fn passwd_all(State(state): State<AppState>, host: RequirePosixHost) -> Response {
    let accounts = match resolve_scope(&state, &host).await {
        Ok(HostScope::WholeOrg(org)) => db::accounts_in_org(&state.db, &org).await,
        Ok(HostScope::Teams(org, teams)) => accounts_in_teams(&state, &org, &teams).await,
        Err(r) => return r,
    };
    match accounts {
        Ok(a) => Json(a.into_iter().map(PasswdEntry::from).collect::<Vec<_>>()).into_response(),
        Err(e) => db_error(e, "passwd_all failed"),
    }
}

/// Union of provisioned members across teams, deduped by identity, stable by username.
async fn accounts_in_teams(
    state: &AppState,
    org: &str,
    teams: &[String],
) -> anyhow::Result<Vec<db::PosixAccount>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for tid in teams {
        for a in db::accounts_in_team(&state.db, org, tid).await? {
            if seen.insert(a.identity_id.clone()) {
                out.push(a);
            }
        }
    }
    out.sort_by(|a, b| a.username.cmp(&b.username));
    Ok(out)
}

/// Uncapped [`accounts_in_teams`]: offline-verifier projection only.
async fn all_accounts_in_teams(
    state: &AppState,
    org: &str,
    teams: &[String],
) -> anyhow::Result<Vec<db::PosixAccount>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for tid in teams {
        for a in db::all_accounts_in_team(&state.db, org, tid).await? {
            if seen.insert(a.identity_id.clone()) {
                out.push(a);
            }
        }
    }
    out.sort_by(|a, b| a.username.cmp(&b.username));
    Ok(out)
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

/// Return the account as a passwd entry only if visible under
/// [`scope::account_visible_on_host`].
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
    let (org, teams) = match resolve_scope(&state, &host).await {
        Ok(HostScope::WholeOrg(org)) => match crate::orgs::teams::list_teams(&state.db, &org).await
        {
            Ok(ts) => (
                org,
                ts.into_iter()
                    .filter(|t| t.gid.is_some())
                    .map(|t| t.id)
                    .collect::<Vec<_>>(),
            ),
            Err(e) => return db_error(e, "group_all team list failed"),
        },
        Ok(HostScope::Teams(org, teams)) => (org, teams),
        Err(r) => return r,
    };
    let mut out = Vec::new();
    for tid in teams {
        match team_group_entry(&state, &org, &tid).await {
            Ok(Some(g)) => out.push(g),
            Ok(None) => {}
            Err(e) => return db_error(e, "group_all entry failed"),
        }
    }
    Json(out).into_response()
}

/// GroupEntry for a team (must have a gid + belong to org). UPG groups are NOT
/// enumerated here, only single-lookup.
async fn team_group_entry(
    state: &AppState,
    org: &str,
    team_id: &str,
) -> anyhow::Result<Option<GroupEntry>> {
    use crate::posix::allocate::posix_group_name;
    let Some(team) = crate::orgs::teams::list_teams(&state.db, org)
        .await?
        .into_iter()
        .find(|t| t.id == team_id)
    else {
        return Ok(None);
    };
    let Some(gid) = team.gid else {
        return Ok(None);
    };
    let members = db::accounts_in_team(&state.db, org, team_id)
        .await?
        .into_iter()
        .map(|a| a.username)
        .collect();
    Ok(Some(GroupEntry {
        name: posix_group_name(&team),
        gid: gid as u32,
        members,
    }))
}

async fn group_by_gid(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(gid): Path<u32>,
) -> Response {
    match db::team_by_gid_in_org(&state.db, &host.org_id, gid).await {
        Ok(Some(team)) => return serve_team_group(&state, &host.org_id, &team).await,
        Ok(None) => {}
        Err(e) => return db_error(e, "group_by_gid team lookup failed"),
    }
    serve_user_private_group_by_gid(&state, &host, gid).await
}

async fn serve_team_group(
    state: &AppState,
    org: &str,
    team: &crate::orgs::teams::Team,
) -> Response {
    use crate::posix::allocate::posix_group_name;
    let Some(gid) = team.gid else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match db::accounts_in_team(&state.db, org, &team.id).await {
        Ok(accts) => Json(GroupEntry {
            name: posix_group_name(team),
            gid: gid as u32,
            members: accts.into_iter().map(|a| a.username).collect(),
        })
        .into_response(),
        Err(e) => db_error(e, "team group members failed"),
    }
}

/// UPG by gid: served only if the owning account is visible on the host. uid !=
/// primary gid (separate sequence bands), so resolve via account_by_primary_gid,
/// not account_by_uid.
async fn serve_user_private_group_by_gid(
    state: &AppState,
    host: &RequirePosixHost,
    gid: u32,
) -> Response {
    let account = match db::group_by_gid(&state.db, gid).await {
        Ok(Some(g)) if g.kind == "user" => match db::account_by_primary_gid(&state.db, gid).await {
            Ok(Some(a)) => a,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => return db_error(e, "upg owner lookup failed"),
        },
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return db_error(e, "upg group lookup failed"),
    };
    match scope::account_visible_on_host(&state.db, host, &account).await {
        Ok(true) => Json(GroupEntry {
            name: account.username.clone(),
            gid,
            members: vec![account.username],
        })
        .into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => db_error(e, "upg scope check failed"),
    }
}

async fn group_by_name(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(name): Path<String>,
) -> Response {
    match db::team_by_posix_name_in_org(&state.db, &host.org_id, &name).await {
        Ok(Some(team)) => return serve_team_group(&state, &host.org_id, &team).await,
        Ok(None) => {}
        Err(e) => return db_error(e, "group_by_name team lookup failed"),
    }
    let account = match db::account_by_username(&state.db, &name).await {
        Ok(Some(a)) if a.enabled == 1 => a,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return db_error(e, "group_by_name upg lookup failed"),
    };
    match scope::account_visible_on_host(&state.db, &host, &account).await {
        Ok(true) => Json(GroupEntry {
            name: account.username.clone(),
            gid: account.gid as u32,
            members: vec![account.username],
        })
        .into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => db_error(e, "group_by_name scope failed"),
    }
}

async fn authorized_keys(
    State(state): State<AppState>,
    host: RequirePosixHost,
    Path(name): Path<String>,
) -> Response {
    // Empty body is sshd's "no keys"; reuse it for every miss so a probe can't
    // distinguish unknown/disabled/out-of-scope.
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
        // Serve-time expiry.
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
/// while partitioned. The host wholesale-replaces its keystore, so withdrawal
/// (disable / de-scope / clear / force_mfa-flip) is just absence from the next pull.
///
/// force_mfa hosts get an empty set unconditionally: closes the AAL2-downgrade
/// where going offline would skip the second factor. Checked before any DB work.
async fn offline_verifiers(State(state): State<AppState>, host: RequirePosixHost) -> Response {
    if !state.cfg.posix.offline_auth_enabled || host.force_mfa {
        return Json(OfflineVerifiersResponse { verifiers: vec![] }).into_response();
    }

    // Candidates: accounts visible under the host's scope (both queries filter
    // enabled=1). Uncapped: this is an auth-decision surface, so it must be
    // complete (the NSS enumeration queries stay capped).
    let candidates = match resolve_scope(&state, &host).await {
        Ok(HostScope::WholeOrg(org)) => match db::all_accounts_in_org(&state.db, &org).await {
            Ok(rows) => rows,
            Err(e) => return db_error(e, "offline_verifiers org query failed"),
        },
        Ok(HostScope::Teams(org, teams)) => {
            match all_accounts_in_teams(&state, &org, &teams).await {
                Ok(rows) => rows,
                Err(e) => return db_error(e, "offline_verifiers team query failed"),
            }
        }
        Err(r) => return r,
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

/// Cap on a single offline-audit batch so a compromised/buggy host can't flood
/// the audit table in one request.
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

/// Ingest a host's queued offline-auth events into the server audit log as
/// `posix.offline.auth_{succeeded,failed}` rows (host_id + username + coarse
/// reason; SafeMetadata blocks the passphrase/verifier regardless). Malformed
/// entries are skipped; an oversized batch is rejected. `accepted` counts only
/// rows that actually persisted, so the host retries anything that didn't.
async fn offline_audit(
    State(state): State<AppState>,
    host: RequirePosixHost,
    JsonBody(batch): JsonBody<OfflineAuditBatch>,
) -> Response {
    if batch.events.len() > OFFLINE_AUDIT_MAX_BATCH {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    let mut events = Vec::new();
    for ev in batch.events {
        // No username means nothing auditable.
        if ev.username.trim().is_empty() {
            continue;
        }
        let success = ev.result == "success";
        let action = if success {
            action::POSIX_OFFLINE_AUTH_SUCCEEDED
        } else {
            action::POSIX_OFFLINE_AUTH_FAILED
        };
        // Truncate so a hostile host can't bloat the row.
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
        events.push(event);
    }

    // One insert; on failure zero rows landed and the host keeps its queue.
    let written = audit::log_batch(&state.db, events).await.unwrap_or(0);

    Json(serde_json::json!({ "accepted": written })).into_response()
}
