use crate::cache::Cache;
use crate::config::Config;
use crate::device::{
    capped_expiry, DeviceClient, DeviceFlowState, InitOutcome, SessionLookup, SessionStore,
};
use crate::upstream::Upstream;
use anyhow::{Context, Result};
use forseti_unix_proto::{
    ClientRequest, ClientResponse, PamRequest, PamResponse, MAX_REQUEST_FRAME,
};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

/// Per-frame idle bound. A legitimate NSS/PAM caller writes its request frame
/// immediately; a peer that opens the (0666) socket and stalls a half-written
/// frame is a slowloris, so drop it well before it pins a task indefinitely.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on concurrent in-flight connections. The socket is world-connectable,
/// so this bounds task/buffer growth. Generous enough to never starve real NSS
/// lookups; acquisition awaits a permit rather than dropping, so a momentary
/// burst queues instead of failing a lookup.
const MAX_CONNECTIONS: usize = 128;

struct Handler {
    upstream: Upstream,
    cache: Cache,
    ttl_secs: u64,
    device: DeviceClient,
    sessions: SessionStore,
    session_cap_secs: u64,
    keystore: crate::offline::Keystore,
}

/// A frame is unambiguously one protocol or the other — `ClientRequest` (NSS,
/// world-callable) and `PamRequest` (device-auth, root-gated) have disjoint
/// variant names — so we decode by trying each in turn.
enum Frame {
    Nss(ClientRequest),
    Pam(PamRequest),
}

/// Peer-credential gate for `PamRequest` opcodes only (R2, security-critical).
///
/// Only root (sshd/login pre-auth context) may drive device-auth: `device/init`
/// is a confused-deputy lever (it mints a phishable `user_code`). kanidm does
/// not gate its password challenge; we must, because ours is phishable. NSS
/// opcodes stay world-callable. Returns true iff the peer may issue PamRequests.
fn pam_peer_allowed(peer_uid: Option<u32>) -> bool {
    // None == peer_cred() errored → fail closed.
    peer_uid == Some(0)
}

/// SshKeys is deliberately uncacheable: the resolver returns plain key lines
/// without the server-side `expires_at`, so the daemon can't re-check expiry —
/// caching would risk serving keys past their TTL. Always fetch fresh.
fn cache_key(req: &ClientRequest) -> Option<String> {
    match req {
        ClientRequest::PasswdByName(n) => Some(format!("passwd_name:{n}")),
        ClientRequest::PasswdByUid(u) => Some(format!("passwd_uid:{u}")),
        ClientRequest::PasswdAll => Some("passwd_all".to_string()),
        ClientRequest::GroupByName(n) => Some(format!("group_name:{n}")),
        ClientRequest::GroupByGid(g) => Some(format!("group_gid:{g}")),
        ClientRequest::GroupAll => Some("group_all".to_string()),
        ClientRequest::SshKeys(_) => None,
    }
}

/// Fail-soft "absent" response per request kind — never an Error frame, which
/// the NSS client would treat as "service unavailable".
fn empty_response(req: &ClientRequest) -> ClientResponse {
    match req {
        ClientRequest::PasswdByName(_) | ClientRequest::PasswdByUid(_) => {
            ClientResponse::Passwd(None)
        }
        ClientRequest::PasswdAll => ClientResponse::PasswdList(Vec::new()),
        ClientRequest::GroupByName(_) | ClientRequest::GroupByGid(_) => ClientResponse::Group(None),
        ClientRequest::GroupAll => ClientResponse::GroupList(Vec::new()),
        ClientRequest::SshKeys(_) => ClientResponse::SshKeys(Vec::new()),
    }
}

impl Handler {
    async fn fetch_upstream(&self, req: &ClientRequest) -> Result<ClientResponse> {
        match req {
            ClientRequest::PasswdByName(n) => self.upstream.passwd_by_name(n).await,
            ClientRequest::PasswdByUid(u) => self.upstream.passwd_by_uid(*u).await,
            ClientRequest::PasswdAll => self.upstream.passwd_all().await,
            ClientRequest::GroupByName(n) => self.upstream.group_by_name(n).await,
            ClientRequest::GroupByGid(g) => self.upstream.group_by_gid(*g).await,
            ClientRequest::GroupAll => self.upstream.group_all().await,
            ClientRequest::SshKeys(n) => self.upstream.ssh_keys(n).await,
        }
    }

    async fn dispatch(&self, req: ClientRequest) -> ClientResponse {
        let key = cache_key(&req);

        if let Some(k) = &key {
            if let Some(hit) = self.cache.get(k, self.ttl_secs) {
                return hit;
            }
        }

        match self.fetch_upstream(&req).await {
            Ok(resp) => {
                if let Some(k) = &key {
                    if let Err(e) = self.cache.put(k, &resp) {
                        tracing::warn!(error = %e, key = %k, "cache write failed");
                    }
                }
                resp
            }
            Err(e) => {
                // Fail-soft: serve an unexpired cache entry if one exists, else "absent".
                tracing::warn!(error = %e, "upstream request failed");
                if let Some(k) = &key {
                    if let Some(hit) = self.cache.get(k, self.ttl_secs) {
                        return hit;
                    }
                }
                empty_response(&req)
            }
        }
    }

    /// Dispatch a root-gated PAM device-auth request. The caller has already
    /// verified peer credentials.
    async fn dispatch_pam(&self, req: PamRequest) -> PamResponse {
        match req {
            PamRequest::AuthBegin { username } => self.auth_begin(&username).await,
            PamRequest::AuthPoll { session_id } => self.auth_poll(&session_id).await,
            PamRequest::AccountAllowed { username } => self.account_allowed(&username).await,
            PamRequest::OfflineAuthStep { username, secret } => {
                self.offline_auth_step(&username, &secret).await
            }
        }
    }

    /// Local offline verification (server-unreachable path). Gates + verifies
    /// the passphrase against the keystore and queues an audit event. Runs on a
    /// blocking task so the synchronous Argon2id KDF doesn't stall the runtime.
    async fn offline_auth_step(&self, username: &str, secret: &str) -> PamResponse {
        use crate::offline::OfflineVerifyOutcome;
        let now = now_secs();
        let ks = self.keystore.clone();
        let user = username.to_string();
        let pass = secret.to_string();
        let outcome = tokio::task::spawn_blocking(move || ks.verify(&user, &pass, now))
            .await
            .unwrap_or(OfflineVerifyOutcome::Denied(
                crate::offline::OfflineRefuseReason::LockedOut,
            ));
        let (resp, result, reason) = match outcome {
            OfflineVerifyOutcome::Ok => (PamResponse::OfflineSuccess, "ok", "ok".to_string()),
            OfflineVerifyOutcome::NoCred => (
                PamResponse::OfflineDenied {
                    reason: "no_cred".into(),
                },
                "deny",
                "no_cred".to_string(),
            ),
            OfflineVerifyOutcome::Denied(r) => (
                PamResponse::OfflineDenied {
                    reason: r.as_str().into(),
                },
                "deny",
                r.as_str().to_string(),
            ),
        };
        let event = serde_json::json!({
            "username": username,
            "result": result,
            "reason": reason,
            "occurred_at": now,
        })
        .to_string();
        if let Err(e) = self.keystore.enqueue_audit(&event, now) {
            tracing::error!(error = %e, "failed to enqueue offline audit event");
        }
        resp
    }

    async fn auth_begin(&self, username: &str) -> PamResponse {
        match self.device.init(username).await {
            // 404: not a Forseti account / not allowed here → PAM_IGNORE.
            // Server reached + denied here, so NO offline fallback.
            InitOutcome::Unknown => PamResponse::Unknown,
            // Transport/server failure (server UNREACHABLE) is the only branch
            // eligible for offline auth: if a usable, non-expired cred exists,
            // signal OfflineAvailable; otherwise stay PAM_AUTHINFO_UNAVAIL.
            InitOutcome::Unavailable => {
                if self.keystore.has_usable_cred(username, now_secs()) {
                    PamResponse::OfflineAvailable
                } else {
                    PamResponse::Denied {
                        reason: "unavailable".into(),
                    }
                }
            }
            InitOutcome::Started(init) => {
                let expires_at =
                    capped_expiry(Instant::now(), init.expires_in, self.session_cap_secs);
                let state = DeviceFlowState {
                    device_code: init.device_code,
                    interval: init.interval,
                    expires_at,
                    username: Some(username.to_string()),
                };
                match self.sessions.insert(state) {
                    Some(session_id) => PamResponse::ShowDeviceCode {
                        session_id,
                        verification_uri: init.verification_uri,
                        user_code: init.user_code,
                        interval: init.interval,
                        expires_in: init.expires_in,
                    },
                    // Concurrent-session cap hit; treat as temporarily unavailable.
                    None => {
                        tracing::warn!("device session cap reached; refusing AuthBegin");
                        PamResponse::Denied {
                            reason: "unavailable".into(),
                        }
                    }
                }
            }
        }
    }

    async fn auth_poll(&self, session_id: &str) -> PamResponse {
        let state = match self.sessions.get_live(session_id) {
            SessionLookup::Found(s) => s,
            // Absent or past hard expiry.
            SessionLookup::Expired => {
                return PamResponse::Denied {
                    reason: "expired".into(),
                }
            }
        };

        match self.device.poll(&state.device_code).await {
            Ok(poll) => match poll.status.as_str() {
                "pending" => {
                    // Forseti owns the backoff; widen our stored interval on slow_down.
                    if let Some(i) = poll.interval {
                        self.sessions.set_interval(session_id, i);
                    }
                    PamResponse::Pending
                }
                "approved" => {
                    self.sessions.remove(session_id);
                    // Stamp the offline ceiling to this genuine ONLINE auth so
                    // offline_max_lifetime tracks the last real login. Best-effort
                    // and a no-op if the user has no provisioned cred yet.
                    if let Some(u) = &state.username {
                        if let Err(e) = self.keystore.set_last_online_auth(u, now_secs()) {
                            tracing::warn!(error = %e, "stamping last_online_auth failed");
                        }
                    }
                    PamResponse::Success
                }
                "denied" | "expired" => {
                    self.sessions.remove(session_id);
                    PamResponse::Denied {
                        reason: poll.reason.unwrap_or_else(|| poll.status.clone()),
                    }
                }
                other => {
                    tracing::warn!(status = %other, "unexpected device/poll status");
                    PamResponse::Pending
                }
            },
            Err(e) => {
                // Transient: keep the session, let PAM retry on the next poll.
                tracing::warn!(error = %e, "device/poll failed; staying pending");
                PamResponse::Pending
            }
        }
    }

    /// `account` hook. 200 → allowed (Success); 404 (clean) → Unknown (PAM_IGNORE
    /// → falls through to pam_unix, which denies the shadow-less NSS-only user).
    ///
    /// On a transport/server-unreachable failure (`Err`, NOT a clean 404) we
    /// answer from the M1 cache's last-known passwd entry: a user present there
    /// was last-seen visible+enabled (the resolver only caches visible accounts),
    /// so the account phase clears for an offline-authed user. Absent from the
    /// cache → Unknown (fail-safe: a Forseti-only user is still denied downstream
    /// by pam_unix). A passwd lookup is cheap enough to run on the NSS upstream.
    async fn account_allowed(&self, username: &str) -> PamResponse {
        match self.upstream.passwd_by_name(username).await {
            Ok(ClientResponse::Passwd(Some(_))) => PamResponse::Success,
            // Clean 404: the server is reachable and says no — never fall back.
            Ok(ClientResponse::Passwd(None)) => PamResponse::Unknown,
            Ok(other) => {
                tracing::warn!(?other, "unexpected passwd response in account_allowed");
                PamResponse::Unknown
            }
            Err(e) => {
                // Server unreachable: answer from the last-known cache entry.
                tracing::warn!(error = %e, "account_allowed lookup failed; consulting cache");
                match self.cache.get_any(&format!("passwd_name:{username}")) {
                    Some(ClientResponse::Passwd(Some(_))) => PamResponse::Success,
                    _ => PamResponse::Unknown,
                }
            }
        }
    }
}

/// Read one frame and classify it. The NSS `.so` keeps sending `ClientRequest`;
/// a `PamRequest` frame is detected by falling through to the second decode.
async fn read_frame(stream: &mut UnixStream) -> Result<Option<Frame>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading frame length"),
    }
    let len = u32::from_be_bytes(len_buf);
    // Requests are tiny; reject oversize before allocating.
    if len > MAX_REQUEST_FRAME {
        anyhow::bail!("request frame exceeds MAX_REQUEST_FRAME");
    }
    let mut body = vec![0u8; len as usize];
    stream
        .read_exact(&mut body)
        .await
        .context("reading frame body")?;
    if let Ok(req) = serde_json::from_slice::<ClientRequest>(&body) {
        return Ok(Some(Frame::Nss(req)));
    }
    let req: PamRequest = serde_json::from_slice(&body).context("decoding request frame")?;
    Ok(Some(Frame::Pam(req)))
}

async fn write_response<T: serde::Serialize>(stream: &mut UnixStream, resp: &T) -> Result<()> {
    let body = serde_json::to_vec(resp).context("encoding response")?;
    let len = u32::try_from(body.len()).context("response too large")?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

/// PAM responses for a peer that failed the root gate (R2). `AuthBegin`/
/// `AccountAllowed` → `Unknown`; `AuthPoll` → `Denied{forbidden}`.
fn pam_forbidden(req: &PamRequest) -> PamResponse {
    match req {
        PamRequest::AuthBegin { .. } | PamRequest::AccountAllowed { .. } => PamResponse::Unknown,
        PamRequest::AuthPoll { .. } => PamResponse::Denied {
            reason: "forbidden".into(),
        },
        PamRequest::OfflineAuthStep { .. } => PamResponse::OfflineDenied {
            reason: "forbidden".into(),
        },
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn handle_conn(handler: Arc<Handler>, mut stream: UnixStream) {
    // Captured by the kernel at connect → TOCTOU-free. NSS opcodes stay
    // ungated; only PamRequest opcodes consult this.
    let peer_uid = stream.peer_cred().ok().map(|c| c.uid());

    loop {
        let framed = match tokio::time::timeout(FRAME_READ_TIMEOUT, read_frame(&mut stream)).await {
            Ok(r) => r,
            Err(_) => {
                tracing::debug!("frame read timed out; closing conn");
                return;
            }
        };
        match framed {
            Ok(Some(Frame::Nss(req))) => {
                let resp = handler.dispatch(req).await;
                if let Err(e) = write_response(&mut stream, &resp).await {
                    tracing::debug!(error = %e, "write response failed; closing conn");
                    return;
                }
            }
            Ok(Some(Frame::Pam(req))) => {
                let resp = if pam_peer_allowed(peer_uid) {
                    handler.dispatch_pam(req).await
                } else {
                    tracing::warn!(?peer_uid, "rejecting PamRequest from non-root peer");
                    pam_forbidden(&req)
                };
                if let Err(e) = write_response(&mut stream, &resp).await {
                    tracing::debug!(error = %e, "write pam response failed; closing conn");
                    return;
                }
            }
            Ok(None) => return, // clean EOF
            Err(e) => {
                tracing::debug!(error = %e, "read request failed; closing conn");
                return;
            }
        }
    }
}

/// The parent dir of the socket must exist, be owned by root or the current
/// euid, and not be group/world-writable — otherwise an attacker could swap in
/// a rogue socket and harvest lookups.
fn check_socket_dir(socket_path: &Path) -> Result<()> {
    check_parent_dir(socket_path, "socket")
}

/// The parent dir of the credentials DB must satisfy the same constraints as
/// the socket dir: an attacker who can write there could swap in a keystore
/// holding a chosen verifier or read the host pepper.
fn check_credentials_dir(creds_path: &Path) -> Result<()> {
    check_parent_dir(creds_path, "credentials")
}

/// Shared predicate: `path`'s parent must exist, not be group/world-writable,
/// and be owned by root or the current euid.
fn check_parent_dir(path: &Path, label: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .with_context(|| format!("{label} path has no parent directory"))?;
    let meta = std::fs::metadata(parent)
        .with_context(|| format!("{label} dir {} does not exist", parent.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        anyhow::bail!(
            "{label} dir {} is group/world-writable (mode {:o}); refusing to start",
            parent.display(),
            mode & 0o7777
        );
    }
    use std::os::unix::fs::MetadataExt;
    let owner = meta.uid();
    let euid = unsafe { libc::geteuid() };
    if owner != 0 && owner != euid {
        anyhow::bail!(
            "{label} dir {} is owned by uid {} (not root or {}); refusing to start",
            parent.display(),
            owner,
            euid
        );
    }
    Ok(())
}

/// Bind the Unix socket and serve until a shutdown signal arrives.
pub async fn run(config: Config) -> Result<()> {
    // The network-facing, secret-holding process must never be root.
    if unsafe { libc::geteuid() } == 0 {
        anyhow::bail!("forseti-unixd refuses to run as root");
    }

    let socket_path = std::path::PathBuf::from(&config.socket_path);
    check_socket_dir(&socket_path)?;

    let upstream = Upstream::new(
        &config.server_url,
        &config.host_id,
        &config.host_secret,
        config.request_timeout_secs,
    )?;
    let cache = Cache::open(Path::new(&config.cache_db))?;
    // Own client/timeout for the device path; never reuses the NSS Upstream.
    let device = DeviceClient::new(
        &config.server_url,
        &config.host_id,
        &config.host_secret,
        config.device_timeout_secs,
    )?;

    // Offline-auth keystore + provisioning poller.
    let creds_path = std::path::PathBuf::from(&config.credentials_db);
    check_credentials_dir(&creds_path)?;
    let keystore = crate::offline::Keystore::open(
        &creds_path,
        config.offline_lockout_max,
        config.offline_max_lifetime_secs,
    )?;
    let poller = crate::provision::Poller::new(
        &config.server_url,
        &config.host_id,
        &config.host_secret,
        config.request_timeout_secs,
        keystore.clone(),
        config.offline_poll_secs,
    )?;
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let poller_handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move { poller.run(shutdown).await })
    };

    let handler = Arc::new(Handler {
        upstream,
        cache,
        ttl_secs: config.cache_ttl_secs,
        device,
        sessions: SessionStore::new(),
        session_cap_secs: config.device_session_cap_secs,
        keystore: keystore.clone(),
    });

    // Remove a stale socket from a previous run before binding.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("removing stale socket {}", socket_path.display()))?;
    }
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding socket {}", socket_path.display()))?;
    // NSS must be able to connect from any uid; only public data crosses this socket.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
        .context("setting socket permissions")?;

    tracing::info!(socket = %socket_path.display(), "forseti-unixd listening");

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    let conn_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        // Acquire a permit before accepting so backlog stays in the kernel, not in userspace fds.
        let permit = tokio::select! {
            p = conn_limit.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break, // semaphore is never closed; treat as shutdown
            },
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received; shutting down");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received; shutting down");
                break;
            }
        };

        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let h = handler.clone();
                        // Permit held for the connection lifetime, released when handle_conn returns.
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_conn(h, stream).await;
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "accept failed"),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received; shutting down");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received; shutting down");
                break;
            }
        }
    }

    drop(listener);
    let _ = std::fs::remove_file(&socket_path);

    // Stop the poller cleanly so an in-flight pull/flush isn't aborted mid-write.
    shutdown.notify_one();
    if let Err(e) = poller_handle.await {
        tracing::warn!(error = %e, "provisioning poller join failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_skips_ssh_keys() {
        assert_eq!(cache_key(&ClientRequest::SshKeys("alice".into())), None);
        assert_eq!(
            cache_key(&ClientRequest::PasswdByName("alice".into())),
            Some("passwd_name:alice".to_string())
        );
        assert_eq!(
            cache_key(&ClientRequest::PasswdAll),
            Some("passwd_all".to_string())
        );
    }

    #[test]
    fn empty_response_matches_kind() {
        assert_eq!(
            empty_response(&ClientRequest::PasswdByName("x".into())),
            ClientResponse::Passwd(None)
        );
        assert_eq!(
            empty_response(&ClientRequest::GroupAll),
            ClientResponse::GroupList(Vec::new())
        );
        assert_eq!(
            empty_response(&ClientRequest::SshKeys("x".into())),
            ClientResponse::SshKeys(Vec::new())
        );
    }

    #[test]
    fn pam_gate_allows_only_root() {
        assert!(pam_peer_allowed(Some(0)));
        assert!(!pam_peer_allowed(Some(1000)));
        assert!(!pam_peer_allowed(Some(1)));
        // peer_cred() error → fail closed.
        assert!(!pam_peer_allowed(None));
    }

    #[test]
    fn check_credentials_dir_accepts_owned_unwritable_dir() {
        let dir = tempfile::tempdir().unwrap();
        // A tempdir is owned by the current euid and not group/world-writable.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = dir.path().join("credentials.db");
        assert!(check_credentials_dir(&db).is_ok());
    }

    #[test]
    fn check_credentials_dir_rejects_group_writable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let db = dir.path().join("credentials.db");
        assert!(check_credentials_dir(&db).is_err());
    }

    #[test]
    fn check_credentials_dir_rejects_missing_parent() {
        let db = Path::new("/nonexistent-forseti-test-dir-xyz/credentials.db");
        assert!(check_credentials_dir(db).is_err());
    }

    #[test]
    fn pam_forbidden_maps_by_opcode() {
        assert_eq!(
            pam_forbidden(&PamRequest::AuthBegin {
                username: "x".into()
            }),
            PamResponse::Unknown
        );
        assert_eq!(
            pam_forbidden(&PamRequest::AccountAllowed {
                username: "x".into()
            }),
            PamResponse::Unknown
        );
        assert_eq!(
            pam_forbidden(&PamRequest::AuthPoll {
                session_id: "s".into()
            }),
            PamResponse::Denied {
                reason: "forbidden".into()
            }
        );
    }

    // Dual-format dispatch: feed a framed payload through the real read_frame
    // over a UnixStream pair and assert it classifies correctly.
    async fn classify(bytes: &[u8]) -> Frame {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let len = (bytes.len() as u32).to_be_bytes();
        writer.write_all(&len).await.unwrap();
        writer.write_all(bytes).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);
        read_frame(&mut reader).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn frame_classifies_nss_and_pam() {
        let nss = serde_json::to_vec(&ClientRequest::PasswdByName("alice".into())).unwrap();
        let pam = serde_json::to_vec(&PamRequest::AuthBegin {
            username: "alice".into(),
        })
        .unwrap();
        assert!(matches!(classify(&nss).await, Frame::Nss(_)));
        assert!(matches!(classify(&pam).await, Frame::Pam(_)));
    }

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn handler_for(url: &str) -> Handler {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::open(&dir.path().join("c.db")).unwrap();
        // Keep the tempdir alive for the duration of the test process; leaking
        // is acceptable in a unit test.
        std::mem::forget(dir);
        let ks_dir = tempfile::tempdir().unwrap();
        let keystore =
            crate::offline::Keystore::open(&ks_dir.path().join("creds.db"), 5, 604_800).unwrap();
        std::mem::forget(ks_dir);
        Handler {
            upstream: Upstream::new(url, "host", "secret", 3).unwrap(),
            cache,
            ttl_secs: 3600,
            device: DeviceClient::new(url, "host", "secret", 5).unwrap(),
            sessions: SessionStore::new(),
            session_cap_secs: 90,
            keystore,
        }
    }

    #[tokio::test]
    async fn auth_begin_started_returns_show_device_code() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "dc-1", "user_code": "WDJB-MJHT",
                "verification_uri": "https://idp.example/device",
                "interval": 5, "expires_in": 600
            })))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        match h.auth_begin("alice").await {
            PamResponse::ShowDeviceCode {
                user_code,
                verification_uri,
                ..
            } => {
                assert_eq!(user_code, "WDJB-MJHT");
                assert_eq!(verification_uri, "https://idp.example/device");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn auth_begin_404_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        assert_eq!(h.auth_begin("ghost").await, PamResponse::Unknown);
    }

    #[tokio::test]
    async fn auth_begin_error_is_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        assert_eq!(
            h.auth_begin("alice").await,
            PamResponse::Denied {
                reason: "unavailable".into()
            }
        );
    }

    #[tokio::test]
    async fn auth_begin_then_poll_pending_then_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "dc-1", "user_code": "WDJB-MJHT",
                "verification_uri": "https://idp.example/device",
                "interval": 5, "expires_in": 600
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/poll"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "status": "pending" })),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/poll"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "status": "approved" })),
            )
            .mount(&server)
            .await;

        let h = handler_for(&server.uri());
        let session_id = match h.auth_begin("alice").await {
            PamResponse::ShowDeviceCode { session_id, .. } => session_id,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(h.auth_poll(&session_id).await, PamResponse::Pending);
        assert_eq!(h.auth_poll(&session_id).await, PamResponse::Success);
        // Session dropped after success → next poll is expired.
        assert_eq!(
            h.auth_poll(&session_id).await,
            PamResponse::Denied {
                reason: "expired".into()
            }
        );
    }

    #[tokio::test]
    async fn auth_poll_unknown_session_is_expired() {
        let server = MockServer::start().await;
        let h = handler_for(&server.uri());
        assert_eq!(
            h.auth_poll("no-such-session").await,
            PamResponse::Denied {
                reason: "expired".into()
            }
        );
    }

    #[tokio::test]
    async fn account_allowed_200_is_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/alice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "alice", "uid": 2000000, "gid": 2000000,
                "gecos": "", "dir": "/home/alice", "shell": "/bin/sh"
            })))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        assert_eq!(h.account_allowed("alice").await, PamResponse::Success);
    }

    #[tokio::test]
    async fn account_allowed_404_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/ghost"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        assert_eq!(h.account_allowed("ghost").await, PamResponse::Unknown);
    }

    #[tokio::test]
    async fn account_allowed_error_without_cache_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/alice"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        // No cached passwd entry → fail-safe Unknown even on transport failure.
        assert_eq!(h.account_allowed("alice").await, PamResponse::Unknown);
    }

    // --- offline-auth trigger correctness ---

    fn mint_phc(passphrase: &str) -> String {
        use argon2::password_hash::rand_core::OsRng;
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{Algorithm, Argon2, Params, Version};
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(65536, 3, 1, None).unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon
            .hash_password(passphrase.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    fn cached_passwd(name: &str) -> ClientResponse {
        ClientResponse::Passwd(Some(forseti_unix_proto::PasswdEntry {
            name: name.into(),
            uid: 2_000_000,
            gid: 2_000_000,
            gecos: String::new(),
            dir: format!("/home/{name}"),
            shell: "/bin/sh".into(),
        }))
    }

    #[tokio::test]
    async fn auth_begin_unavailable_with_cred_offers_offline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        h.keystore
            .upsert_cred("alice", &mint_phc("correct horse battery"), 100_000, now_secs(), 1, now_secs())
            .unwrap();
        assert_eq!(h.auth_begin("alice").await, PamResponse::OfflineAvailable);
    }

    #[tokio::test]
    async fn auth_begin_unavailable_without_cred_is_denied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        // No provisioned cred → preserve the unavailable denial, no offline.
        assert_eq!(
            h.auth_begin("alice").await,
            PamResponse::Denied {
                reason: "unavailable".into()
            }
        );
    }

    #[tokio::test]
    async fn auth_begin_denied_404_never_offers_offline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        // Even with a usable cred, a server-reached 404 (Unknown) must NOT fall
        // back to offline — the server explicitly denied this user here.
        h.keystore
            .upsert_cred("alice", &mint_phc("correct horse battery"), 100_000, now_secs(), 1, now_secs())
            .unwrap();
        assert_eq!(h.auth_begin("alice").await, PamResponse::Unknown);
    }

    #[tokio::test]
    async fn account_allowed_transport_failure_answers_from_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/alice"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        // Seed the last-known passwd entry; transport failure → answer Success.
        h.cache.put("passwd_name:alice", &cached_passwd("alice")).unwrap();
        assert_eq!(h.account_allowed("alice").await, PamResponse::Success);
    }

    #[tokio::test]
    async fn account_allowed_clean_404_ignores_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/alice"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let h = handler_for(&server.uri());
        // A stale cache entry must NOT override a clean, server-reached 404.
        h.cache.put("passwd_name:alice", &cached_passwd("alice")).unwrap();
        assert_eq!(h.account_allowed("alice").await, PamResponse::Unknown);
    }
}
