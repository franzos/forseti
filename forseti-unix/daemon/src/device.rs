//! Device-authorization-grant driver for the PAM auth path (M2 Part C).
//!
//! Kept fully separate from the NSS `Upstream`: its own reqwest client (the
//! NSS ~3s timeout is tuned for sub-second passwd lookups, not the device
//! endpoints), its own session store, and it never touches the NSS cache mutex.

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Global cap on concurrent in-flight device sessions per daemon. A simple
/// global ceiling is enough for v1 — it bounds memory and limits how many
/// flows a single misbehaving caller can pin open.
pub const MAX_SESSIONS: usize = 256;

/// Forseti's `device/init` success body.
#[derive(Debug, Deserialize)]
pub struct InitResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u32,
    pub expires_in: u32,
}

/// Forseti's `device/poll` body. `status` is one of
/// `pending | approved | denied | expired`.
#[derive(Debug, Deserialize)]
pub struct PollResponse {
    pub status: String,
    #[serde(default)]
    pub interval: Option<u32>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Outcome of an init call, distinguishing the 404 "not a Forseti user here"
/// case (→ PAM_IGNORE) from a transport/server failure (→ PAM_AUTHINFO_UNAVAIL).
pub enum InitOutcome {
    Started(InitResponse),
    /// 404: username is not enabled/visible on this host.
    Unknown,
    /// Daemon→Forseti failure; PAM should fall through to the next module.
    Unavailable,
}

/// HTTP client for Forseti's host-authed `/posix/v1/device/{init,poll}`.
pub struct DeviceClient {
    client: reqwest::Client,
    server_url: String,
    auth_header: String,
}

impl DeviceClient {
    pub fn new(
        server_url: &str,
        host_id: &str,
        host_secret: &str,
        timeout_secs: u64,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("building device reqwest client")?;
        let creds =
            base64::engine::general_purpose::STANDARD.encode(format!("{host_id}:{host_secret}"));
        Ok(Self {
            client,
            server_url: server_url.trim_end_matches('/').to_string(),
            auth_header: format!("Basic {creds}"),
        })
    }

    pub async fn init(&self, username: &str) -> InitOutcome {
        let url = format!("{}/posix/v1/device/init", self.server_url);
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .json(&serde_json::json!({ "username": username }))
            .send()
            .await;
        match resp {
            Ok(r) if r.status() == StatusCode::OK => match r.json::<InitResponse>().await {
                Ok(body) => InitOutcome::Started(body),
                Err(e) => {
                    tracing::warn!(error = %e, "device/init decode failed");
                    InitOutcome::Unavailable
                }
            },
            Ok(r) if r.status() == StatusCode::NOT_FOUND => InitOutcome::Unknown,
            Ok(r) => {
                tracing::warn!(status = %r.status(), "device/init unexpected status");
                InitOutcome::Unavailable
            }
            Err(e) => {
                tracing::warn!(error = %e, "device/init request failed");
                InitOutcome::Unavailable
            }
        }
    }

    pub async fn poll(&self, device_code: &str) -> Result<PollResponse> {
        let url = format!("{}/posix/v1/device/poll", self.server_url);
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .json(&serde_json::json!({ "device_code": device_code }))
            .send()
            .await
            .context("device/poll request")?;
        if resp.status() != StatusCode::OK {
            anyhow::bail!("device/poll status {}", resp.status());
        }
        resp.json::<PollResponse>()
            .await
            .context("device/poll decode")
    }
}

/// Per-session daemon-owned state. The daemon owns the hard expiry independent
/// of the PAM-side poll loop, so an abandoned SSH session can't keep a flow
/// alive past Hydra's `expires_in` (capped by config).
#[derive(Debug, Clone)]
pub struct DeviceFlowState {
    pub device_code: String,
    pub interval: u32,
    pub expires_at: Instant,
    /// The user this flow authenticates, so the approved poll can stamp the
    /// offline `last_online_auth` ceiling. `None` keeps older call sites valid.
    pub username: Option<String>,
}

/// Outcome of a session lookup that also prunes on expiry.
pub enum SessionLookup {
    Found(DeviceFlowState),
    /// Absent or past hard expiry → PAM gets `Denied{expired}`.
    Expired,
}

pub struct SessionStore {
    inner: Mutex<HashMap<String, DeviceFlowState>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a fresh session under a random id; returns `None` if the global
    /// cap is reached (after lazily reaping anything already expired) or if the
    /// OS RNG was unavailable — the caller maps both to a temporary-unavailable.
    pub fn insert(&self, state: DeviceFlowState) -> Option<String> {
        let id = new_session_id()?;
        let mut map = self.inner.lock().expect("session store poisoned");
        prune_expired(&mut map, Instant::now());
        if map.len() >= MAX_SESSIONS {
            return None;
        }
        map.insert(id.clone(), state);
        Some(id)
    }

    /// Look the session up, dropping it if it is absent or past hard expiry.
    pub fn get_live(&self, session_id: &str) -> SessionLookup {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("session store poisoned");
        match map.get(session_id) {
            Some(s) if s.expires_at > now => SessionLookup::Found(s.clone()),
            Some(_) => {
                map.remove(session_id);
                SessionLookup::Expired
            }
            None => SessionLookup::Expired,
        }
    }

    /// Drop a session once it reaches a terminal state (approved/denied).
    pub fn remove(&self, session_id: &str) {
        let mut map = self.inner.lock().expect("session store poisoned");
        map.remove(session_id);
    }

    /// Update the stored interval (server `slow_down` widening).
    pub fn set_interval(&self, session_id: &str, interval: u32) {
        let mut map = self.inner.lock().expect("session store poisoned");
        if let Some(s) = map.get_mut(session_id) {
            s.interval = interval;
        }
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.inner.lock().expect("session store poisoned").len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

fn prune_expired(map: &mut HashMap<String, DeviceFlowState>, now: Instant) {
    map.retain(|_, s| s.expires_at > now);
}

/// 32 random bytes, base64url (no padding). uuid would do too; this keeps the
/// dep surface tiny and is plenty of entropy for a short-lived session handle.
/// `None` if the OS RNG was unavailable — never panics on the request path.
fn new_session_id() -> Option<String> {
    let mut bytes = [0u8; 32];
    // getrandom via the OS; reqwest already pulls it in transitively.
    getrandom_bytes(&mut bytes)?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Fill `buf` from the OS RNG. `None` on error (negative ret) or short read.
fn getrandom_bytes(buf: &mut [u8]) -> Option<()> {
    // SAFETY: getrandom(2) writes up to `buf.len()` bytes into a valid mut slice.
    let ret = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    if ret < 0 || ret as usize != buf.len() {
        tracing::warn!(ret, "getrandom failed; treating session as unavailable");
        return None;
    }
    Some(())
}

/// The hard expiry for a new session: Hydra's `expires_in`, capped by config so
/// a long Hydra TTL can't keep a daemon session alive past our ceiling.
pub fn capped_expiry(now: Instant, expires_in: u32, cap_secs: u64) -> Instant {
    let secs = u64::from(expires_in).min(cap_secs);
    now + Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_expiry_clamps_to_cap() {
        let now = Instant::now();
        let e = capped_expiry(now, 600, 90);
        assert!(e <= now + Duration::from_secs(90));
        assert!(e > now + Duration::from_secs(89));
    }

    #[test]
    fn capped_expiry_uses_expires_in_when_smaller() {
        let now = Instant::now();
        let e = capped_expiry(now, 30, 90);
        assert!(e <= now + Duration::from_secs(30));
        assert!(e > now + Duration::from_secs(29));
    }

    #[test]
    fn store_insert_and_lookup() {
        let store = SessionStore::new();
        let id = store
            .insert(DeviceFlowState {
                device_code: "dc".into(),
                interval: 5,
                expires_at: Instant::now() + Duration::from_secs(60),
                username: None,
            })
            .unwrap();
        match store.get_live(&id) {
            SessionLookup::Found(s) => assert_eq!(s.device_code, "dc"),
            SessionLookup::Expired => panic!("should be live"),
        }
    }

    #[test]
    fn store_expires_past_deadline() {
        let store = SessionStore::new();
        let id = store
            .insert(DeviceFlowState {
                device_code: "dc".into(),
                interval: 5,
                // already expired
                expires_at: Instant::now() - Duration::from_secs(1),
                username: None,
            })
            .unwrap();
        assert!(matches!(store.get_live(&id), SessionLookup::Expired));
        // lookup must have pruned it
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn store_unknown_session_is_expired() {
        let store = SessionStore::new();
        assert!(matches!(store.get_live("nope"), SessionLookup::Expired));
    }

    #[test]
    fn store_remove_drops_session() {
        let store = SessionStore::new();
        let id = store
            .insert(DeviceFlowState {
                device_code: "dc".into(),
                interval: 5,
                expires_at: Instant::now() + Duration::from_secs(60),
                username: None,
            })
            .unwrap();
        store.remove(&id);
        assert!(matches!(store.get_live(&id), SessionLookup::Expired));
    }

    #[test]
    fn store_caps_concurrent_sessions() {
        let store = SessionStore::new();
        for _ in 0..MAX_SESSIONS {
            assert!(store
                .insert(DeviceFlowState {
                    device_code: "dc".into(),
                    interval: 5,
                    expires_at: Instant::now() + Duration::from_secs(60),
                    username: None,
                })
                .is_some());
        }
        // one over the cap is refused
        assert!(store
            .insert(DeviceFlowState {
                device_code: "dc".into(),
                interval: 5,
                expires_at: Instant::now() + Duration::from_secs(60),
                username: None,
            })
            .is_none());
    }

    #[test]
    fn session_ids_are_unique_and_urlsafe() {
        let a = new_session_id().unwrap();
        let b = new_session_id().unwrap();
        assert_ne!(a, b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn dc(url: &str) -> DeviceClient {
        DeviceClient::new(url, "host", "secret", 5).unwrap()
    }

    #[tokio::test]
    async fn init_ok_yields_started() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "dc-1",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://idp.example/device",
                "interval": 5,
                "expires_in": 600
            })))
            .mount(&server)
            .await;
        match dc(&server.uri()).init("alice").await {
            InitOutcome::Started(b) => {
                assert_eq!(b.device_code, "dc-1");
                assert_eq!(b.user_code, "WDJB-MJHT");
            }
            _ => panic!("expected Started"),
        }
    }

    #[tokio::test]
    async fn init_404_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        assert!(matches!(
            dc(&server.uri()).init("ghost").await,
            InitOutcome::Unknown
        ));
    }

    #[tokio::test]
    async fn init_500_is_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/init"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(matches!(
            dc(&server.uri()).init("alice").await,
            InitOutcome::Unavailable
        ));
    }

    #[tokio::test]
    async fn poll_pending_then_approved() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/poll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "pending", "interval": 7
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/poll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "approved"
            })))
            .mount(&server)
            .await;
        let client = dc(&server.uri());
        let first = client.poll("dc-1").await.unwrap();
        assert_eq!(first.status, "pending");
        assert_eq!(first.interval, Some(7));
        let second = client.poll("dc-1").await.unwrap();
        assert_eq!(second.status, "approved");
    }

    #[tokio::test]
    async fn poll_denied_carries_reason() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/posix/v1/device/poll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "denied", "reason": "force_mfa"
            })))
            .mount(&server)
            .await;
        let p = dc(&server.uri()).poll("dc-1").await.unwrap();
        assert_eq!(p.status, "denied");
        assert_eq!(p.reason.as_deref(), Some("force_mfa"));
    }
}
