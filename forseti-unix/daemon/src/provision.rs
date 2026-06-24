//! Offline-auth provisioning poller (M3a). On a `tokio` interval it:
//!   1. GETs `/posix/v1/offline_verifiers` and wholesale-replaces the keystore
//!      (withdrawal is just absence from the next pull).
//!   2. Drains the local audit queue and POSTs it to `/posix/v1/offline_audit`,
//!      deleting flushed rows on a 2xx.
//!
//! A transport error logs and retries next tick — it NEVER clears the keystore,
//! so a partitioned host keeps its credentials until their TTL expires.

use crate::offline::{Keystore, ProvisionedCred};
use anyhow::{Context, Result};
use base64::Engine;
use reqwest::StatusCode;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Max audit events flushed per tick — bounds one POST body.
const AUDIT_BATCH: i64 = 256;

#[derive(Debug, Deserialize)]
struct VerifierRow {
    username: String,
    verifier: String,
    ttl_secs: i64,
    algo_version: i32,
}

#[derive(Debug, Deserialize)]
struct VerifiersBody {
    verifiers: Vec<VerifierRow>,
}

/// Source of the authorized verifier set. Abstracted so the poll/flush logic is
/// unit-testable without a live server.
#[async_trait::async_trait]
pub trait VerifierFetcher: Send + Sync {
    async fn fetch_verifiers(&self) -> Result<Vec<ProvisionedCred>>;
    async fn post_audit(&self, events: &[String]) -> Result<()>;
}

/// reqwest-backed fetcher authenticated by HTTP Basic `host_id:host_secret`,
/// mirroring `upstream.rs`.
pub struct HttpFetcher {
    client: reqwest::Client,
    server_url: String,
    auth_header: String,
}

impl HttpFetcher {
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
            .context("building provision reqwest client")?;
        let creds =
            base64::engine::general_purpose::STANDARD.encode(format!("{host_id}:{host_secret}"));
        Ok(Self {
            client,
            server_url: server_url.trim_end_matches('/').to_string(),
            auth_header: format!("Basic {creds}"),
        })
    }
}

#[async_trait::async_trait]
impl VerifierFetcher for HttpFetcher {
    async fn fetch_verifiers(&self) -> Result<Vec<ProvisionedCred>> {
        let url = format!("{}/posix/v1/offline_verifiers", self.server_url);
        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if resp.status() != StatusCode::OK {
            anyhow::bail!("offline_verifiers status {}", resp.status());
        }
        let body: VerifiersBody = resp.json().await.context("decoding offline_verifiers")?;
        Ok(body
            .verifiers
            .into_iter()
            .map(|r| ProvisionedCred {
                username: r.username,
                verifier_phc: r.verifier,
                ttl_secs: r.ttl_secs,
                algo_version: r.algo_version,
            })
            .collect())
    }

    async fn post_audit(&self, events: &[String]) -> Result<()> {
        let url = format!("{}/posix/v1/offline_audit", self.server_url);
        // Each queued event is a JSON object string; assemble the batch.
        let parsed: Vec<serde_json::Value> = events
            .iter()
            .filter_map(|e| serde_json::from_str(e).ok())
            .collect();
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .json(&serde_json::json!({ "events": parsed }))
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("offline_audit status {}", resp.status());
        }
        Ok(())
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct Poller {
    fetcher: Arc<dyn VerifierFetcher>,
    keystore: Keystore,
    poll_secs: u64,
}

impl Poller {
    pub fn new(
        server_url: &str,
        host_id: &str,
        host_secret: &str,
        timeout_secs: u64,
        keystore: Keystore,
        poll_secs: u64,
    ) -> Result<Self> {
        let fetcher = Arc::new(HttpFetcher::new(
            server_url,
            host_id,
            host_secret,
            timeout_secs,
        )?);
        Ok(Self {
            fetcher,
            keystore,
            poll_secs,
        })
    }

    #[cfg(test)]
    fn with_fetcher(fetcher: Arc<dyn VerifierFetcher>, keystore: Keystore, poll_secs: u64) -> Self {
        Self {
            fetcher,
            keystore,
            poll_secs,
        }
    }

    /// Run until `shutdown` fires. Each tick is best-effort: a failure logs and
    /// the loop continues, never panicking and never tearing down the keystore.
    pub async fn run(self, shutdown: Arc<tokio::sync::Notify>) {
        let mut interval =
            tokio::time::interval(Duration::from_secs(self.poll_secs.max(1)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => self.tick().await,
                () = shutdown.notified() => {
                    tracing::info!("provisioning poller shutting down");
                    break;
                }
            }
        }
    }

    async fn tick(&self) {
        if let Err(e) = self.pull().await {
            tracing::warn!(error = %e, "offline_verifiers pull failed; keeping existing creds");
        }
        if let Err(e) = self.flush_audit().await {
            tracing::warn!(error = %e, "offline_audit flush failed; will retry");
        }
    }

    /// Pull the authorized set and wholesale-replace the keystore.
    async fn pull(&self) -> Result<()> {
        let creds = self.fetcher.fetch_verifiers().await?;
        self.keystore.replace_all(&creds, now_secs())?;
        Ok(())
    }

    /// Drain the queue, POST it, and delete the flushed rows on success.
    async fn flush_audit(&self) -> Result<()> {
        let drained = self.keystore.drain_audit(AUDIT_BATCH);
        if drained.is_empty() {
            return Ok(());
        }
        let events: Vec<String> = drained.iter().map(|(_, e)| e.clone()).collect();
        self.fetcher.post_audit(&events).await?;
        let ids: Vec<i64> = drained.iter().map(|(id, _)| *id).collect();
        self.keystore.delete_audit(&ids)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn mint(passphrase: &str) -> String {
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

    fn store() -> (tempfile::TempDir, Keystore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(&dir.path().join("creds.db"), 5, 604_800).unwrap();
        (dir, ks)
    }

    struct FakeFetcher {
        creds: Vec<ProvisionedCred>,
        audit_fails: bool,
        posted: Mutex<Vec<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl VerifierFetcher for FakeFetcher {
        async fn fetch_verifiers(&self) -> Result<Vec<ProvisionedCred>> {
            Ok(self.creds.clone())
        }
        async fn post_audit(&self, events: &[String]) -> Result<()> {
            if self.audit_fails {
                anyhow::bail!("simulated transport error");
            }
            self.posted.lock().unwrap().push(events.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn pull_replaces_keystore_set() {
        let (_d, ks) = store();
        // Seed an existing user that the next pull omits → must be dropped.
        ks.upsert_cred("stale", &mint("stale passphrase"), 10_000, 1000, 1, 1000)
            .unwrap();

        let fetcher = Arc::new(FakeFetcher {
            creds: vec![ProvisionedCred {
                username: "alice".into(),
                verifier_phc: mint("alice passphrase"),
                ttl_secs: 10_000,
                algo_version: 1,
            }],
            audit_fails: false,
            posted: Mutex::new(Vec::new()),
        });
        let poller = Poller::with_fetcher(fetcher, ks.clone(), 300);
        poller.pull().await.unwrap();

        assert!(ks.has_usable_cred("alice", now_secs()));
        assert!(!ks.has_usable_cred("stale", now_secs()));
    }

    #[tokio::test]
    async fn flush_drains_queue_on_success() {
        let (_d, ks) = store();
        ks.enqueue_audit("{\"username\":\"alice\",\"result\":\"ok\"}", 1000)
            .unwrap();
        ks.enqueue_audit("{\"username\":\"bob\",\"result\":\"deny\"}", 1001)
            .unwrap();

        let fetcher = Arc::new(FakeFetcher {
            creds: Vec::new(),
            audit_fails: false,
            posted: Mutex::new(Vec::new()),
        });
        let poller = Poller::with_fetcher(fetcher.clone(), ks.clone(), 300);
        poller.flush_audit().await.unwrap();

        assert_eq!(fetcher.posted.lock().unwrap().len(), 1);
        assert_eq!(fetcher.posted.lock().unwrap()[0].len(), 2);
        assert!(ks.drain_audit(10).is_empty(), "queue must be drained");
    }

    #[tokio::test]
    async fn flush_keeps_queue_on_transport_error() {
        let (_d, ks) = store();
        ks.enqueue_audit("{\"username\":\"alice\",\"result\":\"ok\"}", 1000)
            .unwrap();

        let fetcher = Arc::new(FakeFetcher {
            creds: Vec::new(),
            audit_fails: true,
            posted: Mutex::new(Vec::new()),
        });
        let poller = Poller::with_fetcher(fetcher, ks.clone(), 300);
        assert!(poller.flush_audit().await.is_err());
        // Rows survive a failed flush → retried next tick.
        assert_eq!(ks.drain_audit(10).len(), 1);
    }

    #[tokio::test]
    async fn empty_pull_withdraws_all() {
        let (_d, ks) = store();
        ks.upsert_cred("alice", &mint("alice passphrase"), 10_000, 1000, 1, 1000)
            .unwrap();
        let fetcher = Arc::new(FakeFetcher {
            creds: Vec::new(),
            audit_fails: false,
            posted: Mutex::new(Vec::new()),
        });
        let poller = Poller::with_fetcher(fetcher, ks.clone(), 300);
        poller.pull().await.unwrap();
        assert!(!ks.has_usable_cred("alice", now_secs()));
    }
}
