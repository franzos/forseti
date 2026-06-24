//! M1 public-data cache only (passwd/group, world-readable resolver output).
//! The M3 credential keystore is a separate, identity-keyed store — not built here.

use anyhow::{Context, Result};
use forseti_unix_proto::ClientResponse;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Cache {
    conn: Arc<Mutex<Connection>>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Cache {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating cache dir {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening cache db {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cache (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL,
                 fetched_at INTEGER NOT NULL
             );",
        )
        .context("creating cache table")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Return the cached response iff `now - fetched_at <= ttl`.
    pub fn get(&self, key: &str, ttl_secs: u64) -> Option<ClientResponse> {
        self.get_at(key, ttl_secs, now_secs())
    }

    fn get_at(&self, key: &str, ttl_secs: u64, now: i64) -> Option<ClientResponse> {
        let conn = self.conn.lock().ok()?;
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT value, fetched_at FROM cache WHERE key = ?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let (value, fetched_at) = row?;
        if now.saturating_sub(fetched_at) > ttl_secs as i64 {
            return None;
        }
        serde_json::from_str(&value).ok()
    }

    /// Return the cached response ignoring TTL (last-known value). Used by the
    /// offline account-check: when the server is unreachable for longer than the
    /// NSS TTL, we still want the last-known passwd entry to clear the account
    /// phase for an offline-authed user.
    pub fn get_any(&self, key: &str) -> Option<ClientResponse> {
        let conn = self.conn.lock().ok()?;
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM cache WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .ok();
        serde_json::from_str(&value?).ok()
    }

    pub fn put(&self, key: &str, resp: &ClientResponse) -> Result<()> {
        self.put_at(key, resp, now_secs())
    }

    fn put_at(&self, key: &str, resp: &ClientResponse, now: i64) -> Result<()> {
        let value = serde_json::to_string(resp).context("serializing cache value")?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("cache mutex poisoned"))?;
        conn.execute(
            "INSERT INTO cache (key, value, fetched_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, fetched_at = excluded.fetched_at",
            rusqlite::params![key, value, now],
        )
        .context("writing cache row")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forseti_unix_proto::PasswdEntry;

    fn entry() -> ClientResponse {
        ClientResponse::Passwd(Some(PasswdEntry {
            name: "alice".into(),
            uid: 2000000,
            gid: 2000000,
            gecos: "Alice".into(),
            dir: "/home/alice".into(),
            shell: "/bin/bash".into(),
        }))
    }

    fn tmp_cache() -> (tempfile::TempDir, Cache) {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::open(&dir.path().join("c.db")).unwrap();
        (dir, cache)
    }

    #[test]
    fn put_then_get_roundtrip() {
        let (_d, cache) = tmp_cache();
        cache.put("passwd_name:alice", &entry()).unwrap();
        assert_eq!(cache.get("passwd_name:alice", 3600), Some(entry()));
    }

    #[test]
    fn missing_key_is_none() {
        let (_d, cache) = tmp_cache();
        assert_eq!(cache.get("passwd_name:nobody", 3600), None);
    }

    #[test]
    fn expired_entry_is_none() {
        let (_d, cache) = tmp_cache();
        // Stored 100s ago, ttl 10s -> expired.
        cache.put_at("passwd_name:alice", &entry(), 1000).unwrap();
        assert_eq!(cache.get_at("passwd_name:alice", 10, 1100), None);
        // Same row within ttl is still served.
        assert_eq!(cache.get_at("passwd_name:alice", 200, 1100), Some(entry()));
    }

    #[test]
    fn get_any_ignores_ttl() {
        let (_d, cache) = tmp_cache();
        cache.put("passwd_name:alice", &entry()).unwrap();
        // get_any returns the row regardless of how stale it is.
        assert_eq!(cache.get_any("passwd_name:alice"), Some(entry()));
        assert_eq!(cache.get_any("passwd_name:nobody"), None);
    }

    #[test]
    fn put_overwrites() {
        let (_d, cache) = tmp_cache();
        cache.put("k", &ClientResponse::Passwd(None)).unwrap();
        cache.put("k", &entry()).unwrap();
        assert_eq!(cache.get("k", 3600), Some(entry()));
    }
}
