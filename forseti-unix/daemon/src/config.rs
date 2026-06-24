use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/forseti/unixd.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server_url: String,
    pub host_id: String,
    pub host_secret: String,
    pub socket_path: String,
    pub cache_db: String,
    pub cache_ttl_secs: u64,
    pub request_timeout_secs: u64,
    /// Per-request timeout for the device-flow client (init/poll). Distinct from
    /// `request_timeout_secs` (NSS): a single device HTTP call is short; the long
    /// wait is the PAM-side poll loop, not one request.
    pub device_timeout_secs: u64,
    /// Hard cap on a single device session's lifetime, regardless of Hydra's
    /// `expires_in`. Kept below sshd's LoginGraceTime (default ~120s).
    pub device_session_cap_secs: u64,
    /// Offline-auth keystore path (`forseti-unixd`-owned `0600`).
    pub credentials_db: String,
    /// Hard lock after this many consecutive offline failures (live-guess defence).
    pub offline_lockout_max: u32,
    /// How often the provisioning poller pulls verifiers / flushes audit.
    pub offline_poll_secs: u64,
    /// Refuse an offline cred older than this since the last successful online pull.
    pub offline_max_lifetime_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            host_id: String::new(),
            host_secret: String::new(),
            socket_path: "/run/forseti/unixd.sock".to_string(),
            cache_db: "/var/cache/forseti/unixd.db".to_string(),
            cache_ttl_secs: 3600,
            request_timeout_secs: 3,
            device_timeout_secs: 8,
            device_session_cap_secs: 90,
            credentials_db: "/var/lib/forseti/credentials.db".to_string(),
            offline_lockout_max: 5,
            offline_poll_secs: 300,
            offline_max_lifetime_secs: 604_800,
        }
    }
}

impl Config {
    pub fn parse_str(s: &str) -> Result<Self> {
        toml::from_str(s).context("parsing unixd config TOML")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("reading config at {}", path.display()))?;
        Self::parse_str(&s)
    }
}

/// Resolve the config path: argv[1], else `FORSETI_UNIXD_CONFIG`, else the default.
pub fn resolve_path(argv1: Option<String>) -> String {
    argv1
        .or_else(|| std::env::var("FORSETI_UNIXD_CONFIG").ok())
        .unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let c = Config::parse_str(
            r#"
            server_url = "https://id.example.com"
            host_id = "host-123"
            host_secret = "s3cr3t"
            socket_path = "/tmp/unixd.sock"
            cache_db = "/tmp/unixd.db"
            cache_ttl_secs = 60
            request_timeout_secs = 5
            device_timeout_secs = 10
            device_session_cap_secs = 75
            credentials_db = "/tmp/creds.db"
            offline_lockout_max = 3
            offline_poll_secs = 120
            offline_max_lifetime_secs = 86400
        "#,
        )
        .unwrap();
        assert_eq!(c.server_url, "https://id.example.com");
        assert_eq!(c.host_id, "host-123");
        assert_eq!(c.host_secret, "s3cr3t");
        assert_eq!(c.socket_path, "/tmp/unixd.sock");
        assert_eq!(c.cache_db, "/tmp/unixd.db");
        assert_eq!(c.cache_ttl_secs, 60);
        assert_eq!(c.request_timeout_secs, 5);
        assert_eq!(c.device_timeout_secs, 10);
        assert_eq!(c.device_session_cap_secs, 75);
        assert_eq!(c.credentials_db, "/tmp/creds.db");
        assert_eq!(c.offline_lockout_max, 3);
        assert_eq!(c.offline_poll_secs, 120);
        assert_eq!(c.offline_max_lifetime_secs, 86400);
    }

    #[test]
    fn defaults_apply_when_keys_omitted() {
        let c = Config::parse_str(
            r#"
            server_url = "https://id.example.com"
            host_id = "h"
            host_secret = "s"
        "#,
        )
        .unwrap();
        assert_eq!(c.socket_path, "/run/forseti/unixd.sock");
        assert_eq!(c.cache_db, "/var/cache/forseti/unixd.db");
        assert_eq!(c.cache_ttl_secs, 3600);
        assert_eq!(c.request_timeout_secs, 3);
        assert_eq!(c.device_timeout_secs, 8);
        assert_eq!(c.device_session_cap_secs, 90);
        assert_eq!(c.credentials_db, "/var/lib/forseti/credentials.db");
        assert_eq!(c.offline_lockout_max, 5);
        assert_eq!(c.offline_poll_secs, 300);
        assert_eq!(c.offline_max_lifetime_secs, 604_800);
    }
}
