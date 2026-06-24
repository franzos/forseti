//! Host-side offline-auth keystore (M3a). A `forseti-unixd`-owned `0600`
//! rusqlite store holding re-peppered Argon2id verifiers, a per-user lockout,
//! and a queued offline-audit log the poller flushes upstream.
//!
//! Crypto: the server ships an Argon2id PHC verifier; the host never stores the
//! bare server hash. It stores `verify_tag = HMAC_SHA256(pepper, hash_bytes)`
//! plus the salt/params/algo_version. At login it recomputes the raw Argon2id
//! hash from the typed passphrase and constant-time-compares the HMAC tag.
//!
//! The host pepper lives in a `0600` row (M3b moves it into a TPM). A stolen
//! disk therefore permits an offline brute-force bounded by the Argon2id work
//! factor × passphrase entropy — the lockout below defends LIVE guessing only.

use anyhow::{Context, Result};
use argon2::password_hash::PasswordHash;
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use sha2::Sha256;
use std::path::Path;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// The one algo version this host understands; a verifier stamped otherwise is
/// refused by the gate (forward-compat for a future KDF change).
pub const KNOWN_ALGO_VERSION: i32 = 1;

/// Lockout backoff base (seconds) and cap. Exponential per consecutive failure,
/// clamped so a wallclock value never overflows.
const LOCKOUT_BASE_SECS: i64 = 1;
const LOCKOUT_CAP_SECS: i64 = 3600;

/// One provisioned credential from the `/posix/v1/offline_verifiers` pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedCred {
    pub username: String,
    pub verifier_phc: String,
    pub ttl_secs: i64,
    pub algo_version: i32,
}

/// A stored credential row, read back for verification.
struct CredRow {
    salt: Vec<u8>,
    params: String,
    verify_tag: Vec<u8>,
    ttl_expires_at: i64,
    last_online_auth: i64,
    algo_version: i32,
    synced_at: i64,
}

/// Outcome of a local offline verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineVerifyOutcome {
    Ok,
    Denied(OfflineRefuseReason),
    /// No credential row for this user (never provisioned / withdrawn).
    NoCred,
}

// --- Pure precondition gate ------------------------------------------------

/// Inputs to [`evaluate_offline_gate`]; all clock values are epoch seconds.
#[derive(Debug, Clone, Copy)]
pub struct OfflineGateInputs {
    pub now: i64,
    pub synced_at: i64,
    pub ttl_expires_at: i64,
    pub last_online_auth: i64,
    pub max_lifetime_secs: i64,
    pub locked_until: i64,
    pub algo_version: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineDecision {
    Verify,
    Refuse(OfflineRefuseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineRefuseReason {
    Expired,
    ClockRollback,
    LockedOut,
    MaxLifetime,
    UnknownAlgo,
    BadPassphrase,
}

impl OfflineRefuseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::ClockRollback => "clock_rollback",
            Self::LockedOut => "locked_out",
            Self::MaxLifetime => "max_lifetime",
            Self::UnknownAlgo => "unknown_algo",
            Self::BadPassphrase => "bad_passphrase",
        }
    }
}

/// Pure precondition gate; does NOT touch the passphrase. Run before the KDF.
pub fn evaluate_offline_gate(i: &OfflineGateInputs) -> OfflineDecision {
    use OfflineRefuseReason::*;
    if i.now < i.synced_at {
        return OfflineDecision::Refuse(ClockRollback);
    }
    if i.now >= i.ttl_expires_at {
        return OfflineDecision::Refuse(Expired);
    }
    if i.now >= i.last_online_auth.saturating_add(i.max_lifetime_secs) {
        return OfflineDecision::Refuse(MaxLifetime);
    }
    if i.now < i.locked_until {
        return OfflineDecision::Refuse(LockedOut);
    }
    if i.algo_version != KNOWN_ALGO_VERSION {
        return OfflineDecision::Refuse(UnknownAlgo);
    }
    OfflineDecision::Verify
}

// --- Crypto core -----------------------------------------------------------

/// Argon2id params parsed from a stored verifier's PHC string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Params {
    fn encode(self) -> String {
        format!("m={},t={},p={}", self.m_kib, self.t, self.p)
    }

    fn decode(s: &str) -> Result<Self> {
        let mut m = None;
        let mut t = None;
        let mut p = None;
        for kv in s.split(',') {
            let (k, v) = kv.split_once('=').context("malformed argon2 params")?;
            let v: u32 = v.parse().context("non-numeric argon2 param")?;
            match k {
                "m" => m = Some(v),
                "t" => t = Some(v),
                "p" => p = Some(v),
                _ => {}
            }
        }
        Ok(Self {
            m_kib: m.context("missing m param")?,
            t: t.context("missing t param")?,
            p: p.context("missing p param")?,
        })
    }
}

/// Parsed pieces of a server verifier PHC: the raw salt bytes, the Argon2id
/// params, and the raw output hash bytes (what we re-pepper, never stored bare).
struct ParsedVerifier {
    salt: Vec<u8>,
    params: Argon2Params,
    hash: Vec<u8>,
}

/// Parse a server Argon2id PHC string into salt/params/raw-hash. Returns an
/// error on any malformed or non-Argon2id input — never panics.
fn parse_verifier(phc: &str) -> Result<ParsedVerifier> {
    let parsed = PasswordHash::new(phc).map_err(|e| anyhow::anyhow!("bad PHC: {e}"))?;
    let salt = parsed.salt.context("PHC has no salt")?;
    let mut salt_buf = [0u8; 64];
    let salt_bytes = salt
        .decode_b64(&mut salt_buf)
        .map_err(|e| anyhow::anyhow!("bad salt b64: {e}"))?
        .to_vec();
    let hash = parsed
        .hash
        .context("PHC has no output hash")?
        .as_bytes()
        .to_vec();
    let p = &parsed.params;
    let m_kib = p
        .get("m")
        .and_then(|v| v.decimal().ok())
        .context("PHC missing m param")?;
    let t = p
        .get("t")
        .and_then(|v| v.decimal().ok())
        .context("PHC missing t param")?;
    let par = p
        .get("p")
        .and_then(|v| v.decimal().ok())
        .context("PHC missing p param")?;
    Ok(ParsedVerifier {
        salt: salt_bytes,
        params: Argon2Params { m_kib, t, p: par },
        hash,
    })
}

/// Raw Argon2id hash of `passphrase` under the stored salt/params, with output
/// length matching the stored tag. `None` on any KDF failure (never panics).
fn argon2id_raw(passphrase: &str, salt: &[u8], params: Argon2Params, out_len: usize) -> Option<Vec<u8>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(out_len)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = vec![0u8; out_len];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .ok()?;
    Some(out)
}

/// `HMAC_SHA256(pepper, msg)`.
fn hmac_tag(pepper: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Recompute the tag from the typed passphrase and constant-time-compare it to
/// `stored_tag`. `false` on any KDF failure or mismatch.
pub fn verify_offline(
    passphrase: &str,
    salt: &[u8],
    params: Argon2Params,
    pepper: &[u8],
    stored_tag: &[u8],
) -> bool {
    let Some(cand) = argon2id_raw(passphrase, salt, params, stored_tag.len()) else {
        return false;
    };
    let cand_tag = hmac_tag(pepper, &cand);
    cand_tag.ct_eq(stored_tag).into()
}

// --- Keystore --------------------------------------------------------------

#[derive(Clone)]
pub struct Keystore {
    conn: Arc<Mutex<Connection>>,
    lockout_max: i64,
    max_lifetime_secs: i64,
}

impl Keystore {
    /// Open (creating if absent) the keystore at `path` with WAL + a busy
    /// timeout, and ensure the schema. The caller is responsible for the file
    /// being `forseti-unixd`-owned `0600` (see `check_credentials_dir`).
    pub fn open(path: &Path, lockout_max: u32, max_lifetime_secs: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating credentials dir {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening credentials db {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .context("setting busy_timeout")?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enabling WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS offline_cred (
                 username TEXT PRIMARY KEY,
                 salt BLOB NOT NULL,
                 params TEXT NOT NULL,
                 verify_tag BLOB NOT NULL,
                 ttl_expires_at INTEGER NOT NULL,
                 last_online_auth INTEGER NOT NULL,
                 algo_version INTEGER NOT NULL,
                 synced_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS offline_lockout (
                 username TEXT PRIMARY KEY,
                 fail_count INTEGER NOT NULL,
                 locked_until INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS offline_audit_queue (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_json TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS host_pepper (
                 id TEXT PRIMARY KEY,
                 key BLOB NOT NULL
             );",
        )
        .context("creating keystore schema")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            lockout_max: i64::from(lockout_max),
            max_lifetime_secs: i64::try_from(max_lifetime_secs).unwrap_or(i64::MAX),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("keystore mutex poisoned"))
    }

    /// The host pepper: 32 random bytes generated once and stored, returned
    /// thereafter. Abstracted behind this one call so M3b can move it to a TPM.
    pub fn get_or_create_pepper(&self) -> Result<Vec<u8>> {
        let conn = self.lock()?;
        Self::pepper_inner(&conn)
    }

    fn pepper_inner(conn: &Connection) -> Result<Vec<u8>> {
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT key FROM host_pepper WHERE id = 'default'",
                [],
                |r| r.get(0),
            )
            .ok();
        if let Some(k) = existing {
            return Ok(k);
        }
        let mut key = vec![0u8; 32];
        rand::fill(&mut key[..]);
        conn.execute(
            "INSERT INTO host_pepper (id, key) VALUES ('default', ?1)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![key],
        )
        .context("storing host pepper")?;
        // A racing writer may have won; re-read to return the persisted value.
        conn.query_row(
            "SELECT key FROM host_pepper WHERE id = 'default'",
            [],
            |r| r.get(0),
        )
        .context("reading host pepper after insert")
    }

    /// Parse a server verifier PHC, compute `verify_tag = HMAC(pepper, hash)`,
    /// and upsert the row, stamping `ttl_expires_at = now + ttl_secs` and
    /// `synced_at = now`. Never stores the bare server hash.
    pub fn upsert_cred(
        &self,
        username: &str,
        verifier_phc: &str,
        ttl_secs: i64,
        last_online_auth: i64,
        algo_version: i32,
        now: i64,
    ) -> Result<()> {
        let conn = self.lock()?;
        Self::upsert_cred_inner(
            &conn,
            username,
            verifier_phc,
            ttl_secs,
            last_online_auth,
            algo_version,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_cred_inner(
        conn: &Connection,
        username: &str,
        verifier_phc: &str,
        ttl_secs: i64,
        last_online_auth: i64,
        algo_version: i32,
        now: i64,
    ) -> Result<()> {
        let pepper = Self::pepper_inner(conn)?;
        let parsed = parse_verifier(verifier_phc)?;
        let verify_tag = hmac_tag(&pepper, &parsed.hash);
        let params = parsed.params.encode();
        let ttl_expires_at = now.saturating_add(ttl_secs);
        conn.execute(
            "INSERT INTO offline_cred
                 (username, salt, params, verify_tag, ttl_expires_at, last_online_auth, algo_version, synced_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(username) DO UPDATE SET
                 salt = excluded.salt,
                 params = excluded.params,
                 verify_tag = excluded.verify_tag,
                 ttl_expires_at = excluded.ttl_expires_at,
                 last_online_auth = excluded.last_online_auth,
                 algo_version = excluded.algo_version,
                 synced_at = excluded.synced_at",
            rusqlite::params![
                username,
                parsed.salt,
                params,
                verify_tag,
                ttl_expires_at,
                last_online_auth,
                algo_version,
                now
            ],
        )
        .context("upserting offline_cred")?;
        Ok(())
    }

    /// Wholesale-replace the credential set: upsert every present cred, DELETE
    /// any user absent from `creds` (withdrawal by absence). One transaction.
    pub fn replace_all(&self, creds: &[ProvisionedCred], now: i64) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().context("begin replace_all tx")?;
        for c in creds {
            // last_online_auth = now: a successful pull proves recent online contact.
            Self::upsert_cred_inner(
                &tx,
                &c.username,
                &c.verifier_phc,
                c.ttl_secs,
                now,
                c.algo_version,
                now,
            )?;
        }
        if creds.is_empty() {
            tx.execute("DELETE FROM offline_cred", [])
                .context("clearing offline_cred")?;
        } else {
            let placeholders = creds
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 1))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!("DELETE FROM offline_cred WHERE username NOT IN ({placeholders})");
            let names: Vec<&str> = creds.iter().map(|c| c.username.as_str()).collect();
            let params = rusqlite::params_from_iter(names);
            tx.execute(&sql, params)
                .context("deleting withdrawn offline_cred")?;
        }
        tx.commit().context("commit replace_all tx")?;
        Ok(())
    }

    /// A non-expired credential row exists for `username` (the OfflineAvailable
    /// signal). Cheap pre-check; full gating happens in [`verify`].
    pub fn has_usable_cred(&self, username: &str, now: i64) -> bool {
        let Ok(conn) = self.lock() else {
            return false;
        };
        conn.query_row(
            "SELECT 1 FROM offline_cred WHERE username = ?1 AND ttl_expires_at > ?2",
            rusqlite::params![username, now],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// Run the precondition gate, then the KDF+HMAC verify, updating lockout.
    /// Never panics — a poisoned mutex or missing row maps to a denial.
    pub fn verify(&self, username: &str, passphrase: &str, now: i64) -> OfflineVerifyOutcome {
        let conn = match self.lock() {
            Ok(c) => c,
            Err(_) => return OfflineVerifyOutcome::Denied(OfflineRefuseReason::LockedOut),
        };

        let row: Option<CredRow> = conn
            .query_row(
                "SELECT salt, params, verify_tag, ttl_expires_at, last_online_auth, algo_version, synced_at
                 FROM offline_cred WHERE username = ?1",
                rusqlite::params![username],
                |r| {
                    Ok(CredRow {
                        salt: r.get(0)?,
                        params: r.get(1)?,
                        verify_tag: r.get(2)?,
                        ttl_expires_at: r.get(3)?,
                        last_online_auth: r.get(4)?,
                        algo_version: r.get(5)?,
                        synced_at: r.get(6)?,
                    })
                },
            )
            .ok();
        let Some(row) = row else {
            return OfflineVerifyOutcome::NoCred;
        };

        let locked_until: i64 = conn
            .query_row(
                "SELECT locked_until FROM offline_lockout WHERE username = ?1",
                rusqlite::params![username],
                |r| r.get(0),
            )
            .unwrap_or(0);

        // last_online_auth is stamped to the last successful pull; the gate
        // refuses a cred older than max_lifetime since then (TTL is the tighter
        // revocation knob, this is the hard ceiling on a partitioned host).
        let inputs = OfflineGateInputs {
            now,
            synced_at: row.synced_at,
            ttl_expires_at: row.ttl_expires_at,
            last_online_auth: row.last_online_auth,
            max_lifetime_secs: self.max_lifetime_secs,
            locked_until,
            algo_version: row.algo_version,
        };
        if let OfflineDecision::Refuse(reason) = evaluate_offline_gate(&inputs) {
            return OfflineVerifyOutcome::Denied(reason);
        }

        let Ok(params) = Argon2Params::decode(&row.params) else {
            return OfflineVerifyOutcome::Denied(OfflineRefuseReason::UnknownAlgo);
        };
        let pepper = match Self::pepper_inner(&conn) {
            Ok(p) => p,
            Err(_) => return OfflineVerifyOutcome::Denied(OfflineRefuseReason::LockedOut),
        };

        if verify_offline(passphrase, &row.salt, params, &pepper, &row.verify_tag) {
            let _ = Self::reset_lockout(&conn, username);
            OfflineVerifyOutcome::Ok
        } else {
            // A wrong attempt that trips (or is already past) the hard lock reports
            // LockedOut; an ordinary miss reports BadPassphrase so PAM can re-prompt.
            let locked = Self::bump_lockout(&conn, username, now, self.lockout_max).unwrap_or(true);
            if locked {
                OfflineVerifyOutcome::Denied(OfflineRefuseReason::LockedOut)
            } else {
                OfflineVerifyOutcome::Denied(OfflineRefuseReason::BadPassphrase)
            }
        }
    }

    /// Single-SQL atomic increment of the fail counter, then compute the new
    /// `locked_until` with exponential backoff (hard lock past `lockout_max`).
    /// Returns whether the account is now hard-locked (`fail_count >= lockout_max`);
    /// the per-miss exponential backoff is NOT a hard lock for this purpose.
    /// Lockout defends LIVE guessing only — a disk thief just rewrites this row.
    fn bump_lockout(conn: &Connection, username: &str, now: i64, lockout_max: i64) -> Result<bool> {
        conn.execute(
            "INSERT INTO offline_lockout (username, fail_count, locked_until)
             VALUES (?1, 1, 0)
             ON CONFLICT(username) DO UPDATE SET fail_count = fail_count + 1",
            rusqlite::params![username],
        )
        .context("incrementing lockout")?;
        let fail_count: i64 = conn.query_row(
            "SELECT fail_count FROM offline_lockout WHERE username = ?1",
            rusqlite::params![username],
            |r| r.get(0),
        )?;
        let locked_until = backoff_until(fail_count, lockout_max, now);
        conn.execute(
            "UPDATE offline_lockout SET locked_until = ?2 WHERE username = ?1",
            rusqlite::params![username, locked_until],
        )
        .context("setting locked_until")?;
        Ok(fail_count >= lockout_max)
    }

    fn reset_lockout(conn: &Connection, username: &str) -> Result<()> {
        conn.execute(
            "INSERT INTO offline_lockout (username, fail_count, locked_until)
             VALUES (?1, 0, 0)
             ON CONFLICT(username) DO UPDATE SET fail_count = 0, locked_until = 0",
            rusqlite::params![username],
        )
        .context("resetting lockout")?;
        Ok(())
    }

    /// Stamp `last_online_auth = now` for `username` after a genuine ONLINE
    /// auth, so the `offline_max_lifetime` ceiling tracks the last real online
    /// login rather than just the last verifier pull. No-op if the user has no
    /// row yet — the next pull provisions it.
    pub fn set_last_online_auth(&self, username: &str, now: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE offline_cred SET last_online_auth = ?2 WHERE username = ?1",
            rusqlite::params![username, now],
        )
        .context("updating last_online_auth")?;
        Ok(())
    }

    pub fn enqueue_audit(&self, event_json: &str, now: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO offline_audit_queue (event_json, created_at) VALUES (?1, ?2)",
            rusqlite::params![event_json, now],
        )
        .context("enqueuing audit event")?;
        Ok(())
    }

    /// Drain up to `max` queued audit events (oldest first), returning
    /// `(id, event_json)` pairs for the poller to POST and then delete.
    pub fn drain_audit(&self, max: i64) -> Vec<(i64, String)> {
        let Ok(conn) = self.lock() else {
            return Vec::new();
        };
        let mut stmt = match conn.prepare(
            "SELECT id, event_json FROM offline_audit_queue ORDER BY id ASC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "preparing drain_audit failed");
                return Vec::new();
            }
        };
        let rows = stmt.query_map(rusqlite::params![max], |r| Ok((r.get(0)?, r.get(1)?)));
        match rows {
            Ok(it) => it.filter_map(std::result::Result::ok).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "querying drain_audit failed");
                Vec::new()
            }
        }
    }

    pub fn delete_audit(&self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let conn = self.lock()?;
        let placeholders = ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM offline_audit_queue WHERE id IN ({placeholders})");
        conn.execute(&sql, rusqlite::params_from_iter(ids.iter().copied()))
            .context("deleting flushed audit rows")?;
        Ok(())
    }
}

/// Exponential backoff deadline: hard-lock for the cap once `fail_count`
/// exceeds `lockout_max`, else `now + base * 2^(fail_count-1)` clamped to cap.
fn backoff_until(fail_count: i64, lockout_max: i64, now: i64) -> i64 {
    if fail_count <= 0 {
        return 0;
    }
    if fail_count >= lockout_max {
        return now.saturating_add(LOCKOUT_CAP_SECS);
    }
    let shift = (fail_count - 1).min(20) as u32;
    let delay = LOCKOUT_BASE_SECS
        .saturating_mul(1_i64.checked_shl(shift).unwrap_or(i64::MAX))
        .min(LOCKOUT_CAP_SECS);
    now.saturating_add(delay)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint(passphrase: &str) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::password_hash::rand_core::OsRng;
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

    fn base_inputs() -> OfflineGateInputs {
        OfflineGateInputs {
            now: 1000,
            synced_at: 900,
            ttl_expires_at: 2000,
            last_online_auth: 900,
            max_lifetime_secs: 100_000,
            locked_until: 0,
            algo_version: KNOWN_ALGO_VERSION,
        }
    }

    // --- gate taxonomy: one test per reason + happy path ---

    #[test]
    fn gate_happy_path() {
        assert_eq!(evaluate_offline_gate(&base_inputs()), OfflineDecision::Verify);
    }

    #[test]
    fn gate_clock_rollback() {
        let mut i = base_inputs();
        i.now = 800; // before synced_at
        assert_eq!(
            evaluate_offline_gate(&i),
            OfflineDecision::Refuse(OfflineRefuseReason::ClockRollback)
        );
    }

    #[test]
    fn gate_expired() {
        let mut i = base_inputs();
        i.now = 2000; // == ttl_expires_at
        assert_eq!(
            evaluate_offline_gate(&i),
            OfflineDecision::Refuse(OfflineRefuseReason::Expired)
        );
    }

    #[test]
    fn gate_max_lifetime() {
        let mut i = base_inputs();
        i.last_online_auth = 0;
        i.max_lifetime_secs = 500; // now=1000 >= 0+500
        assert_eq!(
            evaluate_offline_gate(&i),
            OfflineDecision::Refuse(OfflineRefuseReason::MaxLifetime)
        );
    }

    #[test]
    fn gate_locked_out() {
        let mut i = base_inputs();
        i.locked_until = 1500; // now=1000 < 1500
        assert_eq!(
            evaluate_offline_gate(&i),
            OfflineDecision::Refuse(OfflineRefuseReason::LockedOut)
        );
    }

    #[test]
    fn gate_unknown_algo() {
        let mut i = base_inputs();
        i.algo_version = 99;
        assert_eq!(
            evaluate_offline_gate(&i),
            OfflineDecision::Refuse(OfflineRefuseReason::UnknownAlgo)
        );
    }

    // --- verify round-trip ---

    #[test]
    fn verify_correct_passphrase() {
        let (_d, ks) = store();
        let phc = mint("correct horse battery");
        ks.upsert_cred("alice", &phc, 10_000, 1000, 1, 1000).unwrap();
        assert_eq!(
            ks.verify("alice", "correct horse battery", 2000),
            OfflineVerifyOutcome::Ok
        );
    }

    #[test]
    fn verify_incorrect_passphrase() {
        let (_d, ks) = store();
        let phc = mint("correct horse battery");
        ks.upsert_cred("alice", &phc, 10_000, 1000, 1, 1000).unwrap();
        // A first wrong attempt is a plain miss, not a lockout.
        assert_eq!(
            ks.verify("alice", "wrong passphrase", 2000),
            OfflineVerifyOutcome::Denied(OfflineRefuseReason::BadPassphrase)
        );
    }

    #[test]
    fn verify_reports_locked_out_once_lockout_max_reached() {
        let (_d, ks) = store();
        let phc = mint("correct horse battery");
        ks.upsert_cred("alice", &phc, 1_000_000, 1000, 1, 1000)
            .unwrap();
        // lockout_max is 5 (see `store`). The first four misses report
        // BadPassphrase; the fifth trips the hard lock → LockedOut.
        let mut now = 2000;
        for _ in 0..4 {
            assert_eq!(
                ks.verify("alice", "wrong", now),
                OfflineVerifyOutcome::Denied(OfflineRefuseReason::BadPassphrase)
            );
            now += 100;
        }
        assert_eq!(
            ks.verify("alice", "wrong", now),
            OfflineVerifyOutcome::Denied(OfflineRefuseReason::LockedOut)
        );
    }

    #[test]
    fn verify_no_cred() {
        let (_d, ks) = store();
        assert_eq!(ks.verify("ghost", "x", 1000), OfflineVerifyOutcome::NoCred);
    }

    #[test]
    fn verify_is_pepper_sensitive() {
        // A tag computed under a different pepper must not verify: re-pepper the
        // same raw hash under pepper A, then verify with pepper B → false.
        let phc = mint("correct horse battery");
        let parsed = parse_verifier(&phc).unwrap();
        let pepper_a = vec![1u8; 32];
        let pepper_b = vec![2u8; 32];
        let tag_a = hmac_tag(&pepper_a, &parsed.hash);
        assert!(verify_offline(
            "correct horse battery",
            &parsed.salt,
            parsed.params,
            &pepper_a,
            &tag_a
        ));
        assert!(!verify_offline(
            "correct horse battery",
            &parsed.salt,
            parsed.params,
            &pepper_b,
            &tag_a
        ));
    }

    #[test]
    fn never_stores_bare_server_hash() {
        let (_d, ks) = store();
        let phc = mint("correct horse battery");
        let parsed = parse_verifier(&phc).unwrap();
        ks.upsert_cred("alice", &phc, 10_000, 1000, 1, 1000).unwrap();
        let conn = ks.conn.lock().unwrap();
        let tag: Vec<u8> = conn
            .query_row(
                "SELECT verify_tag FROM offline_cred WHERE username = 'alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(tag, parsed.hash, "stored tag must not equal the bare hash");
    }

    // --- lockout ---

    #[test]
    fn lockout_increments_and_locks() {
        let (_d, ks) = store();
        let phc = mint("correct horse battery");
        ks.upsert_cred("alice", &phc, 1_000_000, 1000, 1, 1000)
            .unwrap();
        // Each wrong attempt waits past the previous backoff window so the gate
        // doesn't short-circuit before the counter bumps. Backoff: 1,2,4,8,16.
        let mut now = 2000;
        for _ in 0..5 {
            assert!(matches!(
                ks.verify("alice", "wrong", now),
                OfflineVerifyOutcome::Denied(_)
            ));
            now += 100; // well past any sub-100s backoff
        }
        let conn = ks.conn.lock().unwrap();
        let (fail, locked): (i64, i64) = conn
            .query_row(
                "SELECT fail_count, locked_until FROM offline_lockout WHERE username='alice'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fail, 5);
        // At the hard cap (fail_count >= lockout_max) the lock is the long cap.
        assert_eq!(locked, (now - 100) + LOCKOUT_CAP_SECS);
        drop(conn);
        // Within the lock window the gate refuses even a correct passphrase.
        assert!(matches!(
            ks.verify("alice", "correct horse battery", now),
            OfflineVerifyOutcome::Denied(OfflineRefuseReason::LockedOut)
        ));
    }

    #[test]
    fn success_resets_lockout() {
        let (_d, ks) = store();
        let phc = mint("correct horse battery");
        ks.upsert_cred("alice", &phc, 10_000, 1000, 1, 1000).unwrap();
        ks.verify("alice", "wrong", 2000);
        ks.verify("alice", "wrong", 2000);
        // Past the short backoff window, a correct passphrase resets the counter.
        assert_eq!(
            ks.verify("alice", "correct horse battery", 9000),
            OfflineVerifyOutcome::Ok
        );
        let conn = ks.conn.lock().unwrap();
        let (fail, locked): (i64, i64) = conn
            .query_row(
                "SELECT fail_count, locked_until FROM offline_lockout WHERE username='alice'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fail, 0);
        assert_eq!(locked, 0);
    }

    #[test]
    fn backoff_is_exponential_then_capped() {
        assert_eq!(backoff_until(0, 5, 1000), 0);
        assert_eq!(backoff_until(1, 5, 1000), 1000 + 1);
        assert_eq!(backoff_until(2, 5, 1000), 1000 + 2);
        assert_eq!(backoff_until(3, 5, 1000), 1000 + 4);
        assert_eq!(backoff_until(4, 5, 1000), 1000 + 8);
        // hard lock at/over the cap
        assert_eq!(backoff_until(5, 5, 1000), 1000 + LOCKOUT_CAP_SECS);
    }

    // --- replace_all ---

    #[test]
    fn replace_all_drops_absent_users() {
        let (_d, ks) = store();
        let pa = mint("alice passphrase");
        let pb = mint("bob passphrase");
        ks.replace_all(
            &[
                ProvisionedCred {
                    username: "alice".into(),
                    verifier_phc: pa.clone(),
                    ttl_secs: 10_000,
                    algo_version: 1,
                },
                ProvisionedCred {
                    username: "bob".into(),
                    verifier_phc: pb,
                    ttl_secs: 10_000,
                    algo_version: 1,
                },
            ],
            1000,
        )
        .unwrap();
        assert!(ks.has_usable_cred("alice", 1000));
        assert!(ks.has_usable_cred("bob", 1000));

        // Next pull omits bob → withdrawn.
        ks.replace_all(
            &[ProvisionedCred {
                username: "alice".into(),
                verifier_phc: pa,
                ttl_secs: 10_000,
                algo_version: 1,
            }],
            2000,
        )
        .unwrap();
        assert!(ks.has_usable_cred("alice", 2000));
        assert!(!ks.has_usable_cred("bob", 2000));

        // Empty pull withdraws everyone.
        ks.replace_all(&[], 3000).unwrap();
        assert!(!ks.has_usable_cred("alice", 3000));
    }

    #[test]
    fn replace_all_stamps_ttl_from_now() {
        let (_d, ks) = store();
        let pa = mint("alice passphrase");
        ks.replace_all(
            &[ProvisionedCred {
                username: "alice".into(),
                verifier_phc: pa,
                ttl_secs: 500,
                algo_version: 1,
            }],
            1000,
        )
        .unwrap();
        let conn = ks.conn.lock().unwrap();
        let (ttl, synced): (i64, i64) = conn
            .query_row(
                "SELECT ttl_expires_at, synced_at FROM offline_cred WHERE username='alice'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(synced, 1000);
        assert_eq!(ttl, 1500);
    }

    // --- last_online_auth ---

    #[test]
    fn set_last_online_auth_updates_existing_row() {
        let (_d, ks) = store();
        let phc = mint("correct horse battery");
        ks.upsert_cred("alice", &phc, 10_000, 1000, 1, 1000).unwrap();
        ks.set_last_online_auth("alice", 5000).unwrap();
        let conn = ks.conn.lock().unwrap();
        let loa: i64 = conn
            .query_row(
                "SELECT last_online_auth FROM offline_cred WHERE username='alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(loa, 5000);
    }

    #[test]
    fn set_last_online_auth_is_noop_for_unknown_user() {
        let (_d, ks) = store();
        // No row for ghost; the update touches nothing and must not error.
        ks.set_last_online_auth("ghost", 5000).unwrap();
        assert!(!ks.has_usable_cred("ghost", 1000));
    }

    // --- pepper ---

    #[test]
    fn pepper_is_stable_across_calls() {
        let (_d, ks) = store();
        let a = ks.get_or_create_pepper().unwrap();
        let b = ks.get_or_create_pepper().unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
    }

    // --- audit queue ---

    #[test]
    fn audit_queue_drains_and_deletes() {
        let (_d, ks) = store();
        ks.enqueue_audit("{\"a\":1}", 1000).unwrap();
        ks.enqueue_audit("{\"b\":2}", 1001).unwrap();
        let drained = ks.drain_audit(10);
        assert_eq!(drained.len(), 2);
        let ids: Vec<i64> = drained.iter().map(|(id, _)| *id).collect();
        ks.delete_audit(&ids).unwrap();
        assert!(ks.drain_audit(10).is_empty());
    }
}
