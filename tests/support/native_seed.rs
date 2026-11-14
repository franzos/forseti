//! Seeding for a running native Forseti, straight into its sqlite file: identities, passwords,
//! TOTP secrets, verification state, admin metadata, and session lookups by cookie value. Shared
//! by the integration suite and `examples/seed_admin_native.rs`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

/// The server's sqlite file: `FORSETI_DATABASE_URL` (a `sqlite://` URL), else `./forseti.db`.
pub fn db_path() -> PathBuf {
    let raw = std::env::var("FORSETI_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./forseti.db".to_string());
    let path = raw
        .strip_prefix("sqlite://")
        .or_else(|| raw.strip_prefix("sqlite:"))
        .unwrap_or(raw.as_str());
    PathBuf::from(path)
}

/// A connection that waits out the server's write locks and cascades deletes.
pub fn open(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    conn.busy_timeout(Duration::from_secs(10))
        .expect("set busy timeout");
    conn.pragma_update(None, "foreign_keys", true)
        .expect("enable foreign keys");
    conn
}

/// The key material of the running server: `FORSETI_SECURITY__COOKIE_SECRET`, else
/// `[security].cookie_secret` of the config named by `FORSETI_CONFIG_PATH` (default `config.toml`).
pub fn cookie_secret() -> Vec<u8> {
    let raw = match std::env::var("FORSETI_SECURITY__COOKIE_SECRET") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            let path =
                std::env::var("FORSETI_CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read the server config {path}: {e}"));
            let doc: toml_edit::DocumentMut = text
                .parse()
                .unwrap_or_else(|e| panic!("parse the server config {path}: {e}"));
            doc.get("security")
                .and_then(|s| s.get("cookie_secret"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{path} has no [security].cookie_secret"))
                .to_string()
        }
    };
    forseti::native_test_support::cookie_secret(&raw)
}

fn now() -> String {
    stamp(Utc::now())
}

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, false)
}

/// A new active identity; its id.
pub fn create_identity(
    conn: &Connection,
    email: &str,
    first: Option<&str>,
    last: Option<&str>,
    verified: bool,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now();
    conn.execute(
        "INSERT INTO identities (id, email, email_norm, email_verified_at, first_name, last_name, \
         state, state_changed_at, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?7, ?7)",
        params![
            id,
            email,
            email.to_lowercase(),
            verified.then_some(now.as_str()),
            first,
            last,
            now
        ],
    )
    .unwrap_or_else(|e| panic!("insert identity {email}: {e}"));
    id
}

fn insert_credential(conn: &Connection, identity_id: &str, kind: &str, config: &str) {
    let now = now();
    conn.execute(
        "INSERT INTO identity_credentials (id, identity_id, kind, config, version, created_at, \
         updated_at) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
        params![
            uuid::Uuid::new_v4().to_string(),
            identity_id,
            kind,
            config,
            now
        ],
    )
    .unwrap_or_else(|e| panic!("insert {kind} credential for {identity_id}: {e}"));
}

pub fn set_password(conn: &Connection, identity_id: &str, password: &str) {
    let config = forseti::native_test_support::password_config(password).expect("hash password");
    insert_credential(conn, identity_id, "password", &config);
}

/// A TOTP credential for the base32 `secret_b32`, sealed under `cookie_secret`.
pub fn plant_totp(conn: &Connection, cookie_secret: &[u8], identity_id: &str, secret_b32: &str) {
    let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
        .expect("TOTP secret is base32");
    let config = forseti::native_test_support::totp_config(cookie_secret, identity_id, &secret)
        .expect("seal TOTP secret");
    insert_credential(conn, identity_id, "totp", &config);
}

pub fn mark_verified(conn: &Connection, identity_id: &str) {
    conn.execute(
        "UPDATE identities SET email_verified_at = COALESCE(email_verified_at, ?2) WHERE id = ?1",
        params![identity_id, now()],
    )
    .expect("mark verified");
}

pub fn set_metadata_admin(conn: &Connection, identity_id: &str, metadata: &Value) {
    conn.execute(
        "UPDATE identities SET metadata_admin = ?2, updated_at = ?3 WHERE id = ?1",
        params![identity_id, metadata.to_string(), now()],
    )
    .expect("set metadata_admin");
}

pub fn identity_id_by_email(conn: &Connection, email: &str) -> Option<String> {
    conn.query_row(
        "SELECT id FROM identities WHERE email_norm = ?1",
        params![email.to_lowercase()],
        |r| r.get(0),
    )
    .optional()
    .expect("look up identity by email")
}

/// Delete an identity; its credentials, sessions, flows, codes and mail go with it.
pub fn delete_identity(conn: &Connection, identity_id: &str) {
    conn.execute("DELETE FROM identities WHERE id = ?1", params![identity_id])
        .expect("delete identity");
}

/// A session row found by the `forseti_session` cookie value.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub identity_id: String,
    pub aal: String,
    /// Not revoked, not expired, identity active.
    pub live: bool,
    /// The identity has a TOTP credential.
    pub totp: bool,
}

pub fn session_by_token(conn: &Connection, token: &str) -> Option<SessionRow> {
    let hash = forseti::native_test_support::token_hash(token);
    conn.query_row(
        "SELECT s.id, s.identity_id, s.aal, \
           (s.revoked_at IS NULL AND s.expires_at > ?2 AND i.state = 'active'), \
           EXISTS (SELECT 1 FROM identity_credentials c \
                   WHERE c.identity_id = s.identity_id AND c.kind = 'totp') \
         FROM identity_sessions s JOIN identities i ON i.id = s.identity_id \
         WHERE s.token_hash = ?1",
        params![hash, now()],
        |r| {
            Ok(SessionRow {
                id: r.get(0)?,
                identity_id: r.get(1)?,
                aal: r.get(2)?,
                live: r.get(3)?,
                totp: r.get(4)?,
            })
        },
    )
    .optional()
    .expect("look up session by token")
}

/// Ids of the identity's sessions that are neither revoked nor expired, newest first.
pub fn live_session_ids(conn: &Connection, identity_id: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(
            "SELECT id FROM identity_sessions WHERE identity_id = ?1 AND revoked_at IS NULL \
             AND expires_at > ?2 ORDER BY issued_at DESC",
        )
        .expect("prepare live sessions");
    stmt.query_map(params![identity_id, now()], |r| r.get(0))
        .expect("query live sessions")
        .collect::<Result<_, _>>()
        .expect("read live sessions")
}

/// Revoke every session of the identity behind Forseti's back.
pub fn end_sessions(conn: &Connection, identity_id: &str) {
    conn.execute(
        "UPDATE identity_sessions SET revoked_at = ?2 WHERE identity_id = ?1 AND revoked_at IS NULL",
        params![identity_id, now()],
    )
    .expect("end sessions");
}

/// Move every second-factor `completed_at` of the identity's sessions `secs` into the past;
/// the number of sessions rewritten.
pub fn backdate_second_factor(conn: &Connection, identity_id: &str, secs: i64) -> u64 {
    let mut stmt = conn
        .prepare("SELECT id, methods FROM identity_sessions WHERE identity_id = ?1")
        .expect("prepare sessions");
    let rows: Vec<(String, String)> = stmt
        .query_map(params![identity_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query sessions")
        .collect::<Result<_, _>>()
        .expect("read sessions");
    let mut changed = 0;
    for (id, methods) in rows {
        let mut methods: Vec<Value> = serde_json::from_str(&methods).expect("methods JSON");
        let mut touched = false;
        for m in &mut methods {
            if !matches!(m["method"].as_str(), Some("totp" | "lookup_secret")) {
                continue;
            }
            let at = m["completed_at"].as_str().expect("completed_at");
            let at = DateTime::parse_from_rfc3339(at)
                .expect("completed_at is RFC 3339")
                .with_timezone(&Utc);
            m["completed_at"] = Value::String(stamp(at - chrono::Duration::seconds(secs)));
            touched = true;
        }
        if touched {
            conn.execute(
                "UPDATE identity_sessions SET methods = ?2 WHERE id = ?1",
                params![id, Value::Array(methods).to_string()],
            )
            .expect("backdate methods");
            changed += 1;
        }
    }
    changed
}
