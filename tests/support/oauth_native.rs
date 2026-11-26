//! OAuth helpers for the native backend: client fixtures and session probes straight through the
//! running server's sqlite file, introspection at the internal listener, plus the issuer and
//! public endpoint base the suite drives. Same names and shapes as `oauth_ory.rs`.

use std::sync::OnceLock;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::common::{INTERNAL, PORTAL, browser_client, forseti_db_path};

const REDIRECT_URI: &str = "http://127.0.0.1:5555/callback";

/// `[self].url` of `config.ci.native-oauth.toml`, the `iss` the native server signs with.
pub fn oauth_issuer() -> &'static str {
    PORTAL
}

/// Base URL of the native `/oauth2/auth` and `/oauth2/token`. The flow cookies are host-scoped
/// with `Path=/oauth2`, so this must be the host the suite signs in at.
pub fn oauth_public() -> &'static str {
    PORTAL
}

/// A connection that waits out the server's write locks and cascades deletes.
fn conn() -> Connection {
    let path = forseti_db_path();
    let conn = Connection::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    conn.busy_timeout(Duration::from_secs(10))
        .expect("set busy timeout");
    conn.pragma_update(None, "foreign_keys", true)
        .expect("enable foreign keys");
    conn
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false)
}

fn strings(v: &[&str]) -> String {
    serde_json::to_string(v).expect("encode a string list")
}

/// The fields a client fixture writes; everything else stays NULL.
struct NewClient<'a> {
    name: &'a str,
    auth_method: &'a str,
    grant_types: &'a [&'a str],
    response_types: &'a [&'a str],
    scope: &'a str,
    redirect_uris: &'a [&'a str],
    audience: Option<&'a [&'a str]>,
    backchannel_logout_uri: Option<&'a str>,
    extra: Value,
}

/// Inserts the client; returns its id and, unless it authenticates with `none`, its secret.
fn insert_client(c: &NewClient<'_>) -> (String, Option<String>) {
    let id = uuid::Uuid::new_v4().to_string();
    let secret = (c.auth_method != "none").then(|| uuid::Uuid::new_v4().simple().to_string());
    let hash = secret
        .as_deref()
        .map(|s| forseti::native_test_support::hash_secret(s).expect("hash the client secret"));
    let now = now();
    conn()
        .execute(
            "INSERT INTO oauth_clients (client_id, client_name, secret_hash, \
             token_endpoint_auth_method, redirect_uris, grant_types, response_types, audience, \
             scope, backchannel_logout_uri, backchannel_logout_session_required, extra, \
             created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
            params![
                id,
                c.name,
                hash,
                c.auth_method,
                strings(c.redirect_uris),
                strings(c.grant_types),
                strings(c.response_types),
                c.audience.map(strings),
                c.scope,
                c.backchannel_logout_uri,
                c.backchannel_logout_uri.map(|_| 1),
                c.extra.to_string(),
                now
            ],
        )
        .unwrap_or_else(|e| panic!("insert OAuth client {}: {e}", c.name));
    (id, secret)
}

/// Register an OAuth2 client for tests, as the Ory helper registers it with Hydra.
///
/// Returns `(client_id, client_secret, redirect_uri)`. The redirect URI is the unreachable
/// `http://127.0.0.1:5555/callback`; tests grab the `code` from the redirect Location header.
pub async fn oauth_create_test_client(scopes: &[&str]) -> (String, String, String) {
    oauth_create_test_client_with_audience(scopes, &[]).await
}

/// As [`oauth_create_test_client`], with an operator-written `audience` on the client record.
pub async fn oauth_create_test_client_with_audience(
    scopes: &[&str],
    audience: &[&str],
) -> (String, String, String) {
    let (id, secret) = insert_client(&NewClient {
        name: "integration-test-client",
        auth_method: "client_secret_post",
        grant_types: &["authorization_code", "refresh_token"],
        response_types: &["code", "id_token"],
        scope: &scopes.join(" "),
        redirect_uris: &[REDIRECT_URI],
        audience: Some(audience),
        backchannel_logout_uri: None,
        extra: json!({ "subject_type": "public" }),
    });
    (
        id,
        secret.expect("a confidential client has a secret"),
        REDIRECT_URI.to_string(),
    )
}

/// Write `audience` onto a client's row, as any out-of-band credential could.
pub async fn oauth_patch_client_audience(client_id: &str, audience: &[&str]) {
    let changed = conn()
        .execute(
            "UPDATE oauth_clients SET audience = ?2, updated_at = ?3 WHERE client_id = ?1",
            params![client_id, strings(audience), now()],
        )
        .expect("patch client audience");
    assert_eq!(changed, 1, "patch audience: no client {client_id}");
}

/// The confidential client the suite introspects with, registered on first use.
fn introspection_client() -> &'static (String, String) {
    static CLIENT: OnceLock<(String, String)> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let (id, secret) = insert_client(&NewClient {
            name: "integration-introspection-client",
            auth_method: "client_secret_basic",
            grant_types: &["authorization_code"],
            response_types: &["code"],
            scope: "openid",
            redirect_uris: &[REDIRECT_URI],
            audience: None,
            backchannel_logout_uri: None,
            extra: json!({}),
        });
        (id, secret.expect("a confidential client has a secret"))
    })
}

/// RFC 7662 introspection of a token at the internal listener. Returns the raw response JSON.
pub async fn oauth_introspect(token: &str) -> Value {
    let (id, secret) = introspection_client();
    let res = browser_client()
        .post(format!("{INTERNAL}/oauth2/introspect"))
        .basic_auth(id, Some(secret))
        .form(&[("token", token)])
        .send()
        .await
        .expect("introspect transport");
    assert!(res.status().is_success(), "introspect: {}", res.status());
    res.json().await.expect("introspect body")
}

/// The client row in the Hydra client JSON shape: list columns decoded (`[]` when unset),
/// flags as booleans (`false` when unset), strings `""` when unset, `extra` merged in.
fn client_json(client_id: &str) -> Option<Value> {
    let conn = conn();
    conn.query_row(
        "SELECT client_id, client_name, token_endpoint_auth_method, redirect_uris, \
         post_logout_redirect_uris, grant_types, response_types, audience, scope, skip_consent, \
         logo_uri, client_uri, backchannel_logout_uri, backchannel_logout_session_required, \
         frontchannel_logout_uri, frontchannel_logout_session_required, metadata, extra, \
         created_at, updated_at FROM oauth_clients WHERE client_id = ?1",
        params![client_id],
        |r| {
            let text = |i: usize| -> rusqlite::Result<Value> {
                Ok(Value::String(
                    r.get::<_, Option<String>>(i)?.unwrap_or_default(),
                ))
            };
            let list = |i: usize| -> rusqlite::Result<Value> {
                Ok(r.get::<_, Option<String>>(i)?.map_or_else(
                    || json!([]),
                    |s| serde_json::from_str(&s).expect("list column is JSON"),
                ))
            };
            let flag = |i: usize| -> rusqlite::Result<Value> {
                Ok(Value::Bool(
                    r.get::<_, Option<i64>>(i)?.is_some_and(|b| b != 0),
                ))
            };
            let metadata = r.get::<_, Option<String>>(16)?.map_or_else(
                || json!({}),
                |s| serde_json::from_str(&s).expect("metadata JSON"),
            );
            let extra: String = r.get(17)?;
            let mut v: Map<String, Value> =
                serde_json::from_str(&extra).expect("extra is a JSON object");
            for (k, val) in [
                ("client_id", text(0)?),
                ("client_name", text(1)?),
                ("token_endpoint_auth_method", text(2)?),
                ("redirect_uris", list(3)?),
                ("post_logout_redirect_uris", list(4)?),
                ("grant_types", list(5)?),
                ("response_types", list(6)?),
                ("audience", list(7)?),
                ("scope", text(8)?),
                ("skip_consent", flag(9)?),
                ("logo_uri", text(10)?),
                ("client_uri", text(11)?),
                ("backchannel_logout_uri", text(12)?),
                ("backchannel_logout_session_required", flag(13)?),
                ("frontchannel_logout_uri", text(14)?),
                ("frontchannel_logout_session_required", flag(15)?),
                ("metadata", metadata),
                ("created_at", text(18)?),
                ("updated_at", text(19)?),
            ] {
                v.insert(k.to_string(), val);
            }
            Ok(Value::Object(v))
        },
    )
    .optional()
    .expect("read OAuth client")
}

/// The `audience` allow-list stored for a client. Empty when the client is unknown or carries
/// none.
pub async fn oauth_client_audience(client_id: &str) -> Vec<String> {
    client_json(client_id)
        .and_then(|v| v["audience"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect()
}

/// The granted `audience` of each consent grant `client_id` holds, oldest first.
pub async fn oauth_grant_audiences(client_id: &str) -> Vec<Vec<String>> {
    let conn = conn();
    let mut stmt = conn
        .prepare(
            "SELECT audience FROM oauth_consent_grants WHERE client_id = ?1 ORDER BY handled_at",
        )
        .expect("prepare grant audience query");
    stmt.query_map(params![client_id], |r| r.get::<_, String>(0))
        .expect("read grant audiences")
        .map(|a| serde_json::from_str(&a.expect("grant audience")).expect("audience is JSON"))
        .collect()
}

/// Write `client_name` onto a client's row, out of band.
pub async fn oauth_set_client_name(client_id: &str, name: &str) {
    let changed = conn()
        .execute(
            "UPDATE oauth_clients SET client_name = ?2, updated_at = ?3 WHERE client_id = ?1",
            params![client_id, name, now()],
        )
        .expect("set client_name");
    assert_eq!(changed, 1, "set client_name: no client {client_id}");
}

/// Delete a client; its flows and grants cascade. Best-effort.
pub async fn oauth_delete_client(client_id: &str) {
    let _ = conn().execute(
        "DELETE FROM oauth_clients WHERE client_id = ?1",
        params![client_id],
    );
}

/// How many clients carry `client_name`.
pub async fn oauth_client_count_by_name(client_name: &str) -> usize {
    let n: i64 = conn()
        .query_row(
            "SELECT COUNT(*) FROM oauth_clients WHERE client_name = ?1",
            params![client_name],
            |r| r.get(0),
        )
        .expect("count clients by name");
    usize::try_from(n).expect("count is non-negative")
}

/// A single field of the client JSON. `None` when the client is gone or the field isn't present.
pub async fn oauth_client_field(client_id: &str, field: &str) -> Option<Value> {
    client_json(client_id)?.get(field).cloned()
}

/// The client JSON; panics when the client does not exist.
pub async fn oauth_get_client_json(client_id: &str) -> Value {
    client_json(client_id).unwrap_or_else(|| panic!("no OAuth client {client_id}"))
}

/// Set a client's `skip_consent`, for tests that need to prove the auto-grant gate gates.
pub async fn oauth_set_client_skip_consent(client_id: &str, skip: bool) {
    let changed = conn()
        .execute(
            "UPDATE oauth_clients SET skip_consent = ?2, updated_at = ?3 WHERE client_id = ?1",
            params![client_id, i32::from(skip), now()],
        )
        .expect("set skip_consent");
    assert_eq!(changed, 1, "set skip_consent: no client {client_id}");
}

/// A public (`token_endpoint_auth_method: none`) client with a self-declared `audience` and no
/// Forseti involvement. Returns its client_id.
pub async fn oauth_admin_create_public_client(
    name: &str,
    scope: &str,
    redirect_uris: &[&str],
    audience: &[&str],
) -> String {
    insert_client(&NewClient {
        name,
        auth_method: "none",
        grant_types: &["authorization_code", "refresh_token"],
        response_types: &["code"],
        scope,
        redirect_uris,
        audience: Some(audience),
        backchannel_logout_uri: None,
        extra: json!({}),
    })
    .0
}

/// A confidential client with `backchannel_logout_uri` (session required) and the refresh grant.
/// Returns `(client_id, client_secret, redirect_uri)`.
pub async fn oauth_create_backchannel_client(
    scopes: &[&str],
    backchannel_logout_uri: &str,
) -> (String, String, String) {
    let (id, secret) = insert_client(&NewClient {
        name: "integration-test-backchannel",
        auth_method: "client_secret_post",
        grant_types: &["authorization_code", "refresh_token"],
        response_types: &["code"],
        scope: &scopes.join(" "),
        redirect_uris: &[REDIRECT_URI],
        audience: None,
        backchannel_logout_uri: Some(backchannel_logout_uri),
        extra: json!({}),
    });
    (
        id,
        secret.expect("a confidential client has a secret"),
        REDIRECT_URI.to_string(),
    )
}

/// Remembered consent grants for a subject that the user gave (not skipped), what Hydra's
/// consent-session list returns.
pub async fn oauth_consent_session_count(subject: &str) -> usize {
    let n: i64 = conn()
        .query_row(
            "SELECT COUNT(*) FROM oauth_consent_grants \
             WHERE subject = ?1 AND remember <> 0 AND skipped = 0",
            params![subject],
            |r| r.get(0),
        )
        .expect("count consent grants");
    usize::try_from(n).expect("count is non-negative")
}

/// Consent grants and authorization codes `subject` holds for `client_id`, remembered or not.
pub async fn oauth_grant_and_code_count(subject: &str, client_id: &str) -> (usize, usize) {
    let count = |table: &str| -> usize {
        let n: i64 = conn()
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE subject = ?1 AND client_id = ?2"),
                params![subject, client_id],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("count {table}: {e}"));
        usize::try_from(n).expect("count is non-negative")
    };
    (
        count("oauth_consent_grants"),
        count("oauth_authorization_codes"),
    )
}

/// Whether the OP login session `sid` still has its row, expired or not.
pub async fn oauth_login_session_exists(sid: &str) -> bool {
    conn()
        .query_row(
            "SELECT 1 FROM oauth_login_sessions WHERE sid = ?1",
            params![sid],
            |_| Ok(()),
        )
        .optional()
        .expect("read login session")
        .is_some()
}

/// Whether the authorization request behind `challenge` skips login on a remembered session.
pub async fn oauth_login_request_skip(challenge: &str) -> bool {
    let hash = hex::encode(Sha256::digest(challenge.as_bytes()));
    conn()
        .query_row(
            "SELECT skip_login FROM oauth_authorize_requests WHERE login_challenge_hash = ?1",
            params![hash],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .expect("read authorization request")
        .map(|skip| skip != 0)
        .expect("no authorization request for the login challenge")
}
