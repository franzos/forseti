//! OAuth helpers for the Ory backend: client fixtures and session probes through Hydra's admin
//! API, plus the issuer and public endpoint base the suite drives.

use reqwest::StatusCode;
use serde_json::Value;

use crate::common::{browser_client, form_urlencode};

pub const HYDRA_ADMIN: &str = "http://localhost:4445";

/// Forseti's issuer under `config.ci.toml` (`[hydra].issuer`), the `iss` Hydra signs with.
pub fn oauth_issuer() -> &'static str {
    "http://host.containers.internal:3000/hydra"
}

/// Base URL of Hydra's public endpoints (`/oauth2/auth`, `/oauth2/token`).
// Must match Hydra's `issuer` host (host.containers.internal, see infra/hydra/hydra.yml):
// Hydra scopes its login/consent CSRF cookie to the issuer host, so driving
// /oauth2/auth via `localhost` drops the cookie mid-flow and the chain 403s with
// `request_forbidden: No CSRF value available`. Resolves to 127.0.0.1 here.
pub fn oauth_public() -> &'static str {
    "http://host.containers.internal:4444"
}

/// Register an OAuth2 client for tests. Mirrors the `hydra create client`
/// invocation in the `ory-up` skill but goes via the admin API directly so
/// we don't have to shell out to `podman exec`.
///
/// Returns `(client_id, client_secret, redirect_uri)`. The redirect URI is
/// the same `http://127.0.0.1:5555/callback` the playground uses (intentionally
/// unreachable — tests grab the `code` from the redirect Location header).
pub async fn oauth_create_test_client(scopes: &[&str]) -> (String, String, String) {
    oauth_create_test_client_with_audience(scopes, &[]).await
}

/// As [`oauth_create_test_client`], with an operator-written `audience` on the
/// client record — the shape an admin-created SSO client has, and the only
/// thing that authorises Hydra's non-standard `audience=` parameter.
pub async fn oauth_create_test_client_with_audience(
    scopes: &[&str],
    audience: &[&str],
) -> (String, String, String) {
    let client = browser_client();
    let redirect_uri = "http://127.0.0.1:5555/callback";
    let scope = scopes.join(" ");
    let body = serde_json::json!({
        "client_name": "integration-test-client",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code", "id_token"],
        "scope": scope,
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "client_secret_post",
        "subject_type": "public",
        "audience": audience,
    });
    let res = client
        .post(format!("{HYDRA_ADMIN}/admin/clients"))
        .json(&body)
        .send()
        .await
        .expect("hydra create client transport");
    assert!(
        res.status().is_success(),
        "hydra create client: status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let v: Value = res.json().await.expect("hydra create client body");
    let id = v["client_id"].as_str().expect("client_id").to_string();
    let secret = v["client_secret"]
        .as_str()
        .expect("client_secret")
        .to_string();
    (id, secret, redirect_uri.to_string())
}

/// Write `audience` onto a client's Hydra record via the admin API. Stands in
/// for any out-of-band credential that can rewrite the record. The client_id
/// path segment is percent-encoded so URL-shaped (CIMD) ids work too.
pub async fn oauth_patch_client_audience(client_id: &str, audience: &[&str]) {
    let client = browser_client();
    let patch = serde_json::json!([
        { "op": "replace", "path": "/audience", "value": audience }
    ]);
    let res = client
        .patch(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(client_id)
        ))
        .header("content-type", "application/json")
        .json(&patch)
        .send()
        .await
        .expect("hydra patch audience transport");
    assert!(
        res.status().is_success(),
        "hydra PATCH /audience: status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
}

/// RFC 7662 introspection of an access token via Hydra admin. Returns the raw
/// JSON so callers can assert on `active`, `aud`, `scope`, …
pub async fn oauth_introspect(token: &str) -> Value {
    let client = browser_client();
    let res = client
        .post(format!("{HYDRA_ADMIN}/admin/oauth2/introspect"))
        .form(&[("token", token)])
        .send()
        .await
        .expect("hydra introspect transport");
    res.json().await.unwrap_or(Value::Null)
}

/// The `audience` allow-list Hydra has stored for a client. Empty when the
/// client is unknown or carries none. Percent-encodes the client_id path
/// segment so URL-shaped (CIMD) ids work too.
pub async fn oauth_client_audience(client_id: &str) -> Vec<String> {
    let client = browser_client();
    let Ok(res) = client
        .get(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(client_id)
        ))
        .send()
        .await
    else {
        return Vec::new();
    };
    let v: Value = res.json().await.unwrap_or(Value::Null);
    v["audience"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Delete a Hydra client. Best-effort.
pub async fn oauth_delete_client(client_id: &str) {
    let client = browser_client();
    // CIMD client ids are whole URLs, so the path segment has to be encoded
    // or the DELETE lands on a different path and the client stays put.
    let _ = client
        .delete(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(client_id)
        ))
        .send()
        .await;
}

/// How many Hydra clients carry `client_name`. Lets a test assert that a
/// rejected create left nothing behind.
pub async fn oauth_client_count_by_name(client_name: &str) -> usize {
    let client = browser_client();
    let Ok(res) = client
        .get(format!("{HYDRA_ADMIN}/admin/clients?page_size=500"))
        .send()
        .await
    else {
        return 0;
    };
    let v: Value = res.json().await.unwrap_or(Value::Null);
    v.as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c["client_name"].as_str() == Some(client_name))
                .count()
        })
        .unwrap_or(0)
}

/// Read a single field off a Hydra client via the admin API. `None` when the
/// client is gone or the field isn't present.
pub async fn oauth_client_field(client_id: &str, field: &str) -> Option<Value> {
    let client = browser_client();
    let res = client
        .get(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(client_id)
        ))
        .send()
        .await
        .ok()?;
    let v: Value = res.json().await.ok()?;
    v.get(field).cloned()
}

/// GET the Hydra client row via the admin API. URL-shaped client_ids need the
/// path segment percent-encoded.
pub async fn oauth_get_client_json(client_id: &str) -> Value {
    let res = browser_client()
        .get(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(client_id)
        ))
        .send()
        .await
        .expect("hydra get client transport");
    assert!(
        res.status().is_success(),
        "hydra get client {client_id}: status {}",
        res.status()
    );
    res.json().await.expect("hydra client json")
}

/// Flip a Hydra client's `skip_consent` via the admin API, for tests that need
/// to prove the auto-grant gate actually gates.
pub async fn oauth_set_client_skip_consent(client_id: &str, skip: bool) {
    let client = browser_client();
    let patch = serde_json::json!([
        { "op": "replace", "path": "/skip_consent", "value": skip }
    ]);
    let res = client
        .patch(format!("{HYDRA_ADMIN}/admin/clients/{client_id}"))
        .json(&patch)
        .send()
        .await
        .expect("patch hydra client skip_consent");
    assert!(
        res.status().is_success(),
        "patch skip_consent: {} {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
}

/// Create a public (`token_endpoint_auth_method: none`) client straight via
/// Hydra's admin API, with a self-declared `audience` on the record and no
/// Forseti involvement. Returns the Hydra-minted client_id.
pub async fn oauth_admin_create_public_client(
    name: &str,
    scope: &str,
    redirect_uris: &[&str],
    audience: &[&str],
) -> String {
    let body = serde_json::json!({
        "client_name": name,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": scope,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "audience": audience,
    });
    let res = browser_client()
        .post(format!("{HYDRA_ADMIN}/admin/clients"))
        .json(&body)
        .send()
        .await
        .expect("hydra admin create transport");
    assert!(
        res.status().is_success(),
        "hydra admin create: status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let v: Value = res.json().await.expect("hydra admin create body");
    v["client_id"].as_str().expect("client_id").to_string()
}

/// A confidential client with `backchannel_logout_uri` (session required) and
/// the refresh grant. Returns `(client_id, client_secret, redirect_uri)`.
pub async fn oauth_create_backchannel_client(
    scopes: &[&str],
    backchannel_logout_uri: &str,
) -> (String, String, String) {
    let redirect_uri = "http://127.0.0.1:5555/callback";
    let body = serde_json::json!({
        "client_name": "integration-test-backchannel",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": scopes.join(" "),
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "client_secret_post",
        "backchannel_logout_uri": backchannel_logout_uri,
        "backchannel_logout_session_required": true,
    });
    let res = browser_client()
        .post(format!("{HYDRA_ADMIN}/admin/clients"))
        .json(&body)
        .send()
        .await
        .expect("hydra create client transport");
    assert!(
        res.status().is_success(),
        "hydra create client: {}",
        res.status()
    );
    let v: Value = res.json().await.expect("hydra create client body");
    (
        v["client_id"].as_str().expect("client_id").to_string(),
        v["client_secret"]
            .as_str()
            .expect("client_secret")
            .to_string(),
        redirect_uri.to_string(),
    )
}

/// Count Hydra consent sessions for a subject via the admin API
/// (`GET /admin/oauth2/auth/sessions/consent?subject=...`). Used to assert the
/// account-delete saga and the per-client revoke actually wiped grants.
pub async fn oauth_consent_session_count(subject: &str) -> usize {
    let client = browser_client();
    let res = client
        .get(format!(
            "{HYDRA_ADMIN}/admin/oauth2/auth/sessions/consent?subject={subject}"
        ))
        .send()
        .await
        .expect("list consent sessions transport");
    if res.status() == StatusCode::NO_CONTENT || !res.status().is_success() {
        return 0;
    }
    let body: Value = res.json().await.unwrap_or(Value::Null);
    body.as_array().map(|a| a.len()).unwrap_or(0)
}

pub async fn oauth_login_request_skip(challenge: &str) -> bool {
    let v: Value = reqwest::Client::new()
        .get(format!(
            "{HYDRA_ADMIN}/admin/oauth2/auth/requests/login?login_challenge={challenge}"
        ))
        .send()
        .await
        .expect("get login request")
        .json()
        .await
        .expect("login request body");
    v["skip"].as_bool().expect("skip field")
}
