//! Shared test helpers: HTTP client setup, identity factories, Mailcrab
//! polling, Hydra client registration.
//!
//! Every helper here is intentionally synchronous-shaped from the test's POV —
//! they take a `&reqwest::Client` and `await` internally. The client is
//! configured with a cookie jar so end-to-end flow tests can chain redirects
//! and the resulting `ory_kratos_session` cookie sticks.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use rusqlite::params;
use serde_json::Value;
use sha2::{Digest, Sha256};

// --- Endpoints -------------------------------------------------------------

// Must match the host used in `config.toml` and Kratos's config — they all
// resolve to `localhost`. When the test client follows a 303 from
// localhost:4433 → localhost:3000 (or vice versa), reqwest's cookie jar
// scopes the CSRF cookie to `localhost`; if the constants were `127.0.0.1`
// the subsequent same-port request goes to a different host and the cookie
// is dropped, sending the portal into an infinite re-init loop.
pub const PORTAL: &str = "http://localhost:3000";
// Internal listener (M2M: audit webhook + posix resolver). Matches
// `[internal].bind` in config.ci.toml (default 0.0.0.0:8081); reached over
// loopback from the test host.
pub const INTERNAL: &str = "http://127.0.0.1:8081";
pub const KRATOS_PUBLIC: &str = "http://localhost:4433";
pub const KRATOS_ADMIN: &str = "http://localhost:4434";
// Must match Hydra's `issuer` (host.containers.internal, see infra/hydra/hydra.yml):
// Hydra scopes its login/consent CSRF cookie to the issuer host, so driving
// /oauth2/auth via `localhost` drops the cookie mid-flow and the chain 403s with
// `request_forbidden: No CSRF value available`. Resolves to 127.0.0.1 here.
pub const HYDRA_PUBLIC: &str = "http://host.containers.internal:4444";
pub const HYDRA_ADMIN: &str = "http://localhost:4445";
/// Mailcrab base URL — the user-prompt-mandated replacement for the
/// older Mailslurper container. Different API shape (`/api/messages`
/// returns `[{ to: [{ email }], subject, ... }]`); use
/// [`read_mailcrab_inbox`] / [`wait_for_mailcrab`] for the helpers.
pub const MAILCRAB: &str = "http://localhost:4436";

// --- Client builders -------------------------------------------------------

/// A `reqwest` client with cookie store enabled and redirect following on.
/// Use this for the "drive the portal like a browser" tests.
pub fn browser_client() -> Client {
    Client::builder()
        .cookie_store(true)
        .redirect(Policy::limited(20))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build browser client")
}

/// A `reqwest` client with cookies but redirects DISABLED. Use this when the
/// test needs to assert on the redirect chain itself (e.g. "303 → Kratos init
/// URL with `aal=aal2` preserved").
pub fn manual_redirect_client() -> Client {
    Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build manual-redirect client")
}

/// Build a paired (auto-redirect, manual-redirect) client tuple that shares
/// the same cookie jar. Useful when a test mostly wants browser-style
/// behaviour but needs one specific step where the redirect chain must be
/// inspected hop by hop (e.g. OAuth code grab from a 303 to an unreachable
/// callback URL).
pub fn paired_clients() -> (Client, Client, std::sync::Arc<reqwest::cookie::Jar>) {
    let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
    let auto = Client::builder()
        .cookie_provider(jar.clone())
        .redirect(Policy::limited(20))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build auto-redirect client");
    let manual = Client::builder()
        .cookie_provider(jar.clone())
        .redirect(Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build manual-redirect client");
    (auto, manual, jar)
}

// --- Email / identity factories -------------------------------------------

/// Generate a unique test email. `prefix` lets the caller embed a per-test
/// marker so they're easy to spot in Mailcrab / Kratos admin.
pub fn unique_email(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{nanos}@example.com")
}

/// Drive the portal's two-step registration flow using a caller-supplied
/// client (and its existing cookie jar). Returns the identity ID + email.
/// Used by regression tests that need to reuse a single cookie jar across
/// successive registrations to reproduce cross-principal cookie leaks.
pub async fn register_test_user_with_client(
    client: &Client,
    prefix: &str,
) -> (String, String, String) {
    let email = unique_email(prefix);
    let password = "Sup3rSecret-Test-Password!";

    let res = client
        .get(format!("{PORTAL}/registration"))
        .send()
        .await
        .expect("init registration");
    assert!(
        res.status().is_success(),
        "registration init: status {}",
        res.status()
    );
    let flow_id = extract_flow_id_from_url(res.url().as_str())
        .expect("flow id in /registration URL after init");

    let flow = fetch_flow(client, "registration", &flow_id).await;
    let csrf = flow_csrf_token(&flow).expect("csrf_token in flow");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("ui.action")
        .to_string();

    let res = client
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("traits.email", email.as_str()),
            ("traits.name.first", "Test"),
            ("traits.name.last", "User"),
            ("method", "profile"),
            ("screen", "credential-selection"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("submit profile step");
    let status = res.status();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    let advanced =
        body["state"].as_str() == Some("choose_method") || flow_has_group(&body, "password");
    assert!(
        status.is_success() || status.is_redirection() || advanced,
        "profile step unexpected status {status} body {body}"
    );
    let flow = fetch_flow(client, "registration", &flow_id).await;
    let csrf = flow_csrf_token(&flow).expect("csrf_token in flow (step 2)");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("ui.action (step 2)")
        .to_string();

    let res = client
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("password", password),
            ("method", "password"),
            ("traits.email", email.as_str()),
            ("traits.name.first", "Test"),
            ("traits.name.last", "User"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("submit password step");
    let status = res.status();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    assert!(status.is_success(), "password step status {status}: {body}");

    let identity_id = match body["identity"]["id"]
        .as_str()
        .or_else(|| body["session"]["identity"]["id"].as_str())
        .map(str::to_string)
    {
        Some(id) => id,
        None => identity_id_by_email(&email)
            .await
            .unwrap_or_else(|| panic!("identity id after registration (not in response body and Kratos admin lookup failed for {email})")),
    };

    (identity_id, email, password.to_string())
}

/// Drive the portal's two-step registration flow end-to-end, returning the
/// authenticated `Client` (its cookie jar carries `ory_kratos_session`) and
/// the identity ID + the email used.
///
/// Kratos's identity schema in this playground requires `traits.email`,
/// `traits.name.first`, `traits.name.last`. Step 1 submits profile fields with
/// `screen=credential-selection`; step 2 submits a password.
///
/// The user is signed in immediately after step 2 (session hook in
/// `kratos.yml`'s `selfservice.flows.registration.after.password.hooks`).
pub async fn register_test_user(prefix: &str) -> RegisteredUser {
    let (client, manual_client, _jar) = paired_clients();
    let email = unique_email(prefix);
    let password = "Sup3rSecret-Test-Password!";

    // 1. Init flow via the portal. Kratos sets its CSRF cookie + the flow
    //    cookie, the portal lands us on /registration?flow=<id>.
    let res = client
        .get(format!("{PORTAL}/registration"))
        .send()
        .await
        .expect("init registration");
    assert!(
        res.status().is_success(),
        "registration init: status {}",
        res.status()
    );
    let flow_id = extract_flow_id_from_url(res.url().as_str())
        .expect("flow id in /registration URL after init");

    // 2. Fetch the flow JSON for the action URL + csrf_token.
    let flow = fetch_flow(&client, "registration", &flow_id).await;
    let csrf = flow_csrf_token(&flow).expect("csrf_token in flow");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("ui.action")
        .to_string();

    // 3. Submit profile step. Kratos returns 400 (+ the advanced flow JSON
    //    in the body) when the flow needs more user input — that's the
    //    "now show the password step" signal, not a failure. We accept any
    //    response whose body parses as a flow with `state == choose_method`
    //    or that exposes the `password` group.
    let res = client
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("traits.email", email.as_str()),
            ("traits.name.first", "Test"),
            ("traits.name.last", "User"),
            ("method", "profile"),
            ("screen", "credential-selection"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("submit profile step");
    let status = res.status();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    let advanced =
        body["state"].as_str() == Some("choose_method") || flow_has_group(&body, "password");
    assert!(
        status.is_success() || status.is_redirection() || advanced,
        "profile step unexpected status {status} body {body}"
    );
    // Refetch the flow — it has been advanced to the password step. We could
    // also parse the response body but refetching keeps the data shape
    // identical to the GET path.
    let flow = fetch_flow(&client, "registration", &flow_id).await;
    let csrf = flow_csrf_token(&flow).expect("csrf_token in flow (step 2)");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("ui.action (step 2)")
        .to_string();

    // 4. Submit password step. Kratos's two-step flow keeps the `traits.*`
    //    fields as hidden inputs in the password screen; they must be
    //    re-submitted or Kratos rejects with "Property email is missing".
    //    Kratos's session hook signs the user in on success.
    let res = client
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("password", password),
            ("method", "password"),
            ("traits.email", email.as_str()),
            ("traits.name.first", "Test"),
            ("traits.name.last", "User"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("submit password step");
    let status = res.status();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    assert!(status.is_success(), "password step status {status}: {body}");

    let identity_id = match body["identity"]["id"]
        .as_str()
        .or_else(|| body["session"]["identity"]["id"].as_str())
        .map(str::to_string)
    {
        Some(id) => id,
        None => identity_id_by_email(&email)
            .await
            .unwrap_or_else(|| panic!("identity id after registration (not in response body and Kratos admin lookup failed for {email})")),
    };

    RegisteredUser {
        client,
        manual_client,
        identity_id,
        email,
        password: password.to_string(),
    }
}

/// Look up an identity ID by email via the Kratos admin API. Used as a
/// fallback when the registration response shape doesn't carry the identity.
pub async fn identity_id_by_email(email: &str) -> Option<String> {
    let client = browser_client();
    let url = format!("{KRATOS_ADMIN}/admin/identities?credentials_identifier={email}");
    let res = client.get(&url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let body: Value = res.json().await.ok()?;
    let arr = body.as_array()?;
    // Kratos returns a list; the credentials_identifier filter should pin it
    // to one row, but be defensive and accept the first.
    arr.iter()
        .find_map(|v| v["id"].as_str().map(str::to_string))
}

/// Materialized state of a freshly-registered user. Owns the client whose
/// cookie jar carries `ory_kratos_session`, so subsequent calls on it are
/// authenticated.
pub struct RegisteredUser {
    /// Browser-style client: cookies + auto-follow redirects.
    pub client: Client,
    /// Sibling client sharing the same cookie jar with redirects disabled —
    /// for tests that need to inspect each hop (e.g. OAuth code capture).
    pub manual_client: Client,
    pub identity_id: String,
    pub email: String,
    pub password: String,
}

impl RegisteredUser {
    /// Best-effort cleanup. Called from test teardown — failures are logged
    /// (via stderr) but not propagated, since a flaky delete shouldn't fail
    /// an otherwise-green test.
    pub async fn cleanup(&self) {
        let _ = delete_test_identity(&self.identity_id).await;
    }
}

/// Delete an identity via the Kratos admin API. No-op when the ID is empty.
pub async fn delete_test_identity(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Ok(());
    }
    let client = browser_client();
    let res = client
        .delete(format!("{KRATOS_ADMIN}/admin/identities/{id}"))
        .send()
        .await
        .map_err(|e| format!("delete identity transport: {e}"))?;
    if !res.status().is_success() && res.status() != StatusCode::NOT_FOUND {
        return Err(format!(
            "delete identity {id}: status {} body {}",
            res.status(),
            res.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

/// Create an identity directly via the admin API, skipping the UI. Faster
/// than `register_test_user` for tests that don't need the portal to be
/// exercised end-to-end (e.g. logout / settings nav). Returns the new
/// identity ID.
pub async fn kratos_admin_create_identity(email: &str) -> String {
    let client = browser_client();
    let body = serde_json::json!({
        "schema_id": "default",
        "traits": {
            "email": email,
            "name": { "first": "Admin", "last": "Test" }
        },
        "verifiable_addresses": [],
    });
    let res = client
        .post(format!("{KRATOS_ADMIN}/admin/identities"))
        .json(&body)
        .send()
        .await
        .expect("create identity transport");
    assert!(
        res.status().is_success(),
        "create identity status {}: {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let v: Value = res.json().await.expect("create identity body");
    v["id"].as_str().expect("identity id").to_string()
}

/// Create an identity *with* a password credential directly via the admin
/// API (Kratos hashes the supplied plaintext). Unlike
/// [`kratos_admin_create_identity`], the returned identity can password-login
/// — used by the AAL2-enforcement test that needs a second-factor-less user
/// to prove enforcement doesn't bounce password-only sessions. Returns the
/// new identity ID.
pub async fn kratos_admin_create_password_identity(email: &str, password: &str) -> String {
    let client = browser_client();
    let body = serde_json::json!({
        "schema_id": "default",
        "traits": {
            "email": email,
            "name": { "first": "NoMfa", "last": "User" }
        },
        "credentials": {
            "password": { "config": { "password": password } }
        },
    });
    let res = client
        .post(format!("{KRATOS_ADMIN}/admin/identities"))
        .json(&body)
        .send()
        .await
        .expect("create password identity transport");
    assert!(
        res.status().is_success(),
        "create password identity status {}: {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let v: Value = res.json().await.expect("create password identity body");
    v["id"].as_str().expect("identity id").to_string()
}

// --- Flow helpers ----------------------------------------------------------

/// Fetch a Kratos self-service flow's JSON shape. The client must carry the
/// flow's continuity cookie (Kratos refuses without it; see CSRF docs).
pub async fn fetch_flow(client: &Client, kind: &str, flow_id: &str) -> Value {
    let url = format!("{KRATOS_PUBLIC}/self-service/{kind}/flows?id={flow_id}");
    let res = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .expect("fetch flow transport");
    assert!(
        res.status().is_success(),
        "fetch flow ({kind}): status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    res.json().await.expect("flow json")
}

/// Does the flow's `ui.nodes` contain any node in the given `group`? Used
/// to detect that a registration flow has advanced past the profile step
/// (which adds the `password` group).
pub fn flow_has_group(flow: &Value, group: &str) -> bool {
    flow["ui"]["nodes"]
        .as_array()
        .map(|arr| arr.iter().any(|n| n["group"].as_str() == Some(group)))
        .unwrap_or(false)
}

/// Pull `csrf_token`'s value out of a flow's `ui.nodes`. Returns `None` if
/// the flow has no CSRF token (e.g. an already-completed flow Kratos returns
/// for inspection only).
pub fn flow_csrf_token(flow: &Value) -> Option<String> {
    let nodes = flow["ui"]["nodes"].as_array()?;
    for n in nodes {
        if n["attributes"]["name"].as_str() == Some("csrf_token") {
            return n["attributes"]["value"].as_str().map(str::to_string);
        }
    }
    None
}

/// Extract the `?flow=<id>` query value from a URL. Handles raw URL strings
/// — no `url` crate needed.
pub fn extract_flow_id_from_url(url: &str) -> Option<String> {
    extract_query_param(url, "flow")
}

/// Generic single-value query parameter extractor. Returns the decoded value
/// or `None` if the parameter isn't present.
pub fn extract_query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == name {
            return Some(urldecode(v));
        }
    }
    None
}

/// Minimal percent-decoder for `+ → ' '` and `%HH` octets. Enough for the
/// query strings these tests inspect; we explicitly avoid pulling in `url`
/// crate just to decode a single value.
pub fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_digit(bytes[i + 1]);
                let lo = hex_digit(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// --- Mailcrab ---------------------------------------------------------------

/// One email captured by Mailcrab.
#[derive(Debug, Clone)]
pub struct MailItem {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
    pub date_sent: String,
}

/// Read the Mailcrab inbox via its `/api/messages` endpoint, filtering
/// down to messages addressed to `to_address`. Mailcrab's shape differs
/// from the older Mailslurper container: items are `{ id, to: [{ email
/// }], subject, time, ... }`. Returns newest-first by `time`.
///
/// Mailcrab returns only the metadata on `/api/messages` — the full
/// body comes from `/api/message/{id}`. We fetch the body lazily for
/// each item we keep so the test path stays single-purpose.
pub async fn read_mailcrab_inbox(to_address: &str) -> Vec<MailItem> {
    let client = browser_client();
    let res = client.get(format!("{MAILCRAB}/api/messages")).send().await;
    let res = match res {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let v: Value = match res.json().await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v.as_array().cloned().unwrap_or_default();
    let needle = to_address.to_lowercase();
    let mut matches: Vec<(String, MailItem)> = Vec::new();
    for m in arr.into_iter() {
        let to: Vec<String> = m["to"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v["email"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if !to.iter().any(|a| a.to_lowercase().contains(&needle)) {
            continue;
        }
        let id = m["id"].as_str().unwrap_or_default().to_string();
        let from = m["from"]["email"].as_str().unwrap_or_default().to_string();
        let subject = m["subject"].as_str().unwrap_or_default().to_string();
        let date_sent = m["date"].as_str().unwrap_or_default().to_string();
        matches.push((
            id.clone(),
            MailItem {
                id,
                from,
                to,
                subject,
                body: String::new(), // filled below
                date_sent,
            },
        ));
    }
    // Fetch bodies in parallel-ish (small N; sequential is fine).
    let mut out = Vec::with_capacity(matches.len());
    for (id, mut item) in matches {
        let body_res = client
            .get(format!("{MAILCRAB}/api/message/{id}"))
            .send()
            .await;
        if let Ok(r) = body_res {
            if let Ok(v) = r.json::<Value>().await {
                // Mailcrab returns plain + html separately. The portal-
                // generated mail we care about (claim-email code, invite)
                // is text/plain only; Kratos's verification email is
                // multipart. Prefer `text` (plain), fall back to `html`.
                let body = v["text"]
                    .as_str()
                    .or_else(|| v["html"].as_str())
                    .unwrap_or_default()
                    .to_string();
                item.body = body;
            }
        }
        out.push(item);
    }
    out.sort_by(|a, b| b.date_sent.cmp(&a.date_sent));
    out
}

/// Poll Mailcrab for an email matching `to_address` and
/// `subject_contains`, returning the first match within `timeout`.
/// Returns `None` on timeout.
pub async fn wait_for_mailcrab(
    to_address: &str,
    subject_contains: &str,
    timeout: Duration,
) -> Option<MailItem> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let inbox = read_mailcrab_inbox(to_address).await;
        if let Some(m) = inbox
            .into_iter()
            .find(|m| m.subject.contains(subject_contains))
        {
            return Some(m);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Extract a 6-digit Kratos code from an email body. Kratos always emits the
/// code as a standalone line of six digits.
pub fn extract_code_from_email(body: &str) -> Option<String> {
    let re = regex::Regex::new(r"\b(\d{6})\b").ok()?;
    re.captures(body)?.get(1).map(|m| m.as_str().to_string())
}

// --- Hydra client registration --------------------------------------------

/// Register an OAuth2 client for tests. Mirrors the `hydra create client`
/// invocation in the `ory-up` skill but goes via the admin API directly so
/// we don't have to shell out to `podman exec`.
///
/// Returns `(client_id, client_secret, redirect_uri)`. The redirect URI is
/// the same `http://127.0.0.1:5555/callback` the playground uses (intentionally
/// unreachable — tests grab the `code` from the redirect Location header).
pub async fn hydra_create_test_client(scopes: &[&str]) -> (String, String, String) {
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

/// Delete a Hydra client. Best-effort.
pub async fn hydra_delete_client(client_id: &str) {
    let client = browser_client();
    let _ = client
        .delete(format!("{HYDRA_ADMIN}/admin/clients/{client_id}"))
        .send()
        .await;
}

// --- Status / sanity ------------------------------------------------------

// --- Admin happy-path test fixtures ---------------------------------------

/// Environment-gated admin fixture. The happy-path admin tests need an
/// authenticated, AAL2, allow-listed admin session — TOTP enrollment
/// isn't programmatically reliable through Kratos's flow API, so we rely
/// on the operator wiring up a real admin identity out-of-band and
/// exposing its credentials via these env vars.
///
/// Required:
///   * `FORSETI_ADMIN_TEST_EMAIL` — admin's session email (must be in the
///     portal's `[admin].allowed_emails` config)
///   * `FORSETI_ADMIN_TEST_PASSWORD` — admin's password
///   * Exactly one of:
///       * `FORSETI_ADMIN_TEST_TOTP_SECRET` — base32 TOTP secret. The
///         helper derives a fresh RFC 6238 code per call (SHA1 / 30s /
///         6 digits). Use this for the integration suite — Kratos
///         rejects code reuse, so a single `_CODE` only works for one
///         test in a multi-test run.
///       * `FORSETI_ADMIN_TEST_TOTP_CODE` — a single 6-digit code. Fine
///         for one-shot invocations; supported for backwards compat.
///
/// Returns `None` when *all three* env vars are unset/empty (legitimate
/// "skip the admin-gated tests" signal). When env vars are present but
/// any step fails, **panics** with the offending step + status — a
/// misconfigured admin credential is a loud test failure, not a silent
/// skip.
pub async fn try_admin_signed_in_client() -> Option<Client> {
    let creds = admin_test_credentials()?;
    let client = browser_client();
    password_login_aal1(&client, &creds.email, &creds.password).await;
    totp_step_up(&client, &creds.totp_code()).await;
    Some(client)
}

/// AAL1-only sibling of [`try_admin_signed_in_client`]: signs the seeded
/// admin in with password alone and stops there. The returned client's jar
/// carries an `ory_kratos_session` at AAL1 — exactly the "user has a second
/// factor but only authenticated with the first" state the AAL2-enforcement
/// tests need to provoke a step-up bounce. Env-gated identically; returns
/// `None` when the admin fixtures aren't wired up.
pub async fn try_admin_aal1_client() -> Option<Client> {
    let creds = admin_test_credentials()?;
    let client = browser_client();
    password_login_aal1(&client, &creds.email, &creds.password).await;
    Some(client)
}

/// Resolved admin test credentials from `FORSETI_ADMIN_TEST_*`. `None` is
/// the legitimate "skip the admin-gated tests" signal (all vars unset, or a
/// partial config with no usable TOTP source).
pub struct AdminTestCredentials {
    pub email: String,
    pub password: String,
    totp_secret: Option<String>,
    totp_code: Option<String>,
}

impl AdminTestCredentials {
    /// A fresh RFC 6238 code from the base32 secret, or the verbatim
    /// single-shot code when only `_CODE` is configured.
    pub fn totp_code(&self) -> String {
        match self.totp_secret.as_deref() {
            Some(secret_b32) => compute_totp_now(secret_b32),
            None => self
                .totp_code
                .clone()
                .expect("at least one TOTP source guaranteed by admin_test_credentials"),
        }
    }
}

/// Parse the `FORSETI_ADMIN_TEST_*` env vars into [`AdminTestCredentials`].
/// Returns `None` when nothing is configured or the config is too partial to
/// drive an AAL2 sign-in (mirrors the old guard in
/// `try_admin_signed_in_client`).
pub fn admin_test_credentials() -> Option<AdminTestCredentials> {
    let email = std::env::var("FORSETI_ADMIN_TEST_EMAIL")
        .ok()
        .filter(|s| !s.is_empty());
    let password = std::env::var("FORSETI_ADMIN_TEST_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());
    let totp_secret = std::env::var("FORSETI_ADMIN_TEST_TOTP_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    let totp_code = std::env::var("FORSETI_ADMIN_TEST_TOTP_CODE")
        .ok()
        .filter(|s| !s.is_empty());

    match (&email, &password, &totp_secret, &totp_code) {
        (Some(_), Some(_), Some(_), _) | (Some(_), Some(_), _, Some(_)) => {}
        _ => return None,
    }
    Some(AdminTestCredentials {
        email: email.expect("checked above"),
        password: password.expect("checked above"),
        totp_secret,
        totp_code,
    })
}

/// Drive a password-only (AAL1) Kratos login on `client`'s cookie jar.
/// After this returns the jar carries `ory_kratos_session` at AAL1. Used as
/// the first leg of every admin sign-in and by the AAL2-enforcement tests
/// that need an under-elevated session.
///
/// Kratos refuses to init an AAL2 step-up flow without a pre-existing AAL1
/// session (`Ory-Error-Id: session_aal1_required`), so AAL1 must come first.
pub async fn password_login_aal1(client: &Client, email: &str, password: &str) {
    let res = client
        .get(format!("{KRATOS_PUBLIC}/self-service/login/browser"))
        .header("Accept", "application/json")
        .send()
        .await
        .expect("init AAL1 login flow: transport");
    assert!(
        res.status().is_success(),
        "init AAL1 login flow: status {}",
        res.status()
    );
    let flow: Value = res.json().await.expect("init AAL1 login flow: parse json");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("AAL1 flow has ui.action")
        .to_string();
    let csrf = flow_csrf_token(&flow).expect("AAL1 flow has csrf_token");
    let res = client
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("identifier", email),
            ("password", password),
            ("method", "password"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("submit AAL1 password: transport");
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    // Kratos returns 200 (when AAL2 required) or 422 with a browser redirect
    // hint; either way the AAL1 session cookie is set on the jar.
    assert!(
        status.is_success() || status == StatusCode::UNPROCESSABLE_ENTITY,
        "submit AAL1 password: status {status} body {body}"
    );
}

/// Step `client`'s AAL1 session up to AAL2 by submitting `totp_code` against
/// a fresh Kratos `aal=aal2` login flow. Precondition: the jar already
/// carries an AAL1 `ory_kratos_session` (see [`password_login_aal1`]) and the
/// identity has TOTP enrolled.
pub async fn totp_step_up(client: &Client, totp_code: &str) {
    let res = client
        .get(format!(
            "{KRATOS_PUBLIC}/self-service/login/browser?aal=aal2"
        ))
        .header("Accept", "application/json")
        .send()
        .await
        .expect("init AAL2 step-up flow: transport");
    assert!(
        res.status().is_success(),
        "init AAL2 step-up flow: status {} — check that the identity has TOTP enrolled",
        res.status()
    );
    let flow: Value = res
        .json()
        .await
        .expect("init AAL2 step-up flow: parse json");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("AAL2 flow has ui.action")
        .to_string();
    let csrf = flow_csrf_token(&flow).expect("AAL2 flow has csrf_token");
    let res = client
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("totp_code", totp_code),
            ("method", "totp"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("submit TOTP: transport");
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "submit TOTP: status {status} body {} \
         — TOTP rejected; secret may be wrong or clock-skewed",
        body.chars().take(400).collect::<String>()
    );
}

/// Derive the current RFC 6238 TOTP code (SHA1, 30 s period, 6 digits)
/// from a base32-encoded shared secret. Panics on bad base32 — caller
/// already filters out the empty/missing case.
fn compute_totp_now(secret_b32: &str) -> String {
    let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret_b32))
        .unwrap_or_else(|| {
            panic!(
                "FORSETI_ADMIN_TEST_TOTP_SECRET is not valid base32 (length {})",
                secret_b32.len()
            )
        });
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs();
    totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret_bytes, seconds)
}

// --- DCR helpers ----------------------------------------------------------
//
// The portal owns the IAT + verification tables; the admin UI is the
// production knob for both, but the DCR integration tests reach into the
// sqlite file directly so a fresh suite run doesn't depend on an admin
// session being wired up. Postgres mode is panic-on-use (sqlite is the
// playground default — TODO: postgres path).

/// Resolve the portal's sqlite database path. The portal binds the file
/// next to the binary (`./forseti.db`) by default; the operator can override
/// via `FORSETI_DATABASE_URL` if their playground points somewhere else.
///
/// Panics with a clear message when the URL points at postgres — the DCR
/// tests speak sqlite only for now.
pub fn forseti_db_path() -> PathBuf {
    let raw = std::env::var("FORSETI_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./forseti.db".to_string());
    if raw.starts_with("postgres://") || raw.starts_with("postgresql://") {
        panic!(
            "DCR tests only support the sqlite playground; got `{raw}`. \
             Point FORSETI_DATABASE_URL at the sqlite file or unset it."
        );
    }
    let path = raw
        .strip_prefix("sqlite://")
        .or_else(|| raw.strip_prefix("sqlite:"))
        .unwrap_or(raw.as_str());
    PathBuf::from(path)
}

/// Open a direct sqlite connection to the portal DB. Used by the DCR
/// helpers below; tests don't open this themselves.
fn forseti_db_conn() -> rusqlite::Connection {
    let p = forseti_db_path();
    rusqlite::Connection::open(&p).unwrap_or_else(|e| panic!("open portal db at {p:?}: {e}"))
}

/// Seed a POSIX account + one SSH key for `identity_id` directly via the
/// portal DB. Mirrors what the resolver/provisioning path would write, so
/// the identity-delete cascade has something to purge. `uid`/`gid` must be
/// unique across the suite — callers derive them from a timestamp.
pub fn seed_posix_account(identity_id: &str, username: &str, uid: i64, gid: i64) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO posix_accounts (\
            identity_id, username, uid, gid, gecos, shell, home_dir, enabled, created_at, updated_at\
         ) VALUES (?1, ?2, ?3, ?4, '', '/bin/bash', ?5, 1, ?6, ?6)",
        params![
            identity_id,
            username,
            uid,
            gid,
            format!("/home/{username}"),
            now
        ],
    )
    .unwrap_or_else(|e| panic!("seed posix_accounts: {e}"));
    conn.execute(
        "INSERT INTO posix_groups (gid, name, org_id, kind, created_at) \
         VALUES (?1, ?2, NULL, 'user', ?3)",
        params![gid, username, now],
    )
    .unwrap_or_else(|e| panic!("seed posix_groups: {e}"));
    conn.execute(
        "INSERT INTO posix_group_members (gid, identity_id, added_at) VALUES (?1, ?2, ?3)",
        params![gid, identity_id, now],
    )
    .unwrap_or_else(|e| panic!("seed posix_group_members: {e}"));
    conn.execute(
        "INSERT INTO ssh_authorized_keys (id, identity_id, public_key, comment, created_at, expires_at) \
         VALUES (?1, ?2, 'ssh-ed25519 AAAATEST test@fixture', '', ?3, NULL)",
        params![uuid::Uuid::new_v4().to_string(), identity_id, now],
    )
    .unwrap_or_else(|e| panic!("seed ssh_authorized_keys: {e}"));
}

/// Seed a `host_enrollments` row for the resolver tests. `secret` is hashed
/// the same way the server compares it (SHA-256 hex). `allowed_gid = NULL`
/// (unscoped host). Returns nothing — the caller already knows `id`/`secret`.
pub fn seed_host_enrollment(id: &str, hostname: &str, secret: &str, allowed_gid: Option<i64>) {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    let secret_hash = hex::encode(h.finalize());
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO host_enrollments (\
            id, hostname, secret_hash, allowed_gid, force_mfa, created_by, created_at, last_seen_at\
         ) VALUES (?1, ?2, ?3, ?4, 0, 'test-fixture', ?5, NULL)",
        params![id, hostname, secret_hash, allowed_gid, now],
    )
    .unwrap_or_else(|e| panic!("seed host_enrollments: {e}"));
}

/// Delete a `host_enrollments` row (test cleanup).
pub fn delete_host_enrollment(id: &str) {
    let conn = forseti_db_conn();
    conn.execute("DELETE FROM host_enrollments WHERE id = ?1", params![id])
        .unwrap_or_else(|e| panic!("delete host_enrollments: {e}"));
}

/// Seed an org-kind `posix_groups` row (the scoped-host roster). `org_id`
/// is nullable so a dummy NULL keeps the fixture self-contained.
pub fn seed_org_group(gid: i64, name: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO posix_groups (gid, name, org_id, kind, created_at) \
         VALUES (?1, ?2, NULL, 'org', ?3)",
        params![gid, name, now],
    )
    .unwrap_or_else(|e| panic!("seed org posix_groups: {e}"));
}

/// Seed an `org`-kind `posix_groups` row with a real `org_id` (the
/// scoped-host roster as `sync_org_groups` writes it). Distinct from
/// [`seed_org_group`], which NULLs `org_id`; the org-removal cleanup helpers
/// key off `org_id`, so they need a non-NULL value to find the group.
pub fn seed_org_group_with_org_id(gid: i64, name: &str, org_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO posix_groups (gid, name, org_id, kind, created_at) \
         VALUES (?1, ?2, ?3, 'org', ?4)",
        params![gid, name, org_id, now],
    )
    .unwrap_or_else(|e| panic!("seed org posix_groups (org_id): {e}"));
}

/// Add a `posix_group_members` row tying `identity_id` to `gid`.
pub fn add_posix_group_member(gid: i64, identity_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO posix_group_members (gid, identity_id, added_at) VALUES (?1, ?2, ?3)",
        params![gid, identity_id, now],
    )
    .unwrap_or_else(|e| panic!("add posix_group_member: {e}"));
}

/// Delete the `posix_group_members` row tying `identity_id` to `gid` — the
/// net effect of `posix::db::remove_identity_from_org_group`.
pub fn delete_org_group_member(gid: i64, identity_id: &str) {
    let conn = forseti_db_conn();
    conn.execute(
        "DELETE FROM posix_group_members WHERE gid = ?1 AND identity_id = ?2",
        params![gid, identity_id],
    )
    .unwrap_or_else(|e| panic!("delete org posix_group_member: {e}"));
}

/// Delete a `posix_groups` row by gid (test cleanup).
pub fn delete_posix_group(gid: i64) {
    let conn = forseti_db_conn();
    conn.execute("DELETE FROM posix_groups WHERE gid = ?1", params![gid])
        .unwrap_or_else(|e| panic!("delete posix_groups: {e}"));
}

/// Delete all `posix_group_members` rows for a gid (test cleanup).
pub fn delete_posix_group_members(gid: i64) {
    let conn = forseti_db_conn();
    conn.execute(
        "DELETE FROM posix_group_members WHERE gid = ?1",
        params![gid],
    )
    .unwrap_or_else(|e| panic!("delete posix_group_members: {e}"));
}

/// Count the POSIX rows tied to `identity_id` across all four tables
/// (accounts + the user-kind primary group + memberships + ssh keys). Used
/// to assert the delete cascade purged everything. `gid` is the account's
/// primary gid — passed explicitly because posix_groups is keyed by gid and
/// the account row (the only identity_id link) is gone after a cascade delete.
pub fn count_posix_rows(identity_id: &str, gid: i64) -> i64 {
    let conn = forseti_db_conn();
    let accounts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM posix_accounts WHERE identity_id = ?1",
            params![identity_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("count posix_accounts: {e}"));
    let groups: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM posix_groups WHERE gid = ?1 AND kind = 'user'",
            params![gid],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("count posix_groups: {e}"));
    let members: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM posix_group_members WHERE identity_id = ?1",
            params![identity_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("count posix_group_members: {e}"));
    let keys: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ssh_authorized_keys WHERE identity_id = ?1",
            params![identity_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("count ssh_authorized_keys: {e}"));
    accounts + groups + members + keys
}

/// Total enabled `posix_accounts` rows. Mirrors `posix::db::count_accounts`
/// (enabled-only — a disabled account frees its seat) so the seat-cap test
/// can fill the free tier directly via the DB.
pub fn count_enabled_posix_accounts() -> i64 {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT COUNT(*) FROM posix_accounts WHERE enabled = 1",
        [],
        |r| r.get(0),
    )
    .unwrap_or_else(|e| panic!("count enabled posix_accounts: {e}"))
}

/// Seed a `host_enrollments` row with `force_mfa = 1`. Mirrors
/// [`seed_host_enrollment`] but flips the MFA flag so the device-auth
/// `force_mfa` binding path can be exercised.
pub fn seed_host_enrollment_mfa(id: &str, hostname: &str, secret: &str, allowed_gid: Option<i64>) {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    let secret_hash = hex::encode(h.finalize());
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO host_enrollments (\
            id, hostname, secret_hash, allowed_gid, force_mfa, created_by, created_at, last_seen_at\
         ) VALUES (?1, ?2, ?3, ?4, 1, 'test-fixture', ?5, NULL)",
        params![id, hostname, secret_hash, allowed_gid, now],
    )
    .unwrap_or_else(|e| panic!("seed host_enrollments (mfa): {e}"));
}

/// Read a `device_sessions.status` by `user_code`. `None` when no such row
/// (e.g. pruned on expiry). Used to assert the atomic single-use transitions.
pub fn device_session_status_by_user_code(user_code: &str) -> Option<String> {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT status FROM device_sessions WHERE user_code = ?1",
        params![user_code],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

/// Read a `device_sessions.device_code` (the PK) by `user_code`. The init
/// response never carries the device_code (it's the Hydra bearer secret); a
/// test driving the daemon's poll leg pulls it from the DB.
pub fn device_code_for_user_code(user_code: &str) -> Option<String> {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT device_code FROM device_sessions WHERE user_code = ?1",
        params![user_code],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

/// Flip `posix_accounts.enabled` for an identity (test fixture for the
/// disabled-account negative path).
pub fn set_posix_account_enabled(identity_id: &str, enabled: bool) {
    let conn = forseti_db_conn();
    conn.execute(
        "UPDATE posix_accounts SET enabled = ?1 WHERE identity_id = ?2",
        params![i32::from(enabled), identity_id],
    )
    .unwrap_or_else(|e| panic!("set posix_accounts.enabled: {e}"));
}

/// Seed an `offline_secrets` row for an identity (M3a offline-auth). The
/// `verifier` is opaque to these tests — they only assert presence/absence in
/// the projection, never re-verify it.
pub fn seed_offline_secret(identity_id: &str, verifier: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT OR REPLACE INTO offline_secrets \
            (identity_id, verifier, algo_version, created_at, updated_at) \
         VALUES (?1, ?2, 1, ?3, ?3)",
        params![identity_id, verifier, now],
    )
    .unwrap_or_else(|e| panic!("seed offline_secrets: {e}"));
}

/// Delete an `offline_secrets` row (test cleanup).
pub fn delete_offline_secret(identity_id: &str) {
    let conn = forseti_db_conn();
    conn.execute(
        "DELETE FROM offline_secrets WHERE identity_id = ?1",
        params![identity_id],
    )
    .unwrap_or_else(|e| panic!("delete offline_secrets: {e}"));
}

/// Count `audit_events` rows matching `action` whose metadata mentions `host_id`.
/// Used by the offline-audit ingest test to assert a batch landed as rows.
pub fn count_audit_events_for_host(action: &str, host_id: &str) -> i64 {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT COUNT(*) FROM audit_events WHERE action = ?1 AND metadata LIKE ?2",
        params![action, format!("%{host_id}%")],
        |r| r.get(0),
    )
    .unwrap_or_else(|e| panic!("count audit_events: {e}"))
}

/// Delete every `device_sessions` row for a host (test cleanup).
pub fn delete_device_sessions_for_host(host_id: &str) {
    let conn = forseti_db_conn();
    conn.execute(
        "DELETE FROM device_sessions WHERE host_id = ?1",
        params![host_id],
    )
    .unwrap_or_else(|e| panic!("delete device_sessions: {e}"));
}

/// Insert a bare `posix_accounts` row (no group / membership / key) for
/// `identity_id`. Used by the seat-cap test to consume seats cheaply
/// without registering a Kratos identity per seat. `uid`/`gid` must be
/// unique across the suite.
pub fn seed_bare_posix_account(identity_id: &str, username: &str, uid: i64, gid: i64) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO posix_accounts (\
            identity_id, username, uid, gid, gecos, shell, home_dir, enabled, created_at, updated_at\
         ) VALUES (?1, ?2, ?3, ?4, '', '/bin/sh', ?5, 1, ?6, ?6)",
        params![identity_id, username, uid, gid, format!("/home/{username}"), now],
    )
    .unwrap_or_else(|e| panic!("seed bare posix_accounts: {e}"));
}

/// Delete every POSIX row tied to `identity_id` plus its primary group
/// (test cleanup for the seat-cap fixtures).
pub fn delete_posix_account(identity_id: &str) {
    let conn = forseti_db_conn();
    conn.execute(
        "DELETE FROM posix_groups WHERE gid IN \
         (SELECT gid FROM posix_accounts WHERE identity_id = ?1) AND kind = 'user'",
        params![identity_id],
    )
    .unwrap_or_else(|e| panic!("delete posix_groups for account: {e}"));
    conn.execute(
        "DELETE FROM ssh_authorized_keys WHERE identity_id = ?1",
        params![identity_id],
    )
    .unwrap_or_else(|e| panic!("delete ssh_authorized_keys for account: {e}"));
    conn.execute(
        "DELETE FROM posix_group_members WHERE identity_id = ?1",
        params![identity_id],
    )
    .unwrap_or_else(|e| panic!("delete posix_group_members for account: {e}"));
    conn.execute(
        "DELETE FROM posix_accounts WHERE identity_id = ?1",
        params![identity_id],
    )
    .unwrap_or_else(|e| panic!("delete posix_accounts: {e}"));
}

/// Count the `org`-kind `posix_group_members` rows for `identity_id` (joined
/// to `posix_groups.kind = 'org'`). Powers the Orgs-gate assertion: zero org
/// memberships when Orgs is unlicensed, ≥1 once licensed.
pub fn count_org_group_memberships(identity_id: &str) -> i64 {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT COUNT(*) FROM posix_group_members m \
         JOIN posix_groups g ON g.gid = m.gid \
         WHERE m.identity_id = ?1 AND g.kind = 'org'",
        params![identity_id],
        |r| r.get(0),
    )
    .unwrap_or_else(|e| panic!("count org group memberships: {e}"))
}

/// Mint a fresh DCR Initial Access Token directly via the portal DB,
/// bypassing the admin UI. Returns the raw bearer string the caller sends
/// in `Authorization: Bearer ...`.
///
/// * `uses_remaining` — `None` means unlimited, an integer is decremented
///   per accepted registration.
/// * `daily_limit` — present here as a no-op placeholder for the per-IAT
///   rolling 24h cap. The actual threshold is read from the portal's
///   config (`oauth.dcr_iat_daily_limit`), not the row; pass it through
///   so the call site stays readable even when the column isn't writable.
pub fn mint_dcr_iat(uses_remaining: Option<i32>, _daily_limit: Option<i32>) -> String {
    // 32 random bytes, base64url-no-pad. Mirrors the format the admin UI
    // uses so the proxy's `sha256(raw_bytes_as_string)` path lines up.
    let mut buf = [0u8; 32];
    use rand::Rng;
    rand::rng().fill(&mut buf);
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);

    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    let token_hash = hex::encode(h.finalize());

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "INSERT INTO dcr_initial_access_tokens (\
            id, token_hash, created_by, created_at, expires_at, \
            uses_remaining, revoked_at, note, daily_use_count, daily_window_started_at\
         ) VALUES (?1, ?2, 'test-fixture', ?3, NULL, ?4, NULL, 'integration test', 0, NULL)",
        params![id, token_hash, now, uses_remaining],
    )
    .unwrap_or_else(|e| panic!("insert IAT: {e}"));
    raw
}

/// Revoke an IAT by its raw bearer string. Used by the
/// `dcr_register_with_revoked_iat_returns_401` test.
pub fn revoke_dcr_iat(raw_token: &str) {
    let mut h = Sha256::new();
    h.update(raw_token.as_bytes());
    let token_hash = hex::encode(h.finalize());
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    conn.execute(
        "UPDATE dcr_initial_access_tokens SET revoked_at = ?1 WHERE token_hash = ?2",
        params![now, token_hash],
    )
    .unwrap_or_else(|e| panic!("revoke IAT: {e}"));
}

/// UPSERT `oauth_client_metadata` so the row records `verification =
/// 'verified'`, `source = 'admin'`, `verified_by = 'test-fixture'`. Works
/// whether or not a DCR row already exists.
pub fn mark_client_verified(client_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    // Try UPDATE first; if no row matched, INSERT a fresh one.
    let updated = conn
        .execute(
            "UPDATE oauth_client_metadata SET \
                verification = 'verified', \
                verified_by = 'test-fixture', \
                verified_at = ?1, \
                source = COALESCE(source, 'admin'), \
                verification_revoked_by = NULL, \
                verification_revoked_at = NULL \
             WHERE client_id = ?2",
            params![now, client_id],
        )
        .unwrap_or_else(|e| panic!("update oauth_client_metadata: {e}"));
    if updated == 0 {
        conn.execute(
            "INSERT INTO oauth_client_metadata (\
                client_id, verification, verified_by, verified_at, source, created_at\
             ) VALUES (?1, 'verified', 'test-fixture', ?2, 'admin', ?2)",
            params![client_id, now],
        )
        .unwrap_or_else(|e| panic!("insert oauth_client_metadata: {e}"));
    }
}

/// UPSERT `oauth_client_metadata` so the row records `verification =
/// 'unverified'`. Symmetric to [`mark_client_verified`].
pub fn mark_client_unverified(client_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = forseti_db_conn();
    let updated = conn
        .execute(
            "UPDATE oauth_client_metadata SET \
                verification = 'unverified', \
                verification_revoked_by = 'test-fixture', \
                verification_revoked_at = ?1 \
             WHERE client_id = ?2",
            params![now, client_id],
        )
        .unwrap_or_else(|e| panic!("update oauth_client_metadata: {e}"));
    if updated == 0 {
        conn.execute(
            "INSERT INTO oauth_client_metadata (\
                client_id, verification, source, verification_revoked_by, \
                verification_revoked_at, created_at\
             ) VALUES (?1, 'unverified', 'admin', 'test-fixture', ?2, ?2)",
            params![client_id, now],
        )
        .unwrap_or_else(|e| panic!("insert oauth_client_metadata: {e}"));
    }
}

/// Read a single column out of `oauth_client_metadata` for the given
/// `client_id`. Returns `None` when no row exists.
pub fn read_client_verification(client_id: &str) -> Option<String> {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT verification FROM oauth_client_metadata WHERE client_id = ?1",
        params![client_id],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

/// Read the `oauth_client_metadata` provenance columns
/// (`audience`, `resource_url`). Returns `None` when no row exists.
pub fn read_client_provenance(client_id: &str) -> Option<(Option<String>, Option<String>)> {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT audience, resource_url FROM oauth_client_metadata WHERE client_id = ?1",
        params![client_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        },
    )
    .ok()
}

/// Read the full `oauth_client_metadata` row for the given `client_id` —
/// (`verification`, `source`, `dcr_iat_id`). Returns `None` when no row
/// exists.
pub fn read_client_metadata_row(client_id: &str) -> Option<(String, String, Option<String>)> {
    let conn = forseti_db_conn();
    conn.query_row(
        "SELECT verification, source, dcr_iat_id FROM oauth_client_metadata WHERE client_id = ?1",
        params![client_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )
    .ok()
}

/// POST `/oauth2/register` with the given IAT and a minimal body. Returns
/// the parsed status + JSON response. On non-2xx the caller still gets the
/// body so it can assert on `error` / `error_description`.
pub async fn dcr_register(
    iat: &str,
    client_name: &str,
    scope: &str,
    redirect_uris: &[&str],
    audience: Option<&[&str]>,
) -> (StatusCode, reqwest::header::HeaderMap, Value) {
    let client = browser_client();
    let body = dcr_register_body(client_name, scope, redirect_uris, audience);
    let res = client
        .post(format!("{PORTAL}/oauth2/register"))
        .bearer_auth(iat)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("dcr register transport");
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.bytes().await.unwrap_or_default();
    let json = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, headers, json)
}

/// POST `/oauth2/register` **without** an `Authorization` header — the
/// anonymous DCR path. Used by tests that exercise the default behaviour
/// (any MCP client can self-register; the resulting client lands as
/// `unverified` and the consent screen renders the caution banner until
/// an operator promotes it).
pub async fn dcr_register_anonymous(
    client_name: &str,
    scope: &str,
    redirect_uris: &[&str],
    audience: Option<&[&str]>,
) -> (StatusCode, reqwest::header::HeaderMap, Value) {
    let client = browser_client();
    let body = dcr_register_body(client_name, scope, redirect_uris, audience);
    let res = client
        .post(format!("{PORTAL}/oauth2/register"))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("dcr register transport");
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.bytes().await.unwrap_or_default();
    let json = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, headers, json)
}

/// POST `/oauth2/register` with a caller-supplied `Authorization` header
/// value verbatim — used by negative tests that need to exercise
/// malformed-header rejection (wrong scheme, missing token, etc).
pub async fn dcr_register_with_authorization(
    authorization: &str,
    client_name: &str,
    scope: &str,
    redirect_uris: &[&str],
    audience: Option<&[&str]>,
) -> (StatusCode, reqwest::header::HeaderMap, Value) {
    let client = browser_client();
    let body = dcr_register_body(client_name, scope, redirect_uris, audience);
    let res = client
        .post(format!("{PORTAL}/oauth2/register"))
        .header("authorization", authorization)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("dcr register transport");
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.bytes().await.unwrap_or_default();
    let json = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, headers, json)
}

fn dcr_register_body(
    client_name: &str,
    scope: &str,
    redirect_uris: &[&str],
    audience: Option<&[&str]>,
) -> Value {
    let mut body = serde_json::json!({
        "client_name": client_name,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": scope,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
    });
    if let Some(aud) = audience {
        body["audience"] = serde_json::json!(aud);
    }
    body
}

/// A fake MCP resource server. Spawned for the golden-path test to assert
/// that an access token introspects successfully against Hydra and carries
/// the expected audience.
pub struct FakeMcpServer {
    pub addr: SocketAddr,
    pub expected_audience: String,
    handle: tokio::task::JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FakeMcpServer {
    /// `GET /tool` URL the test client hits with `Authorization: Bearer ...`.
    pub fn tool_url(&self) -> String {
        format!("http://{}/tool", self.addr)
    }

    /// Stop the server. Best-effort — the listener falls over at drop time
    /// either way, but cleaning up the task lets `cargo test` exit promptly.
    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// Spawn a tiny axum server with one route, `GET /tool`. It introspects
/// the bearer token against Hydra admin and returns 200 only when both
/// `active` is true and `aud` contains `expected_audience`.
///
/// Binds to `127.0.0.1:0` so concurrent test runs don't fight over a port.
pub async fn spawn_fake_mcp_server(expected_audience: &str) -> FakeMcpServer {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode as AxStatus};
    use axum::routing::get;
    use axum::Router;

    #[derive(Clone)]
    struct St {
        expected_audience: String,
    }

    async fn tool(
        State(st): State<St>,
        headers: HeaderMap,
    ) -> (AxStatus, [(axum::http::HeaderName, String); 1], String) {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.strip_prefix("bearer "))
            })
            .unwrap_or("")
            .trim()
            .to_string();
        let deny = (
            AxStatus::UNAUTHORIZED,
            [(
                axum::http::HeaderName::from_static("www-authenticate"),
                r#"Bearer error="invalid_token""#.to_string(),
            )],
            r#"{"error":"invalid_token"}"#.to_string(),
        );
        if bearer.is_empty() {
            return deny;
        }
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{HYDRA_ADMIN}/admin/oauth2/introspect"))
            .form(&[("token", bearer.as_str())])
            .send()
            .await;
        let body: serde_json::Value = match resp {
            Ok(r) if r.status().is_success() => r.json().await.unwrap_or(serde_json::Value::Null),
            _ => return deny,
        };
        let active = body["active"].as_bool().unwrap_or(false);
        let aud_match = body["aud"]
            .as_array()
            .map(|a| {
                a.iter()
                    .any(|v| v.as_str() == Some(st.expected_audience.as_str()))
            })
            .unwrap_or(false);
        if active && aud_match {
            (
                AxStatus::OK,
                [(
                    axum::http::HeaderName::from_static("content-type"),
                    "application/json".to_string(),
                )],
                r#"{"ok":true}"#.to_string(),
            )
        } else {
            deny
        }
    }

    let app: Router = Router::new().route("/tool", get(tool)).with_state(St {
        expected_audience: expected_audience.to_string(),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake mcp listener");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
    });
    FakeMcpServer {
        addr,
        expected_audience: expected_audience.to_string(),
        handle,
        shutdown: tx,
    }
}

/// Skip the test if the portal isn't reachable. Returns `true` when the
/// suite should proceed; prints a helpful message and returns `false`
/// otherwise.
///
/// We don't auto-skip via `#[ignore]` because the user wants tests that don't
/// run when the stack is down to FAIL loudly. This helper is for the smoke
/// preamble — call it from the *first* test only and let cascading failures
/// surface the rest.
pub async fn portal_reachable() -> bool {
    let client = browser_client();
    client
        .get(format!("{PORTAL}/healthz"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}
