//! The native-backend side of the helpers in `common.rs`: the same functions, driving Forseti's
//! own rendered forms instead of Kratos's APIs and seeding through the Forseti database.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{
    PORTAL, RegisteredUser, admin_test_credentials, browser_client, forseti_db_path,
    paired_clients, skip_username_step, unique_email,
};
use crate::native_seed;

const PASSWORD: &str = "Sup3rSecret-Test-Password!";
const SESSION_COOKIE: &str = "forseti_session";

fn db() -> rusqlite::Connection {
    native_seed::open(&forseti_db_path())
}

// --- HTML forms ------------------------------------------------------------

/// One `<form>` of a page: its absolute action and every named input and button in it.
#[derive(Debug, Clone)]
pub struct HtmlForm {
    pub action: String,
    /// `(name, value, type)`.
    pub inputs: Vec<(String, String, String)>,
}

impl HtmlForm {
    fn has(&self, name: &str) -> bool {
        self.inputs.iter().any(|(n, _, _)| n == name)
    }

    /// The form's own values, buttons left out, with `fields` set over them.
    fn fields(&self, fields: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .inputs
            .iter()
            .filter(|(_, _, kind)| kind != "submit" && kind != "button" && kind != "checkbox")
            .filter(|(n, _, _)| !fields.iter().any(|(f, _)| f == n))
            .map(|(n, v, _)| (n.clone(), v.clone()))
            .collect();
        out.extend(fields.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        out
    }
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#x2F;", "/")
        .replace("&amp;", "&")
}

fn attrs(tag: &str) -> HashMap<String, String> {
    let re = regex::Regex::new(r#"([A-Za-z_:][-A-Za-z0-9_:.]*)="([^"]*)""#).expect("attr regex");
    re.captures_iter(tag)
        .map(|c| (c[1].to_ascii_lowercase(), unescape(&c[2])))
        .collect()
}

/// Every form on `html`, actions resolved against `page`.
pub fn html_forms(html: &str, page: &reqwest::Url) -> Vec<HtmlForm> {
    let form_re = regex::Regex::new(r"(?s)<form\b([^>]*)>(.*?)</form>").expect("form regex");
    let input_re = regex::Regex::new(r"(?s)<(input|button)\b([^>]*)>").expect("input regex");
    form_re
        .captures_iter(html)
        .map(|f| {
            let form_attrs = attrs(&f[1]);
            let action = form_attrs.get("action").cloned().unwrap_or_default();
            let action = page.join(&action).map(|u| u.to_string()).unwrap_or(action);
            let inputs = input_re
                .captures_iter(&f[2])
                .filter_map(|i| {
                    let a = attrs(&i[2]);
                    let name = a.get("name")?.clone();
                    let default_kind = if &i[1] == "button" { "submit" } else { "text" };
                    let kind = a
                        .get("type")
                        .cloned()
                        .unwrap_or_else(|| default_kind.to_string());
                    Some((name, a.get("value").cloned().unwrap_or_default(), kind))
                })
                .collect();
            HtmlForm { action, inputs }
        })
        .collect()
}

/// GET `url` and follow redirects by hand, whatever the client's policy; the last response's
/// URL and body.
async fn get_page(client: &Client, url: &str) -> (reqwest::Url, String) {
    let mut url: reqwest::Url = url.parse().expect("page URL");
    for _ in 0..20 {
        let res = client
            .get(url.clone())
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url}: {e}"));
        if res.status().is_redirection() {
            let to = res
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok())
                .expect("redirect Location");
            url = url.join(to).expect("redirect target");
            continue;
        }
        let at = res.url().clone();
        return (at, res.text().await.unwrap_or_default());
    }
    panic!("redirect loop from {url}");
}

/// The form on `url` that has an input named `field`.
async fn page_form(client: &Client, url: &str, field: &str) -> (reqwest::Url, HtmlForm) {
    let (at, html) = get_page(client, url).await;
    let form = html_forms(&html, &at)
        .into_iter()
        .find(|f| f.has(field))
        .unwrap_or_else(|| {
            panic!(
                "no form with `{field}` on {at}: {}",
                html.chars().take(1500).collect::<String>()
            )
        });
    (at, form)
}

/// POST `fields` (over the form's own values) to the form's action; follows redirects by hand
/// and returns the final URL and body.
async fn submit(
    client: &Client,
    form: &HtmlForm,
    fields: &[(&str, &str)],
) -> (reqwest::Url, String) {
    let res = client
        .post(&form.action)
        .form(&form.fields(fields))
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {}: {e}", form.action));
    if res.status().is_redirection() {
        let to = res
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .expect("redirect Location")
            .to_string();
        let next = res.url().join(&to).expect("redirect target");
        return get_page(client, next.as_str()).await;
    }
    let status = res.status();
    let at = res.url().clone();
    let body = res.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "POST {}: status {status}: {}",
        form.action,
        body.chars().take(800).collect::<String>()
    );
    (at, body)
}

/// The flow-level and field messages a rendered flow page shows, for failure output.
fn page_errors(html: &str) -> String {
    let re = regex::Regex::new(r#"(?s)<p class="[^"]*text-error[^"]*">(.*?)</p>"#).expect("re");
    re.captures_iter(html)
        .map(|c| c[1].trim().to_string())
        .collect::<Vec<_>>()
        .join(" | ")
}

// --- Cookies -----------------------------------------------------------------

/// The value of cookie `name` that `client` sends to `localhost`: the client calls a one-shot
/// listener on a loopback port, and cookies are not port-scoped.
pub async fn client_cookie(client: &Client, name: &str) -> Option<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind cookie probe");
    let port = listener.local_addr().expect("probe addr").port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let _ = sock
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        Some(String::from_utf8_lossy(&buf).into_owned())
    });
    let _ = client
        .get(format!("http://localhost:{port}/"))
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    let request = server.await.ok().flatten()?;
    request
        .lines()
        .filter_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        })
        .flat_map(|(_, v)| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// The session row behind `client`'s session cookie.
async fn client_session(client: &Client) -> Option<native_seed::SessionRow> {
    let token = client_cookie(client, SESSION_COOKIE).await?;
    native_seed::session_by_token(&db(), &token)
}

/// A pair of clients sharing one jar that carries `token` as the session cookie.
fn clients_with_session(token: &str) -> (Client, Client) {
    let (auto, manual, jar) = paired_clients();
    for origin in [PORTAL, "http://host.containers.internal:3000"] {
        let url: reqwest::Url = origin.parse().expect("portal origin");
        jar.add_cookie_str(&format!("{SESSION_COOKIE}={token}; Path=/"), &url);
    }
    (auto, manual)
}

// --- Identities ------------------------------------------------------------

pub async fn identity_id_by_email(email: &str) -> Option<String> {
    native_seed::identity_id_by_email(&db(), email)
}

pub async fn delete_test_identity(id: &str) -> Result<(), String> {
    if !id.is_empty() {
        native_seed::delete_identity(&db(), id);
    }
    Ok(())
}

pub async fn kratos_admin_create_identity(email: &str) -> String {
    native_seed::create_identity(&db(), email, Some("Admin"), Some("Test"), false)
}

pub async fn kratos_admin_create_verified_password_identity(email: &str, password: &str) -> String {
    let conn = db();
    let id = native_seed::create_identity(&conn, email, Some("Verified"), Some("User"), true);
    native_seed::set_password(&conn, &id, password);
    id
}

pub async fn kratos_admin_create_password_identity(email: &str, password: &str) -> String {
    let conn = db();
    let id = native_seed::create_identity(&conn, email, Some("NoMfa"), Some("User"), false);
    native_seed::set_password(&conn, &id, password);
    id
}

pub fn backdate_second_factor(identity_id: &str, secs: i64) -> u64 {
    native_seed::backdate_second_factor(&db(), identity_id, secs)
}

pub async fn mark_identity_verified(identity_id: &str) {
    native_seed::mark_verified(&db(), identity_id);
}

pub fn plant_totp(identity_id: &str, secret_b32: &str) {
    native_seed::plant_totp(
        &db(),
        &native_seed::cookie_secret(),
        identity_id,
        secret_b32,
    );
}

pub async fn kratos_set_metadata_admin(identity_id: &str, metadata: Value) {
    native_seed::set_metadata_admin(&db(), identity_id, &metadata);
}

pub async fn identity_metadata_admin(identity_id: &str) -> Value {
    let stored: Option<String> = db()
        .query_row(
            "SELECT metadata_admin FROM identities WHERE id = ?1",
            [identity_id],
            |r| r.get(0),
        )
        .expect("identity row");
    stored.map_or(Value::Null, |s| {
        serde_json::from_str(&s).expect("metadata_admin is JSON")
    })
}

pub async fn kratos_identity_session_ids(identity_id: &str) -> Vec<String> {
    native_seed::live_session_ids(&db(), identity_id)
}

pub async fn kratos_admin_end_sessions(identity_id: &str) {
    native_seed::end_sessions(&db(), identity_id);
}

/// Whether `client`'s session would pass whoami: live, and at AAL2 when the identity has TOTP.
pub async fn whoami_is_active(client: &Client) -> bool {
    client_session(client)
        .await
        .is_some_and(|s| s.live && (s.aal == "aal2" || !s.totp))
}

pub async fn whoami_identity(client: &Client) -> Option<(String, String)> {
    let session = client_session(client)
        .await
        .filter(|s| s.live && (s.aal == "aal2" || !s.totp))?;
    let email = db()
        .query_row(
            "SELECT email FROM identities WHERE id = ?1",
            [&session.identity_id],
            |r| r.get(0),
        )
        .ok()?;
    Some((session.identity_id, email))
}

pub async fn whoami_session_id(client: &Client) -> Option<String> {
    client_session(client)
        .await
        .filter(|s| s.live && (s.aal == "aal2" || !s.totp))
        .map(|s| s.id)
}

// --- Registration ----------------------------------------------------------

/// The two-step registration through Forseti's pages; returns the page it lands on.
async fn register_through_pages(client: &Client, email: &str) -> reqwest::Url {
    let (_, form) = page_form(client, &format!("{PORTAL}/registration"), "traits.email").await;
    let (at, html) = submit(
        client,
        &form,
        &[
            ("traits.email", email),
            ("traits.name.first", "Test"),
            ("traits.name.last", "User"),
            ("method", "profile"),
        ],
    )
    .await;
    let form = html_forms(&html, &at)
        .into_iter()
        .find(|f| f.has("password"))
        .unwrap_or_else(|| {
            panic!(
                "registration did not reach the password step at {at}: {}",
                page_errors(&html)
            )
        });
    let (at, html) = submit(
        client,
        &form,
        &[("password", PASSWORD), ("method", "password")],
    )
    .await;
    assert!(
        identity_id_by_email(email).await.is_some(),
        "registration of {email} created no identity; landed on {at}: {}",
        page_errors(&html)
    );
    at
}

pub async fn register_test_user_with_client(
    client: &Client,
    prefix: &str,
) -> (String, String, String) {
    let email = unique_email(prefix);
    register_through_pages(client, &email).await;
    let id = identity_id_by_email(&email)
        .await
        .expect("registered identity");
    (id, email, PASSWORD.to_string())
}

pub async fn register_inner(email: &str, skip_username: bool, verified: bool) -> RegisteredUser {
    let (client, manual_client, jar) = paired_clients();
    register_through_pages(&client, email).await;
    let identity_id = identity_id_by_email(email)
        .await
        .expect("registered identity");
    if skip_username {
        skip_username_step(&jar, &identity_id);
    }
    if verified {
        mark_identity_verified(&identity_id).await;
    }
    RegisteredUser {
        client,
        manual_client,
        identity_id,
        email: email.to_string(),
        password: PASSWORD.to_string(),
    }
}

// --- Flows -----------------------------------------------------------------

/// A Kratos-shaped view of the flow page `/{kind}?flow=<id>`: `id`, `ui.action` (the form posting
/// to `/self-service/{kind}`) and `ui.nodes` with every input of that form.
pub async fn fetch_flow(client: &Client, kind: &str, flow_id: &str) -> Value {
    let (at, html) = get_page(client, &format!("{PORTAL}/{kind}?flow={flow_id}")).await;
    let forms: Vec<HtmlForm> = html_forms(&html, &at)
        .into_iter()
        .filter(|f| f.action.contains(&format!("/self-service/{kind}")))
        .collect();
    assert!(
        !forms.is_empty(),
        "no /self-service/{kind} form on {at}: {}",
        html.chars().take(1500).collect::<String>()
    );
    let nodes: Vec<Value> = forms
        .iter()
        .flat_map(|f| f.inputs.iter())
        .map(|(name, value, kind)| {
            serde_json::json!({
                "type": "input",
                "attributes": { "name": name, "value": value, "type": kind },
            })
        })
        .collect();
    serde_json::json!({
        "id": flow_id,
        "ui": { "action": forms[0].action, "method": "POST", "nodes": nodes },
    })
}

pub async fn browser_flow_id(client: &Client, kind: &str, query: &str) -> String {
    let (at, _) = get_page(
        client,
        &format!("{PORTAL}/self-service/{kind}/browser{query}"),
    )
    .await;
    crate::common::extract_flow_id_from_url(at.as_str())
        .unwrap_or_else(|| panic!("{kind} init landed on {at}, not a flow page"))
}

pub async fn first_identity_id() -> Option<String> {
    db().query_row("SELECT id FROM identities LIMIT 1", [], |r| r.get(0))
        .ok()
}

pub async fn identity_exists(id: &str) -> bool {
    db().query_row("SELECT 1 FROM identities WHERE id = ?1", [id], |_| Ok(()))
        .is_ok()
}

pub async fn identity_state(identity_id: &str) -> Option<String> {
    db().query_row(
        "SELECT state FROM identities WHERE id = ?1",
        [identity_id],
        |r| r.get(0),
    )
    .ok()
}

pub async fn address_verified(id: &str, email: &str) -> bool {
    db().query_row(
        "SELECT 1 FROM identities WHERE id = ?1 AND email_norm = ?2 \
         AND email_verified_at IS NOT NULL",
        [id, &email.to_lowercase()],
        |_| Ok(()),
    )
    .is_ok()
}

// --- Sign-in ---------------------------------------------------------------

/// A password sign-in through Forseti's login page; leaves an AAL1 session on `client`.
pub async fn password_login_aal1(client: &Client, email: &str, password: &str) {
    let (_, form) = page_form(
        client,
        &format!("{PORTAL}/self-service/login/browser"),
        "identifier",
    )
    .await;
    let (at, html) = submit(
        client,
        &form,
        &[
            ("identifier", email),
            ("password", password),
            ("method", "password"),
        ],
    )
    .await;
    let session = client_session(client).await;
    assert!(
        session.as_ref().is_some_and(|s| s.live),
        "password sign-in of {email} left no session; landed on {at}: {}",
        page_errors(&html)
    );
}

/// Raise `client`'s session to AAL2 with `totp_code` through the second-factor login page.
pub async fn totp_step_up(client: &Client, totp_code: &str) {
    assert!(
        try_totp_step_up(client, totp_code).await,
        "TOTP step-up refused; secret may be wrong, clock-skewed or the code already used"
    );
}

async fn try_totp_step_up(client: &Client, totp_code: &str) -> bool {
    let (_, form) = page_form(
        client,
        &format!("{PORTAL}/self-service/login/browser?aal=aal2"),
        "totp_code",
    )
    .await;
    submit(
        client,
        &form,
        &[("totp_code", totp_code), ("method", "totp")],
    )
    .await;
    client_session(client)
        .await
        .is_some_and(|s| s.live && s.aal == "aal2")
}

/// Change the signed-in user's password through `/settings/password`.
pub async fn kratos_change_password(client: &Client, new_password: &str) {
    let (_, form) = page_form(client, &format!("{PORTAL}/settings/password"), "password").await;
    let (at, html) = submit(
        client,
        &form,
        &[("password", new_password), ("method", "password")],
    )
    .await;
    let errors = page_errors(&html);
    assert!(
        errors.is_empty(),
        "password change refused at {at}: {errors}"
    );
}

// --- Admin -----------------------------------------------------------------

/// The admin's AAL2 session token, shared by every admin client of this process: the admin has
/// one TOTP secret and the native backend accepts each code once (RFC 6238 section 5.2).
static ADMIN_TOKEN: Mutex<Option<String>> = Mutex::new(None);

async fn admin_token() -> Option<String> {
    let creds = admin_test_credentials()?;
    let cached = ADMIN_TOKEN.lock().unwrap().clone();
    if let Some(token) = cached
        && native_seed::session_by_token(&db(), &token).is_some_and(|s| s.live && s.aal == "aal2")
    {
        return Some(token);
    }
    let client = browser_client();
    password_login_aal1(&client, &creds.email, &creds.password).await;
    // A code an earlier run of the suite used in this step is refused; the next step's is not.
    if !try_totp_step_up(&client, &creds.totp_code()).await {
        assert!(
            try_totp_step_up(&client, &creds.totp_code()).await,
            "admin TOTP step-up refused twice"
        );
    }
    let token = client_cookie(&client, SESSION_COOKIE)
        .await
        .expect("admin session cookie");
    *ADMIN_TOKEN.lock().unwrap() = Some(token.clone());
    Some(token)
}

pub async fn try_admin_signed_in_client() -> Option<Client> {
    let token = admin_token().await?;
    Some(clients_with_session(&token).0)
}

pub async fn try_admin_paired_clients() -> Option<(Client, Client)> {
    let token = admin_token().await?;
    Some(clients_with_session(&token))
}

// --- TOTP ------------------------------------------------------------------

/// Steps each secret has had a code computed for in this process.
static USED_STEPS: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

/// The current TOTP step for `secret_b32`, waiting for the next one when this process already
/// computed a code in the current step: the server accepts each step once per credential.
pub fn fresh_totp_step(secret_b32: &str) -> u64 {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch");
        let step = now.as_secs() / 30;
        {
            let mut used = USED_STEPS.lock().unwrap();
            let used = used.get_or_insert_with(HashMap::new);
            if used.get(secret_b32).is_none_or(|last| *last < step) {
                used.insert(secret_b32.to_string(), step);
                return step;
            }
        }
        let next = Duration::from_secs((step + 1) * 30);
        std::thread::sleep(next.saturating_sub(now) + Duration::from_millis(50));
    }
}
