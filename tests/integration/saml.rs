//! SAML SSO integration tests. The keystone test proves the
//! recovery-link session-establishment mechanism the whole SSO
//! callback depends on; the rest cover Forseti-side orchestration.

use crate::common;
use rusqlite::params;
use serde_json::Value;

/// Mint a magic recovery link via the Kratos admin API, optionally with a
/// `return_to` query param. Returns the public redemption URL.
async fn mint_recovery_link(identity_id: &str, return_to: Option<&str>) -> String {
    let api = common::browser_client();
    let mut url = format!("{}/admin/recovery/link", common::KRATOS_ADMIN);
    if let Some(rt) = return_to {
        url = format!("{url}?return_to={rt}");
    }
    let resp = api
        .post(&url)
        // Same TTL the SSO callback mints with, so this keeps proving the
        // mechanism the callback actually uses.
        .json(&serde_json::json!({
            "identity_id": identity_id,
            "expires_in": "1m"
        }))
        .send()
        .await
        .expect("mint recovery link");
    let status = resp.status();
    let body: Value = resp.json().await.expect("mint response json");
    assert!(status.is_success(), "mint failed: {status} body {body}");
    body["recovery_link"]
        .as_str()
        .expect("recovery_link in mint response")
        .to_string()
}

/// Admin-minted recovery link, redeemed by a cookie-jar client, must end
/// with a usable Kratos browser session (whoami 200).
#[tokio::test]
async fn recovery_link_redemption_yields_browser_session() {
    skip_on_native!(
        "redeems a Kratos admin recovery link; the native build issues the SSO session directly"
    );
    let user = common::register_test_user("samlkeystone").await;

    // Mint the link server-side (what the SSO callback will do).
    let link = mint_recovery_link(&user.identity_id, None).await;

    // Fresh "browser": empty cookie jar, follows redirects.
    let (browser, _manual, _jar) = common::paired_clients();
    let final_resp = browser.get(&link).send().await.expect("redeem link");
    assert!(
        final_resp.status().is_success(),
        "redemption landed on {} with status {}",
        final_resp.url(),
        final_resp.status()
    );

    // The jar must now hold a session Kratos accepts.
    let whoami = browser
        .get(format!("{}/sessions/whoami", common::KRATOS_PUBLIC))
        .send()
        .await
        .expect("whoami");
    assert_eq!(whoami.status(), 200, "no session after link redemption");
    let session: Value = whoami.json().await.expect("whoami json");
    assert_eq!(
        session["identity"]["id"].as_str(),
        Some(user.identity_id.as_str()),
        "session belongs to a different identity"
    );

    // Document where the browser lands (drives a later task's interception).
    eprintln!(
        "post-redemption landing (no return_to): {}",
        final_resp.url()
    );

    user.cleanup().await;
}

/// Same mechanism, but the admin mint carries `return_to`. Documents
/// whether Kratos honours it after redemption or always lands on the
/// settings UI.
#[tokio::test]
async fn recovery_link_redemption_with_return_to() {
    skip_on_native!(
        "redeems a Kratos admin recovery link; the native build issues the SSO session directly"
    );
    let user = common::register_test_user("samlkeystonert").await;

    let link = mint_recovery_link(&user.identity_id, Some(&format!("{}/", common::PORTAL))).await;

    let (browser, _manual, _jar) = common::paired_clients();
    let final_resp = browser.get(&link).send().await.expect("redeem link");
    assert!(
        final_resp.status().is_success(),
        "redemption landed on {} with status {}",
        final_resp.url(),
        final_resp.status()
    );

    let whoami = browser
        .get(format!("{}/sessions/whoami", common::KRATOS_PUBLIC))
        .send()
        .await
        .expect("whoami");
    assert_eq!(whoami.status(), 200, "no session after link redemption");
    let session: Value = whoami.json().await.expect("whoami json");
    assert_eq!(
        session["identity"]["id"].as_str(),
        Some(user.identity_id.as_str()),
        "session belongs to a different identity"
    );

    eprintln!(
        "post-redemption landing (return_to={}/): {}",
        common::PORTAL,
        final_resp.url()
    );

    user.cleanup().await;
}

/// Kratos must accept create-identity with a pre-verified address, and
/// must surface that identity via the verifiable-address lookup we use
/// for first-login linking. Pins the upstream behaviour the JIT path
/// assumes.
#[tokio::test]
async fn kratos_jit_assumptions_hold() {
    skip_on_native!("pins Kratos admin API behaviour; the native build has no Kratos");
    let api = common::browser_client();
    let email = common::unique_email("samljit");

    let resp = api
        .post(format!("{}/admin/identities", common::KRATOS_ADMIN))
        .json(&serde_json::json!({
            "schema_id": "default",
            "traits": { "email": email, "name": { "first": "Jit", "last": "Test" } },
            "verifiable_addresses": [{
                "value": email, "verified": true, "via": "email", "status": "completed"
            }]
        }))
        .send()
        .await
        .expect("create identity");
    let status = resp.status();
    let created: Value = resp.json().await.expect("create response json");
    assert_eq!(status, 201, "create: {created}");
    assert_eq!(created["verifiable_addresses"][0]["verified"], true);
    let identity_id = created["id"].as_str().expect("identity id").to_string();

    // The lookup the link-on-first-login path uses: credentials_identifier
    // filter must surface the identity, with the verified flag intact.
    let found: Value = api
        .get(format!(
            "{}/admin/identities?credentials_identifier={email}",
            common::KRATOS_ADMIN
        ))
        .send()
        .await
        .expect("lookup by identifier")
        .json()
        .await
        .expect("lookup json");
    let row = found
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r["id"].as_str() == Some(identity_id.as_str()))
        })
        .unwrap_or_else(|| panic!("identity not found via credentials_identifier: {found}"));
    assert_eq!(row["verifiable_addresses"][0]["verified"], true);

    // Duplicate email must conflict (per-row fallible import semantics).
    let dup = api
        .post(format!("{}/admin/identities", common::KRATOS_ADMIN))
        .json(&serde_json::json!({
            "schema_id": "default",
            "traits": { "email": email, "name": { "first": "Jit", "last": "Dup" } }
        }))
        .send()
        .await
        .expect("create duplicate");
    assert_eq!(dup.status(), 409, "duplicate email must conflict");

    let _ = common::delete_test_identity(&identity_id).await;
}

/// Unknown org slug → the uniform neutral page, NOT a 404 — the URL must
/// not be usable to probe which orgs exist or have SSO.
#[tokio::test]
async fn sso_unknown_slug_is_neutral() {
    let resp = common::browser_client()
        .get(format!("{}/sso/no-such-org-xyzzy", common::PORTAL))
        .send()
        .await
        .expect("GET /sso/no-such-org-xyzzy");
    assert_eq!(resp.status(), 200, "neutral page must be a plain 200");
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("Single sign-on unavailable"),
        "expected the neutral unavailable copy, got: {}",
        &body[..body.len().min(500)]
    );
}

/// Callback without a valid signed state cookie → 400, never a session.
#[tokio::test]
async fn sso_callback_rejects_missing_state() {
    let resp = common::browser_client()
        .get(format!(
            "{}/sso/callback?code=fake&state=fake",
            common::PORTAL
        ))
        .send()
        .await
        .expect("GET /sso/callback");
    assert_eq!(resp.status(), 400, "state mismatch must be rejected");
}

/// SSO arrivals (breadcrumb cookie set) get bounced from the
/// settings-password landing to the dashboard.
#[tokio::test]
async fn sso_arrival_lands_on_dashboard() {
    let user = common::register_test_user("samlarrival").await;

    // Recreate the post-callback browser state: a session (on Kratos from
    // redeeming the recovery link, on native the registration's own session
    // cookie), plus the breadcrumb the callback sets.
    let (browser, manual, jar) = common::paired_clients();
    let portal_url: reqwest::Url = common::PORTAL.parse().expect("portal url");
    if common::is_native() {
        let token = common::client_cookie(&user.client, "forseti_session")
            .await
            .expect("registration session cookie");
        jar.add_cookie_str(&format!("forseti_session={token}; Path=/"), &portal_url);
    } else {
        let link = mint_recovery_link(&user.identity_id, None).await;
        let resp = browser.get(&link).send().await.expect("redeem link");
        assert!(
            resp.status().is_success(),
            "redemption landed on {} with status {}",
            resp.url(),
            resp.status()
        );
    }
    jar.add_cookie_str("forseti_sso_arrival=1; Path=/settings", &portal_url);

    // Breadcrumb present → straight to the dashboard, cookie cleared.
    let resp = manual
        .get(format!("{}/settings/password", common::PORTAL))
        .send()
        .await
        .expect("GET /settings/password with breadcrumb");
    assert!(
        resp.status().is_redirection(),
        "expected a redirect, got {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/",
        "breadcrumb arrival must land on the dashboard"
    );
    let cleared = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| {
            c.starts_with("forseti_sso_arrival=")
                && c.contains("Max-Age=0")
                && c.contains("Path=/settings")
        });
    assert!(cleared, "breadcrumb must be cleared on the bounce");

    // Breadcrumb gone (the clear above removed it from the jar) → the
    // page behaves as before: Kratos flow init, never a dashboard bounce.
    let resp = manual
        .get(format!("{}/settings/password", common::PORTAL))
        .send()
        .await
        .expect("GET /settings/password without breadcrumb");
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_ne!(
        location, "/",
        "no-breadcrumb request must not be bounced home"
    );

    user.cleanup().await;
}

/// Org exists ("default" is always seeded). State-aware: with no SAML
/// connection the route must serve the neutral 200 page; if a connection
/// exists (e.g. the licensed e2e suite ran first) it must redirect to the
/// Jackson authorize endpoint. Either outcome proves the route is mounted,
/// gated, and sane — anything else (404, 5xx, off-site redirect) fails.
#[tokio::test]
async fn sso_org_without_connection_is_neutral() {
    let (_browser, manual, _jar) = common::paired_clients();
    let resp = manual
        .get(format!("{}/sso/default", common::PORTAL))
        .send()
        .await
        .expect("GET /sso/default");
    let status = resp.status();
    if status.is_redirection() {
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            location.starts_with("http://127.0.0.1:5225/api/oauth/authorize"),
            "redirect must target the Jackson authorize endpoint, got: {location}"
        );
    } else {
        assert_eq!(status, 200, "routes must be mounted (not 404)");
        let body = resp.text().await.expect("body");
        assert!(
            body.contains("Single sign-on unavailable"),
            "expected the neutral unavailable copy, got: {}",
            &body[..body.len().min(500)]
        );
    }
}

/// Cross-org guard discriminator. The callback's verified-email branch only
/// links a pre-existing identity if it's ALREADY a member of the requesting
/// org (`orgs::db::find_member` returns `Some`); otherwise it fails closed
/// (`cross_org_not_member`). The full path needs a real IdP assertion, so —
/// like `kratos_jit_assumptions_hold` pins the upstream/DB building blocks —
/// this pins the discriminator the guard keys on: a verified identity that
/// exists in Kratos but holds NO membership row for a freshly-created
/// non-default org. (For the DEFAULT org the guard never triggers: the
/// `auto_join_default_org` middleware makes every authenticated identity a
/// member, so `find_member` is always `Some` there — the hole is only
/// reachable for non-default, i.e. commercial multi-org, tenants.)
#[tokio::test]
async fn cross_org_non_member_is_the_block_discriminator() {
    let email = common::unique_email("samlxorg");
    // A verified identity in Kratos, never joined to the org under test.
    let identity_id = common::kratos_admin_create_identity(&email).await;

    // A non-default org with zero members.
    let org_id = format!("xorg-{}", uuid::Uuid::new_v4());
    {
        let conn = rusqlite::Connection::open(common::forseti_db_path()).expect("open portal db");
        conn.execute(
            "INSERT INTO organizations (id, slug, name, created_at) VALUES (?1, ?1, 'Cross Org Test', ?2)",
            params![org_id, chrono::Utc::now().to_rfc3339()],
        )
        .expect("insert org");

        // Guard precondition: the verified identity is NOT a member → block.
        let member_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM organization_members WHERE org_id = ?1 AND identity_id = ?2",
                params![org_id, identity_id],
                |r| r.get(0),
            )
            .expect("count membership");
        assert_eq!(
            member_count, 0,
            "verified non-member must have no membership row — this is what fails the guard closed"
        );

        // Inverse: once added as a member, the same query flips to Some-shaped
        // (count == 1) and the guard would proceed to link.
        conn.execute(
            "INSERT INTO organization_members (org_id, identity_id, role, added_at) VALUES (?1, ?2, 'member', ?3)",
            params![org_id, identity_id, chrono::Utc::now().to_rfc3339()],
        )
        .expect("add member");
        let member_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM organization_members WHERE org_id = ?1 AND identity_id = ?2",
                params![org_id, identity_id],
                |r| r.get(0),
            )
            .expect("count membership after add");
        assert_eq!(
            member_count, 1,
            "a member identity flips the discriminator — the guard then links"
        );

        // Cleanup the org + member rows.
        conn.execute(
            "DELETE FROM organization_members WHERE org_id = ?1",
            params![org_id],
        )
        .expect("cleanup members");
        conn.execute("DELETE FROM organizations WHERE id = ?1", params![org_id])
            .expect("cleanup org");
    }

    let _ = common::delete_test_identity(&identity_id).await;
}

/// `/sso/confirm` is the return leg of the credential-confirmation bounce. A
/// direct visit carries no pending-link cookie, so it must render the same
/// neutral page every other "no SSO here" cause does — never a link, never a
/// hint that the route means anything.
#[tokio::test]
async fn sso_confirm_without_a_pending_link_is_neutral() {
    assert!(common::portal_reachable().await);
    let client = common::browser_client();
    let res = client
        .get(format!("{}/sso/confirm", common::PORTAL))
        .send()
        .await
        .expect("GET /sso/confirm");
    assert!(
        res.status().is_success(),
        "neutral page, not an error status; got {}",
        res.status()
    );
    let body: String = res.text().await.unwrap_or_default();
    assert!(
        !body.contains("linked"),
        "a bare /sso/confirm must not report a link"
    );
}

/// Whether a SAML-shaped Kratos session (admin recovery link, no local
/// credential) can set a first local password, through Kratos directly and
/// past Forseti's SSO-arrival bounce, plus the TOTP and stale-session controls.
#[tokio::test]
async fn sso_recovery_session_can_set_a_first_local_password() {
    skip_on_native!(
        "drives Kratos settings flows from a recovery-link session; the native build has no Kratos"
    );
    #[cfg(feature = "identity-ory")]
    first_password::run().await;
}

#[cfg(feature = "identity-ory")]
mod first_password {
    use super::mint_recovery_link;
    use crate::common;
    use reqwest::{Client, StatusCode};
    use serde_json::Value;

    const NEW_PASSWORD: &str = "Sso-First-Local-Pw-7731!";

    struct Outcome {
        status: StatusCode,
        body: Value,
    }

    impl Outcome {
        fn state(&self) -> Option<&str> {
            self.body["state"].as_str()
        }
        fn error_id(&self) -> Option<&str> {
            self.body["error"]["id"].as_str()
        }
        fn message_ids(&self) -> Vec<i64> {
            self.body["ui"]["messages"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m["id"].as_i64())
                .collect()
        }
    }

    impl std::fmt::Debug for Outcome {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "status={} state={:?} error={:?} messages={:?} redirect={:?}",
                self.status,
                self.state(),
                self.error_id(),
                self.message_ids(),
                self.body["redirect_browser_to"].as_str()
            )
        }
    }

    async fn create_sso_identity(prefix: &str) -> (String, String) {
        let email = common::unique_email(prefix);
        let resp = common::browser_client()
            .post(format!("{}/admin/identities", common::KRATOS_ADMIN))
            .json(&serde_json::json!({
                "schema_id": "default",
                "traits": { "email": email, "name": { "first": "Sso", "last": "Only" } },
                "verifiable_addresses": [{
                    "value": email, "verified": true, "via": "email", "status": "completed"
                }]
            }))
            .send()
            .await
            .expect("create identity");
        let status = resp.status();
        let body: Value = resp.json().await.expect("create identity json");
        assert_eq!(status, 201, "create identity: {body}");
        (body["id"].as_str().expect("identity id").to_string(), email)
    }

    /// Redeem a freshly minted link (same `return_to` as the SSO callback)
    /// and return where Kratos sends the browser.
    async fn redeem(manual: &Client, identity_id: &str) -> String {
        let link = mint_recovery_link(identity_id, Some(&format!("{}/", common::PORTAL))).await;
        let resp = manual.get(&link).send().await.expect("redeem link");
        location(&resp)
    }

    fn location(resp: &reqwest::Response) -> String {
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    async fn get_json(client: &Client, url: &str) -> Outcome {
        let resp = client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .expect("GET json");
        Outcome {
            status: resp.status(),
            body: resp.json().await.unwrap_or(Value::Null),
        }
    }

    async fn fetch_settings_flow(client: &Client, flow_id: &str) -> Outcome {
        get_json(
            client,
            &format!(
                "{}/self-service/settings/flows?id={flow_id}",
                common::KRATOS_PUBLIC
            ),
        )
        .await
    }

    async fn init_settings_flow(client: &Client) -> Outcome {
        get_json(
            client,
            &format!("{}/self-service/settings/browser", common::KRATOS_PUBLIC),
        )
        .await
    }

    async fn post_password(client: &Client, flow_id: &str, csrf: &str) -> Outcome {
        let url = format!(
            "{}/self-service/settings?flow={flow_id}",
            common::KRATOS_PUBLIC
        );
        // Kratos's breached-password lookup can time out with a 500 ("Unable to
        // initialize string scanner"); the flow stays open, so retrying is safe.
        for _ in 0..3 {
            let resp = client
                .post(&url)
                .header("Accept", "application/json")
                .form(&[
                    ("method", "password"),
                    ("password", NEW_PASSWORD),
                    ("csrf_token", csrf),
                ])
                .send()
                .await
                .expect("submit settings password");
            let outcome = Outcome {
                status: resp.status(),
                body: resp.json().await.unwrap_or(Value::Null),
            };
            if outcome.status != StatusCode::INTERNAL_SERVER_ERROR {
                return outcome;
            }
            eprintln!("settings submit retried after {outcome:?}");
        }
        panic!("settings submit kept answering 500");
    }

    async fn submit_password(client: &Client, flow: &Value) -> Outcome {
        let flow_id = flow["id"].as_str().expect("settings flow id");
        let csrf = common::flow_csrf_token(flow).expect("settings flow csrf_token");
        post_password(client, flow_id, &csrf).await
    }

    async fn has_password(identity_id: &str) -> bool {
        let body: Value = common::browser_client()
            .get(format!(
                "{}/admin/identities/{identity_id}?include_credential=password",
                common::KRATOS_ADMIN
            ))
            .send()
            .await
            .expect("fetch identity")
            .json()
            .await
            .expect("identity json");
        body["credentials"]["password"]["config"]["hashed_password"]
            .as_str()
            .is_some_and(|h| !h.is_empty())
    }

    async fn password_login(email: &str) -> Outcome {
        let client = common::browser_client();
        let flow: Value = client
            .get(format!(
                "{}/self-service/login/browser",
                common::KRATOS_PUBLIC
            ))
            .header("Accept", "application/json")
            .send()
            .await
            .expect("init login flow")
            .json()
            .await
            .expect("login flow json");
        let csrf = common::flow_csrf_token(&flow).expect("login flow csrf_token");
        let resp = client
            .post(flow["ui"]["action"].as_str().expect("login flow action"))
            .header("Accept", "application/json")
            .form(&[
                ("identifier", email),
                ("password", NEW_PASSWORD),
                ("method", "password"),
                ("csrf_token", csrf.as_str()),
            ])
            .send()
            .await
            .expect("submit login");
        Outcome {
            status: resp.status(),
            body: resp.json().await.unwrap_or(Value::Null),
        }
    }

    fn delete_saml_link(identity_id: &str) -> usize {
        rusqlite::Connection::open(common::forseti_db_path())
            .expect("open portal db")
            .execute(
                "DELETE FROM saml_links WHERE identity_id = ?1",
                [identity_id],
            )
            .expect("delete saml_links row")
    }

    /// Mint and redeem a link for `identity_id` on a fresh jar; returns the
    /// manual client, the jar and the settings flow id Kratos lands on.
    async fn sso_session(
        identity_id: &str,
    ) -> (Client, std::sync::Arc<reqwest::cookie::Jar>, String) {
        let (_auto, manual, jar) = common::paired_clients();
        let landing = redeem(&manual, identity_id).await;
        let prefix = format!("{}/settings?flow=", common::PORTAL);
        assert!(
            landing.starts_with(&prefix),
            "redemption must land on the settings UI, got {landing:?}"
        );
        let flow_id = common::extract_flow_id_from_url(&landing).expect("settings flow id");
        (manual, jar, flow_id)
    }

    fn assert_saved(case: &str, outcome: &Outcome) {
        assert_eq!(outcome.status, StatusCode::OK, "{case}: {outcome:?}");
        assert_eq!(outcome.state(), Some("success"), "{case}: {outcome:?}");
        assert!(
            outcome.message_ids().contains(&1_050_001),
            "{case}: {outcome:?}"
        );
    }

    fn assert_refused(case: &str, outcome: &Outcome, error_id: &str) {
        assert_eq!(outcome.status, StatusCode::FORBIDDEN, "{case}: {outcome:?}");
        assert_eq!(outcome.error_id(), Some(error_id), "{case}: {outcome:?}");
    }

    pub async fn run() {
        let portal: reqwest::Url = common::PORTAL.parse().expect("portal url");
        let mut created = Vec::new();

        // Pins: the recovery session's own settings flow is privileged (1060001) and accepts a first password (200, 1050001).
        let (a_id, a_email) = create_sso_identity("ssofirstpwa").await;
        created.push(a_id.clone());
        common::seed_saml_link("default", &a_email, &a_id, &format!("idp-{a_id}"));
        let (manual, _jar, flow_id) = sso_session(&a_id).await;
        let flow = fetch_settings_flow(&manual, &flow_id).await;
        assert_eq!(flow.status, StatusCode::OK, "A flow: {flow:?}");
        assert!(flow.message_ids().contains(&1_060_001), "A flow: {flow:?}");
        assert!(!has_password(&a_id).await, "A starts without a password");
        assert_saved("A", &submit_password(&manual, &flow.body).await);
        assert!(has_password(&a_id).await, "A password credential");

        // Pins: the password keeps signing in (200, session) after the saml_links row is deleted.
        assert_eq!(delete_saml_link(&a_id), 1, "seeded saml_links row");
        let login = password_login(&a_email).await;
        assert_eq!(login.status, StatusCode::OK, "persistence: {login:?}");
        assert_eq!(
            login.body["session"]["identity"]["id"].as_str(),
            Some(a_id.as_str()),
            "persistence: {login:?}"
        );

        // Pins: the arrival cookie bounces /settings/password to / but the landing flow still accepts a first password.
        let (b_id, _) = create_sso_identity("ssofirstpwb").await;
        created.push(b_id.clone());
        let (manual, jar, flow_id) = sso_session(&b_id).await;
        jar.add_cookie_str("forseti_sso_arrival=1; Path=/settings", &portal);
        let resp = manual
            .get(format!("{}/settings?flow={flow_id}", common::PORTAL))
            .send()
            .await
            .expect("GET /settings");
        let hop = location(&resp);
        assert_eq!(
            hop,
            format!("/settings/password?flow={flow_id}"),
            "B /settings"
        );
        let resp = manual
            .get(format!("{}{hop}", common::PORTAL))
            .send()
            .await
            .expect("GET /settings/password");
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "B bounce status");
        assert_eq!(location(&resp), "/", "B bounce target");
        let flow = fetch_settings_flow(&manual, &flow_id).await;
        assert_eq!(flow.status, StatusCode::OK, "B flow: {flow:?}");
        assert_saved("B same flow", &submit_password(&manual, &flow.body).await);
        assert!(has_password(&b_id).await, "B password credential");

        // Pins: after the bounce a freshly initialised settings flow also accepts a first password.
        let (c_id, _) = create_sso_identity("ssofirstpwc").await;
        created.push(c_id.clone());
        let (manual, jar, _landing_flow) = sso_session(&c_id).await;
        jar.add_cookie_str("forseti_sso_arrival=1; Path=/settings", &portal);
        let resp = manual
            .get(format!("{}/settings/password", common::PORTAL))
            .send()
            .await
            .expect("GET /settings/password");
        assert_eq!(location(&resp), "/", "C bounce target");
        let fresh = init_settings_flow(&manual).await;
        assert_eq!(fresh.status, StatusCode::OK, "C init: {fresh:?}");
        assert_saved("B fresh flow", &submit_password(&manual, &fresh.body).await);
        assert!(has_password(&c_id).await, "C password credential");

        // Pins: with TOTP on the identity the AAL1 recovery session gets 403 session_aal2_required on fetch, init and submit.
        let (d_id, _) = create_sso_identity("ssofirstpwd").await;
        created.push(d_id.clone());
        common::plant_totp(&d_id, common::TEST_TOTP_SECRET);
        let (manual, _jar, flow_id) = sso_session(&d_id).await;
        let fetched = fetch_settings_flow(&manual, &flow_id).await;
        assert_refused("D fetch", &fetched, "session_aal2_required");
        assert_refused(
            "D init",
            &init_settings_flow(&manual).await,
            "session_aal2_required",
        );
        // The flow is unreadable at AAL1, so there is no csrf token to send.
        assert_refused(
            "D submit",
            &post_password(&manual, &flow_id, "").await,
            "session_aal2_required",
        );
        assert!(!has_password(&d_id).await, "D must stay passwordless");

        // Pins: a session whose authenticated_at is an hour old gets 403 session_refresh_required on submit.
        let (e_id, _) = create_sso_identity("ssofirstpwe").await;
        created.push(e_id.clone());
        let (manual, _jar, flow_id) = sso_session(&e_id).await;
        let rows = common::kratos_psql(&format!(
            "UPDATE sessions SET authenticated_at = authenticated_at - interval '1 hour' \
             WHERE identity_id = '{e_id}'::uuid"
        ));
        assert_eq!(rows, 1, "backdated session rows");
        let flow = fetch_settings_flow(&manual, &flow_id).await;
        assert_eq!(flow.status, StatusCode::OK, "E flow: {flow:?}");
        assert_refused(
            "E submit",
            &submit_password(&manual, &flow.body).await,
            "session_refresh_required",
        );
        assert!(!has_password(&e_id).await, "E must stay passwordless");

        for id in &created {
            let _ = common::delete_test_identity(id).await;
        }
    }
}
