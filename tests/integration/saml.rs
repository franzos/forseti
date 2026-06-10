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
        .json(&serde_json::json!({
            "identity_id": identity_id,
            "expires_in": "15m"
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

    // Recreate the post-callback browser state: a session from redeeming
    // the recovery link, plus the breadcrumb the callback sets.
    let link = mint_recovery_link(&user.identity_id, None).await;
    let (browser, manual, jar) = common::paired_clients();
    let resp = browser.get(&link).send().await.expect("redeem link");
    assert!(
        resp.status().is_success(),
        "redemption landed on {} with status {}",
        resp.url(),
        resp.status()
    );
    let portal_url: reqwest::Url = common::PORTAL.parse().expect("portal url");
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
