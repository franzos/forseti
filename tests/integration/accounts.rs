//! Integration tests for the multi-account chooser (Phase 1).
//!
//! # Intentionally omitted
//!
//! The security gate inside `accounts::handlers::switch` re-checks `/sessions/whoami`
//! after teardown and aborts to `/error` when the session is still live. That abort
//! path is not testable via integration tests without forcing Kratos to refuse to
//! delete the session (which would require mocking the Kratos side). It is covered
//! by code review, not by a running-stack integration test.

use crate::common::*;

// ---------------------------------------------------------------------------
// CSRF gate tests — no session needed, portal just needs to be reachable.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accounts_switch_requires_csrf() {
    let client = browser_client();
    let res = client
        .post(format!("{PORTAL}/accounts/switch"))
        .form(&[("_csrf", "wrong-token"), ("identity_id", "some-uuid")])
        .send()
        .await
        .expect("POST /accounts/switch (bad csrf)");
    assert_eq!(
        res.status().as_u16(),
        403,
        "bad CSRF token should yield 403 on /accounts/switch"
    );
}

#[tokio::test]
async fn accounts_forget_requires_csrf() {
    let client = browser_client();
    let res = client
        .post(format!("{PORTAL}/accounts/forget"))
        .form(&[
            ("_csrf", "wrong-token"),
            ("identity_id", "some-uuid"),
        ])
        .send()
        .await
        .expect("POST /accounts/forget (bad csrf)");
    assert_eq!(
        res.status().as_u16(),
        403,
        "bad CSRF token should yield 403 on /accounts/forget"
    );
}

#[tokio::test]
async fn consent_switch_requires_csrf() {
    let client = browser_client();
    let res = client
        .post(format!("{PORTAL}/oauth/consent/switch"))
        .form(&[
            ("_csrf", "wrong-token"),
            ("consent_challenge", "fake-challenge"),
            ("identity_id", "some-uuid"),
        ])
        .send()
        .await
        .expect("POST /oauth/consent/switch (bad csrf)");
    assert_eq!(
        res.status().as_u16(),
        403,
        "bad CSRF token should yield 403 on /oauth/consent/switch"
    );
}

// ---------------------------------------------------------------------------
// Switch tears down session and redirects to /login with login_hint.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accounts_switch_tears_down_and_redirects() {
    assert!(
        portal_reachable().await,
        "portal not reachable at {PORTAL} — bring up the playground first"
    );

    let user = register_test_user("acct-switch").await;
    let target_uuid = uuid::Uuid::new_v4().to_string();

    // Fetch the CSRF token from /settings (same pattern as logout.rs).
    let res = user
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings");
    assert!(
        res.status().is_success() || res.status().is_redirection(),
        "settings hub status {}",
        res.status()
    );
    let body = res.text().await.expect("settings body");
    let csrf = extract_csrf_form_token(&body).expect("`_csrf` hidden input in /settings");

    // POST /accounts/switch with redirects disabled so we can inspect the 303.
    let res = user
        .manual_client
        .post(format!("{PORTAL}/accounts/switch"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("identity_id", target_uuid.as_str()),
            ("return_to", "/settings"),
        ])
        .send()
        .await
        .expect("POST /accounts/switch");

    assert_eq!(
        res.status().as_u16(),
        303,
        "switch should 303-redirect; got {}",
        res.status()
    );

    let location = res
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // The redirect should go to /login and carry login_hint=<target_uuid>.
    assert!(
        location.contains("/login"),
        "Location should point to /login; got {location}"
    );
    assert!(
        location.contains(&target_uuid),
        "Location should carry login_hint={target_uuid}; got {location}"
    );

    // At least one Set-Cookie should clear forseti_active_org.
    let clears_active_org = res.headers().get_all(reqwest::header::SET_COOKIE).iter().any(|v| {
        v.to_str()
            .map(|s| s.contains("forseti_active_org") && (s.contains("Max-Age=0") || s.to_ascii_lowercase().contains("expires")))
            .unwrap_or(false)
    });
    assert!(
        clears_active_org,
        "switch should emit a Set-Cookie clearing forseti_active_org"
    );

    // Session should be gone after the switch (the auto-redirect client shares
    // the same cookie jar and the session cookie was cleared server-side).
    let alive = whoami_is_active(&user.client).await;
    assert!(
        !alive,
        "Kratos session should be gone after /accounts/switch"
    );

    user.cleanup().await;
}

// ---------------------------------------------------------------------------
// Consent accept with remember_account sets forseti_known_accounts cookie.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consent_remember_appends_known_account() {
    assert!(
        portal_reachable().await,
        "portal not reachable at {PORTAL} — bring up the playground first"
    );

    let user = register_test_user("acct-consent-remember").await;
    let (client_id, _secret, redirect_uri) =
        hydra_create_test_client(&["openid", "profile"]).await;

    let auth_url = oauth_auth_url(&client_id, &redirect_uri, "openid profile", "");
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;

    // POST consent via the manual client (shared cookie jar, redirects off) so
    // we can inspect Set-Cookie on the response before following the chain.
    let fields: &[(&str, &str)] = &[
        ("_csrf", &csrf),
        ("consent_challenge", &consent_challenge),
        ("decision", "accept"),
        ("grant_scope", "openid"),
        ("grant_scope", "profile"),
        ("remember_account", "true"),
    ];
    let encoded: String = fields
        .iter()
        .map(|(k, v)| format!("{}={}", form_urlencode(k), form_urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let res = user
        .manual_client
        .post(format!("{PORTAL}/oauth/consent"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(encoded)
        .send()
        .await
        .expect("POST /oauth/consent (remember_account)");

    // The handler redirects; the cookie must be on this first response.
    assert!(
        res.status().is_redirection(),
        "consent submit should redirect; got {}",
        res.status()
    );

    let sets_known_accounts = res
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| s.contains("forseti_known_accounts"))
                .unwrap_or(false)
        });
    assert!(
        sets_known_accounts,
        "consent accept with remember_account=true should set forseti_known_accounts cookie"
    );

    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}
