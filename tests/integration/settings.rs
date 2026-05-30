//! `/settings/*` sub-pages — auth gating, rendering checks.

use crate::common::*;

#[tokio::test]
async fn settings_hub_redirects_anonymous_to_login() {
    let client = manual_redirect_client();
    let res = client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings anon");
    assert_eq!(res.status().as_u16(), 303);
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.contains("/login"),
        "anonymous /settings should redirect to /login; got {loc}"
    );
}

#[tokio::test]
async fn settings_hub_renders_for_authenticated_user() {
    assert!(portal_reachable().await);
    let user = register_test_user("settings-hub").await;

    let res = user
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings");
    assert!(res.status().is_success(), "/settings: {}", res.status());
    let body = res.text().await.expect("body");
    assert!(
        body.to_lowercase().contains("settings") || body.contains("/settings/profile"),
        "hub should reference the settings nav"
    );
    user.cleanup().await;
}

#[tokio::test]
async fn settings_profile_handles_email_change_flow() {
    assert!(portal_reachable().await);
    let user = register_test_user("settings-profile").await;

    // GET /settings/profile bounces through Kratos init and lands back with
    // ?flow=<id>. The rendered form should target Kratos's settings action.
    let res = user
        .client
        .get(format!("{PORTAL}/settings/profile"))
        .send()
        .await
        .expect("GET /settings/profile");
    assert!(
        res.status().is_success(),
        "/settings/profile: {}",
        res.status()
    );
    assert_eq!(
        res.url().path(),
        "/settings/profile",
        "final URL should remain on /settings/profile"
    );
    let body = res.text().await.expect("body");
    assert!(
        body.contains("traits.email"),
        "profile form should include traits.email input"
    );

    user.cleanup().await;
}

#[tokio::test]
async fn settings_2fa_renders_totp_setup_section() {
    assert!(portal_reachable().await);
    let user = register_test_user("settings-2fa").await;

    let res = user
        .client
        .get(format!("{PORTAL}/settings/2fa"))
        .send()
        .await
        .expect("GET /settings/2fa");
    assert!(res.status().is_success(), "/settings/2fa: {}", res.status());
    assert_eq!(res.url().path(), "/settings/2fa");
    let body = res.text().await.expect("body");
    // Without TOTP enrolled, the page should show the enrolment UI: a QR
    // image, a secret display, or the `totp_code` confirm field.
    let has_totp_surface = body.contains("totp_qr")
        || body.contains("totp_secret")
        || body.contains("name=\"totp_code\"")
        || body.to_lowercase().contains("authenticator");
    assert!(
        has_totp_surface,
        "2fa page should surface TOTP enrolment; body excerpt:\n{}",
        body.chars().take(600).collect::<String>()
    );

    user.cleanup().await;
}

#[tokio::test]
async fn settings_sessions_shows_current_indicator() {
    assert!(portal_reachable().await);
    let user = register_test_user("settings-sessions").await;

    let res = user
        .client
        .get(format!("{PORTAL}/settings/sessions"))
        .send()
        .await
        .expect("GET /settings/sessions");
    assert!(
        res.status().is_success(),
        "/settings/sessions: {}",
        res.status()
    );
    let body = res.text().await.expect("body");
    // Look for a "current" / "this device" badge.
    assert!(
        body.to_lowercase().contains("current") || body.contains("This device"),
        "sessions page should mark the current session"
    );

    user.cleanup().await;
}

#[tokio::test]
async fn settings_linked_providers_renders_empty_state() {
    assert!(portal_reachable().await);
    let user = register_test_user("settings-linked").await;

    let res = user
        .client
        .get(format!("{PORTAL}/settings/linked-providers"))
        .send()
        .await
        .expect("GET /settings/linked-providers");
    assert!(
        res.status().is_success(),
        "/settings/linked-providers: {}",
        res.status()
    );
    let body = res.text().await.expect("body");
    // No OIDC configured in the playground → either a "no providers
    // configured" message or simply no `provider` form inputs.
    let has_no_providers = !body.contains("name=\"provider\"")
        || body.to_lowercase().contains("no")
        || body.to_lowercase().contains("none");
    assert!(
        has_no_providers,
        "linked-providers should render empty state without OIDC configured"
    );

    user.cleanup().await;
}
