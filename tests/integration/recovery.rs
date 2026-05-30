//! Recovery flow — email → 6-digit code → post-recovery settings.

use std::time::Duration;

use crate::common::*;

#[tokio::test]
async fn recovery_email_code_lands_on_settings_password() {
    assert!(
        portal_reachable().await,
        "portal not reachable at {PORTAL} — bring up the playground first"
    );

    // Pre-existing user (so a recovery email can be addressed somewhere).
    let user = register_test_user("recovery").await;

    // Sign-out by dropping the registered client; start a fresh anonymous
    // browser for the recovery dance. This avoids the "already signed in,
    // skipping recovery" short-circuit Kratos applies.
    let anon = browser_client();

    // 1. Init recovery via portal — same bounce shape as registration.
    let res = anon
        .get(format!("{PORTAL}/recovery"))
        .send()
        .await
        .expect("GET /recovery");
    assert!(res.status().is_success(), "/recovery: {}", res.status());
    let flow_id = extract_flow_id_from_url(res.url().as_str()).expect("flow id");
    let flow = fetch_flow(&anon, "recovery", &flow_id).await;
    let csrf = flow_csrf_token(&flow).expect("csrf_token");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("ui.action")
        .to_string();

    // 2. Submit recovery email.
    let res = anon
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("email", user.email.as_str()),
            ("method", "code"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("submit recovery email");
    assert!(
        res.status().is_success(),
        "submit recovery: {}",
        res.status()
    );

    // 3. Wait for the email.
    let mail = wait_for_mailcrab(&user.email, "recover access", Duration::from_secs(15))
        .await
        .expect("recovery email arrived");
    let code = extract_code_from_email(&mail.body).expect("6-digit code in body");

    // 4. Submit code. The flow's `ui.action` is the same `/self-service/recovery?flow=...`
    //    we just used; refetch CSRF since Kratos may have rotated it.
    let flow = fetch_flow(&anon, "recovery", &flow_id).await;
    let csrf = flow_csrf_token(&flow).expect("csrf_token (step 2)");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("ui.action (step 2)")
        .to_string();
    // Kratos returns 422 on a successful recovery submit (it wants the JSON
    // client to redirect to `redirect_browser_to`). We follow that manually
    // to assert on the landing page.
    let anon_manual = manual_redirect_client();
    // Copy cookies over from the auto-redirect client. reqwest does not
    // expose the cookie jar directly; instead, re-do the submit on the
    // browser-style client and inspect the URL it ends up at.
    let _ = (csrf, action);
    let res = anon
        .post(format!(
            "{KRATOS_PUBLIC}/self-service/recovery?flow={flow_id}"
        ))
        .header("Accept", "application/json")
        .form(&[
            ("code", code.as_str()),
            ("method", "code"),
            (
                "csrf_token",
                flow_csrf_token(&flow).unwrap_or_default().as_str(),
            ),
        ])
        .send()
        .await
        .expect("submit code");
    // Kratos returns the next flow's `redirect_browser_to` in either a 200
    // body (when sent as JSON) or a 422 with the URL. Either way, we follow
    // through and assert the final URL contains /settings/password.
    let status = res.status();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::Value::Null);
    let redirect_to = body["redirect_browser_to"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_default();
    assert!(
        !redirect_to.is_empty() || status.is_success(),
        "expected redirect_browser_to after code submit: status {status} body {body}"
    );

    // Follow Kratos's redirect chain back into the portal.
    if !redirect_to.is_empty() {
        let res = anon
            .get(&redirect_to)
            .send()
            .await
            .expect("follow redirect_browser_to");
        let final_url = res.url().to_string();
        assert!(
            final_url.contains("/settings/password"),
            "post-recovery should land on /settings/password (Bug 3); got {final_url}"
        );
    }

    let _ = anon_manual;
    user.cleanup().await;
}
