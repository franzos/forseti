//! `/login` handler — happy paths.

use crate::common::*;

#[tokio::test]
async fn get_login_without_flow_redirects_to_kratos_init() {
    let client = manual_redirect_client();
    let res = client
        .get(format!("{PORTAL}/login"))
        .send()
        .await
        .expect("GET /login");
    assert_eq!(res.status().as_u16(), 303, "should 303 to Kratos init");
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.contains("/self-service/login/browser"),
        "Location should be Kratos login init: got {loc}"
    );
}

#[tokio::test]
async fn get_login_with_bad_flow_bounces_back_to_fresh_init() {
    // Kratos returns 410 for unknown flow IDs; the portal collapses that to
    // a fresh `/self-service/login/browser` redirect.
    let client = manual_redirect_client();
    let res = client
        .get(format!(
            "{PORTAL}/login?flow=00000000-0000-0000-0000-000000000000"
        ))
        .send()
        .await
        .expect("GET /login?flow=bad");
    assert_eq!(res.status().as_u16(), 303);
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.contains("/self-service/login/browser"),
        "bad flow should restart at Kratos init: got {loc}"
    );
}

#[tokio::test]
async fn get_login_with_valid_flow_renders_form() {
    // Follow the full bounce: GET /login → Kratos init → portal renders form.
    let client = browser_client();
    let res = client
        .get(format!("{PORTAL}/login"))
        .send()
        .await
        .expect("GET /login (follow redirects)");
    assert!(
        res.status().is_success(),
        "final status should be 200: {}",
        res.status()
    );
    // After redirects we should be back at /login?flow=<id>.
    assert!(
        res.url().path() == "/login" && res.url().query().is_some_and(|q| q.contains("flow=")),
        "final URL should be /login?flow=...: {}",
        res.url()
    );
    let body = res.text().await.expect("body");
    // The form posts to Kratos public's `/self-service/login` action URL.
    let kratos_action = format!("action=\"{KRATOS_PUBLIC}/self-service/login");
    assert!(
        body.contains(&kratos_action),
        "form should point at Kratos login action ({kratos_action}); body excerpt:\n{}",
        body.chars().take(400).collect::<String>()
    );
    // And it should have the rendered password input.
    assert!(
        body.contains("type=\"password\""),
        "rendered form should include the password input"
    );
}
