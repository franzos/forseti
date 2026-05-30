//! `/logout` — POST-only, CSRF-protected.

use crate::common::*;

#[tokio::test]
async fn logout_without_csrf_returns_403() {
    let client = browser_client();
    let res = client
        .post(format!("{PORTAL}/logout"))
        .form(&[("_csrf", "wrong-token")])
        .send()
        .await
        .expect("POST /logout (no csrf)");
    assert_eq!(
        res.status().as_u16(),
        403,
        "missing CSRF cookie should yield 403"
    );
}

#[tokio::test]
async fn logout_with_valid_csrf_destroys_session() {
    assert!(
        portal_reachable().await,
        "portal not reachable at {PORTAL} — bring up the playground first"
    );

    let user = register_test_user("logout").await;

    // Trip the portal_csrf cookie + token by visiting /settings (the hub
    // renders the logout form with `_csrf`).
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

    // POST /logout with manual-redirect so we can assert the 303.
    let manual = manual_redirect_client();
    // Copy the session + csrf cookies over by visiting /settings on the
    // manual client. Easiest: re-register? No — the cookie store is
    // independent per Client. We instead drive the logout on the same
    // `user.client` and observe the final state via /sessions/whoami.
    let _ = manual;

    let res = user
        .client
        .post(format!("{PORTAL}/logout"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST /logout");
    assert!(
        res.status().is_success() || res.status().is_redirection(),
        "logout final status: {}",
        res.status()
    );

    // After logout the session should be gone.
    let res = user
        .client
        .get(format!("{KRATOS_PUBLIC}/sessions/whoami"))
        .header("Accept", "application/json")
        .send()
        .await
        .expect("whoami after logout");
    assert!(
        !res.status().is_success(),
        "whoami should fail after logout: status {}",
        res.status()
    );

    user.cleanup().await;
}

/// Pull the `value` of a hidden `_csrf` input out of an HTML form body.
fn extract_csrf_form_token(html: &str) -> Option<String> {
    // The template emits `<input type="hidden" name="_csrf" value="...">`.
    // We do a small substring scan rather than a full HTML parse — it's
    // unambiguous and keeps the dev-graph lean.
    let needle = "name=\"_csrf\"";
    let idx = html.find(needle)?;
    let rest = &html[idx..];
    let val_idx = rest.find("value=\"")?;
    let after = &rest[val_idx + "value=\"".len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}
