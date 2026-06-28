//! Self-service session management — `/settings/sessions` revoke endpoints.
//!
//! `settings.rs` covers the GET render; these cover the destructive POSTs that
//! actually drive Kratos's `DELETE /sessions` and `DELETE /sessions/{id}`.
//! A Kratos upgrade changing the revoke semantics (e.g. the "can't delete the
//! current session" rule, or the bulk-revoke return) would otherwise pass
//! silently.

use crate::common::*;

/// "Sign out of all other devices" must kill every *other* session of the
/// identity while leaving the current one alive. Guards
/// `revoke_other_sessions` (`DELETE /sessions`).
#[tokio::test]
async fn revoke_others_kills_second_session_keeps_current() {
    assert!(portal_reachable().await);

    // Session A: the registered user's authenticated client.
    let user = register_test_user("sess-revoke-others").await;
    // Session B: a second password login on a fresh jar for the same identity.
    let client_b = browser_client();
    password_login_aal1(&client_b, &user.email, &user.password).await;

    assert!(
        whoami_is_active(&user.client).await,
        "session A should be active"
    );
    assert!(
        whoami_is_active(&client_b).await,
        "session B should be active before revoke"
    );

    // From session A, fetch the page CSRF then POST revoke-others.
    let page = user
        .client
        .get(format!("{PORTAL}/settings/sessions"))
        .send()
        .await
        .expect("GET /settings/sessions");
    let body = page.text().await.unwrap_or_default();
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf on sessions page");

    let res = user
        .client
        .post(format!("{PORTAL}/settings/sessions/revoke-others"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST revoke-others");
    assert!(
        res.status().is_success() || res.status().is_redirection(),
        "revoke-others status {}",
        res.status()
    );

    assert!(
        !whoami_is_active(&client_b).await,
        "session B must be revoked by revoke-others"
    );
    assert!(
        whoami_is_active(&user.client).await,
        "the current session A must survive revoke-others"
    );

    user.cleanup().await;
}

/// Revoking a specific (non-current) session by ID must kill exactly that
/// session. Guards `revoke_session` (`DELETE /sessions/{id}`).
#[tokio::test]
async fn revoke_single_session_by_id() {
    assert!(portal_reachable().await);

    let user = register_test_user("sess-revoke-one").await;
    let client_b = browser_client();
    password_login_aal1(&client_b, &user.email, &user.password).await;

    let b_session = whoami_session_id(&client_b)
        .await
        .expect("session B has an id");
    assert!(
        whoami_is_active(&client_b).await,
        "session B active before revoke"
    );

    let page = user
        .client
        .get(format!("{PORTAL}/settings/sessions"))
        .send()
        .await
        .expect("GET /settings/sessions");
    let body = page.text().await.unwrap_or_default();
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf on sessions page");

    let res = user
        .client
        .post(format!("{PORTAL}/settings/sessions/{b_session}/revoke"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST revoke single session");
    assert!(
        res.status().is_success() || res.status().is_redirection(),
        "revoke single status {}",
        res.status()
    );

    assert!(
        !whoami_is_active(&client_b).await,
        "the targeted session B must be revoked"
    );
    assert!(
        whoami_is_active(&user.client).await,
        "session A (current) must be untouched"
    );

    user.cleanup().await;
}
