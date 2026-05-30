//! Full registration flow happy path.

use crate::common::*;

#[tokio::test]
async fn registration_two_step_flow_creates_identity_and_signs_in() {
    assert!(
        portal_reachable().await,
        "portal not reachable at {PORTAL} — bring up the playground first"
    );

    let user = register_test_user("reg-happy").await;

    // The cookie jar should now carry `ory_kratos_session`.
    let res = user
        .client
        .get(format!("{KRATOS_PUBLIC}/sessions/whoami"))
        .header("Accept", "application/json")
        .send()
        .await
        .expect("whoami");
    assert!(
        res.status().is_success(),
        "whoami after register: {}",
        res.status()
    );
    let v: serde_json::Value = res.json().await.expect("whoami body");
    assert_eq!(
        v["identity"]["id"].as_str(),
        Some(user.identity_id.as_str()),
        "session.identity.id should match the newly created identity"
    );
    let email_trait = v["identity"]["traits"]["email"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        email_trait, user.email,
        "identity.traits.email should match"
    );

    // Lands on the dashboard after sign-in.
    let res = user
        .client
        .get(format!("{PORTAL}/"))
        .send()
        .await
        .expect("GET /");
    assert!(
        res.status().is_success(),
        "GET / after register: {}",
        res.status()
    );

    user.cleanup().await;
}
