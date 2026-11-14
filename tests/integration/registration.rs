//! Full registration flow happy path.

use crate::common::*;

#[tokio::test]
async fn registration_two_step_flow_creates_identity_and_signs_in() {
    assert!(
        portal_reachable().await,
        "portal not reachable at {PORTAL} — bring up the playground first"
    );

    let user = register_test_user("reg-happy").await;

    // The cookie jar now carries the new session.
    let (identity_id, email_trait) = whoami_identity(&user.client)
        .await
        .expect("whoami after register");
    assert_eq!(
        identity_id, user.identity_id,
        "session.identity.id should match the newly created identity"
    );
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
