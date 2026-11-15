//! Upstream sign-in on the native build against the playground's `mock-oidc` (`playground`).

use std::time::Duration;

use serde_json::json;

use crate::common::*;

const LOGIN: &str = "http://localhost:3000/self-service/login/browser";
const LINKED: &str = "http://localhost:3000/settings/linked-providers";

const ACCOUNT_EXISTS: &str =
    "An account with the same identifier (email, phone, username, ...) exists already.";
const INVALID_CREDENTIALS: &str = "The provided credentials are invalid";
const LAST_METHOD: &str = "Unable to remove the last sign-in method.";

fn subject(prefix: &str) -> String {
    unique_email(prefix).replace('@', "-at-")
}

fn verified_claims(email: &str) -> serde_json::Value {
    json!({ "email": email, "email_verified": true, "given_name": "Up", "family_name": "Stream" })
}

/// A new identity signed up through the provider; its id, with the signed-in client pair.
async fn provider_sign_up(prefix: &str) -> (String, String, reqwest::Client, reqwest::Client) {
    let email = unique_email(prefix);
    let sub = subject(prefix);
    let (auto, manual, _) = paired_clients();
    let (at, html) =
        provider_round_trip(&manual, LOGIN, "provider", &sub, &verified_claims(&email)).await;
    let id = identity_id_by_email(&email).await.unwrap_or_else(|| {
        panic!(
            "provider sign-up of {email} created nothing; landed on {at}: {}",
            html.chars().take(800).collect::<String>()
        )
    });
    (id, sub, auto, manual)
}

#[tokio::test]
async fn provider_sign_up_creates_a_verified_linked_account() {
    assert!(portal_reachable().await);
    let email = unique_email("up-signup");
    let sub = subject("up-signup");
    let (_, manual, _) = paired_clients();

    let (at, _) =
        provider_round_trip(&manual, LOGIN, "provider", &sub, &verified_claims(&email)).await;
    assert_eq!(at.path(), "/", "a sign-up lands on return_to");

    let id = identity_id_by_email(&email)
        .await
        .expect("identity created");
    assert!(
        address_verified(&id, &email).await,
        "a provider-verified address is stored verified"
    );
    assert!(first_verified(&id));
    assert_eq!(
        provider_link_owner(PLAYGROUND, &sub).as_deref(),
        Some(id.as_str())
    );
    assert_eq!(
        credential_kinds(&id),
        Vec::<String>::new(),
        "no password was set"
    );
    let (methods, _) = session_auth(&manual).await.expect("session issued");
    assert_eq!(methods[0]["method"], "oidc", "{methods}");
    assert_eq!(methods[0]["provider"], PLAYGROUND, "{methods}");
    assert!(whoami_is_active(&manual).await);
    assert!(audit_row_exists("identity.created", &id));
    assert!(
        wait_for_mailcrab(&email, "verify your account", Duration::from_secs(2))
            .await
            .is_none(),
        "a provider-verified address gets no verification mail"
    );

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn provider_sign_in_reaches_the_linked_identity() {
    assert!(portal_reachable().await);
    let (id, sub, _, _) = provider_sign_up("up-signin").await;

    // A second browser, and claims with another address: the link decides, not the address.
    let (_, manual, _) = paired_clients();
    let other = unique_email("up-signin-other");
    let (at, _) =
        provider_round_trip(&manual, LOGIN, "provider", &sub, &verified_claims(&other)).await;
    assert_eq!(at.path(), "/");
    assert_eq!(
        whoami_identity(&manual).await.map(|(i, _)| i).as_deref(),
        Some(id.as_str())
    );
    assert!(
        identity_id_by_email(&other).await.is_none(),
        "no second account"
    );

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn provider_sign_in_with_a_taken_address_is_refused() {
    assert!(portal_reachable().await);
    let email = unique_email("up-taken");
    let existing =
        kratos_admin_create_verified_password_identity(&email, "Sup3rSecret-Taken-Pw!").await;
    let sub = subject("up-taken");
    let (_, manual, _) = paired_clients();

    let (at, html) =
        provider_round_trip(&manual, LOGIN, "provider", &sub, &verified_claims(&email)).await;
    assert_eq!(
        at.path(),
        "/registration",
        "a refusal lands on a registration flow"
    );
    assert!(html.contains(ACCOUNT_EXISTS), "4000007 shown");
    assert!(
        provider_link_owner(PLAYGROUND, &sub).is_none(),
        "nothing linked"
    );
    assert!(
        provider_links(&existing).is_empty(),
        "the existing account is not linked"
    );
    assert!(!whoami_is_active(&manual).await, "no session");

    delete_test_identity(&existing).await.ok();
}

#[tokio::test]
async fn provider_sign_up_without_a_verified_address_needs_the_mailed_code() {
    assert!(portal_reachable().await);
    let sub = subject("up-needed");
    let asserted = unique_email("up-needed-asserted");
    let (_, manual, _) = paired_clients();

    // An address the provider does not assert verified counts as none.
    let (at, html) = provider_round_trip(
        &manual,
        LOGIN,
        "provider",
        &sub,
        &json!({ "email": asserted }),
    )
    .await;
    assert_eq!(at.path(), "/registration", "email-needed screen");
    assert!(
        html.contains("name=\"traits.email\""),
        "asks for an address"
    );
    assert!(identity_id_by_email(&asserted).await.is_none());

    let email = unique_email("up-needed");
    let to = submit_flow_fields(
        &manual,
        at.as_str(),
        &[("traits.email", &email), ("provider", PLAYGROUND)],
    )
    .await
    .0;
    assert_eq!(to.path(), "/verification", "the address gets a code");
    assert!(
        identity_id_by_email(&email).await.is_none(),
        "nothing exists before the code"
    );
    assert!(provider_link_owner(PLAYGROUND, &sub).is_none());

    let mail = wait_for_mailcrab(&email, "verify your account", Duration::from_secs(15))
        .await
        .expect("sign-up code mailed");
    let code = extract_code_from_email(&mail.body).expect("code in mail");

    // The flow is bound to the browser that started the sign-up.
    let (_, stranger, _) = paired_clients();
    let res = stranger
        .get(to.as_str())
        .send()
        .await
        .expect("stranger GET");
    let stranger_sees_form = res.status().is_success()
        && res
            .text()
            .await
            .unwrap_or_default()
            .contains("name=\"code\"");
    assert!(!stranger_sees_form, "another browser does not get the flow");

    let (at, _) =
        submit_flow_fields(&manual, to.as_str(), &[("code", &code), ("method", "code")]).await;
    assert_eq!(at.path(), "/", "the code signs the new account in");
    let id = identity_id_by_email(&email)
        .await
        .expect("identity created by the code");
    assert!(address_verified(&id, &email).await);
    assert_eq!(
        provider_link_owner(PLAYGROUND, &sub).as_deref(),
        Some(id.as_str())
    );
    assert!(whoami_is_active(&manual).await);

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn settings_link_then_unlink_with_a_password() {
    assert!(portal_reachable().await);
    let user = register_test_user("up-link").await;
    let sub = subject("up-link");
    let anyone = unique_email("up-link-upstream");

    // A saved settings flow returns to its `return_to`, as on Kratos: the page opens a new flow.
    let (at, html) = provider_round_trip(
        &user.manual_client,
        LINKED,
        "link",
        &sub,
        &verified_claims(&anyone),
    )
    .await;
    assert_eq!(at.path(), "/settings/linked-providers");
    assert!(
        html.contains("name=\"unlink\""),
        "the linked provider offers unlink"
    );
    assert_eq!(
        provider_links(&user.identity_id),
        vec![(PLAYGROUND.to_string(), sub.clone())]
    );
    assert!(audit_row_exists("identity.oidc.linked", &user.identity_id));

    // A password remains, so the page offers unlink and it goes through without a provider hop.
    let to = press_provider(&user.manual_client, LINKED, "unlink", PLAYGROUND).await;
    assert!(
        to.as_str().starts_with(PORTAL),
        "unlink stays on Forseti: {to}"
    );
    assert!(provider_links(&user.identity_id).is_empty(), "link removed");
    assert!(audit_row_exists(
        "identity.oidc.unlinked",
        &user.identity_id
    ));

    user.cleanup().await;
}

#[tokio::test]
async fn settings_link_needs_a_verified_address() {
    assert!(portal_reachable().await);
    let user = register_test_user_unverified("up-link-unverified").await;

    let to = press_provider(&user.manual_client, LINKED, "link", PLAYGROUND).await;
    assert!(to.as_str().starts_with(PORTAL), "no provider hop: {to}");
    let page = user
        .client
        .get(to.as_str())
        .send()
        .await
        .expect("flow page")
        .text()
        .await
        .unwrap_or_default();
    assert!(
        page.contains("Account not active yet"),
        "4000010 shown: {}",
        page.chars().take(800).collect::<String>()
    );
    assert!(provider_links(&user.identity_id).is_empty());

    user.cleanup().await;
}

#[tokio::test]
async fn unlink_of_the_last_sign_in_method_is_refused() {
    assert!(portal_reachable().await);
    let (id, sub, auto, manual) = provider_sign_up("up-guard").await;

    let page = auto
        .get(LINKED)
        .send()
        .await
        .expect("linked providers")
        .text()
        .await
        .unwrap_or_default();
    assert!(
        !page.contains("name=\"unlink\""),
        "no unlink offered for the only sign-in method"
    );

    let (_, html) = submit_flow_fields(&manual, LINKED, &[("unlink", PLAYGROUND)]).await;
    assert!(
        html.contains(LAST_METHOD),
        "forged unlink answered with 4000001"
    );
    assert_eq!(
        provider_link_owner(PLAYGROUND, &sub).as_deref(),
        Some(id.as_str())
    );

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn refresh_through_the_provider_needs_a_fresh_auth_time() {
    assert!(portal_reachable().await);
    let (id, sub, _, manual) = provider_sign_up("up-refresh").await;
    let (_, signed_up_at) = session_auth(&manual).await.expect("session");
    let refresh = format!("{PORTAL}/self-service/login/browser?refresh=true");

    // mock-oidc ignores max_age=0 and sends no auth_time unless the claims carry one.
    let (at, html) = provider_round_trip(&manual, &refresh, "provider", &sub, &json!({})).await;
    assert_eq!(at.path(), "/login", "a refused refresh stays on the flow");
    assert!(
        html.contains(INVALID_CREDENTIALS),
        "4000006 without auth_time"
    );
    assert_eq!(
        session_auth(&manual).await.expect("session").1,
        signed_up_at
    );

    // The hop starts during the round trip, so this lies more than the 60 s skew before it.
    let before_hop = chrono::Utc::now().timestamp() - 120;
    let (at, _) = provider_round_trip(
        &manual,
        &refresh,
        "provider",
        &sub,
        &json!({ "auth_time": before_hop }),
    )
    .await;
    assert_eq!(
        at.path(),
        "/login",
        "a login from before the hop is refused"
    );

    let now = chrono::Utc::now().timestamp();
    let (at, _) = provider_round_trip(
        &manual,
        &refresh,
        "provider",
        &sub,
        &json!({ "auth_time": now }),
    )
    .await;
    assert_eq!(at.path(), "/", "a fresh login refreshes the session");
    let (methods, refreshed_at) = session_auth(&manual).await.expect("same session");
    assert!(refreshed_at > signed_up_at, "authenticated_at advanced");
    assert!(
        methods.as_array().is_some_and(|m| m
            .iter()
            .any(|m| m["method"] == "oidc" && m["provider"] == PLAYGROUND)),
        "{methods}"
    );

    // A provider account linked to another identity does not refresh this one.
    let (other, other_sub, _, _) = provider_sign_up("up-refresh-other").await;
    let (at, html) = provider_round_trip(
        &manual,
        &refresh,
        "provider",
        &other_sub,
        &json!({ "auth_time": now }),
    )
    .await;
    assert_eq!(at.path(), "/login");
    assert!(html.contains(INVALID_CREDENTIALS));

    delete_test_identity(&other).await.ok();
    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn recovery_of_a_never_verified_account_resets_it() {
    assert!(portal_reachable().await);
    let user = register_test_user_unverified("up-reset").await;
    let id = user.identity_id.clone();
    assert!(
        whoami_is_active(&user.client).await,
        "the registrant is signed in"
    );
    plant_totp(&id, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ");
    seed_provider_link(&id, PLAYGROUND, &subject("up-reset"));
    seed_offline_secret(
        &id,
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
    );
    assert_eq!(credential_kinds(&id), ["password", "totp"]);

    // The address owner recovers from another browser with the mailed code.
    let (anon, _, _) = paired_clients();
    let flow = browser_flow_id(&anon, "recovery", "").await;
    let page = format!("{PORTAL}/recovery?flow={flow}");
    submit_flow_fields(&anon, &page, &[("email", &user.email), ("method", "code")]).await;
    let mail = wait_for_mailcrab(&user.email, "recover access", Duration::from_secs(15))
        .await
        .expect("recovery code mailed");
    let code = extract_code_from_email(&mail.body).expect("code in mail");
    let (at, _) = submit_flow_fields(&anon, &page, &[("code", &code), ("method", "code")]).await;
    assert_eq!(
        at.path(),
        "/settings/password",
        "the recovery session sets a new password"
    );

    assert!(
        credential_kinds(&id).is_empty(),
        "password and TOTP removed"
    );
    assert!(provider_links(&id).is_empty(), "provider links removed");
    assert_eq!(
        kratos_identity_session_ids(&id).await.len(),
        1,
        "only the recovery session is left"
    );
    assert!(
        !whoami_is_active(&user.client).await,
        "the registrant's session is revoked"
    );
    assert!(whoami_is_active(&anon).await);
    assert!(address_verified(&id, &user.email).await);
    let offline: bool = rusqlite::Connection::open(forseti_db_path())
        .expect("db")
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM offline_secrets WHERE identity_id = ?1)",
            [&id],
            |r| r.get(0),
        )
        .expect("offline secret lookup");
    assert!(!offline, "offline passphrase removed");

    user.cleanup().await;
}
