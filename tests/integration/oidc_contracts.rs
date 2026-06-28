//! Hydra consent + id_token contract tests.
//!
//! These exercise the parts of the OAuth2 bridge that the existing
//! `oauth.rs` test doesn't: the consent DENY path, the full id_token claim
//! construction (email / profile / extended_profile / org / orgs), the
//! `/settings/authorized-apps` grant list + per-client revoke, and the
//! `organization_id` request param on the login challenge. All drive the real
//! Hydra playground — nothing is mocked. They're the early-warning system for
//! a Hydra upgrade silently changing the consent/claim shapes.

use crate::common::*;

/// Denying consent must reject the challenge with `access_denied` and bounce
/// the browser back to the client's redirect URI carrying that OAuth error —
/// not strand the user or 500. Guards `reject_consent_request`.
#[tokio::test]
async fn consent_deny_redirects_with_access_denied() {
    assert!(portal_reachable().await);

    let user = register_test_user("consent-deny").await;
    let (client_id, _secret, redirect_uri) =
        hydra_create_test_client(&["openid", "offline", "email"]).await;

    let auth_url = oauth_auth_url(&client_id, &redirect_uri, "openid offline email", "");
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;

    let location = consent_deny_chase_location(&user.manual_client, &csrf, &consent_challenge)
        .await
        .expect("deny should redirect to the client callback");
    assert!(
        location.contains(&redirect_uri),
        "deny should land on the client redirect URI; got {location}"
    );
    let error = extract_query_param(&location, "error").unwrap_or_default();
    assert_eq!(
        error, "access_denied",
        "denied consent must carry error=access_denied; full location {location}"
    );

    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

/// The id_token must carry every claim family the granted scopes ask for.
/// `oauth.rs` only proves `email` can be *dropped*; this proves the positive
/// construction: standard OIDC (`email`, `name`, `given_name`, `family_name`),
/// the Forseti profile slots (`picture`, `website`), the non-standard
/// `extended_profile` claims (`bio`, `pronouns`, `links`), and the org claims
/// (`org`, `orgs`). This is the richest Forseti-specific surface in the
/// consent path and the easiest to regress on a Hydra/claims refactor.
#[tokio::test]
async fn id_token_carries_email_profile_and_org_claims() {
    assert!(portal_reachable().await);

    let user = register_test_user("idtoken-claims").await;
    // Seed a profile so picture/website/extended_profile have something to
    // project (config.ci.toml has [profiles].enabled = true).
    seed_member_profile(
        &user.identity_id,
        "https://cdn.example.com/avatar.png",
        "https://example.com",
        "Building identity plumbing.",
        "they/them",
        &[("GitHub", "https://github.com/example")],
    );

    let scope = "openid email profile extended_profile org orgs";
    let (client_id, _secret, redirect_uri) = hydra_create_test_client(&[
        "openid",
        "email",
        "profile",
        "extended_profile",
        "org",
        "orgs",
        "offline",
    ])
    .await;

    let auth_url = oauth_auth_url(&client_id, &redirect_uri, scope, "");
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;

    let granted = [
        "openid",
        "email",
        "profile",
        "extended_profile",
        "org",
        "orgs",
    ];
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &granted,
        false,
    )
    .await
    .expect("authorization code on callback");

    let tokens = exchange_code_for_tokens(&client_id, &_secret, &redirect_uri, &code).await;
    let id_token = tokens["id_token"]
        .as_str()
        .expect("id_token in token response");
    let claims = decode_jwt_claims(id_token);

    // Subject is always the Kratos identity ID.
    assert_eq!(
        claims["sub"].as_str(),
        Some(user.identity_id.as_str()),
        "sub must be the Kratos identity ID"
    );

    // email scope.
    assert_eq!(
        claims["email"].as_str(),
        Some(user.email.as_str()),
        "email claim must match the registered address"
    );
    assert!(
        claims.get("email_verified").map(|v| v.is_boolean()) == Some(true),
        "email_verified must be present as a bool; claims: {claims}"
    );

    // profile scope: name flattened from {first,last}, plus profile slots.
    assert_eq!(claims["name"].as_str(), Some("Test User"));
    assert_eq!(claims["given_name"].as_str(), Some("Test"));
    assert_eq!(claims["family_name"].as_str(), Some("User"));
    assert_eq!(
        claims["picture"].as_str(),
        Some("https://cdn.example.com/avatar.png")
    );
    assert_eq!(claims["website"].as_str(), Some("https://example.com"));

    // extended_profile scope.
    assert_eq!(claims["bio"].as_str(), Some("Building identity plumbing."));
    assert_eq!(claims["pronouns"].as_str(), Some("they/them"));
    let links = claims["links"].as_array().expect("links claim is an array");
    assert_eq!(links.len(), 1, "one seeded link");
    assert_eq!(links[0]["label"].as_str(), Some("GitHub"));
    assert_eq!(links[0]["url"].as_str(), Some("https://github.com/example"));

    // org scope: active org (falls back to first membership = the seeded
    // default org the user auto-joined at registration).
    let org = claims["org"].as_object().expect("org claim is an object");
    assert!(
        org.get("slug").and_then(|v| v.as_str()).is_some(),
        "org claim must carry a slug; got {:?}",
        org
    );
    assert!(
        matches!(
            org.get("role").and_then(|v| v.as_str()),
            Some("owner") | Some("member")
        ),
        "org role must be a known role; got {:?}",
        org.get("role")
    );

    // orgs scope: full membership list, at least the default org.
    let orgs = claims["orgs"].as_array().expect("orgs claim is an array");
    assert!(
        !orgs.is_empty(),
        "orgs claim must list at least the default-org membership"
    );

    hydra_delete_client(&client_id).await;
    delete_member_profile(&user.identity_id);
    user.cleanup().await;
}

/// A remembered grant must surface on `/settings/authorized-apps`, and the
/// per-client revoke must wipe it from Hydra. Guards
/// `list_consent_sessions_by_subject` + `revoke_consent_sessions_for_client`.
#[tokio::test]
async fn authorized_apps_lists_then_revoke_clears_grant() {
    assert!(portal_reachable().await);

    let user = register_test_user("authzapps").await;
    let (client_id, _secret, redirect_uri) =
        hydra_create_test_client(&["openid", "offline", "email"]).await;

    // 1. Complete a consent with remember=true so Hydra persists a consent
    //    session for this (subject, client).
    let auth_url = oauth_auth_url(&client_id, &redirect_uri, "openid offline email", "");
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let _code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline", "email"],
        true,
    )
    .await
    .expect("authorization code on callback");

    assert!(
        hydra_consent_session_count(&user.identity_id).await >= 1,
        "Hydra should record a consent session after a remembered grant"
    );

    // 2. The grant should render on the authorized-apps page.
    let page = user
        .client
        .get(format!("{PORTAL}/settings/authorized-apps"))
        .send()
        .await
        .expect("GET /settings/authorized-apps");
    assert!(page.status().is_success());
    let body = page.text().await.unwrap_or_default();
    assert!(
        body.contains(&client_id) || body.contains("integration-test-client"),
        "authorized-apps page should list the granted client"
    );

    // 3. Revoke via the per-client form (needs the page CSRF token).
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf on authorized-apps page");
    let revoke = user
        .client
        .post(format!(
            "{PORTAL}/settings/authorized-apps/{client_id}/revoke"
        ))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST authorized-apps revoke");
    assert!(
        revoke.status().is_success() || revoke.status().is_redirection(),
        "revoke status {}",
        revoke.status()
    );

    // 4. Hydra should no longer hold a consent session for this subject.
    assert_eq!(
        hydra_consent_session_count(&user.identity_id).await,
        0,
        "per-client revoke must clear the Hydra consent session"
    );

    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

/// The login challenge accepts an `organization_id` request param (Forseti
/// parses it off Hydra's `request_url` to pre-select the active org). Driving
/// the authorize chain with it set must still complete to a usable code —
/// regression guard for the org-binding parse in `oauth/login.rs`.
#[tokio::test]
async fn oauth_authorize_with_organization_id_param_completes() {
    assert!(portal_reachable().await);

    let user = register_test_user("oauth-orgid").await;
    let (client_id, _secret, redirect_uri) =
        hydra_create_test_client(&["openid", "offline", "org"]).await;

    // DEFAULT_ORG_ID is the seeded org every identity auto-joins.
    let auth_url = oauth_auth_url(
        &client_id,
        &redirect_uri,
        "openid offline org",
        "&organization_id=default",
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline", "org"],
        false,
    )
    .await
    .expect("authorize with organization_id should still yield a code");

    let tokens = exchange_code_for_tokens(&client_id, &_secret, &redirect_uri, &code).await;
    assert!(
        tokens["id_token"].as_str().is_some(),
        "token exchange after organization_id authorize must succeed"
    );

    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

/// `/handoff` must validate the referrer against Hydra (`get_client`) and
/// origin-match the `referrer_uri` against the client's registered URIs
/// before setting the app-referrer banner cookie. A matching origin sets the
/// signed cookie; a mismatched origin (the open-redirect-style attack the
/// origin check exists to stop) is rejected with no cookie.
#[tokio::test]
async fn handoff_validates_client_and_origin_matches_referrer() {
    assert!(portal_reachable().await);

    // The test client registers redirect_uri http://127.0.0.1:5555/callback,
    // so its origin is http://127.0.0.1:5555.
    let (client_id, _secret, _redirect_uri) =
        hydra_create_test_client(&["openid", "offline"]).await;
    let client = manual_redirect_client();

    // Matching origin → cookie set, 30x to the per-action target.
    let res = client
        .get(format!(
            "{PORTAL}/handoff?referrer={client_id}&referrer_uri=http://127.0.0.1:5555/back&action=password"
        ))
        .send()
        .await
        .expect("GET /handoff (match)");
    assert!(
        res.status().is_redirection(),
        "valid handoff should redirect; got {}",
        res.status()
    );
    let set_cookie = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        set_cookie.contains("forseti_app_referrer"),
        "matching-origin handoff must set the app-referrer cookie; headers: {set_cookie}"
    );

    // Mismatched origin → 400, no cookie (the spoofed-banner guard).
    let res = client
        .get(format!(
            "{PORTAL}/handoff?referrer={client_id}&referrer_uri=https://attacker.example/x&action=password"
        ))
        .send()
        .await
        .expect("GET /handoff (mismatch)");
    assert_eq!(
        res.status().as_u16(),
        400,
        "origin-mismatched referrer_uri must be rejected"
    );
    let set_cookie = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.contains("forseti_app_referrer"));
    assert!(
        !set_cookie,
        "a rejected handoff must not set the app-referrer cookie"
    );

    hydra_delete_client(&client_id).await;
}
