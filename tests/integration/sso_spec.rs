//! Forseti as a standard OP: discovery, logout by `sid`, `prompt` handling,
//! remembered consent and the authorize shim.

use crate::common::*;

/// Discovery advertises only what Forseti serves (Discovery 1.0 §3).
#[tokio::test]
async fn discovery_advertises_only_supported_features() {
    assert!(portal_reachable().await);

    let doc: serde_json::Value = browser_client()
        .get("http://host.containers.internal:3000/hydra/.well-known/openid-configuration")
        .send()
        .await
        .expect("discovery transport")
        .json()
        .await
        .expect("discovery json");

    assert_eq!(doc["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(
        doc["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(
        doc["prompt_values_supported"],
        serde_json::json!(["none", "login", "consent", "create"])
    );
    assert_eq!(
        doc["acr_values_supported"],
        serde_json::json!(["aal1", "aal2"])
    );
    for (key, value) in doc.as_object().unwrap() {
        if key.ends_with("_signing_alg_values_supported") {
            assert!(
                !value.as_array().unwrap().iter().any(|a| a == "none"),
                "{key} must not advertise `none`"
            );
        }
        assert!(!key.starts_with("credentials_"), "{key} must be dropped");
    }
    let listed = |key: &str| -> Vec<String> {
        doc[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} missing"))
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    };
    let scopes = listed("scopes_supported");
    for s in [
        "openid",
        "offline_access",
        "email",
        "profile",
        "org",
        "orgs",
        "groups",
    ] {
        assert!(
            scopes.iter().any(|x| x == s),
            "scopes_supported lacks {s}: {scopes:?}"
        );
    }
    let claims = listed("claims_supported");
    for c in [
        "sub",
        "sid",
        "email",
        "email_verified",
        "preferred_username",
        "groups",
    ] {
        assert!(
            claims.iter().any(|x| x == c),
            "claims_supported lacks {c}: {claims:?}"
        );
    }
    assert_eq!(doc["backchannel_logout_supported"], serde_json::json!(true));
}

// --- Logout by `sid` (goal 1) ----------------------------------------------

pub(crate) struct Browser {
    pub(crate) client: reqwest::Client,
    pub(crate) manual: reqwest::Client,
}

/// A second, separately signed-in browser for `user`.
async fn second_browser(user: &RegisteredUser) -> Browser {
    let (client, manual, _jar) = paired_clients();
    password_login_aal1(&client, &user.email, &user.password).await;
    Browser { client, manual }
}

/// Authorize `client_id` in `browser` through the consent screen; returns the
/// ID token's `sid` and the refresh token.
pub(crate) async fn authorize(
    browser: &Browser,
    client_id: &str,
    secret: &str,
    redirect_uri: &str,
) -> (String, String) {
    let auth_url = oauth_auth_url(client_id, redirect_uri, "openid offline_access", "");
    let (challenge, csrf, _) = drive_to_consent(&browser.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &browser.manual,
        &csrf,
        &challenge,
        &["openid", "offline_access"],
        false,
    )
    .await
    .expect("authorization code");
    let tokens = exchange_code_for_tokens(client_id, secret, redirect_uri, &code).await;
    let sid = decode_jwt_claims(tokens["id_token"].as_str().expect("id_token"))["sid"]
        .as_str()
        .expect("sid claim")
        .to_string();
    (
        sid,
        tokens["refresh_token"]
            .as_str()
            .expect("refresh_token")
            .to_string(),
    )
}

/// One user signed in on two browsers, plus a back-channel client posting to `sink`.
async fn two_browsers_authorized(
    prefix: &str,
    sink: &BackchannelSink,
) -> (RegisteredUser, Browser, Browser, (String, String, String)) {
    let user = register_test_user(prefix).await;
    mark_identity_verified(&user.identity_id).await;
    let a = Browser {
        client: user.client.clone(),
        manual: user.manual_client.clone(),
    };
    let b = second_browser(&user).await;
    let rp = hydra_create_backchannel_client(&["openid", "offline_access"], &sink.url).await;
    (user, a, b, rp)
}

#[tokio::test]
async fn dashboard_logout_sends_backchannel_for_that_browser_only() {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let (user, a, b, (id, secret, redirect)) =
        two_browsers_authorized("bc-logout-one", &sink).await;
    let (sid_a, _) = authorize(&a, &id, &secret, &redirect).await;
    let (sid_b, refresh_b) = authorize(&b, &id, &secret, &redirect).await;
    assert_ne!(sid_a, sid_b, "two browsers must hold two Hydra sessions");

    let body = a
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings")
        .text()
        .await
        .expect("settings body");
    let csrf = extract_csrf_form_token(&body).expect("_csrf on /settings");
    a.client
        .post(format!("{PORTAL}/logout"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST /logout");

    assert_eq!(sink.sids_after(1, 10).await, vec![sid_a]);
    assert!(
        refresh_succeeds(&id, &secret, &refresh_b).await,
        "the other browser's grant must survive"
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn revoke_others_keeps_current_browser() {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let (user, a, b, (id, secret, redirect)) =
        two_browsers_authorized("bc-revoke-others", &sink).await;
    let (_sid_a, refresh_a) = authorize(&a, &id, &secret, &redirect).await;
    let (sid_b, refresh_b) = authorize(&b, &id, &secret, &redirect).await;

    let body = a
        .client
        .get(format!("{PORTAL}/settings/sessions"))
        .send()
        .await
        .expect("GET /settings/sessions")
        .text()
        .await
        .unwrap_or_default();
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf on sessions page");
    a.client
        .post(format!("{PORTAL}/settings/sessions/revoke-others"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST revoke-others");

    assert_eq!(sink.sids_after(1, 10).await, vec![sid_b]);
    assert!(
        whoami_is_active(&a.client).await,
        "current browser stays signed in"
    );
    assert!(
        !refresh_succeeds(&id, &secret, &refresh_b).await,
        "the other browser's grant must die"
    );
    assert!(
        refresh_succeeds(&id, &secret, &refresh_a).await,
        "the current browser keeps its grant"
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn admin_disable_sends_backchannel_for_every_session() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!(
            "Skipping admin_disable_sends_backchannel_for_every_session: admin env-vars not set"
        );
        return;
    };
    let sink = BackchannelSink::start().await;
    let (user, a, b, (id, secret, redirect)) =
        two_browsers_authorized("bc-admin-disable", &sink).await;
    let (sid_a, _) = authorize(&a, &id, &secret, &redirect).await;
    let (sid_b, _) = authorize(&b, &id, &secret, &redirect).await;

    let confirm = format!("{PORTAL}/admin/identities/{}/disable", user.identity_id);
    let body = admin
        .get(&confirm)
        .send()
        .await
        .expect("GET disable confirm")
        .text()
        .await
        .unwrap_or_default();
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf in disable confirm");
    admin
        .post(&confirm)
        .form(&[("_csrf", csrf.as_str()), ("confirm", "yes")])
        .send()
        .await
        .expect("POST disable");

    let mut got = sink.sids_after(2, 10).await;
    got.sort();
    let mut want = vec![sid_a, sid_b];
    want.sort();
    assert_eq!(got, want);

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

// --- Security events revoke grants, logout keeps them ------------------------

/// Authorize a `skip_consent` client in `browser` (no consent screen); returns
/// the ID token's `sid` and the refresh token.
async fn authorize_skip_consent(
    browser: &Browser,
    client_id: &str,
    secret: &str,
    redirect_uri: &str,
) -> (String, String) {
    let auth_url = oauth_auth_url(client_id, redirect_uri, "openid offline_access", "");
    let loc = authorize_chase_callback(&browser.manual, &auth_url)
        .await
        .expect("skip_consent authorize reaches the client");
    let code = extract_query_param(&loc, "code").expect("authorization code");
    let tokens = exchange_code_for_tokens(client_id, secret, redirect_uri, &code).await;
    let sid = decode_jwt_claims(tokens["id_token"].as_str().expect("id_token"))["sid"]
        .as_str()
        .expect("sid claim")
        .to_string();
    (
        sid,
        tokens["refresh_token"]
            .as_str()
            .expect("refresh_token")
            .to_string(),
    )
}

/// Revoke `target`'s Kratos session from `from` through `/settings/sessions`.
async fn revoke_session_from(from: &Browser, target: &Browser) {
    let ksid = whoami_session_id(&target.client)
        .await
        .expect("target browser has a session");
    let body = from
        .client
        .get(format!("{PORTAL}/settings/sessions"))
        .send()
        .await
        .expect("GET /settings/sessions")
        .text()
        .await
        .unwrap_or_default();
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf on sessions page");
    let res = from
        .client
        .post(format!("{PORTAL}/settings/sessions/{ksid}/revoke"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST session revoke");
    assert!(
        res.status().is_success() || res.status().is_redirection(),
        "session revoke status {}",
        res.status()
    );
}

/// Revoking a session is a security event (RFC 9700 §4.14.2): its app
/// sessions end and its grants die, including refresh tokens minted by a
/// later refresh in the chain. `skip_consent` settles whether Hydra still
/// routes such clients through Forseti's consent endpoint.
async fn revoke_session_kills_the_grant_for(skip_consent: bool) {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let (user, a, b, (id, secret, redirect)) =
        two_browsers_authorized("bc-revoke-grant", &sink).await;
    if skip_consent {
        mark_client_verified(&id);
        hydra_set_client_skip_consent(&id, true).await;
    }
    let (sid_b, refresh_b) = if skip_consent {
        authorize_skip_consent(&b, &id, &secret, &redirect).await
    } else {
        authorize(&b, &id, &secret, &redirect).await
    };
    let rotated = refresh_tokens(&id, &secret, &refresh_b)
        .await
        .expect("refresh before the revoke");
    let refresh_b = rotated["refresh_token"]
        .as_str()
        .expect("rotated refresh_token")
        .to_string();

    revoke_session_from(&a, &b).await;

    assert_eq!(sink.sids_after(1, 10).await, vec![sid_b]);
    assert!(
        !refresh_succeeds(&id, &secret, &refresh_b).await,
        "the revoked session's grant must die (skip_consent: {skip_consent})"
    );

    hydra_delete_client(&id).await;
    if skip_consent {
        delete_client_metadata(&id);
    }
    user.cleanup().await;
}

#[tokio::test]
async fn revoke_session_kills_the_grant() {
    revoke_session_kills_the_grant_for(false).await;
}

#[tokio::test]
async fn revoke_session_kills_a_skip_consent_grant() {
    revoke_session_kills_the_grant_for(true).await;
}

/// A password change ends the other browsers' app sessions and grants and
/// keeps the current one (RFC 9700 §4.14.2, ASVS V3.3.3).
#[tokio::test]
async fn password_change_signs_out_other_browsers_and_kills_grants() {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let (user, a, b, (id, secret, redirect)) =
        two_browsers_authorized("bc-password-change", &sink).await;
    let (_sid_a, refresh_a) = authorize(&a, &id, &secret, &redirect).await;
    let (sid_b, refresh_b) = authorize(&b, &id, &secret, &redirect).await;

    kratos_change_password(&a.client, &format!("{}-changed", user.password)).await;

    assert_eq!(sink.sids_after(1, 15).await, vec![sid_b]);
    assert!(
        !refresh_succeeds(&id, &secret, &refresh_b).await,
        "the other browser's grant must die"
    );
    assert!(
        refresh_succeeds(&id, &secret, &refresh_a).await,
        "the browser that changed the password keeps its grant"
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

/// Plain logout ends the browser's app sessions but keeps offline grants
/// (Back-Channel Logout 1.0 §2.7).
#[tokio::test]
async fn logout_keeps_offline_grants() {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let (user, a, _b, (id, secret, redirect)) =
        two_browsers_authorized("bc-logout-keeps", &sink).await;
    let (sid_a, refresh_a) = authorize(&a, &id, &secret, &redirect).await;

    let body = a
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings")
        .text()
        .await
        .expect("settings body");
    let csrf = extract_csrf_form_token(&body).expect("_csrf on /settings");
    a.client
        .post(format!("{PORTAL}/logout"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST /logout");

    assert_eq!(sink.sids_after(1, 10).await, vec![sid_a]);
    assert!(
        refresh_succeeds(&id, &secret, &refresh_a).await,
        "an offline grant survives plain logout"
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

// --- `prompt=none` and errors back to the RP (goals 2, 4) -------------------

/// Assert `callback` is the client's redirect carrying `error` and our `state`.
fn assert_rp_error(callback: Option<String>, error: &str) {
    let loc = callback.unwrap_or_else(|| panic!("expected a redirect to the client with {error}"));
    assert_eq!(
        extract_query_param(&loc, "error").as_deref(),
        Some(error),
        "{loc}"
    );
    assert_eq!(
        extract_query_param(&loc, "state").as_deref(),
        Some("forseti-test-state"),
        "{loc}"
    );
}

/// Authorize once interactively so Hydra remembers the login; returns the code.
async fn first_authorize(
    user: &RegisteredUser,
    client_id: &str,
    redirect: &str,
    scope: &str,
) -> String {
    let auth_url = oauth_auth_url(client_id, redirect, scope, "");
    let (challenge, csrf, _) = drive_to_consent(&user.client, &auth_url).await;
    let scopes: Vec<&str> = scope.split(' ').collect();
    consent_accept_chase_code(&user.manual_client, &csrf, &challenge, &scopes, false)
        .await
        .expect("authorization code")
}

#[tokio::test]
async fn prompt_none_without_kratos_session_returns_login_required() {
    assert!(portal_reachable().await);
    let user = register_test_user("prompt-none-signed-out").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    first_authorize(&user, &id, &redirect, "openid").await;

    kratos_admin_end_sessions(&user.identity_id).await;
    let url = oauth_auth_url(&id, &redirect, "openid", "&prompt=none");
    assert_rp_error(
        authorize_chase_callback(&user.manual_client, &url).await,
        "login_required",
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn prompt_none_needing_step_up_returns_login_required() {
    assert!(portal_reachable().await);
    let user = register_test_user("prompt-none-step-up").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    first_authorize(&user, &id, &redirect, "openid").await;

    let url = oauth_auth_url(&id, &redirect, "openid", "&prompt=none&acr_values=aal2");
    assert_rp_error(
        authorize_chase_callback(&user.manual_client, &url).await,
        "login_required",
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn prompt_none_with_username_step_returns_interaction_required() {
    assert!(portal_reachable().await);
    // A fresh account without a username would see the username step on a
    // `profile` request; the first authorize asks for `openid` only.
    let user = register_test_user_with_username_step("prompt-none-username").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid", "profile"]).await;
    first_authorize(&user, &id, &redirect, "openid").await;

    let url = oauth_auth_url(&id, &redirect, "openid profile", "&prompt=none");
    assert_rp_error(
        authorize_chase_callback(&user.manual_client, &url).await,
        "interaction_required",
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn prompt_none_unvouched_client_returns_consent_required() {
    assert!(portal_reachable().await);
    let user = register_test_user("prompt-none-consent").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    // Consent not remembered, so the next request needs the consent screen.
    first_authorize(&user, &id, &redirect, "openid").await;

    let url = oauth_auth_url(&id, &redirect, "openid", "&prompt=none");
    assert_rp_error(
        authorize_chase_callback(&user.manual_client, &url).await,
        "consent_required",
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

/// `none` with another value (OIDC Core 3.1.2.1) never reaches Forseti: with
/// `login` in the value Hydra v26 disregards the remembered session and
/// answers `login_required` itself. Either way the client gets an error, not
/// a code.
#[tokio::test]
async fn prompt_none_with_another_value_is_an_error() {
    assert!(portal_reachable().await);
    let user = register_test_user("prompt-none-login").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    first_authorize(&user, &id, &redirect, "openid").await;

    let url = oauth_auth_url(&id, &redirect, "openid", "&prompt=none+login");
    assert_rp_error(
        authorize_chase_callback(&user.manual_client, &url).await,
        "login_required",
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

/// A consent failure while the challenge is valid goes back to the client
/// as an OAuth error, not to Forseti's `/error`.
#[tokio::test]
async fn consent_failure_returns_server_error_to_client() {
    assert!(portal_reachable().await);
    let user = register_test_user("consent-server-error").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    let auth_url = oauth_auth_url(&id, &redirect, "openid", "");
    let (challenge, csrf, _) = drive_to_consent(&user.client, &auth_url).await;

    let mut resp = user
        .manual_client
        .post(format!("{PORTAL}/oauth/consent"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("consent_challenge", challenge.as_str()),
            ("decision", "bogus"),
        ])
        .send()
        .await
        .expect("POST consent");
    let mut callback = None;
    for _ in 0..10 {
        let Some(next) = next_hop(resp).await else {
            break;
        };
        assert_ne!(next.path(), "/error", "must not land on Forseti's /error");
        if next.path().contains("/callback") {
            callback = Some(next.to_string());
            break;
        }
        resp = user.manual_client.get(next).send().await.expect("hop");
    }
    assert_rp_error(callback, "server_error");

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

/// The double sign-in: Hydra still remembers user A's login on this browser
/// after A's Kratos session ended elsewhere, and B signs in through an app.
/// Forseti ends A's Hydra session (back-channel logout for it) and restarts
/// the authorize request, so B signs in once.
#[tokio::test]
async fn stale_hydra_login_for_other_subject_signs_in_once() {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let a = register_test_user("stale-login-a").await;
    let b = register_test_user("stale-login-b").await;
    mark_identity_verified(&b.identity_id).await;
    let (id, secret, redirect) = hydra_create_backchannel_client(&["openid"], &sink.url).await;

    let code = first_authorize(&a, &id, &redirect, "openid").await;
    let tokens = exchange_code_for_tokens(&id, &secret, &redirect, &code).await;
    let sid_a = decode_jwt_claims(tokens["id_token"].as_str().unwrap())["sid"]
        .as_str()
        .unwrap()
        .to_string();

    kratos_admin_end_sessions(&a.identity_id).await;
    password_login_aal1(&a.client, &b.email, &b.password).await;

    // Walk the chain by hand: two login challenges (the stale one, then a
    // fresh one), no sign-in page, and the consent screen for B.
    let auth_url = oauth_auth_url(&id, &redirect, "openid", "");
    let mut resp = a
        .manual_client
        .get(&auth_url)
        .send()
        .await
        .expect("authorize");
    let mut challenges = Vec::new();
    let consent = loop {
        let next = next_hop(resp).await.expect("chain continues");
        assert_ne!(next.path(), "/login", "B is signed in; no sign-in page");
        if let Some(c) = extract_query_param(next.as_str(), "login_challenge") {
            challenges.push(c);
        }
        if next.path() == "/oauth/consent" {
            break next;
        }
        assert!(challenges.len() <= 2, "more than one restart");
        resp = a.manual_client.get(next).send().await.expect("hop");
    };
    assert_eq!(
        challenges.len(),
        2,
        "the stale challenge is abandoned for a fresh one"
    );
    assert_ne!(challenges[0], challenges[1]);

    let body = a
        .client
        .get(consent)
        .send()
        .await
        .expect("consent")
        .text()
        .await
        .unwrap();
    let challenge = extract_input_value(&body, "consent_challenge").expect("consent_challenge");
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf");
    let code = consent_accept_chase_code(&a.manual_client, &csrf, &challenge, &["openid"], false)
        .await
        .expect("code for B");
    let tokens = exchange_code_for_tokens(&id, &secret, &redirect, &code).await;
    assert_eq!(
        decode_jwt_claims(tokens["id_token"].as_str().unwrap())["sub"],
        serde_json::json!(b.identity_id)
    );
    assert_eq!(sink.sids_after(1, 10).await, vec![sid_a]);

    hydra_delete_client(&id).await;
    a.cleanup().await;
    b.cleanup().await;
}

/// A remembered login replayed into a browser signed in as someone else, while
/// its own Kratos session is still live, is refused and revokes nothing.
#[tokio::test]
async fn stale_hydra_login_with_live_session_rejects_login_required() {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let a = register_test_user("stale-live-a").await;
    let b = register_test_user("stale-live-b").await;
    mark_identity_verified(&a.identity_id).await;
    mark_identity_verified(&b.identity_id).await;
    let (id, _secret, redirect) = hydra_create_backchannel_client(&["openid"], &sink.url).await;

    // A authorizes in a browser whose cookie jar we can read.
    let (a_client, a_manual, a_jar) = paired_clients();
    password_login_aal1(&a_client, &a.email, &a.password).await;
    let auth_url = oauth_auth_url(&id, &redirect, "openid", "");
    let (challenge, csrf, _) = drive_to_consent(&a_client, &auth_url).await;
    consent_accept_chase_code(&a_manual, &csrf, &challenge, &["openid"], false)
        .await
        .expect("code for A");

    // B's browser carries A's Hydra cookies; A's Kratos session stays live.
    let (b_client, b_manual, b_jar) = paired_clients();
    password_login_aal1(&b_client, &b.email, &b.password).await;
    let hydra: reqwest::Url = HYDRA_PUBLIC.parse().unwrap();
    let hydra_cookies = reqwest::cookie::CookieStore::cookies(a_jar.as_ref(), &hydra)
        .expect("A holds Hydra cookies")
        .to_str()
        .unwrap()
        .to_string();
    for c in hydra_cookies.split("; ") {
        b_jar.add_cookie_str(&format!("{c}; Path=/"), &hydra);
    }

    let callback = authorize_chase_callback(&b_manual, &auth_url).await;
    assert_rp_error(callback, "login_required");
    assert!(sink.sids_after(1, 3).await.is_empty(), "nothing is revoked");

    hydra_delete_client(&id).await;
    a.cleanup().await;
    b.cleanup().await;
}

/// Logout also ends the `sid`s of a Kratos session the browser rotated away
/// from.
#[tokio::test]
async fn logout_sweeps_a_rotated_browsers_dead_sid() {
    assert!(portal_reachable().await);
    let sink = BackchannelSink::start().await;
    let user = register_test_user("bc-sweep").await;
    mark_identity_verified(&user.identity_id).await;
    let (id, secret, redirect) =
        hydra_create_backchannel_client(&["openid", "offline_access"], &sink.url).await;
    let a = Browser {
        client: user.client.clone(),
        manual: user.manual_client.clone(),
    };
    let (sid, _) = authorize(&a, &id, &secret, &redirect).await;

    // The Kratos session the sid was recorded against ends; the browser
    // signs in again under a new one.
    kratos_admin_end_sessions(&user.identity_id).await;
    password_login_aal1(&a.client, &user.email, &user.password).await;

    let body = a
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings")
        .text()
        .await
        .expect("settings body");
    let csrf = extract_csrf_form_token(&body).expect("_csrf on /settings");
    a.client
        .post(format!("{PORTAL}/logout"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST /logout");

    assert_eq!(sink.sids_after(1, 10).await, vec![sid]);

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

/// Under `prompt=none` an `organization_id` the user would have to join is
/// ignored, so the response doesn't reveal whether they could join it.
#[tokio::test]
async fn prompt_none_ignores_an_org_the_user_would_have_to_join() {
    assert!(portal_reachable().await);
    let user = register_test_user("prompt-none-org").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    mark_client_verified(&id);
    hydra_set_client_skip_consent(&id, true).await;
    let org_id = uuid::Uuid::new_v4().to_string();
    let slug = format!("pn-{}", &org_id[..8]);
    seed_organization(&org_id, &slug, "Prompt None Org", "all");
    open_org_signup(&org_id);

    let first = oauth_auth_url(&id, &redirect, "openid", "");
    authorize_chase_callback(&user.manual_client, &first)
        .await
        .expect("auto-granted first authorize");

    let silent = oauth_auth_url(
        &id,
        &redirect,
        "openid",
        &format!("&prompt=none&organization_id={org_id}"),
    );
    let loc = authorize_chase_callback(&user.manual_client, &silent)
        .await
        .expect("prompt=none reaches the client");
    assert!(
        extract_query_param(&loc, "code").is_some(),
        "the pin is ignored, not answered with interaction_required: {loc}"
    );

    delete_organization(&org_id);
    hydra_delete_client(&id).await;
    delete_client_metadata(&id);
    user.cleanup().await;
}

/// The consent screen is the challenge owner's: another account's browser
/// opening it gets `access_denied` at the client instead of a page with the
/// owner's email and requested scopes.
#[tokio::test]
async fn consent_page_from_another_session_is_rejected() {
    assert!(portal_reachable().await);
    let a = register_test_user("consent-view2-a").await;
    let b = register_test_user("consent-view2-b").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;

    let auth_url = oauth_auth_url(&id, &redirect, "openid", "");
    let (challenge, _csrf_a, _) = drive_to_consent(&a.client, &auth_url).await;

    let consent_url = format!(
        "{PORTAL}/oauth/consent?consent_challenge={}",
        form_urlencode(&challenge)
    );
    let callback = authorize_chase_callback(&b.manual_client, &consent_url).await;
    assert_rp_error(callback, "access_denied");

    hydra_delete_client(&id).await;
    a.cleanup().await;
    b.cleanup().await;
}

/// A deny posted from a browser signed in as someone else hits the subject
/// gate first, so it is never recorded as the challenge owner's decision.
#[tokio::test]
async fn consent_deny_from_another_session_is_rejected() {
    assert!(portal_reachable().await);
    let a = register_test_user("consent-deny-a").await;
    let b = register_test_user("consent-deny-b").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;

    let auth_url = oauth_auth_url(&id, &redirect, "openid", "");
    let (challenge, _csrf_a, _) = drive_to_consent(&a.client, &auth_url).await;

    let body = b
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings as B")
        .text()
        .await
        .expect("settings body");
    let csrf_b = extract_csrf_form_token(&body).expect("_csrf on /settings");
    let loc = consent_deny_chase_location(&b.manual_client, &csrf_b, &challenge).await;
    assert_rp_error(loc, "access_denied");
    assert_eq!(
        count_audit_events_for_target("oauth.consent.denied", &id),
        0,
        "B's deny must not be recorded as A's decision"
    );

    hydra_delete_client(&id).await;
    a.cleanup().await;
    b.cleanup().await;
}

// --- Remembered consent (goal 3) ---------------------------------------------

#[tokio::test]
async fn skip_consent_client_prompt_none_returns_code_on_second_authorize() {
    assert!(portal_reachable().await);
    let user = register_test_user("remember-skip-consent").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    mark_client_verified(&id);
    hydra_set_client_skip_consent(&id, true).await;

    let first = oauth_auth_url(&id, &redirect, "openid", "");
    let loc = authorize_chase_callback(&user.manual_client, &first)
        .await
        .expect("auto-granted first authorize");
    assert!(extract_query_param(&loc, "code").is_some(), "{loc}");

    let silent = oauth_auth_url(&id, &redirect, "openid", "&prompt=none");
    let loc = authorize_chase_callback(&user.manual_client, &silent)
        .await
        .expect("prompt=none reaches the client");
    assert!(
        extract_query_param(&loc, "code").is_some(),
        "silent sign-in: {loc}"
    );

    hydra_delete_client(&id).await;
    delete_client_metadata(&id);
    user.cleanup().await;
}

#[tokio::test]
async fn org_vouched_remembered_consent_is_not_shown_again() {
    assert!(portal_reachable().await);
    let user = register_test_user("remember-org-vouched").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    mark_client_org_verified(&id);

    let auth_url = oauth_auth_url(&id, &redirect, "openid", "");
    let (challenge, csrf, body) = drive_to_consent(&user.client, &auth_url).await;
    assert!(
        body.contains("name=\"remember\""),
        "org-vouched clients offer remember"
    );
    consent_accept_chase_code(&user.manual_client, &csrf, &challenge, &["openid"], true)
        .await
        .expect("first code");

    let loc = authorize_chase_callback(&user.manual_client, &auth_url)
        .await
        .expect("second authorize skips the consent page");
    assert!(extract_query_param(&loc, "code").is_some(), "{loc}");

    hydra_delete_client(&id).await;
    delete_client_metadata(&id);
    user.cleanup().await;
}

// --- The authorize endpoint (goals 5, 7) -------------------------------------

/// `/oauth2/authorize` on the portal origin (Forseti's authorization endpoint).
/// On the issuer's origin, as discovery advertises it: Hydra's CSRF cookie is
/// host-scoped, and a flow resumed on another host fails `request_forbidden`.
fn shim_url(client_id: &str, redirect: &str, extra: &str) -> String {
    format!(
        "http://host.containers.internal:3000/oauth2/authorize?client_id={}&response_type=code&scope=openid\
         &redirect_uri={}&state=forseti-test-state{extra}",
        form_urlencode(client_id),
        form_urlencode(redirect),
    )
}

/// Follow `resp` hop by hop on `client` until a hop's path is `path`.
async fn chase_to_path(
    client: &reqwest::Client,
    mut resp: reqwest::Response,
    path: &str,
) -> Option<reqwest::Url> {
    for _ in 0..15 {
        let next = next_hop(resp).await?;
        if next.path() == path {
            return Some(next);
        }
        resp = client.get(next).send().await.ok()?;
    }
    None
}

#[tokio::test]
async fn authorize_via_post_completes_with_a_code() {
    assert!(portal_reachable().await);
    let user = register_test_user("post-authorize").await;
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    let form = [
        ("client_id", id.as_str()),
        ("response_type", "code"),
        ("scope", "openid"),
        ("redirect_uri", redirect.as_str()),
        ("state", "forseti-test-state"),
    ];
    let resp = user
        .manual_client
        .post("http://host.containers.internal:3000/oauth2/authorize")
        .form(&form)
        .send()
        .await
        .expect("POST authorize");
    assert_eq!(resp.status().as_u16(), 303);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location")
        .to_string();
    let hydra_auth = resp.url().join(&location).expect("Location resolves");
    assert!(hydra_auth.path().ends_with("/oauth2/auth"), "{hydra_auth}");
    assert_eq!(
        extract_query_param(hydra_auth.as_str(), "client_id").as_deref(),
        Some(id.as_str())
    );

    // Login and consent resume from Hydra's stored request URL, so the
    // parameters must survive into it.
    let (challenge, csrf, _) = drive_to_consent(&user.client, hydra_auth.as_str()).await;
    let code =
        consent_accept_chase_code(&user.manual_client, &csrf, &challenge, &["openid"], false).await;
    assert!(
        code.is_some(),
        "a POSTed authorization request ends in a code"
    );

    hydra_delete_client(&id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn prompt_create_lands_on_registration_with_challenge() {
    assert!(portal_reachable().await);
    let (id, secret, redirect) = hydra_create_test_client(&["openid"]).await;
    let (client, manual, _jar) = paired_clients();
    let resp = manual
        .get(shim_url(&id, &redirect, "&prompt=create"))
        .send()
        .await
        .expect("authorize");
    let reg = chase_to_path(&manual, resp, "/registration")
        .await
        .expect("prompt=create lands on sign-up");
    let return_to = extract_query_param(reg.as_str(), "return_to").expect("return_to");
    assert!(
        return_to.contains("/oauth/login?login_challenge="),
        "{return_to}"
    );

    // Sign up in the same browser, then pick the flow back up where sign-up's
    // Continue would: the challenge is still good and ends in a code.
    let (identity_id, _email, _pw) = register_test_user_with_client(&client, "prompt-create").await;
    let resp = manual.get(&return_to).send().await.expect("resume login");
    let consent = chase_to_path(&manual, resp, "/oauth/consent")
        .await
        .expect("consent after sign-up");
    let body = client
        .get(consent)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let challenge = extract_input_value(&body, "consent_challenge").expect("consent_challenge");
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf");
    let code = consent_accept_chase_code(&manual, &csrf, &challenge, &["openid"], false)
        .await
        .expect("code for the new account");
    let tokens = exchange_code_for_tokens(&id, &secret, &redirect, &code).await;
    assert_eq!(
        decode_jwt_claims(tokens["id_token"].as_str().unwrap())["sub"],
        serde_json::json!(identity_id)
    );

    hydra_delete_client(&id).await;
    let _ = delete_test_identity(&identity_id).await;
}

#[tokio::test]
async fn login_hint_prefills_identifier() {
    assert!(portal_reachable().await);
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    let client = browser_client();
    let body = client
        .get(shim_url(&id, &redirect, "&login_hint=hinted%40example.com"))
        .send()
        .await
        .expect("authorize")
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("value=\"hinted@example.com\""),
        "the sign-in identifier is prefilled from login_hint"
    );
    hydra_delete_client(&id).await;
}

/// The CIMD limiter guards URL-shaped client_ids only: a busy first-party app
/// behind one NAT never sees a 429.
#[tokio::test]
async fn non_cimd_authorize_is_not_rate_limited() {
    assert!(portal_reachable().await);
    let (id, _secret, redirect) = hydra_create_test_client(&["openid"]).await;
    let client = manual_redirect_client();
    for _ in 0..60 {
        let res = client
            .get(shim_url(&id, &redirect, ""))
            .send()
            .await
            .expect("authorize");
        assert_ne!(
            res.status().as_u16(),
            429,
            "non-CIMD authorize must not be limited"
        );
    }
    // The CIMD half isn't asserted here: the test configs raise
    // `[oauth.cimd]` limits to 1000/min so the CIMD suite can run.
    hydra_delete_client(&id).await;
}
