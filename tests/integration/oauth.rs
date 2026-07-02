//! OAuth2 authorization-code flow end-to-end via the portal bridge.

use crate::common::*;

#[tokio::test]
async fn auth_code_flow_with_reduced_scope_drops_email_from_token() {
    assert!(portal_reachable().await);

    // 1. User exists and is signed in.
    let user = register_test_user("oauth").await;

    // 2. Register a Hydra client that *requests* openid + offline + email.
    let (client_id, client_secret, redirect_uri) =
        hydra_create_test_client(&["openid", "offline", "email", "profile"]).await;

    // 3. Build the auth URL and follow the chain.
    let state = "explore-test-state-1234";
    let auth_url = format!(
        "{HYDRA_PUBLIC}/oauth2/auth?client_id={client_id}\
         &response_type=code\
         &scope=openid+offline+email+profile\
         &redirect_uri={redirect_uri}\
         &state={state}"
    );

    // The portal's `/oauth/consent` form is the place where the user picks
    // which scopes to grant. We follow redirects up to the consent page, then
    // do a manual POST that omits `email` from `grant_scope`.
    let res = user
        .client
        .get(&auth_url)
        .send()
        .await
        .expect("follow auth chain");
    // We should land on the consent page (or hit Hydra's auto-grant).
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("/oauth/consent") || final_url.contains(&redirect_uri),
        "should be at consent or callback: {final_url}"
    );

    // If Hydra auto-granted (skip_consent or trusted), the test of "reduced
    // scope" is impossible. Make sure we *are* on the consent page.
    assert!(
        final_url.contains("/oauth/consent"),
        "test requires user-facing consent page; got {final_url}"
    );
    let body = res.text().await.expect("consent body");

    // 4. Inspect the consent UI for the checkbox bug (Deviation 4).
    assert!(
        body.contains("type=\"checkbox\""),
        "consent should render checkboxes, not hidden inputs"
    );
    assert!(
        body.contains("name=\"grant_scope\""),
        "checkboxes should be named grant_scope"
    );
    // `openid` is mandatory and should be disabled (and emitted as a hidden
    // duplicate so it always submits).
    let openid_idx = body
        .find("value=\"openid\"")
        .expect("openid scope listed in consent");
    let around = &body[openid_idx.saturating_sub(200)..openid_idx + 200];
    assert!(
        around.contains("disabled"),
        "openid checkbox should be disabled; surrounding:\n{around}"
    );

    // Extract the consent challenge + _csrf from the form.
    let consent_challenge =
        extract_input_value(&body, "consent_challenge").expect("consent_challenge hidden input");
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf hidden input");

    // 5. POST consent acceptance with `email` REMOVED — `openid` (and
    // optionally `offline`, `profile`) only.
    // Submit consent on `manual_client` (shares cookie jar with
    // `user.client` but does NOT auto-follow redirects). The auth-code flow
    // ends with a 303 → `http://127.0.0.1:5555/callback?code=...`; we walk
    // each hop and read `code` from the final Location.
    let code = post_consent_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline", "profile"],
    )
    .await
    .expect("authorization code on callback URL");

    // 6. Exchange the code at Hydra's token endpoint.
    let token_client = browser_client();
    let res = token_client
        .post(format!("{HYDRA_PUBLIC}/oauth2/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code", code.as_str()),
        ])
        .send()
        .await
        .expect("token exchange");
    assert!(
        res.status().is_success(),
        "token exchange: {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let token: serde_json::Value = res.json().await.expect("token body");
    let access_token = token["access_token"]
        .as_str()
        .expect("access_token in response")
        .to_string();
    let granted_scope = token["scope"].as_str().unwrap_or_default().to_string();
    assert!(
        !granted_scope.split_whitespace().any(|s| s == "email"),
        "token scope should NOT contain `email` (was dropped); got `{granted_scope}`"
    );

    // 7. Introspect to confirm.
    let res = token_client
        .post(format!("{HYDRA_ADMIN}/admin/oauth2/introspect"))
        .form(&[("token", access_token.as_str())])
        .send()
        .await
        .expect("introspect");
    assert!(res.status().is_success(), "introspect: {}", res.status());
    let v: serde_json::Value = res.json().await.expect("introspect body");
    let introspected = v["scope"].as_str().unwrap_or_default();
    assert!(
        v["active"].as_bool().unwrap_or(false),
        "introspected token should be active"
    );
    assert!(
        !introspected.split_whitespace().any(|s| s == "email"),
        "introspect: scope should NOT contain `email`; got `{introspected}`"
    );

    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

/// POST `/oauth/consent` carrying the given `grant_scope` set, then chase
/// the resulting 303s manually until a `Location` pointing at the callback
/// URI surfaces; return the `code` query parameter from that URL. Returns
/// `None` if the chain ends somewhere unexpected (e.g. `/error`).
async fn post_consent_chase_code(
    client: &reqwest::Client,
    csrf: &str,
    consent_challenge: &str,
    grant_scopes: &[&str],
) -> Option<String> {
    // Build the form body manually so `grant_scope` can repeat.
    let mut body = vec![
        ("_csrf", csrf.to_string()),
        ("consent_challenge", consent_challenge.to_string()),
        ("decision", "accept".to_string()),
    ];
    for s in grant_scopes {
        body.push(("grant_scope", (*s).to_string()));
    }
    let body_str: String = body
        .iter()
        .map(|(k, v)| format!("{}={}", form_urlencode(k), form_urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");

    // `client` has redirects disabled — every hop is observable. Walk
    // until we see a Location pointing at the unreachable callback
    // (`http://127.0.0.1:5555/callback?code=...`) and extract `code` from it.
    let mut resp = client
        .post(format!("{PORTAL}/oauth/consent"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body_str)
        .send()
        .await
        .ok()?;
    for _ in 0..20 {
        if !resp.status().is_redirection() {
            return None;
        }
        let loc = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|h| h.to_str().ok())?
            .to_string();
        if loc.contains("/callback") {
            return extract_query_param(&loc, "code");
        }
        // Resolve relative redirects against the current response's URL.
        let next = match reqwest::Url::parse(&loc) {
            Ok(u) => u,
            Err(_) => resp.url().join(&loc).ok()?,
        };
        resp = client.get(next).send().await.ok()?;
    }
    None
}

/// `application/x-www-form-urlencoded` encoder, kept self-contained so the
/// test surface doesn't depend on an encoding crate.
fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn extract_input_value(html: &str, name: &str) -> Option<String> {
    // Match `name="<NAME>"` and return the `value="..."` that follows on the
    // SAME `<input>` element. Scan forward up to the next `>` so we don't
    // grab a `value="..."` from a different element.
    let needle = format!("name=\"{name}\"");
    let mut start = 0usize;
    while let Some(idx) = html[start..].find(&needle) {
        let abs = start + idx;
        let after = &html[abs + needle.len()..];
        // Limit to the current element by stopping at the next `>` (the
        // closing bracket of this `<input ...>`).
        let elem_end = after.find('>').unwrap_or(after.len());
        let elem = &after[..elem_end];
        if let Some(vi) = elem.find("value=\"") {
            let val = &elem[vi + "value=\"".len()..];
            if let Some(end) = val.find('"') {
                return Some(val[..end].to_string());
            }
        }
        start = abs + needle.len();
    }
    None
}

// --- groups claim tests ----------------------------------------------------

#[tokio::test]
async fn groups_only_emits_active_org_slugs() {
    assert!(portal_reachable().await);

    let user = register_test_user("grp-active").await;
    let (client_id, client_secret, redirect_uri) =
        hydra_create_test_client(&["openid", "groups"]).await;

    let org_id = uuid::Uuid::new_v4().to_string();
    let team_id = uuid::Uuid::new_v4().to_string();
    seed_organization(&org_id, "test-grp-active", "Test Grp Active", "all");
    seed_org_membership(&org_id, &user.identity_id, "member");
    seed_team(&team_id, &org_id, "Platform", "platform", None);
    add_team_member(&team_id, &user.identity_id);

    let auth_url = oauth_auth_url(
        &client_id,
        &redirect_uri,
        "openid groups",
        &format!("&organization_id={org_id}"),
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "groups"],
        false,
    )
    .await
    .expect("code from groups consent");

    let tokens = exchange_code_for_tokens(&client_id, &client_secret, &redirect_uri, &code).await;
    let id_token = tokens["id_token"].as_str().expect("id_token present");
    let claims = decode_jwt_claims(id_token);
    let groups = claims["groups"].as_array().expect("groups claim is array");
    assert_eq!(
        groups,
        &[serde_json::json!("platform")],
        "groups should contain exactly the active org's team slug"
    );

    delete_team(&team_id);
    delete_org_membership(&org_id, &user.identity_id);
    delete_organization(&org_id);
    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn groups_excludes_other_orgs() {
    assert!(portal_reachable().await);

    let user = register_test_user("grp-exclude").await;
    let (client_id, client_secret, redirect_uri) =
        hydra_create_test_client(&["openid", "groups"]).await;

    // Pin a resolvable default-org membership at consent time. The auto-join
    // middleware seeds it lazily on authenticated portal requests; this makes
    // the assertion independent of that timing (INSERT OR IGNORE is idempotent).
    seed_org_membership("default", &user.identity_id, "member");

    // Seed a second org with a team the user belongs to.
    let org2_id = uuid::Uuid::new_v4().to_string();
    let team_id = uuid::Uuid::new_v4().to_string();
    seed_organization(&org2_id, "test-grp-other", "Test Grp Other", "all");
    seed_org_membership(&org2_id, &user.identity_id, "member");
    seed_team(&team_id, &org2_id, "Infra", "infra", None);
    add_team_member(&team_id, &user.identity_id);

    // Drive consent scoped to the default org; user has no teams there.
    let auth_url = oauth_auth_url(
        &client_id,
        &redirect_uri,
        "openid groups",
        "&organization_id=default",
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "groups"],
        false,
    )
    .await
    .expect("code from groups exclude consent");

    let tokens = exchange_code_for_tokens(&client_id, &client_secret, &redirect_uri, &code).await;
    let id_token = tokens["id_token"].as_str().expect("id_token present");
    let claims = decode_jwt_claims(id_token);
    // The user has no team in the active (default) org, so groups must be
    // exactly empty. Asserting `== []` (not just "infra absent") pins both
    // the exclusion AND that an empty result reflects no active-org teams
    // rather than a broken implementation that always returns [].
    assert_eq!(
        claims["groups"],
        serde_json::json!([]),
        "active-org groups must be empty (and must exclude org2's 'infra'); got {}",
        claims["groups"]
    );

    delete_team(&team_id);
    delete_org_membership(&org2_id, &user.identity_id);
    delete_organization(&org2_id);
    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn groups_present_on_skip_consent() {
    assert!(portal_reachable().await);

    let user = register_test_user("grp-skip").await;
    let (client_id, client_secret, redirect_uri) =
        hydra_create_test_client(&["openid", "groups"]).await;

    // Pin a resolvable default-org membership so active-org resolution sees the
    // user as a member regardless of auto-join timing (INSERT OR IGNORE).
    seed_org_membership("default", &user.identity_id, "member");

    let team_id = uuid::Uuid::new_v4().to_string();
    seed_team(&team_id, "default", "Ops", "ops", None);
    add_team_member(&team_id, &user.identity_id);

    let auth_url = oauth_auth_url(
        &client_id,
        &redirect_uri,
        "openid groups",
        "&organization_id=default",
    );

    // First pass: explicit consent with remember=true so Hydra stores the grant.
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let _code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "groups"],
        true,
    )
    .await
    .expect("first-pass code");

    // Second pass: Hydra sets skip=true on the challenge; portal auto-grants.
    // Use manual_client (redirects disabled) to walk 303s until the callback.
    let mut resp = user
        .manual_client
        .get(&auth_url)
        .send()
        .await
        .expect("second auth pass");
    let code = 'walk: {
        for _ in 0..20 {
            if resp.status().is_redirection() {
                let loc = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                if let Some(loc) = loc {
                    if loc.contains("/callback") {
                        break 'walk extract_query_param(&loc, "code").expect("code in callback");
                    }
                    let next = reqwest::Url::parse(&loc)
                        .unwrap_or_else(|_| resp.url().join(&loc).unwrap());
                    resp = user
                        .manual_client
                        .get(next)
                        .send()
                        .await
                        .expect("follow redirect");
                    continue;
                }
            }
            panic!("auto-grant chain did not reach callback");
        }
        panic!("too many redirects in auto-grant chain");
    };

    let tokens = exchange_code_for_tokens(&client_id, &client_secret, &redirect_uri, &code).await;
    let id_token = tokens["id_token"].as_str().expect("id_token present");
    let claims = decode_jwt_claims(id_token);
    let groups = claims["groups"]
        .as_array()
        .expect("groups claim is array on skip");
    let contains_ops = groups.iter().any(|v| v.as_str() == Some("ops"));
    assert!(
        contains_ops,
        "groups must contain 'ops' even on skip-consent path; got {groups:?}"
    );

    delete_team(&team_id);
    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

#[tokio::test]
async fn groups_empty_array_when_no_teams() {
    assert!(portal_reachable().await);

    let user = register_test_user("grp-empty").await;
    let (client_id, client_secret, redirect_uri) =
        hydra_create_test_client(&["openid", "groups"]).await;

    // User is in the default org but has no team memberships.
    let auth_url = oauth_auth_url(
        &client_id,
        &redirect_uri,
        "openid groups",
        "&organization_id=default",
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "groups"],
        false,
    )
    .await
    .expect("code from empty-groups consent");

    let tokens = exchange_code_for_tokens(&client_id, &client_secret, &redirect_uri, &code).await;
    let id_token = tokens["id_token"].as_str().expect("id_token present");
    let claims = decode_jwt_claims(id_token);
    assert_eq!(
        claims["groups"],
        serde_json::json!([]),
        "groups must be an empty array when user has no team memberships"
    );

    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}
