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
