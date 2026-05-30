//! Verification flow — Kratos sends a verification email after registration;
//! submitting the code flips the verifiable address to `verified=true`.

use std::time::Duration;

use crate::common::*;

/// Find a UUID v4 immediately following `marker` in `haystack`. Returns
/// the first contiguous run of hex+dashes (up to 36 chars) after the
/// marker. Returns `None` if `marker` is absent or the run is empty.
fn extract_uuid_after(haystack: &str, marker: &str) -> Option<String> {
    let idx = haystack.find(marker)?;
    let after = &haystack[idx + marker.len()..];
    let uuid: String = after
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
        .take(36)
        .collect();
    if uuid.len() == 36 {
        Some(uuid)
    } else {
        None
    }
}

#[tokio::test]
async fn verification_code_flips_verified_status() {
    assert!(
        portal_reachable().await,
        "portal not reachable at {PORTAL} — bring up the playground first"
    );

    let user = register_test_user("verify").await;

    // Wait for the verification email to land.
    let mail = wait_for_mailcrab(&user.email, "verify your account", Duration::from_secs(15))
        .await
        .expect("verification email arrived");
    let code = extract_code_from_email(&mail.body).expect("6-digit code");
    // Kratos embeds the flow ID in the verification email link
    // (`?code=<six>&flow=<uuid>`). The code is bound to that flow — using
    // any other flow ID rejects with "The provided code is invalid". The
    // email body uses HTML-entity-encoded ampersands (`&amp;`), so
    // un-escape before extracting.
    let unescaped = mail.body.replace("&amp;", "&");
    // The body contains the link twice (href + anchor text) plus prose.
    // `extract_query_param` would happily slurp the rest of the line into
    // the captured value. Instead, find the flow= marker and stop at the
    // next non-uuid-character (uuid v4 is 36 chars of hex+dashes).
    let flow_id = extract_uuid_after(&unescaped, "flow=").expect("flow id in email link");

    // Submit the code as a browser would: POST the flow's action URL with
    // `code` + `csrf_token`. Kratos validates and flips `verified=true`.
    // We fetch the flow first (using the user.client cookies, which carry
    // the flow's continuity cookie set during registration) to get the
    // right CSRF token + action URL.
    let flow = fetch_flow(&user.client, "verification", &flow_id).await;
    let csrf = flow_csrf_token(&flow).expect("csrf_token on verification flow");
    let action = flow["ui"]["action"]
        .as_str()
        .expect("ui.action on verification flow")
        .to_string();
    let res = user
        .client
        .post(&action)
        .header("Accept", "application/json")
        .form(&[
            ("code", code.as_str()),
            ("method", "code"),
            ("csrf_token", csrf.as_str()),
        ])
        .send()
        .await
        .expect("POST verification code");
    let status = res.status();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::Value::Null);
    assert!(
        status.is_success() || status.is_redirection() || status.as_u16() == 422,
        "verification POST unexpected: {status} body {body}"
    );

    // Confirm via the admin API that the address is now verified. Kratos
    // commits the flag synchronously on `passed_challenge`, but we poll
    // briefly to be robust against any micro-delay.
    let admin = browser_client();
    let mut verified = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let res = admin
            .get(format!(
                "{KRATOS_ADMIN}/admin/identities/{}",
                user.identity_id
            ))
            .send()
            .await
            .expect("admin get identity");
        assert!(res.status().is_success());
        let id: serde_json::Value = res.json().await.expect("identity json");
        verified = id["verifiable_addresses"]
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|a| a["value"].as_str() == Some(&user.email))
            })
            .and_then(|a| a["verified"].as_bool())
            .unwrap_or(false);
        if verified {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(verified, "address should be verified after submitting code");

    user.cleanup().await;
}
