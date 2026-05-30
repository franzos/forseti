//! `/settings/account/delete` — self-service account deletion saga.
//!
//! The saga has three observable effects: (1) the Kratos identity is gone,
//! (2) the user's session is invalidated and they land on `/login`, and
//! (3) registered apps get an RFC 8417 Security Event Token at their
//! configured `account_deletion_url` (RISC `account-purged` event).
//!
//! This file covers (1) + (2), plus a lightweight sanity check on the
//! portal's JWKS endpoint. The full fan-out test for (3) needs more
//! scaffolding — see [`_todo_webhook_fanout_test`] for the shape of what's
//! missing.

use crate::common::*;
use reqwest::StatusCode;
use serde_json::Value;

#[tokio::test]
async fn account_delete_landing_page_renders_for_authenticated_user() {
    assert!(portal_reachable().await);
    let user = register_test_user("acct-delete-landing").await;

    let res = user
        .client
        .get(format!("{PORTAL}/settings/account"))
        .send()
        .await
        .expect("GET /settings/account");
    assert!(
        res.status().is_success(),
        "/settings/account: {}",
        res.status()
    );
    let body = res.text().await.expect("body");
    assert!(
        body.contains("Delete my account"),
        "danger zone should advertise the delete action"
    );

    user.cleanup().await;
}

#[tokio::test]
async fn account_delete_landing_redirects_anonymous_to_login() {
    let client = manual_redirect_client();
    let res = client
        .get(format!("{PORTAL}/settings/account"))
        .send()
        .await
        .expect("GET /settings/account anon");
    assert_eq!(res.status().as_u16(), 303);
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.contains("/login"),
        "anonymous /settings/account should redirect to /login; got {loc}"
    );
}

#[tokio::test]
async fn account_delete_saga_removes_kratos_identity() {
    assert!(portal_reachable().await);

    // A freshly-registered user has a privileged Kratos session for the
    // next 15 minutes (Kratos's `privileged_session_max_age`), so we can
    // post directly to `/settings/account/delete` without bouncing
    // through `/login?refresh=true`.
    let user = register_test_user("acct-delete-saga").await;
    let identity_id = user.identity_id.clone();
    let email = user.email.clone();

    // 1. GET the confirm page — verifies the privileged-session gate
    //    works AND gives us a fresh CSRF token bound to the same cookie
    //    jar that the POST will use.
    let res = user
        .client
        .get(format!("{PORTAL}/settings/account/delete"))
        .send()
        .await
        .expect("GET /settings/account/delete");
    assert!(
        res.status().is_success(),
        "GET /settings/account/delete: {}",
        res.status()
    );
    assert!(
        res.url().path().starts_with("/settings/account/delete"),
        "expected to land on the confirm page, got {}",
        res.url()
    );
    // The confirm-page URL carries `?flow=<id>` after Kratos init —
    // POST must hit the same URL so the privileged-session probe in the
    // POST handler sees the same flow id.
    let post_url = res.url().clone();
    let body = res.text().await.expect("confirm body");
    let csrf = extract_form_csrf(&body).expect("_csrf hidden input on confirm page");

    // 2. POST the deletion form. CSRF + the typed-email belt-and-braces
    //    confirm must match the session's email.
    let res = user
        .client
        .post(post_url)
        .form(&[("_csrf", csrf.as_str()), ("confirm_email", email.as_str())])
        .send()
        .await
        .expect("POST /settings/account/delete");

    // 3. The saga succeeded if we land on /login (Kratos session is
    //    invalid and the redirect chain bottoms out there). The route's
    //    direct response is `303 /login?msg=account_deleted`, which the
    //    auto-redirect client follows.
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("/login"),
        "expected to land on /login after delete; got {final_url}"
    );

    // 4. The identity should be gone from Kratos.
    let post_delete = identity_id_by_email(&email).await;
    assert!(
        post_delete.is_none(),
        "kratos identity should be deleted; admin lookup returned Some({post_delete:?}) for {email} (id was {identity_id})"
    );

    // 5. The user's session should be invalid — `/dashboard`/`/settings`
    //    bounces to /login.
    let manual = manual_redirect_client();
    // Steal the cookie jar via a separate request from `user.client`
    // (which kept following redirects above). Easiest portable check:
    // re-issue the same `user.client` against a protected route and
    // confirm it redirects to /login.
    let res = user
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings after delete");
    // Either 303 → /login (manual_client style) or the auto-redirect
    // client landed on /login after following hops.
    assert!(
        res.url().path().starts_with("/login") || res.status() == StatusCode::SEE_OTHER,
        "after delete, /settings should redirect to /login; got url={} status={}",
        res.url(),
        res.status()
    );
    let _ = manual; // unused — kept for documentation of the alternative

    // No cleanup — the identity is already gone.
}

/// Pull a `_csrf` hidden input value out of a settings page render. Settings
/// pages name their CSRF token `_csrf` (portal-owned forms — see
/// `src/csrf.rs`); the Kratos-driven forms use `csrf_token` and have a
/// separate helper (`flow_csrf_token`).
fn extract_form_csrf(html: &str) -> Option<String> {
    // Match `name="_csrf"` and read the `value="..."` that follows in the
    // same `<input>` element.
    let needle = "name=\"_csrf\"";
    let idx = html.find(needle)?;
    let after = &html[idx + needle.len()..];
    let elem_end = after.find('>').unwrap_or(after.len());
    let elem = &after[..elem_end];
    let value_start = elem.find("value=\"")? + "value=\"".len();
    let tail = &elem[value_start..];
    let value_end = tail.find('"')?;
    Some(tail[..value_end].to_string())
}

/// The portal's webhook JWKS endpoint is public and unauthenticated —
/// any receiver should be able to fetch it before verifying a SET. Smoke-
/// test the shape so any boot-time regression (key didn't load, JWK
/// missing fields) surfaces here.
#[tokio::test]
async fn webhook_jwks_endpoint_serves_well_formed_ed25519_key() {
    assert!(portal_reachable().await);
    let client = browser_client();
    let res = client
        .get(format!("{PORTAL}/.well-known/webhook-jwks.json"))
        .send()
        .await
        .expect("GET webhook-jwks");
    assert!(res.status().is_success(), "status {}", res.status());
    let cache = res
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        cache.contains("max-age=86400"),
        "JWKS should advertise a day-long cache; got {cache}"
    );
    let body: Value = res.json().await.expect("jwks json");
    let keys = body["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1, "exactly one signing key");
    let jwk = &keys[0];
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["alg"], "EdDSA");
    assert!(jwk["kid"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
    assert!(jwk["x"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
}

/// Sketch of the full webhook fan-out integration test that's not yet
/// wired up. Captured here so the next person (or future-me) can stand
/// it up without re-deriving the design.
///
/// **What it should prove.** End-to-end, a `POST /settings/account/delete`
/// fans out an RFC 8417 Security Event Token (RISC `account-purged`,
/// signed EdDSA against the portal's JWKS) to every OAuth2 client whose
/// `metadata.portal.account_deletion_url` is set.
///
/// **Scaffolding still missing.**
///
/// 1. **Mock HTTP receiver.** Bind a `tokio::net::TcpListener` to
///    `127.0.0.1:0`, accept one connection, read the request bytes, and
///    return `200 OK`. Surface the captured body + headers via an
///    `Arc<Mutex<...>>`. ~50 lines.
///
/// 2. **Hydra client with `account_deletion_url` metadata.** Extend
///    `hydra_create_test_client` (`common.rs:531`) to accept a
///    `serde_json::Value` for `metadata`; pass through `account_deletion_url`
///    under `metadata.portal.account_deletion_url`. No webhook-secret
///    minting step is needed anymore — the portal owns the signing key.
///
/// 3. **Drive Hydra consent.** Reuse `post_consent_chase_code` (in
///    `tests/integration/oauth.rs:148`) so Hydra has a recorded
///    consent session for the subject; the saga reads
///    `list_consent_sessions_by_subject` to decide who to notify.
///
/// 4. **Wait for the worker.** Worker tick is 5s
///    (`webhook.rs::TICK`); allow ~15s with a poll loop on the mock
///    receiver's captured list.
///
/// 5. **Verify the payload.** Fetch
///    `/.well-known/webhook-jwks.json` via the test client, build a
///    `jsonwebtoken::DecodingKey::from_jwk(...)`, and call
///    `jsonwebtoken::decode::<Value>(jws, &key, &Validation::new(Algorithm::EdDSA))`.
///    Assert the resulting claims carry `iss == portal_self_url`,
///    `aud == client_id`, the RISC URI
///    `https://schemas.openid.net/secevent/risc/event-type/account-purged`
///    is present in `events`, and `events[..].subject.sub` equals the
///    deleted identity id. Also assert the `X-Portal-Event` header
///    matches `claims.jti`.
///
/// Putting this in place: maybe 200 lines including the mock receiver
/// and helpers. Worth doing before the next Phase-1-touching change
/// lands.
#[allow(dead_code)]
fn _todo_webhook_fanout_test() {}
