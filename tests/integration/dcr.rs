//! Dynamic Client Registration (RFC 7591) + the MCP-shaped end-to-end
//! flow: mint an IAT, self-register a client, mark it verified, drive
//! PKCE auth-code with a custom audience, exchange the code, validate
//! the token at a fake resource server via Hydra introspection, and
//! rotate the refresh token.
//!
//! Plus a row of negatives covering the gates the portal proxy puts in
//! front of Hydra's anonymous `/oauth2/register`: bad IATs, revoked
//! IATs, reserved client names (incl. Unicode bypass attempts the H2
//! fix closed), and per-IAT daily caps.
//!
//! The CRITICAL test is `dcr_rfc_7592_put_cannot_flip_verification` —
//! it codifies the C1 fix that moved verification state out of
//! `metadata.portal.*` on the Hydra client (RAT-mutable) into the
//! portal-owned `oauth_client_metadata` table (not mutable by the
//! RAT). If a future refactor accidentally re-introduces the bypass,
//! this test fails.

use crate::common::*;
use reqwest::StatusCode;

// --- helpers local to this module -----------------------------------------

/// Best-effort cleanup of a DCR-registered client. Calls Hydra admin
/// DELETE; failure is logged but not propagated.
async fn cleanup_dcr_client(client_id: &str) {
    if client_id.is_empty() {
        return;
    }
    hydra_delete_client(client_id).await;
}

/// Try to drive the consent screen with `audience=<aud>` and a custom
/// scope set, returning the HTML response body so callers can assert on
/// the unverified banner. Test users are reused via `register_test_user`.
async fn render_consent_page(
    user: &RegisteredUser,
    client_id: &str,
    redirect_uri: &str,
    audience: &str,
    scope: &str,
) -> (StatusCode, String, String) {
    let state = format!(
        "dcr-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let auth_url = format!(
        "{HYDRA_PUBLIC}/oauth2/auth?client_id={client_id}\
         &response_type=code\
         &scope={scope}\
         &redirect_uri={redirect_uri}\
         &state={state}\
         &audience={audience}"
    );
    let res = user
        .client
        .get(&auth_url)
        .send()
        .await
        .expect("follow auth chain");
    let status = res.status();
    let final_url = res.url().to_string();
    let body = res.text().await.unwrap_or_default();
    (status, final_url, body)
}

/// Extract a hidden `<input>` value by name. Lifted from `oauth.rs`
/// because it's the same shape and we want this module self-contained.
fn extract_input_value(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let mut start = 0usize;
    while let Some(idx) = html[start..].find(&needle) {
        let abs = start + idx;
        let after = &html[abs + needle.len()..];
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

/// `application/x-www-form-urlencoded` encoder. Same as `oauth.rs`.
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

/// POST `/oauth/consent` accepting all listed scopes, then chase the
/// 303s back to the unreachable callback URL; return the `code` query
/// parameter from that URL. Mirrors `oauth.rs::post_consent_chase_code`
/// — kept inline (rather than promoted to `common.rs`) because we want
/// the oauth.rs version to stay free of extra parameters.
async fn post_consent_chase_code(
    client: &reqwest::Client,
    csrf: &str,
    consent_challenge: &str,
    grant_scopes: &[&str],
) -> Option<String> {
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
        let next = match reqwest::Url::parse(&loc) {
            Ok(u) => u,
            Err(_) => resp.url().join(&loc).ok()?,
        };
        resp = client.get(next).send().await.ok()?;
    }
    None
}

/// Compute a PKCE code_verifier + S256 code_challenge pair.
fn pkce_pair() -> (String, String) {
    use base64::Engine;
    use rand::Rng;
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
    (verifier, challenge)
}

// --- tests ----------------------------------------------------------------

/// Drive the whole DCR + MCP chain top to bottom:
///
/// 1. Mint an IAT, register a client, assert the portal-owned metadata
///    row landed (`source = dcr`, `verification = unverified`).
/// 2. Operator marks it verified.
/// 3. PKCE auth-code with `audience=https://mcp.test/`.
/// 4. Exchange code for tokens.
/// 5. Fake MCP server validates via Hydra introspection.
/// 6. Refresh token rotates — old refresh now returns `invalid_grant`.
#[tokio::test]
async fn dcr_golden_path_end_to_end() {
    assert!(portal_reachable().await);

    let audience = "https://mcp.test/";
    let redirect_uri = "http://127.0.0.1:5555/callback";
    let scope = "openid offline";

    // 1. Mint IAT + register.
    let iat = mint_dcr_iat(Some(1), None);
    let (status, _hdrs, body) = dcr_register(
        &iat,
        "integration-test-dcr-golden",
        scope,
        &[redirect_uri],
        Some(&[audience]),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "DCR register status: {body}");
    let client_id = body["client_id"]
        .as_str()
        .expect("client_id in DCR response")
        .to_string();
    assert!(
        body["registration_access_token"].is_string(),
        "DCR response must include a registration_access_token"
    );

    // 2. Portal-side metadata row must have landed with `source=dcr`.
    let row = read_client_metadata_row(&client_id)
        .expect("oauth_client_metadata row inserted by DCR proxy");
    assert_eq!(row.0, "unverified", "fresh DCR client must be unverified");
    assert_eq!(row.1, "dcr", "source must be dcr");
    assert!(row.2.is_some(), "dcr_iat_id must be recorded");

    // 3. Operator marks the client verified (admin-UI surrogate).
    mark_client_verified(&client_id);
    let user = register_test_user("dcr-golden").await;

    // 4. PKCE flow. Browser-style client follows the chain into the
    //    consent screen; we then POST consent grant + capture the code.
    let (verifier, challenge) = pkce_pair();
    let state = format!(
        "dcr-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let auth_url = format!(
        "{HYDRA_PUBLIC}/oauth2/auth?client_id={client_id}\
         &response_type=code\
         &scope={scope}\
         &redirect_uri={redirect_uri}\
         &state={state}\
         &audience={audience}\
         &code_challenge={challenge}\
         &code_challenge_method=S256"
    );
    let res = user.client.get(&auth_url).send().await.expect("auth-chain");
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("/oauth/consent"),
        "auth chain must land on consent screen; got {final_url}"
    );
    let consent_html = res.text().await.expect("consent body");
    let csrf = extract_input_value(&consent_html, "_csrf").expect("csrf in consent form");
    let consent_challenge = extract_input_value(&consent_html, "consent_challenge")
        .expect("consent_challenge hidden input");
    let code = post_consent_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline"],
    )
    .await
    .expect("authorization code on callback URL");

    // 5. Token exchange (public client → no client_secret, PKCE only).
    let token_client = browser_client();
    let res = token_client
        .post(format!("{HYDRA_PUBLIC}/oauth2/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .expect("token exchange transport");
    assert!(
        res.status().is_success(),
        "token exchange: status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let token: serde_json::Value = res.json().await.expect("token body");
    let access_token = token["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let refresh_token = token["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    assert!(token["id_token"].is_string(), "id_token must be present");

    // 6. Fake MCP server accepts the token.
    let mcp = spawn_fake_mcp_server(audience).await;
    let res = token_client
        .get(mcp.tool_url())
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("fake mcp transport");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "MCP server should accept the audience-bound token; body: {}",
        res.text().await.unwrap_or_default()
    );

    // 7. Refresh token rotates. First use must succeed; second use of
    //    the *original* refresh token must be rejected with invalid_grant.
    let res = token_client
        .post(format!("{HYDRA_PUBLIC}/oauth2/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .expect("refresh transport");
    assert!(res.status().is_success(), "first refresh must succeed");
    let refreshed: serde_json::Value = res.json().await.expect("refresh body");
    assert!(
        refreshed["access_token"].is_string() && refreshed["refresh_token"].is_string(),
        "rotated token pair expected"
    );
    let new_refresh = refreshed["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, refresh_token, "refresh token must rotate");

    let res = token_client
        .post(format!("{HYDRA_PUBLIC}/oauth2/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .expect("second refresh transport");
    assert!(
        !res.status().is_success(),
        "second use of original refresh token must fail"
    );
    let err_body: serde_json::Value = res.json().await.unwrap_or(serde_json::Value::Null);
    assert_eq!(
        err_body["error"].as_str(),
        Some("invalid_grant"),
        "second refresh must surface invalid_grant; got {err_body}"
    );

    mcp.stop().await;
    cleanup_dcr_client(&client_id).await;
    user.cleanup().await;
}

/// Garbage IAT → 401 with the RFC 6750 `WWW-Authenticate` header.
#[tokio::test]
async fn dcr_register_with_bad_iat_returns_401_with_www_authenticate() {
    assert!(portal_reachable().await);

    let (status, headers, body) = dcr_register(
        "not-a-real-iat",
        "integration-test-dcr-bad-iat",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let www = headers
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        www.contains("Bearer") && www.contains(r#"error="invalid_token""#),
        "WWW-Authenticate must carry Bearer + invalid_token; got {www}"
    );
    assert_eq!(body["error"].as_str(), Some("invalid_token"));
}

/// Anonymous DCR (no `Authorization` header) is the default path — Claude
/// and friends self-register without any way to present an IAT. The
/// registration must succeed (201) and land as `unverified` so the consent
/// screen renders the caution banner until an operator promotes it via
/// `/admin/clients/{id}/verify`. `dcr_iat_id` must be NULL on the row.
#[tokio::test]
async fn dcr_anonymous_register_succeeds_and_lands_unverified() {
    assert!(portal_reachable().await);

    let (status, _headers, body) = dcr_register_anonymous(
        "integration-test-dcr-anonymous",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "anonymous DCR must succeed; body: {body}"
    );
    let client_id = body["client_id"]
        .as_str()
        .expect("client_id in DCR response")
        .to_string();

    let row =
        read_client_metadata_row(&client_id).expect("oauth_client_metadata row inserted by proxy");
    assert_eq!(
        row.0, "unverified",
        "anonymous DCR client must land unverified"
    );
    assert_eq!(row.1, "dcr", "source must be dcr");
    assert!(
        row.2.is_none(),
        "dcr_iat_id must be NULL for anonymous DCR; got {:?}",
        row.2
    );

    cleanup_dcr_client(&client_id).await;
}

/// Anonymous DCR still applies the reserved-name denylist — a caller
/// shouldn't be able to bypass policy by dropping the `Authorization`
/// header.
#[tokio::test]
async fn dcr_anonymous_register_still_rejects_reserved_name() {
    assert!(portal_reachable().await);

    let (status, _headers, body) = dcr_register_anonymous(
        "Microsoft Login",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "reserved name must be rejected even on anonymous path; body: {body}"
    );
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_client_metadata"),
        "anonymous reserved-name rejection must surface invalid_client_metadata: {body}"
    );
}

/// A malformed `Authorization` header must NOT silently fall through to
/// the anonymous path — that would let an attacker probe IATs without
/// leaving a `dcr_rejected` audit row. Both "wrong scheme" and "Bearer
/// without a token" must come back as 401.
#[tokio::test]
async fn dcr_register_with_malformed_authorization_returns_401() {
    assert!(portal_reachable().await);

    // Wrong scheme.
    let (status, _headers, body) = dcr_register_with_authorization(
        "Banana xyz",
        "integration-test-dcr-malformed-scheme",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong scheme must 401; body: {body}"
    );
    assert_eq!(body["error"].as_str(), Some("invalid_token"));

    // Bearer with no token.
    let (status, _headers, body) = dcr_register_with_authorization(
        "Bearer ",
        "integration-test-dcr-malformed-empty",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "empty Bearer must 401; body: {body}"
    );
    assert_eq!(body["error"].as_str(), Some("invalid_token"));
}

/// A known but revoked IAT must 401. Mirrors the `bad_iat` path but
/// exercises the `revoked_at IS NOT NULL` branch in `lookup_iat`.
#[tokio::test]
async fn dcr_register_with_revoked_iat_returns_401() {
    assert!(portal_reachable().await);

    let iat = mint_dcr_iat(Some(5), None);
    revoke_dcr_iat(&iat);
    let (status, _headers, body) = dcr_register(
        &iat,
        "integration-test-dcr-revoked",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"].as_str(), Some("invalid_token"));
}

/// Reserved-name denylist + the four Unicode bypass classes the H2 fix
/// closed (zero-width split, fullwidth, NBSP, combining-mark). Plus one
/// honest positive control to make sure the test isn't mis-asserting
/// across the board.
#[tokio::test]
async fn dcr_register_with_reserved_client_name_returns_400() {
    assert!(portal_reachable().await);

    // Each case gets a fresh IAT so a name-rejection doesn't burn through
    // a single-use IAT and contaminate the next case.
    let cases: &[(&str, &str)] = &[
        ("plain-match", "Microsoft Login"),
        ("zero-width-split", "Goog\u{200B}le Login"),
        ("fullwidth", "ＧＯＯＧＬＥ Login"),
        ("nbsp-separated", "Microsoft\u{00A0}Login"),
        ("combining-mark", "Mi\u{0301}crosoft Login"),
    ];
    for (label, name) in cases {
        let iat = mint_dcr_iat(Some(1), None);
        let (status, _headers, body) = dcr_register(
            &iat,
            name,
            "openid",
            &["http://127.0.0.1:5555/callback"],
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "case `{label}` ({name:?}) must be rejected as reserved; body: {body}"
        );
        assert_eq!(
            body["error"].as_str(),
            Some("invalid_client_metadata"),
            "case `{label}` body error mismatch: {body}"
        );
    }

    // Positive control: a clean name registers successfully.
    let iat = mint_dcr_iat(Some(1), None);
    let (status, _headers, body) = dcr_register(
        &iat,
        "My Custom MCP Server",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "honest name must succeed; got body: {body}"
    );
    if let Some(cid) = body["client_id"].as_str() {
        cleanup_dcr_client(cid).await;
    }
}

/// Per-IAT rolling 24h cap. Mint an IAT with `daily_limit = 2`, do 3
/// registrations in quick succession; assert the 3rd returns 429 with
/// `temporarily_unavailable` and a `Retry-After` header.
///
/// The actual `daily_limit` is read from `[oauth].dcr_iat_daily_limit`
/// in `config.toml` — the test assumes the playground is running with
/// the default config that ships `dcr_iat_daily_limit = 2` for tests.
/// If your local config sets a higher value, this test will fail with
/// "3rd register still succeeded" — turn the config knob down or rerun
/// against a fresh playground.
#[tokio::test]
async fn dcr_per_iat_daily_limit_returns_429() {
    assert!(portal_reachable().await);

    // We can't mutate the running portal's config from a test, so this
    // case depends on the playground being started with
    // `oauth.dcr_iat_daily_limit = 2`. Confirm by stopping after the
    // expected boundary; the test fails loudly if the config differs.
    let iat = mint_dcr_iat(None, Some(2));
    let mut created: Vec<String> = Vec::new();
    let mut last_status = StatusCode::OK;
    let mut last_body = serde_json::Value::Null;
    let mut last_headers = reqwest::header::HeaderMap::new();
    for i in 0..3 {
        let name = format!("integration-test-dcr-rate-{i}");
        let (status, headers, body) = dcr_register(
            &iat,
            &name,
            "openid",
            &["http://127.0.0.1:5555/callback"],
            None,
        )
        .await;
        last_status = status;
        last_body = body.clone();
        last_headers = headers;
        if status.is_success() {
            if let Some(cid) = body["client_id"].as_str() {
                created.push(cid.to_string());
            }
        }
    }
    for cid in &created {
        cleanup_dcr_client(cid).await;
    }
    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "3rd register should hit per-IAT daily cap (set oauth.dcr_iat_daily_limit = 2 in config); \
         last status {last_status} body {last_body}"
    );
    assert_eq!(
        last_body["error"].as_str(),
        Some("temporarily_unavailable"),
        "429 body must carry temporarily_unavailable; got {last_body}"
    );
    assert!(
        last_headers.get("retry-after").is_some(),
        "429 must include a Retry-After header"
    );
}

/// M1 regression: an unverified DCR client must always render the
/// consent screen (with the caution banner), even when the admin has
/// flipped `metadata.skip_consent = true` on the Hydra client.
#[tokio::test]
async fn dcr_unverified_client_forces_consent_screen_render_even_with_skip_consent() {
    assert!(portal_reachable().await);

    let audience = "https://mcp.test/";
    let redirect_uri = "http://127.0.0.1:5555/callback";
    let scope = "openid";

    // Register via DCR — `source=dcr`, `verification=unverified` by
    // default. Do NOT call `mark_client_verified`.
    let iat = mint_dcr_iat(Some(1), None);
    let (status, _hdrs, body) = dcr_register(
        &iat,
        "integration-test-dcr-skip-consent",
        scope,
        &[redirect_uri],
        Some(&[audience]),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "DCR register: {body}");
    let client_id = body["client_id"].as_str().expect("client_id").to_string();

    // Flip `metadata.skip_consent = true` on the Hydra client. The
    // verification trust state is portal-side, so this metadata bit on
    // the Hydra row must NOT be enough to bypass the caution screen.
    let admin = browser_client();
    let patch = serde_json::json!([
        { "op": "replace", "path": "/metadata", "value": { "skip_consent": true } }
    ]);
    let res = admin
        .patch(format!("{HYDRA_ADMIN}/admin/clients/{client_id}"))
        .header("content-type", "application/json")
        .json(&patch)
        .send()
        .await
        .expect("hydra patch transport");
    assert!(
        res.status().is_success(),
        "hydra PATCH skip_consent: status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );

    // Drive the auth chain. With skip_consent on a verified client we'd
    // see a redirect straight to the callback; with skip_consent on an
    // unverified client we must still see the consent screen + banner.
    let user = register_test_user("dcr-unverified-skip").await;
    let (status, final_url, page) =
        render_consent_page(&user, &client_id, redirect_uri, audience, scope).await;
    assert!(
        status.is_success(),
        "consent render status {status} final_url {final_url}"
    );
    assert!(
        final_url.contains("/oauth/consent"),
        "must NOT auto-grant for unverified client even with skip_consent; final url {final_url}"
    );
    assert!(
        page.contains("has not been reviewed by an administrator"),
        "consent page must render the unverified caution banner; got {} chars",
        page.len()
    );

    cleanup_dcr_client(&client_id).await;
    user.cleanup().await;
}

/// DCR body carries `audience: [...]` → the portal stamps it on the
/// `oauth_client_metadata.audience` column (space-separated, matching how
/// `scope` is stored across the rest of the schema). First half of the
/// "what is this client for?" provenance signal.
#[tokio::test]
async fn dcr_register_with_audience_captures_audience() {
    assert!(portal_reachable().await);

    let iat = mint_dcr_iat(Some(1), None);
    let (status, _hdrs, body) = dcr_register(
        &iat,
        "integration-test-dcr-audience-capture",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        Some(&["http://example.test/api"]),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "DCR register: {body}");
    let client_id = body["client_id"].as_str().expect("client_id").to_string();

    let (audience, resource_url) = read_client_provenance(&client_id)
        .expect("oauth_client_metadata row inserted by DCR proxy");
    assert_eq!(
        audience.as_deref(),
        Some("http://example.test/api"),
        "DCR-declared audience must be captured (space-joined when multi)"
    );
    assert!(
        resource_url.is_none(),
        "resource_url stays NULL until first consent; got {resource_url:?}"
    );

    cleanup_dcr_client(&client_id).await;
}

/// DCR body without `audience` → column stays NULL. The lazy
/// `resource_url` capture on first consent picks these clients up; see
/// `consent_captures_resource_url_from_request_url`.
#[tokio::test]
async fn dcr_register_without_audience_leaves_audience_null() {
    assert!(portal_reachable().await);

    let iat = mint_dcr_iat(Some(1), None);
    let (status, _hdrs, body) = dcr_register(
        &iat,
        "integration-test-dcr-no-audience",
        "openid",
        &["http://127.0.0.1:5555/callback"],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "DCR register: {body}");
    let client_id = body["client_id"].as_str().expect("client_id").to_string();

    let (audience, resource_url) = read_client_provenance(&client_id)
        .expect("oauth_client_metadata row inserted by DCR proxy");
    assert!(
        audience.is_none(),
        "audience must be NULL when DCR body didn't declare one; got {audience:?}"
    );
    assert!(
        resource_url.is_none(),
        "resource_url is NULL before consent"
    );

    cleanup_dcr_client(&client_id).await;
}

/// Second half of the provenance capture: drive an authorization code
/// flow with `?resource=<url>` on the auth URL (RFC 8707, what Claude
/// sends), POST consent, and assert the portal stamped
/// `oauth_client_metadata.resource_url` on the row.
#[tokio::test]
async fn consent_captures_resource_url_from_request_url() {
    assert!(portal_reachable().await);

    let resource = "http://mcp.example.test/";
    let redirect_uri = "http://127.0.0.1:5555/callback";
    let scope = "openid offline";

    // Register a DCR client without an audience so we know the capture
    // came from `?resource=...` on the auth URL, not from the DCR body.
    let iat = mint_dcr_iat(Some(1), None);
    let (status, _hdrs, body) = dcr_register(
        &iat,
        "integration-test-consent-resource-capture",
        scope,
        &[redirect_uri],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "DCR register: {body}");
    let client_id = body["client_id"].as_str().expect("client_id").to_string();
    mark_client_verified(&client_id);

    let user = register_test_user("consent-resource").await;
    let (verifier, challenge) = pkce_pair();
    let state = format!(
        "rsrc-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let auth_url = format!(
        "{HYDRA_PUBLIC}/oauth2/auth?client_id={client_id}\
         &response_type=code\
         &scope={scope}\
         &redirect_uri={redirect_uri}\
         &state={state}\
         &resource={resource}\
         &code_challenge={challenge}\
         &code_challenge_method=S256"
    );
    let res = user.client.get(&auth_url).send().await.expect("auth-chain");
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("/oauth/consent"),
        "auth chain must land on consent screen; got {final_url}"
    );
    let consent_html = res.text().await.expect("consent body");
    let csrf = extract_input_value(&consent_html, "_csrf").expect("csrf in consent form");
    let consent_challenge = extract_input_value(&consent_html, "consent_challenge")
        .expect("consent_challenge hidden input");
    let code = post_consent_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline"],
    )
    .await
    .expect("authorization code on callback URL");

    // Exchange the code so the flow completes end-to-end. The
    // `resource_url` capture fires from the consent POST, so the
    // assertion below would also pass without this step, but a real
    // RP would always exchange — keep the test honest.
    let token_client = browser_client();
    let res = token_client
        .post(format!("{HYDRA_PUBLIC}/oauth2/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .expect("token exchange transport");
    assert!(
        res.status().is_success(),
        "token exchange: {}",
        res.text().await.unwrap_or_default()
    );

    let (_audience, resource_url) = read_client_provenance(&client_id)
        .expect("oauth_client_metadata row inserted by DCR proxy");
    assert_eq!(
        resource_url.as_deref(),
        Some(resource),
        "consent flow must stamp resource_url from the `?resource=` query param"
    );

    cleanup_dcr_client(&client_id).await;
    user.cleanup().await;
}

/// C1 regression — the heart of the trust-boundary fix.
///
/// Before C1, a DCR client could PUT `/oauth2/register/{id}` directly
/// against Hydra (Hydra handles RFC 7592, the portal does not proxy
/// it) using its `registration_access_token`, replacing the full
/// client representation including `metadata.portal.verification`.
/// That let a self-registered client forge the trust badge on the
/// consent screen.
///
/// The fix moved verification state into the portal-owned
/// `oauth_client_metadata` table. The RAT can still flip whatever
/// metadata Hydra holds, but the portal never reads trust state from
/// the Hydra row. This test asserts the bypass stays closed: a PUT to
/// Hydra with `metadata.portal.verification = "verified"` must NOT
/// flip the `oauth_client_metadata.verification` column or the
/// rendered consent badge.
#[tokio::test]
async fn dcr_rfc_7592_put_cannot_flip_verification() {
    assert!(portal_reachable().await);

    let audience = "https://mcp.test/";
    let redirect_uri = "http://127.0.0.1:5555/callback";
    let scope = "openid";

    let iat = mint_dcr_iat(Some(1), None);
    let (status, _hdrs, body) = dcr_register(
        &iat,
        "integration-test-dcr-c1-regression",
        scope,
        &[redirect_uri],
        Some(&[audience]),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "DCR register: {body}");
    let client_id = body["client_id"].as_str().expect("client_id").to_string();
    let rat = body["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // Sanity: the portal-owned row is still `unverified` at this point.
    assert_eq!(
        read_client_verification(&client_id).as_deref(),
        Some("unverified"),
        "fresh DCR client must be unverified before the PUT"
    );

    // Forge attempt: PUT to Hydra's `/oauth2/register/{id}` with the
    // RAT and a body that tries to seed `metadata.portal.verification =
    // "verified"`. Hydra accepts the PUT (this is the underlying
    // upstream issue); we assert the portal table doesn't follow.
    let attacker = browser_client();
    let put_body = serde_json::json!({
        "client_id": client_id,
        "client_name": "integration-test-dcr-c1-regression",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": scope,
        "token_endpoint_auth_method": "none",
        "audience": [audience],
        "metadata": {
            "portal": {
                "verification": "verified",
                "verified_by": "attacker@example.com",
            }
        },
    });
    let res = attacker
        .put(format!("{HYDRA_PUBLIC}/oauth2/register/{client_id}"))
        .bearer_auth(&rat)
        .header("content-type", "application/json")
        .json(&put_body)
        .send()
        .await
        .expect("rfc7592 PUT transport");
    // We're testing the portal's protection regardless of what Hydra
    // does here. Most builds accept the PUT; if a future Hydra version
    // tightens this we still want the assertion below to hold.
    let put_status = res.status();
    let put_body_text = res.text().await.unwrap_or_default();

    // **The core assertion:** the portal table must NOT have flipped.
    let row_verification = read_client_verification(&client_id);
    assert_eq!(
        row_verification.as_deref(),
        Some("unverified"),
        "C1 regression: oauth_client_metadata.verification must remain 'unverified' \
         after an RFC 7592 PUT carrying metadata.portal.verification=verified. \
         Hydra PUT status: {put_status}, body: {put_body_text}"
    );

    // And the consent screen must still render the caution banner.
    let user = register_test_user("dcr-c1").await;
    let (cstatus, final_url, page) =
        render_consent_page(&user, &client_id, redirect_uri, audience, scope).await;
    assert!(
        cstatus.is_success(),
        "consent render status {cstatus} url {final_url}"
    );
    assert!(
        final_url.contains("/oauth/consent"),
        "must show consent screen, not auto-grant; final {final_url}"
    );
    assert!(
        page.contains("has not been reviewed by an administrator"),
        "consent page must still render the unverified banner; {} chars",
        page.len()
    );

    cleanup_dcr_client(&client_id).await;
    user.cleanup().await;
}
