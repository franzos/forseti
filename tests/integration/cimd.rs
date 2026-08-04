//! CIMD authorization shim (`GET /oauth2/authorize`) integration tests:
//! document validation rejections, non-CIMD passthrough, the admin-client
//! collision guard, loopback port-literal upsert + eviction, the warm-path
//! skip of the Hydra admin write, the golden-path flow (PKCE + RFC 8707
//! `resource=` + refresh-leg audience assertions), the ports of the retired
//! DCR suite's audience invariants (client-record-is-never-policy, the
//! no-metadata-row direct-Hydra client, resource_url provenance capture), and
//! the front proxy's discovery augmentation + redirect/cookie passthrough.
//!
//! Fixture CIMD documents are served from a tokio loopback listener inside
//! each test; `[oauth.cimd].allow_private_targets = true` in the playground
//! config lets the shim treat those `http://127.0.0.1:{port}/doc` URLs as
//! CIMD client_ids and fetch them past the SSRF guard.

use crate::common::*;
use reqwest::StatusCode;

// --- helpers local to this module -----------------------------------------

/// Serve a static CIMD document from a loopback listener; returns the doc URL,
/// which doubles as the client_id. `mutate` edits the Claude-shaped default
/// (whose `client_id` member echoes the URL exactly) before it is frozen.
async fn serve_cimd_doc(mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture listener");
    let addr = listener.local_addr().expect("fixture addr");
    let url = format!("http://{addr}/doc");
    let mut doc = serde_json::json!({
        "client_id": url,
        "client_name": "integration-test-cimd",
        "redirect_uris": ["http://127.0.0.1/callback", "http://localhost/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    mutate(&mut doc);
    let body = doc.to_string();
    let handler = move || {
        let body = body.clone();
        async move {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
        }
    };
    let app = axum::Router::new().route("/doc", axum::routing::get(handler));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    url
}

/// Drive the shim without following redirects. Returns status, the Location
/// header (empty when absent) and the body.
async fn shim_authorize(client_id: &str, redirect_uri: &str) -> (StatusCode, String, String) {
    let url = format!(
        "{PORTAL}/oauth2/authorize?client_id={}&response_type=code&scope=openid+offline\
         &redirect_uri={}&state=cimd-test",
        form_urlencode(client_id),
        form_urlencode(redirect_uri)
    );
    let res = manual_redirect_client()
        .get(&url)
        .send()
        .await
        .expect("shim transport");
    let status = res.status();
    let location = res
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = res.text().await.unwrap_or_default();
    (status, location, body)
}

/// GET the Hydra client row via the admin API. URL-shaped client_ids need the
/// path segment percent-encoded.
async fn hydra_get_client_json(client_id: &str) -> serde_json::Value {
    let res = browser_client()
        .get(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(client_id)
        ))
        .send()
        .await
        .expect("hydra get client transport");
    assert!(
        res.status().is_success(),
        "hydra get client {client_id}: status {}",
        res.status()
    );
    res.json().await.expect("hydra client json")
}

fn client_redirect_uris(client: &serde_json::Value) -> Vec<String> {
    client["redirect_uris"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// PKCE code_verifier + S256 code_challenge pair. Hydra enforces PKCE for
/// public clients, which every CIMD client is.
fn pkce_pair() -> (String, String) {
    use base64::Engine;
    use rand::RngExt;
    use sha2::Digest;
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    let mut h = sha2::Sha256::new();
    h.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
    (verifier, challenge)
}

/// Full shim authorize URL for a browser-style (session-carrying) flow. Uses
/// the issuer's host (not `localhost`) so Hydra's CSRF cookie set on the
/// first `/hydra/oauth2/auth` hop rides along on the resumed one. The
/// verifier is discarded — callers that exchange the code use
/// [`shim_auth_url_with`] with a caller-held pair.
fn shim_auth_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    shim_auth_url_with(client_id, redirect_uri, state, &pkce_pair().1, "")
}

/// As [`shim_auth_url`], with a caller-held PKCE challenge and extra query
/// parameters (`&key=value`-shaped, or empty).
fn shim_auth_url_with(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    extra: &str,
) -> String {
    format!(
        "http://host.containers.internal:3000/oauth2/authorize?client_id={}&response_type=code\
         &scope=openid+offline&redirect_uri={}&state={state}\
         &code_challenge={challenge}&code_challenge_method=S256{extra}",
        form_urlencode(client_id),
        form_urlencode(redirect_uri),
    )
}

/// Exchange an authorization code at Hydra's token endpoint as a public
/// client: no client_secret, PKCE verifier only. Returns the parsed token
/// response JSON.
async fn exchange_code_public(
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> serde_json::Value {
    let res = browser_client()
        .post(format!("{HYDRA_PUBLIC}/oauth2/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("code", code),
            ("code_verifier", verifier),
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
    res.json().await.expect("token body")
}

/// The `aud` claim of a decoded JWT as a list; absent/empty both come back
/// as an empty vec.
fn jwt_aud(claims: &serde_json::Value) -> Vec<String> {
    match &claims["aud"] {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Best-effort cleanup of a shim-created Hydra client (URL-shaped id).
async fn cleanup_cimd_client(client_id: &str) {
    let _ = browser_client()
        .delete(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(client_id)
        ))
        .send()
        .await;
}

// --- tests ----------------------------------------------------------------

/// The document's `client_id` member must equal the fetched URL byte-for-byte.
#[tokio::test]
async fn cimd_document_client_id_mismatch_rejected() {
    assert!(portal_reachable().await);

    let url = serve_cimd_doc(|d| {
        d["client_id"] = serde_json::json!("https://claude.ai/oauth/other-doc");
    })
    .await;
    let (status, _loc, body) = shim_authorize(&url, "http://127.0.0.1:43210/callback").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(
        body.contains("client_id"),
        "rejection must name the client_id mismatch; got: {body}"
    );
}

/// v1 accepts public clients only: any auth method but "none" is refused.
#[tokio::test]
async fn cimd_confidential_doc_rejected() {
    assert!(portal_reachable().await);

    let url = serve_cimd_doc(|d| {
        d["token_endpoint_auth_method"] = serde_json::json!("client_secret_basic");
    })
    .await;
    let (status, _loc, body) = shim_authorize(&url, "http://127.0.0.1:43210/callback").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(
        body.contains("token_endpoint_auth_method"),
        "rejection must name the auth method; got: {body}"
    );
}

/// A conventional (non-URL) client_id passes straight through to Hydra with
/// the query untouched — pre-registered clients never hit the CIMD machinery.
#[tokio::test]
async fn cimd_non_https_client_id_passes_through() {
    assert!(portal_reachable().await);

    let (status, location, body) = shim_authorize(
        "integration-test-cimd-passthrough",
        "http://127.0.0.1:5555/callback",
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "body: {body}");
    assert!(
        location.starts_with("/hydra/oauth2/auth"),
        "passthrough must 302 to the fronted Hydra authorize endpoint; got {location}"
    );
    assert!(
        location.contains("client_id=integration-test-cimd-passthrough"),
        "query must ride through byte-identical; got {location}"
    );
}

/// Invariant D.2: a CIMD flow must never create or mutate a Hydra client whose
/// metadata row has `source != 'cimd'`. Seed an admin-sourced row for the
/// fixture URL (what `/admin/clients` create would write) and drive the shim.
#[tokio::test]
async fn cimd_cannot_overwrite_admin_client() {
    assert!(portal_reachable().await);

    let url = serve_cimd_doc(|_| {}).await;
    // Inserts an `oauth_client_metadata` row with `source = 'admin'` — the
    // same trust state an admin-created URL-named client carries.
    mark_client_verified(&url);

    let (status, _loc, body) = shim_authorize(&url, "http://127.0.0.1:43210/callback").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(
        body.contains("collides"),
        "rejection must name the collision; got: {body}"
    );
}

/// Loopback port-literal compensation for Hydra's `localhost` gap: each flow
/// with a fresh ephemeral port upserts the literal onto the Hydra row, capped
/// at 5 with the oldest evicted; the document URIs are never evicted.
#[tokio::test]
async fn cimd_loopback_port_literal_upserted_and_capped() {
    assert!(portal_reachable().await);

    let url = serve_cimd_doc(|_| {}).await;
    let ports: Vec<u16> = (43301..=43306).collect();
    for port in &ports {
        let redirect = format!("http://127.0.0.1:{port}/callback");
        let (status, location, body) = shim_authorize(&url, &redirect).await;
        assert_eq!(status, StatusCode::FOUND, "port {port} body: {body}");
        assert!(
            location.starts_with("/hydra/oauth2/auth"),
            "port {port}: got {location}"
        );
    }

    let client = hydra_get_client_json(&url).await;
    let uris = client_redirect_uris(&client);
    for doc_uri in ["http://127.0.0.1/callback", "http://localhost/callback"] {
        assert!(
            uris.iter().any(|u| u == doc_uri),
            "document URI {doc_uri} must never be evicted; got {uris:?}"
        );
    }
    assert!(
        !uris
            .iter()
            .any(|u| u == &format!("http://127.0.0.1:{}/callback", ports[0])),
        "oldest literal (port {}) must be evicted; got {uris:?}",
        ports[0]
    );
    for port in &ports[1..] {
        assert!(
            uris.iter()
                .any(|u| u == &format!("http://127.0.0.1:{port}/callback")),
            "literal for port {port} must survive; got {uris:?}"
        );
    }
    assert_eq!(
        uris.len(),
        2 + 5,
        "row must hold the 2 document URIs + 5 capped literals; got {uris:?}"
    );

    cleanup_cimd_client(&url).await;
}

/// Design B hard requirement: a remembered consent must never skip the
/// consent screen for a `source='cimd'` client (the skip guard keys on
/// verification, and cimd rows are always unverified), and the rendered page
/// shows the client_id URL's host as the primary identity with the
/// self-asserted document name demoted to a secondary line — never the
/// verification badge.
#[tokio::test]
async fn cimd_consent_always_rendered_and_shows_host() {
    assert!(portal_reachable().await);

    let url = serve_cimd_doc(|_| {}).await;
    let redirect = "http://127.0.0.1:43377/callback";
    let user = register_test_user("cimd-consent-render").await;

    // First flow: land on the consent screen and accept with remember=true.
    let (consent_challenge, csrf, _body) = drive_to_consent(
        &user.client,
        &shim_auth_url(&url, redirect, "cimd-consent-1"),
    )
    .await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline"],
        true,
    )
    .await;
    assert!(code.is_some(), "remember=true accept must yield a code");

    // Second flow: Hydra now remembers the grant (skip=true), but an
    // unverified cimd client must still render the consent screen.
    let (_challenge2, _csrf2, body) = drive_to_consent(
        &user.client,
        &shim_auth_url(&url, redirect, "cimd-consent-2"),
    )
    .await;
    assert!(
        body.contains("Authorize 127.0.0.1"),
        "client_id URL host must render as the primary identity; got {} chars",
        body.len()
    );
    assert!(
        body.contains("integration-test-cimd"),
        "self-asserted client_name must render as the secondary line"
    );
    assert!(
        !body.contains("Reviewed by your administrator"),
        "the verification badge must never render for a cimd client"
    );

    cleanup_cimd_client(&url).await;
    user.cleanup().await;
}

/// Warm path: a second identical flow (same cached document, redirect_uri
/// already on the row) must skip the Hydra admin write entirely. An
/// out-of-band `client_name` canary distinguishes skip from an idempotent
/// rewrite: a cold-path upsert would reset it from the document.
#[tokio::test]
async fn cimd_warm_path_skips_admin_write() {
    assert!(portal_reachable().await);

    let url = serve_cimd_doc(|_| {}).await;
    let redirect = "http://127.0.0.1:43399/callback";

    let (status, _loc, body) = shim_authorize(&url, redirect).await;
    assert_eq!(status, StatusCode::FOUND, "first flow body: {body}");
    assert!(
        read_client_cimd_doc_hash(&url).is_some(),
        "first flow must store the document hash on the metadata row"
    );
    let uris_after_first = client_redirect_uris(&hydra_get_client_json(&url).await);

    // Canary a cold-path upsert would overwrite from the document.
    let patch = serde_json::json!([
        { "op": "replace", "path": "/client_name", "value": "cimd-warm-canary" }
    ]);
    let res = browser_client()
        .patch(format!(
            "{HYDRA_ADMIN}/admin/clients/{}",
            form_urlencode(&url)
        ))
        .header("content-type", "application/json")
        .json(&patch)
        .send()
        .await
        .expect("hydra patch transport");
    assert!(res.status().is_success(), "canary patch: {}", res.status());

    let (status, _loc, body) = shim_authorize(&url, redirect).await;
    assert_eq!(status, StatusCode::FOUND, "second flow body: {body}");

    let client = hydra_get_client_json(&url).await;
    assert_eq!(
        client["client_name"].as_str(),
        Some("cimd-warm-canary"),
        "warm path must not touch the Hydra row; a write would have reset the canary"
    );
    assert_eq!(
        client_redirect_uris(&client),
        uris_after_first,
        "redirect list must be unchanged after the identical second flow"
    );

    cleanup_cimd_client(&url).await;
}

/// The marquee CIMD flow, top to bottom: a fixture document on a loopback
/// port doubles as the URL client_id, PKCE auth-code runs through the shim
/// with RFC 8707 `resource=` naming an allow-listed resource, login+consent
/// complete programmatically, the code is exchanged as a public client, and
/// the JWT access token carries the granted `aud`. Then the **refresh** leg:
/// fosite re-validates the granted audience against the client record on
/// refresh (not on the code exchange), so the refreshed token only keeps its
/// `aud` because consent registered the granted audience onto the record.
#[tokio::test]
async fn cimd_golden_path_end_to_end() {
    assert!(portal_reachable().await);

    // Canonical form: `resource=https://mcp.test/` is granted without the
    // trailing slash.
    let resource = "https://mcp.test";
    let url = serve_cimd_doc(|_| {}).await;
    let redirect = "http://127.0.0.1:43411/callback";
    let user = register_test_user("cimd-golden").await;

    let (verifier, challenge) = pkce_pair();
    let auth_url = shim_auth_url_with(
        &url,
        redirect,
        "cimd-golden-1",
        &challenge,
        &format!("&resource={}", form_urlencode("https://mcp.test/")),
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline"],
        false,
    )
    .await
    .expect("authorization code on callback URL");

    // Consent is what registers the audience on the record, and only the
    // granted one — the refresh below breaks without it.
    assert_eq!(
        hydra_client_audience(&url).await,
        vec![resource.to_string()],
        "consent must register exactly the audience it granted"
    );

    let token = exchange_code_public(&url, redirect, &code, &verifier).await;
    let access_token = token["access_token"].as_str().expect("access_token");
    let refresh_token = token["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    let claims = decode_jwt_claims(access_token);
    assert!(
        jwt_aud(&claims).iter().any(|a| a == resource),
        "access token must carry the granted audience; got {claims}"
    );
    let scope = token["scope"].as_str().unwrap_or_default();
    assert!(
        scope.contains("openid") && scope.contains("offline"),
        "granted scope must survive into the token response; got {scope:?}"
    );

    // Refresh as the same public client: the CIMD URL is the client_id, no
    // client secret.
    let res = browser_client()
        .post(format!("{HYDRA_PUBLIC}/oauth2/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", url.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .expect("refresh transport");
    assert!(
        res.status().is_success(),
        "refresh must keep the granted audience; status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let refreshed: serde_json::Value = res.json().await.expect("refresh body");
    let refreshed_access = refreshed["access_token"]
        .as_str()
        .expect("refreshed access_token");
    let refreshed_claims = decode_jwt_claims(refreshed_access);
    assert!(
        jwt_aud(&refreshed_claims).iter().any(|a| a == resource),
        "refreshed access token must still carry the audience; got {refreshed_claims}"
    );
    let refreshed_scope = refreshed["scope"].as_str().unwrap_or_default();
    assert!(
        refreshed_scope.contains("openid") && refreshed_scope.contains("offline"),
        "granted scope must survive the refresh; got {refreshed_scope:?}"
    );

    cleanup_cimd_client(&url).await;
    user.cleanup().await;
}

/// Regression: consent used to dedup the audience write against the
/// source-filtered policy view of the record, which is empty for every client
/// no operator created — so a CIMD client re-appended the same audience on
/// every consent and its record grew without bound.
#[tokio::test]
async fn repeat_consent_does_not_duplicate_the_client_audience() {
    assert!(portal_reachable().await);

    let resource = "https://mcp.test";
    let url = serve_cimd_doc(|_| {}).await;
    let redirect = "http://127.0.0.1:43433/callback";
    let user = register_test_user("cimd-audience-dup").await;

    for round in 0..2 {
        let (_verifier, challenge) = pkce_pair();
        let auth_url = shim_auth_url_with(
            &url,
            redirect,
            &format!("cimd-dup-{round}"),
            &challenge,
            &format!("&resource={}", form_urlencode(resource)),
        );
        let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
        consent_accept_chase_code(
            &user.manual_client,
            &csrf,
            &consent_challenge,
            &["openid", "offline"],
            false,
        )
        .await
        .expect("authorization code on callback URL");
    }

    assert_eq!(
        hydra_client_audience(&url).await,
        vec![resource.to_string()],
        "a repeat consent for the same resource must not re-append it"
    );

    cleanup_cimd_client(&url).await;
    user.cleanup().await;
}

/// Port of `dcr_client_cannot_grant_itself_a_self_written_audience`: a CIMD
/// client's Hydra record stays reachable out of band (admin API here,
/// standing in for any credential that can rewrite the record), and fosite
/// validates `audience=` against exactly that record — so a self-written
/// audience passes the authorize gate and consent is the only gate left.
/// An audience on a `source='cimd'` record is never operator policy, so the
/// token's `aud` must not carry it.
#[tokio::test]
async fn cimd_client_record_audience_is_never_policy() {
    assert!(portal_reachable().await);

    // Deliberately not in `allowed_resource_audiences`: the allow-list arm is
    // a ceiling for every client, so it would mask what this pins.
    let self_written = "https://evil.mcp.test";
    let url = serve_cimd_doc(|_| {}).await;
    let redirect = "http://127.0.0.1:43422/callback";
    let user = register_test_user("cimd-self-write").await;

    // Cold-path flow creates the Hydra row the audience is then written onto.
    let (status, _loc, body) = shim_authorize(&url, redirect).await;
    assert_eq!(status, StatusCode::FOUND, "setup flow body: {body}");

    hydra_patch_client_audience(&url, &[self_written]).await;
    assert_eq!(
        hydra_client_audience(&url).await,
        vec![self_written.to_string()],
        "test setup: the record must carry the self-written audience"
    );

    let (verifier, challenge) = pkce_pair();
    let auth_url = shim_auth_url_with(
        &url,
        redirect,
        "cimd-self-write-2",
        &challenge,
        &format!("&audience={}", form_urlencode(self_written)),
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline"],
        false,
    )
    .await
    .expect("authorization code on callback URL");

    let token = exchange_code_public(&url, redirect, &code, &verifier).await;
    let claims = decode_jwt_claims(token["access_token"].as_str().expect("access_token"));
    assert!(
        !jwt_aud(&claims).iter().any(|a| a == self_written),
        "a cimd client's self-written audience must never reach the token; got {claims}"
    );

    cleanup_cimd_client(&url).await;
    user.cleanup().await;
}

/// Create a public (`token_endpoint_auth_method: none`) client straight via
/// Hydra's admin API, with a self-declared `audience` on the record and no
/// Forseti involvement. Returns the Hydra-minted client_id.
async fn hydra_admin_create_public_client(
    name: &str,
    scope: &str,
    redirect_uris: &[&str],
    audience: &[&str],
) -> String {
    let body = serde_json::json!({
        "client_name": name,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": scope,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "audience": audience,
    });
    let res = browser_client()
        .post(format!("{HYDRA_ADMIN}/admin/clients"))
        .json(&body)
        .send()
        .await
        .expect("hydra admin create transport");
    assert!(
        res.status().is_success(),
        "hydra admin create: status {} body {}",
        res.status(),
        res.text().await.unwrap_or_default()
    );
    let v: serde_json::Value = res.json().await.expect("hydra admin create body");
    v["client_id"].as_str().expect("client_id").to_string()
}

/// Port of dcr.rs `client_registered_outside_forseti_gets_no_audience`: a
/// client created straight against Hydra's admin API (standing in for any
/// out-of-band path now that DCR is retired) declares its own audience and
/// leaves no `oauth_client_metadata` row. No row is not evidence an operator
/// chose that audience, so consent ignores the record just as it does a
/// `source='cimd'` one.
#[tokio::test]
async fn client_registered_outside_forseti_gets_no_audience() {
    assert!(portal_reachable().await);

    // Unlisted, for the same reason as in the test above.
    let self_declared = "https://outside-forseti.test/mcp";
    let redirect_uri = "http://127.0.0.1:5555/callback";

    let client_id = hydra_admin_create_public_client(
        "integration-test-direct-hydra",
        "openid",
        &[redirect_uri],
        &[self_declared],
    )
    .await;
    assert_eq!(
        hydra_client_audience(&client_id).await,
        vec![self_declared.to_string()],
        "test setup: the admin API honours a declared audience"
    );
    assert!(
        read_client_metadata_row(&client_id).is_none(),
        "test setup: bypassing Forseti must leave no metadata row"
    );

    let user = register_test_user("direct-hydra").await;
    let (verifier, challenge) = pkce_pair();
    let auth_url = format!(
        "{HYDRA_PUBLIC}/oauth2/auth?client_id={client_id}\
         &response_type=code\
         &scope=openid\
         &redirect_uri={redirect_uri}\
         &state=direct-hydra\
         &audience={}\
         &code_challenge={challenge}\
         &code_challenge_method=S256",
        form_urlencode(self_declared)
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid"],
        false,
    )
    .await
    .expect("authorization code on callback URL");

    let token = exchange_code_public(&client_id, redirect_uri, &code, &verifier).await;
    let claims = decode_jwt_claims(token["access_token"].as_str().expect("access_token"));
    assert!(
        !jwt_aud(&claims).iter().any(|a| a == self_declared),
        "a client with no metadata row must not have its record trusted; got {claims}"
    );

    hydra_delete_client(&client_id).await;
    user.cleanup().await;
}

/// Port of dcr.rs `consent_captures_resource_url_from_request_url`: the lazy
/// `resource_url` provenance capture fires for every client with a metadata
/// row, CIMD included. Drive a flow with `?resource=` and assert the row got
/// stamped. Capture is provenance, not grant, so the resource needs no
/// registry row.
#[tokio::test]
async fn cimd_consent_captures_resource_url_from_request_url() {
    assert!(portal_reachable().await);

    let resource = "http://mcp.example.test/";
    let url = serve_cimd_doc(|_| {}).await;
    let redirect = "http://127.0.0.1:43444/callback";
    let user = register_test_user("cimd-resource-capture").await;

    let (verifier, challenge) = pkce_pair();
    let auth_url = shim_auth_url_with(
        &url,
        redirect,
        "cimd-resource-capture-1",
        &challenge,
        &format!("&resource={}", form_urlencode(resource)),
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline"],
        false,
    )
    .await
    .expect("authorization code on callback URL");

    // Exchange so the flow completes end-to-end; the capture fires from the
    // consent POST, but a real RP always exchanges.
    let _token = exchange_code_public(&url, redirect, &code, &verifier).await;

    let (_audience, resource_url) =
        read_client_provenance(&url).expect("oauth_client_metadata row inserted by the CIMD shim");
    assert_eq!(
        resource_url.as_deref(),
        Some(resource),
        "consent flow must stamp resource_url from the `?resource=` query param"
    );

    cleanup_cimd_client(&url).await;
    user.cleanup().await;
}

/// Drive a full CIMD PKCE flow requesting RFC 8707 `resource=` and return
/// the access token's `aud`. Owns (and cleans up) its fixture doc, user and
/// the shim-created Hydra client; registry rows are the caller's business.
/// `pub(crate)`: the admin-UI registry tests (`resources_admin.rs`) reuse it.
pub(crate) async fn cimd_flow_aud(resource: &str, redirect_port: u16, tag: &str) -> Vec<String> {
    let url = serve_cimd_doc(|_| {}).await;
    let redirect = format!("http://127.0.0.1:{redirect_port}/callback");
    let user = register_test_user(tag).await;

    let (verifier, challenge) = pkce_pair();
    let auth_url = shim_auth_url_with(
        &url,
        &redirect,
        &format!("{tag}-1"),
        &challenge,
        &format!("&resource={}", form_urlencode(resource)),
    );
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline"],
        false,
    )
    .await
    .expect("authorization code on callback URL");
    let token = exchange_code_public(&url, &redirect, &code, &verifier).await;
    let claims = decode_jwt_claims(token["access_token"].as_str().expect("access_token"));

    cleanup_cimd_client(&url).await;
    user.cleanup().await;
    jwt_aud(&claims)
}

/// Task 11 arm swap: a resource enrolled ONLY in the registry — never in
/// `[oauth].allowed_resource_audiences` — binds into the token's `aud`.
#[tokio::test]
async fn registry_resource_binds_audience() {
    assert!(portal_reachable().await);

    let resource = "https://registry-only.mcp.test";
    seed_registry_resource(resource);
    // Explicit, in case a prior run left the shared row disabled.
    set_registry_resource_enabled(resource, true);

    let aud = cimd_flow_aud(resource, 43431, "cimd-registry-bind").await;
    delete_registry_resource(resource);
    assert!(
        aud.iter().any(|a| a == resource),
        "a registry-enrolled resource must bind into the audience; got {aud:?}"
    );
}

/// The same row disabled must deny the audience — `enabled` is the gate,
/// not mere row existence.
#[tokio::test]
async fn registry_disabled_resource_is_denied() {
    assert!(portal_reachable().await);

    let resource = "https://registry-only.mcp.test";
    seed_registry_resource(resource);
    set_registry_resource_enabled(resource, false);

    let aud = cimd_flow_aud(resource, 43432, "cimd-registry-disabled").await;
    delete_registry_resource(resource);
    assert!(
        aud.is_empty(),
        "a disabled registry row must not bind an audience; got {aud:?}"
    );
}

/// Default deny survives the arm swap: a resource with no registry row at
/// all is dropped.
#[tokio::test]
async fn unregistered_resource_is_denied() {
    assert!(portal_reachable().await);

    let aud = cimd_flow_aud(
        "https://never-registered.mcp.test",
        43433,
        "cimd-registry-none",
    )
    .await;
    assert!(
        aud.is_empty(),
        "an unregistered resource must not bind an audience; got {aud:?}"
    );
}

/// The running server imported the deprecated config entries at boot:
/// `https://mcp.test` (listed in the playground + CI config) must exist as
/// an enabled registry row created by `config-import`.
#[tokio::test]
async fn config_import_seeded_registry_rows() {
    assert!(portal_reachable().await);

    let (enabled, created_by) = read_registry_resource("https://mcp.test")
        .expect("boot import must have seeded a row for https://mcp.test");
    assert!(enabled, "the imported row must be enabled");
    assert_eq!(
        created_by, "config-import",
        "the imported row must be attributed to the config import"
    );
}

/// Design A: all three discovery surfaces — both path-insertion routes on the
/// portal origin and the passthrough's special case — serve Hydra's document
/// with the CIMD mutations, CORS `*`, and the issuer untouched.
#[tokio::test]
async fn front_proxy_discovery_is_augmented_with_cors() {
    assert!(portal_reachable().await);

    for url in [
        format!("{PORTAL}/.well-known/oauth-authorization-server/hydra"),
        format!("{PORTAL}/.well-known/openid-configuration/hydra"),
        "http://host.containers.internal:3000/hydra/.well-known/openid-configuration".to_string(),
    ] {
        let res = browser_client()
            .get(&url)
            .send()
            .await
            .expect("discovery transport");
        assert!(res.status().is_success(), "{url}: status {}", res.status());
        let cors = res
            .headers()
            .get("access-control-allow-origin")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(cors, "*", "{url}: discovery must be CORS-open");

        let doc: serde_json::Value = res.json().await.expect("discovery json");
        assert_eq!(
            doc["client_id_metadata_document_supported"],
            serde_json::json!(true),
            "{url}: must advertise CIMD support"
        );
        assert!(
            doc.get("registration_endpoint").is_none(),
            "{url}: registration_endpoint must be removed"
        );
        assert_eq!(
            doc["issuer"],
            serde_json::json!("http://host.containers.internal:3000/hydra"),
            "{url}: issuer must stay Hydra's, byte-identical"
        );
    }
}

/// M0 lesson 1: the passthrough must behave like haproxy — hand Hydra's 3xx
/// to the caller unfollowed and let the (multi-valued) Set-Cookie ride
/// through, or Hydra's flow CSRF checks fail on the resumed hop.
#[tokio::test]
async fn front_proxy_forwards_cookies_and_does_not_follow_redirects() {
    assert!(portal_reachable().await);

    let (client_id, _secret, redirect_uri) = hydra_create_test_client(&["openid"]).await;
    // Syntactically plausible but bogus flow: real client, throwaway state.
    let url = format!(
        "http://host.containers.internal:3000/hydra/oauth2/auth?client_id={}&response_type=code\
         &scope=openid&redirect_uri={}&state=front-proxy-bogus",
        form_urlencode(&client_id),
        form_urlencode(&redirect_uri),
    );
    let res = manual_redirect_client()
        .get(&url)
        .send()
        .await
        .expect("front proxy transport");
    assert!(
        res.status().is_redirection(),
        "Hydra's 3xx must surface unfollowed; got {}",
        res.status()
    );
    let set_cookies = res
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .count();
    assert!(
        set_cookies >= 1,
        "Hydra's Set-Cookie must ride through the proxy"
    );

    hydra_delete_client(&client_id).await;
}
