//! `/settings/resource-claims`: self-service resource claim linking against
//! the stack's mock-oauth2-server.

use crate::common::*;

const PAGE: &str = "/settings/resource-claims";

/// Deletes the listed `resource_registry` rows and organizations when
/// dropped, so a failed assertion leaves no self-service claim behind.
#[derive(Default)]
struct Fixtures {
    resources: Vec<String>,
    orgs: Vec<String>,
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        for r in &self.resources {
            delete_registry_resource(r);
        }
        for o in &self.orgs {
            delete_organization(o);
        }
    }
}

fn unique_suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Seed an enabled default-org row with self-service on claim `ss_<sfx>`
/// against the mock issuer; returns `(resource, claim, id)`.
fn seed_self_service_row(fx: &mut Fixtures, label: &str, template: &str) -> (String, String, i64) {
    let sfx = unique_suffix();
    let resource = format!("https://{label}-{sfx}.claims.test/mcp");
    let claim = format!("ss_{sfx}");
    fx.resources.push(resource.clone());
    seed_registry_resource(&resource);
    set_registry_resource_claims(&resource, &claim);
    set_registry_resource_self_service(
        &resource,
        &claim,
        MOCK_OIDC_ISSUER,
        "claims-test-client",
        template,
    );
    let (id, _) = read_registry_resource_claims(&resource).expect("seeded row");
    (resource, claim, id)
}

async fn get_page(client: &reqwest::Client) -> reqwest::Response {
    client
        .get(format!("{PORTAL}{PAGE}"))
        .send()
        .await
        .expect("GET resource claims page")
}

#[tokio::test]
async fn resource_claims_page_redirects_anonymous_to_login() {
    let res = get_page(&manual_redirect_client()).await;
    assert_eq!(res.status().as_u16(), 303);
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    assert!(loc.contains("/login"), "got {loc}");
}

/// A visible default-org row lists its name, resource, a value input (the
/// template has `{uuid}`), the start form, and whether a value is set; the
/// page's CSP lets the start form reach the issuer. Rows that are disabled
/// stay off the page; with no visible rows the empty state shows.
#[tokio::test]
async fn resource_claims_page_lists_a_visible_row() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-list").await;
    let mut fx = Fixtures::default();
    let (resource, claim, id) = seed_self_service_row(&mut fx, "visible", "u:{sub}:{uuid}");
    let (disabled, _, disabled_id) = seed_self_service_row(&mut fx, "disabled", "{sub}");
    set_registry_resource_enabled(&disabled, false);

    let res = get_page(&user.client).await;
    assert!(res.status().is_success(), "status {}", res.status());
    let csp = res
        .headers()
        .get("content-security-policy")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        csp.contains("form-action") && csp.contains("http://host.containers.internal:8092"),
        "issuer origin allowed in form-action; got {csp}"
    );
    let body = res.text().await.expect("body");
    assert!(body.contains(&resource), "row listed");
    assert!(body.contains(&claim), "claim shown");
    assert!(
        body.contains(&format!("action=\"/settings/resource-claims/{id}/start\"")),
        "start form"
    );
    assert!(body.contains(&format!("id=\"value-{id}\"")), "value input");
    assert!(
        !body.contains(&format!("/settings/resource-claims/{id}/remove")),
        "no remove form without a value"
    );
    assert!(!body.contains(&disabled), "disabled row hidden");
    assert!(
        !body.contains(&format!("/settings/resource-claims/{disabled_id}/start")),
        "disabled row has no start form"
    );

    let mut metadata = serde_json::Map::new();
    metadata.insert(claim.clone(), "u:1:x".into());
    kratos_set_metadata_admin(&user.identity_id, metadata.into()).await;
    let body = get_page(&user.client).await.text().await.expect("body");
    assert!(
        body.contains(&format!("action=\"/settings/resource-claims/{id}/remove\"")),
        "remove form once a value is set"
    );

    drop(fx);
    let body = get_page(&user.client).await.text().await.expect("body");
    assert!(!body.contains(&resource), "row gone after cleanup");
    if !body.contains("/start\"") {
        assert!(
            body.contains("No resources offer account linking."),
            "empty state"
        );
    }
    user.cleanup().await;
}

/// A row in a named org shows only to members of that org.
#[tokio::test]
async fn resource_claims_page_hides_named_org_rows_from_non_members() {
    assert!(portal_reachable().await);
    let member = register_test_user("claims-member").await;
    let outsider = register_test_user("claims-outsider").await;
    let mut fx = Fixtures::default();
    let (resource, _, id) = seed_self_service_row(&mut fx, "named-org", "{sub}");
    let org = format!("org-{}", unique_suffix());
    seed_organization(&org, &org, "Claims Org", "all");
    fx.orgs.push(org.clone());
    seed_org_membership(&org, &member.identity_id, "member");
    set_registry_resource_org(&resource, &org);

    let body = get_page(&outsider.client).await.text().await.expect("body");
    assert!(!body.contains(&resource), "hidden from a non-member");
    assert!(!body.contains(&format!("/settings/resource-claims/{id}/start")));

    let body = get_page(&member.client).await.text().await.expect("body");
    assert!(body.contains(&resource), "shown to a member");
    assert!(
        !body.contains(&format!("id=\"value-{id}\"")),
        "no value input for a {{sub}}-only template"
    );

    member.cleanup().await;
    outsider.cleanup().await;
}

const UUID: &str = "0b6f7d3c-1a2b-4c3d-8e9f-0a1b2c3d4e5f";

/// The `_csrf` token from the list page, read with `user`'s cookie jar.
async fn page_csrf(user: &RegisteredUser) -> String {
    let body = get_page(&user.client).await.text().await.expect("body");
    extract_csrf_form_token(&body).expect("_csrf on the page")
}

/// POST the start form for row `id` without following the redirect.
async fn post_start(user: &RegisteredUser, id: i64, form: &[(&str, &str)]) -> reqwest::Response {
    user.manual_client
        .post(format!("{PORTAL}{PAGE}/{id}/start"))
        .form(form)
        .send()
        .await
        .expect("POST start")
}

fn location(res: &reqwest::Response) -> String {
    res.headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn link_failed_reason(identity_id: &str) -> Option<String> {
    let ev = latest_audit_event("resource.claim.link_failed", identity_id)?;
    ev.metadata
        .get("reason")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Start sends the browser to the mock's authorization endpoint with PKCE
/// (S256), state, nonce and the fixed redirect URI, and sets the path-scoped
/// link cookie; signing in at the mock lands on that redirect URI with the
/// same state.
#[tokio::test]
async fn resource_claim_start_redirects_to_the_issuer() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-start").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "start", "u:{sub}:{uuid}");
    let csrf = page_csrf(&user).await;

    let value = format!("u:42:{UUID}");
    let res = post_start(&user, id, &[("_csrf", &csrf), ("value", &value)]).await;
    assert_eq!(res.status().as_u16(), 303);
    let loc = location(&res);
    assert!(
        loc.starts_with(&format!("{MOCK_OIDC_ISSUER}/authorize?")),
        "Location targets the mock's authorize endpoint; got {loc}"
    );
    let param = |name: &str| extract_query_param(&loc, name);
    assert_eq!(param("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(param("response_type").as_deref(), Some("code"));
    assert_eq!(param("client_id").as_deref(), Some("claims-test-client"));
    assert_eq!(
        param("redirect_uri").as_deref(),
        Some("http://localhost:3000/settings/resource-claims/callback")
    );
    let state = param("state").expect("state");
    assert!(state.len() >= 43, "state carries 256 bits");
    assert!(param("nonce").is_some_and(|n| !n.is_empty()), "nonce");
    assert!(
        param("code_challenge").is_some_and(|c| c.len() == 43),
        "S256 challenge"
    );
    assert!(!loc.contains(UUID), "the value stays out of the URL");

    let cookie = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find(|c| c.starts_with("forseti_claim_link="))
        .expect("link cookie set")
        .to_string();
    assert!(
        cookie.contains("Path=/settings/resource-claims"),
        "{cookie}"
    );
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");

    let callback = mock_oidc_login(&loc, "42").await;
    assert!(
        callback.starts_with("http://localhost:3000/settings/resource-claims/callback?"),
        "mock returns to the callback; got {callback}"
    );
    assert_eq!(extract_query_param(&callback, "state"), Some(state));
    assert!(extract_query_param(&callback, "code").is_some(), "code");

    user.cleanup().await;
}

/// A value that doesn't match the template is refused before any redirect:
/// flashed and audited, without the value in the audit row.
#[tokio::test]
async fn resource_claim_start_refuses_a_malformed_value() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-malformed").await;
    let mut fx = Fixtures::default();
    let (resource, claim, id) = seed_self_service_row(&mut fx, "malformed", "u:{sub}:{uuid}");
    let csrf = page_csrf(&user).await;

    let value = format!("u:42:{}", UUID.to_uppercase());
    let res = post_start(&user, id, &[("_csrf", &csrf), ("value", &value)]).await;
    assert_eq!(res.status().as_u16(), 303);
    assert_eq!(location(&res), PAGE);
    assert!(
        !res.headers().get_all("set-cookie").iter().any(|h| h
            .to_str()
            .is_ok_and(|c| c.starts_with("forseti_claim_link="))),
        "no link cookie"
    );

    let body = get_page(&user.client).await.text().await.expect("body");
    assert!(
        body.contains("That value doesn&#39;t have the expected format.")
            || body.contains("That value doesn't have the expected format."),
        "flash shown"
    );
    let ev = latest_audit_event("resource.claim.link_failed", &user.identity_id)
        .expect("link_failed audited");
    assert_eq!(ev.metadata["reason"], "invalid_value");
    assert_eq!(ev.metadata["resource"], resource.as_str());
    assert_eq!(ev.metadata["claim"], claim.as_str());
    assert!(
        !ev.metadata.to_string().to_lowercase().contains(UUID),
        "value not audited"
    );

    user.cleanup().await;
}

/// Disabled, unconfigured and unknown rows get the same refusal.
#[tokio::test]
async fn resource_claim_start_refuses_unavailable_rows() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-unavailable").await;
    let mut fx = Fixtures::default();
    let (disabled, _, disabled_id) = seed_self_service_row(&mut fx, "off", "{sub}");
    set_registry_resource_enabled(&disabled, false);
    let (plain, _, plain_id) = seed_self_service_row(&mut fx, "plain", "{sub}");
    set_registry_resource_self_service(&plain, "", "", "", "");
    let csrf = page_csrf(&user).await;

    for id in [disabled_id, plain_id, i64::MAX] {
        let res = post_start(&user, id, &[("_csrf", &csrf)]).await;
        assert_eq!(res.status().as_u16(), 303, "row {id}");
        assert_eq!(location(&res), PAGE, "row {id}");
        assert_eq!(
            link_failed_reason(&user.identity_id).as_deref(),
            Some("not_available"),
            "row {id}"
        );
        let body = get_page(&user.client).await.text().await.expect("body");
        assert!(
            body.contains("That resource isn&#39;t available for linking.")
                || body.contains("That resource isn't available for linking."),
            "flash shown for row {id}"
        );
    }

    user.cleanup().await;
}

/// Start is a CSRF-protected POST.
#[tokio::test]
async fn resource_claim_start_requires_csrf() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-csrf").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "csrf", "{sub}");
    let _ = page_csrf(&user).await;

    let res = post_start(&user, id, &[]).await;
    assert_eq!(res.status().as_u16(), 403);
    let res = post_start(&user, id, &[("_csrf", "forged")]).await;
    assert_eq!(res.status().as_u16(), 403);
    assert_eq!(
        link_failed_reason(&user.identity_id),
        None,
        "nothing audited"
    );

    user.cleanup().await;
}

const UUID_2: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

/// POST start with a fresh CSRF token and return the issuer authorize URL.
async fn start_link(user: &RegisteredUser, id: i64, value: &str) -> String {
    let csrf = page_csrf(user).await;
    let res = post_start(user, id, &[("_csrf", &csrf), ("value", value)]).await;
    assert_eq!(res.status().as_u16(), 303, "start");
    let loc = location(&res);
    assert!(loc.starts_with(MOCK_OIDC_ISSUER), "start went to {loc}");
    loc
}

/// GET the callback URL without following the redirect.
async fn get_callback(client: &reqwest::Client, url: &str) -> reqwest::Response {
    client.get(url).send().await.expect("GET callback")
}

fn clears_link_cookie(res: &reqwest::Response) -> bool {
    res.headers().get_all("set-cookie").iter().any(|h| {
        h.to_str().is_ok_and(|c| {
            c.starts_with("forseti_claim_link=;") && c.contains("Expires=Thu, 01 Jan 1970")
        })
    })
}

/// Assert the callback answered with a redirect to the list page that clears
/// the link cookie.
fn assert_back_on_page(res: &reqwest::Response) {
    assert_eq!(res.status().as_u16(), 303, "callback status");
    assert_eq!(location(res), PAGE, "callback redirects to the list page");
    assert!(clears_link_cookie(res), "callback clears the link cookie");
}

async fn kratos_metadata_admin(identity_id: &str) -> serde_json::Value {
    let res = browser_client()
        .get(format!("{KRATOS_ADMIN}/admin/identities/{identity_id}"))
        .send()
        .await
        .expect("GET identity");
    assert!(res.status().is_success(), "GET identity: {}", res.status());
    let identity: serde_json::Value = res.json().await.expect("identity body");
    identity["metadata_admin"].clone()
}

async fn page_shows(user: &RegisteredUser, text: &str) -> bool {
    get_page(&user.client)
        .await
        .text()
        .await
        .expect("body")
        .contains(text)
}

/// POST remove for row `id` with a fresh CSRF token.
async fn post_remove(user: &RegisteredUser, id: i64) -> reqwest::Response {
    let csrf = page_csrf(user).await;
    user.manual_client
        .post(format!("{PORTAL}{PAGE}/{id}/remove"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST remove")
}

/// Signing in at the issuer as the `sub` the value names writes the value
/// onto an identity whose `metadata_admin` is null, audited critical with the
/// upstream `sub`; linking again replaces it; remove drops it, and a second
/// remove has nothing to drop and audits nothing.
#[tokio::test]
async fn resource_claim_link_replace_and_remove() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-link").await;
    let mut fx = Fixtures::default();
    let (resource, claim, id) = seed_self_service_row(&mut fx, "link", "u:{sub}:{uuid}");
    assert!(
        kratos_metadata_admin(&user.identity_id).await.is_null(),
        "fixture starts with null metadata_admin"
    );

    let res = post_remove(&user, id).await;
    assert_eq!(location(&res), PAGE);
    assert!(page_shows(&user, "There was no linked value to remove.").await);
    assert!(
        latest_audit_event("resource.claim.removed", &user.identity_id).is_none(),
        "nothing removed, nothing audited"
    );

    let value = format!("u:42:{UUID}");
    let auth = start_link(&user, id, &value).await;
    let callback = mock_oidc_login(&auth, "42").await;
    let res = get_callback(&user.manual_client, &callback).await;
    assert_back_on_page(&res);
    assert!(page_shows(&user, "Account linked.").await, "success flash");
    assert_eq!(
        kratos_metadata_admin(&user.identity_id).await,
        serde_json::json!({ claim.as_str(): value }),
    );
    let ev = latest_audit_event("resource.claim.linked", &user.identity_id).expect("linked");
    assert_eq!(ev.severity, "critical");
    assert_eq!(ev.actor_kind, "user");
    assert_eq!(ev.metadata["resource"], resource.as_str());
    assert_eq!(ev.metadata["claim"], claim.as_str());
    assert_eq!(ev.metadata["upstream_sub"], "42");
    assert!(!ev.metadata.to_string().contains(UUID), "value not audited");

    let replaced = format!("u:43:{UUID_2}");
    let auth = start_link(&user, id, &replaced).await;
    let callback = mock_oidc_login(&auth, "43").await;
    assert_back_on_page(&get_callback(&user.manual_client, &callback).await);
    assert_eq!(
        kratos_metadata_admin(&user.identity_id).await[&claim],
        replaced.as_str(),
        "linking again replaces the value"
    );

    let res = post_remove(&user, id).await;
    assert_eq!(res.status().as_u16(), 303);
    assert_eq!(location(&res), PAGE);
    assert!(page_shows(&user, "Link removed.").await, "removed flash");
    assert!(
        kratos_metadata_admin(&user.identity_id)
            .await
            .get(&claim)
            .is_none(),
        "value removed"
    );
    let ev = latest_audit_event("resource.claim.removed", &user.identity_id).expect("removed");
    assert_eq!(ev.severity, "critical");
    assert_eq!(ev.metadata["claim"], claim.as_str());

    let res = post_remove(&user, id).await;
    assert_eq!(location(&res), PAGE);
    assert!(page_shows(&user, "There was no linked value to remove.").await);

    user.cleanup().await;
}

/// A `{sub}` template needs no value; the link adds its key next to an
/// existing `metadata_admin` key and leaves that key alone.
#[tokio::test]
async fn resource_claim_link_keeps_sibling_keys() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-sibling").await;
    let mut fx = Fixtures::default();
    let (_, claim, id) = seed_self_service_row(&mut fx, "sibling", "{sub}");
    kratos_set_metadata_admin(
        &user.identity_id,
        serde_json::json!({"note": {"kept": true}}),
    )
    .await;

    let auth = start_link(&user, id, "").await;
    let callback = mock_oidc_login(&auth, "alice-7").await;
    assert_back_on_page(&get_callback(&user.manual_client, &callback).await);
    assert_eq!(
        kratos_metadata_admin(&user.identity_id).await,
        serde_json::json!({"note": {"kept": true}, claim.as_str(): "alice-7"}),
    );

    user.cleanup().await;
}

/// Signing in as a different upstream account than the value names writes
/// nothing; the audit row names the `sub` that signed in.
#[tokio::test]
async fn resource_claim_link_refuses_a_value_mismatch() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-mismatch").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "mismatch", "u:{sub}:{uuid}");

    let auth = start_link(&user, id, &format!("u:42:{UUID}")).await;
    let callback = mock_oidc_login(&auth, "99").await;
    assert_back_on_page(&get_callback(&user.manual_client, &callback).await);
    assert!(
        page_shows(&user, "match the value you entered").await,
        "mismatch flash"
    );
    assert!(kratos_metadata_admin(&user.identity_id).await.is_null());
    let ev = latest_audit_event("resource.claim.link_failed", &user.identity_id).expect("audited");
    assert_eq!(ev.metadata["reason"], "value_mismatch");
    assert_eq!(ev.metadata["upstream_sub"], "99");

    user.cleanup().await;
}

/// A callback whose `state` differs from the link cookie's is refused before
/// the code is exchanged.
#[tokio::test]
async fn resource_claim_callback_refuses_a_tampered_state() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-state").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "state", "{sub}");

    let auth = start_link(&user, id, "").await;
    let callback = mock_oidc_login(&auth, "7").await;
    let state = extract_query_param(&callback, "state").expect("state");
    let tampered = callback.replace(&format!("state={state}"), "state=forged");
    assert_ne!(tampered, callback);
    assert_back_on_page(&get_callback(&user.manual_client, &tampered).await);
    assert!(page_shows(&user, "Please start again.").await, "flash");
    assert_eq!(
        link_failed_reason(&user.identity_id).as_deref(),
        Some("state_mismatch")
    );
    assert!(kratos_metadata_admin(&user.identity_id).await.is_null());

    user.cleanup().await;
}

/// Another identity's session replaying the callback with the first
/// identity's link cookie writes nothing to either identity.
#[tokio::test]
async fn resource_claim_callback_refuses_another_identitys_cookie() {
    assert!(portal_reachable().await);
    let alice = register_test_user("claims-alice").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "replay", "{sub}");

    let csrf = page_csrf(&alice).await;
    let res = post_start(&alice, id, &[("_csrf", &csrf)]).await;
    let link_cookie = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find(|c| c.starts_with("forseti_claim_link="))
        .and_then(|c| c.split(';').next())
        .expect("link cookie")
        .to_string();
    let callback = mock_oidc_login(&location(&res), "7").await;

    let (bob_client, bob_manual, jar) = paired_clients();
    let (bob_id, _, _) = register_test_user_with_client(&bob_client, "claims-bob").await;
    jar.add_cookie_str(
        &format!("{link_cookie}; Path=/settings/resource-claims"),
        &PORTAL.parse().expect("portal url"),
    );
    let res = get_callback(&bob_manual, &callback).await;
    assert_back_on_page(&res);
    assert_eq!(
        link_failed_reason(&bob_id).as_deref(),
        Some("identity_mismatch")
    );
    assert!(kratos_metadata_admin(&bob_id).await.is_null());
    assert!(kratos_metadata_admin(&alice.identity_id).await.is_null());

    let _ = delete_test_identity(&bob_id).await;
    alice.cleanup().await;
}

/// A session that ended between start and callback fails the link without a
/// detour through login; the audit row targets the identity the cookie names.
#[tokio::test]
async fn resource_claim_callback_without_a_session_fails() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-nosession").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "nosession", "{sub}");

    let auth = start_link(&user, id, "").await;
    let callback = mock_oidc_login(&auth, "7").await;
    kratos_admin_end_sessions(&user.identity_id).await;
    let res = get_callback(&user.manual_client, &callback).await;
    assert_back_on_page(&res);
    let ev = latest_audit_event("resource.claim.link_failed", &user.identity_id).expect("audited");
    assert_eq!(ev.metadata["reason"], "no_session");
    assert_eq!(ev.actor_kind, "system", "no signed-in actor");
    assert!(kratos_metadata_admin(&user.identity_id).await.is_null());

    user.cleanup().await;
}

/// An upstream `error` fails the link; the upstream description is neither
/// flashed nor audited.
#[tokio::test]
async fn resource_claim_callback_reports_an_upstream_error() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-denied").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "denied", "{sub}");

    let auth = start_link(&user, id, "").await;
    let state = extract_query_param(&auth, "state").expect("state");
    let url = format!(
        "{PORTAL}{PAGE}/callback?error=access_denied&error_description=upstream-said-no&state={state}"
    );
    assert_back_on_page(&get_callback(&user.manual_client, &url).await);
    let body = get_page(&user.client).await.text().await.expect("body");
    assert!(body.contains("Could not link your account."), "flash");
    assert!(
        !body.contains("upstream-said-no"),
        "description not flashed"
    );
    let ev = latest_audit_event("resource.claim.link_failed", &user.identity_id).expect("audited");
    assert_eq!(ev.metadata["reason"], "upstream_error");
    assert!(!ev.metadata.to_string().contains("upstream-said-no"));
    assert!(kratos_metadata_admin(&user.identity_id).await.is_null());

    user.cleanup().await;
}

/// Remove is a CSRF-protected POST and refuses rows that aren't available.
#[tokio::test]
async fn resource_claim_remove_requires_csrf_and_an_available_row() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-remove-gates").await;
    let mut fx = Fixtures::default();
    let (resource, claim, id) = seed_self_service_row(&mut fx, "remove-gates", "{sub}");
    kratos_set_metadata_admin(
        &user.identity_id,
        serde_json::json!({ claim.as_str(): "7" }),
    )
    .await;
    let _ = page_csrf(&user).await;

    let res = user
        .manual_client
        .post(format!("{PORTAL}{PAGE}/{id}/remove"))
        .form(&[("_csrf", "forged")])
        .send()
        .await
        .expect("POST remove");
    assert_eq!(res.status().as_u16(), 403);

    set_registry_resource_enabled(&resource, false);
    let res = post_remove(&user, id).await;
    assert_eq!(location(&res), PAGE);
    assert!(
        page_shows(&user, "available for linking.").await,
        "not available flash"
    );
    assert_eq!(
        kratos_metadata_admin(&user.identity_id).await[&claim],
        "7",
        "value untouched"
    );

    user.cleanup().await;
}

/// Turning the row's self-service off between start and callback refuses the
/// link and writes nothing.
#[tokio::test]
async fn resource_claim_callback_refuses_a_row_turned_off_meanwhile() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-turned-off").await;
    let mut fx = Fixtures::default();
    let (resource, _, id) = seed_self_service_row(&mut fx, "turned-off", "{sub}");

    let auth = start_link(&user, id, "").await;
    let callback = mock_oidc_login(&auth, "7").await;
    set_registry_resource_self_service(&resource, "", "", "", "");
    assert_back_on_page(&get_callback(&user.manual_client, &callback).await);
    assert_eq!(
        link_failed_reason(&user.identity_id).as_deref(),
        Some("not_available")
    );
    assert!(kratos_metadata_admin(&user.identity_id).await.is_null());

    user.cleanup().await;
}

/// A link cookie with a broken signature is treated as absent: "start
/// again", nothing written, no audit row.
#[tokio::test]
async fn resource_claim_callback_ignores_a_tampered_cookie() {
    assert!(portal_reachable().await);
    let (client, manual_client, jar) = paired_clients();
    let (identity_id, email, password) =
        register_test_user_with_client(&client, "claims-cookie").await;
    mark_identity_verified(&identity_id).await;
    let user = RegisteredUser {
        client,
        manual_client,
        identity_id,
        email,
        password,
    };
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "cookie", "{sub}");

    let csrf = page_csrf(&user).await;
    let res = post_start(&user, id, &[("_csrf", &csrf)]).await;
    let pair = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find(|c| c.starts_with("forseti_claim_link="))
        .and_then(|c| c.split(';').next())
        .expect("link cookie")
        .to_string();
    let callback = mock_oidc_login(&location(&res), "7").await;
    let mut tampered = pair.into_bytes();
    let mid = tampered.len() / 2;
    tampered[mid] = if tampered[mid] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("ascii cookie");
    jar.add_cookie_str(
        &format!("{tampered}; Path=/settings/resource-claims"),
        &PORTAL.parse().expect("portal url"),
    );

    assert_back_on_page(&get_callback(&user.manual_client, &callback).await);
    assert!(page_shows(&user, "Please start again.").await, "flash");
    assert_eq!(link_failed_reason(&user.identity_id), None, "no audit row");
    assert!(kratos_metadata_admin(&user.identity_id).await.is_null());

    user.cleanup().await;
}

/// An RFC 9207 `iss` that differs from the discovered issuer refuses the link.
#[tokio::test]
async fn resource_claim_callback_refuses_a_foreign_iss() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-iss").await;
    let mut fx = Fixtures::default();
    let (_, _, id) = seed_self_service_row(&mut fx, "iss", "{sub}");

    let auth = start_link(&user, id, "").await;
    let callback = mock_oidc_login(&auth, "7").await;
    let mut url = reqwest::Url::parse(&callback).expect("callback url");
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "iss")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("iss", "https://issuer.example.com");
    assert_back_on_page(&get_callback(&user.manual_client, url.as_str()).await);
    assert_eq!(
        link_failed_reason(&user.identity_id).as_deref(),
        Some("issuer_mismatch")
    );
    assert!(kratos_metadata_admin(&user.identity_id).await.is_null());

    user.cleanup().await;
}

/// A value linked through the self-service flow reaches access tokens for
/// its resource (under `ext`; the claim isn't in Hydra's
/// `allowed_top_level_claims`) and not for a resource without the claim.
#[tokio::test]
async fn resource_claim_linked_value_reaches_the_access_token() {
    assert!(portal_reachable().await);
    let user = register_test_user("claims-token").await;
    let mut fx = Fixtures::default();
    let (resource, claim, id) = seed_self_service_row(&mut fx, "token", "u:{sub}:{uuid}");
    let other = format!("https://other-{}.claims.test/mcp", unique_suffix());
    fx.resources.push(other.clone());
    seed_registry_resource(&other);

    let value = format!("u:42:{UUID}");
    let auth = start_link(&user, id, &value).await;
    let callback = mock_oidc_login(&auth, "42").await;
    assert_back_on_page(&get_callback(&user.manual_client, &callback).await);

    let (tokens, client_id, _) = crate::oauth::registry_claims_flow(&user, &resource).await;
    let claims = decode_jwt_claims(tokens["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["ext"][&claim], value.as_str(), "got {claims}");
    hydra_delete_client(&client_id).await;
    delete_client_metadata(&client_id);

    let (tokens, client_id, _) = crate::oauth::registry_claims_flow(&user, &other).await;
    let claims = decode_jwt_claims(tokens["access_token"].as_str().expect("access_token"));
    assert!(
        claims.get(&claim).is_none() && claims["ext"].get(&claim).is_none(),
        "a resource without the claim must not get it; got {claims}"
    );
    hydra_delete_client(&client_id).await;
    delete_client_metadata(&client_id);

    user.cleanup().await;
}
