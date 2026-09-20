//! The admin tier boundary: which of `/admin/*` an org owner can reach.
//!
//! An org owner is not a Forseti operator. Kratos identities and sessions are
//! global - one identity spans every org - so the identity and session admin
//! surfaces are Tier-1 (`[admin].allowed_emails` + AAL2) and `?org=<slug>`
//! buys nothing there. These tests drive a *non-allowlisted* owner of the
//! Default org at AAL2, which is exactly the principal the org-scoped tier
//! used to let through.
//!
//! The fixture needs a second AAL2-capable identity, so it plants a TOTP
//! credential into Kratos the way `make seed-admin` does. The Tier-1 control
//! assertions additionally need `FORSETI_ADMIN_TEST_*` and skip without it.

use crate::common::*;

fn extract_form_csrf(body: &str) -> Option<String> {
    let re = regex::Regex::new(r#"name="_csrf"\s+value="([^"]+)""#).ok()?;
    re.captures(body).map(|c| c[1].to_string())
}

/// A non-allowlisted identity at AAL2 who owns the Default org - the exact
/// principal `RequireAdminScoped` admitted. Default is used rather than a
/// named org so the fixture needs no Orgs license.
struct OrgOwner {
    user: RegisteredUser,
    csrf: String,
}

impl OrgOwner {
    async fn build(prefix: &str) -> Self {
        let user = register_test_user(prefix).await;
        // The floor membership row is written by the orgs middleware on the
        // first request, so make one before promoting the role.
        let _ = user.client.get(PORTAL).send().await;
        set_org_member_role("default", &user.identity_id, "owner");

        plant_totp(&user.identity_id, TEST_TOTP_SECRET);
        totp_step_up(&user.client, &totp_code_for(TEST_TOTP_SECRET)).await;

        let body = user
            .client
            .get(format!("{PORTAL}/settings"))
            .send()
            .await
            .expect("GET /settings as org owner")
            .text()
            .await
            .expect("settings body");
        let csrf = extract_form_csrf(&body).expect("_csrf on /settings");
        OrgOwner { user, csrf }
    }
}

/// Every identity and session admin route refuses a non-allowlisted org
/// owner, whether or not they thread `?org=`. The `recovery` POST is the
/// account-takeover vector from the security review: it minted a Kratos
/// recovery code for any co-member.
#[tokio::test]
async fn org_owner_is_refused_on_identity_and_session_admin() {
    assert!(portal_reachable().await);

    let owner = OrgOwner::build("tier-owner").await;
    let victim = register_test_user("tier-victim").await;
    let _ = victim.client.get(PORTAL).send().await;

    // Control: this principal really is an AAL2 org owner the scoped tier
    // admits - they keep client self-service. Without this the 403s below
    // could just be a fixture that never reached owner+AAL2 at all.
    let res = owner
        .user
        .client
        .get(format!("{PORTAL}/admin/clients?org=default"))
        .send()
        .await
        .expect("GET /admin/clients?org=default");
    assert_eq!(
        res.status().as_u16(),
        200,
        "fixture must be an AAL2 owner the org-scoped tier admits; got {}",
        res.status()
    );

    let vid = &victim.identity_id;
    let gets = [
        "/admin/identities".to_string(),
        format!("/admin/identities/{vid}"),
        format!("/admin/identities/{vid}/disable"),
        format!("/admin/identities/{vid}/delete"),
        "/admin/identity-picker?return_to=/admin/posix/new&org=default".to_string(),
        "/admin/sessions".to_string(),
        "/admin/sessions/00000000-0000-0000-0000-000000000000/revoke".to_string(),
    ];
    for path in &gets {
        let sep = if path.contains('?') {
            ""
        } else {
            "?org=default"
        };
        let url = format!("{PORTAL}{path}{sep}");
        let res = owner
            .user
            .client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url}: {e}"));
        assert_eq!(
            res.status().as_u16(),
            403,
            "org owner must be refused on {url}; got {}",
            res.status()
        );
    }

    let posts = [
        format!("/admin/identities/{vid}/recovery"),
        format!("/admin/identities/{vid}/disable"),
        format!("/admin/identities/{vid}/enable"),
        format!("/admin/identities/{vid}/delete"),
    ];
    for path in &posts {
        let url = format!("{PORTAL}{path}?org=default");
        let res = owner
            .user
            .client
            .post(&url)
            .form(&[("_csrf", owner.csrf.as_str()), ("confirm", "yes")])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {url}: {e}"));
        let status = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        assert_eq!(
            status, 403,
            "org owner must be refused on POST {url}; got {status}"
        );
        // Distinguish the admin gate's 403 from the CSRF layer's, so a token
        // that silently stopped working can't make this test pass hollow.
        assert!(
            !body.contains("CSRF check failed"),
            "POST {url} was refused by CSRF, not by the admin gate"
        );
    }

    // The victim's account is untouched: still able to load their dashboard.
    let res = victim
        .client
        .get(PORTAL)
        .send()
        .await
        .expect("victim GET /");
    assert!(
        res.status().is_success(),
        "victim's session must survive; got {}",
        res.status()
    );

    delete_org_membership("default", &owner.user.identity_id);
    owner.user.cleanup().await;
    victim.cleanup().await;
}

/// Org owners keep client self-service, but not on operator terms: a client
/// they create can't skip the consent screen, can't borrow another tenant's
/// audience, and is stamped `source=org` so the consent path stops reading
/// its registered audience as operator policy.
#[tokio::test]
async fn org_owner_client_cannot_skip_consent_or_borrow_audience() {
    assert!(portal_reachable().await);

    let owner = OrgOwner::build("tier-client").await;
    let base = [
        ("_csrf", owner.csrf.as_str()),
        ("name", "org-scoped-client"),
        ("grant_types", "authorization_code"),
        ("response_types", "code"),
        ("scope", "openid email"),
        ("redirect_uris", "http://127.0.0.1:5556/callback"),
        ("post_logout_redirect_uris", ""),
        ("token_endpoint_auth_method", "client_secret_post"),
        ("client_type", "web_app"),
    ];

    // Asking for silent consent is not an error, it just doesn't happen.
    let mut form = base.to_vec();
    form.push(("skip_consent", "on"));
    let res = owner
        .user
        .client
        .post(format!("{PORTAL}/admin/clients?org=default"))
        .form(&form)
        .send()
        .await
        .expect("POST /admin/clients?org=default");
    assert_eq!(
        res.status().as_u16(),
        200,
        "create should land on the show page"
    );
    let show_url = res.url().clone();
    let client_id = show_url
        .path()
        .strip_prefix("/admin/clients/")
        .map(str::to_string)
        .expect("client_id in show URL path");

    assert_eq!(
        hydra_client_field(&client_id, "skip_consent").await,
        Some(serde_json::Value::Bool(false)),
        "an org owner must not be able to mint a silent-consent client"
    );
    assert_eq!(
        client_metadata_source(&client_id).as_deref(),
        Some("org"),
        "an org-owner-created client must be stamped source=org"
    );
    hydra_delete_client(&client_id).await;

    // An audience the org hasn't registered is refused, and nothing is created.
    let before = hydra_client_count_by_name("org-scoped-audience").await;
    let mut form = base.to_vec();
    form[1] = ("name", "org-scoped-audience");
    form.push(("audience", "https://someone-elses.example/mcp"));
    let res = owner
        .user
        .client
        .post(format!("{PORTAL}/admin/clients?org=default"))
        .form(&form)
        .send()
        .await
        .expect("POST /admin/clients with a foreign audience");
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("is not an enabled resource of your organization"),
        "a foreign audience must be refused on the form; body was: {}",
        body.chars().take(400).collect::<String>()
    );
    assert_eq!(
        hydra_client_count_by_name("org-scoped-audience").await,
        before,
        "a refused create must not leave a Hydra client behind"
    );

    delete_org_membership("default", &owner.user.identity_id);
    owner.user.cleanup().await;
}

/// The Forseti operator keeps the capability the org owner just lost.
#[tokio::test]
async fn forseti_admin_client_may_still_skip_consent() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin client control test");
        return;
    };

    let body = admin
        .get(format!("{PORTAL}/admin/clients/new"))
        .send()
        .await
        .expect("GET /admin/clients/new")
        .text()
        .await
        .expect("new client form");
    let csrf = extract_form_csrf(&body).expect("csrf in new client form");

    let res = admin
        .post(format!("{PORTAL}/admin/clients"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "operator-skip-consent"),
            ("grant_types", "authorization_code"),
            ("response_types", "code"),
            ("scope", "openid email"),
            ("redirect_uris", "http://127.0.0.1:5557/callback"),
            ("post_logout_redirect_uris", ""),
            ("token_endpoint_auth_method", "client_secret_post"),
            ("skip_consent", "on"),
        ])
        .send()
        .await
        .expect("POST /admin/clients as operator");
    let client_id = res
        .url()
        .path()
        .strip_prefix("/admin/clients/")
        .map(str::to_string)
        .expect("client_id in show URL path");

    assert_eq!(
        hydra_client_field(&client_id, "skip_consent").await,
        Some(serde_json::Value::Bool(true)),
        "a Forseti operator must keep skip_consent"
    );
    assert_eq!(
        client_metadata_source(&client_id).as_deref(),
        Some("admin"),
        "an operator-created client stays source=admin"
    );
    hydra_delete_client(&client_id).await;
}

/// The Tier-1 operator still reaches both surfaces - the fix narrows who may
/// enter, not what the operator can do.
#[tokio::test]
async fn forseti_admin_still_reaches_identity_and_session_admin() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin tier control test");
        return;
    };

    for path in [
        "/admin/identities",
        "/admin/sessions",
        "/admin/identities?org=default",
    ] {
        let res = admin
            .get(format!("{PORTAL}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"));
        assert_eq!(
            res.status().as_u16(),
            200,
            "Tier-1 admin must still reach {path}; got {}",
            res.status()
        );
    }
}

/// A one-shot reveal token is the bearer credential for a client secret or a
/// recovery code, so the row holds a hash of it. Driven through client
/// creation, whose redirect carries the raw token; the show page then still
/// redeems it, proving the take path hashes too.
#[tokio::test]
async fn reveal_token_is_hashed_at_rest() {
    assert!(portal_reachable().await);
    let Some((browser, manual)) = try_admin_paired_clients().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping reveal hashing test");
        return;
    };

    let body = browser
        .get(format!("{PORTAL}/admin/clients/new"))
        .send()
        .await
        .expect("GET /admin/clients/new")
        .text()
        .await
        .expect("new client form");
    let csrf = extract_form_csrf(&body).expect("csrf in new client form");

    // Manual redirects: the show page consumes the reveal, so the raw token
    // has to be read off the Location header before anything follows it.
    let res = manual
        .post(format!("{PORTAL}/admin/clients"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "reveal-hashing"),
            ("grant_types", "authorization_code"),
            ("response_types", "code"),
            ("scope", "openid email"),
            ("redirect_uris", "http://127.0.0.1:5558/callback"),
            ("post_logout_redirect_uris", ""),
            ("token_endpoint_auth_method", "client_secret_post"),
        ])
        .send()
        .await
        .expect("POST /admin/clients");
    let location = res
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let raw = extract_query_param(&location, "reveal").expect("?reveal= on the create redirect");
    let client_id = location
        .trim_start_matches("/admin/clients/")
        .split('?')
        .next()
        .unwrap_or_default()
        .to_string();

    assert_eq!(
        count_reveals_with_token(&raw),
        0,
        "the raw reveal token must not be stored"
    );
    assert_eq!(
        count_reveals_with_token(&sha256_hex(&raw)),
        1,
        "the stored reveal token must be its SHA-256"
    );

    // Following the redirect still redeems it. The row going away is the
    // proof: only a take that hashed the raw token could have matched it.
    let res = browser
        .get(format!("{PORTAL}{location}"))
        .send()
        .await
        .expect("GET the show page with ?reveal=");
    assert!(res.status().is_success(), "show page: {}", res.status());
    assert_eq!(
        count_reveals_with_token(&sha256_hex(&raw)),
        0,
        "redeeming the reveal must consume the row"
    );

    hydra_delete_client(&client_id).await;
    delete_client_metadata(&client_id);
}
