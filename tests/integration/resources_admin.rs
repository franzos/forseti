//! `/admin/resources` UI coverage: create-through-the-form lands in the
//! registry and binds an audience end-to-end; org-scoped admins are fenced
//! to their verified domains.
//!
//! Admin-authorised tests follow the `admin.rs` precedent: they need the
//! env-gated `FORSETI_ADMIN_TEST_*` fixture (see `common.rs`,
//! `make seed-admin`) and skip gracefully when it isn't wired up.

use crate::common::*;

/// Extract the value of the `_csrf` hidden input from a rendered HTML form.
/// (Private sibling of the helper in `admin.rs`.)
fn extract_form_csrf(body: &str) -> Option<String> {
    let re = regex::Regex::new(r#"name="_csrf"\s+value="([^"]+)""#).ok()?;
    re.captures(body).map(|c| c[1].to_string())
}

/// Full UI round-trip: create a registry row via `POST /admin/resources/new`,
/// see it on the list page, then drive a CIMD flow requesting it and assert
/// the access token carries the audience (Task 11's consent arm reads the
/// row this UI just wrote).
#[tokio::test]
async fn registry_ui_created_resource_binds_audience() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin resources test");
        return;
    };

    let resource = "https://ui-created.mcp.test";
    delete_registry_resource(resource);

    let res = admin
        .get(format!("{PORTAL}/admin/resources/new"))
        .send()
        .await
        .expect("GET /admin/resources/new");
    assert_eq!(res.status().as_u16(), 200, "create form must render");
    let body = res.text().await.expect("create form body");
    let csrf = extract_form_csrf(&body).expect("csrf in create form");

    let res = admin
        .post(format!("{PORTAL}/admin/resources/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("resource", resource),
            ("display_name", "UI created"),
            ("org_id", "default"),
        ])
        .send()
        .await
        .expect("POST /admin/resources/new");
    assert!(
        res.status().is_success(),
        "create should redirect to the list; got {}",
        res.status()
    );

    let list = admin
        .get(format!("{PORTAL}/admin/resources"))
        .send()
        .await
        .expect("GET /admin/resources")
        .text()
        .await
        .expect("list body");
    assert!(
        list.contains(resource),
        "list page must show the freshly created resource"
    );

    let (enabled, created_by) =
        read_registry_resource(resource).expect("row must exist after UI create");
    assert!(enabled, "UI-created rows default to enabled");
    assert!(
        !created_by.is_empty(),
        "created_by must record the admin's email"
    );

    let aud = crate::cimd::cimd_flow_aud(resource, 43441, "res-ui-bind").await;
    delete_registry_resource(resource);
    assert!(
        aud.iter().any(|a| a == resource),
        "a UI-registered resource must bind into the audience; got {aud:?}"
    );
}

/// Org-scoped admins fail closed: creating a resource whose host is not a
/// verified domain of their org re-renders the form with an error and writes
/// no row. Uses `?org=default` — the seeded admin is auto-owner of the
/// Default org (ensure_default_floor) and the Default org needs no license.
#[tokio::test]
async fn org_admin_cannot_register_resource_on_unverified_domain() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin resources test");
        return;
    };

    let resource = "https://unverified-domain.mcp.test/mcp";
    delete_registry_resource(resource);

    let res = admin
        .get(format!("{PORTAL}/admin/resources/new?org=default"))
        .send()
        .await
        .expect("GET /admin/resources/new?org=default");
    assert_eq!(
        res.status().as_u16(),
        200,
        "org-scoped create form must render"
    );
    let body = res.text().await.expect("create form body");
    let csrf = extract_form_csrf(&body).expect("csrf in org-scoped create form");

    let res = admin
        .post(format!("{PORTAL}/admin/resources/new?org=default"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("resource", resource),
            ("display_name", "should not land"),
        ])
        .send()
        .await
        .expect("POST /admin/resources/new?org=default");
    assert_eq!(
        res.status().as_u16(),
        200,
        "rejected create re-renders the form, no redirect"
    );
    let body = res.text().await.expect("re-rendered form body");
    assert!(
        body.contains("verified domain"),
        "form must explain the verified-domain requirement; got: {}",
        &body[..body.len().min(2000)]
    );
    assert!(
        read_registry_resource(resource).is_none(),
        "no registry row may be written for an unverified domain"
    );
}

/// Claims set through the create form and the edit page land on the row;
/// a reserved name re-renders the edit page with the input echoed and the row
/// unchanged.
#[tokio::test]
async fn registry_ui_sets_and_edits_access_token_claims() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin resources test");
        return;
    };

    let resource = "https://ui-claims.mcp.test/mcp";
    delete_registry_resource(resource);

    let body = admin
        .get(format!("{PORTAL}/admin/resources/new"))
        .send()
        .await
        .expect("GET /admin/resources/new")
        .text()
        .await
        .expect("create form body");
    assert!(
        body.contains(r#"name="access_token_claims""#),
        "Forseti admins get the claims field"
    );
    let csrf = extract_form_csrf(&body).expect("csrf in create form");
    let res = admin
        .post(format!("{PORTAL}/admin/resources/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("resource", resource),
            ("org_id", "default"),
            ("access_token_claims", "forgejo_aud, team forgejo_aud"),
        ])
        .send()
        .await
        .expect("POST /admin/resources/new");
    assert!(
        res.status().is_success(),
        "create redirects; got {}",
        res.status()
    );
    let (id, claims) = read_registry_resource_claims(resource).expect("row after create");
    assert_eq!(claims, "forgejo_aud team", "parsed, deduped, space-joined");

    let list = admin
        .get(format!("{PORTAL}/admin/resources"))
        .send()
        .await
        .expect("GET /admin/resources")
        .text()
        .await
        .expect("list body");
    assert!(list.contains("forgejo_aud team"), "list shows the claims");
    assert!(
        list.contains(&format!("/admin/resources/{id}/claims")),
        "list links the editor"
    );

    let edit_url = format!("{PORTAL}/admin/resources/{id}/claims");
    let body = admin
        .get(&edit_url)
        .send()
        .await
        .expect("GET claims editor")
        .text()
        .await
        .expect("editor body");
    assert!(
        body.contains(r#"value="forgejo_aud team""#),
        "editor prefilled; got {body}"
    );
    let csrf = extract_form_csrf(&body).expect("csrf in editor");

    let res = admin
        .post(&edit_url)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("access_token_claims", "forgejo_aud sub"),
        ])
        .send()
        .await
        .expect("POST reserved claim");
    assert_eq!(
        res.status().as_u16(),
        200,
        "invalid input re-renders, no redirect"
    );
    let body = res.text().await.expect("re-rendered editor");
    assert!(body.contains("reserved claim"), "explains the refusal");
    assert!(
        body.contains(r#"value="forgejo_aud sub""#),
        "echoes the input"
    );
    assert_eq!(
        read_registry_resource_claims(resource).expect("row").1,
        "forgejo_aud team"
    );

    let res = admin
        .post(&edit_url)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("access_token_claims", "forgejo_aud"),
        ])
        .send()
        .await
        .expect("POST valid claims");
    assert!(
        res.status().is_success(),
        "update redirects; got {}",
        res.status()
    );
    assert_eq!(
        read_registry_resource_claims(resource).expect("row").1,
        "forgejo_aud"
    );

    let res = admin
        .post(&edit_url)
        .form(&[("_csrf", csrf.as_str()), ("access_token_claims", "")])
        .send()
        .await
        .expect("POST cleared claims");
    assert!(
        res.status().is_success(),
        "clearing redirects; got {}",
        res.status()
    );
    assert_eq!(read_registry_resource_claims(resource).expect("row").1, "");

    let res = admin
        .post(&edit_url)
        .form(&[("access_token_claims", "forgejo_aud")])
        .send()
        .await
        .expect("POST without csrf");
    assert!(
        !res.status().is_success(),
        "missing CSRF is refused; got {}",
        res.status()
    );
    assert_eq!(read_registry_resource_claims(resource).expect("row").1, "");

    delete_registry_resource(resource);
}

/// Org-scoped admins can't set claims: no field, no editor, and a crafted
/// create POST carrying claims writes no row.
#[tokio::test]
async fn org_admin_cannot_set_access_token_claims() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin resources test");
        return;
    };

    let resource = "https://org-claims.mcp.test/mcp";
    delete_registry_resource(resource);
    seed_registry_resource(resource);
    let (id, _) = read_registry_resource_claims(resource).expect("seeded row");

    let body = admin
        .get(format!("{PORTAL}/admin/resources/new?org=default"))
        .send()
        .await
        .expect("GET org-scoped create form")
        .text()
        .await
        .expect("form body");
    assert!(
        !body.contains(r#"name="access_token_claims""#),
        "no claims field for org admins"
    );
    let csrf = extract_form_csrf(&body).expect("csrf");

    let list = admin
        .get(format!("{PORTAL}/admin/resources?org=default"))
        .send()
        .await
        .expect("GET org-scoped list")
        .text()
        .await
        .expect("list body");
    assert!(!list.contains("/claims"), "no editor link for org admins");

    let res = admin
        .get(format!("{PORTAL}/admin/resources/{id}/claims?org=default"))
        .send()
        .await
        .expect("GET editor as org admin");
    let body = res.text().await.expect("body");
    assert!(
        body.contains("Not found") && !body.contains(r#"name="access_token_claims""#),
        "editor is not found for org admins; got {}",
        &body[..body.len().min(2000)]
    );

    let res = admin
        .post(format!("{PORTAL}/admin/resources/{id}/claims?org=default"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("access_token_claims", "forgejo_aud"),
        ])
        .send()
        .await
        .expect("POST editor as org admin");
    assert!(res.status().is_success() || res.status().is_client_error());
    assert_eq!(
        read_registry_resource_claims(resource).expect("row").1,
        "",
        "row untouched"
    );
    delete_registry_resource(resource);

    let crafted = "https://org-crafted.mcp.test/mcp";
    delete_registry_resource(crafted);
    let res = admin
        .post(format!("{PORTAL}/admin/resources/new?org=default"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("resource", crafted),
            ("access_token_claims", "forgejo_aud"),
        ])
        .send()
        .await
        .expect("crafted create POST");
    let body = res.text().await.expect("body");
    assert!(
        body.contains("Only Forseti administrators"),
        "explains the refusal"
    );
    assert!(
        read_registry_resource_claims(crafted).is_none(),
        "no row written"
    );
}
