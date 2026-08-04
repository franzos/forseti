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
