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
            ("self_service_claim", "forgejo_aud"),
            ("self_service_issuer", "https://git.example.com/"),
            ("self_service_client_id", "c"),
            ("self_service_template", "{sub}"),
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
    assert_eq!(
        read_registry_resource_self_service(resource).expect("row")[0],
        "",
        "self-service untouched"
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

/// Deletes the listed `resource_registry` rows when dropped, so a failed
/// assertion doesn't leave a self-service claim behind in the shared DB.
struct RegistryRows(Vec<String>);

impl Drop for RegistryRows {
    fn drop(&mut self) {
        for r in &self.0 {
            delete_registry_resource(r);
        }
    }
}

fn unique_suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

async fn get_claims_editor(admin: &reqwest::Client, id: i64) -> (String, String) {
    let body = admin
        .get(format!("{PORTAL}/admin/resources/{id}/claims"))
        .send()
        .await
        .expect("GET claims editor")
        .text()
        .await
        .expect("editor body");
    let csrf = extract_form_csrf(&body).expect("csrf in editor");
    (body, csrf)
}

async fn post_claims(
    admin: &reqwest::Client,
    id: i64,
    csrf: &str,
    claims: &str,
    ss: [&str; 4],
) -> reqwest::Response {
    admin
        .post(format!("{PORTAL}/admin/resources/{id}/claims"))
        .form(&[
            ("_csrf", csrf),
            ("access_token_claims", claims),
            ("self_service_claim", ss[0]),
            ("self_service_issuer", ss[1]),
            ("self_service_client_id", ss[2]),
            ("self_service_template", ss[3]),
        ])
        .send()
        .await
        .expect("POST claims editor")
}

/// The conflict message, as rendered (Askama escapes the quotes).
fn names_conflict(body: &str, claim: &str) -> bool {
    body.contains(&format!(
        "claim &#34;{claim}&#34; is already used by another resource"
    ))
}

/// Self-service config set through the claims page reads back, prefills the
/// editor, marks the list row and audits critically; an invalid field
/// re-renders with every input echoed and the row unchanged; all four fields
/// empty turns it off.
#[tokio::test]
async fn registry_ui_sets_self_service() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin resources test");
        return;
    };

    let sfx = unique_suffix();
    let resource = format!("https://ui-self-service-{sfx}.mcp.test/mcp");
    let claim = format!("ss_{sfx}");
    let _rows = RegistryRows(vec![resource.clone()]);
    seed_registry_resource(&resource);
    let (id, _) = read_registry_resource_claims(&resource).expect("seeded row");

    let (body, csrf) = get_claims_editor(&admin, id).await;
    for field in [
        "self_service_claim",
        "self_service_issuer",
        "self_service_client_id",
        "self_service_template",
    ] {
        assert!(
            body.contains(&format!(r#"name="{field}""#)),
            "{field} field"
        );
    }

    let claims = format!("{claim} team");
    let issuer = "https://git.example.com/";
    let res = post_claims(
        &admin,
        id,
        &csrf,
        &claims,
        [&claim, issuer, " forseti-client ", "u:{sub}:{uuid}"],
    )
    .await;
    assert!(
        res.status().is_success(),
        "update redirects; got {}",
        res.status()
    );
    assert_eq!(
        read_registry_resource_self_service(&resource).expect("row"),
        [
            claim.clone(),
            issuer.to_string(),
            "forseti-client".to_string(),
            "u:{sub}:{uuid}".to_string(),
        ]
    );
    assert_eq!(
        read_registry_resource_claims(&resource).expect("row").1,
        claims
    );

    let ev = latest_audit_event("admin.resource.claims_updated", &resource).expect("audit row");
    assert_eq!(ev.severity, "critical");
    assert_eq!(ev.metadata["claims"], claims.as_str());
    assert_eq!(ev.metadata["self_service_claim"], claim.as_str());
    assert_eq!(ev.metadata["self_service_issuer"], issuer);
    assert_eq!(ev.metadata["self_service_client_id"], "forseti-client");
    assert_eq!(ev.metadata["self_service_template"], "u:{sub}:{uuid}");

    let (body, csrf) = get_claims_editor(&admin, id).await;
    assert!(
        body.contains(&format!(r#"value="{claim}""#)),
        "claim prefilled"
    );
    assert!(
        body.contains(r#"value="https://git.example.com/""#),
        "issuer prefilled"
    );
    assert!(
        body.contains(r#"value="forseti-client""#),
        "client id prefilled"
    );
    assert!(
        body.contains(r#"value="u:{sub}:{uuid}""#),
        "template prefilled"
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
        list.contains(&format!(r#"title="{claim}">Self-service</span>"#)),
        "list marks the self-service row"
    );

    let res = post_claims(
        &admin,
        id,
        &csrf,
        &claims,
        [
            &claim,
            "https://git.example.com/?x=1",
            "other-client",
            "u|{sub}",
        ],
    )
    .await;
    assert_eq!(res.status().as_u16(), 200, "invalid input re-renders");
    let body = res.text().await.expect("re-rendered editor");
    assert!(body.contains("query or fragment"), "explains the refusal");
    assert!(
        body.contains(&format!(r#"value="{claims}""#)),
        "claims echoed"
    );
    assert!(
        body.contains(&format!(r#"value="{claim}""#)),
        "claim echoed"
    );
    assert!(
        body.contains(r#"value="https://git.example.com/?x=1""#),
        "issuer echoed"
    );
    assert!(body.contains(r#"value="other-client""#), "client id echoed");
    assert!(body.contains(r#"value="u|{sub}""#), "template echoed");
    assert_eq!(
        read_registry_resource_self_service(&resource).expect("row")[2],
        "forseti-client",
        "row unchanged"
    );

    let res = post_claims(
        &admin,
        id,
        &csrf,
        "team",
        [&claim, issuer, "forseti-client", "{sub}"],
    )
    .await;
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.expect("re-rendered editor");
    assert!(
        body.contains("must be one of the access-token claims"),
        "the self-service claim has to stay listed"
    );

    let res = post_claims(&admin, id, &csrf, "team", ["", "", "", ""]).await;
    assert!(res.status().is_success(), "clearing redirects");
    assert_eq!(
        read_registry_resource_self_service(&resource).expect("row"),
        [String::new(), String::new(), String::new(), String::new()]
    );
    assert_eq!(
        read_registry_resource_claims(&resource).expect("row").1,
        "team"
    );
}

/// A self-service claim is exclusive across rows: neither another row's
/// claims nor its self-service claim may name it, a row may not take a
/// self-service claim another row lists, and the create form refuses it.
#[tokio::test]
async fn self_service_claim_conflicts_are_refused() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin resources test");
        return;
    };

    let sfx = unique_suffix();
    let owner = format!("https://ss-owner-{sfx}.mcp.test/mcp");
    let other = format!("https://ss-other-{sfx}.mcp.test/mcp");
    let created = format!("https://ss-created-{sfx}.mcp.test/mcp");
    let claim = format!("ss_{sfx}");
    let listed = format!("listed_{sfx}");
    let _rows = RegistryRows(vec![owner.clone(), other.clone(), created.clone()]);
    seed_registry_resource(&owner);
    seed_registry_resource(&other);
    set_registry_resource_claims(&owner, &claim);
    set_registry_resource_self_service(&owner, &claim, "https://git.example.com/", "c", "{sub}");
    set_registry_resource_claims(&other, &listed);
    let (owner_id, _) = read_registry_resource_claims(&owner).expect("owner row");
    let (other_id, _) = read_registry_resource_claims(&other).expect("other row");

    // Another row listing the self-service claim.
    let (_, csrf) = get_claims_editor(&admin, other_id).await;
    let both = format!("{listed} {claim}");
    let res = post_claims(&admin, other_id, &csrf, &both, ["", "", "", ""]).await;
    assert_eq!(res.status().as_u16(), 200, "conflict re-renders");
    let body = res.text().await.expect("body");
    assert!(
        names_conflict(&body, &claim),
        "names the claim; got {}",
        &body[..body.len().min(4000)]
    );
    assert_eq!(
        read_registry_resource_claims(&other).expect("row").1,
        listed
    );

    // Another row taking the same self-service claim.
    let res = post_claims(
        &admin,
        other_id,
        &csrf,
        &both,
        [&claim, "https://git.example.com/", "c", "{sub}"],
    )
    .await;
    assert_eq!(res.status().as_u16(), 200, "conflict re-renders");
    let body = res.text().await.expect("body");
    assert!(names_conflict(&body, &claim), "names the claim");
    assert_eq!(
        read_registry_resource_self_service(&other).expect("row")[0],
        ""
    );

    // The owner taking a self-service claim another row lists.
    let (_, csrf) = get_claims_editor(&admin, owner_id).await;
    let res = post_claims(
        &admin,
        owner_id,
        &csrf,
        &format!("{claim} {listed}"),
        [&listed, "https://git.example.com/", "c", "{sub}"],
    )
    .await;
    assert_eq!(res.status().as_u16(), 200, "conflict re-renders");
    let body = res.text().await.expect("body");
    assert!(names_conflict(&body, &listed), "names the claim");
    assert_eq!(
        read_registry_resource_self_service(&owner).expect("row")[0],
        claim
    );
    assert_eq!(read_registry_resource_claims(&owner).expect("row").1, claim);

    // The owner keeps its own self-service claim on a plain save.
    let res = post_claims(
        &admin,
        owner_id,
        &csrf,
        &claim,
        [&claim, "https://git.example.com/", "c", "{sub}"],
    )
    .await;
    assert!(res.status().is_success(), "own claim is no conflict");

    // The create form.
    let body = admin
        .get(format!("{PORTAL}/admin/resources/new"))
        .send()
        .await
        .expect("GET /admin/resources/new")
        .text()
        .await
        .expect("create form body");
    let csrf = extract_form_csrf(&body).expect("csrf in create form");
    let res = admin
        .post(format!("{PORTAL}/admin/resources/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("resource", created.as_str()),
            ("org_id", "default"),
            ("access_token_claims", claim.as_str()),
        ])
        .send()
        .await
        .expect("POST /admin/resources/new");
    assert_eq!(res.status().as_u16(), 200, "conflict re-renders the form");
    let body = res.text().await.expect("body");
    assert!(names_conflict(&body, &claim), "names the claim");
    assert!(
        read_registry_resource_claims(&created).is_none(),
        "no row written"
    );
}

/// Create and re-check store the RFC 9728 document's `scopes_supported` and
/// audit the change.
#[tokio::test]
async fn registry_ui_stores_and_rechecks_scopes() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("FORSETI_ADMIN_TEST_* not set; skipping admin resources test");
        return;
    };
    let sfx = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let (first, second) = (format!("cimdtest:{sfx}a"), format!("cimdtest:{sfx}b"));
    let prm = crate::cimd::serve_prm("/mcp", None, None, &[&first]).await;

    let body = admin
        .get(format!("{PORTAL}/admin/resources/new"))
        .send()
        .await
        .expect("GET /admin/resources/new")
        .text()
        .await
        .expect("create form body");
    let csrf = extract_form_csrf(&body).expect("csrf in create form");
    let res = admin
        .post(format!("{PORTAL}/admin/resources/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("resource", prm.resource.as_str()),
            ("display_name", "Scopes fixture"),
            ("org_id", "default"),
        ])
        .send()
        .await
        .expect("POST /admin/resources/new");
    assert!(res.status().is_success(), "create: {}", res.status());
    assert_eq!(
        read_registry_resource_scopes(&prm.resource),
        Some(("corroborated".to_string(), first.clone()))
    );
    let ev = latest_audit_event("resource.scopes_changed", &prm.resource).expect("audit row");
    assert_eq!(ev.metadata["added"], serde_json::json!(first));

    prm.advertise(&second);
    let (id, _) = read_registry_resource_claims(&prm.resource).expect("row id");
    let list = admin
        .get(format!("{PORTAL}/admin/resources"))
        .send()
        .await
        .expect("GET /admin/resources")
        .text()
        .await
        .expect("list body");
    let csrf = extract_form_csrf(&list).expect("csrf on list page");
    let res = admin
        .post(format!("{PORTAL}/admin/resources/{id}/recheck"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST recheck");
    assert!(res.status().is_success(), "recheck: {}", res.status());
    assert_eq!(
        read_registry_resource_scopes(&prm.resource),
        Some(("corroborated".to_string(), format!("{first} {second}")))
    );

    delete_registry_resource(&prm.resource);
}
