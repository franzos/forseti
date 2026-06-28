//! POSIX-row cascade on identity deletion.
//!
//! When a Kratos identity is deleted through any Forseti path, the local
//! POSIX tables (posix_accounts / posix_group_members / the user-kind
//! primary group / ssh_authorized_keys) must be purged in lockstep. An
//! orphaned posix_account is a security issue — it keeps a usable login
//! (uid + ssh keys) alive for an identity that no longer exists.
//!
//! This drives the self-service account-deletion saga (the cheapest path
//! to exercise — a freshly-registered user has a privileged Kratos
//! session for 15 minutes), seeds posix rows directly via rusqlite, runs
//! the delete over HTTP, then asserts the rows are gone.

use crate::common::*;
use reqwest::StatusCode;
use serde_json::Value;

/// Pull a `_csrf` hidden input value out of a settings page render.
/// (Local copy — `account_delete.rs`'s is private to that module.)
fn extract_form_csrf(html: &str) -> Option<String> {
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

/// Local copy of admin.rs's private skip helper.
async fn admin_client_or_skip() -> Option<reqwest::Client> {
    let c = try_admin_signed_in_client().await;
    if c.is_none() {
        eprintln!(
            "Skipping admin happy-path test: \
FORSETI_ADMIN_TEST_EMAIL/PASSWORD/TOTP_CODE not set or sign-in failed."
        );
    }
    c
}

#[tokio::test]
async fn posix_new_two_step_prefills_email() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = admin_client_or_skip().await else {
        return;
    };
    let email = unique_email("twostep");
    let id = kratos_admin_create_identity(&email).await;

    let body = client
        .get(format!("{PORTAL}/admin/posix/new"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("/admin/identity-picker?return_to=/admin/posix/new"),
        "step 1 must offer the picker"
    );
    assert!(
        !body.contains("name=\"username\""),
        "username field hidden in step 1"
    );

    let body = client
        .get(format!("{PORTAL}/admin/posix/new?identity_id={id}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains(&email), "step 2 shows the selected email");
    assert!(
        body.contains(&format!("value=\"{id}\"")),
        "hidden authoritative UUID"
    );
    assert!(
        body.contains("name=\"username\""),
        "username field present in step 2"
    );

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn provision_accepts_email() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = admin_client_or_skip().await else {
        return;
    };
    let email = unique_email("byemail");
    let id = kratos_admin_create_identity(&email).await;
    let username = format!("byemail{}", chrono::Utc::now().timestamp_millis() % 50_000);

    let body = client
        .get(format!("{PORTAL}/admin/posix/new?identity_id={id}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = extract_form_csrf(&body).expect("_csrf on step 2");

    let res = client
        .post(format!("{PORTAL}/admin/posix/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("identity_id", email.as_str()),
            ("username", username.as_str()),
            ("shell", "/bin/sh"),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        res.url().as_str().contains(&format!("/admin/posix/{id}")),
        "typing an email should resolve to the identity and provision; landed at {}",
        res.url()
    );

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn provision_rejects_unknown_email() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = admin_client_or_skip().await else {
        return;
    };
    // A real identity, used only to obtain a session-bound CSRF token from
    // the step-2 render before we POST a deliberately unresolvable email.
    let email = unique_email("csrfsrc");
    let id = kratos_admin_create_identity(&email).await;
    let body = client
        .get(format!("{PORTAL}/admin/posix/new?identity_id={id}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = extract_form_csrf(&body).expect("_csrf on step 2");

    let bogus = "no-such-user@nonexistent.example";
    let res = client
        .post(format!("{PORTAL}/admin/posix/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("identity_id", bogus),
            ("username", "nobodyx"),
            ("shell", "/bin/sh"),
        ])
        .send()
        .await
        .unwrap();
    let landed = res.url().to_string();
    let text = res.text().await.unwrap();
    assert!(
        landed.ends_with("/admin/posix/new"),
        "unknown email must re-render the form, not redirect; landed at {landed}"
    );
    // The error string's quotes are HTML-escaped in the render, so match on
    // the stable prefix plus the (special-char-free) email separately.
    assert!(
        text.contains("No identity found for") && text.contains(bogus),
        "expected unknown-email error message in the re-rendered form"
    );

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn identity_picker_renders_select_links() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = admin_client_or_skip().await else {
        return;
    };
    let email = unique_email("picker");
    let id = kratos_admin_create_identity(&email).await;

    let res = client
        .get(format!(
            "{PORTAL}/admin/identity-picker?return_to=/admin/posix/new&q={email}"
        ))
        .send()
        .await
        .expect("GET picker");
    assert!(res.status().is_success());
    let body = res.text().await.unwrap();
    assert!(
        body.contains(&format!("/admin/posix/new?identity_id={id}")),
        "row should carry a Select link back to return_to with identity_id"
    );

    let res = client
        .get(format!(
            "{PORTAL}/admin/identity-picker?return_to=https://evil.example/x"
        ))
        .send()
        .await
        .expect("GET picker bad rt");
    let body = res.text().await.unwrap();
    assert!(
        body.contains("Invalid return target"),
        "must reject foreign return_to"
    );

    delete_test_identity(&id).await.ok();
}

#[tokio::test]
async fn self_delete_purges_posix_rows() {
    assert!(portal_reachable().await);

    let user = register_test_user("posix-cascade").await;
    let identity_id = user.identity_id.clone();
    let email = user.email.clone();

    // Seed posix rows for this identity. uid/gid are timestamp-derived so
    // they don't collide with anything else the suite may have left behind.
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 70_000 + seed;
    let gid = 70_000 + seed;
    let username = format!("posixcascade{seed}");
    seed_posix_account(&identity_id, &username, uid, gid);
    assert_eq!(
        count_posix_rows(&identity_id, gid),
        4,
        "fixture should have seeded account + primary group + membership + ssh key rows"
    );

    // GET the confirm page for a CSRF token bound to the same cookie jar.
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
    let post_url = res.url().clone();
    let body = res.text().await.expect("confirm body");
    let csrf = extract_form_csrf(&body).expect("_csrf hidden input on confirm page");

    // POST the deletion form.
    let res = user
        .client
        .post(post_url)
        .form(&[("_csrf", csrf.as_str()), ("confirm_email", email.as_str())])
        .send()
        .await
        .expect("POST /settings/account/delete");
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("/login"),
        "expected to land on /login after delete; got {final_url}"
    );

    // The Kratos identity should be gone...
    assert!(
        identity_id_by_email(&email).await.is_none(),
        "kratos identity should be deleted for {email} (id {identity_id})"
    );

    // ...and so should every posix row tied to it.
    assert_eq!(
        count_posix_rows(&identity_id, gid),
        0,
        "posix rows must be purged on identity delete; orphans found for {identity_id}"
    );

    // No cleanup — the identity is already gone.
}

/// Black-box exercise of the `/posix/v1/*` resolver on the internal listener
/// for a WHOLE-ORG host (no `host_allowed_groups` rows): host Basic auth, a
/// single passwd lookup, authorized_keys, enumeration limited to the host
/// org's provisioned members, and a 401 on a wrong secret.
///
/// Uses a non-default org so enumeration is isolated to the seeded member
/// (every registered user auto-joins the `default` org).
#[tokio::test]
async fn resolver_unscoped_host_basic_lookups() {
    assert!(portal_reachable().await);

    let user = register_test_user("posix-resolver").await;
    let identity_id = user.identity_id.clone();

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 71_000 + seed;
    let gid = 71_000 + seed;
    let username = format!("posixresolver{seed}");
    let org_id = format!("test-org-wholeorg-{seed}");
    seed_posix_account(&identity_id, &username, uid, gid);
    seed_org_membership(&org_id, &identity_id, "member");

    let host_id = format!("test-host-{seed}");
    let secret = "s3cret-resolver";
    seed_host_enrollment(&host_id, "fixture.example", secret, &org_id);

    // Plain client (no cookie jar): the resolver is Basic-auth only.
    let client = reqwest::Client::new();

    // 1. passwd by name → 200 + matching JSON.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{username}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name");
    assert_eq!(res.status(), StatusCode::OK, "passwd/name should be 200");
    let body: Value = res.json().await.expect("passwd json");
    assert_eq!(body["name"], username);
    assert_eq!(body["uid"], uid);
    assert_eq!(body["shell"], "/bin/bash");

    // 2. authorized_keys → 200 + the seeded key line.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/authorized_keys/{username}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET authorized_keys");
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.expect("keys body");
    assert_eq!(body.trim(), "ssh-ed25519 AAAATEST test@fixture");

    // 3. Whole-org enumeration lists the org's provisioned members (just the
    //    one seeded into this isolated org).
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd (enumerate)");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("passwd_all json");
    let names: Vec<&str> = body
        .as_array()
        .expect("passwd_all array")
        .iter()
        .filter_map(|e| e["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec![username.as_str()],
        "whole-org enumeration must list exactly the org's provisioned member"
    );

    // 4. Wrong secret → 401.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{username}"))
        .basic_auth(&host_id, Some("wrong"))
        .send()
        .await
        .expect("GET passwd with bad secret");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    delete_host_enrollment(&host_id);
    delete_org_membership(&org_id, &identity_id);
    user.cleanup().await;
}

/// Team-scoped host (one `host_allowed_groups` row): only members of the
/// allowed team are reachable, enumeration is restricted to them, the team's
/// gid resolves the roster, and a host scoped to a team that belongs to a
/// DIFFERENT org fails closed (resolves nothing) — a cross-org team can never
/// widen visibility.
#[tokio::test]
async fn resolver_scoped_host_enforces_gid() {
    assert!(portal_reachable().await);

    const TEAM_GID: i64 = 2_500_000;
    let stamp = chrono::Utc::now().timestamp_millis();
    let org_id = format!("test-org-scoped-{stamp}");
    let team_id = format!("test-team-scoped-{stamp}");

    // In-scope member: org member + team member.
    let member = register_test_user("posix-scoped-in").await;
    let member_id = member.identity_id.clone();
    let seed_a = stamp % 50_000;
    let member_uid = 72_000 + seed_a;
    let member_gid = 72_000 + seed_a;
    let member_name = format!("posixscopedin{seed_a}");
    seed_posix_account(&member_id, &member_name, member_uid, member_gid);
    seed_org_membership(&org_id, &member_id, "member");
    seed_team(
        &team_id,
        &org_id,
        "engineering",
        "engineering",
        Some(TEAM_GID),
    );
    add_team_member(&team_id, &member_id);

    // Out-of-scope account: org member but NOT a member of the allowed team.
    let outsider = register_test_user("posix-scoped-out").await;
    let outsider_id = outsider.identity_id.clone();
    let seed_b = (stamp + 1) % 50_000;
    let outsider_uid = 73_000 + seed_b;
    let outsider_gid = 73_000 + seed_b;
    let outsider_name = format!("posixscopedout{seed_b}");
    seed_posix_account(&outsider_id, &outsider_name, outsider_uid, outsider_gid);
    seed_org_membership(&org_id, &outsider_id, "member");

    // Host scoped to the team.
    let host_id = format!("test-scoped-host-{seed_a}");
    let secret = "s3cret-scoped";
    seed_host_enrollment(&host_id, "scoped.example", secret, &org_id);
    set_host_allowed_team_ids(&host_id, &[team_id.as_str()]);

    let client = reqwest::Client::new();

    // In-scope member resolves.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{member_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name member");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "in-scope member should be 200"
    );
    let body: Value = res.json().await.expect("member passwd json");
    assert_eq!(body["name"], member_name);

    // Out-of-scope account is not reachable.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{outsider_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name outsider");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "out-of-scope account must 404 on a scoped host"
    );

    // Group roster by the team gid lists the member.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{TEAM_GID}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET group/gid");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "team group lookup should be 200"
    );
    let body: Value = res.json().await.expect("group json");
    let members = body["members"].as_array().expect("group members array");
    assert!(
        members
            .iter()
            .any(|m| m == &Value::from(member_name.clone())),
        "team roster must include the member; got {members:?}"
    );

    // Scoped enumeration contains the member but not the outsider.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd (scoped enumerate)");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("scoped passwd_all json");
    let names: Vec<&str> = body
        .as_array()
        .expect("passwd_all array")
        .iter()
        .filter_map(|e| e["name"].as_str())
        .collect();
    assert!(
        names.contains(&member_name.as_str()),
        "scoped enumeration must include the member; got {names:?}"
    );
    assert!(
        !names.contains(&outsider_name.as_str()),
        "scoped enumeration must NOT include the out-of-scope account; got {names:?}"
    );

    // Fail-closed: a host (in `org_id`) scoped to a team that belongs to a
    // DIFFERENT org resolves nothing, even for a real member of that foreign
    // team — the resolver asserts each allowed team's org == the host's org.
    let other_org = format!("test-org-foreign-{stamp}");
    let foreign_team = format!("test-team-foreign-{stamp}");
    seed_team(
        &foreign_team,
        &other_org,
        "foreign-eng",
        "foreign-eng",
        Some(TEAM_GID + 1),
    );
    add_team_member(&foreign_team, &member_id);

    let bad_host_id = format!("test-foreignscope-host-{seed_a}");
    let bad_secret = "s3cret-foreignscope";
    seed_host_enrollment(&bad_host_id, "foreignscope.example", bad_secret, &org_id);
    set_host_allowed_team_ids(&bad_host_id, &[foreign_team.as_str()]);

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd"))
        .basic_auth(&bad_host_id, Some(bad_secret))
        .send()
        .await
        .expect("GET passwd (foreign-org team scoped)");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("foreign-team passwd_all json");
    assert_eq!(
        body,
        serde_json::json!([]),
        "a foreign-org allowed team must fail closed (empty enumeration)"
    );

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{member_name}"))
        .basic_auth(&bad_host_id, Some(bad_secret))
        .send()
        .await
        .expect("GET passwd/name (foreign-org team scoped)");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a foreign-org allowed team must fail closed (no name resolution)"
    );

    delete_host_enrollment(&bad_host_id);
    delete_host_enrollment(&host_id);
    delete_team(&foreign_team);
    delete_team(&team_id);
    delete_org_membership(&org_id, &member_id);
    delete_org_membership(&org_id, &outsider_id);
    member.cleanup().await;
    outsider.cleanup().await;
}

/// A host scoped to TWO teams resolves a member of EITHER team, and 404s a
/// non-member of both (any-of-N scope via `host_allowed_groups`). Both teams
/// (and all three accounts) live in one non-default org.
#[tokio::test]
async fn host_scoped_to_two_groups_resolves_either() {
    assert!(portal_reachable().await);

    const TEAM_GID_A: i64 = 2_700_000;
    const TEAM_GID_B: i64 = 2_710_000;
    let stamp = chrono::Utc::now().timestamp_millis();
    let org_id = format!("test-org-two-{stamp}");
    let team_a = format!("test-team-two-a-{stamp}");
    let team_b = format!("test-team-two-b-{stamp}");

    // Member of team A.
    let member_a = register_test_user("posix-two-a").await;
    let member_a_id = member_a.identity_id.clone();
    let seed_a = stamp % 50_000;
    let member_a_uid = 75_000 + seed_a;
    let member_a_name = format!("posixtwoa{seed_a}");
    seed_posix_account(&member_a_id, &member_a_name, member_a_uid, member_a_uid);

    // Member of team B.
    let member_b = register_test_user("posix-two-b").await;
    let member_b_id = member_b.identity_id.clone();
    let seed_b = (stamp + 1) % 50_000;
    let member_b_uid = 76_000 + seed_b;
    let member_b_name = format!("posixtwob{seed_b}");
    seed_posix_account(&member_b_id, &member_b_name, member_b_uid, member_b_uid);

    // Org member of neither team.
    let outsider = register_test_user("posix-two-out").await;
    let outsider_id = outsider.identity_id.clone();
    let seed_c = (stamp + 2) % 50_000;
    let outsider_uid = 77_000 + seed_c;
    let outsider_name = format!("posixtwoout{seed_c}");
    seed_posix_account(&outsider_id, &outsider_name, outsider_uid, outsider_uid);

    for id in [&member_a_id, &member_b_id, &outsider_id] {
        seed_org_membership(&org_id, id, "member");
    }
    seed_team(&team_a, &org_id, "two-eng", "two-eng", Some(TEAM_GID_A));
    seed_team(&team_b, &org_id, "two-ops", "two-ops", Some(TEAM_GID_B));
    add_team_member(&team_a, &member_a_id);
    add_team_member(&team_b, &member_b_id);

    // Host scoped to BOTH teams.
    let host_id = format!("test-twogrp-host-{seed_a}");
    let secret = "s3cret-twogrp";
    seed_host_enrollment(&host_id, "two.example", secret, &org_id);
    set_host_allowed_team_ids(&host_id, &[team_a.as_str(), team_b.as_str()]);

    let client = reqwest::Client::new();

    for name in [&member_a_name, &member_b_name] {
        let res = client
            .get(format!("{INTERNAL}/posix/v1/passwd/name/{name}"))
            .basic_auth(&host_id, Some(secret))
            .send()
            .await
            .expect("GET passwd/name member");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "member of either scoped team should be 200 ({name})"
        );
        let body: Value = res.json().await.expect("member passwd json");
        assert_eq!(body["name"], *name);
    }

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{outsider_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name outsider");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a non-member of both scoped teams must 404"
    );

    delete_host_enrollment(&host_id);
    delete_team(&team_a);
    delete_team(&team_b);
    for id in [&member_a_id, &member_b_id, &outsider_id] {
        delete_org_membership(&org_id, id);
    }
    member_a.cleanup().await;
    member_b.cleanup().await;
    outsider.cleanup().await;
}

/// Org-membership removal must revoke the ex-member from the org's teams, so a
/// host SCOPED to one of that org's teams stops resolving them (H1).
///
/// Seeds the team-model shape directly via rusqlite (org membership + a team +
/// a team membership), proves the scoped host resolves the member, then applies
/// the exact net effect of removing the identity from the org — purge their
/// team memberships (`teams::remove_identity_from_org_teams`) and drop the org
/// membership row — and asserts the host no longer resolves the ex-member.
///
/// TODO: the full handler path (`POST .../members` remove → the wired
/// `remove_identity_from_org_teams` call) needs an active Orgs license to pass
/// `require_org_owner_with_license`; the integration harness has no
/// license-activation path (the licensed e2e bucket does it over HTTP). The
/// handler → helper wiring is covered by `cargo check`; this test pins the
/// resulting access-revocation invariant the resolver enforces.
#[tokio::test]
async fn org_member_removal_revokes_scoped_host_access() {
    assert!(portal_reachable().await);

    const TEAM_GID: i64 = 2_600_000;
    let stamp = chrono::Utc::now().timestamp_millis();
    let org_id = format!("test-org-orgremove-{stamp}");
    let team_id = format!("test-team-orgremove-{stamp}");

    let member = register_test_user("posix-orgremove").await;
    let member_id = member.identity_id.clone();
    let seed = stamp % 50_000;
    let member_uid = 74_000 + seed;
    let member_name = format!("posixorgremove{seed}");
    seed_posix_account(&member_id, &member_name, member_uid, member_uid);

    seed_org_membership(&org_id, &member_id, "member");
    seed_team(
        &team_id,
        &org_id,
        "scoped-eng",
        "scoped-eng",
        Some(TEAM_GID),
    );
    add_team_member(&team_id, &member_id);

    let host_id = format!("test-orgremove-host-{seed}");
    let secret = "s3cret-orgremove";
    seed_host_enrollment(&host_id, "orgremove.example", secret, &org_id);
    set_host_allowed_team_ids(&host_id, &[team_id.as_str()]);

    let client = reqwest::Client::new();

    // Precondition: the member resolves on the scoped host.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{member_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name member (pre-removal)");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "member must resolve on the scoped host before removal"
    );

    // The org-removal cleanup: purge team membership + drop the org membership.
    // Mirrors `remove_identity_from_org_teams` + the org-members handler delete.
    remove_team_member(&team_id, &member_id);
    delete_org_membership(&org_id, &member_id);

    // Post-removal: the scoped host must NOT resolve the ex-member.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{member_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name member (post-removal)");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "ex-member must 404 on the scoped host once org membership is revoked"
    );

    delete_host_enrollment(&host_id);
    delete_team(&team_id);
    member.cleanup().await;
}

/// The free-tier seat cap (`[posix].free_seats`) the CI config runs under.
/// `config.ci.toml` ships no `[posix]` table, so this is the `PosixConfig`
/// default (`src/config.rs`).
const FREE_SEATS: i64 = 25;

/// Drive the POSIX-provisioning admin surface: fill the free-tier seat cap
/// with bare seeded accounts, assert the NEXT provision over HTTP is
/// REJECTED with the cap message (no license needed — unlicensed falls back
/// to the free cap), then free a seat and assert the happy-path provision
/// succeeds and lands on the account page.
///
/// TODO: the licensed-raise case (a `max_seats` LinuxAuth license lifting the
/// cap above `free_seats`) needs a license fixture activated via
/// `/admin/license`; deferred until a `max_seats` LinuxAuth blob exists.
#[tokio::test]
async fn admin_posix_seat_cap_enforced_then_happy_path() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = try_admin_signed_in_client().await else {
        eprintln!(
            "Skipping posix-admin test: FORSETI_ADMIN_TEST_EMAIL/PASSWORD/TOTP_CODE not set."
        );
        return;
    };

    // A real Kratos identity for the over-cap and happy-path provisions —
    // the handler verifies the identity exists before touching the seat cap.
    let user = register_test_user("posix-provision").await;
    let identity_id = user.identity_id.clone();

    // Fill the free tier with bare seeded accounts. uid/gid are timestamp-
    // derived so they don't collide with other suite fixtures.
    let base = 80_000 + (chrono::Utc::now().timestamp_millis() % 40_000);
    let mut seeded: Vec<String> = Vec::new();
    let mut next = base;
    while count_enabled_posix_accounts() < FREE_SEATS {
        let id = format!("seat-filler-{next}");
        seed_bare_posix_account(&id, &format!("seatfill{next}"), next, next);
        seeded.push(id);
        next += 1;
    }
    assert!(
        count_enabled_posix_accounts() >= FREE_SEATS,
        "free tier should be full before the over-cap provision"
    );

    // Fetch the provision form for a CSRF token bound to the admin cookie jar.
    let res = client
        .get(format!("{PORTAL}/admin/posix/new"))
        .send()
        .await
        .expect("GET /admin/posix/new");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("csrf in provision form");

    let username = format!("provtest{base}");

    // Over-cap provision must be rejected with the seat-cap message and must
    // NOT create the account.
    let res = client
        .post(format!("{PORTAL}/admin/posix/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("identity_id", identity_id.as_str()),
            ("username", username.as_str()),
            ("shell", ""),
        ])
        .send()
        .await
        .expect("POST provision (over cap)");
    assert_eq!(
        res.status().as_u16(),
        200,
        "rerendered form after rejection"
    );
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("Seat cap reached"),
        "over-cap provision must show the cap message; got: {body}"
    );
    assert!(
        count_posix_rows(&identity_id, 0) == 0,
        "rejected provision must not create any posix row for the identity"
    );

    // Free one seat, then the same provision succeeds and redirects to the
    // account page.
    let freed = seeded.pop().expect("at least one seeded filler");
    delete_posix_account(&freed);
    assert!(
        count_enabled_posix_accounts() < FREE_SEATS,
        "a seat should be free after deleting a filler"
    );

    let res = client
        .post(format!("{PORTAL}/admin/posix/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("identity_id", identity_id.as_str()),
            ("username", username.as_str()),
            ("shell", ""),
        ])
        .send()
        .await
        .expect("POST provision (happy path)");
    assert!(
        res.status().is_success(),
        "provision status {}",
        res.status()
    );
    let final_url = res.url().to_string();
    assert!(
        final_url.contains(&format!("/admin/posix/{identity_id}")),
        "happy-path provision should land on the account page; got {final_url}"
    );
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains(&username),
        "account page should show the provisioned username"
    );

    // Cleanup: the provisioned account, the remaining fillers, the identity.
    delete_posix_account(&identity_id);
    for id in &seeded {
        delete_posix_account(id);
    }
    user.cleanup().await;
}

/// Drive the host-enrollment admin surface end to end as a seeded admin:
/// enroll a host (following the `?reveal=` redirect to the list page),
/// assert the one-shot `host_id:secret` banner shows exactly once, confirm
/// a second list GET does NOT re-show it, then revoke the host.
#[tokio::test]
async fn admin_host_enroll_reveal_once_then_revoke() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = try_admin_signed_in_client().await else {
        eprintln!("Skipping host-admin test: FORSETI_ADMIN_TEST_EMAIL/PASSWORD/TOTP_CODE not set.");
        return;
    };

    // 1. Fetch the enroll form to capture the portal CSRF token.
    let res = client
        .get(format!("{PORTAL}/admin/hosts/new"))
        .send()
        .await
        .expect("GET /admin/hosts/new");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("csrf in enroll form");

    // 2. POST enroll. The redirect lands on /admin/hosts?reveal=... with the
    //    one-shot host_id:secret banner.
    let hostname = format!("it-host-{}", chrono::Utc::now().timestamp_millis());
    let res = client
        .post(format!("{PORTAL}/admin/hosts/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("hostname", hostname.as_str()),
            ("org_id", "default"),
        ])
        .send()
        .await
        .expect("POST /admin/hosts/new");
    assert_eq!(res.status().as_u16(), 200, "list page after enroll");
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("Host credential (shown once)"),
        "list body must include the one-shot reveal banner"
    );
    assert!(
        body.contains(&hostname),
        "list body must include the enrolled hostname"
    );
    // The revealed credential is host_id:secret; pull the host_id out of the
    // <pre> banner so we can revoke it afterwards.
    let cred = {
        let pre_start = body.find("<pre").expect("reveal <pre>");
        let open_end = body[pre_start..].find('>').expect("pre tag end") + pre_start + 1;
        let close = body[open_end..].find("</pre>").expect("pre close") + open_end;
        body[open_end..close].trim().to_string()
    };
    let host_id = cred.split_once(':').expect("host_id:secret").0.to_string();
    assert!(!host_id.is_empty(), "host_id present in reveal");

    // 3. A second GET of the list must NOT re-show the secret (single-use).
    let res = client
        .get(format!("{PORTAL}/admin/hosts"))
        .send()
        .await
        .expect("GET /admin/hosts (second)");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    assert!(
        !body.contains("Host credential (shown once)"),
        "the one-shot banner must not reappear on a plain refresh"
    );
    assert!(
        body.contains(&hostname),
        "the enrolled host should still be listed"
    );

    // 4. Revoke via the confirm + POST cycle.
    let res = client
        .get(format!("{PORTAL}/admin/hosts/{host_id}/revoke"))
        .send()
        .await
        .expect("GET revoke-confirm");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("csrf in revoke confirm");
    let res = client
        .post(format!("{PORTAL}/admin/hosts/{host_id}/revoke"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "yes")])
        .send()
        .await
        .expect("POST revoke");
    assert!(res.status().is_success(), "revoke status {}", res.status());

    // Belt-and-braces: ensure the row is gone even if the assertions above bailed.
    delete_host_enrollment(&host_id);
}

/// Enroll a SCOPED host through the real admin handler (`POST
/// /admin/hosts/new` with repeated `team_ids=`), then prove the
/// handler-written `host_allowed_groups` join table actually scopes the
/// resolver: a member of the seeded team resolves 200, a non-member 404.
///
/// The handler enrolls into `DEFAULT_ORG_ID` and only accepts `team_ids`
/// belonging to that org, so the team is seeded in `default` and both
/// accounts (auto-joined to `default` at registration) qualify org-wise;
/// team membership is what gates resolution.
#[tokio::test]
async fn admin_host_enroll_scoped_via_handler() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = admin_client_or_skip().await else {
        return;
    };

    let ts = chrono::Utc::now().timestamp_millis();
    let seed = ts % 50_000;
    let team_id = format!("test-team-scoped-handler-{ts}");
    // gid None: the enroll handler allocates one via find_or_create_team_gid.
    seed_team(
        &team_id,
        "default",
        &format!("scoped-handler-{ts}"),
        &format!("scoped-handler-{ts}"),
        None,
    );

    // Member of the seeded team.
    let member = register_test_user("posix-scoped-handler-in").await;
    let member_id = member.identity_id.clone();
    let member_uid = 76_000 + seed;
    let member_name = format!("posixscopedhin{seed}");
    seed_posix_account(&member_id, &member_name, member_uid, member_uid);
    seed_org_membership("default", &member_id, "member");
    add_team_member(&team_id, &member_id);

    // Non-member: an org member who is NOT in the team (proves it's the team
    // scope, not org membership, that excludes them).
    let other = register_test_user("posix-scoped-handler-out").await;
    let other_id = other.identity_id.clone();
    let other_uid = 77_000 + seed;
    let other_name = format!("posixscopedhout{seed}");
    seed_posix_account(&other_id, &other_name, other_uid, other_uid);
    seed_org_membership("default", &other_id, "member");

    // 1. Fetch the enroll form for a fresh portal CSRF.
    let res = client
        .get(format!("{PORTAL}/admin/hosts/new"))
        .send()
        .await
        .expect("GET /admin/hosts/new");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("csrf in enroll form");

    // 2. POST enroll with `team_ids` = the seeded team. The redirect lands on
    //    /admin/hosts?reveal=... with the one-shot banner.
    let hostname = format!("it-scoped-host-{ts}");
    let res = client
        .post(format!("{PORTAL}/admin/hosts/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("hostname", hostname.as_str()),
            ("org_id", "default"),
            ("team_ids", team_id.as_str()),
        ])
        .send()
        .await
        .expect("POST /admin/hosts/new");
    assert_eq!(res.status().as_u16(), 200, "list page after enroll");
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("Host credential (shown once)"),
        "list body must include the one-shot reveal banner"
    );

    // Parse the revealed host_id:secret out of the <pre> banner exactly as
    // `admin_host_enroll_reveal_once_then_revoke` does.
    let cred = {
        let pre_start = body.find("<pre").expect("reveal <pre>");
        let open_end = body[pre_start..].find('>').expect("pre tag end") + pre_start + 1;
        let close = body[open_end..].find("</pre>").expect("pre close") + open_end;
        body[open_end..close].trim().to_string()
    };
    let (host_id, secret) = cred.split_once(':').expect("host_id:secret");
    assert!(!host_id.is_empty(), "host_id present in reveal");
    assert!(!secret.is_empty(), "secret present in reveal");

    // 3. Resolve via the host's credentials: the member is in scope (200),
    //    the non-member is out of scope (404) — proving the HANDLER-written
    //    join table scopes the resolver.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{member_name}"))
        .basic_auth(host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name member");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "in-scope member should be 200 on the handler-scoped host"
    );
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{other_name}"))
        .basic_auth(host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name non-member");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "non-member must 404 on the handler-scoped host"
    );

    delete_host_enrollment(host_id);
    delete_team(&team_id);
    delete_posix_account(&member_id);
    delete_posix_account(&other_id);
    member.cleanup().await;
    other.cleanup().await;
}

/// Enroll a host scoped to team t1 through the handler, then EDIT its scope to
/// t2 via `POST /admin/hosts/{id}/edit`. A t2-only member must flip from 404 to
/// 200 (and a t1-only member from 200 to 404) — proving the edit handler
/// rewrites `host_allowed_groups`. Both teams live in `DEFAULT_ORG_ID` (the
/// only org the enroll/edit handlers scope against).
#[tokio::test]
async fn admin_host_edit_changes_scope() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = admin_client_or_skip().await else {
        return;
    };

    let ts = chrono::Utc::now().timestamp_millis();
    let seed = ts % 50_000;
    let team1 = format!("test-team-edit-t1-{ts}");
    let team2 = format!("test-team-edit-t2-{ts}");
    seed_team(
        &team1,
        "default",
        &format!("edit-t1-{ts}"),
        &format!("edit-t1-{ts}"),
        None,
    );
    seed_team(
        &team2,
        "default",
        &format!("edit-t2-{ts}"),
        &format!("edit-t2-{ts}"),
        None,
    );

    // Member of t1 only.
    let m1 = register_test_user("posix-edit-g1").await;
    let m1_id = m1.identity_id.clone();
    let m1_uid = 78_000 + seed;
    let m1_name = format!("posixeditg1{seed}");
    seed_posix_account(&m1_id, &m1_name, m1_uid, m1_uid);
    seed_org_membership("default", &m1_id, "member");
    add_team_member(&team1, &m1_id);

    // Member of t2 only.
    let m2 = register_test_user("posix-edit-g2").await;
    let m2_id = m2.identity_id.clone();
    let m2_uid = 79_000 + seed;
    let m2_name = format!("posixeditg2{seed}");
    seed_posix_account(&m2_id, &m2_name, m2_uid, m2_uid);
    seed_org_membership("default", &m2_id, "member");
    add_team_member(&team2, &m2_id);

    // 1. Enroll a host scoped to t1 via the handler.
    let res = client
        .get(format!("{PORTAL}/admin/hosts/new"))
        .send()
        .await
        .expect("GET /admin/hosts/new");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("csrf in enroll form");

    let hostname = format!("it-edit-host-{ts}");
    let res = client
        .post(format!("{PORTAL}/admin/hosts/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("hostname", hostname.as_str()),
            ("org_id", "default"),
            ("team_ids", team1.as_str()),
        ])
        .send()
        .await
        .expect("POST /admin/hosts/new");
    assert_eq!(res.status().as_u16(), 200, "list page after enroll");
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("Host credential (shown once)"),
        "list body must include the one-shot reveal banner"
    );
    let cred = {
        let pre_start = body.find("<pre").expect("reveal <pre>");
        let open_end = body[pre_start..].find('>').expect("pre tag end") + pre_start + 1;
        let close = body[open_end..].find("</pre>").expect("pre close") + open_end;
        body[open_end..close].trim().to_string()
    };
    let (host_id, secret) = cred.split_once(':').expect("host_id:secret");
    let host_id = host_id.to_string();
    let secret = secret.to_string();
    assert!(!host_id.is_empty(), "host_id present in reveal");

    // Initially scoped to t1: m1 resolves, m2 does not.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{m1_name}"))
        .basic_auth(&host_id, Some(&secret))
        .send()
        .await
        .expect("GET passwd/name t1 member (pre-edit)");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "t1 member should resolve while host is scoped to t1"
    );
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{m2_name}"))
        .basic_auth(&host_id, Some(&secret))
        .send()
        .await
        .expect("GET passwd/name t2 member (pre-edit)");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "t2 member must 404 before the scope is changed"
    );

    // 2. Edit the host's scope to t2 (GET first for a fresh CSRF).
    let res = client
        .get(format!("{PORTAL}/admin/hosts/{host_id}/edit"))
        .send()
        .await
        .expect("GET /admin/hosts/{id}/edit");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("csrf in edit form");

    let res = client
        .post(format!("{PORTAL}/admin/hosts/{host_id}/edit"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("hostname", hostname.as_str()),
            ("team_ids", team2.as_str()),
        ])
        .send()
        .await
        .expect("POST /admin/hosts/{id}/edit");
    assert!(res.status().is_success(), "edit status {}", res.status());

    // 3. Scope is now t2: m2 resolves, m1 no longer does.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{m2_name}"))
        .basic_auth(&host_id, Some(&secret))
        .send()
        .await
        .expect("GET passwd/name t2 member (post-edit)");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "t2 member should resolve after the edit re-scopes the host to t2"
    );
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{m1_name}"))
        .basic_auth(&host_id, Some(&secret))
        .send()
        .await
        .expect("GET passwd/name t1 member (post-edit)");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "t1 member must 404 once the host is re-scoped away from t1"
    );

    delete_host_enrollment(&host_id);
    delete_team(&team1);
    delete_team(&team2);
    delete_posix_account(&m1_id);
    delete_posix_account(&m2_id);
    m1.cleanup().await;
    m2.cleanup().await;
}

// --- M2 Part B: device-auth flow ----------------------------------------
//
// These drive the full RFC 8628 device grant through Forseti's host-authed
// endpoints + the browser verification leg against the LIVE stack (Kratos +
// Hydra). They need `make stack-up` + a running Forseti + the `forseti-linux-pam`
// client seeded (`forseti posix-init-client` / playground seed). Skipped at
// runtime when the portal isn't reachable; compile-checked unconditionally.

/// Pull `value="..."` for an input with the given `name` out of a render.
fn extract_input_value(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let idx = html.find(&needle)?;
    let after = &html[idx + needle.len()..];
    let elem_end = after.find('>').unwrap_or(after.len());
    let elem = &after[..elem_end];
    let vi = elem.find("value=\"")? + "value=\"".len();
    let val = &elem[vi..];
    let end = val.find('"')?;
    Some(val[..end].to_string())
}

/// Read `{json}["field"]` as a string off a reqwest JSON response body.
async fn device_init(host_id: &str, secret: &str, username: &str) -> (reqwest::StatusCode, Value) {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{INTERNAL}/posix/v1/device/init"))
        .basic_auth(host_id, Some(secret))
        .json(&serde_json::json!({ "username": username }))
        .send()
        .await
        .expect("POST device/init");
    let status = res.status();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// One `device/poll` round-trip. Returns the parsed JSON `{status: ...}`.
async fn device_poll(host_id: &str, secret: &str, device_code: &str) -> Value {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{INTERNAL}/posix/v1/device/poll"))
        .basic_auth(host_id, Some(secret))
        .json(&serde_json::json!({ "device_code": device_code }))
        .send()
        .await
        .expect("POST device/poll");
    res.json().await.unwrap_or(Value::Null)
}

/// Script the browser approval as `approver` (a signed-in Forseti user).
/// Opens Hydra's `verification_uri` (auto-follows the redirect onto Forseti's
/// `/oauth/device?device_challenge=…&user_code=…`), confirms the host-bound
/// panel, then walks the resulting Hydra login → consent leg, granting the
/// `openid` scope. Returns `true` if the approval chain completed.
async fn browser_approve(
    approver: &RegisteredUser,
    verification_uri: &str,
    user_code: &str,
) -> bool {
    // 1. GET Hydra's verification_uri — Hydra renders/accepts the code and
    //    redirects to Forseti's /oauth/device with device_challenge + user_code.
    //    Some Hydra builds want the code as a query param; append it.
    let entry = if verification_uri.contains('?') {
        format!("{verification_uri}&user_code={user_code}")
    } else {
        format!("{verification_uri}?user_code={user_code}")
    };
    let res = approver
        .client
        .get(&entry)
        .send()
        .await
        .expect("GET verification_uri");
    let landed = res.url().to_string();
    let body = res.text().await.unwrap_or_default();

    // 2. If we're on Forseti's device_verify panel, confirm it.
    if landed.contains("/oauth/device") {
        let challenge = extract_input_value(&body, "device_challenge").unwrap_or_default();
        let csrf = extract_form_csrf(&body).unwrap_or_default();
        let res = approver
            .client
            .post(format!("{PORTAL}/oauth/device"))
            .form(&[
                ("_csrf", csrf.as_str()),
                ("device_challenge", challenge.as_str()),
                ("user_code", user_code),
            ])
            .send()
            .await
            .expect("POST /oauth/device confirm");
        // 3. The confirm drives login (auto-skips for the signed-in user) +
        //    consent. The consent screen MUST render for the PAM client — find
        //    it and accept the openid grant.
        let after = res.url().to_string();
        let confirm_ok = res.status().is_success();
        let body = res.text().await.unwrap_or_default();
        if after.contains("/oauth/consent") {
            let challenge = extract_input_value(&body, "consent_challenge").unwrap_or_default();
            let csrf = extract_input_value(&body, "_csrf").unwrap_or_default();
            let res = approver
                .client
                .post(format!("{PORTAL}/oauth/consent"))
                .form(&[
                    ("_csrf", csrf.as_str()),
                    ("consent_challenge", challenge.as_str()),
                    ("decision", "accept"),
                    ("grant_scope", "openid"),
                ])
                .send()
                .await
                .expect("POST /oauth/consent");
            return res.status().is_success();
        }
        // No consent leg surfaced (already granted) — treat the confirm as done.
        return confirm_ok;
    }
    false
}

/// Poll until terminal (approved/denied/expired) or `max` pending rounds.
async fn poll_until_terminal(host_id: &str, secret: &str, device_code: &str, max: u32) -> String {
    for _ in 0..max {
        let v = device_poll(host_id, secret, device_code).await;
        let status = v["status"].as_str().unwrap_or("").to_string();
        if status != "pending" {
            return status;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    "pending".to_string()
}

/// Happy path: a signed-in user approves a device login for their OWN named
/// account → `approved`. Then a replay poll must NOT re-approve a fresh flow
/// (single-use is asserted via the negative tests below).
#[tokio::test]
async fn device_auth_happy_path_binds_and_approves() {
    if !portal_reachable().await {
        return;
    }
    let approver = register_test_user("dev-ok").await;
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 72_000 + seed;
    let gid = 72_000 + seed;
    let username = format!("devok{seed}");
    let org_id = format!("dev-org-ok-{seed}");
    seed_posix_account(&approver.identity_id, &username, uid, gid);
    seed_org_membership(&org_id, &approver.identity_id, "member");

    let host_id = format!("dev-host-ok-{seed}");
    let secret = "s3cret-dev-ok";
    seed_host_enrollment(&host_id, "ok.example", secret, &org_id);

    let (status, body) = device_init(&host_id, secret, &username).await;
    assert_eq!(status, StatusCode::OK, "device/init: {status} {body}");
    let user_code = body["user_code"].as_str().expect("user_code").to_string();
    let verification_uri = body["verification_uri"]
        .as_str()
        .expect("verification_uri")
        .to_string();
    let device_code = {
        // device_code never leaves Forseti in the init response — read it from
        // the DB by user_code so the test can poll on behalf of the daemon.
        device_code_for_user_code(&user_code).expect("device_code row")
    };

    let approved = browser_approve(&approver, &verification_uri, &user_code).await;
    assert!(approved, "browser approval chain should complete");

    let outcome = poll_until_terminal(&host_id, secret, &device_code, 10).await;
    assert_eq!(
        outcome, "approved",
        "named-target approval should bind+approve"
    );

    // Replay: a second poll after approval returns the settled state, never a
    // fresh approve.
    let v = device_poll(&host_id, secret, &device_code).await;
    assert_eq!(
        v["status"], "approved",
        "replay returns settled approved, not re-approve"
    );
    assert_eq!(
        device_session_status_by_user_code(&user_code).as_deref(),
        Some("approved")
    );

    delete_device_sessions_for_host(&host_id);
    delete_host_enrollment(&host_id);
    delete_org_membership(&org_id, &approver.identity_id);
    approver.cleanup().await;
}

/// Wrong-user-approves: the flow names alice, but bob (a different signed-in
/// user) approves → `denied{binding}`.
#[tokio::test]
async fn device_auth_wrong_user_denied() {
    if !portal_reachable().await {
        return;
    }
    let alice = register_test_user("dev-alice").await;
    let bob = register_test_user("dev-bob").await;
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let a_uid = 73_000 + seed;
    let b_uid = 74_000 + seed;
    let alice_name = format!("devalice{seed}");
    let bob_name = format!("devbob{seed}");
    let org_id = format!("dev-org-wrong-{seed}");
    seed_posix_account(&alice.identity_id, &alice_name, a_uid, a_uid);
    seed_posix_account(&bob.identity_id, &bob_name, b_uid, b_uid);
    // alice is the named target, so she must be visible on the host (org member);
    // bob only needs a signed-in browser session to drive the wrong-user approval.
    seed_org_membership(&org_id, &alice.identity_id, "member");

    let host_id = format!("dev-host-wrong-{seed}");
    let secret = "s3cret-wrong";
    seed_host_enrollment(&host_id, "wrong.example", secret, &org_id);

    // Init names ALICE, but BOB approves.
    let (status, body) = device_init(&host_id, secret, &alice_name).await;
    assert_eq!(status, StatusCode::OK);
    let user_code = body["user_code"].as_str().unwrap().to_string();
    let verification_uri = body["verification_uri"].as_str().unwrap().to_string();
    let device_code = device_code_for_user_code(&user_code).expect("device_code row");

    browser_approve(&bob, &verification_uri, &user_code).await;

    let outcome = poll_until_terminal(&host_id, secret, &device_code, 10).await;
    assert_eq!(outcome, "denied", "approver != named target must be denied");

    delete_device_sessions_for_host(&host_id);
    delete_host_enrollment(&host_id);
    delete_org_membership(&org_id, &alice.identity_id);
    alice.cleanup().await;
    bob.cleanup().await;
}

/// force_mfa host + an AAL1 (password-only) approver → `denied{mfa_required}`.
/// `register_test_user` produces an AAL1 session, so the happy-path approver
/// here is exactly the AAL1 case a force_mfa host must reject.
#[tokio::test]
async fn device_auth_force_mfa_aal1_denied() {
    if !portal_reachable().await {
        return;
    }
    let approver = register_test_user("dev-mfa").await;
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 75_000 + seed;
    let username = format!("devmfa{seed}");
    let org_id = format!("dev-org-mfa-{seed}");
    seed_posix_account(&approver.identity_id, &username, uid, uid);
    seed_org_membership(&org_id, &approver.identity_id, "member");

    let host_id = format!("dev-host-mfa-{seed}");
    let secret = "s3cret-mfa";
    seed_host_enrollment_mfa(&host_id, "mfa.example", secret, &org_id);

    let (status, body) = device_init(&host_id, secret, &username).await;
    assert_eq!(status, StatusCode::OK);
    // force_mfa hosts must NOT receive verification_uri_complete (R1).
    assert!(
        body.get("verification_uri_complete").is_none()
            || body["verification_uri_complete"].is_null(),
        "force_mfa init must omit verification_uri_complete; got {body}"
    );
    let user_code = body["user_code"].as_str().unwrap().to_string();
    let verification_uri = body["verification_uri"].as_str().unwrap().to_string();
    let device_code = device_code_for_user_code(&user_code).expect("device_code row");

    browser_approve(&approver, &verification_uri, &user_code).await;

    let outcome = poll_until_terminal(&host_id, secret, &device_code, 10).await;
    assert_eq!(
        outcome, "denied",
        "force_mfa + AAL1 approver must be denied"
    );

    delete_device_sessions_for_host(&host_id);
    delete_host_enrollment(&host_id);
    delete_org_membership(&org_id, &approver.identity_id);
    approver.cleanup().await;
}

/// Disabled account → `device/init` returns 404 (don't reveal the reason).
#[tokio::test]
async fn device_auth_disabled_account_init_denied() {
    if !portal_reachable().await {
        return;
    }
    let approver = register_test_user("dev-disabled").await;
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 76_000 + seed;
    let username = format!("devdisabled{seed}");
    let org_id = format!("dev-org-disabled-{seed}");
    seed_posix_account(&approver.identity_id, &username, uid, uid);
    seed_org_membership(&org_id, &approver.identity_id, "member");
    set_posix_account_enabled(&approver.identity_id, false);

    let host_id = format!("dev-host-disabled-{seed}");
    let secret = "s3cret-disabled";
    seed_host_enrollment(&host_id, "disabled.example", secret, &org_id);

    let (status, _body) = device_init(&host_id, secret, &username).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "disabled account init → 404");

    delete_device_sessions_for_host(&host_id);
    delete_host_enrollment(&host_id);
    delete_org_membership(&org_id, &approver.identity_id);
    approver.cleanup().await;
}

/// Out-of-scope account (team-scoped host whose allowed team the account isn't
/// a member of, though it IS an org member) → `device/init` 404.
#[tokio::test]
async fn device_auth_out_of_scope_init_denied() {
    if !portal_reachable().await {
        return;
    }
    let approver = register_test_user("dev-scope").await;
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 77_000 + seed;
    let team_gid = 78_000 + seed;
    let username = format!("devscope{seed}");
    let org_id = format!("dev-org-scope-{seed}");
    let team_id = format!("dev-team-scope-{seed}");
    seed_posix_account(&approver.identity_id, &username, uid, uid);
    // Org member, and the team exists, but the account is NOT a team member →
    // out of scope on a team-scoped host.
    seed_org_membership(&org_id, &approver.identity_id, "member");
    seed_team(
        &team_id,
        &org_id,
        &format!("scopegrp{seed}"),
        &format!("scopegrp{seed}"),
        Some(team_gid),
    );

    let host_id = format!("dev-host-scope-{seed}");
    let secret = "s3cret-scope";
    seed_host_enrollment(&host_id, "scope.example", secret, &org_id);
    set_host_allowed_team_ids(&host_id, &[team_id.as_str()]);

    let (status, _body) = device_init(&host_id, secret, &username).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "out-of-scope account init → 404"
    );

    delete_device_sessions_for_host(&host_id);
    delete_host_enrollment(&host_id);
    delete_team(&team_id);
    delete_org_membership(&org_id, &approver.identity_id);
    approver.cleanup().await;
}

// --- M3a: offline auth ---------------------------------------------------

/// Pull the `verifiers` array off a `/posix/v1/offline_verifiers` response.
fn offline_verifier_usernames(body: &Value) -> Vec<String> {
    body["verifiers"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e["username"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `/posix/v1/offline_verifiers` projection on a team-SCOPED host: a member
/// that is enabled + team-scoped + has an offline secret is included; disabled,
/// de-scoped (org member but not a team member), and no-secret accounts are all
/// excluded.
#[tokio::test]
async fn offline_verifiers_includes_only_eligible() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    // Per-run-unique team gid in a high band so a leftover row from an aborted
    // prior run can't collide on org_teams.gid.
    let team_gid: i64 = 2_700_000 + seed;
    let org_id = format!("offl-org-{seed}");
    let team_id = format!("offl-team-{seed}");
    seed_team(
        &team_id,
        &org_id,
        &format!("offlgrp{seed}"),
        &format!("offlgrp{seed}"),
        Some(team_gid),
    );

    // member: enabled + scoped + has-secret → included.
    let member = register_test_user("offl-member").await;
    let member_id = member.identity_id.clone();
    let member_name = format!("offlmember{seed}");
    seed_posix_account(&member_id, &member_name, 90_000 + seed, 90_000 + seed);
    seed_org_membership(&org_id, &member_id, "member");
    add_team_member(&team_id, &member_id);
    seed_offline_secret(
        &member_id,
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
    );

    // nosecret: enabled + scoped but NO offline secret → excluded.
    let nosecret = register_test_user("offl-nosecret").await;
    let nosecret_id = nosecret.identity_id.clone();
    let nosecret_name = format!("offlnosecret{seed}");
    seed_posix_account(&nosecret_id, &nosecret_name, 91_000 + seed, 91_000 + seed);
    seed_org_membership(&org_id, &nosecret_id, "member");
    add_team_member(&team_id, &nosecret_id);

    // disabled: scoped + has-secret but DISABLED → excluded.
    let disabled = register_test_user("offl-disabled").await;
    let disabled_id = disabled.identity_id.clone();
    let disabled_name = format!("offldisabled{seed}");
    seed_posix_account(&disabled_id, &disabled_name, 92_000 + seed, 92_000 + seed);
    seed_org_membership(&org_id, &disabled_id, "member");
    add_team_member(&team_id, &disabled_id);
    seed_offline_secret(
        &disabled_id,
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
    );
    set_posix_account_enabled(&disabled_id, false);

    // descoped: enabled + has-secret + org member but NOT a team member → excluded.
    let descoped = register_test_user("offl-descoped").await;
    let descoped_id = descoped.identity_id.clone();
    let descoped_name = format!("offldescoped{seed}");
    seed_posix_account(&descoped_id, &descoped_name, 93_000 + seed, 93_000 + seed);
    seed_org_membership(&org_id, &descoped_id, "member");
    seed_offline_secret(
        &descoped_id,
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
    );

    let host_id = format!("offl-host-{seed}");
    let secret = "s3cret-offl";
    seed_host_enrollment(&host_id, "offl.example", secret, &org_id);
    set_host_allowed_team_ids(&host_id, &[team_id.as_str()]);

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{INTERNAL}/posix/v1/offline_verifiers"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET offline_verifiers");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "offline_verifiers should be 200"
    );
    let body: Value = res.json().await.expect("offline_verifiers json");
    let names = offline_verifier_usernames(&body);

    assert!(
        names.contains(&member_name),
        "enabled+scoped+has-secret member must be included; got {names:?}"
    );
    assert!(
        !names.contains(&nosecret_name),
        "account with no offline secret must be excluded; got {names:?}"
    );
    assert!(
        !names.contains(&disabled_name),
        "disabled account must be excluded; got {names:?}"
    );
    assert!(
        !names.contains(&descoped_name),
        "de-scoped account must be excluded; got {names:?}"
    );

    // The included row carries the verifier + a positive ttl_secs (24h default).
    let member_row = body["verifiers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["username"] == member_name.as_str())
        .expect("member row present");
    assert!(
        member_row["verifier"]
            .as_str()
            .is_some_and(|v| v.starts_with("$argon2id$")),
        "verifier must be the Argon2id PHC string"
    );
    assert_eq!(member_row["ttl_secs"], Value::from(24 * 3600));
    assert_eq!(member_row["algo_version"], Value::from(1));

    delete_offline_secret(&member_id);
    delete_offline_secret(&disabled_id);
    delete_offline_secret(&descoped_id);
    delete_host_enrollment(&host_id);
    delete_team(&team_id);
    for id in [&member_id, &nosecret_id, &disabled_id, &descoped_id] {
        delete_org_membership(&org_id, id);
    }
    member.cleanup().await;
    nosecret.cleanup().await;
    disabled.cleanup().await;
    descoped.cleanup().await;
}

/// A `force_mfa` host gets an EMPTY offline-verifier set even when users
/// otherwise qualify — closing the AAL2-downgrade (offline = no second factor).
#[tokio::test]
async fn offline_verifiers_force_mfa_host_is_empty() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let user = register_test_user("offl-mfa").await;
    let user_id = user.identity_id.clone();
    let username = format!("offlmfa{seed}");
    seed_posix_account(&user_id, &username, 94_000 + seed, 94_000 + seed);
    seed_offline_secret(
        &user_id,
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
    );

    // Whole-org force_mfa host: the user would qualify on a normal host.
    let org_id = format!("offl-mfa-org-{seed}");
    seed_org_membership(&org_id, &user_id, "member");
    let host_id = format!("offl-mfa-host-{seed}");
    let secret = "s3cret-offl-mfa";
    seed_host_enrollment_mfa(&host_id, "offlmfa.example", secret, &org_id);

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{INTERNAL}/posix/v1/offline_verifiers"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET offline_verifiers (force_mfa)");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("offline_verifiers json");
    assert_eq!(
        body,
        serde_json::json!({ "verifiers": [] }),
        "force_mfa host must get an empty offline-verifier set"
    );

    delete_offline_secret(&user_id);
    delete_host_enrollment(&host_id);
    delete_org_membership(&org_id, &user_id);
    user.cleanup().await;
}

/// `/posix/v1/offline_audit` ingest: a batch of queued offline-auth events
/// lands as audit rows; an oversized batch is rejected with 413.
#[tokio::test]
async fn offline_audit_ingest_writes_rows_and_caps_batch() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let org_id = format!("offl-audit-org-{seed}");
    let host_id = format!("offl-audit-host-{seed}");
    let secret = "s3cret-offl-audit";
    seed_host_enrollment(&host_id, "offlaudit.example", secret, &org_id);

    let client = reqwest::Client::new();
    let username = format!("offlauditeer{seed}");

    // A small valid batch: one success, one failure.
    let res = client
        .post(format!("{INTERNAL}/posix/v1/offline_audit"))
        .basic_auth(&host_id, Some(secret))
        .json(&serde_json::json!({
            "events": [
                { "username": username, "result": "success", "reason": "", "occurred_at": "2026-01-01T00:00:00Z" },
                { "username": username, "result": "failure", "reason": "wrong_passphrase", "occurred_at": "2026-01-01T00:01:00Z" },
                // Garbage entry (empty username) must be silently skipped.
                { "username": "", "result": "failure", "reason": "noise", "occurred_at": "" }
            ]
        }))
        .send()
        .await
        .expect("POST offline_audit");
    assert_eq!(res.status(), StatusCode::OK, "valid batch should be 200");

    assert_eq!(
        count_audit_events_for_host("posix.offline.auth_succeeded", &host_id),
        1,
        "one success event must land as an audit row"
    );
    assert_eq!(
        count_audit_events_for_host("posix.offline.auth_failed", &host_id),
        1,
        "one failure event must land (the empty-username entry is dropped)"
    );

    // Oversized batch (> 256 events) is rejected outright.
    let big: Vec<Value> = (0..300)
        .map(|i| serde_json::json!({ "username": format!("u{i}"), "result": "success" }))
        .collect();
    let res = client
        .post(format!("{INTERNAL}/posix/v1/offline_audit"))
        .basic_auth(&host_id, Some(secret))
        .json(&serde_json::json!({ "events": big }))
        .send()
        .await
        .expect("POST offline_audit (oversized)");
    assert_eq!(
        res.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "an oversized batch must be rejected with 413"
    );

    delete_host_enrollment(&host_id);
}

// --- Task 11b: cross-org tenant isolation --------------------------------
//
// Every host below lives in a NON-default org and every account's org/team
// membership is seeded explicitly. Registration auto-joins `default`, so a
// host in `default` would resolve every registered user and pass vacuously;
// these tests use distinct orgs ("a1"/"a2") so a leak across the org boundary
// is the only way an assertion can flip.

/// Pull the `name` strings off a `/posix/v1/passwd` enumeration body.
fn passwd_names(body: &Value) -> Vec<String> {
    body.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Whole-org host: enumeration + name lookup see ONLY the host org's members.
/// alice is a member of a1, carol of a2; the a1 host must never surface carol.
#[tokio::test]
async fn whole_org_host_resolves_org_members_only() {
    assert!(portal_reachable().await);

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let org_a1 = format!("iso1-a1-{seed}");
    let org_a2 = format!("iso1-a2-{seed}");

    let alice = register_test_user("iso1-alice").await;
    let alice_id = alice.identity_id.clone();
    let alice_name = format!("iso1alice{seed}");
    seed_posix_account(&alice_id, &alice_name, 100_000 + seed, 100_000 + seed);
    seed_org_membership(&org_a1, &alice_id, "member");

    let carol = register_test_user("iso1-carol").await;
    let carol_id = carol.identity_id.clone();
    let carol_name = format!("iso1carol{seed}");
    seed_posix_account(&carol_id, &carol_name, 101_000 + seed, 101_000 + seed);
    seed_org_membership(&org_a2, &carol_id, "member");

    let host_id = format!("iso1-host-{seed}");
    let secret = "s3cret-iso1";
    seed_host_enrollment(&host_id, "iso1.example", secret, &org_a1);

    let client = reqwest::Client::new();

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd (enumerate)");
    assert_eq!(res.status(), StatusCode::OK);
    let names = passwd_names(&res.json().await.expect("passwd_all json"));
    assert!(
        names.contains(&alice_name),
        "a1 host must enumerate its own member alice; got {names:?}"
    );
    assert!(
        !names.contains(&carol_name),
        "a1 host must NOT enumerate a2's member carol; got {names:?}"
    );

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{carol_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name carol");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a member of a different org must 404 on a whole-org host"
    );

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{alice_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name alice");
    assert_eq!(res.status(), StatusCode::OK, "own-org member must resolve");

    delete_host_enrollment(&host_id);
    delete_org_membership(&org_a1, &alice_id);
    delete_org_membership(&org_a2, &carol_id);
    alice.cleanup().await;
    carol.cleanup().await;
}

/// Team-scoped host: only members of the allowed team resolve, and the team's
/// gid roster lists exactly them. alice is in team T; dave is an a1 member but
/// not in T.
#[tokio::test]
async fn team_scoped_host_resolves_team_members_only() {
    assert!(portal_reachable().await);

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let team_gid: i64 = 3_000_000 + seed;
    let org_a1 = format!("iso2-a1-{seed}");
    let team_id = format!("iso2-t1-{seed}");

    let alice = register_test_user("iso2-alice").await;
    let alice_id = alice.identity_id.clone();
    let alice_name = format!("iso2alice{seed}");
    seed_posix_account(&alice_id, &alice_name, 102_000 + seed, 102_000 + seed);
    seed_org_membership(&org_a1, &alice_id, "member");
    seed_team(&team_id, &org_a1, "Platform", "platform", Some(team_gid));
    add_team_member(&team_id, &alice_id);

    let dave = register_test_user("iso2-dave").await;
    let dave_id = dave.identity_id.clone();
    let dave_name = format!("iso2dave{seed}");
    seed_posix_account(&dave_id, &dave_name, 103_000 + seed, 103_000 + seed);
    seed_org_membership(&org_a1, &dave_id, "member");

    let host_id = format!("iso2-host-{seed}");
    let secret = "s3cret-iso2";
    seed_host_enrollment(&host_id, "iso2.example", secret, &org_a1);
    set_host_allowed_team_ids(&host_id, &[team_id.as_str()]);

    let client = reqwest::Client::new();

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{alice_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name alice");
    assert_eq!(res.status(), StatusCode::OK, "team member must resolve");

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{dave_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/name dave");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "an org member NOT in the scoped team must 404"
    );

    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{team_gid}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET group/gid");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "team gid roster should be 200"
    );
    let body: Value = res.json().await.expect("group json");
    let members: Vec<&str> = body["members"]
        .as_array()
        .expect("group members array")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    assert_eq!(
        members,
        vec![alice_name.as_str()],
        "team roster must be exactly the team member alice; got {members:?}"
    );

    delete_host_enrollment(&host_id);
    delete_team(&team_id);
    delete_org_membership(&org_a1, &alice_id);
    delete_org_membership(&org_a1, &dave_id);
    alice.cleanup().await;
    dave.cleanup().await;
}

/// A team that exists only in a FOREIGN org is invisible to the host: neither
/// its gid nor its slug resolves on an a1 host when the team lives in a2.
#[tokio::test]
async fn other_org_team_is_404_on_host() {
    assert!(portal_reachable().await);

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let team_gid_b: i64 = 3_100_000 + seed;
    let org_a1 = format!("iso3-a1-{seed}");
    let org_a2 = format!("iso3-a2-{seed}");
    let team_b = format!("iso3-tb-{seed}");
    let team_b_slug = format!("iso3eng{seed}");

    seed_team(
        &team_b,
        &org_a2,
        "Foreign Eng",
        &team_b_slug,
        Some(team_gid_b),
    );

    let host_id = format!("iso3-host-{seed}");
    let secret = "s3cret-iso3";
    seed_host_enrollment(&host_id, "iso3.example", secret, &org_a1);

    let client = reqwest::Client::new();

    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{team_gid_b}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET group/gid foreign team");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a foreign-org team's gid must not resolve on the host"
    );

    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/name/{team_b_slug}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET group/name foreign team");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a foreign-org team's slug must not resolve on the host"
    );

    delete_host_enrollment(&host_id);
    delete_team(&team_b);
}

/// uid lookups are org-scoped too: bob (a2 only) must 404 by uid on an a1 host
/// even though the account row exists and is enabled.
#[tokio::test]
async fn passwd_by_uid_is_org_scoped() {
    assert!(portal_reachable().await);

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let org_a1 = format!("iso4-a1-{seed}");
    let org_a2 = format!("iso4-a2-{seed}");
    let bob_uid = 105_000 + seed;

    let bob = register_test_user("iso4-bob").await;
    let bob_id = bob.identity_id.clone();
    let bob_name = format!("iso4bob{seed}");
    seed_posix_account(&bob_id, &bob_name, bob_uid, bob_uid);
    seed_org_membership(&org_a2, &bob_id, "member");

    let host_id = format!("iso4-host-{seed}");
    let secret = "s3cret-iso4";
    seed_host_enrollment(&host_id, "iso4.example", secret, &org_a1);

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/uid/{bob_uid}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd/uid bob");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a uid belonging to a foreign-org account must 404"
    );

    delete_host_enrollment(&host_id);
    delete_org_membership(&org_a2, &bob_id);
    bob.cleanup().await;
}

/// authorized_keys for a foreign-org account returns 200 with an empty body
/// (the "no keys" answer), never the seeded key line.
#[tokio::test]
async fn authorized_keys_cross_org_returns_empty() {
    assert!(portal_reachable().await);

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let org_a1 = format!("iso5-a1-{seed}");
    let org_a2 = format!("iso5-a2-{seed}");

    let carol = register_test_user("iso5-carol").await;
    let carol_id = carol.identity_id.clone();
    let carol_name = format!("iso5carol{seed}");
    // seed_posix_account also seeds one ssh_authorized_keys row.
    seed_posix_account(&carol_id, &carol_name, 106_000 + seed, 106_000 + seed);
    seed_org_membership(&org_a2, &carol_id, "member");

    let host_id = format!("iso5-host-{seed}");
    let secret = "s3cret-iso5";
    seed_host_enrollment(&host_id, "iso5.example", secret, &org_a1);

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{INTERNAL}/posix/v1/authorized_keys/{carol_name}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET authorized_keys carol");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "authorized_keys is always 200"
    );
    let body = res.text().await.expect("keys body");
    assert!(
        body.trim().is_empty(),
        "a foreign-org account must yield no keys; got {body:?}"
    );

    delete_host_enrollment(&host_id);
    delete_org_membership(&org_a2, &carol_id);
    carol.cleanup().await;
}

/// The offline-verifier projection is org-bound: a whole-org a1 host sees a1's
/// provisioned members with secrets, never a2's.
#[tokio::test]
async fn offline_verifiers_are_org_bound() {
    assert!(portal_reachable().await);

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let org_a1 = format!("iso6-a1-{seed}");
    let org_a2 = format!("iso6-a2-{seed}");
    const PHC: &str = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";

    let a1_user = register_test_user("iso6-a1").await;
    let a1_id = a1_user.identity_id.clone();
    let a1_name = format!("iso6a1u{seed}");
    seed_posix_account(&a1_id, &a1_name, 107_000 + seed, 107_000 + seed);
    seed_org_membership(&org_a1, &a1_id, "member");
    seed_offline_secret(&a1_id, PHC);

    let a2_user = register_test_user("iso6-a2").await;
    let a2_id = a2_user.identity_id.clone();
    let a2_name = format!("iso6a2u{seed}");
    seed_posix_account(&a2_id, &a2_name, 108_000 + seed, 108_000 + seed);
    seed_org_membership(&org_a2, &a2_id, "member");
    seed_offline_secret(&a2_id, PHC);

    let host_id = format!("iso6-host-{seed}");
    let secret = "s3cret-iso6";
    seed_host_enrollment(&host_id, "iso6.example", secret, &org_a1);

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{INTERNAL}/posix/v1/offline_verifiers"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET offline_verifiers");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("offline_verifiers json");
    let names = offline_verifier_usernames(&body);
    assert!(
        names.contains(&a1_name),
        "a1 host must include a1's provisioned member; got {names:?}"
    );
    assert!(
        !names.contains(&a2_name),
        "a1 host must NEVER include a2's member; got {names:?}"
    );

    delete_offline_secret(&a1_id);
    delete_offline_secret(&a2_id);
    delete_host_enrollment(&host_id);
    delete_org_membership(&org_a1, &a1_id);
    delete_org_membership(&org_a2, &a2_id);
    a1_user.cleanup().await;
    a2_user.cleanup().await;
}

/// A user who belongs to teams in two different orgs is partitioned per host:
/// each host only exposes the team that lives in ITS org. eve is in team T1
/// (a1, gid g1) and team T2 (a2, gid g2).
#[tokio::test]
async fn multi_org_user_sees_only_host_org_team() {
    assert!(portal_reachable().await);

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let g1: i64 = 3_200_000 + seed;
    let g2: i64 = 3_300_000 + seed;
    let org_a1 = format!("iso7-a1-{seed}");
    let org_a2 = format!("iso7-a2-{seed}");
    let team1 = format!("iso7-t1-{seed}");
    let team2 = format!("iso7-t2-{seed}");

    let eve = register_test_user("iso7-eve").await;
    let eve_id = eve.identity_id.clone();
    let eve_name = format!("iso7eve{seed}");
    seed_posix_account(&eve_id, &eve_name, 109_000 + seed, 109_000 + seed);

    seed_org_membership(&org_a1, &eve_id, "member");
    seed_org_membership(&org_a2, &eve_id, "member");
    seed_team(&team1, &org_a1, "Team One", "team-one", Some(g1));
    seed_team(&team2, &org_a2, "Team Two", "team-two", Some(g2));
    add_team_member(&team1, &eve_id);
    add_team_member(&team2, &eve_id);

    let host1 = format!("iso7-h1-{seed}");
    let host2 = format!("iso7-h2-{seed}");
    let secret = "s3cret-iso7";
    seed_host_enrollment(&host1, "iso7-h1.example", secret, &org_a1);
    set_host_allowed_team_ids(&host1, &[team1.as_str()]);
    seed_host_enrollment(&host2, "iso7-h2.example", secret, &org_a2);
    set_host_allowed_team_ids(&host2, &[team2.as_str()]);

    let client = reqwest::Client::new();

    // H1 (a1): g1 resolves with eve, g2 (a2's team) does not.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{g1}"))
        .basic_auth(&host1, Some(secret))
        .send()
        .await
        .expect("GET group/gid g1 on H1");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "g1 must resolve on its own-org host"
    );
    let body: Value = res.json().await.expect("g1 group json");
    let members: Vec<&str> = body["members"]
        .as_array()
        .expect("members array")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    assert_eq!(members, vec![eve_name.as_str()], "g1 roster is eve");

    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{g2}"))
        .basic_auth(&host1, Some(secret))
        .send()
        .await
        .expect("GET group/gid g2 on H1");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a2's team gid must not resolve on the a1 host"
    );

    // H2 (a2): symmetric.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{g2}"))
        .basic_auth(&host2, Some(secret))
        .send()
        .await
        .expect("GET group/gid g2 on H2");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "g2 must resolve on its own-org host"
    );
    let body: Value = res.json().await.expect("g2 group json");
    let members: Vec<&str> = body["members"]
        .as_array()
        .expect("members array")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    assert_eq!(members, vec![eve_name.as_str()], "g2 roster is eve");

    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{g1}"))
        .basic_auth(&host2, Some(secret))
        .send()
        .await
        .expect("GET group/gid g1 on H2");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a1's team gid must not resolve on the a2 host"
    );

    delete_host_enrollment(&host1);
    delete_host_enrollment(&host2);
    delete_team(&team1);
    delete_team(&team2);
    delete_org_membership(&org_a1, &eve_id);
    delete_org_membership(&org_a2, &eve_id);
    eve.cleanup().await;
}
