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

/// Black-box exercise of the `/posix/v1/*` resolver on the internal
/// listener: host Basic auth, a single passwd lookup, authorized_keys, the
/// enumeration-returns-empty rule for an unscoped (allowed_gid = NULL) host,
/// and a 401 on a wrong secret.
#[tokio::test]
async fn resolver_unscoped_host_basic_lookups() {
    assert!(portal_reachable().await);

    let user = register_test_user("posix-resolver").await;
    let identity_id = user.identity_id.clone();

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 71_000 + seed;
    let gid = 71_000 + seed;
    let username = format!("posixresolver{seed}");
    seed_posix_account(&identity_id, &username, uid, gid);

    let host_id = format!("test-host-{seed}");
    let secret = "s3cret-resolver";
    seed_host_enrollment(&host_id, "fixture.example", secret, None);

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

    // 3. Enumeration on an unscoped host returns an empty array.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET passwd (enumerate)");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("passwd_all json");
    assert_eq!(
        body,
        serde_json::json!([]),
        "unscoped enumeration must be empty"
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
    user.cleanup().await;
}

/// Scoped host (`allowed_gid = Some`): only members of the org group are
/// reachable, enumeration is restricted to them, and an `allowed_gid` that
/// points at a non-org (`kind='user'`) gid fails closed (resolves nothing).
#[tokio::test]
async fn resolver_scoped_host_enforces_gid() {
    assert!(portal_reachable().await);

    const ORG_GID: i64 = 2_500_000;

    // In-scope member.
    let member = register_test_user("posix-scoped-in").await;
    let member_id = member.identity_id.clone();
    let seed_a = chrono::Utc::now().timestamp_millis() % 50_000;
    let member_uid = 72_000 + seed_a;
    let member_gid = 72_000 + seed_a;
    let member_name = format!("posixscopedin{seed_a}");
    seed_posix_account(&member_id, &member_name, member_uid, member_gid);

    seed_org_group(ORG_GID, "engineering");
    add_posix_group_member(ORG_GID, &member_id);

    // Out-of-scope account (NOT a member of ORG_GID).
    let outsider = register_test_user("posix-scoped-out").await;
    let outsider_id = outsider.identity_id.clone();
    let seed_b = (chrono::Utc::now().timestamp_millis() + 1) % 50_000;
    let outsider_uid = 73_000 + seed_b;
    let outsider_gid = 73_000 + seed_b;
    let outsider_name = format!("posixscopedout{seed_b}");
    seed_posix_account(&outsider_id, &outsider_name, outsider_uid, outsider_gid);

    // Scoped host bound to the org gid.
    let host_id = format!("test-scoped-host-{seed_a}");
    let secret = "s3cret-scoped";
    seed_host_enrollment(&host_id, "scoped.example", secret, Some(ORG_GID));

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

    // Group roster by gid lists the member.
    let res = client
        .get(format!("{INTERNAL}/posix/v1/group/gid/{ORG_GID}"))
        .basic_auth(&host_id, Some(secret))
        .send()
        .await
        .expect("GET group/gid");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "org group lookup should be 200"
    );
    let body: Value = res.json().await.expect("group json");
    let members = body["members"].as_array().expect("group members array");
    assert!(
        members
            .iter()
            .any(|m| m == &Value::from(member_name.clone())),
        "org roster must include the member; got {members:?}"
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

    // Fail-closed: a host whose allowed_gid is a kind='user' gid (the
    // member's own primary group) resolves nothing.
    let bad_host_id = format!("test-userscoped-host-{seed_a}");
    let bad_secret = "s3cret-userscoped";
    seed_host_enrollment(
        &bad_host_id,
        "userscoped.example",
        bad_secret,
        Some(member_gid),
    );

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd"))
        .basic_auth(&bad_host_id, Some(bad_secret))
        .send()
        .await
        .expect("GET passwd (user-gid scoped)");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("user-gid passwd_all json");
    assert_eq!(
        body,
        serde_json::json!([]),
        "a non-org allowed_gid must fail closed (empty enumeration)"
    );

    let res = client
        .get(format!("{INTERNAL}/posix/v1/passwd/name/{member_name}"))
        .basic_auth(&bad_host_id, Some(bad_secret))
        .send()
        .await
        .expect("GET passwd/name (user-gid scoped)");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a non-org allowed_gid must fail closed (no name resolution)"
    );

    delete_host_enrollment(&bad_host_id);
    delete_host_enrollment(&host_id);
    delete_posix_group_members(ORG_GID);
    delete_posix_group(ORG_GID);
    member.cleanup().await;
    outsider.cleanup().await;
}

/// Org-membership removal must revoke the ex-member from the org's POSIX
/// mirror, so a host SCOPED to that org's gid stops resolving them (H1).
///
/// Seeds the licensed-state shape directly via rusqlite (an `org`-kind
/// `posix_groups` row keyed by a real `org_id` + a membership), proves the
/// scoped host resolves the member, then applies the exact net effect of
/// `posix::db::remove_identity_from_org_group` — `DELETE FROM
/// posix_group_members WHERE gid = <org gid> AND identity_id = ?` — and
/// asserts the host no longer resolves the ex-member.
///
/// TODO: the full handler path (`POST .../members` remove → the wired
/// `remove_identity_from_org_group` call) needs an active Orgs license to
/// pass `require_org_owner_with_license`; the integration harness has no
/// license-activation path (the licensed e2e bucket does it over HTTP).
/// The handler → helper wiring is covered by `cargo check`; this test pins
/// the resulting access-revocation invariant the resolver enforces.
#[tokio::test]
async fn org_member_removal_revokes_scoped_host_access() {
    assert!(portal_reachable().await);

    const ORG_GID: i64 = 2_600_000;
    let org_id = format!("test-org-{}", chrono::Utc::now().timestamp_millis());

    let member = register_test_user("posix-orgremove").await;
    let member_id = member.identity_id.clone();
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let member_uid = 74_000 + seed;
    let member_name = format!("posixorgremove{seed}");
    seed_posix_account(&member_id, &member_name, member_uid, member_uid);

    seed_org_group_with_org_id(ORG_GID, "scoped-eng", &org_id);
    add_posix_group_member(ORG_GID, &member_id);

    let host_id = format!("test-orgremove-host-{seed}");
    let secret = "s3cret-orgremove";
    seed_host_enrollment(&host_id, "orgremove.example", secret, Some(ORG_GID));

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

    // The org-removal cleanup: drop the member from the org's POSIX mirror.
    // Mirrors `remove_identity_from_org_group`'s net effect exactly.
    delete_org_group_member(ORG_GID, &member_id);
    assert_eq!(
        count_org_group_memberships(&member_id),
        0,
        "org-group membership must be gone after removal"
    );

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
    delete_posix_group_members(ORG_GID);
    delete_posix_group(ORG_GID);
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

/// Org→posix-group sync is gated behind the commercial `Feature::Orgs`. In
/// the default CI state (no license) provisioning a user who already belongs
/// to an org (every user auto-joins the seeded `default` org) must NOT create
/// any `org`-kind group or membership — only the `user`-kind primary group.
///
/// TODO: the licensed case (an active Orgs license → one `org`-kind group per
/// org, shared membership) needs a license fixture activated via
/// `/admin/license`; the integration harness has no license-activation path
/// yet (the licensed e2e bucket does it over HTTP). Deferred, mirroring the
/// `max_seats` TODO above.
#[tokio::test]
async fn admin_posix_org_group_sync_gated_off_unlicensed() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = try_admin_signed_in_client().await else {
        eprintln!(
            "Skipping posix-org-sync test: FORSETI_ADMIN_TEST_EMAIL/PASSWORD/TOTP_CODE not set."
        );
        return;
    };

    // A freshly-registered user auto-joins the seeded `default` org, so it has
    // at least one membership the sync WOULD mirror if Orgs were licensed.
    let user = register_test_user("posix-orgsync").await;
    let identity_id = user.identity_id.clone();

    let base = 85_000 + (chrono::Utc::now().timestamp_millis() % 40_000);
    let username = format!("orgsync{base}");

    let res = client
        .get(format!("{PORTAL}/admin/posix/new"))
        .send()
        .await
        .expect("GET /admin/posix/new");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("csrf in provision form");

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
        .expect("POST provision");
    assert!(
        res.status().is_success(),
        "provision status {}",
        res.status()
    );
    let final_url = res.url().to_string();
    assert!(
        final_url.contains(&format!("/admin/posix/{identity_id}")),
        "provision should land on the account page; got {final_url}"
    );

    // Unlicensed: no org-kind group membership mirrored — only the user-kind
    // primary group from `provision_account`.
    assert_eq!(
        count_org_group_memberships(&identity_id),
        0,
        "unlicensed provision must not mirror org memberships into org-kind posix groups"
    );

    delete_posix_account(&identity_id);
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
            ("allowed_gid", ""),
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
    seed_posix_account(&approver.identity_id, &username, uid, gid);

    let host_id = format!("dev-host-ok-{seed}");
    let secret = "s3cret-dev-ok";
    seed_host_enrollment(&host_id, "ok.example", secret, None);

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
    seed_posix_account(&alice.identity_id, &alice_name, a_uid, a_uid);
    seed_posix_account(&bob.identity_id, &bob_name, b_uid, b_uid);

    let host_id = format!("dev-host-wrong-{seed}");
    let secret = "s3cret-wrong";
    seed_host_enrollment(&host_id, "wrong.example", secret, None);

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
    seed_posix_account(&approver.identity_id, &username, uid, uid);

    let host_id = format!("dev-host-mfa-{seed}");
    let secret = "s3cret-mfa";
    seed_host_enrollment_mfa(&host_id, "mfa.example", secret, None);

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
    seed_posix_account(&approver.identity_id, &username, uid, uid);
    set_posix_account_enabled(&approver.identity_id, false);

    let host_id = format!("dev-host-disabled-{seed}");
    let secret = "s3cret-disabled";
    seed_host_enrollment(&host_id, "disabled.example", secret, None);

    let (status, _body) = device_init(&host_id, secret, &username).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "disabled account init → 404");

    delete_device_sessions_for_host(&host_id);
    delete_host_enrollment(&host_id);
    approver.cleanup().await;
}

/// Out-of-scope account (scoped host whose allowed_gid group the account
/// isn't a member of) → `device/init` 404.
#[tokio::test]
async fn device_auth_out_of_scope_init_denied() {
    if !portal_reachable().await {
        return;
    }
    let approver = register_test_user("dev-scope").await;
    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    let uid = 77_000 + seed;
    let org_gid = 78_000 + seed;
    let username = format!("devscope{seed}");
    seed_posix_account(&approver.identity_id, &username, uid, uid);
    // Org group exists, but the account is NOT a member → out of scope.
    seed_org_group(org_gid, &format!("scopegrp{seed}"));

    let host_id = format!("dev-host-scope-{seed}");
    let secret = "s3cret-scope";
    seed_host_enrollment(&host_id, "scope.example", secret, Some(org_gid));

    let (status, _body) = device_init(&host_id, secret, &username).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "out-of-scope account init → 404"
    );

    delete_device_sessions_for_host(&host_id);
    delete_host_enrollment(&host_id);
    delete_posix_group(org_gid);
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

/// `/posix/v1/offline_verifiers` projection on a SCOPED host: a member that is
/// enabled + scoped + has an offline secret is included; disabled, de-scoped,
/// and no-secret accounts are all excluded.
#[tokio::test]
async fn offline_verifiers_includes_only_eligible() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }

    let seed = chrono::Utc::now().timestamp_millis() % 50_000;
    // Per-run-unique org gid in a high band so a leftover row from an aborted
    // prior run can't collide on posix_groups.gid (UNIQUE).
    let org_gid: i64 = 2_700_000 + seed;

    // member: enabled + scoped + has-secret → included.
    let member = register_test_user("offl-member").await;
    let member_id = member.identity_id.clone();
    let member_name = format!("offlmember{seed}");
    seed_posix_account(&member_id, &member_name, 90_000 + seed, 90_000 + seed);
    seed_org_group(org_gid, &format!("offlgrp{seed}"));
    add_posix_group_member(org_gid, &member_id);
    seed_offline_secret(
        &member_id,
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
    );

    // nosecret: enabled + scoped but NO offline secret → excluded.
    let nosecret = register_test_user("offl-nosecret").await;
    let nosecret_id = nosecret.identity_id.clone();
    let nosecret_name = format!("offlnosecret{seed}");
    seed_posix_account(&nosecret_id, &nosecret_name, 91_000 + seed, 91_000 + seed);
    add_posix_group_member(org_gid, &nosecret_id);

    // disabled: scoped + has-secret but DISABLED → excluded.
    let disabled = register_test_user("offl-disabled").await;
    let disabled_id = disabled.identity_id.clone();
    let disabled_name = format!("offldisabled{seed}");
    seed_posix_account(&disabled_id, &disabled_name, 92_000 + seed, 92_000 + seed);
    add_posix_group_member(org_gid, &disabled_id);
    seed_offline_secret(
        &disabled_id,
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
    );
    set_posix_account_enabled(&disabled_id, false);

    // descoped: enabled + has-secret but NOT a member of ORG_GID → excluded.
    let descoped = register_test_user("offl-descoped").await;
    let descoped_id = descoped.identity_id.clone();
    let descoped_name = format!("offldescoped{seed}");
    seed_posix_account(&descoped_id, &descoped_name, 93_000 + seed, 93_000 + seed);
    seed_offline_secret(
        &descoped_id,
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
    );

    let host_id = format!("offl-host-{seed}");
    let secret = "s3cret-offl";
    seed_host_enrollment(&host_id, "offl.example", secret, Some(org_gid));

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
        .find(|e| e["username"] == Value::from(member_name.clone()))
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
    delete_posix_group_members(org_gid);
    delete_posix_group(org_gid);
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

    // Unscoped force_mfa host: the user would qualify on a normal host.
    let host_id = format!("offl-mfa-host-{seed}");
    let secret = "s3cret-offl-mfa";
    seed_host_enrollment_mfa(&host_id, "offlmfa.example", secret, None);

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
    let host_id = format!("offl-audit-host-{seed}");
    let secret = "s3cret-offl-audit";
    seed_host_enrollment(&host_id, "offlaudit.example", secret, None);

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
