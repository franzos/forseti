//! Cross-tenant isolation on the org settings surface.
//!
//! `team_id` and org slug arrive separately from the URL, so the pairing has
//! to be checked rather than assumed; and the org read views have to say the
//! same thing about "not your org" as they do about "no such org", or the
//! 404 becomes a slug oracle.
//!
//! Org A is the Default org (no Orgs license needed to act as its owner);
//! org B is seeded straight into the DB as the foreign tenant.

use crate::common::*;

fn extract_form_csrf(body: &str) -> Option<String> {
    let re = regex::Regex::new(r#"name="_csrf"\s+value="([^"]+)""#).ok()?;
    re.captures(body).map(|c| c[1].to_string())
}

/// Owner of the Default org, signed in, with a CSRF token in hand.
async fn default_org_owner(prefix: &str) -> (RegisteredUser, String) {
    let user = register_test_user(prefix).await;
    let _ = user.client.get(PORTAL).send().await;
    set_org_member_role("default", &user.identity_id, "owner");
    let body = user
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings")
        .text()
        .await
        .expect("settings body");
    let csrf = extract_form_csrf(&body).expect("_csrf on /settings");
    (user, csrf)
}

/// Posting your own org's slug with another tenant's `team_id` is a 404, and
/// the foreign team comes through it unchanged: same name, same roster.
#[tokio::test]
async fn team_mutations_refuse_a_foreign_team_id() {
    assert!(portal_reachable().await);
    if !with_orgs_license(foreign_team_id_body).await {
        eprintln!("admin fixture or license blob missing; skipping team isolation test");
    }
}

async fn foreign_team_id_body() {
    let (owner, csrf) = default_org_owner("iso-owner").await;
    let victim = register_test_user("iso-victim").await;
    let _ = victim.client.get(PORTAL).send().await;

    let other_org = format!("iso-org-{}", chrono::Utc::now().timestamp_micros());
    let other_team = format!("iso-team-{}", chrono::Utc::now().timestamp_micros());
    seed_organization(&other_org, &other_org, "Other Tenant", "all");
    seed_team(&other_team, &other_org, "Theirs", "theirs", None);
    add_team_member(&other_team, &victim.identity_id);

    let base = format!("{PORTAL}/settings/organization/teams/{other_team}");
    let cases = [
        (
            format!("{base}/rename"),
            vec![("_csrf", csrf.as_str()), ("name", "Mine Now")],
        ),
        (
            format!("{base}/members"),
            vec![
                ("_csrf", csrf.as_str()),
                ("identity_id", owner.identity_id.as_str()),
            ],
        ),
        (
            format!("{base}/members/{}/remove", victim.identity_id),
            vec![("_csrf", csrf.as_str())],
        ),
        (format!("{base}/delete"), vec![("_csrf", csrf.as_str())]),
    ];
    for (url, form) in &cases {
        let res = owner
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {url}: {e}"));
        assert_eq!(
            res.status().as_u16(),
            404,
            "a foreign team_id must be a miss on {url}; got {}",
            res.status()
        );
    }

    let (name, members) = read_team_state(&other_team);
    assert_eq!(name.as_deref(), Some("Theirs"), "foreign team was renamed");
    assert_eq!(
        members,
        vec![victim.identity_id.clone()],
        "foreign team's roster was changed"
    );

    remove_team_member(&other_team, &victim.identity_id);
    delete_team(&other_team);
    delete_organization(&other_org);
    delete_org_membership("default", &owner.identity_id);
    owner.cleanup().await;
    victim.cleanup().await;
}

/// The owner's own team still renames and takes members - the check binds the
/// pair, it doesn't break the page.
#[tokio::test]
async fn team_mutations_still_work_within_the_org() {
    assert!(portal_reachable().await);
    if !with_orgs_license(same_org_team_body).await {
        eprintln!("admin fixture or license blob missing; skipping team isolation test");
    }
}

async fn same_org_team_body() {
    let (owner, csrf) = default_org_owner("iso-same").await;
    // Slug is unique per org and immutable, so it carries the run stamp.
    let stamp = chrono::Utc::now().timestamp_micros();
    let team_id = format!("iso-own-{stamp}");
    seed_team(&team_id, "default", "Ours", &format!("ours-{stamp}"), None);

    let res = owner
        .client
        .post(format!(
            "{PORTAL}/settings/organization/teams/{team_id}/rename"
        ))
        .form(&[("_csrf", csrf.as_str()), ("name", "Ours Renamed")])
        .send()
        .await
        .expect("POST rename own team");
    assert!(
        res.status().is_success(),
        "renaming a team in your own org must work; got {}",
        res.status()
    );
    let (name, _) = read_team_state(&team_id);
    assert_eq!(name.as_deref(), Some("Ours Renamed"));

    let res = owner
        .client
        .post(format!(
            "{PORTAL}/settings/organization/teams/{team_id}/members"
        ))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("identity_id", owner.identity_id.as_str()),
        ])
        .send()
        .await
        .expect("POST add member to own team");
    assert!(
        res.status().is_success(),
        "adding a member in your own org must work; got {}",
        res.status()
    );
    let (_, members) = read_team_state(&team_id);
    assert_eq!(members, vec![owner.identity_id.clone()]);

    delete_team(&team_id);
    delete_org_membership("default", &owner.identity_id);
    owner.cleanup().await;
}

/// A non-member gets the same not-found on the org read views as they would
/// for a slug that doesn't exist, byte for byte - otherwise the difference
/// tells them which orgs are real.
#[tokio::test]
async fn org_read_views_are_closed_to_non_members() {
    assert!(portal_reachable().await);

    let outsider = register_test_user("iso-outsider").await;
    let _ = outsider.client.get(PORTAL).send().await;

    let org = format!("iso-read-{}", chrono::Utc::now().timestamp_micros());
    seed_organization(&org, &org, "Read Tenant", "all");
    let unknown = format!("{org}-does-not-exist");

    for view in ["info", "branding"] {
        let real = outsider
            .client
            .get(format!("{PORTAL}/settings/organizations/{org}/{view}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {view}: {e}"));
        let real_status = real.status().as_u16();
        let real_body = real.text().await.unwrap_or_default();

        let fake = outsider
            .client
            .get(format!("{PORTAL}/settings/organizations/{unknown}/{view}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET unknown {view}: {e}"));
        let fake_status = fake.status().as_u16();
        let fake_body = fake.text().await.unwrap_or_default();

        assert_eq!(
            real_status, 404,
            "non-member must not read /{view}; got {real_status}"
        );
        assert_eq!(
            (real_status, real_body),
            (fake_status, fake_body),
            "/{view} must answer a real slug and an unknown one identically"
        );
    }

    // A member reads the info view fine.
    seed_org_membership(&org, &outsider.identity_id, "member");
    let res = outsider
        .client
        .get(format!("{PORTAL}/settings/organizations/{org}/info"))
        .send()
        .await
        .expect("GET info as member");
    assert!(
        res.status().is_success(),
        "a member must still read /info; got {}",
        res.status()
    );

    delete_org_membership(&org, &outsider.identity_id);
    delete_organization(&org);
    outsider.cleanup().await;
}

/// The invite token is the whole credential the emailed link carries, so the
/// row holds a hash of it. The link still accepts - proving the lookup path
/// hashes too - and the raw value appears nowhere in the table.
#[tokio::test]
async fn invite_token_is_hashed_at_rest() {
    assert!(portal_reachable().await);

    let (owner, csrf) = default_org_owner("inv-owner").await;

    // The accept path requires a signed-in, verified identity at the invited
    // address, so the invitee exists before the invite is minted.
    let invitee_email = unique_email("invitee");
    let invitee_password = "correct-horse-battery-staple-9";
    let invitee_id =
        kratos_admin_create_verified_password_identity(&invitee_email, invitee_password).await;
    delete_invites_for_email(&invitee_email);

    let res = owner
        .client
        .post(format!("{PORTAL}/settings/organization/members/invite"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("email", invitee_email.as_str()),
            ("role", "member"),
        ])
        .send()
        .await
        .expect("POST invite");
    assert!(
        res.status().is_success(),
        "minting an invite should succeed; got {}",
        res.status()
    );

    // The raw token only exists in the email Forseti just sent.
    let mail = wait_for_mailcrab(
        &invitee_email,
        "invited you to",
        std::time::Duration::from_secs(20),
    )
    .await
    .expect("invite email");
    let raw = regex::Regex::new(r"token=([0-9a-f]+)")
        .expect("token regex")
        .captures(&mail.body)
        .map(|c| c[1].to_string())
        .expect("accept link carries ?token= in the invite email");

    assert_eq!(
        count_invites_with_token(&raw),
        0,
        "the raw invite token must not be stored"
    );
    assert_eq!(
        count_invites_with_token(&sha256_hex(&raw)),
        1,
        "the stored token must be its SHA-256"
    );

    // The emailed link still resolves the invite, so the lookup hashes too.
    let invitee_client = browser_client();
    password_login_aal1(&invitee_client, &invitee_email, invitee_password).await;
    let body = invitee_client
        .get(format!("{PORTAL}/invite/accept?token={raw}"))
        .send()
        .await
        .expect("GET /invite/accept")
        .text()
        .await
        .expect("accept page");
    let accept_csrf = extract_form_csrf(&body).expect("_csrf on the accept page");

    let res = invitee_client
        .post(format!("{PORTAL}/invite/accept"))
        .form(&[("_csrf", accept_csrf.as_str()), ("token", raw.as_str())])
        .send()
        .await
        .expect("POST /invite/accept");
    assert!(
        res.status().is_success(),
        "accepting via the emailed token must work; got {}",
        res.status()
    );
    assert!(
        invite_is_accepted(&sha256_hex(&raw)),
        "the POST should have marked the invite accepted, which it can only \
         find by hashing the token it was handed"
    );

    delete_invites_for_email(&invitee_email);
    delete_org_membership("default", &owner.identity_id);
    delete_org_membership("default", &invitee_id);
    owner.cleanup().await;
    let _ = delete_test_identity(&invitee_id).await;
}
