//! `/settings/account/delete` — self-service account deletion saga.
//!
//! The saga has three observable effects: (1) the Kratos identity is gone,
//! (2) the user's session is invalidated and they land on `/login`, and
//! (3) registered apps get an RFC 8417 Security Event Token at their
//! configured `account_deletion_url` (RISC `account-purged` event).
//!
//! This file covers (1) + (2), plus a lightweight sanity check on the
//! portal's JWKS endpoint. The full fan-out test for (3) needs more
//! scaffolding — see [`_todo_webhook_fanout_test`] for the shape of what's
//! missing.

use crate::common::*;
use reqwest::StatusCode;
use serde_json::Value;

#[tokio::test]
async fn account_delete_landing_page_renders_for_authenticated_user() {
    assert!(portal_reachable().await);
    let user = register_test_user("acct-delete-landing").await;

    let res = user
        .client
        .get(format!("{PORTAL}/settings/account"))
        .send()
        .await
        .expect("GET /settings/account");
    assert!(
        res.status().is_success(),
        "/settings/account: {}",
        res.status()
    );
    let body = res.text().await.expect("body");
    assert!(
        body.contains("Delete my account"),
        "danger zone should advertise the delete action"
    );

    user.cleanup().await;
}

#[tokio::test]
async fn account_delete_landing_redirects_anonymous_to_login() {
    let client = manual_redirect_client();
    let res = client
        .get(format!("{PORTAL}/settings/account"))
        .send()
        .await
        .expect("GET /settings/account anon");
    assert_eq!(res.status().as_u16(), 303);
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.contains("/login"),
        "anonymous /settings/account should redirect to /login; got {loc}"
    );
}

#[tokio::test]
async fn account_delete_saga_removes_kratos_identity() {
    assert!(portal_reachable().await);

    // A freshly-registered user has a privileged Kratos session for the
    // next 15 minutes (Kratos's `privileged_session_max_age`), so we can
    // post directly to `/settings/account/delete` without bouncing
    // through `/login?refresh=true`.
    let user = register_test_user("acct-delete-saga").await;
    let identity_id = user.identity_id.clone();
    let email = user.email.clone();

    // 1. GET the confirm page — verifies the privileged-session gate
    //    works AND gives us a fresh CSRF token bound to the same cookie
    //    jar that the POST will use.
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
    assert!(
        res.url().path().starts_with("/settings/account/delete"),
        "expected to land on the confirm page, got {}",
        res.url()
    );
    // The confirm-page URL carries `?flow=<id>` after Kratos init —
    // POST must hit the same URL so the privileged-session probe in the
    // POST handler sees the same flow id.
    let post_url = res.url().clone();
    let body = res.text().await.expect("confirm body");
    let csrf = extract_form_csrf(&body).expect("_csrf hidden input on confirm page");

    // 2. POST the deletion form. CSRF + the typed-email belt-and-braces
    //    confirm must match the session's email.
    let res = user
        .client
        .post(post_url)
        .form(&[("_csrf", csrf.as_str()), ("confirm_email", email.as_str())])
        .send()
        .await
        .expect("POST /settings/account/delete");

    // 3. The saga succeeded if we land on /login (Kratos session is
    //    invalid and the redirect chain bottoms out there). The route's
    //    direct response is `303 /login?msg=account_deleted`, which the
    //    auto-redirect client follows.
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("/login"),
        "expected to land on /login after delete; got {final_url}"
    );

    // 4. The identity should be gone from Kratos.
    let post_delete = identity_id_by_email(&email).await;
    assert!(
        post_delete.is_none(),
        "kratos identity should be deleted; admin lookup returned Some({post_delete:?}) for {email} (id was {identity_id})"
    );

    // 5. The user's session should be invalid — `/dashboard`/`/settings`
    //    bounces to /login.
    let manual = manual_redirect_client();
    // Steal the cookie jar via a separate request from `user.client`
    // (which kept following redirects above). Easiest portable check:
    // re-issue the same `user.client` against a protected route and
    // confirm it redirects to /login.
    let res = user
        .client
        .get(format!("{PORTAL}/settings"))
        .send()
        .await
        .expect("GET /settings after delete");
    // Either 303 → /login (manual_client style) or the auto-redirect
    // client landed on /login after following hops.
    assert!(
        res.url().path().starts_with("/login") || res.status() == StatusCode::SEE_OTHER,
        "after delete, /settings should redirect to /login; got url={} status={}",
        res.url(),
        res.status()
    );
    let _ = manual; // unused — kept for documentation of the alternative

    // No cleanup — the identity is already gone.
}

/// The deletion saga must also revoke the user's Hydra consent sessions, so a
/// stale refresh token can't outlive the account. `account_delete_saga_*`
/// proves the Kratos identity is gone; this proves the OAuth side
/// (`revoke_consent_sessions_for_subject`) is wiped too.
#[tokio::test]
async fn account_delete_saga_revokes_hydra_consent_sessions() {
    assert!(portal_reachable().await);

    let user = register_test_user("acct-delete-consent").await;
    let identity_id = user.identity_id.clone();
    let email = user.email.clone();

    // 1. Establish a remembered Hydra consent grant for this subject.
    let (client_id, _secret, redirect_uri) =
        hydra_create_test_client(&["openid", "offline", "email"]).await;
    let auth_url = oauth_auth_url(&client_id, &redirect_uri, "openid offline email", "");
    let (consent_challenge, csrf, _body) = drive_to_consent(&user.client, &auth_url).await;
    let _code = consent_accept_chase_code(
        &user.manual_client,
        &csrf,
        &consent_challenge,
        &["openid", "offline", "email"],
        true,
    )
    .await
    .expect("authorization code on callback");
    assert!(
        hydra_consent_session_count(&identity_id).await >= 1,
        "precondition: a remembered consent session should exist before delete"
    );

    // 2. Run the delete saga (privileged session is fresh post-registration).
    let res = user
        .client
        .get(format!("{PORTAL}/settings/account/delete"))
        .send()
        .await
        .expect("GET /settings/account/delete");
    assert!(res.status().is_success());
    let post_url = res.url().clone();
    let body = res.text().await.expect("confirm body");
    let csrf = extract_form_csrf(&body).expect("_csrf on confirm page");
    let res = user
        .client
        .post(post_url)
        .form(&[("_csrf", csrf.as_str()), ("confirm_email", email.as_str())])
        .send()
        .await
        .expect("POST /settings/account/delete");
    assert!(
        res.url().to_string().contains("/login"),
        "saga should land on /login"
    );

    // 3. Both the identity and its Hydra consent sessions must be gone.
    assert!(
        identity_id_by_email(&email).await.is_none(),
        "kratos identity should be deleted"
    );
    assert_eq!(
        hydra_consent_session_count(&identity_id).await,
        0,
        "delete saga must revoke all Hydra consent sessions for the subject"
    );

    hydra_delete_client(&client_id).await;
    // No identity cleanup — already deleted.
}

/// Pull a `_csrf` hidden input value out of a settings page render. Settings
/// pages name their CSRF token `_csrf` (portal-owned forms — see
/// `src/csrf.rs`); the Kratos-driven forms use `csrf_token` and have a
/// separate helper (`flow_csrf_token`).
fn extract_form_csrf(html: &str) -> Option<String> {
    // Match `name="_csrf"` and read the `value="..."` that follows in the
    // same `<input>` element.
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

/// The portal's webhook JWKS endpoint is public and unauthenticated —
/// any receiver should be able to fetch it before verifying a SET. Smoke-
/// test the shape so any boot-time regression (key didn't load, JWK
/// missing fields) surfaces here.
#[tokio::test]
async fn webhook_jwks_endpoint_serves_well_formed_ed25519_key() {
    assert!(portal_reachable().await);
    let client = browser_client();
    let res = client
        .get(format!("{PORTAL}/.well-known/webhook-jwks.json"))
        .send()
        .await
        .expect("GET webhook-jwks");
    assert!(res.status().is_success(), "status {}", res.status());
    let cache = res
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        cache.contains("max-age=86400"),
        "JWKS should advertise a day-long cache; got {cache}"
    );
    let body: Value = res.json().await.expect("jwks json");
    let keys = body["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1, "exactly one signing key");
    let jwk = &keys[0];
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["alg"], "EdDSA");
    assert!(jwk["kid"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
    assert!(jwk["x"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
}

/// Sketch of the full webhook fan-out integration test that's not yet
/// wired up. Captured here so the next person (or future-me) can stand
/// it up without re-deriving the design.
///
/// **What it should prove.** End-to-end, a `POST /settings/account/delete`
/// fans out an RFC 8417 Security Event Token (RISC `account-purged`,
/// signed EdDSA against the portal's JWKS) to every OAuth2 client whose
/// `metadata.portal.account_deletion_url` is set.
///
/// **Scaffolding still missing.**
///
/// 1. **Mock HTTP receiver.** Bind a `tokio::net::TcpListener` to
///    `127.0.0.1:0`, accept one connection, read the request bytes, and
///    return `200 OK`. Surface the captured body + headers via an
///    `Arc<Mutex<...>>`. ~50 lines.
///
/// 2. **Hydra client with `account_deletion_url` metadata.** Extend
///    `hydra_create_test_client` (`common.rs:531`) to accept a
///    `serde_json::Value` for `metadata`; pass through `account_deletion_url`
///    under `metadata.portal.account_deletion_url`. No webhook-secret
///    minting step is needed anymore — the portal owns the signing key.
///
/// 3. **Drive Hydra consent.** Reuse `post_consent_chase_code` (in
///    `tests/integration/oauth.rs:148`) so Hydra has a recorded
///    consent session for the subject; the saga reads
///    `list_consent_sessions_by_subject` to decide who to notify.
///
/// 4. **Wait for the worker.** Worker tick is 5s
///    (`webhook.rs::TICK`); allow ~15s with a poll loop on the mock
///    receiver's captured list.
///
/// 5. **Verify the payload.** Fetch
///    `/.well-known/webhook-jwks.json` via the test client, build a
///    `jsonwebtoken::DecodingKey::from_jwk(...)`, and call
///    `jsonwebtoken::decode::<Value>(jws, &key, &Validation::new(Algorithm::EdDSA))`.
///    Assert the resulting claims carry `iss == portal_self_url`,
///    `aud == client_id`, the RISC URI
///    `https://schemas.openid.net/secevent/risc/event-type/account-purged`
///    is present in `events`, and `events[..].subject.sub` equals the
///    deleted identity id. Also assert the `X-Portal-Event` header
///    matches `claims.jti`.
///
/// Putting this in place: maybe 200 lines including the mock receiver
/// and helpers. Worth doing before the next Phase-1-touching change
/// lands.
#[allow(dead_code)]
fn _todo_webhook_fanout_test() {}

/// One row in every table the Kratos cascade never reaches and one value in
/// every reference column, seeded for one user so each deletion step has
/// something to remove or null.
struct Fixture {
    org_id: String,
    team_id: String,
    host_id: String,
    resource: String,
    client_id: String,
    invite_own: String,
    invite_other: String,
    other_email: String,
    gid: i64,
}

fn seed_fixture(user: &RegisteredUser) -> Fixture {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let digits = format!("{seed}");
    let short = digits[digits.len() - 10..].to_string();
    let id = user.identity_id.as_str();
    let email = user.email.as_str();
    let org_id = format!("org-del-{short}");
    let team_id = format!("team-del-{short}");
    let host_id = format!("host-del-{short}");
    let resource = format!("https://del-{short}.example.test");
    let client_id = format!("client-del-{short}");
    let invite_own = format!("del-invite-own-{short}");
    let invite_other = format!("del-invite-other-{short}");
    let other_email = format!("other-{short}@example.test");
    let gid = 800_000 + (seed % 90_000) as i64;

    seed_profile_username(id, &format!("del-{short}"), &format!("old-{short}"));
    seed_offline_secret(id, &format!("verifier-{short}"));
    seed_oidc_link(id, "github");
    seed_posix_account(id, &format!("deluser{short}"), gid, gid);
    seed_organization(&org_id, &org_id, "Delete Test Org", "all");
    set_reference_column("organizations", "created_by", "id", &org_id, id);
    seed_org_membership(&org_id, id, "member");
    set_reference_column("organization_members", "added_by", "org_id", &org_id, id);
    seed_team(&team_id, &org_id, "Delete Team", &team_id, None);
    set_reference_column("org_teams", "created_by", "id", &team_id, id);
    add_team_member(&team_id, id);
    seed_allowed_domain(&org_id, &format!("del-{short}.example.test"), id);
    seed_saml_connection(&org_id, id);
    seed_saml_link(&org_id, email, id, &format!("idp-{short}"));
    seed_host_enrollment(&host_id, &format!("{host_id}.example.test"), "s", &org_id);
    set_reference_column("host_enrollments", "created_by", "id", &host_id, email);
    seed_host_account_login(&host_id, id);
    seed_device_session(
        &format!("dc-{short}"),
        &format!("UC{short}"),
        &host_id,
        "deluser",
        id,
        &format!("cch-{short}"),
    );
    seed_hydra_op_rows(id, &format!("sid-{short}"), &client_id);
    seed_registry_resource(&resource);
    set_reference_column(
        "resource_registry",
        "created_by",
        "resource",
        &resource,
        email,
    );
    seed_cimd_metadata_row(&client_id);
    set_reference_column(
        "oauth_client_metadata",
        "verified_by",
        "client_id",
        &client_id,
        id,
    );
    set_reference_column(
        "oauth_client_metadata",
        "verification_revoked_by",
        "client_id",
        &client_id,
        email,
    );
    seed_org_invite(&invite_own, email, Some(id));
    seed_org_invite(&invite_other, &other_email, Some(id));
    set_reference_column(
        "organization_invites",
        "accepted_by",
        "token",
        &invite_other,
        id,
    );
    Fixture {
        org_id,
        team_id,
        host_id,
        resource,
        client_id,
        invite_own,
        invite_other,
        other_email,
        gid,
    }
}

impl Fixture {
    fn cleanup(&self, email: &str) {
        delete_team(&self.team_id);
        delete_host_account_logins(&self.host_id);
        delete_device_sessions_for_host(&self.host_id);
        delete_host_enrollment(&self.host_id);
        delete_org_rows(&self.org_id);
        delete_registry_resource(&self.resource);
        delete_client_metadata(&self.client_id);
        delete_invites_for_email(email);
        delete_invites_for_email(&self.other_email);
        delete_posix_group_members(self.gid);
        delete_posix_group(self.gid);
    }
}

/// Everything a deletion must have done regardless of entry point: the
/// id-matched rows and columns, the other person's invite kept with its
/// provenance nulled, and the critical audit row.
fn assert_common_outcome(fx: &Fixture, user: &RegisteredUser, action: &str, actor_kind: &str) {
    let left = rows_referencing(&user.identity_id, "");
    assert!(left.is_empty(), "rows left after {action}: {left:?}");
    assert_eq!(
        count_invites_with_token(&fx.invite_other),
        1,
        "the invite to another address survives"
    );
    assert_eq!(
        reference_column_value(
            "organization_invites",
            "invited_by",
            "token",
            &fx.invite_other
        ),
        None,
        "invited_by nulled on the surviving invite"
    );
    assert_eq!(
        reference_column_value(
            "organization_invites",
            "accepted_by",
            "token",
            &fx.invite_other
        ),
        None,
        "accepted_by nulled on the surviving invite"
    );
    let row = latest_audit_event(action, &user.identity_id)
        .unwrap_or_else(|| panic!("audit row {action} for {}", user.identity_id));
    assert_eq!(row.severity, "critical");
    assert_eq!(row.actor_kind, actor_kind);
    assert!(
        row.metadata["event_id"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "metadata.event_id: {}",
        row.metadata
    );
    assert_eq!(
        row.metadata["orphan_count"], 0,
        "metadata: {}",
        row.metadata
    );
    assert_eq!(
        row.metadata["webhook_targets"], 0,
        "metadata: {}",
        row.metadata
    );
}

/// Drive the self-service confirm page and POST; returns the final URL and body.
async fn self_delete(user: &RegisteredUser) -> (String, String) {
    let res = user
        .client
        .get(format!("{PORTAL}/settings/account/delete"))
        .send()
        .await
        .expect("GET /settings/account/delete");
    assert!(res.status().is_success(), "confirm page: {}", res.status());
    let post_url = res.url().clone();
    let body = res.text().await.expect("confirm body");
    assert!(
        body.contains("What we keep"),
        "confirm page should carry the retention card"
    );
    let csrf = extract_form_csrf(&body).expect("_csrf on confirm page");
    let res = user
        .client
        .post(post_url)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("confirm_email", user.email.as_str()),
        ])
        .send()
        .await
        .expect("POST /settings/account/delete");
    let url = res.url().to_string();
    (url, res.text().await.unwrap_or_default())
}

async fn warm_up(user: &RegisteredUser) {
    let _ = user
        .client
        .get(format!("{PORTAL}/"))
        .send()
        .await
        .expect("warm-up");
}

/// A verified address: the invite to it goes and the email-matched
/// provenance columns are nulled.
#[tokio::test]
async fn account_delete_leaves_no_referencing_rows() {
    assert!(portal_reachable().await);
    let user = register_test_user("acct-delete-refs").await;
    warm_up(&user).await;
    mark_identity_verified(&user.identity_id).await;
    let fx = seed_fixture(&user);
    assert!(
        rows_referencing(&user.identity_id, &user.email).len() >= 20,
        "precondition: every seeded table and column should reference the user"
    );

    let (final_url, _) = self_delete(&user).await;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(final_url.contains("/login"), "landed on {final_url}");
        assert_common_outcome(&fx, &user, "account.self_deleted", "user");
        let left = rows_referencing(&user.identity_id, &user.email);
        assert!(left.is_empty(), "email-matched rows left: {left:?}");
        assert_eq!(count_invites_with_token(&fx.invite_own), 0);
        let row = latest_audit_event("account.self_deleted", &user.identity_id).expect("audit");
        assert_eq!(row.metadata["reason"], "self_service");
    }));
    fx.cleanup(&user.email);
    if let Err(e) = outcome {
        std::panic::resume_unwind(e);
    }
    assert!(identity_id_by_email(&user.email).await.is_none());
}

/// An unverified address: the invite to it and the email-matched provenance
/// survive, because the address may belong to someone else.
#[tokio::test]
async fn admin_delete_leaves_no_referencing_rows() {
    assert!(portal_reachable().await);
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("Skipping admin_delete_leaves_no_referencing_rows: admin env not set");
        return;
    };
    let target = register_test_user_unverified("admin-delete-refs").await;
    warm_up(&target).await;
    let fx = seed_fixture(&target);
    let id = target.identity_id.clone();

    let res = admin
        .get(format!("{PORTAL}/admin/identities/{id}/delete"))
        .send()
        .await
        .expect("GET admin delete-confirm");
    assert_eq!(res.status().as_u16(), 200, "delete-confirm status");
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("Apps holding a copy of the data are told to delete it."),
        "admin confirm text should list what deletion does"
    );
    let csrf = extract_form_csrf(&body).expect("_csrf in admin delete confirm");
    let res = admin
        .post(format!("{PORTAL}/admin/identities/{id}/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "yes")])
        .send()
        .await
        .expect("POST admin delete");
    let status = res.status();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(
            status.is_success() || status.as_u16() == 303,
            "admin delete status: {status}"
        );
        assert_common_outcome(&fx, &target, "admin.identity.deleted", "admin");
        let row = latest_audit_event("admin.identity.deleted", &id).expect("audit");
        assert_eq!(row.metadata["reason"], "admin");
        assert_eq!(
            count_invites_with_token(&fx.invite_own),
            1,
            "an invite to the unverified trait email survives"
        );
        assert_eq!(
            reference_column_value("host_enrollments", "created_by", "id", &fx.host_id).as_deref(),
            Some(target.email.as_str()),
            "email-matched provenance survives for an unverified address"
        );
    }));
    fx.cleanup(&target.email);
    if let Err(e) = outcome {
        std::panic::resume_unwind(e);
    }
    assert!(identity_id_by_email(&target.email).await.is_none());
}

/// Reclaiming an unverified address deletes the identity's own rows but keeps
/// the invites addressed to the email and the email-matched provenance: the
/// person registering next needs them.
#[tokio::test]
async fn reclaim_delete_leaves_no_referencing_rows_and_keeps_invites() {
    assert!(portal_reachable().await);
    let user = register_test_user_unverified("reclaim-refs").await;
    warm_up(&user).await;
    let fx = seed_fixture(&user);
    let id = user.identity_id.clone();
    let email = user.email.clone();

    let claimer = manual_redirect_client();
    for _ in 0..2 {
        claimer
            .get(format!("{PORTAL}/claim-email"))
            .send()
            .await
            .expect("GET /claim-email");
    }
    let body = claimer
        .get(format!("{PORTAL}/claim-email"))
        .send()
        .await
        .expect("GET /claim-email")
        .text()
        .await
        .expect("claim form");
    let csrf = extract_form_csrf(&body).expect("_csrf in claim form");
    let res = claimer
        .post(format!("{PORTAL}/claim-email"))
        .form(&[("_csrf", csrf.as_str()), ("email", email.as_str())])
        .send()
        .await
        .expect("POST /claim-email");
    assert_eq!(res.status().as_u16(), 303, "claim mint");
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("Location on claim 303")
        .to_string();
    let mail = wait_for_mailcrab(
        &email,
        "Confirm your email",
        std::time::Duration::from_secs(15),
    )
    .await
    .expect("claim code email");
    let code = extract_code_from_email(&mail.body).expect("six-digit code");
    let body = claimer
        .get(format!("{PORTAL}{loc}"))
        .send()
        .await
        .expect("GET confirm")
        .text()
        .await
        .expect("confirm body");
    let csrf = extract_form_csrf(&body).expect("_csrf in confirm form");
    let token = extract_input_value(&body, "token").expect("token input");
    let res = claimer
        .post(format!("{PORTAL}/claim-email/confirm"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("token", token.as_str()),
            ("code", code.as_str()),
        ])
        .send()
        .await
        .expect("POST confirm");
    let status = res.status();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(status.as_u16(), 303, "claim confirm should 303");
        assert_common_outcome(&fx, &user, "identity.reclaimed", "user");
        let row = latest_audit_event("identity.reclaimed", &id).expect("audit");
        assert_eq!(row.metadata["reason"], "reclaim");
        assert_eq!(row.metadata["reclaim_email"], email.as_str());
        assert_eq!(
            count_invites_with_token(&fx.invite_own),
            1,
            "the invite to the reclaimed address survives"
        );
        assert_eq!(
            reference_column_value("host_enrollments", "created_by", "id", &fx.host_id).as_deref(),
            Some(email.as_str()),
            "email-matched provenance survives on reclaim"
        );
    }));
    fx.cleanup(&email);
    if let Err(e) = outcome {
        std::panic::resume_unwind(e);
    }
    assert!(identity_id_by_email(&email).await.is_none());
}

/// The only owner of an org with other members is refused before anything
/// is touched.
#[tokio::test]
async fn account_delete_refused_for_sole_owner_with_other_members() {
    assert!(portal_reachable().await);
    let user = register_test_user("acct-delete-sole-owner").await;
    warm_up(&user).await;
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let org_id = format!("org-sole-{}", seed % 10_000_000_000);
    seed_organization(&org_id, &org_id, "Sole Owner Org", "all");
    seed_org_membership(&org_id, &user.identity_id, "owner");
    seed_org_membership(&org_id, &format!("other-{seed}"), "member");

    let (final_url, body) = self_delete(&user).await;
    delete_org_rows(&org_id);
    assert!(
        !final_url.contains("/login"),
        "refusal must not sign the user out; got {final_url}"
    );
    assert!(
        body.contains("only owner of") && body.contains("Sole Owner Org"),
        "refusal names the org"
    );
    assert!(
        identity_id_by_email(&user.email).await.is_some(),
        "identity must still exist"
    );
    assert_eq!(
        count_audit_events_for_target("account.self_deleted", &user.identity_id),
        0,
        "no audit row for a refused deletion"
    );
    user.cleanup().await;
}
