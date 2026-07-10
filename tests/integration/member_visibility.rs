//! Member-directory visibility: the `member_visibility` policy, the per-member
//! `hidden_from_directory` opt-out, the `visible(...)` predicate, and the two
//! surfaces it gates (`/settings/.../members` and `/users/{id}`).
//!
//! HARNESS CONSTRAINT — the integration suite runs UNLICENSED and has no
//! license-activation path (the licensed e2e bucket does that over HTTP; see
//! `posix.rs::org_member_removal_revokes_scoped_host_access`). The members
//! page for a NON-default org is license-gated (`require_org_license` →
//! upsell), so the members-list visibility filter is only HTTP-drivable on the
//! `default` org (seeded `admins_only`). The `/users/{id}` profile surface has
//! NO license gate, so the full predicate (all / same_group / admins_only /
//! owner-override / opt-out / chip filter) is driven there against seeded
//! NON-default orgs. The opt-out toggle routes (`members_hidden`) carry no
//! license gate either, so those are driven directly.
//!
//! Deferred cases (and why) are listed at the bottom of this file.

use crate::common::*;
use reqwest::StatusCode;

/// The `default` org id (registration auto-joins everyone here). The crate
/// const isn't reachable from the test crate, so it's spelled out.
const DEFAULT_ORG_ID: &str = "default";

/// Pull a `_csrf` hidden input value out of a rendered page. Local copy —
/// the equivalents in `posix.rs` / `bug_regressions.rs` are module-private.
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

/// The chip span renders the shared-org NAME as `>{name}</span>` (name
/// immediately after `>`). The nav switcher renders the same names as
/// `{{ m.name }} <span ...>` (name followed by a space + role span), so this
/// exact-substring match scopes the assertion to the chips and never matches
/// the nav dropdown.
fn chip_present(body: &str, org_name: &str) -> bool {
    // Scope to the profile's shared-orgs chip block (templates/profiles/view.html:
    // `<div class="flex flex-wrap gap-stack-sm mt-stack-md"> ... <bdi>NAME</bdi> ...`).
    // The page chrome's org-switcher also `<bdi>`-wraps the viewer's OWN org
    // names, but those aren't chips and aren't a visibility leak — matching the
    // whole body would mistake the nav for a chip.
    let Some((_, rest)) = body.split_once(r#"flex flex-wrap gap-stack-sm mt-stack-md""#) else {
        return false;
    };
    let block = rest.split("</div>").next().unwrap_or(rest);
    block.contains(&format!("<bdi>{org_name}</bdi>"))
}

fn uniq(tag: &str) -> String {
    format!("{tag}-{}", uuid::Uuid::new_v4())
}

/// `/users/{id}`: a viewer who can't see the target in ANY shared org gets a
/// 404. A and B share only the `default` org, which is `admins_only`, so B is
/// invisible to A there and nowhere else → 404.
#[tokio::test]
async fn users_404_when_only_shared_org_is_admins_only() {
    assert!(portal_reachable().await, "portal must be up");
    let viewer = register_test_user("vis-404-viewer").await;
    let target = register_test_user("vis-404-target").await;

    let res = viewer
        .client
        .get(format!("{PORTAL}/users/{}", target.identity_id))
        .send()
        .await
        .expect("GET /users/{target}");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "target invisible in the only shared org (default=admins_only) → 404"
    );

    viewer.cleanup().await;
    target.cleanup().await;
}

/// `/users/{id}` chip filter: the viewer shares two non-default orgs with the
/// target — one `all` (target visible), one `admins_only` (target NOT visible).
/// The page renders (200, visible via the `all` org) and its chip list MUST
/// include the `all` org but exclude the restrictive one the viewer is also a
/// member of.
#[tokio::test]
async fn users_chip_excludes_restrictive_shared_org() {
    assert!(portal_reachable().await, "portal must be up");
    let viewer = register_test_user("vis-chip-viewer").await;
    let target = register_test_user("vis-chip-target").await;

    let vis_id = uniq("visorg");
    let vis_slug = uniq("vis");
    let vis_name = uniq("VisibleOrg");
    let restrict_id = uniq("rstorg");
    let restrict_slug = uniq("rst");
    let restrict_name = uniq("RestrictedOrg");

    seed_organization(&vis_id, &vis_slug, &vis_name, "all");
    seed_organization(&restrict_id, &restrict_slug, &restrict_name, "admins_only");
    for org in [&vis_id, &restrict_id] {
        seed_org_membership(org, &viewer.identity_id, "member");
        seed_org_membership(org, &target.identity_id, "member");
    }

    let res = viewer
        .client
        .get(format!("{PORTAL}/users/{}", target.identity_id))
        .send()
        .await
        .expect("GET /users/{target}");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "target is visible via the `all` org → page renders"
    );
    let body = res.text().await.unwrap_or_default();
    assert!(
        chip_present(&body, &vis_name),
        "the `all` org chip must render"
    );
    assert!(
        !chip_present(&body, &restrict_name),
        "the `admins_only` org must NOT leak as a chip even though the viewer shares it"
    );

    delete_organization(&vis_id);
    delete_organization(&restrict_id);
    viewer.cleanup().await;
    target.cleanup().await;
}

/// `/users/{id}` under `same_group`: a co-team peer is visible; once the shared
/// team is gone the same viewer gets a 404.
#[tokio::test]
async fn users_same_group_visible_only_to_co_team() {
    assert!(portal_reachable().await, "portal must be up");
    let viewer = register_test_user("vis-sg-viewer").await;
    let target = register_test_user("vis-sg-target").await;

    let org_id = uniq("sgorg");
    let org_slug = uniq("sg");
    let org_name = uniq("SameGroupOrg");
    let team_id = uniq("sgteam");

    seed_organization(&org_id, &org_slug, &org_name, "same_group");
    seed_org_membership(&org_id, &viewer.identity_id, "member");
    seed_org_membership(&org_id, &target.identity_id, "member");
    seed_team(&team_id, &org_id, "eng", &uniq("eng"), None);
    add_team_member(&team_id, &viewer.identity_id);
    add_team_member(&team_id, &target.identity_id);

    // Phase 1: co-team → visible.
    let res = viewer
        .client
        .get(format!("{PORTAL}/users/{}", target.identity_id))
        .send()
        .await
        .expect("GET /users/{target} co-team");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "same_group: a co-team peer is visible"
    );
    let body = res.text().await.unwrap_or_default();
    assert!(
        chip_present(&body, &org_name),
        "the same_group org chip must render for a co-team peer"
    );

    // Phase 2: drop the shared team → no longer visible.
    remove_team_member(&team_id, &target.identity_id);
    let res = viewer
        .client
        .get(format!("{PORTAL}/users/{}", target.identity_id))
        .send()
        .await
        .expect("GET /users/{target} no shared team");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "same_group: no shared team → invisible → 404"
    );

    delete_team(&team_id);
    delete_organization(&org_id);
    viewer.cleanup().await;
    target.cleanup().await;
}

/// `/users/{id}` opt-out: a hidden member is invisible to a plain peer but
/// still visible to an owner of the same org.
#[tokio::test]
async fn users_opt_out_hidden_from_peer_visible_to_owner() {
    assert!(portal_reachable().await, "portal must be up");
    let viewer = register_test_user("vis-opt-viewer").await;
    let target = register_test_user("vis-opt-target").await;

    let org_id = uniq("optorg");
    let org_slug = uniq("opt");
    let org_name = uniq("OptOutOrg");

    seed_organization(&org_id, &org_slug, &org_name, "all");
    seed_org_membership(&org_id, &viewer.identity_id, "member");
    seed_org_membership(&org_id, &target.identity_id, "member");
    set_member_hidden(&org_id, &target.identity_id, true);

    // Plain peer: hidden target invisible (only shared visible org would be
    // `all`, but the opt-out trumps it; default is admins_only) → 404.
    let res = viewer
        .client
        .get(format!("{PORTAL}/users/{}", target.identity_id))
        .send()
        .await
        .expect("GET /users/{target} as peer");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "opt-out hides the target from a plain peer"
    );

    // Promote the viewer to owner of the org → owner override sees through the
    // opt-out.
    set_org_member_role(&org_id, &viewer.identity_id, "owner");
    let res = viewer
        .client
        .get(format!("{PORTAL}/users/{}", target.identity_id))
        .send()
        .await
        .expect("GET /users/{target} as owner");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "an owner sees a hidden member"
    );

    delete_organization(&org_id);
    viewer.cleanup().await;
    target.cleanup().await;
}

/// Members page on the `default` org (seeded `admins_only`, no license gate):
/// a plain member sees only themselves — a co-member is filtered out — and the
/// admins-only policy statement renders.
#[tokio::test]
async fn members_page_admins_only_hides_peers() {
    assert!(portal_reachable().await, "portal must be up");
    let viewer = register_test_user("vis-members-viewer").await;
    let peer = register_test_user("vis-members-peer").await;

    // Warm up default membership (also settles the CSRF double-cookie race).
    let _ = viewer.client.get(format!("{PORTAL}/")).send().await;

    let res = viewer
        .client
        .get(format!("{PORTAL}/settings/organization/members"))
        .send()
        .await
        .expect("GET default members");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "members page renders for a member"
    );
    let body = res.text().await.unwrap_or_default();

    assert!(
        body.contains("Only administrators can see the full member list."),
        "the admins_only policy statement must render for a non-owner"
    );
    assert!(
        !body.contains(&peer.email),
        "a co-member must be filtered out of an admins_only directory for a non-owner"
    );

    viewer.cleanup().await;
    peer.cleanup().await;
}

/// The self opt-out toggle on the default org: POST → 303, flag flips; POST
/// again → flag clears. No owner role or license required (self-toggle).
#[tokio::test]
async fn member_self_opt_out_toggle_flips_flag() {
    assert!(portal_reachable().await, "portal must be up");
    let user = register_test_user("vis-selftoggle").await;
    let _ = user.client.get(format!("{PORTAL}/")).send().await;

    // CSRF token off the members page (double-submit cookie token, shared
    // across pages).
    let body = user
        .client
        .get(format!("{PORTAL}/settings/organization/members"))
        .send()
        .await
        .expect("GET members for csrf")
        .text()
        .await
        .unwrap_or_default();
    let csrf = extract_form_csrf(&body).expect("_csrf in members page");

    let url = format!(
        "{PORTAL}/settings/organization/members/{}/hidden",
        user.identity_id
    );
    let res = user
        .manual_client
        .post(&url)
        .form(&[("_csrf", csrf.as_str()), ("hidden", "true")])
        .send()
        .await
        .expect("POST hidden=true");
    assert!(
        res.status().is_redirection(),
        "self opt-out POST should 303, got {}",
        res.status()
    );
    assert_eq!(
        member_hidden_flag(DEFAULT_ORG_ID, &user.identity_id),
        Some(1),
        "hidden flag must be set after opt-out"
    );

    let res = user
        .manual_client
        .post(&url)
        .form(&[("_csrf", csrf.as_str()), ("hidden", "false")])
        .send()
        .await
        .expect("POST hidden=false");
    assert!(res.status().is_redirection(), "opt back in should 303");
    assert_eq!(
        member_hidden_flag(DEFAULT_ORG_ID, &user.identity_id),
        Some(0),
        "hidden flag must clear after opting back in"
    );

    user.cleanup().await;
}

/// Owner opt-out toggle on a NON-default org (the `members_hidden` route has no
/// license gate). The owner flips a co-member's flag; a plain member may not
/// toggle anyone else's.
#[tokio::test]
async fn owner_toggles_peer_opt_out_but_member_cannot() {
    assert!(portal_reachable().await, "portal must be up");
    let owner = register_test_user("vis-ownertoggle-owner").await;
    let member = register_test_user("vis-ownertoggle-member").await;
    let _ = owner.client.get(format!("{PORTAL}/")).send().await;
    let _ = member.client.get(format!("{PORTAL}/")).send().await;

    let org_id = uniq("toggleorg");
    let org_slug = uniq("tg");
    seed_organization(&org_id, &org_slug, &uniq("ToggleOrg"), "all");
    seed_org_membership(&org_id, &owner.identity_id, "owner");
    seed_org_membership(&org_id, &member.identity_id, "member");

    let hidden_url = format!(
        "{PORTAL}/settings/organizations/{}/members/{}/hidden",
        org_slug, member.identity_id
    );

    // Owner flips the member's flag → 303, flag set.
    let owner_csrf = {
        let b = owner
            .client
            .get(format!("{PORTAL}/"))
            .send()
            .await
            .expect("GET / owner")
            .text()
            .await
            .unwrap_or_default();
        extract_form_csrf(&b).expect("_csrf for owner")
    };
    let res = owner
        .manual_client
        .post(&hidden_url)
        .form(&[("_csrf", owner_csrf.as_str()), ("hidden", "true")])
        .send()
        .await
        .expect("owner POST hidden=true");
    assert!(
        res.status().is_redirection(),
        "owner toggle should 303, got {}",
        res.status()
    );
    assert_eq!(
        member_hidden_flag(&org_id, &member.identity_id),
        Some(1),
        "owner toggled the member's hidden flag"
    );

    // Plain member tries to toggle the OWNER's flag → 403.
    let member_csrf = {
        let b = member
            .client
            .get(format!("{PORTAL}/"))
            .send()
            .await
            .expect("GET / member")
            .text()
            .await
            .unwrap_or_default();
        extract_form_csrf(&b).expect("_csrf for member")
    };
    let forbid_url = format!(
        "{PORTAL}/settings/organizations/{}/members/{}/hidden",
        org_slug, owner.identity_id
    );
    let res = member
        .manual_client
        .post(&forbid_url)
        .form(&[("_csrf", member_csrf.as_str()), ("hidden", "true")])
        .send()
        .await
        .expect("member POST against owner row");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a plain member may not toggle another member's opt-out"
    );

    delete_organization(&org_id);
    owner.cleanup().await;
    member.cleanup().await;
}

// ----------------------------------------------------------------------------
// Deferred (NOT drivable in the unlicensed integration harness):
//
// * members-list 404 for a signed-in non-member of a NAMED org — the
//   `require_org_license` gate fires (upsell) BEFORE the role/404 check, so the
//   404 is unreachable unlicensed; and the `default` org auto-joins everyone so
//   there is no non-member there. The membership gate itself is covered by
//   `cargo check`; the equivalent "not visible → 404" invariant is exercised on
//   `/users/{id}` above.
//
// * members-LIST visibility filter on NON-default orgs (same_group co-team list,
//   admins_only on a named org, owner-sees-hidden in the list) — license-gated
//   members page. The `visible(...)` predicate is covered by the `/users/{id}`
//   tests above + the `default`-org admins_only members-page test + the unit
//   tests in `src/orgs/visibility.rs`.
//
// * same_group-needs-a-team guardrail (400) — lives in `members_visibility`,
//   which is gated by `require_org_owner_with_license`: on a NON-default org the
//   license gate fires first (upsell), and the only license-free org (`default`)
//   is shared singleton state we must not mutate. Deferred to the licensed e2e
//   bucket.
//
// * teams-management handlers (`/settings/.../teams`, `src/orgs/settings_page/
//   teams.rs`) — every handler runs `require_team_admin` = owner +
//   `gate_orgs_feature_or_upsell`, and teams are commercial EVERYWHERE (the gate
//   does NOT short-circuit for `default`, unlike the members page). So the whole
//   surface returns the upsell unlicensed and is undrivable here. Deferred to the
//   licensed e2e bucket: team create / rename / delete, membership add + remove
//   (incl. the "add a non-org-member → 400" guard), the owner+`Feature::Orgs`
//   gate (non-owner → 403, member-without-license → upsell), and the host
//   enroll/edit org-selection + team-scope-follows-host-org behaviour
//   (`src/admin/hosts.rs`). The pure helpers (`teams::list_teams_with_counts`,
//   `teams::team_member_ids`, `teams::co_team_member_ids`, and the `visible(...)`
//   predicate) are unit-tested in-module under `src/orgs/`.
// ----------------------------------------------------------------------------
