//! `GET /users/{identity_id}` — public-within-shared-org profile view.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::HashSet;

use crate::commercial::license::Feature;
use crate::commercial::FeatureStatus;
use crate::extractors::{Csrf, RequireSession};
use crate::orgs::Role;
use crate::page_chrome::PageChrome;
use crate::profiles::{self, ProfileLink};
use crate::render::render;
use crate::state::AppState;

#[derive(serde::Serialize)]
struct TeamChip {
    name: String,
    org_name: String,
}

#[derive(serde::Serialize)]
struct HostView {
    hostname: String,
    org_name: String,
}

#[derive(Template)]
#[template(path = "profiles/view.html")]
struct ProfileViewTemplate {
    chrome: PageChrome,
    /// SVG identicon, inlined via `|safe`. Used when `avatar_url` is empty.
    identicon: String,
    /// From Kratos traits; empty falls back to the email in the template.
    display_name: String,
    email: String,
    bio: String,
    location: String,
    pronouns: String,
    website: String,
    avatar_url: String,
    links: Vec<ProfileLink>,
    /// Orgs the viewer and target share; shown as chips so the viewer
    /// understands why the page is visible.
    shared_org_names: Vec<String>,
    updated_humanised: String,
    nav: crate::orgs::nav::OrgNav,
    /// Team memberships, audience-scoped to this viewer.
    teams: Vec<TeamChip>,
    /// Reachable Linux hosts (self/admin only).
    hosts: Vec<HostView>,
    show_teams: bool,
    show_hosts: bool,
}

pub(crate) async fn show_profile(
    State(state): State<AppState>,
    Path(identity_id): Path<String>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    if !state.cfg.profiles.enabled {
        return (StatusCode::NOT_FOUND, "profiles disabled").into_response();
    }

    // 404 (not 403, and decided before the Kratos lookup) when the viewer can't
    // see the target in any shared org, so a hidden target is indistinguishable
    // from a nonexistent one (no status/timing oracle).
    let viewer_memberships = crate::orgs::list_memberships(&state.db, &sess.identity_id)
        .await
        .unwrap_or_default();
    let viewer_orgs: HashSet<&str> = viewer_memberships
        .iter()
        .map(|m| m.org_id.as_str())
        .collect();
    let target_memberships = crate::orgs::list_memberships(&state.db, &identity_id)
        .await
        .unwrap_or_default();
    let shared: Vec<&crate::orgs::Membership> = target_memberships
        .iter()
        .filter(|m| viewer_orgs.contains(m.org_id.as_str()))
        .collect();

    let admin_aal2 = state.cfg.admin.is_admin(&sess.email)
        && crate::ory::kratos::session_satisfies_aal2(&sess.session);

    // Chips derive from the visible-to-viewer subset, never the raw
    // intersection, so a restrictive org membership doesn't leak.
    let mut visible_orgs: Vec<&crate::orgs::Membership> = Vec::new();
    for m in &shared {
        if crate::orgs::visibility::member_visible_to_in_org(
            &state.db,
            &m.org_id,
            &sess.identity_id,
            &identity_id,
            admin_aal2,
        )
        .await
        {
            visible_orgs.push(m);
        }
    }

    let is_self = sess.identity_id == identity_id;
    let gate = is_self || admin_aal2 || !visible_orgs.is_empty();
    if !gate {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let mut shared_org_names: Vec<String> = visible_orgs.iter().map(|m| m.name.clone()).collect();
    shared_org_names.sort();
    shared_org_names.dedup();

    // Org-name lookup sourced from the target's memberships.
    let org_name = |org_id: &str| -> String {
        target_memberships
            .iter()
            .find(|m| m.org_id == org_id)
            .map(|m| m.name.clone())
            .unwrap_or_default()
    };

    // Commercial surfaces only when licensed or in grace.
    let orgs_licensed = matches!(
        state.license.feature(Feature::Orgs),
        FeatureStatus::Allowed | FeatureStatus::GraceReadOnly
    );
    let linux_licensed = matches!(
        state.license.feature(Feature::LinuxAuth),
        FeatureStatus::Allowed | FeatureStatus::GraceReadOnly
    );

    // Owners see teams only, scoped to the shared+visible orgs they own.
    let mut owned_org_ids: HashSet<String> = HashSet::new();
    if !is_self && !admin_aal2 {
        for m in &visible_orgs {
            if crate::orgs::org_role(&state.db, &sess.identity_id, &m.org_id).await
                == Some(Role::Owner)
            {
                owned_org_ids.insert(m.org_id.clone());
            }
        }
    }

    // Teams audience: self/admin see all orgs, owners only their owned orgs.
    let teams: Vec<TeamChip> =
        if orgs_licensed && (is_self || admin_aal2 || !owned_org_ids.is_empty()) {
            let rows = crate::orgs::teams::teams_for_identity_any_org(&state.db, &identity_id)
                .await
                .unwrap_or_default();
            rows.into_iter()
                .filter(|t| is_self || admin_aal2 || owned_org_ids.contains(&t.org_id))
                .map(|t| TeamChip {
                    org_name: org_name(&t.org_id),
                    name: t.name,
                })
                .collect()
        } else {
            Vec::new()
        };
    let show_teams = orgs_licensed && (is_self || admin_aal2 || !owned_org_ids.is_empty());

    // Hosts audience: self or admin only, never owners.
    let hosts: Vec<HostView> = if linux_licensed && (is_self || admin_aal2) {
        crate::posix::db::hosts_reachable_by(&state.db, &identity_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|h| HostView {
                org_name: org_name(&h.org_id),
                hostname: h.hostname,
            })
            .collect()
    } else {
        Vec::new()
    };
    let show_hosts = linux_licensed && (is_self || admin_aal2);

    let target = match crate::ory::kratos::admin_get_identity(&state.ory, &identity_id).await {
        Ok(id) => id,
        Err(_) => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let traits = target.traits.unwrap_or(serde_json::Value::Null);
    let first = traits
        .pointer("/name/first")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let last = traits
        .pointer("/name/last")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let display_name = match (first.is_empty(), last.is_empty()) {
        (true, true) => String::new(),
        (false, true) => first.to_string(),
        (true, false) => last.to_string(),
        (false, false) => format!("{first} {last}"),
    };
    let email = traits
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let profile = profiles::fetch(&state.db, &identity_id)
        .await
        .unwrap_or_default();
    let identicon = profiles::identicon::render(&identity_id);
    let updated_humanised = crate::format::humanise_timestamp(&locale, &profile.updated_at);
    let token = csrf.0;
    let chrome = PageChrome::from_parts_themed(
        &state,
        &viewer_memberships,
        &headers,
        sess.email,
        token,
        locale,
    );
    let nav = crate::orgs::nav::OrgNav::from(None, viewer_memberships);

    let mut resp = render(&ProfileViewTemplate {
        chrome,
        identicon,
        display_name,
        email,
        bio: profile.bio.unwrap_or_default(),
        location: profile.location.unwrap_or_default(),
        pronouns: profile.pronouns.unwrap_or_default(),
        website: profile.website.unwrap_or_default(),
        avatar_url: profile.avatar_url.unwrap_or_default(),
        links: profile.links,
        shared_org_names,
        updated_humanised,
        nav,
        teams,
        hosts,
        show_teams,
        show_hosts,
    });
    // Varies by viewer and per-org visibility; never cache.
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    resp
}
