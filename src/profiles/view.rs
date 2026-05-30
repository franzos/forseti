//! `GET /users/{identity_id}` — public-within-shared-org profile view.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::collections::HashSet;

use crate::extractors::{Csrf, RequireSession};
use crate::page_chrome::PageChrome;
use crate::profiles::{self, ProfileLink};
use crate::render::render;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "profiles/view.html")]
struct ProfileViewTemplate {
    chrome: PageChrome,
    /// SVG identicon, inlined via `|safe`. Used when `avatar_url` is empty.
    identicon: String,
    /// Resolved display name from Kratos traits (`name.first name.last`).
    /// Empty when the identity has no name set — template falls back to
    /// the email instead.
    display_name: String,
    /// Resolved email; surfaced on the page so the visitor can copy it.
    email: String,
    bio: String,
    location: String,
    pronouns: String,
    website: String,
    avatar_url: String,
    links: Vec<ProfileLink>,
    /// Org slugs the viewer + target share — shown as small chips so the
    /// viewer understands why this page is visible to them.
    shared_org_names: Vec<String>,
    /// Humanised "updated 3 days ago" — surfaces stale data so readers
    /// can calibrate.
    updated_humanised: String,
    /// Pre-built nav switcher view-model.
    nav: crate::orgs::nav::OrgNav,
}

pub(crate) async fn show_profile(
    State(state): State<AppState>,
    Path(identity_id): Path<String>,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    if !state.cfg.profiles.enabled {
        return (StatusCode::NOT_FOUND, "profiles disabled").into_response();
    }

    // Shared-org visibility gate. Anonymous viewers were already
    // bounced to /login by `RequireSession`. A signed-in viewer who
    // shares no orgs with the target sees a 404 (not 403 — same shape
    // as "user doesn't exist", no leakage of profile existence).
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
    let mut shared_org_names: Vec<String> = target_memberships
        .iter()
        .filter(|m| viewer_orgs.contains(m.org_id.as_str()))
        .map(|m| m.name.clone())
        .collect();
    shared_org_names.sort();
    shared_org_names.dedup();
    if shared_org_names.is_empty() {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Resolve Kratos identity for the display name + email.
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
    let updated_humanised = crate::format::humanise_timestamp(&profile.updated_at);
    let token = csrf.0;
    let nav = crate::orgs::nav::OrgNav::from(None, viewer_memberships);

    render(&ProfileViewTemplate {
        chrome: PageChrome::from_parts(&state, sess.email, token),
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
    })
}
