//! `/settings/profile` — edit display fields on the identity's traits
//! (via Kratos) and the Forseti-owned extended profile (bio, website,
//! pronouns, links) when `[profiles].enabled = true`.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::audit::{self, action, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::flow_view::{GroupedNodes, MessageView};
use crate::page_chrome::PageChrome;
use crate::profiles::{self, ProfileLink};
use crate::state::AppState;
use crate::FlowQuery;

use super::{settings_subpage, InlineRenderSection, ProfileSavedQuery};

#[derive(Template)]
#[template(path = "settings_profile.html")]
pub(crate) struct SettingsProfileTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    pub(crate) groups: GroupedNodes,
    /// `[profiles].enabled` — gates the extended-fields form below.
    pub(crate) profiles_enabled: bool,
    /// Existing extended-profile values (or empty when no row yet).
    /// Each field is plain text; the template binds them as `value`
    /// attributes on the second form.
    pub(crate) bio: String,
    pub(crate) location: String,
    pub(crate) pronouns: String,
    pub(crate) website: String,
    pub(crate) avatar_url: String,
    /// Serialised as one `<textarea>` (one `label|url` per line). v1
    /// keeps the editing UI dead-simple; a reorder/drag UI would belong
    /// in v2.
    pub(crate) links_text: String,
    /// Set after a successful POST. Template renders a green note.
    pub(crate) extended_saved: bool,
    /// Mirrors the dashboard's "Email address" account-health row: `false`
    /// when the identity has at least one unverified `verifiable_address`.
    /// Drives the "Not verified" hint shown below the email field.
    pub(crate) email_verified: bool,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

pub(crate) async fn settings_profile(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    Query(saved): Query<ProfileSavedQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: crate::extractors::Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    settings_subpage(
        &state,
        &headers,
        &csrf.0,
        &query,
        InlineRenderSection::Profile,
        &sess,
        banner,
        saved.profile_saved.unwrap_or(false),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExtendedProfileForm {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: Option<String>,
    #[serde(default)]
    pub(crate) bio: String,
    #[serde(default)]
    pub(crate) location: String,
    #[serde(default)]
    pub(crate) pronouns: String,
    #[serde(default)]
    pub(crate) website: String,
    #[serde(default)]
    pub(crate) avatar_url: String,
    /// One `label|url` per line.
    #[serde(default)]
    pub(crate) links: String,
}

pub(crate) async fn settings_profile_extended_save(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    Form(form): Form<ExtendedProfileForm>,
) -> Response {
    if !state.cfg.profiles.enabled {
        return (StatusCode::NOT_FOUND, "profiles disabled").into_response();
    }
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    // URLs must parse as http(s) with a host when present — these get
    // emitted as OIDC `website`/`picture` claims to relying parties, so a
    // prefix check isn't enough. Empty strings collapse to NULL in
    // storage, so the user can clear a field by submitting it blank.
    let url_ok = |s: &str| {
        let t = s.trim();
        if t.is_empty() {
            return true;
        }
        match url::Url::parse(t) {
            Ok(u) => {
                matches!(u.scheme(), "http" | "https")
                    && u.host_str().is_some_and(|h| !h.is_empty())
            }
            Err(_) => false,
        }
    };
    if !url_ok(&form.website) || !url_ok(&form.avatar_url) {
        return (
            StatusCode::BAD_REQUEST,
            "website and avatar_url must be valid http:// or https:// URLs",
        )
            .into_response();
    }

    let links = parse_links(&form.links);
    for link in &links {
        if !url_ok(&link.url) {
            return (
                StatusCode::BAD_REQUEST,
                "every link URL must be a valid http:// or https:// URL",
            )
                .into_response();
        }
    }

    if let Err(e) = profiles::upsert(
        &state.db,
        profiles::ProfileInput {
            identity_id: &sess.identity_id,
            bio: form.bio.trim(),
            location: form.location.trim(),
            pronouns: form.pronouns.trim(),
            website: form.website.trim(),
            avatar_url: form.avatar_url.trim(),
            links: &links,
        },
    )
    .await
    {
        tracing::error!(error = ?e, "settings_profile_extended_save: upsert failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "save failed").into_response();
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::PROFILE_UPDATED)
            .actor_user(&sess.identity_id, &sess.email)
            .target(
                crate::audit::target_kind::IDENTITY,
                sess.identity_id.clone(),
            )
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "link_count" => links.len() as i64,
            )),
    )
    .await;

    Redirect::to("/settings/profile?profile_saved=1").into_response()
}

/// Parse the textarea-edited links: one `label|url` per line. Empty
/// lines + malformed lines silently dropped so the form stays
/// forgiving.
fn parse_links(raw: &str) -> Vec<ProfileLink> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (label, url) = trimmed.split_once('|')?;
            let label = label.trim();
            let url = url.trim();
            if label.is_empty() || url.is_empty() {
                None
            } else {
                Some(ProfileLink {
                    label: label.to_string(),
                    url: url.to_string(),
                })
            }
        })
        .collect()
}

/// Serialise stored links back into the textarea-friendly format.
pub(crate) fn links_to_text(links: &[ProfileLink]) -> String {
    links
        .iter()
        .map(|l| format!("{}|{}", l.label, l.url))
        .collect::<Vec<_>>()
        .join("\n")
}
