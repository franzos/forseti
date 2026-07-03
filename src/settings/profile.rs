//! `/settings/profile` — edit display fields on the identity's traits
//! (via Kratos) and the Forseti-owned extended profile (bio, website,
//! pronouns, links) when `[profiles].enabled = true`.

use crate::csrf::CsrfForm;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
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
    pub(crate) profiles_enabled: bool,
    pub(crate) bio: String,
    pub(crate) location: String,
    pub(crate) pronouns: String,
    pub(crate) website: String,
    pub(crate) avatar_url: String,
    /// One `label|url` per line, edited as a single textarea.
    pub(crate) links_text: String,
    pub(crate) extended_saved: bool,
    /// `false` when the identity has any unverified `verifiable_address`;
    /// drives the "Not verified" hint.
    pub(crate) email_verified: bool,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

// Axum handler: each argument is an extractor; signature is dictated by the framework.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn settings_profile(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    Query(saved): Query<ProfileSavedQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: crate::extractors::Csrf,
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
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
        locale,
    )
    .await
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExtendedProfileForm {
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
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<ExtendedProfileForm>,
) -> Response {
    if !state.cfg.profiles.enabled {
        return (StatusCode::NOT_FOUND, "profiles disabled").into_response();
    }

    // URLs are emitted as OIDC `website`/`picture` claims, so validate full
    // http(s)-with-host rather than a prefix. Empty clears the field (NULL).
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
            crate::i18n::lookup(&locale, "settings-profile-url-invalid"),
        )
            .into_response();
    }

    let links = parse_links(&form.links);
    for link in &links {
        if !url_ok(&link.url) {
            return (
                StatusCode::BAD_REQUEST,
                crate::i18n::lookup(&locale, "settings-profile-link-url-invalid"),
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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::i18n::lookup(&locale, "settings-save-failed"),
        )
            .into_response();
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

/// Parse one `label|url` per line; empty and malformed lines are dropped.
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

#[derive(Debug, Deserialize)]
pub(crate) struct LangForm {
    #[serde(default)]
    pub(crate) lang: String,
}

pub(crate) async fn settings_language_save(
    State(state): State<AppState>,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<LangForm>,
) -> Response {
    let Some(tag) = crate::locale::from_query_or_cookie(&form.lang) else {
        return Redirect::to("/settings/profile").into_response();
    };
    let lang = tag.language.as_str().to_string();
    if let Err(e) =
        crate::ory::kratos::admin_set_identity_language(&state.ory, &sess.identity_id, &lang).await
    {
        tracing::error!(error = ?e, "settings_language_save: failed to persist language preference");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::i18n::lookup(&locale, "settings-save-failed"),
        )
            .into_response();
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
            .metadata(audit_metadata!("lang" => lang.as_str())),
    )
    .await;
    let secure = state.cfg.self_.is_https();
    let cookie = crate::locale::build_locale_cookie(&lang, secure);
    let mut resp = Redirect::to("/settings/profile").into_response();
    crate::web::append_set_cookie(&mut resp, Some(cookie));
    resp
}

/// Serialise stored links back into the textarea-friendly format.
pub(crate) fn links_to_text(links: &[ProfileLink]) -> String {
    links
        .iter()
        .map(|l| format!("{}|{}", l.label, l.url))
        .collect::<Vec<_>>()
        .join("\n")
}
