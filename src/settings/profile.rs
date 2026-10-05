//! `/settings/profile` — edit display fields on the identity's traits
//! (via Kratos), the handle emitted as `preferred_username`, and the
//! Forseti-owned extended profile (bio, website, pronouns, links) when
//! `[profiles].enabled = true`.

use crate::csrf::CsrfForm;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::FlowQuery;
use crate::audit::{self, AuditCtx, AuditEvent, action};
use crate::audit_metadata;
use crate::flow_view::{GroupedNodes, MessageView};
use crate::page_chrome::PageChrome;
use crate::profiles::{self, ProfileLink};
use crate::state::AppState;

use super::{InlineRenderSection, ProfileSavedQuery, settings_subpage};

#[derive(Template)]
#[template(path = "settings_profile.html")]
pub(crate) struct SettingsProfileTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    pub(crate) groups: GroupedNodes,
    pub(crate) profiles_enabled: bool,
    pub(crate) username: String,
    pub(crate) bio: String,
    pub(crate) location: String,
    pub(crate) pronouns: String,
    pub(crate) website: String,
    pub(crate) avatar_url: String,
    /// One `label|url` per line, edited as a single textarea.
    pub(crate) links_text: String,
    pub(crate) extended_saved: bool,
    pub(crate) username_saved: bool,
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
        saved.username_saved.unwrap_or(false),
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

    // URLs are emitted as OIDC `website`/`picture` claims and rendered as
    // `href`/`<img src>`, so they get the same gate as client-supplied URLs.
    // Empty clears the field (NULL).
    let url_ok = |s: &str| {
        let t = s.trim();
        t.is_empty() || crate::web::safe_external_uri(t, false).is_some()
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

    let input = profiles::ProfileInput {
        identity_id: &sess.identity_id,
        bio: form.bio.trim(),
        location: form.location.trim(),
        pronouns: form.pronouns.trim(),
        website: form.website.trim(),
        avatar_url: form.avatar_url.trim(),
        links: &links,
    };
    if !input.within_limits() {
        return (
            StatusCode::BAD_REQUEST,
            crate::i18n::lookup(&locale, "settings-profile-too-long"),
        )
            .into_response();
    }
    if let Err(err) = profiles::upsert(&state.db, input).await {
        tracing::error!(error = ?err, "settings_profile_extended_save: upsert failed");
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

#[derive(Debug, Deserialize)]
pub(crate) struct UsernameForm {
    #[serde(default)]
    pub(crate) username: String,
}

/// Why a username save was refused; each maps to the message shown.
pub(crate) enum UsernameSaveError {
    Invalid,
    Reserved,
    Taken,
    Cooldown,
    Failed,
}

impl UsernameSaveError {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Invalid | Self::Reserved => StatusCode::BAD_REQUEST,
            Self::Taken | Self::Cooldown => StatusCode::CONFLICT,
            Self::Failed => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub(crate) fn message_key(&self) -> &'static str {
        match self {
            Self::Invalid => "settings-profile-username-invalid",
            Self::Reserved => "settings-profile-username-reserved",
            Self::Taken => "settings-profile-username-taken",
            Self::Cooldown => "settings-profile-username-cooldown",
            Self::Failed => "settings-save-failed",
        }
    }
}

/// Validate, store and audit a handle. An empty `raw` clears it. Shared by the
/// profile page and the post-signup onboarding step.
pub(crate) async fn save_username(
    state: &AppState,
    identity_id: &str,
    email: &str,
    actx: &AuditCtx,
    raw: &str,
) -> Result<(), UsernameSaveError> {
    // Anything non-empty must survive validation before it can reach an RP as
    // `preferred_username`.
    let username = if raw.trim().is_empty() {
        String::new()
    } else {
        profiles::username::validate(raw).map_err(|e| match e {
            profiles::username::UsernameError::Reserved => UsernameSaveError::Reserved,
            _ => UsernameSaveError::Invalid,
        })?
    };

    let previous = profiles::fetch(&state.db, identity_id)
        .await
        .ok()
        .and_then(|p| p.username);

    if let Err(e) = profiles::set_username(&state.db, identity_id, &username).await {
        return Err(match e {
            profiles::SaveError::UsernameTaken => UsernameSaveError::Taken,
            profiles::SaveError::UsernameCooldown => UsernameSaveError::Cooldown,
            profiles::SaveError::Other(err) => {
                tracing::error!(error = ?err, "save_username: save failed");
                UsernameSaveError::Failed
            }
        });
    }

    // An RP may have provisioned a local account from the old handle, so
    // operators need the before/after.
    let new_username = (!username.is_empty()).then_some(username.as_str());
    if previous.as_deref() != new_username {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::PROFILE_USERNAME_CHANGED)
                .actor_user(identity_id, email)
                .target(crate::audit::target_kind::IDENTITY, identity_id.to_string())
                .with_ctx(actx)
                .metadata(audit_metadata!(
                    "from" => previous.as_deref().unwrap_or(""),
                    "to" => new_username.unwrap_or(""),
                )),
        )
        .await;
    }
    Ok(())
}

/// Save the handle. Not gated by `[profiles].enabled`: `preferred_username`
/// is a standard `profile` claim and RPs provision local accounts from it.
pub(crate) async fn settings_profile_username_save(
    State(state): State<AppState>,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<UsernameForm>,
) -> Response {
    match save_username(
        &state,
        &sess.identity_id,
        &sess.email,
        &actx,
        &form.username,
    )
    .await
    {
        Ok(()) => Redirect::to("/settings/profile?username_saved=1").into_response(),
        Err(e) => (e.status(), crate::i18n::lookup(&locale, e.message_key())).into_response(),
    }
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
