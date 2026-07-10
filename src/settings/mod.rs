//! User-facing `/settings/*` surface: profile, password (incl. recovery
//! hand-off), 2FA, sessions, linked providers, plus the hub redirector Kratos
//! sends every settings flow through. The shared gate / fetch /
//! privileged-refresh dance lives here in `fetch_settings_subpage`.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;

use askama::Template;
use serde::Deserialize;

use crate::cookies;
use crate::flow_view::{
    flow_messages, flow_state, form_target, group_nodes, mark_settings_primary, session_email,
    session_needs_verification, translate_inputs, translate_messages,
};
use crate::locale::LanguageIdentifier;
use crate::ory::kratos::FlowOutcome;
use crate::ory::{self, FlowFetch, FlowKind};
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, FlowQuery};

pub(crate) mod account;
pub(crate) mod authorized_apps;
pub(crate) mod linked_providers;
pub(crate) mod offline_access;
pub(crate) mod oidc_links_db;
pub(crate) mod password;
pub(crate) mod profile;
pub(crate) mod sessions;
pub(crate) mod two_factor;

use password::{SettingsPasswordHandoffTemplate, SettingsPasswordTemplate};
use profile::SettingsProfileTemplate;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/settings", get(settings_hub))
        .route("/settings/profile", get(profile::settings_profile))
        .route(
            "/settings/profile/extended",
            post(profile::settings_profile_extended_save),
        )
        .route("/settings/language", post(profile::settings_language_save))
        .route("/settings/password", get(password::settings_password))
        .route("/settings/2fa", get(two_factor::settings_2fa))
        .route("/settings/sessions", get(sessions::settings_sessions))
        .route(
            "/settings/sessions/{id}/revoke",
            post(sessions::settings_sessions_revoke),
        )
        .route(
            "/settings/sessions/revoke-others",
            post(sessions::settings_sessions_revoke_others),
        )
        .route(
            "/settings/linked-providers",
            get(linked_providers::settings_linked_providers),
        )
        .route(
            "/settings/authorized-apps",
            get(authorized_apps::settings_authorized_apps),
        )
        .route(
            "/settings/authorized-apps/{client_id}/revoke",
            post(authorized_apps::settings_authorized_apps_revoke),
        )
        .route(
            "/settings/offline-access",
            get(offline_access::settings_offline_access)
                .post(offline_access::settings_offline_access_save),
        )
        .route(
            "/settings/offline-access/clear",
            post(offline_access::settings_offline_access_clear),
        )
        .route("/settings/account", get(account::settings_account))
        .route(
            "/settings/account/delete",
            get(account::settings_account_delete).post(account::settings_account_delete_submit),
        )
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsHubTemplate {
    chrome: PageChrome,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

async fn settings_hub(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    _sess: crate::extractors::RequireSession,
    banner: crate::handoff::ReferrerBanner,
    themed: ThemedChrome,
) -> Response {
    // Kratos's `selfservice.flows.settings.ui_url` points at `/settings`, so
    // every settings flow lands here with `?flow=<id>`. Inspect the flow's
    // `request_url` to recover the originally-targeted sub-page.
    if let Some(flow_id) = query.flow.as_deref() {
        let cookie = cookies::cookie_header(&headers);
        let target_section =
            match ory::kratos::get_flow(&state.ory, FlowKind::Settings, flow_id, &cookie).await {
                Ok(FlowFetch::Ok(flow)) => settings_section_from_flow(&flow),
                // Unreadable flow: fall back to /settings/password since
                // recovery hand-offs (where it's the only finishable action)
                // dominate this case.
                _ => SettingsSection::Password,
            };
        let url = format!(
            "/settings/{}?flow={}",
            target_section.as_slug(),
            ory_client::apis::urlencode(flow_id)
        );
        return Redirect::to(&url).into_response();
    }

    render(&SettingsHubTemplate {
        chrome: themed.chrome,
        referrer_banner: banner.0,
    })
}

#[derive(Clone, Copy)]
pub(crate) enum SettingsSection {
    Profile,
    Password,
    TwoFactor,
    Sessions,
    LinkedProviders,
    AccountOverview,
    /// Account self-deletion: uses the flow only as a privileged-session probe.
    Account,
}

impl SettingsSection {
    fn as_slug(self) -> &'static str {
        match self {
            SettingsSection::Profile => "profile",
            SettingsSection::Password => "password",
            SettingsSection::TwoFactor => "2fa",
            SettingsSection::Sessions => "sessions",
            SettingsSection::LinkedProviders => "linked-providers",
            SettingsSection::AccountOverview => "account",
            SettingsSection::Account => "account/delete",
        }
    }
    fn path(self) -> &'static str {
        match self {
            SettingsSection::Profile => "/settings/profile",
            SettingsSection::Password => "/settings/password",
            SettingsSection::TwoFactor => "/settings/2fa",
            SettingsSection::Sessions => "/settings/sessions",
            SettingsSection::LinkedProviders => "/settings/linked-providers",
            SettingsSection::AccountOverview => "/settings/account",
            SettingsSection::Account => "/settings/account/delete",
        }
    }
}

/// The subset of [`SettingsSection`] rendered inline by `render_settings`.
/// Encoding it separately keeps the renderer's match exhaustive without an
/// `unreachable!`.
#[derive(Clone, Copy)]
pub(crate) enum InlineRenderSection {
    Profile,
    Password,
}

impl InlineRenderSection {
    fn section(self) -> SettingsSection {
        match self {
            InlineRenderSection::Profile => SettingsSection::Profile,
            InlineRenderSection::Password => SettingsSection::Password,
        }
    }
    fn group(self) -> &'static str {
        match self {
            InlineRenderSection::Profile => "profile",
            InlineRenderSection::Password => "password",
        }
    }
}

/// True when this settings flow was issued by Kratos's `recovery.after.password`
/// hook (user just completed `/recovery` and is in the privileged
/// change-password window). Drives focused-mode rendering.
fn is_recovery_handoff(flow: &serde_json::Value) -> bool {
    let url = flow
        .get("request_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if url.contains("/self-service/recovery") {
        return true;
    }
    if let Some(ctx) = flow.get("internal_context") {
        if ctx.get("recovery_link_token").is_some()
            || ctx.get("RecoveryFlow").is_some()
            || ctx.get("recovery_flow").is_some()
        {
            return true;
        }
    }
    false
}

/// Privileged-session deadline as RFC3339: flow `issued_at` plus Kratos's
/// `privileged_session_max_age` (15m). `None` when `issued_at` is unparseable.
fn privileged_deadline_rfc3339(flow: &serde_json::Value) -> Option<String> {
    let issued = flow.get("issued_at").and_then(|v| v.as_str())?;
    let parsed = chrono::DateTime::parse_from_rfc3339(issued).ok()?;
    let deadline = parsed + chrono::Duration::minutes(15);
    Some(deadline.to_rfc3339())
}

fn settings_section_from_flow(flow: &serde_json::Value) -> SettingsSection {
    let url = flow
        .get("request_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Explicit `return_to` takes precedence: that's how `/settings/profile`
    // and `/settings/password` advertise their target.
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let decoded = url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "return_to")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    if decoded.ends_with("/settings/password") {
        return SettingsSection::Password;
    }
    if decoded.ends_with("/settings/profile") {
        return SettingsSection::Profile;
    }
    if decoded.ends_with("/settings/2fa") {
        return SettingsSection::TwoFactor;
    }
    if decoded.ends_with("/settings/sessions") {
        return SettingsSection::Sessions;
    }
    if decoded.ends_with("/settings/linked-providers") {
        return SettingsSection::LinkedProviders;
    }
    // account-delete confirm reuses the privileged-session gate, so its flow
    // carries `return_to=.../settings/account/delete`; route it back there
    // instead of the unknown-target /profile fallback.
    if decoded.ends_with("/settings/account/delete") {
        return SettingsSection::Account;
    }
    if decoded.ends_with("/settings/account") {
        return SettingsSection::AccountOverview;
    }

    // No `return_to`: recovery hand-offs land here. Route them to
    // /settings/password, the only place they can finish (set a new password).
    if url.contains("/self-service/recovery") {
        return SettingsSection::Password;
    }
    let state = flow_state(flow);
    if state == "show_form" {
        if let Some(ctx) = flow.get("internal_context") {
            if ctx.get("recovery_link_token").is_some()
                || ctx.get("RecoveryFlow").is_some()
                || ctx.get("recovery_flow").is_some()
            {
                return SettingsSection::Password;
            }
        }
    }

    // Fall back to password: Kratos's code-based recovery hand-off (v1.3.1)
    // lands here with no return_to and no `recovery_*` internal_context keys,
    // and /settings/password is the only place it can be finished.
    SettingsSection::Password
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrandConfig;
    use askama::Template;

    #[test]
    #[ignore]
    fn render_settings_hub_demo() {
        let brand = BrandConfig {
            name: "Forseti".to_string(),
            support_email: None,
            logo_url: None,
            consent_intro: String::new(),
            theme_preset: None,
            brand_primary: None,
            brand_on_primary: None,
            brand_secondary: None,
            operator_trust_anchor: None,
        };

        for locale_str in ["en", "de"] {
            let locale: crate::locale::LanguageIdentifier = locale_str.parse().unwrap();
            let chrome = PageChrome::from_brand_with_admin(
                brand.clone(),
                "maria@example.de".to_string(),
                "csrf-demo".to_string(),
                true,
                locale,
            );
            let tmpl = SettingsHubTemplate {
                chrome,
                referrer_banner: None,
            };
            let html = tmpl.render().unwrap();
            std::fs::write(format!("demo_settings_{locale_str}.html"), html).unwrap();
        }
    }
}

/// `Err(resp)` is a fully-formed early-return (redirect / error page) so
/// callers can `?`-short-circuit; `Ok` lets them run their own renderer.
pub(crate) type SettingsFlowOutcome = Result<(ory::Session, Box<serde_json::Value>), Response>;

/// Shared gate + fetch for a settings sub-page: keeps the privileged-refresh
/// redirect, missing-flow init, and gone-flow re-init consistent across
/// handlers.
pub(crate) async fn fetch_settings_subpage(
    state: &AppState,
    headers: &HeaderMap,
    query: &FlowQuery,
    section: SettingsSection,
    sess: &crate::extractors::RequireSession,
    locale: &LanguageIdentifier,
) -> SettingsFlowOutcome {
    let cookie = cookies::cookie_header(headers);

    let return_to_full = format!(
        "{}{}",
        state.cfg.self_.url.trim_end_matches('/'),
        section.path()
    );

    let flow_id = query.flow.as_deref();
    let init_url = || {
        ory::kratos::browser_init_url(
            FlowKind::Settings,
            &state.cfg.kratos.public_url,
            Some(&return_to_full),
        )
    };

    match ory::kratos::resolve_flow(&state.ory, FlowKind::Settings, flow_id, &cookie).await {
        FlowOutcome::Init | FlowOutcome::Reinit => Err(Redirect::to(&init_url()).into_response()),
        FlowOutcome::Ready(flow) => Ok((sess.session.clone(), flow)),
        FlowOutcome::Privileged(reason) => {
            // The two 403 reasons need different `/login` params: sending
            // `refresh=true` when Kratos wanted `aal=aal2` livelocks the user
            // on `/settings/*` after a recovery hand-off.
            let url = match reason {
                crate::ory::PrivilegedReason::Aal2Required => {
                    crate::auth::aal2_step_up_url(&return_to_full)
                }
                crate::ory::PrivilegedReason::SessionRefresh => format!(
                    "/login?refresh=true&return_to={}",
                    ory_client::apis::urlencode(&return_to_full)
                ),
            };
            Err(Redirect::to(&url).into_response())
        }
        FlowOutcome::Error(e) => {
            tracing::error!(error = ?e, ?flow_id, "failed to fetch Kratos settings flow");
            Err(render_error_boundary(
                state,
                locale,
                &crate::i18n::lookup(locale, "error-boundary-settings-title"),
                &crate::i18n::lookup(locale, "error-boundary-auth-unavailable-body"),
                "/settings",
                crate::i18n::lookup(locale, "error-boundary-cta-back-to-settings"),
            )
            .into_response())
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProfileSavedQuery {
    #[serde(default, deserialize_with = "crate::web::deserialize_bool_str")]
    pub(crate) profile_saved: Option<bool>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn settings_subpage(
    state: &AppState,
    headers: &HeaderMap,
    csrf_token: &str,
    query: &FlowQuery,
    section: InlineRenderSection,
    sess: &crate::extractors::RequireSession,
    banner: crate::handoff::ReferrerBanner,
    profile_saved: bool,
    locale: LanguageIdentifier,
) -> Response {
    let (session, flow) =
        match fetch_settings_subpage(state, headers, query, section.section(), sess, &locale).await
        {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };
    let memberships = crate::orgs::list_memberships(&state.db, &sess.identity_id)
        .await
        .unwrap_or_default();
    let is_profile = matches!(section, InlineRenderSection::Profile);
    // Load the Forseti-owned extended fields only for the profile section.
    let profile = if is_profile && state.cfg.profiles.enabled {
        Some(
            crate::profiles::fetch(&state.db, &sess.identity_id)
                .await
                .unwrap_or_default(),
        )
    } else {
        None
    };
    let extended_saved = is_profile && profile_saved;
    render_settings(
        state,
        headers,
        &memberships,
        csrf_token,
        &session,
        &flow,
        section,
        profile,
        extended_saved,
        banner.0,
        locale,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_settings(
    state: &AppState,
    headers: &HeaderMap,
    memberships: &[crate::orgs::Membership],
    csrf_token: &str,
    session: &ory::Session,
    flow: &serde_json::Value,
    section: InlineRenderSection,
    profile: Option<crate::profiles::Profile>,
    extended_saved: bool,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
    locale: LanguageIdentifier,
) -> Response {
    let (form_action, form_method) = form_target(flow);
    let mut groups = group_nodes(flow);
    mark_settings_primary(&mut groups, section.group());

    // Translate node labels and per-node messages.
    translate_inputs(&mut groups.default, &locale);
    translate_inputs(&mut groups.oidc, &locale);
    translate_inputs(&mut groups.code, &locale);
    translate_inputs(&mut groups.password, &locale);
    translate_inputs(&mut groups.profile, &locale);
    translate_inputs(&mut groups.other, &locale);

    let mut msgs = flow_messages(flow);
    translate_messages(&mut msgs, &locale);
    let token = csrf_token.to_string();

    match section {
        InlineRenderSection::Profile => {
            let p = profile.unwrap_or_default();
            let links_text = crate::settings::profile::links_to_text(&p.links);
            render(&SettingsProfileTemplate {
                chrome: PageChrome::from_parts_themed(
                    state,
                    memberships,
                    headers,
                    session_email(session),
                    token,
                    locale,
                ),
                form_action,
                form_method,
                flow_messages: msgs,
                groups,
                profiles_enabled: state.cfg.profiles.enabled,
                bio: p.bio.unwrap_or_default(),
                location: p.location.unwrap_or_default(),
                pronouns: p.pronouns.unwrap_or_default(),
                website: p.website.unwrap_or_default(),
                avatar_url: p.avatar_url.unwrap_or_default(),
                links_text,
                extended_saved,
                email_verified: !session_needs_verification(session),
                referrer_banner,
            })
        }
        InlineRenderSection::Password => {
            if is_recovery_handoff(flow) {
                // Land on the dashboard once the new credential is in place;
                // Kratos's default "changes saved" settings screen is wrong for
                // focused recovery mode.
                if flow_state(flow) == "success" {
                    return Redirect::to("/").into_response();
                }
                render(&SettingsPasswordHandoffTemplate {
                    chrome: PageChrome::from_parts_themed(
                        state,
                        memberships,
                        headers,
                        String::new(),
                        token,
                        locale,
                    ),
                    form_action,
                    form_method,
                    flow_messages: msgs,
                    groups,
                    privileged_deadline: privileged_deadline_rfc3339(flow),
                })
            } else {
                render(&SettingsPasswordTemplate {
                    chrome: PageChrome::from_parts_themed(
                        state,
                        memberships,
                        headers,
                        session_email(session),
                        token,
                        locale,
                    ),
                    form_action,
                    form_method,
                    flow_messages: msgs,
                    groups,
                    referrer_banner,
                })
            }
        }
    }
}
