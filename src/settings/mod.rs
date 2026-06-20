//! User-facing `/settings/*` surface: profile, password (incl. recovery
//! hand-off), 2FA, sessions, linked providers, plus the hub redirector
//! Kratos sends every settings flow through.
//!
//! Each submodule owns one section: template + handler + section-specific
//! render helper. The shared gate / fetch / privileged-refresh dance lives
//! here in `fetch_settings_subpage`. The Profile and Password renderers live
//! here; the other sections own their own render helpers.

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
    session_needs_verification,
};
use crate::ory::{self, FlowFetch, FlowKind};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, FlowQuery};

pub(crate) mod account;
pub(crate) mod authorized_apps;
pub(crate) mod linked_providers;
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
    sess: crate::extractors::RequireSession,
    csrf: crate::extractors::Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    // Kratos's `selfservice.flows.settings.ui_url` points at `/settings`, so
    // every settings flow Kratos initiates (whether from `/settings/profile`
    // or the post-recovery hand-off) lands here with `?flow=<id>`. We
    // inspect the flow's `request_url` to figure out which sub-page the user
    // was actually heading for and forward them there. Falls back to the
    // profile editor when the original target can't be determined.
    if let Some(flow_id) = query.flow.as_deref() {
        let cookie = cookies::cookie_header(&headers);
        let target_section =
            match ory::kratos::get_flow(&state.ory, FlowKind::Settings, flow_id, &cookie).await {
                Ok(FlowFetch::Ok(flow)) => settings_section_from_flow(&flow),
                // When we can't read the flow (gone, AAL2 required, or transport
                // error) we don't know the originally-requested sub-page. Land
                // the user on /settings/password rather than /settings/profile:
                // recovery hand-offs are the dominant case for this fallback,
                // and "set a new password" is the only thing they can actually
                // finish there. Wrong choice for a non-recovery flow just costs
                // an extra click in the sidebar.
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
        chrome: PageChrome::from_parts(&state, sess.email, csrf.0),
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
    /// Account overview page (`/settings/account`). Only used as a redirect
    /// target by the hub dispatcher; never goes through `render_settings`.
    AccountOverview,
    /// Danger zone — account self-deletion. Doesn't consume a Kratos
    /// settings group; uses the flow only as a privileged-session probe.
    Account,
}

impl SettingsSection {
    /// Bare slug for `/settings/{slug}` redirect targets.
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

/// The subset of [`SettingsSection`] that `settings_subpage` / `render_settings`
/// actually render inline (they share the same flow-driven template shape). The
/// other sections hand-roll their own templates and drive `fetch_settings_subpage`
/// directly, so they never reach the generic renderer — encoding that here keeps
/// the renderer's match exhaustive without an `unreachable!`.
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
    /// Kratos group consumed as the "primary CTA" hint by `mark_settings_primary`.
    fn group(self) -> &'static str {
        match self {
            InlineRenderSection::Profile => "profile",
            InlineRenderSection::Password => "password",
        }
    }
}

/// Read the flow's `request_url` and infer which settings sub-page the user
/// was navigating to. Kratos always lands the flow on `selfservice.flows.settings.ui_url`,
/// so we encode the actual section in the `return_to` portion of the
/// browser-init URL and recover it here.
///
/// Two origins funnel into this:
///   * Normal navigation from `/settings/profile` or `/settings/password` —
///     `request_url` carries an explicit `return_to=<self>/settings/<section>`
///     which uniquely identifies the target.
///   * Recovery hand-off — after a successful `/recovery` flow Kratos issues a
///     fresh settings flow (Kratos's `selfservice.flows.recovery.after.password`
///     hook) without a `return_to`, expecting the UI to land the user on
///     `/settings/password` so they can pick a new password. We detect this
///     by inspecting the `request_url`'s path (`/self-service/recovery/...`
///     when the flow originated from a recovery hand-off; Kratos preserves
///     the originating path inside `internal_context.recovery_link_token` on
///     newer versions, but the `request_url` is the stable cross-version
///     signal).
///
/// True when this settings flow was issued by Kratos's `recovery.after.password`
/// hook — i.e. the user just successfully completed `/recovery` and is now in
/// the privileged window where they must change their password. Mirrors the
/// detection in [`settings_section_from_flow`] but as a boolean we can pass
/// into the template for focused-mode rendering.
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

/// Compute the privileged-session deadline as RFC3339, taking the flow's
/// `issued_at` (the moment Kratos opened the privileged window for this
/// hand-off) and adding Kratos's `privileged_session_max_age` (15m in our
/// playground config). Returns `None` when the flow lacks a parseable
/// `issued_at`.
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

    // Explicit `return_to` takes precedence — that's how `/settings/profile`
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
    // The account-delete confirm page reuses the privileged-session
    // gate via `fetch_settings_subpage`, so it issues a Kratos settings
    // flow with `return_to=.../settings/account/delete`. The hub
    // dispatcher needs to know how to land the user back there;
    // otherwise the unknown-target fallback drops them on /profile.
    if decoded.ends_with("/settings/account/delete") {
        return SettingsSection::Account;
    }
    if decoded.ends_with("/settings/account") {
        return SettingsSection::AccountOverview;
    }

    // No `return_to`. Recovery hand-offs land here — Kratos issues the
    // post-recovery settings flow from the recovery endpoint, so the
    // `request_url` (or the flow's internal context) carries that origin.
    // Routing recovery-originated flows to /settings/password is what the
    // design brief specifies, and it's also the only place the user can
    // actually finish the recovery (set a new password).
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

    // Fall back to password when we genuinely can't tell. Kratos's code-based
    // recovery hand-off lands here without a return_to and (in v1.3.1) without
    // the `recovery_*` keys in internal_context, so the explicit checks above
    // miss it. Routing to /settings/password is the only way the user can
    // actually finish the recovery (set a new password); the alternative —
    // /settings/profile — left the user staring at trait fields they didn't
    // need and unable to navigate to /password (the AAL2 step-up loop made
    // sidebar links useless until they re-authed). Wrong choice for an
    // unusual non-recovery fall-through just costs a sidebar click.
    SettingsSection::Password
}

/// Outcome of fetching a Kratos settings flow on behalf of a sub-page.
///
/// `Ok((session, flow))` lets callers run their own renderer. `Err(resp)` is
/// a fully-formed early-return (redirect / error page) the caller hands back
/// directly. The shape lets callers use `?` to short-circuit.
pub(crate) type SettingsFlowOutcome = Result<(ory::Session, Box<serde_json::Value>), Response>;

/// Run the shared gate + fetch for a settings sub-page. Used by all settings
/// sub-page handlers (profile, password, 2fa, sessions equivalent paths,
/// linked-providers) so the privileged-refresh redirect, missing-flow init,
/// and gone-flow re-init behaviour stays consistent.
pub(crate) async fn fetch_settings_subpage(
    state: &AppState,
    headers: &HeaderMap,
    query: &FlowQuery,
    section: SettingsSection,
    sess: &crate::extractors::RequireSession,
) -> SettingsFlowOutcome {
    let cookie = cookies::cookie_header(headers);

    let return_to_full = format!(
        "{}{}",
        state.cfg.self_.url.trim_end_matches('/'),
        section.path()
    );

    let Some(flow_id) = query.flow.as_deref() else {
        let url = ory::kratos::browser_init_url(
            FlowKind::Settings,
            &state.cfg.kratos.public_url,
            Some(&return_to_full),
        );
        return Err(Redirect::to(&url).into_response());
    };

    match ory::kratos::get_flow(&state.ory, FlowKind::Settings, flow_id, &cookie).await {
        Ok(FlowFetch::Ok(flow)) => Ok((sess.session.clone(), flow)),
        Ok(FlowFetch::Gone) => {
            let url = ory::kratos::browser_init_url(
                FlowKind::Settings,
                &state.cfg.kratos.public_url,
                Some(&return_to_full),
            );
            Err(Redirect::to(&url).into_response())
        }
        Ok(FlowFetch::PrivilegedRequired(reason)) => {
            // The two privileged-session 403 reasons (`session_refresh_required`
            // / `session_aal2_required`) need different `/login` parameters.
            // Sending `refresh=true` when Kratos wanted `aal=aal2` is what
            // livelocks the user on `/settings/*` after a recovery hand-off:
            // refresh proves "you're still you" but doesn't satisfy the AAL2
            // requirement, so /login bounces them straight back.
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
        Err(e) => {
            tracing::error!(error = ?e, flow_id, "failed to fetch Kratos settings flow");
            Err(render_error_boundary(
                state,
                "Settings unavailable",
                crate::web::AUTH_UNAVAILABLE_BODY,
                "/settings",
                "Back to settings",
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
) -> Response {
    let (session, flow) =
        match fetch_settings_subpage(state, headers, query, section.section(), sess).await {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };
    let is_profile = matches!(section, InlineRenderSection::Profile);
    // Profile page needs the Forseti-owned extended fields too.
    // Load lazily so non-profile sections don't pay for it.
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
        csrf_token,
        &session,
        &flow,
        section,
        profile,
        extended_saved,
        banner.0,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_settings(
    state: &AppState,
    csrf_token: &str,
    session: &ory::Session,
    flow: &serde_json::Value,
    section: InlineRenderSection,
    profile: Option<crate::profiles::Profile>,
    extended_saved: bool,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
) -> Response {
    let (form_action, form_method) = form_target(flow);
    let mut groups = group_nodes(flow);
    mark_settings_primary(&mut groups, section.group());
    let token = csrf_token.to_string();

    match section {
        InlineRenderSection::Profile => {
            let p = profile.unwrap_or_default();
            let links_text = crate::settings::profile::links_to_text(&p.links);
            render(&SettingsProfileTemplate {
                chrome: PageChrome::from_parts(state, session_email(session), token),
                form_action,
                form_method,
                flow_messages: flow_messages(flow),
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
                // After a successful password change in the recovery hand-off,
                // send the user to the dashboard. Kratos itself stays on the
                // settings UI with a "Your changes have been saved!" message
                // (no `after.password.default_browser_return_url` is set),
                // which is right for normal settings edits but wrong for the
                // recovery hand-off — the whole point of focused mode is to
                // land on a working session once the new credential is in place.
                if flow_state(flow) == "success" {
                    return Redirect::to("/").into_response();
                }
                render(&SettingsPasswordHandoffTemplate {
                    chrome: PageChrome::from_parts(state, String::new(), token),
                    form_action,
                    form_method,
                    flow_messages: flow_messages(flow),
                    groups,
                    privileged_deadline: privileged_deadline_rfc3339(flow),
                })
            } else {
                render(&SettingsPasswordTemplate {
                    chrome: PageChrome::from_parts(state, session_email(session), token),
                    form_action,
                    form_method,
                    flow_messages: flow_messages(flow),
                    groups,
                    referrer_banner,
                })
            }
        }
    }
}
