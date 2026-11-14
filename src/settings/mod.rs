//! User-facing `/settings/*` surface: profile, password (incl. recovery
//! hand-off), 2FA, sessions, linked providers, plus the hub redirector Kratos
//! sends every settings flow through. The shared gate / fetch /
//! privileged-refresh dance lives here in `fetch_settings_subpage`.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};

use askama::Template;
use serde::Deserialize;

use crate::backend::IdentityBackend;
use crate::backend::identity::FlowInit;
use crate::backend::identity::FlowOutcome;
use crate::backend::identity::{FlowFetch, FlowKind, Session};
use crate::cookies;
use crate::flow_view::{
    Flow, GroupedNodes, mark_settings_primary, translate_inputs, translate_messages,
};
use crate::locale::LanguageIdentifier;
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{FlowQuery, render_error_boundary};

pub(crate) mod account;
pub(crate) mod authorized_apps;
pub(crate) mod export;
pub(crate) mod linked_providers;
pub(crate) mod offline_access;
pub(crate) mod oidc_links_db;
pub(crate) mod password;
pub(crate) mod profile;
pub(crate) mod resource_claims;
pub(crate) mod sessions;
pub(crate) mod two_factor;

use password::{SettingsPasswordHandoffTemplate, SettingsPasswordTemplate};
use profile::SettingsProfileTemplate;

pub(crate) fn router(cfg: &crate::config::AppConfig) -> Router<AppState> {
    Router::new()
        .route("/settings", get(settings_hub))
        .route("/settings/profile", get(profile::settings_profile))
        .route(
            "/settings/profile/extended",
            post(profile::settings_profile_extended_save),
        )
        .route(
            "/settings/profile/username",
            post(profile::settings_profile_username_save),
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
            "/settings/resource-claims",
            get(resource_claims::settings_resource_claims),
        )
        .route(
            "/settings/resource-claims/{id}/remove",
            post(resource_claims::settings_resource_claims_remove),
        )
        .route(
            "/settings/offline-access",
            get(offline_access::settings_offline_access),
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
        .route(
            "/settings/account/export",
            get(export::settings_account_export),
        )
        .merge(offline_access_router(cfg))
        .merge(resource_claims_router(cfg))
        .merge(resource_claims_callback_router(cfg))
}

/// The offline-passphrase save on its own sub-router so its rate limit
/// applies to nothing else. Each save runs Argon2id at m=64MiB/t=3, which is
/// deliberately expensive and therefore a denial-of-service amplifier if
/// anyone can call it in a loop.
fn offline_access_router(cfg: &crate::config::AppConfig) -> Router<AppState> {
    let r = Router::new().route(
        "/settings/offline-access",
        post(offline_access::settings_offline_access_save),
    );
    crate::rate_limit::single_window(
        r,
        &cfg.proxy,
        3_600_000,
        cfg.posix.offline_saves_per_hour,
        crate::rate_limit::plain_text_error("settings.offline_access"),
    )
}

/// The link start on its own sub-router: each call fetches the issuer's
/// discovery document, so an unthrottled loop turns Forseti into a fetcher.
fn resource_claims_router(cfg: &crate::config::AppConfig) -> Router<AppState> {
    let r = Router::new().route(
        "/settings/resource-claims/{id}/start",
        post(resource_claims::settings_resource_claims_start),
    );
    crate::rate_limit::single_window(
        r,
        &cfg.proxy,
        600_000,
        30,
        crate::rate_limit::plain_text_error("settings.resource_claims"),
    )
}

/// The issuer's redirect back, in its own bucket: a valid link cookie can be
/// replayed until it expires, and each replay fetches from the issuer.
fn resource_claims_callback_router(cfg: &crate::config::AppConfig) -> Router<AppState> {
    let r = Router::new().route(
        "/settings/resource-claims/callback",
        get(resource_claims::settings_resource_claims_callback),
    );
    crate::rate_limit::single_window(
        r,
        &cfg.proxy,
        600_000,
        60,
        crate::rate_limit::plain_text_error("settings.resource_claims_callback"),
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
        let target_section = match state
            .identity
            .get_flow(FlowKind::Settings, flow_id, &cookie)
            .await
        {
            Ok(FlowFetch::Ok(flow)) => settings_section_from_flow(&flow),
            // Unreadable flow: fall back to /settings/password since
            // recovery hand-offs (where it's the only finishable action)
            // dominate this case.
            _ => SettingsSection::Password,
        };
        let url = format!(
            "/settings/{}?flow={}",
            target_section.as_slug(),
            crate::web::urlencode(flow_id)
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
    /// Offline passphrase: same probe-only use as [`SettingsSection::Account`].
    /// The verifier it mints authenticates on hosts that can't reach Forseti,
    /// so it gets the same gate as any other credential change.
    OfflineAccess,
    /// Account export: a bulk read of everything held about the person, so
    /// it gets the same probe-only gate as the delete.
    Export,
}

impl SettingsSection {
    /// Sections that use the settings flow only as a privileged-session probe
    /// for a Forseti-owned action, so Kratos never sees a submit for them.
    fn is_probe_only(self) -> bool {
        matches!(
            self,
            SettingsSection::Account | SettingsSection::OfflineAccess | SettingsSection::Export
        )
    }

    fn as_slug(self) -> &'static str {
        match self {
            SettingsSection::Profile => "profile",
            SettingsSection::Password => "password",
            SettingsSection::TwoFactor => "2fa",
            SettingsSection::Sessions => "sessions",
            SettingsSection::LinkedProviders => "linked-providers",
            SettingsSection::AccountOverview => "account",
            SettingsSection::Account => "account/delete",
            SettingsSection::OfflineAccess => "offline-access",
            SettingsSection::Export => "account/export",
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
            SettingsSection::OfflineAccess => "/settings/offline-access",
            SettingsSection::Export => "/settings/account/export",
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

/// Privileged-session deadline as RFC3339: flow `issued_at` plus the
/// privileged `window`. `None` when `issued_at` is unparseable.
// Display only; DB timestamps go through crate::db::rfc3339.
#[allow(clippy::disallowed_methods)]
fn privileged_deadline_rfc3339(flow: &Flow, window: chrono::Duration) -> Option<String> {
    let issued = flow.issued_at.as_deref()?;
    let parsed = chrono::DateTime::parse_from_rfc3339(issued).ok()?;
    let deadline = parsed + window;
    Some(deadline.to_rfc3339())
}

/// Whether `session` signed in within the privileged `window` of `now`.
fn recently_authenticated(
    session: &Session,
    now: chrono::DateTime<chrono::Utc>,
    window: chrono::Duration,
) -> bool {
    crate::oauth::reauth::session_auth_time(session).is_some_and(|t| now - t <= window)
}

fn settings_section_from_flow(flow: &Flow) -> SettingsSection {
    // The `return_to` each sub-page puts on the flow names its target.
    let decoded = flow.request_return_to.as_str();
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
    // Same probe-only reuse as account delete.
    if decoded.ends_with("/settings/offline-access") {
        return SettingsSection::OfflineAccess;
    }
    if decoded.ends_with("/settings/account/export") {
        return SettingsSection::Export;
    }
    if decoded.ends_with("/settings/account") {
        return SettingsSection::AccountOverview;
    }

    // Recovery hand-offs carry no `return_to` and can only finish at /settings/password.
    SettingsSection::Password
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrandConfig;
    use askama::Template;

    fn flow_returning_to(path: &str) -> Flow {
        let return_to =
            url::form_urlencoded::byte_serialize(format!("http://localhost:3000{path}").as_bytes())
                .collect::<String>();
        crate::flow_json::project(&serde_json::json!({
            "request_url": format!(
                "http://localhost:4433/self-service/settings/browser?return_to={return_to}"
            )
        }))
    }

    /// Every probe-only section must route its flow back to itself, or the
    /// privileged gate lands the user on an unrelated page.
    #[test]
    fn probe_sections_route_back_to_themselves() {
        for section in [
            SettingsSection::Account,
            SettingsSection::OfflineAccess,
            SettingsSection::Export,
        ] {
            assert!(section.is_probe_only());
            let routed = settings_section_from_flow(&flow_returning_to(section.path()));
            assert_eq!(routed.as_slug(), section.as_slug());
        }
    }

    fn session_signed_in_at(rfc3339: &str) -> Session {
        let mut s = Session {
            id: "sess-1".to_string(),
            ..Default::default()
        };
        s.authenticated_at = Some(rfc3339.to_string());
        s
    }

    const WINDOW: chrono::Duration = chrono::Duration::minutes(15);

    fn at(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn sign_in_inside_the_window_is_recent() {
        let s = session_signed_in_at("2026-01-01T10:00:00Z");
        assert!(recently_authenticated(
            &s,
            at("2026-01-01T10:14:59Z"),
            WINDOW
        ));
    }

    #[test]
    fn sign_in_outside_the_window_is_not_recent() {
        let s = session_signed_in_at("2026-01-01T10:00:00Z");
        assert!(!recently_authenticated(
            &s,
            at("2026-01-01T10:15:01Z"),
            WINDOW
        ));
    }

    #[test]
    fn session_without_a_timestamp_is_not_recent() {
        let s = Session {
            id: "sess-1".to_string(),
            ..Default::default()
        };
        assert!(!recently_authenticated(
            &s,
            at("2026-01-01T10:00:00Z"),
            WINDOW
        ));
    }

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
pub(crate) type SettingsFlowOutcome = Result<(Session, Box<Flow>), Response>;

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
        state.identity.flow_init_url(
            FlowKind::Settings,
            FlowInit {
                return_to: Some(&return_to_full),
                ..Default::default()
            },
        )
    };

    match state
        .identity
        .resolve_flow(FlowKind::Settings, flow_id, &cookie)
        .await
    {
        FlowOutcome::Init | FlowOutcome::Reinit => Err(Redirect::to(&init_url()).into_response()),
        // Kratos checks only AAL when a flow is fetched; it enforces the
        // privileged window on submit. Probe-only sections never submit, so
        // they enforce it here.
        FlowOutcome::Ready(_)
            if section.is_probe_only()
                && !recently_authenticated(
                    &sess.session,
                    chrono::Utc::now(),
                    state.cfg.identity.privileged_window(),
                ) =>
        {
            Err(Redirect::to(&format!(
                "/login?refresh=true&return_to={}",
                crate::web::urlencode(&return_to_full)
            ))
            .into_response())
        }
        FlowOutcome::Ready(flow) => Ok((sess.session.clone(), flow)),
        FlowOutcome::Privileged(reason) => {
            // The two 403 reasons need different `/login` params: sending
            // `refresh=true` when Kratos wanted `aal=aal2` livelocks the user
            // on `/settings/*` after a recovery hand-off.
            let url = match reason {
                crate::backend::identity::PrivilegedReason::Aal2Required => {
                    crate::auth::aal2_step_up_url(&return_to_full)
                }
                crate::backend::identity::PrivilegedReason::SessionRefresh => format!(
                    "/login?refresh=true&return_to={}",
                    crate::web::urlencode(&return_to_full)
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
    #[serde(default, deserialize_with = "crate::web::deserialize_bool_str")]
    pub(crate) username_saved: Option<bool>,
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
    username_saved: bool,
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
    // Load the Forseti-owned fields only for the profile section. The handle
    // is shown regardless of `[profiles].enabled`; the template hides the rest.
    let profile = if is_profile {
        Some(
            crate::profiles::fetch(&state.db, &sess.identity_id)
                .await
                .unwrap_or_default(),
        )
    } else {
        None
    };
    render_settings(
        state,
        headers,
        &memberships,
        csrf_token,
        &session,
        &flow,
        section,
        profile,
        is_profile && profile_saved,
        is_profile && username_saved,
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
    session: &Session,
    flow: &Flow,
    section: InlineRenderSection,
    profile: Option<crate::profiles::Profile>,
    extended_saved: bool,
    username_saved: bool,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
    locale: LanguageIdentifier,
) -> Response {
    let form_action = flow.form_action.clone();
    let form_method = flow.form_method.clone();
    let mut groups = GroupedNodes::from_flow(flow);
    mark_settings_primary(&mut groups, section.group());

    // Translate node labels and per-node messages.
    translate_inputs(&mut groups.default, &locale);
    translate_inputs(&mut groups.oidc, &locale);
    translate_inputs(&mut groups.code, &locale);
    translate_inputs(&mut groups.password, &locale);
    translate_inputs(&mut groups.profile, &locale);
    translate_inputs(&mut groups.other, &locale);

    let mut msgs = flow.messages.clone();
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
                    session.email(),
                    session.addresses(),
                    token,
                    locale,
                ),
                form_action,
                form_method,
                flow_messages: msgs,
                groups,
                profiles_enabled: state.cfg.profiles.enabled,
                username: p.username.unwrap_or_default(),
                bio: p.bio.unwrap_or_default(),
                location: p.location.unwrap_or_default(),
                pronouns: p.pronouns.unwrap_or_default(),
                website: p.website.unwrap_or_default(),
                avatar_url: p.avatar_url.unwrap_or_default(),
                links_text,
                extended_saved,
                username_saved,
                email_verified: !session.needs_verification(),
                referrer_banner,
            })
        }
        InlineRenderSection::Password => {
            if flow.recovery_handoff {
                // Land on the dashboard once the new credential is in place;
                // Kratos's default "changes saved" settings screen is wrong for
                // focused recovery mode.
                if flow.state == "success" {
                    return Redirect::to("/").into_response();
                }
                render(&SettingsPasswordHandoffTemplate {
                    chrome: PageChrome::from_parts_themed(
                        state,
                        memberships,
                        headers,
                        String::new(),
                        None,
                        token,
                        locale,
                    ),
                    form_action,
                    form_method,
                    flow_messages: msgs,
                    groups,
                    privileged_deadline: privileged_deadline_rfc3339(
                        flow,
                        state.cfg.identity.privileged_window(),
                    ),
                })
            } else {
                render(&SettingsPasswordTemplate {
                    chrome: PageChrome::from_parts_themed(
                        state,
                        memberships,
                        headers,
                        session.email(),
                        session.addresses(),
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
