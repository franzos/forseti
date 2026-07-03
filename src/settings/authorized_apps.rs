//! `/settings/authorized-apps` — list and revoke OAuth2 consent grants the
//! user has given to downstream apps. Forseti-owned (no Kratos settings flow);
//! reads from Hydra's consent-session API and revokes per-client.

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::csrf::CsrfForm;
use crate::flash;
use crate::format::humanise_timestamp;
use crate::ory;
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::render_error_boundary;
use crate::state::AppState;

/// Per-scope chip in the authorized-apps row. `description` is the human label
/// (from `oauth.scope_descriptions`); `name` is the raw scope ID.
pub(crate) struct ScopeChip {
    pub(crate) name: String,
    pub(crate) description: String,
}

pub(crate) struct AuthorizedAppView {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) client_uri: String,
    pub(crate) logo_uri: String,
    pub(crate) scopes: Vec<ScopeChip>,
    pub(crate) granted_at: String,
    pub(crate) granted_at_pretty: String,
    pub(crate) verified: bool,
}

#[derive(Template)]
#[template(path = "settings_authorized_apps.html")]
pub(crate) struct SettingsAuthorizedAppsTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) apps: Vec<AuthorizedAppView>,
    pub(crate) flash: String,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

pub(crate) async fn settings_authorized_apps(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
) -> Response {
    let subject = sess.identity_id.clone();
    if subject.is_empty() {
        return render_error_boundary(
            &state,
            &locale,
            &crate::i18n::lookup(&locale, "error-boundary-authorized-apps-title"),
            &crate::i18n::lookup(&locale, "error-boundary-authorized-apps-no-session-body"),
            "/login",
            crate::i18n::lookup(&locale, "error-boundary-cta-sign-in"),
        )
        .into_response();
    }

    let sessions = match ory::hydra::list_consent_sessions_by_subject(&state.ory, &subject).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = ?e, "list_consent_sessions failed");
            return render_error_boundary(
                &state,
                &locale,
                &crate::i18n::lookup(&locale, "error-boundary-authorized-apps-title"),
                &crate::i18n::lookup(&locale, "error-boundary-authorized-apps-service-body"),
                "/settings",
                crate::i18n::lookup(&locale, "error-boundary-cta-back-to-settings"),
            )
            .into_response();
        }
    };

    let apps = collapse_sessions_to_apps(&state, &locale, sessions);

    let (flash_msg, clear_flash) = state.take_flash(&headers, "/settings/authorized-apps");
    let body = render(&SettingsAuthorizedAppsTemplate {
        chrome: themed.chrome,
        apps,
        flash: flash_msg,
        referrer_banner: banner.0,
    });
    flash::attach_set_cookie(body, clear_flash)
}

/// Fold Hydra's per-session rows into one row per `client_id`, keeping the
/// newest `handled_at` and the union of granted scopes (what "Revoke access"
/// wipes anyway).
fn collapse_sessions_to_apps(
    state: &AppState,
    locale: &crate::locale::LanguageIdentifier,
    sessions: Vec<ory_client::models::OAuth2ConsentSession>,
) -> Vec<AuthorizedAppView> {
    use std::collections::BTreeMap;

    let mut by_client: BTreeMap<String, AuthorizedAppView> = BTreeMap::new();
    for s in sessions {
        let Some(req) = s.consent_request.as_ref() else {
            continue;
        };
        let Some(client) = req.client.as_ref() else {
            continue;
        };
        let Some(client_id) = client.client_id.clone() else {
            continue;
        };

        let client_name = client
            .client_name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| client_id.clone());
        let client_uri = client.client_uri.clone().unwrap_or_default();
        let logo_uri = client.logo_uri.clone().unwrap_or_default();
        let verified = client_metadata_verified(client);

        let granted_at = s.handled_at.clone().unwrap_or_default();
        let granted_scopes = s.grant_scope.clone().unwrap_or_default();

        let entry = by_client
            .entry(client_id.clone())
            .or_insert_with(|| AuthorizedAppView {
                client_id: client_id.clone(),
                client_name,
                client_uri,
                logo_uri,
                scopes: Vec::new(),
                granted_at: granted_at.clone(),
                granted_at_pretty: humanise_timestamp(locale, &granted_at),
                verified,
            });
        if !granted_at.is_empty() && granted_at.as_str() > entry.granted_at.as_str() {
            entry.granted_at_pretty = humanise_timestamp(locale, &granted_at);
            entry.granted_at = granted_at;
        }
        for scope in granted_scopes {
            if !entry.scopes.iter().any(|c| c.name == scope) {
                let description = state
                    .cfg
                    .oauth
                    .scope_descriptions
                    .get(&scope)
                    .cloned()
                    .unwrap_or_else(|| scope.clone());
                entry.scopes.push(ScopeChip {
                    name: scope,
                    description,
                });
            }
        }
    }

    by_client.into_values().collect()
}

/// Hydra's stored `metadata.verified` flag; mirrors the consent page's badge
/// heuristic.
fn client_metadata_verified(client: &ory_client::models::OAuth2Client) -> bool {
    client
        .metadata
        .as_ref()
        .and_then(|m| m.get("verified"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub(crate) async fn settings_authorized_apps_revoke(
    State(state): State<AppState>,
    axum::extract::Path(client_id): axum::extract::Path<String>,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    let actor_id = sess.identity_id;
    let actor_email = sess.email;

    let (msg, ok) =
        match ory::hydra::revoke_consent_sessions_for_client(&state.ory, &actor_id, &client_id)
            .await
        {
            Ok(()) => (
                crate::i18n::lookup(&locale, "flash-app-access-revoked"),
                true,
            ),
            Err(e) => {
                tracing::error!(error = ?e, client_id, "revoke_consent_for_client failed");
                (
                    crate::i18n::lookup(&locale, "flash-app-access-revoke-failed"),
                    false,
                )
            }
        };
    if ok {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::OAUTH_CONSENT_REVOKED)
                .actor_user(&actor_id, &actor_email)
                .target(target_kind::OAUTH_CLIENT, client_id.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!("reason" => "settings_self_serve")),
        )
        .await;
    }
    state.flash_redirect("/settings/authorized-apps", &msg)
}
