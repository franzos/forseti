//! `/settings/authorized-apps` — list and revoke OAuth2 consent grants the
//! user has given to downstream apps. Forseti-owned (no Kratos settings flow);
//! reads from Hydra's consent-session API and revokes per-client.

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::extractors::Csrf;
use crate::flash;
use crate::format::humanise_timestamp;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::render_error_boundary;
use crate::state::AppState;

/// Per-scope chip in the authorized-apps row. `description` is the
/// human label (from `config.toml`'s `oauth.scope_descriptions`); `name` is
/// the raw scope ID kept as a tooltip so power-users can still see it.
pub(crate) struct ScopeChip {
    pub(crate) name: String,
    pub(crate) description: String,
}

/// View-model for a single authorized app row.
pub(crate) struct AuthorizedAppView {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) client_uri: String,
    pub(crate) logo_uri: String,
    pub(crate) scopes: Vec<ScopeChip>,
    /// Absolute timestamp kept for hover tooltips.
    pub(crate) granted_at: String,
    /// Relative form ("3d ago") rendered as the primary timestamp.
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
    csrf: Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    let subject = sess.identity_id.clone();
    if subject.is_empty() {
        return render_error_boundary(
            &state,
            "Authorized apps unavailable",
            "We couldn't read your session. Please sign in again.",
            "/login",
            "Sign in",
        )
        .into_response();
    }

    let sessions = match ory::hydra::list_consent_sessions_by_subject(&state.ory, &subject).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = ?e, "list_consent_sessions failed");
            return render_error_boundary(
                &state,
                "Authorized apps unavailable",
                "We couldn't reach the OAuth service. Please try again in a moment.",
                "/settings",
                "Back to settings",
            )
            .into_response();
        }
    };

    let apps = collapse_sessions_to_apps(&state, sessions);

    let secure = state.cfg.self_.is_https();
    let (flash_msg, clear_flash) = flash::take_flash(
        &headers,
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        "/settings/authorized-apps",
        secure,
    );
    let body = render(&SettingsAuthorizedAppsTemplate {
        chrome: PageChrome::from_parts(&state, sess.email, csrf.0),
        apps,
        flash: flash_msg,
        referrer_banner: banner.0,
    });
    flash::attach_set_cookie(body, clear_flash)
}

/// Hydra returns one row per consent session; users that re-consent (or grant
/// the same client across several browser sessions) will appear multiple
/// times. The settings UI shows one row per client, so we fold sessions by
/// `client_id`, keeping the newest `handled_at` and the union of granted
/// scopes — that's what "Revoke access" is going to wipe anyway.
fn collapse_sessions_to_apps(
    state: &AppState,
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
                granted_at_pretty: humanise_timestamp(&granted_at),
                verified,
            });
        // Keep the newest grant timestamp.
        if !granted_at.is_empty() && granted_at.as_str() > entry.granted_at.as_str() {
            entry.granted_at_pretty = humanise_timestamp(&granted_at);
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

/// True when Hydra's stored `metadata.verified` flag is set on the client.
/// Mirrors the same heuristic the consent page uses to decide whether to
/// show the "Reviewed by your administrator" badge.
fn client_metadata_verified(client: &ory_client::models::OAuth2Client) -> bool {
    client
        .metadata
        .as_ref()
        .and_then(|m| m.get("verified"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[derive(Debug, Deserialize)]
pub(crate) struct RevokeForm {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: Option<String>,
}

pub(crate) async fn settings_authorized_apps_revoke(
    State(state): State<AppState>,
    axum::extract::Path(client_id): axum::extract::Path<String>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    Form(form): Form<RevokeForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let actor_id = sess.identity_id;
    let actor_email = sess.email;

    let secure = state.cfg.self_.is_https();
    let (msg, ok) =
        match ory::hydra::revoke_consent_sessions_for_client(&state.ory, &actor_id, &client_id)
            .await
        {
            Ok(()) => ("Access revoked.", true),
            Err(e) => {
                tracing::error!(error = ?e, client_id, "revoke_consent_for_client failed");
                ("Could not revoke access for that application.", false)
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
    let cookie = flash::store_flash(
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        "/settings/authorized-apps",
        msg,
        secure,
    );
    flash::redirect_with_cookie("/settings/authorized-apps", &cookie)
}
