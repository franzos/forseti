//! `GET /admin/clients/{id}` (detail) and `POST /admin/clients/{id}` (update).

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::admin::with_org;
use crate::admin::{render_admin_error, AdminSection};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::extractors::Csrf;
use crate::flash::{self, attach_set_cookie, SecretReveal};
use crate::oauth_client_metadata;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use crate::admin::clients::form::ClientForm;
use crate::admin::clients::projection::{
    project_row, read_client_type, read_require_pkce, ClientRow,
};
use crate::admin::clients::scope::RequireClientInScope;

/// Provider-wide OIDC endpoints shown on the "Connection details" card.
/// An empty doc (cold discovery failure) yields all-empty fields, which the
/// template hides per-row — so a failed fetch never shows a wrong issuer.
#[derive(Default)]
struct ConnectionDetails {
    issuer: String,
    discovery_url: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: String,
}

impl ConnectionDetails {
    fn from_discovery(d: crate::ory::discovery::OidcDiscovery) -> Self {
        Self {
            discovery_url: if d.issuer.is_empty() {
                String::new()
            } else {
                format!(
                    "{}/.well-known/openid-configuration",
                    d.issuer.trim_end_matches('/')
                )
            },
            issuer: d.issuer,
            authorization_endpoint: d.authorization_endpoint,
            token_endpoint: d.token_endpoint,
            userinfo_endpoint: d.userinfo_endpoint,
            jwks_uri: d.jwks_uri,
            end_session_endpoint: d.end_session_endpoint,
        }
    }
}

#[derive(askama::Template)]
#[template(path = "admin/client_show.html")]
struct ClientShowTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    row: ClientRow,
    scope: String,
    response_types: String,
    post_logout_redirect_uris: String,
    /// OIDC back-channel logout URI — read-only for the show-page row;
    /// editable via the embedded edit form below.
    backchannel_logout_uri: String,
    backchannel_logout_session_required: bool,
    frontchannel_logout_uri: String,
    frontchannel_logout_session_required: bool,
    token_endpoint_auth_method: String,
    skip_consent: bool,
    /// Selected grant types (for the embedded edit form's checkbox state).
    grant_types_selected: Vec<String>,
    /// Audience allow-list, newline-joined for the textarea.
    audience: String,
    require_pkce: bool,
    /// Phase 1: `client.metadata.forseti.account_deletion_url`. Empty
    /// string when not configured. Forseti signs the SET fan-out
    /// with its own RSA key (see `src/webhook.rs`); no per-client
    /// secret to mint.
    account_deletion_url: String,
    /// Scopes registered on this client that have no entry in
    /// `config.oauth.scope_descriptions`. Shown as a warning banner so
    /// the operator knows the consent screen will fall back to the raw
    /// scope name for those.
    missing_scope_descriptions: Vec<String>,
    /// One-time reveal: shown only when redirected here from create /
    /// rotate-secret. The handler reads `?secret_revealed=1` and looks up
    /// the most-recent secret out-of-band (we don't persist it ourselves —
    /// Hydra returns it in the response body of create/patch).
    secret_revealed: Option<String>,
    registration_access_token: Option<String>,
    /// Required post-create step from the app template (audience step etc.).
    /// Empty for non-template or note-less creations.
    setup_note: String,
    /// One-shot informational banner (e.g. "Client verified.") set by a
    /// redirect from the verify / unverify handler. Empty when no flash
    /// is pending.
    flash: String,
    /// `oauth_client_metadata.audience` — the DCR caller-declared
    /// audience string captured at registration. Empty when the row
    /// has none (operator-created clients, or DCR clients that
    /// didn't send `audience: [...]`).
    provenance_audience: String,
    /// `oauth_client_metadata.resource_url` — the first observed
    /// `resource=` URL (or fallback audience) seen at consent time.
    /// Empty when never captured.
    provenance_resource_url: String,
    /// Provider endpoints for the integrator-facing connection card.
    conn: ConnectionDetails,
    /// False only on a cold discovery failure (no cached doc) → the card
    /// hides the endpoints and shows the "couldn't reach Hydra" note. A
    /// stale-but-cached doc still counts as true (the values stay valid).
    discovery_ok: bool,
}

impl ClientShowTemplate {
    fn has_grant(&self, name: &str) -> bool {
        self.grant_types_selected.iter().any(|s| s == name)
    }
}

#[derive(Debug, Deserialize)]
pub struct ShowQuery {
    /// Opaque token for a one-shot secret reveal (`flash::take_secret_reveal`).
    /// Replaces the previous `?secret=...&rat=...` URL hand-off which leaked
    /// credentials into browser history and server logs.
    #[serde(default)]
    reveal: Option<String>,
}

pub async fn show(
    State(state): State<AppState>,
    Query(query): Query<ShowQuery>,
    headers: HeaderMap,
    client_in_scope: RequireClientInScope,
    csrf: Csrf,
) -> Response {
    let RequireClientInScope { id, ctx, .. } = client_in_scope;

    let client = match ory::hydra::get_client(&state.ory, &id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: get_client failed");
            return render_admin_error(
                &state,
                "Client unavailable",
                "We couldn't load that OAuth2 client. It may have been deleted.",
            );
        }
    };

    let meta = match oauth_client_metadata::get(&state.db, &id).await {
        Ok(m) => m,
        Err(e) => {
            // Render the page with legacy defaults rather than 500ing on
            // a DB hiccup — operators still want to inspect the Hydra
            // side of a client they're trying to triage.
            tracing::error!(error = ?e, id, "admin: oauth_client_metadata lookup failed for show; rendering with legacy defaults");
            None
        }
    };

    let reveal = match query.reveal.as_deref().filter(|s| !s.is_empty()) {
        Some(token) => {
            flash::take_secret_reveal(&state.db, state.cfg.flash.reveal_ttl_seconds, token).await
        }
        None => None,
    };

    let secure = state.cfg.self_.is_https();
    let show_path = format!("/admin/clients/{id}");
    let (flash_msg, clear_flash) = flash::take_flash(
        &headers,
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        &show_path,
        secure,
    );

    let chrome = ctx.chrome(&csrf);
    let (disc, discovery_ok) = state.openid_configuration().await;
    let tpl = build_show_view(
        client,
        meta,
        reveal,
        &state.cfg.oauth.scope_descriptions,
        chrome,
        flash_msg,
        disc,
        discovery_ok,
    );
    let resp = render(&tpl);
    attach_set_cookie(resp, clear_flash)
}

/// Pure projection from Hydra client + Forseti metadata row + reveal flash
/// into the show-page view-model. No DB / no cookies / no AppState.
// Flat arg list keeps this a pure, easily-tested projection — a params
// struct would only exist to dodge the lint.
#[allow(clippy::too_many_arguments)]
fn build_show_view(
    client: ory_client::models::OAuth2Client,
    meta: Option<oauth_client_metadata::Row>,
    reveal: Option<SecretReveal>,
    scope_descriptions: &std::collections::HashMap<String, String>,
    chrome: PageChrome,
    flash_msg: String,
    discovery: crate::ory::discovery::OidcDiscovery,
    discovery_ok: bool,
) -> ClientShowTemplate {
    // Provenance fields surfaced under the configuration block. Lifted
    // off the Forseti-owned `oauth_client_metadata` row before we hand
    // it to `project_row`, which discards them — the show page is the
    // only consumer.
    let (provenance_audience, provenance_resource_url) = match meta.as_ref() {
        Some(m) => (
            m.audience.clone().unwrap_or_default(),
            m.resource_url.clone().unwrap_or_default(),
        ),
        None => (String::new(), String::new()),
    };
    let row = project_row(&client, meta.as_ref());
    let scope_str = client.scope.clone().unwrap_or_default();
    let response_types = client.response_types.clone().unwrap_or_default().join(", ");
    let post_logout_redirect_uris = client
        .post_logout_redirect_uris
        .clone()
        .unwrap_or_default()
        .join(", ");
    let backchannel_logout_uri = client.backchannel_logout_uri.clone().unwrap_or_default();
    let backchannel_logout_session_required =
        client.backchannel_logout_session_required.unwrap_or(false);
    let frontchannel_logout_uri = client.frontchannel_logout_uri.clone().unwrap_or_default();
    let frontchannel_logout_session_required =
        client.frontchannel_logout_session_required.unwrap_or(false);
    let token_endpoint_auth_method = client
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_default();
    let skip_consent = client.skip_consent.unwrap_or(false);
    let grant_types_selected = client.grant_types.clone().unwrap_or_default();
    // One audience URI per line — matches the textarea format the edit
    // form expects on POST.
    let audience = client.audience.clone().unwrap_or_default().join("\n");
    let require_pkce = read_require_pkce(&client);
    // Diff this client's registered scopes against the documented set so
    // operators see which ones will show up as raw strings on the consent
    // screen. Sorted + deduped for stable rendering.
    let mut missing_scope_descriptions: Vec<String> = scope_str
        .split_whitespace()
        .filter(|s| {
            !s.is_empty()
                && !scope_descriptions.contains_key(*s)
                && crate::oauth::default_scope_description(s).is_none()
        })
        .map(str::to_string)
        .collect();
    missing_scope_descriptions.sort();
    missing_scope_descriptions.dedup();

    // Same `?reveal=` channel is used by create + rotate-secret. Pattern-
    // match on the variant so the template only sees the field(s)
    // relevant to the flow that minted the reveal.
    let (secret_revealed, registration_access_token, setup_note) = match reveal {
        Some(SecretReveal::ClientCreated {
            secret,
            registration_access_token,
            setup_note,
        }) => (
            Some(secret).filter(|s| !s.is_empty()),
            Some(registration_access_token).filter(|s| !s.is_empty()),
            setup_note,
        ),
        Some(SecretReveal::ClientSecretRotated { secret }) => {
            (Some(secret).filter(|s| !s.is_empty()), None, String::new())
        }
        _ => (None, None, String::new()),
    };

    let account_deletion_url = client
        .metadata
        .as_ref()
        .and_then(|m| m.get("forseti"))
        .and_then(|p| p.get("account_deletion_url"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let conn = ConnectionDetails::from_discovery(discovery);

    ClientShowTemplate {
        chrome,
        admin_active: AdminSection::Clients,
        row,
        scope: scope_str,
        response_types,
        post_logout_redirect_uris,
        backchannel_logout_uri,
        backchannel_logout_session_required,
        frontchannel_logout_uri,
        frontchannel_logout_session_required,
        token_endpoint_auth_method,
        skip_consent,
        grant_types_selected,
        audience,
        require_pkce,
        account_deletion_url,
        missing_scope_descriptions,
        secret_revealed,
        registration_access_token,
        setup_note,
        flash: flash_msg,
        provenance_audience,
        provenance_resource_url,
        conn,
        discovery_ok,
    }
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    client_in_scope: RequireClientInScope,
    actx: AuditCtx,
    Form(form): Form<ClientForm>,
) -> Response {
    let RequireClientInScope { id, ctx, scope } = client_in_scope;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    if let Err(e) = crate::webhook::validate_webhook_url(&form.account_deletion_url) {
        return render_admin_error(
            &state,
            "Account-deletion URL rejected",
            &format!("The webhook URL was not accepted: {e}"),
        );
    }

    // Round-trip the current client so we don't blow away unrelated fields.
    let existing = match ory::hydra::get_client(&state.ory, &id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: get_client for update failed");
            return render_admin_error(
                &state,
                "Client unavailable",
                "We couldn't load that OAuth2 client. It may have been deleted.",
            );
        }
    };
    let payload = form.to_oauth2_client(Some(existing));
    // Read the client_type back off the payload so the audit row matches
    // what actually got persisted (handles legacy edits where the form
    // didn't carry a `client_type` input).
    let client_type = read_client_type(&payload);
    match ory::hydra::update_client(&state.ory, &id, payload).await {
        Ok(_) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ADMIN_CLIENT_UPDATED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::OAUTH_CLIENT, id.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!("client_type" => client_type)),
            )
            .await;
            Redirect::to(&with_org(
                &format!("/admin/clients/{}", ory_client::apis::urlencode(&id)),
                &scope,
            ))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: update_client failed");
            render_admin_error(
                &state,
                "Update failed",
                &format!("Could not update client: {e}"),
            )
        }
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use crate::ory::discovery::OidcDiscovery;

    #[test]
    fn from_discovery_populates_endpoints_and_derives_discovery_url() {
        let disc = OidcDiscovery {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/oauth2/auth".to_string(),
            token_endpoint: "https://auth.example.com/oauth2/token".to_string(),
            userinfo_endpoint: "https://auth.example.com/userinfo".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            end_session_endpoint: "https://auth.example.com/oauth2/sessions/logout".to_string(),
            ..Default::default()
        };
        let conn = ConnectionDetails::from_discovery(disc);
        assert_eq!(conn.issuer, "https://auth.example.com");
        assert_eq!(conn.token_endpoint, "https://auth.example.com/oauth2/token");
        assert_eq!(
            conn.discovery_url,
            "https://auth.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn from_discovery_empty_doc_yields_all_empty_so_rows_hide() {
        // Cold-failure fallback: empty doc → every endpoint blank → the
        // template's per-row `{% if !conn.x.is_empty() %}` guards hide them.
        let conn = ConnectionDetails::from_discovery(OidcDiscovery::default());
        assert!(conn.issuer.is_empty());
        assert!(conn.discovery_url.is_empty());
        assert!(conn.token_endpoint.is_empty());
    }
}
