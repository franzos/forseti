//! `GET /admin/clients/new` (picker + pre-filled form) and `POST /admin/clients` (create).

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::admin::with_org;
use crate::admin::AdminSection;
use crate::audit::{self, action, target_kind, AuditCtx};
use crate::audit_metadata;
use crate::csrf::CsrfForm;
use crate::extractors::Csrf;
use crate::flash::{self, SecretReveal};
use crate::oauth_client_metadata;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::list::ListQuery;
use crate::admin::clients::app_templates::AppTemplate;
use crate::admin::clients::form::ClientForm;
use crate::admin::clients::presets::{picker_cards, ClientTypeCard, Preset};
use crate::admin::clients::scope::resolve_create_target_org;

/// Step-1 picker shown by `GET /admin/clients/new` (no `?type=`). Five
/// cards, each linking to `/admin/clients/new?type=<slug>`. No form on
/// this page — the picker just routes the operator to the right
/// pre-filled form.
#[derive(askama::Template)]
#[template(path = "admin/client_type_picker.html")]
struct ClientTypePickerTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    options: Vec<ClientTypeCard>,
    app_cards: Vec<crate::admin::clients::app_templates::AppCard>,
}

#[derive(askama::Template)]
#[template(path = "admin/client_form.html")]
struct ClientFormTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    /// Empty when creating; pre-filled when editing.
    id: String,
    name: String,
    /// Selected grant types — drives checkbox state. Each grant in this
    /// list renders as `checked`.
    grant_types_selected: Vec<String>,
    response_types: String,
    scope: String,
    redirect_uris: String,
    redirect_uri_hint: String,
    post_logout_redirect_uris: String,
    /// OIDC back-channel logout URI (`Option<String>` on the wire; rendered
    /// as a plain text input — empty = unset).
    backchannel_logout_uri: String,
    /// Per-preset placeholder for the back-channel input; empty hides it.
    backchannel_logout_uri_hint: String,
    backchannel_logout_session_required: bool,
    frontchannel_logout_uri: String,
    frontchannel_logout_uri_hint: String,
    frontchannel_logout_session_required: bool,
    token_endpoint_auth_method: String,
    skip_consent: bool,
    /// Whether the audience textarea is rendered. Set per preset; always
    /// shown on edit via the show page.
    audience_visible: bool,
    /// Multi-line audience list (one URI per line). Hydra's non-standard
    /// `audience` allow-list — used by MCP and other resource-server
    /// flows where the client requests a specific `aud`.
    audience: String,
    /// Informational Forseti-side flag: true → operator wants this client
    /// to require PKCE. Stored in `metadata.forseti.require_pkce`.
    /// Enforcement actually lives in Hydra config (`oauth2.pkce.enforced_for_public_clients`).
    require_pkce: bool,
    /// `client.metadata.forseti.account_deletion_url`: where to POST a signed
    /// delete notification on account self-deletion.
    account_deletion_url: String,
    /// Preset slug ("mcp" etc.) carried through the form as a hidden
    /// input so create() can stamp it into metadata. Empty when the
    /// operator hits the form without choosing a preset (legacy edits).
    preset_slug: String,
    /// Human label of the preset for the badge above the form. Empty
    /// suppresses the badge.
    preset_label: String,
    /// App-template slug carried through as a hidden input so a validation
    /// re-render keeps the template context. Empty when no template chosen.
    template_slug: String,
    /// Operator guidance banner (PROVIDER_NAME substitution etc.). Empty
    /// suppresses the banner.
    template_note: String,
    /// Guidance for the OIDC logout fan-out fieldset (app-specific). Empty
    /// suppresses it.
    template_logout_note: String,
    /// "Create" or "Save changes" on the submit button.
    submit_label: &'static str,
    /// Inline error message ("Failed to save: …"). Empty when no error.
    error_message: String,
}

impl ClientFormTemplate {
    /// Used from the template to drive checkbox `checked` state without
    /// resorting to closure syntax (Askama doesn't parse it).
    fn has_grant(&self, name: &str) -> bool {
        self.grant_types_selected.iter().any(|s| s == name)
    }

    /// Single point of truth for the create form: editable values from
    /// `form`, hints + visibility from the resolved `preset`. Shared by
    /// the preset-prefill and the validation re-render.
    fn from_form(
        chrome: PageChrome,
        form: &ClientForm,
        preset: Option<Preset>,
        template: Option<&AppTemplate>,
        error_message: String,
    ) -> Self {
        let defaults = preset.map(|p| p.defaults());
        let hint = |pick: fn(&crate::admin::clients::presets::PresetDefaults) -> &'static str| {
            defaults
                .as_ref()
                .map(|d| pick(d).to_string())
                .unwrap_or_default()
        };
        Self {
            chrome,
            admin_active: AdminSection::Clients,
            id: String::new(),
            name: form.name.clone(),
            grant_types_selected: form.grant_types.clone(),
            response_types: form.response_types.clone(),
            scope: form.scope.clone(),
            redirect_uris: form.redirect_uris.clone(),
            redirect_uri_hint: hint(|d| d.redirect_uri_hint),
            post_logout_redirect_uris: form.post_logout_redirect_uris.clone(),
            backchannel_logout_uri: form.backchannel_logout_uri.clone(),
            backchannel_logout_uri_hint: hint(|d| d.backchannel_logout_uri_hint),
            backchannel_logout_session_required: form.backchannel_logout_session_required_flag(),
            frontchannel_logout_uri: form.frontchannel_logout_uri.clone(),
            frontchannel_logout_uri_hint: hint(|d| d.frontchannel_logout_uri_hint),
            frontchannel_logout_session_required: form.frontchannel_logout_session_required_flag(),
            token_endpoint_auth_method: form.token_endpoint_auth_method.clone(),
            skip_consent: form.skip_consent_flag(),
            // Template flag is authoritative when a template is present;
            // otherwise a known preset honours its visibility default and an
            // unknown preset (legacy edit) renders the textarea.
            audience_visible: if let Some(t) = template {
                t.audience_visible
            } else {
                defaults
                    .as_ref()
                    .map(|d| d.audience_visible)
                    .unwrap_or(true)
            },
            audience: form.audience.clone(),
            require_pkce: form.require_pkce_flag(),
            account_deletion_url: form.account_deletion_url.clone(),
            preset_slug: form.client_type.clone(),
            preset_label: preset.map(|p| p.label().to_string()).unwrap_or_default(),
            template_slug: template.map(|t| t.slug.to_string()).unwrap_or_default(),
            template_note: template
                .and_then(|t| t.note)
                .unwrap_or_default()
                .to_string(),
            template_logout_note: template
                .and_then(|t| t.logout_guidance())
                .unwrap_or_default()
                .to_string(),
            submit_label: "Create client",
            error_message,
        }
    }
}

/// Empty form pre-loaded with the preset's editable defaults, so the
/// initial `GET .../new?type=` render flows through `from_form` like the
/// re-render does. Hints/visibility are derived from the preset there.
fn seed_form_from_preset(preset: Preset) -> ClientForm {
    let defaults = preset.defaults();
    ClientForm {
        name: String::new(),
        grant_types: defaults
            .grant_types
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        response_types: defaults.response_types.to_string(),
        scope: defaults.scope.to_string(),
        redirect_uris: String::new(),
        post_logout_redirect_uris: String::new(),
        backchannel_logout_uri: String::new(),
        frontchannel_logout_uri: String::new(),
        backchannel_logout_session_required: None,
        frontchannel_logout_session_required: None,
        token_endpoint_auth_method: defaults.token_endpoint_auth_method.to_string(),
        audience: String::new(),
        require_pkce: defaults.require_pkce.then(|| "on".to_string()),
        skip_consent: None,
        account_deletion_url: String::new(),
        client_type: preset.slug().to_string(),
        template: String::new(),
    }
}

/// Empty form pre-loaded with an app template: base-preset technical
/// defaults + the template's app-specific overrides (concrete redirect
/// URIs, scope, auth method, PKCE, logout/webhook URLs). Flows through the
/// same `from_form` assembly as presets.
fn seed_form_from_template(t: &AppTemplate) -> ClientForm {
    let mut form = seed_form_from_preset(t.base_preset);
    form.name = t.client_name.to_string();
    form.grant_types = t.grant_types.iter().map(|s| (*s).to_string()).collect();
    form.scope = t.scope.to_string();
    form.token_endpoint_auth_method = t.token_endpoint_auth_method.to_string();
    form.require_pkce = t.require_pkce.then(|| "on".to_string());
    form.redirect_uris = t.redirect_uris_joined();
    form.post_logout_redirect_uris = t.post_logout_joined();
    form.backchannel_logout_uri = t.backchannel_logout_uri.unwrap_or_default().to_string();
    form.account_deletion_url = t.account_deletion_url.unwrap_or_default().to_string();
    form.template = t.slug.to_string();
    form
}

#[derive(Debug, Deserialize)]
pub(crate) struct NewQuery {
    /// Preset slug — picks the application-type defaults. Absent → show
    /// the picker. Unknown → redirect back to the picker.
    #[serde(rename = "type", default)]
    type_: Option<String>,
    /// App-template slug — picks a curated "popular app" prefill. Absent →
    /// fall through to the preset/picker logic. Unknown → bounce to picker.
    #[serde(default)]
    template: Option<String>,
}

/// `GET /admin/clients/new` — picker (no `?type=`), pre-filled form
/// (recognised `?type=`), or redirect to the picker (unknown `?type=`).
pub async fn new(
    Query(query): Query<NewQuery>,
    admin: crate::extractors::RequireAdminScoped,
    csrf: Csrf,
) -> Response {
    let ctx = admin.ctx;
    let chrome = ctx.chrome(&csrf);

    // App template takes precedence over a bare ?type=.
    if let Some(slug) = query.template.as_deref().filter(|s| !s.is_empty()) {
        return match AppTemplate::from_slug(slug) {
            Some(t) => {
                let seed = seed_form_from_template(t);
                render(&ClientFormTemplate::from_form(
                    chrome,
                    &seed,
                    Some(t.base_preset),
                    Some(t),
                    String::new(),
                ))
            }
            None => Redirect::to("/admin/clients/new").into_response(),
        };
    }

    match query.type_.as_deref() {
        None | Some("") => render(&ClientTypePickerTemplate {
            chrome,
            admin_active: AdminSection::Clients,
            options: picker_cards(),
            app_cards: crate::admin::clients::app_templates::app_template_cards(),
        }),
        Some(slug) => match Preset::from_slug(slug) {
            Some(preset) => {
                let seed = seed_form_from_preset(preset);
                render(&ClientFormTemplate::from_form(
                    chrome,
                    &seed,
                    Some(preset),
                    None,
                    String::new(),
                ))
            }
            // Unknown slug bounces to the picker, so a stale link doesn't
            // land on a half-filled form.
            None => Redirect::to("/admin/clients/new").into_response(),
        },
    }
}

pub async fn create(
    State(state): State<AppState>,
    Query(_query): Query<ListQuery>,
    headers: HeaderMap,
    admin: crate::extractors::RequireAdminScoped,
    csrf: Csrf,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<ClientForm>,
) -> Response {
    let ctx = admin.ctx;
    let scope = admin.scope;

    // Re-render preserving every typed field so a validation/Hydra error
    // doesn't wipe the operator's input.
    let rerender = |error_message: String| -> Response {
        let chrome = ctx.chrome(&csrf);
        let preset = Preset::from_slug(&form.client_type);
        let template = AppTemplate::from_slug(&form.template);
        render(&ClientFormTemplate::from_form(
            chrome,
            &form,
            preset,
            template,
            error_message,
        ))
    };

    if let Err(e) = crate::webhook::validate_webhook_url(&form.account_deletion_url) {
        return rerender(lookup_with_error(
            &ctx.locale,
            "flash-client-account-deletion-url-rejected",
            &e.to_string(),
        ));
    }

    let client_name = form.name.clone();
    let client_type = form.client_type.clone();
    let payload = form.to_oauth2_client(None);
    match ory::hydra::create_client(&state.ory, payload).await {
        Ok(mut new) => {
            let id = new.client_id.clone().unwrap_or_default();
            let template = AppTemplate::from_slug(&form.template);

            // rusty-common apps (Formshive) send audience=<their own
            // client_id>; Hydra only stamps an aud the client is allow-listed
            // for, so fold the freshly generated id into the audience and
            // PUT it back. Hydra has already committed, so a failure here
            // only loses the convenience — never the client.
            let mut audience_set = false;
            if !id.is_empty() && template.is_some_and(|t| t.self_audience) {
                let mut audience = new.audience.clone().unwrap_or_default();
                if !audience.iter().any(|a| a == &id) {
                    audience.push(id.clone());
                }
                new.audience = Some(audience);
                match ory::hydra::update_client(&state.ory, &id, new.clone()).await {
                    Ok(_) => audience_set = true,
                    Err(e) => {
                        tracing::error!(
                            error = ?e,
                            client_id = %id,
                            "admin: create_client succeeded but self-audience update failed — \
                             operator must add the client's own ID to its audience allow-list manually",
                        );
                    }
                }
            }
            // Admin-created clients are implicitly verified (creating via the
            // form is the vouching). DCR clients arrive via `/oauth2/register`
            // as `source = "dcr"` + `verification = "unverified"`. INSERT
            // failure is logged but doesn't fail the create (Hydra already
            // committed); the row is created lazily on first verify/unverify.
            if !id.is_empty() {
                let target_org = resolve_create_target_org(&state, &headers, &ctx, &scope).await;
                if let Err(e) = oauth_client_metadata::insert_admin_verified(
                    &state.db,
                    &id,
                    &ctx.email,
                    &target_org,
                    // Persist the resolved compile-time slug, never the raw
                    // operator-supplied string — junk never reaches the column.
                    AppTemplate::from_slug(&form.template).map(|t| t.slug),
                    chrono::Utc::now(),
                )
                .await
                {
                    tracing::error!(
                        error = ?e,
                        client_id = %id,
                        "admin: create_client succeeded but Forseti metadata INSERT failed — \
                         client will render as verified (legacy fallback) until reconciled",
                    );
                }
            }
            let _ = audit::log(
                &state.db,
                ctx.audit_event(action::ADMIN_CLIENT_CREATED, &actx)
                    .target(target_kind::OAUTH_CLIENT, id.clone())
                    .metadata(audit_metadata!(
                        "client_name" => client_name,
                        "client_type" => client_type,
                    )),
            )
            .await;
            // Stash the secret + token server-side; redirect with only a
            // UUID-shaped token, so the secret never lands in browser history,
            // logs, or a proxy/CDN in the redirect chain.
            let reveal = SecretReveal::ClientCreated {
                secret: new.client_secret.clone().unwrap_or_default(),
                registration_access_token: new
                    .registration_access_token
                    .clone()
                    .unwrap_or_default(),
                // On a successful self-audience update the manual instruction
                // is redundant; on failure fall back to it so the operator
                // can fix it by hand.
                setup_note: if template.is_some_and(|t| t.self_audience) && audience_set {
                    "This client's ID was added to its audience allow-list automatically."
                        .to_string()
                } else {
                    template
                        .and_then(|t| t.post_create_note)
                        .unwrap_or_default()
                        .to_string()
                },
            };
            let token = match flash::store_secret_reveal(
                &state.db,
                state.cfg.flash.reveal_ttl_seconds,
                reveal,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    // Hydra has the client; audit row landed. Don't
                    // strand the operator on a generic error page —
                    // bounce to the show page (where the rotate-secret
                    // button lives) with a flash banner so they can
                    // recover the secret on the next click.
                    tracing::error!(error = ?e, id, "admin: client_created reveal store failed");
                    let target = with_org(
                        &format!("/admin/clients/{}", ory_client::apis::urlencode(&id)),
                        &scope,
                    );
                    return state.flash_redirect(
                        &target,
                        &crate::i18n::lookup(&ctx.locale, "flash-client-secret-stage-failed"),
                    );
                }
            };
            let url = with_org(
                &format!(
                    "/admin/clients/{}?reveal={}",
                    ory_client::apis::urlencode(&id),
                    ory_client::apis::urlencode(&token),
                ),
                &scope,
            );
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, "admin: create_client failed");
            rerender(lookup_with_error(
                &ctx.locale,
                "flash-client-create-failed",
                &e.to_string(),
            ))
        }
    }
}

/// Look up `key` binding the developer error detail to `$error`. Kept local
/// because both create failure paths interpolate an upstream error string.
fn lookup_with_error(locale: &crate::locale::LanguageIdentifier, key: &str, error: &str) -> String {
    let mut args: std::collections::HashMap<
        std::borrow::Cow<'static, str>,
        fluent_templates::fluent_bundle::FluentValue,
    > = std::collections::HashMap::new();
    args.insert(
        std::borrow::Cow::Borrowed("error"),
        error.to_string().into(),
    );
    crate::i18n::lookup_args(locale, key, &args)
}

#[cfg(test)]
mod template_seed_tests {
    use super::*;
    use crate::admin::clients::app_templates::AppTemplate;

    #[test]
    fn seed_from_gitlab_template_fills_app_fields() {
        let t = AppTemplate::from_slug("gitlab").unwrap();
        let form = seed_form_from_template(t);
        assert_eq!(form.scope, "openid profile email");
        assert_eq!(form.token_endpoint_auth_method, "client_secret_basic");
        assert_eq!(
            form.redirect_uris,
            "https://YOUR_DOMAIN/users/auth/openid_connect/callback"
        );
        // Base preset (web_app) drives the technical defaults + stamped type.
        assert_eq!(form.client_type, "web_app");
        assert!(form.grant_types.contains(&"authorization_code".to_string()));
        assert!(form.require_pkce.is_none());
        assert!(!form.grant_types.contains(&"refresh_token".to_string()));
    }

    #[test]
    fn seed_from_formshive_template_fills_webhook_and_backchannel() {
        let t = AppTemplate::from_slug("formshive").unwrap();
        let form = seed_form_from_template(t);
        assert_eq!(
            form.backchannel_logout_uri,
            "https://YOUR_DOMAIN/v1/auth/oidc/backchannel-logout"
        );
        assert_eq!(
            form.account_deletion_url,
            "https://YOUR_DOMAIN/v1/auth/oidc/account-deletion-webhook"
        );
        assert!(form.scope.contains("offline_access"));
        assert_eq!(form.require_pkce.as_deref(), Some("on"));
    }

    #[test]
    fn seed_from_immich_joins_multiple_redirects() {
        let t = AppTemplate::from_slug("immich").unwrap();
        let form = seed_form_from_template(t);
        let lines: Vec<&str> = form.redirect_uris.lines().collect();
        assert_eq!(lines.len(), 3);
        // Custom-scheme mobile URIs are dropped (Hydra is HTTPS-only); the
        // third URI is Immich's HTTPS mobile relay.
        assert_eq!(lines[2], "https://YOUR_DOMAIN/api/oauth/mobile-redirect");
    }
}
