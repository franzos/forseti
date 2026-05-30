//! `GET /admin/clients/new` (picker + pre-filled form) and `POST /admin/clients` (create).

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::admin::with_org;
use crate::admin::AdminSection;
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::extractors::Csrf;
use crate::flash::{self, redirect_with_cookie, SecretReveal};
use crate::oauth_client_metadata;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::list::ListQuery;
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
    /// `client.metadata.forseti.account_deletion_url` — POST'd by the
    /// user when an app, hit, wants to receive a signed delete
    /// notification on account self-deletion (Phase 1).
    account_deletion_url: String,
    /// Preset slug ("mcp" etc.) carried through the form as a hidden
    /// input so create() can stamp it into metadata. Empty when the
    /// operator hits the form without choosing a preset (legacy edits).
    preset_slug: String,
    /// Human label of the preset for the badge above the form. Empty
    /// suppresses the badge.
    preset_label: String,
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
            // Unknown preset → render the audience textarea (legacy edits
            // need it); a known preset honours its visibility default.
            audience_visible: defaults
                .as_ref()
                .map(|d| d.audience_visible)
                .unwrap_or(true),
            audience: form.audience.clone(),
            require_pkce: form.require_pkce_flag(),
            account_deletion_url: form.account_deletion_url.clone(),
            preset_slug: form.client_type.clone(),
            preset_label: preset.map(|p| p.label().to_string()).unwrap_or_default(),
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
        csrf: None,
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
    }
}

#[derive(Debug, Deserialize)]
pub struct NewQuery {
    /// Preset slug — picks the application-type defaults. Absent → show
    /// the picker. Unknown → redirect back to the picker.
    #[serde(rename = "type", default)]
    type_: Option<String>,
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

    match query.type_.as_deref() {
        // No `?type=` → show the picker.
        None | Some("") => render(&ClientTypePickerTemplate {
            chrome,
            admin_active: AdminSection::Clients,
            options: picker_cards(),
        }),
        // Recognised slug → form pre-filled from the preset defaults.
        Some(slug) => match Preset::from_slug(slug) {
            Some(preset) => {
                // Seed an empty form with the preset's editable defaults,
                // then share the field assembly with the re-render path.
                let seed = seed_form_from_preset(preset);
                render(&ClientFormTemplate::from_form(
                    chrome,
                    &seed,
                    Some(preset),
                    String::new(),
                ))
            }
            // Unknown slug → bounce to the picker so the operator picks
            // one consciously. Avoids a stale link silently landing on a
            // half-filled form.
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
    Form(form): Form<ClientForm>,
) -> Response {
    let ctx = admin.ctx;
    let scope = admin.scope;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    // Helper: re-render the form preserving every field the operator just
    // typed, so a validation/Hydra error doesn't wipe their input. Used by
    // both error branches below.
    let rerender = |error_message: String| -> Response {
        let chrome = ctx.chrome(&csrf);
        let preset = Preset::from_slug(&form.client_type);
        render(&ClientFormTemplate::from_form(
            chrome,
            &form,
            preset,
            error_message,
        ))
    };

    if let Err(e) = crate::webhook::validate_webhook_url(&form.account_deletion_url) {
        return rerender(format!("Account-deletion URL rejected: {e}"));
    }

    let client_name = form.name.clone();
    let client_type = form.client_type.clone();
    let payload = form.to_oauth2_client(None);
    match ory::hydra::create_client(&state.ory, payload).await {
        Ok(new) => {
            let id = new.client_id.clone().unwrap_or_default();
            // Admin-created clients are implicitly verified — the act of
            // an operator creating the client through the form is the
            // vouching. Stamp the Forseti-side metadata row so the show
            // page and consent screen don't need a separate
            // "creator implicitly trusted" branch. DCR-registered
            // clients arrive via `/oauth2/register` (different handler),
            // which inserts `source = "dcr"` + `verification = "unverified"`.
            // INSERT failure here is logged but doesn't fail the create
            // (Hydra has already committed); the row will be created
            // lazily on first verify/unverify if it's missing.
            if !id.is_empty() {
                // Org targeting precedence:
                //   1. AdminScope::Org → that org's id (caller is acting
                //      as owner of an explicit org via `?org=<slug>`).
                //   2. AdminScope::Forseti → admin's active-org cookie
                //      via `orgs::active_org`. Non-Default targets are
                //      re-gated on the Orgs license so a Forseti admin
                //      whose cookie points at a non-Default org can't
                //      sneak a client into a locked org via direct POST.
                //   3. Default org as the final fallback.
                let target_org = resolve_create_target_org(&state, &headers, &ctx, &scope).await;
                if let Err(e) = oauth_client_metadata::insert_admin_verified(
                    &state.db,
                    &id,
                    &ctx.email,
                    &target_org,
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
                AuditEvent::new(action::ADMIN_CLIENT_CREATED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::OAUTH_CLIENT, id.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!(
                        "client_name" => client_name,
                        "client_type" => client_type,
                    )),
            )
            .await;
            // Stash the secret + registration token server-side and
            // redirect with only a UUID-shaped token in the URL. Avoids
            // leaking the freshly minted secret into browser history,
            // server logs, or any proxy/CDN in the redirect chain.
            let reveal = SecretReveal::ClientCreated {
                secret: new.client_secret.clone().unwrap_or_default(),
                registration_access_token: new
                    .registration_access_token
                    .clone()
                    .unwrap_or_default(),
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
                    let cookie = flash::store_flash(
                        &state.cookie_secret,
                        state.cfg.flash.cookie_ttl_seconds,
                        &target,
                        "Client created, but we couldn't stage the secret for one-shot \
                         display. Rotate the secret to retrieve a fresh value.",
                        state.cfg.self_.is_https(),
                    );
                    return redirect_with_cookie(&target, &cookie);
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
            rerender(format!("Failed to create client: {e}"))
        }
    }
}
