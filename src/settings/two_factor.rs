//! `/settings/2fa` — enrol / unlink TOTP, recovery codes, and WebAuthn /
//! passkey credentials. The flow groups multiple Kratos credential methods
//! together so the renderer is bespoke (the shared profile/password renderer
//! doesn't fit).

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::FlowQuery;
use crate::backend::identity::Session;
use crate::flow_view::{
    Flow, InputView, MessageView, ScriptView, translate_inputs, translate_messages,
};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::{SettingsSection, fetch_settings_subpage};

#[derive(Template)]
#[template(path = "settings_2fa.html")]
pub(crate) struct Settings2faTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    pub(crate) hidden_defaults: Vec<InputView>,
    pub(crate) totp_nodes: Vec<InputView>,
    /// `data:image/png;base64,…` QR for TOTP enrolment (None when enrolled).
    pub(crate) totp_qr: Option<String>,
    pub(crate) totp_secret: Option<String>,
    pub(crate) totp_enrolled: bool,
    pub(crate) lookup_nodes: Vec<InputView>,
    /// Present only on the render right after regeneration; Kratos discards
    /// them on subsequent fetches.
    pub(crate) lookup_codes: Vec<String>,
    pub(crate) lookup_enrolled: bool,
    /// Device factor enrolled but no recovery codes: the lone state where
    /// losing the device means permanent lockout. Drives the warning banner.
    pub(crate) needs_recovery_codes: bool,
    /// True only on the render right after regenerating lookup codes;
    /// distinguishes "show new codes" from "lookup is configured".
    pub(crate) lookup_just_regenerated: bool,
    /// Empty when the operator hasn't enabled webauthn in `kratos.yml`.
    pub(crate) webauthn_nodes: Vec<InputView>,
    pub(crate) webauthn_enabled: bool,
    /// Kratos-served `/.well-known/ory/webauthn.js` helper, rendered verbatim so
    /// it agrees with the running Kratos's flow wire format.
    pub(crate) webauthn_scripts: Vec<ScriptView>,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

pub(crate) async fn settings_2fa(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: crate::extractors::Csrf,
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    match fetch_settings_subpage(
        &state,
        &headers,
        &query,
        SettingsSection::TwoFactor,
        &sess,
        &locale,
    )
    .await
    {
        Ok((session, flow)) => {
            let memberships = crate::orgs::list_memberships(&state.db, &sess.identity_id)
                .await
                .unwrap_or_default();
            render_2fa(
                &state,
                &memberships,
                &headers,
                &csrf.0,
                &session,
                &flow,
                banner.0,
                locale,
            )
        }
        Err(resp) => resp,
    }
}

#[allow(clippy::too_many_arguments)]
fn render_2fa(
    state: &AppState,
    memberships: &[crate::orgs::Membership],
    headers: &HeaderMap,
    csrf_token: &str,
    session: &Session,
    flow: &Flow,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
    locale: crate::locale::LanguageIdentifier,
) -> Response {
    let group = |name: &str| -> Vec<InputView> { flow.inputs(name).cloned().collect() };
    let mut hidden_defaults = flow.default_hidden();
    let mut totp_nodes = group("totp");
    let mut lookup_nodes = group("lookup_secret");
    let mut webauthn_nodes = group("webauthn");
    let mut passkey_nodes = group("passkey");
    translate_inputs(&mut hidden_defaults, &locale);
    translate_inputs(&mut totp_nodes, &locale);
    translate_inputs(&mut lookup_nodes, &locale);
    translate_inputs(&mut webauthn_nodes, &locale);
    translate_inputs(&mut passkey_nodes, &locale);
    webauthn_nodes.extend(passkey_nodes);

    // Promote the non-destructive CTA in each section (Verify / Generate / Add
    // key); unlink/disable/regenerate stay secondary.
    promote_primary(&mut totp_nodes, &["totp_code"]);
    promote_primary(
        &mut lookup_nodes,
        &["lookup_secret_confirm", "lookup_secret_regenerate"],
    );
    promote_primary(&mut webauthn_nodes, &["webauthn_register_trigger"]);

    let totp_enrolled = flow.has_node("totp", "totp_unlink");
    // `lookup_enrolled`: Kratos emits `lookup_secret_disable` when there's an
    // enrolment to tear down. `lookup_just_regenerated`: the one render where
    // Kratos emits `lookup_secret_reveal` plus the plaintext codes.
    let lookup_enrolled = flow.has_node("lookup_secret", "lookup_secret_disable");
    let lookup_codes = flow.lookup_codes.clone();
    let lookup_just_regenerated =
        flow.has_node("lookup_secret", "lookup_secret_reveal") && !lookup_codes.is_empty();
    let webauthn_enabled = !webauthn_nodes.is_empty();
    // Enrolment (vs merely-enabled) is signalled by the per-credential remove
    // node Kratos emits for each registered authenticator.
    let webauthn_enrolled =
        flow.has_node("webauthn", "webauthn_remove") || flow.has_node("passkey", "passkey_remove");
    let needs_recovery_codes = (totp_enrolled || webauthn_enrolled) && !lookup_enrolled;
    let webauthn_scripts = flow.webauthn_scripts();

    let mut msgs = flow.messages.clone();
    translate_messages(&mut msgs, &locale);
    render(&Settings2faTemplate {
        chrome: PageChrome::from_parts_themed(
            state,
            memberships,
            headers,
            session.email(),
            session.addresses(),
            csrf_token.to_string(),
            locale,
        ),
        form_action: flow.form_action.clone(),
        form_method: flow.form_method.clone(),
        flow_messages: msgs,
        hidden_defaults,
        totp_nodes,
        totp_qr: flow.totp_qr.clone(),
        totp_secret: flow.totp_secret.clone(),
        totp_enrolled,
        lookup_nodes,
        lookup_codes,
        lookup_enrolled,
        needs_recovery_codes,
        lookup_just_regenerated,
        webauthn_nodes,
        webauthn_enabled,
        webauthn_scripts,
        referrer_banner,
    })
}

/// Mark the input named in `primary_names` as the form's primary CTA, falling
/// back to the first non-destructive button.
///
/// `"button"` is included because Kratos's WebAuthn / passkey trigger nodes are
/// `type="button"` (clicks fire JS, not a submit); excluding them leaves those
/// forms with no primary-styled action.
fn promote_primary(nodes: &mut [InputView], primary_names: &[&str]) {
    let is_button = |n: &InputView| n.input_type == "submit" || n.input_type == "button";
    let mut found = false;
    for node in nodes.iter_mut() {
        if is_button(node) && primary_names.contains(&node.name.as_str()) {
            node.is_primary = true;
            found = true;
        }
    }
    if !found {
        // Never promote a destructive action (e.g. a `webauthn_remove` button
        // Kratos emits before the add trigger).
        let is_destructive = |n: &InputView| n.name.ends_with("_remove");
        if let Some(first) = nodes
            .iter_mut()
            .find(|n| is_button(n) && !is_destructive(n))
        {
            first.is_primary = true;
        }
    }
}
