//! `/settings/2fa` — enrol / unlink TOTP, recovery codes, and WebAuthn /
//! passkey credentials. The flow groups multiple Kratos credential methods
//! together so the renderer is bespoke (the shared profile/password renderer
//! doesn't fit).

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::flow_view::{
    collect_default_hidden, collect_input_nodes, collect_webauthn_scripts, flow_messages,
    form_target, group_has_node, lookup_codes, session_email, totp_qr_and_secret, InputView,
    MessageView, ScriptView,
};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;
use crate::FlowQuery;

use super::{fetch_settings_subpage, SettingsSection};

#[derive(Template)]
#[template(path = "settings_2fa.html")]
pub(crate) struct Settings2faTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    /// CSRF + method hiddens emitted on every sub-form.
    pub(crate) hidden_defaults: Vec<InputView>,
    /// TOTP group nodes (input fields + submit buttons).
    pub(crate) totp_nodes: Vec<InputView>,
    /// `data:image/png;base64,…` QR for TOTP enrolment (None when already enrolled).
    pub(crate) totp_qr: Option<String>,
    /// Plain-text secret matching the QR (None when already enrolled).
    pub(crate) totp_secret: Option<String>,
    /// True when the identity has TOTP enabled (Kratos emits a `totp_unlink` node).
    pub(crate) totp_enrolled: bool,
    /// Lookup-secret group nodes (generate/regenerate/disable submits).
    pub(crate) lookup_nodes: Vec<InputView>,
    /// Freshly generated lookup codes (only present on the render right after
    /// regeneration — Kratos discards them on subsequent fetches).
    pub(crate) lookup_codes: Vec<String>,
    /// True when the identity has recovery codes configured (Kratos emits a
    /// `lookup_secret_disable` node).
    pub(crate) lookup_enrolled: bool,
    /// True on the single render right after regenerating lookup codes —
    /// Kratos emits a `lookup_secret_reveal` node alongside the plaintext
    /// codes. Templates use this to distinguish "show new codes" from the
    /// general "lookup is configured" state.
    pub(crate) lookup_just_regenerated: bool,
    /// WebAuthn / passkey group nodes. Empty when the operator hasn't
    /// enabled webauthn in `kratos.yml`.
    pub(crate) webauthn_nodes: Vec<InputView>,
    /// True iff the operator enabled webauthn (i.e. Kratos emitted any
    /// webauthn nodes on this flow). Drives the "Passkey support not enabled"
    /// fallback.
    pub(crate) webauthn_enabled: bool,
    /// `<script>` tags Kratos asks us to inject for the webauthn / passkey
    /// flow — typically a single entry pointing at the Kratos-served
    /// `/.well-known/ory/webauthn.js` helper, version-matched to the running
    /// Kratos instance. Rendered verbatim (src + integrity + …) so the helper
    /// always agrees with the flow's wire format.
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
) -> Response {
    match fetch_settings_subpage(&state, &headers, &query, SettingsSection::TwoFactor, &sess).await
    {
        Ok((session, flow)) => render_2fa(&state, &csrf.0, &session, &flow, banner.0),
        Err(resp) => resp,
    }
}

fn render_2fa(
    state: &AppState,
    csrf_token: &str,
    session: &ory::Session,
    flow: &serde_json::Value,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
) -> Response {
    let (form_action, form_method) = form_target(flow);
    let hidden_defaults = collect_default_hidden(flow);
    let mut totp_nodes = collect_input_nodes(flow, "totp");
    let mut lookup_nodes = collect_input_nodes(flow, "lookup_secret");
    let mut webauthn_nodes = collect_input_nodes(flow, "webauthn");
    webauthn_nodes.extend(collect_input_nodes(flow, "passkey"));

    // Promote the primary CTA in each section to filled-button styling so the
    // form's intent reads clearly. The "primary" submit is the one without a
    // destructive intent — Verify (TOTP confirm), Generate (lookup), Add key
    // (webauthn). Unlink/disable/regenerate stay as secondary buttons.
    promote_primary(&mut totp_nodes, &["totp_code"]);
    promote_primary(
        &mut lookup_nodes,
        &["lookup_secret_confirm", "lookup_secret_regenerate"],
    );
    promote_primary(&mut webauthn_nodes, &["webauthn_register_displayname"]);

    let (totp_qr, totp_secret) = totp_qr_and_secret(flow);
    let totp_enrolled = group_has_node(flow, "totp", "totp_unlink");
    // Two related states that the previous heuristic conflated:
    //   * `lookup_enrolled`: identity has lookup-secret codes configured.
    //     Kratos emits the `lookup_secret_disable` node when there's an
    //     existing enrolment that can be torn down.
    //   * `lookup_just_regenerated`: this is the one render-pass right after
    //     regeneration where Kratos emits a `lookup_secret_reveal` node AND
    //     a non-empty list of plaintext codes. The codes are shown once;
    //     subsequent fetches discard them.
    let lookup_enrolled = group_has_node(flow, "lookup_secret", "lookup_secret_disable");
    let lookup_codes = lookup_codes(flow);
    let lookup_just_regenerated =
        group_has_node(flow, "lookup_secret", "lookup_secret_reveal") && !lookup_codes.is_empty();
    let webauthn_enabled = !webauthn_nodes.is_empty();
    let webauthn_scripts = collect_webauthn_scripts(flow);

    render(&Settings2faTemplate {
        chrome: PageChrome::from_parts(state, session_email(session), csrf_token.to_string()),
        form_action,
        form_method,
        flow_messages: flow_messages(flow),
        hidden_defaults,
        totp_nodes,
        totp_qr,
        totp_secret,
        totp_enrolled,
        lookup_nodes,
        lookup_codes,
        lookup_enrolled,
        lookup_just_regenerated,
        webauthn_nodes,
        webauthn_enabled,
        webauthn_scripts,
        referrer_banner,
    })
}

/// Mark the submit/button input whose `name` is in `primary_names` as the
/// form's primary CTA. If no match is found, the first submit-or-button in
/// the list is promoted so the form still has a visually-dominant action.
///
/// `"button"` is included because Kratos's WebAuthn / passkey trigger nodes
/// are `type="button"` (clicks fire JS via `onclickTrigger`, not a form
/// submit). Without including them, those forms would render with no
/// primary-styled action and look broken.
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
        if let Some(first) = nodes.iter_mut().find(|n| is_button(n)) {
            first.is_primary = true;
        }
    }
}
