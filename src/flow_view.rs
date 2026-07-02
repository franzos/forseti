//! Flow view-models: pre-shape Kratos's raw flow JSON into template-iterable structs, sidestepping
//! `ory_client`'s untagged enums (which can't deserialize, see ory.rs). Grouping by Kratos `node.group`
//! drives the visual layout (OIDC stack, code shortcut, profile/password form, OR-divider).

use crate::locale::LanguageIdentifier;
use crate::ory::{self, FlowKind};

/// A single input field projected from a `UiNode` whose attributes are `Input`.
#[derive(Default)]
pub(crate) struct InputView {
    pub(crate) name: String,
    /// HTML `type=` attribute (`text`, `password`, `hidden`, `submit`, …).
    pub(crate) input_type: String,
    /// Stringified `value`, suitable for emitting as the input's `value=` attr.
    /// Submit buttons use this as their label.
    pub(crate) value: String,
    pub(crate) label: Option<String>,
    pub(crate) autocomplete: Option<String>,
    /// HTML5 `pattern` regex for client-side validation (Kratos sets this on
    /// short numeric inputs like recovery / verification codes, `[0-9]+`).
    pub(crate) pattern: Option<String>,
    /// `inputmode` hint (e.g. `numeric`) so mobile keyboards pop the right
    /// keypad. Not on Kratos's node directly; inferred from `pattern`.
    pub(crate) inputmode: Option<&'static str>,
    pub(crate) required: bool,
    pub(crate) disabled: bool,
    /// `true` when this submit button is the form's primary CTA. The flow_node
    /// partial uses this to pick primary vs. secondary button styling. Only
    /// meaningful for `input_type == "submit"`.
    pub(crate) is_primary: bool,
    /// JS to run on click. Kratos populates this on WebAuthn / passkey trigger
    /// buttons, either as the legacy `onclick` attribute (literal JS to eval)
    /// or the newer `onclickTrigger` enum which we map to
    /// `window.<name>(event)`. The partial renders it verbatim on buttons.
    pub(crate) onclick: Option<String>,
    /// Validation messages attached to this specific node.
    pub(crate) messages: Vec<MessageView>,
    /// Kratos `meta.label.id` — stable numeric id for the node's label, used
    /// by `translate_ory` to produce a localized label. Zero when absent.
    pub(crate) label_id: u64,
    /// Kratos `meta.label.context` — arg bag for the label translation
    /// (e.g. `{"provider": "Google"}` for OIDC buttons). `Null` when absent.
    pub(crate) label_context: serde_json::Value,
}

/// A flash/validation message, with a coarse severity used to pick styling.
pub(crate) struct MessageView {
    pub(crate) text: String,
    /// `"error"`, `"success"`, or `"info"`.
    pub(crate) severity: &'static str,
    /// Kratos message ID; a stable identifier templates can branch on (e.g.
    /// 4000007 = "account exists already", which lets the registration page
    /// surface a `/claim-email` CTA without sniffing the localised text).
    pub(crate) id: u64,
    /// Kratos `context` object — arg bag for `translate_ory`. `Null` when absent.
    pub(crate) context: serde_json::Value,
}

/// A `<script>` tag projected from a `UiNode` whose `type == "script"`.
/// Kratos emits one of these in the webauthn / passkey group, pointing at
/// its own `/.well-known/ory/webauthn.js` helper. We render the tag verbatim
/// so the helper version always matches the Kratos instance serving the flow.
pub(crate) struct ScriptView {
    pub(crate) src: String,
    /// Subresource Integrity hash, when Kratos sets one.
    pub(crate) integrity: Option<String>,
    pub(crate) referrerpolicy: Option<String>,
    pub(crate) crossorigin: Option<String>,
    /// HTML element id (e.g. `webauthn_script`), useful for the helper's
    /// own internal lookups.
    pub(crate) id: Option<String>,
    pub(crate) nonce: Option<String>,
    /// True iff Kratos emitted `async` on the script attributes.
    pub(crate) is_async: bool,
}

/// Inputs grouped by Kratos `node.group`, ordered for rendering.
#[derive(Default)]
pub(crate) struct GroupedNodes {
    pub(crate) default: Vec<InputView>,
    pub(crate) oidc: Vec<InputView>,
    pub(crate) code: Vec<InputView>,
    pub(crate) password: Vec<InputView>,
    pub(crate) profile: Vec<InputView>,
    /// Anything we don't have a dedicated slot for (TOTP, lookup_secret, …).
    pub(crate) other: Vec<InputView>,
}

/// True when the `default` group has any non-hidden input, i.e. the form has
/// its own visible fields rather than only carrying CSRF/method hidden inputs.
pub fn has_visible_default_inputs(groups: &GroupedNodes) -> bool {
    groups.default.iter().any(|n| n.input_type != "hidden")
}

/// Shared view-model for the four self-service flow forms (login,
/// registration, recovery, verification). Collapses the
/// form_target / group_nodes / mark_primary_submits / has_visible_default /
/// flow_messages / return_to_qs sequence each `render_*` repeated. Embedded in
/// each template struct as `form`; templates read `form.form_action`,
/// `form.groups.*`, etc. Bespoke per-flow extras (webauthn scripts, flow
/// `state`, `is_logged_in`, …) stay as sibling fields on the template struct.
pub(crate) struct FlowFormView {
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    pub(crate) groups: GroupedNodes,
    pub(crate) has_visible_default: bool,
    pub(crate) return_to_qs: String,
}

impl FlowFormView {
    /// Project a fetched flow into the shared form view-model. `return_to`
    /// falls back to the flow's own `return_to` when the caller's is absent,
    /// matching the open-coded `return_to.or_else(|| flow_return_to(flow))`.
    /// Messages and node labels are translated through `translate_ory` using
    /// `locale`; Kratos English is the fallback for unmapped/failed ids.
    pub(crate) fn from_flow(
        flow: &serde_json::Value,
        kind: FlowKind,
        return_to: Option<&str>,
        locale: &LanguageIdentifier,
    ) -> Self {
        let (form_action, form_method) = form_target(flow);
        let mut groups = group_nodes(flow);
        mark_primary_submits(&mut groups, kind);
        let has_visible_default = has_visible_default_inputs(&groups);
        translate_all_groups(&mut groups, locale);
        let mut msgs = flow_messages(flow);
        translate_messages(&mut msgs, locale);
        FlowFormView {
            form_action,
            form_method,
            flow_messages: msgs,
            groups,
            has_visible_default,
            return_to_qs: return_to_qs(return_to.or_else(|| flow_return_to(flow))),
        }
    }
}

pub(crate) fn map_message(m: &serde_json::Value) -> Option<MessageView> {
    let text = m.get("text")?.as_str()?.to_string();
    let severity = match m.get("type").and_then(|t| t.as_str()).unwrap_or("info") {
        "error" => "error",
        "success" => "success",
        _ => "info",
    };
    let id = m.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
    let context = m.get("context").cloned().unwrap_or(serde_json::Value::Null);
    Some(MessageView {
        text,
        severity,
        id,
        context,
    })
}

pub(crate) fn node_to_input(node: &serde_json::Value) -> Option<InputView> {
    if node.get("type")?.as_str()? != "input" {
        return None;
    }
    let attrs = node.get("attributes")?.as_object()?;
    let name = attrs.get("name")?.as_str()?.to_string();
    // Suppress the Kratos-generated field for preferred_language; it is set
    // exclusively via /settings/language and must not appear on registration
    // or settings/profile forms.
    if name == "traits.preferred_language" {
        return None;
    }
    let input_type = attrs.get("type")?.as_str()?.to_string();

    let value = match attrs.get("value") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };

    let autocomplete = attrs
        .get("autocomplete")
        .and_then(|a| a.as_str())
        .map(str::to_string);

    let pattern = attrs
        .get("pattern")
        .and_then(|p| p.as_str())
        .map(str::to_string);
    // If Kratos's pattern is digits-only, hint mobile keyboards. Kratos doesn't
    // emit `inputmode` itself, so this is the only signal.
    let inputmode = pattern.as_deref().and_then(|p| match p {
        "[0-9]+" | "[0-9]*" => Some("numeric"),
        _ => None,
    });

    let attr_label = attrs
        .get("label")
        .and_then(|l| l.get("text"))
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let meta = node.get("meta").and_then(|m| m.get("label"));
    let meta_label = meta
        .and_then(|l| l.get("text"))
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let label = attr_label.or_else(|| meta_label.clone());
    // Retain the label's Kratos id + context for translate_ory (OIDC provider
    // buttons and other meta-label nodes carry these for translation).
    let label_id = meta
        .and_then(|l| l.get("id"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let label_context = meta
        .and_then(|l| l.get("context"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // Prefer `onclickTrigger` (function on `window` from Kratos's webauthn.js) over the legacy literal `onclick`.
    // Trigger functions must be called bare: a truthy first arg (e.g. `event`) is treated as the options object and crashes at `opt.publicKey.user.id`.
    let onclick_trigger = attrs.get("onclickTrigger").and_then(|t| t.as_str());
    let onclick_literal = attrs.get("onclick").and_then(|o| o.as_str());
    let onclick = onclick_trigger
        .map(|t| format!("window.{}()", t))
        .or_else(|| onclick_literal.map(str::to_string));

    let display_value = if (input_type == "submit" || input_type == "button") && value.is_empty() {
        meta_label.unwrap_or_default()
    } else {
        value
    };

    let required = attrs
        .get("required")
        .and_then(|r| r.as_bool())
        .unwrap_or(false);
    let disabled = attrs
        .get("disabled")
        .and_then(|r| r.as_bool())
        .unwrap_or(false);

    let messages = node
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|arr| arr.iter().filter_map(map_message).collect())
        .unwrap_or_default();

    Some(InputView {
        name,
        input_type,
        value: display_value,
        label,
        autocomplete,
        pattern,
        inputmode,
        required,
        disabled,
        is_primary: false,
        onclick,
        messages,
        label_id,
        label_context,
    })
}

/// The flow's `ui.nodes` array, or an empty slice on any miss. Lets callers
/// iterate without re-opening the `get("ui").get("nodes").as_array()` guard.
fn nodes(flow: &serde_json::Value) -> &[serde_json::Value] {
    flow.get("ui")
        .and_then(|ui| ui.get("nodes"))
        .and_then(|n| n.as_array())
        .map_or(&[], Vec::as_slice)
}

pub(crate) fn group_nodes(flow: &serde_json::Value) -> GroupedNodes {
    let mut groups = GroupedNodes::default();
    for node in nodes(flow) {
        let Some(input) = node_to_input(node) else {
            continue;
        };
        let group = node.get("group").and_then(|g| g.as_str()).unwrap_or("");
        match group {
            "default" => groups.default.push(input),
            "oidc" => groups.oidc.push(input),
            "code" => groups.code.push(input),
            "password" => groups.password.push(input),
            "profile" => groups.profile.push(input),
            _ => groups.other.push(input),
        }
    }
    groups
}

/// Collect every `input`-type node from a specific group, preserving order.
/// Used by settings sub-pages that drive a single section of the settings
/// flow (TOTP, lookup_secret, webauthn, oidc) and need finer control than the
/// catch-all [`group_nodes`].
pub(crate) fn collect_input_nodes(flow: &serde_json::Value, group: &str) -> Vec<InputView> {
    let mut out = Vec::new();
    for node in nodes(flow) {
        let g = node.get("group").and_then(|g| g.as_str()).unwrap_or("");
        if g != group {
            continue;
        }
        if let Some(input) = node_to_input(node) {
            out.push(input);
        }
    }
    out
}

/// Collect every `script`-type node from a specific group. Kratos uses this
/// in the webauthn / passkey groups to point at its served-by-Kratos helper
/// (`/.well-known/ory/webauthn.js`), version-matched to the running instance.
pub(crate) fn collect_script_nodes(flow: &serde_json::Value, group: &str) -> Vec<ScriptView> {
    let mut out = Vec::new();
    for node in nodes(flow) {
        let g = node.get("group").and_then(|g| g.as_str()).unwrap_or("");
        if g != group {
            continue;
        }
        if node.get("type").and_then(|t| t.as_str()) != Some("script") {
            continue;
        }
        let Some(attrs) = node.get("attributes").and_then(|a| a.as_object()) else {
            continue;
        };
        let Some(src) = attrs.get("src").and_then(|s| s.as_str()) else {
            continue;
        };
        let str_attr = |k: &str| attrs.get(k).and_then(|v| v.as_str()).map(str::to_string);
        out.push(ScriptView {
            src: src.to_string(),
            integrity: str_attr("integrity"),
            referrerpolicy: str_attr("referrerpolicy"),
            crossorigin: str_attr("crossorigin"),
            id: str_attr("id"),
            nonce: str_attr("nonce"),
            is_async: attrs
                .get("async")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        });
    }
    out
}

/// WebAuthn and passkey credentials both ship their own Kratos-served helper
/// script; collect them as one list so the template renders both.
pub fn collect_webauthn_scripts(flow: &serde_json::Value) -> Vec<ScriptView> {
    let mut scripts = collect_script_nodes(flow, "webauthn");
    scripts.extend(collect_script_nodes(flow, "passkey"));
    scripts
}

/// Collect the form's CSRF/method hidden inputs from the `default` group.
/// Every settings form needs them re-emitted, regardless of which credential
/// group drives the page.
pub(crate) fn collect_default_hidden(flow: &serde_json::Value) -> Vec<InputView> {
    let mut out = Vec::new();
    for node in nodes(flow) {
        let g = node.get("group").and_then(|g| g.as_str()).unwrap_or("");
        if g != "default" {
            continue;
        }
        if let Some(input) = node_to_input(node) {
            if input.input_type == "hidden" {
                out.push(input);
            }
        }
    }
    out
}

/// Pull TOTP's QR-code data URI and human-readable secret out of the flow's
/// non-input nodes. Kratos emits `node.type=="img"` (with `attributes.id ==
/// "totp_qr"`, `attributes.src == "data:image/png;base64,..."`) and
/// `node.type=="text"` (`attributes.id == "totp_secret_key"`,
/// `attributes.text.text == "JBSWY3DPEHPK3PXP"`) during enrolment. After
/// enrolment those nodes disappear and only an `unlink` submit remains.
pub(crate) fn totp_qr_and_secret(flow: &serde_json::Value) -> (Option<String>, Option<String>) {
    let mut qr = None;
    let mut secret = None;
    for node in nodes(flow) {
        let attrs = match node.get("attributes").and_then(|a| a.as_object()) {
            Some(a) => a,
            None => continue,
        };
        let id = attrs.get("id").and_then(|v| v.as_str()).unwrap_or("");
        match node.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "img" if id == "totp_qr" => {
                qr = attrs
                    .get("src")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            "text" if id == "totp_secret_key" => {
                // Kratos wraps text in `attributes.text.text`.
                secret = attrs
                    .get("text")
                    .and_then(|t| t.get("text"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            _ => {}
        }
    }
    (qr, secret)
}

/// Extract freshly-generated lookup-secret codes from the flow's text nodes.
/// Kratos returns them once, in `attributes.text.context.secrets[]` of a
/// `node.type=="text"` whose `attributes.id == "lookup_secret_codes"`. After
/// the user confirms display, subsequent flow renders don't include them, so
/// this is genuinely the only time the UI ever sees the plaintext codes.
pub(crate) fn lookup_codes(flow: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes(flow) {
        let attrs = match node.get("attributes").and_then(|a| a.as_object()) {
            Some(a) => a,
            None => continue,
        };
        if attrs.get("id").and_then(|v| v.as_str()) != Some("lookup_secret_codes") {
            continue;
        }
        // The codes may arrive as a comma-joined string or as an array under
        // `text.context.secrets` (which can be either array of strings or
        // array of `{secret, used_at}` objects). Handle every shape Kratos
        // has used across recent versions.
        let text_obj = attrs.get("text").and_then(|t| t.as_object());
        if let Some(text) = text_obj {
            if let Some(arr) = text
                .get("context")
                .and_then(|c| c.get("secrets"))
                .and_then(|s| s.as_array())
            {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        if !s.is_empty() {
                            out.push(s.to_string());
                        }
                    } else if let Some(s) = item.get("secret").and_then(|v| v.as_str()) {
                        if !s.is_empty() {
                            out.push(s.to_string());
                        }
                    }
                }
            }
            // Fallback: comma-joined plain text.
            if out.is_empty() {
                if let Some(s) = text.get("text").and_then(|v| v.as_str()) {
                    for code in s.split(|c: char| c == ',' || c.is_whitespace()) {
                        let code = code.trim();
                        if !code.is_empty() {
                            out.push(code.to_string());
                        }
                    }
                }
            }
        }
    }
    out
}

/// Heuristic: does the flow contain any node in `group=="totp"` whose attribute
/// id starts with `totp_unlink`? If yes, the identity already has TOTP enabled
/// and the page should render the disable button instead of the enrolment QR.
pub(crate) fn group_has_node(flow: &serde_json::Value, group: &str, id_prefix: &str) -> bool {
    nodes(flow).iter().any(|node| {
        let g = node.get("group").and_then(|g| g.as_str()).unwrap_or("");
        if g != group {
            return false;
        }
        let id = node
            .get("attributes")
            .and_then(|a| a.get("id"))
            .or_else(|| node.get("attributes").and_then(|a| a.get("name")))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        id.starts_with(id_prefix)
    })
}

/// Flag every submit button in `group` as the form's primary CTA.
fn mark_submits_primary(group: &mut [InputView]) {
    for input in group {
        if input.input_type == "submit" {
            input.is_primary = true;
        }
    }
}

pub(crate) fn mark_primary_submits(groups: &mut GroupedNodes, kind: FlowKind) {
    let primary_group: &mut Vec<InputView> = match kind {
        FlowKind::Login => &mut groups.password,
        FlowKind::Registration => {
            if !groups.password.is_empty() {
                &mut groups.password
            } else {
                &mut groups.profile
            }
        }
        FlowKind::Recovery | FlowKind::Verification => &mut groups.code,
        FlowKind::Settings => &mut groups.password,
    };
    mark_submits_primary(primary_group);
}

/// Like [`mark_primary_submits`] but targeting an arbitrary settings group
/// (`profile` for `/settings/profile`, `password` for `/settings/password`).
pub(crate) fn mark_settings_primary(groups: &mut GroupedNodes, group: &str) {
    match group {
        "profile" => mark_submits_primary(&mut groups.profile),
        "password" => mark_submits_primary(&mut groups.password),
        _ => {}
    }
}

pub(crate) fn form_target(flow: &serde_json::Value) -> (String, String) {
    let ui = flow.get("ui");
    let form_action = ui
        .and_then(|u| u.get("action"))
        .and_then(|a| a.as_str())
        .unwrap_or("")
        .to_string();
    let form_method = ui
        .and_then(|u| u.get("method"))
        .and_then(|m| m.as_str())
        .unwrap_or("POST")
        .to_string();
    (form_action, form_method)
}

pub(crate) fn flow_messages(flow: &serde_json::Value) -> Vec<MessageView> {
    flow.get("ui")
        .and_then(|u| u.get("messages"))
        .and_then(|m| m.as_array())
        .map(|arr| arr.iter().filter_map(map_message).collect())
        .unwrap_or_default()
}

/// Translate all messages in `msgs` through `translate_ory`. Messages without
/// a Kratos id (id == 0) are left unchanged. Must be called after `flow_messages`
/// or `map_message` has populated the `id` and `context` fields.
pub(crate) fn translate_messages(msgs: &mut [MessageView], locale: &LanguageIdentifier) {
    for msg in msgs {
        if msg.id > 0 {
            let translated = crate::i18n::translate_ory(locale, msg.id, &msg.context, &msg.text);
            msg.text = translated;
        }
    }
}

/// Well-known Kratos trait / identifier field names whose label is the identity
/// schema `title`. Kratos emits these with the generic label id 1070002, a
/// passthrough whose text IS the title, so the numeric catalog cannot localize
/// them. Map them to Forseti surface keys instead.
fn trait_label_key(name: &str) -> Option<&'static str> {
    match name {
        "identifier" | "traits.email" => Some("auth-field-email"),
        "traits.name.first" => Some("auth-field-first-name"),
        "traits.name.last" => Some("auth-field-last-name"),
        _ => None,
    }
}

/// Translate node labels through `translate_ory` for nodes that carry a
/// `label_id`. Also translates per-node messages recursively.
pub(crate) fn translate_inputs(nodes: &mut [InputView], locale: &LanguageIdentifier) {
    for node in nodes {
        if node.label_id > 0 {
            if let Some(label) = &node.label {
                let translated =
                    crate::i18n::translate_ory(locale, node.label_id, &node.label_context, label);
                node.label = Some(translated);
            }
        }
        // Schema-driven trait labels can't be reached by numeric id; override by name.
        if let Some(key) = trait_label_key(&node.name) {
            node.label = Some(crate::i18n::lookup(locale, key));
        }
        translate_messages(&mut node.messages, locale);
    }
}

fn translate_all_groups(groups: &mut GroupedNodes, locale: &LanguageIdentifier) {
    translate_inputs(&mut groups.default, locale);
    translate_inputs(&mut groups.oidc, locale);
    translate_inputs(&mut groups.code, locale);
    translate_inputs(&mut groups.password, locale);
    translate_inputs(&mut groups.profile, locale);
    translate_inputs(&mut groups.other, locale);
}

pub(crate) fn return_to_qs(return_to: Option<&str>) -> String {
    match return_to {
        Some(rt) if !rt.is_empty() => {
            format!("?return_to={}", ory_client::apis::urlencode(rt))
        }
        _ => String::new(),
    }
}

/// Pull `return_to` out of a Kratos flow body. Kratos stores the
/// `return_to` passed at flow-init time inside the flow JSON but does
/// **not** echo it back into the UI URL (the redirect to Forseti
/// only carries `?flow=<id>`). Handlers that need to forward
/// `return_to` to sibling flow links (e.g. login → "Create account")
/// must read it from here instead of relying on the query string.
pub(crate) fn flow_return_to(flow: &serde_json::Value) -> Option<&str> {
    flow.get("return_to")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

pub(crate) fn flow_state(flow: &serde_json::Value) -> &str {
    flow.get("state").and_then(|s| s.as_str()).unwrap_or("")
}

/// Pull a display email out of a session's identity traits. Returns empty
/// string when the trait is missing or the identity is unavailable.
pub(crate) fn session_email(session: &ory::Session) -> String {
    session
        .identity
        .as_ref()
        .and_then(|id| id.traits.as_ref())
        .and_then(|t| t.get("email"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Pull the (identity_id, email) pair out of a session. Both default to
/// empty strings when missing; matches the open-coded `.unwrap_or_default()`
/// pattern callers use across extractors, the admin gate, and consent.
pub(crate) fn session_principal(session: &ory::Session) -> (String, String) {
    let identity_id = session
        .identity
        .as_ref()
        .map(|id| id.id.clone())
        .unwrap_or_default();
    let email = session_email(session);
    (identity_id, email)
}

/// True when the session's identity has at least one verifiable address
/// that's still pending verification; drives the dashboard verify banner.
pub(crate) fn session_needs_verification(session: &ory::Session) -> bool {
    session
        .identity
        .as_ref()
        .and_then(|id| id.verifiable_addresses.as_ref())
        .map(|addrs| addrs.iter().any(|a| !a.verified))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input_node(
        group: &str,
        name: &str,
        input_type: &str,
        value: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "type": "input",
            "group": group,
            "attributes": {
                "name": name,
                "type": input_type,
                "value": value,
            },
            "messages": [],
        })
    }

    fn flow_with(nodes: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "ui": {
                "action": "https://kratos/self-service/login?flow=abc",
                "method": "POST",
                "nodes": nodes,
                "messages": [],
            },
            "state": "choose_method",
        })
    }

    // --- node_to_input ------------------------------------------------------

    #[test]
    fn node_to_input_extracts_basic_fields() {
        let n = input_node("password", "password", "password", json!(""));
        let v = node_to_input(&n).expect("should produce InputView");
        assert_eq!(v.name, "password");
        assert_eq!(v.input_type, "password");
        assert_eq!(v.value, "");
    }

    #[test]
    fn node_to_input_suppresses_preferred_language() {
        // Both the registration flow (group "default") and the settings/profile
        // flow (group "profile") may emit this node; it must be filtered in both.
        for group in &["default", "profile"] {
            let n = input_node(group, "traits.preferred_language", "text", json!("en"));
            assert!(
                node_to_input(&n).is_none(),
                "expected None for traits.preferred_language in group {group}"
            );
        }
    }

    #[test]
    fn translate_inputs_overrides_schema_trait_labels() {
        // Trait fields carry Kratos label id 1070002 (schema title passthrough);
        // flow_view must override them by name with the localized surface label.
        let de: crate::locale::LanguageIdentifier = "de".parse().unwrap();
        let mut nodes: Vec<InputView> = [
            input_node("default", "traits.name.first", "text", json!("")),
            input_node("default", "traits.name.last", "text", json!("")),
        ]
        .iter()
        .filter_map(node_to_input)
        .collect();
        translate_inputs(&mut nodes, &de);
        assert_eq!(nodes[0].label.as_deref(), Some("Vorname"));
        assert_eq!(nodes[1].label.as_deref(), Some("Nachname"));
    }

    #[test]
    fn node_to_input_rejects_non_input_node() {
        let n = json!({
            "type": "script",
            "attributes": {"name": "x", "type": "text"},
        });
        assert!(node_to_input(&n).is_none());
    }

    #[test]
    fn node_to_input_stringifies_non_string_values() {
        let n = input_node("default", "n", "hidden", json!(42));
        let v = node_to_input(&n).unwrap();
        assert_eq!(v.value, "42");
        let n2 = input_node("default", "n", "hidden", json!(true));
        let v2 = node_to_input(&n2).unwrap();
        assert_eq!(v2.value, "true");
        let n3 = input_node("default", "n", "hidden", serde_json::Value::Null);
        let v3 = node_to_input(&n3).unwrap();
        assert_eq!(v3.value, "");
    }

    #[test]
    fn node_to_input_infers_numeric_inputmode_from_pattern() {
        let n = json!({
            "type": "input",
            "group": "code",
            "attributes": {
                "name": "code",
                "type": "text",
                "pattern": "[0-9]+",
            },
        });
        let v = node_to_input(&n).unwrap();
        assert_eq!(v.inputmode, Some("numeric"));
        assert_eq!(v.pattern.as_deref(), Some("[0-9]+"));
    }

    #[test]
    fn node_to_input_picks_meta_label_for_submit_when_value_empty() {
        let n = json!({
            "type": "input",
            "group": "password",
            "attributes": {
                "name": "method",
                "type": "submit",
                "value": "",
            },
            "meta": {"label": {"text": "Sign in"}},
        });
        let v = node_to_input(&n).unwrap();
        assert_eq!(v.value, "Sign in");
    }

    #[test]
    fn node_to_input_attr_label_takes_precedence_over_meta() {
        let n = json!({
            "type": "input",
            "group": "default",
            "attributes": {
                "name": "x",
                "type": "text",
                "label": {"text": "Attr Label"},
            },
            "meta": {"label": {"text": "Meta Label"}},
        });
        let v = node_to_input(&n).unwrap();
        assert_eq!(v.label.as_deref(), Some("Attr Label"));
    }

    #[test]
    fn node_to_input_onclick_trigger_wraps_in_window_call() {
        let n = json!({
            "type": "input",
            "group": "webauthn",
            "attributes": {
                "name": "webauthn_register_trigger",
                "type": "button",
                "onclickTrigger": "oryWebAuthnRegistration",
            },
        });
        let v = node_to_input(&n).unwrap();
        assert_eq!(
            v.onclick.as_deref(),
            Some("window.oryWebAuthnRegistration()")
        );
    }

    #[test]
    fn node_to_input_required_and_disabled_flags() {
        let n = json!({
            "type": "input",
            "group": "password",
            "attributes": {
                "name": "password",
                "type": "password",
                "required": true,
                "disabled": true,
            },
        });
        let v = node_to_input(&n).unwrap();
        assert!(v.required);
        assert!(v.disabled);
    }

    #[test]
    fn node_to_input_collects_messages() {
        let n = json!({
            "type": "input",
            "group": "password",
            "attributes": {"name": "password", "type": "password"},
            "messages": [
                {"text": "Wrong password.", "type": "error"},
                {"text": "Try again.", "type": "info"},
            ],
        });
        let v = node_to_input(&n).unwrap();
        assert_eq!(v.messages.len(), 2);
        assert_eq!(v.messages[0].severity, "error");
        assert_eq!(v.messages[1].severity, "info");
    }

    // --- group_nodes -------------------------------------------------------

    #[test]
    fn group_nodes_partitions_login_password() {
        let flow = flow_with(vec![
            input_node("default", "csrf_token", "hidden", json!("abc")),
            input_node("password", "identifier", "email", json!("")),
            input_node("password", "password", "password", json!("")),
            input_node("password", "method", "submit", json!("password")),
            input_node("oidc", "provider", "submit", json!("google")),
            input_node("code", "code", "text", json!("")),
        ]);
        let g = group_nodes(&flow);
        assert_eq!(g.default.len(), 1);
        assert_eq!(g.password.len(), 3);
        assert_eq!(g.oidc.len(), 1);
        assert_eq!(g.code.len(), 1);
        assert!(g.profile.is_empty());
        assert!(g.other.is_empty());
    }

    #[test]
    fn group_nodes_excludes_preferred_language_keeps_email() {
        // Simulates a registration flow: preferred_language lands in "default"
        // alongside email/csrf; a settings/profile flow puts it in "profile".
        // Either way it must be absent; normal fields must survive.
        let flow = flow_with(vec![
            input_node("default", "csrf_token", "hidden", json!("tok")),
            input_node("default", "traits.email", "email", json!("")),
            input_node("default", "traits.preferred_language", "text", json!("en")),
            input_node("profile", "traits.preferred_language", "text", json!("de")),
            input_node("profile", "method", "submit", json!("profile")),
        ]);
        let g = group_nodes(&flow);
        assert!(
            g.default.iter().any(|n| n.name == "traits.email"),
            "traits.email must survive in default group"
        );
        let all: Vec<_> = g
            .default
            .iter()
            .chain(g.profile.iter())
            .map(|n| n.name.as_str())
            .collect();
        assert!(
            !all.contains(&"traits.preferred_language"),
            "traits.preferred_language must not appear in any group; got: {all:?}"
        );
        // The profile group should only have the submit node.
        assert_eq!(g.profile.len(), 1);
        assert_eq!(g.profile[0].name, "method");
    }

    #[test]
    fn group_nodes_unknown_groups_fall_to_other() {
        let flow = flow_with(vec![
            input_node("totp", "totp_code", "text", json!("")),
            input_node("lookup_secret", "lookup_secret", "text", json!("")),
        ]);
        let g = group_nodes(&flow);
        assert_eq!(g.other.len(), 2);
    }

    #[test]
    fn group_nodes_handles_missing_nodes_array() {
        let flow = json!({"ui": {"action": "x", "method": "POST"}, "state": "x"});
        let g = group_nodes(&flow);
        assert!(g.default.is_empty());
        assert!(g.password.is_empty());
    }

    // --- collect_input_nodes & collect_default_hidden ----------------------

    #[test]
    fn collect_input_nodes_filters_by_group() {
        let flow = flow_with(vec![
            input_node("default", "csrf_token", "hidden", json!("abc")),
            input_node("totp", "totp_code", "text", json!("")),
            input_node("totp", "method", "submit", json!("totp")),
        ]);
        let totp = collect_input_nodes(&flow, "totp");
        assert_eq!(totp.len(), 2);
        assert_eq!(totp[0].name, "totp_code");
    }

    #[test]
    fn collect_default_hidden_only_picks_hidden_default() {
        let flow = flow_with(vec![
            input_node("default", "csrf_token", "hidden", json!("abc")),
            input_node("default", "submit", "submit", json!("ok")),
            input_node("password", "password", "hidden", json!("")),
        ]);
        let hidden = collect_default_hidden(&flow);
        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].name, "csrf_token");
    }

    // --- map_message + flow_messages ---------------------------------------

    #[test]
    fn map_message_severity_mapping() {
        let m = json!({"text": "Bad password", "type": "error"});
        assert_eq!(map_message(&m).unwrap().severity, "error");
        let m = json!({"text": "Welcome", "type": "success"});
        assert_eq!(map_message(&m).unwrap().severity, "success");
        let m = json!({"text": "Heads up", "type": "info"});
        assert_eq!(map_message(&m).unwrap().severity, "info");
        // Unknown type → info.
        let m = json!({"text": "x", "type": "weird"});
        assert_eq!(map_message(&m).unwrap().severity, "info");
    }

    #[test]
    fn map_message_missing_text_returns_none() {
        let m = json!({"type": "error"});
        assert!(map_message(&m).is_none());
    }

    #[test]
    fn flow_messages_pulls_top_level_ui_messages() {
        let flow = json!({
            "ui": {
                "messages": [
                    {"text": "Login failed.", "type": "error"},
                ],
                "nodes": [],
            },
        });
        let msgs = flow_messages(&flow);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "Login failed.");
    }

    // --- TOTP / lookup-secret / group_has_node -----------------------------

    #[test]
    fn totp_qr_and_secret_extracts_both() {
        let flow = json!({
            "ui": {
                "nodes": [
                    {
                        "type": "img",
                        "attributes": {
                            "id": "totp_qr",
                            "src": "data:image/png;base64,XYZ",
                        },
                    },
                    {
                        "type": "text",
                        "attributes": {
                            "id": "totp_secret_key",
                            "text": {"text": "JBSWY3DPEHPK3PXP"},
                        },
                    },
                ],
            },
        });
        let (qr, secret) = totp_qr_and_secret(&flow);
        assert_eq!(qr.as_deref(), Some("data:image/png;base64,XYZ"));
        assert_eq!(secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn totp_qr_and_secret_absent_when_not_enrolling() {
        let flow = flow_with(vec![input_node(
            "totp",
            "totp_unlink",
            "submit",
            json!("Unlink"),
        )]);
        let (qr, secret) = totp_qr_and_secret(&flow);
        assert!(qr.is_none());
        assert!(secret.is_none());
    }

    #[test]
    fn lookup_codes_from_secrets_array_of_strings() {
        let flow = json!({
            "ui": {
                "nodes": [
                    {
                        "attributes": {
                            "id": "lookup_secret_codes",
                            "text": {
                                "context": {"secrets": ["aaa", "bbb", "ccc"]},
                                "text": "aaa,bbb,ccc",
                            },
                        },
                    },
                ],
            },
        });
        let codes = lookup_codes(&flow);
        assert_eq!(codes, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn lookup_codes_from_secrets_array_of_objects() {
        let flow = json!({
            "ui": {
                "nodes": [
                    {
                        "attributes": {
                            "id": "lookup_secret_codes",
                            "text": {
                                "context": {
                                    "secrets": [
                                        {"secret": "aaa"},
                                        {"secret": "bbb"},
                                    ]
                                },
                            },
                        },
                    },
                ],
            },
        });
        let codes = lookup_codes(&flow);
        assert_eq!(codes, vec!["aaa", "bbb"]);
    }

    #[test]
    fn lookup_codes_fallback_comma_split() {
        let flow = json!({
            "ui": {
                "nodes": [
                    {
                        "attributes": {
                            "id": "lookup_secret_codes",
                            "text": {"text": "aaa, bbb, ccc"},
                        },
                    },
                ],
            },
        });
        let codes = lookup_codes(&flow);
        assert_eq!(codes, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn group_has_node_matches_prefix() {
        let flow = flow_with(vec![input_node(
            "totp",
            "totp_unlink",
            "submit",
            json!("Unlink"),
        )]);
        assert!(group_has_node(&flow, "totp", "totp_unlink"));
        assert!(!group_has_node(&flow, "totp", "totp_qr"));
        assert!(!group_has_node(&flow, "password", "totp_unlink"));
    }

    // --- mark_primary_submits ----------------------------------------------

    #[test]
    fn mark_primary_submits_login_flags_password_submits() {
        let mut g = GroupedNodes {
            password: vec![
                InputView {
                    name: "method".into(),
                    input_type: "submit".into(),
                    value: "Sign in".into(),
                    ..Default::default()
                },
                InputView {
                    name: "password".into(),
                    input_type: "password".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        mark_primary_submits(&mut g, FlowKind::Login);
        assert!(g.password[0].is_primary);
        // Non-submit untouched.
        assert!(!g.password[1].is_primary);
    }

    // --- form_target + flow_state + return_to_qs ---------------------------

    #[test]
    fn form_target_pulls_action_and_method() {
        let flow = flow_with(vec![]);
        let (action, method) = form_target(&flow);
        assert_eq!(action, "https://kratos/self-service/login?flow=abc");
        assert_eq!(method, "POST");
    }

    #[test]
    fn form_target_defaults_method_to_post() {
        let flow = json!({"ui": {"action": "x"}, "state": "y"});
        let (action, method) = form_target(&flow);
        assert_eq!(action, "x");
        assert_eq!(method, "POST");
    }

    #[test]
    fn flow_state_returns_state_field() {
        let flow = flow_with(vec![]);
        assert_eq!(flow_state(&flow), "choose_method");
    }

    #[test]
    fn return_to_qs_encodes_or_empty() {
        assert_eq!(return_to_qs(None), "");
        assert_eq!(return_to_qs(Some("")), "");
        let q = return_to_qs(Some("/dashboard?x=1"));
        assert!(q.starts_with("?return_to="));
        assert!(q.contains("%2Fdashboard"));
    }

    #[test]
    fn flow_return_to_reads_field_when_present() {
        let flow = json!({"return_to": "http://localhost:3000/oauth/login?login_challenge=abc"});
        assert_eq!(
            flow_return_to(&flow),
            Some("http://localhost:3000/oauth/login?login_challenge=abc"),
        );
    }

    #[test]
    fn flow_return_to_none_when_missing_or_empty() {
        assert_eq!(flow_return_to(&json!({})), None);
        assert_eq!(flow_return_to(&json!({"return_to": ""})), None);
        assert_eq!(flow_return_to(&json!({"return_to": null})), None);
    }
}
