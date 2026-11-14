//! Flow view-models: [`Flow`] is a self-service flow as the identity backend hands it over
//! (`crate::flow_json` builds it from Kratos JSON), and the template-iterable structs here shape it
//! for rendering. Grouping by `node.group` drives the visual layout (OIDC stack, code shortcut,
//! profile/password form, OR-divider).

use crate::backend::identity::FlowKind;
use crate::locale::LanguageIdentifier;

/// A single input field projected from a `UiNode` whose attributes are `Input`.
#[derive(Clone, Default)]
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
    /// Resolved provider display name for OIDC submit nodes (e.g. `GitHub`).
    /// Empty for non-OIDC nodes; populated by [`enrich_oidc_branding`].
    pub(crate) provider_display: String,
    /// Inline brand-mark SVG for OIDC submit nodes; empty for others.
    pub(crate) provider_icon_svg: &'static str,
}

/// A flash/validation message, with a coarse severity used to pick styling.
#[derive(Clone)]
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
#[derive(Clone)]
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

impl GroupedNodes {
    /// Partition the flow's inputs into the render slots, keeping document order.
    pub(crate) fn from_flow(flow: &Flow) -> Self {
        let mut groups = GroupedNodes::default();
        for (group, input) in &flow.inputs {
            let slot = match group.as_str() {
                "default" => &mut groups.default,
                "oidc" => &mut groups.oidc,
                "code" => &mut groups.code,
                "password" => &mut groups.password,
                "profile" => &mut groups.profile,
                _ => &mut groups.other,
            };
            slot.push(input.clone());
        }
        groups
    }
}

/// A self-service flow: untranslated inputs and scripts tagged with their
/// group in document order, messages, node-presence keys, and the scalars
/// handlers act on.
pub(crate) struct Flow {
    pub(crate) id: String,
    pub(crate) state: String,
    /// Non-empty `return_to` stored at flow init.
    pub(crate) return_to: Option<String>,
    pub(crate) requested_aal: Option<String>,
    pub(crate) refresh: bool,
    pub(crate) issued_at: Option<String>,
    /// Decoded `return_to` of the flow's `request_url`; empty when absent.
    pub(crate) request_return_to: String,
    /// Settings flow issued by the recovery `after.password` hook.
    pub(crate) recovery_handoff: bool,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    #[cfg_attr(all(feature = "identity-native", not(test)), expect(dead_code))]
    pub(crate) csrf_token: Option<String>,
    pub(crate) messages: Vec<MessageView>,
    pub(crate) inputs: Vec<(String, InputView)>,
    pub(crate) scripts: Vec<(String, ScriptView)>,
    /// `(group, attributes.id or name)` for every node, inputs or not.
    pub(crate) node_keys: Vec<(String, String)>,
    pub(crate) totp_qr: Option<String>,
    pub(crate) totp_secret: Option<String>,
    /// Plaintext lookup codes, present only right after regeneration.
    pub(crate) lookup_codes: Vec<String>,
}

impl Flow {
    /// Inputs of one group, in document order.
    pub(crate) fn inputs<'a>(&'a self, group: &'a str) -> impl Iterator<Item = &'a InputView> {
        self.inputs
            .iter()
            .filter(move |(g, _)| g == group)
            .map(|(_, input)| input)
    }

    /// The `default` group's hidden inputs (CSRF token and friends).
    pub(crate) fn default_hidden(&self) -> Vec<InputView> {
        self.inputs("default")
            .filter(|n| n.input_type == "hidden")
            .cloned()
            .collect()
    }

    /// WebAuthn then passkey helper scripts; each credential ships its own.
    pub(crate) fn webauthn_scripts(&self) -> Vec<ScriptView> {
        ["webauthn", "passkey"]
            .into_iter()
            .flat_map(|group| self.scripts.iter().filter(move |(g, _)| g == group))
            .map(|(_, script)| script.clone())
            .collect()
    }

    /// Whether any node in `group` has an id (or name) starting with `prefix`.
    pub(crate) fn has_node(&self, group: &str, prefix: &str) -> bool {
        self.node_keys
            .iter()
            .any(|(g, key)| g == group && key.starts_with(prefix))
    }

    /// Upstream provider ids the flow offers: the `oidc` group's `provider`
    /// submit nodes, deduped in order.
    pub(crate) fn oidc_provider_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        for node in self.inputs("oidc") {
            if node.name == "provider"
                && node.input_type == "submit"
                && !node.value.is_empty()
                && !ids.contains(&node.value)
            {
                ids.push(node.value.clone());
            }
        }
        ids
    }
}

/// True when the `default` group has any non-hidden input, i.e. the form has
/// its own visible fields rather than only carrying CSRF/method hidden inputs.
pub fn has_visible_default_inputs(groups: &GroupedNodes) -> bool {
    groups.default.iter().any(|n| n.input_type != "hidden")
}

/// Shared view-model for the four self-service flow forms (login,
/// registration, recovery, verification). Collapses the
/// grouping / mark_primary_submits / has_visible_default_inputs /
/// translation / return_to_qs sequence each `render_*` repeated. Embedded in
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
    /// Shape a fetched flow into the shared form view-model. `return_to`
    /// falls back to the flow's own `return_to` when the caller's is absent.
    /// Messages and node labels are translated through `translate_ory` using
    /// `locale`; Kratos English is the fallback for unmapped/failed ids.
    pub(crate) fn from_flow(
        flow: &Flow,
        kind: FlowKind,
        return_to: Option<&str>,
        locale: &LanguageIdentifier,
    ) -> Self {
        let mut groups = GroupedNodes::from_flow(flow);
        mark_primary_submits(&mut groups, kind);
        enrich_oidc_branding(&mut groups.oidc);
        let has_visible_default = has_visible_default_inputs(&groups);
        translate_all_groups(&mut groups, locale);
        let mut msgs = flow.messages.clone();
        translate_messages(&mut msgs, locale);
        FlowFormView {
            form_action: flow.form_action.clone(),
            form_method: flow.form_method.clone(),
            flow_messages: msgs,
            groups,
            has_visible_default,
            return_to_qs: return_to_qs(return_to.or(flow.return_to.as_deref())),
        }
    }
}

/// Resolve provider branding onto OIDC submit/button nodes: `provider_display`
/// (registry name from the raw provider id in `value`) and `provider_icon_svg`.
/// Left untouched for hidden nodes, whose `value` isn't a provider id.
pub(crate) fn enrich_oidc_branding(nodes: &mut [InputView]) {
    for n in nodes {
        if n.input_type == "submit" || n.input_type == "button" {
            n.provider_display = crate::oidc_providers::display_name(&n.value);
            n.provider_icon_svg = crate::oidc_providers::icon_svg(&n.value);
        }
    }
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

/// Translate all messages in `msgs` through `translate_ory`. Messages without
/// a Kratos id (id == 0) are left unchanged. Expects the `id` and `context`
/// fields the flow projection populates.
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
        if node.label_id > 0
            && let Some(label) = &node.label
        {
            let translated =
                crate::i18n::translate_ory(locale, node.label_id, &node.label_context, label);
            node.label = Some(translated);
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
            format!("?return_to={}", crate::web::urlencode(rt))
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- return_to_qs ------------------------------------------------------

    #[test]
    fn return_to_qs_encodes_or_empty() {
        assert_eq!(return_to_qs(None), "");
        assert_eq!(return_to_qs(Some("")), "");
        let q = return_to_qs(Some("/dashboard?x=1"));
        assert!(q.starts_with("?return_to="));
        assert!(q.contains("%2Fdashboard"));
    }
}
