//! Kratos self-service flow JSON to [`Flow`]. Reads raw JSON rather than the SDK
//! models because the SDK's `ui.nodes` deserializer rejects the real wire shape.

use serde_json::Value;

use crate::flow_view::{Flow, InputView, MessageView, ScriptView};

/// Project a Kratos flow body into a [`Flow`]. Inputs, scripts and messages
/// stay untranslated; missing fields fall back to empty values.
pub(crate) fn project(flow: &Value) -> Flow {
    let ui = flow.get("ui");
    let str_at = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);

    let mut inputs = Vec::new();
    let mut scripts = Vec::new();
    let mut node_keys = Vec::new();
    for node in nodes(flow) {
        let group = node.get("group").and_then(Value::as_str).unwrap_or("");
        node_keys.push((group.to_string(), node_key(node).to_string()));
        if let Some(input) = node_to_input(node) {
            inputs.push((group.to_string(), input));
        } else if let Some(script) = node_to_script(node) {
            scripts.push((group.to_string(), script));
        }
    }
    let (totp_qr, totp_secret) = totp_qr_and_secret(flow);

    Flow {
        id: str_at(flow.get("id")).unwrap_or_default(),
        state: str_at(flow.get("state")).unwrap_or_default(),
        return_to: str_at(flow.get("return_to")).filter(|s| !s.is_empty()),
        requested_aal: str_at(flow.get("requested_aal")),
        refresh: flow.get("refresh").and_then(Value::as_bool) == Some(true),
        issued_at: str_at(flow.get("issued_at")),
        request_return_to: request_return_to(flow),
        recovery_handoff: is_recovery_handoff(flow),
        form_action: str_at(ui.and_then(|u| u.get("action"))).unwrap_or_default(),
        form_method: str_at(ui.and_then(|u| u.get("method"))).unwrap_or_else(|| "POST".to_string()),
        csrf_token: csrf_token(flow),
        messages: ui
            .and_then(|u| u.get("messages"))
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(map_message).collect())
            .unwrap_or_default(),
        inputs,
        scripts,
        node_keys,
        totp_qr,
        totp_secret,
        lookup_codes: lookup_codes(flow),
    }
}

/// The flow's `ui.nodes` array, or an empty slice on any miss.
fn nodes(flow: &Value) -> &[Value] {
    flow.get("ui")
        .and_then(|ui| ui.get("nodes"))
        .and_then(|n| n.as_array())
        .map_or(&[], Vec::as_slice)
}

/// Presence key for [`Flow::has_node`]: `attributes.id`, else `attributes.name`.
fn node_key(node: &Value) -> &str {
    node.get("attributes")
        .and_then(|a| a.get("id"))
        .or_else(|| node.get("attributes").and_then(|a| a.get("name")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// The first `csrf_token` node's string value, searched over every node.
fn csrf_token(flow: &Value) -> Option<String> {
    nodes(flow).iter().find_map(|node| {
        if node.pointer("/attributes/name")?.as_str()? == "csrf_token" {
            node.pointer("/attributes/value")?
                .as_str()
                .map(str::to_string)
        } else {
            None
        }
    })
}

/// The `return_to` query parameter of the flow's `request_url`, decoded.
fn request_return_to(flow: &Value) -> String {
    let url = flow
        .get("request_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "return_to")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// True when Kratos's `recovery.after.password` hook issued this settings flow.
fn is_recovery_handoff(flow: &Value) -> bool {
    let url = flow
        .get("request_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if url.contains("/self-service/recovery") {
        return true;
    }
    if let Some(ctx) = flow.get("internal_context")
        && (ctx.get("recovery_link_token").is_some()
            || ctx.get("RecoveryFlow").is_some()
            || ctx.get("recovery_flow").is_some())
    {
        return true;
    }
    false
}

fn map_message(m: &Value) -> Option<MessageView> {
    let text = m.get("text")?.as_str()?.to_string();
    let severity = match m.get("type").and_then(|t| t.as_str()).unwrap_or("info") {
        "error" => "error",
        "success" => "success",
        _ => "info",
    };
    let id = m.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
    let context = m.get("context").cloned().unwrap_or(Value::Null);
    Some(MessageView {
        text,
        severity,
        id,
        context,
    })
}

fn node_to_input(node: &Value) -> Option<InputView> {
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
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Null) | None => String::new(),
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
        .unwrap_or(Value::Null);

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
        provider_display: String::new(),
        provider_icon_svg: "",
    })
}

fn node_to_script(node: &Value) -> Option<ScriptView> {
    if node.get("type").and_then(|t| t.as_str()) != Some("script") {
        return None;
    }
    let attrs = node.get("attributes").and_then(|a| a.as_object())?;
    let src = attrs.get("src").and_then(|s| s.as_str())?;
    let str_attr = |k: &str| attrs.get(k).and_then(|v| v.as_str()).map(str::to_string);
    Some(ScriptView {
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
    })
}

/// TOTP's QR-code data URI and human-readable secret from the flow's non-input
/// nodes. Kratos emits `node.type=="img"` (with `attributes.id == "totp_qr"`,
/// `attributes.src == "data:image/png;base64,..."`) and `node.type=="text"`
/// (`attributes.id == "totp_secret_key"`, `attributes.text.text ==
/// "JBSWY3DPEHPK3PXP"`) during enrolment. After enrolment those nodes disappear
/// and only an `unlink` submit remains.
fn totp_qr_and_secret(flow: &Value) -> (Option<String>, Option<String>) {
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

/// Freshly generated lookup-secret codes from the flow's text nodes. Kratos
/// returns them once, in `attributes.text.context.secrets[]` of a
/// `node.type=="text"` whose `attributes.id == "lookup_secret_codes"`; later
/// renders of the flow don't include them.
fn lookup_codes(flow: &Value) -> Vec<String> {
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
                    } else if let Some(s) = item.get("secret").and_then(|v| v.as_str())
                        && !s.is_empty()
                    {
                        out.push(s.to_string());
                    }
                }
            }
            // Fallback: comma-joined plain text.
            if out.is_empty()
                && let Some(s) = text.get("text").and_then(|v| v.as_str())
            {
                for code in s.split(|c: char| c == ',' || c.is_whitespace()) {
                    let code = code.trim();
                    if !code.is_empty() {
                        out.push(code.to_string());
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_view::GroupedNodes;
    use serde_json::json;

    fn input_node(group: &str, name: &str, input_type: &str, value: Value) -> Value {
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

    fn flow_with(nodes: Vec<Value>) -> Value {
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

    fn group_nodes(flow: &Value) -> GroupedNodes {
        GroupedNodes::from_flow(&project(flow))
    }

    fn collect_input_nodes(flow: &Value, group: &str) -> Vec<InputView> {
        project(flow).inputs(group).cloned().collect()
    }

    #[test]
    fn oidc_provider_ids_lists_provider_submits_in_order() {
        let submit = |group: &str, name: &str, value: &str| {
            json!({
                "type": "input",
                "group": group,
                "attributes": { "name": name, "type": "submit", "value": value },
            })
        };
        let flow = json!({ "ui": { "nodes": [
            submit("default", "csrf_token", "tok"),
            submit("oidc", "provider", "github"),
            submit("oidc", "provider", "playground"),
            submit("oidc", "provider", "github"),
            submit("oidc", "link", "google"),
            submit("password", "provider", "nope"),
            { "type": "input", "group": "oidc",
              "attributes": { "name": "provider", "type": "hidden", "value": "hidden-one" } },
        ] } });
        assert_eq!(
            project(&flow).oidc_provider_ids(),
            vec!["github", "playground"]
        );
    }

    #[test]
    fn oidc_provider_ids_is_empty_without_oidc_nodes() {
        let flow = json!({ "ui": { "nodes": [
            { "type": "input", "group": "password",
              "attributes": { "name": "method", "type": "submit", "value": "password" } },
        ] } });
        assert!(project(&flow).oidc_provider_ids().is_empty());
        assert!(project(&json!({})).oidc_provider_ids().is_empty());
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
        crate::flow_view::translate_inputs(&mut nodes, &de);
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
        let n3 = input_node("default", "n", "hidden", Value::Null);
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
        let hidden = project(&flow).default_hidden();
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
        let msgs = project(&flow).messages;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "Login failed.");
    }

    // --- TOTP / lookup-secret / has_node -----------------------------------

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
        let f = project(&flow);
        assert_eq!(f.totp_qr.as_deref(), Some("data:image/png;base64,XYZ"));
        assert_eq!(f.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn totp_qr_and_secret_absent_when_not_enrolling() {
        let flow = flow_with(vec![input_node(
            "totp",
            "totp_unlink",
            "submit",
            json!("Unlink"),
        )]);
        let f = project(&flow);
        assert!(f.totp_qr.is_none());
        assert!(f.totp_secret.is_none());
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
        assert_eq!(project(&flow).lookup_codes, vec!["aaa", "bbb", "ccc"]);
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
        assert_eq!(project(&flow).lookup_codes, vec!["aaa", "bbb"]);
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
        assert_eq!(project(&flow).lookup_codes, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn group_has_node_matches_prefix() {
        let flow = project(&flow_with(vec![input_node(
            "totp",
            "totp_unlink",
            "submit",
            json!("Unlink"),
        )]));
        assert!(flow.has_node("totp", "totp_unlink"));
        assert!(!flow.has_node("totp", "totp_qr"));
        assert!(!flow.has_node("password", "totp_unlink"));
    }

    #[test]
    fn has_node_sees_non_input_nodes() {
        let flow = project(&json!({ "ui": { "nodes": [
            { "type": "script", "group": "webauthn",
              "attributes": { "id": "webauthn_script", "src": "/webauthn.js" } },
            { "type": "text", "group": "lookup_secret",
              "attributes": { "id": "lookup_secret_codes", "text": { "text": "a" } } },
        ] } }));
        assert!(flow.has_node("webauthn", "webauthn_script"));
        assert!(flow.has_node("lookup_secret", "lookup_secret_codes"));
    }

    // --- form_target + flow_state + return_to ------------------------------

    #[test]
    fn form_target_pulls_action_and_method() {
        let flow = project(&flow_with(vec![]));
        assert_eq!(
            flow.form_action,
            "https://kratos/self-service/login?flow=abc"
        );
        assert_eq!(flow.form_method, "POST");
    }

    #[test]
    fn form_target_defaults_method_to_post() {
        let flow = project(&json!({"ui": {"action": "x"}, "state": "y"}));
        assert_eq!(flow.form_action, "x");
        assert_eq!(flow.form_method, "POST");
    }

    #[test]
    fn flow_state_returns_state_field() {
        assert_eq!(project(&flow_with(vec![])).state, "choose_method");
    }

    #[test]
    fn flow_return_to_reads_field_when_present() {
        let flow = json!({"return_to": "http://localhost:3000/oauth/login?login_challenge=abc"});
        assert_eq!(
            project(&flow).return_to.as_deref(),
            Some("http://localhost:3000/oauth/login?login_challenge=abc"),
        );
    }

    #[test]
    fn flow_return_to_none_when_missing_or_empty() {
        assert_eq!(project(&json!({})).return_to, None);
        assert_eq!(project(&json!({"return_to": ""})).return_to, None);
        assert_eq!(project(&json!({"return_to": null})).return_to, None);
    }

    // --- scalars -----------------------------------------------------------

    #[test]
    fn scalars_project_from_the_flow_body() {
        let flow = project(&json!({
            "id": "f1",
            "requested_aal": "aal2",
            "refresh": true,
            "issued_at": "2026-01-01T10:00:00Z",
            "request_url": "http://kratos/self-service/settings/browser?return_to=http%3A%2F%2Flocalhost%3A3000%2Fsettings%2F2fa",
            "ui": { "nodes": [
                { "type": "input", "group": "default",
                  "attributes": { "name": "csrf_token", "type": "hidden", "value": "tok" } },
            ] },
        }));
        assert_eq!(flow.id, "f1");
        assert_eq!(flow.requested_aal.as_deref(), Some("aal2"));
        assert!(flow.refresh);
        assert_eq!(flow.issued_at.as_deref(), Some("2026-01-01T10:00:00Z"));
        assert_eq!(flow.request_return_to, "http://localhost:3000/settings/2fa");
        assert!(!flow.recovery_handoff);
        assert_eq!(flow.csrf_token.as_deref(), Some("tok"));
    }

    #[test]
    fn recovery_handoff_from_request_url_or_internal_context() {
        let by_url = json!({"request_url": "http://kratos/self-service/recovery?flow=r"});
        assert!(project(&by_url).recovery_handoff);
        for key in ["recovery_link_token", "RecoveryFlow", "recovery_flow"] {
            let by_ctx = json!({"internal_context": { key: "x" }});
            assert!(project(&by_ctx).recovery_handoff, "{key}");
        }
        assert!(!project(&json!({"internal_context": {}})).recovery_handoff);
    }

    #[test]
    fn csrf_token_skips_non_string_values() {
        let flow = json!({ "ui": { "nodes": [
            { "type": "input", "group": "default",
              "attributes": { "name": "csrf_token", "type": "hidden", "value": null } },
            { "type": "input", "group": "default",
              "attributes": { "name": "csrf_token", "type": "hidden", "value": "second" } },
        ] } });
        assert_eq!(project(&flow).csrf_token.as_deref(), Some("second"));
        assert_eq!(project(&json!({})).csrf_token, None);
    }

    #[test]
    fn webauthn_scripts_list_webauthn_then_passkey() {
        let script = |group: &str, src: &str| {
            json!({ "type": "script", "group": group,
                    "attributes": { "src": src, "async": true, "id": "s" } })
        };
        let flow = project(&json!({ "ui": { "nodes": [
            script("passkey", "/passkey.js"),
            script("webauthn", "/webauthn.js"),
            script("default", "/other.js"),
        ] } }));
        let srcs: Vec<_> = flow.webauthn_scripts().into_iter().map(|s| s.src).collect();
        assert_eq!(srcs, vec!["/webauthn.js", "/passkey.js"]);
    }
}

/// Flows captured from the playground Kratos by `tests/fixtures/kratos_flows/capture.sh`.
#[cfg(test)]
mod kratos_fixtures {
    use std::collections::BTreeSet;

    use super::*;

    /// (group, name, input type, label id, required) of an input node.
    type Node = (&'static str, &'static str, &'static str, u64, bool);

    struct Case {
        file: &'static str,
        json: &'static str,
        /// Path segment of `ui.action`; `None` when the action leaves self-service.
        kind: Option<&'static str>,
        state: &'static str,
        messages: &'static [u64],
        nodes: Vec<Node>,
    }

    const CSRF: Node = ("default", "csrf_token", "hidden", 0, true);
    const LOGIN: &[Node] = &[
        CSRF,
        ("default", "identifier", "text", 1070002, true),
        ("password", "password", "password", 1070001, true),
        ("password", "method", "submit", 1010022, false),
    ];
    const REFRESH: &[Node] = &[
        CSRF,
        ("default", "identifier", "hidden", 0, false),
        ("password", "password", "password", 1070001, true),
        ("password", "method", "submit", 1010001, false),
    ];
    const TOTP_STEP_UP: &[Node] = &[
        CSRF,
        ("totp", "totp_code", "text", 1010006, true),
        ("totp", "method", "submit", 1010009, false),
    ];
    const LOOKUP_STEP_UP: &[Node] = &[
        ("lookup_secret", "lookup_secret", "text", 1010007, true),
        ("lookup_secret", "method", "submit", 1010010, false),
    ];
    const CODE_CHOOSE: &[Node] = &[
        CSRF,
        ("code", "email", "email", 1070007, true),
        ("code", "method", "submit", 1070009, false),
    ];
    const CODE_SENT: &[Node] = &[
        CSRF,
        ("code", "method", "hidden", 0, false),
        ("code", "method", "submit", 1070009, false),
        ("code", "email", "submit", 1070008, false),
    ];
    const SETTINGS: &[Node] = &[
        CSRF,
        ("profile", "traits.email", "email", 1070002, true),
        ("profile", "traits.name.first", "text", 1070002, false),
        ("profile", "traits.name.last", "text", 1070002, false),
        ("profile", "method", "submit", 1070003, false),
        ("password", "password", "password", 1070001, true),
        ("password", "method", "submit", 1070003, false),
    ];
    const TOTP_ENROL: &[Node] = &[
        ("totp", "totp_code", "text", 1070006, true),
        ("totp", "method", "submit", 1070003, false),
        (
            "lookup_secret",
            "lookup_secret_regenerate",
            "submit",
            1050008,
            false,
        ),
    ];
    const TOTP_ENROLLED: &[Node] = &[
        ("totp", "totp_unlink", "submit", 1050004, true),
        (
            "lookup_secret",
            "lookup_secret_regenerate",
            "submit",
            1050008,
            false,
        ),
    ];
    const LOOKUP_GENERATED: &[Node] = &[
        ("totp", "totp_unlink", "submit", 1050004, true),
        (
            "lookup_secret",
            "lookup_secret_confirm",
            "submit",
            1050011,
            false,
        ),
    ];
    const LOOKUP_CONFIRMED: &[Node] = &[
        ("totp", "totp_unlink", "submit", 1050004, true),
        (
            "lookup_secret",
            "lookup_secret_reveal",
            "submit",
            1050007,
            false,
        ),
        (
            "lookup_secret",
            "lookup_secret_disable",
            "submit",
            1050016,
            false,
        ),
    ];
    const LOOKUP_REVEALED: &[Node] = &[
        ("totp", "totp_unlink", "submit", 1050004, true),
        (
            "lookup_secret",
            "lookup_secret_disable",
            "submit",
            1050016,
            false,
        ),
        (
            "lookup_secret",
            "lookup_secret_regenerate",
            "submit",
            1050008,
            false,
        ),
    ];

    fn cat(parts: &[&[Node]]) -> Vec<Node> {
        parts.concat()
    }

    fn cases() -> Vec<Case> {
        // `include_str!` takes a literal path, so the file name is spliced in at compile time.
        macro_rules! case {
            ($file:literal, $kind:expr, $state:literal, $messages:expr, $nodes:expr) => {
                Case {
                    file: $file,
                    json: include_str!(concat!("../tests/fixtures/kratos_flows/", $file, ".json")),
                    kind: $kind,
                    state: $state,
                    messages: $messages,
                    nodes: $nodes,
                }
            };
        }
        let (login, reg, ver, rec, set) = (
            Some("login"),
            Some("registration"),
            Some("verification"),
            Some("recovery"),
            Some("settings"),
        );
        vec![
            case!("login", login, "choose_method", &[], cat(&[LOGIN])),
            case!(
                "login_invalid_credentials",
                login,
                "choose_method",
                &[4000006],
                cat(&[LOGIN])
            ),
            case!(
                "login_aal2_no_second_factor",
                login,
                "choose_method",
                &[1010004],
                cat(&[&[CSRF]])
            ),
            case!(
                "login_aal2_totp",
                login,
                "choose_method",
                &[1010004],
                cat(&[TOTP_STEP_UP])
            ),
            case!(
                "login_aal2_totp_lookup",
                login,
                "choose_method",
                &[1010004],
                cat(&[TOTP_STEP_UP, LOOKUP_STEP_UP])
            ),
            case!(
                "login_refresh",
                login,
                "choose_method",
                &[1010003],
                cat(&[REFRESH])
            ),
            case!(
                "login_refresh_aal2",
                login,
                "choose_method",
                &[1010003],
                cat(&[REFRESH])
            ),
            case!(
                "registration_profile",
                reg,
                "choose_method",
                &[],
                cat(&[&[
                    CSRF,
                    ("default", "traits.email", "email", 1070002, true),
                    ("default", "traits.name.first", "text", 1070002, false),
                    ("default", "traits.name.last", "text", 1070002, false),
                    ("profile", "method", "submit", 1040001, false),
                ]])
            ),
            case!(
                "registration_password",
                reg,
                "choose_method",
                &[1040009],
                cat(&[&[
                    CSRF,
                    ("default", "traits.email", "hidden", 1070002, true),
                    ("default", "traits.name.first", "hidden", 1070002, false),
                    ("default", "traits.name.last", "hidden", 1070002, false),
                    ("password", "password", "password", 1070001, true),
                    ("password", "method", "submit", 1040001, false),
                    ("profile", "screen", "submit", 1040008, false),
                ]])
            ),
            case!(
                "verification_choose_method",
                ver,
                "choose_method",
                &[],
                cat(&[CODE_CHOOSE])
            ),
            case!(
                "verification_sent_email",
                ver,
                "sent_email",
                &[1080003],
                cat(&[CODE_SENT, &[("code", "code", "text", 1070011, true)]])
            ),
            case!(
                "verification_passed_challenge",
                None,
                "passed_challenge",
                &[1080002],
                cat(&[&[CSRF]])
            ),
            case!(
                "recovery_choose_method",
                rec,
                "choose_method",
                &[],
                cat(&[CODE_CHOOSE])
            ),
            case!(
                "recovery_sent_email",
                rec,
                "sent_email",
                &[1060003],
                cat(&[CODE_SENT, &[("code", "code", "text", 1070010, true)]])
            ),
            case!(
                "recovery_passed_challenge",
                rec,
                "passed_challenge",
                &[],
                cat(&[CODE_SENT, &[("code", "code", "text", 1070010, true)]])
            ),
            case!(
                "settings_recovery_handoff",
                set,
                "show_form",
                &[1060001],
                cat(&[SETTINGS, TOTP_ENROL])
            ),
            case!(
                "settings_fresh",
                set,
                "show_form",
                &[],
                cat(&[SETTINGS, TOTP_ENROL])
            ),
            case!(
                "settings_totp_pending",
                set,
                "show_form",
                &[],
                cat(&[SETTINGS, TOTP_ENROL])
            ),
            case!(
                "settings_totp_enrolled_submit",
                set,
                "success",
                &[1050001],
                cat(&[SETTINGS, TOTP_ENROLLED])
            ),
            case!(
                "settings_totp_enrolled",
                set,
                "show_form",
                &[],
                cat(&[SETTINGS, TOTP_ENROLLED])
            ),
            case!(
                "settings_lookup_generated",
                set,
                "show_form",
                &[],
                cat(&[SETTINGS, LOOKUP_GENERATED])
            ),
            case!(
                "settings_lookup_confirmed_submit",
                set,
                "success",
                &[1050001],
                cat(&[SETTINGS, LOOKUP_CONFIRMED])
            ),
            case!(
                "settings_lookup_confirmed",
                set,
                "show_form",
                &[],
                cat(&[SETTINGS, LOOKUP_CONFIRMED])
            ),
            case!(
                "settings_lookup_revealed",
                set,
                "show_form",
                &[],
                cat(&[SETTINGS, LOOKUP_REVEALED])
            ),
        ]
    }

    fn case(file: &str) -> Flow {
        let case = cases()
            .into_iter()
            .find(|c| c.file == file)
            .expect("fixture listed");
        project(&serde_json::from_str(case.json).expect("fixture is JSON"))
    }

    #[test]
    fn every_fixture_projects_with_the_node_contract() {
        for case in cases() {
            let file = case.file;
            let flow = project(&serde_json::from_str(case.json).expect("fixture is JSON"));
            assert!(!flow.id.is_empty(), "{file}: id");
            assert_eq!(flow.state, case.state, "{file}: state");
            if let Some(kind) = case.kind {
                // A settings flow in `success` keeps its id; its action targets a fresh flow.
                let action = if flow.state == "success" {
                    format!("/self-service/{kind}?flow=")
                } else {
                    format!("/self-service/{kind}?flow={}", flow.id)
                };
                assert!(
                    flow.form_action.contains(&action),
                    "{file}: {}",
                    flow.form_action
                );
                if flow.state == "success" {
                    assert!(!flow.form_action.ends_with(&flow.id), "{file}");
                }
            }
            let messages: Vec<u64> = flow.messages.iter().map(|m| m.id).collect();
            assert_eq!(messages, case.messages, "{file}: messages");
            assert!(flow.csrf_token.is_some(), "{file}: csrf token");

            let set: BTreeSet<(&str, &str, &str, u64, bool)> = flow
                .inputs
                .iter()
                .map(|(group, i)| {
                    let (name, input_type) = (i.name.as_str(), i.input_type.as_str());
                    (group.as_str(), name, input_type, i.label_id, i.required)
                })
                .collect();
            assert!(!set.is_empty(), "{file}: nodes");
            for node in &case.nodes {
                assert!(set.contains(node), "{file}: missing {node:?} in {set:#?}");
            }
            // Handlers post `method=<group>`; Kratos names every method submit after its group.
            for (group, input) in &flow.inputs {
                if input.name == "method" && input.input_type == "submit" {
                    assert_eq!(&input.value, group, "{file}: method value");
                }
            }
        }
    }

    #[test]
    fn login_flags_follow_the_init_parameters() {
        for case in cases().into_iter().filter(|c| c.kind == Some("login")) {
            let file = case.file;
            let flow = project(&serde_json::from_str(case.json).expect("fixture is JSON"));
            let aal = if file.starts_with("login_aal2") {
                "aal2"
            } else {
                "aal1"
            };
            assert_eq!(flow.requested_aal.as_deref(), Some(aal), "{file}");
            assert_eq!(flow.refresh, file.starts_with("login_refresh"), "{file}");
        }
    }

    #[test]
    fn settings_fixtures_carry_the_two_factor_page_contract() {
        // (file, totp_unlink, lookup_secret_disable, lookup_secret_reveal, lookup codes, enrolment QR)
        let expected = [
            ("settings_fresh", false, false, false, 0, true),
            ("settings_recovery_handoff", false, false, false, 0, true),
            ("settings_totp_pending", false, false, false, 0, true),
            (
                "settings_totp_enrolled_submit",
                true,
                false,
                false,
                0,
                false,
            ),
            ("settings_totp_enrolled", true, false, false, 0, false),
            ("settings_lookup_generated", true, false, false, 12, false),
            (
                "settings_lookup_confirmed_submit",
                true,
                true,
                true,
                0,
                false,
            ),
            ("settings_lookup_confirmed", true, true, true, 0, false),
            ("settings_lookup_revealed", true, true, false, 12, false),
        ];
        for (file, unlink, disable, reveal, codes, qr) in expected {
            let flow = case(file);
            assert_eq!(flow.has_node("totp", "totp_unlink"), unlink, "{file}");
            assert_eq!(
                flow.has_node("lookup_secret", "lookup_secret_disable"),
                disable,
                "{file}"
            );
            assert_eq!(
                flow.has_node("lookup_secret", "lookup_secret_reveal"),
                reveal,
                "{file}"
            );
            assert_eq!(flow.lookup_codes.len(), codes, "{file}");
            assert_eq!(
                flow.has_node("lookup_secret", "lookup_secret_codes"),
                codes > 0,
                "{file}"
            );
            assert_eq!(flow.totp_qr.is_some(), qr, "{file}");
            assert_eq!(flow.totp_secret.is_some(), qr, "{file}");
            assert_eq!(
                flow.recovery_handoff,
                file == "settings_recovery_handoff",
                "{file}"
            );
        }
    }

    #[test]
    fn invalid_totp_code_is_reported_on_its_node() {
        let flow = case("settings_totp_pending");
        let code = flow
            .inputs("totp")
            .find(|i| i.name == "totp_code")
            .expect("totp_code");
        let ids: Vec<u64> = code.messages.iter().map(|m| m.id).collect();
        assert_eq!(ids, [4000008]);
    }

    #[test]
    fn verification_success_offers_the_continue_link() {
        let flow = case("verification_passed_challenge");
        assert!(flow.has_node("code", "continue"));
        assert_eq!(flow.inputs.len(), 1, "only the csrf token is an input");
    }
}
