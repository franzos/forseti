//! Flow documents in Kratos's wire shape, one builder per kind and state, read by
//! [`crate::flow_json::project`]. Node names, groups, label ids and messages follow the captured
//! Kratos flows in `tests/fixtures/kratos_flows/`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::backend::identity::FlowKind;

/// A `ui.messages` entry, or a message on one node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct Message {
    pub(super) id: u64,
    /// `info`, `error` or `success`.
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) context: Option<Value>,
}

impl Message {
    pub(super) fn info(id: u64, text: impl Into<String>) -> Self {
        Self::new(id, "info", text)
    }

    pub(super) fn error(id: u64, text: impl Into<String>) -> Self {
        Self::new(id, "error", text)
    }

    pub(super) fn success(id: u64, text: impl Into<String>) -> Self {
        Self::new(id, "success", text)
    }

    fn new(id: u64, kind: &str, text: impl Into<String>) -> Self {
        Self {
            id,
            kind: kind.to_string(),
            text: text.into(),
            context: None,
        }
    }

    pub(super) fn with_context(mut self, context: Value) -> Self {
        self.context = Some(context);
        self
    }

    fn to_json(&self) -> Value {
        let mut m = json!({ "id": self.id, "text": self.text, "type": self.kind });
        if let Some(ctx) = &self.context {
            m["context"] = ctx.clone();
        }
        m
    }
}

/// A message shown under the input named `node`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct NodeMessage {
    pub(super) node: String,
    pub(super) message: Message,
}

/// The flow-level fields of a document.
pub(super) struct Meta<'a> {
    pub(super) id: &'a str,
    pub(super) kind: FlowKind,
    pub(super) request_url: &'a str,
    pub(super) return_to: Option<&'a str>,
    pub(super) issued_at: &'a str,
    pub(super) expires_at: &'a str,
    /// Value of the `csrf_token` node: the browser's Forseti CSRF token.
    pub(super) csrf_token: &'a str,
    /// Login only.
    pub(super) requested_aal: Option<&'a str>,
    /// Login only.
    pub(super) refresh: bool,
}

/// Messages stored on the flow by earlier submits, shown after the state's own.
#[derive(Clone, Copy, Default)]
pub(super) struct Notes<'a> {
    pub(super) flow: &'a [Message],
    pub(super) nodes: &'a [NodeMessage],
}

#[derive(Clone, Copy, Default)]
pub(super) struct Traits<'a> {
    pub(super) email: &'a str,
    pub(super) first: &'a str,
    pub(super) last: &'a str,
}

pub(super) enum Screen<'a> {
    Login(Login<'a>),
    Registration(Registration<'a>),
    Verification(Code<'a>),
    Recovery(Code<'a>),
    Settings(Settings<'a>),
}

pub(super) enum Login<'a> {
    /// Sign-in with identifier and password; `identifier` echoes a failed attempt.
    Password { identifier: &'a str },
    /// Re-authentication of the signed-in identity.
    Refresh { identifier: &'a str },
    /// Second factor; with neither factor enrolled only the CSRF token and message 1010004 remain.
    SecondFactor { totp: bool, lookup: bool },
}

pub(super) enum Registration<'a> {
    /// Step 1: the traits, echoed after a failed attempt.
    Profile(Traits<'a>),
    /// Step 2: the traits ride along hidden while a password is chosen.
    Password(Traits<'a>),
}

pub(super) enum Code<'a> {
    ChooseMethod,
    /// `code` prefills the code input.
    SentEmail {
        email: &'a str,
        code: &'a str,
    },
    /// Verification links to `continue_to`; recovery keeps the code form.
    PassedChallenge {
        email: &'a str,
        continue_to: &'a str,
    },
}

pub(super) struct Settings<'a> {
    pub(super) traits: Traits<'a>,
    pub(super) totp: Totp<'a>,
    pub(super) lookup: Lookup<'a>,
    /// The last submit was saved: state `success`, message 1050001.
    pub(super) saved: bool,
    /// Settings flow handed over by a completed recovery.
    pub(super) handoff: Option<Handoff>,
}

pub(super) enum Totp<'a> {
    /// Not enrolled: the enrolment QR (a data URI) and the base32 secret.
    Pending {
        qr: &'a str,
        secret: &'a str,
    },
    Enrolled,
}

/// Lookup states. Stored codes are MACs and are shown only at generation, so unlike Kratos there
/// is no reveal and no revealed state.
pub(super) enum Lookup<'a> {
    /// No TOTP, so no lookup group at all.
    Unavailable,
    /// TOTP enrolled, no codes yet.
    Offer,
    /// Fresh codes waiting for confirmation.
    Generated(&'a [String]),
    /// Codes stored: regenerate or disable.
    Confirmed,
}

pub(super) struct Handoff {
    /// End of the privileged window.
    pub(super) until: chrono::DateTime<chrono::Utc>,
    pub(super) window_minutes: u32,
}

impl Screen<'_> {
    /// Kratos's `state` for this screen.
    pub(super) fn state(&self) -> &'static str {
        match self {
            Screen::Login(_) | Screen::Registration(_) => "choose_method",
            Screen::Verification(code) | Screen::Recovery(code) => match code {
                Code::ChooseMethod => "choose_method",
                Code::SentEmail { .. } => "sent_email",
                Code::PassedChallenge { .. } => "passed_challenge",
            },
            Screen::Settings(s) if s.saved => "success",
            Screen::Settings(_) => "show_form",
        }
    }
}

/// The Kratos-shaped flow document for `screen`.
pub(super) fn document(meta: &Meta<'_>, screen: &Screen<'_>, notes: Notes<'_>) -> Value {
    let mut nodes = Vec::new();
    let mut messages = Vec::new();
    let mut action = format!(
        "/self-service/{}?flow={}",
        meta.kind.path_segment(),
        meta.id
    );
    let csrf = input("default", "csrf_token", "hidden")
        .value(meta.csrf_token)
        .required();
    match screen {
        Screen::Login(login) => {
            nodes.push(csrf);
            login_nodes(login, &mut nodes, &mut messages);
        }
        Screen::Registration(reg) => {
            nodes.push(csrf);
            registration_nodes(reg, &mut nodes, &mut messages);
        }
        Screen::Verification(code) => {
            if let Code::PassedChallenge { continue_to, .. } = code {
                action = (*continue_to).to_string();
            }
            verification_nodes(code, csrf, &mut nodes, &mut messages);
        }
        Screen::Recovery(code) => {
            nodes.push(csrf);
            recovery_nodes(code, &mut nodes, &mut messages);
        }
        Screen::Settings(settings) => {
            nodes.push(csrf);
            settings_nodes(settings, &mut nodes, &mut messages);
        }
    }
    messages.extend(notes.flow.iter().map(Message::to_json));

    let mut nodes: Vec<Value> = nodes.into_iter().map(Node::into_json).collect();
    for note in notes.nodes {
        if let Some(node) = nodes
            .iter_mut()
            .find(|n| n.pointer("/attributes/name").and_then(Value::as_str) == Some(&note.node))
            && let Some(list) = node.get_mut("messages").and_then(Value::as_array_mut)
        {
            list.push(note.message.to_json());
        }
    }

    let is_login = matches!(meta.kind, FlowKind::Login);
    json!({
        "id": meta.id,
        "type": "browser",
        "state": screen.state(),
        "request_url": meta.request_url,
        "return_to": meta.return_to,
        "requested_aal": if is_login { json!(meta.requested_aal.unwrap_or("aal1")) } else { Value::Null },
        "refresh": if is_login { json!(meta.refresh) } else { Value::Null },
        "issued_at": meta.issued_at,
        "expires_at": meta.expires_at,
        "ui": {
            "action": action,
            "method": "POST",
            "nodes": nodes,
            "messages": messages,
        },
    })
}

fn login_nodes(login: &Login<'_>, nodes: &mut Vec<Node>, messages: &mut Vec<Value>) {
    match login {
        Login::Password { identifier } => {
            nodes.push(
                input("default", "identifier", "text")
                    .value(identifier)
                    .required()
                    .attr("autocomplete", "username")
                    .label(email_label()),
            );
            nodes.push(password("current-password"));
            nodes.push(method("password", 1_010_022, "Sign in with password"));
        }
        Login::Refresh { identifier } => {
            messages.push(
                Message::info(
                    1_010_003,
                    "Please confirm this action by verifying that it is you.",
                )
                .to_json(),
            );
            nodes.push(input("default", "identifier", "hidden").value(identifier));
            nodes.push(password("current-password"));
            nodes.push(method("password", 1_010_001, "Sign in"));
        }
        Login::SecondFactor { totp, lookup } => {
            messages.push(
                Message::info(
                    1_010_004,
                    "Please complete the second authentication challenge.",
                )
                .to_json(),
            );
            if *totp {
                nodes.push(
                    input("totp", "totp_code", "text")
                        .required()
                        .label(label(1_010_006, "Authentication code")),
                );
                nodes.push(method("totp", 1_010_009, "Use Authenticator"));
                if *lookup {
                    nodes.push(
                        input("lookup_secret", "lookup_secret", "text")
                            .required()
                            .label(label(1_010_007, "Backup recovery code")),
                    );
                    nodes.push(method(
                        "lookup_secret",
                        1_010_010,
                        "Use backup recovery code",
                    ));
                }
            }
        }
    }
}

fn registration_nodes(reg: &Registration<'_>, nodes: &mut Vec<Node>, messages: &mut Vec<Value>) {
    match reg {
        Registration::Profile(traits) => {
            trait_nodes("default", traits, false, nodes);
            nodes.push(method("profile", 1_040_001, "Sign up"));
        }
        Registration::Password(traits) => {
            messages.push(
                Message::info(
                    1_040_009,
                    "Please choose a credential to authenticate yourself with.",
                )
                .to_json(),
            );
            trait_nodes("default", traits, true, nodes);
            nodes.push(password("new-password"));
            nodes.push(method("password", 1_040_001, "Sign up"));
            nodes.push(
                input("profile", "screen", "submit")
                    .value("previous")
                    .label(label(1_040_008, "Back")),
            );
        }
    }
}

fn verification_nodes(
    code: &Code<'_>,
    csrf: Node,
    nodes: &mut Vec<Node>,
    messages: &mut Vec<Value>,
) {
    match code {
        Code::ChooseMethod => {
            nodes.push(email_input());
            nodes.push(method("code", 1_070_009, "Continue"));
            nodes.push(csrf);
        }
        Code::SentEmail { email, code } => {
            messages.push(
                Message::info(
                    1_080_003,
                    "An email containing a verification code has been sent to the email address you provided. If you have not received an email, check the spelling of the address and make sure to use the address you registered with.",
                )
                .to_json(),
            );
            nodes.push(input("code", "method", "hidden").value("code"));
            nodes.push(
                input("code", "code", "text")
                    .value(code)
                    .required()
                    .label(label(1_070_011, "Verification code")),
            );
            nodes.push(method("code", 1_070_009, "Continue"));
            nodes.push(csrf);
            nodes.push(resend(email));
        }
        Code::PassedChallenge { continue_to, .. } => {
            messages.push(
                Message::success(1_080_002, "You successfully verified your email address.")
                    .to_json(),
            );
            nodes.push(csrf);
            nodes.push(Node::Raw(json!({
                "type": "a",
                "group": "code",
                "attributes": {
                    "href": continue_to,
                    "title": { "id": 1_070_009, "text": "Continue", "type": "info" },
                    "id": "continue",
                    "node_type": "a",
                },
                "messages": [],
                "meta": { "label": label(1_070_009, "Continue") },
            })));
        }
    }
}

fn recovery_nodes(code: &Code<'_>, nodes: &mut Vec<Node>, messages: &mut Vec<Value>) {
    match code {
        Code::ChooseMethod => {
            nodes.push(email_input());
            nodes.push(method("code", 1_070_009, "Continue"));
        }
        Code::SentEmail { email, code } => {
            messages.push(
                Message::info(
                    1_060_003,
                    "An email containing a recovery code has been sent to the email address you provided. If you have not received an email, check the spelling of the address and make sure to use the address you registered with.",
                )
                .to_json(),
            );
            recovery_code_form(email, code, nodes);
        }
        Code::PassedChallenge { email, .. } => recovery_code_form(email, "", nodes),
    }
}

fn recovery_code_form(email: &str, code: &str, nodes: &mut Vec<Node>) {
    nodes.push(
        input("code", "code", "text")
            .value(code)
            .required()
            .attr("pattern", "[0-9]+")
            .attr("maxlength", 6)
            .label(label(1_070_010, "Recovery code")),
    );
    nodes.push(input("code", "method", "hidden").value("code"));
    nodes.push(method("code", 1_070_009, "Continue"));
    nodes.push(resend(email));
}

fn settings_nodes(settings: &Settings<'_>, nodes: &mut Vec<Node>, messages: &mut Vec<Value>) {
    if let Some(handoff) = &settings.handoff {
        let until = crate::db::rfc3339(handoff.until);
        messages.push(
            Message::success(
                1_060_001,
                format!(
                    "You successfully recovered your account. Please change your password or set up an alternative login method (e.g. social sign in) within the next {}.00 minutes.",
                    handoff.window_minutes
                ),
            )
            .with_context(json!({
                "privilegedSessionExpiresAt": until,
                "privileged_session_expires_at": until,
                "privileged_session_expires_at_unix": handoff.until.timestamp(),
            }))
            .to_json(),
        );
    }
    if settings.saved {
        messages.push(Message::success(1_050_001, "Your changes have been saved!").to_json());
    }

    trait_nodes("profile", &settings.traits, false, nodes);
    nodes.push(method("profile", 1_070_003, "Save"));
    nodes.push(password("new-password"));
    nodes.push(method("password", 1_070_003, "Save"));

    match settings.totp {
        Totp::Pending { qr, secret } => {
            nodes.push(Node::Raw(json!({
                "type": "img",
                "group": "totp",
                "attributes": {
                    "src": qr,
                    "id": "totp_qr",
                    "width": 256,
                    "height": 256,
                    "node_type": "img",
                },
                "messages": [],
                "meta": { "label": label(1_050_005, "Authenticator app QR code") },
            })));
            nodes.push(Node::Raw(json!({
                "type": "text",
                "group": "totp",
                "attributes": {
                    "text": {
                        "id": 1_050_006,
                        "text": secret,
                        "type": "info",
                        "context": { "secret": secret },
                    },
                    "id": "totp_secret_key",
                    "node_type": "text",
                },
                "messages": [],
                "meta": {
                    "label": label(
                        1_050_017,
                        "This is your authenticator app secret. Use it if you can not scan the QR code.",
                    ),
                },
            })));
            nodes.push(
                input("totp", "totp_code", "text")
                    .required()
                    .label(label(1_070_006, "Verify code")),
            );
            nodes.push(method("totp", 1_070_003, "Save"));
        }
        Totp::Enrolled => nodes.push(
            input("totp", "totp_unlink", "submit")
                .value("true")
                .required()
                .label(label(1_050_004, "Unlink TOTP Authenticator App")),
        ),
    }

    let regenerate = || {
        lookup_submit(
            "lookup_secret_regenerate",
            1_050_008,
            "Generate new backup recovery codes",
        )
    };
    let disable = || lookup_submit("lookup_secret_disable", 1_050_016, "Disable this method");
    match settings.lookup {
        Lookup::Unavailable => {}
        Lookup::Offer => nodes.push(regenerate()),
        Lookup::Generated(codes) => {
            nodes.push(lookup_codes(codes));
            nodes.push(lookup_submit(
                "lookup_secret_confirm",
                1_050_011,
                "Confirm backup recovery codes",
            ));
        }
        Lookup::Confirmed => {
            nodes.push(regenerate());
            nodes.push(disable());
        }
    }
}

fn lookup_codes(codes: &[String]) -> Node {
    let secrets: Vec<Value> = codes
        .iter()
        .map(|c| json!({ "id": 1_050_009, "text": c, "type": "info", "context": { "secret": c } }))
        .collect();
    Node::Raw(json!({
        "type": "text",
        "group": "lookup_secret",
        "attributes": {
            "text": {
                "id": 1_050_015,
                "text": codes.join(", "),
                "type": "info",
                "context": { "secrets": secrets },
            },
            "id": "lookup_secret_codes",
            "node_type": "text",
        },
        "messages": [],
        "meta": {
            "label": label(
                1_050_010,
                "These are your back up recovery codes. Please keep them in a safe place!",
            ),
        },
    }))
}

fn lookup_submit(name: &str, label_id: u64, text: &str) -> Node {
    input("lookup_secret", name, "submit")
        .value("true")
        .label(label(label_id, text))
}

/// `traits.email`, `traits.name.first` and `traits.name.last` in `group`.
fn trait_nodes(group: &str, traits: &Traits<'_>, hidden: bool, nodes: &mut Vec<Node>) {
    let ty = |visible: &'static str| if hidden { "hidden" } else { visible };
    nodes.push(
        input(group, "traits.email", ty("email"))
            .value(traits.email)
            .required()
            .attr("autocomplete", "email")
            .label(email_label()),
    );
    nodes.push(
        input(group, "traits.name.first", ty("text"))
            .value(traits.first)
            .label(trait_label("traits.name.first", "First Name")),
    );
    nodes.push(
        input(group, "traits.name.last", ty("text"))
            .value(traits.last)
            .label(trait_label("traits.name.last", "Last Name")),
    );
}

fn email_input() -> Node {
    input("code", "email", "email")
        .required()
        .label(label(1_070_007, "Email"))
}

fn resend(email: &str) -> Node {
    input("code", "email", "submit")
        .value(email)
        .label(label(1_070_008, "Resend code"))
}

fn password(autocomplete: &str) -> Node {
    input("password", "password", "password")
        .required()
        .attr("autocomplete", autocomplete)
        .label(label(1_070_001, "Password"))
}

/// The `method=<group>` submit Kratos names after its group.
fn method(group: &str, label_id: u64, text: &str) -> Node {
    input(group, "method", "submit")
        .value(group)
        .label(label(label_id, text))
}

fn label(id: u64, text: &str) -> Value {
    json!({ "id": id, "text": text, "type": "info" })
}

fn trait_label(name: &str, title: &str) -> Value {
    json!({ "id": 1_070_002, "text": title, "type": "info", "context": { "name": name, "title": title } })
}

fn email_label() -> Value {
    trait_label("traits.email", "E-Mail")
}

enum Node {
    Input {
        group: String,
        attributes: Map<String, Value>,
        label: Option<Value>,
    },
    Raw(Value),
}

fn input(group: &str, name: &str, ty: &str) -> Node {
    let mut attributes = Map::new();
    attributes.insert("name".into(), json!(name));
    attributes.insert("type".into(), json!(ty));
    attributes.insert("disabled".into(), json!(false));
    attributes.insert("node_type".into(), json!("input"));
    Node::Input {
        group: group.to_string(),
        attributes,
        label: None,
    }
}

impl Node {
    fn attr(mut self, key: &str, value: impl Into<Value>) -> Self {
        if let Node::Input { attributes, .. } = &mut self {
            attributes.insert(key.to_string(), value.into());
        }
        self
    }

    /// Kratos leaves `value` out when there is none.
    fn value(self, value: &str) -> Self {
        if value.is_empty() {
            self
        } else {
            self.attr("value", value)
        }
    }

    fn required(self) -> Self {
        self.attr("required", true)
    }

    fn label(mut self, value: Value) -> Self {
        if let Node::Input { label, .. } = &mut self {
            *label = Some(value);
        }
        self
    }

    fn into_json(self) -> Value {
        match self {
            Node::Input {
                group,
                attributes,
                label,
            } => json!({
                "type": "input",
                "group": group,
                "attributes": attributes,
                "messages": [],
                "meta": label.map_or_else(|| json!({}), |l| json!({ "label": l })),
            }),
            Node::Raw(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::flow_json::project;
    use crate::settings::two_factor::{PageFlags, page_flags};

    /// (group, node type, name or id, input type, label id, required)
    type Tuple = (String, String, String, String, u64, bool);

    /// Groups the native backend does not offer: upstream OIDC, WebAuthn and passkeys.
    const OUT_OF_SCOPE: &[&str] = &["oidc", "webauthn", "passkey"];

    fn tuples(doc: &Value, without_lookup: bool) -> BTreeSet<Tuple> {
        doc.pointer("/ui/nodes")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|n| {
                let s = |ptr: &str| {
                    n.pointer(ptr)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                };
                let group = s("/group");
                let key = if n.pointer("/attributes/id").is_some() {
                    s("/attributes/id")
                } else {
                    s("/attributes/name")
                };
                // The projector drops this node; language is set at /settings/language.
                let skip = OUT_OF_SCOPE.contains(&group.as_str())
                    || key == "traits.preferred_language"
                    || (without_lookup && group == "lookup_secret");
                (!skip).then(|| {
                    (
                        group,
                        s("/type"),
                        key,
                        s("/attributes/type"),
                        n.pointer("/meta/label/id")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        n.pointer("/attributes/required").and_then(Value::as_bool) == Some(true),
                    )
                })
            })
            .collect()
    }

    fn message_ids(doc: &Value) -> Vec<u64> {
        doc.pointer("/ui/messages")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|m| m["id"].as_u64().unwrap())
            .collect()
    }

    fn node_message_ids(doc: &Value) -> BTreeSet<(String, u64)> {
        let mut out = BTreeSet::new();
        for n in doc.pointer("/ui/nodes").and_then(Value::as_array).unwrap() {
            for m in n["messages"].as_array().unwrap() {
                let name = n
                    .pointer("/attributes/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                out.insert((name.to_string(), m["id"].as_u64().unwrap()));
            }
        }
        out
    }

    fn fixture(file: &str) -> Value {
        let path = format!(
            "{}/tests/fixtures/kratos_flows/{file}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn codes() -> Vec<String> {
        (0..10).map(|i| format!("abc{i}-defg-hijk")).collect()
    }

    const TRAITS: Traits<'static> = Traits {
        email: "ann@example.com",
        first: "Ann",
        last: "Lee",
    };

    struct Case {
        file: &'static str,
        kind: FlowKind,
        requested_aal: Option<&'static str>,
        refresh: bool,
        request_url: &'static str,
        notes: Notes<'static>,
    }

    fn case(file: &'static str, kind: FlowKind) -> Case {
        Case {
            file,
            kind,
            requested_aal: None,
            refresh: false,
            request_url: "http://localhost:3000/self-service/x/browser",
            notes: Notes::default(),
        }
    }

    fn native(case: &Case, screen: &Screen<'_>) -> Value {
        let meta = Meta {
            id: "flow-1",
            kind: case.kind,
            request_url: case.request_url,
            return_to: None,
            issued_at: "2026-11-13T17:26:21.000000+00:00",
            expires_at: "2026-11-13T17:36:21.000000+00:00",
            csrf_token: "csrf-token",
            requested_aal: case.requested_aal,
            refresh: case.refresh,
        };
        document(&meta, screen, case.notes)
    }

    static INVALID_CREDENTIALS: std::sync::LazyLock<Vec<Message>> =
        std::sync::LazyLock::new(|| {
            vec![Message::error(
                4_000_006,
                "The provided credentials are invalid.",
            )]
        });
    static INVALID_TOTP: std::sync::LazyLock<Vec<NodeMessage>> = std::sync::LazyLock::new(|| {
        vec![NodeMessage {
            node: "totp_code".into(),
            message: Message::error(4_000_008, "The provided authentication code is invalid."),
        }]
    });

    fn handoff() -> Handoff {
        Handoff {
            until: chrono::DateTime::parse_from_rfc3339("2026-11-13T17:41:21Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            window_minutes: 15,
        }
    }

    /// Every fixture with the native screen for the same state. The pending TOTP enrolment and
    /// lookup codes are placeholders; the QR is not decoded.
    fn pairs(codes: &[String]) -> Vec<(Case, Screen<'_>)> {
        let pending = || Totp::Pending {
            qr: "data:image/svg+xml;base64,AA==",
            secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        };
        let settings = |totp, lookup, saved, handoff| {
            Screen::Settings(super::Settings {
                traits: TRAITS,
                totp,
                lookup,
                saved,
                handoff,
            })
        };
        let aal2 = |file| Case {
            requested_aal: Some("aal2"),
            ..case(file, FlowKind::Login)
        };
        let refresh = |file| Case {
            requested_aal: Some("aal1"),
            refresh: true,
            ..case(file, FlowKind::Login)
        };
        vec![
            (
                case("login", FlowKind::Login),
                Screen::Login(Login::Password { identifier: "" }),
            ),
            (
                Case {
                    notes: Notes {
                        flow: &INVALID_CREDENTIALS,
                        nodes: &[],
                    },
                    ..case("login_invalid_credentials", FlowKind::Login)
                },
                Screen::Login(Login::Password {
                    identifier: "ann@example.com",
                }),
            ),
            (
                aal2("login_aal2_no_second_factor"),
                Screen::Login(Login::SecondFactor {
                    totp: false,
                    lookup: false,
                }),
            ),
            (
                aal2("login_aal2_totp"),
                Screen::Login(Login::SecondFactor {
                    totp: true,
                    lookup: false,
                }),
            ),
            (
                aal2("login_aal2_totp_lookup"),
                Screen::Login(Login::SecondFactor {
                    totp: true,
                    lookup: true,
                }),
            ),
            (
                refresh("login_refresh"),
                Screen::Login(Login::Refresh {
                    identifier: "ann@example.com",
                }),
            ),
            (
                refresh("login_refresh_aal2"),
                Screen::Login(Login::Refresh {
                    identifier: "ann@example.com",
                }),
            ),
            (
                case("registration_profile", FlowKind::Registration),
                Screen::Registration(super::Registration::Profile(Traits::default())),
            ),
            (
                case("registration_password", FlowKind::Registration),
                Screen::Registration(super::Registration::Password(TRAITS)),
            ),
            (
                case("verification_choose_method", FlowKind::Verification),
                Screen::Verification(Code::ChooseMethod),
            ),
            (
                case("verification_sent_email", FlowKind::Verification),
                Screen::Verification(Code::SentEmail {
                    email: "ann@example.com",
                    code: "",
                }),
            ),
            (
                case("verification_passed_challenge", FlowKind::Verification),
                Screen::Verification(Code::PassedChallenge {
                    email: "ann@example.com",
                    continue_to: "http://localhost:3000/",
                }),
            ),
            (
                case("recovery_choose_method", FlowKind::Recovery),
                Screen::Recovery(Code::ChooseMethod),
            ),
            (
                case("recovery_sent_email", FlowKind::Recovery),
                Screen::Recovery(Code::SentEmail {
                    email: "ann@example.com",
                    code: "",
                }),
            ),
            (
                case("recovery_passed_challenge", FlowKind::Recovery),
                Screen::Recovery(Code::PassedChallenge {
                    email: "ann@example.com",
                    continue_to: "",
                }),
            ),
            (
                case("settings_fresh", FlowKind::Settings),
                settings(pending(), Lookup::Unavailable, false, None),
            ),
            (
                Case {
                    request_url: "http://localhost:3000/self-service/recovery?flow=r&return_to=http%3A%2F%2Flocalhost%3A3000%2F",
                    ..case("settings_recovery_handoff", FlowKind::Settings)
                },
                settings(pending(), Lookup::Unavailable, false, Some(handoff())),
            ),
            (
                Case {
                    notes: Notes {
                        flow: &[],
                        nodes: &INVALID_TOTP,
                    },
                    ..case("settings_totp_pending", FlowKind::Settings)
                },
                settings(pending(), Lookup::Unavailable, false, None),
            ),
            (
                case("settings_totp_enrolled", FlowKind::Settings),
                settings(Totp::Enrolled, Lookup::Offer, false, None),
            ),
            (
                case("settings_totp_enrolled_submit", FlowKind::Settings),
                settings(Totp::Enrolled, Lookup::Offer, true, None),
            ),
            (
                case("settings_lookup_generated", FlowKind::Settings),
                settings(Totp::Enrolled, Lookup::Generated(codes), false, None),
            ),
            (
                case("settings_lookup_confirmed", FlowKind::Settings),
                settings(Totp::Enrolled, Lookup::Confirmed, false, None),
            ),
            (
                case("settings_lookup_confirmed_submit", FlowKind::Settings),
                settings(Totp::Enrolled, Lookup::Confirmed, true, None),
            ),
        ]
    }

    /// Kratos states native does not have: lookup codes are shown only at generation.
    const NO_NATIVE_STATE: &[&str] = &["settings_lookup_revealed"];

    /// The Kratos node tuples a native document must match. Where Kratos offers
    /// `lookup_secret_reveal`, native offers Kratos's `lookup_secret_regenerate` node instead.
    fn expected_tuples(kratos: &Value, without_lookup: bool) -> BTreeSet<Tuple> {
        let mut expected = tuples(kratos, without_lookup);
        let reveal = expected
            .iter()
            .find(|t| t.2 == "lookup_secret_reveal")
            .cloned();
        if let Some(reveal) = reveal {
            expected.remove(&reveal);
            let regenerate = tuples(&fixture("settings_totp_enrolled"), false)
                .into_iter()
                .find(|t| t.2 == "lookup_secret_regenerate")
                .unwrap();
            expected.insert(regenerate);
        }
        expected
    }

    /// Native settings flows omit the lookup group until TOTP is enrolled.
    fn without_lookup(screen: &Screen<'_>) -> bool {
        matches!(
            screen,
            Screen::Settings(super::Settings {
                lookup: Lookup::Unavailable,
                ..
            })
        )
    }

    #[test]
    fn every_fixture_has_a_native_document_with_the_same_nodes_and_messages() {
        let codes = codes();
        let pairs = pairs(&codes);
        let mut files: Vec<&str> = pairs.iter().map(|(c, _)| c.file).collect();
        files.extend(NO_NATIVE_STATE);
        files.sort_unstable();
        let mut on_disk: Vec<String> = std::fs::read_dir(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/kratos_flows"
        ))
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".json").map(str::to_string))
        .collect();
        on_disk.sort_unstable();
        assert_eq!(files, on_disk, "one native screen per fixture");

        for (case, screen) in &pairs {
            let file = case.file;
            let kratos = fixture(file);
            let ours = native(case, screen);
            assert_eq!(
                tuples(&ours, false),
                expected_tuples(&kratos, without_lookup(screen)),
                "{file}: nodes"
            );
            assert_eq!(message_ids(&ours), message_ids(&kratos), "{file}: messages");
            assert_eq!(
                node_message_ids(&ours),
                node_message_ids(&kratos),
                "{file}: node messages"
            );
            assert_eq!(ours["state"], kratos["state"], "{file}: state");
            assert_eq!(screen.state(), kratos["state"], "{file}: state()");

            let (ours, kratos) = (project(&ours), project(&kratos));
            assert_eq!(ours.state, kratos.state, "{file}");
            assert_eq!(
                ours.requested_aal, kratos.requested_aal,
                "{file}: requested_aal"
            );
            assert_eq!(ours.refresh, kratos.refresh, "{file}: refresh");
            // Only settings handlers read the flag; Kratos's own recovery flows also set it.
            if matches!(case.kind, FlowKind::Settings) {
                assert_eq!(
                    ours.recovery_handoff, kratos.recovery_handoff,
                    "{file}: handoff"
                );
            }
            assert_eq!(
                ours.totp_qr.is_some(),
                kratos.totp_qr.is_some(),
                "{file}: qr"
            );
            assert_eq!(
                ours.totp_secret.is_some(),
                kratos.totp_secret.is_some(),
                "{file}"
            );
            assert_eq!(ours.csrf_token.as_deref(), Some("csrf-token"), "{file}");
            // Native lookup codes: 10 of `xxxx-xxxx-xxxx`; Kratos shows 12 of 8 characters.
            assert_eq!(
                ours.lookup_codes.len(),
                kratos.lookup_codes.len() * 10 / 12,
                "{file}"
            );
            if file != "verification_passed_challenge" {
                let action = format!("/self-service/{}?flow=flow-1", case.kind.path_segment());
                assert_eq!(ours.form_action, action, "{file}");
            }
            for (group, input) in &ours.inputs {
                if input.name == "method" && input.input_type == "submit" {
                    assert_eq!(&input.value, group, "{file}: method value");
                }
            }
        }
    }

    #[test]
    fn verification_success_continues_to_the_return_target() {
        let case = case("verification_passed_challenge", FlowKind::Verification);
        let doc = native(
            &case,
            &Screen::Verification(Code::PassedChallenge {
                email: "ann@example.com",
                continue_to: "http://localhost:3000/oauth/login?login_challenge=c",
            }),
        );
        assert_eq!(
            doc.pointer("/ui/action").and_then(Value::as_str),
            Some("http://localhost:3000/oauth/login?login_challenge=c")
        );
        assert!(project(&doc).has_node("code", "continue"));
    }

    #[test]
    fn prefilled_code_and_handoff_context_reach_the_projection() {
        let case = case("verification_sent_email", FlowKind::Verification);
        let flow = project(&native(
            &case,
            &Screen::Verification(Code::SentEmail {
                email: "ann@example.com",
                code: "123456",
            }),
        ));
        let code = flow.inputs("code").find(|i| i.name == "code").unwrap();
        assert_eq!(code.value, "123456");
        let resend = flow
            .inputs("code")
            .find(|i| i.name == "email" && i.input_type == "submit")
            .unwrap();
        assert_eq!(resend.value, "ann@example.com");

        let doc = native(
            &case_with_handoff(),
            &Screen::Settings(super::Settings {
                traits: TRAITS,
                totp: Totp::Enrolled,
                lookup: Lookup::Offer,
                saved: false,
                handoff: Some(handoff()),
            }),
        );
        let msg = &project(&doc).messages[0];
        assert_eq!(msg.id, 1_060_001);
        assert_eq!(
            msg.context["privileged_session_expires_at_unix"],
            1_794_591_681
        );
        assert!(msg.text.contains("15.00 minutes"), "{}", msg.text);
    }

    fn case_with_handoff() -> Case {
        Case {
            request_url: "http://localhost:3000/self-service/recovery?flow=r",
            ..case("settings_recovery_handoff", FlowKind::Settings)
        }
    }

    #[test]
    fn two_factor_page_contract_per_settings_state() {
        let codes = codes();
        let expected = [
            ("settings_fresh", (false, false, false, false)),
            ("settings_recovery_handoff", (false, false, false, false)),
            ("settings_totp_pending", (false, false, false, false)),
            ("settings_totp_enrolled", (true, false, false, true)),
            ("settings_totp_enrolled_submit", (true, false, false, true)),
            ("settings_lookup_generated", (true, false, true, true)),
            ("settings_lookup_confirmed", (true, true, false, false)),
            (
                "settings_lookup_confirmed_submit",
                (true, true, false, false),
            ),
        ];
        let pairs = pairs(&codes);
        for (file, (totp, lookup, regenerated, needs_codes)) in expected {
            let (case, screen) = pairs.iter().find(|(c, _)| c.file == file).unwrap();
            let ours = page_flags(&project(&native(case, screen)));
            assert_eq!(
                ours,
                PageFlags {
                    totp_enrolled: totp,
                    lookup_enrolled: lookup,
                    lookup_just_regenerated: regenerated,
                    needs_recovery_codes: needs_codes,
                },
                "{file}"
            );
            assert_eq!(ours, page_flags(&project(&fixture(file))), "{file}: Kratos");
        }
    }
}
