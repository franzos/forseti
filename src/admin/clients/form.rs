//! Form deserialisation + JSON-merge surgery for the OAuth2 client form.
//!
//! Both `create` and `update` POST into the same `ClientForm`. The
//! `to_oauth2_client` worker round-trips through the existing Hydra
//! payload so an update touches only the fields the operator actually
//! filled in.

use serde::Deserialize;

use crate::ory;

#[derive(Debug, Deserialize)]
pub(crate) struct ClientForm {
    #[serde(rename = "_csrf")]
    pub(super) csrf: Option<String>,
    pub(super) name: String,
    /// Each checked grant in the form posts a separate `grant_types=<value>`
    /// entry; `serde_html_form` (via `axum_extra::Form`) collects them
    /// into a Vec. Unchecked → omitted entirely → empty Vec.
    #[serde(default)]
    pub(super) grant_types: Vec<String>,
    pub(super) response_types: String,
    pub(super) scope: String,
    pub(super) redirect_uris: String,
    pub(super) post_logout_redirect_uris: String,
    /// OIDC back-channel logout URI — Hydra POSTs a signed logout token here
    /// when the user ends their session. Optional; blank disables fan-out
    /// to this client.
    #[serde(default)]
    pub(super) backchannel_logout_uri: String,
    /// OIDC front-channel logout URI — iframe-loaded by Hydra during the
    /// logout flow. Optional; blank disables.
    #[serde(default)]
    pub(super) frontchannel_logout_uri: String,
    /// Whether `sid` must be included in the back-channel logout token.
    /// Checkbox — absent = false.
    #[serde(default)]
    pub(super) backchannel_logout_session_required: Option<String>,
    /// Whether `iss` + `sid` must be included on the front-channel logout
    /// URL. Checkbox — absent = false.
    #[serde(default)]
    pub(super) frontchannel_logout_session_required: Option<String>,
    pub(super) token_endpoint_auth_method: String,
    /// Multi-line audience list. Parsed with the same comma/whitespace
    /// rule as redirect_uris.
    #[serde(default)]
    pub(super) audience: String,
    #[serde(default)]
    pub(super) require_pkce: Option<String>,
    #[serde(default)]
    pub(super) skip_consent: Option<String>,
    /// Phase 1 — `client.metadata.forseti.account_deletion_url`. Empty
    /// string clears the field; on edit, blank is treated the same as
    /// "no change" only if the field was absent in the underlying
    /// `to_oauth2_client` round-trip — see implementation.
    #[serde(default)]
    pub(super) account_deletion_url: String,
    /// Hidden input set by the picker — preset slug ("mcp" etc.).
    /// Stamped into `metadata.forseti.client_type`. Empty on legacy edits.
    #[serde(default)]
    pub(super) client_type: String,
    /// Hidden input set by the picker — app-template slug ("gitlab" etc.).
    /// Used only to re-render the template note banner on a validation
    /// re-render; not persisted (the base preset's slug is what gets
    /// stamped into metadata via `client_type`).
    #[serde(default)]
    pub(super) template: String,
}

impl ClientForm {
    pub(super) fn require_pkce_flag(&self) -> bool {
        matches!(self.require_pkce.as_deref(), Some("on") | Some("true"))
    }

    pub(super) fn skip_consent_flag(&self) -> bool {
        matches!(self.skip_consent.as_deref(), Some("on") | Some("true"))
    }

    pub(super) fn backchannel_logout_session_required_flag(&self) -> bool {
        matches!(
            self.backchannel_logout_session_required.as_deref(),
            Some("on") | Some("true")
        )
    }

    pub(super) fn frontchannel_logout_session_required_flag(&self) -> bool {
        matches!(
            self.frontchannel_logout_session_required.as_deref(),
            Some("on") | Some("true")
        )
    }

    pub(super) fn to_oauth2_client(
        &self,
        existing: Option<ory::OAuth2Client>,
    ) -> ory::OAuth2Client {
        let editing = existing.is_some();
        let mut c = existing.unwrap_or_default();
        self.merge_form_into_client(&mut c, editing);
        self.merge_forseti_metadata(&mut c);
        c
    }

    /// Apply top-level OAuth2 client fields from the form onto `c`.
    ///
    /// On update (`editing = true`), an empty form field means "leave
    /// alone" rather than "clear". Without this, an admin who saves the
    /// show page after editing only the name would wipe out grant_types,
    /// scope, redirect_uris, etc. Create-time still accepts empty fields
    /// (they round-trip to Hydra as-is).
    fn merge_form_into_client(&self, c: &mut ory::OAuth2Client, editing: bool) {
        let trim_list = |s: &str| -> Vec<String> {
            s.split(|c: char| c == ',' || c.is_whitespace())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        let parse_list = |raw: &str, current: Option<&Vec<String>>| -> Vec<String> {
            if editing && raw.trim().is_empty() {
                current.cloned().unwrap_or_default()
            } else {
                trim_list(raw)
            }
        };
        let parse_string = |raw: &str, current: Option<&String>| -> String {
            if editing && raw.trim().is_empty() {
                current.cloned().unwrap_or_default()
            } else {
                raw.trim().to_string()
            }
        };
        // Variant of parse_string for SDK `Option<String>` fields where the
        // canonical "unset" representation is `None` (not `Some("")`).
        // Matches the URI fields that Hydra omits from its payload when
        // unset (`backchannel_logout_uri`, `frontchannel_logout_uri`).
        let parse_optional = |raw: &str, current: Option<&String>| -> Option<String> {
            if editing && raw.trim().is_empty() {
                current.cloned()
            } else {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
        };

        // `name` is required by the form (HTML `required`), so blank should
        // not survive an actual update — but treat it consistently with
        // the other fields just in case.
        c.client_name = Some(parse_string(&self.name, c.client_name.as_ref()));
        // Grants are checkboxes — an empty Vec on update means "operator
        // unchecked everything", which we should honour rather than
        // silently keeping the old value. (Different from text fields,
        // where blank input is more likely to be an accident.)
        c.grant_types = Some(self.grant_types.clone());
        c.response_types = Some(parse_list(&self.response_types, c.response_types.as_ref()));
        c.scope = Some(parse_string(&self.scope, c.scope.as_ref()));
        c.redirect_uris = Some(parse_list(&self.redirect_uris, c.redirect_uris.as_ref()));
        c.post_logout_redirect_uris = Some(parse_list(
            &self.post_logout_redirect_uris,
            c.post_logout_redirect_uris.as_ref(),
        ));
        c.backchannel_logout_uri = parse_optional(
            &self.backchannel_logout_uri,
            c.backchannel_logout_uri.as_ref(),
        );
        c.frontchannel_logout_uri = parse_optional(
            &self.frontchannel_logout_uri,
            c.frontchannel_logout_uri.as_ref(),
        );
        // Checkboxes — absence means false; always honour the form.
        c.backchannel_logout_session_required =
            Some(self.backchannel_logout_session_required_flag());
        c.frontchannel_logout_session_required =
            Some(self.frontchannel_logout_session_required_flag());
        c.token_endpoint_auth_method = Some(parse_string(
            &self.token_endpoint_auth_method,
            c.token_endpoint_auth_method.as_ref(),
        ));
        // Audience: same parse rules as redirect_uris. Empty list on
        // update means "leave alone"; non-empty replaces wholesale.
        c.audience = Some(parse_list(&self.audience, c.audience.as_ref()));
        // `skip_consent` is a checkbox — its absence from the POST body
        // genuinely means "off" (unchecked), so we always honour the form.
        c.skip_consent = Some(self.skip_consent_flag());
    }

    /// Merge Forseti-owned fields into `metadata.forseti.*`, preserving
    /// anything else the operator (or future Forseti feature) has stashed
    /// in metadata.
    fn merge_forseti_metadata(&self, c: &mut ory::OAuth2Client) {
        let url_input = self.account_deletion_url.trim();
        let require_pkce_input = self.require_pkce_flag();
        let client_type_input = self.client_type.trim();
        let mut metadata = c
            .metadata
            .take()
            .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        if !metadata.is_object() {
            metadata = serde_json::Value::Object(Default::default());
        }
        {
            let obj = metadata.as_object_mut().expect("ensured above");
            let forseti = obj
                .entry("forseti".to_string())
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            if !forseti.is_object() {
                *forseti = serde_json::Value::Object(Default::default());
            }
            let forseti_obj = forseti.as_object_mut().expect("ensured above");
            if url_input.is_empty() {
                forseti_obj.remove("account_deletion_url");
            } else {
                forseti_obj.insert(
                    "account_deletion_url".to_string(),
                    serde_json::Value::String(url_input.to_string()),
                );
            }
            // `require_pkce` is a checkbox — absence = false, so we always
            // honour the form value.
            forseti_obj.insert(
                "require_pkce".to_string(),
                serde_json::Value::Bool(require_pkce_input),
            );
            // Client type: on create the hidden input carries the chosen
            // preset; on update, the form re-posts the existing value
            // (rendered from the show page). Empty input on update means
            // "this is a legacy client without a preset" — don't fabricate
            // one, but also don't wipe a previously stamped value if a
            // newer form posts blank.
            if !client_type_input.is_empty() {
                forseti_obj.insert(
                    "client_type".to_string(),
                    serde_json::Value::String(client_type_input.to_string()),
                );
            }
        }
        c.metadata = Some(metadata);
    }
}
