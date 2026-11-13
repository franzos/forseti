//! `/settings/linked-providers` — link / unlink upstream OIDC providers.
//!
//! The Kratos settings flow only surfaces actionable link/unlink submit nodes,
//! and it *suppresses* the unlink node when OIDC is the identity's sole
//! credential. So the flow alone can't tell us what's actually linked. We also
//! fetch the full identity (admin API) to read the linked provider set and
//! detect the sole-credential case, degrading to flow-nodes-only if that fails.

use std::collections::{BTreeSet, HashMap};

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::FlowQuery;
use crate::backend::IdentityBackend;
use crate::backend::identity::{Identity, Session};
use crate::flow_view::{Flow, InputView, MessageView, translate_inputs, translate_messages};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::{SettingsSection, fetch_settings_subpage, oidc_links_db};

/// What the right-hand side of a provider row offers.
pub(crate) enum RowAction {
    /// An unlink submit node exists; render a destructive form.
    Unlink,
    /// A link submit node exists; render a secondary "Link" form.
    Link,
    /// Linked but Kratos withholds the unlink node (sole credential).
    UnlinkBlockedSoleCredential,
    /// Nothing actionable (e.g. linked with no unlink node and not sole).
    None,
}

/// One provider's row in the linked-providers list.
pub(crate) struct LinkedProviderRow {
    pub(crate) provider_id: String,
    pub(crate) display_name: String,
    pub(crate) icon_svg: &'static str,
    pub(crate) linked: bool,
    /// Friendly "first connected" date, when known.
    pub(crate) connected_at: Option<String>,
    pub(crate) action: RowAction,
    /// Submit node name/value for the Link/Unlink forms (empty otherwise).
    pub(crate) action_name: String,
    pub(crate) action_value: String,
}

#[derive(Template)]
#[template(path = "settings_linked_providers.html")]
pub(crate) struct SettingsLinkedProvidersTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) form_action: String,
    pub(crate) form_method: String,
    pub(crate) flow_messages: Vec<MessageView>,
    pub(crate) hidden_defaults: Vec<InputView>,
    pub(crate) rows: Vec<LinkedProviderRow>,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

pub(crate) async fn settings_linked_providers(
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
        SettingsSection::LinkedProviders,
        &sess,
        &locale,
    )
    .await
    {
        Ok((session, flow)) => {
            // Linking POSTs to Kratos, which 303s on to the provider.
            let auth_origins = crate::oidc_providers::flow_auth_origins(&flow);
            let memberships = crate::orgs::list_memberships(&state.db, &sess.identity_id)
                .await
                .unwrap_or_default();
            render_linked_providers(
                &state,
                &memberships,
                &headers,
                &csrf.0,
                &sess.identity_id,
                &session,
                &flow,
                &auth_origins,
                banner.0,
                locale,
            )
            .await
        }
        Err(resp) => resp,
    }
}

#[allow(clippy::too_many_arguments)]
async fn render_linked_providers(
    state: &AppState,
    memberships: &[crate::orgs::Membership],
    headers: &HeaderMap,
    csrf_token: &str,
    identity_id: &str,
    session: &Session,
    flow: &Flow,
    auth_origins: &[String],
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
    locale: crate::locale::LanguageIdentifier,
) -> Response {
    let mut hidden_defaults = flow.default_hidden();
    let mut oidc_nodes: Vec<InputView> = flow.inputs("oidc").cloned().collect();
    translate_inputs(&mut hidden_defaults, &locale);
    translate_inputs(&mut oidc_nodes, &locale);
    let mut msgs = flow.messages.clone();
    translate_messages(&mut msgs, &locale);

    // Kratos names oidc submit nodes `link` / `unlink`, with the provider id as
    // the value. Map each by provider id so rows can find their action node.
    let mut link_nodes: HashMap<String, String> = HashMap::new();
    let mut unlink_nodes: HashMap<String, String> = HashMap::new();
    for n in &oidc_nodes {
        if n.input_type != "submit" && n.input_type != "button" {
            continue;
        }
        match n.name.as_str() {
            "link" => {
                link_nodes.insert(n.value.clone(), n.name.clone());
            }
            "unlink" => {
                unlink_nodes.insert(n.value.clone(), n.name.clone());
            }
            _ => {}
        }
    }

    // Full identity (admin API) reveals the actual linked set + whether OIDC is
    // the sole credential. Degrade to flow-nodes-only if it can't be fetched.
    let identity = state
        .identity
        .admin_get_identity_full(identity_id)
        .await
        .ok();
    let (linked_set, sole_credential_flag) = match &identity {
        Some(id) => (linked_provider_ids(id), sole_credential(id)),
        None => (BTreeSet::new(), false),
    };
    let identity_available = identity.is_some();

    // Record link dates for the currently-linked providers, then read them back.
    for provider in &linked_set {
        if let Err(e) = oidc_links_db::upsert_seen(&state.db, identity_id, provider).await {
            tracing::warn!(error = ?e, provider = provider.as_str(), "oidc_links upsert failed");
        }
    }
    let dates: HashMap<String, String> = oidc_links_db::list_for_identity(&state.db, identity_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

    // Providers to render = linked set ∪ flow link/unlink node values.
    let mut providers: BTreeSet<String> = linked_set.clone();
    providers.extend(link_nodes.keys().cloned());
    providers.extend(unlink_nodes.keys().cloned());

    let mut rows: Vec<LinkedProviderRow> = providers
        .into_iter()
        .map(|provider| {
            // With the identity, the linked set is authoritative; without it, an
            // unlink node from Kratos is the only "is linked" signal we have.
            let linked = if identity_available {
                linked_set.contains(&provider)
            } else {
                unlink_nodes.contains_key(&provider)
            };
            let (action, action_name, action_value) = if linked {
                if let Some(name) = unlink_nodes.get(&provider) {
                    (RowAction::Unlink, name.clone(), provider.clone())
                } else if sole_credential_flag {
                    (
                        RowAction::UnlinkBlockedSoleCredential,
                        String::new(),
                        String::new(),
                    )
                } else {
                    (RowAction::None, String::new(), String::new())
                }
            } else if let Some(name) = link_nodes.get(&provider) {
                (RowAction::Link, name.clone(), provider.clone())
            } else {
                (RowAction::None, String::new(), String::new())
            };
            let connected_at = if linked {
                dates.get(&provider).map(|ts| crate::format::short_date(ts))
            } else {
                None
            };
            LinkedProviderRow {
                display_name: crate::oidc_providers::display_name(&provider),
                icon_svg: crate::oidc_providers::icon_svg(&provider),
                linked,
                connected_at,
                action,
                action_name,
                action_value,
                provider_id: provider,
            }
        })
        .collect();
    // Linked providers first, then alphabetical for a stable order.
    rows.sort_by(|a, b| (!a.linked, &a.provider_id).cmp(&(!b.linked, &b.provider_id)));

    let mut resp = render(&SettingsLinkedProvidersTemplate {
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
        rows,
        referrer_banner,
    });
    crate::app::allow_form_action_to(&mut resp, auth_origins);
    resp
}

/// Linked provider ids from the identity's `oidc` credential. Reads both the
/// typed `config.providers[].provider` and the `identifiers` ("provider:subject")
/// shapes, since Kratos versions vary in which they populate.
pub(crate) fn linked_provider_ids(identity: &Identity) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Some(oidc) = identity.credentials.as_ref().and_then(|c| c.get("oidc")) else {
        return set;
    };
    if let Some(arr) = oidc
        .config
        .as_ref()
        .and_then(|c| c.get("providers"))
        .and_then(|p| p.as_array())
    {
        for p in arr {
            if let Some(id) = p.get("provider").and_then(|v| v.as_str())
                && !id.is_empty()
            {
                set.insert(id.to_string());
            }
        }
    }
    if let Some(ids) = oidc.identifiers.as_ref() {
        for id in ids {
            if let Some((prov, _)) = id.split_once(':')
                && !prov.is_empty()
            {
                set.insert(prov.to_string());
            }
        }
    }
    set
}

/// True when a credential method carries real enrolment data, not just the
/// identifier reservation Kratos seeds for an OIDC-created identity (whose
/// password/webauthn/code entries exist with empty `config`).
fn credential_enrolled(method: &str, cred: &crate::backend::identity::Credential) -> bool {
    let config = cred.config.as_ref();
    let non_empty_str = |key: &str| {
        config
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    };
    let non_empty_arr = |key: &str| {
        config
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    };
    match method {
        "password" => non_empty_str("hashed_password"),
        "webauthn" | "passkey" => non_empty_arr("credentials"),
        "lookup_secret" => non_empty_arr("recovery_codes"),
        "totp" => non_empty_str("totp_url"),
        _ => false,
    }
}

/// True when OIDC is the identity's only real sign-in method: at least one OIDC
/// provider is linked and no other credential is actually enrolled.
pub(crate) fn sole_credential(identity: &Identity) -> bool {
    if linked_provider_ids(identity).is_empty() {
        return false;
    }
    let Some(creds) = identity.credentials.as_ref() else {
        return false;
    };
    !creds
        .iter()
        .any(|(method, cred)| method != "oidc" && credential_enrolled(method, cred))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::identity::Credential;
    use serde_json::json;

    fn cred(identifiers: &[&str], config: serde_json::Value) -> Credential {
        Credential {
            identifiers: Some(identifiers.iter().map(ToString::to_string).collect()),
            config: Some(config),
            ..Default::default()
        }
    }

    fn identity(creds: Vec<(&str, Credential)>) -> Identity {
        Identity {
            credentials: Some(creds.into_iter().map(|(k, c)| (k.to_string(), c)).collect()),
            ..Default::default()
        }
    }

    /// OIDC-created identity: oidc linked, and password/webauthn present only as
    /// identifier reservations (empty config).
    fn oidc_only() -> Identity {
        identity(vec![
            (
                "oidc",
                cred(
                    &["github:12345"],
                    json!({ "providers": [{ "provider": "github", "subject": "12345" }] }),
                ),
            ),
            ("password", cred(&["user@example.com"], json!({}))),
            (
                "webauthn",
                cred(&["user@example.com"], json!({ "user_handle": "abc=" })),
            ),
        ])
    }

    /// Same identity but with a real password enrolled.
    fn oidc_plus_password() -> Identity {
        identity(vec![
            (
                "oidc",
                cred(
                    &["github:12345"],
                    json!({ "providers": [{ "provider": "github", "subject": "12345" }] }),
                ),
            ),
            (
                "password",
                Credential {
                    config: Some(json!({ "hashed_password": "$argon2id$..." })),
                    ..Default::default()
                },
            ),
        ])
    }

    #[test]
    fn linked_provider_ids_reads_config_and_identifiers() {
        let ids = linked_provider_ids(&oidc_only());
        assert!(ids.contains("github"));
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn sole_credential_true_for_oidc_only() {
        assert!(sole_credential(&oidc_only()));
    }

    #[test]
    fn sole_credential_false_with_real_password() {
        assert!(!sole_credential(&oidc_plus_password()));
    }
}
