//! Device-local remembered-accounts chooser: signed cookie of identity UUIDs, labels resolved server-side.

use crate::ory;
use crate::state::AppState;

pub(crate) mod cookie;
pub(crate) mod handlers;

pub(crate) use handlers::router;

#[derive(Debug, Clone)]
pub(crate) struct AccountView {
    pub id: String,
    pub email: String,
    pub display_name: String,
}

/// Build a display view from a Kratos identity; falls back email then id.
pub(crate) fn account_view_from_identity(id: &str, identity: &ory::Identity) -> AccountView {
    let traits = identity.traits.as_ref();
    let email = traits
        .and_then(|t| t.get("email").and_then(|v| v.as_str()))
        .unwrap_or_default()
        .to_string();

    let name = traits.and_then(|t| t.get("name"));
    let display_name = match name {
        Some(v) if v.as_str().is_some_and(|s| !s.is_empty()) => v.as_str().unwrap().to_string(),
        Some(v) if v.is_object() => {
            let o = v.as_object().unwrap();
            let first = o.get("first").and_then(|x| x.as_str()).unwrap_or("");
            let last = o.get("last").and_then(|x| x.as_str()).unwrap_or("");
            let joined = format!("{first} {last}").trim().to_string();
            if joined.is_empty() { email.clone() } else { joined }
        }
        _ => email.clone(),
    };
    let display_name = if display_name.is_empty() { id.to_string() } else { display_name };

    AccountView { id: id.to_string(), email, display_name }
}

/// Resolve identity ids to display views; failed lookups are silently dropped so the list self-heals.
pub(crate) async fn resolve(state: &AppState, ids: &[String]) -> Vec<AccountView> {
    let mut views = Vec::with_capacity(ids.len());
    for id in ids {
        if let Ok(identity) = ory::kratos::admin_get_identity(&state.ory, id).await {
            views.push(account_view_from_identity(id, &identity));
        }
    }
    views
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_with(traits: serde_json::Value) -> ory::Identity {
        ory::Identity::new(
            String::new(),
            String::new(),
            String::new(),
            Some(traits),
        )
    }

    #[test]
    fn view_reads_email_and_string_name() {
        let identity = identity_with(serde_json::json!({"email": "a@example.com", "name": "Ada"}));
        let v = account_view_from_identity("id-1", &identity);
        assert_eq!(v.id, "id-1");
        assert_eq!(v.email, "a@example.com");
        assert_eq!(v.display_name, "Ada");
    }

    #[test]
    fn view_joins_first_last_name() {
        let identity = identity_with(serde_json::json!({
            "email": "b@example.com",
            "name": {"first": "Grace", "last": "Hopper"}
        }));
        let v = account_view_from_identity("id-2", &identity);
        assert_eq!(v.display_name, "Grace Hopper");
    }

    #[test]
    fn view_falls_back_to_email_when_no_name() {
        let identity = identity_with(serde_json::json!({"email": "c@example.com"}));
        let v = account_view_from_identity("id-3", &identity);
        assert_eq!(v.display_name, "c@example.com");
    }
}
