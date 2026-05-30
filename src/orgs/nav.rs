//! View-model for the top-nav active-org dropdown.
//!
//! Every layout template that renders the header reads this struct via the
//! base template's `org_nav` block. OSS deployments see a single Default
//! row in the dropdown (visually present-but-trivial); commercial
//! deployments see the full membership list.

use serde::Serialize;

use crate::orgs::Membership;

#[derive(Debug, Clone, Default, Serialize)]
pub struct OrgNav {
    /// Currently-active org. `None` when the user has no memberships
    /// (shouldn't happen in practice — registration auto-joins Default).
    pub active: Option<Membership>,
    /// Every org the user belongs to, sorted by name. Capped to 32 entries
    /// at the consent layer; the dropdown shows the full list.
    pub memberships: Vec<Membership>,
}

impl OrgNav {
    pub fn from(active: Option<Membership>, memberships: Vec<Membership>) -> Self {
        Self {
            active,
            memberships,
        }
    }

    pub fn active_name(&self) -> Option<&str> {
        self.active.as_ref().map(|m| m.name.as_str())
    }

    pub fn active_slug(&self) -> Option<&str> {
        self.active.as_ref().map(|m| m.slug.as_str())
    }
}

/// Cap applied to the `orgs` OIDC claim (per the spec). The nav dropdown
/// itself is uncapped.
pub const ORGS_CLAIM_CAP: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    fn membership(slug: &str, name: &str) -> Membership {
        Membership {
            org_id: format!("org-{slug}"),
            slug: slug.to_string(),
            name: name.to_string(),
            role: "owner".to_string(),
        }
    }

    #[test]
    fn active_name_and_slug_present() {
        let active = membership("acme", "Acme Inc");
        let nav = OrgNav::from(Some(active.clone()), vec![active]);
        assert_eq!(nav.active_name(), Some("Acme Inc"));
        assert_eq!(nav.active_slug(), Some("acme"));
    }

    #[test]
    fn active_name_and_slug_none_when_empty() {
        let nav = OrgNav::from(None, vec![]);
        assert_eq!(nav.active_name(), None);
        assert_eq!(nav.active_slug(), None);
    }
}
