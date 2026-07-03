//! Organizations — data model, membership, active-org resolution.
//!
//! OSS seeds exactly one real "Default" org; commercial licenses unlock more
//! rows. Every code path uses the same query shape regardless of tier.
//!
//! Cross-cutting helpers ([`resolve_admin_scope`], [`active_org`],
//! [`org_role`]) live at the module root so admin / oauth / settings handlers
//! can pull them without depending on internal submodules.

pub mod cookie;
pub mod db;
pub mod invite;
pub(crate) mod logo;
pub mod middleware;
pub mod nav;
pub mod public_landing;
pub mod settings_page;
pub mod teams;
pub mod visibility;

use std::str::FromStr;

use axum::http::HeaderMap;

pub use db::{
    add_member, count_orgs, create_org, delete_org, fetch_invite, find_member, insert_invite,
    is_reserved_slug, list_member_profiles, list_members, list_members_paged, list_memberships,
    list_memberships_limited, list_org_invites, org_by_id, org_by_slug, remove_member,
    set_member_hidden, set_member_visibility, slugify, suggest_slug, update_branding, update_role,
    Membership, Org, OrgInvite,
};

/// Stable PK of the seeded "Default" org. Matches the migration's INSERT.
pub const DEFAULT_ORG_ID: &str = "default";

/// Org roles. `owner` runs governance; `member` is read-only for org-scoped
/// resources. Stored / wired as the lowercase variant name via [`Role::as_str`]
/// and `FromStr` (forms, DB, OIDC claims all share that vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }
}

/// Parse a DB / form / wire role string. `None` on anything unrecognised.
pub fn parse_role(s: &str) -> Option<Role> {
    match s {
        "owner" => Some(Role::Owner),
        "member" => Some(Role::Member),
        _ => None,
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_role(s).ok_or(())
    }
}

/// `true` iff the DB-row `role` parses as [`Role::Owner`]. Unknown strings
/// (should be impossible given the `CHECK` constraint) fail closed and log.
pub(crate) fn is_owner_role(s: &str) -> bool {
    match parse_role(s) {
        Some(r) => r == Role::Owner,
        None => {
            tracing::warn!(role = %s, "orgs: unknown role string in DB row");
            false
        }
    }
}

/// Admin scope a request runs in. `Forseti` is the operator-tier surface gated
/// by `admin.allowed_emails`; `Org` is owner-scoped to a single org without
/// the global Forseti-admin privilege.
#[derive(Debug, Clone)]
pub enum AdminScope {
    /// Forseti-wide admin (full surface).
    Forseti,
    /// Org-scoped admin: `?org=<slug>` resolved to an org the caller owns.
    Org { id: String, slug: String },
}

impl AdminScope {
    pub fn org_id(&self) -> Option<&str> {
        match self {
            AdminScope::Org { id, .. } => Some(id),
            AdminScope::Forseti => None,
        }
    }

    pub fn slug(&self) -> Option<&str> {
        match self {
            AdminScope::Org { slug, .. } => Some(slug),
            AdminScope::Forseti => None,
        }
    }
}

/// Resolve the active org from a pre-loaded membership list:
/// 1. Signed `active_org` cookie, if valid and still a member.
/// 2. First membership.
/// 3. `None` when the list is empty.
///
/// Takes a slice so callers that already loaded memberships for the nav
/// switcher avoid a duplicate DB roundtrip.
pub fn active_org(
    memberships: &[Membership],
    cookie_secret: &[u8],
    cookie_ttl_secs: u64,
    headers: &HeaderMap,
) -> Option<Membership> {
    if memberships.is_empty() {
        return None;
    }
    if let Some(cookie_id) = cookie::read_active_org_cookie(headers, cookie_secret, cookie_ttl_secs)
    {
        if let Some(m) = memberships.iter().find(|m| m.org_id == cookie_id) {
            return Some(m.clone());
        }
    }
    memberships.first().cloned()
}

/// Look up the caller's role inside `org_id`. `None` when not a member.
pub async fn org_role(db: &crate::db::DbPool, identity_id: &str, org_id: &str) -> Option<Role> {
    find_member(db, identity_id, org_id)
        .await
        .ok()
        .flatten()
        .and_then(|m| parse_role(&m.role))
}

/// Quick membership probe used by the oauth-login resolver.
pub async fn is_member(db: &crate::db::DbPool, identity_id: &str, org_id: &str) -> bool {
    org_role(db, identity_id, org_id).await.is_some()
}

/// Auto-join the caller into the Default org if they're in no org yet, called
/// per authenticated request from [`crate::orgs::middleware::auto_join_default_org`].
/// Cheap membership probe first; otherwise the race-safe
/// [`db::auto_join_default_txn`] (role decided inside the txn).
///
/// Role: first user on a fresh install → `owner`; later registrants on
/// `admin.allowed_emails` → `owner`; everyone else → `member`.
///
/// Errors are swallowed (logged at `warn!`) so a transient DB hiccup never
/// breaks the request; the next request retries.
pub async fn ensure_default_membership(
    db: &crate::db::DbPool,
    cfg: &crate::config::AppConfig,
    identity_id: &str,
    email: &str,
) {
    match db::has_any_membership(db, identity_id).await {
        Ok(true) => {}
        Ok(false) => {
            if let Err(e) = db::auto_join_default_txn(db, &cfg.admin, identity_id, email).await {
                // Diesel collapses unique-constraint violations into a
                // generic error string; "already a member" is the
                // expected loser-of-race shape.
                tracing::warn!(
                    error = ?e,
                    identity_id,
                    "ensure_default_membership: auto-join insert failed (will retry on next request)"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = ?e,
                identity_id,
                "ensure_default_membership: membership probe failed (will retry on next request)"
            );
        }
    }
}

/// Role for a fresh registration of `email`: admin allowlist match wins, then
/// `is_default_empty` decides owner (first user) vs member. Pure helper;
/// `auto_join_default_txn` calls it inside a txn so two concurrent first
/// registrations can't both observe an empty table.
pub fn pick_default_role(
    admin_cfg: &crate::config::AdminConfig,
    email: &str,
    is_default_empty: bool,
) -> Role {
    if admin_cfg.is_admin(email) {
        return Role::Owner;
    }
    if is_default_empty {
        return Role::Owner;
    }
    Role::Member
}

/// Outcome of [`resolve_admin_scope`]. Not a `Result<_, Response>` so the
/// caller can render the rejection in the admin layout itself.
#[derive(Debug, Clone)]
pub enum AdminScopeOutcome {
    Resolved(AdminScope),
    /// `?org=<slug>` named an org that doesn't exist.
    UnknownOrg,
    /// `?org=<slug>` named an org the caller isn't an owner of.
    NotOwner,
}

/// Resolve admin scope from the `?org=<slug>` param and caller identity.
/// Doesn't touch the Forseti-admin allowlist; `None`/empty slug yields
/// [`AdminScope::Forseti`]. Caller must already have passed `require_admin`.
pub async fn resolve_admin_scope(
    db: &crate::db::DbPool,
    identity_id: &str,
    slug_query: Option<&str>,
) -> AdminScopeOutcome {
    let slug = slug_query.unwrap_or("").trim();
    if slug.is_empty() {
        return AdminScopeOutcome::Resolved(AdminScope::Forseti);
    }
    let org = match org_by_slug(db, slug).await {
        Ok(Some(o)) => o,
        Ok(None) => return AdminScopeOutcome::UnknownOrg,
        Err(e) => {
            tracing::error!(error = ?e, slug, "resolve_admin_scope: org_by_slug failed");
            return AdminScopeOutcome::UnknownOrg;
        }
    };
    match org_role(db, identity_id, &org.id).await {
        Some(Role::Owner) => AdminScopeOutcome::Resolved(AdminScope::Org {
            id: org.id,
            slug: org.slug,
        }),
        _ => AdminScopeOutcome::NotOwner,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdminConfig;

    fn admin_cfg(emails: &[&str]) -> AdminConfig {
        AdminConfig {
            allowed_emails: emails.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn pick_default_role_admin_email_always_owner() {
        let cfg = admin_cfg(&["admin@example.com"]);
        assert_eq!(
            pick_default_role(&cfg, "admin@example.com", false),
            Role::Owner
        );
        assert_eq!(
            pick_default_role(&cfg, "admin@example.com", true),
            Role::Owner
        );
    }

    #[test]
    fn pick_default_role_first_user_owner() {
        let cfg = admin_cfg(&[]);
        assert_eq!(
            pick_default_role(&cfg, "user@example.com", true),
            Role::Owner
        );
    }

    #[test]
    fn pick_default_role_subsequent_user_member() {
        let cfg = admin_cfg(&[]);
        assert_eq!(
            pick_default_role(&cfg, "user@example.com", false),
            Role::Member
        );
    }

    #[test]
    fn role_from_str_known() {
        assert_eq!("owner".parse::<Role>().unwrap(), Role::Owner);
        assert_eq!("member".parse::<Role>().unwrap(), Role::Member);
    }

    #[test]
    fn role_from_str_unknown_errs() {
        assert!("admin".parse::<Role>().is_err());
        assert!("".parse::<Role>().is_err());
        // Case-sensitive: the DB stores lowercase strings.
        assert!("Owner".parse::<Role>().is_err());
    }

    #[test]
    fn role_as_str_round_trips_from_str() {
        for r in [Role::Owner, Role::Member] {
            assert_eq!(r.as_str().parse::<Role>().unwrap(), r);
        }
    }
}
