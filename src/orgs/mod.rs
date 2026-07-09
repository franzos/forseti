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
pub mod domain_prompt;
pub mod domains;
pub mod invite;
pub mod join;
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
    count_orgs, create_org, delete_org, fetch_invite, find_member, insert_invite, is_reserved_slug,
    list_member_profiles, list_members, list_members_paged, list_memberships,
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

/// Org access mode. `external` unlocks licensed public self-serve signup;
/// `internal` (the default and fail-closed fallback) is invite + domain
/// auto-join only. Stored as the lowercase variant name. Open enum: a future
/// `customer` variant (Model 2) parses here without a schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Internal,
    External,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessMode::Internal => "internal",
            AccessMode::External => "external",
        }
    }

    pub fn is_external(self) -> bool {
        matches!(self, AccessMode::External)
    }
}

/// Parse a DB `access_mode` string. Fail-closed: only the exact literal
/// `"external"` yields `External`; everything else (unknown, NULL-derived
/// empty, wrong case) is `Internal`, so an unrecognised value never opens
/// self-serve or domain auto-join.
pub fn parse_access_mode(s: &str) -> AccessMode {
    match s {
        "external" => AccessMode::External,
        _ => AccessMode::Internal,
    }
}

/// How an internal org admits verified-domain users. `invite_only` (the default
/// and fail-closed fallback) admits only via invite; `auto_join` also offers a
/// verified-domain user an explicit profile prompt to self-join. Ignored for
/// external orgs (open by design). Open enum for future policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainJoinPolicy {
    InviteOnly,
    AutoJoin,
}

impl DomainJoinPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            DomainJoinPolicy::InviteOnly => "invite_only",
            DomainJoinPolicy::AutoJoin => "auto_join",
        }
    }

    pub fn is_auto_join(self) -> bool {
        matches!(self, DomainJoinPolicy::AutoJoin)
    }
}

/// Parse a DB `domain_join_policy` string. Fail-closed: only the exact literal
/// `"auto_join"` yields `AutoJoin`; everything else (unknown, NULL-derived
/// empty, wrong case) is `InviteOnly`, so an unrecognised value never opens the
/// domain auto-join door.
pub fn parse_domain_join_policy(s: &str) -> DomainJoinPolicy {
    match s {
        "auto_join" => DomainJoinPolicy::AutoJoin,
        _ => DomainJoinPolicy::InviteOnly,
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

/// Extract the lowercase domain from an email's local@domain shape. `None`
/// for a malformed trait email (should be impossible past Kratos's schema
/// validation, but never let a malformed value crash the auto-join path).
fn email_domain(email: &str) -> Option<String> {
    email.rsplit_once('@').map(|(_, d)| d.to_lowercase())
}

/// Resolve `email`'s domain to a proven org eligible for the domain auto-join
/// profile prompt: excludes the Default org and any org that has since flipped
/// to External (fail-closed on both), and requires the org's
/// `domain_join_policy` to be `auto_join`. Returns the org only when the prompt
/// should be offered; the caller still requires a verified address.
pub(crate) async fn lookup_proven_org_for_email(
    db: &crate::db::DbPool,
    email: &str,
) -> anyhow::Result<Option<Org>> {
    let Some(domain) = email_domain(email) else {
        return Ok(None);
    };
    // Re-assert freemail rejection at decision time (not just at add time), so
    // extending the denylist retroactively suppresses any already-verified row.
    if domains::is_freemail_domain(&domain) {
        return Ok(None);
    }
    let Some(org) = domains::lookup_proven_org_by_domain(db, &domain).await? else {
        return Ok(None);
    };
    if org.id == DEFAULT_ORG_ID || parse_access_mode(&org.access_mode).is_external() {
        return Ok(None);
    }
    if !parse_domain_join_policy(&org.domain_join_policy).is_auto_join() {
        return Ok(None);
    }
    Ok(Some(org))
}

/// Pure floor decision for a non-allowlisted identity, factored out so it's
/// unit-testable without a database. The Default floor holds iff the identity
/// has zero non-default memberships; add it only when it isn't already present.
/// (Allowlisted operators are handled separately in [`ensure_default_floor`]:
/// they are always Default `Owner` and exempt from this count.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MembershipAction {
    /// Member-less non-allowlisted identity with no Default row: add Default.
    AddDefaultFloor,
    /// Floor already satisfied (has a non-default org, or already in Default).
    DoNothing,
}

pub(crate) fn decide_membership_action(
    default_present: bool,
    non_default_count: usize,
) -> MembershipAction {
    if non_default_count == 0 && !default_present {
        MembershipAction::AddDefaultFloor
    } else {
        MembershipAction::DoNothing
    }
}

/// Maintain the Default-org floor for the caller, lazily on each authenticated
/// request from [`crate::orgs::middleware::auto_join_default_org`]. Two rules,
/// both verification-independent (`email` is used only for the allowlist check):
/// - **Allowlisted (operator):** always a member of Default as `Owner`, kept
///   alongside tenant orgs (exempt from the count and from the join-side drop).
/// - **Non-allowlisted:** a member of Default as `Member` iff they hold zero
///   non-default memberships. The count-and-insert is atomic (H4).
///
/// Never promotes a non-allowlisted identity to `Owner` (H3). Errors are
/// swallowed (logged at `warn!`) so a transient DB hiccup never breaks the
/// request; the next request retries.
pub async fn ensure_default_floor(
    db: &crate::db::DbPool,
    admin_cfg: &crate::config::AdminConfig,
    identity_id: &str,
    email: &str,
) {
    let (default_present, non_default_count) =
        match db::floor_membership_facts(db, identity_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    identity_id,
                    "ensure_default_floor: membership probe failed (will retry on next request)"
                );
                return;
            }
        };
    if admin_cfg.is_admin(email) {
        if !default_present {
            if let Err(e) =
                db::add_member_race_safe(db, identity_id, DEFAULT_ORG_ID, Role::Owner).await
            {
                tracing::warn!(
                    error = ?e,
                    identity_id,
                    "ensure_default_floor: operator Default owner insert failed (will retry on next request)"
                );
            }
        }
        return;
    }
    if decide_membership_action(default_present, non_default_count)
        == MembershipAction::AddDefaultFloor
    {
        if let Err(e) = db::add_default_floor_member_txn(db, identity_id).await {
            // Diesel collapses unique-constraint violations into a generic
            // error string; "already a member" is the expected loser-of-race.
            tracing::warn!(
                error = ?e,
                identity_id,
                "ensure_default_floor: Default floor insert failed (will retry on next request)"
            );
        }
    }
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

    #[test]
    fn access_mode_parses_external_only() {
        assert_eq!(parse_access_mode("external"), AccessMode::External);
        assert_eq!(parse_access_mode("internal"), AccessMode::Internal);
    }

    #[test]
    fn access_mode_fails_closed_on_unknown() {
        assert_eq!(parse_access_mode(""), AccessMode::Internal);
        assert_eq!(parse_access_mode("External"), AccessMode::Internal);
        assert_eq!(parse_access_mode("customer"), AccessMode::Internal);
        assert!(!parse_access_mode("bogus").is_external());
    }

    #[test]
    fn access_mode_as_str_round_trips() {
        for m in [AccessMode::Internal, AccessMode::External] {
            assert_eq!(parse_access_mode(m.as_str()), m);
        }
    }

    #[test]
    fn domain_join_policy_parses_auto_join_only() {
        assert_eq!(
            parse_domain_join_policy("auto_join"),
            DomainJoinPolicy::AutoJoin
        );
        assert_eq!(
            parse_domain_join_policy("invite_only"),
            DomainJoinPolicy::InviteOnly
        );
    }

    #[test]
    fn domain_join_policy_fails_closed_on_unknown() {
        assert_eq!(parse_domain_join_policy(""), DomainJoinPolicy::InviteOnly);
        assert_eq!(
            parse_domain_join_policy("Auto_Join"),
            DomainJoinPolicy::InviteOnly
        );
        assert_eq!(
            parse_domain_join_policy("open"),
            DomainJoinPolicy::InviteOnly
        );
        assert!(!parse_domain_join_policy("bogus").is_auto_join());
    }

    #[test]
    fn domain_join_policy_as_str_round_trips() {
        for p in [DomainJoinPolicy::InviteOnly, DomainJoinPolicy::AutoJoin] {
            assert_eq!(parse_domain_join_policy(p.as_str()), p);
        }
    }

    #[test]
    fn email_domain_extracts_lowercase() {
        assert_eq!(email_domain("Owner@ACME.com"), Some("acme.com".to_string()));
        assert_eq!(email_domain("no-at-sign"), None);
    }

    #[test]
    fn decide_membership_action_member_less_and_no_default_adds_floor() {
        assert_eq!(
            decide_membership_action(false, 0),
            MembershipAction::AddDefaultFloor
        );
    }

    #[test]
    fn decide_membership_action_already_in_default_is_noop() {
        assert_eq!(
            decide_membership_action(true, 0),
            MembershipAction::DoNothing
        );
    }

    #[test]
    fn decide_membership_action_has_non_default_is_noop() {
        // A tenant member is never floored, whether or not Default lingers.
        assert_eq!(
            decide_membership_action(false, 1),
            MembershipAction::DoNothing
        );
        assert_eq!(
            decide_membership_action(true, 2),
            MembershipAction::DoNothing
        );
    }

    #[tokio::test]
    async fn lookup_proven_org_for_email_matches_verified_domain() {
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        domains::add_pending_domain(&db, "acme-id", "acme.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        domains::mark_domain_verified(&db, "acme-id", "acme.com")
            .await
            .unwrap();
        db::set_domain_join_policy(&db, "acme-id", DomainJoinPolicy::AutoJoin)
            .await
            .unwrap();
        let org = lookup_proven_org_for_email(&db, "owner@acme.com")
            .await
            .unwrap()
            .expect("expected a proven org match");
        assert_eq!(org.id, "acme-id");
    }

    #[tokio::test]
    async fn lookup_proven_org_for_email_invite_only_returns_none() {
        // Default policy is invite_only: a proven domain must NOT offer the prompt.
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        domains::add_pending_domain(&db, "acme-id", "acme.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        domains::mark_domain_verified(&db, "acme-id", "acme.com")
            .await
            .unwrap();
        assert!(lookup_proven_org_for_email(&db, "owner@acme.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn lookup_proven_org_for_email_unknown_policy_returns_none() {
        // An unrecognised policy value fails closed (parse -> InviteOnly).
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        domains::add_pending_domain(&db, "acme-id", "acme.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        domains::mark_domain_verified(&db, "acme-id", "acme.com")
            .await
            .unwrap();
        db::set_domain_join_policy_raw(&db, "acme-id", "bogus")
            .await
            .unwrap();
        assert!(lookup_proven_org_for_email(&db, "owner@acme.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn lookup_proven_org_for_email_ignores_default_org() {
        let db = db::test_pool().await;
        // Should never happen via the settings-page gate, but the lookup
        // itself must still fail closed if a row ever pointed at Default
        // (migrations already seed the Default org row into `test_pool`).
        domains::add_pending_domain(&db, DEFAULT_ORG_ID, "acme.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        domains::mark_domain_verified(&db, DEFAULT_ORG_ID, "acme.com")
            .await
            .unwrap();
        assert!(lookup_proven_org_for_email(&db, "owner@acme.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn lookup_proven_org_for_email_ignores_external_org() {
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        db::set_access_mode(&db, "acme-id", AccessMode::External)
            .await
            .unwrap();
        domains::add_pending_domain(&db, "acme-id", "acme.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        domains::mark_domain_verified(&db, "acme-id", "acme.com")
            .await
            .unwrap();
        assert!(lookup_proven_org_for_email(&db, "owner@acme.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn lookup_proven_org_for_email_ignores_freemail_domain() {
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        // A freemail row shouldn't exist (add-time rejects it), but if one ever
        // did, the decision-time re-check must still fail closed.
        domains::add_pending_domain(&db, "acme-id", "gmail.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        domains::mark_domain_verified(&db, "acme-id", "gmail.com")
            .await
            .unwrap();
        assert!(lookup_proven_org_for_email(&db, "someone@gmail.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn lookup_proven_org_for_email_none_when_no_row() {
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        assert!(lookup_proven_org_for_email(&db, "owner@acme.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn ensure_default_floor_member_less_non_allowlisted_gets_default_member() {
        let db = db::test_pool().await;
        let cfg = admin_cfg(&[]);
        ensure_default_floor(&db, &cfg, "ident-1", "user@example.com").await;
        assert_eq!(
            org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Member)
        );
    }

    #[tokio::test]
    async fn ensure_default_floor_non_allowlisted_never_becomes_default_owner() {
        // H3: even the very first Default member is a Member, never Owner, once
        // the owner-on-emptiness bootstrap is gone.
        let db = db::test_pool().await;
        let cfg = admin_cfg(&[]);
        ensure_default_floor(&db, &cfg, "ident-1", "user@example.com").await;
        assert_eq!(
            org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Member)
        );
    }

    #[tokio::test]
    async fn ensure_default_floor_identity_with_tenant_org_gets_no_default() {
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        db::add_member_race_safe(&db, "ident-1", "acme-id", Role::Member)
            .await
            .unwrap();
        let cfg = admin_cfg(&[]);
        ensure_default_floor(&db, &cfg, "ident-1", "user@example.com").await;
        assert_eq!(org_role(&db, "ident-1", DEFAULT_ORG_ID).await, None);
    }

    #[tokio::test]
    async fn ensure_default_floor_allowlisted_gets_owner_and_keeps_it_with_tenant() {
        let db = db::test_pool().await;
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        db::add_member_race_safe(&db, "ident-1", "acme-id", Role::Owner)
            .await
            .unwrap();
        let cfg = admin_cfg(&["boss@example.com"]);
        // Operator is added to Default as Owner despite holding a tenant org.
        ensure_default_floor(&db, &cfg, "ident-1", "boss@example.com").await;
        assert_eq!(
            org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Owner)
        );
        assert_eq!(org_role(&db, "ident-1", "acme-id").await, Some(Role::Owner));
    }

    #[tokio::test]
    async fn ensure_default_floor_is_idempotent() {
        let db = db::test_pool().await;
        let cfg = admin_cfg(&[]);
        ensure_default_floor(&db, &cfg, "ident-1", "user@example.com").await;
        ensure_default_floor(&db, &cfg, "ident-1", "user@example.com").await;
        assert_eq!(
            org_role(&db, "ident-1", DEFAULT_ORG_ID).await,
            Some(Role::Member)
        );
    }
}
