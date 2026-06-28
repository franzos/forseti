//! Per-org member-directory visibility policy + the visibility predicate.
#![allow(dead_code)] // wired incrementally by the member-directory surface.
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberVisibility {
    All,
    SameGroup,
    AdminsOnly,
}

impl MemberVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::SameGroup => "same_group",
            Self::AdminsOnly => "admins_only",
        }
    }
}

impl FromStr for MemberVisibility {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "all" => Ok(Self::All),
            "same_group" => Ok(Self::SameGroup),
            "admins_only" => Ok(Self::AdminsOnly),
            _ => Err(()),
        }
    }
}

/// Fail closed to the MOST RESTRICTIVE on an unknown DB string (mirrors `orgs::is_owner_role`).
pub fn parse_visibility(s: &str) -> MemberVisibility {
    s.parse().unwrap_or_else(|()| {
        tracing::warn!(value = %s, "orgs: unknown member_visibility; failing closed to admins_only");
        MemberVisibility::AdminsOnly
    })
}

/// Pure visibility decision: may `viewer` see `target` in `org`'s directory?
/// `viewer_is_admin` MUST already fold in the AAL2 check at the call site.
pub fn visible(
    policy: MemberVisibility,
    is_self: bool,
    viewer_is_owner: bool,
    viewer_is_admin: bool,
    target_hidden: bool,
    shares_team: bool,
) -> bool {
    if is_self || viewer_is_owner || viewer_is_admin {
        return true;
    }
    if target_hidden {
        return false;
    }
    match policy {
        MemberVisibility::All => true,
        MemberVisibility::AdminsOnly => false,
        MemberVisibility::SameGroup => shares_team,
    }
}

/// Is `target` visible to `viewer` in `org_id`'s directory? Resolves the
/// policy, viewer-owner, target-opt-out, and shared-team inputs, then applies
/// [`visible`]. `viewer_is_admin_aal2` is computed once by the caller.
pub async fn member_visible_to_in_org(
    db: &crate::db::DbPool,
    org_id: &str,
    viewer_id: &str,
    target_id: &str,
    viewer_is_admin_aal2: bool,
) -> bool {
    if viewer_id == target_id {
        return true;
    }
    let policy = match crate::orgs::db::org_by_id(db, org_id).await {
        Ok(Some(o)) => parse_visibility(&o.member_visibility),
        _ => return false, // unknown org → fail closed
    };
    let viewer_is_owner = matches!(
        crate::orgs::org_role(db, viewer_id, org_id).await,
        Some(crate::orgs::Role::Owner)
    );
    // Fail closed: anything but a confirmed not-hidden membership counts as
    // hidden, so a DB hiccup never momentarily exposes an opted-out member.
    let target_hidden = !matches!(
        crate::orgs::find_member(db, target_id, org_id).await,
        Ok(Some(m)) if m.hidden_from_directory == 0
    );
    let shares = crate::orgs::teams::shared_team(db, org_id, viewer_id, target_id)
        .await
        .unwrap_or(false);
    visible(
        policy,
        false,
        viewer_is_owner,
        viewer_is_admin_aal2,
        target_hidden,
        shares,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fails_closed() {
        assert_eq!(parse_visibility("bogus"), MemberVisibility::AdminsOnly);
    }

    #[test]
    fn roundtrip() {
        for p in [
            MemberVisibility::All,
            MemberVisibility::SameGroup,
            MemberVisibility::AdminsOnly,
        ] {
            assert_eq!(p.as_str().parse::<MemberVisibility>().unwrap(), p);
        }
    }

    #[test]
    fn self_owner_admin_always_visible() {
        for p in [
            MemberVisibility::All,
            MemberVisibility::SameGroup,
            MemberVisibility::AdminsOnly,
        ] {
            assert!(visible(p, true, false, false, true, false)); // self, even if hidden
            assert!(visible(p, false, true, false, true, false)); // owner
            assert!(visible(p, false, false, true, true, false)); // admin(aal2)
        }
    }

    #[test]
    fn opt_out_hides_from_peers() {
        assert!(!visible(
            MemberVisibility::All,
            false,
            false,
            false,
            true,
            true
        ));
    }

    #[test]
    fn same_group_needs_shared_team() {
        assert!(visible(
            MemberVisibility::SameGroup,
            false,
            false,
            false,
            false,
            true
        ));
        assert!(!visible(
            MemberVisibility::SameGroup,
            false,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn admins_only_hides_peers() {
        assert!(!visible(
            MemberVisibility::AdminsOnly,
            false,
            false,
            false,
            false,
            true
        ));
    }

    #[test]
    fn all_shows_peers() {
        assert!(visible(
            MemberVisibility::All,
            false,
            false,
            false,
            false,
            false
        ));
    }
}
