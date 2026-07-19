//! Invariant: the OAuth login/consent handlers never write org membership.
//! Placement happens only in `/join/confirm` (CSRF POST). See the org-scoped
//! OAuth entry design.

#[test]
fn oauth_modules_never_write_membership() {
    for rel in ["src/oauth/login.rs", "src/oauth/consent.rs"] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        assert!(
            !src.contains("join_org_race_safe"),
            "{rel} must not write membership"
        );
        assert!(
            !src.contains("ORG_MEMBER_ADDED"),
            "{rel} must not emit member-added audit"
        );
    }
}
