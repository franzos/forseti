//! License data model — what Forseti carries in memory after
//! [`crate::commercial::verify::decode_and_verify`] has accepted a blob.
//!
//! The on-wire `Claims` shape (in `forseti-license/src/claims.rs`) is
//! deliberately stringly-typed for forward compatibility; this module
//! normalises it into typed enums so the rest of Forseti pattern-matches
//! against [`Feature`] instead of stringly-typed claims.

use chrono::{DateTime, Utc};

/// Gated feature names recognised by Forseti. The license blob carries
/// strings; unknown strings are ignored at parse time so an old binary
/// reading a newer license doesn't reject otherwise-valid features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feature {
    /// Multi-tenant organisations + membership + OIDC `orgs` claim.
    Orgs,
    /// SAML 2.0 Service Provider connectors.
    Saml,
    /// SCIM 2.0 provisioning bridge.
    Scim,
    /// Audit log streaming to external SIEM destinations.
    SiemStreaming,
    /// Bulk admin ops (mass suspend, force-MFA, etc.).
    BulkAdmin,
}

impl Feature {
    pub fn wire_name(self) -> &'static str {
        match self {
            Feature::Orgs => "orgs",
            Feature::Saml => "saml",
            Feature::Scim => "scim",
            Feature::SiemStreaming => "siem_streaming",
            Feature::BulkAdmin => "bulk_admin",
        }
    }

    /// Reverse of [`Feature::wire_name`]. Returns `None` for unknown
    /// strings so the parser can silently drop forward-compat features
    /// rather than rejecting the whole blob.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "orgs" => Some(Feature::Orgs),
            "saml" => Some(Feature::Saml),
            "scim" => Some(Feature::Scim),
            "siem_streaming" => Some(Feature::SiemStreaming),
            "bulk_admin" => Some(Feature::BulkAdmin),
            _ => None,
        }
    }

    /// Human-readable label for the upsell template.
    pub fn label(self) -> &'static str {
        match self {
            Feature::Orgs => "Organizations",
            Feature::Saml => "SAML connectors",
            Feature::Scim => "SCIM provisioning",
            Feature::SiemStreaming => "SIEM streaming",
            Feature::BulkAdmin => "Bulk admin operations",
        }
    }
}

/// True when `current` is strictly below `cap`. `None` (unlimited) is
/// always under.
pub fn org_cap_allows(cap: Option<u32>, current: u32) -> bool {
    cap.is_none_or(|c| current < c)
}

/// Normalised, post-verification license. Held by [`LicenseStatus`] —
/// constructed by [`crate::commercial::verify::decode_and_verify`].
#[derive(Debug, Clone)]
pub struct License {
    pub license_id: String,
    pub customer: String,
    pub email: String,
    pub issued_at: DateTime<Utc>,
    /// `None` = lifetime license.
    pub expires_at: Option<DateTime<Utc>>,
    pub features: Vec<Feature>,
    /// `None` = unlimited.
    pub max_orgs: Option<u32>,
}

impl License {
    pub fn has_feature(&self, feature: Feature) -> bool {
        self.features.contains(&feature)
    }

    /// True iff a hard expiry has passed (lifetime licenses never expire).
    pub fn is_past_expiry(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            None => false,
            Some(exp) => now > exp,
        }
    }
}

/// Cached runtime status. Active / Grace / Expired / Unlicensed lets the
/// dashboard banner decide what to render without re-evaluating clock math
/// on every request.
#[derive(Debug, Clone)]
pub enum LicenseStatus {
    /// No license row in the DB. OSS-tier shape.
    Unlicensed,
    /// Active license, before any expiry.
    Active(License),
    /// Past hard expiry but inside the configured grace window. Features
    /// gated by the license go read-only.
    Grace(License),
    /// Past expiry AND past the grace window. Treated like Unlicensed for
    /// feature checks, but the dashboard surfaces a "Renew" banner.
    Expired(License),
}

impl LicenseStatus {
    pub fn license(&self) -> Option<&License> {
        match self {
            LicenseStatus::Unlicensed => None,
            LicenseStatus::Active(l) | LicenseStatus::Grace(l) | LicenseStatus::Expired(l) => {
                Some(l)
            }
        }
    }
}

/// What the gate at a call site sees.
#[derive(Debug, Clone)]
pub enum FeatureStatus {
    /// Fully licensed — proceed with the real action.
    Allowed,
    /// Inside the grace window — surface the feature as read-only and
    /// nudge the operator to renew. Hard POSTs (e.g. "create new org")
    /// MUST still bail; reads stay accessible.
    GraceReadOnly,
    /// Not licensed (no blob, blob missing the feature, or past grace).
    /// Render the upsell page.
    Locked,
}

/// Pure function so it can be unit-tested without an `ArcSwap`.
pub(crate) fn evaluate_feature(status: &LicenseStatus, feature: Feature) -> FeatureStatus {
    let license = match status {
        LicenseStatus::Unlicensed | LicenseStatus::Expired(_) => return FeatureStatus::Locked,
        LicenseStatus::Active(l) | LicenseStatus::Grace(l) => l,
    };
    if !license.has_feature(feature) {
        return FeatureStatus::Locked;
    }
    match status {
        LicenseStatus::Active(_) => FeatureStatus::Allowed,
        LicenseStatus::Grace(_) => FeatureStatus::GraceReadOnly,
        // Unreachable — the two non-licensed arms returned `Locked` above.
        _ => FeatureStatus::Locked,
    }
}

/// Fixed read-only window after license expiry before hard-gating; not operator-configurable.
pub const GRACE_DAYS: i64 = 30;

/// Reclassify an `Active` license against the wall clock. Called at boot
/// (after the DB row is decoded) and on every activation. Keeps the
/// runtime status in sync with reality without forcing every feature
/// check to redo the expiry math.
pub fn classify(license: License, grace_days: i64, now: DateTime<Utc>) -> LicenseStatus {
    if !license.is_past_expiry(now) {
        return LicenseStatus::Active(license);
    }
    let days_past = license
        .expires_at
        .map(|exp| (now - exp).num_days())
        .unwrap_or(0);
    if days_past <= grace_days {
        LicenseStatus::Grace(license)
    } else {
        LicenseStatus::Expired(license)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn license_with(expires: Option<DateTime<Utc>>, features: Vec<Feature>) -> License {
        License {
            license_id: "test".into(),
            customer: "Test Co".into(),
            email: "t@example.com".into(),
            issued_at: Utc::now(),
            expires_at: expires,
            features,
            max_orgs: None,
        }
    }

    #[test]
    fn unlicensed_is_locked() {
        let s = LicenseStatus::Unlicensed;
        assert!(matches!(
            evaluate_feature(&s, Feature::Orgs),
            FeatureStatus::Locked
        ));
    }

    #[test]
    fn active_with_feature_is_allowed() {
        let l = license_with(None, vec![Feature::Orgs]);
        let s = LicenseStatus::Active(l);
        assert!(matches!(
            evaluate_feature(&s, Feature::Orgs),
            FeatureStatus::Allowed
        ));
    }

    #[test]
    fn active_without_feature_is_locked() {
        let l = license_with(None, vec![Feature::Saml]);
        let s = LicenseStatus::Active(l);
        assert!(matches!(
            evaluate_feature(&s, Feature::Orgs),
            FeatureStatus::Locked
        ));
    }

    #[test]
    fn grace_is_read_only_when_feature_present() {
        let l = license_with(
            Some(Utc::now() - chrono::Duration::days(5)),
            vec![Feature::Orgs],
        );
        let s = LicenseStatus::Grace(l);
        assert!(matches!(
            evaluate_feature(&s, Feature::Orgs),
            FeatureStatus::GraceReadOnly
        ));
    }

    #[test]
    fn expired_is_locked() {
        let l = license_with(
            Some(Utc::now() - chrono::Duration::days(30)),
            vec![Feature::Orgs],
        );
        let s = LicenseStatus::Expired(l);
        assert!(matches!(
            evaluate_feature(&s, Feature::Orgs),
            FeatureStatus::Locked
        ));
    }

    #[test]
    fn classify_picks_grace_under_window() {
        let l = license_with(
            Some(Utc::now() - chrono::Duration::days(3)),
            vec![Feature::Orgs],
        );
        let s = classify(l, 14, Utc::now());
        assert!(matches!(s, LicenseStatus::Grace(_)));
    }

    #[test]
    fn classify_picks_expired_past_window() {
        let l = license_with(
            Some(Utc::now() - chrono::Duration::days(30)),
            vec![Feature::Orgs],
        );
        let s = classify(l, 14, Utc::now());
        assert!(matches!(s, LicenseStatus::Expired(_)));
    }

    #[test]
    fn grace_window_is_fixed_at_thirty_days() {
        assert_eq!(GRACE_DAYS, 30);

        let in_grace = license_with(
            Some(Utc::now() - chrono::Duration::days(20)),
            vec![Feature::Orgs],
        );
        assert!(matches!(
            classify(in_grace, GRACE_DAYS, Utc::now()),
            LicenseStatus::Grace(_)
        ));

        let past_grace = license_with(
            Some(Utc::now() - chrono::Duration::days(40)),
            vec![Feature::Orgs],
        );
        assert!(matches!(
            classify(past_grace, GRACE_DAYS, Utc::now()),
            LicenseStatus::Expired(_)
        ));
    }
}
