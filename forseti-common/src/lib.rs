//! Values and checks shared by the `forseti` server and the `forseti-config` tool.

/// Shortest audit webhook token accepted on a production-shaped deployment.
pub const WEBHOOK_TOKEN_MIN_LEN: usize = 32;

/// Scopes the server's ID token builder acts on, advertised through Hydra's
/// `webfinger.oidc_discovery.supported_scope` (Hydra adds `openid`,
/// `offline` and `offline_access` itself).
pub const SUPPORTED_SCOPES: [&str; 6] = [
    "email",
    "profile",
    "org",
    "orgs",
    "groups",
    "extended_profile",
];

/// A string that is empty, missing, or an obvious placeholder isn't a
/// real secret/URL. Case-insensitive substring match against known tells.
#[must_use]
pub fn is_placeholder(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    const TELLS: &[&str] = &[
        "change-me",
        "changeme",
        "change_me",
        "please-change",
        "not-secure",
        "not-a-secret",
        "secret-here",
        "your-secret",
        "example-secret",
        "todo",
    ];
    TELLS.iter().any(|t| lower.contains(t))
}

/// Best-effort check for "this deployment looks production-shaped". True iff
/// Forseti's own URL is https AND the host is not localhost / loopback /
/// RFC1918 / IPv6 ULA or link-local. Can't detect the actual instance count,
/// only the deployment shape.
#[must_use]
pub fn looks_like_production(self_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(self_url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host() else {
        return false;
    };
    match host {
        url::Host::Domain(name) => name != "localhost",
        url::Host::Ipv4(v4) => !(v4.is_loopback() || v4.is_private()),
        // 2001:db8::/32 (documentation prefix) is intentionally NOT treated as
        // non-prod: it's reserved for examples, not private deployments.
        url::Host::Ipv6(v6) => {
            !(v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local())
        }
    }
}
