//! Webhook target URL validation — SSRF guard before persisting on a client.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Validate a webhook target URL before persisting it on a Hydra client.
///
/// Admins are not root-of-trust against the internal network — without
/// validation, a `metadata.forseti.account_deletion_url` of
/// `http://169.254.169.254/...` (IMDS), `http://localhost:5432`, or a
/// `file://` URL turns the webhook worker into a confused-deputy SSRF
/// vector. We require:
///
/// - `https://` scheme (transport integrity for signed payloads)
/// - a host that's neither a literal loopback, link-local, nor RFC1918 IP
///
/// This is the save-time half of the guard. DNS-rebinding (a public
/// hostname that later resolves to an internal IP) is closed at connect
/// time by [`GuardedResolver`], which re-runs [`is_blocked_ip`] against
/// every resolved address before the worker dials it. The worker also
/// disables redirects so a `302` to a private address can't redirect
/// through.
pub fn validate_webhook_url(raw: &str) -> Result<(), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(());
    }
    let parsed = url::Url::parse(raw).map_err(|e| format!("not a valid URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("webhook URL must use https://".to_string());
    }
    // Userinfo would land verbatim in the outbox `last_error` column (shown
    // on the admin page) via the reqwest error, leaking the credentials.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("webhook URL must not embed userinfo (username/password)".to_string());
    }
    // Typed Host extraction — avoids ambiguity around whether `host_str`
    // strips IPv6 brackets, and gets us straight to `Ipv4Addr` /
    // `Ipv6Addr` for the private-range check.
    match parsed.host() {
        Some(url::Host::Domain(d)) => {
            if d.eq_ignore_ascii_case("localhost") {
                return Err("webhook URL host must not be a loopback address".to_string());
            }
        }
        Some(url::Host::Ipv4(v4)) => {
            if is_blocked_ip(IpAddr::V4(v4)) {
                return Err(
                    "webhook URL host must not be a loopback, link-local, or private-network IPv4"
                        .to_string(),
                );
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_blocked_ip(IpAddr::V6(v6)) {
                return Err(
                    "webhook URL host must not be a loopback, link-local, or unique-local IPv6"
                        .to_string(),
                );
            }
        }
        None => return Err("webhook URL must include a host".to_string()),
    }
    Ok(())
}

/// Single source of truth for the SSRF blocklist, shared between the
/// save-time URL check and the connect-time [`GuardedResolver`]. An
/// address matching any internal/special range is refused.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        // RFC1918
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        // CGNAT
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        // 169.254/16 — link-local + IMDS
        || o[0] == 169 && o[1] == 254
}

fn is_blocked_v6(v6: Ipv6Addr) -> bool {
    if let Some(embedded) = embedded_ipv4(v6) {
        return is_blocked_v4(embedded);
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
}

/// IPv4-mapped (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`), and 6to4
/// (`2002::/16`) addresses classify by their embedded IPv4 address, so a
/// NAT64/6to4-capable egress can't smuggle a blocked v4 target through v6.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return Some(mapped);
    }
    let s = v6.segments();
    let o = v6.octets();
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

/// Connect-time SSRF guard. Resolves names via the system resolver and
/// drops every [`is_blocked_ip`] address before reqwest dials it, closing
/// the DNS-rebinding gap left by the save-time [`validate_webhook_url`]
/// check. If resolution yields only blocked addresses the request fails
/// with an empty address set, surfacing as a transport error in the
/// outbox row.
#[derive(Debug, Default)]
pub struct GuardedResolver;

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // getaddrinfo on tokio's blocking pool; port 0 is replaced by
            // reqwest with the scheme's conventional port post-resolution.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let safe: Vec<SocketAddr> = resolved
                .filter(|addr| {
                    if is_blocked_ip(addr.ip()) {
                        tracing::warn!(
                            host = %host,
                            addr = %addr.ip(),
                            "webhook target resolved to a blocked address; refusing"
                        );
                        false
                    } else {
                        true
                    }
                })
                .collect();
            let addrs: Addrs = Box::new(safe.into_iter());
            Ok(addrs)
        })
    }
}

/// Convenience handle for wiring [`GuardedResolver`] into a
/// `reqwest::ClientBuilder::dns_resolver`.
pub fn guarded_resolver() -> Arc<GuardedResolver> {
    Arc::new(GuardedResolver)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_webhook_url_accepts_https_public() {
        assert!(validate_webhook_url("").is_ok());
        assert!(validate_webhook_url("https://example.com/webhook").is_ok());
        assert!(validate_webhook_url("https://api.example.com:8443/hook").is_ok());
    }

    #[test]
    fn validate_webhook_url_rejects_http_and_other_schemes() {
        assert!(validate_webhook_url("http://example.com/webhook").is_err());
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
        assert!(validate_webhook_url("ftp://example.com/").is_err());
        assert!(validate_webhook_url("not-a-url").is_err());
    }

    #[test]
    fn validate_webhook_url_rejects_internal_targets() {
        for url in [
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://10.0.0.1/hook",
            "https://172.16.0.1/hook",
            "https://172.31.255.255/hook",
            "https://192.168.1.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://100.64.0.1/hook",
            "https://0.0.0.0/hook",
            "https://224.0.0.1/hook",
            "https://[::1]/hook",
            "https://[fe80::1]/hook",
            "https://[fc00::1]/hook",
        ] {
            assert!(validate_webhook_url(url).is_err(), "should reject: {url}");
        }
    }

    #[test]
    fn validate_webhook_url_rejects_embedded_userinfo() {
        assert!(validate_webhook_url("https://user:pass@example.com/hook").is_err());
        assert!(validate_webhook_url("https://user@example.com/hook").is_err());
    }

    #[test]
    fn is_blocked_ip_matches_save_time_ranges() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            // IPv4-mapped IPv6 must classify by its embedded v4 address.
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "should block: {ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "should allow: {ip}");
        }
    }

    #[test]
    fn is_blocked_ip_classifies_nat64_and_6to4_by_embedded_v4() {
        for ip in [
            // NAT64 well-known prefix wrapping 10.0.0.1
            "64:ff9b::a00:1",
            // NAT64 wrapping the IMDS address
            "64:ff9b::a9fe:a9fe",
            // 6to4 wrapping 127.0.0.1
            "2002:7f00:0001::",
            // 6to4 wrapping 192.168.1.1
            "2002:c0a8:0101::",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "should block: {ip}");
        }
        for ip in [
            // NAT64 wrapping public 8.8.8.8
            "64:ff9b::808:808",
            // 6to4 wrapping public 8.8.8.8
            "2002:808:808::",
        ] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "should allow: {ip}");
        }
    }
}
