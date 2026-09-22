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
        || (o[0] == 169 && o[1] == 254)
        // 0.0.0.0/8 "this network" — on Linux 0.x.y.z reaches loopback
        || o[0] == 0
        // 192.0.0.0/24 IETF protocol assignments (incl. 192.0.0.192 NAT64 discovery)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 benchmarking
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        // 240.0.0.0/4 reserved, and 255.255.255.255 is caught by is_broadcast
        || o[0] >= 240
}

fn is_blocked_v6(v6: Ipv6Addr) -> bool {
    if let Some(embedded) = embedded_ipv4(v6) {
        return is_blocked_v4(embedded);
    }
    let s = v6.segments();
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        // 2001::/32 Teredo — tunnels to an arbitrary v4 endpoint
        || (s[0] == 0x2001 && s[1] == 0)
        // fec0::/10 deprecated site-local, still routed by some stacks
        || (s[0] & 0xffc0) == 0xfec0
        // 64:ff9b:1::/48 local-use NAT64, the sibling of the well-known prefix
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
}

/// IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::a.b.c.d`), NAT64
/// (`64:ff9b::/96`), and 6to4 (`2002::/16`) addresses classify by their
/// embedded IPv4 address, so a NAT64/6to4-capable egress can't smuggle a
/// blocked v4 target through v6.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return Some(mapped);
    }
    // IPv4-compatible (`::a.b.c.d`): deprecated, but still parsed and routed.
    // `to_ipv4` covers it and the mapped form; the mapped case already
    // returned above.
    if let Some(compat) = v6.to_ipv4() {
        return Some(compat);
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

#[cfg(test)]
mod range_gap_tests {
    use super::is_blocked_ip;
    use std::net::IpAddr;

    fn blocked(addr: &str) -> bool {
        is_blocked_ip(addr.parse::<IpAddr>().expect("test address parses"))
    }

    #[test]
    fn this_network_reaches_loopback_on_linux() {
        assert!(blocked("0.0.0.0"));
        assert!(blocked("0.1.2.3"));
    }

    #[test]
    fn ietf_protocol_assignments_are_blocked() {
        // 192.0.0.192 is the NAT64 discovery address.
        assert!(blocked("192.0.0.1"));
        assert!(blocked("192.0.0.192"));
        // 192.0.2.0/24 (TEST-NET-1) is a different block and not part of this.
        assert!(!blocked("192.0.2.1"));
    }

    #[test]
    fn benchmarking_range_is_blocked() {
        assert!(blocked("198.18.0.1"));
        assert!(blocked("198.19.255.255"));
        assert!(!blocked("198.20.0.1"));
    }

    #[test]
    fn reserved_class_e_is_blocked() {
        assert!(blocked("240.0.0.1"));
        assert!(blocked("255.255.255.254"));
        // 239/8 is multicast, caught by a different arm — 239.x is not 240/4.
        assert!(blocked("239.255.255.255"));
    }

    #[test]
    fn ipv4_compatible_v6_classifies_by_its_embedded_address() {
        // `::127.0.0.1` is loopback wearing a v6 hat.
        assert!(blocked("::127.0.0.1"));
        assert!(blocked("::10.0.0.1"));
    }

    #[test]
    fn local_use_nat64_is_blocked() {
        assert!(blocked("64:ff9b:1::1"));
    }

    #[test]
    fn teredo_is_blocked() {
        assert!(blocked("2001:0:4136:e378:8000:63bf:3fff:fdd2"));
        // 2001:db8::/32 (documentation) is a different prefix; 2001::/32 is
        // specifically `s[1] == 0`.
        assert!(!blocked("2001:db8::1"));
    }

    #[test]
    fn deprecated_site_local_is_blocked() {
        assert!(blocked("fec0::1"));
        assert!(blocked("feff::1"));
    }

    #[test]
    fn ordinary_public_addresses_still_pass() {
        assert!(!blocked("93.184.216.34"));
        assert!(!blocked("2606:2800:220:1:248:1893:25c8:1946"));
    }
}
