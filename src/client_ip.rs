//! One client-IP derivation shared by the audit middleware and every per-IP
//! rate limiter, so the audited address and the throttling key can't drift.
//!
//! Behind a trusted proxy (`[proxy].trust_forwarded_for = true`) the client
//! is the `X-Forwarded-For` entry `trusted_hops` from the right: each proxy
//! in the chain appends the address it accepted the connection from, so the
//! rightmost `trusted_hops` entries were written by infrastructure the
//! operator controls and everything left of them is caller-supplied. Taking
//! the leftmost entry instead would let any caller pick their own key.

use std::net::IpAddr;

use axum::http::HeaderMap;
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

use crate::config::ProxyConfig;

/// Client address from the forwarded-for chain, `None` when the chain is
/// absent or shorter than the trusted hop count (the request bypassed the
/// proxy, or the proxy is misconfigured).
pub(crate) fn forwarded_client_ip(headers: &HeaderMap, trusted_hops: u8) -> Option<IpAddr> {
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let hops_back = usize::from(trusted_hops.max(1));
    if hops.len() < hops_back {
        return None;
    }
    hops[hops.len() - hops_back].parse().ok()
}

/// Resolve the client address for this request under the operator's proxy
/// trust settings: the forwarded chain, else the TCP peer. With trust off
/// only the peer counts.
///
/// There is deliberately no `X-Real-IP` fallback. A single-entry `X-Forwarded-For`
/// is what a request that reached Forseti directly looks like, and on that path
/// any caller can also set `X-Real-IP` - so falling back to it hands the caller
/// their own rate-limit key and their own audit trail.
pub(crate) fn client_ip(
    headers: &HeaderMap,
    proxy: &ProxyConfig,
    peer: Option<IpAddr>,
) -> Option<IpAddr> {
    if proxy.trust_forwarded_for {
        forwarded_client_ip(headers, proxy.trusted_hops).or(peer)
    } else {
        peer
    }
}

/// `tower_governor` key extractor over [`client_ip`], built from
/// `[proxy]` so limiter and audit share one answer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientIpKeyExtractor {
    trust_forwarded_for: bool,
    trusted_hops: u8,
}

impl ClientIpKeyExtractor {
    pub(crate) fn from_config(proxy: &ProxyConfig) -> Self {
        Self {
            trust_forwarded_for: proxy.trust_forwarded_for,
            trusted_hops: proxy.trusted_hops,
        }
    }

    fn as_proxy_config(self) -> ProxyConfig {
        ProxyConfig {
            trust_forwarded_for: self.trust_forwarded_for,
            trusted_hops: self.trusted_hops,
        }
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());
        client_ip(req.headers(), &self.as_proxy_config(), peer)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(xff: &[&str], real: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in xff {
            h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        if let Some(r) = real {
            h.insert("x-real-ip", HeaderValue::from_str(r).unwrap());
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn proxy(trust: bool, hops: u8) -> ProxyConfig {
        ProxyConfig {
            trust_forwarded_for: trust,
            trusted_hops: hops,
        }
    }

    #[test]
    fn one_hop_takes_the_entry_the_proxy_appended() {
        // Caller forged "1.1.1.1"; the proxy appended the real peer.
        let h = headers(&["1.1.1.1, 203.0.113.9"], None);
        assert_eq!(forwarded_client_ip(&h, 1), Some(ip("203.0.113.9")));
    }

    #[test]
    fn two_hops_skips_the_inner_proxy() {
        let h = headers(&["1.1.1.1, 203.0.113.9, 10.0.0.2"], None);
        assert_eq!(forwarded_client_ip(&h, 2), Some(ip("203.0.113.9")));
    }

    #[test]
    fn chain_shorter_than_hops_is_none() {
        let h = headers(&["203.0.113.9"], None);
        assert_eq!(forwarded_client_ip(&h, 2), None);
        assert_eq!(forwarded_client_ip(&HeaderMap::new(), 1), None);
    }

    #[test]
    fn multiple_header_lines_are_one_chain() {
        let h = headers(&["1.1.1.1", "203.0.113.9"], None);
        assert_eq!(forwarded_client_ip(&h, 1), Some(ip("203.0.113.9")));
    }

    #[test]
    fn unparsable_trusted_entry_is_none() {
        let h = headers(&["203.0.113.9, unknown"], None);
        assert_eq!(forwarded_client_ip(&h, 1), None);
    }

    #[test]
    fn zero_hops_is_treated_as_one() {
        let h = headers(&["1.1.1.1, 203.0.113.9"], None);
        assert_eq!(forwarded_client_ip(&h, 0), Some(ip("203.0.113.9")));
    }

    #[test]
    fn untrusted_proxy_uses_peer_only() {
        let h = headers(&["1.1.1.1"], Some("2.2.2.2"));
        assert_eq!(
            client_ip(&h, &proxy(false, 1), Some(ip("203.0.113.9"))),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn trusted_proxy_falls_back_to_the_peer_not_a_header() {
        // A spoofable `X-Real-IP` must lose to the peer, with or without a
        // forwarded chain too short to satisfy `trusted_hops`.
        let h = headers(&[], Some("2.2.2.2"));
        assert_eq!(
            client_ip(&h, &proxy(true, 1), Some(ip("203.0.113.9"))),
            Some(ip("203.0.113.9"))
        );
        let h = headers(&["1.1.1.1"], Some("2.2.2.2"));
        assert_eq!(
            client_ip(&h, &proxy(true, 2), Some(ip("203.0.113.9"))),
            Some(ip("203.0.113.9"))
        );
        assert_eq!(
            client_ip(&HeaderMap::new(), &proxy(true, 1), Some(ip("203.0.113.9"))),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn forged_leftmost_entry_never_wins() {
        let h = headers(&["9.9.9.9, 203.0.113.9"], Some("8.8.8.8"));
        assert_eq!(
            client_ip(&h, &proxy(true, 1), Some(ip("10.0.0.1"))),
            Some(ip("203.0.113.9"))
        );
    }
}
