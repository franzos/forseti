//! Shared outbound HTTP for attacker-influenceable targets: CIMD documents,
//! domain-verification files, protected-resource metadata, webhook delivery.
//! One `reqwest::Client` per trust policy, built once (a fresh client
//! reloads the platform root store from disk), plus the capped body read
//! every caller needs. Redirects are never followed: a 302 to an internal
//! address would bypass the save-time URL checks.

use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

use futures_util::StreamExt;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

static GUARDED: LazyLock<reqwest::Client> = LazyLock::new(|| build(true));
static UNGUARDED: LazyLock<reqwest::Client> = LazyLock::new(|| build(false));

fn build(guarded: bool) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // No environment proxy. `HTTP_PROXY`/`ALL_PROXY` would route every
        // attacker-influenceable fetch through a third party, and the
        // connect-time SSRF guard would then be checking the proxy's address
        // rather than the target's — the guard silently stops guarding.
        .no_proxy();
    if guarded {
        // Connect-time SSRF guard: re-checks every resolved address so a
        // public hostname that rebinds to an internal IP can't slip past
        // the save-time check.
        builder = builder.dns_resolver(crate::webhook::guarded_resolver());
    }
    builder.build().expect("static reqwest client config")
}

/// The client for a policy. `allow_private` skips the DNS-rebinding guard
/// (the `[oauth.cimd].allow_private_targets` dev hatch). Set the per-request
/// timeout on the request builder; the client carries only a connect timeout.
pub(crate) fn client(allow_private: bool) -> &'static reqwest::Client {
    if allow_private { &UNGUARDED } else { &GUARDED }
}

#[derive(Debug)]
pub(crate) enum FetchError {
    Transport(String),
    Status(u16),
    TooLarge,
}

/// GET `url` and require a 2xx. Returns the response so the caller can read
/// headers before draining the body with [`read_capped`].
pub(crate) async fn get_ok(
    client: &reqwest::Client,
    url: &str,
    accept: Option<&str>,
    timeout: Duration,
) -> Result<reqwest::Response, FetchError> {
    let mut req = client.get(url).timeout(timeout);
    if let Some(a) = accept {
        req = req.header(reqwest::header::ACCEPT, a);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| FetchError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(FetchError::Status(resp.status().as_u16()));
    }
    Ok(resp)
}

/// Drain a body of at most `limit` bytes. Rejects on the declared length
/// first, then while streaming, so a chunked body without `Content-Length`
/// can't buffer past the cap.
pub(crate) async fn read_capped(
    resp: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, FetchError> {
    if resp.content_length().is_some_and(|l| l > limit as u64) {
        return Err(FetchError::TooLarge);
    }
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| FetchError::Transport(e.to_string()))?;
        if buf.len() + chunk.len() > limit {
            return Err(FetchError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Pre-flight check on an outbound URL: `https` (or `http` with the
/// private-target hatch), no userinfo, a host, and no loopback or blocked IP
/// literal. Domain hosts are re-checked at connect time by [`client`].
/// Errors read as a predicate for the caller to prefix, e.g. "issuer URL ".
pub(crate) fn check_target(url: &url::Url, allow_private: bool) -> Result<(), &'static str> {
    match url.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => return Err("must use https://"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not embed credentials");
    }
    match url.host() {
        None => Err("must include a host"),
        Some(_) if allow_private => Ok(()),
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            Err("host must not be a loopback address")
        }
        Some(url::Host::Ipv4(v4)) if crate::webhook::is_blocked_ip(IpAddr::V4(v4)) => {
            Err("host must not be a private or special-use IP")
        }
        Some(url::Host::Ipv6(v6)) if crate::webhook::is_blocked_ip(IpAddr::V6(v6)) => {
            Err("host must not be a private or special-use IP")
        }
        Some(_) => Ok(()),
    }
}

/// POST `form` as `application/x-www-form-urlencoded` and return the status
/// with a body of at most `limit` bytes, whatever the status.
pub(crate) async fn post_form(
    client: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
    timeout: Duration,
    limit: usize,
) -> Result<(u16, Vec<u8>), FetchError> {
    let resp = client
        .post(url)
        .timeout(timeout)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await
        .map_err(|e| FetchError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    Ok((status, read_capped(resp, limit).await?))
}

#[cfg(test)]
mod tests {
    use super::check_target;

    fn check(raw: &str, allow_private: bool) -> Result<(), &'static str> {
        check_target(&url::Url::parse(raw).unwrap(), allow_private)
    }

    #[test]
    fn https_public_host_ok() {
        assert!(check("https://git.example.com/", false).is_ok());
        assert!(check("https://93.184.216.34/", false).is_ok());
    }

    #[test]
    fn http_only_with_hatch() {
        assert_eq!(
            check("http://git.example.com/", false),
            Err("must use https://")
        );
        assert!(check("http://git.example.com/", true).is_ok());
        assert!(check("ftp://git.example.com/", true).is_err());
    }

    #[test]
    fn loopback_refused_without_hatch() {
        for raw in [
            "https://localhost/",
            "https://LOCALHOST:8443/",
            "https://127.0.0.1/",
            "https://[::1]/",
        ] {
            assert!(check(raw, false).is_err(), "should reject: {raw}");
            assert!(check(raw, true).is_ok(), "hatch should allow: {raw}");
        }
    }

    #[test]
    fn private_literal_refused_without_hatch() {
        for raw in [
            "https://10.0.0.1/",
            "https://192.168.1.10/",
            "https://169.254.169.254/",
            "https://[fd00::1]/",
        ] {
            assert_eq!(
                check(raw, false),
                Err("host must not be a private or special-use IP"),
                "{raw}"
            );
        }
    }

    #[test]
    fn userinfo_refused_even_with_hatch() {
        for raw in [
            "https://user@git.example.com/",
            "https://user:pw@git.example.com/",
            "https://:pw@git.example.com/",
        ] {
            assert_eq!(check(raw, true), Err("must not embed credentials"), "{raw}");
        }
    }
}
