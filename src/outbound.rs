//! Shared outbound HTTP for attacker-influenceable targets: CIMD documents,
//! domain-verification files, protected-resource metadata, webhook delivery.
//! One `reqwest::Client` per trust policy, built once (a fresh client
//! reloads the platform root store from disk), plus the capped body read
//! every caller needs. Redirects are never followed: a 302 to an internal
//! address would bypass the save-time URL checks.

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
