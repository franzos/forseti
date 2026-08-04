//! CIMD document fetcher: SSRF-guarded HTTP GET of a client_id metadata URL,
//! parsed into [`CimdDocument`] and cached (bounded, per-entry TTL,
//! single-flight, serve-stale-on-error). Policy validation of the parsed
//! document (client_id equality, auth method, redirect matching) stays in
//! `oauth::cimd`.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use futures_util::StreamExt;
use moka::Expiry;
use moka::future::Cache;
use sha2::Digest;
use url::Url;

use crate::state::AppState;

/// Accepted client_id URL length cap; anything longer is attacker noise.
const MAX_URL_BYTES: usize = 512;
const DOC_LIMIT_BYTES: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_ENTRIES: u64 = 1024;
const TTL_MIN_SECS: u64 = 60;
const TTL_MAX_SECS: u64 = 24 * 60 * 60;
const TTL_DEFAULT: Duration = Duration::from_secs(300);
/// How long past freshness a last-good document may still serve on fetch failure.
const STALE_GRACE: Duration = Duration::from_secs(60 * 60);

/// Parsed client metadata document. Absent `grant_types`/`response_types`/
/// `token_endpoint_auth_method` take their RFC 7591 defaults at parse time so
/// `cimd::validate_doc` semantics match the pre-cache spike behavior.
#[derive(Debug)]
pub struct CimdDocument {
    /// SHA-256 of the raw response body; drives the shim's warm-path skip.
    pub raw_hash: [u8; 32],
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    /// Unioned into the Hydra row's scope ceiling at upsert time.
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub enum CimdFetchError {
    /// Rejected by the pre-flight SSRF/shape guard.
    UrlRejected(String),
    Transport(String),
    Status(u16),
    TooLarge,
    Invalid(String),
}

impl std::fmt::Display for CimdFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UrlRejected(m) => write!(f, "client_id URL rejected: {m}"),
            Self::Transport(m) => write!(f, "client metadata fetch failed: {m}"),
            Self::Status(s) => write!(f, "client metadata fetch returned HTTP {s}"),
            Self::TooLarge => f.write_str("client metadata document too large"),
            Self::Invalid(m) => write!(f, "client metadata document invalid: {m}"),
        }
    }
}

impl std::error::Error for CimdFetchError {}

#[derive(Clone)]
struct CachedDoc {
    doc: Arc<CimdDocument>,
    ttl: Duration,
}

struct PerEntryTtl;

impl Expiry<String, CachedDoc> for PerEntryTtl {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CachedDoc,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

type DocCache = Cache<String, CachedDoc>;

fn new_cache() -> DocCache {
    Cache::builder()
        .max_capacity(CACHE_ENTRIES)
        .expire_after(PerEntryTtl)
        .build()
}

static FRESH: LazyLock<DocCache> = LazyLock::new(new_cache);
/// Serve-stale design: last-good docs live in this second cache with entry
/// TTL = fresh TTL + grace — simpler than fetched_at bookkeeping per entry.
static LAST_GOOD: LazyLock<DocCache> = LazyLock::new(new_cache);

/// Fetch (or serve from cache) the client metadata document at `url`.
pub async fn fetch_document(
    state: &AppState,
    url: &Url,
) -> Result<Arc<CimdDocument>, CimdFetchError> {
    fetch_with(
        &FRESH,
        &LAST_GOOD,
        url,
        state.cfg.oauth.cimd.allow_private_targets,
        FETCH_TIMEOUT,
    )
    .await
}

/// Cache-fronted fetch; `try_get_with` coalesces concurrent misses per key
/// into one network fetch. Split from [`fetch_document`] so tests can inject
/// isolated caches and a short timeout.
async fn fetch_with(
    fresh: &DocCache,
    last_good: &DocCache,
    url: &Url,
    allow_private: bool,
    timeout: Duration,
) -> Result<Arc<CimdDocument>, CimdFetchError> {
    let key = url.as_str().to_string();
    let loaded = fresh
        .try_get_with(key.clone(), async {
            let (doc, ttl) = fetch_once(url, allow_private, timeout).await?;
            last_good
                .insert(
                    key.clone(),
                    CachedDoc {
                        doc: Arc::clone(&doc),
                        ttl: ttl + STALE_GRACE,
                    },
                )
                .await;
            Ok::<_, CimdFetchError>(CachedDoc { doc, ttl })
        })
        .await;
    match loaded {
        Ok(cached) => Ok(cached.doc),
        Err(e) => match last_good.get(url.as_str()).await {
            Some(stale) => {
                tracing::warn!(url = %url, error = %e, "cimd: serving stale document after fetch failure");
                Ok(stale.doc)
            }
            None => Err(Arc::unwrap_or_clone(e)),
        },
    }
}

async fn fetch_once(
    url: &Url,
    allow_private: bool,
    timeout: Duration,
) -> Result<(Arc<CimdDocument>, Duration), CimdFetchError> {
    guard_url(url, allow_private)?;
    let resp = doc_client(allow_private, timeout)
        .get(url.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| CimdFetchError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(CimdFetchError::Status(resp.status().as_u16()));
    }
    let ttl = ttl_from_cache_control(
        resp.headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
    );
    if resp
        .content_length()
        .is_some_and(|l| l > DOC_LIMIT_BYTES as u64)
    {
        return Err(CimdFetchError::TooLarge);
    }
    // Chunked/streamed bodies carry no Content-Length; enforce the cap while reading.
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| CimdFetchError::Transport(e.to_string()))?;
        if buf.len() + chunk.len() > DOC_LIMIT_BYTES {
            return Err(CimdFetchError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    let doc = parse_document(&buf)?;
    Ok((Arc::new(doc), ttl))
}

/// Pre-flight shape + SSRF check on the client_id URL. IP-literal hosts are
/// checked here; domain hosts are re-checked at connect time by the
/// `webhook::guarded_resolver` DNS-rebinding guard wired into [`doc_client`].
fn guard_url(url: &Url, allow_private: bool) -> Result<(), CimdFetchError> {
    let reject = |m: &str| Err(CimdFetchError::UrlRejected(m.to_string()));
    if url.as_str().len() > MAX_URL_BYTES {
        return reject("client_id URL exceeds 512 bytes");
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => return reject("client_id URL must use https://"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return reject("client_id URL must not embed credentials");
    }
    if url.fragment().is_some() {
        return reject("client_id URL must not carry a fragment");
    }
    match url.host() {
        None => return reject("client_id URL must include a host"),
        Some(_) if allow_private => {}
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            return reject("client_id URL host must not be a loopback address");
        }
        Some(url::Host::Ipv4(v4)) if crate::webhook::is_blocked_ip(IpAddr::V4(v4)) => {
            return reject("client_id URL host must not be a private or special-use IP");
        }
        Some(url::Host::Ipv6(v6)) if crate::webhook::is_blocked_ip(IpAddr::V6(v6)) => {
            return reject("client_id URL host must not be a private or special-use IP");
        }
        Some(_) => {}
    }
    Ok(())
}

fn doc_client(allow_private: bool, timeout: Duration) -> reqwest::Client {
    // Redirect policy NONE is stricter than the CIMD draft on purpose: the doc
    // URL must answer directly, so a hop can never re-target a vetted address.
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if !allow_private {
        builder = builder.dns_resolver(crate::webhook::guarded_resolver());
    }
    builder.build().expect("static reqwest client config")
}

/// Freshness TTL from `Cache-Control: max-age`, clamped to [60 s, 24 h];
/// absent or unparsable → 300 s.
fn ttl_from_cache_control(header: Option<&str>) -> Duration {
    let secs = header.and_then(|h| {
        h.split(',').find_map(|directive| {
            directive
                .trim()
                .to_ascii_lowercase()
                .strip_prefix("max-age=")?
                .trim()
                .parse::<u64>()
                .ok()
        })
    });
    match secs {
        Some(s) => Duration::from_secs(s.clamp(TTL_MIN_SECS, TTL_MAX_SECS)),
        None => TTL_DEFAULT,
    }
}

fn parse_document(raw: &[u8]) -> Result<CimdDocument, CimdFetchError> {
    #[derive(serde::Deserialize)]
    struct RawDoc {
        client_id: String,
        client_name: Option<String>,
        client_uri: Option<String>,
        logo_uri: Option<String>,
        #[serde(default)]
        redirect_uris: Vec<String>,
        grant_types: Option<Vec<String>>,
        response_types: Option<Vec<String>>,
        token_endpoint_auth_method: Option<String>,
        scope: Option<String>,
    }
    let doc: RawDoc =
        serde_json::from_slice(raw).map_err(|e| CimdFetchError::Invalid(e.to_string()))?;
    Ok(CimdDocument {
        raw_hash: sha2::Sha256::digest(raw).into(),
        client_id: doc.client_id,
        client_name: doc.client_name,
        client_uri: doc.client_uri,
        logo_uri: doc.logo_uri,
        redirect_uris: doc.redirect_uris,
        grant_types: doc
            .grant_types
            .unwrap_or_else(|| vec!["authorization_code".to_string()]),
        response_types: doc
            .response_types
            .unwrap_or_else(|| vec!["code".to_string()]),
        token_endpoint_auth_method: doc
            .token_endpoint_auth_method
            .unwrap_or_else(|| "client_secret_basic".to_string()),
        scope: doc.scope,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn doc_json() -> Vec<u8> {
        br#"{"client_id":"https://client.example/doc","token_endpoint_auth_method":"none","redirect_uris":["http://localhost/cb"]}"#
            .to_vec()
    }

    /// Loopback fixture server counting hits; `chunked` streams the body in
    /// 1 KiB frames (no Content-Length) to exercise the streaming cap.
    async fn serve_fixture(
        body: Vec<u8>,
        chunked: bool,
        delay: Duration,
        cache_control: Option<&'static str>,
    ) -> (Url, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        let handler = move || {
            let h = Arc::clone(&h);
            let body = body.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                let axum_body = if chunked {
                    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
                        body.chunks(1024).map(|c| Ok(c.to_vec())).collect();
                    axum::body::Body::from_stream(futures_util::stream::iter(chunks))
                } else {
                    axum::body::Body::from(body)
                };
                let mut resp = axum::http::Response::new(axum_body);
                resp.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                if let Some(cc) = cache_control {
                    resp.headers_mut().insert(
                        axum::http::header::CACHE_CONTROL,
                        axum::http::HeaderValue::from_static(cc),
                    );
                }
                resp
            }
        };
        let app = axum::Router::new().route("/doc", axum::routing::get(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (Url::parse(&format!("http://{addr}/doc")).unwrap(), hits)
    }

    #[tokio::test]
    async fn oversized_doc_rejected() {
        let (url, _hits) = serve_fixture(
            vec![b'a'; DOC_LIMIT_BYTES + 1024],
            true,
            Duration::ZERO,
            None,
        )
        .await;
        let (fresh, stale) = (new_cache(), new_cache());
        let err = fetch_with(&fresh, &stale, &url, true, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, CimdFetchError::TooLarge), "got: {err}");
    }

    #[tokio::test]
    async fn slow_doc_times_out() {
        let (url, _hits) = serve_fixture(doc_json(), false, Duration::from_secs(2), None).await;
        let (fresh, stale) = (new_cache(), new_cache());
        let err = fetch_with(&fresh, &stale, &url, true, Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(matches!(err, CimdFetchError::Transport(_)), "got: {err}");
    }

    #[tokio::test]
    async fn cache_hit_skips_second_fetch() {
        let (url, hits) = serve_fixture(doc_json(), false, Duration::ZERO, None).await;
        let (fresh, stale) = (new_cache(), new_cache());
        let first = fetch_with(&fresh, &stale, &url, true, Duration::from_secs(5))
            .await
            .unwrap();
        let second = fetch_with(&fresh, &stale, &url, true, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(first.client_id, "https://client.example/doc");
        assert_eq!(first.raw_hash, second.raw_hash);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_calls_coalesce_to_one_fetch() {
        let (url, hits) = serve_fixture(doc_json(), false, Duration::from_millis(100), None).await;
        let (fresh, stale) = (new_cache(), new_cache());
        let results = futures_util::future::join_all(
            (0..5).map(|_| fetch_with(&fresh, &stale, &url, true, Duration::from_secs(5))),
        )
        .await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn private_target_rejected_when_disallowed() {
        let (fresh, stale) = (new_cache(), new_cache());
        for raw in [
            "https://127.0.0.1:9/doc",
            "https://localhost/doc",
            "https://[::1]/doc",
        ] {
            let url = Url::parse(raw).unwrap();
            let err = fetch_with(&fresh, &stale, &url, false, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert!(
                matches!(err, CimdFetchError::UrlRejected(_)),
                "{raw} got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn http_url_rejected_when_disallowed() {
        let (fresh, stale) = (new_cache(), new_cache());
        let url = Url::parse("http://client.example/doc").unwrap();
        let err = fetch_with(&fresh, &stale, &url, false, Duration::from_secs(1))
            .await
            .unwrap_err();
        match err {
            CimdFetchError::UrlRejected(m) => assert!(m.contains("https"), "got: {m}"),
            other => panic!("expected UrlRejected, got: {other}"),
        }
    }

    #[test]
    fn guard_rejects_shape_violations() {
        let long = format!("https://client.example/{}", "a".repeat(600));
        for raw in [
            long.as_str(),
            "https://user:pass@client.example/doc",
            "https://user@client.example/doc",
            "https://client.example/doc#frag",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(guard_url(&url, true).is_err(), "should reject: {raw}");
        }
        let ok = Url::parse("https://client.example/doc?v=1").unwrap();
        assert!(guard_url(&ok, false).is_ok());
    }

    #[test]
    fn ttl_from_cache_control_clamps_and_defaults() {
        assert_eq!(ttl_from_cache_control(None), Duration::from_secs(300));
        assert_eq!(
            ttl_from_cache_control(Some("public, max-age=600")),
            Duration::from_secs(600)
        );
        assert_eq!(
            ttl_from_cache_control(Some("max-age=5")),
            Duration::from_secs(60)
        );
        assert_eq!(
            ttl_from_cache_control(Some("Max-Age=999999999")),
            Duration::from_secs(24 * 60 * 60)
        );
        assert_eq!(
            ttl_from_cache_control(Some("no-store")),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn parse_document_applies_rfc7591_defaults() {
        let doc = parse_document(&doc_json()).unwrap();
        assert_eq!(doc.grant_types, vec!["authorization_code"]);
        assert_eq!(doc.response_types, vec!["code"]);
        assert_eq!(doc.token_endpoint_auth_method, "none");
        assert_eq!(
            doc.raw_hash,
            <[u8; 32]>::from(sha2::Sha256::digest(doc_json()))
        );
        assert!(parse_document(b"[]").is_err());
        assert!(parse_document(b"{\"redirect_uris\":[]}").is_err());
    }
}
