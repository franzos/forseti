//! Upstream sign-in providers from `[[identity.oidc_providers]]`: authorization URLs and code
//! exchange for generic OIDC (discovery, confidential client, ID token) and GitHub (OAuth2 plus
//! the REST API). Upstream tokens are used for the exchange and dropped.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderName, USER_AGENT};
use serde::Deserialize;
use url::Url;

use super::store;
use crate::config::{OidcProviderConfig, OidcProviderKind, Redacted};
use crate::oidc_rp::discovery::{self, ClientAuth, Jwks, Provider};
use crate::oidc_rp::{self, AuthorizeRequest, id_token};
use crate::outbound::{self, FetchError};

/// Most `[[identity.oidc_providers]]` entries accepted.
const MAX_PROVIDERS: usize = 16;
const DISCOVERY_TTL: Duration = Duration::from_secs(60 * 60);
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);
/// Least time between two JWKS fetches forced by an unknown signing key.
const FORCED_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// How long a stale copy is served before the next refresh attempt.
const STALE_RETRY: Duration = Duration::from_secs(60);
/// RFC 5321 path limit; a longer address cannot be mailed.
const EMAIL_MAX_CHARS: usize = 254;
const BODY_LIMIT: usize = 64 * 1024;
const OIDC_SCOPES: &[&str] = &["openid", "email", "profile"];
const GITHUB_SCOPES: &[&str] = &["read:user", "user:email"];
const GITHUB_API_VERSION: &str = "2022-11-28";
/// Kratos's redirect URI shape, so an install moving from the Ory build re-registers only the host.
pub(crate) const CALLBACK_PATH: &str = "/self-service/methods/oidc/callback/";
const REAUTHENTICATE: &[(&str, &str)] = &[("max_age", "0")];
const NO_MATCHING_KEY: &str = "no matching signing key";

/// HMAC key the PKCE verifier and nonce are derived from, per `state`.
pub(super) struct PkceKey(pub(super) [u8; 32]);

impl std::fmt::Debug for PkceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PkceKey(..)")
    }
}

/// GitHub endpoints; tests point them at a stub.
#[derive(Debug, Clone)]
pub(crate) struct GithubUrls {
    pub authorize: Url,
    pub token: Url,
    pub user: Url,
    pub emails: Url,
}

impl Default for GithubUrls {
    fn default() -> Self {
        let url = |raw: &str| Url::parse(raw).expect("static GitHub URL");
        Self {
            authorize: url("https://github.com/login/oauth/authorize"),
            token: url("https://github.com/login/oauth/access_token"),
            user: url("https://api.github.com/user"),
            emails: url("https://api.github.com/user/emails"),
        }
    }
}

/// What a provider asserted about the account that signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamUser {
    /// OIDC `sub`, or the decimal GitHub account id.
    pub subject: String,
    /// Present only when the provider asserts it verified and the store can mail it.
    pub email: Option<String>,
    pub first: Option<String>,
    pub last: Option<String>,
    /// OIDC `auth_time` in unix seconds; GitHub never sets it.
    pub auth_time: Option<i64>,
}

/// The configured providers, in config order, with per-provider discovery and JWKS caches.
pub(crate) struct Upstream {
    providers: Vec<Configured>,
    allow_private: bool,
    github: GithubUrls,
}

struct Configured {
    id: String,
    client_id: String,
    secret: Redacted,
    scope: String,
    redirect_uri: String,
    source: Source,
}

enum Source {
    Oidc(OidcSource),
    Github,
}

struct OidcSource {
    issuer: String,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    provider: Option<Cached<Provider>>,
    jwks: Option<CachedJwks>,
    next_forced_refresh: Option<Instant>,
}

struct Cached<T> {
    value: Arc<T>,
    expires: Instant,
}

struct CachedJwks {
    uri: Url,
    entry: Cached<Jwks>,
}

impl Upstream {
    /// Validate `providers` and resolve their secrets from config or the environment. No
    /// network I/O; `self_url` is `[self].url`.
    pub(crate) fn from_config(
        providers: &[OidcProviderConfig],
        self_url: &str,
        allow_private: bool,
    ) -> Result<Self, String> {
        Self::build(providers, self_url, allow_private, &|name| {
            std::env::var(name).ok()
        })
    }

    fn build(
        providers: &[OidcProviderConfig],
        self_url: &str,
        allow_private: bool,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        if providers.len() > MAX_PROVIDERS {
            return Err(format!(
                "[[identity.oidc_providers]] lists {} providers; at most {MAX_PROVIDERS} are supported.",
                providers.len()
            ));
        }
        let self_url = self_url.trim_end_matches('/');
        let mut seen = HashSet::new();
        let mut configured = Vec::with_capacity(providers.len());
        for p in providers {
            let err = |msg: &str| format!("[[identity.oidc_providers]] id {:?}: {msg}", p.id);
            if crate::auth::idp_hint::parse(&p.id).is_none() {
                return Err(err(
                    "the id must be 1 to 64 characters of A-Z, a-z, 0-9, '.', '_' or '-'.",
                ));
            }
            if !seen.insert(p.id.to_ascii_lowercase()) {
                return Err(err("the id is used twice; ids compare case-insensitively."));
            }
            if p.client_id.trim().is_empty() {
                return Err(err("client_id must not be empty."));
            }
            let secret = resolve_secret(p, env).map_err(|m| err(&m))?;
            let scopes: Vec<String> = match (&p.scopes, p.kind) {
                (Some(s), _) => s.clone(),
                (None, OidcProviderKind::Oidc) => OIDC_SCOPES.iter().map(|s| (*s).into()).collect(),
                (None, OidcProviderKind::Github) => {
                    GITHUB_SCOPES.iter().map(|s| (*s).into()).collect()
                }
            };
            if scopes.is_empty() || !scopes.iter().all(|s| is_scope_token(s)) {
                return Err(err(
                    "scopes must be a non-empty list of scope tokens without spaces or quotes.",
                ));
            }
            let source = match p.kind {
                OidcProviderKind::Oidc => {
                    let issuer = p
                        .issuer
                        .as_deref()
                        .ok_or_else(|| err("kind = \"oidc\" needs an issuer."))?;
                    let url = Url::parse(issuer).map_err(|_| err("issuer is not a URL."))?;
                    outbound::check_target(&url, allow_private)
                        .map_err(|m| err(&format!("issuer URL {m}.")))?;
                    if url.query().is_some() || url.fragment().is_some() {
                        return Err(err("issuer must not have a query or fragment."));
                    }
                    if !scopes.iter().any(|s| s == "openid") {
                        return Err(err("scopes must include openid."));
                    }
                    Source::Oidc(OidcSource {
                        issuer: issuer.to_string(),
                        cache: Mutex::default(),
                    })
                }
                OidcProviderKind::Github => {
                    if p.issuer.is_some() {
                        return Err(err("kind = \"github\" takes no issuer."));
                    }
                    Source::Github
                }
            };
            configured.push(Configured {
                id: p.id.clone(),
                client_id: p.client_id.clone(),
                secret,
                scope: scopes.join(" "),
                redirect_uri: format!("{self_url}{CALLBACK_PATH}{}", p.id),
                source,
            });
        }
        Ok(Self {
            providers: configured,
            allow_private,
            github: GithubUrls::default(),
        })
    }

    #[cfg(test)]
    pub(super) fn with_github_urls(mut self, urls: GithubUrls) -> Self {
        self.github = urls;
        self
    }

    fn get(&self, id: &str) -> Result<&Configured, &'static str> {
        self.providers
            .iter()
            .find(|p| p.id == id)
            .ok_or("provider is not configured")
    }

    /// Configured provider ids, in config order.
    pub(super) fn ids(&self) -> impl Iterator<Item = &str> {
        self.providers.iter().map(|p| p.id.as_str())
    }

    pub(super) fn kind(&self, id: &str) -> Option<OidcProviderKind> {
        self.get(id).ok().map(|p| match p.source {
            Source::Oidc(_) => OidcProviderKind::Oidc,
            Source::Github => OidcProviderKind::Github,
        })
    }

    /// Whether a refresh may go through the provider: only an `oidc` one can be asked for a fresh
    /// login and report its time; GitHub has neither `max_age` nor `auth_time`.
    pub(super) fn can_reauthenticate(&self, id: &str) -> bool {
        self.kind(id) == Some(OidcProviderKind::Oidc)
    }

    /// The configured issuer of an `oidc` provider, for the RFC 9207 `iss` check.
    pub(super) fn issuer(&self, id: &str) -> Option<&str> {
        match &self.get(id).ok()?.source {
            Source::Oidc(src) => Some(&src.issuer),
            Source::Github => None,
        }
    }

    /// Whether the provider advertises `authorization_response_iss_parameter_supported`, so a
    /// callback without `iss` is refused (RFC 9207 2.4). Reads the cached discovery document.
    pub(super) async fn requires_iss(&self, id: &str) -> Result<bool, &'static str> {
        match &self.get(id)?.source {
            Source::Oidc(src) => Ok(src
                .provider(self.allow_private)
                .await?
                .authorization_response_iss_parameter_supported),
            Source::Github => Ok(false),
        }
    }

    /// The authorization request for `state`, PKCE and nonce derived from it under `key`.
    /// `reauthenticate` asks an `oidc` provider for a fresh login (`max_age=0`); GitHub has no
    /// equivalent and ignores it.
    pub(super) async fn authorize_url(
        &self,
        id: &str,
        state: &str,
        key: &PkceKey,
        reauthenticate: bool,
    ) -> Result<Url, &'static str> {
        let p = self.get(id)?;
        let pkce = oidc_rp::derive_pkce(&key.0, state);
        let mut req = AuthorizeRequest {
            client_id: &p.client_id,
            redirect_uri: &p.redirect_uri,
            state,
            nonce: None,
            code_challenge: &pkce.challenge,
            scope: &p.scope,
            extra: &[],
        };
        match &p.source {
            Source::Oidc(src) => {
                let provider = src.provider(self.allow_private).await?;
                let nonce = oidc_rp::derive_nonce(&key.0, state);
                req.nonce = Some(&nonce);
                if reauthenticate {
                    req.extra = REAUTHENTICATE;
                }
                Ok(oidc_rp::authorize_url_for(
                    &provider.authorization_endpoint,
                    &req,
                ))
            }
            Source::Github => Ok(oidc_rp::authorize_url_for(&self.github.authorize, &req)),
        }
    }

    /// Redeem `code` from the callback for `state` and read the account it proves.
    pub(super) async fn exchange(
        &self,
        id: &str,
        code: &str,
        state: &str,
        key: &PkceKey,
    ) -> Result<UpstreamUser, &'static str> {
        let p = self.get(id)?;
        let verifier = oidc_rp::derive_pkce(&key.0, state).verifier;
        match &p.source {
            Source::Oidc(src) => {
                let nonce = oidc_rp::derive_nonce(&key.0, state);
                self.exchange_oidc(p, src, code, &verifier, &nonce).await
            }
            Source::Github => self.exchange_github(p, code, &verifier).await,
        }
    }

    async fn exchange_oidc(
        &self,
        p: &Configured,
        src: &OidcSource,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<UpstreamUser, &'static str> {
        let provider = src.provider(self.allow_private).await?;
        let id_token = discovery::exchange_code_with(
            &provider,
            &p.client_id,
            ClientAuth::for_provider(&provider, &p.secret),
            &p.redirect_uri,
            code,
            verifier,
            self.allow_private,
        )
        .await?;
        let now = chrono::Utc::now().timestamp();
        let verify = |jwks: &Jwks| {
            id_token::verify_claims(&id_token, jwks, &provider.issuer, &p.client_id, nonce, now)
        };
        let jwks = src.jwks(&provider, self.allow_private, false).await?;
        let claims = match verify(&jwks) {
            Err(NO_MATCHING_KEY) if src.take_forced_refresh() => {
                verify(&*src.jwks(&provider, self.allow_private, true).await?)
            }
            other => other,
        }?;
        let email = if claims.email_verified {
            claims.email.filter(|e| mailable(e))
        } else {
            None
        };
        Ok(UpstreamUser {
            subject: claims.sub,
            email,
            first: claims.given_name,
            last: claims.family_name,
            auth_time: claims.auth_time,
        })
    }

    async fn exchange_github(
        &self,
        p: &Configured,
        code: &str,
        verifier: &str,
    ) -> Result<UpstreamUser, &'static str> {
        let token = self.github_token(p, code, verifier).await?;
        let bearer = Redacted(format!("Bearer {}", &*token));
        let user: GithubUser = self.github_get(&self.github.user, &bearer).await?;
        let emails: Vec<GithubEmail> = self.github_get(&self.github.emails, &bearer).await?;
        let email = emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .map(|e| e.email)
            .filter(|e| mailable(e));
        let (first, last) = split_name(user.name.as_deref());
        Ok(UpstreamUser {
            subject: user.id.to_string(),
            email,
            first,
            last,
            auth_time: None,
        })
    }

    /// GitHub reports token errors with HTTP 200, so the answer must carry `access_token`.
    async fn github_token(
        &self,
        p: &Configured,
        code: &str,
        verifier: &str,
    ) -> Result<Redacted, &'static str> {
        #[derive(Deserialize)]
        struct TokenResponse {
            #[serde(default)]
            access_token: Option<String>,
        }
        let url = &self.github.token;
        outbound::check_target(url, self.allow_private).map_err(|_| "upstream URL not allowed")?;
        let form = [
            ("client_id", p.client_id.as_str()),
            ("client_secret", &*p.secret),
            ("code", code),
            ("redirect_uri", p.redirect_uri.as_str()),
            ("code_verifier", verifier),
        ];
        let (status, body) = outbound::post_form(
            outbound::client(self.allow_private),
            url.as_str(),
            &form,
            &[(USER_AGENT, "forseti")],
            discovery::TIMEOUT,
            BODY_LIMIT,
        )
        .await
        .map_err(|e| fetch_reason(url, e))?;
        if !(200..300).contains(&status) {
            return Err("token endpoint refused the code");
        }
        match serde_json::from_slice::<TokenResponse>(&body) {
            Ok(TokenResponse {
                access_token: Some(t),
            }) if !t.is_empty() => Ok(Redacted(t)),
            _ => Err("token endpoint refused the code"),
        }
    }

    async fn github_get<T: serde::de::DeserializeOwned>(
        &self,
        url: &Url,
        bearer: &Redacted,
    ) -> Result<T, &'static str> {
        outbound::check_target(url, self.allow_private).map_err(|_| "upstream URL not allowed")?;
        let headers = [
            (USER_AGENT, "forseti"),
            (AUTHORIZATION, &**bearer),
            (ACCEPT, "application/vnd.github+json"),
            (
                HeaderName::from_static("x-github-api-version"),
                GITHUB_API_VERSION,
            ),
        ];
        let resp = outbound::get_ok_with(
            outbound::client(self.allow_private),
            url.as_str(),
            &headers,
            discovery::TIMEOUT,
        )
        .await
        .map_err(|e| fetch_reason(url, e))?;
        let body = outbound::read_capped(resp, BODY_LIMIT)
            .await
            .map_err(|e| fetch_reason(url, e))?;
        serde_json::from_slice(&body).map_err(|_| "GitHub API response is malformed")
    }
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

impl OidcSource {
    /// The discovery document, cached for [`DISCOVERY_TTL`]; an expired copy is served for
    /// [`STALE_RETRY`] when the refresh fails.
    async fn provider(&self, allow_private: bool) -> Result<Arc<Provider>, &'static str> {
        let now = Instant::now();
        let cached = self
            .lock()
            .provider
            .as_ref()
            .map(|c| (c.value.clone(), c.expires > now));
        if let Some((provider, true)) = &cached {
            return Ok(provider.clone());
        }
        match discovery::discover_configured(&self.issuer, allow_private).await {
            Ok(provider) => {
                let provider = Arc::new(provider);
                self.lock().provider = Some(Cached {
                    value: provider.clone(),
                    expires: Instant::now() + DISCOVERY_TTL,
                });
                Ok(provider)
            }
            Err(e) => match cached {
                Some((provider, _)) => {
                    if let Some(c) = self.lock().provider.as_mut() {
                        c.expires = Instant::now() + STALE_RETRY;
                    }
                    tracing::warn!(issuer = %self.issuer, error = e, "upstream: serving stale discovery document");
                    Ok(provider)
                }
                None => Err(e),
            },
        }
    }

    /// The key set at `provider.jwks_uri`, cached for [`JWKS_TTL`] unless `force`; an older copy
    /// is served when the refresh fails.
    async fn jwks(
        &self,
        provider: &Provider,
        allow_private: bool,
        force: bool,
    ) -> Result<Arc<Jwks>, &'static str> {
        let now = Instant::now();
        let cached = self
            .lock()
            .jwks
            .as_ref()
            .filter(|c| c.uri == provider.jwks_uri)
            .map(|c| (c.entry.value.clone(), c.entry.expires > now));
        if let Some((jwks, true)) = &cached
            && !force
        {
            return Ok(jwks.clone());
        }
        match discovery::fetch_jwks(&provider.jwks_uri, allow_private).await {
            Ok(jwks) => {
                let jwks = Arc::new(jwks);
                self.lock().jwks = Some(CachedJwks {
                    uri: provider.jwks_uri.clone(),
                    entry: Cached {
                        value: jwks.clone(),
                        expires: Instant::now() + JWKS_TTL,
                    },
                });
                Ok(jwks)
            }
            Err(e) => match cached {
                Some((jwks, _)) => {
                    if let Some(c) = self.lock().jwks.as_mut() {
                        c.entry.expires = Instant::now() + STALE_RETRY;
                    }
                    tracing::warn!(issuer = %self.issuer, error = e, "upstream: serving stale JWKS");
                    Ok(jwks)
                }
                None => Err(e),
            },
        }
    }

    /// Whether an unknown signing key may force a JWKS fetch now; at most one per
    /// [`FORCED_REFRESH_INTERVAL`].
    fn take_forced_refresh(&self) -> bool {
        let now = Instant::now();
        let mut cache = self.lock();
        if cache.next_forced_refresh.is_some_and(|t| t > now) {
            return false;
        }
        cache.next_forced_refresh = Some(now + FORCED_REFRESH_INTERVAL);
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn expire(&self) {
        let now = Instant::now();
        let mut cache = self.lock();
        if let Some(c) = cache.provider.as_mut() {
            c.expires = now;
        }
        if let Some(c) = cache.jwks.as_mut() {
            c.entry.expires = now;
        }
    }
}

fn resolve_secret(
    p: &OidcProviderConfig,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Redacted, String> {
    match (&p.client_secret, p.client_secret_env.as_deref()) {
        (Some(_), Some(_)) => Err("set client_secret or client_secret_env, not both.".into()),
        (None, None) => Err("set client_secret or client_secret_env.".into()),
        (Some(secret), None) if secret.trim().is_empty() => {
            Err("client_secret must not be empty.".into())
        }
        (Some(secret), None) => Ok(secret.clone()),
        (None, Some(name)) => match env(name) {
            Some(secret) if !secret.trim().is_empty() => Ok(Redacted(secret)),
            _ => Err(format!(
                "client_secret_env names {name:?}, which is unset or empty."
            )),
        },
    }
}

/// RFC 6749 3.3 `scope-token`: one or more of `%x21 / %x23-5B / %x5D-7E`.
fn is_scope_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

fn mailable(email: &str) -> bool {
    email.chars().count() <= EMAIL_MAX_CHARS && store::is_mailable(email)
}

/// GitHub's single `name`, split at the first space.
fn split_name(name: Option<&str>) -> (Option<String>, Option<String>) {
    let part = |s: &str| Some(s.trim()).filter(|s| !s.is_empty()).map(str::to_string);
    match name.map(str::trim) {
        None | Some("") => (None, None),
        Some(name) => match name.split_once(' ') {
            Some((first, last)) => (part(first), part(last)),
            None => (part(name), None),
        },
    }
}

fn fetch_reason(url: &Url, e: FetchError) -> &'static str {
    match e {
        FetchError::Transport(m) => {
            tracing::warn!(url = %url, error = %m, "upstream: request failed");
            "upstream request failed"
        }
        FetchError::Status(_) => "upstream returned an error status",
        FetchError::TooLarge => "upstream response too large",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::test_support::{
        GithubAccount, GithubAddress, GithubStub, OidcStub, StubKey, upstream,
    };
    use super::*;

    const KEY: PkceKey = PkceKey([9; 32]);
    const STATE: &str = "state-1";
    const CALLBACK: &str = "http://localhost:3000/self-service/methods/oidc/callback/";

    fn cfg(id: &str, kind: OidcProviderKind) -> OidcProviderConfig {
        OidcProviderConfig {
            id: id.into(),
            kind,
            issuer: (kind == OidcProviderKind::Oidc).then(|| "https://id.example.com".into()),
            client_id: "forseti".into(),
            client_secret: Some("s3cret-value".into()),
            client_secret_env: None,
            scopes: None,
        }
    }

    fn check(providers: &[OidcProviderConfig], allow_private: bool) -> Result<Upstream, String> {
        let env = |name: &str| match name {
            "GH_SECRET" => Some("env-s3cret".to_string()),
            "BLANK" => Some("  ".to_string()),
            _ => None,
        };
        Upstream::build(providers, "https://id.example.com/", allow_private, &env)
    }

    fn query(url: &Url) -> Vec<(String, String)> {
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn param(url: &Url, name: &str) -> Option<String> {
        query(url)
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }

    fn source<'a>(u: &'a Upstream, id: &str) -> &'a OidcSource {
        match &u.get(id).unwrap().source {
            Source::Oidc(src) => src,
            Source::Github => panic!("{id} is GitHub"),
        }
    }

    #[test]
    fn validation_table() {
        let oidc = || cfg("google", OidcProviderKind::Oidc);
        let github = || cfg("github", OidcProviderKind::Github);
        let with = |f: &dyn Fn(&mut OidcProviderConfig)| {
            let mut c = oidc();
            f(&mut c);
            c
        };
        let cases: Vec<(&str, Vec<OidcProviderConfig>, bool, Option<&str>)> = vec![
            ("defaults", vec![oidc(), github()], false, None),
            ("none", vec![], false, None),
            (
                "too many",
                (0..17)
                    .map(|i| cfg(&format!("p{i}"), OidcProviderKind::Github))
                    .collect(),
                false,
                Some("at most 16"),
            ),
            (
                "sixteen",
                (0..16)
                    .map(|i| cfg(&format!("p{i}"), OidcProviderKind::Github))
                    .collect(),
                false,
                None,
            ),
            (
                "colon in id",
                vec![with(&|c| c.id = "a:b".into())],
                false,
                Some("the id must be"),
            ),
            (
                "empty id",
                vec![with(&|c| c.id = String::new())],
                false,
                Some("the id must be"),
            ),
            (
                "duplicate id",
                vec![oidc(), with(&|c| c.id = "Google".into())],
                false,
                Some("used twice"),
            ),
            (
                "empty client_id",
                vec![with(&|c| c.client_id = " ".into())],
                false,
                Some("client_id"),
            ),
            (
                "both secrets",
                vec![with(&|c| c.client_secret_env = Some("GH_SECRET".into()))],
                false,
                Some("not both"),
            ),
            (
                "no secret",
                vec![with(&|c| c.client_secret = None)],
                false,
                Some("set client_secret or client_secret_env."),
            ),
            (
                "empty secret",
                vec![with(&|c| c.client_secret = Some(String::new().into()))],
                false,
                Some("must not be empty"),
            ),
            (
                "secret from env",
                vec![with(&|c| {
                    c.client_secret = None;
                    c.client_secret_env = Some("GH_SECRET".into());
                })],
                false,
                None,
            ),
            (
                "env unset",
                vec![with(&|c| {
                    c.client_secret = None;
                    c.client_secret_env = Some("MISSING".into());
                })],
                false,
                Some("\"MISSING\", which is unset or empty"),
            ),
            (
                "env blank",
                vec![with(&|c| {
                    c.client_secret = None;
                    c.client_secret_env = Some("BLANK".into());
                })],
                false,
                Some("unset or empty"),
            ),
            (
                "oidc without issuer",
                vec![with(&|c| c.issuer = None)],
                false,
                Some("needs an issuer"),
            ),
            (
                "github with issuer",
                vec![{
                    let mut c = github();
                    c.issuer = Some("https://github.com".into());
                    c
                }],
                false,
                Some("takes no issuer"),
            ),
            (
                "issuer not a URL",
                vec![with(&|c| c.issuer = Some("id.example.com".into()))],
                false,
                Some("not a URL"),
            ),
            (
                "issuer http",
                vec![with(&|c| c.issuer = Some("http://id.example.com".into()))],
                false,
                Some("issuer URL must use https://"),
            ),
            (
                "issuer http with hatch",
                vec![with(&|c| {
                    c.issuer = Some("http://127.0.0.1:8092/default".into())
                })],
                true,
                None,
            ),
            (
                "issuer private IP",
                vec![with(&|c| c.issuer = Some("https://10.0.0.5/".into()))],
                false,
                Some("private or special-use"),
            ),
            (
                "issuer with query",
                vec![with(&|c| {
                    c.issuer = Some("https://id.example.com/?tenant=a".into())
                })],
                false,
                Some("query or fragment"),
            ),
            (
                "issuer with fragment",
                vec![with(&|c| {
                    c.issuer = Some("https://id.example.com/#x".into())
                })],
                false,
                Some("query or fragment"),
            ),
            (
                "scopes without openid",
                vec![with(&|c| c.scopes = Some(vec!["email".into()]))],
                false,
                Some("include openid"),
            ),
            (
                "empty scopes",
                vec![with(&|c| c.scopes = Some(vec![]))],
                false,
                Some("non-empty list"),
            ),
            (
                "scope with a space",
                vec![with(&|c| c.scopes = Some(vec!["openid email".into()]))],
                false,
                Some("non-empty list"),
            ),
            (
                "github custom scopes",
                vec![{
                    let mut c = github();
                    c.scopes = Some(vec!["user:email".into()]);
                    c
                }],
                false,
                None,
            ),
        ];
        for (name, providers, allow_private, expected) in cases {
            let got = check(&providers, allow_private);
            match (expected, got) {
                (None, Ok(_)) => {}
                (Some(want), Err(e)) => {
                    assert!(e.contains(want), "{name}: {e}");
                    assert!(!e.contains("s3cret"), "{name}: secret in {e}");
                }
                (None, Err(e)) => panic!("{name}: refused: {e}"),
                (Some(want), Ok(_)) => panic!("{name}: accepted, wanted {want}"),
            }
        }
    }

    #[test]
    fn secrets_stay_out_of_debug() {
        let mut c = cfg("google", OidcProviderKind::Oidc);
        assert!(!format!("{c:?}").contains("s3cret"));
        c.client_secret = None;
        c.client_secret_env = Some("GH_SECRET".into());
        let u = check(&[c], false).unwrap();
        assert_eq!(&*u.providers[0].secret, "env-s3cret");
        assert_eq!(format!("{:?}", u.providers[0].secret), "[redacted]");
        assert_eq!(format!("{KEY:?}"), "PkceKey(..)");
    }

    #[test]
    fn defaults_and_accessors() {
        let u = check(
            &[
                cfg("google", OidcProviderKind::Oidc),
                cfg("github", OidcProviderKind::Github),
            ],
            false,
        )
        .unwrap();
        assert_eq!(u.ids().collect::<Vec<_>>(), ["google", "github"]);
        assert_eq!(u.kind("github"), Some(OidcProviderKind::Github));
        assert_eq!(u.kind("Google"), None);
        assert_eq!(u.issuer("google"), Some("https://id.example.com"));
        assert_eq!(u.issuer("github"), None);
        assert_eq!(u.get("google").unwrap().scope, "openid email profile");
        assert_eq!(u.get("github").unwrap().scope, "read:user user:email");
        assert_eq!(
            u.get("google").unwrap().redirect_uri,
            "https://id.example.com/self-service/methods/oidc/callback/google"
        );
    }

    #[test]
    fn helpers() {
        let split = |n: Option<&str>| split_name(n);
        let some = |s: &str| Some(s.to_string());
        assert_eq!(split(Some("Ada Lovelace")), (some("Ada"), some("Lovelace")));
        assert_eq!(
            split(Some("Ada King Lovelace")),
            (some("Ada"), some("King Lovelace"))
        );
        assert_eq!(split(Some(" Ada ")), (some("Ada"), None));
        assert_eq!(split(Some("   ")), (None, None));
        assert_eq!(split(None), (None, None));
        assert!(is_scope_token("read:user"));
        assert!(!is_scope_token("a\"b"));
        assert!(!is_scope_token("a\\b"));
        assert!(!is_scope_token(""));
        let long = format!("{}@example.com", "a".repeat(254 - 12));
        assert_eq!(long.len(), 254);
        assert!(mailable(&long));
        assert!(!mailable(&format!("a{long}")));
        assert!(!mailable("Ada <ada@example.com>"));
    }

    #[tokio::test]
    async fn oidc_authorize_url() {
        let stub = OidcStub::start().await;
        let u = upstream(&[stub.provider_config("stub")], None);
        let url = u.authorize_url("stub", STATE, &KEY, false).await.unwrap();
        assert!(
            url.as_str()
                .starts_with(&format!("{}/authorize?", stub.issuer))
        );
        assert_eq!(param(&url, "scope").unwrap(), "openid email profile");
        assert_eq!(
            param(&url, "redirect_uri").unwrap(),
            format!("{CALLBACK}stub")
        );
        assert_eq!(param(&url, "state").unwrap(), STATE);
        assert_eq!(
            param(&url, "nonce").unwrap(),
            oidc_rp::derive_nonce(&KEY.0, STATE)
        );
        assert_eq!(
            param(&url, "code_challenge").unwrap(),
            oidc_rp::derive_pkce(&KEY.0, STATE).challenge
        );
        assert_eq!(param(&url, "max_age"), None);
        let url = u.authorize_url("stub", STATE, &KEY, true).await.unwrap();
        assert_eq!(param(&url, "max_age").unwrap(), "0");
        assert_eq!(stub.discovery_fetches(), 1, "discovery is cached");
        assert!(u.authorize_url("other", STATE, &KEY, false).await.is_err());
    }

    #[tokio::test]
    async fn oidc_exchange_reads_verified_profile() {
        let stub = OidcStub::start().await;
        let u = upstream(&[stub.provider_config("stub")], None);
        let url = u.authorize_url("stub", STATE, &KEY, false).await.unwrap();
        let code = stub.issue(
            &url,
            json!({
                "sub": "user-7",
                "email": "ada@example.com",
                "email_verified": true,
                "given_name": "Ada",
                "family_name": "Lovelace",
                "auth_time": 1_800_000_000,
            }),
        );
        let user = u.exchange("stub", &code, STATE, &KEY).await.unwrap();
        assert_eq!(
            user,
            UpstreamUser {
                subject: "user-7".into(),
                email: Some("ada@example.com".into()),
                first: Some("Ada".into()),
                last: Some("Lovelace".into()),
                auth_time: Some(1_800_000_000),
            }
        );
        assert_eq!(stub.client_auth(), ["basic"]);
        assert!(
            u.exchange("stub", &code, STATE, &KEY).await.is_err(),
            "a code is redeemed once"
        );
        let code = stub.issue(&url, json!({}));
        assert!(
            u.exchange("stub", &code, "other-state", &KEY)
                .await
                .is_err(),
            "verifier and nonce follow the state"
        );
    }

    #[tokio::test]
    async fn oidc_email_only_when_verified_and_mailable() {
        let stub = OidcStub::start().await;
        let u = upstream(&[stub.provider_config("stub")], None);
        let url = u.authorize_url("stub", STATE, &KEY, false).await.unwrap();
        let long = format!("{}@example.com", "a".repeat(250));
        for (claims, expected) in [
            (
                json!({"email": "a@example.com", "email_verified": "true"}),
                Some("a@example.com"),
            ),
            (
                json!({"email": "a@example.com", "email_verified": false}),
                None,
            ),
            (json!({"email": "a@example.com"}), None),
            (json!({"email_verified": true}), None),
            (json!({"email": long, "email_verified": true}), None),
            (
                json!({"email": "a<b>@example.com", "email_verified": true}),
                None,
            ),
        ] {
            let code = stub.issue(&url, claims.clone());
            let user = u.exchange("stub", &code, STATE, &KEY).await.unwrap();
            assert_eq!(user.email.as_deref(), expected, "{claims}");
        }
    }

    #[tokio::test]
    async fn oidc_post_auth_when_basic_not_advertised() {
        let stub = OidcStub::start().await;
        stub.set_auth_methods(Some(&["client_secret_post"]));
        let u = upstream(&[stub.provider_config("stub")], None);
        let url = u.authorize_url("stub", STATE, &KEY, false).await.unwrap();
        let code = stub.issue(&url, json!({}));
        assert_eq!(
            u.exchange("stub", &code, STATE, &KEY)
                .await
                .unwrap()
                .subject,
            "stub-subject"
        );
        assert_eq!(stub.client_auth(), ["post"]);
    }

    #[tokio::test]
    async fn requires_iss_follows_discovery() {
        let stub = OidcStub::start().await;
        let github = GithubStub::start().await;
        let u = upstream(
            &[stub.provider_config("stub"), github.provider_config("gh")],
            Some(&github),
        );
        assert!(!u.requires_iss("stub").await.unwrap());
        assert!(!u.requires_iss("gh").await.unwrap());
        assert_eq!(u.issuer("stub"), Some(stub.issuer.as_str()));
        let stub = OidcStub::start().await;
        stub.set_iss_parameter(true);
        let u = upstream(&[stub.provider_config("stub")], None);
        assert!(u.requires_iss("stub").await.unwrap());
    }

    #[tokio::test]
    async fn unknown_key_triggers_one_jwks_refresh() {
        let stub = OidcStub::start().await;
        let u = upstream(&[stub.provider_config("stub")], None);
        let url = u.authorize_url("stub", STATE, &KEY, false).await.unwrap();
        let sign_in = async || {
            let code = stub.issue(&url, json!({}));
            u.exchange("stub", &code, STATE, &KEY).await
        };
        sign_in().await.unwrap();
        sign_in().await.unwrap();
        assert_eq!(stub.jwks_fetches(), 1, "JWKS is cached");

        stub.rotate(StubKey::Ec);
        sign_in().await.unwrap();
        assert_eq!(stub.jwks_fetches(), 2, "one forced refresh");
        sign_in().await.unwrap();
        assert_eq!(stub.jwks_fetches(), 2);

        stub.rotate(StubKey::Rsa);
        assert_eq!(sign_in().await.unwrap_err(), NO_MATCHING_KEY);
        assert_eq!(stub.jwks_fetches(), 2, "forced refreshes are rate limited");

        source(&u, "stub").lock().next_forced_refresh = None;
        sign_in().await.unwrap();
        assert_eq!(stub.jwks_fetches(), 3);
    }

    #[tokio::test]
    async fn stale_caches_served_when_refresh_fails() {
        let stub = OidcStub::start().await;
        let u = upstream(&[stub.provider_config("stub")], None);
        let url = u.authorize_url("stub", STATE, &KEY, false).await.unwrap();
        let code = stub.issue(&url, json!({}));
        u.exchange("stub", &code, STATE, &KEY).await.unwrap();

        stub.set_discovery_failing(true);
        stub.set_jwks_failing(true);
        source(&u, "stub").expire();
        let url = u.authorize_url("stub", STATE, &KEY, false).await.unwrap();
        let code = stub.issue(&url, json!({}));
        u.exchange("stub", &code, STATE, &KEY).await.unwrap();
        assert_eq!(
            stub.discovery_fetches(),
            2,
            "one failed refresh, then the stale copy"
        );
        assert_eq!(stub.jwks_fetches(), 2);

        let fresh = upstream(&[stub.provider_config("stub")], None);
        assert!(
            fresh
                .authorize_url("stub", STATE, &KEY, false)
                .await
                .is_err()
        );
        stub.set_discovery_failing(false);
        let url = fresh
            .authorize_url("stub", STATE, &KEY, false)
            .await
            .unwrap();
        let code = stub.issue(&url, json!({}));
        assert!(
            fresh.exchange("stub", &code, STATE, &KEY).await.is_err(),
            "no JWKS to fall back on"
        );
    }

    fn address(email: &str, primary: bool, verified: bool) -> GithubAddress {
        GithubAddress {
            email: email.into(),
            primary,
            verified,
        }
    }

    async fn github_sign_in(
        account: GithubAccount,
    ) -> (GithubStub, Result<UpstreamUser, &'static str>) {
        let stub = GithubStub::start().await;
        let u = upstream(&[stub.provider_config("github")], Some(&stub));
        let url = u.authorize_url("github", STATE, &KEY, true).await.unwrap();
        let code = stub.issue(&url, account);
        let user = u.exchange("github", &code, STATE, &KEY).await;
        (stub, user)
    }

    #[tokio::test]
    async fn github_authorize_url() {
        let stub = GithubStub::start().await;
        let u = upstream(&[stub.provider_config("github")], Some(&stub));
        let url = u.authorize_url("github", STATE, &KEY, true).await.unwrap();
        assert_eq!(url.path(), "/login/oauth/authorize");
        assert_eq!(param(&url, "scope").unwrap(), "read:user user:email");
        assert_eq!(
            param(&url, "redirect_uri").unwrap(),
            format!("{CALLBACK}github")
        );
        assert_eq!(param(&url, "nonce"), None);
        assert_eq!(param(&url, "max_age"), None);
        assert_eq!(param(&url, "code_challenge_method").unwrap(), "S256");
    }

    #[tokio::test]
    async fn github_primary_verified_address_and_name_split() {
        let (stub, user) = github_sign_in(GithubAccount {
            id: 583_231,
            name: Some("Ada King Lovelace".into()),
            emails: vec![
                address("old@example.com", false, true),
                address("ada@example.com", true, true),
            ],
        })
        .await;
        assert_eq!(
            user.unwrap(),
            UpstreamUser {
                subject: "583231".into(),
                email: Some("ada@example.com".into()),
                first: Some("Ada".into()),
                last: Some("King Lovelace".into()),
                auth_time: None,
            }
        );
        assert_eq!(stub.refused_without_agent(), 0);
    }

    #[tokio::test]
    async fn github_without_verified_primary_has_no_address() {
        let (_, user) = github_sign_in(GithubAccount {
            id: 1,
            name: None,
            emails: vec![
                address("ada@example.com", true, false),
                address("other@example.com", false, true),
            ],
        })
        .await;
        let user = user.unwrap();
        assert_eq!(user.email, None);
        assert_eq!((user.first, user.last), (None, None));
    }

    #[tokio::test]
    async fn github_token_error_with_200_is_refused() {
        let stub = GithubStub::start().await;
        let u = upstream(&[stub.provider_config("github")], Some(&stub));
        assert_eq!(
            u.exchange("github", "not-a-code", STATE, &KEY)
                .await
                .unwrap_err(),
            "token endpoint refused the code"
        );
        let url = u.authorize_url("github", STATE, &KEY, false).await.unwrap();
        let code = stub.issue(
            &url,
            GithubAccount {
                id: 1,
                name: None,
                emails: vec![],
            },
        );
        assert!(
            u.exchange("github", &code, "other-state", &KEY)
                .await
                .is_err(),
            "verifier follows the state"
        );
    }

    #[tokio::test]
    async fn github_stub_refuses_missing_user_agent() {
        let stub = GithubStub::start().await;
        let resp = outbound::client(true)
            .get(stub.urls().user.as_str())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
        assert_eq!(stub.refused_without_agent(), 1);
    }
}
