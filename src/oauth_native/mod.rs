//! Native OAuth2/OIDC authorization server: client registrations, signing keys, discovery, the
//! JWKS, the authorization endpoint with its login and consent challenges, OP login sessions,
//! consent grants, the token endpoint, revocation, introspection, userinfo and the device
//! authorization grant, RP-initiated logout and back-channel logout.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use arc_swap::ArcSwapOption;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::seal::SealKey;
use crate::signed_cookie::derive_subkey;

mod authorize;
mod backend;
mod challenge;
pub(crate) mod clients;
mod device;
mod discovery;
mod grants;
mod jwt;
mod keys;
mod logout;
pub(crate) mod maintenance;
mod response;
mod revocation;
pub(crate) mod routes;
mod sessions;
#[cfg(test)]
mod test_support;
mod token_endpoint;
mod tokens;
mod userinfo;

pub(crate) use device::normalize_user_code;

/// HKDF label of the key that seals private signing keys at rest.
const SEAL_LABEL: &[u8] = b"forseti::oauth::seal::v1";

/// Lifetime of an authorization code.
pub(crate) const CODE_TTL_SECS: i64 = 600;
/// Token lifetimes, as `infra/hydra/hydra.yml` sets them for the Ory build.
pub(crate) const ACCESS_TOKEN_TTL_SECS: i64 = 300;
pub(crate) const ID_TOKEN_TTL_SECS: i64 = 3600;
/// Counted from each rotation.
pub(crate) const REFRESH_TOKEN_TTL_SECS: i64 = 720 * 60 * 60;
/// Time an authorization request has from authorize to the code.
pub(crate) const FLOW_TTL_SECS: i64 = 30 * 60;
/// Longest remembered login; `remember_for = 0` asks for it.
pub(crate) const REMEMBER_CAP_SECS: i64 = 30 * 24 * 60 * 60;
/// Shortest gap between two key reloads; bounds what unknown `kid`s and JWKS requests can cost.
const KEY_RELOAD_INTERVAL: Duration = Duration::from_secs(2);
/// How long shutdown and the session-ending CLI verbs wait for back-channel logout deliveries:
/// one delivery's timeout plus slack.
pub(crate) const DELIVERY_DRAIN: Duration = Duration::from_secs(5);

pub struct NativeOAuth {
    db: DbPool,
    /// Operator cookie secret; signing and sealing keys derive from it.
    cookie_secret: Box<[u8]>,
    /// `[self].url` without a trailing slash.
    issuer: String,
    seal: Arc<SealKey>,
    keys: Arc<ArcSwapOption<keys::KeySet>>,
    /// When the last reload finished; held for the whole reload.
    last_reload: Arc<Mutex<Option<Instant>>>,
    #[cfg(test)]
    key_loads: Arc<std::sync::atomic::AtomicUsize>,
    /// Bounds concurrent Argon2 runs on client secrets.
    hash_permits: Arc<Semaphore>,
    /// `[oauth.cimd].allow_private_targets`, which back-channel logout delivery shares.
    allow_private_targets: bool,
    /// Back-channel logout deliveries in flight; finished ones are reaped on the next spawn.
    deliveries: std::sync::Mutex<JoinSet<()>>,
}

impl NativeOAuth {
    pub fn new(cfg: &AppConfig, db: &DbPool, cookie_secret: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            db: db.clone(),
            cookie_secret: cookie_secret.into(),
            issuer: cfg.self_.url.trim_end_matches('/').to_string(),
            seal: Arc::new(SealKey::new(&derive_subkey(cookie_secret, SEAL_LABEL))),
            keys: Arc::new(ArcSwapOption::empty()),
            last_reload: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            key_loads: Arc::default(),
            hash_permits: Arc::new(Semaphore::new(
                std::thread::available_parallelism().map_or(1, usize::from),
            )),
            allow_private_targets: cfg.oauth.cimd.allow_private_targets,
            deliveries: std::sync::Mutex::new(JoinSet::new()),
        })
    }

    /// Loads the signing keys, generating the first on an empty table. Fails when a stored key
    /// does not open under the cookie secret.
    pub async fn init(&self) -> anyhow::Result<()> {
        let keys = keys::load_or_bootstrap(&self.db, &self.seal).await?;
        self.keys.store(Some(Arc::new(keys)));
        Ok(())
    }

    /// The keys as last loaded.
    pub(crate) fn keys(&self) -> anyhow::Result<Arc<keys::KeySet>> {
        self.keys
            .load_full()
            .context("OAuth signing keys are not loaded")
    }

    /// Replaces the loaded keys with the stored ones, at most once per [`KEY_RELOAD_INTERVAL`]
    /// after the previous reload finished; a call inside the interval returns at once. On error
    /// the loaded keys stay.
    pub(crate) async fn reload_keys(&self) -> anyhow::Result<()> {
        let (db, seal, store) = (self.db.clone(), self.seal.clone(), self.keys.clone());
        let last_reload = self.last_reload.clone();
        #[cfg(test)]
        let key_loads = self.key_loads.clone();
        // Spawned so a caller that goes away cannot abort a reload that already holds the lock.
        tokio::spawn(async move {
            let mut last = last_reload.lock_owned().await;
            if last.is_some_and(|t| t.elapsed() < KEY_RELOAD_INTERVAL) {
                return Ok(());
            }
            #[cfg(test)]
            key_loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let loaded = keys::load(&db, &seal).await;
            *last = Some(Instant::now());
            store.store(Some(Arc::new(loaded?)));
            Ok(())
        })
        .await
        .context("OAuth signing key reload task")?
    }

    /// [`jwt::verify`] against the loaded keys; a token whose `kid` they lack triggers one
    /// [`Self::reload_keys`] and one retry.
    pub(crate) async fn verify_jwt(
        &self,
        token: &str,
        typ: jwt::Typ,
        audience: Option<&str>,
    ) -> anyhow::Result<Value> {
        self.verify_reloading(token, |keys| {
            jwt::verify(keys, &self.issuer, token, typ, audience)
        })
        .await
    }

    /// [`jwt::verify_hint`]: an ID token this server issued, its `exp` unchecked, with the same
    /// reload as [`Self::verify_jwt`].
    pub(crate) async fn verify_hint(&self, token: &str) -> anyhow::Result<Value> {
        self.verify_reloading(token, |keys| jwt::verify_hint(keys, &self.issuer, token))
            .await
    }

    async fn verify_reloading(
        &self,
        token: &str,
        check: impl Fn(&keys::KeySet) -> anyhow::Result<Value>,
    ) -> anyhow::Result<Value> {
        let keys = self.keys()?;
        let first = check(&keys);
        if first.is_ok() || !jwt::has_unknown_kid(&keys, token) {
            return first;
        }
        if let Err(e) = self.reload_keys().await {
            tracing::warn!(error = %e, "oauth signing keys reload failed; keeping the loaded keys");
            return first;
        }
        check(&*self.keys()?)
    }

    /// Waits up to `within` for the back-channel logout deliveries in flight; the ones still
    /// running then are aborted. `false` when any was.
    pub(crate) async fn drain_deliveries(&self, within: Duration) -> bool {
        let mut set = std::mem::take(
            &mut *self
                .deliveries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let finished =
            tokio::time::timeout(within, async { while set.join_next().await.is_some() {} })
                .await
                .is_ok();
        if !finished {
            tracing::warn!(
                pending = set.len(),
                "oauth back-channel logout deliveries still running at the drain deadline"
            );
        }
        finished
    }

    /// The keys JWKS publishes: reloaded first when the stored `kid`s differ from the loaded ones.
    /// A failed listing or reload is logged and the loaded keys are served.
    pub(crate) async fn published_keys(&self) -> anyhow::Result<Arc<keys::KeySet>> {
        let loaded = self.keys()?;
        let stale = match keys::stored_kids(&self.db).await {
            Ok(mut stored) => {
                stored.sort_unstable();
                stored != loaded.kids()
            }
            Err(e) => {
                tracing::warn!(error = %e, "oauth signing key listing failed");
                false
            }
        };
        if !stale {
            return Ok(loaded);
        }
        if let Err(e) = self.reload_keys().await {
            tracing::warn!(error = %e, "oauth signing keys reload failed; keeping the loaded keys");
        }
        self.keys()
    }

    /// Accepts a consent challenge the way the consent handler reached it; an automatic accept
    /// is never a basis for consent skip.
    pub(crate) async fn accept_consent_on(
        &self,
        path: crate::oauth::consent::GrantPath,
        challenge: &str,
        grant_scope: Vec<String>,
        grant_audience: Vec<String>,
        id_token_session: Value,
        access_token_session: serde_json::Map<String, Value>,
    ) -> anyhow::Result<crate::backend::oauth::RedirectTo> {
        challenge::accept_consent(
            self,
            challenge,
            grant_scope,
            grant_audience,
            path,
            id_token_session,
            access_token_session,
        )
        .await
    }

    /// Retires the active signing key and stores a new one. Running instances sign with the new
    /// key after their next reload.
    pub(crate) async fn rotate_key(&self) -> anyhow::Result<keys::Rotated> {
        keys::rotate(&self.db, &self.seal).await
    }
}

/// 32 random bytes, base64url: a challenge, verifier or code.
fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(crate::seal::random_bytes::<32>())
}

/// The stored form of a [`random_token`].
fn token_hash(token: &str) -> String {
    crate::seal::sha256_hex(token.as_bytes())
}

fn to_json<T: serde::Serialize + ?Sized>(v: &T) -> anyhow::Result<String> {
    serde_json::to_string(v).map_err(|e| anyhow::anyhow!("encode an OAuth column: {e}"))
}

fn from_json<T: serde::de::DeserializeOwned>(raw: &str) -> anyhow::Result<T> {
    serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("decode an OAuth column: {e}"))
}

fn parse_time(raw: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| anyhow::anyhow!("decode an OAuth timestamp: {e}"))
}
