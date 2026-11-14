//! Native identity backend: identities, credentials, sessions and self-service flows in Forseti's own database.

use std::sync::Arc;

use tokio::sync::{Notify, Semaphore};

use crate::config::{AppConfig, IdentityConfig};
use crate::db::DbPool;
use crate::rate_limit::KeyedQuota;
use crate::signed_cookie::derive_subkey;
use crate::webhook::WorkerHandle;

mod backend;
mod codes;
mod errors;
mod flows;
mod lookup;
pub(crate) mod mail;
pub(crate) mod maintenance;
pub(crate) mod password;
pub(crate) mod routes;
mod seal;
pub(crate) mod seed;
mod session;
mod store;
#[cfg(test)]
mod test_support;
mod totp;
mod ui;

pub struct NativeBackend {
    db: DbPool,
    settings: IdentityConfig,
    /// `[self].url` without a trailing slash.
    self_url: String,
    /// `[self].url` is https: session cookies are `Secure` and `__Host-` prefixed.
    https: bool,
    /// Issuer shown in authenticator apps.
    totp_issuer: String,
    keys: Keys,
    limiters: Limiters,
    hash_permits: Arc<Semaphore>,
    breach_check: Option<password::BreachCheck>,
    /// Heartbeat of the mail worker, read by `/readyz`.
    mail_worker: WorkerHandle,
    /// Wakes the mail worker as soon as a row is queued.
    mail_wake: Arc<Notify>,
}

/// Keys each in-process attempt counter tracks at most; see [`KeyedQuota::bounded`] for a full map.
const LIMITER_MAX_KEYS: usize = 10_000;

/// Per-identity cap on TOTP and lookup-code attempts in [`ATTEMPT_WINDOW`].
const SECOND_FACTOR_ATTEMPTS: usize = 10;

/// Per-identity cap on email and password change attempts in [`ATTEMPT_WINDOW`].
const SETTINGS_CHANGES: usize = 10;

const ATTEMPT_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Codes mailed to one address per [`RECIPIENT_WINDOW`], verification and recovery together.
const RECIPIENT_MAILS: usize = 5;

const RECIPIENT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// In-process attempt counters; the per-IP limits are `tower_governor` layers in [`routes`].
struct Limiters {
    /// Password attempts, keyed by [`store::address_key`] of the identifier.
    password: KeyedQuota,
    /// TOTP and lookup-code attempts, keyed by identity id.
    second_factor: KeyedQuota,
    /// Email and password changes in settings, keyed by identity id.
    settings_changes: KeyedQuota,
    /// Code mail requests, keyed by [`store::address_key`] of the address typed.
    recipient: KeyedQuota,
}

impl Limiters {
    fn new(settings: &IdentityConfig) -> Self {
        let quota = |limit: usize| KeyedQuota::bounded(ATTEMPT_WINDOW, limit, LIMITER_MAX_KEYS);
        Self {
            password: quota(settings.login_identifier_rate_per_15m as usize),
            second_factor: quota(SECOND_FACTOR_ATTEMPTS),
            settings_changes: quota(SETTINGS_CHANGES),
            recipient: KeyedQuota::bounded(RECIPIENT_WINDOW, RECIPIENT_MAILS, LIMITER_MAX_KEYS),
        }
    }
}

/// Subkeys of the operator cookie secret, one per purpose.
#[derive(Debug)]
struct Keys {
    seal: seal::SealKey,
    code_mac: codes::MacKey,
    lookup_mac: codes::MacKey,
    logout: codes::MacKey,
}

impl Keys {
    fn derive(cookie_secret: &[u8]) -> Self {
        Self {
            seal: seal::SealKey::new(&derive_subkey(
                cookie_secret,
                b"forseti::identity::seal::v1",
            )),
            code_mac: codes::MacKey::new(derive_subkey(
                cookie_secret,
                b"forseti::identity::code-mac::v1",
            )),
            lookup_mac: codes::MacKey::new(derive_subkey(
                cookie_secret,
                b"forseti::identity::lookup-mac::v1",
            )),
            logout: codes::MacKey::new(derive_subkey(
                cookie_secret,
                b"forseti::identity::logout::v1",
            )),
        }
    }
}

impl NativeBackend {
    pub fn new(cfg: &AppConfig, db: &DbPool, cookie_secret: &[u8]) -> Arc<Self> {
        Arc::new(Self::build(cfg, db, cookie_secret))
    }

    fn build(cfg: &AppConfig, db: &DbPool, cookie_secret: &[u8]) -> Self {
        let hash_concurrency = std::thread::available_parallelism().map_or(1, usize::from);
        let brand = cfg.brand.name.trim();
        Self {
            db: db.clone(),
            settings: cfg.identity.clone(),
            self_url: cfg.self_.url.trim_end_matches('/').to_string(),
            https: cfg.self_.is_https(),
            totp_issuer: if brand.is_empty() { "Forseti" } else { brand }.to_string(),
            keys: Keys::derive(cookie_secret),
            limiters: Limiters::new(&cfg.identity),
            hash_permits: Arc::new(Semaphore::new(hash_concurrency)),
            breach_check: cfg
                .identity
                .password_breach_check
                .then(password::BreachCheck::new),
            mail_worker: WorkerHandle::new(),
            mail_wake: Arc::new(Notify::new()),
        }
    }

    /// Heartbeat of the mail worker.
    pub(crate) fn mail_worker(&self) -> &WorkerHandle {
        &self.mail_worker
    }

    #[cfg(test)]
    pub(crate) fn for_test(db: &DbPool) -> Arc<Self> {
        Self::new(&AppConfig::test_fixture(), db, &[0x42; 32])
    }
}

/// `N` bytes from the operating system's CSPRNG.
fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::TryRng as _;
    let mut buf = [0u8; N];
    // An OS without a working random source cannot mint keys or tokens safely; there is no fallback.
    rand::rngs::SysRng
        .try_fill_bytes(&mut buf)
        .expect("OS random source is available");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_use_their_labels_and_stay_out_of_debug() {
        let secret = [0x42; 32];
        let keys = Keys::derive(&secret);
        let sealed = keys.seal.seal("p", "b", b"x");
        let by_label = seal::SealKey::new(&derive_subkey(&secret, b"forseti::identity::seal::v1"));
        assert_eq!(by_label.open("p", "b", &sealed).as_deref(), Some(&b"x"[..]));
        let code = codes::MacKey::new(derive_subkey(&secret, b"forseti::identity::code-mac::v1"));
        let lookup =
            codes::MacKey::new(derive_subkey(&secret, b"forseti::identity::lookup-mac::v1"));
        assert_eq!(keys.code_mac.hex(&["a"]), code.hex(&["a"]));
        assert_eq!(keys.lookup_mac.hex(&["a"]), lookup.hex(&["a"]));
        let logout = codes::MacKey::new(derive_subkey(&secret, b"forseti::identity::logout::v1"));
        assert_eq!(keys.logout.hex(&["a"]), logout.hex(&["a"]));
        assert_ne!(keys.code_mac.hex(&["a"]), keys.lookup_mac.hex(&["a"]));
        assert_ne!(keys.code_mac.hex(&["a"]), keys.logout.hex(&["a"]));

        assert_eq!(
            format!("{keys:?}"),
            "Keys { seal: SealKey(..), code_mac: MacKey(..), lookup_mac: MacKey(..), logout: MacKey(..) }"
        );
    }
}
