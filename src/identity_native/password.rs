//! Password policy, Argon2id hashing off the async runtime, and the optional HaveIBeenPwned range check.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::digest;
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Lowest accepted `[identity].password_min_length`.
pub(crate) const MIN_LENGTH_FLOOR: usize = 8;
/// Longest accepted password, in characters.
pub(crate) const MAX_LENGTH: usize = 256;

// OWASP Password Storage Cheat Sheet, first Argon2id configuration.
const ARGON2_M_KIB: u32 = 19_456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

/// Verified when the account does not exist, so the response takes as long as a real verify.
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c1NSVVc4ODVMSk9RdGZJOGgxdmduZw$7NbJXi95HFEt7hF767fIYjodMRP3AW8Zzccp8Ropi7c";

/// Longest wait for a hashing permit before the request is answered as busy.
const PERMIT_WAIT: Duration = Duration::from_secs(3);

const HIBP_BASE_URL: &str = "https://api.pwnedpasswords.com";
const HIBP_TIMEOUT: Duration = Duration::from_secs(2);
// A padded range answer is about 40 KiB.
const HIBP_BODY_LIMIT: usize = 512 * 1024;

/// `identity_credentials.config` for kind `password`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct PasswordConfig {
    /// Argon2id PHC string.
    pub(super) hashed_password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PolicyError {
    TooShort {
        min_length: usize,
        actual_length: usize,
    },
    TooLong {
        max_length: usize,
        actual_length: usize,
    },
    TooSimilar,
    Breached,
}

impl PolicyError {
    /// The Kratos message id, its context, and the English text, for a flow node message.
    pub(super) fn message(&self) -> (u64, Value, String) {
        let reason = |reason: &str| {
            (
                4_000_005,
                json!({ "reason": reason }),
                format!("The password can not be used because {reason}."),
            )
        };
        match self {
            Self::TooShort {
                min_length,
                actual_length,
            } => (
                4_000_032,
                json!({ "min_length": min_length, "actual_length": actual_length }),
                format!(
                    "The password must be at least {min_length} characters long, but got {actual_length}."
                ),
            ),
            Self::TooLong { max_length, .. } => {
                reason(&format!("it is longer than {max_length} characters"))
            }
            Self::TooSimilar => reason("it is too similar to the identifier"),
            Self::Breached => {
                reason("it has been found in data breaches and must no longer be used")
            }
        }
    }
}

fn hasher() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None)
        .expect("static Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Length and identifier-similarity rules; the breach check is [`BreachCheck::is_breached`].
pub(super) fn check_policy(
    password: &str,
    email: &str,
    min_length: usize,
) -> Result<(), PolicyError> {
    let actual_length = password.chars().count();
    if actual_length < min_length {
        return Err(PolicyError::TooShort {
            min_length,
            actual_length,
        });
    }
    if actual_length > MAX_LENGTH {
        return Err(PolicyError::TooLong {
            max_length: MAX_LENGTH,
            actual_length,
        });
    }
    if too_similar(email, password) {
        return Err(PolicyError::TooSimilar);
    }
    Ok(())
}

/// Kratos's rule: Levenshtein distance under 5, or a common substring over half the password.
fn too_similar(identifier: &str, password: &str) -> bool {
    let id: Vec<char> = identifier.to_lowercase().chars().collect();
    let pw: Vec<char> = password.to_lowercase().chars().collect();
    if id.is_empty() || pw.is_empty() || id.len() > MAX_LENGTH || pw.len() > MAX_LENGTH {
        return false;
    }
    levenshtein(&id, &pw) < 5 || longest_common_substring(&id, &pw) * 2 > pw.len()
}

fn levenshtein(a: &[char], b: &[char]) -> usize {
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitute = prev[j] + usize::from(ca != cb);
            cur[j + 1] = substitute.min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

fn longest_common_substring(a: &[char], b: &[char]) -> usize {
    let mut prev = vec![0usize; b.len() + 1];
    let mut cur = vec![0usize; b.len() + 1];
    let mut best = 0;
    for ca in a {
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = if ca == cb { prev[j] + 1 } else { 0 };
            best = best.max(cur[j + 1]);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    best
}

/// Why a hash or verify did not produce an answer.
#[derive(Debug)]
pub(super) enum HashError {
    /// No permit freed up within [`PERMIT_WAIT`]; the caller answers "busy, try again".
    Busy,
    Failed(anyhow::Error),
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("password hashing is at capacity"),
            Self::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for HashError {}

/// A permit for one Argon2 run, waiting at most [`PERMIT_WAIT`]. Owned so it travels into the
/// blocking task and is released only when the hash finishes, not when the request is dropped.
async fn permit(permits: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, HashError> {
    match tokio::time::timeout(PERMIT_WAIT, permits.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(HashError::Failed(anyhow::anyhow!("hash semaphore closed"))),
        Err(_) => Err(HashError::Busy),
    }
}

fn over_length(password: &str) -> bool {
    password.chars().count() > MAX_LENGTH
}

/// Argon2id PHC string for `password`, hashed on the blocking pool once a permit is free.
pub(super) async fn hash(permits: &Arc<Semaphore>, password: String) -> Result<String, HashError> {
    if over_length(&password) {
        return Err(HashError::Failed(anyhow::anyhow!(
            "password is longer than {MAX_LENGTH} characters"
        )));
    }
    let permit = permit(permits).await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_blocking(&password).map_err(HashError::Failed)
    })
    .await
    .map_err(|e| HashError::Failed(anyhow::anyhow!("argon2 hash task: {e}")))?
}

/// Argon2id PHC string for `password` on the calling thread.
pub(super) fn hash_blocking(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))
}

/// An Argon2 PHC string with salt, hash and usable parameters; anything else fails
/// `verify_password` before any hashing work.
fn verifiable(phc: &PasswordHash<'_>) -> bool {
    Algorithm::try_from(phc.algorithm).is_ok()
        && phc.salt.is_some()
        && phc.hash.is_some()
        && Params::try_from(phc).is_ok()
}

/// Whether `password` matches `phc`. A missing, unreadable, incomplete or non-Argon2 `phc` and an
/// over-length password all cost one Argon2 verify of a fixed hash and answer `false`.
pub(super) async fn verify(
    permits: &Arc<Semaphore>,
    password: String,
    phc: Option<String>,
) -> Result<bool, HashError> {
    let permit = permit(permits).await?;
    #[cfg(test)]
    let counted = Arc::clone(permits);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let matched = verify_blocking(&password, phc);
        #[cfg(test)]
        argon2_runs::record(&counted);
        matched
    })
    .await
    .map_err(|e| HashError::Failed(anyhow::anyhow!("argon2 verify task: {e}")))
}

fn verify_blocking(password: &str, phc: Option<String>) -> bool {
    let dummy = || {
        let parsed = PasswordHash::new(DUMMY_PHC).expect("DUMMY_PHC is a valid PHC string");
        let _ = hasher().verify_password(b"", &parsed);
        false
    };
    if over_length(password) {
        return dummy();
    }
    let Some(phc) = phc else {
        return dummy();
    };
    let parsed = match PasswordHash::new(&phc) {
        Ok(p) if verifiable(&p) => p,
        Ok(p) => {
            tracing::error!(
                algorithm = %p.algorithm,
                "stored password hash is not a complete Argon2 hash"
            );
            return dummy();
        }
        Err(e) => {
            tracing::error!(error = %e, "stored password hash is not a PHC string");
            return dummy();
        }
    };
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Argon2 verifies finished per hashing semaphore, so a test can see that a path did the work.
#[cfg(test)]
pub(super) mod argon2_runs {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tokio::sync::Semaphore;

    static RUNS: Mutex<Option<HashMap<usize, usize>>> = Mutex::new(None);

    fn key(permits: &Arc<Semaphore>) -> usize {
        Arc::as_ptr(permits) as usize
    }

    pub(in crate::identity_native) fn record(permits: &Arc<Semaphore>) {
        let mut runs = RUNS.lock().unwrap();
        *runs
            .get_or_insert_with(HashMap::new)
            .entry(key(permits))
            .or_default() += 1;
    }

    pub(in crate::identity_native) fn count(permits: &Arc<Semaphore>) -> usize {
        RUNS.lock()
            .unwrap()
            .as_ref()
            .and_then(|m| m.get(&key(permits)).copied())
            .unwrap_or(0)
    }
}

/// HaveIBeenPwned range API (k-anonymity): only the first five hex characters of the SHA-1 leave the process.
pub(super) struct BreachCheck {
    client: &'static reqwest::Client,
    base_url: String,
}

impl BreachCheck {
    pub(super) fn new() -> Self {
        Self {
            client: crate::outbound::client(false),
            base_url: HIBP_BASE_URL.to_string(),
        }
    }

    /// A check against a local stand-in for the range API.
    #[cfg(test)]
    pub(super) fn at(base_url: String) -> Self {
        Self {
            client: crate::outbound::client(true),
            base_url,
        }
    }

    /// `true` only when the API lists the password; any failure answers `false`.
    pub(super) async fn is_breached(&self, password: &str) -> bool {
        let sha1 = hex::encode_upper(digest::digest(
            &digest::SHA1_FOR_LEGACY_USE_ONLY,
            password.as_bytes(),
        ));
        let (prefix, suffix) = sha1.split_at(5);
        match self.range(prefix).await {
            Ok(body) => listed(&body, suffix),
            Err(e) => {
                tracing::warn!(error = %e, "password breach check failed; accepting the password");
                false
            }
        }
    }

    /// The range body. Errors never carry the request URL: it holds the hash prefix.
    async fn range(&self, prefix: &str) -> Result<String> {
        let resp = self
            .client
            .get(format!("{}/range/{prefix}", self.base_url))
            .header("Add-Padding", "true")
            .timeout(HIBP_TIMEOUT)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(reqwest::Error::without_url)?;
        let body = crate::outbound::read_capped(resp, HIBP_BODY_LIMIT)
            .await
            .map_err(|e| match e {
                crate::outbound::FetchError::TooLarge => anyhow::anyhow!("range body too large"),
                _ => anyhow::anyhow!("range body read failed"),
            })?;
        Ok(String::from_utf8(body)?)
    }
}

/// Whether `suffix` appears with a non-zero count; padding entries carry a count of 0.
fn listed(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        line.trim().split_once(':').is_some_and(|(s, count)| {
            s.eq_ignore_ascii_case(suffix) && count.trim().parse::<u64>().is_ok_and(|c| c > 0)
        })
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn length_rules() {
        assert_eq!(
            check_policy("short1!", "ann@example.com", 8),
            Err(PolicyError::TooShort {
                min_length: 8,
                actual_length: 7
            })
        );
        assert!(check_policy("correct horse", "ann@example.com", 8).is_ok());
        assert_eq!(
            check_policy("correct horse", "ann@example.com", 14),
            Err(PolicyError::TooShort {
                min_length: 14,
                actual_length: 13
            })
        );
        let max = "x".repeat(MAX_LENGTH);
        assert!(check_policy(&max, "ann@example.com", 8).is_ok());
        assert_eq!(
            check_policy(&format!("{max}y"), "ann@example.com", 8),
            Err(PolicyError::TooLong {
                max_length: MAX_LENGTH,
                actual_length: MAX_LENGTH + 1
            })
        );
        // Characters, not bytes.
        assert!(check_policy("ääääääää", "ann@example.com", 8).is_ok());
    }

    #[test]
    fn similarity_to_email() {
        let email = "Ann.Smith@example.com";
        for similar in [
            "ann.smith@example.com",
            "ann.smith@example.co",
            "Ann.Smith@Example.com1",
            "ann.smith@exam",
            "xxann.smith@exyy",
        ] {
            assert_eq!(
                check_policy(similar, email, 8),
                Err(PolicyError::TooSimilar),
                "{similar}"
            );
        }
        for fine in [
            "correct horse battery staple",
            "ann-likes-tea-a-lot",
            "Tr0ub4dor&3xtra",
        ] {
            assert!(check_policy(fine, email, 8).is_ok(), "{fine}");
        }
    }

    #[test]
    fn edit_distance_and_substring() {
        let c = |s: &str| s.chars().collect::<Vec<_>>();
        assert_eq!(levenshtein(&c("kitten"), &c("sitting")), 3);
        assert_eq!(levenshtein(&c(""), &c("abc")), 3);
        assert_eq!(longest_common_substring(&c("xabcdy"), &c("zabcdw")), 4);
        assert_eq!(longest_common_substring(&c("abc"), &c("xyz")), 0);
    }

    #[test]
    fn messages_use_catalogued_ids() {
        let (id, ctx, text) = PolicyError::TooShort {
            min_length: 8,
            actual_length: 3,
        }
        .message();
        assert_eq!(id, 4_000_032);
        assert_eq!(ctx, json!({ "min_length": 8, "actual_length": 3 }));
        assert_eq!(
            text,
            "The password must be at least 8 characters long, but got 3."
        );
        for err in [
            PolicyError::TooLong {
                max_length: 256,
                actual_length: 300,
            },
            PolicyError::TooSimilar,
            PolicyError::Breached,
        ] {
            let (id, ctx, text) = err.message();
            assert_eq!(id, 4_000_005);
            let reason = ctx["reason"].as_str().unwrap();
            assert_eq!(
                text,
                format!("The password can not be used because {reason}.")
            );
        }
    }

    fn permits(n: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(n))
    }

    #[tokio::test]
    async fn phc_carries_owasp_parameters() {
        let permits = permits(1);
        let phc = hash(&permits, "correct horse".into()).await.unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(
            verify(&permits, "correct horse".into(), Some(phc.clone()))
                .await
                .unwrap()
        );
        assert!(
            !verify(&permits, "wrong horse".into(), Some(phc))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn over_length_input_is_refused_by_hash_and_never_verifies() {
        let permits = permits(1);
        let max = "x".repeat(MAX_LENGTH);
        let phc = hash(&permits, max.clone()).await.unwrap();
        assert!(
            verify(&permits, max.clone(), Some(phc.clone()))
                .await
                .unwrap()
        );
        let long = format!("{max}x");
        assert!(matches!(
            hash(&permits, long.clone()).await,
            Err(HashError::Failed(_))
        ));
        let salt = SaltString::generate(&mut OsRng);
        let long_phc = hasher()
            .hash_password(long.as_bytes(), &salt)
            .unwrap()
            .to_string();
        assert!(!verify(&permits, long, Some(long_phc)).await.unwrap());
    }

    #[tokio::test]
    async fn incomplete_argon2_hashes_cost_a_dummy_verify_and_never_match() {
        let permits = permits(1);
        let incomplete = [
            "$argon2id$v=19$m=19456,t=2,p=1",
            "$argon2id$v=19$m=19456,t=2,p=1$c1NSVVc4ODVMSk9RdGZJOGgxdmduZw",
            "$argon2id$v=19$m=1,t=2,p=1$c1NSVVc4ODVMSk9RdGZJOGgxdmduZw$7NbJXi95HFEt7hF767fIYjodMRP3AW8Zzccp8Ropi7c",
        ];
        for stored in incomplete {
            let parsed = PasswordHash::new(stored).expect("parses as PHC");
            assert!(!verifiable(&parsed), "{stored}");
            let started = std::time::Instant::now();
            assert!(
                !verify(&permits, "x".into(), Some(stored.into()))
                    .await
                    .unwrap(),
                "{stored}"
            );
            assert!(
                started.elapsed() >= Duration::from_millis(5),
                "{stored} answered without Argon2 work"
            );
        }
        assert!(verifiable(&PasswordHash::new(DUMMY_PHC).unwrap()));
    }

    #[tokio::test]
    async fn waiting_for_a_permit_is_bounded() {
        let permits = permits(0);
        let started = std::time::Instant::now();
        assert!(matches!(
            hash(&permits, "correct horse".into()).await,
            Err(HashError::Busy)
        ));
        assert!(matches!(
            verify(&permits, "correct horse".into(), None).await,
            Err(HashError::Busy)
        ));
        assert!(started.elapsed() >= PERMIT_WAIT * 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_abandoned_request_keeps_its_permit_until_the_hash_ends() {
        let permits = permits(1);
        let task = tokio::spawn({
            let permits = permits.clone();
            async move { hash(&permits, "correct horse".into()).await }
        });
        while permits.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(permits.available_permits(), 0, "hash still running");
        tokio::time::timeout(Duration::from_secs(60), async {
            while permits.available_permits() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the permit comes back once the hash finishes");
    }

    #[test]
    fn dummy_hash_has_live_parameters_and_never_matches() {
        assert!(DUMMY_PHC.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        let parsed = PasswordHash::new(DUMMY_PHC).unwrap();
        let (dummy, live) = (
            Params::try_from(&parsed).unwrap(),
            hasher().params().clone(),
        );
        assert_eq!(
            (dummy.m_cost(), dummy.t_cost(), dummy.p_cost()),
            (live.m_cost(), live.t_cost(), live.p_cost())
        );
        assert_eq!(parsed.hash.unwrap().len(), Params::DEFAULT_OUTPUT_LEN);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let permits = permits(1);
        assert!(!rt.block_on(verify(&permits, String::new(), None)).unwrap());
        assert!(
            !rt.block_on(verify(&permits, "anything".into(), None))
                .unwrap()
        );
    }

    #[tokio::test]
    async fn unusable_stored_hashes_never_verify() {
        let permits = permits(1);
        let md5 = "$md5$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
        assert!(PasswordHash::new(md5).is_ok(), "parses, but is not Argon2");
        for stored in ["not a phc", "", md5] {
            assert!(
                !verify(&permits, "x".into(), Some(stored.into()))
                    .await
                    .unwrap(),
                "{stored:?}"
            );
        }
    }

    #[test]
    fn range_body_parsing() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n\
                    011053FD0102E94D6AE2F8B83D76FAF94F6:3\r\n";
        assert!(listed(body, "011053FD0102E94D6AE2F8B83D76FAF94F6"));
        assert!(listed(body, "0018a45c4d1def81644b54ab7f969b88d65"));
        assert!(
            !listed(body, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC"),
            "padding entry"
        );
        assert!(!listed(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
    }

    type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

    async fn stub(body: &'static str, status: u16, delay: Duration) -> (BreachCheck, Seen) {
        let seen: Seen = Arc::default();
        let seen_in = seen.clone();
        let app = axum::Router::new().route(
            "/range/{prefix}",
            axum::routing::get(
                move |axum::extract::Path(prefix): axum::extract::Path<String>,
                      headers: axum::http::HeaderMap| {
                    let seen = seen_in.clone();
                    async move {
                        let padding = headers
                            .get("add-padding")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        seen.lock().unwrap().push((prefix, padding));
                        tokio::time::sleep(delay).await;
                        (axum::http::StatusCode::from_u16(status).unwrap(), body)
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let check = BreachCheck {
            client: crate::outbound::client(true),
            base_url: format!("http://{addr}"),
        };
        (check, seen)
    }

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
    const PASSWORD_SUFFIX_LINE: &str =
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n0000000000000000000000000000000000A:0\r\n";

    #[tokio::test]
    async fn breached_password_is_reported_with_prefix_and_padding() {
        let (check, seen) = stub(PASSWORD_SUFFIX_LINE, 200, Duration::ZERO).await;
        assert!(check.is_breached("password").await);
        assert!(!check.is_breached("correct horse battery staple").await);
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], ("5BAA6".to_string(), Some("true".to_string())));
    }

    #[tokio::test]
    async fn failure_messages_leave_out_the_hash_prefix() {
        let (check, _) = stub(PASSWORD_SUFFIX_LINE, 503, Duration::ZERO).await;
        let unreachable = BreachCheck {
            client: crate::outbound::client(true),
            base_url: "http://127.0.0.1:9".to_string(),
        };
        for check in [check, unreachable] {
            let e = check.range("5BAA6").await.unwrap_err();
            let text = format!("{e:#} {e:?}");
            assert!(!text.contains("5BAA6"), "{text}");
            assert!(!text.contains("/range/"), "{text}");
        }
    }

    #[tokio::test]
    async fn failures_fail_open() {
        let (check, _) = stub(PASSWORD_SUFFIX_LINE, 503, Duration::ZERO).await;
        assert!(!check.is_breached("password").await);
        let (check, _) = stub(PASSWORD_SUFFIX_LINE, 200, Duration::from_secs(3)).await;
        assert!(!check.is_breached("password").await);
        let unreachable = BreachCheck {
            client: crate::outbound::client(true),
            base_url: "http://127.0.0.1:9".to_string(),
        };
        assert!(!unreachable.is_breached("password").await);
    }
}
