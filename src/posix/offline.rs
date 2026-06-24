//! Offline-auth verifier (pure). Mints the Argon2id PHC string Forseti stores
//! and ships to enrolled hosts so a partitioned host can verify a dedicated
//! offline passphrase locally. Mirrors M2's `BindingInputs` split: this module
//! is the security core, free of DB/HTTP — set/clear/projection plumbing lives
//! elsewhere.
//!
//! The server stores ONLY this verifier (salt + params embedded in the PHC
//! string). No pepper server-side — the host owns its own HMAC pepper, so a
//! stolen server DB still costs the full Argon2id work factor per guess.
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::Serialize;

/// Hard floor on the offline passphrase. ≥8 chars, enforced server-side; it's
/// a *passphrase*, never a "PIN" (short PINs are M3b/TPM).
pub const OFFLINE_MIN_LEN: usize = 8;
/// Argon2id memory cost in KiB (64 MiB).
pub const ARGON2_M_KIB: u32 = 65536;
/// Argon2id time cost (iterations).
pub const ARGON2_T: u32 = 3;
/// Argon2id parallelism (lanes).
pub const ARGON2_P: u32 = 1;
/// Verifier scheme version stamped on each row. Bumped if the KDF shape changes
/// so a host can refuse a verifier it doesn't understand.
pub const OFFLINE_ALGO_VERSION: i32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetSecretError {
    TooShort,
}

/// Build the configured Argon2id hasher. Params are fixed consts, so the only
/// failure mode is a programmer error in the constants — surfaced via expect.
fn hasher() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None)
        .expect("static Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Mint an Argon2id PHC string (`$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`)
/// for `passphrase`, with a fresh random salt per call. Rejects passphrases
/// shorter than [`OFFLINE_MIN_LEN`].
pub fn mint_verifier(passphrase: &str) -> Result<String, SetSecretError> {
    if passphrase.chars().count() < OFFLINE_MIN_LEN {
        return Err(SetSecretError::TooShort);
    }
    let salt = SaltString::generate(&mut OsRng);
    let phc = hasher()
        .hash_password(passphrase.as_bytes(), &salt)
        .expect("argon2 hash over valid params/salt cannot fail")
        .to_string();
    Ok(phc)
}

/// One row in the `/posix/v1/offline_verifiers` projection: the username, the
/// Argon2id verifier the host re-peppers and stores, the TTL (seconds) the host
/// stamps the credential with, and the algo version the host uses to refuse a
/// scheme it doesn't understand. No pepper, no identity id — the host keys by
/// username.
#[derive(Debug, Clone, Serialize)]
pub struct OfflineVerifier {
    pub username: String,
    pub verifier: String,
    pub ttl_secs: i64,
    pub algo_version: i32,
}

/// Top-level body of the `/posix/v1/offline_verifiers` endpoint. The host
/// wholesale-replaces its keystore from `verifiers`; an empty list withdraws
/// every offline credential (force_mfa hosts always get this).
#[derive(Debug, Clone, Serialize)]
pub struct OfflineVerifiersResponse {
    pub verifiers: Vec<OfflineVerifier>,
}

/// Verify `passphrase` against a stored PHC string. Returns `false` on any
/// mismatch or malformed PHC — never panics on attacker-supplied input.
#[cfg_attr(not(test), allow(dead_code))] // host re-implements verification; server-side use is tests only.
pub fn verify(passphrase: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    hasher()
        .verify_password(passphrase.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_passphrase_verifies() {
        let phc = mint_verifier("correct horse battery").unwrap();
        assert!(verify("correct horse battery", &phc));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let phc = mint_verifier("correct horse battery").unwrap();
        assert!(!verify("Tr0ub4dor&3xtra", &phc));
    }

    #[test]
    fn two_mints_differ_random_salt() {
        let a = mint_verifier("samepassphrase").unwrap();
        let b = mint_verifier("samepassphrase").unwrap();
        assert_ne!(
            a, b,
            "random per-call salt must make the PHC strings differ"
        );
        // Both still verify the same passphrase.
        assert!(verify("samepassphrase", &a));
        assert!(verify("samepassphrase", &b));
    }

    #[test]
    fn seven_chars_rejected_too_short() {
        assert_eq!(mint_verifier("1234567"), Err(SetSecretError::TooShort));
        // Exactly the floor is accepted.
        assert!(mint_verifier("12345678").is_ok());
    }

    #[test]
    fn phc_carries_named_params() {
        let phc = mint_verifier("correct horse battery").unwrap();
        assert!(
            phc.contains("m=65536,t=3,p=1"),
            "PHC must carry the named Argon2id params, got: {phc}"
        );
        assert!(phc.starts_with("$argon2id$v=19$"));
    }
}
