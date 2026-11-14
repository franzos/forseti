//! What `tests/support/native_seed.rs` needs to write identities and credentials straight into
//! the database of a running native Forseti: the stored forms of a password, a TOTP secret and a
//! session token, under the server's own keys.

use super::Keys;
use super::codes::session_token_hash;
use super::password::{PasswordConfig, hash_blocking};
use super::totp::TotpConfig;

/// The key material the server derives from a `[security].cookie_secret` value.
pub fn cookie_secret(configured: &str) -> Vec<u8> {
    crate::app::resolve_cookie_secret(Some(configured), "http://localhost").to_vec()
}

/// `identity_credentials.config` of a `password` credential for `password`.
pub fn password_config(password: &str) -> anyhow::Result<String> {
    let config = PasswordConfig {
        hashed_password: hash_blocking(password)?,
    };
    Ok(serde_json::to_string(&config)?)
}

/// `identity_credentials.config` of a `totp` credential holding `secret`, sealed for `identity_id`
/// under the key derived from `cookie_secret`.
pub fn totp_config(
    cookie_secret: &[u8],
    identity_id: &str,
    secret: &[u8],
) -> anyhow::Result<String> {
    let keys = Keys::derive(cookie_secret);
    Ok(serde_json::to_string(&TotpConfig::new(
        &keys.seal,
        identity_id,
        secret,
    ))?)
}

/// `identity_sessions.token_hash` of a `forseti_session` cookie value.
pub fn token_hash(token: &str) -> String {
    session_token_hash(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_native::seal::SealKey;
    use crate::signed_cookie::derive_subkey;

    #[test]
    fn a_seeded_totp_secret_opens_under_the_servers_key() {
        let secret = cookie_secret(&"ab".repeat(32));
        assert_eq!(secret, vec![0xab; 32]);
        let config: TotpConfig =
            serde_json::from_str(&totp_config(&secret, "id-1", b"twenty-byte-secret!!").unwrap())
                .unwrap();
        let key = SealKey::new(&derive_subkey(&secret, b"forseti::identity::seal::v1"));
        assert_eq!(
            config.open(&key, "id-1").as_deref(),
            Some(&b"twenty-byte-secret!!"[..])
        );
        assert_eq!(config.open(&key, "id-2"), None);
    }

    #[test]
    fn a_seeded_password_verifies() {
        let config: PasswordConfig =
            serde_json::from_str(&password_config("correct horse").unwrap()).unwrap();
        let phc = argon2::PasswordHash::new(&config.hashed_password).unwrap();
        use argon2::PasswordVerifier as _;
        assert!(
            argon2::Argon2::default()
                .verify_password(b"correct horse", &phc)
                .is_ok()
        );
    }
}
