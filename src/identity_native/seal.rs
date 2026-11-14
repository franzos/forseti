//! AES-256-GCM sealing of secrets stored at rest, as `v1.<nonce>.<ciphertext+tag>` (URL-safe base64).

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::random_bytes;

const VERSION: &str = "v1";

pub(super) struct SealKey(LessSafeKey);

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey(..)")
    }
}

/// `purpose` names what is sealed; `binding` ties it to one row (e.g. an identity id), and may be empty.
fn aad(purpose: &str, binding: &str) -> Vec<u8> {
    // Length prefix so no (purpose, binding) pair aliases another.
    let mut out = Vec::with_capacity(8 + purpose.len() + binding.len());
    out.extend_from_slice(&(purpose.len() as u64).to_be_bytes());
    out.extend_from_slice(purpose.as_bytes());
    out.extend_from_slice(binding.as_bytes());
    out
}

impl SealKey {
    pub(super) fn new(key: &[u8; 32]) -> Self {
        let unbound = UnboundKey::new(&AES_256_GCM, key).expect("32 bytes is an AES-256 key");
        Self(LessSafeKey::new(unbound))
    }

    pub(super) fn seal(&self, purpose: &str, binding: &str, plaintext: &[u8]) -> String {
        self.seal_with_nonce(random_bytes(), purpose, binding, plaintext)
    }

    fn seal_with_nonce(
        &self,
        nonce: [u8; NONCE_LEN],
        purpose: &str,
        binding: &str,
        plaintext: &[u8],
    ) -> String {
        let mut buf = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(purpose, binding)),
                &mut buf,
            )
            // AES-GCM refuses only inputs above 64 GiB.
            .expect("AES-GCM seal of an in-memory value");
        format!(
            "{VERSION}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(&buf)
        )
    }

    /// The plaintext, or `None` on any version, format, key, purpose or binding mismatch.
    pub(super) fn open(&self, purpose: &str, binding: &str, sealed: &str) -> Option<Vec<u8>> {
        let mut parts = sealed.split('.');
        let (Some(VERSION), Some(nonce), Some(body), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let nonce: [u8; NONCE_LEN] = URL_SAFE_NO_PAD.decode(nonce).ok()?.try_into().ok()?;
        let mut buf = URL_SAFE_NO_PAD.decode(body).ok()?;
        let plain = self
            .0
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(purpose, binding)),
                &mut buf,
            )
            .ok()?;
        Some(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SealKey {
        SealKey::new(&[0x11; 32])
    }

    #[test]
    fn round_trip() {
        let k = key();
        let sealed = k.seal("totp-secret", "identity-1", b"secret bytes");
        assert!(sealed.starts_with("v1."));
        assert_eq!(
            k.open("totp-secret", "identity-1", &sealed).as_deref(),
            Some(&b"secret bytes"[..])
        );
        assert_ne!(sealed, k.seal("totp-secret", "identity-1", b"secret bytes"));
    }

    #[test]
    fn mismatches_fail_closed() {
        let k = key();
        let sealed = k.seal("totp-secret", "identity-1", b"secret bytes");
        assert!(k.open("mail-payload", "identity-1", &sealed).is_none());
        assert!(k.open("totp-secret", "identity-2", &sealed).is_none());
        assert!(
            SealKey::new(&[0x12; 32])
                .open("totp-secret", "identity-1", &sealed)
                .is_none()
        );
        assert!(
            k.open(
                "totp-secret",
                "identity-1",
                &sealed.replacen("v1.", "v2.", 1)
            )
            .is_none()
        );
        assert!(
            k.open("totp-secret", "identity-1", &format!("{sealed}.x"))
                .is_none()
        );
        assert!(
            k.open("totp-secret", "identity-1", "v1.short.body")
                .is_none()
        );
        assert!(k.open("totp-secret", "identity-1", "").is_none());
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(k.open("totp-secret", "identity-1", &tampered).is_none());
    }

    #[test]
    fn purpose_and_binding_do_not_alias() {
        let k = key();
        let sealed = k.seal("ab", "c", b"x");
        assert!(k.open("a", "bc", &sealed).is_none());
    }

    #[test]
    fn golden_vector() {
        let k = key();
        let sealed = k.seal_with_nonce([0x22; NONCE_LEN], "totp-secret", "identity-1", b"hello");
        assert_eq!(sealed, GOLDEN);
        assert_eq!(
            k.open("totp-secret", "identity-1", GOLDEN).as_deref(),
            Some(&b"hello"[..])
        );
    }

    // Computed independently with Python `cryptography` AESGCM.
    const GOLDEN: &str = "v1.IiIiIiIiIiIiIiIi.f5JrJa9CB5TVv9F4fU95ME_mAPOG";
}
