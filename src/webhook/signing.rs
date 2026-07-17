//! Ed25519 signing key load/generate, JWS signing, SET minting, subject extraction.
//!
//! ## Signing
//!
//! Every payload is a compact-serialised RFC 8417 Security Event Token
//! (SET) signed EdDSA (RFC 8037) against the Forseti-owned key at
//! `[webhook].signing_key_path`. Receivers verify with the matching JWK
//! served from `/.well-known/webhook-jwks.json` — same library + pattern
//! they already use for id_token validation.
//!
//! The claims set follows the Google Cross-Account Protection / RISC
//! convention so integrators can reuse existing RISC handlers. The JWS
//! header carries `typ: "secevent+jwt"` (RFC 8417 §2.3) and a `kid`
//! deterministically derived from SHA-256(public_key) so receivers
//! can cache JWKS by `kid` across Forseti restarts.

use std::path::Path;

use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::event_type;

/// Forseti-owned Ed25519 signing key + the pre-derived public JWK we hand
/// out at `/.well-known/webhook-jwks.json`. Cloned around via `Arc` (held
/// in `AppState`) so handlers don't have to re-parse the PEM on every
/// request.
#[derive(Clone)]
pub struct SigningKey {
    /// Pre-parsed `EncodingKey` built once at load time. `EncodingKey` is
    /// opaque but `Clone`, so cloning a `SigningKey` is cheap.
    encoding_key: EncodingKey,
    /// Deterministic JWK `kid`: base64url(SHA-256(public key bytes))[..16].
    pub kid: String,
    /// Pre-serialised JWK ready for the JWKS endpoint. `serde_json::Value`
    /// rather than the typed `jsonwebtoken::jwk::Jwk` because the endpoint
    /// just splats the value into a `{ "keys": [...] }` envelope.
    pub jwk: serde_json::Value,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish()
    }
}

impl SigningKey {
    /// Load the Ed25519 private key from `path`, generating + persisting a
    /// fresh key when the file is missing. The file is created with `0600`
    /// permissions from the start. An existing file that isn't a valid
    /// Ed25519 PKCS#8 PEM is a hard error — the operator must remove or
    /// replace it deliberately.
    pub fn load_or_generate(path: &Path) -> anyhow::Result<Self> {
        let key = if path.exists() {
            let pem = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("read webhook signing key {path:?}: {e}"))?;
            EdSigningKey::from_pkcs8_pem(&pem).map_err(|e| {
                anyhow::anyhow!(
                    "webhook signing key {path:?} is not a valid Ed25519 PKCS#8 PEM ({e}); \
                     remove or replace it with a valid key, or delete it to have Forseti \
                     generate a fresh one"
                )
            })?
        } else {
            tracing::warn!(
                path = %path.display(),
                "webhook signing key not found; generating a fresh Ed25519 key. \
                 Back up this file with the rest of your Forseti state — losing it \
                 forces every integrator to reload their JWKS cache."
            );
            generate_and_persist(path)?
        };

        // DER (not PEM) so the transient private-key bytes stay in a
        // `SecretDocument`, which zeroizes on drop — jsonwebtoken has no
        // raw-seed constructor, so some intermediate copy is unavoidable.
        let der = key
            .to_pkcs8_der()
            .map_err(|e| anyhow::anyhow!("re-encode webhook signing key as DER: {e}"))?;
        let encoding_key = EncodingKey::from_ed_der(der.as_bytes());

        let verifying: VerifyingKey = key.verifying_key();
        let pub_bytes = verifying.as_bytes();
        let kid = compute_kid(pub_bytes);

        // JWK shape per RFC 8037: OKP / Ed25519 / x = base64url(public key
        // bytes), no padding. JWA `alg` is `EdDSA`. Receivers' libraries
        // (Node `jose`, PyJWT, etc.) consume this verbatim.
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": kid,
            "x":   x_b64,
        });

        Ok(Self {
            encoding_key,
            kid,
            jwk,
        })
    }

    /// Encode a SET as a compact JWS using this key. Headers carry
    /// `alg=EdDSA`, `kid=<this key>`, `typ=secevent+jwt` (RFC 8417 §2.3).
    fn sign<T: Serialize>(&self, claims: &T) -> anyhow::Result<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        header.typ = Some("secevent+jwt".to_string());
        jsonwebtoken::encode(&header, claims, &self.encoding_key)
            .map_err(|e| anyhow::anyhow!("encode SET JWS: {e}"))
    }
}

/// Generate a fresh Ed25519 key and persist it to `path`. Returns the
/// in-memory key so the caller can derive the public half + JWK.
fn generate_and_persist(path: &Path) -> anyhow::Result<EdSigningKey> {
    // `ed25519-dalek` 2's `SigningKey::generate` expects a
    // `rand_core::CryptoRngCore` (rand_core 0.6). Forseti pins
    // `rand = "0.9"` which ships rand_core 0.9 — trait-incompatible.
    // Bypass the version mismatch by drawing a 32-byte seed from the OS
    // CSPRNG explicitly and feeding it to `from_bytes`, which is what
    // `generate` does internally anyway.
    use rand::rngs::OsRng;
    use rand::TryRngCore;
    let mut seed = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| anyhow::anyhow!("draw Ed25519 key seed from OsRng: {e}"))?;
    let key = EdSigningKey::from_bytes(&seed);
    persist_new_key(path, &key)?;
    Ok(key)
}

/// Write a freshly-generated key to `path`, created `0600` at open time so
/// the private key is never world-readable, even transiently. Creates the
/// parent directory if needed. `create_new` (O_EXCL) is safe here: the
/// caller only generates when the file is missing.
fn persist_new_key(path: &Path, key: &EdSigningKey) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!("create parent dir {parent:?} for webhook signing key: {e}")
            })?;
        }
    }
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("serialise generated webhook signing key: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| anyhow::anyhow!("write webhook signing key {path:?}: {e}"))?;
    file.write_all(pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("write webhook signing key {path:?}: {e}"))?;
    Ok(())
}

/// Compute a deterministic JWK `kid` from the public key bytes. SHA-256,
/// base64url-no-pad, first 16 chars — collision-resistant in the trust
/// model (one Forseti, a handful of keys over its lifetime) and short
/// enough to log without clutter.
fn compute_kid(pub_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(pub_bytes);
    let digest = h.finalize();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    b64.chars().take(16).collect()
}

/// Sign an `account-purged` SET targeting a single receiver. Returns the
/// compact-serialised JWS that becomes the body of the webhook POST.
///
/// `iss` is Forseti's own externally reachable URL — matches the
/// `iss` Hydra puts on id_tokens, so a receiver that already pins the
/// Forseti as an issuer can apply the same rule here.
pub fn sign_set(
    key: &SigningKey,
    iss: &str,
    event_id: Uuid,
    subject_kratos_id: &str,
    audience_client_id: &str,
    issued_at: DateTime<Utc>,
) -> anyhow::Result<String> {
    let claims = json!({
        "iss": iss,
        "aud": audience_client_id,
        "iat": issued_at.timestamp(),
        "jti": event_id.to_string(),
        "events": {
            event_type::ACCOUNT_PURGED: {
                "subject": {
                    "subject_type": "iss-sub",
                    "iss": iss,
                    "sub": subject_kratos_id,
                }
            }
        }
    });
    key.sign(&claims)
}

/// Pull `events.<account-purged>.subject.sub` out of an outbox payload.
/// Decode the middle JWS segment as base64url JSON without verifying the
/// signature — we wrote it ourselves and the only field we need is the
/// kratos identity id we already trusted on enqueue.
///
/// Never run this on externally-controlled JWS: only on Forseti's own
/// stored SETs, since it trusts the payload without signature verification.
pub(super) fn extract_subject_from_jws(compact: &str) -> Option<String> {
    let middle = compact.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(middle)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("events")?
        .get(event_type::ACCOUNT_PURGED)?
        .get("subject")?
        .get("sub")?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let dir = tempdir_path();
            let path = dir.join("test-key.pem");
            SigningKey::load_or_generate(&path).expect("generate test key")
        })
        .clone()
    }

    fn tempdir_path() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("forseti-webhook-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create tempdir");
        p
    }

    #[test]
    fn sign_set_produces_three_segment_compact_jws() {
        let key = test_key();
        let evt = Uuid::new_v4();
        let when = DateTime::parse_from_rfc3339("2026-05-21T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let jws = sign_set(
            &key,
            "https://forseti.example.com",
            evt,
            "kratos-user-id",
            "client-abc",
            when,
        )
        .expect("sign");
        let segments: Vec<&str> = jws.split('.').collect();
        assert_eq!(segments.len(), 3, "compact JWS has three segments");
        assert!(!segments[0].is_empty());
        assert!(!segments[1].is_empty());
        assert!(!segments[2].is_empty());
    }

    #[test]
    fn sign_set_header_carries_typ_and_kid() {
        let key = test_key();
        let evt = Uuid::new_v4();
        let when = Utc::now();
        let jws = sign_set(
            &key,
            "https://forseti.example.com",
            evt,
            "kratos-user-id",
            "client-abc",
            when,
        )
        .expect("sign");
        let header_b64 = jws.split('.').next().unwrap();
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("base64url header");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("json header");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "secevent+jwt");
        assert_eq!(header["kid"], key.kid);
    }

    #[test]
    fn sign_set_claims_match_risc_shape() {
        let key = test_key();
        let evt = Uuid::parse_str("12345678-1234-1234-1234-1234567890ab").unwrap();
        let when = DateTime::parse_from_rfc3339("2026-05-21T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let iss = "https://forseti.example.com";
        let jws = sign_set(&key, iss, evt, "kratos-user-id", "client-abc", when).expect("sign");
        let payload_b64 = jws.split('.').nth(1).unwrap();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("base64url payload");
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("claims");
        assert_eq!(claims["iss"], iss);
        assert_eq!(claims["aud"], "client-abc");
        assert_eq!(claims["jti"], "12345678-1234-1234-1234-1234567890ab");
        assert_eq!(claims["iat"], when.timestamp());
        let event = &claims["events"][event_type::ACCOUNT_PURGED];
        assert!(event.is_object(), "event object present at RISC URI key");
        assert_eq!(event["subject"]["subject_type"], "iss-sub");
        assert_eq!(event["subject"]["iss"], iss);
        assert_eq!(event["subject"]["sub"], "kratos-user-id");
    }

    #[test]
    fn extract_subject_from_jws_round_trip() {
        let key = test_key();
        let evt = Uuid::new_v4();
        let jws = sign_set(
            &key,
            "https://forseti.example.com",
            evt,
            "kratos-user-42",
            "client-abc",
            Utc::now(),
        )
        .expect("sign");
        assert_eq!(
            extract_subject_from_jws(&jws),
            Some("kratos-user-42".to_string())
        );
    }

    #[test]
    fn kid_is_deterministic() {
        // Two `SigningKey::load_or_generate` calls against the same
        // on-disk PEM produce the same `kid`.
        let dir = tempdir_path();
        let path = dir.join("kid-stability.pem");
        let _ = std::fs::remove_file(&path);
        let a = SigningKey::load_or_generate(&path).expect("first load");
        let b = SigningKey::load_or_generate(&path).expect("second load");
        assert_eq!(a.kid, b.kid);
        assert_eq!(a.kid.len(), 16);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn jwk_shape_advertises_eddsa_signing_key() {
        let key = test_key();
        assert_eq!(key.jwk["kty"], "OKP");
        assert_eq!(key.jwk["crv"], "Ed25519");
        assert_eq!(key.jwk["use"], "sig");
        assert_eq!(key.jwk["alg"], "EdDSA");
        assert_eq!(key.jwk["kid"], key.kid);
        assert!(key.jwk["x"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn generated_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir_path();
        let path = dir.join("perms.pem");
        let _ = std::fs::remove_file(&path);
        SigningKey::load_or_generate(&path).expect("generate");
        let mode = std::fs::metadata(&path)
            .expect("stat generated key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn invalid_pem_is_a_hard_error() {
        // A file that exists but isn't a valid Ed25519 PKCS#8 PEM must
        // fail loudly rather than silently regenerate.
        let dir = tempdir_path();
        let path = dir.join("invalid.pem");
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            "-----BEGIN PRIVATE KEY-----\nnot-actually-a-key\n-----END PRIVATE KEY-----\n",
        )
        .expect("seed invalid pem");
        assert!(SigningKey::load_or_generate(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
