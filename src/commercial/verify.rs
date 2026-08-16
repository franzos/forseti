//! Decode + verify a base64-encoded license blob against the baked-in
//! Ed25519 public keys (offline root, and the licence shop's web key).
//! The OPLB/CBOR/Ed25519 wire format lives in the
//! MIT-licensed `signetlib` crate; this module only maps its verified
//! claims into Forseti's typed [`License`] and applies entitlement policy.
//! Forseti never signs licenses.

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::VerifyingKey;
use signetlib::claims::Claims;
use signetlib::codec::{DecodeError, decode_and_verify_any as signet_decode_any};

use crate::commercial::license::{Feature, License};
use crate::commercial::{PUBLIC_KEY_BYTES, WEB_PUBLIC_KEY_BYTES};

#[derive(Debug)]
pub enum VerifyError {
    /// Empty input. Surfaces nicer in the UI than "base64 error".
    Empty,
    /// Couldn't base64-decode, doesn't carry the magic, unknown version,
    /// or CBOR parse failure.
    Malformed(String),
    /// Parses fine, but the signature doesn't verify against either
    /// baked-in key. Either tampered or signed with the wrong key
    /// (e.g. an old key after rotation).
    BadSignature,
    /// `issued_at` or `expires_at` couldn't be coerced into a UTC
    /// `DateTime`. Should never happen for issuer-emitted blobs but is
    /// recorded explicitly so we don't accidentally accept zero-stamp
    /// licenses.
    BadTimestamp,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Empty => write!(f, "no license provided"),
            VerifyError::Malformed(s) => write!(f, "malformed license blob: {s}"),
            VerifyError::BadSignature => {
                write!(
                    f,
                    "license signature did not verify (wrong key or tampered)"
                )
            }
            VerifyError::BadTimestamp => write!(f, "license carries an invalid timestamp"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// User-facing message for the activate page. Deliberately terse and
/// non-technical; the detailed `Display` form goes into `tracing::warn`
/// for the operator.
pub fn user_message(err: &VerifyError) -> &'static str {
    match err {
        VerifyError::Empty => "Paste your license key to activate.",
        VerifyError::BadSignature => {
            "This license isn't valid for this installation. Double-check you pasted the right key."
        }
        _ => "We couldn't read that license. Please check it and try again.",
    }
}

/// Decode a base64 license blob, verify its signature against either
/// baked-in public key, and convert it into the typed [`License`].
///
/// Both the offline root key and the shop's web key are accepted; see
/// [`WEB_PUBLIC_KEY_BYTES`] for why the split exists.
pub fn decode_and_verify(b64: &str) -> Result<License, VerifyError> {
    let trimmed = b64.trim();
    if trimmed.is_empty() {
        return Err(VerifyError::Empty);
    }

    let root = VerifyingKey::from_bytes(PUBLIC_KEY_BYTES)
        .map_err(|e| VerifyError::Malformed(format!("baked-in pubkey: {e}")))?;
    let web = VerifyingKey::from_bytes(WEB_PUBLIC_KEY_BYTES)
        .map_err(|e| VerifyError::Malformed(format!("baked-in web pubkey: {e}")))?;

    let claims = signet_decode_any(trimmed, &[root, web]).map_err(|e| match e {
        DecodeError::Malformed(s) => VerifyError::Malformed(s),
        DecodeError::BadSignature => VerifyError::BadSignature,
    })?;

    into_license(claims)
}

fn into_license(claims: Claims) -> Result<License, VerifyError> {
    let issued_at = unix_to_utc(claims.issued_at)?;
    let expires_at = match claims.expires_at {
        Some(ts) => Some(unix_to_utc(ts)?),
        None => None,
    };
    let features = claims
        .features
        .iter()
        .filter_map(|s| Feature::from_wire(s))
        .collect();
    Ok(License {
        license_id: claims.license_id,
        customer: claims.customer,
        email: claims.email,
        issued_at,
        expires_at,
        features,
        max_orgs: claims.max_orgs,
        max_seats: claims.max_seats,
    })
}

fn unix_to_utc(ts: i64) -> Result<DateTime<Utc>, VerifyError> {
    match Utc.timestamp_opt(ts, 0).single() {
        Some(dt) => Ok(dt),
        None => Err(VerifyError::BadTimestamp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_rejected() {
        assert!(matches!(decode_and_verify(""), Err(VerifyError::Empty)));
    }

    #[test]
    fn garbage_rejected() {
        assert!(matches!(
            decode_and_verify("not-a-license"),
            Err(VerifyError::Malformed(_))
        ));
    }

    /// The blob the licence shop actually sells is signed with the web key, not
    /// the root one. Self-gating on the fixture because signed blobs are
    /// gitignored (anyone holding one can unlock the features): run
    /// `make license-fixtures` and this starts asserting.
    #[test]
    fn web_signed_blob_verifies_when_fixture_present() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/license/web-signed.blob"
        );
        let Ok(blob) = std::fs::read_to_string(path) else {
            eprintln!("skipping: no web-signed.blob, run `make license-fixtures`");
            return;
        };
        let license = decode_and_verify(&blob).expect("web-signed blob verifies");
        assert!(license.has_feature(Feature::Saml));
        assert!(license.has_feature(Feature::Observability));
        assert_eq!(license.max_orgs, Some(25));
        assert_eq!(license.max_seats, Some(500));
    }

    /// Guards the key material itself: a truncated file, or web-pubkey.bin
    /// accidentally holding a copy of the root key, would silently collapse
    /// this back to single-key verification.
    #[test]
    fn both_baked_in_keys_are_valid_and_distinct() {
        let root = VerifyingKey::from_bytes(PUBLIC_KEY_BYTES).expect("root pubkey parses");
        let web = VerifyingKey::from_bytes(WEB_PUBLIC_KEY_BYTES).expect("web pubkey parses");
        assert_ne!(
            root.to_bytes(),
            web.to_bytes(),
            "web-pubkey.bin must not be a copy of pubkey.bin"
        );
    }
}
