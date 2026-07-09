//! Decode + verify a base64-encoded license blob against the baked-in
//! Ed25519 public key. The OPLB/CBOR/Ed25519 wire format lives in the
//! MIT-licensed `signetlib` crate; this module only maps its verified
//! claims into Forseti's typed [`License`] and applies entitlement policy.
//! Forseti never signs licenses.

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::VerifyingKey;
use signetlib::claims::Claims;
use signetlib::codec::{decode_and_verify as signet_decode, DecodeError};

use crate::commercial::license::{Feature, License};
use crate::commercial::PUBLIC_KEY_BYTES;

#[derive(Debug)]
pub enum VerifyError {
    /// Empty input. Surfaces nicer in the UI than "base64 error".
    Empty,
    /// Couldn't base64-decode, doesn't carry the magic, unknown version,
    /// or CBOR parse failure.
    Malformed(String),
    /// Parses fine, but the signature doesn't verify against
    /// [`PUBLIC_KEY_BYTES`]. Either tampered or signed with the wrong
    /// key (e.g. an old key after rotation).
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

/// Decode a base64 license blob, verify its signature against the
/// baked-in public key, and convert it into the typed [`License`].
pub fn decode_and_verify(b64: &str) -> Result<License, VerifyError> {
    let trimmed = b64.trim();
    if trimmed.is_empty() {
        return Err(VerifyError::Empty);
    }

    let verifying = VerifyingKey::from_bytes(PUBLIC_KEY_BYTES)
        .map_err(|e| VerifyError::Malformed(format!("baked-in pubkey: {e}")))?;

    let claims = signet_decode(trimmed, &verifying).map_err(|e| match e {
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
}
