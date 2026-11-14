//! RFC 4226 HOTP and RFC 6238 TOTP (HMAC-SHA1, 30 s, 6 digits), the `otpauth://` key URI and its QR code.

use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::random_bytes;
use super::seal::SealKey;

pub(super) const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
pub(super) const SECRET_LEN: usize = 20;

/// RFC 3986 unreserved characters stay literal; everything else is percent-encoded.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Seal purpose of the secret in a stored TOTP credential; the binding is the identity id.
const SEAL_CREDENTIAL: &str = "credential-totp";

/// `identity_credentials.config` for kind `totp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TotpConfig {
    /// The 20-byte secret, sealed for its identity.
    pub(super) secret: String,
    /// Newest step accepted at login; RFC 6238 section 5.2 forbids accepting it again.
    #[serde(default)]
    pub(super) last_used_step: Option<u64>,
}

impl TotpConfig {
    pub(super) fn new(key: &SealKey, identity_id: &str, secret: &[u8]) -> Self {
        Self {
            secret: key.seal(SEAL_CREDENTIAL, identity_id, secret),
            last_used_step: None,
        }
    }

    /// The plain secret; `None` when it does not open under this key and identity.
    pub(super) fn open(&self, key: &SealKey, identity_id: &str) -> Option<Vec<u8>> {
        key.open(SEAL_CREDENTIAL, identity_id, &self.secret)
    }
}

/// Seconds since the Unix epoch, the clock TOTP steps count from.
pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(super) fn new_secret() -> [u8; SECRET_LEN] {
    random_bytes()
}

/// Base32 without padding, the form shown to the user and put in the key URI.
pub(super) fn encode_secret(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let offset = usize::from(h[h.len() - 1] & 0x0f);
    let bin = u32::from_be_bytes([
        h[offset] & 0x7f,
        h[offset + 1],
        h[offset + 2],
        h[offset + 3],
    ]);
    bin % 10u32.pow(digits)
}

fn code_at(secret: &[u8], step: u64, digits: u32) -> String {
    format!(
        "{:0width$}",
        hotp(secret, step, digits),
        width = digits as usize
    )
}

pub(super) fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// The step `code` matches within t-1..=t+1 of `now_unix`, compared in constant time.
pub(super) fn verify(secret: &[u8], code: &str, now_unix: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_at(now_unix);
    let mut matched = Choice::from(0);
    let mut step = 0u64;
    for candidate in [now.checked_sub(1), Some(now), now.checked_add(1)]
        .into_iter()
        .flatten()
    {
        let hit = code_at(secret, candidate, DIGITS)
            .as_bytes()
            .ct_eq(code.as_bytes());
        step.conditional_assign(&candidate, hit);
        matched |= hit;
    }
    bool::from(matched).then_some(step)
}

/// RFC 6238 section 5.2: a step at or below the last accepted one is a replay.
pub(super) fn step_is_fresh(step: u64, last_used_step: Option<u64>) -> bool {
    last_used_step.is_none_or(|last| step > last)
}

/// `otpauth://totp/<issuer>:<account>?secret=..&issuer=..`.
pub(super) fn key_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let issuer = utf8_percent_encode(issuer, COMPONENT);
    let account = utf8_percent_encode(account, COMPONENT);
    format!("otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}")
}

/// The QR code for `data` as a `data:image/svg+xml;base64,` URI.
pub(super) fn qr_data_uri(data: &str) -> anyhow::Result<String> {
    let svg = qrcode::QrCode::new(data.as_bytes())?
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(256, 256)
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_appendix_d() {
        let expected = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (counter, want) in expected.into_iter().enumerate() {
            assert_eq!(
                hotp(RFC_SECRET, counter as u64, 6),
                want,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha1() {
        let vectors = [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (time, want) in vectors {
            assert_eq!(code_at(RFC_SECRET, step_at(time), 8), want, "time {time}");
        }
    }

    #[test]
    fn six_digit_path_matches_totp_lite() {
        let secret = new_secret();
        for time in [
            0,
            59,
            1_111_111_109,
            1_700_000_000,
            2_000_000_000,
            20_000_000_000,
        ] {
            let oracle = totp_lite::totp_custom::<totp_lite::Sha1>(STEP_SECS, 6, &secret, time);
            assert_eq!(
                verify(&secret, &oracle, time),
                Some(step_at(time)),
                "time {time}"
            );
        }
    }

    #[test]
    fn window_accepts_one_step_either_side() {
        let t = 1_700_000_000;
        let now = step_at(t);
        for (step, accepted) in [
            (now - 2, false),
            (now - 1, true),
            (now, true),
            (now + 1, true),
            (now + 2, false),
        ] {
            let code = code_at(RFC_SECRET, step, 6);
            let got = verify(RFC_SECRET, &code, t);
            if accepted {
                assert_eq!(got, Some(step), "step offset {}", step as i64 - now as i64);
            } else {
                assert!(
                    got.is_none_or(|s| s != step),
                    "step offset {} accepted",
                    step as i64 - now as i64
                );
            }
        }
    }

    #[test]
    fn window_at_step_zero() {
        let code = code_at(RFC_SECRET, 0, 6);
        assert_eq!(verify(RFC_SECRET, &code, 10), Some(0));
    }

    #[test]
    fn malformed_codes_rejected() {
        let t = 1_700_000_000;
        let code = code_at(RFC_SECRET, step_at(t), 6);
        assert_eq!(
            verify(RFC_SECRET, &format!(" {code} "), t),
            Some(step_at(t))
        );
        for bad in ["", "12345", "1234567", "12a456", "１２３４５６"] {
            assert!(verify(RFC_SECRET, bad, t).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn replay_rule() {
        assert!(step_is_fresh(10, None));
        assert!(step_is_fresh(11, Some(10)));
        assert!(!step_is_fresh(10, Some(10)));
        assert!(!step_is_fresh(9, Some(10)));
    }

    #[test]
    fn secret_is_20_bytes_as_32_base32_chars() {
        let encoded = encode_secret(&new_secret());
        assert_eq!(encoded.len(), 32);
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        );
        assert_eq!(encode_secret(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn key_uri_percent_encodes_label_and_issuer() {
        assert_eq!(
            key_uri("Acme Corp", "ann+x@example.com", "JBSWY3DPEHPK3PXP"),
            "otpauth://totp/Acme%20Corp:ann%2Bx%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme%20Corp"
        );
        assert_eq!(
            key_uri("A:B&c=d", "x", "S"),
            "otpauth://totp/A%3AB%26c%3Dd:x?secret=S&issuer=A%3AB%26c%3Dd"
        );
    }

    #[test]
    fn credential_config_seals_the_secret_for_its_identity() {
        let key = SealKey::new(&[5; 32]);
        let secret = new_secret();
        let config = TotpConfig::new(&key, "id-1", &secret);
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["last_used_step"], serde_json::Value::Null);
        assert!(!json.to_string().contains(&encode_secret(&secret)));
        let parsed: TotpConfig = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.open(&key, "id-1").as_deref(), Some(&secret[..]));
        assert_eq!(parsed.open(&key, "id-2"), None);
        assert_eq!(parsed.open(&SealKey::new(&[6; 32]), "id-1"), None);
        let legacy: TotpConfig = serde_json::from_str(r#"{"secret":"x"}"#).unwrap();
        assert_eq!(legacy.last_used_step, None);
    }

    #[test]
    fn qr_is_svg_data_uri() {
        let uri = qr_data_uri(&key_uri("Forseti", "ann@example.com", "JBSWY3DPEHPK3PXP")).unwrap();
        let b64 = uri.strip_prefix("data:image/svg+xml;base64,").unwrap();
        let svg = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert!(svg.contains("<svg"), "{svg}");
    }
}
