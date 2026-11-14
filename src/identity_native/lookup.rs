//! Lookup (backup) codes: generation, normalisation, and the MACs stored in the credential config.

use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::codes::MacKey;
use super::random_bytes;

pub(super) const COUNT: usize = 10;
const CODE_LEN: usize = 12;
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// `identity_credentials.config` for kind `lookup_secret`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LookupConfig {
    pub(super) codes: Vec<LookupCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LookupCode {
    pub(super) mac: String,
    pub(super) used_at: Option<String>,
}

/// [`COUNT`] fresh codes in display form, `xxxx-xxxx-xxxx`.
pub(super) fn generate() -> Vec<String> {
    (0..COUNT)
        .map(|_| {
            let raw: [u8; CODE_LEN] = random_bytes();
            // 256 is a multiple of 32, so masking keeps the alphabet uniform.
            let chars: Vec<char> = raw
                .iter()
                .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
                .collect();
            chars
                .chunks(4)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("-")
        })
        .collect()
}

/// Lowercase with spaces and dashes removed, so `ABCD EFGH-ijkl` and `abcd-efgh-ijkl` are the same code.
pub(super) fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn mac(key: &MacKey, identity_id: &str, code: &str) -> String {
    key.hex(&[identity_id, &normalize(code)])
}

/// The stored config for freshly generated `codes`, none used.
pub(super) fn config_for(key: &MacKey, identity_id: &str, codes: &[String]) -> LookupConfig {
    LookupConfig {
        codes: codes
            .iter()
            .map(|code| LookupCode {
                mac: mac(key, identity_id, code),
                used_at: None,
            })
            .collect(),
    }
}

/// Index of the unused code `input` matches; every stored MAC is compared in constant time.
pub(super) fn match_unused(
    key: &MacKey,
    identity_id: &str,
    input: &str,
    config: &LookupConfig,
) -> Option<usize> {
    let candidate = mac(key, identity_id, input);
    let mut matched = Choice::from(0);
    let mut index = 0u64;
    for (i, code) in config.codes.iter().enumerate() {
        let hit = code.mac.as_bytes().ct_eq(candidate.as_bytes())
            & Choice::from(u8::from(code.used_at.is_none()));
        index.conditional_assign(&(i as u64), hit);
        matched |= hit;
    }
    bool::from(matched).then(|| usize::try_from(index).expect("index came from a usize"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MacKey {
        MacKey::new([3; 32])
    }

    #[test]
    fn generates_ten_formatted_codes() {
        let codes = generate();
        assert_eq!(codes.len(), COUNT);
        for code in &codes {
            assert_eq!(code.len(), 14, "{code}");
            let parts: Vec<&str> = code.split('-').collect();
            assert_eq!(parts.len(), 3);
            assert!(parts.iter().all(|p| p.len() == 4));
            assert!(normalize(code).bytes().all(|b| ALPHABET.contains(&b)));
        }
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), COUNT);
    }

    #[test]
    fn normalisation() {
        assert_eq!(normalize("ABCD-efgh-IJKL"), "abcdefghijkl");
        assert_eq!(normalize(" abcd efgh\tijkl "), "abcdefghijkl");
        assert_eq!(normalize("abcdefghijkl"), "abcdefghijkl");
        assert_eq!(normalize("ab--cd"), "abcd");
    }

    #[test]
    fn matches_normalised_input_and_skips_used() {
        let k = key();
        let codes = vec!["abcd-efgh-ijkl".to_string(), "mnop-qrst-uvwx".to_string()];
        let mut config = config_for(&k, "id-1", &codes);
        assert_eq!(match_unused(&k, "id-1", "MNOP QRST UVWX", &config), Some(1));
        assert_eq!(match_unused(&k, "id-1", "abcdefghijkl", &config), Some(0));
        assert_eq!(match_unused(&k, "id-2", "abcd-efgh-ijkl", &config), None);
        assert_eq!(match_unused(&k, "id-1", "abcd-efgh-ijkm", &config), None);
        config.codes[0].used_at = Some("2026-11-13T00:00:00Z".into());
        assert_eq!(match_unused(&k, "id-1", "abcd-efgh-ijkl", &config), None);
        assert_eq!(match_unused(&k, "id-1", "mnop-qrst-uvwx", &config), Some(1));
    }

    #[test]
    fn config_serialises_to_the_stored_shape() {
        let config = config_for(&key(), "id-1", &["abcd-efgh-ijkl".to_string()]);
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["codes"][0]["used_at"], serde_json::Value::Null);
        assert_eq!(json["codes"][0]["mac"].as_str().unwrap().len(), 64);
    }
}
