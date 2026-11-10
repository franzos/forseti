//! Relying-party side of an upstream OIDC authorization code flow with a
//! public client: PKCE (S256), nonce, discovery, code exchange.
//!
//! The PKCE verifier and nonce are derived from `state` under a server-side
//! key, so the browser-held state cookie carries no secret.

pub(crate) mod discovery;
pub(crate) mod id_token;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use url::Url;

const KEY_LABEL: &[u8] = b"forseti::resource_claim_link::pkce::v1";

/// PKCE pair for one authorization request (RFC 7636).
pub(crate) struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// The HMAC key for [`derive_pkce`] and [`derive_nonce`], from
/// `state.cookie_secret`.
pub(crate) fn link_key(cookie_secret: &[u8]) -> [u8; 32] {
    crate::signed_cookie::derive_subkey(cookie_secret, KEY_LABEL)
}

fn derive(key: &[u8; 32], purpose: &[u8], state: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(purpose);
    mac.update(&[0]);
    mac.update(state.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Verifier (43 base64url characters) and its S256 challenge for `state`.
pub(crate) fn derive_pkce(key: &[u8; 32], state: &str) -> Pkce {
    let verifier = derive(key, b"pkce", state);
    let challenge = s256_challenge(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

/// The `nonce` sent with the authorization request for `state`.
pub(crate) fn derive_nonce(key: &[u8; 32], state: &str) -> String {
    derive(key, b"nonce", state)
}

fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `bytes` random bytes, base64url without padding.
pub(crate) fn random_urlsafe(bytes: usize) -> String {
    use rand::RngExt;
    let mut buf = vec![0u8; bytes];
    rand::rng().fill(&mut buf[..]);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Authorization request URL (OIDC Core 3.1.2.1). Query parameters already on
/// `endpoint` are kept unless they collide with one set here.
pub(crate) fn authorize_url(
    endpoint: &Url,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> Url {
    let params = [
        ("response_type", "code"),
        ("scope", "openid"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ];
    let kept: Vec<(String, String)> = endpoint
        .query_pairs()
        .filter(|(k, _)| !params.iter().any(|(p, _)| p == k))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut url = endpoint.clone();
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(kept)
        .extend_pairs(params);
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn s256_matches_rfc7636_appendix_b() {
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn derivation_is_deterministic_per_state() {
        let a = derive_pkce(&KEY, "state-a");
        let again = derive_pkce(&KEY, "state-a");
        assert_eq!(a.verifier, again.verifier);
        assert_eq!(a.challenge, again.challenge);
        assert_eq!(a.challenge, s256_challenge(&a.verifier));
        assert_eq!(derive_nonce(&KEY, "state-a"), derive_nonce(&KEY, "state-a"));
    }

    #[test]
    fn derivation_differs_across_states_keys_and_purposes() {
        let a = derive_pkce(&KEY, "state-a");
        let b = derive_pkce(&KEY, "state-b");
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(derive_nonce(&KEY, "state-a"), derive_nonce(&KEY, "state-b"));
        assert_ne!(a.verifier, derive_nonce(&KEY, "state-a"));
        assert_ne!(a.verifier, derive_pkce(&[8; 32], "state-a").verifier);
        assert_ne!(link_key(b"secret-one"), link_key(b"secret-two"));
    }

    #[test]
    fn verifier_meets_rfc7636_shape() {
        let v = derive_pkce(&KEY, "s").verifier;
        assert_eq!(v.len(), 43);
        assert!(
            v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        );
    }

    #[test]
    fn random_urlsafe_is_fresh() {
        let a = random_urlsafe(32);
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_urlsafe(32));
    }

    #[test]
    fn authorize_url_merges_existing_query() {
        let endpoint =
            Url::parse("https://git.example.com/login/oauth/authorize?tenant=a&scope=x&state=old")
                .unwrap();
        let url = authorize_url(
            &endpoint,
            "client 1",
            "https://id.example.com/settings/resource-claims/callback",
            "st",
            "nn",
            "ch",
        );
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let get = |name: &str| -> Vec<&str> {
            pairs
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .collect()
        };
        assert_eq!(url.path(), "/login/oauth/authorize");
        assert_eq!(get("tenant"), ["a"]);
        assert_eq!(get("scope"), ["openid"]);
        assert_eq!(get("state"), ["st"]);
        assert_eq!(get("response_type"), ["code"]);
        assert_eq!(get("client_id"), ["client 1"]);
        assert_eq!(
            get("redirect_uri"),
            ["https://id.example.com/settings/resource-claims/callback"]
        );
        assert_eq!(get("nonce"), ["nn"]);
        assert_eq!(get("code_challenge"), ["ch"]);
        assert_eq!(get("code_challenge_method"), ["S256"]);
    }

    #[test]
    fn authorize_url_without_query() {
        let endpoint = Url::parse("https://git.example.com/authorize").unwrap();
        let url = authorize_url(&endpoint, "c", "https://r.example/cb", "s", "n", "x");
        assert!(url.as_str().starts_with(
            "https://git.example.com/authorize?response_type=code&scope=openid&client_id=c&"
        ));
    }
}
