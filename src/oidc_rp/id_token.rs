//! ID token validation for the upstream code flow (OIDC Core 3.1.3.7).

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::discovery::{Jwk, Jwks};

const LEEWAY_SECS: i64 = 60;
const MAX_SUB_OCTETS: usize = 255;

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    #[serde(default)]
    azp: Option<String>,
    exp: i64,
    iat: i64,
    #[serde(default)]
    nonce: Option<String>,
}

fn usable(jwk: &Jwk, alg: Algorithm) -> bool {
    let (kty, crv, name) = match alg {
        Algorithm::RS256 => ("RSA", None, "RS256"),
        Algorithm::ES256 => ("EC", Some("P-256"), "ES256"),
        _ => return false,
    };
    jwk.kty == kty
        && (crv.is_none() || jwk.crv.as_deref() == crv)
        && jwk.use_.as_deref().is_none_or(|u| u == "sig")
        && jwk.alg.as_deref().is_none_or(|a| a == name)
}

fn select_key<'a>(
    jwks: &'a Jwks,
    alg: Algorithm,
    kid: Option<&str>,
) -> Result<&'a Jwk, &'static str> {
    let mut candidates = jwks
        .keys
        .iter()
        .filter(|k| usable(k, alg))
        .filter(|k| kid.is_none_or(|kid| k.kid.as_deref() == Some(kid)));
    match (candidates.next(), candidates.next()) {
        (Some(key), None) => Ok(key),
        (None, _) => Err("no matching signing key"),
        (Some(_), Some(_)) => Err("signing key is ambiguous"),
    }
}

fn decoding_key(jwk: &Jwk, alg: Algorithm) -> Result<DecodingKey, &'static str> {
    let key = match alg {
        Algorithm::RS256 => match (jwk.n.as_deref(), jwk.e.as_deref()) {
            (Some(n), Some(e)) => DecodingKey::from_rsa_components(n, e),
            _ => return Err("signing key is incomplete"),
        },
        _ => match (jwk.x.as_deref(), jwk.y.as_deref()) {
            (Some(x), Some(y)) => DecodingKey::from_ec_components(x, y),
            _ => return Err("signing key is incomplete"),
        },
    };
    key.map_err(|_| "signing key is invalid")
}

/// Validate `id_token` against the issuer's `jwks` and return its `sub`.
/// Accepts RS256 and ES256 (P-256) only; `now` is unix seconds.
pub(crate) fn verify(
    id_token: &str,
    jwks: &Jwks,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<String, &'static str> {
    let header = decode_header(id_token).map_err(|_| "ID token header is malformed")?;
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
        return Err("ID token algorithm not accepted");
    }
    let jwk = select_key(jwks, header.alg, header.kid.as_deref())?;
    let key = decoding_key(jwk, header.alg)?;

    // Time and audience checks run below against the caller's `now`.
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims = decode::<Claims>(id_token, &key, &validation)
        .map_err(|e| match e.kind() {
            ErrorKind::InvalidSignature => "ID token signature is invalid",
            _ => "ID token is malformed",
        })?
        .claims;

    if claims.iss != issuer {
        return Err("ID token issuer does not match");
    }
    let audiences = match &claims.aud {
        Audience::One(a) => std::slice::from_ref(a),
        Audience::Many(a) => a.as_slice(),
    };
    if !audiences.iter().any(|a| a == client_id) {
        return Err("ID token audience does not include the client");
    }
    match claims.azp.as_deref() {
        Some(azp) if azp != client_id => return Err("ID token azp is not the client"),
        None if audiences.len() > 1 => return Err("ID token has several audiences and no azp"),
        _ => {}
    }
    if claims.exp.saturating_add(LEEWAY_SECS) < now {
        return Err("ID token has expired");
    }
    if claims.iat > now.saturating_add(LEEWAY_SECS) {
        return Err("ID token was issued in the future");
    }
    let nonce_ok = claims
        .nonce
        .as_deref()
        .is_some_and(|n| bool::from(n.as_bytes().ct_eq(nonce.as_bytes())));
    if !nonce_ok {
        return Err("ID token nonce does not match");
    }
    if claims.sub.is_empty() || claims.sub.len() > MAX_SUB_OCTETS {
        return Err("ID token sub is empty or too long");
    }
    Ok(claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};

    const ISS: &str = "https://git.example.com/";
    const CLIENT: &str = "forseti-claims";
    const NONCE: &str = "n-0S6_WzA2Mj";
    const NOW: i64 = 1_800_000_000;

    // Test-only keys; never used outside this module.
    const RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDF+oOCuo8VOVaq
LO091+JSPajNhG36l7mjsV1qHLK0v2LpbFLJsZJVCueZ43dFJYblIJayZKbORdvx
JeyYFAnSNfC2QT1gUY1D0sKSU0oZPYKfdt4Xowe3KyivE9i9/RAZmjPkfIPAEXST
TqwNNAYRIrxYP2ojjfluTtG62+qDo3l/XpnrkiUbLw43YWhke4d0cfkD+2CY73KO
V1kRupn9QVVxF3M5bJbNbSXdmuOBy3lfmcoERXg/7XnRL7I0gEorVT65vJTjR4YO
u09CbIV01fN4VK+gzctqt1FG6PaftRqvZpL4B1PxsTKbePdUT0DFL4BhKgKzGlU0
FoSJohQbAgMBAAECggEADTiyaRviZzIGYX/jcvqSUgZI/qij255EW2HLqI4QFTE3
/tS7jYK168cn8LUqB4NsfvUS6Qj+5s44+QZBNIrOnav5YKcfAcWQe280QwLS80qS
LaD3mFQ6NUCgeRHjz4IM2Vjc17+gcyH3SzaUhXpZzfG6WFCr2u+4MNQe/mRdIE2b
GoAwgEf/XMPqsVk0am2y8JHSG/WWiQUHVtJvoRAqWxLvYXNwH0zQ2xp6WwK6r0vq
pMRPYr2wcLHF5P8yzREHumt1mwJ55hpeghsV3BQtGMIAyY200++ra5nmrgnm8nPV
gsGOToF4oVEVUiwyLBDwOQUWhwnulzbvl1qnEcYfiQKBgQDzCKECEFKpjmhBJbY1
vRxD2TJBMZeyk8J15Uy7jQe9z2psu+BpivlMNBsohi7YQsue+N5YbHnHV+BA8s9L
VBMNBJWWpqWMemKmocD9nM+fo3cjHsv/DRNNMxeselxxOAyzNLWcv7MIGGoab9pq
+N1T3qNbhcbI3fKdfBne/YNxFQKBgQDQioTDuPWnaEDWXs7iDrP0ayIDzn8bvVLe
Tb3Bnr9pRXP3FSBZ9rDZP1MGIwJCXDOa0q9V35f3OVvgE1S1AXFC/864hEH0Q2CF
a+YKiXFpYrDFKXvQ6QeqAMxj0ZH4UdhRs+Iw7vPLVsIqK7bk2QC4JvQNFdoirZ4b
cBhYyB7cbwKBgGPxjXzyx3uw85Cu+IKa9W+1dyQ2R8MJXrPrCyYptiBJluOGU6Az
pZe/6dc9bzBCL8h9YbqNSXs/2Rn8gGDi/z6gPwAIIhZmEgGijWH+RafJqmnH9W46
q1BZDYhBfZiVyys7JuCCORbAK4oZq4HIPASMjzNJDVl3ZJl8+oqoSJCNAoGBAI/f
YOUfD+ulE0ZSNmzjM+fmmZsCtdLPdQKFo+qWuPvJvM20N5OZjDz1YTQUpxRdRAUG
YYzfK5qWafpXm9Mc4aUVkurd5Bq++TJTVGvkkuff/JCppBBnFLCGyHv9M7Wb0Z/c
eKrF0FBy1JX/fri3tbVWunzknI/cM/4+Aa4OsqvlAoGAYhDBtRnImVSAfgNpXy0R
DYdE3meWvcsigL4A5ryE1L1eOwBQ/bOdicl2Ith9mvmTsDrYBLZQbULJc/G20pbK
QTamh3BbCGcy8hvejXyyAccRPCjZ2Ege7Bh4QF78xJJQdPMc1SKthIhnnR1zjrkY
oYPJJ+0gfUPJBVIr/ByVahY=
-----END PRIVATE KEY-----
";
    const RSA_N: &str = "xfqDgrqPFTlWqiztPdfiUj2ozYRt-pe5o7FdahyytL9i6WxSybGSVQrnmeN3RSWG5SCWsmSmzkXb8SXsmBQJ0jXwtkE9YFGNQ9LCklNKGT2Cn3beF6MHtysorxPYvf0QGZoz5HyDwBF0k06sDTQGESK8WD9qI435bk7Rutvqg6N5f16Z65IlGy8ON2FoZHuHdHH5A_tgmO9yjldZEbqZ_UFVcRdzOWyWzW0l3Zrjgct5X5nKBEV4P-150S-yNIBKK1U-ubyU40eGDrtPQmyFdNXzeFSvoM3LardRRuj2n7Uar2aS-AdT8bEym3j3VE9AxS-AYSoCsxpVNBaEiaIUGw";
    const RSA_E: &str = "AQAB";

    const EC_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZrQgzo6sWmSLK4zM
+HjwY2azXU8/WzNhqtTc+1LG6NmhRANCAATuV59boX6AtX9kfHI3ylWErroSm5cq
RllZIfBDxQA0QAiej2PmjYzxYaJLFFsvDIdaQqr3CcBwMr1yqVlXpwUZ
-----END PRIVATE KEY-----
";
    const EC_X: &str = "7lefW6F-gLV_ZHxyN8pVhK66EpuXKkZZWSHwQ8UANEA";
    const EC_Y: &str = "CJ6PY-aNjPFhoksUWy8Mh1pCqvcJwHAyvXKpWVenBRk";

    fn jwks(keys: Value) -> Jwks {
        serde_json::from_value(json!({ "keys": keys })).unwrap()
    }

    fn rsa_jwk(kid: &str) -> Value {
        json!({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": RSA_N, "e": RSA_E})
    }

    fn ec_jwk(kid: &str) -> Value {
        json!({"kty": "EC", "kid": kid, "crv": "P-256", "x": EC_X, "y": EC_Y})
    }

    fn default_jwks() -> Jwks {
        jwks(json!([rsa_jwk("rsa-1"), ec_jwk("ec-1")]))
    }

    fn claims() -> Value {
        json!({
            "iss": ISS,
            "sub": "42",
            "aud": CLIENT,
            "exp": NOW + 300,
            "iat": NOW,
            "nonce": NONCE,
        })
    }

    fn with(overrides: Value) -> Value {
        let mut c = claims();
        for (k, v) in overrides.as_object().unwrap() {
            if v.is_null() {
                c.as_object_mut().unwrap().remove(k);
            } else {
                c[k] = v.clone();
            }
        }
        c
    }

    fn mint(alg: Algorithm, kid: Option<&str>, claims: &Value) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);
        let key = match alg {
            Algorithm::RS256 => EncodingKey::from_rsa_pem(RSA_PEM.as_bytes()).unwrap(),
            Algorithm::ES256 => EncodingKey::from_ec_pem(EC_PEM.as_bytes()).unwrap(),
            _ => EncodingKey::from_secret(b"shared-secret"),
        };
        encode(&header, claims, &key).unwrap()
    }

    fn check(token: &str) -> Result<String, &'static str> {
        verify(token, &default_jwks(), ISS, CLIENT, NONCE, NOW)
    }

    #[test]
    fn rs256_happy_path() {
        assert_eq!(
            check(&mint(Algorithm::RS256, Some("rsa-1"), &claims())).unwrap(),
            "42"
        );
    }

    #[test]
    fn es256_happy_path() {
        assert_eq!(
            check(&mint(Algorithm::ES256, Some("ec-1"), &claims())).unwrap(),
            "42"
        );
    }

    #[test]
    fn missing_kid_uses_the_only_matching_key() {
        assert_eq!(
            check(&mint(Algorithm::RS256, None, &claims())).unwrap(),
            "42"
        );
        assert_eq!(
            check(&mint(Algorithm::ES256, None, &claims())).unwrap(),
            "42"
        );
    }

    #[test]
    fn missing_kid_with_several_matching_keys_refused() {
        let set = jwks(json!([rsa_jwk("rsa-1"), rsa_jwk("rsa-2"), ec_jwk("ec-1")]));
        let token = mint(Algorithm::RS256, None, &claims());
        assert_eq!(
            verify(&token, &set, ISS, CLIENT, NONCE, NOW).unwrap_err(),
            "signing key is ambiguous"
        );
        let token = mint(Algorithm::RS256, Some("rsa-2"), &claims());
        assert_eq!(verify(&token, &set, ISS, CLIENT, NONCE, NOW).unwrap(), "42");
    }

    #[test]
    fn unknown_kid_or_wrong_key_type_refused() {
        assert_eq!(
            check(&mint(Algorithm::RS256, Some("nope"), &claims())).unwrap_err(),
            "no matching signing key"
        );
        assert_eq!(
            check(&mint(Algorithm::ES256, Some("rsa-1"), &claims())).unwrap_err(),
            "no matching signing key"
        );
    }

    #[test]
    fn encryption_key_or_other_curve_not_used() {
        let enc = jwks(json!([{"kty": "RSA", "kid": "k", "use": "enc", "n": RSA_N, "e": RSA_E}]));
        let token = mint(Algorithm::RS256, Some("k"), &claims());
        assert!(verify(&token, &enc, ISS, CLIENT, NONCE, NOW).is_err());
        let p384 = jwks(json!([{"kty": "EC", "kid": "k", "crv": "P-384", "x": EC_X, "y": EC_Y}]));
        let token = mint(Algorithm::ES256, Some("k"), &claims());
        assert!(verify(&token, &p384, ISS, CLIENT, NONCE, NOW).is_err());
    }

    #[test]
    fn hs256_refused() {
        let token = mint(Algorithm::HS256, Some("rsa-1"), &claims());
        assert_eq!(
            check(&token).unwrap_err(),
            "ID token algorithm not accepted"
        );
    }

    #[test]
    fn alg_none_refused() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims().to_string());
        assert!(check(&format!("{header}.{payload}.")).is_err());
    }

    #[test]
    fn tampered_payload_refused() {
        let token = mint(Algorithm::RS256, Some("rsa-1"), &claims());
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        parts[1] = URL_SAFE_NO_PAD.encode(with(json!({"sub": "43"})).to_string());
        assert_eq!(
            check(&parts.join(".")).unwrap_err(),
            "ID token signature is invalid"
        );
    }

    #[test]
    fn wrong_issuer_refused() {
        for iss in ["https://git.example.com", "https://evil.example.com/"] {
            let token = mint(
                Algorithm::RS256,
                Some("rsa-1"),
                &with(json!({ "iss": iss })),
            );
            assert_eq!(check(&token).unwrap_err(), "ID token issuer does not match");
        }
    }

    #[test]
    fn wrong_audience_refused() {
        for aud in [json!("other"), json!(["other", "third"])] {
            let token = mint(
                Algorithm::RS256,
                Some("rsa-1"),
                &with(json!({ "aud": aud })),
            );
            assert_eq!(
                check(&token).unwrap_err(),
                "ID token audience does not include the client"
            );
        }
    }

    #[test]
    fn azp_rules() {
        let token = |c: Value| mint(Algorithm::RS256, Some("rsa-1"), &with(c));
        assert_eq!(
            check(&token(json!({"aud": [CLIENT, "other"]}))).unwrap_err(),
            "ID token has several audiences and no azp"
        );
        assert_eq!(
            check(&token(json!({"aud": [CLIENT, "other"], "azp": CLIENT}))).unwrap(),
            "42"
        );
        assert_eq!(
            check(&token(json!({"aud": [CLIENT, "other"], "azp": "other"}))).unwrap_err(),
            "ID token azp is not the client"
        );
        assert_eq!(
            check(&token(json!({"azp": "other"}))).unwrap_err(),
            "ID token azp is not the client"
        );
        assert_eq!(check(&token(json!({"aud": [CLIENT]}))).unwrap(), "42");
    }

    #[test]
    fn expiry_with_leeway() {
        let token = |exp: i64| {
            mint(
                Algorithm::RS256,
                Some("rsa-1"),
                &with(json!({ "exp": exp })),
            )
        };
        assert_eq!(check(&token(NOW - 30)).unwrap(), "42");
        assert_eq!(check(&token(NOW - 61)).unwrap_err(), "ID token has expired");
    }

    #[test]
    fn iat_in_the_future_refused() {
        let token = |iat: i64| {
            mint(
                Algorithm::RS256,
                Some("rsa-1"),
                &with(json!({ "iat": iat })),
            )
        };
        assert_eq!(check(&token(NOW + 30)).unwrap(), "42");
        assert_eq!(
            check(&token(NOW + 120)).unwrap_err(),
            "ID token was issued in the future"
        );
    }

    #[test]
    fn missing_required_claim_refused() {
        for drop in ["exp", "iat", "iss", "aud", "sub"] {
            let token = mint(
                Algorithm::RS256,
                Some("rsa-1"),
                &with(json!({ drop: null })),
            );
            assert_eq!(
                check(&token).unwrap_err(),
                "ID token is malformed",
                "{drop}"
            );
        }
    }

    #[test]
    fn bad_or_missing_nonce_refused() {
        for nonce in [json!("other"), json!(""), Value::Null] {
            let token = mint(
                Algorithm::ES256,
                Some("ec-1"),
                &with(json!({ "nonce": nonce })),
            );
            assert_eq!(check(&token).unwrap_err(), "ID token nonce does not match");
        }
    }

    #[test]
    fn sub_bounds() {
        let token = |sub: String| {
            mint(
                Algorithm::RS256,
                Some("rsa-1"),
                &with(json!({ "sub": sub })),
            )
        };
        assert!(check(&token(String::new())).is_err());
        assert!(check(&token("a".repeat(256))).is_err());
        assert_eq!(check(&token("a".repeat(255))).unwrap(), "a".repeat(255));
    }
}
