//! Compact RS256 JWTs: signed with the active key, verified against every stored key by `kid`;
//! and the claim sets of the ID and access tokens.

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, Header, Validation};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use super::keys::KeySet;
use super::{ACCESS_TOKEN_TTL_SECS, ID_TOKEN_TTL_SECS};
use crate::resource_registry::RESERVED_CLAIMS;

/// Claims the ID token sets itself; a snapshot key with one of these names is dropped.
const ID_TOKEN_SERVER_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "jti",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "at_hash",
    "azp",
];

/// What an ID token says besides the consent snapshot.
pub(crate) struct IdTokenFor<'a> {
    pub(crate) issuer: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) sid: &'a str,
    /// Unix seconds.
    pub(crate) auth_time: i64,
    pub(crate) acr: Option<&'a str>,
    pub(crate) amr: &'a [String],
    /// The authorization request's nonce; `None` on refresh (OIDC Core section 12.2).
    pub(crate) nonce: Option<&'a str>,
    pub(crate) access_token: &'a str,
    /// The consent handler's `id_token_session`.
    pub(crate) snapshot: &'a Map<String, Value>,
    /// Unix seconds.
    pub(crate) now: i64,
}

/// What an access token says besides the consent snapshot.
pub(crate) struct AccessTokenFor<'a> {
    pub(crate) issuer: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) audience: &'a [String],
    pub(crate) scope: &'a [String],
    pub(crate) acr: Option<&'a str>,
    pub(crate) grant_id: &'a str,
    /// The consent handler's `access_token_session`, carried under `ext`.
    pub(crate) snapshot: &'a Map<String, Value>,
    /// Registry claim names; the snapshot keys among them are copied to the top level too.
    pub(crate) promoted: &'a [String],
    /// Unix seconds.
    pub(crate) now: i64,
}

/// OIDC Core section 3.1.3.6: base64url of the left half of SHA-256 over the access token.
pub(crate) fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

pub(crate) fn id_token_claims(t: &IdTokenFor<'_>) -> Map<String, Value> {
    let mut claims = t.snapshot.clone();
    claims.retain(|k, _| !ID_TOKEN_SERVER_CLAIMS.contains(&k.as_str()));
    claims.insert("iss".into(), json!(t.issuer));
    claims.insert("sub".into(), json!(t.subject));
    claims.insert("aud".into(), json!([t.client_id]));
    claims.insert("iat".into(), json!(t.now));
    claims.insert("exp".into(), json!(t.now + ID_TOKEN_TTL_SECS));
    claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string()));
    claims.insert("auth_time".into(), json!(t.auth_time));
    claims.insert("sid".into(), json!(t.sid));
    claims.insert("at_hash".into(), json!(at_hash(t.access_token)));
    if let Some(acr) = t.acr {
        claims.insert("acr".into(), json!(acr));
    }
    if !t.amr.is_empty() {
        claims.insert("amr".into(), json!(t.amr));
    }
    if let Some(nonce) = t.nonce {
        claims.insert("nonce".into(), json!(nonce));
    }
    claims
}

/// RFC 9068 claims plus Hydra's `scp` and `ext`, so a resource server written against either
/// build reads the same token.
pub(crate) fn access_token_claims(t: &AccessTokenFor<'_>) -> Map<String, Value> {
    let mut claims: Map<String, Value> = t
        .snapshot
        .iter()
        .filter(|(k, _)| t.promoted.contains(k) && !RESERVED_CLAIMS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    claims.insert("iss".into(), json!(t.issuer));
    claims.insert("sub".into(), json!(t.subject));
    claims.insert("aud".into(), json!(t.audience));
    claims.insert("client_id".into(), json!(t.client_id));
    claims.insert("iat".into(), json!(t.now));
    claims.insert("nbf".into(), json!(t.now));
    claims.insert("exp".into(), json!(t.now + ACCESS_TOKEN_TTL_SECS));
    claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string()));
    claims.insert("scope".into(), json!(t.scope.join(" ")));
    claims.insert("scp".into(), json!(t.scope));
    claims.insert("ext".into(), Value::Object(t.snapshot.clone()));
    claims.insert("gid".into(), json!(t.grant_id));
    if let Some(acr) = t.acr {
        claims.insert("acr".into(), json!(acr));
    }
    claims
}

/// The `events` member of a logout token (Back-Channel Logout 1.0 section 2.4).
pub(crate) const BACKCHANNEL_LOGOUT_EVENT: &str =
    "http://schemas.openid.net/event/backchannel-logout";
pub(crate) const LOGOUT_TOKEN_TTL_SECS: i64 = 120;

/// Back-Channel Logout 1.0 section 2.4: both `sub` and `sid`, the `events` member, no `nonce`.
pub(crate) fn logout_token_claims(
    issuer: &str,
    client_id: &str,
    subject: &str,
    sid: &str,
    now: i64,
) -> Value {
    json!({
        "iss": issuer,
        "aud": [client_id],
        "iat": now,
        "exp": now + LOGOUT_TOKEN_TTL_SECS,
        "jti": uuid::Uuid::new_v4().to_string(),
        "sub": subject,
        "sid": sid,
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
    })
}

/// The `typ` header, so one kind of token cannot be passed off as another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Typ {
    /// `JWT`, for ID tokens.
    IdToken,
    /// `at+jwt`, for access tokens (RFC 9068 section 2.1).
    AccessToken,
    /// `logout+jwt`, for back-channel logout tokens (Back-Channel Logout 1.0 section 2.4).
    Logout,
}

impl Typ {
    fn as_str(self) -> &'static str {
        match self {
            Self::IdToken => "JWT",
            Self::AccessToken => "at+jwt",
            Self::Logout => "logout+jwt",
        }
    }
}

pub(crate) fn sign<T: Serialize>(keys: &KeySet, typ: Typ, claims: &T) -> Result<String> {
    let signing = keys.signing();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(signing.kid.clone());
    header.typ = Some(typ.as_str().to_string());
    jsonwebtoken::encode(&header, claims, &signing.key).map_err(|_| anyhow!("JWT signing failed"))
}

/// Claims of `token` once it carries `expected_typ`, an RS256 signature under the stored key its
/// `kid` names, `iss` equal to `issuer` and an unexpired `exp`. `audience`, when given, must be
/// in `aud`; `None` leaves `aud` unchecked.
pub(crate) fn verify(
    keys: &KeySet,
    issuer: &str,
    token: &str,
    expected_typ: Typ,
    audience: Option<&str>,
) -> Result<Value> {
    let failed = || anyhow!("JWT verification failed");
    let header = jsonwebtoken::decode_header(token).map_err(|_| anyhow!("malformed JWT header"))?;
    if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some(expected_typ.as_str()) {
        return Err(failed());
    }
    let key = header
        .kid
        .as_deref()
        .and_then(|kid| keys.verifying(kid))
        .ok_or_else(failed)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.validate_nbf = true;
    match audience {
        Some(aud) => {
            validation.set_audience(&[aud]);
            validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        }
        None => {
            validation.validate_aud = false;
            validation.set_required_spec_claims(&["exp", "iss"]);
        }
    }
    jsonwebtoken::decode::<Value>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|_| failed())
}

/// Claims of an ID token used as an `id_token_hint`: `typ` `JWT`, an RS256 signature under the
/// stored key its `kid` names and `iss` equal to `issuer`. `exp` is not checked: RP-Initiated
/// Logout 1.0 section 2 has the OP accept a hint "even when the exp time has passed".
pub(crate) fn verify_hint(keys: &KeySet, issuer: &str, token: &str) -> Result<Value> {
    let failed = || anyhow!("JWT verification failed");
    let header = jsonwebtoken::decode_header(token).map_err(|_| anyhow!("malformed JWT header"))?;
    if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some(Typ::IdToken.as_str()) {
        return Err(failed());
    }
    let key = header
        .kid
        .as_deref()
        .and_then(|kid| keys.verifying(kid))
        .ok_or_else(failed)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["iss"]);
    jsonwebtoken::decode::<Value>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|_| failed())
}

/// Whether `token`'s header names a `kid` that `keys` does not hold.
pub(crate) fn has_unknown_kid(keys: &KeySet, token: &str) -> bool {
    jsonwebtoken::decode_header(token)
        .ok()
        .and_then(|h| h.kid)
        .is_some_and(|kid| keys.verifying(&kid).is_none())
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use super::*;
    use crate::db::test_pool;
    use crate::oauth_native::keys::load_or_bootstrap;
    use crate::seal::SealKey;

    const ISSUER: &str = "https://issuer.test";
    const FUTURE: u64 = 4_000_000_000;

    async fn key_set() -> KeySet {
        load_or_bootstrap(&test_pool().await, &SealKey::new(&[1; 32]))
            .await
            .unwrap()
    }

    fn claims() -> Value {
        json!({ "iss": ISSUER, "sub": "s-1", "aud": "client-1", "exp": FUTURE })
    }

    fn id_token_verify(keys: &KeySet, token: &str) -> Result<Value> {
        verify(keys, ISSUER, token, Typ::IdToken, Some("client-1"))
    }

    fn assert_refused(result: Result<Value>) {
        assert_eq!(result.unwrap_err().to_string(), "JWT verification failed");
    }

    /// `claims` signed by the active key under `header`, bypassing [`sign`].
    fn encode_raw(keys: &KeySet, header: &Header, claims: &Value) -> String {
        jsonwebtoken::encode(header, claims, &keys.signing().key).unwrap()
    }

    fn rs256_header(keys: &KeySet) -> Header {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(keys.signing().kid.clone());
        header
    }

    #[tokio::test]
    async fn sign_then_verify() {
        let keys = key_set().await;
        let token = sign(&keys, Typ::IdToken, &claims()).unwrap();
        assert_eq!(id_token_verify(&keys, &token).unwrap(), claims());
        let token = sign(&keys, Typ::AccessToken, &claims()).unwrap();
        assert_eq!(
            verify(&keys, ISSUER, &token, Typ::AccessToken, None).unwrap(),
            claims()
        );
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some(keys.signing().kid.as_str()));
    }

    #[tokio::test]
    async fn typ_is_the_one_asked_for() {
        let keys = key_set().await;
        for (typ, header_typ) in [(Typ::IdToken, "JWT"), (Typ::AccessToken, "at+jwt")] {
            let token = sign(&keys, typ, &claims()).unwrap();
            let header = jsonwebtoken::decode_header(&token).unwrap();
            assert_eq!(header.typ.as_deref(), Some(header_typ));
        }
    }

    #[tokio::test]
    async fn one_typ_is_not_accepted_as_the_other() {
        let keys = key_set().await;
        let id_token = sign(&keys, Typ::IdToken, &claims()).unwrap();
        assert_refused(verify(&keys, ISSUER, &id_token, Typ::AccessToken, None));
        let access_token = sign(&keys, Typ::AccessToken, &claims()).unwrap();
        assert_refused(verify(&keys, ISSUER, &access_token, Typ::IdToken, None));
        let mut header = rs256_header(&keys);
        header.typ = None;
        assert_refused(id_token_verify(
            &keys,
            &encode_raw(&keys, &header, &claims()),
        ));
    }

    #[tokio::test]
    async fn issuer_is_required_and_pinned() {
        let keys = key_set().await;
        let token = sign(&keys, Typ::IdToken, &claims()).unwrap();
        assert_refused(verify(
            &keys,
            "https://other.test",
            &token,
            Typ::IdToken,
            Some("client-1"),
        ));
        let mut no_iss = claims();
        no_iss.as_object_mut().unwrap().remove("iss");
        let token = sign(&keys, Typ::IdToken, &no_iss).unwrap();
        assert_refused(id_token_verify(&keys, &token));
    }

    #[tokio::test]
    async fn exp_is_required_and_enforced() {
        let keys = key_set().await;
        let mut no_exp = claims();
        no_exp.as_object_mut().unwrap().remove("exp");
        let token = sign(&keys, Typ::IdToken, &no_exp).unwrap();
        assert_refused(id_token_verify(&keys, &token));
        let mut expired = claims();
        expired["exp"] = json!(jsonwebtoken::get_current_timestamp() - 3600);
        let token = sign(&keys, Typ::IdToken, &expired).unwrap();
        assert_refused(id_token_verify(&keys, &token));
    }

    #[tokio::test]
    async fn audience_is_checked_when_given() {
        let keys = key_set().await;
        let token = sign(&keys, Typ::IdToken, &claims()).unwrap();
        assert_refused(verify(
            &keys,
            ISSUER,
            &token,
            Typ::IdToken,
            Some("client-2"),
        ));
        let mut no_aud = claims();
        no_aud.as_object_mut().unwrap().remove("aud");
        let token = sign(&keys, Typ::IdToken, &no_aud).unwrap();
        assert_refused(id_token_verify(&keys, &token));
        assert!(verify(&keys, ISSUER, &token, Typ::IdToken, None).is_ok());
    }

    #[tokio::test]
    async fn tampered_signature_fails() {
        let keys = key_set().await;
        let token = sign(&keys, Typ::IdToken, &claims()).unwrap();
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let mut signature = signature.as_bytes().to_vec();
        let mid = signature.len() / 2;
        signature[mid] = if signature[mid] == b'A' { b'B' } else { b'A' };
        let tampered = format!("{signed}.{}", String::from_utf8(signature).unwrap());
        assert_refused(id_token_verify(&keys, &tampered));
    }

    #[tokio::test]
    async fn tampered_claims_fail() {
        let keys = key_set().await;
        let token = sign(&keys, Typ::IdToken, &claims()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut forged = claims();
        forged["sub"] = json!("admin");
        let forged = URL_SAFE_NO_PAD.encode(forged.to_string());
        parts[1] = &forged;
        assert_refused(id_token_verify(&keys, &parts.join(".")));
    }

    #[tokio::test]
    async fn a_malformed_header_has_a_fixed_message() {
        let keys = key_set().await;
        let err = id_token_verify(&keys, "not-a-jwt").unwrap_err();
        assert_eq!(err.to_string(), "malformed JWT header");
    }

    #[tokio::test]
    async fn algs_other_than_rs256_fail() {
        let keys = key_set().await;
        let kid = keys.signing().kid.clone();
        let jwk = keys.public_jwks().remove(0);

        let header =
            URL_SAFE_NO_PAD.encode(json!({ "alg": "none", "typ": "JWT", "kid": kid }).to_string());
        let body = URL_SAFE_NO_PAD.encode(claims().to_string());
        assert!(id_token_verify(&keys, &format!("{header}.{body}.")).is_err());

        let mut hs = Header::new(Algorithm::HS256);
        hs.kid = Some(kid.clone());
        for secret in [jwk.to_string(), jwk["n"].as_str().unwrap().to_string()] {
            let token =
                jsonwebtoken::encode(&hs, &claims(), &EncodingKey::from_secret(secret.as_bytes()))
                    .unwrap();
            assert_refused(id_token_verify(&keys, &token));
        }

        let mut rs384 = rs256_header(&keys);
        rs384.alg = Algorithm::RS384;
        assert_refused(id_token_verify(
            &keys,
            &encode_raw(&keys, &rs384, &claims()),
        ));
    }

    const NOW: i64 = 1_800_000_000;

    fn snapshot(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn id_input<'a>(snap: &'a Map<String, Value>, amr: &'a [String]) -> IdTokenFor<'a> {
        IdTokenFor {
            issuer: ISSUER,
            subject: "alice",
            client_id: "app",
            sid: "sid-1",
            auth_time: NOW - 60,
            acr: Some("aal1"),
            amr,
            nonce: Some("n-1"),
            access_token: "an-access-token",
            snapshot: snap,
            now: NOW,
        }
    }

    fn access_input<'a>(
        snap: &'a Map<String, Value>,
        audience: &'a [String],
        scope: &'a [String],
        promoted: &'a [String],
    ) -> AccessTokenFor<'a> {
        AccessTokenFor {
            issuer: ISSUER,
            subject: "alice",
            client_id: "app",
            audience,
            scope,
            acr: Some("aal1"),
            grant_id: "grant-1",
            snapshot: snap,
            promoted,
            now: NOW,
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// `claims` without `jti`, after checking it is a UUID.
    fn without_jti(mut claims: Map<String, Value>) -> Map<String, Value> {
        let jti = claims.remove("jti").unwrap();
        assert!(
            uuid::Uuid::parse_str(jti.as_str().unwrap()).is_ok(),
            "{jti}"
        );
        claims
    }

    #[test]
    fn at_hash_is_the_left_half_of_sha256() {
        let token = "an-access-token";
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(&digest.as_ref()[..16]);
        assert_eq!(at_hash(token), expected);
        assert_eq!(at_hash(token).len(), 22);
    }

    #[test]
    fn id_token_claim_shape() {
        let snap = snapshot(json!({"email": "alice@example.com", "email_verified": true}));
        let amr = strings(&["pwd"]);
        let claims = without_jti(id_token_claims(&id_input(&snap, &amr)));
        assert_eq!(
            Value::Object(claims),
            json!({
                "iss": ISSUER,
                "sub": "alice",
                "aud": ["app"],
                "iat": NOW,
                "exp": NOW + ID_TOKEN_TTL_SECS,
                "auth_time": NOW - 60,
                "sid": "sid-1",
                "acr": "aal1",
                "amr": ["pwd"],
                "nonce": "n-1",
                "at_hash": at_hash("an-access-token"),
                "email": "alice@example.com",
                "email_verified": true,
            })
        );
    }

    #[test]
    fn id_token_on_refresh_has_no_nonce_and_omits_empty_amr() {
        let snap = Map::new();
        let mut input = id_input(&snap, &[]);
        input.nonce = None;
        input.acr = None;
        let claims = id_token_claims(&input);
        for absent in ["nonce", "amr", "acr"] {
            assert!(!claims.contains_key(absent), "{absent}");
        }
        assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
    }

    #[test]
    fn id_token_server_claims_win_over_the_snapshot() {
        let mut collide = Map::new();
        for name in ID_TOKEN_SERVER_CLAIMS {
            collide.insert((*name).to_string(), json!("forged"));
        }
        collide.insert("name".to_string(), json!("Alice"));
        let amr = strings(&["pwd"]);
        let mut input = id_input(&collide, &amr);
        input.nonce = None;
        input.acr = None;
        let claims = id_token_claims(&input);
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["aud"], json!(["app"]));
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["sid"], "sid-1");
        assert_eq!(claims["amr"], json!(["pwd"]));
        assert_eq!(claims["at_hash"], at_hash("an-access-token"));
        assert_ne!(claims["jti"], "forged");
        for absent in ["nonce", "acr", "azp"] {
            assert!(!claims.contains_key(absent), "{absent}");
        }
        assert_eq!(claims["name"], "Alice");
    }

    #[test]
    fn access_token_claim_shape() {
        let snap = snapshot(json!({"forgejo_aud": "u:7", "note": "operator only"}));
        let (audience, scope) = (
            strings(&["https://api.example"]),
            strings(&["openid", "email"]),
        );
        let promoted = strings(&["forgejo_aud", "team"]);
        let claims = without_jti(access_token_claims(&access_input(
            &snap, &audience, &scope, &promoted,
        )));
        assert_eq!(
            Value::Object(claims),
            json!({
                "iss": ISSUER,
                "sub": "alice",
                "aud": ["https://api.example"],
                "client_id": "app",
                "iat": NOW,
                "nbf": NOW,
                "exp": NOW + ACCESS_TOKEN_TTL_SECS,
                "scope": "openid email",
                "scp": ["openid", "email"],
                "acr": "aal1",
                "gid": "grant-1",
                "ext": {"forgejo_aud": "u:7", "note": "operator only"},
                "forgejo_aud": "u:7",
            })
        );
    }

    #[test]
    fn access_token_audience_is_an_array_even_when_empty() {
        let snap = Map::new();
        let claims = access_token_claims(&access_input(&snap, &[], &[], &[]));
        assert_eq!(claims["aud"], json!([]));
        assert_eq!(claims["scope"], "");
        assert_eq!(claims["ext"], json!({}));
    }

    #[test]
    fn promotion_never_overrides_a_server_claim() {
        let mut snap = Map::new();
        for name in RESERVED_CLAIMS {
            snap.insert((*name).to_string(), json!("forged"));
        }
        snap.insert("forgejo_aud".to_string(), json!("u:7"));
        let promoted: Vec<String> = RESERVED_CLAIMS
            .iter()
            .map(|s| (*s).to_string())
            .chain(["forgejo_aud".to_string()])
            .collect();
        let (audience, scope) = (strings(&["https://api.example"]), strings(&["openid"]));
        let mut input = access_input(&snap, &audience, &scope, &promoted);
        input.acr = None;
        let claims = access_token_claims(&input);
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["client_id"], "app");
        assert_eq!(claims["scope"], "openid");
        assert_eq!(claims["gid"], "grant-1");
        assert_eq!(claims["aud"], json!(["https://api.example"]));
        assert_ne!(claims["jti"], "forged");
        for absent in [
            "acr",
            "amr",
            "sid",
            "auth_time",
            "azp",
            "typ",
            "nonce",
            "at_hash",
        ] {
            assert!(!claims.contains_key(absent), "{absent}");
        }
        assert_eq!(claims["forgejo_aud"], "u:7");
        assert_eq!(claims["ext"]["sub"], "forged");
    }

    #[tokio::test]
    async fn minted_tokens_carry_their_typ_and_verify() {
        let keys = key_set().await;
        let snap = Map::new();
        let (audience, scope) = (strings(&[]), strings(&["openid"]));
        let mut access = access_token_claims(&access_input(&snap, &audience, &scope, &[]));
        let now = i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap();
        access.insert("iat".into(), json!(now));
        access.insert("nbf".into(), json!(now));
        access.insert("exp".into(), json!(now + ACCESS_TOKEN_TTL_SECS));
        let token = sign(&keys, Typ::AccessToken, &access).unwrap();
        assert_eq!(
            jsonwebtoken::decode_header(&token).unwrap().typ.as_deref(),
            Some("at+jwt")
        );
        assert_eq!(
            verify(&keys, ISSUER, &token, Typ::AccessToken, None).unwrap(),
            Value::Object(access)
        );
        assert_refused(verify(&keys, ISSUER, &token, Typ::IdToken, None));
    }

    #[tokio::test]
    async fn an_unknown_kid_is_one_the_set_lacks() {
        let keys = key_set().await;
        let other = key_set().await;
        assert!(!has_unknown_kid(
            &keys,
            &sign(&keys, Typ::IdToken, &claims()).unwrap()
        ));
        assert!(has_unknown_kid(
            &keys,
            &sign(&other, Typ::IdToken, &claims()).unwrap()
        ));
        let mut header = rs256_header(&keys);
        header.kid = None;
        assert!(!has_unknown_kid(
            &keys,
            &encode_raw(&keys, &header, &claims())
        ));
        assert!(!has_unknown_kid(&keys, "not-a-jwt"));
    }

    #[tokio::test]
    async fn unknown_kid_fails() {
        let keys = key_set().await;
        let other = key_set().await;
        let token = sign(&other, Typ::IdToken, &claims()).unwrap();
        assert_refused(id_token_verify(&keys, &token));

        let mut header = rs256_header(&keys);
        header.kid = Some("unknown".into());
        assert_refused(id_token_verify(
            &keys,
            &encode_raw(&keys, &header, &claims()),
        ));

        header.kid = None;
        assert_refused(id_token_verify(
            &keys,
            &encode_raw(&keys, &header, &claims()),
        ));
    }
}
