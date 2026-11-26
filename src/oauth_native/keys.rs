//! RS256 signing keys, generated on first boot and stored sealed in `oauth_signing_keys`.

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use diesel::prelude::*;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::backend::oauth::JwkSummary;
use crate::db::{DbPool, now_rfc3339};
use crate::db_interact;
use crate::schema::oauth_signing_keys;
use crate::seal::SealKey;

pub(crate) const ALG: &str = "RS256";
const SEAL_PURPOSE: &str = "oauth-signing-key";
const ACTIVE: &str = "active";
const RETIRED: &str = "retired";
const NO_ACTIVE_KEY: &str = "oauth_signing_keys has no active key";

#[derive(Queryable, Insertable)]
#[diesel(table_name = oauth_signing_keys)]
struct Row {
    kid: String,
    alg: String,
    public_jwk: String,
    private_sealed: String,
    status: String,
    created_at: String,
    retired_at: Option<String>,
}

/// The key new tokens are signed with.
pub(crate) struct SigningKey {
    pub(crate) kid: String,
    pub(crate) key: EncodingKey,
}

struct VerifyingKey {
    kid: String,
    n: String,
    e: String,
    key: DecodingKey,
}

/// Every stored key, public halves only, plus the private half of the active one.
pub(crate) struct KeySet {
    signing: SigningKey,
    verifying: Vec<VerifyingKey>,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("signing_kid", &self.signing.kid)
            .field(
                "kids",
                &self.verifying.iter().map(|k| &k.kid).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl KeySet {
    pub(crate) fn signing(&self) -> &SigningKey {
        &self.signing
    }

    pub(crate) fn verifying(&self, kid: &str) -> Option<&DecodingKey> {
        self.verifying.iter().find(|k| k.kid == kid).map(|k| &k.key)
    }

    /// The public JWK of every stored key, active and retired.
    pub(crate) fn public_jwks(&self) -> Vec<Value> {
        self.verifying
            .iter()
            .map(|k| public_jwk(&k.kid, &k.n, &k.e))
            .collect()
    }

    /// Every `kid`, sorted.
    pub(crate) fn kids(&self) -> Vec<&str> {
        let mut kids: Vec<&str> = self.verifying.iter().map(|k| k.kid.as_str()).collect();
        kids.sort_unstable();
        kids
    }

    /// The same keys as [`Self::public_jwks`], as `/admin/configuration` lists them.
    pub(crate) fn summaries(&self) -> Vec<JwkSummary> {
        self.verifying
            .iter()
            .map(|k| JwkSummary {
                kid: k.kid.clone(),
                alg: ALG.to_string(),
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
            })
            .collect()
    }
}

/// The stored keys; on a table without an active key, one is generated and inserted first.
/// Every row must open under `seal` and match its `kid`, retired ones included.
pub(crate) async fn load_or_bootstrap(db: &DbPool, seal: &SealKey) -> Result<KeySet> {
    if let Some(keys) = key_set(&load_rows(db).await?, seal)? {
        return Ok(keys);
    }
    let row = new_row(&generate().await?, seal)?;
    // A concurrent boot that inserted first trips the partial unique index; its key is the one to use.
    db_interact!(db, |c| {
        diesel::insert_into(oauth_signing_keys::table)
            .values(&row)
            .on_conflict_do_nothing()
            .execute(c)
    })?;
    load(db, seal).await
}

/// The stored keys, under the same checks as [`load_or_bootstrap`]; generates nothing.
pub(crate) async fn load(db: &DbPool, seal: &SealKey) -> Result<KeySet> {
    key_set(&load_rows(db).await?, seal)?.context(NO_ACTIVE_KEY)
}

/// Every stored `kid`, without opening any key.
pub(crate) async fn stored_kids(db: &DbPool) -> Result<Vec<String>> {
    Ok(db_interact!(db, |c| {
        oauth_signing_keys::table
            .select(oauth_signing_keys::kid)
            .load::<String>(c)
    })?)
}

/// The `kid`s a [`rotate`] retired and inserted.
#[derive(Debug)]
pub(crate) struct Rotated {
    pub(crate) retired: String,
    pub(crate) active: String,
}

/// Retires the active key and inserts a new one in one transaction. Refuses when a stored key
/// does not open under `seal`, or when the active key changed since it was read.
pub(crate) async fn rotate(db: &DbPool, seal: &SealKey) -> Result<Rotated> {
    let current = key_set(&load_rows(db).await?, seal)
        .context("refusing to rotate")?
        .context(NO_ACTIVE_KEY)?;
    let retired = current.signing.kid.clone();
    let row = new_row(&generate().await?, seal)?;
    let active = row.kid.clone();
    swap_active(db, retired.clone(), row).await?;
    Ok(Rotated { retired, active })
}

async fn swap_active(db: &DbPool, retired: String, row: Row) -> Result<()> {
    let swapped = crate::serialized_txn!(db, bool, diesel::result::Error, |c| {
        let changed = diesel::update(
            oauth_signing_keys::table
                .find(&retired)
                .filter(oauth_signing_keys::status.eq(ACTIVE)),
        )
        .set((
            oauth_signing_keys::status.eq(RETIRED),
            oauth_signing_keys::retired_at.eq(Some(now_rfc3339())),
        ))
        .execute(c)?;
        if changed == 0 {
            return Ok(false);
        }
        diesel::insert_into(oauth_signing_keys::table)
            .values(&row)
            .execute(c)?;
        Ok(true)
    });
    match swapped {
        Ok(true) => Ok(()),
        Ok(false)
        | Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => bail!("another rotation changed the active OAuth signing key first; nothing changed"),
        Err(e) => Err(e).context("store the rotated OAuth signing key"),
    }
}

async fn generate() -> Result<KeyPair> {
    tokio::task::spawn_blocking(|| KeyPair::generate(KeySize::Rsa2048))
        .await
        .context("RSA key generation task")?
        .map_err(|_| anyhow!("generate an RSA-2048 signing key"))
}

async fn load_rows(db: &DbPool) -> Result<Vec<Row>> {
    Ok(db_interact!(db, |c| {
        oauth_signing_keys::table
            .order((
                oauth_signing_keys::created_at.desc(),
                oauth_signing_keys::kid,
            ))
            .load::<Row>(c)
    })?)
}

/// `n` and `e` of a key pair, base64url as in a JWK.
fn components(pair: &KeyPair) -> (String, String) {
    let public = pair.public_key();
    (
        URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
        URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()),
    )
}

fn new_row(pair: &KeyPair, seal: &SealKey) -> Result<Row> {
    let (n, e) = components(pair);
    let kid = thumbprint(&n, &e);
    let pkcs8 = pair
        .as_der()
        .map_err(|_| anyhow!("encode the signing key as PKCS#8"))?;
    Ok(Row {
        private_sealed: seal.seal(SEAL_PURPOSE, &kid, pkcs8.as_ref()),
        public_jwk: public_jwk(&kid, &n, &e).to_string(),
        kid,
        alg: ALG.to_string(),
        status: ACTIVE.to_string(),
        created_at: now_rfc3339(),
        retired_at: None,
    })
}

/// `None` when every row opens but none is active.
fn key_set(rows: &[Row], seal: &SealKey) -> Result<Option<KeySet>> {
    let mut signing = None;
    let mut verifying = Vec::with_capacity(rows.len());
    for row in rows {
        let (key, encoding) = open_row(row, seal)?;
        if let Some(key) = encoding {
            signing = Some(SigningKey {
                kid: row.kid.clone(),
                key,
            });
        }
        verifying.push(key);
    }
    Ok(signing.map(|signing| KeySet { signing, verifying }))
}

/// The public half derived from the unsealed private key, and the private half for the active row.
fn open_row(row: &Row, seal: &SealKey) -> Result<(VerifyingKey, Option<EncodingKey>)> {
    if row.alg != ALG {
        bail!(
            "OAuth signing key {:?} has unsupported alg {:?}",
            row.kid,
            row.alg
        );
    }
    let pkcs8 = seal
        .open(SEAL_PURPOSE, &row.kid, &row.private_sealed)
        .ok_or_else(|| {
            anyhow!(
                "the sealed OAuth signing key {:?} does not open under the current \
                 [security].cookie_secret; restore the cookie secret it was sealed with",
                row.kid
            )
        })?;
    let pair = KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| anyhow!("OAuth signing key {:?} is not an RSA PKCS#8 key", row.kid))?;
    let (n, e) = components(&pair);
    if thumbprint(&n, &e) != row.kid {
        bail!("OAuth signing key {:?} does not match its kid", row.kid);
    }
    let key = DecodingKey::from_rsa_components(&n, &e)
        .map_err(|_| anyhow!("OAuth signing key {:?} has an unusable public key", row.kid))?;
    let encoding = if row.status == ACTIVE {
        Some(encoding_key(&pkcs8)?)
    } else {
        None
    };
    Ok((
        VerifyingKey {
            kid: row.kid.clone(),
            n,
            e,
            key,
        },
        encoding,
    ))
}

fn public_jwk(kid: &str, n: &str, e: &str) -> Value {
    json!({ "kty": "RSA", "n": n, "e": e, "kid": kid, "alg": ALG, "use": "sig" })
}

/// RFC 7638 section 3.2: the required RSA members in lexicographic order, no whitespace.
fn thumbprint(n: &str, e: &str) -> String {
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

// jsonwebtoken signs RSA from PKCS#1 DER only; its PEM reader unwraps a PKCS#8 `PRIVATE KEY` to that.
fn encoding_key(pkcs8: &[u8]) -> Result<EncodingKey> {
    let body = STANDARD.encode(pkcs8);
    let mut pem = String::with_capacity(body.len() + body.len() / 64 + 64);
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    EncodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|_| anyhow!("the OAuth signing key is not an RSA PKCS#8 key"))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, Header, Validation};

    use super::*;
    use crate::db::test_pool;

    /// The Postgres tests share one `oauth_signing_keys` table and clear it.
    static POSTGRES_KEYS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn seal_key(byte: u8) -> SealKey {
        SealKey::new(&[byte; 32])
    }

    /// Rows in the table, and how many of them are active.
    async fn counts(db: &DbPool) -> (i64, i64) {
        async fn run(db: &DbPool) -> Result<(i64, i64)> {
            let all = db_interact!(db, |c| {
                oauth_signing_keys::table.count().get_result::<i64>(c)
            })?;
            let active = db_interact!(db, |c| {
                oauth_signing_keys::table
                    .filter(oauth_signing_keys::status.eq(ACTIVE))
                    .count()
                    .get_result::<i64>(c)
            })?;
            Ok((all, active))
        }
        run(db).await.unwrap()
    }

    async fn clear(db: &DbPool) {
        async fn run(db: &DbPool) -> Result<usize> {
            Ok(db_interact!(db, |c| {
                diesel::delete(oauth_signing_keys::table).execute(c)
            })?)
        }
        run(db).await.unwrap();
    }

    async fn retire(db: &DbPool, kid: &str) {
        async fn run(db: &DbPool, kid: String) -> Result<usize> {
            Ok(db_interact!(db, |c| {
                diesel::update(oauth_signing_keys::table.find(kid))
                    .set((
                        oauth_signing_keys::status.eq("retired"),
                        oauth_signing_keys::retired_at.eq(Some(now_rfc3339())),
                    ))
                    .execute(c)
            })?)
        }
        assert_eq!(run(db, kid.to_string()).await.unwrap(), 1);
    }

    async fn insert(db: &DbPool, row: Row) {
        async fn run(db: &DbPool, row: Row) -> Result<usize> {
            Ok(db_interact!(db, |c| {
                diesel::insert_into(oauth_signing_keys::table)
                    .values(&row)
                    .execute(c)
            })?)
        }
        assert_eq!(run(db, row).await.unwrap(), 1);
    }

    async fn set_public_jwk(db: &DbPool, kid: &str, jwk: String) {
        async fn run(db: &DbPool, kid: String, jwk: String) -> Result<usize> {
            Ok(db_interact!(db, |c| {
                diesel::update(oauth_signing_keys::table.find(kid))
                    .set(oauth_signing_keys::public_jwk.eq(jwk))
                    .execute(c)
            })?)
        }
        assert_eq!(run(db, kid.to_string(), jwk).await.unwrap(), 1);
    }

    fn retired_row(seal: &SealKey) -> Row {
        let mut row = new_row(&KeyPair::generate(KeySize::Rsa2048).unwrap(), seal).unwrap();
        row.status = "retired".to_string();
        row.retired_at = Some(now_rfc3339());
        row
    }

    async fn bootstrap_concurrently(pools: Vec<DbPool>) -> Vec<String> {
        let tasks: Vec<_> = pools
            .into_iter()
            .map(|db| {
                tokio::spawn(async move {
                    load_or_bootstrap(&db, &seal_key(1))
                        .await
                        .unwrap()
                        .signing()
                        .kid
                        .clone()
                })
            })
            .collect();
        let mut kids = Vec::new();
        for task in tasks {
            kids.push(task.await.unwrap());
        }
        kids
    }

    #[test]
    fn rsa_pkcs8_signs_rs256_and_verifies_from_public_components() {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = pair.as_der().unwrap();
        let header = Header::new(Algorithm::RS256);
        let claims = json!({ "sub": "s", "exp": 4_000_000_000_u64 });

        let from_der = EncodingKey::from_rsa_der(pkcs8.as_ref());
        assert!(jsonwebtoken::encode(&header, &claims, &from_der).is_err());

        let token =
            jsonwebtoken::encode(&header, &claims, &encoding_key(pkcs8.as_ref()).unwrap()).unwrap();
        let public = pair.public_key();
        let n = URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero());
        let e = URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero());
        let key = DecodingKey::from_rsa_components(&n, &e).unwrap();
        let data = jsonwebtoken::decode::<Value>(&token, &key, &Validation::new(Algorithm::RS256))
            .unwrap();
        assert_eq!(data.claims, claims);
    }

    #[tokio::test]
    async fn bootstrap_creates_one_active_key_and_reloads_it() {
        let db = test_pool().await;
        let first = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        assert_eq!(counts(&db).await, (1, 1));
        let second = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        assert_eq!(second.signing().kid, first.signing().kid);
        assert_eq!(counts(&db).await, (1, 1));
    }

    #[tokio::test]
    async fn kid_is_the_rfc7638_thumbprint() {
        let db = test_pool().await;
        let keys = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let [jwk] = keys.public_jwks().try_into().unwrap();
        let parsed: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        assert_eq!(
            parsed
                .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
                .unwrap(),
            keys.signing().kid
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_bootstrap_ends_with_one_key() {
        let db = test_pool().await;
        let mut kids = bootstrap_concurrently(vec![db.clone(); 4]).await;
        kids.sort();
        kids.dedup();
        assert_eq!(kids.len(), 1);
        assert_eq!(counts(&db).await, (1, 1));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
    async fn concurrent_bootstrap_ends_with_one_key_on_postgres() {
        let _serial = POSTGRES_KEYS.lock().await;
        let db = crate::db::test_postgres_pool().await;
        clear(&db).await;
        let mut pools = Vec::new();
        for _ in 0..4 {
            pools.push(crate::db::test_postgres_pool().await);
        }
        let mut kids = bootstrap_concurrently(pools).await;
        let after = counts(&db).await;
        clear(&db).await;
        kids.sort();
        kids.dedup();
        assert_eq!(kids.len(), 1);
        assert_eq!(after, (1, 1));
    }

    #[tokio::test]
    async fn wrong_secret_is_an_error_and_regenerates_nothing() {
        let db = test_pool().await;
        let keys = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let err = load_or_bootstrap(&db, &seal_key(2)).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("does not open under the current [security].cookie_secret"));
        assert!(msg.contains(&keys.signing().kid));
        assert_eq!(counts(&db).await, (1, 1));
    }

    #[tokio::test]
    async fn jwks_has_public_members_only() {
        let db = test_pool().await;
        let keys = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        for jwk in keys.public_jwks() {
            let mut members: Vec<_> = jwk.as_object().unwrap().keys().cloned().collect();
            members.sort();
            assert_eq!(members, ["alg", "e", "kid", "kty", "n", "use"]);
            assert_eq!(jwk["kty"], "RSA");
            assert_eq!(jwk["alg"], "RS256");
            assert_eq!(jwk["use"], "sig");
        }
    }

    #[tokio::test]
    async fn retired_keys_stay_published() {
        let db = test_pool().await;
        let old = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let old_kid = old.signing().kid.clone();
        retire(&db, &old_kid).await;
        let new = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        assert_ne!(new.signing().kid, old_kid);
        assert!(new.verifying(&old_kid).is_some());
        assert_eq!(new.public_jwks().len(), 2);
        assert_eq!(counts(&db).await, (2, 1));
    }

    #[tokio::test]
    async fn a_retired_row_with_a_foreign_public_key_and_no_private_key_fails_the_load() {
        let db = test_pool().await;
        load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let mut row = retired_row(&seal_key(1));
        row.public_jwk = retired_row(&seal_key(1)).public_jwk;
        row.private_sealed = "garbage".to_string();
        insert(&db, row).await;
        let err = load_or_bootstrap(&db, &seal_key(1)).await.unwrap_err();
        assert!(format!("{err:#}").contains("does not open"));
        assert_eq!(counts(&db).await, (2, 1));
    }

    #[tokio::test]
    async fn an_all_retired_table_with_a_foreign_sealed_row_errors_and_generates_nothing() {
        let db = test_pool().await;
        insert(&db, retired_row(&seal_key(2))).await;
        let err = load_or_bootstrap(&db, &seal_key(1)).await.unwrap_err();
        assert!(format!("{err:#}").contains("does not open under the current"));
        assert_eq!(counts(&db).await, (1, 0));
    }

    #[tokio::test]
    async fn a_row_whose_kid_is_not_its_key_fails_the_load() {
        let db = test_pool().await;
        let mut row = retired_row(&seal_key(1));
        let pkcs8 = seal_key(1)
            .open(SEAL_PURPOSE, &row.kid, &row.private_sealed)
            .unwrap();
        row.kid = retired_row(&seal_key(1)).kid;
        // Resealed under the new kid, so only the thumbprint check can refuse it.
        row.private_sealed = seal_key(1).seal(SEAL_PURPOSE, &row.kid, &pkcs8);
        insert(&db, row).await;
        let err = load_or_bootstrap(&db, &seal_key(1)).await.unwrap_err();
        assert!(format!("{err:#}").contains("does not match its kid"));
        assert_eq!(counts(&db).await, (1, 0));
    }

    #[tokio::test]
    async fn rotate_leaves_one_active_and_one_retired_key_both_published() {
        let db = test_pool().await;
        let old = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let rotated = rotate(&db, &seal_key(1)).await.unwrap();
        assert_eq!(rotated.retired, old.signing().kid);
        assert_ne!(rotated.active, rotated.retired);
        assert_eq!(counts(&db).await, (2, 1));
        let keys = load(&db, &seal_key(1)).await.unwrap();
        assert_eq!(keys.signing().kid, rotated.active);
        let mut want = vec![rotated.active.as_str(), rotated.retired.as_str()];
        want.sort_unstable();
        assert_eq!(keys.kids(), want);
        let published: Vec<_> = keys
            .public_jwks()
            .iter()
            .map(|k| k["kid"].clone())
            .collect();
        assert_eq!(published.len(), 2);
        assert!(published.contains(&json!(rotated.retired)));
        assert!(published.contains(&json!(rotated.active)));
    }

    #[tokio::test]
    async fn a_foreign_sealed_row_refuses_rotation() {
        let db = test_pool().await;
        let keys = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        insert(&db, retired_row(&seal_key(2))).await;
        let err = rotate(&db, &seal_key(1)).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.starts_with("refusing to rotate: "), "{msg}");
        assert!(msg.contains("does not open under the current"), "{msg}");
        assert_eq!(counts(&db).await, (2, 1));
        let rows = load_rows(&db).await.unwrap();
        let active = rows.iter().find(|r| r.status == ACTIVE).unwrap();
        assert_eq!(active.kid, keys.signing().kid);
    }

    #[tokio::test]
    async fn a_planted_kid_is_escaped_in_the_rotate_refusal() {
        let db = test_pool().await;
        load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let mut row = retired_row(&seal_key(1));
        row.kid = "evil\n\u{1b}[31mkid".to_string();
        insert(&db, row).await;
        let msg = format!("{:#}", rotate(&db, &seal_key(1)).await.unwrap_err());
        assert!(!msg.contains('\n') && !msg.contains('\u{1b}'), "{msg:?}");
        assert!(msg.contains(r#""evil\n\u{1b}[31mkid""#), "{msg}");
    }

    #[tokio::test]
    async fn rotate_without_an_active_key_generates_nothing() {
        let db = test_pool().await;
        let err = rotate(&db, &seal_key(1)).await.unwrap_err();
        assert!(format!("{err:#}").contains(NO_ACTIVE_KEY));
        assert_eq!(counts(&db).await, (0, 0));
    }

    #[tokio::test]
    async fn a_rotation_that_lost_the_race_changes_nothing() {
        let db = test_pool().await;
        let stale = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let winner = rotate(&db, &seal_key(1)).await.unwrap();
        let row = new_row(&generate().await.unwrap(), &seal_key(1)).unwrap();
        let err = swap_active(&db, stale.signing().kid.clone(), row)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("another rotation"), "{err:#}");
        assert_eq!(counts(&db).await, (2, 1));
        let keys = load(&db, &seal_key(1)).await.unwrap();
        assert_eq!(keys.signing().kid, winner.active);
    }

    #[tokio::test]
    async fn load_does_not_bootstrap() {
        let db = test_pool().await;
        let err = load(&db, &seal_key(1)).await.unwrap_err();
        assert!(format!("{err:#}").contains(NO_ACTIVE_KEY));
        assert_eq!(counts(&db).await, (0, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
    async fn concurrent_rotations_and_bootstraps_keep_one_active_key_on_postgres() {
        let _serial = POSTGRES_KEYS.lock().await;
        let db = crate::db::test_postgres_pool().await;
        clear(&db).await;
        let mut boots = Vec::new();
        let mut rotations = Vec::new();
        for _ in 0..3 {
            let pool = crate::db::test_postgres_pool().await;
            boots.push(tokio::spawn(async move {
                load_or_bootstrap(&pool, &seal_key(1))
                    .await
                    .map(|k| k.signing().kid.clone())
            }));
            let pool = crate::db::test_postgres_pool().await;
            rotations.push(tokio::spawn(
                async move { rotate(&pool, &seal_key(1)).await },
            ));
        }
        let mut booted = Vec::new();
        for task in boots {
            booted.push(task.await.unwrap());
        }
        let mut rotated = Vec::new();
        let mut refused = Vec::new();
        for task in rotations {
            match task.await.unwrap() {
                Ok(r) => rotated.push(r),
                Err(e) => refused.push(format!("{e:#}")),
            }
        }
        // A second round on a table that certainly has an active key.
        let mut racers = Vec::new();
        for _ in 0..4 {
            let pool = crate::db::test_postgres_pool().await;
            racers.push(tokio::spawn(
                async move { rotate(&pool, &seal_key(1)).await },
            ));
        }
        for task in racers {
            match task.await.unwrap() {
                Ok(r) => rotated.push(r),
                Err(e) => refused.push(format!("{e:#}")),
            }
        }
        let after = counts(&db).await;
        let stored = stored_kids(&db).await.unwrap();
        let loaded = load(&db, &seal_key(1)).await;
        clear(&db).await;

        let booted: Vec<String> = booted.into_iter().map(Result::unwrap).collect();
        assert!(!rotated.is_empty());
        for msg in &refused {
            assert!(
                msg.contains("another rotation") || msg.contains(NO_ACTIVE_KEY),
                "{msg}"
            );
        }
        assert_eq!(after, (1 + i64::try_from(rotated.len()).unwrap(), 1));
        for kid in booted.iter().chain(rotated.iter().map(|r| &r.active)) {
            assert!(stored.contains(kid), "{kid}");
        }
        let loaded = loaded.unwrap();
        assert_eq!(loaded.kids().len(), stored.len());
        let retired: Vec<&String> = rotated.iter().map(|r| &r.retired).collect();
        let mut unique = retired.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), retired.len(), "a key was retired twice");
    }

    mod instances {
        use std::sync::Arc;
        use std::time::Instant;

        use super::*;
        use crate::config::AppConfig;
        use crate::oauth_native::jwt::{self, Typ};
        use crate::oauth_native::{KEY_RELOAD_INTERVAL, NativeOAuth};

        async fn instance(db: &DbPool) -> Arc<NativeOAuth> {
            let oauth = NativeOAuth::new(&AppConfig::test_fixture(), db, &[0x42; 32]);
            oauth.init().await.unwrap();
            oauth
        }

        /// An access token from whatever key is active in the database now.
        async fn token_from_stored_key(oauth: &NativeOAuth) -> String {
            let keys = load(&oauth.db, &oauth.seal).await.unwrap();
            let claims = json!({ "iss": oauth.issuer, "sub": "s-1", "exp": 4_000_000_000_u64 });
            jwt::sign(&keys, Typ::AccessToken, &claims).unwrap()
        }

        async fn published(oauth: &NativeOAuth) -> Vec<String> {
            let keys = oauth.published_keys().await.unwrap();
            keys.public_jwks()
                .iter()
                .map(|k| k["kid"].as_str().unwrap().to_string())
                .collect()
        }

        /// Lets the next [`NativeOAuth::reload_keys`] run.
        async fn age_last_reload(oauth: &NativeOAuth) {
            *oauth.last_reload.lock().await = Instant::now().checked_sub(KEY_RELOAD_INTERVAL);
        }

        #[tokio::test]
        async fn a_second_instance_serves_and_verifies_a_key_rotated_elsewhere() {
            let db = test_pool().await;
            let rotating = instance(&db).await;
            let serving = instance(&db).await;
            let verifying = instance(&db).await;
            let rotated = rotating.rotate_key().await.unwrap();
            assert_eq!(rotating.keys().unwrap().signing().kid, rotated.retired);

            let mut jwks = published(&serving).await;
            jwks.sort_unstable();
            let mut want = vec![rotated.active.clone(), rotated.retired.clone()];
            want.sort_unstable();
            assert_eq!(jwks, want);
            assert_eq!(serving.keys().unwrap().signing().kid, rotated.active);

            let token = token_from_stored_key(&verifying).await;
            assert!(
                !verifying
                    .keys()
                    .unwrap()
                    .kids()
                    .contains(&rotated.active.as_str())
            );
            let claims = verifying
                .verify_jwt(&token, Typ::AccessToken, None)
                .await
                .unwrap();
            assert_eq!(claims["sub"], "s-1");
            assert_eq!(verifying.keys().unwrap().signing().kid, rotated.active);
            assert_eq!(published(&verifying).await.len(), 2);
        }

        #[tokio::test]
        async fn reloads_are_throttled_for_unknown_kids_and_the_jwks() {
            let db = test_pool().await;
            let oauth = instance(&db).await;
            let first = oauth.rotate_key().await.unwrap();
            oauth.reload_keys().await.unwrap();
            assert_eq!(oauth.keys().unwrap().signing().kid, first.active);

            let second = oauth.rotate_key().await.unwrap();
            let token = token_from_stored_key(&oauth).await;
            assert!(
                oauth
                    .verify_jwt(&token, Typ::AccessToken, None)
                    .await
                    .is_err()
            );
            assert!(!published(&oauth).await.contains(&second.active));
            oauth.reload_keys().await.unwrap();
            assert_eq!(oauth.keys().unwrap().signing().kid, first.active);

            age_last_reload(&oauth).await;
            assert!(
                oauth
                    .verify_jwt(&token, Typ::AccessToken, None)
                    .await
                    .is_ok()
            );
            assert_eq!(oauth.keys().unwrap().signing().kid, second.active);
            assert!(published(&oauth).await.contains(&second.active));
        }

        fn loads(oauth: &NativeOAuth) -> usize {
            oauth.key_loads.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Takes the test pool's only connection, so a key load waits until it is dropped.
        async fn hold_connection(db: &DbPool) -> impl Drop {
            let DbPool::Sqlite(pool) = db else {
                panic!("the test pool is sqlite")
            };
            pool.get().await.unwrap()
        }

        #[tokio::test]
        async fn a_caller_queued_behind_a_slow_reload_does_not_load_again() {
            let db = test_pool().await;
            let oauth = instance(&db).await;
            let held = hold_connection(&db).await;
            let first = tokio::spawn({
                let oauth = oauth.clone();
                async move { oauth.reload_keys().await }
            });
            while loads(&oauth) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let second = tokio::spawn({
                let oauth = oauth.clone();
                async move { oauth.reload_keys().await }
            });
            tokio::time::sleep(KEY_RELOAD_INTERVAL + std::time::Duration::from_millis(200)).await;
            drop(held);
            first.await.unwrap().unwrap();
            second.await.unwrap().unwrap();
            assert_eq!(loads(&oauth), 1);
        }

        #[tokio::test]
        async fn a_reload_whose_caller_is_dropped_still_stores_the_new_keys() {
            let db = test_pool().await;
            let oauth = instance(&db).await;
            let rotated = instance(&db).await.rotate_key().await.unwrap();
            let held = hold_connection(&db).await;
            let dropped =
                tokio::time::timeout(std::time::Duration::from_millis(100), oauth.reload_keys())
                    .await;
            assert!(dropped.is_err());
            assert_eq!(oauth.keys().unwrap().signing().kid, rotated.retired);
            drop(held);
            let deadline = Instant::now() + std::time::Duration::from_secs(5);
            while oauth.keys().unwrap().signing().kid != rotated.active {
                assert!(Instant::now() < deadline, "the reload never stored");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert_eq!(loads(&oauth), 1);
        }

        #[tokio::test]
        async fn a_token_with_a_known_kid_never_reloads() {
            let db = test_pool().await;
            let oauth = instance(&db).await;
            let keys = oauth.keys().unwrap();
            let token = jwt::sign(&keys, Typ::IdToken, &json!({ "iss": oauth.issuer })).unwrap();
            assert!(oauth.verify_jwt(&token, Typ::IdToken, None).await.is_err());
            assert!(oauth.last_reload.lock().await.is_none());
            assert!(
                oauth
                    .verify_jwt("not-a-jwt", Typ::IdToken, None)
                    .await
                    .is_err()
            );
            assert!(oauth.last_reload.lock().await.is_none());
        }

        #[tokio::test]
        async fn a_failed_reload_keeps_the_loaded_keys() {
            let db = test_pool().await;
            let oauth = instance(&db).await;
            let before = oauth.keys().unwrap();
            let token = token_from_stored_key(&oauth).await;
            insert(&db, retired_row(&seal_key(2))).await;

            let err = oauth.reload_keys().await.unwrap_err();
            assert!(format!("{err:#}").contains("does not open"));
            assert!(Arc::ptr_eq(&oauth.keys().unwrap(), &before));
            age_last_reload(&oauth).await;
            assert_eq!(published(&oauth).await, before.kids());
            assert!(Arc::ptr_eq(&oauth.keys().unwrap(), &before));
            assert!(
                oauth
                    .verify_jwt(&token, Typ::AccessToken, None)
                    .await
                    .is_ok()
            );
        }

        #[tokio::test]
        async fn a_planted_public_jwk_row_is_never_served() {
            let db = test_pool().await;
            let oauth = instance(&db).await;
            let real = oauth.keys().unwrap().public_jwks();
            let mut planted = retired_row(&seal_key(1));
            planted.private_sealed = "garbage".to_string();
            let (kid, jwk) = (planted.kid.clone(), planted.public_jwk.clone());
            insert(&db, planted).await;

            let served = oauth.published_keys().await.unwrap().public_jwks();
            assert_eq!(served, real);
            assert!(!served.iter().any(|k| k["kid"] == kid.as_str()));
            let planted_n = serde_json::from_str::<Value>(&jwk).unwrap()["n"].clone();
            assert!(!served.iter().any(|k| k["n"] == planted_n));
            // A fresh instance refuses to boot on it rather than serve it.
            let fresh = NativeOAuth::new(&AppConfig::test_fixture(), &db, &[0x42; 32]);
            assert!(fresh.init().await.is_err());
            assert!(fresh.published_keys().await.is_err());
        }
    }

    #[tokio::test]
    async fn an_altered_public_jwk_column_is_ignored() {
        let db = test_pool().await;
        let keys = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        let real = keys.public_jwks();
        let foreign = retired_row(&seal_key(1)).public_jwk;
        set_public_jwk(&db, &keys.signing().kid, foreign).await;
        let reloaded = load_or_bootstrap(&db, &seal_key(1)).await.unwrap();
        assert_eq!(reloaded.public_jwks(), real);
        assert_eq!(reloaded.signing().kid, keys.signing().kid);
    }
}
