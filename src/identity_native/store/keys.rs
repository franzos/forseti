//! WebAuthn keys: passkeys, a way to sign in, and security keys (kind `webauthn`), a second factor.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diesel::prelude::*;
use diesel::query_dsl::LoadQuery;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use webauthn_rs::prelude::{AuthenticationResult, Passkey, SecurityKey};

use super::{OwnedWriter, Refused, Writer, admit, identity_lock};
use crate::db::DbPool;
use crate::schema::{identity_credentials, identity_oidc_links, identity_webauthn_keys};
use crate::{db_interact, serialized_txn};

/// Read-and-swap rounds before a contended [`apply_use`] gives up.
const SWAP_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::identity_native) enum KeyKind {
    Passkey,
    Webauthn,
}

impl KeyKind {
    pub(in crate::identity_native) fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "passkey",
            Self::Webauthn => "webauthn",
        }
    }
}

/// A stored credential as webauthn-rs uses it.
#[derive(Debug, Clone)]
pub(in crate::identity_native) enum Key {
    Passkey(Passkey),
    SecurityKey(SecurityKey),
}

impl Key {
    pub(in crate::identity_native) fn kind(&self) -> KeyKind {
        match self {
            Self::Passkey(_) => KeyKind::Passkey,
            Self::SecurityKey(_) => KeyKind::Webauthn,
        }
    }

    /// The credential id as base64url, the form the table keeps it in.
    pub(in crate::identity_native) fn credential_id(&self) -> String {
        let id = match self {
            Self::Passkey(k) => k.cred_id(),
            Self::SecurityKey(k) => k.cred_id(),
        };
        URL_SAFE_NO_PAD.encode(id)
    }

    fn update_credential(&mut self, result: &AuthenticationResult) -> Option<bool> {
        match self {
            Self::Passkey(k) => k.update_credential(result),
            Self::SecurityKey(k) => k.update_credential(result),
        }
    }

    fn to_json(&self) -> Result<String> {
        Ok(match self {
            Self::Passkey(k) => serde_json::to_string(k)?,
            Self::SecurityKey(k) => serde_json::to_string(k)?,
        })
    }
}

/// One key of an identity; `credential` holds the public key and metadata, no secret.
#[derive(Queryable, Selectable, Insertable, Debug, Clone, PartialEq)]
#[diesel(table_name = identity_webauthn_keys)]
pub(in crate::identity_native) struct KeyRow {
    pub(in crate::identity_native) id: String,
    pub(in crate::identity_native) identity_id: String,
    pub(in crate::identity_native) kind: String,
    pub(in crate::identity_native) credential_id: String,
    pub(in crate::identity_native) display_name: String,
    pub(in crate::identity_native) credential: String,
    /// The last signature counter accepted; 0 while the authenticator keeps none.
    pub(in crate::identity_native) sign_count: i64,
    pub(in crate::identity_native) version: i32,
    pub(in crate::identity_native) created_at: String,
    pub(in crate::identity_native) updated_at: String,
}

impl KeyRow {
    pub(in crate::identity_native) fn key(&self) -> Result<Key> {
        let context = || format!("identity_webauthn_keys.credential of {}", self.id);
        Ok(match self.kind.as_str() {
            "passkey" => {
                Key::Passkey(serde_json::from_str(&self.credential).with_context(context)?)
            }
            "webauthn" => {
                Key::SecurityKey(serde_json::from_str(&self.credential).with_context(context)?)
            }
            other => bail!("identity_webauthn_keys.kind of {} is {other:?}", self.id),
        })
    }
}

/// A key to store for the writer's identity.
pub(in crate::identity_native) struct NewKey {
    pub(in crate::identity_native) display_name: String,
    pub(in crate::identity_native) key: Key,
}

/// How [`add`] ended. Nothing is written unless `Added`.
#[derive(Debug, PartialEq)]
pub(in crate::identity_native) enum KeyAdded {
    Added,
    /// The credential id is registered already, to this identity or another.
    Taken,
    Refused(Refused),
}

/// How [`remove`] ended. Nothing is written unless `Removed`.
#[derive(Debug, PartialEq)]
pub(in crate::identity_native) enum KeyRemoved {
    Removed,
    /// No key of that kind with that row id belongs to the writer's identity.
    NotFound,
    /// The passkey is the identity's last way to sign in.
    LastSignIn,
    Refused(Refused),
}

/// How [`apply_use`] ended.
#[derive(Debug, PartialEq)]
pub(in crate::identity_native) enum KeyUsed {
    Applied,
    /// The counter did not advance past the stored one: a replay or a cloned authenticator.
    Replayed,
    Gone,
}

/// What [`reset_second_factors`] deleted.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct SecondFactorsReset {
    pub(crate) totp: usize,
    pub(crate) lookup_secret: usize,
    pub(crate) security_keys: usize,
}

impl SecondFactorsReset {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

enum AddAbort {
    Taken,
    Db(DieselError),
}

impl From<DieselError> for AddAbort {
    fn from(e: DieselError) -> Self {
        Self::Db(e)
    }
}

/// The row that stores `new_key` for `identity_id`.
pub(super) fn new_row(identity_id: &str, new_key: NewKey) -> Result<KeyRow> {
    let now = crate::db::now_rfc3339();
    Ok(KeyRow {
        id: uuid::Uuid::new_v4().to_string(),
        identity_id: identity_id.to_string(),
        kind: new_key.key.kind().as_str().to_string(),
        credential_id: new_key.key.credential_id(),
        display_name: new_key.display_name,
        credential: new_key.key.to_json()?,
        sign_count: 0,
        version: 0,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Store `new_key` for the writer's identity, behind its [`admit`].
pub(in crate::identity_native) async fn add(
    db: &DbPool,
    writer: Writer<'_>,
    new_key: NewKey,
) -> Result<KeyAdded> {
    let row = new_row(writer.identity_id, new_key)?;
    let writer = OwnedWriter::from(writer);
    let outcome = serialized_txn!(db, KeyAdded, AddAbort, |c| {
        if let Some(refused) = admit(c, &writer)? {
            return Ok(KeyAdded::Refused(refused));
        }
        diesel::insert_into(identity_webauthn_keys::table)
            .values(&row)
            .execute(c)
            .map_err(|e| match e {
                DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                    AddAbort::Taken
                }
                other => AddAbort::Db(other),
            })?;
        Ok(KeyAdded::Added)
    });
    match outcome {
        Ok(added) => Ok(added),
        Err(AddAbort::Taken) => Ok(KeyAdded::Taken),
        Err(AddAbort::Db(e)) => Err(e.into()),
    }
}

#[diesel::dsl::auto_type]
fn has_totp(identity_id: String) -> _ {
    diesel::dsl::select(diesel::dsl::exists(
        identity_credentials::table
            .filter(identity_credentials::identity_id.eq(identity_id))
            .filter(identity_credentials::kind.eq("totp")),
    ))
}

#[diesel::dsl::auto_type]
fn has_security_key(identity_id: String) -> _ {
    diesel::dsl::select(diesel::dsl::exists(
        identity_webauthn_keys::table
            .filter(identity_webauthn_keys::identity_id.eq(identity_id))
            .filter(identity_webauthn_keys::kind.eq("webauthn")),
    ))
}

#[diesel::dsl::auto_type]
fn lookup_delete(identity_id: String) -> _ {
    diesel::dsl::delete(
        identity_credentials::table
            .filter(identity_credentials::identity_id.eq(identity_id))
            .filter(identity_credentials::kind.eq("lookup_secret")),
    )
}

/// Whether the identity has TOTP or a security key, on the caller's connection.
pub(super) fn second_factor_on<C>(conn: &mut C, identity_id: &str) -> QueryResult<bool>
where
    C: Connection,
    for<'a> has_totp: LoadQuery<'a, C, bool>,
    for<'a> has_security_key: LoadQuery<'a, C, bool>,
{
    Ok(has_totp(identity_id.to_string()).get_result::<bool>(conn)?
        || has_security_key(identity_id.to_string()).get_result::<bool>(conn)?)
}

/// Whether the identity has TOTP or a security key.
pub(in crate::identity_native) async fn has_second_factor(
    db: &DbPool,
    identity_id: &str,
) -> Result<bool> {
    let identity_id = identity_id.to_string();
    Ok(db_interact!(db, |c| { second_factor_on(c, &identity_id) })?)
}

/// Delete the identity's lookup codes once it has neither TOTP nor a security key, on the
/// caller's connection inside its transaction; returns how many credentials went.
fn drop_lookup_without_second_factor<C>(conn: &mut C, identity_id: &str) -> QueryResult<usize>
where
    C: Connection,
    for<'a> has_totp: LoadQuery<'a, C, bool>,
    for<'a> has_security_key: LoadQuery<'a, C, bool>,
    lookup_delete: diesel::query_dsl::methods::ExecuteDsl<C>,
{
    if second_factor_on(conn, identity_id)? {
        return Ok(0);
    }
    lookup_delete(identity_id.to_string()).execute(conn)
}

/// Delete the writer's `kind` key `row_id`, behind its [`admit`]. A passkey goes only while the
/// identity keeps a password, another passkey or a link to one of `configured`; the last second
/// factor takes the lookup codes with it.
pub(in crate::identity_native) async fn remove(
    db: &DbPool,
    writer: Writer<'_>,
    kind: KeyKind,
    row_id: &str,
    configured: &[&str],
) -> Result<KeyRemoved> {
    let writer = OwnedWriter::from(writer);
    let row_id = row_id.to_string();
    let configured: Vec<String> = configured.iter().map(|p| (*p).to_string()).collect();
    Ok(serialized_txn!(db, KeyRemoved, DieselError, |c| {
        if let Some(refused) = admit(c, &writer)? {
            return Ok(KeyRemoved::Refused(refused));
        }
        let identity_id = &writer.identity_id;
        let own = identity_webauthn_keys::table
            .filter(identity_webauthn_keys::id.eq(&row_id))
            .filter(identity_webauthn_keys::identity_id.eq(identity_id))
            .filter(identity_webauthn_keys::kind.eq(kind.as_str()));
        let found = own
            .select(identity_webauthn_keys::id)
            .first::<String>(c)
            .optional()?;
        if found.is_none() {
            return Ok(KeyRemoved::NotFound);
        }
        if kind == KeyKind::Passkey {
            let has_password = diesel::select(diesel::dsl::exists(
                identity_credentials::table
                    .filter(identity_credentials::identity_id.eq(identity_id))
                    .filter(identity_credentials::kind.eq("password")),
            ))
            .get_result::<bool>(c)?;
            let other_passkey = diesel::select(diesel::dsl::exists(
                identity_webauthn_keys::table
                    .filter(identity_webauthn_keys::identity_id.eq(identity_id))
                    .filter(identity_webauthn_keys::kind.eq(KeyKind::Passkey.as_str()))
                    .filter(identity_webauthn_keys::id.ne(&row_id)),
            ))
            .get_result::<bool>(c)?;
            let usable_link = diesel::select(diesel::dsl::exists(
                identity_oidc_links::table
                    .filter(identity_oidc_links::identity_id.eq(identity_id))
                    .filter(identity_oidc_links::provider.eq_any(&configured)),
            ))
            .get_result::<bool>(c)?;
            if !has_password && !other_passkey && !usable_link {
                return Ok(KeyRemoved::LastSignIn);
            }
        }
        diesel::delete(own).execute(c)?;
        if kind == KeyKind::Webauthn {
            drop_lookup_without_second_factor(c, identity_id)?;
        }
        Ok(KeyRemoved::Removed)
    })?)
}

/// Delete the identity's TOTP credential, and its lookup codes unless a security key remains.
/// Returns how many credentials went.
pub(in crate::identity_native) async fn remove_totp(
    db: &DbPool,
    identity_id: &str,
) -> Result<usize> {
    let identity_id = identity_id.to_string();
    Ok(serialized_txn!(db, usize, DieselError, |c| {
        identity_lock(identity_id.clone()).execute(c)?;
        let totp = diesel::delete(
            identity_credentials::table
                .filter(identity_credentials::identity_id.eq(&identity_id))
                .filter(identity_credentials::kind.eq("totp")),
        )
        .execute(c)?;
        Ok(totp + drop_lookup_without_second_factor(c, &identity_id)?)
    })?)
}

/// Delete the identity's TOTP credential, lookup codes and security keys; passkeys stay.
pub(in crate::identity_native) async fn reset_second_factors(
    db: &DbPool,
    identity_id: &str,
) -> Result<SecondFactorsReset> {
    let identity_id = identity_id.to_string();
    Ok(serialized_txn!(db, SecondFactorsReset, DieselError, |c| {
        identity_lock(identity_id.clone()).execute(c)?;
        let credential = |c: &mut _, kind: &str| {
            diesel::delete(
                identity_credentials::table
                    .filter(identity_credentials::identity_id.eq(&identity_id))
                    .filter(identity_credentials::kind.eq(kind)),
            )
            .execute(c)
        };
        let totp = credential(c, "totp")?;
        let lookup_secret = credential(c, "lookup_secret")?;
        let security_keys = diesel::delete(
            identity_webauthn_keys::table
                .filter(identity_webauthn_keys::identity_id.eq(&identity_id))
                .filter(identity_webauthn_keys::kind.eq(KeyKind::Webauthn.as_str())),
        )
        .execute(c)?;
        Ok(SecondFactorsReset {
            totp,
            lookup_secret,
            security_keys,
        })
    })?)
}

/// The identity's keys, oldest first.
pub(in crate::identity_native) async fn of_identity(
    db: &DbPool,
    identity_id: &str,
) -> Result<Vec<KeyRow>> {
    let identity_id = identity_id.to_string();
    Ok(db_interact!(db, |c| {
        identity_webauthn_keys::table
            .filter(identity_webauthn_keys::identity_id.eq(&identity_id))
            .order((
                identity_webauthn_keys::created_at,
                identity_webauthn_keys::id,
            ))
            .select(KeyRow::as_select())
            .load(c)
    })?)
}

async fn by_id(db: &DbPool, id: &str) -> Result<Option<KeyRow>> {
    let id = id.to_string();
    Ok(db_interact!(db, |c| {
        identity_webauthn_keys::table
            .find(&id)
            .select(KeyRow::as_select())
            .first(c)
            .optional()
    })?)
}

/// The key with the raw credential id `credential_id`, of any identity.
pub(in crate::identity_native) async fn by_credential_id(
    db: &DbPool,
    credential_id: &[u8],
) -> Result<Option<KeyRow>> {
    let credential_id = URL_SAFE_NO_PAD.encode(credential_id);
    Ok(db_interact!(db, |c| {
        identity_webauthn_keys::table
            .filter(identity_webauthn_keys::credential_id.eq(&credential_id))
            .select(KeyRow::as_select())
            .first(c)
            .optional()
    })?)
}

/// Record a verified use of `row`: the counter and the credential JSON updated by `result`, if
/// the counter advanced past the stored one or both are 0. A concurrent write to the row is
/// re-read and applied on top.
pub(in crate::identity_native) async fn apply_use(
    db: &DbPool,
    row: &KeyRow,
    result: &AuthenticationResult,
) -> Result<KeyUsed> {
    let counter = i64::from(result.counter());
    // Counters are never negative, so `< 1` is `= 0`: a counter-less authenticator stays at 0.
    let below = counter.max(1);
    let mut current = row.clone();
    for _ in 0..SWAP_ATTEMPTS {
        let mut key = current.key()?;
        if key.update_credential(result).is_none() {
            bail!("authentication result is not for key {}", current.id);
        }
        let (id, version, credential) = (current.id.clone(), current.version, key.to_json()?);
        let now = crate::db::now_rfc3339();
        let swapped = db_interact!(db, |c| {
            diesel::update(
                identity_webauthn_keys::table
                    .find(&id)
                    .filter(identity_webauthn_keys::version.eq(version))
                    .filter(identity_webauthn_keys::sign_count.lt(below)),
            )
            .set((
                identity_webauthn_keys::credential.eq(&credential),
                identity_webauthn_keys::sign_count.eq(counter),
                identity_webauthn_keys::version.eq(version + 1),
                identity_webauthn_keys::updated_at.eq(&now),
            ))
            .execute(c)
        })?;
        if swapped > 0 {
            return Ok(KeyUsed::Applied);
        }
        let Some(reread) = by_id(db, &current.id).await? else {
            return Ok(KeyUsed::Gone);
        };
        if reread.version == current.version {
            return Ok(KeyUsed::Replayed);
        }
        current = reread;
    }
    bail!(
        "key {} changed on every one of {SWAP_ATTEMPTS} attempts",
        row.id
    )
}

/// A key row with a placeholder credential, for tests that never parse it.
#[cfg(test)]
pub(in crate::identity_native) async fn plant(
    db: &DbPool,
    identity_id: &str,
    kind: KeyKind,
) -> String {
    let credential_id = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
    plant_row(db, identity_id, kind, credential_id, "{}".to_string()).await
}

/// A key row holding `key`, without the guards of [`add`].
#[cfg(test)]
pub(in crate::identity_native) async fn plant_key(
    db: &DbPool,
    identity_id: &str,
    key: &Key,
) -> String {
    let credential = key.to_json().unwrap();
    plant_row(db, identity_id, key.kind(), key.credential_id(), credential).await
}

#[cfg(test)]
async fn plant_row(
    db: &DbPool,
    identity_id: &str,
    kind: KeyKind,
    credential_id: String,
    credential: String,
) -> String {
    let now = crate::db::now_rfc3339();
    let row = KeyRow {
        id: uuid::Uuid::new_v4().to_string(),
        identity_id: identity_id.to_string(),
        kind: kind.as_str().to_string(),
        credential_id,
        display_name: "key".to_string(),
        credential,
        sign_count: 0,
        version: 0,
        created_at: now.clone(),
        updated_at: now,
    };
    let id = row.id.clone();
    crate::identity_native::test_support::sql(db, move |c| {
        diesel::insert_into(identity_webauthn_keys::table)
            .values(&row)
            .execute(c)
    })
    .await;
    id
}

#[cfg(test)]
mod tests {
    use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential, Uuid, Webauthn};

    use super::*;
    use crate::db::test_pool;
    use crate::identity_native::store;
    use crate::identity_native::test_authenticator::Authenticator;
    use crate::identity_native::test_support::sql;
    use crate::identity_native::webauthn::{passkey_options, relying_party};
    use crate::schema::identity_sessions;

    const ORIGIN: &str = "http://localhost:3000";
    const RP_ID: &str = "localhost";

    fn rp() -> Webauthn {
        relying_party(ORIGIN, "Test").expect("localhost is a secure context")
    }

    fn register(rp: &Webauthn, authenticator: &mut Authenticator) -> SecurityKey {
        let (options, state) = rp
            .start_securitykey_registration(
                Uuid::new_v4(),
                "a@x.test",
                "a@x.test",
                None,
                None,
                None,
            )
            .unwrap();
        let response =
            authenticator.register(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        let response: RegisterPublicKeyCredential = serde_json::from_value(response).unwrap();
        rp.finish_securitykey_registration(&response, &state)
            .unwrap()
    }

    fn register_passkey(rp: &Webauthn, authenticator: &mut Authenticator) -> Passkey {
        let (options, state) = rp
            .start_passkey_registration(Uuid::new_v4(), "a@x.test", "a@x.test", None)
            .unwrap();
        let response = authenticator.register(RP_ID, ORIGIN, &passkey_options(&options));
        let response: RegisterPublicKeyCredential = serde_json::from_value(response).unwrap();
        rp.finish_passkey_registration(&response, &state).unwrap()
    }

    fn use_key(
        rp: &Webauthn,
        key: &SecurityKey,
        authenticator: &mut Authenticator,
    ) -> AuthenticationResult {
        let (options, state) = rp
            .start_securitykey_authentication(std::slice::from_ref(key))
            .unwrap();
        let response =
            authenticator.assert(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        let response: PublicKeyCredential = serde_json::from_value(response).unwrap();
        rp.finish_securitykey_authentication(&response, &state)
            .unwrap()
    }

    fn use_passkey(
        rp: &Webauthn,
        key: &Passkey,
        authenticator: &mut Authenticator,
    ) -> AuthenticationResult {
        let (options, state) = rp
            .start_passkey_authentication(std::slice::from_ref(key))
            .unwrap();
        let response =
            authenticator.assert(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        let response: PublicKeyCredential = serde_json::from_value(response).unwrap();
        rp.finish_passkey_authentication(&response, &state).unwrap()
    }

    /// A verified identity without credentials and a live session of it.
    async fn signed_in(db: &DbPool, email: &str) -> (String, String) {
        let identity = store::create(db, email, None, None, true)
            .await
            .unwrap()
            .expect("address is free")
            .id;
        let session = uuid::Uuid::new_v4().to_string();
        let (id, sid) = (identity.clone(), session.clone());
        let now = crate::db::now_rfc3339();
        sql(db, move |c| {
            diesel::insert_into(identity_sessions::table)
                .values((
                    identity_sessions::id.eq(&sid),
                    identity_sessions::identity_id.eq(&id),
                    identity_sessions::token_hash.eq(format!("h-{sid}")),
                    identity_sessions::aal.eq("aal1"),
                    identity_sessions::methods.eq("[]"),
                    identity_sessions::issued_at.eq(&now),
                    identity_sessions::authenticated_at.eq(&now),
                    identity_sessions::expires_at.eq("9999-12-31T00:00:00.000000+00:00"),
                ))
                .execute(c)
        })
        .await;
        (identity, session)
    }

    fn writer<'a>(identity_id: &'a str, session_id: &'a str) -> Writer<'a> {
        Writer {
            identity_id,
            session_id,
            verified_only: true,
        }
    }

    async fn credential(db: &DbPool, identity_id: &str, kind: &str) {
        assert!(
            store::insert_credential(db, identity_id, kind, "{}")
                .await
                .unwrap()
        );
    }

    async fn credential_kinds(db: &DbPool, identity_id: &str) -> Vec<String> {
        let identity_id = identity_id.to_string();
        sql(db, move |c| {
            identity_credentials::table
                .filter(identity_credentials::identity_id.eq(&identity_id))
                .order(identity_credentials::kind)
                .select(identity_credentials::kind)
                .load(c)
        })
        .await
    }

    async fn key_kinds(db: &DbPool, identity_id: &str) -> Vec<String> {
        of_identity(db, identity_id)
            .await
            .unwrap()
            .into_iter()
            .map(|k| k.kind)
            .collect()
    }

    fn security_key(key: &SecurityKey) -> NewKey {
        NewKey {
            display_name: "YubiKey".to_string(),
            key: Key::SecurityKey(key.clone()),
        }
    }

    async fn bump(db: &DbPool, row_id: &str, sign_count: Option<i64>) {
        let row_id = row_id.to_string();
        sql(db, move |c| {
            let target = identity_webauthn_keys::table.find(&row_id);
            diesel::update(target)
                .set((
                    identity_webauthn_keys::display_name.eq("renamed"),
                    identity_webauthn_keys::version.eq(identity_webauthn_keys::version + 1),
                ))
                .execute(c)?;
            if let Some(n) = sign_count {
                diesel::update(target)
                    .set(identity_webauthn_keys::sign_count.eq(n))
                    .execute(c)?;
            }
            Ok(())
        })
        .await;
    }

    #[tokio::test]
    async fn a_credential_id_belongs_to_one_identity() {
        let db = test_pool().await;
        let (a, a_session) = signed_in(&db, "a@x.test").await;
        let (b, b_session) = signed_in(&db, "b@x.test").await;
        let key = register(&rp(), &mut Authenticator::security_key());

        assert_eq!(
            add(&db, writer(&a, &a_session), security_key(&key))
                .await
                .unwrap(),
            KeyAdded::Added
        );
        for (identity, session) in [(&b, &b_session), (&a, &a_session)] {
            assert_eq!(
                add(&db, writer(identity, session), security_key(&key))
                    .await
                    .unwrap(),
                KeyAdded::Taken
            );
        }
        assert!(of_identity(&db, &b).await.unwrap().is_empty());
        let rows = of_identity(&db, &a).await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            (row.kind.as_str(), row.display_name.as_str(), row.sign_count),
            ("webauthn", "YubiKey", 0)
        );
        assert_eq!(
            row.credential_id,
            Key::SecurityKey(key.clone()).credential_id()
        );
        assert!(matches!(row.key().unwrap(), Key::SecurityKey(k) if k.cred_id() == key.cred_id()));

        let other = register(&rp(), &mut Authenticator::security_key());
        assert_eq!(
            add(&db, writer(&b, "revoked"), security_key(&other))
                .await
                .unwrap(),
            KeyAdded::Refused(Refused::SignedOut)
        );
        assert!(of_identity(&db, &b).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_use_must_advance_the_counter() {
        let db = test_pool().await;
        let rp = rp();
        let (id, session) = signed_in(&db, "c@x.test").await;
        let mut authenticator = Authenticator::security_key();
        let key = register(&rp, &mut authenticator);
        add(&db, writer(&id, &session), security_key(&key))
            .await
            .unwrap();
        let fresh = of_identity(&db, &id).await.unwrap().remove(0);

        authenticator.sign_count = 1;
        let first = use_key(&rp, &key, &mut authenticator);
        let replay = use_key(&rp, &key, &mut authenticator);
        assert_eq!(
            apply_use(&db, &fresh, &first).await.unwrap(),
            KeyUsed::Applied
        );
        let used = of_identity(&db, &id).await.unwrap().remove(0);
        assert_eq!((used.sign_count, used.version), (1, 1));
        assert_ne!(
            used.credential, fresh.credential,
            "the credential JSON follows the use"
        );

        assert_eq!(
            apply_use(&db, &used, &replay).await.unwrap(),
            KeyUsed::Replayed
        );
        assert_eq!(
            apply_use(&db, &fresh, &replay).await.unwrap(),
            KeyUsed::Replayed,
            "a stale row is re-read before the counter is judged"
        );
        authenticator.sign_count = 0;
        let reset = use_key(&rp, &key, &mut authenticator);
        assert_eq!(
            apply_use(&db, &used, &reset).await.unwrap(),
            KeyUsed::Replayed,
            "a counter falling back to 0 is refused"
        );
        assert_eq!(of_identity(&db, &id).await.unwrap()[0], used);

        authenticator.sign_count = 2;
        let next = use_key(&rp, &key, &mut authenticator);
        assert_eq!(
            apply_use(&db, &used, &next).await.unwrap(),
            KeyUsed::Applied
        );
        assert_eq!(of_identity(&db, &id).await.unwrap()[0].sign_count, 2);
    }

    #[tokio::test]
    async fn a_passkey_without_a_counter_is_used_again_and_again() {
        let db = test_pool().await;
        let rp = rp();
        let (id, session) = signed_in(&db, "p@x.test").await;
        let mut authenticator = Authenticator::passkey();
        let passkey = register_passkey(&rp, &mut authenticator);
        let new_key = NewKey {
            display_name: "Phone".to_string(),
            key: Key::Passkey(passkey.clone()),
        };
        assert_eq!(
            add(&db, writer(&id, &session), new_key).await.unwrap(),
            KeyAdded::Added
        );
        for version in 1..=2 {
            let row = of_identity(&db, &id).await.unwrap().remove(0);
            let result = use_passkey(&rp, &passkey, &mut authenticator);
            assert_eq!(
                apply_use(&db, &row, &result).await.unwrap(),
                KeyUsed::Applied
            );
            let after = of_identity(&db, &id).await.unwrap().remove(0);
            assert_eq!(
                (after.kind.as_str(), after.sign_count, after.version),
                ("passkey", 0, version)
            );
        }
    }

    #[tokio::test]
    async fn a_use_survives_a_concurrent_write() {
        let db = test_pool().await;
        let rp = rp();
        let (id, session) = signed_in(&db, "r@x.test").await;
        let mut authenticator = Authenticator::security_key();
        let key = register(&rp, &mut authenticator);
        add(&db, writer(&id, &session), security_key(&key))
            .await
            .unwrap();
        let stale = of_identity(&db, &id).await.unwrap().remove(0);

        bump(&db, &stale.id, None).await;
        authenticator.sign_count = 1;
        let result = use_key(&rp, &key, &mut authenticator);
        assert_eq!(
            apply_use(&db, &stale, &result).await.unwrap(),
            KeyUsed::Applied
        );
        let row = of_identity(&db, &id).await.unwrap().remove(0);
        assert_eq!(
            (row.display_name.as_str(), row.sign_count, row.version),
            ("renamed", 1, 2)
        );

        bump(&db, &row.id, Some(5)).await;
        authenticator.sign_count = 3;
        let behind = use_key(&rp, &key, &mut authenticator);
        assert_eq!(
            apply_use(&db, &row, &behind).await.unwrap(),
            KeyUsed::Replayed,
            "a concurrent use that got further wins"
        );

        let row_id = row.id.clone();
        sql(&db, move |c| {
            diesel::delete(identity_webauthn_keys::table.find(&row_id)).execute(c)
        })
        .await;
        authenticator.sign_count = 9;
        let late = use_key(&rp, &key, &mut authenticator);
        assert_eq!(apply_use(&db, &row, &late).await.unwrap(), KeyUsed::Gone);
    }

    #[tokio::test]
    async fn a_passkey_goes_only_while_another_way_in_remains() {
        let db = test_pool().await;
        let (id, session) = signed_in(&db, "w@x.test").await;
        let me = writer(&id, &session);
        let first = plant(&db, &id, KeyKind::Passkey).await;
        let second = plant(&db, &id, KeyKind::Passkey).await;
        plant(&db, &id, KeyKind::Webauthn).await;

        assert_eq!(
            remove(&db, me, KeyKind::Webauthn, &first, &[])
                .await
                .unwrap(),
            KeyRemoved::NotFound,
            "a passkey is not removed as a security key"
        );
        assert_eq!(
            remove(&db, me, KeyKind::Passkey, &first, &[])
                .await
                .unwrap(),
            KeyRemoved::Removed,
            "a second passkey remains"
        );
        assert_eq!(
            remove(&db, me, KeyKind::Passkey, &second, &[])
                .await
                .unwrap(),
            KeyRemoved::LastSignIn,
            "a security key is no way in"
        );
        store::insert_link(&db, &id, "github", "1").await.unwrap();
        assert_eq!(
            remove(&db, me, KeyKind::Passkey, &second, &["google"])
                .await
                .unwrap(),
            KeyRemoved::LastSignIn,
            "a link to a provider no longer configured does not count"
        );
        assert_eq!(
            remove(&db, me, KeyKind::Passkey, &second, &["github"])
                .await
                .unwrap(),
            KeyRemoved::Removed
        );
        assert_eq!(key_kinds(&db, &id).await, ["webauthn"]);

        let (other, other_session) = signed_in(&db, "x@x.test").await;
        credential(&db, &other, "password").await;
        let theirs = plant(&db, &other, KeyKind::Passkey).await;
        assert_eq!(
            remove(&db, me, KeyKind::Passkey, &theirs, &[])
                .await
                .unwrap(),
            KeyRemoved::NotFound,
            "another identity's row id"
        );
        assert_eq!(
            remove(
                &db,
                writer(&other, "revoked"),
                KeyKind::Passkey,
                &theirs,
                &[]
            )
            .await
            .unwrap(),
            KeyRemoved::Refused(Refused::SignedOut)
        );
        assert_eq!(key_kinds(&db, &other).await, ["passkey"]);
        assert_eq!(
            remove(
                &db,
                writer(&other, &other_session),
                KeyKind::Passkey,
                &theirs,
                &[]
            )
            .await
            .unwrap(),
            KeyRemoved::Removed,
            "a password remains"
        );
        assert_eq!(
            remove(
                &db,
                writer(&other, &other_session),
                KeyKind::Passkey,
                &theirs,
                &[]
            )
            .await
            .unwrap(),
            KeyRemoved::NotFound
        );
    }

    #[tokio::test]
    async fn lookup_codes_go_with_the_last_second_factor() {
        let db = test_pool().await;
        let (id, session) = signed_in(&db, "l@x.test").await;
        let me = writer(&id, &session);
        for kind in ["password", "totp", "lookup_secret"] {
            credential(&db, &id, kind).await;
        }
        let key = plant(&db, &id, KeyKind::Webauthn).await;
        let passkey = plant(&db, &id, KeyKind::Passkey).await;

        assert_eq!(remove_totp(&db, &id).await.unwrap(), 1);
        assert_eq!(
            credential_kinds(&db, &id).await,
            ["lookup_secret", "password"]
        );
        assert_eq!(
            remove(&db, me, KeyKind::Passkey, &passkey, &[])
                .await
                .unwrap(),
            KeyRemoved::Removed
        );
        assert_eq!(
            credential_kinds(&db, &id).await,
            ["lookup_secret", "password"],
            "a passkey is no second factor"
        );
        assert_eq!(
            remove(&db, me, KeyKind::Webauthn, &key, &[]).await.unwrap(),
            KeyRemoved::Removed
        );
        assert_eq!(credential_kinds(&db, &id).await, ["password"]);

        credential(&db, &id, "totp").await;
        credential(&db, &id, "lookup_secret").await;
        let key = plant(&db, &id, KeyKind::Webauthn).await;
        assert_eq!(
            remove(&db, me, KeyKind::Webauthn, &key, &[]).await.unwrap(),
            KeyRemoved::Removed
        );
        assert_eq!(
            credential_kinds(&db, &id).await,
            ["lookup_secret", "password", "totp"]
        );
        assert_eq!(remove_totp(&db, &id).await.unwrap(), 2);
        assert_eq!(credential_kinds(&db, &id).await, ["password"]);
    }

    #[tokio::test]
    async fn lookup_codes_are_stored_only_with_a_second_factor() {
        let db = test_pool().await;
        let (id, session) = signed_in(&db, "g@x.test").await;
        let me = writer(&id, &session);
        let write = || store::write_credential(&db, me, "lookup_secret", "{}", true);

        assert_eq!(write().await.unwrap(), Ok(false));
        plant(&db, &id, KeyKind::Passkey).await;
        assert_eq!(
            write().await.unwrap(),
            Ok(false),
            "a passkey is no second factor"
        );
        assert!(credential_kinds(&db, &id).await.is_empty());

        let key = plant(&db, &id, KeyKind::Webauthn).await;
        assert!(has_second_factor(&db, &id).await.unwrap());
        assert_eq!(write().await.unwrap(), Ok(true));
        assert_eq!(
            remove(&db, me, KeyKind::Webauthn, &key, &[]).await.unwrap(),
            KeyRemoved::Removed
        );
        assert!(credential_kinds(&db, &id).await.is_empty());
        assert_eq!(write().await.unwrap(), Ok(false));

        credential(&db, &id, "totp").await;
        assert_eq!(write().await.unwrap(), Ok(true));
        assert_eq!(credential_kinds(&db, &id).await, ["lookup_secret", "totp"]);
    }

    #[tokio::test]
    async fn a_second_factor_reset_keeps_passkeys() {
        let db = test_pool().await;
        let (id, _) = signed_in(&db, "s@x.test").await;
        let (other, _) = signed_in(&db, "t@x.test").await;
        for identity in [&id, &other] {
            for kind in ["password", "totp", "lookup_secret"] {
                credential(&db, identity, kind).await;
            }
            plant(&db, identity, KeyKind::Webauthn).await;
            plant(&db, identity, KeyKind::Passkey).await;
        }
        plant(&db, &id, KeyKind::Webauthn).await;
        assert_eq!(
            reset_second_factors(&db, &id).await.unwrap(),
            SecondFactorsReset {
                totp: 1,
                lookup_secret: 1,
                security_keys: 2,
            }
        );
        assert_eq!(credential_kinds(&db, &id).await, ["password"]);
        assert_eq!(key_kinds(&db, &id).await, ["passkey"]);
        assert_eq!(credential_kinds(&db, &other).await.len(), 3);
        assert_eq!(key_kinds(&db, &other).await.len(), 2);
        assert!(reset_second_factors(&db, &id).await.unwrap().is_empty());
    }
}
