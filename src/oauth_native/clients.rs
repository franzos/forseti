//! OAuth client registrations in `oauth_clients`, read and written in the shape Hydra's admin API
//! uses, and client authentication for the token endpoint.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;

use crate::backend::oauth::OAuthClient;
use crate::db::{DbPool, now_rfc3339};
use crate::db_interact;
use crate::oauth::device::generate_secret;
use crate::schema::oauth_clients;

pub(crate) const AUTH_NONE: &str = "none";
pub(crate) const AUTH_BASIC: &str = "client_secret_basic";
pub(crate) const AUTH_POST: &str = "client_secret_post";

const MAX_PAGE_SIZE: i64 = 500;

/// Lowercase, as `Url::scheme` returns them.
pub(crate) const REFUSED_SCHEMES: &[&str] = &["javascript", "data", "vbscript", "file", "blob"];

/// Longer presented secrets are a mismatch; generated ones are 40 bytes.
const MAX_SECRET_BYTES: usize = 512;

// The identity password parameters: OWASP Password Storage Cheat Sheet, first Argon2id configuration.
const ARGON2_M_KIB: u32 = 19_456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

/// Verified when there is no registered hash to check, so a refusal costs one Argon2 run.
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c1NSVVc4ODVMSk9RdGZJOGgxdmduZw$7NbJXi95HFEt7hF767fIYjodMRP3AW8Zzccp8Ropi7c";

/// Longest wait for a hashing permit.
const PERMIT_WAIT: Duration = Duration::from_secs(3);

/// Client fields that have a column, or that the store sets itself; never kept in `extra`.
const NOT_EXTRA: &[&str] = &[
    "audience",
    "backchannel_logout_session_required",
    "backchannel_logout_uri",
    "client_id",
    "client_name",
    "client_secret",
    "client_uri",
    "created_at",
    "frontchannel_logout_session_required",
    "frontchannel_logout_uri",
    "grant_types",
    "logo_uri",
    "metadata",
    "post_logout_redirect_uris",
    "redirect_uris",
    "registration_access_token",
    "registration_client_uri",
    "response_types",
    "scope",
    "skip_consent",
    "token_endpoint_auth_method",
    "updated_at",
];

#[derive(Debug)]
pub(crate) enum ClientError {
    NotFound,
    Conflict,
    Invalid(&'static str),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("OAuth client not found"),
            Self::Conflict => f.write_str("an OAuth client with this client_id already exists"),
            Self::Invalid(why) => write!(f, "invalid OAuth client: {why}"),
        }
    }
}

impl std::error::Error for ClientError {}

#[derive(Debug)]
enum HashError {
    Busy,
    Failed(anyhow::Error),
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("client secret hashing is at capacity"),
            Self::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for HashError {}

/// Why client authentication did not produce a client.
#[derive(Debug)]
pub(crate) enum ClientAuthError {
    /// Every refusal: unknown client, wrong method, wrong or missing secret.
    InvalidClient,
    Busy,
    Failed(anyhow::Error),
}

impl std::fmt::Display for ClientAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidClient => f.write_str("invalid_client"),
            Self::Busy => f.write_str("client secret hashing is at capacity"),
            Self::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for ClientAuthError {}

impl From<HashError> for ClientAuthError {
    fn from(e: HashError) -> Self {
        match e {
            HashError::Busy => Self::Busy,
            HashError::Failed(e) => Self::Failed(e),
        }
    }
}

/// The credentials a token request presented, by the method it used.
pub(crate) enum ClientCredentials<'a> {
    None {
        client_id: &'a str,
    },
    Basic {
        client_id: &'a str,
        client_secret: &'a str,
    },
    Post {
        client_id: &'a str,
        client_secret: &'a str,
    },
}

fn argon2() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None)
        .expect("static Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Argon2id PHC string of a client secret, on the calling thread.
pub fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("argon2 hash: {e}"))
}

/// Whether `secret` matches `phc`. Without a usable `phc`, or for a secret over
/// [`MAX_SECRET_BYTES`], the dummy hash is verified instead, over at most that many bytes.
fn verify_secret(secret: &str, phc: Option<&str>) -> bool {
    let presented = secret.as_bytes();
    let dummy = || {
        let parsed = PasswordHash::new(DUMMY_PHC).expect("DUMMY_PHC is a valid PHC string");
        let bounded = &presented[..presented.len().min(MAX_SECRET_BYTES)];
        let _ = argon2().verify_password(bounded, &parsed);
        false
    };
    if presented.len() > MAX_SECRET_BYTES {
        return dummy();
    }
    let Some(phc) = phc else {
        return dummy();
    };
    match PasswordHash::new(phc) {
        Ok(parsed) => argon2().verify_password(secret.as_bytes(), &parsed).is_ok(),
        Err(e) => {
            tracing::error!(error = %e, "stored client secret hash is not a PHC string");
            dummy()
        }
    }
}

/// Runs `f` on the blocking pool once a permit is free.
async fn off_runtime<T: Send + 'static>(
    permits: &Arc<Semaphore>,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, HashError> {
    let permit = match tokio::time::timeout(PERMIT_WAIT, permits.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return Err(HashError::Failed(anyhow!("hash semaphore closed"))),
        Err(_) => return Err(HashError::Busy),
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| HashError::Failed(anyhow!("argon2 task: {e}")))
}

async fn hash_off_runtime(permits: &Arc<Semaphore>, secret: &str) -> Result<String> {
    let secret = secret.to_string();
    off_runtime(permits, move || hash_secret(&secret)).await?
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = oauth_clients)]
struct Row {
    client_id: String,
    client_name: Option<String>,
    secret_hash: Option<String>,
    token_endpoint_auth_method: String,
    redirect_uris: Option<String>,
    post_logout_redirect_uris: Option<String>,
    grant_types: Option<String>,
    response_types: Option<String>,
    audience: Option<String>,
    scope: Option<String>,
    skip_consent: Option<i32>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<i32>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: Option<i32>,
    metadata: Option<String>,
    extra: String,
    created_at: String,
    updated_at: String,
}

/// Every column a create or update writes, apart from the id, the secret hash and `created_at`.
#[derive(Insertable, AsChangeset)]
#[diesel(table_name = oauth_clients, treat_none_as_null = true)]
struct Fields {
    client_name: Option<String>,
    token_endpoint_auth_method: String,
    redirect_uris: Option<String>,
    post_logout_redirect_uris: Option<String>,
    grant_types: Option<String>,
    response_types: Option<String>,
    audience: Option<String>,
    scope: Option<String>,
    skip_consent: Option<i32>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<i32>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: Option<i32>,
    metadata: Option<String>,
    extra: String,
    updated_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = oauth_clients)]
struct NewRow {
    client_id: String,
    secret_hash: Option<String>,
    created_at: String,
    #[diesel(embed)]
    fields: Fields,
}

/// The registered method; an empty or missing one is `client_secret_basic`, as in Hydra.
fn auth_method(c: &OAuthClient) -> Result<String, ClientError> {
    match c.token_endpoint_auth_method.as_deref().unwrap_or_default() {
        "" => Ok(AUTH_BASIC.to_string()),
        m @ (AUTH_NONE | AUTH_BASIC | AUTH_POST) => Ok(m.to_string()),
        _ => Err(ClientError::Invalid(
            "token_endpoint_auth_method must be none, client_secret_basic or client_secret_post",
        )),
    }
}

// `Url::parse` strips tabs and newlines, so `java\tscript:` would parse as `javascript:`.
pub(crate) fn has_whitespace_or_control(raw: &str) -> bool {
    raw.chars()
        .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
}

/// Absolute ASCII, no fragment, no userinfo, no script or local-content scheme.
fn acceptable_uri(raw: &str) -> bool {
    // A non-ASCII `Location` header fails to serialise and the response becomes a 500.
    if !raw.is_ascii() || has_whitespace_or_control(raw) {
        return false;
    }
    let Ok(u) = url::Url::parse(raw) else {
        return false;
    };
    // `Url` reads `https:app.example/cb` as `https://app.example/cb`; exact matching would not.
    let literal_authority = !matches!(u.scheme(), "http" | "https")
        || raw
            .get(..u.scheme().len() + 3)
            .is_some_and(|p| p.eq_ignore_ascii_case(&format!("{}://", u.scheme())));
    literal_authority
        && u.fragment().is_none()
        && u.username().is_empty()
        && u.password().is_none()
        && !REFUSED_SCHEMES.contains(&u.scheme())
}

/// The shape the store requires of `client_uri`, `logo_uri` and the logout URIs.
pub(crate) fn acceptable_web_uri(raw: &str) -> bool {
    acceptable_uri(raw)
        && url::Url::parse(raw).is_ok_and(|u| matches!(u.scheme(), "http" | "https"))
}

fn check_uris(c: &OAuthClient) -> Result<(), ClientError> {
    let uris = c.redirect_uris.iter().chain(&c.post_logout_redirect_uris);
    if !uris.flatten().all(|uri| acceptable_uri(uri)) {
        return Err(ClientError::Invalid(
            "redirect URIs must be absolute, without whitespace, fragment or userinfo, and not \
             use the javascript, data, vbscript, file or blob scheme",
        ));
    }
    // Hydra reports an unset one as an empty string.
    let web_uris = [
        &c.backchannel_logout_uri,
        &c.frontchannel_logout_uri,
        &c.client_uri,
        &c.logo_uri,
    ];
    let web_ok = web_uris
        .into_iter()
        .flatten()
        .filter(|uri| !uri.is_empty())
        .all(|uri| acceptable_web_uri(uri));
    if web_ok {
        Ok(())
    } else {
        Err(ClientError::Invalid(
            "client_uri, logo_uri and the logout URIs must be absolute http or https URIs, \
             without whitespace, fragment or userinfo",
        ))
    }
}

const GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
];
/// `id_token` because the PAM client registers it; authorize still requires `code`.
const RESPONSE_TYPES: &[&str] = &["code", "id_token"];

/// An empty or missing list keeps its default.
fn check_types(c: &OAuthClient) -> Result<(), ClientError> {
    let within = |list: &Option<Vec<String>>, allowed: &[&str]| {
        list.iter().flatten().all(|v| allowed.contains(&v.as_str()))
    };
    if !within(&c.grant_types, GRANT_TYPES) {
        return Err(ClientError::Invalid(
            "grant_types must be within authorization_code, refresh_token and \
             urn:ietf:params:oauth:grant-type:device_code",
        ));
    }
    if !within(&c.response_types, RESPONSE_TYPES) {
        return Err(ClientError::Invalid(
            "response_types must be within code and id_token",
        ));
    }
    Ok(())
}

fn to_json<T: Serialize>(v: Option<&T>) -> Result<Option<String>> {
    v.map(serde_json::to_string)
        .transpose()
        .context("encode an OAuth client field")
}

fn from_json<T: DeserializeOwned>(v: Option<&str>) -> Result<Option<T>> {
    v.map(serde_json::from_str)
        .transpose()
        .context("decode an OAuth client field")
}

fn to_fields(c: OAuthClient, method: String, now: String) -> Result<Fields> {
    let mut extra = c.extra;
    extra.retain(|k, _| !NOT_EXTRA.contains(&k.as_str()));
    Ok(Fields {
        client_name: c.client_name,
        token_endpoint_auth_method: method,
        redirect_uris: to_json(c.redirect_uris.as_ref())?,
        post_logout_redirect_uris: to_json(c.post_logout_redirect_uris.as_ref())?,
        grant_types: to_json(c.grant_types.as_ref())?,
        response_types: to_json(c.response_types.as_ref())?,
        audience: to_json(c.audience.as_ref())?,
        scope: c.scope,
        skip_consent: c.skip_consent.map(i32::from),
        logo_uri: c.logo_uri,
        client_uri: c.client_uri,
        backchannel_logout_uri: c.backchannel_logout_uri,
        backchannel_logout_session_required: c.backchannel_logout_session_required.map(i32::from),
        frontchannel_logout_uri: c.frontchannel_logout_uri,
        frontchannel_logout_session_required: c.frontchannel_logout_session_required.map(i32::from),
        metadata: to_json(c.metadata.as_ref())?,
        extra: serde_json::to_string(&extra).context("encode OAuth client extra fields")?,
        updated_at: now,
    })
}

/// The client as Hydra returns it: no secret, `updated_at` among the extra fields.
fn from_row(row: Row) -> Result<OAuthClient> {
    let mut extra: Map<String, Value> =
        serde_json::from_str(&row.extra).context("decode OAuth client extra fields")?;
    extra.insert("updated_at".to_string(), Value::String(row.updated_at));
    Ok(OAuthClient {
        audience: from_json(row.audience.as_deref())?,
        backchannel_logout_session_required: row
            .backchannel_logout_session_required
            .map(|b| b != 0),
        backchannel_logout_uri: row.backchannel_logout_uri,
        client_id: Some(row.client_id),
        client_name: row.client_name,
        client_secret: None,
        client_uri: row.client_uri,
        created_at: Some(row.created_at),
        frontchannel_logout_session_required: row
            .frontchannel_logout_session_required
            .map(|b| b != 0),
        frontchannel_logout_uri: row.frontchannel_logout_uri,
        grant_types: from_json(row.grant_types.as_deref())?,
        logo_uri: row.logo_uri,
        metadata: from_json(row.metadata.as_deref())?,
        post_logout_redirect_uris: from_json(row.post_logout_redirect_uris.as_deref())?,
        redirect_uris: from_json(row.redirect_uris.as_deref())?,
        registration_access_token: None,
        response_types: from_json(row.response_types.as_deref())?,
        scope: row.scope,
        skip_consent: row.skip_consent.map(|b| b != 0),
        token_endpoint_auth_method: Some(row.token_endpoint_auth_method),
        extra,
    })
}

async fn fetch_row(db: &DbPool, id: &str) -> Result<Option<Row>> {
    let id = id.to_string();
    Ok(db_interact!(db, |c| {
        oauth_clients::table
            .find(id)
            .select(Row::as_select())
            .first(c)
            .optional()
    })?)
}

pub(crate) async fn get(db: &DbPool, id: &str) -> Result<Option<OAuthClient>> {
    fetch_row(db, id).await?.map(from_row).transpose()
}

async fn get_written(db: &DbPool, id: &str, secret: Option<String>) -> Result<OAuthClient> {
    let mut client = get(db, id).await?.ok_or(ClientError::NotFound)?;
    client.client_secret = secret;
    Ok(client)
}

/// Stores a new client. The id is generated unless given; a client other than `none` gets the
/// given secret or a generated one, returned in plaintext here only.
pub(crate) async fn create(
    db: &DbPool,
    permits: &Arc<Semaphore>,
    client: OAuthClient,
) -> Result<OAuthClient> {
    let method = auth_method(&client)?;
    check_uris(&client)?;
    check_types(&client)?;
    let client_id = client
        .client_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let secret = (method != AUTH_NONE).then(|| {
        client
            .client_secret
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(generate_secret)
    });
    let secret_hash = match &secret {
        Some(s) => Some(hash_off_runtime(permits, s).await?),
        None => None,
    };
    let now = now_rfc3339();
    let row = NewRow {
        client_id: client_id.clone(),
        secret_hash,
        created_at: now.clone(),
        fields: to_fields(client, method, now)?,
    };
    let inserted = db_interact!(db, |c| {
        diesel::insert_into(oauth_clients::table)
            .values(&row)
            .execute(c)
    });
    match inserted {
        Ok(_) => {}
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            return Err(ClientError::Conflict.into());
        }
        Err(e) => return Err(e).context("insert OAuth client"),
    }
    get_written(db, &client_id, secret).await
}

/// Replaces every field of client `id` but its id and `created_at`. A given secret replaces the
/// stored one; switching to `none` removes it; otherwise it stays.
pub(crate) async fn update(
    db: &DbPool,
    permits: &Arc<Semaphore>,
    id: &str,
    client: OAuthClient,
) -> Result<OAuthClient> {
    let method = auth_method(&client)?;
    check_uris(&client)?;
    check_types(&client)?;
    let secret = (method != AUTH_NONE)
        .then(|| client.client_secret.clone().filter(|s| !s.is_empty()))
        .flatten();
    // `None` leaves the stored hash alone.
    let new_hash = match &secret {
        Some(s) => Some(Some(hash_off_runtime(permits, s).await?)),
        None if method == AUTH_NONE => Some(None),
        None => None,
    };
    let fields = to_fields(client, method, now_rfc3339())?;
    let target = id.to_string();
    let changed = db_interact!(db, |c| {
        let row = oauth_clients::table.find(target);
        match new_hash {
            Some(hash) => diesel::update(row)
                .set((fields, oauth_clients::secret_hash.eq(hash)))
                .execute(c),
            None => diesel::update(row).set(fields).execute(c),
        }
    })
    .context("update OAuth client")?;
    if changed == 0 {
        return Err(ClientError::NotFound.into());
    }
    get_written(db, id, secret).await
}

pub(crate) async fn delete(db: &DbPool, id: &str) -> Result<()> {
    let target = id.to_string();
    let deleted = db_interact!(db, |c| {
        diesel::delete(oauth_clients::table.find(target)).execute(c)
    })
    .context("delete OAuth client")?;
    if deleted == 0 {
        return Err(ClientError::NotFound.into());
    }
    Ok(())
}

/// Replaces the secret with a generated one, returned in plaintext here only. Like Hydra, this
/// also stores one on a `none` client, which still authenticates without it.
pub(crate) async fn rotate_secret(
    db: &DbPool,
    permits: &Arc<Semaphore>,
    id: &str,
) -> Result<OAuthClient> {
    let secret = generate_secret();
    let hash = hash_off_runtime(permits, &secret).await?;
    let target = id.to_string();
    let changed = db_interact!(db, |c| {
        diesel::update(oauth_clients::table.find(target))
            .set((
                oauth_clients::secret_hash.eq(Some(hash)),
                oauth_clients::updated_at.eq(now_rfc3339()),
            ))
            .execute(c)
    })
    .context("rotate OAuth client secret")?;
    if changed == 0 {
        return Err(ClientError::NotFound.into());
    }
    get_written(db, id, Some(secret)).await
}

/// One page ordered by `client_id`, starting after `page_token` (the last `client_id` of the
/// previous page). `client_name` matches exactly.
pub(crate) async fn list(
    db: &DbPool,
    page_size: i64,
    page_token: Option<&str>,
    client_name: Option<&str>,
) -> Result<Vec<OAuthClient>> {
    let limit = page_size.clamp(1, MAX_PAGE_SIZE);
    let after = page_token.map(str::to_string);
    let name = client_name.map(str::to_string);
    let rows = db_interact!(db, |c| {
        let mut q = oauth_clients::table
            .select(Row::as_select())
            .order(oauth_clients::client_id)
            .limit(limit)
            .into_boxed();
        if let Some(after) = after {
            q = q.filter(oauth_clients::client_id.gt(after));
        }
        if let Some(name) = name {
            q = q.filter(oauth_clients::client_name.eq(name));
        }
        q.load::<Row>(c)
    })
    .context("list OAuth clients")?;
    rows.into_iter().map(from_row).collect()
}

/// The client the credentials authenticate, by exactly its registered method. A presented secret
/// always costs one Argon2 verify, against the dummy hash when there is nothing to check.
pub(crate) async fn authenticate(
    db: &DbPool,
    permits: &Arc<Semaphore>,
    credentials: ClientCredentials<'_>,
) -> Result<OAuthClient, ClientAuthError> {
    let (client_id, method, secret) = match credentials {
        ClientCredentials::None { client_id } => (client_id, AUTH_NONE, None),
        ClientCredentials::Basic {
            client_id,
            client_secret,
        } => (client_id, AUTH_BASIC, Some(client_secret)),
        ClientCredentials::Post {
            client_id,
            client_secret,
        } => (client_id, AUTH_POST, Some(client_secret)),
    };
    let registered = fetch_row(db, client_id)
        .await
        .map_err(ClientAuthError::Failed)?
        .filter(|r| r.token_endpoint_auth_method == method);
    let matched = match secret {
        None => registered.is_some(),
        Some(secret) => {
            let secret = secret.to_string();
            let phc = registered.as_ref().and_then(|r| r.secret_hash.clone());
            off_runtime(permits, move || verify_secret(&secret, phc.as_deref())).await?
        }
    };
    match registered {
        Some(row) if matched => from_row(row).map_err(ClientAuthError::Failed),
        _ => Err(ClientAuthError::InvalidClient),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::db::test_pool;

    const FIXTURE: &str = include_str!("../ory/fixtures/hydra/client.json");
    const FIXTURE_ID: &str = "forseti-fixture-client";

    fn permits() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(2))
    }

    fn fixture() -> OAuthClient {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn client(id: &str, method: &str) -> OAuthClient {
        OAuthClient {
            client_id: Some(id.to_string()),
            client_name: Some(id.to_string()),
            redirect_uris: Some(vec!["https://app.example/cb".to_string()]),
            token_endpoint_auth_method: Some(method.to_string()),
            ..OAuthClient::default()
        }
    }

    fn client_error(e: &anyhow::Error) -> Option<&ClientError> {
        e.downcast_ref::<ClientError>()
    }

    fn is_not_found(e: &anyhow::Error) -> bool {
        matches!(client_error(e), Some(ClientError::NotFound))
    }

    async fn stored_hash(db: &DbPool, id: &str) -> Option<String> {
        fetch_row(db, id).await.unwrap().unwrap().secret_hash
    }

    /// `c` without what the store sets itself: the secret, `created_at` and `updated_at`.
    fn without_server_set(mut c: OAuthClient) -> OAuthClient {
        c.client_secret = None;
        c.created_at = None;
        c.extra.remove("updated_at");
        c
    }

    async fn basic(db: &DbPool, id: &str, secret: &str) -> Result<OAuthClient, ClientAuthError> {
        let credentials = ClientCredentials::Basic {
            client_id: id,
            client_secret: secret,
        };
        authenticate(db, &permits(), credentials).await
    }

    #[tokio::test]
    async fn hydra_fixture_round_trips_through_create_get_and_put() {
        let db = test_pool().await;
        let p = permits();
        let input = fixture();
        assert_eq!(input.extra["skip_logout_consent"], Value::Null);
        assert_eq!(
            input.extra["authorization_code_grant_access_token_lifespan"],
            Value::Null
        );

        let created = create(&db, &p, input.clone()).await.unwrap();
        assert_eq!(created.client_secret.as_deref().map(str::len), Some(40));
        let fetched = get(&db, FIXTURE_ID).await.unwrap().unwrap();
        assert_eq!(fetched.client_secret, None);
        assert_ne!(fetched.created_at, input.created_at);
        assert_ne!(fetched.extra["updated_at"], input.extra["updated_at"]);

        let put = update(&db, &p, FIXTURE_ID, fetched.clone()).await.unwrap();
        assert_eq!(put.client_secret, None);
        let after = get(&db, FIXTURE_ID).await.unwrap().unwrap();
        assert_eq!(after.created_at, fetched.created_at);

        let want = without_server_set(input);
        for got in [created.clone(), fetched, put, after.clone()] {
            assert_eq!(without_server_set(got), want);
        }
        let wire = serde_json::to_string(&after).unwrap();
        assert!(!wire.contains("$argon2"), "{wire}");
        assert!(!after.extra.contains_key("client_secret"));
        let secret = created.client_secret.as_deref().unwrap();
        assert!(basic(&db, FIXTURE_ID, secret).await.is_ok());
        assert!(basic(&db, FIXTURE_ID, "wrong").await.is_err());
    }

    #[tokio::test]
    async fn create_mints_a_secret_for_confidential_clients_only() {
        let db = test_pool().await;
        let p = permits();

        let public = create(&db, &p, client("pub", AUTH_NONE)).await.unwrap();
        assert_eq!(public.client_secret, None);
        assert_eq!(stored_hash(&db, "pub").await, None);

        let mut supplied = client("pub-with-secret", AUTH_NONE);
        supplied.client_secret = Some("ignored".to_string());
        let public = create(&db, &p, supplied).await.unwrap();
        assert_eq!(public.client_secret, None);
        assert_eq!(stored_hash(&db, "pub-with-secret").await, None);

        let conf = create(&db, &p, client("conf", AUTH_POST)).await.unwrap();
        let secret = conf.client_secret.clone().unwrap();
        assert_eq!(secret.len(), 40);
        let hash = stored_hash(&db, "conf").await.unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash}"
        );
        assert_eq!(get(&db, "conf").await.unwrap().unwrap().client_secret, None);
        let listed = list(&db, 10, None, None).await.unwrap();
        assert_eq!(listed.len(), 3);
        assert!(listed.iter().all(|c| c.client_secret.is_none()));

        let mut given = client("given", AUTH_BASIC);
        given.client_secret = Some("operator-secret".to_string());
        let given = create(&db, &p, given).await.unwrap();
        assert_eq!(given.client_secret.as_deref(), Some("operator-secret"));
        assert!(basic(&db, "given", "operator-secret").await.is_ok());

        let err = create(&db, &p, client("conf", AUTH_NONE))
            .await
            .unwrap_err();
        assert!(matches!(client_error(&err), Some(ClientError::Conflict)));
    }

    #[tokio::test]
    async fn create_generates_a_uuid_and_defaults_the_method() {
        let db = test_pool().await;
        let created = create(&db, &permits(), OAuthClient::default())
            .await
            .unwrap();
        let id = created.client_id.unwrap();
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "{id}");
        assert_eq!(
            created.token_endpoint_auth_method.as_deref(),
            Some(AUTH_BASIC)
        );
        assert!(created.client_secret.is_some());
    }

    #[tokio::test]
    async fn create_and_update_refuse_invalid_clients() {
        let db = test_pool().await;
        let p = permits();
        let mut bad = vec![client("x", "private_key_jwt")];
        for uri in ["/cb", "https://app.example/cb#frag", "not a uri"] {
            let mut c = client("x", AUTH_NONE);
            c.redirect_uris = Some(vec![uri.to_string()]);
            bad.push(c);
        }
        let mut c = client("x", AUTH_NONE);
        c.post_logout_redirect_uris = Some(vec!["https://app.example/bye#x".to_string()]);
        bad.push(c);
        create(&db, &p, client("x", AUTH_NONE)).await.unwrap();
        for c in bad {
            let err = create(&db, &p, c.clone()).await.unwrap_err();
            assert!(matches!(client_error(&err), Some(ClientError::Invalid(_))));
            let err = update(&db, &p, "x", c).await.unwrap_err();
            assert!(matches!(client_error(&err), Some(ClientError::Invalid(_))));
        }
        let mut native = client("native", AUTH_NONE);
        native.redirect_uris = Some(vec!["com.example.app:/oauth".to_string()]);
        create(&db, &p, native).await.unwrap();
    }

    #[test]
    fn redirect_uri_table() {
        for uri in [
            "https://app.example.com/cb",
            "http://127.0.0.1:5555/callback",
            "http://grafana.lan/login/generic_oauth",
            "com.example.app:/oauth2redirect",
            "myapp:/cb",
            "HTTPS://app.example.com/cb",
        ] {
            assert!(acceptable_uri(uri), "{uri}");
        }
        for uri in [
            "/cb",
            "not a uri",
            "https://app.example/cb#frag",
            "https://app.example/cb#",
            "java\tscript:alert(1)",
            "https://app.example/cb\r\nSet-Cookie: x=1",
            "https://app.example/c\nb",
            " https://app.example/cb",
            "https://app.example/cb ",
            "https://app.example/\u{7f}cb",
            "https://app.example/\u{0}cb",
            "https://good@evil/",
            "https://user:pass@app.example/cb",
            "https://:pass@app.example/cb",
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "data:text/html,hi",
            "DATA:text/html,hi",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "FILE:///etc/passwd",
            "blob:https://app.example/1234",
            "https://app.example/caf\u{e9}",
            "https://b\u{fc}cher.example/cb",
            "https:app.example/cb",
            "https:/app.example/cb",
            "http:\\\\app.example/cb",
            "HTTP:/app.example/cb",
        ] {
            assert!(!acceptable_uri(uri), "{uri:?}");
            let mut c = client("x", AUTH_NONE);
            c.redirect_uris = Some(vec![uri.to_string()]);
            assert!(matches!(check_uris(&c), Err(ClientError::Invalid(_))));
            let mut c = client("x", AUTH_NONE);
            c.post_logout_redirect_uris = Some(vec![uri.to_string()]);
            assert!(matches!(check_uris(&c), Err(ClientError::Invalid(_))));
        }
    }

    fn strings(v: &[&str]) -> Option<Vec<String>> {
        Some(v.iter().map(|s| (*s).to_string()).collect())
    }

    /// Whether create accepts `c`; an update of a stored client to `c` must agree.
    async fn store_accepts(db: &DbPool, c: OAuthClient) -> bool {
        let p = permits();
        let id = c.client_id.clone().unwrap();
        let created = create(db, &p, c.clone()).await;
        let updated = match &created {
            Ok(_) => update(db, &p, &id, c).await,
            Err(_) => {
                create(db, &p, client(&id, AUTH_BASIC)).await.unwrap();
                update(db, &p, &id, c).await
            }
        };
        delete(db, &id).await.unwrap();
        for r in [&created, &updated] {
            if let Err(e) = r {
                assert!(
                    matches!(client_error(e), Some(ClientError::Invalid(_))),
                    "{e:#}"
                );
            }
        }
        assert_eq!(created.is_ok(), updated.is_ok());
        created.is_ok()
    }

    #[tokio::test]
    async fn grant_and_response_type_allowlist() {
        let db = test_pool().await;
        let pam = crate::oauth::device::pam_client_model("forseti-linux-pam", "s3cret");
        // The model `cimd::upsert_client` builds from a document.
        let cimd = OAuthClient {
            client_id: Some("https://cimd.example/client".to_string()),
            client_name: Some("CIMD app".to_string()),
            client_uri: Some("https://cimd.example/".to_string()),
            logo_uri: Some("https://cimd.example/logo.png".to_string()),
            token_endpoint_auth_method: Some(AUTH_NONE.to_string()),
            grant_types: strings(&["authorization_code", "refresh_token"]),
            response_types: strings(&["code"]),
            scope: Some("openid".to_string()),
            redirect_uris: strings(&["https://cimd.example/cb"]),
            skip_consent: Some(false),
            ..OAuthClient::default()
        };
        // The M2M preset in `admin/clients/presets.rs`.
        let m2m = OAuthClient {
            grant_types: strings(&["client_credentials"]),
            response_types: strings(&["token"]),
            ..client("m2m", AUTH_POST)
        };
        let typed = |grants: Option<Vec<String>>, responses: Option<Vec<String>>| OAuthClient {
            grant_types: grants,
            response_types: responses,
            ..client("typed", AUTH_BASIC)
        };
        let device = "urn:ietf:params:oauth:grant-type:device_code";
        let accepted = [
            ("pam", pam),
            ("cimd", cimd),
            ("fixture", fixture()),
            ("unset", typed(None, None)),
            ("empty", typed(Some(vec![]), Some(vec![]))),
            (
                "all",
                typed(
                    strings(&["authorization_code", "refresh_token", device]),
                    strings(&["code", "id_token"]),
                ),
            ),
        ];
        for (name, c) in accepted {
            assert!(store_accepts(&db, c).await, "{name}");
        }
        let refused = [
            ("m2m", m2m),
            (
                "client_credentials",
                typed(strings(&["client_credentials"]), None),
            ),
            (
                "implicit",
                typed(strings(&["authorization_code", "implicit"]), None),
            ),
            ("password", typed(strings(&["password"]), None)),
            (
                "joined",
                typed(strings(&["authorization_code,refresh_token"]), None),
            ),
            ("token", typed(None, strings(&["token"]))),
            ("hybrid", typed(None, strings(&["code id_token"]))),
            ("none", typed(None, strings(&["none"]))),
            ("case", typed(None, strings(&["Code"]))),
        ];
        for (name, c) in refused {
            assert!(!store_accepts(&db, c).await, "{name}");
        }
    }

    #[tokio::test]
    async fn client_and_logout_uris_must_be_absolute_http() {
        let db = test_pool().await;
        type Field = fn(&mut OAuthClient) -> &mut Option<String>;
        let fields: [(&str, Field); 4] = [
            ("backchannel_logout_uri", |c| &mut c.backchannel_logout_uri),
            ("frontchannel_logout_uri", |c| {
                &mut c.frontchannel_logout_uri
            }),
            ("client_uri", |c| &mut c.client_uri),
            ("logo_uri", |c| &mut c.logo_uri),
        ];
        let good = [
            "",
            "https://app.example/logout",
            "http://127.0.0.1:9999/bcl",
            "HTTPS://app.example/",
        ];
        let bad = [
            "https://user@app.example/logout",
            "https://user:pass@app.example/logout",
            "https://app.example/logout#frag",
            "https://app.example/log\nout",
            "https://app.example/\u{0}",
            "https://app.example/log\tout",
            "/logout",
            "app.example/logout",
            "ftp://app.example/logout",
            "myapp:/logout",
            "javascript:alert(1)",
            "https:app.example/logout",
        ];
        for (name, field) in fields {
            for (uri, want) in good
                .iter()
                .map(|u| (u, true))
                .chain(bad.iter().map(|u| (u, false)))
            {
                let mut c = client("uris", AUTH_BASIC);
                *field(&mut c) = Some((*uri).to_string());
                assert_eq!(store_accepts(&db, c).await, want, "{name} {uri:?}");
            }
            let mut c = client("uris", AUTH_BASIC);
            *field(&mut c) = None;
            assert!(store_accepts(&db, c).await, "{name} unset");
        }
    }

    #[tokio::test]
    async fn rotate_replaces_the_secret() {
        let db = test_pool().await;
        let p = permits();
        let old = create(&db, &p, client("conf", AUTH_BASIC))
            .await
            .unwrap()
            .client_secret
            .unwrap();
        let rotated = rotate_secret(&db, &p, "conf").await.unwrap();
        let new = rotated.client_secret.clone().unwrap();
        assert_ne!(new, old);
        assert_eq!(new.len(), 40);
        assert!(matches!(
            basic(&db, "conf", &old).await,
            Err(ClientAuthError::InvalidClient)
        ));
        assert!(basic(&db, "conf", &new).await.is_ok());
        assert_eq!(get(&db, "conf").await.unwrap().unwrap().client_secret, None);

        let err = rotate_secret(&db, &p, "missing").await.unwrap_err();
        assert!(is_not_found(&err));
    }

    #[tokio::test]
    async fn rotate_on_a_public_client_returns_a_secret_it_never_accepts() {
        let db = test_pool().await;
        let p = permits();
        create(&db, &p, client("pub", AUTH_NONE)).await.unwrap();
        let rotated = rotate_secret(&db, &p, "pub").await.unwrap();
        let secret = rotated.client_secret.unwrap();
        assert_eq!(
            rotated.token_endpoint_auth_method.as_deref(),
            Some(AUTH_NONE)
        );
        assert!(
            authenticate(&db, &p, ClientCredentials::None { client_id: "pub" })
                .await
                .is_ok()
        );
        assert!(matches!(
            basic(&db, "pub", &secret).await,
            Err(ClientAuthError::InvalidClient)
        ));
    }

    #[tokio::test]
    async fn update_keeps_replaces_or_clears_the_secret() {
        let db = test_pool().await;
        let p = permits();
        let first = create(&db, &p, client("conf", AUTH_BASIC))
            .await
            .unwrap()
            .client_secret
            .unwrap();

        let mut edit = get(&db, "conf").await.unwrap().unwrap();
        edit.client_name = Some("Renamed".to_string());
        edit.client_id = Some("ignored".to_string());
        let updated = update(&db, &p, "conf", edit.clone()).await.unwrap();
        assert_eq!(updated.client_name.as_deref(), Some("Renamed"));
        assert_eq!(updated.client_id.as_deref(), Some("conf"));
        assert_eq!(updated.client_secret, None);
        assert!(basic(&db, "conf", &first).await.is_ok());

        edit.client_secret = Some("replaced".to_string());
        let updated = update(&db, &p, "conf", edit.clone()).await.unwrap();
        assert_eq!(updated.client_secret.as_deref(), Some("replaced"));
        assert!(basic(&db, "conf", &first).await.is_err());
        assert!(basic(&db, "conf", "replaced").await.is_ok());

        edit.client_secret = None;
        edit.token_endpoint_auth_method = Some(AUTH_NONE.to_string());
        update(&db, &p, "conf", edit).await.unwrap();
        assert_eq!(stored_hash(&db, "conf").await, None);

        let err = update(&db, &p, "missing", client("missing", AUTH_NONE))
            .await
            .unwrap_err();
        assert!(is_not_found(&err));
        assert!(get(&db, "missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_pages_by_client_id() {
        let db = test_pool().await;
        let p = permits();
        let ids = ["c3", "c0", "c6", "c1", "c5", "c2", "c4"];
        for id in ids {
            create(&db, &p, client(id, AUTH_NONE)).await.unwrap();
        }
        for (id, name) in [("b9", "Other"), ("c35", "Other")] {
            let mut c = client(id, AUTH_NONE);
            c.client_name = Some(name.to_string());
            create(&db, &p, c).await.unwrap();
        }

        // The admin list's paging: the next token is the last id of a full page.
        let walk = |name: Option<&'static str>, size: i64| {
            let db = db.clone();
            async move {
                let mut pages: Vec<Vec<String>> = Vec::new();
                let mut token: Option<String> = None;
                loop {
                    let page = list(&db, size, token.as_deref(), name).await.unwrap();
                    let page_ids: Vec<String> =
                        page.into_iter().map(|c| c.client_id.unwrap()).collect();
                    let full = page_ids.len() as i64 == size;
                    token = page_ids.last().cloned();
                    pages.push(page_ids);
                    if !full {
                        return pages;
                    }
                }
            }
        };

        let pages = walk(None, 3).await;
        assert_eq!(
            pages,
            [
                vec!["b9", "c0", "c1"],
                vec!["c2", "c3", "c35"],
                vec!["c4", "c5", "c6"],
                vec![]
            ]
        );
        assert_eq!(
            walk(Some("Other"), 1).await,
            [vec!["b9"], vec!["c35"], vec![]]
        );
        assert_eq!(walk(Some("c2"), 3).await, [vec!["c2"]]);
        assert_eq!(list(&db, 0, None, None).await.unwrap().len(), 1);
        assert_eq!(list(&db, 10_000, None, None).await.unwrap().len(), 9);
    }

    #[tokio::test]
    async fn authentication_matrix() {
        let db = test_pool().await;
        let p = permits();
        create(&db, &p, client("pub", AUTH_NONE)).await.unwrap();
        for (id, method) in [("basic", AUTH_BASIC), ("post", AUTH_POST)] {
            let mut c = client(id, method);
            c.client_secret = Some(format!("{id}-secret"));
            create(&db, &p, c).await.unwrap();
        }
        let none = |client_id| ClientCredentials::None { client_id };
        let basic = |client_id, client_secret| ClientCredentials::Basic {
            client_id,
            client_secret,
        };
        let post = |client_id, client_secret| ClientCredentials::Post {
            client_id,
            client_secret,
        };

        for (credentials, want) in [
            (none("pub"), "pub"),
            (basic("basic", "basic-secret"), "basic"),
            (post("post", "post-secret"), "post"),
        ] {
            let got = authenticate(&db, &p, credentials).await.unwrap();
            assert_eq!(got.client_id.as_deref(), Some(want));
            assert_eq!(got.client_secret, None);
        }

        for credentials in [
            none("basic"),
            none("post"),
            none("unknown"),
            basic("pub", "anything"),
            post("pub", "anything"),
            post("basic", "basic-secret"),
            basic("post", "post-secret"),
            basic("basic", "wrong"),
            post("post", "wrong"),
            basic("basic", ""),
            basic("unknown", "basic-secret"),
            post("unknown", "post-secret"),
        ] {
            let err = authenticate(&db, &p, credentials).await.unwrap_err();
            assert!(matches!(err, ClientAuthError::InvalidClient), "{err:?}");
            assert_eq!(err.to_string(), "invalid_client");
        }
    }

    #[tokio::test]
    async fn every_presented_secret_reaches_argon2() {
        let db = test_pool().await;
        create(&db, &permits(), client("pub", AUTH_NONE))
            .await
            .unwrap();
        let closed = Arc::new(Semaphore::new(1));
        closed.close();
        for credentials in [
            ClientCredentials::Basic {
                client_id: "unknown",
                client_secret: "s",
            },
            ClientCredentials::Post {
                client_id: "pub",
                client_secret: "s",
            },
        ] {
            let err = authenticate(&db, &closed, credentials).await.unwrap_err();
            assert!(matches!(err, ClientAuthError::Failed(_)), "{err:?}");
        }
        let err = authenticate(
            &db,
            &closed,
            ClientCredentials::None {
                client_id: "unknown",
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ClientAuthError::InvalidClient));
    }

    #[test]
    fn dummy_hash_has_the_secret_parameters() {
        let parsed = PasswordHash::new(DUMMY_PHC).unwrap();
        assert_eq!(
            Params::try_from(&parsed).unwrap(),
            Params::try_from(&PasswordHash::new(&hash_secret("x").unwrap()).unwrap()).unwrap()
        );
        assert!(!verify_secret("x", None));
        assert!(!verify_secret("x", Some("not a phc")));
        assert!(verify_secret("x", Some(&hash_secret("x").unwrap())));
        let long = "x".repeat(MAX_SECRET_BYTES + 1);
        assert!(!verify_secret(&long, Some(&hash_secret(&long).unwrap())));
        let edge = "x".repeat(MAX_SECRET_BYTES);
        assert!(verify_secret(&edge, Some(&hash_secret(&edge).unwrap())));
    }

    #[tokio::test]
    async fn an_oversized_secret_is_refused_after_one_argon2_run() {
        let db = test_pool().await;
        let p = permits();
        let secret = create(&db, &p, client("conf", AUTH_BASIC))
            .await
            .unwrap()
            .client_secret
            .unwrap();
        let oversized = format!("{secret}{}", "x".repeat(MAX_SECRET_BYTES));
        let err = basic(&db, "conf", &oversized).await.unwrap_err();
        assert!(matches!(err, ClientAuthError::InvalidClient), "{err:?}");

        let closed = Arc::new(Semaphore::new(1));
        closed.close();
        let credentials = ClientCredentials::Basic {
            client_id: "conf",
            client_secret: &oversized,
        };
        let err = authenticate(&db, &closed, credentials).await.unwrap_err();
        assert!(matches!(err, ClientAuthError::Failed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn delete_removes_the_client() {
        let db = test_pool().await;
        create(&db, &permits(), client("gone", AUTH_NONE))
            .await
            .unwrap();
        delete(&db, "gone").await.unwrap();
        assert!(get(&db, "gone").await.unwrap().is_none());
        assert!(is_not_found(&delete(&db, "gone").await.unwrap_err()));
    }

    #[tokio::test]
    #[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
    async fn create_list_and_rotate_on_postgres() {
        let db = crate::db::test_postgres_pool().await;
        let p = permits();
        let run = uuid::Uuid::new_v4().simple().to_string();
        let ids: Vec<String> = (0..5).map(|i| format!("{run}{i:02}")).collect();
        for id in ids.iter().rev() {
            let mut c = client(id, AUTH_NONE);
            c.client_name = Some(run.clone());
            c.metadata = Some(json!({"forseti": {"client_type": "web_app"}}));
            create(&db, &p, c).await.unwrap();
        }
        let mut seen = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = list(&db, 2, token.as_deref(), Some(&run)).await.unwrap();
            let full = page.len() == 2;
            token = page.last().and_then(|c| c.client_id.clone());
            seen.extend(page.into_iter().map(|c| c.client_id.unwrap()));
            if !full {
                break;
            }
        }
        let conf_id = format!("{run}c");
        let mut conf = client(&conf_id, AUTH_BASIC);
        conf.client_name = Some(run.clone());
        let old = create(&db, &p, conf).await.unwrap().client_secret.unwrap();
        let new = rotate_secret(&db, &p, &conf_id)
            .await
            .unwrap()
            .client_secret
            .unwrap();
        let old_ok = basic(&db, &conf_id, &old).await.is_ok();
        let new_ok = basic(&db, &conf_id, &new).await.is_ok();
        let fetched = get(&db, &ids[0]).await.unwrap().unwrap();

        for id in ids.iter().chain([&conf_id]) {
            delete(&db, id).await.unwrap();
        }
        assert_eq!(seen, ids);
        assert!(!old_ok);
        assert!(new_ok);
        assert_eq!(
            fetched.metadata,
            Some(json!({"forseti": {"client_type": "web_app"}}))
        );
    }
}
