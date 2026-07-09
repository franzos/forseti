//! Ownership-proven email domains for internal-org auto-join.

use chrono::Utc;
use diesel::prelude::*;
use rand::Rng;
use serde::Serialize;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{org_allowed_domains, organizations};

// Selectable maps every column; some fields (org_id, added_by, added_at) are
// carried for completeness but not read back, so scope the allow to the struct.
#[allow(dead_code)]
#[derive(Queryable, Selectable, Debug, Clone, Serialize)]
#[diesel(table_name = org_allowed_domains)]
pub struct OrgAllowedDomain {
    pub org_id: String,
    pub domain: String,
    pub method: String,
    pub verification_token: String,
    pub verified_at: Option<String>,
    pub added_by: Option<String>,
    pub added_at: String,
}

#[derive(Insertable)]
#[diesel(table_name = org_allowed_domains)]
struct NewOrgAllowedDomain<'a> {
    org_id: &'a str,
    domain: &'a str,
    method: &'a str,
    verification_token: &'a str,
    added_by: Option<&'a str>,
    added_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddDomainOutcome {
    Added,
    AlreadyPending,
}

pub async fn add_pending_domain(
    db: &DbPool,
    org_id: &str,
    domain: &str,
    method: &str,
    token: &str,
    added_by: Option<&str>,
) -> anyhow::Result<AddDomainOutcome> {
    let (o, d, m, ab) = (
        org_id.to_string(),
        domain.to_string(),
        method.to_string(),
        added_by.map(str::to_string),
    );
    // Email-method tokens are bearer secrets (mailbox-control proof), so only
    // their hash is persisted; DNS/HTTP tokens are published by the owner and
    // stay plaintext so the settings page can display them.
    let t = if method == "email" {
        hash_email_token(token)
    } else {
        token.to_string()
    };
    let now = Utc::now().to_rfc3339();
    let result = db_interact!(db, |conn| {
        diesel::insert_into(org_allowed_domains::table)
            .values(NewOrgAllowedDomain {
                org_id: &o,
                domain: &d,
                method: &m,
                verification_token: &t,
                added_by: ab.as_deref(),
                added_at: now.clone(),
            })
            .execute(conn)
    });
    match result {
        Ok(_) => Ok(AddDomainOutcome::Added),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Ok(AddDomainOutcome::AlreadyPending),
        Err(e) => Err(e.into()),
    }
}

pub async fn list_domains_for_org(
    db: &DbPool,
    org_id: &str,
) -> anyhow::Result<Vec<OrgAllowedDomain>> {
    let o = org_id.to_string();
    let rows: Vec<OrgAllowedDomain> = db_interact!(db, |conn| {
        org_allowed_domains::table
            .filter(org_allowed_domains::org_id.eq(&o))
            .order(org_allowed_domains::added_at.asc())
            .select(OrgAllowedDomain::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

pub async fn count_domains_for_org(db: &DbPool, org_id: &str) -> anyhow::Result<i64> {
    let o = org_id.to_string();
    let count: i64 = db_interact!(db, |conn| {
        org_allowed_domains::table
            .filter(org_allowed_domains::org_id.eq(&o))
            .count()
            .get_result(conn)
    })?;
    Ok(count)
}

pub async fn get_domain(
    db: &DbPool,
    org_id: &str,
    domain: &str,
) -> anyhow::Result<Option<OrgAllowedDomain>> {
    let (o, d) = (org_id.to_string(), domain.to_string());
    let row: Option<OrgAllowedDomain> = db_interact!(db, |conn| {
        org_allowed_domains::table
            .filter(org_allowed_domains::org_id.eq(&o))
            .filter(org_allowed_domains::domain.eq(&d))
            .select(OrgAllowedDomain::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainVerifyOutcome {
    Verified,
    /// The unique partial index rejected the write: some other org already
    /// owns this domain. The re-check IS the constraint, not a separate SELECT.
    AlreadyClaimedElsewhere,
    NotFound,
    /// Email method only: the pasted-back code didn't match the stored
    /// token. Distinct from `NotFound` so the settings page can render
    /// "wrong code" instead of "unknown domain".
    TokenMismatch,
}

pub async fn mark_domain_verified(
    db: &DbPool,
    org_id: &str,
    domain: &str,
) -> anyhow::Result<DomainVerifyOutcome> {
    let (o, d) = (org_id.to_string(), domain.to_string());
    let now = Utc::now().to_rfc3339();
    let result = db_interact!(db, |conn| {
        diesel::update(
            org_allowed_domains::table
                .filter(org_allowed_domains::org_id.eq(&o))
                .filter(org_allowed_domains::domain.eq(&d)),
        )
        .set(org_allowed_domains::verified_at.eq(Some(now.clone())))
        .execute(conn)
    });
    match result {
        Ok(0) => Ok(DomainVerifyOutcome::NotFound),
        Ok(_) => Ok(DomainVerifyOutcome::Verified),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Ok(DomainVerifyOutcome::AlreadyClaimedElsewhere),
        Err(e) => Err(e.into()),
    }
}

pub async fn delete_domain(db: &DbPool, org_id: &str, domain: &str) -> anyhow::Result<()> {
    let (o, d) = (org_id.to_string(), domain.to_string());
    db_interact!(db, |conn| {
        diesel::delete(
            org_allowed_domains::table
                .filter(org_allowed_domains::org_id.eq(&o))
                .filter(org_allowed_domains::domain.eq(&d)),
        )
        .execute(conn)
        .map(|_| ())
    })?;
    Ok(())
}

/// Only a `verified_at IS NOT NULL` row matches; the global partial unique
/// index guarantees at most one such row per domain across all orgs.
pub async fn lookup_proven_org_by_domain(
    db: &DbPool,
    domain: &str,
) -> anyhow::Result<Option<crate::orgs::db::Org>> {
    let d = domain.to_string();
    let row: Option<(OrgAllowedDomain, crate::orgs::db::Org)> = db_interact!(db, |conn| {
        org_allowed_domains::table
            .inner_join(organizations::table)
            .filter(org_allowed_domains::domain.eq(&d))
            .filter(org_allowed_domains::verified_at.is_not_null())
            .select((
                OrgAllowedDomain::as_select(),
                crate::orgs::db::Org::as_select(),
            ))
            .first(conn)
            .optional()
    })?;
    Ok(row.map(|(_, org)| org))
}

/// Reasonable, non-exhaustive denylist of public/freemail domains. Ownership
/// proof (DNS/HTTP/mailbox control) is the real gate; this shortcuts the
/// obviously-wrong case before wasting a challenge round-trip.
const FREEMAIL_DENYLIST: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "hotmail.co.uk",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.co.uk",
    "ymail.com",
    "rocketmail.com",
    "protonmail.com",
    "proton.me",
    "pm.me",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "gmx.com",
    "gmx.net",
    "gmx.de",
    "mail.com",
    "yandex.com",
    "yandex.ru",
    "zoho.com",
    "fastmail.com",
    "fastmail.fm",
    "tutanota.com",
    "tutanota.de",
    "mailbox.org",
    "hey.com",
    "web.de",
    "t-online.de",
    "freenet.de",
    "gmx.at",
    "gmx.ch",
    "yahoo.de",
    "yahoo.fr",
    "yahoo.it",
    "yahoo.es",
    "yahoo.ca",
    "yahoo.in",
    "outlook.de",
    "outlook.fr",
    "hotmail.fr",
    "hotmail.de",
    "hotmail.it",
    "hotmail.es",
    "live.co.uk",
    "mail.ru",
    "inbox.ru",
    "list.ru",
    "bk.ru",
    "qq.com",
    "163.com",
    "126.com",
    "sina.com",
    "naver.com",
    "daum.net",
    "seznam.cz",
    "wp.pl",
    "o2.pl",
];

pub fn is_freemail_domain(domain: &str) -> bool {
    FREEMAIL_DENYLIST.contains(&domain)
}

/// Lowercase, strip a leading scheme/path/query/fragment/userinfo, strip a
/// trailing dot, reject `host:port` shapes and bare IP literals, and require
/// at least one label plus a TLD dot. Returns `None` on anything that isn't a
/// plausible registrable domain.
pub fn normalize_domain(input: &str) -> Option<String> {
    let s = input.trim().to_lowercase();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(&s);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    let s = s.rsplit_once('@').map_or(s, |(_, h)| h);
    let s = s.strip_suffix('.').unwrap_or(s);
    // Reject a `host:port` shape and bare IP literals (owning an address
    // isn't owning a domain).
    if s.contains(':') || s.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return None;
    }
    let valid = s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            // Reject raw punycode (`xn--`) labels: without IDNA/uts46 folding
            // they enable homograph/lookalike claims. IDN domains can't use
            // domain auto-join, which is an acceptable trade for fail-closed.
            && !label.starts_with("xn--")
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    valid.then(|| s.to_string())
}

pub fn mint_verification_token() -> String {
    let bytes: [u8; 24] = rand::rng().random();
    hex::encode(bytes)
}

/// SHA-256 hex of an email-method token. Used both to store the token at rest
/// and to compare a pasted-back code (constant-time), so the plaintext bearer
/// secret is never persisted.
pub fn hash_email_token(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.trim().as_bytes()))
}

const HTTP_VERIFY_PATH: &str = "/.well-known/forseti-domain-verify";
const MAX_VERIFY_BODY_BYTES: usize = 8 * 1024;

// Payload strings are diagnostic detail surfaced via `Debug`; callers treat any
// failure as "not verified yet" and don't destructure them.
#[allow(dead_code)]
#[derive(Debug)]
pub enum VerifyError {
    /// Rejected by the pre-flight SSRF check (bad scheme/loopback/private IP).
    UnsafeTarget(String),
    Transport(String),
    BodyTooLarge,
}

fn http_verify_client(timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(timeout)
        // A redirect to a private address would otherwise bypass both the
        // save-time and connect-time SSRF checks below.
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(crate::webhook::guarded_resolver())
        .build()
        .expect("static reqwest client config")
}

/// `true` iff `body` contains `token` as a substring, decoded lossily as
/// UTF-8. Split out from [`verify_http_file`] so the match logic is
/// unit-testable without a live server.
fn body_contains_token(body: &[u8], token: &str) -> bool {
    String::from_utf8_lossy(body).contains(token)
}

/// GET `https://<domain>/.well-known/forseti-domain-verify`; verified iff the
/// response is 2xx and the (size-capped) body contains `expected_token`.
///
/// SSRF-guarded the same way outbound webhook delivery is: `domain` is
/// owner-submitted and attacker-influenceable, so this reuses (never
/// reimplements) `webhook::validate_webhook_url` (https-only, blocks
/// private/loopback/IMDS ranges at save-time) plus `webhook::guarded_resolver`
/// (DNS-rebinding guard re-checked at connect time), and disables redirects.
pub async fn verify_http_file(
    domain: &str,
    expected_token: &str,
    timeout: std::time::Duration,
) -> Result<bool, VerifyError> {
    let url = format!("https://{domain}{HTTP_VERIFY_PATH}");
    crate::webhook::validate_webhook_url(&url).map_err(VerifyError::UnsafeTarget)?;
    let resp = http_verify_client(timeout)
        .get(&url)
        .send()
        .await
        .map_err(|e| VerifyError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Ok(false);
    }
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| VerifyError::Transport(e.to_string()))?;
        buf.extend_from_slice(&chunk);
        if buf.len() > MAX_VERIFY_BODY_BYTES {
            return Err(VerifyError::BodyTooLarge);
        }
    }
    Ok(body_contains_token(&buf, expected_token))
}

/// Lazily-built shared resolver. Fallible rather than `expect`: an unreadable
/// system DNS config would otherwise panic inside a live verify request. On
/// failure it isn't cached, so a later request retries the build.
fn dns_resolver() -> Result<&'static hickory_resolver::TokioResolver, VerifyError> {
    static RESOLVER: std::sync::OnceLock<hickory_resolver::TokioResolver> =
        std::sync::OnceLock::new();
    if let Some(r) = RESOLVER.get() {
        return Ok(r);
    }
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|e| VerifyError::Transport(format!("DNS resolver config: {e}")))?
        .build()
        .map_err(|e| VerifyError::Transport(format!("DNS resolver build: {e}")))?;
    Ok(RESOLVER.get_or_init(|| resolver))
}

const DNS_VERIFY_LABEL: &str = "_forseti-verify";

/// Wall-clock bound on a single TXT lookup: an owner-submitted domain delegates
/// the query to an attacker-influenced authoritative nameserver, so cap it
/// (mirrors the HTTP verifier's explicit timeout) rather than trusting resolver
/// defaults to tie up the handler task.
const DNS_VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `true` iff any of `txt_data`'s chunks (as UTF-8) contains `token`.
/// Split out from [`verify_dns_txt`] so the match logic is unit-testable
/// without a live resolver.
fn txt_data_contains_token(txt_data: &[Box<[u8]>], token: &str) -> bool {
    txt_data
        .iter()
        .any(|chunk| std::str::from_utf8(chunk).is_ok_and(|s| s.contains(token)))
}

/// TXT lookup at `_forseti-verify.<domain>`; verified iff any returned TXT
/// record's decoded text contains `expected_token`. NXDOMAIN / no-records is
/// `Ok(false)` (not yet verified, not an error); transport/timeout failures
/// are `Err`.
pub async fn verify_dns_txt(domain: &str, expected_token: &str) -> Result<bool, VerifyError> {
    let name = format!("{DNS_VERIFY_LABEL}.{domain}.");
    let lookup = tokio::time::timeout(DNS_VERIFY_TIMEOUT, dns_resolver()?.txt_lookup(name))
        .await
        .map_err(|_| VerifyError::Transport("DNS TXT lookup timed out".to_string()))?;
    match lookup {
        Ok(lookup) => Ok(lookup.answers().iter().any(|record| {
            matches!(
                &record.data,
                hickory_resolver::proto::rr::RData::TXT(txt)
                    if txt_data_contains_token(&txt.txt_data, expected_token)
            )
        })),
        Err(e) if e.is_no_records_found() => Ok(false),
        Err(e) => Err(VerifyError::Transport(e.to_string())),
    }
}

/// Collapse CR/LF in an owner-controlled value before interpolating it into a
/// challenge email sent to a third party, so a crafted org name can't inject
/// extra lines into the message body.
fn sanitize_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

fn build_domain_challenge_email(
    brand_name: &str,
    domain: &str,
    token: &str,
    requesting_org_name: &str,
    actor_email: &str,
) -> (String, String) {
    let subject = format!("{brand_name}: confirm ownership of {domain}");
    let requesting_org_name = sanitize_line(requesting_org_name);
    let actor_email = sanitize_line(actor_email);
    let body = format!(
        "Hello,\n\n\"{requesting_org_name}\" ({actor_email}) on {brand_name} requested to link \
         the domain \"{domain}\" to their organization, using this mailbox as proof of \
         ownership.\n\n\
         If this was you, paste the following code back into the domain settings page to \
         confirm:\n\n  {token}\n\n\
         If you did not expect this, you can safely ignore this email.\n",
    );
    (subject, body)
}

/// Per-destination-domain cooldown so an owner can't fan challenge mail out to
/// a third party's `admin@`/`postmaster@` by looping add -> remove -> add (the
/// per-org row cap bounds concurrent rows, not send throughput). Process-local:
/// a multi-instance deployment multiplies the effective rate by the instance
/// count, so the audit trail (every add is logged with its actor) stays the
/// backstop.
const CHALLENGE_EMAIL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3600);

/// `true` (and records the send) iff a challenge to `domain` is on cooldown.
fn challenge_email_recently_sent(domain: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;
    static SENT: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let mut map = SENT
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    map.retain(|_, t| now.duration_since(*t) < CHALLENGE_EMAIL_COOLDOWN);
    if map.contains_key(domain) {
        return true;
    }
    map.insert(domain.to_string(), now);
    false
}

/// Sends the challenge token to `admin@<domain>` and `postmaster@<domain>`.
/// Best-effort per recipient — a bounce on one address doesn't block the
/// other; the owner pastes the token back into the UI to confirm. Names the
/// requesting org + actor in the body so this paid, owner-gated surface is
/// traceable back to the paying account rather than an anonymous spam vector.
/// Rate-limited per destination domain ([`challenge_email_recently_sent`]).
pub async fn send_domain_challenge_emails(
    cfg: &crate::config::AppConfig,
    domain: &str,
    token: &str,
    requesting_org_name: &str,
    actor_email: &str,
) {
    if challenge_email_recently_sent(domain) {
        tracing::warn!(domain = %domain, "domain challenge email suppressed: destination on cooldown");
        return;
    }
    let (subject, body) = build_domain_challenge_email(
        &cfg.brand.name,
        domain,
        token,
        requesting_org_name,
        actor_email,
    );
    for local in ["admin", "postmaster"] {
        let to = format!("{local}@{domain}");
        if let Err(e) =
            crate::mailer::send_text(cfg.email.as_ref(), &cfg.self_, &to, &subject, &body).await
        {
            tracing::warn!(error = ?e, recipient = %to, "domain verification courier dispatch failed");
        }
    }
}

/// Constant-time-compares the pasted-back token against the stored one
/// (hash-then-ct_eq, mirroring `audit::kratos_webhook`'s bearer compare, to
/// dodge both a length oracle and a timing side-channel), then marks the
/// domain verified.
pub async fn confirm_email_token(
    db: &DbPool,
    org_id: &str,
    domain: &str,
    submitted: &str,
) -> anyhow::Result<DomainVerifyOutcome> {
    let Some(row) = get_domain(db, org_id, domain).await? else {
        return Ok(DomainVerifyOutcome::NotFound);
    };
    if row.method != "email" {
        anyhow::bail!("domain {domain} is not using the email verification method");
    }
    // Stored value is already the token hash (email method hashes at rest);
    // compare the pasted-back code's hash against it in constant time.
    let submitted_hash = hash_email_token(submitted);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        submitted_hash.as_bytes(),
        row.verification_token.as_bytes(),
    )) {
        return Ok(DomainVerifyOutcome::TokenMismatch);
    }
    mark_domain_verified(db, org_id, domain).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::db::test_pool;

    #[tokio::test]
    async fn add_pending_domain_then_list_roundtrips() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok123", Some("alice"))
            .await
            .unwrap();
        let rows = list_domains_for_org(&db, "o1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, "acme.com");
        assert_eq!(rows[0].method, "dns_txt");
        assert!(rows[0].verified_at.is_none());
    }

    #[tokio::test]
    async fn add_pending_domain_duplicate_returns_already_pending() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok1", None)
            .await
            .unwrap();
        let outcome = add_pending_domain(&db, "o1", "acme.com", "http_file", "tok2", None)
            .await
            .unwrap();
        assert_eq!(outcome, AddDomainOutcome::AlreadyPending);
    }

    #[tokio::test]
    async fn mark_domain_verified_sets_timestamp() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok1", None)
            .await
            .unwrap();
        let outcome = mark_domain_verified(&db, "o1", "acme.com").await.unwrap();
        assert_eq!(outcome, DomainVerifyOutcome::Verified);
        let row = get_domain(&db, "o1", "acme.com").await.unwrap().unwrap();
        assert!(row.verified_at.is_some());
    }

    #[tokio::test]
    async fn mark_domain_verified_unknown_row_returns_not_found() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        let outcome = mark_domain_verified(&db, "o1", "nope.com").await.unwrap();
        assert_eq!(outcome, DomainVerifyOutcome::NotFound);
    }

    #[tokio::test]
    async fn mark_domain_verified_rejects_second_org_same_domain() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        crate::orgs::db::create_org(&db, "o2", "acme-inc", "Acme Inc", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok1", None)
            .await
            .unwrap();
        mark_domain_verified(&db, "o1", "acme.com").await.unwrap();
        add_pending_domain(&db, "o2", "acme.com", "dns_txt", "tok2", None)
            .await
            .unwrap();
        let outcome = mark_domain_verified(&db, "o2", "acme.com").await.unwrap();
        assert_eq!(outcome, DomainVerifyOutcome::AlreadyClaimedElsewhere);
    }

    #[tokio::test]
    async fn lookup_proven_org_by_domain_ignores_unverified_rows() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok1", None)
            .await
            .unwrap();
        assert!(lookup_proven_org_by_domain(&db, "acme.com")
            .await
            .unwrap()
            .is_none());
        mark_domain_verified(&db, "o1", "acme.com").await.unwrap();
        let org = lookup_proven_org_by_domain(&db, "acme.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(org.id, "o1");
    }

    #[tokio::test]
    async fn count_domains_for_org_counts_pending_and_verified() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        assert_eq!(count_domains_for_org(&db, "o1").await.unwrap(), 0);
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok1", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.org", "dns_txt", "tok2", None)
            .await
            .unwrap();
        mark_domain_verified(&db, "o1", "acme.com").await.unwrap();
        assert_eq!(count_domains_for_org(&db, "o1").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn delete_domain_removes_row() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok1", None)
            .await
            .unwrap();
        delete_domain(&db, "o1", "acme.com").await.unwrap();
        assert!(list_domains_for_org(&db, "o1").await.unwrap().is_empty());
    }

    #[test]
    fn normalize_domain_lowercases_and_strips_scheme() {
        assert_eq!(
            normalize_domain("https://Acme.COM/"),
            Some("acme.com".to_string())
        );
    }

    #[test]
    fn normalize_domain_rejects_ip_literal() {
        assert!(normalize_domain("127.0.0.1").is_none());
        assert!(normalize_domain("::1").is_none());
    }

    #[test]
    fn normalize_domain_rejects_port_and_no_tld() {
        assert!(normalize_domain("acme.com:8080").is_none());
        assert!(normalize_domain("localhost").is_none());
    }

    #[test]
    fn normalize_domain_strips_userinfo_and_trailing_dot() {
        assert_eq!(
            normalize_domain("user@Acme.com."),
            Some("acme.com".to_string())
        );
    }

    #[test]
    fn normalize_domain_rejects_punycode_label() {
        assert!(normalize_domain("xn--pple-43d.com").is_none());
        assert!(normalize_domain("shop.xn--80ak6aa92e.com").is_none());
        assert_eq!(normalize_domain("acme.com"), Some("acme.com".to_string()));
    }

    #[test]
    fn is_freemail_denies_common_providers() {
        assert!(is_freemail_domain("gmail.com"));
        assert!(is_freemail_domain("web.de"));
        assert!(is_freemail_domain("qq.com"));
        assert!(is_freemail_domain("mail.ru"));
        assert!(!is_freemail_domain("acme.com"));
    }

    #[tokio::test]
    async fn add_pending_domain_hashes_email_token_at_rest() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "email", "plain-secret", None)
            .await
            .unwrap();
        let row = get_domain(&db, "o1", "acme.com").await.unwrap().unwrap();
        assert_ne!(row.verification_token, "plain-secret");
        assert_eq!(row.verification_token, hash_email_token("plain-secret"));
        // DNS/HTTP tokens are published by the owner, so they stay plaintext.
        add_pending_domain(&db, "o1", "acme.org", "dns_txt", "public-tok", None)
            .await
            .unwrap();
        let dns = get_domain(&db, "o1", "acme.org").await.unwrap().unwrap();
        assert_eq!(dns.verification_token, "public-tok");
    }

    #[test]
    fn mint_verification_token_is_nonempty_hex_and_unique() {
        let a = mint_verification_token();
        let b = mint_verification_token();
        assert_ne!(a, b);
        assert!(!a.is_empty());
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn http_verify_path_is_stable() {
        assert_eq!(HTTP_VERIFY_PATH, "/.well-known/forseti-domain-verify");
    }

    #[test]
    fn body_contains_token_matches_substring() {
        assert!(body_contains_token(b"prefix TOKEN123 suffix", "TOKEN123"));
        assert!(!body_contains_token(b"nope", "TOKEN123"));
    }

    #[test]
    fn forseti_verify_txt_name_shape() {
        let domain = "acme.com";
        assert_eq!(
            format!("{DNS_VERIFY_LABEL}.{domain}."),
            "_forseti-verify.acme.com."
        );
    }

    #[test]
    fn txt_data_contains_token_matches_any_chunk() {
        let chunks: Vec<Box<[u8]>> = vec![
            b"unrelated".to_vec().into_boxed_slice(),
            b"forseti-verify=TOKEN123".to_vec().into_boxed_slice(),
        ];
        assert!(txt_data_contains_token(&chunks, "TOKEN123"));
        assert!(!txt_data_contains_token(&chunks, "NOPE"));
    }

    #[test]
    fn domain_challenge_email_contains_domain_and_token() {
        let (subject, body) = build_domain_challenge_email(
            "Forseti",
            "acme.com",
            "abc123",
            "Acme Inc",
            "alice@acme.com",
        );
        assert!(subject.contains("acme.com"));
        assert!(body.contains("abc123"));
        assert!(body.contains("Acme Inc"));
        assert!(body.contains("alice@acme.com"));
    }

    #[tokio::test]
    async fn confirm_email_token_rejects_wrong_method() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "dns_txt", "tok1", None)
            .await
            .unwrap();
        let result = confirm_email_token(&db, "o1", "acme.com", "tok1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn confirm_email_token_accepts_matching_token() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "email", "tok1", None)
            .await
            .unwrap();
        let outcome = confirm_email_token(&db, "o1", "acme.com", "tok1")
            .await
            .unwrap();
        assert_eq!(outcome, DomainVerifyOutcome::Verified);
    }

    #[tokio::test]
    async fn confirm_email_token_rejects_wrong_token() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        add_pending_domain(&db, "o1", "acme.com", "email", "tok1", None)
            .await
            .unwrap();
        let outcome = confirm_email_token(&db, "o1", "acme.com", "wrong")
            .await
            .unwrap();
        assert_eq!(outcome, DomainVerifyOutcome::TokenMismatch);
        let row = get_domain(&db, "o1", "acme.com").await.unwrap().unwrap();
        assert!(row.verified_at.is_none());
    }
}
