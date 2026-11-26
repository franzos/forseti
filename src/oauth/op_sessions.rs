//! The Hydra login sessions (`sid`) Forseti accepted, keyed to the subject and
//! the Kratos session that signed them in. Hydra sends back-channel logout
//! only when a session is revoked by `sid`, and it can't list a subject's
//! sessions, so logout looks them up here.

use diesel::prelude::*;

use serde::Serialize;

#[cfg(feature = "oauth-native")]
use crate::backend::OAuthBackend;
use crate::backend::{IdentityBackend, IdentityImpl, OAuthImpl};
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{hydra_consent_grants, hydra_login_sessions};

/// Rows outlive Hydra's remembered login by this much before pruning.
const PRUNE_MARGIN_SECS: i64 = 24 * 60 * 60;
/// Prune horizon when Hydra remembers logins for its maximum (`remember_for = 0`).
const MAX_REMEMBER_SECS: i64 = 30 * 24 * 60 * 60;

/// Whether ending a session also revokes the grants it consented to. Plain
/// logout keeps them (Back-Channel Logout 1.0 §2.7); a security event revokes
/// them (RFC 9700 §4.14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantRevocation {
    Keep,
    Revoke,
}

/// The Kratos session a `sid` was recorded against.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecordedKratosSession {
    /// No row: the `sid` predates the table or was already forgotten.
    Unknown,
    /// A row without a Kratos session.
    None,
    Some(String),
}

/// Record (or refresh) the Hydra `sid` an accepted login belongs to, and prune
/// rows older than any login Hydra still remembers.
pub(crate) async fn record(
    db: &DbPool,
    sid: &str,
    subject: &str,
    kratos_session_id: &str,
    remember_for: i64,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    let horizon = if remember_for > 0 {
        remember_for.min(MAX_REMEMBER_SECS)
    } else {
        MAX_REMEMBER_SECS
    };
    let cutoff = crate::db::rfc3339(
        now - chrono::Duration::seconds(horizon.saturating_add(PRUNE_MARGIN_SECS)),
    );
    let (sid, subject, ksid, now) = (
        sid.to_string(),
        subject.to_string(),
        kratos_session_id.to_string(),
        crate::db::rfc3339(now),
    );
    db_interact!(db, |conn| {
        use diesel::upsert::excluded;
        diesel::delete(
            hydra_login_sessions::table.filter(hydra_login_sessions::created_at.lt(&cutoff)),
        )
        .execute(conn)?;
        diesel::delete(
            hydra_consent_grants::table.filter(hydra_consent_grants::created_at.lt(&cutoff)),
        )
        .execute(conn)?;
        diesel::insert_into(hydra_login_sessions::table)
            .values((
                hydra_login_sessions::sid.eq(&sid),
                hydra_login_sessions::subject.eq(&subject),
                hydra_login_sessions::kratos_session_id.eq(Some(&ksid)),
                hydra_login_sessions::created_at.eq(&now),
            ))
            .on_conflict(hydra_login_sessions::sid)
            .do_update()
            .set((
                hydra_login_sessions::subject.eq(excluded(hydra_login_sessions::subject)),
                hydra_login_sessions::kratos_session_id
                    .eq(excluded(hydra_login_sessions::kratos_session_id)),
                hydra_login_sessions::created_at.eq(excluded(hydra_login_sessions::created_at)),
            ))
            .execute(conn)
    })?;
    Ok(())
}

/// Record a consent request Hydra accepted under `sid`, so a security event
/// ending that `sid` can revoke the grant.
pub(crate) async fn record_consent(
    db: &DbPool,
    consent_request_id: &str,
    sid: &str,
    subject: &str,
    client_id: &str,
) -> anyhow::Result<()> {
    let (crid, sid, subject, client_id, now) = (
        consent_request_id.to_string(),
        sid.to_string(),
        subject.to_string(),
        client_id.to_string(),
        crate::db::now_rfc3339(),
    );
    db_interact!(db, |conn| {
        diesel::insert_into(hydra_consent_grants::table)
            .values((
                hydra_consent_grants::consent_request_id.eq(&crid),
                hydra_consent_grants::sid.eq(&sid),
                hydra_consent_grants::subject.eq(&subject),
                hydra_consent_grants::client_id.eq(&client_id),
                hydra_consent_grants::created_at.eq(&now),
            ))
            .on_conflict(hydra_consent_grants::consent_request_id)
            .do_nothing()
            .execute(conn)
    })?;
    Ok(())
}

/// The consent request ids Forseti accepted under `sid`.
pub(crate) async fn consent_grants_for_sid(db: &DbPool, sid: &str) -> anyhow::Result<Vec<String>> {
    let sid = sid.to_string();
    Ok(db_interact!(db, |conn| {
        hydra_consent_grants::table
            .filter(hydra_consent_grants::sid.eq(&sid))
            .select(hydra_consent_grants::consent_request_id)
            .load::<String>(conn)
    })?)
}

pub(crate) async fn recorded_kratos_session(
    db: &DbPool,
    sid: &str,
) -> anyhow::Result<RecordedKratosSession> {
    let sid = sid.to_string();
    let row = db_interact!(db, |conn| {
        hydra_login_sessions::table
            .filter(hydra_login_sessions::sid.eq(&sid))
            .select(hydra_login_sessions::kratos_session_id)
            .first::<Option<String>>(conn)
            .optional()
    })?;
    Ok(match row {
        None => RecordedKratosSession::Unknown,
        Some(None) => RecordedKratosSession::None,
        Some(Some(ksid)) => RecordedKratosSession::Some(ksid),
    })
}

/// The subject's `(sid, kratos_session_id)` pairs that name a Kratos session.
pub(crate) async fn sids_with_kratos_session_for_subject(
    db: &DbPool,
    subject: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    let subject = subject.to_string();
    let rows = db_interact!(db, |conn| {
        hydra_login_sessions::table
            .filter(hydra_login_sessions::subject.eq(&subject))
            .filter(hydra_login_sessions::kratos_session_id.is_not_null())
            .select((
                hydra_login_sessions::sid,
                hydra_login_sessions::kratos_session_id,
            ))
            .load::<(String, Option<String>)>(conn)
    })?;
    Ok(rows
        .into_iter()
        .filter_map(|(sid, ksid)| ksid.map(|k| (sid, k)))
        .collect())
}

async fn subject_for_sid(db: &DbPool, sid: &str) -> anyhow::Result<Option<String>> {
    let sid = sid.to_string();
    Ok(db_interact!(db, |conn| {
        hydra_login_sessions::table
            .filter(hydra_login_sessions::sid.eq(&sid))
            .select(hydra_login_sessions::subject)
            .first::<String>(conn)
            .optional()
    })?)
}

async fn sids_for_browser(
    db: &DbPool,
    subject: &str,
    kratos_session_id: &str,
) -> anyhow::Result<Vec<String>> {
    let (subject, ksid) = (subject.to_string(), kratos_session_id.to_string());
    Ok(db_interact!(db, |conn| {
        hydra_login_sessions::table
            .filter(hydra_login_sessions::subject.eq(&subject))
            .filter(hydra_login_sessions::kratos_session_id.eq(&ksid))
            .select(hydra_login_sessions::sid)
            .load::<String>(conn)
    })?)
}

async fn sids_for_subject(
    db: &DbPool,
    subject: &str,
    except_kratos_session: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let subject = subject.to_string();
    let except = except_kratos_session.map(str::to_string);
    Ok(db_interact!(db, |conn| {
        let mut q = hydra_login_sessions::table
            .filter(hydra_login_sessions::subject.eq(&subject))
            .select(hydra_login_sessions::sid)
            .into_boxed();
        if let Some(except) = &except {
            q = q.filter(
                hydra_login_sessions::kratos_session_id
                    .is_null()
                    .or(hydra_login_sessions::kratos_session_id.ne(except)),
            );
        }
        q.load::<String>(conn)
    })?)
}

/// Clear the row's Kratos session. The logout and sweep lookups match on it and
/// end rows with [`GrantRevocation::Keep`], which would drop a row that still
/// owes a grant revoke; the subject-wide ends still find it.
async fn detach_from_browser(db: &DbPool, sid: &str) -> anyhow::Result<()> {
    let sid = sid.to_string();
    db_interact!(db, |conn| {
        diesel::update(hydra_login_sessions::table.filter(hydra_login_sessions::sid.eq(&sid)))
            .set(hydra_login_sessions::kratos_session_id.eq(None::<String>))
            .execute(conn)
    })?;
    Ok(())
}

async fn forget(db: &DbPool, sid: &str) -> anyhow::Result<()> {
    let sid = sid.to_string();
    db_interact!(db, |conn| {
        diesel::delete(hydra_consent_grants::table.filter(hydra_consent_grants::sid.eq(&sid)))
            .execute(conn)?;
        diesel::delete(hydra_login_sessions::table.filter(hydra_login_sessions::sid.eq(&sid)))
            .execute(conn)
    })?;
    Ok(())
}

/// Where collecting the grants of a `sid` failed.
enum GrantLookupError {
    /// Forseti's own rows.
    Local(anyhow::Error),
    /// The OAuth server's listing by login session, which Hydra can't answer
    /// once that login session is deleted.
    Listing(anyhow::Error),
}

/// The consent request ids granted under `sid`: the recorded ones, else the
/// consents Hydra lists for the login session. Empty when the `sid` has no
/// row.
async fn grant_ids_for_sid(
    db: &DbPool,
    oauth: &OAuthImpl,
    sid: &str,
) -> Result<Vec<String>, GrantLookupError> {
    use anyhow::Context as _;
    let recorded = consent_grants_for_sid(db, sid)
        .await
        .context("hydra consent grant lookup failed")
        .map_err(GrantLookupError::Local)?;
    if !recorded.is_empty() {
        return Ok(recorded);
    }
    let Some(subject) = subject_for_sid(db, sid)
        .await
        .context("hydra login session lookup failed")
        .map_err(GrantLookupError::Local)?
    else {
        return Ok(Vec::new());
    };
    let sessions = oauth
        .list_consent_sessions_by_login_session(&subject, sid)
        .await
        .context("hydra consent listing by login session failed")
        .map_err(GrantLookupError::Listing)?;
    Ok(sessions
        .into_iter()
        .filter_map(|s| s.consent_request_id)
        .collect())
}

/// Revoke one `sid` at Hydra (firing back-channel logout) and drop its row.
/// Under [`GrantRevocation::Revoke`] its grants are collected first, while
/// Hydra can still list them by login session, and revoked after the logout:
/// Hydra picks the clients to notify from the login session's consents, so
/// revoking those first would silence the back-channel. On failure the row
/// stays so a later logout can retry it. When the OAuth server's listing
/// fails nothing is revoked. When Forseti's own grant rows can't be read or a
/// grant revoke fails, the login session is still revoked, the row is kept
/// off the browser lookups (see [`detach_from_browser`]) and the call fails.
pub(crate) async fn end_sid(
    db: &DbPool,
    oauth: &OAuthImpl,
    sid: &str,
    grants: GrantRevocation,
) -> anyhow::Result<()> {
    let grant_ids = match grants {
        GrantRevocation::Keep => Ok(Vec::new()),
        GrantRevocation::Revoke => match grant_ids_for_sid(db, oauth, sid).await {
            Ok(ids) => Ok(ids),
            Err(GrantLookupError::Listing(e)) => return Err(e),
            Err(GrantLookupError::Local(e)) => Err(e),
        },
    };
    oauth.revoke_login_session_by_sid(sid).await?;
    let mut failed = None;
    match grant_ids {
        Ok(ids) => {
            for consent_request_id in ids {
                if let Err(e) = oauth
                    .revoke_consent_sessions_by_request_id(&consent_request_id)
                    .await
                {
                    tracing::warn!(error = %e, "hydra consent revoke by request id failed");
                    failed = Some(e);
                }
            }
        }
        Err(e) => failed = Some(e),
    }
    if let Some(e) = failed {
        if let Err(e) = detach_from_browser(db, sid).await {
            tracing::warn!(error = %e, "hydra login session row update failed");
        }
        return Err(e);
    }
    if let Err(e) = forget(db, sid).await {
        tracing::warn!(error = %e, "hydra login session row delete failed");
    }
    Ok(())
}

/// `false` when any `sid` could not be revoked.
async fn revoke_sids(
    db: &DbPool,
    oauth: &OAuthImpl,
    sids: Vec<String>,
    grants: GrantRevocation,
) -> bool {
    let mut all = true;
    for sid in sids {
        if let Err(e) = end_sid(db, oauth, &sid, grants).await {
            tracing::warn!(
                error = format!("{e:#}"),
                "hydra login-session revoke by sid failed"
            );
            all = false;
        }
    }
    all
}

/// End the app sessions one browser's Kratos session signed in to. The
/// subject's sessions in other browsers stay, and so do its grants unless
/// `grants` says otherwise. `false` when the lookup or any login-session or
/// grant revoke failed.
pub(crate) async fn end_op_sessions_for_browser(
    db: &DbPool,
    oauth: &OAuthImpl,
    subject: &str,
    kratos_session_id: &str,
    grants: GrantRevocation,
) -> bool {
    match sids_for_browser(db, subject, kratos_session_id).await {
        Ok(sids) => revoke_sids(db, oauth, sids, grants).await,
        Err(e) => {
            tracing::warn!(error = %e, "hydra login session lookup failed");
            false
        }
    }
}

/// End the subject's `sid`s whose recorded Kratos session is no longer active,
/// such as one a browser rotated away from. Grants stay, as on logout. A
/// failed Kratos lookup skips the sweep.
pub(crate) async fn sweep_dead_browser_sessions(
    db: &DbPool,
    identity: &IdentityImpl,
    oauth: &OAuthImpl,
    subject: &str,
) {
    let recorded = match sids_with_kratos_session_for_subject(db, subject).await {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(error = %e, "hydra login session lookup failed");
            return;
        }
    };
    let active = match identity.active_session_ids(subject).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "kratos session lookup failed; skipping the sid sweep");
            return;
        }
    };
    let dead = recorded
        .into_iter()
        .filter(|(_, ksid)| !active.contains(ksid))
        .map(|(sid, _)| sid)
        .collect();
    revoke_sids(db, oauth, dead, GrantRevocation::Keep).await;
}

/// End every app session of a subject, optionally sparing one browser's
/// Kratos session. Subject-wide login and consent revokes follow as the
/// backstop for sessions recorded before this table existed; those fire no
/// back-channel logout but kill the grants. `false` when any lookup or revoke failed.
pub(crate) async fn end_op_sessions_for_subject(
    db: &DbPool,
    oauth: &OAuthImpl,
    subject: &str,
    except_kratos_session: Option<&str>,
    grants: GrantRevocation,
) -> bool {
    end_for_subject(db, oauth, subject, except_kratos_session, grants, true).await
        == SubjectEnd::Done
}

/// `flash` with `flash-oauth-sessions-partial` appended when the session end
/// reported failure (`ended` false), else `flash` unchanged.
pub(crate) fn flash_with_partial_end(
    locale: &crate::locale::LanguageIdentifier,
    flash: String,
    ended: bool,
) -> String {
    if ended {
        return flash;
    }
    // Chinese sentences follow a full-width stop without a space.
    let sep = if flash.ends_with('。') { "" } else { " " };
    let partial = crate::i18n::lookup(locale, "flash-oauth-sessions-partial");
    format!("{flash}{sep}{partial}")
}

/// How far ending a subject's sessions got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubjectEnd {
    Done,
    /// Every step but the closing subject-wide consent revoke succeeded.
    ConsentRevokeFailed,
    Failed,
}

/// [`end_op_sessions_for_subject`] ahead of an account deletion, grants kept.
/// After a failed step the subject-wide revokes are skipped, so a retry still
/// finds the consents whose clients it notifies.
pub(crate) async fn end_op_sessions_before_deletion(
    db: &DbPool,
    oauth: &OAuthImpl,
    subject: &str,
) -> SubjectEnd {
    end_for_subject(db, oauth, subject, None, GrantRevocation::Keep, false).await
}

async fn end_for_subject(
    db: &DbPool,
    oauth: &OAuthImpl,
    subject: &str,
    except_kratos_session: Option<&str>,
    grants: GrantRevocation,
    backstop_after_failure: bool,
) -> SubjectEnd {
    let mut all = match sids_for_subject(db, subject, except_kratos_session).await {
        Ok(sids) => revoke_sids(db, oauth, sids, grants).await,
        Err(e) => {
            tracing::warn!(error = %e, "hydra login session lookup failed");
            false
        }
    };
    let outcome = |all: bool| {
        if all {
            SubjectEnd::Done
        } else {
            SubjectEnd::Failed
        }
    };
    if except_kratos_session.is_some() || (!all && !backstop_after_failure) {
        return outcome(all);
    }
    if let Err(e) = oauth.revoke_login_sessions_for_subject(subject).await {
        tracing::warn!(error = %e, "hydra login-session revoke failed");
        if !backstop_after_failure {
            return SubjectEnd::Failed;
        }
        all = false;
    }
    if let Err(e) = oauth.revoke_consent_sessions_for_subject(subject).await {
        tracing::warn!(error = %e, "hydra consent-session revoke failed");
        return if all {
            SubjectEnd::ConsentRevokeFailed
        } else {
            SubjectEnd::Failed
        };
    }
    outcome(all)
}

/// A recorded Hydra login session of a subject.
#[derive(Queryable, Selectable, Debug, Clone, PartialEq, Eq, Serialize)]
#[diesel(table_name = hydra_login_sessions)]
pub(crate) struct LoginSessionRow {
    pub sid: String,
    pub kratos_session_id: Option<String>,
    pub created_at: String,
}

/// A recorded consent grant of a subject.
#[derive(Queryable, Selectable, Debug, Clone, PartialEq, Eq, Serialize)]
#[diesel(table_name = hydra_consent_grants)]
pub(crate) struct ConsentGrantRow {
    pub consent_request_id: String,
    pub sid: String,
    pub client_id: String,
    pub created_at: String,
}

/// Everything recorded locally for a subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SubjectRows {
    pub login_sessions: Vec<LoginSessionRow>,
    pub consent_grants: Vec<ConsentGrantRow>,
}

pub(crate) async fn rows_for_subject(db: &DbPool, subject: &str) -> anyhow::Result<SubjectRows> {
    let subject = subject.to_string();
    let (login_sessions, consent_grants) = db_interact!(db, |conn| {
        let sessions = hydra_login_sessions::table
            .filter(hydra_login_sessions::subject.eq(&subject))
            .order(hydra_login_sessions::created_at.asc())
            .select(LoginSessionRow::as_select())
            .load(conn)?;
        let grants = hydra_consent_grants::table
            .filter(hydra_consent_grants::subject.eq(&subject))
            .order(hydra_consent_grants::created_at.asc())
            .select(ConsentGrantRow::as_select())
            .load(conn)?;
        Ok::<_, diesel::result::Error>((sessions, grants))
    })?;
    Ok(SubjectRows {
        login_sessions,
        consent_grants,
    })
}

/// Drop every recorded login session and consent grant of a subject. The
/// Hydra side is revoked by [`end_op_sessions_for_subject`]; this only
/// clears the local rows. Idempotent.
pub(crate) async fn forget_subject(db: &DbPool, subject: &str) -> anyhow::Result<()> {
    let subject = subject.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(
                hydra_consent_grants::table.filter(hydra_consent_grants::subject.eq(&subject)),
            )
            .execute(c)?;
            diesel::delete(
                hydra_login_sessions::table.filter(hydra_login_sessions::subject.eq(&subject)),
            )
            .execute(c)
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_end_leaves_the_flash_alone() {
        let en = crate::locale::default_locale();
        assert_eq!(
            flash_with_partial_end(&en, "Session revoked.".to_string(), true),
            "Session revoked."
        );
    }

    #[test]
    fn a_partial_end_appends_the_translated_notice() {
        let en = crate::locale::default_locale();
        assert_eq!(
            flash_with_partial_end(&en, "Session revoked.".to_string(), false),
            "Session revoked. Some sessions could not be ended."
        );
        let zh: crate::locale::LanguageIdentifier = "zh".parse().unwrap();
        assert_eq!(
            flash_with_partial_end(&zh, "会话已撤销。".to_string(), false),
            "会话已撤销。部分会话无法结束。"
        );
    }

    #[tokio::test]
    async fn record_is_idempotent_and_follows_the_latest_kratos_session() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        // A remembered (skipped) login on the same Hydra session re-records it.
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        assert_eq!(
            sids_for_browser(&db, "user-a", "ks-1").await.unwrap(),
            vec!["sid-1"]
        );

        record(&db, "sid-1", "user-a", "ks-2", 86400).await.unwrap();
        assert!(
            sids_for_browser(&db, "user-a", "ks-1")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            sids_for_browser(&db, "user-a", "ks-2").await.unwrap(),
            vec!["sid-1"]
        );
    }

    #[tokio::test]
    async fn subject_lookup_spares_the_excepted_browser() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        record(&db, "sid-2", "user-a", "ks-2", 86400).await.unwrap();
        record(&db, "sid-3", "user-b", "ks-3", 86400).await.unwrap();

        let mut all = sids_for_subject(&db, "user-a", None).await.unwrap();
        all.sort();
        assert_eq!(all, vec!["sid-1", "sid-2"]);
        assert_eq!(
            sids_for_subject(&db, "user-a", Some("ks-1")).await.unwrap(),
            vec!["sid-2"]
        );
    }

    #[tokio::test]
    async fn record_prunes_rows_past_the_remember_horizon() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-old", "user-a", "ks-1", 86400)
            .await
            .unwrap();
        let stale = crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::days(3));
        let aged: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::update(hydra_login_sessions::table)
                    .set(hydra_login_sessions::created_at.eq(&stale))
                    .execute(conn)
            })?)
        }
        .await;
        aged.unwrap();
        record(&db, "sid-new", "user-a", "ks-2", 86400)
            .await
            .unwrap();
        assert_eq!(
            sids_for_subject(&db, "user-a", None).await.unwrap(),
            vec!["sid-new"]
        );
    }

    async fn consent_ids(db: &DbPool, sid: &str) -> Vec<String> {
        let mut ids = consent_grants_for_sid(db, sid).await.unwrap();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn record_consent_is_idempotent_and_keyed_by_consent_request_id() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        record_consent(&db, "cr-1", "sid-1", "user-a", "app-1")
            .await
            .unwrap();
        record_consent(&db, "cr-1", "sid-1", "user-a", "app-1")
            .await
            .unwrap();
        record_consent(&db, "cr-2", "sid-1", "user-a", "app-2")
            .await
            .unwrap();
        record_consent(&db, "cr-3", "sid-2", "user-a", "app-1")
            .await
            .unwrap();
        assert_eq!(consent_ids(&db, "sid-1").await, vec!["cr-1", "cr-2"]);
        assert_eq!(consent_ids(&db, "sid-2").await, vec!["cr-3"]);
    }

    #[tokio::test]
    async fn forget_drops_consent_grants_too() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        record_consent(&db, "cr-1", "sid-1", "user-a", "app-1")
            .await
            .unwrap();
        record_consent(&db, "cr-2", "sid-2", "user-a", "app-1")
            .await
            .unwrap();
        forget(&db, "sid-1").await.unwrap();
        assert!(consent_ids(&db, "sid-1").await.is_empty());
        assert_eq!(
            recorded_kratos_session(&db, "sid-1").await.unwrap(),
            RecordedKratosSession::Unknown
        );
        assert_eq!(consent_ids(&db, "sid-2").await, vec!["cr-2"]);
    }

    #[tokio::test]
    async fn prune_drops_consent_grants_past_the_horizon() {
        let db = crate::orgs::db::test_pool().await;
        record_consent(&db, "cr-old", "sid-old", "user-a", "app-1")
            .await
            .unwrap();
        let stale = crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::days(3));
        let aged: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::update(hydra_consent_grants::table)
                    .set(hydra_consent_grants::created_at.eq(&stale))
                    .execute(conn)
            })?)
        }
        .await;
        aged.unwrap();
        record_consent(&db, "cr-new", "sid-new", "user-a", "app-1")
            .await
            .unwrap();
        record(&db, "sid-new", "user-a", "ks-2", 86400)
            .await
            .unwrap();
        assert!(consent_ids(&db, "sid-old").await.is_empty());
        assert_eq!(consent_ids(&db, "sid-new").await, vec!["cr-new"]);
    }

    #[tokio::test]
    async fn record_clamps_an_absurd_remember_for() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-1", "user-a", "ks-1", i64::MAX)
            .await
            .unwrap();
        assert_eq!(
            sids_for_subject(&db, "user-a", None).await.unwrap(),
            vec!["sid-1"]
        );
    }

    #[tokio::test]
    async fn recorded_kratos_session_distinguishes_no_row_from_null_session() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        let now = crate::db::now_rfc3339();
        let inserted: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::insert_into(hydra_login_sessions::table)
                    .values((
                        hydra_login_sessions::sid.eq("sid-null"),
                        hydra_login_sessions::subject.eq("user-a"),
                        hydra_login_sessions::kratos_session_id.eq(None::<String>),
                        hydra_login_sessions::created_at.eq(&now),
                    ))
                    .execute(conn)
            })?)
        }
        .await;
        inserted.unwrap();

        assert_eq!(
            recorded_kratos_session(&db, "sid-1").await.unwrap(),
            RecordedKratosSession::Some("ks-1".into())
        );
        assert_eq!(
            recorded_kratos_session(&db, "sid-null").await.unwrap(),
            RecordedKratosSession::None
        );
        assert_eq!(
            recorded_kratos_session(&db, "sid-missing").await.unwrap(),
            RecordedKratosSession::Unknown
        );
        assert_eq!(
            sids_with_kratos_session_for_subject(&db, "user-a")
                .await
                .unwrap(),
            vec![("sid-1".to_string(), "ks-1".to_string())]
        );
    }

    #[tokio::test]
    async fn rows_for_subject_lists_and_forget_subject_clears_only_that_subject() {
        let db = crate::orgs::db::test_pool().await;
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        record(&db, "sid-2", "user-a", "ks-2", 86400).await.unwrap();
        record(&db, "sid-3", "user-b", "ks-3", 86400).await.unwrap();
        record_consent(&db, "cr-1", "sid-1", "user-a", "app-1")
            .await
            .unwrap();
        record_consent(&db, "cr-3", "sid-3", "user-b", "app-1")
            .await
            .unwrap();

        let rows = rows_for_subject(&db, "user-a").await.unwrap();
        let sids: Vec<&str> = rows.login_sessions.iter().map(|r| r.sid.as_str()).collect();
        assert_eq!(sids, vec!["sid-1", "sid-2"]);
        assert_eq!(
            rows.login_sessions[0].kratos_session_id.as_deref(),
            Some("ks-1")
        );
        assert_eq!(rows.consent_grants.len(), 1);
        assert_eq!(rows.consent_grants[0].consent_request_id, "cr-1");
        assert_eq!(rows.consent_grants[0].client_id, "app-1");

        forget_subject(&db, "user-a").await.unwrap();
        let gone = rows_for_subject(&db, "user-a").await.unwrap();
        assert!(gone.login_sessions.is_empty());
        assert!(gone.consent_grants.is_empty());
        assert_eq!(
            sids_for_subject(&db, "user-b", None).await.unwrap(),
            vec!["sid-3"]
        );
        assert_eq!(consent_ids(&db, "sid-3").await, vec!["cr-3"]);
        forget_subject(&db, "user-a").await.unwrap();
    }

    #[cfg(feature = "oauth-ory")]
    #[tokio::test]
    async fn failed_revoke_at_hydra_fails_and_keeps_the_sid() {
        let db = crate::orgs::db::test_pool().await;
        let mut cfg = crate::config::AppConfig::test_fixture();
        cfg.hydra.admin_url = "http://127.0.0.1:9".to_string();
        cfg.hydra.public_url = "http://127.0.0.1:9".to_string();
        let oauth = crate::backend::build_oauth(&cfg, &db, &[]);
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();

        // The listing error, not the login-session revoke's: the listing fails before the revoke.
        let err = end_sid(&db, &oauth, "sid-1", GrantRevocation::Revoke)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("consent listing"), "{err:#}");
        assert!(
            !end_op_sessions_for_browser(&db, &oauth, "user-a", "ks-1", GrantRevocation::Revoke)
                .await
        );
        assert_eq!(
            end_op_sessions_before_deletion(&db, &oauth, "user-a").await,
            SubjectEnd::Failed
        );
        assert!(
            !end_op_sessions_for_subject(
                &db,
                &oauth,
                "user-a",
                Some("ks-2"),
                GrantRevocation::Revoke
            )
            .await
        );
        assert_eq!(
            recorded_kratos_session(&db, "sid-1").await.unwrap(),
            RecordedKratosSession::Some("ks-1".into())
        );
    }

    #[cfg(feature = "oauth-native")]
    async fn exec(db: &DbPool, sql: &'static str) {
        let r: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::sql_query(sql).execute(conn)
            })?)
        }
        .await;
        r.unwrap();
    }

    #[cfg(feature = "oauth-native")]
    async fn native_session_exists(db: &DbPool, sid: &str) -> bool {
        use crate::schema::oauth_login_sessions;
        let sid = sid.to_string();
        let r: anyhow::Result<i64> = async {
            Ok(db_interact!(db, |conn| {
                oauth_login_sessions::table
                    .filter(oauth_login_sessions::sid.eq(&sid))
                    .count()
                    .get_result(conn)
            })?)
        }
        .await;
        r.unwrap() > 0
    }

    /// `user-a` signed in as `sid-1` from browser `ks-1`, recorded here and at the native server.
    #[cfg(feature = "oauth-native")]
    async fn native_fixture() -> (DbPool, std::sync::Arc<OAuthImpl>) {
        use crate::schema::oauth_login_sessions;
        let db = crate::orgs::db::test_pool().await;
        let oauth = crate::backend::build_oauth(
            &crate::config::AppConfig::test_fixture(),
            &db,
            &[0x42; 32],
        );
        record(&db, "sid-1", "user-a", "ks-1", 86400).await.unwrap();
        let now = crate::db::now_rfc3339();
        let inserted: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::insert_into(oauth_login_sessions::table)
                    .values((
                        oauth_login_sessions::sid.eq("sid-1"),
                        oauth_login_sessions::subject.eq("user-a"),
                        oauth_login_sessions::auth_time.eq(&now),
                        oauth_login_sessions::amr.eq("[]"),
                        oauth_login_sessions::remember.eq(1),
                        oauth_login_sessions::created_at.eq(&now),
                        oauth_login_sessions::expires_at.eq("2999-01-01T00:00:00Z"),
                    ))
                    .execute(conn)
            })?)
        }
        .await;
        inserted.unwrap();
        (db, oauth)
    }

    /// The subject-wide revoke that retries a kept row; the gone login session counts as revoked.
    #[cfg(feature = "oauth-native")]
    async fn assert_retry_clears(db: &DbPool, oauth: &OAuthImpl) {
        assert!(
            end_op_sessions_for_subject(db, oauth, "user-a", Some("ks-2"), GrantRevocation::Revoke)
                .await
        );
        assert_eq!(
            recorded_kratos_session(db, "sid-1").await.unwrap(),
            RecordedKratosSession::Unknown
        );
    }

    /// A row kept for its grants is off the logout and sweep lookups.
    #[cfg(feature = "oauth-native")]
    async fn assert_detached(db: &DbPool, oauth: &OAuthImpl) {
        assert_eq!(
            recorded_kratos_session(db, "sid-1").await.unwrap(),
            RecordedKratosSession::None
        );
        assert!(
            end_op_sessions_for_browser(db, oauth, "user-a", "ks-1", GrantRevocation::Keep).await
        );
        assert!(
            sids_with_kratos_session_for_subject(db, "user-a")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            recorded_kratos_session(db, "sid-1").await.unwrap(),
            RecordedKratosSession::None
        );
    }

    #[cfg(feature = "oauth-native")]
    #[tokio::test]
    async fn failed_backend_listing_revokes_nothing_and_keeps_the_row_attached() {
        let (db, oauth) = native_fixture().await;
        exec(
            &db,
            "ALTER TABLE oauth_consent_grants RENAME TO oauth_consent_grants_gone",
        )
        .await;

        assert!(
            !end_op_sessions_for_browser(&db, &oauth, "user-a", "ks-1", GrantRevocation::Revoke)
                .await
        );
        assert!(native_session_exists(&db, "sid-1").await);
        assert_eq!(
            recorded_kratos_session(&db, "sid-1").await.unwrap(),
            RecordedKratosSession::Some("ks-1".into())
        );

        exec(
            &db,
            "ALTER TABLE oauth_consent_grants_gone RENAME TO oauth_consent_grants",
        )
        .await;
        assert!(
            end_op_sessions_for_browser(&db, &oauth, "user-a", "ks-1", GrantRevocation::Revoke)
                .await
        );
        assert!(!native_session_exists(&db, "sid-1").await);
        assert_eq!(
            recorded_kratos_session(&db, "sid-1").await.unwrap(),
            RecordedKratosSession::Unknown
        );
    }

    #[cfg(feature = "oauth-native")]
    #[tokio::test]
    async fn failed_local_grant_lookup_still_logs_out_and_keeps_a_detached_row() {
        let (db, oauth) = native_fixture().await;
        exec(
            &db,
            "ALTER TABLE hydra_consent_grants RENAME TO hydra_consent_grants_gone",
        )
        .await;

        assert!(
            !end_op_sessions_for_browser(&db, &oauth, "user-a", "ks-1", GrantRevocation::Revoke)
                .await
        );
        assert!(!native_session_exists(&db, "sid-1").await);
        assert_detached(&db, &oauth).await;

        exec(
            &db,
            "ALTER TABLE hydra_consent_grants_gone RENAME TO hydra_consent_grants",
        )
        .await;
        assert_retry_clears(&db, &oauth).await;
    }

    #[cfg(feature = "oauth-native")]
    #[tokio::test]
    async fn failed_grant_revoke_keeps_a_detached_row_and_its_grant_ids() {
        use crate::schema::oauth_consent_grants;
        let (db, oauth) = native_fixture().await;
        oauth
            .create_client(crate::backend::oauth::OAuthClient {
                client_id: Some("app-1".to_string()),
                redirect_uris: Some(vec!["https://app.example/cb".to_string()]),
                scope: Some("openid".to_string()),
                token_endpoint_auth_method: Some("client_secret_basic".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        let now = crate::db::now_rfc3339();
        let inserted: anyhow::Result<usize> = async {
            Ok(db_interact!(db, |conn| {
                diesel::insert_into(oauth_consent_grants::table)
                    .values((
                        oauth_consent_grants::id.eq("cr-1"),
                        oauth_consent_grants::client_id.eq("app-1"),
                        oauth_consent_grants::subject.eq("user-a"),
                        oauth_consent_grants::session_id.eq("sid-1"),
                        oauth_consent_grants::scope.eq("[\"openid\"]"),
                        oauth_consent_grants::audience.eq("[]"),
                        oauth_consent_grants::id_token_claims.eq("{}"),
                        oauth_consent_grants::access_token_claims.eq("{}"),
                        oauth_consent_grants::remember.eq(1),
                        oauth_consent_grants::skipped.eq(0),
                        oauth_consent_grants::handled_at.eq(&now),
                    ))
                    .execute(conn)
            })?)
        }
        .await;
        inserted.unwrap();
        record_consent(&db, "cr-1", "sid-1", "user-a", "app-1")
            .await
            .unwrap();
        exec(
            &db,
            "CREATE TRIGGER block_grant_delete BEFORE DELETE ON oauth_consent_grants \
             BEGIN SELECT RAISE(ABORT, 'blocked'); END",
        )
        .await;

        assert!(
            end_sid(&db, &oauth, "sid-1", GrantRevocation::Revoke)
                .await
                .is_err()
        );
        assert!(!native_session_exists(&db, "sid-1").await);
        assert_eq!(consent_ids(&db, "sid-1").await, vec!["cr-1"]);
        assert_detached(&db, &oauth).await;

        exec(&db, "DROP TRIGGER block_grant_delete").await;
        assert_retry_clears(&db, &oauth).await;
        assert!(consent_ids(&db, "sid-1").await.is_empty());
    }
}
