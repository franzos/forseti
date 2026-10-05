//! The Hydra login sessions (`sid`) Forseti accepted, keyed to the subject and
//! the Kratos session that signed them in. Hydra sends back-channel logout
//! only when a session is revoked by `sid`, and it can't list a subject's
//! sessions, so logout looks them up here.

use diesel::prelude::*;

use crate::db::DbPool;
use crate::db_interact;
use crate::ory;
use crate::schema::{hydra_consent_grants, hydra_login_sessions};
use crate::state::AppState;

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
    let cutoff =
        (now - chrono::Duration::seconds(horizon.saturating_add(PRUNE_MARGIN_SECS))).to_rfc3339();
    let (sid, subject, ksid, now) = (
        sid.to_string(),
        subject.to_string(),
        kratos_session_id.to_string(),
        now.to_rfc3339(),
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
        chrono::Utc::now().to_rfc3339(),
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

/// The consent request ids granted under `sid`: the recorded ones, else the
/// consents Hydra lists for the login session. Empty when neither lookup
/// works.
async fn grant_ids_for_sid(state: &AppState, sid: &str) -> Vec<String> {
    match consent_grants_for_sid(&state.db, sid).await {
        Ok(recorded) if !recorded.is_empty() => return recorded,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "hydra consent grant lookup failed");
            return Vec::new();
        }
    }
    let subject = match subject_for_sid(&state.db, sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Vec::new(),
        Err(e) => {
            tracing::warn!(error = %e, "hydra login session lookup failed");
            return Vec::new();
        }
    };
    match ory::hydra::list_consent_sessions_by_login_session(&state.ory, &subject, sid).await {
        Ok(sessions) => sessions
            .into_iter()
            .filter_map(|s| s.consent_request_id)
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "hydra consent listing by login session failed");
            Vec::new()
        }
    }
}

/// Revoke one `sid` at Hydra (firing back-channel logout) and drop its row.
/// Under [`GrantRevocation::Revoke`] its grants are collected first, while
/// Hydra can still list them by login session, and revoked after the logout:
/// Hydra picks the clients to notify from the login session's consents, so
/// revoking those first would silence the back-channel. On failure the row
/// stays so a later logout can retry it.
pub(crate) async fn end_sid(
    state: &AppState,
    sid: &str,
    grants: GrantRevocation,
) -> anyhow::Result<()> {
    let grant_ids = match grants {
        GrantRevocation::Revoke => grant_ids_for_sid(state, sid).await,
        GrantRevocation::Keep => Vec::new(),
    };
    ory::hydra::revoke_login_session_by_sid(&state.ory, sid).await?;
    for consent_request_id in grant_ids {
        if let Err(e) =
            ory::hydra::revoke_consent_sessions_by_request_id(&state.ory, &consent_request_id).await
        {
            tracing::warn!(error = %e, "hydra consent revoke by request id failed");
        }
    }
    if let Err(e) = forget(&state.db, sid).await {
        tracing::warn!(error = %e, "hydra login session row delete failed");
    }
    Ok(())
}

async fn revoke_sids(state: &AppState, sids: Vec<String>, grants: GrantRevocation) {
    for sid in sids {
        if let Err(e) = end_sid(state, &sid, grants).await {
            tracing::warn!(error = %e, "hydra login-session revoke by sid failed");
        }
    }
}

/// End the app sessions one browser's Kratos session signed in to. The
/// subject's sessions in other browsers stay, and so do its grants unless
/// `grants` says otherwise.
pub(crate) async fn end_op_sessions_for_browser(
    state: &AppState,
    subject: &str,
    kratos_session_id: &str,
    grants: GrantRevocation,
) {
    match sids_for_browser(&state.db, subject, kratos_session_id).await {
        Ok(sids) => revoke_sids(state, sids, grants).await,
        Err(e) => tracing::warn!(error = %e, "hydra login session lookup failed"),
    }
}

/// End the subject's `sid`s whose recorded Kratos session is no longer active,
/// such as one a browser rotated away from. Grants stay, as on logout. A
/// failed Kratos lookup skips the sweep.
pub(crate) async fn sweep_dead_browser_sessions(state: &AppState, subject: &str) {
    let recorded = match sids_with_kratos_session_for_subject(&state.db, subject).await {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(error = %e, "hydra login session lookup failed");
            return;
        }
    };
    let active = match ory::kratos::active_session_ids(&state.ory, subject).await {
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
    revoke_sids(state, dead, GrantRevocation::Keep).await;
}

/// End every app session of a subject, optionally sparing one browser's
/// Kratos session. Subject-wide login and consent revokes follow as the
/// backstop for sessions recorded before this table existed; those fire no
/// back-channel logout but kill the grants.
pub(crate) async fn end_op_sessions_for_subject(
    state: &AppState,
    subject: &str,
    except_kratos_session: Option<&str>,
    grants: GrantRevocation,
) {
    match sids_for_subject(&state.db, subject, except_kratos_session).await {
        Ok(sids) => revoke_sids(state, sids, grants).await,
        Err(e) => tracing::warn!(error = %e, "hydra login session lookup failed"),
    }
    if except_kratos_session.is_some() {
        return;
    }
    if let Err(e) = ory::hydra::revoke_login_sessions_for_subject(&state.ory, subject).await {
        tracing::warn!(error = %e, "hydra login-session revoke failed");
    }
    if let Err(e) = ory::hydra::revoke_consent_sessions_for_subject(&state.ory, subject).await {
        tracing::warn!(error = %e, "hydra consent-session revoke failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let stale = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
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
        let stale = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
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
        let now = chrono::Utc::now().to_rfc3339();
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
}
