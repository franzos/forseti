//! Hourly cleanup: dead sessions, expired flows (their codes go with them) and old mail rows.

use std::time::Duration;

use anyhow::Result;
use diesel::prelude::*;
use tokio_util::sync::CancellationToken;

use super::mail::state;
use super::session;
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{identity_flows, identity_mail_outbox};

const FIRST_RUN_DELAY: Duration = Duration::from_secs(60);
const INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Flows stay this long past their expiry.
const FLOW_GRACE_DAYS: i64 = 1;

/// Sent and abandoned mail rows stay this long after they were queued.
const MAIL_RETENTION_DAYS: i64 = 30;

/// Run the cleanup a minute after boot, then hourly, until `shutdown`.
pub(crate) fn spawn(db: DbPool, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + FIRST_RUN_DELAY, INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => run_once(&db).await,
            }
        }
        tracing::info!("identity maintenance: shutdown received, exiting");
    })
}

/// One pass; a failing step is logged and the others still run.
async fn run_once(db: &DbPool) {
    let steps = [
        ("sessions", session::delete_stale(db).await),
        ("flows", delete_expired_flows(db).await),
        ("mail rows", delete_old_mail(db).await),
    ];
    for (what, result) in steps {
        match result {
            Ok(deleted) => tracing::debug!(deleted, "identity maintenance: {what} deleted"),
            Err(e) => tracing::warn!(error = %e, "identity maintenance: deleting {what} failed"),
        }
    }
}

/// Delete flows expired more than [`FLOW_GRACE_DAYS`] ago; their codes cascade.
async fn delete_expired_flows(db: &DbPool) -> Result<usize> {
    let cutoff = crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::days(FLOW_GRACE_DAYS));
    Ok(db_interact!(db, |c| {
        diesel::delete(identity_flows::table.filter(identity_flows::expires_at.lt(&cutoff)))
            .execute(c)
    })?)
}

/// Delete sent and abandoned mail rows queued more than [`MAIL_RETENTION_DAYS`] ago.
async fn delete_old_mail(db: &DbPool) -> Result<usize> {
    let cutoff =
        crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::days(MAIL_RETENTION_DAYS));
    Ok(db_interact!(db, |c| {
        diesel::delete(
            identity_mail_outbox::table
                .filter(identity_mail_outbox::state.eq_any([state::SENT, state::ABANDONED]))
                .filter(identity_mail_outbox::created_at.lt(&cutoff)),
        )
        .execute(c)
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_native::NativeBackend;
    use crate::identity_native::codes::Purpose;
    use crate::identity_native::test_support::{identity_with_password, sql};
    use crate::schema::identity_codes;

    fn days_ago(days: i64) -> String {
        crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::days(days))
    }

    fn hours_ago(hours: i64) -> String {
        crate::db::rfc3339(chrono::Utc::now() - chrono::Duration::hours(hours))
    }

    /// A verification flow with a mailed code, expiring at `expires_at`; returns the flow id.
    async fn flow_with_code(backend: &NativeBackend, email: &str, expires_at: String) -> String {
        let identity = identity_with_password(&backend.db, email, false).await;
        let flow = backend
            .create_verification_flow(email, None, None)
            .await
            .unwrap();
        backend
            .send_code(&flow.row.id, Purpose::Verification, &identity, email)
            .await
            .unwrap();
        let id = flow.row.id.clone();
        sql(&backend.db, move |c| {
            diesel::update(identity_flows::table.find(&id))
                .set(identity_flows::expires_at.eq(&expires_at))
                .execute(c)
        })
        .await;
        flow.row.id
    }

    async fn flow_ids(db: &DbPool) -> Vec<String> {
        sql(db, |c| {
            identity_flows::table
                .select(identity_flows::id)
                .order(identity_flows::id)
                .load(c)
        })
        .await
    }

    async fn code_flows(db: &DbPool) -> Vec<String> {
        sql(db, |c| {
            identity_codes::table
                .select(identity_codes::flow_id)
                .order(identity_codes::flow_id)
                .load(c)
        })
        .await
    }

    #[tokio::test]
    async fn flows_expired_over_a_day_ago_go_with_their_codes() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let old = flow_with_code(&backend, "old@x.test", days_ago(2)).await;
        let recent = flow_with_code(&backend, "recent@x.test", hours_ago(23)).await;
        let live = backend
            .create_verification_flow("live@x.test", None, None)
            .await
            .unwrap()
            .row
            .id;

        assert_eq!(delete_expired_flows(&db).await.unwrap(), 1);
        let mut kept = vec![recent.clone(), live];
        kept.sort();
        assert_eq!(flow_ids(&db).await, kept);
        assert_eq!(code_flows(&db).await, [recent], "{old}'s code went with it");
    }

    async fn mail_row(db: &DbPool, backend: &NativeBackend, email: &str, state: &str, age: i64) {
        let identity = identity_with_password(db, email, false).await;
        let mut row = backend.outbox_row(Purpose::Verification, &identity, email, "f", "123456");
        row.state = state.to_string();
        row.created_at = days_ago(age);
        sql(db, move |c| {
            diesel::insert_into(identity_mail_outbox::table)
                .values(&row)
                .execute(c)
        })
        .await;
    }

    async fn recipients(db: &DbPool) -> Vec<String> {
        sql(db, |c| {
            identity_mail_outbox::table
                .select(identity_mail_outbox::recipient)
                .order(identity_mail_outbox::recipient)
                .load(c)
        })
        .await
    }

    #[tokio::test]
    async fn sent_and_abandoned_mail_older_than_30_days_is_deleted() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        mail_row(&db, &backend, "a-sent-old@x.test", state::SENT, 31).await;
        mail_row(
            &db,
            &backend,
            "b-abandoned-old@x.test",
            state::ABANDONED,
            31,
        )
        .await;
        mail_row(&db, &backend, "c-queued-old@x.test", state::QUEUED, 31).await;
        mail_row(&db, &backend, "d-sent-recent@x.test", state::SENT, 29).await;
        mail_row(
            &db,
            &backend,
            "e-abandoned-recent@x.test",
            state::ABANDONED,
            29,
        )
        .await;

        assert_eq!(delete_old_mail(&db).await.unwrap(), 2);
        assert_eq!(
            recipients(&db).await,
            [
                "c-queued-old@x.test",
                "d-sent-recent@x.test",
                "e-abandoned-recent@x.test"
            ]
        );
    }

    #[tokio::test]
    async fn one_pass_runs_every_step() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        flow_with_code(&backend, "flow@x.test", days_ago(2)).await;
        mail_row(&db, &backend, "mail@x.test", state::SENT, 31).await;
        let identity = identity_with_password(&db, "s@x.test", true).await;
        let issued = backend
            .issue_session(
                &identity,
                "password",
                crate::backend::identity::Aal::Aal1,
                session::Device::default(),
            )
            .await
            .unwrap();
        let id = issued.id.clone();
        let old = days_ago(31);
        sql(&db, move |c| {
            use crate::schema::identity_sessions;
            diesel::update(identity_sessions::table.find(&id))
                .set(identity_sessions::revoked_at.eq(&old))
                .execute(c)
        })
        .await;

        run_once(&db).await;
        assert!(flow_ids(&db).await.is_empty());
        assert_eq!(
            recipients(&db).await,
            ["flow@x.test"],
            "only the queued code mail of the deleted flow stays"
        );
        assert!(session::find_live(&db, &issued.id).await.unwrap().is_none());
        let left: i64 = sql(&db, |c| {
            crate::schema::identity_sessions::table
                .count()
                .get_result(c)
        })
        .await;
        assert_eq!(left, 0);
    }
}
