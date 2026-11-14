//! Verification and recovery mail: outbox rows queued with their code, and the worker that sends
//! them through [`crate::mailer::send_text`].

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::NativeBackend;
use super::codes::Purpose;
use crate::config::{AppConfig, EmailConfig, SelfConfig};
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::identity_mail_outbox;

/// Seconds between drains when nothing wakes the worker.
pub(crate) const TICK_SECS: u64 = 5;

const BATCH: usize = 32;
const CONCURRENCY: usize = 4;
/// How long a claimed row stays invisible to other workers while its send runs.
const LEASE_SECS: i64 = 120;
/// A send still running after this counts as failed, well inside [`LEASE_SECS`].
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ATTEMPTS: i32 = 10;
const BACKOFF_FIRST_SECS: i64 = 10;
const BACKOFF_CAP_SECS: i64 = 300;
/// `last_error` is shown to operators; transport errors can be long.
const ERROR_MAX_CHARS: usize = 500;

const SEAL_PAYLOAD: &str = "mail-payload";

pub(super) mod state {
    pub(crate) const QUEUED: &str = "queued";
    pub(crate) const SENT: &str = "sent";
    pub(crate) const ABANDONED: &str = "abandoned";
}

/// What a mail carries, sealed in `identity_mail_outbox.payload` until it is sent.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Payload {
    code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<String>,
}

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = identity_mail_outbox)]
pub(super) struct OutboxRow {
    pub(super) id: String,
    pub(super) identity_id: String,
    pub(super) recipient: String,
    pub(super) kind: String,
    pub(super) payload: String,
    pub(super) state: String,
    pub(super) attempts: i32,
    pub(super) next_attempt_at: String,
    pub(super) last_error: Option<String>,
    pub(super) created_at: String,
    pub(super) sent_at: Option<String>,
}

fn subject(purpose: Purpose, code: &str) -> String {
    match purpose {
        Purpose::Verification => format!("Use code {code} to verify your account"),
        Purpose::Recovery => format!("Use code {code} to recover access to your account"),
    }
}

/// The code on its own line, then the link when there is one.
fn body(payload: &Payload) -> String {
    match &payload.link {
        Some(link) => format!("{}\n\n{link}\n", payload.code),
        None => format!("{}\n", payload.code),
    }
}

impl NativeBackend {
    /// The queued mail for `code`. Verification mail links to the flow with the code; recovery
    /// mail carries the code only.
    pub(super) fn outbox_row(
        &self,
        purpose: Purpose,
        identity_id: &str,
        recipient: &str,
        flow_id: &str,
        code: &str,
    ) -> OutboxRow {
        let id = uuid::Uuid::new_v4().to_string();
        let link = (purpose == Purpose::Verification).then(|| {
            format!(
                "{}/self-service/verification?flow={}&code={code}",
                self.self_url,
                crate::web::urlencode(flow_id)
            )
        });
        let payload = Payload {
            code: code.to_string(),
            link,
        };
        let plain = serde_json::to_vec(&payload).expect("mail payload serialises");
        let now = crate::db::now_rfc3339();
        OutboxRow {
            payload: self.keys.seal.seal(SEAL_PAYLOAD, &id, &plain),
            id,
            identity_id: identity_id.to_string(),
            recipient: recipient.to_string(),
            kind: purpose.as_str().to_string(),
            state: state::QUEUED.to_string(),
            attempts: 0,
            next_attempt_at: now.clone(),
            last_error: None,
            created_at: now,
            sent_at: None,
        }
    }

    fn open_payload(&self, row: &OutboxRow) -> Option<Payload> {
        let plain = self.keys.seal.open(SEAL_PAYLOAD, &row.id, &row.payload)?;
        serde_json::from_slice(&plain).ok()
    }

    /// Outbox rows in `state`, at most `cap`.
    pub(super) async fn count_mail(&self, state: &'static str, cap: i64) -> Result<u64> {
        let n: i64 = db_interact!(self.db, |c| {
            identity_mail_outbox::table
                .filter(identity_mail_outbox::state.eq(state))
                .count()
                .get_result(c)
        })?;
        Ok(u64::try_from(n.min(cap).max(0)).unwrap_or_default())
    }
}

/// Delivers one mail; the worker's only way out of the process.
pub(crate) trait Sender: Send + Sync + 'static {
    fn send(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// [`Sender`] over the `[email]` transport.
pub(crate) struct Smtp {
    email: Option<EmailConfig>,
    self_cfg: SelfConfig,
}

impl Smtp {
    pub(crate) fn new(cfg: &AppConfig) -> Self {
        Self {
            email: cfg.email.clone(),
            self_cfg: cfg.self_.clone(),
        }
    }
}

impl Sender for Smtp {
    async fn send(&self, recipient: &str, subject: &str, body: &str) -> Result<()> {
        // `send_text` logs the subject, which holds the code, when mail is off.
        if !self.email.as_ref().is_some_and(|e| e.enabled) {
            anyhow::bail!("[email] is disabled");
        }
        crate::mailer::send_text(
            self.email.as_ref(),
            &self.self_cfg,
            recipient,
            subject,
            body,
        )
        .await
    }
}

/// Drain the outbox until `shutdown`: every [`TICK_SECS`], right after a row is queued, and again
/// at once after a full batch. A drain in flight finishes its bookkeeping before the task exits.
pub(crate) fn spawn_worker<S: Sender>(
    backend: Arc<NativeBackend>,
    sender: S,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            let full_batch = match drain_once(&backend, &sender).await {
                Ok(fetched) => fetched >= BATCH,
                Err(e) => {
                    tracing::warn!(error = %e, "identity mail worker tick failed");
                    false
                }
            };
            backend.mail_worker.beat();
            if full_batch {
                continue;
            }
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = backend.mail_wake.notified() => {}
                () = tokio::time::sleep(Duration::from_secs(TICK_SECS)) => {}
            }
        }
        tracing::info!("identity mail worker: shutdown received, exiting");
    })
}

/// One batch of due rows; returns how many were fetched.
async fn drain_once<S: Sender>(backend: &NativeBackend, sender: &S) -> Result<usize> {
    let now = crate::db::now_rfc3339();
    let due: Vec<OutboxRow> = db_interact!(backend.db, |c| {
        identity_mail_outbox::table
            .filter(identity_mail_outbox::state.eq(state::QUEUED))
            .filter(identity_mail_outbox::next_attempt_at.le(&now))
            .order(identity_mail_outbox::next_attempt_at.asc())
            .limit(BATCH as i64)
            .select(OutboxRow::as_select())
            .load(c)
    })?;
    let fetched = due.len();
    futures_util::stream::iter(due)
        .for_each_concurrent(CONCURRENCY, |row| async move {
            match claim(&backend.db, &row).await {
                Ok(Some(lease)) => deliver(backend, sender, row, &lease, SEND_TIMEOUT).await,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, row_id = %row.id, "identity mail claim failed")
                }
            }
        })
        .await;
    Ok(fetched)
}

/// Lease the row by moving `next_attempt_at` from the value read to the returned lease value;
/// `None` when another worker got there first.
async fn claim(db: &DbPool, row: &OutboxRow) -> Result<Option<String>> {
    let lease = crate::db::rfc3339(Utc::now() + chrono::Duration::seconds(LEASE_SECS));
    let (id, seen, held) = (row.id.clone(), row.next_attempt_at.clone(), lease.clone());
    let n = db_interact!(db, |c| {
        diesel::update(
            identity_mail_outbox::table
                .find(&id)
                .filter(identity_mail_outbox::state.eq(state::QUEUED))
                .filter(identity_mail_outbox::next_attempt_at.eq(&seen)),
        )
        .set(identity_mail_outbox::next_attempt_at.eq(&held))
        .execute(c)
    })?;
    Ok((n > 0).then_some(lease))
}

enum Outcome {
    Sent,
    Failed(String),
    /// The payload no longer opens (key change); retrying cannot help.
    Unreadable,
    /// The code in it no longer works.
    Expired,
}

async fn deliver<S: Sender>(
    backend: &NativeBackend,
    sender: &S,
    row: OutboxRow,
    lease: &str,
    send_timeout: Duration,
) {
    let purpose = Purpose::parse(&row.kind);
    let outcome = match (purpose, backend.open_payload(&row)) {
        _ if aged_out(&row.created_at, Utc::now()) => Outcome::Expired,
        (Some(purpose), Some(payload)) => {
            let (subject, body) = (subject(purpose, &payload.code), body(&payload));
            let send = sender.send(&row.recipient, &subject, &body);
            match tokio::time::timeout(send_timeout, send).await {
                Ok(Ok(())) => Outcome::Sent,
                Ok(Err(e)) => Outcome::Failed(format!("{e:#}")),
                Err(_) => Outcome::Failed(format!("no answer within {send_timeout:?}")),
            }
        }
        _ => Outcome::Unreadable,
    };
    if let Err(e) = record(&backend.db, &row, lease, outcome).await {
        // The lease runs out and the row is tried again.
        tracing::error!(error = %e, row_id = %row.id, "identity mail bookkeeping failed");
    }
}

/// Write the outcome of a send under `lease`. Nothing is written when the row is no longer
/// queued under that lease: it ran out and another worker holds the row now.
async fn record(db: &DbPool, row: &OutboxRow, lease: &str, outcome: Outcome) -> Result<()> {
    let (id, attempts, now) = (row.id.clone(), row.attempts + 1, Utc::now());
    let held = lease.to_string();
    let target = move || {
        identity_mail_outbox::table
            .find(id.clone())
            .filter(identity_mail_outbox::state.eq(state::QUEUED))
            .filter(identity_mail_outbox::next_attempt_at.eq(held.clone()))
    };
    let (error, give_up) = match outcome {
        Outcome::Sent => {
            let stamp = crate::db::rfc3339(now);
            let n = db_interact!(db, |c| {
                diesel::update(target())
                    .set((
                        identity_mail_outbox::state.eq(state::SENT),
                        identity_mail_outbox::payload.eq(""),
                        identity_mail_outbox::attempts.eq(attempts),
                        identity_mail_outbox::sent_at.eq(&stamp),
                        identity_mail_outbox::last_error.eq(None::<String>),
                    ))
                    .execute(c)
            })?;
            if !lease_lost(row, n) {
                tracing::info!(row_id = %row.id, kind = %row.kind, attempts, "identity mail sent");
            }
            return Ok(());
        }
        Outcome::Failed(e) => (e, attempts >= MAX_ATTEMPTS),
        Outcome::Unreadable => ("payload does not open".to_string(), true),
        Outcome::Expired => (
            "the code expired before the mail was sent".to_string(),
            true,
        ),
    };
    let error: String = error.chars().take(ERROR_MAX_CHARS).collect();
    let stored = error.clone();
    if give_up {
        let n = db_interact!(db, |c| {
            diesel::update(target())
                .set((
                    identity_mail_outbox::state.eq(state::ABANDONED),
                    identity_mail_outbox::payload.eq(""),
                    identity_mail_outbox::attempts.eq(attempts),
                    identity_mail_outbox::last_error.eq(Some(stored)),
                ))
                .execute(c)
        })?;
        if !lease_lost(row, n) {
            tracing::warn!(row_id = %row.id, kind = %row.kind, attempts, error = %error, "identity mail abandoned");
        }
    } else {
        let next = crate::db::rfc3339(now + chrono::Duration::seconds(backoff_secs(attempts)));
        let n = db_interact!(db, |c| {
            diesel::update(target())
                .set((
                    identity_mail_outbox::attempts.eq(attempts),
                    identity_mail_outbox::next_attempt_at.eq(&next),
                    identity_mail_outbox::last_error.eq(Some(stored)),
                ))
                .execute(c)
        })?;
        if !lease_lost(row, n) {
            tracing::info!(row_id = %row.id, kind = %row.kind, attempts, error = %error, "identity mail retry scheduled");
        }
    }
    Ok(())
}

fn lease_lost(row: &OutboxRow, updated: usize) -> bool {
    if updated == 0 {
        tracing::warn!(row_id = %row.id, "identity mail lease ran out before the result was written");
    }
    updated == 0
}

/// Older than a code lives. An unparseable `created_at` counts as aged out, so a poison row
/// cannot retry forever.
fn aged_out(created_at: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(created_at).map_or(true, |t| {
        now - t.with_timezone(&Utc) >= super::codes::code_lifespan()
    })
}

/// 10 s after the first failure, doubling, at most 5 minutes.
fn backoff_secs(attempts: i32) -> i64 {
    let doublings = u32::try_from(attempts.saturating_sub(1).clamp(0, 16)).unwrap_or(0);
    BACKOFF_FIRST_SECS
        .saturating_mul(1_i64 << doublings)
        .min(BACKOFF_CAP_SECS)
}

/// A queued mail as the worker would send it.
#[cfg(test)]
#[derive(Debug)]
pub(super) struct Mailed {
    pub(super) subject: String,
    pub(super) body: String,
    pub(super) code: String,
}

#[cfg(test)]
impl NativeBackend {
    /// Mail to `recipient` whose payload still opens, oldest first.
    pub(super) async fn mailed(&self, recipient: &str) -> Vec<Mailed> {
        self.outbox_for(recipient)
            .await
            .expect("outbox readable")
            .iter()
            .filter_map(|row| {
                let purpose = Purpose::parse(&row.kind)?;
                let payload = self.open_payload(row)?;
                Some(Mailed {
                    subject: subject(purpose, &payload.code),
                    body: body(&payload),
                    code: payload.code,
                })
            })
            .collect()
    }

    /// Every outbox row for `recipient`, oldest first.
    pub(super) async fn outbox_for(&self, recipient: &str) -> Result<Vec<OutboxRow>> {
        let recipient = recipient.to_string();
        Ok(db_interact!(self.db, |c| {
            identity_mail_outbox::table
                .filter(identity_mail_outbox::recipient.eq(&recipient))
                .order(identity_mail_outbox::created_at.asc())
                .select(OutboxRow::as_select())
                .load(c)
        })?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::CourierStatus;
    use crate::identity_native::test_support::identity_with_password;

    /// Records every send; fails while `fail` is set.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(String, String, String)>>,
        fail: AtomicBool,
    }

    impl Sender for Arc<Recorder> {
        async fn send(&self, recipient: &str, subject: &str, body: &str) -> Result<()> {
            if self.fail.load(Ordering::SeqCst) {
                anyhow::bail!("smtp: 451 try again later");
            }
            self.sent.lock().unwrap().push((
                recipient.to_string(),
                subject.to_string(),
                body.to_string(),
            ));
            Ok(())
        }
    }

    impl Recorder {
        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    async fn setup() -> (DbPool, Arc<NativeBackend>, Arc<Recorder>) {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        (db, backend, Arc::default())
    }

    /// An identity with one queued verification mail; returns its address and flow id.
    async fn queued(backend: &NativeBackend, email: &str) -> (String, String) {
        let id = identity_with_password(&backend.db, email, false).await;
        let flow = backend
            .create_verification_flow(email, None, None)
            .await
            .unwrap();
        backend
            .send_code(&flow.row.id, Purpose::Verification, &id, email)
            .await
            .unwrap();
        (email.to_string(), flow.row.id)
    }

    async fn only_row(backend: &NativeBackend, email: &str) -> OutboxRow {
        let mut rows = backend.outbox_for(email).await.unwrap();
        assert_eq!(rows.len(), 1);
        rows.remove(0)
    }

    async fn set(db: &DbPool, id: &str, attempts: i32, next: &str, created: &str) {
        let (id, next, created) = (id.to_string(), next.to_string(), created.to_string());
        let run = async {
            Ok::<_, anyhow::Error>(db_interact!(db, |c| {
                diesel::update(identity_mail_outbox::table.find(&id))
                    .set((
                        identity_mail_outbox::attempts.eq(attempts),
                        identity_mail_outbox::next_attempt_at.eq(&next),
                        identity_mail_outbox::created_at.eq(&created),
                    ))
                    .execute(c)
            })?)
        };
        run.await.unwrap();
    }

    fn ago(minutes: i64) -> String {
        crate::db::rfc3339(Utc::now() - chrono::Duration::minutes(minutes))
    }

    /// The first standalone run of six digits, as the test suites read a code from a mail body.
    fn first_six_digits(body: &str) -> Option<&str> {
        body.split(|c: char| !c.is_ascii_alphanumeric())
            .find(|w| w.len() == 6 && w.bytes().all(|b| b.is_ascii_digit()))
    }

    #[tokio::test]
    async fn verification_and_recovery_mail_have_the_agreed_shape() {
        let (_, backend, _) = setup().await;
        let row = backend.outbox_row(Purpose::Verification, "i-1", "a@x.test", "flow 1", "012345");
        assert!(!row.payload.contains("012345"), "the payload is sealed");
        assert_eq!((row.state.as_str(), row.attempts), ("queued", 0));
        let payload = backend.open_payload(&row).unwrap();
        assert_eq!(
            subject(Purpose::Verification, &payload.code),
            "Use code 012345 to verify your account"
        );
        let text = body(&payload);
        assert_eq!(
            text,
            "012345\n\nhttp://localhost:3000/self-service/verification?flow=flow+1&code=012345\n"
        );
        assert_eq!(text.lines().next(), Some("012345"));
        assert_eq!(first_six_digits(&text), Some("012345"));

        let row = backend.outbox_row(Purpose::Recovery, "i-1", "a@x.test", "flow-2", "987654");
        let payload = backend.open_payload(&row).unwrap();
        assert_eq!(
            subject(Purpose::Recovery, &payload.code),
            "Use code 987654 to recover access to your account"
        );
        assert_eq!(body(&payload), "987654\n", "recovery mail carries no link");

        let mut moved = row.clone();
        moved.id = "another-row".into();
        assert!(backend.open_payload(&moved).is_none(), "bound to its row");
    }

    #[tokio::test]
    async fn a_sent_mail_is_marked_sent_and_its_payload_blanked() {
        let (_, backend, sender) = setup().await;
        let (email, _) = queued(&backend, "sent@x.test").await;
        let code = backend.mailed(&email).await[0].code.clone();
        assert_eq!(drain_once(&backend, &sender).await.unwrap(), 1);
        let sent = sender.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, email);
        assert_eq!(sent[0].1, format!("Use code {code} to verify your account"));
        assert!(sent[0].2.starts_with(&format!("{code}\n\n")));

        let row = only_row(&backend, &email).await;
        assert_eq!((row.state.as_str(), row.attempts), ("sent", 1));
        assert_eq!(row.payload, "");
        assert!(row.sent_at.is_some() && row.last_error.is_none());
        assert_eq!(drain_once(&backend, &sender).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_failed_send_backs_off_then_retries() {
        let (db, backend, sender) = setup().await;
        let (email, _) = queued(&backend, "retry@x.test").await;
        sender.fail.store(true, Ordering::SeqCst);
        let before = Utc::now();
        drain_once(&backend, &sender).await.unwrap();
        let row = only_row(&backend, &email).await;
        assert_eq!((row.state.as_str(), row.attempts), ("queued", 1));
        assert!(row.last_error.as_deref().unwrap().contains("451"));
        let next = DateTime::parse_from_rfc3339(&row.next_attempt_at).unwrap();
        let wait = next.with_timezone(&Utc) - before;
        assert!((9..=11).contains(&wait.num_seconds()), "{wait}");
        assert_eq!(
            drain_once(&backend, &sender).await.unwrap(),
            0,
            "not due yet"
        );

        set(&db, &row.id, 1, &ago(1), &row.created_at).await;
        sender.fail.store(false, Ordering::SeqCst);
        drain_once(&backend, &sender).await.unwrap();
        let row = only_row(&backend, &email).await;
        assert_eq!((row.state.as_str(), row.attempts), ("sent", 2));
        assert_eq!(sender.count(), 1);
    }

    #[tokio::test]
    async fn a_mail_is_abandoned_after_ten_attempts() {
        let (db, backend, sender) = setup().await;
        sender.fail.store(true, Ordering::SeqCst);
        let (many, _) = queued(&backend, "many@x.test").await;
        let row = only_row(&backend, &many).await;
        set(&db, &row.id, 9, &ago(1), &ago(5)).await;

        drain_once(&backend, &sender).await.unwrap();
        let row = only_row(&backend, &many).await;
        assert_eq!((row.state.as_str(), row.attempts), ("abandoned", 10));
        assert_eq!(row.payload, "", "an abandoned code is not kept");
        assert!(row.last_error.is_some());
        assert_eq!(drain_once(&backend, &sender).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_mail_older_than_its_code_is_abandoned_unsent() {
        let (db, backend, sender) = setup().await;
        let (late, _) = queued(&backend, "late@x.test").await;
        let row = only_row(&backend, &late).await;
        set(&db, &row.id, 2, &ago(1), &ago(16)).await;
        let (fresh, _) = queued(&backend, "fresh@x.test").await;
        let row = only_row(&backend, &fresh).await;
        set(&db, &row.id, 2, &ago(1), &ago(14)).await;

        drain_once(&backend, &sender).await.unwrap();
        let row = only_row(&backend, &late).await;
        assert_eq!((row.state.as_str(), row.attempts), ("abandoned", 3));
        assert_eq!(row.payload, "");
        assert!(row.last_error.as_deref().unwrap().contains("expired"));
        assert_eq!(only_row(&backend, &fresh).await.state, "sent");
        let sent = sender.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, fresh, "the expired code never went out");
    }

    /// Never answers.
    struct Hung;

    impl Sender for Hung {
        async fn send(&self, _: &str, _: &str, _: &str) -> Result<()> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn a_send_that_hangs_times_out_and_is_retried() {
        let (_, backend, _) = setup().await;
        let (email, _) = queued(&backend, "hang@x.test").await;
        let row = only_row(&backend, &email).await;
        let lease = claim(&backend.db, &row).await.unwrap().unwrap();
        deliver(&backend, &Hung, row, &lease, Duration::from_millis(50)).await;
        let row = only_row(&backend, &email).await;
        assert_eq!((row.state.as_str(), row.attempts), ("queued", 1));
        assert!(
            row.last_error.as_deref().unwrap().contains("no answer"),
            "{:?}",
            row.last_error
        );
    }

    #[tokio::test]
    async fn a_result_is_written_only_under_the_workers_own_lease() {
        let (db, backend, _) = setup().await;
        let (email, _) = queued(&backend, "lapse@x.test").await;
        let row = only_row(&backend, &email).await;
        let first = claim(&db, &row).await.unwrap().expect("claimed");
        // The first lease runs out and a second worker claims the row.
        set(&db, &row.id, 0, &ago(1), &row.created_at).await;
        let again = only_row(&backend, &email).await;
        let second = claim(&db, &again).await.unwrap().expect("claimed again");
        assert_ne!(first, second);

        record(&db, &row, &first, Outcome::Failed("late".into()))
            .await
            .unwrap();
        record(&db, &row, &first, Outcome::Sent).await.unwrap();
        let stored = only_row(&backend, &email).await;
        assert_eq!(
            (stored.state.as_str(), stored.attempts, stored.last_error),
            ("queued", 0, None),
            "the lapsed worker wrote nothing"
        );
        assert_eq!(stored.next_attempt_at, second);
        assert!(!stored.payload.is_empty());

        record(&db, &again, &second, Outcome::Sent).await.unwrap();
        assert_eq!(only_row(&backend, &email).await.state, "sent");
    }

    #[tokio::test]
    async fn the_smtp_sender_refuses_when_mail_is_disabled() {
        let mut cfg = AppConfig::test_fixture();
        cfg.email = None;
        let err = Smtp::new(&cfg)
            .send(
                "a@x.test",
                "Use code 123456 to verify your account",
                "123456\n",
            )
            .await
            .unwrap_err();
        assert!(!format!("{err:#}").contains("123456"));
        cfg.email = Some(
            serde_json::from_str(r#"{"enabled":false,"provider":"sendgrid","api_key":""}"#)
                .unwrap(),
        );
        assert!(Smtp::new(&cfg).send("a@x.test", "s", "b").await.is_err());
    }

    #[tokio::test]
    async fn a_leased_row_is_sent_once() {
        let (_, backend, sender) = setup().await;
        let (email, _) = queued(&backend, "lease@x.test").await;
        let row = only_row(&backend, &email).await;
        assert!(claim(&backend.db, &row).await.unwrap().is_some());
        assert!(
            claim(&backend.db, &row).await.unwrap().is_none(),
            "a second worker holding the same snapshot loses"
        );
        assert_eq!(drain_once(&backend, &sender).await.unwrap(), 0, "leased");

        let (email, _) = queued(&backend, "race@x.test").await;
        let (a, b) = tokio::join!(drain_once(&backend, &sender), drain_once(&backend, &sender));
        a.unwrap();
        b.unwrap();
        assert_eq!(sender.count(), 1);
        assert_eq!(only_row(&backend, &email).await.state, "sent");
    }

    #[tokio::test]
    async fn the_courier_backlog_counts_queued_and_abandoned_mail() {
        let (db, backend, sender) = setup().await;
        for i in 0..3 {
            queued(&backend, &format!("q{i}@x.test")).await;
        }
        assert_eq!(
            backend
                .courier_backlog(CourierStatus::Queued, 100)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            backend
                .courier_backlog(CourierStatus::Queued, 2)
                .await
                .unwrap(),
            2,
            "capped like Kratos's first page"
        );
        assert_eq!(
            backend
                .courier_backlog(CourierStatus::Abandoned, 100)
                .await
                .unwrap(),
            0
        );
        let row = only_row(&backend, "q0@x.test").await;
        set(&db, &row.id, 9, &ago(1), &row.created_at).await;
        sender.fail.store(true, Ordering::SeqCst);
        drain_once(&backend, &sender).await.unwrap();
        assert_eq!(
            backend
                .courier_backlog(CourierStatus::Abandoned, 100)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            backend
                .courier_backlog(CourierStatus::Queued, 100)
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn the_worker_sends_as_soon_as_a_code_is_queued_and_stops_on_shutdown() {
        let (_, backend, sender) = setup().await;
        let shutdown = CancellationToken::new();
        backend.mail_worker.last_beat_ago(600);
        let task = spawn_worker(backend.clone(), sender.clone(), shutdown.clone());
        tokio::time::timeout(Duration::from_secs(2), async {
            while backend.mail_worker.seconds_since_last_tick() > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the first drain beats the heartbeat");
        queued(&backend, "wake@x.test").await;
        tokio::time::timeout(Duration::from_secs(TICK_SECS / 2), async {
            while sender.count() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sent before the next tick");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the worker exits on shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn readyz_reports_a_stale_mail_worker() {
        use axum::extract::State;
        let (db, backend, _) = setup().await;
        let state = crate::state::AppState::for_test(
            AppConfig::test_fixture(),
            db,
            backend.clone(),
            &[0x42; 32],
        );
        let body = |resp: axum::response::Response| async move {
            let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        };
        assert_eq!(
            body(crate::app::readyz(State(state.clone())).await).await,
            "ready"
        );
        backend.mail_worker.last_beat_ago(60);
        let degraded = body(crate::app::readyz(State(state)).await).await;
        assert!(
            degraded.starts_with("ready (degraded: mail worker stale, 6"),
            "{degraded}"
        );
    }

    #[test]
    fn backoff_starts_at_ten_seconds_and_doubles_to_five_minutes() {
        let steps: Vec<i64> = (1..=8).map(backoff_secs).collect();
        assert_eq!(steps, [10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(backoff_secs(0), 10);
        assert_eq!(backoff_secs(i32::MAX), 300);
    }
}
