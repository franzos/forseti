//! Outbox saga state machine + DB row read/write.
//!
//! ## State machine
//!
//! ```text
//!   PENDING  ─(Kratos delete succeeded)──▶  CONFIRMED  ──(worker delivers)──▶  delivered_at set
//!      │
//!      ├─(Kratos delete failed)──────────▶  ABORTED
//!      │
//!      └─(crash recovery: identity gone)─▶  CONFIRMED
//!                            (still there)─▶ ABORTED
//!
//!   CONFIRMED  ─(>12 attempts or >72h)───▶  DEAD
//! ```
//!
//! Rows are written `PENDING` *before* the destructive Kratos call. Once
//! Kratos confirms the identity is gone, they flip to `CONFIRMED` and a
//! background worker drains them with retry/backoff. Worker only ever
//! touches `CONFIRMED` — `PENDING` rows are invisible to it.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use crate::db::DbPool;
use crate::db_interact;
use crate::ory::OryClients;
use crate::schema::webhook_outbox;

use super::signing::{extract_subject_from_jws, sign_set, SigningKey};

/// Outbox row state. Stored as a `TEXT` column so the strings are the
/// source of truth — no `#[repr]` games across the diesel boundary.
pub mod state {
    pub const PENDING: &str = "PENDING";
    pub const CONFIRMED: &str = "CONFIRMED";
    pub const ABORTED: &str = "ABORTED";
    pub const DEAD: &str = "DEAD";
}

/// Target of a single webhook delivery as recorded at enqueue time.
#[derive(Debug, Clone)]
pub struct WebhookTarget {
    pub client_id: String,
    pub url: String,
}

/// Full row projection. Some fields (`state`, `delivered_at`) aren't
/// field-accessed in Rust today but are written / filtered on via
/// `webhook_outbox::dsl::*`; dropping them from the struct would force
/// every `.load()` call to project a partial row. Allow the dead-code
/// warning rather than fight that.
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = webhook_outbox)]
#[allow(dead_code)]
pub struct OutboxRow {
    pub id: String,
    pub event_id: String,
    pub client_id: String,
    pub url: String,
    pub payload: String,
    pub state: String,
    pub attempts: i32,
    pub next_attempt_at: String,
    pub last_error: Option<String>,
    pub created_at: String,
    pub delivered_at: Option<String>,
}

#[derive(Insertable)]
#[diesel(table_name = webhook_outbox)]
struct NewOutboxRow {
    id: String,
    event_id: String,
    client_id: String,
    url: String,
    payload: String,
    state: String,
    attempts: i32,
    next_attempt_at: String,
    created_at: String,
}

/// Write one PENDING outbox row per (client, target URL) for a single
/// delete event. Returns the row ids so a caller can correlate them with
/// log lines.
pub async fn enqueue_pending(
    db: &DbPool,
    key: &SigningKey,
    iss: &str,
    event_id: Uuid,
    user_id: &str,
    deleted_at: DateTime<Utc>,
    targets: &[WebhookTarget],
) -> anyhow::Result<Vec<String>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let now = Utc::now().to_rfc3339();
    let mut rows = Vec::with_capacity(targets.len());
    for target in targets {
        let payload = sign_set(key, iss, event_id, user_id, &target.client_id, deleted_at)?;
        rows.push(NewOutboxRow {
            id: Uuid::new_v4().to_string(),
            event_id: event_id.to_string(),
            client_id: target.client_id.clone(),
            url: target.url.clone(),
            payload,
            state: state::PENDING.to_string(),
            attempts: 0,
            next_attempt_at: now.clone(),
            created_at: now.clone(),
        });
    }
    let row_ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    db_interact!(db, |conn| {
        diesel::insert_into(webhook_outbox::table)
            .values(&rows)
            .execute(conn)?;
        Ok::<_, diesel::result::Error>(())
    })?;
    Ok(row_ids)
}

/// Flip every PENDING row for an event to CONFIRMED so the worker can
/// pick them up. Called immediately after Kratos confirms the identity is
/// gone.
pub async fn confirm_event(db: &DbPool, event_id: Uuid) -> anyhow::Result<usize> {
    let event_id = event_id.to_string();
    let n = db_interact!(db, |conn| {
        diesel::update(
            webhook_outbox::table
                .filter(webhook_outbox::event_id.eq(&event_id))
                .filter(webhook_outbox::state.eq(state::PENDING)),
        )
        .set(webhook_outbox::state.eq(state::CONFIRMED))
        .execute(conn)
    })?;
    Ok(n)
}

/// Flip every PENDING row for an event to ABORTED so the worker never
/// picks them up. Called when the Kratos delete fails — the user is told
/// nothing happened, so neither should the downstream apps be.
pub async fn abort_event(db: &DbPool, event_id: Uuid) -> anyhow::Result<usize> {
    let event_id = event_id.to_string();
    let n = db_interact!(db, |conn| {
        diesel::update(
            webhook_outbox::table
                .filter(webhook_outbox::event_id.eq(&event_id))
                .filter(webhook_outbox::state.eq(state::PENDING)),
        )
        .set(webhook_outbox::state.eq(state::ABORTED))
        .execute(conn)
    })?;
    Ok(n)
}

/// Count of rows in `DEAD` state. Drives the banner on `/admin/status`.
pub async fn dead_letter_count(db: &DbPool) -> anyhow::Result<i64> {
    let n: i64 = db_interact!(db, |conn| {
        webhook_outbox::table
            .filter(webhook_outbox::state.eq(state::DEAD))
            .count()
            .get_result(conn)
    })?;
    Ok(n)
}

/// Fetch a single outbox row by id, regardless of state. Used by the
/// `/admin/webhooks/{id}` detail page so an operator can inspect the
/// payload, full URL, and full last_error without the summary table
/// having to carry them.
pub async fn find_by_id(db: &DbPool, row_id: &str) -> anyhow::Result<Option<OutboxRow>> {
    let row_id = row_id.to_string();
    let row = db_interact!(db, |conn| {
        webhook_outbox::table
            .filter(webhook_outbox::id.eq(&row_id))
            .select(OutboxRow::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Hard cap on the dead-letter list (see `orgs::db::MAX_ROWS_PER_LIST`).
const MAX_ROWS_PER_LIST: i64 = 500;

/// DEAD rows for the `/admin/webhooks` page. Newest first, capped at
/// [`MAX_ROWS_PER_LIST`].
pub async fn list_dead(db: &DbPool) -> anyhow::Result<Vec<OutboxRow>> {
    let rows = db_interact!(db, |conn| {
        webhook_outbox::table
            .filter(webhook_outbox::state.eq(state::DEAD))
            .order(webhook_outbox::created_at.desc())
            .limit(MAX_ROWS_PER_LIST)
            .select(OutboxRow::as_select())
            .load(conn)
    })?;
    Ok(rows)
}

/// Reset a DEAD row back to CONFIRMED with `attempts=0` so the worker
/// picks it up again on the next tick.
pub async fn requeue_dead(db: &DbPool, row_id: &str) -> anyhow::Result<bool> {
    let row_id = row_id.to_string();
    let now = Utc::now().to_rfc3339();
    let n = db_interact!(db, |conn| {
        diesel::update(
            webhook_outbox::table
                .filter(webhook_outbox::id.eq(&row_id))
                .filter(webhook_outbox::state.eq(state::DEAD)),
        )
        .set((
            webhook_outbox::state.eq(state::CONFIRMED),
            webhook_outbox::attempts.eq(0),
            webhook_outbox::next_attempt_at.eq(&now),
            webhook_outbox::last_error.eq::<Option<String>>(None),
        ))
        .execute(conn)
    })?;
    Ok(n > 0)
}

/// Hard-delete a DEAD row. Operator explicitly chose to drop it; no
/// retention.
pub async fn discard_dead(db: &DbPool, row_id: &str) -> anyhow::Result<bool> {
    let row_id = row_id.to_string();
    let n = db_interact!(db, |conn| {
        diesel::delete(
            webhook_outbox::table
                .filter(webhook_outbox::id.eq(&row_id))
                .filter(webhook_outbox::state.eq(state::DEAD)),
        )
        .execute(conn)
    })?;
    Ok(n > 0)
}

/// Crash recovery: if Forseti died between writing PENDING rows and
/// flipping them (saga step 4 → step 6), reconcile against Kratos. If the
/// identity is gone, flip to CONFIRMED; if it still exists, flip to
/// ABORTED. Bounded to rows older than the 5-minute reconcile window so
/// in-flight transactions aren't disturbed.
pub async fn reconcile_pending(db: &DbPool, ory: &Arc<OryClients>) -> anyhow::Result<()> {
    let cutoff = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    let stuck = db_interact!(db, |conn| {
        webhook_outbox::table
            .filter(webhook_outbox::state.eq(state::PENDING))
            .filter(webhook_outbox::created_at.lt(&cutoff))
            .select(OutboxRow::as_select())
            .load(conn)
    })?;
    if stuck.is_empty() {
        return Ok(());
    }
    tracing::warn!(rows = stuck.len(), "reconciling stuck PENDING outbox rows");

    // Group by event_id and probe Kratos once per event. The subject lives
    // inside the SET JWS, which Forseti signed itself, so we extract it
    // without verifying — refusing the row only if the payload won't parse.
    let mut by_event: std::collections::HashMap<String, Vec<OutboxRow>> = Default::default();
    for row in stuck {
        by_event.entry(row.event_id.clone()).or_default().push(row);
    }

    for (event_id, rows) in by_event {
        let user_id = rows
            .first()
            .and_then(|r| extract_subject_from_jws(&r.payload));
        let Some(user_id) = user_id else {
            tracing::error!(
                event_id,
                "could not parse stuck PENDING payload for reconcile"
            );
            continue;
        };

        let identity_gone = match crate::ory::kratos::admin_get_identity_optional(ory, &user_id)
            .await
        {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(e) => {
                tracing::warn!(error = %e, event_id, "reconcile: identity probe failed; leaving PENDING");
                continue;
            }
        };

        let event_uuid = match Uuid::parse_str(&event_id) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if identity_gone {
            confirm_event(db, event_uuid).await?;
            tracing::info!(event_id, "reconciled: identity gone, rows → CONFIRMED");
        } else {
            abort_event(db, event_uuid).await?;
            tracing::info!(
                event_id,
                "reconciled: identity still present, rows → ABORTED"
            );
        }
    }
    Ok(())
}
