//! Initial Access Token (IAT) lookup + rate-limit window logic for the
//! DCR proxy. See the module docstring on [`crate::oauth::register`] for
//! how this fits into the overall pipeline.

use axum::http::HeaderMap;
use chrono::{Duration as ChronoDuration, Utc};
use diesel::prelude::*;
use sha2::{Digest, Sha256};

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::dcr_initial_access_tokens as iat;

/// Canonical row for `dcr_initial_access_tokens`, reused from
/// `admin::dcr_tokens` so the two readers can't desync on a column drift.
pub(super) use crate::admin::dcr_tokens::StoredIat as IatRow;

/// Default `dcr_iat_daily_limit`. Caps even an "unlimited" IAT to this many
/// clients per rolling 24h window.
pub(crate) const DEFAULT_IAT_DAILY_LIMIT: u32 = 50;

/// Outcome of parsing the `Authorization` header. "No header" (anonymous
/// path) is split from "malformed" (rejected with 401) so a garbage header
/// can't silently probe past IAT validation.
pub(super) enum AuthOutcome {
    /// No `Authorization` header at all — proceed anonymously.
    None,
    /// Header present but not a usable bearer token (wrong scheme, empty
    /// value, non-ASCII). Rejected with 401 + audit row.
    Malformed,
    /// Looks like a bearer token; pass to [`lookup_iat`].
    Token(String),
}

/// Outcome of validating the IAT in the request.
pub(super) enum IatCheck {
    Ok(IatRow),
    /// Header missing, malformed, or token didn't match a row.
    Invalid,
    /// Token matched a row but the row is revoked, expired, or has no
    /// uses remaining. The `iat_id` is surfaced so the audit row carries
    /// the actor identity even when the IAT is no longer usable.
    Exhausted {
        iat_id: String,
    },
    /// The DB read failed. Distinct from `Invalid` so the handler can
    /// return 503 (`server_error`) instead of 401 — a transient DB blip
    /// should not look like "your token is wrong" to the caller.
    DatabaseError,
}

/// Outcome of trying to consume one use of an IAT.
pub(super) enum IatConsume {
    Ok,
    /// Row no longer has uses remaining, was revoked, or expired between
    /// the lookup and the consume. Race-only path under single-use IATs.
    Exhausted,
    /// The token still has `uses_remaining > 0` but has burned through
    /// its rolling 24h cap. Distinct from `Exhausted` so the handler can
    /// emit a `dcr_rate_limited` audit row (WARNING) and a 429 instead
    /// of a 401.
    DailyLimit {
        count: i32,
    },
}

/// SHA-256 hex of `raw_token`. Tokens are 32 random bytes base64url-encoded;
/// we never persist the plaintext, only this hash.
pub(crate) fn hash_token(raw_token: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw_token.as_bytes());
    hex::encode(h.finalize())
}

/// Parse the `Authorization` header into absent / malformed / bearer token.
/// Case-insensitive scheme match per RFC 6750 §2.1.
pub(super) fn parse_authorization(headers: &HeaderMap) -> AuthOutcome {
    let Some(raw_header) = headers.get("authorization") else {
        return AuthOutcome::None;
    };
    let Ok(raw) = raw_header.to_str() else {
        return AuthOutcome::Malformed;
    };
    let Some((scheme, token)) = raw.split_once(' ') else {
        return AuthOutcome::Malformed;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return AuthOutcome::Malformed;
    }
    let token = token.trim();
    if token.is_empty() {
        return AuthOutcome::Malformed;
    }
    AuthOutcome::Token(token.to_string())
}

/// Validate an IAT without consuming it. The decrement happens in
/// [`consume_iat`] only after all validations pass, so name-probing can't
/// burn through someone else's single-use IAT.
pub(super) async fn lookup_iat(db: &DbPool, raw_token: &str) -> IatCheck {
    let hash = hash_token(raw_token);
    let now = Utc::now().to_rfc3339();

    let outcome: anyhow::Result<IatCheck> = async {
        let result = db_interact!(db, |conn| {
            let row: Option<IatRow> = iat::table
                .filter(iat::token_hash.eq(hash))
                .select(IatRow::as_select())
                .first(conn)
                .optional()?;
            let Some(row) = row else {
                return Ok::<_, diesel::result::Error>(IatCheck::Invalid);
            };
            if row.revoked_at.is_some() {
                return Ok(IatCheck::Exhausted { iat_id: row.id });
            }
            if let Some(exp) = row.expires_at.as_deref() {
                if exp <= now.as_str() {
                    return Ok(IatCheck::Exhausted { iat_id: row.id });
                }
            }
            if let Some(uses) = row.uses_remaining {
                if uses <= 0 {
                    return Ok(IatCheck::Exhausted { iat_id: row.id });
                }
            }
            Ok(IatCheck::Ok(row))
        })?;
        Ok(result)
    }
    .await;

    match outcome {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "dcr: IAT lookup failed");
            IatCheck::DatabaseError
        }
    }
}

/// Atomically decrement `uses_remaining` and advance the daily counter in one
/// transaction. `uses_remaining` (NULL = unlimited) is gated on `> 0` so
/// concurrent racers against a single-use IAT can't both win.
///
/// Atomicity: the UPDATE's `WHERE` carries the daily-counter predicate
/// (`daily_use_count < daily_limit`, or the observed-window match on reset),
/// so a second racer that read the same count at a READ COMMITTED boundary
/// matches zero rows and falls through to `DailyLimit`. Redundant but
/// harmless on sqlite (serialised writers).
///
/// `daily_limit == 0` disables the cap (counters still advance for observability).
pub(super) async fn consume_iat(db: &DbPool, row: &IatRow, daily_limit: u32) -> IatConsume {
    let id = row.id.clone();
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let window_cutoff = (now - ChronoDuration::hours(24)).to_rfc3339();

    let outcome: anyhow::Result<IatConsume> = async {
        let r: IatConsume = db_interact!(db, |conn| {
            conn.transaction::<IatConsume, diesel::result::Error, _>(|c| {
                // Re-read inside the transaction for committed state, not the
                // `lookup_iat` snapshot.
                let current: Option<IatRow> = iat::table
                    .filter(iat::id.eq(&id))
                    .select(IatRow::as_select())
                    .first(c)
                    .optional()?;
                let Some(current) = current else {
                    return Ok(IatConsume::Exhausted);
                };
                if current.revoked_at.is_some() {
                    return Ok(IatConsume::Exhausted);
                }
                if let Some(exp) = current.expires_at.as_deref() {
                    if exp <= now_str.as_str() {
                        return Ok(IatConsume::Exhausted);
                    }
                }
                if let Some(rem) = current.uses_remaining {
                    if rem <= 0 {
                        return Ok(IatConsume::Exhausted);
                    }
                }

                // Live only if `started_at` is set and within 24h; else reset.
                let in_window = current
                    .daily_window_started_at
                    .as_deref()
                    .map(|started| started > window_cutoff.as_str())
                    .unwrap_or(false);
                let observed_window = current.daily_window_started_at.clone();

                let capped = daily_limit > 0;
                let limit = daily_limit as i32;
                let new_window = Some(now_str.clone());

                // One predicate covers both: NULL (unlimited) stays NULL under
                // `- 1` and passes; bounded rows must still have a use left.
                let not_exhausted = iat::uses_remaining.is_null().or(iat::uses_remaining.gt(0));
                let dec_uses = iat::uses_remaining.eq(iat::uses_remaining - 1);
                let base = iat::table.filter(iat::id.eq(&id)).filter(not_exhausted);

                let updated = if in_window {
                    // Skip the UPDATE when already at the cap so the caller
                    // keeps the actual count for the audit row (the predicate
                    // below would match zero rows but lose the count).
                    if capped && current.daily_use_count >= limit {
                        return Ok(IatConsume::DailyLimit {
                            count: current.daily_use_count,
                        });
                    }
                    let next_count = current.daily_use_count + 1;
                    let set = (dec_uses, iat::daily_use_count.eq(next_count));
                    if capped {
                        // `daily_use_count < limit` is the atomicity backstop
                        // for the READ COMMITTED boundary race.
                        diesel::update(base.filter(iat::daily_use_count.lt(limit)))
                            .set(set)
                            .execute(c)?
                    } else {
                        diesel::update(base).set(set).execute(c)?
                    }
                } else {
                    // Gate the reset on the observed prior window so a racer
                    // that already reset isn't clobbered back to `count = 1`.
                    let set = (
                        dec_uses,
                        iat::daily_use_count.eq(1),
                        iat::daily_window_started_at.eq(&new_window),
                    );
                    match observed_window.clone() {
                        Some(obs) => {
                            diesel::update(base.filter(iat::daily_window_started_at.eq(obs)))
                                .set(set)
                                .execute(c)?
                        }
                        None => diesel::update(base.filter(iat::daily_window_started_at.is_null()))
                            .set(set)
                            .execute(c)?,
                    }
                };
                if updated == 0 {
                    // Either `uses_remaining` hit zero or the daily predicate
                    // rejected us at the boundary. `DailyLimit` only when we
                    // were inside the window at the limit; else `Exhausted`.
                    if in_window && capped && current.daily_use_count + 1 > limit {
                        return Ok(IatConsume::DailyLimit {
                            count: current.daily_use_count,
                        });
                    }
                    return Ok(IatConsume::Exhausted);
                }
                Ok(IatConsume::Ok)
            })
        })?;
        Ok(r)
    }
    .await;

    match outcome {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "dcr: IAT consume failed");
            IatConsume::Exhausted
        }
    }
}
