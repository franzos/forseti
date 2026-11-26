//! OP login sessions in `oauth_login_sessions`, keyed by `sid`, and the `forseti_op` cookie that
//! names a remembered one.

use anyhow::Result;
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use diesel::prelude::*;

use super::authorize::LoginSessionSnapshot;
use super::{REMEMBER_CAP_SECS, parse_time};
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::{oauth_authorization_codes, oauth_login_sessions};
use crate::signed_cookie::{SignedCookie, unix_seconds_now};

const OP_COOKIE: &str = "forseti_op";
const OP_COOKIE_LABEL: &[u8] = b"forseti::oauth::op-session::v1";
/// Scoped to the authorization and resume endpoints, the only readers.
pub(super) const COOKIE_PATH: &str = "/oauth2";

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = oauth_login_sessions)]
pub(super) struct SessionRow {
    pub(super) sid: String,
    pub(super) subject: String,
    pub(super) auth_time: String,
    pub(super) acr: Option<String>,
    pub(super) amr: String,
    pub(super) remember: i32,
    pub(super) created_at: String,
    pub(super) expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LoginSession {
    pub(super) sid: String,
    pub(super) subject: String,
    pub(super) auth_time: DateTime<Utc>,
    pub(super) remember: bool,
    pub(super) expires_at: DateTime<Utc>,
}

impl LoginSession {
    pub(super) fn snapshot(&self) -> LoginSessionSnapshot {
        LoginSessionSnapshot {
            sid: self.sid.clone(),
            auth_time: self.auth_time,
            remember: self.remember,
            expires_at: self.expires_at,
        }
    }

    fn from_row(row: SessionRow) -> Result<Self> {
        Ok(Self {
            auth_time: parse_time(&row.auth_time)?,
            expires_at: parse_time(&row.expires_at)?,
            remember: row.remember != 0,
            sid: row.sid,
            subject: row.subject,
        })
    }
}

/// Seconds a login is remembered for: `remember_for` capped at [`REMEMBER_CAP_SECS`], which
/// zero or less also means.
pub(super) fn remember_window(remember_for: i64) -> i64 {
    if remember_for > 0 {
        remember_for.min(REMEMBER_CAP_SECS)
    } else {
        REMEMBER_CAP_SECS
    }
}

/// The session `sid`, expired or not.
pub(super) async fn find(db: &DbPool, sid: &str) -> Result<Option<LoginSession>> {
    let sid = sid.to_string();
    let row = db_interact!(db, |c| {
        oauth_login_sessions::table
            .find(sid)
            .select(SessionRow::as_select())
            .first(c)
            .optional()
    })?;
    row.map(LoginSession::from_row).transpose()
}

/// Deletes the session and the codes issued under it that were not redeemed yet; grants stay.
/// `true` when this call deleted the session row.
pub(super) async fn revoke_by_sid(db: &DbPool, sid: &str) -> Result<bool> {
    let sid = sid.to_string();
    let deleted = db_interact!(db, |c| {
        c.transaction(|c| {
            diesel::delete(
                oauth_authorization_codes::table
                    .filter(oauth_authorization_codes::session_id.eq(&sid))
                    .filter(oauth_authorization_codes::used_at.is_null()),
            )
            .execute(c)?;
            diesel::delete(oauth_login_sessions::table.find(&sid)).execute(c)
        })
    })?;
    Ok(deleted > 0)
}

/// Deletes the subject's sessions and its codes that were not redeemed yet; grants stay.
pub(super) async fn revoke_for_subject(db: &DbPool, subject: &str) -> Result<()> {
    let subject = subject.to_string();
    db_interact!(db, |c| {
        c.transaction(|c| {
            diesel::delete(
                oauth_authorization_codes::table
                    .filter(oauth_authorization_codes::subject.eq(&subject))
                    .filter(oauth_authorization_codes::used_at.is_null()),
            )
            .execute(c)?;
            diesel::delete(
                oauth_login_sessions::table.filter(oauth_login_sessions::subject.eq(&subject)),
            )
            .execute(c)
        })
    })?;
    Ok(())
}

fn op_cookie(secure: bool) -> SignedCookie<'static> {
    SignedCookie {
        name: OP_COOKIE,
        salt: OP_COOKIE_LABEL,
        ttl_secs: REMEMBER_CAP_SECS.unsigned_abs(),
        secure,
        path: COOKIE_PATH,
    }
}

/// The `sid` the `forseti_op` cookie names; a tampered or foreign value reads as absent.
pub(super) fn read_op_cookie(secret: &[u8], headers: &HeaderMap) -> Option<String> {
    let payload = op_cookie(false).decode(secret, headers, unix_seconds_now())?;
    String::from_utf8(payload).ok().filter(|s| !s.is_empty())
}

pub(super) fn set_op_cookie(secret: &[u8], sid: &str, max_age: i64, secure: bool) -> String {
    let codec = op_cookie(secure);
    let value = codec.encode(secret, sid.as_bytes(), unix_seconds_now());
    format!("{}; Max-Age={max_age}", codec.set_header(&value))
}

pub(super) fn clear_op_cookie(secure: bool) -> String {
    op_cookie(secure).clear_header()
}

#[cfg(test)]
mod tests;
