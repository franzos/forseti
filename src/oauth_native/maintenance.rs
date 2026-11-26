//! Hourly cleanup of authorization requests, login sessions, codes, refresh tokens, grants,
//! revoked access tokens, device authorizations and logout requests, and a reload of the signing
//! keys. Signing keys are never deleted here.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use tokio_util::sync::CancellationToken;

use super::NativeOAuth;
use crate::db::{DbPool, rfc3339};
use crate::db_interact;
use crate::schema::{
    oauth_authorization_codes, oauth_authorize_requests, oauth_consent_grants, oauth_device_codes,
    oauth_login_sessions, oauth_logout_requests, oauth_refresh_tokens, oauth_revoked_tokens,
};

const FIRST_RUN_DELAY: Duration = Duration::from_secs(60);
const INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Authorization requests, login sessions, device authorizations, logout requests and one-off
/// grants stay this long past expiry or handling.
const GRACE: chrono::Duration = chrono::Duration::days(1);
/// Expired codes stay this long, used ones too, so a replay is still recognised.
const CODE_GRACE: chrono::Duration = chrono::Duration::hours(1);
/// Used refresh tokens stay this long after use, so a replay still revokes the family.
const USED_REFRESH_GRACE: chrono::Duration = chrono::Duration::days(7);
/// Denylisted access tokens stay this long past the expiry stored with them.
const REVOKED_TOKEN_GRACE: chrono::Duration = chrono::Duration::hours(1);

/// Rows deleted by one [`prune`], per table.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Pruned {
    pub flows: usize,
    pub sessions: usize,
    pub codes: usize,
    pub refresh_tokens: usize,
    pub grants: usize,
    pub revoked_tokens: usize,
    pub device_codes: usize,
    pub logout_requests: usize,
}

/// Run [`prune`] and reload the signing keys a minute after boot, then hourly, until `shutdown`.
pub(crate) fn spawn(
    oauth: Arc<NativeOAuth>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + FIRST_RUN_DELAY, INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    match prune(&oauth.db, Utc::now()).await {
                        Ok(p) => tracing::debug!(
                            flows = p.flows,
                            sessions = p.sessions,
                            codes = p.codes,
                            refresh_tokens = p.refresh_tokens,
                            grants = p.grants,
                            revoked_tokens = p.revoked_tokens,
                            device_codes = p.device_codes,
                            logout_requests = p.logout_requests,
                            "oauth maintenance: rows deleted"
                        ),
                        Err(e) => tracing::warn!(error = %e, "oauth maintenance: prune failed"),
                    }
                    if let Err(e) = oauth.reload_keys().await {
                        tracing::warn!(error = %e, "oauth maintenance: signing key reload failed");
                    }
                }
            }
        }
        tracing::info!("oauth maintenance: shutdown received, exiting");
    })
}

/// Deletes what the retention rules no longer need as of `now`. A one-off or skipped grant stays
/// while a refresh token or its login session row exists. Grants go last so one whose refresh
/// tokens or login session were pruned in this pass goes in the same pass.
pub(crate) async fn prune(db: &DbPool, now: DateTime<Utc>) -> Result<Pruned> {
    let now_s = rfc3339(now);
    let grace = rfc3339(now - GRACE);
    let code_grace = rfc3339(now - CODE_GRACE);
    let used_refresh_grace = rfc3339(now - USED_REFRESH_GRACE);
    let revoked_grace = rfc3339(now - REVOKED_TOKEN_GRACE);
    Ok(db_interact!(db, |c| {
        let flows = diesel::delete(
            oauth_authorize_requests::table.filter(oauth_authorize_requests::expires_at.lt(&grace)),
        )
        .execute(c)?;
        let sessions = diesel::delete(
            oauth_login_sessions::table.filter(oauth_login_sessions::expires_at.lt(&grace)),
        )
        .execute(c)?;
        let codes = diesel::delete(
            oauth_authorization_codes::table
                .filter(oauth_authorization_codes::expires_at.lt(&code_grace)),
        )
        .execute(c)?;
        let expired_unused = diesel::delete(
            oauth_refresh_tokens::table
                .filter(oauth_refresh_tokens::used_at.is_null())
                .filter(oauth_refresh_tokens::expires_at.le(&now_s)),
        )
        .execute(c)?;
        let used = diesel::delete(
            oauth_refresh_tokens::table
                .filter(oauth_refresh_tokens::used_at.lt(&used_refresh_grace)),
        )
        .execute(c)?;
        let grants = diesel::delete(
            oauth_consent_grants::table
                .filter(
                    oauth_consent_grants::remember
                        .eq(0)
                        .or(oauth_consent_grants::skipped.ne(0)),
                )
                .filter(oauth_consent_grants::handled_at.lt(&grace))
                .filter(diesel::dsl::not(oauth_consent_grants::id.eq_any(
                    oauth_refresh_tokens::table.select(oauth_refresh_tokens::grant_id),
                )))
                // Back-channel logout finds a session's clients through its grants.
                .filter(diesel::dsl::not(oauth_consent_grants::session_id.eq_any(
                    oauth_login_sessions::table.select(oauth_login_sessions::sid),
                ))),
        )
        .execute(c)?;
        let revoked_tokens = diesel::delete(
            oauth_revoked_tokens::table.filter(oauth_revoked_tokens::expires_at.lt(&revoked_grace)),
        )
        .execute(c)?;
        let device_codes = diesel::delete(
            oauth_device_codes::table.filter(oauth_device_codes::expires_at.lt(&grace)),
        )
        .execute(c)?;
        let logout_requests = diesel::delete(
            oauth_logout_requests::table.filter(oauth_logout_requests::expires_at.lt(&grace)),
        )
        .execute(c)?;
        Ok::<_, diesel::result::Error>(Pruned {
            flows,
            sessions,
            codes,
            refresh_tokens: expired_unused + used,
            grants,
            revoked_tokens,
            device_codes,
            logout_requests,
        })
    })?)
}

#[cfg(test)]
mod tests {
    use diesel::sql_types::Text;

    use super::*;
    use crate::oauth_native::CODE_TTL_SECS;

    fn at(now: DateTime<Utc>, offset: chrono::Duration) -> String {
        rfc3339(now + offset)
    }

    fn mins(m: i64) -> chrono::Duration {
        chrono::Duration::minutes(m)
    }

    fn hours(h: i64) -> chrono::Duration {
        chrono::Duration::hours(h)
    }

    fn days(d: i64) -> chrono::Duration {
        chrono::Duration::days(d)
    }

    fn sql_opt(v: Option<&str>) -> String {
        v.map_or_else(|| "NULL".to_string(), |v| format!("'{v}'"))
    }

    async fn exec(db: &DbPool, sql: String) {
        let run = async {
            Ok::<_, anyhow::Error>(db_interact!(db, |c| { diesel::sql_query(sql).execute(c) })?)
        };
        run.await.unwrap();
    }

    async fn ids(db: &DbPool, table: &str, column: &str) -> Vec<String> {
        let sql = format!("{column} FROM {table} ORDER BY {column}");
        let load = async {
            Ok::<_, anyhow::Error>(db_interact!(db, |c| {
                diesel::select(diesel::dsl::sql::<Text>(&sql)).load::<String>(c)
            })?)
        };
        load.await.unwrap()
    }

    async fn flow(db: &DbPool, id: &str, expires_at: &str) {
        exec(
            db,
            format!(
                "INSERT INTO oauth_authorize_requests (id, client_id, login_challenge_hash, state, \
                 request_url, redirect_uri, response_mode, requested_scope, requested_audience, \
                 requested_resource, oidc_context, session_id, skip_login, created_at, expires_at) \
                 VALUES ('{id}', 'c', '{id}-h', 'login', 'u', 'r', 'query', '[]', '[]', '[]', \
                 '{{}}', 's', 0, '{expires_at}', '{expires_at}')"
            ),
        )
        .await;
    }

    async fn session(db: &DbPool, sid: &str, expires_at: &str) {
        exec(
            db,
            format!(
                "INSERT INTO oauth_login_sessions (sid, subject, auth_time, amr, remember, \
                 created_at, expires_at) \
                 VALUES ('{sid}', 'sub', '{expires_at}', '[]', 1, '{expires_at}', '{expires_at}')"
            ),
        )
        .await;
    }

    async fn grant(db: &DbPool, id: &str, remember: bool, skipped: bool, handled_at: &str) {
        grant_in(db, id, "s", remember, skipped, handled_at).await;
    }

    async fn grant_in(
        db: &DbPool,
        id: &str,
        sid: &str,
        remember: bool,
        skipped: bool,
        handled_at: &str,
    ) {
        let (remember, skipped) = (i32::from(remember), i32::from(skipped));
        exec(
            db,
            format!(
                "INSERT INTO oauth_consent_grants (id, client_id, subject, session_id, scope, \
                 audience, id_token_claims, access_token_claims, remember, skipped, handled_at) \
                 VALUES ('{id}', 'c', 'sub', '{sid}', '[]', '[]', '{{}}', '{{}}', {remember}, \
                 {skipped}, '{handled_at}')"
            ),
        )
        .await;
    }

    async fn code(db: &DbPool, id: &str, grant: &str, expires_at: &str, used_at: Option<&str>) {
        let used_at = sql_opt(used_at);
        exec(
            db,
            format!(
                "INSERT INTO oauth_authorization_codes (code_hash, grant_id, client_id, subject, \
                 session_id, redirect_uri, scope, audience, auth_time, amr, family_id, created_at, \
                 expires_at, used_at) \
                 VALUES ('{id}', '{grant}', 'c', 'sub', 's', 'r', '[]', '[]', '{expires_at}', '[]', \
                 'f', '{expires_at}', '{expires_at}', {used_at})"
            ),
        )
        .await;
    }

    async fn refresh(db: &DbPool, id: &str, grant: &str, expires_at: &str, used_at: Option<&str>) {
        let used_at = sql_opt(used_at);
        exec(
            db,
            format!(
                "INSERT INTO oauth_refresh_tokens (id, token_hash, family_id, grant_id, client_id, \
                 subject, session_id, scope, audience, auth_time, amr, created_at, expires_at, \
                 used_at) \
                 VALUES ('{id}', '{id}-h', 'f', '{grant}', 'c', 'sub', 's', '[]', '[]', \
                 '{expires_at}', '[]', '{expires_at}', '{expires_at}', {used_at})"
            ),
        )
        .await;
    }

    async fn signing_key(db: &DbPool, kid: &str, status: &str, at: &str, retired: Option<&str>) {
        let retired = sql_opt(retired);
        exec(
            db,
            format!(
                "INSERT INTO oauth_signing_keys (kid, alg, public_jwk, private_sealed, status, \
                 created_at, retired_at) \
                 VALUES ('{kid}', 'RS256', '{{}}', 'x', '{status}', '{at}', {retired})"
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn prune_keeps_each_row_its_retention_window_needs() {
        // An unredeemed, unexpired code can only sit under a grant handled within CODE_TTL_SECS,
        // so pruning grants older than a day never cascades onto one.
        assert!(CODE_TTL_SECS < GRACE.num_seconds());

        let db = crate::db::test_pool().await;
        let now = Utc::now();
        let t = |offset| at(now, offset);
        exec(
            &db,
            format!(
                "INSERT INTO oauth_clients (client_id, token_endpoint_auth_method, extra, \
                 created_at, updated_at) VALUES ('c', 'none', '{{}}', '{0}', '{0}')",
                t(-days(400))
            ),
        )
        .await;

        flow(&db, "f-expired-25h", &t(-hours(25))).await;
        flow(&db, "f-expired-23h", &t(-hours(23))).await;
        flow(&db, "f-live", &t(mins(30))).await;

        session(&db, "s-expired-25h", &t(-hours(25))).await;
        session(&db, "s-expired-23h", &t(-hours(23))).await;
        session(&db, "s-live", &t(days(30))).await;

        grant(&db, "g-remembered-old", true, false, &t(-days(30))).await;
        grant(&db, "g-skipped-old", true, true, &t(-hours(25))).await;
        grant(&db, "g-once-old", false, false, &t(-hours(25))).await;
        grant(&db, "g-once-young", false, false, &t(-hours(23))).await;
        grant(&db, "g-skipped-young", true, true, &t(-hours(23))).await;
        grant(&db, "g-once-live-refresh", false, false, &t(-days(10))).await;
        grant(&db, "g-skipped-used-refresh", true, true, &t(-days(10))).await;
        grant(&db, "g-once-expired-refresh", false, false, &t(-days(40))).await;
        let old = t(-days(10));
        grant_in(&db, "g-skipped-live-session", "s-live", true, true, &old).await;
        grant_in(&db, "g-once-live-session", "s-live", false, false, &old).await;
        grant_in(
            &db,
            "g-skipped-unpruned-session",
            "s-expired-23h",
            true,
            true,
            &old,
        )
        .await;
        grant_in(
            &db,
            "g-skipped-pruned-session",
            "s-expired-25h",
            true,
            true,
            &old,
        )
        .await;

        let holder = "g-remembered-old";
        code(&db, "c-unused-expired-61m", holder, &t(-mins(61)), None).await;
        code(&db, "c-unused-expired-59m", holder, &t(-mins(59)), None).await;
        let used = t(-mins(65));
        code(
            &db,
            "c-used-expired-61m",
            holder,
            &t(-mins(61)),
            Some(&used),
        )
        .await;
        code(
            &db,
            "c-used-expired-59m",
            holder,
            &t(-mins(59)),
            Some(&used),
        )
        .await;
        code(&db, "c-unused-live", holder, &t(mins(5)), None).await;

        refresh(&db, "r-unused-expired", holder, &t(-mins(1)), None).await;
        refresh(&db, "r-unused-live", holder, &t(days(20)), None).await;
        let (six, eight) = (t(-days(6)), t(-days(8)));
        refresh(&db, "r-used-6d", holder, &t(days(20)), Some(&six)).await;
        refresh(&db, "r-used-8d", holder, &t(days(20)), Some(&eight)).await;
        refresh(&db, "r-used-6d-expired", holder, &t(-days(1)), Some(&six)).await;
        refresh(&db, "r-live", "g-once-live-refresh", &t(days(20)), None).await;
        refresh(
            &db,
            "r-grant-used-6d",
            "g-skipped-used-refresh",
            &t(days(20)),
            Some(&six),
        )
        .await;
        refresh(
            &db,
            "r-grant-expired",
            "g-once-expired-refresh",
            &t(-days(10)),
            None,
        )
        .await;

        for (jti, expires_at) in [
            ("j-expired-61m", t(-mins(61))),
            ("j-expired-59m", t(-mins(59))),
            ("j-live", t(mins(5))),
        ] {
            exec(
                &db,
                format!(
                    "INSERT INTO oauth_revoked_tokens (jti, expires_at) \
                     VALUES ('{jti}', '{expires_at}')"
                ),
            )
            .await;
        }

        for (hash, status, expires_at) in [
            ("d-expired-25h", "approved", t(-hours(25))),
            ("d-expired-23h", "pending", t(-hours(23))),
            ("d-live", "pending", t(mins(5))),
        ] {
            exec(
                &db,
                format!(
                    "INSERT INTO oauth_device_codes (device_code_hash, user_code, client_id, \
                     scope, status, interval_secs, created_at, expires_at) \
                     VALUES ('{hash}', '{hash}-u', 'c', '[]', '{status}', 5, '{expires_at}', \
                     '{expires_at}')"
                ),
            )
            .await;
        }

        for (id, accepted_at, expires_at) in [
            ("l-expired-25h", None, t(-hours(25))),
            ("l-accepted-expired-25h", Some(t(-hours(26))), t(-hours(25))),
            ("l-expired-23h", None, t(-hours(23))),
            ("l-live", None, t(mins(30))),
        ] {
            exec(
                &db,
                format!(
                    "INSERT INTO oauth_logout_requests (id, challenge_hash, sid, subject, \
                     accepted_at, created_at, expires_at) \
                     VALUES ('{id}', '{id}-h', 's', 'sub', {}, '{expires_at}', '{expires_at}')",
                    sql_opt(accepted_at.as_deref())
                ),
            )
            .await;
        }

        signing_key(&db, "k-active", "active", &t(-days(400)), None).await;
        signing_key(
            &db,
            "k-retired",
            "retired",
            &t(-days(800)),
            Some(&t(-days(400))),
        )
        .await;

        assert_eq!(
            prune(&db, now).await.unwrap(),
            Pruned {
                flows: 1,
                sessions: 1,
                codes: 2,
                refresh_tokens: 3,
                grants: 4,
                revoked_tokens: 1,
                device_codes: 1,
                logout_requests: 2,
            }
        );
        assert_eq!(
            ids(&db, "oauth_logout_requests", "id").await,
            ["l-expired-23h", "l-live"]
        );
        assert_eq!(
            ids(&db, "oauth_revoked_tokens", "jti").await,
            ["j-expired-59m", "j-live"]
        );
        assert_eq!(
            ids(&db, "oauth_device_codes", "device_code_hash").await,
            ["d-expired-23h", "d-live"]
        );

        assert_eq!(
            ids(&db, "oauth_authorize_requests", "id").await,
            ["f-expired-23h", "f-live"]
        );
        assert_eq!(
            ids(&db, "oauth_login_sessions", "sid").await,
            ["s-expired-23h", "s-live"]
        );
        assert_eq!(
            ids(&db, "oauth_authorization_codes", "code_hash").await,
            [
                "c-unused-expired-59m",
                "c-unused-live",
                "c-used-expired-59m"
            ]
        );
        assert_eq!(
            ids(&db, "oauth_refresh_tokens", "id").await,
            [
                "r-grant-used-6d",
                "r-live",
                "r-unused-live",
                "r-used-6d",
                "r-used-6d-expired"
            ]
        );
        assert_eq!(
            ids(&db, "oauth_consent_grants", "id").await,
            [
                "g-once-live-refresh",
                "g-once-live-session",
                "g-once-young",
                "g-remembered-old",
                "g-skipped-live-session",
                "g-skipped-unpruned-session",
                "g-skipped-used-refresh",
                "g-skipped-young"
            ]
        );
        assert_eq!(
            ids(&db, "oauth_signing_keys", "kid").await,
            ["k-active", "k-retired"]
        );

        assert_eq!(prune(&db, now).await.unwrap(), Pruned::default());
    }
}
