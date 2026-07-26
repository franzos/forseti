//! Diesel queries for the `client_logos` blob table, plus the serve route.
//!
//! An OAuth2 client's logo is uploaded by whoever administers the client
//! (`/admin/clients/{id}/logo`) and shown on the consent screen, so the
//! image the user sees is vouched for by the operator. The client-supplied
//! `logo_uri` is deliberately not used here: rendering a remote URL would
//! leak every consenting user's IP and user-agent to the relying party
//! before they've agreed to anything.
//!
//! Unlike `org_logos` there's no `has_logo` companion flag — this table is
//! the single source of truth, so nothing can diverge from it, and a legacy
//! client with no `oauth_client_metadata` row can still carry a logo.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_method;
use axum::Router;
use chrono::Utc;
use diesel::prelude::*;

use crate::config::{OrgsConfig, ProxyConfig};
use crate::db::DbPool;
use crate::db_interact;
use crate::extractors::OptionalSession;
use crate::logo_cache::CachedLogo;
use crate::rate_limit;
use crate::schema::client_logos;
use crate::state::AppState;

#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = client_logos)]
pub struct LogoRow {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub etag: String,
}

#[derive(Insertable)]
#[diesel(table_name = client_logos)]
struct NewLogo<'a> {
    client_id: &'a str,
    bytes: &'a [u8],
    content_type: &'a str,
    etag: &'a str,
    updated_at: String,
}

pub async fn upsert(
    db: &DbPool,
    client_id: &str,
    bytes: Vec<u8>,
    content_type: &str,
    etag: &str,
) -> anyhow::Result<()> {
    let client_id = client_id.to_string();
    let content_type = content_type.to_string();
    let etag = etag.to_string();
    let updated_at = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        use diesel::upsert::excluded;
        diesel::insert_into(client_logos::table)
            .values(NewLogo {
                client_id: &client_id,
                bytes: &bytes,
                content_type: &content_type,
                etag: &etag,
                updated_at: updated_at.clone(),
            })
            .on_conflict(client_logos::client_id)
            .do_update()
            .set((
                client_logos::bytes.eq(excluded(client_logos::bytes)),
                client_logos::content_type.eq(excluded(client_logos::content_type)),
                client_logos::etag.eq(excluded(client_logos::etag)),
                client_logos::updated_at.eq(excluded(client_logos::updated_at)),
            ))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn delete(db: &DbPool, client_id: &str) -> anyhow::Result<()> {
    let client_id = client_id.to_string();
    db_interact!(db, |conn| {
        diesel::delete(client_logos::table.filter(client_logos::client_id.eq(&client_id)))
            .execute(conn)
            .map(|_| ())
    })?;
    Ok(())
}

pub async fn get(db: &DbPool, client_id: &str) -> anyhow::Result<Option<LogoRow>> {
    let client_id = client_id.to_string();
    let row: Option<LogoRow> = db_interact!(db, |conn| {
        client_logos::table
            .filter(client_logos::client_id.eq(&client_id))
            .select(LogoRow::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

/// Existence probe for the render paths (consent screen, admin show page).
/// Selects the key only, so a 256 KB blob never crosses the wire just to
/// decide whether to emit an `<img>`.
pub async fn exists(db: &DbPool, client_id: &str) -> anyhow::Result<bool> {
    let client_id = client_id.to_string();
    let hit: Option<String> = db_interact!(db, |conn| {
        client_logos::table
            .filter(client_logos::client_id.eq(&client_id))
            .select(client_logos::client_id)
            .first(conn)
            .optional()
    })?;
    Ok(hit.is_some())
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Anything but "no session at all" may fetch. `InsufficientAal` counts: the
/// caller proved a session, and refusing would leave a broken image on a
/// step-up screen.
fn session_may_fetch(session: &OptionalSession) -> bool {
    !matches!(session, OptionalSession::None)
}

/// `GET /clients/{client_id}/logo`.
///
/// Gated on any resolvable session — the consent screen is post-login, so
/// this costs real users nothing, and it keeps the route from answering
/// "does client X exist?" for anonymous callers. `InsufficientAal` counts:
/// the caller still proved a session, and rejecting it would leave a broken
/// image on a step-up screen.
pub(crate) async fn serve(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    session: OptionalSession,
) -> Response {
    if !session_may_fetch(&session) {
        return not_found();
    }

    let cache_key = crate::logo_cache::client_key(&client_id);
    let cached = state.logo_cache.lock().await.get(&cache_key);
    let logo = match cached {
        Some(logo) => logo,
        None => match get(&state.db, &client_id).await {
            Ok(Some(row)) => {
                let logo = Arc::new(CachedLogo {
                    etag: row.etag,
                    content_type: row.content_type,
                    bytes: axum::body::Bytes::from(row.bytes),
                });
                state
                    .logo_cache
                    .lock()
                    .await
                    .insert(cache_key, Arc::clone(&logo));
                logo
            }
            Ok(None) => return not_found(),
            Err(e) => {
                tracing::warn!(error = ?e, client_id, "client_logo::serve: get failed");
                return not_found();
            }
        },
    };

    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if inm.as_bytes() == logo.etag.as_bytes() {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, logo.etag.as_str())
                .header(header::CACHE_CONTROL, "private, max-age=300")
                .header(header::VARY, "Cookie")
                .body(axum::body::Body::empty())
                .expect("client logo 304 response is well-formed");
        }
    }

    Response::builder()
        .header(header::CONTENT_TYPE, logo.content_type.as_str())
        .header(header::ETAG, logo.etag.as_str())
        .header("x-content-type-options", "nosniff")
        .header(header::CACHE_CONTROL, "private, max-age=300")
        .header(header::VARY, "Cookie")
        .body(axum::body::Body::from(logo.bytes.clone()))
        .expect("client logo response is well-formed")
}

/// Shares the org-logo rate-limit knobs: same class of route (a blob served
/// per page render), so a second pair of config keys would only be noise.
pub(crate) fn router(orgs_cfg: &OrgsConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    let r = Router::new().route("/clients/{client_id}/logo", get_method(serve));

    let per_minute = orgs_cfg.logo_ip_rate_per_minute.unwrap_or(60);
    let per_hour = orgs_cfg.logo_ip_rate_per_hour.unwrap_or(600);

    rate_limit::dual_window(
        r,
        proxy_cfg.trust_forwarded_for,
        per_minute,
        per_hour,
        rate_limit::plain_text_error("logo"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upsert_get_exists_delete_round_trip() {
        let db = crate::orgs::db::test_pool().await;

        assert!(!exists(&db, "c1").await.expect("exists"));

        let bytes = b"fake-png-bytes".to_vec();
        let etag = crate::orgs::logo::etag_of(&bytes);
        upsert(&db, "c1", bytes.clone(), "image/png", &etag)
            .await
            .expect("upsert");

        let row = get(&db, "c1")
            .await
            .expect("get")
            .expect("row should exist after upsert");
        assert_eq!(row.bytes, bytes);
        assert_eq!(row.content_type, "image/png");
        assert_eq!(row.etag, etag);
        assert!(exists(&db, "c1").await.expect("exists"));

        let replacement = b"other-bytes".to_vec();
        let etag2 = crate::orgs::logo::etag_of(&replacement);
        upsert(&db, "c1", replacement.clone(), "image/webp", &etag2)
            .await
            .expect("re-upsert");
        let row = get(&db, "c1").await.expect("get").expect("row");
        assert_eq!(row.bytes, replacement);
        assert_eq!(row.content_type, "image/webp");

        delete(&db, "c1").await.expect("delete");
        assert!(get(&db, "c1").await.expect("get after delete").is_none());
        assert!(!exists(&db, "c1").await.expect("exists after delete"));
    }

    #[tokio::test]
    async fn delete_is_idempotent_for_unknown_client() {
        let db = crate::orgs::db::test_pool().await;
        delete(&db, "nope").await.expect("delete unknown");
    }

    #[test]
    fn anonymous_callers_are_refused() {
        assert!(!session_may_fetch(&OptionalSession::None));
        assert!(session_may_fetch(&OptionalSession::InsufficientAal));
    }
}
