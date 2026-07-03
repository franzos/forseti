//! Diesel queries for the `org_logos` blob table, plus the public serve route.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_method;
use axum::Router;
use chrono::Utc;
use diesel::prelude::*;
use sha2::{Digest, Sha256};

use crate::config::{OrgsConfig, ProxyConfig};
use crate::db::DbPool;
use crate::db_interact;
use crate::extractors::OptionalSession;
use crate::logo_cache::CachedLogo;
use crate::rate_limit;
use crate::schema::{org_logos, organizations};
use crate::state::AppState;

#[allow(dead_code)]
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = org_logos)]
pub struct LogoRow {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub etag: String,
}

#[derive(Insertable)]
#[diesel(table_name = org_logos)]
struct NewLogo<'a> {
    org_id: &'a str,
    bytes: &'a [u8],
    content_type: &'a str,
    etag: &'a str,
    updated_at: String,
}

pub fn etag_of(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::digest(bytes)))
}

// One transaction so has_logo never diverges from the row.
pub async fn upsert(
    db: &DbPool,
    org_id: &str,
    bytes: Vec<u8>,
    content_type: &str,
    etag: &str,
) -> anyhow::Result<()> {
    let org_id = org_id.to_string();
    let content_type = content_type.to_string();
    let etag = etag.to_string();
    let updated_at = Utc::now().to_rfc3339();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            use diesel::upsert::excluded;
            diesel::insert_into(org_logos::table)
                .values(NewLogo {
                    org_id: &org_id,
                    bytes: &bytes,
                    content_type: &content_type,
                    etag: &etag,
                    updated_at: updated_at.clone(),
                })
                .on_conflict(org_logos::org_id)
                .do_update()
                .set((
                    org_logos::bytes.eq(excluded(org_logos::bytes)),
                    org_logos::content_type.eq(excluded(org_logos::content_type)),
                    org_logos::etag.eq(excluded(org_logos::etag)),
                    org_logos::updated_at.eq(excluded(org_logos::updated_at)),
                ))
                .execute(c)?;
            diesel::update(organizations::table.filter(organizations::id.eq(&org_id)))
                .set(organizations::has_logo.eq(1))
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

/// Delete the logo blob and flip `has_logo = 0`, in one transaction.
pub async fn delete(db: &DbPool, org_id: &str) -> anyhow::Result<()> {
    let org_id = org_id.to_string();
    db_interact!(db, |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|c| {
            diesel::delete(org_logos::table.filter(org_logos::org_id.eq(&org_id))).execute(c)?;
            diesel::update(organizations::table.filter(organizations::id.eq(&org_id)))
                .set(organizations::has_logo.eq(0))
                .execute(c)?;
            Ok(())
        })
    })?;
    Ok(())
}

pub async fn get(db: &DbPool, org_id: &str) -> anyhow::Result<Option<LogoRow>> {
    let org_id = org_id.to_string();
    let row: Option<LogoRow> = db_interact!(db, |conn| {
        org_logos::table
            .filter(org_logos::org_id.eq(&org_id))
            .select(LogoRow::as_select())
            .first(conn)
            .optional()
    })?;
    Ok(row)
}

const DEFAULT_LOGO_IP_RATE_PER_MINUTE: u32 = 60;
const DEFAULT_LOGO_IP_RATE_PER_HOUR: u32 = 600;

pub(crate) enum ServeOutcome {
    NotFound,
    ServePublic,
    ServePrivate,
}

// Every "no access" combination collapses into NotFound so the route can't distinguish slug, gate, or logo presence.
pub(crate) fn serve_decision(public: bool, is_member: bool, has_logo: bool) -> ServeOutcome {
    if !has_logo || !(public || is_member) {
        ServeOutcome::NotFound
    } else if public {
        ServeOutcome::ServePublic
    } else {
        ServeOutcome::ServePrivate
    }
}

fn shared_not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

pub(crate) async fn serve(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    session: OptionalSession,
) -> Response {
    let org = match crate::orgs::org_by_slug(&state.db, &slug).await {
        Ok(Some(org)) => org,
        Ok(None) => return shared_not_found(),
        Err(e) => {
            tracing::warn!(error = ?e, slug, "logo::serve: org_by_slug failed");
            return shared_not_found();
        }
    };

    let public = org.public_login_enabled == 1;
    let is_member = match session.identity_id() {
        Some(identity_id) => crate::orgs::is_member(&state.db, identity_id, &org.id).await,
        None => false,
    };
    if !public && !is_member {
        return shared_not_found();
    }

    let cached = state.logo_cache.lock().await.get(&org.id);
    let logo = match cached {
        Some(logo) => logo,
        None => match get(&state.db, &org.id).await {
            Ok(Some(row)) => {
                let logo = CachedLogo {
                    etag: row.etag,
                    content_type: row.content_type,
                    bytes: Arc::new(row.bytes),
                };
                state
                    .logo_cache
                    .lock()
                    .await
                    .insert(org.id.clone(), logo.clone());
                logo
            }
            Ok(None) => return shared_not_found(),
            Err(e) => {
                tracing::warn!(error = ?e, org_id = %org.id, "logo::serve: get failed");
                return shared_not_found();
            }
        },
    };

    let cache_control = match serve_decision(public, is_member, true) {
        ServeOutcome::ServePublic => "public, max-age=3600",
        _ => "private, no-store",
    };

    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if inm.as_bytes() == logo.etag.as_bytes() {
            let mut builder = Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, logo.etag.clone())
                .header(header::CACHE_CONTROL, cache_control);
            if !public {
                builder = builder.header(header::VARY, "Cookie");
            }
            return builder
                .body(axum::body::Body::empty())
                .expect("logo 304 response is well-formed");
        }
    }

    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, logo.content_type.clone())
        .header(header::ETAG, logo.etag.clone())
        .header("x-content-type-options", "nosniff")
        .header(header::CACHE_CONTROL, cache_control);
    if !public {
        builder = builder.header(header::VARY, "Cookie");
    }
    builder
        .body(axum::body::Body::from((*logo.bytes).clone()))
        .expect("logo response is well-formed")
}

pub(crate) fn router(orgs_cfg: &OrgsConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    let r = Router::new().route("/branding/{slug}/logo", get_method(serve));

    let per_minute = orgs_cfg
        .logo_ip_rate_per_minute
        .unwrap_or(DEFAULT_LOGO_IP_RATE_PER_MINUTE);
    let per_hour = orgs_cfg
        .logo_ip_rate_per_hour
        .unwrap_or(DEFAULT_LOGO_IP_RATE_PER_HOUR);

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
    use crate::orgs::db::create_org;

    #[tokio::test]
    async fn upsert_get_delete_round_trip() {
        let db = crate::orgs::db::test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None)
            .await
            .expect("create_org");

        let bytes = b"fake-png-bytes".to_vec();
        let etag = etag_of(&bytes);
        upsert(&db, "o1", bytes.clone(), "image/png", &etag)
            .await
            .expect("upsert");

        let row = get(&db, "o1")
            .await
            .expect("get")
            .expect("row should exist after upsert");
        assert_eq!(row.bytes, bytes);
        assert_eq!(row.content_type, "image/png");
        assert_eq!(row.etag, etag);

        let org = crate::orgs::db::org_by_id(&db, "o1")
            .await
            .expect("org_by_id")
            .expect("org should exist");
        assert_eq!(org.has_logo, 1);

        delete(&db, "o1").await.expect("delete");
        assert!(get(&db, "o1").await.expect("get after delete").is_none());

        let org = crate::orgs::db::org_by_id(&db, "o1")
            .await
            .expect("org_by_id")
            .expect("org should exist");
        assert_eq!(org.has_logo, 0);
    }

    // --- serve_decision ----------------------------------------------------

    fn outcome_name(o: &ServeOutcome) -> &'static str {
        match o {
            ServeOutcome::NotFound => "not_found",
            ServeOutcome::ServePublic => "serve_public",
            ServeOutcome::ServePrivate => "serve_private",
        }
    }

    #[test]
    fn not_public_not_member_is_not_found_regardless_of_logo() {
        assert_eq!(
            outcome_name(&serve_decision(false, false, true)),
            "not_found"
        );
        assert_eq!(
            outcome_name(&serve_decision(false, false, false)),
            "not_found"
        );
    }

    #[test]
    fn gated_in_without_logo_is_not_found() {
        assert_eq!(
            outcome_name(&serve_decision(true, false, false)),
            "not_found"
        );
        assert_eq!(
            outcome_name(&serve_decision(false, true, false)),
            "not_found"
        );
        assert_eq!(
            outcome_name(&serve_decision(true, true, false)),
            "not_found"
        );
    }

    #[test]
    fn public_org_with_logo_serves_public() {
        assert_eq!(
            outcome_name(&serve_decision(true, false, true)),
            "serve_public"
        );
        assert_eq!(
            outcome_name(&serve_decision(true, true, true)),
            "serve_public"
        );
    }

    #[test]
    fn member_only_org_with_logo_serves_private() {
        assert_eq!(
            outcome_name(&serve_decision(false, true, true)),
            "serve_private"
        );
    }
}
