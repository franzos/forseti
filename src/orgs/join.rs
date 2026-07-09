//! External self-serve join: signup-org resolution and the explicit
//! CSRF-confirmed `/join/confirm` handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::csrf::CsrfForm;
use crate::db::DbPool;
use crate::extractors::{Csrf, OptionalSession};
use crate::orgs::db::Org;
use crate::orgs::{self, parse_access_mode, Role};
use crate::ory;
use crate::page_chrome::{PageChrome, ReqLocale};
use crate::render::render;
use crate::state::AppState;
use crate::theming;

/// Resolve `landing_slug` to an org eligible for external self-serve signup:
/// exists, is `external`, and `public_login_enabled=1`. Re-read at call time.
pub(crate) async fn resolve_signup_org(db: &DbPool, landing_slug: &str) -> Option<Org> {
    let org = crate::orgs::db::org_by_slug(db, landing_slug)
        .await
        .ok()
        .flatten()?;
    if !parse_access_mode(&org.access_mode).is_external() {
        return None;
    }
    if org.public_login_enabled != 1 {
        return None;
    }
    Some(org)
}

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/join/confirm",
        get(join_confirm_get).post(join_confirm_post),
    )
}

#[derive(Debug, Deserialize)]
struct JoinConfirmQuery {
    org: Option<String>,
}

#[derive(Template)]
#[template(path = "orgs/join_confirm.html")]
struct JoinConfirmTemplate {
    chrome: PageChrome,
    org_name: String,
    org_slug: String,
    /// `true` renders the CSRF-protected POST form; `false` renders an `<a>`
    /// CTA into Kratos registration (anonymous branch).
    can_join_now: bool,
    register_url: String,
}

/// Theme the chrome from `org`'s branding (colors only, no tenant logo — the
/// page renders before the caller is confirmed a member).
fn themed_chrome(state: &AppState, org: &Org, chrome: PageChrome) -> PageChrome {
    chrome.with_theme(theming::resolve(
        &theming::overrides_from_org(org),
        &theming::global_overrides(&state.cfg.brand),
    ))
}

/// `GET /join/confirm?org=<slug>`: idempotent confirmation page only; the
/// membership write is gated behind the POST handler so it's CSRF-protected.
///
/// 1. Unknown/internal/disabled slug -> 404 (anti-enumeration, like `/o/{slug}`).
/// 2. Anonymous -> CTA into Kratos registration, `return_to=/join/confirm?org=<slug>`.
/// 3. Signed in + already a member -> redirect `/`.
/// 4. Signed in + not a member -> CSRF-protected confirm form.
async fn join_confirm_get(
    State(state): State<AppState>,
    Query(q): Query<JoinConfirmQuery>,
    Csrf(csrf_token): Csrf,
    session: OptionalSession,
    ReqLocale(locale): ReqLocale,
) -> Response {
    let Some(slug) = q.org.filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, "missing org").into_response();
    };
    let Some(org) = resolve_signup_org(&state.db, &slug).await else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };

    let session = match session {
        OptionalSession::Ok { session, .. } => Some(*session),
        _ => None,
    };

    let Some(session) = session else {
        let return_to = format!(
            "{}/join/confirm?org={}",
            state.cfg.self_.url.trim_end_matches('/'),
            ory_client::apis::urlencode(&slug)
        );
        let register_url = ory::kratos::browser_init_url(
            ory::FlowKind::Registration,
            &state.cfg.kratos.public_url,
            Some(&return_to),
        );
        return render(&JoinConfirmTemplate {
            chrome: themed_chrome(
                &state,
                &org,
                PageChrome::from_parts(&state, String::new(), csrf_token, locale),
            ),
            org_name: org.name.clone(),
            org_slug: slug,
            can_join_now: false,
            register_url,
        });
    };

    let (identity_id, session_email) = crate::flow_view::session_principal(&session);
    if orgs::org_role(&state.db, &identity_id, &org.id)
        .await
        .is_some()
    {
        return Redirect::to("/").into_response();
    }

    render(&JoinConfirmTemplate {
        chrome: themed_chrome(
            &state,
            &org,
            PageChrome::from_parts(&state, session_email, csrf_token, locale),
        ),
        org_name: org.name.clone(),
        org_slug: slug,
        can_join_now: true,
        register_url: String::new(),
    })
}

#[derive(Debug, Deserialize)]
struct JoinConfirmForm {
    org: String,
}

/// `POST /join/confirm` — explicit confirmation of a self-serve join.
/// Validates CSRF, re-resolves the org (TOCTOU-safe against a mode/toggle
/// flip between GET and POST), then writes the membership row. No
/// verification gate: join happens immediately on explicit confirm, matching
/// today's Default auto-join.
async fn join_confirm_post(
    State(state): State<AppState>,
    actx: AuditCtx,
    session: OptionalSession,
    CsrfForm(form): CsrfForm<JoinConfirmForm>,
) -> Response {
    if form.org.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing org").into_response();
    }
    let Some(org) = resolve_signup_org(&state.db, &form.org).await else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let session = match session {
        OptionalSession::Ok { session, .. } => *session,
        _ => {
            return Redirect::to(&format!(
                "/join/confirm?org={}",
                ory_client::apis::urlencode(&form.org)
            ))
            .into_response();
        }
    };
    let (identity_id, session_email) = crate::flow_view::session_principal(&session);
    if orgs::org_role(&state.db, &identity_id, &org.id)
        .await
        .is_some()
    {
        return Redirect::to("/").into_response();
    }

    let drop_default = !state.cfg.admin.is_admin(&session_email);
    if let Err(e) = crate::orgs::db::join_org_race_safe(
        &state.db,
        &identity_id,
        &org.id,
        Role::Member,
        drop_default,
    )
    .await
    {
        tracing::error!(error = ?e, org_id = %org.id, "join_confirm_post: join_org_race_safe failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not join").into_response();
    }
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_MEMBER_ADDED)
            .actor_user(&identity_id, &session_email)
            .target(target_kind::IDENTITY, identity_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "org_id" => &org.id,
                "role" => Role::Member.as_str(),
                "via" => "self_serve",
            )),
    )
    .await;
    Redirect::to("/").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdminConfig;
    use crate::orgs::db::{
        add_member_race_safe, create_org, join_org_race_safe, set_access_mode, test_pool,
        update_theme,
    };
    use crate::orgs::{AccessMode, DEFAULT_ORG_ID};

    #[tokio::test]
    async fn resolves_external_enabled_org() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None).await.unwrap();
        set_access_mode(&db, "o1", AccessMode::External)
            .await
            .unwrap();
        update_theme(&db, "o1", None, None, None, None, 1)
            .await
            .unwrap();
        assert_eq!(
            resolve_signup_org(&db, "acme").await.map(|o| o.id),
            Some("o1".to_string())
        );
    }

    #[tokio::test]
    async fn rejects_internal_org() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None).await.unwrap();
        update_theme(&db, "o1", None, None, None, None, 1)
            .await
            .unwrap();
        assert!(resolve_signup_org(&db, "acme").await.is_none());
    }

    #[tokio::test]
    async fn rejects_disabled_org() {
        let db = test_pool().await;
        create_org(&db, "o1", "acme", "Acme", None).await.unwrap();
        set_access_mode(&db, "o1", AccessMode::External)
            .await
            .unwrap();
        assert!(resolve_signup_org(&db, "acme").await.is_none());
    }

    #[tokio::test]
    async fn rejects_unknown_slug() {
        let db = test_pool().await;
        assert!(resolve_signup_org(&db, "nope").await.is_none());
    }

    // Mirrors `join_confirm_post`'s wiring: drop_default = !is_admin(email).
    #[tokio::test]
    async fn self_serve_join_drops_default_for_non_allowlisted() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Member)
            .await
            .unwrap();
        let admin = AdminConfig::default();
        let drop_default = !admin.is_admin("user@example.com");
        join_org_race_safe(&db, "ident-1", "acme-id", Role::Member, drop_default)
            .await
            .unwrap();
        assert_eq!(
            orgs::org_role(&db, "ident-1", "acme-id").await,
            Some(Role::Member)
        );
        assert!(orgs::org_role(&db, "ident-1", DEFAULT_ORG_ID)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn self_serve_join_keeps_default_for_allowlisted() {
        let db = test_pool().await;
        create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        add_member_race_safe(&db, "op-1", DEFAULT_ORG_ID, Role::Owner)
            .await
            .unwrap();
        let admin = AdminConfig {
            allowed_emails: vec!["op@example.com".to_string()],
        };
        let drop_default = !admin.is_admin("op@example.com");
        join_org_race_safe(&db, "op-1", "acme-id", Role::Member, drop_default)
            .await
            .unwrap();
        assert_eq!(
            orgs::org_role(&db, "op-1", DEFAULT_ORG_ID).await,
            Some(Role::Owner)
        );
        assert_eq!(
            orgs::org_role(&db, "op-1", "acme-id").await,
            Some(Role::Member)
        );
    }
}
