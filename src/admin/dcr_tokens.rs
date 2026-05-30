//! `/admin/dcr-tokens/*` — Initial Access Tokens (IATs) for Forseti's
//! Dynamic Client Registration proxy.
//!
//! Operators issue, list, and revoke tokens here. Issued tokens are
//! revealed exactly once via the same `SecretReveal` flash mechanism
//! used by client-secret rotation — the raw token is never persisted,
//! only `sha256(token)`.
//!
//! Validation of inbound tokens (at `POST /oauth2/register`) lives in
//! `src/oauth/register.rs`; this module is the lifecycle surface.
//!
//! ## Scope
//!
//! This surface is **Forseti-tier only** — it does NOT honour the
//! `?org=<slug>` org-scoping convention used by the rest of `/admin/*`.
//! The underlying `dcr_initial_access_tokens` table has no `org_id`
//! column (see `migrations/sqlite/20260517000000_initial_schema`),
//! so an IAT can mint a client into any org based on the
//! `org` query param passed at `/oauth2/register` time. Restricting
//! issuance per-org would require an `org_id` column + scope-aware
//! validation in the DCR endpoint; intentionally deferred.
//!
//! Practical consequence: only admins whose email appears on
//! `admin.allowed_emails` can reach `/admin/dcr-tokens/*`. Org owners
//! who land here via `?org=<slug>` get a 403 from `require_admin`.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use rand::Rng;
use serde::Deserialize;
use uuid::Uuid;

use crate::admin::{render_admin_error, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::db_interact;
use crate::extractors::{Csrf, RequireAdmin};
use crate::flash::{self, SecretReveal};
use crate::format::humanise_timestamp;
use crate::oauth::register::hash_token;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::schema::dcr_initial_access_tokens as iat;
use crate::state::AppState;

// --- View models -----------------------------------------------------------

/// One row on the IAT list page. Status is derived in the projection
/// (revoked > expired > exhausted > active) so the template doesn't
/// have to re-implement the ordering.
struct IatRow {
    id: String,
    created_by: String,
    created_at: String,
    created_at_pretty: String,
    expires_at: String,
    expires_at_pretty: String,
    uses_remaining: String,
    note: String,
    /// One of "active", "revoked", "expired", "exhausted". Drives the
    /// badge colour + the visibility of the revoke button.
    status: &'static str,
}

/// Canonical row for `dcr_initial_access_tokens`. Defined here because this
/// `pub mod` is reachable from `oauth::register::iat` (which the admin can't
/// reach the other way — its `iat` submodule is private), so the proxy
/// re-uses this exact struct as its `IatRow`. One `Selectable` derive ties
/// both readers to the schema: a column rename/removal breaks both at
/// compile time. The admin list ignores the two daily-counter columns.
#[allow(dead_code)] // some columns are only field-accessed by the proxy
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = iat)]
pub(crate) struct StoredIat {
    pub(crate) id: String,
    pub(crate) token_hash: String,
    pub(crate) created_by: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) uses_remaining: Option<i32>,
    pub(crate) revoked_at: Option<String>,
    pub(crate) note: String,
    pub(crate) daily_use_count: i32,
    pub(crate) daily_window_started_at: Option<String>,
}

fn project_row(s: StoredIat) -> IatRow {
    let now = Utc::now().to_rfc3339();
    let status = if s.revoked_at.is_some() {
        "revoked"
    } else if s
        .expires_at
        .as_deref()
        .map(|e| e <= now.as_str())
        .unwrap_or(false)
    {
        "expired"
    } else if matches!(s.uses_remaining, Some(n) if n <= 0) {
        "exhausted"
    } else {
        "active"
    };
    let expires_at = s.expires_at.clone().unwrap_or_default();
    let expires_at_pretty = if expires_at.is_empty() {
        "never".to_string()
    } else {
        humanise_timestamp(&expires_at)
    };
    let uses_remaining = match s.uses_remaining {
        Some(n) => n.to_string(),
        None => "unlimited".to_string(),
    };
    IatRow {
        id: s.id,
        created_by: s.created_by,
        created_at_pretty: humanise_timestamp(&s.created_at),
        created_at: s.created_at,
        expires_at,
        expires_at_pretty,
        uses_remaining,
        note: s.note,
        status,
    }
}

// --- Templates -------------------------------------------------------------

#[derive(askama::Template)]
#[template(path = "admin/dcr_tokens_list.html")]
struct DcrTokensListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<IatRow>,
    /// One-shot reveal of a freshly issued token. Read out of the
    /// `SecretReveal` flash store; `None` on plain refresh.
    revealed_token: Option<String>,
}

#[derive(askama::Template)]
#[template(path = "admin/dcr_token_new.html")]
struct DcrTokenNewTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    /// Inline error from the previous submission, if any.
    error_message: String,
    /// Echo the operator's input back so a validation failure doesn't
    /// wipe what they typed.
    note: String,
    ttl_hours: String,
    max_uses: String,
}

// --- Handlers --------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Opaque secret-reveal token from a redirect after issuing.
    #[serde(default)]
    reveal: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
    admin: RequireAdmin,
    csrf: Csrf,
) -> Response {
    let ctx = admin.ctx;

    let stored: anyhow::Result<Vec<StoredIat>> = async {
        let r = db_interact!(&state.db, |conn| {
            iat::table
                .order(iat::created_at.desc())
                .limit(100)
                .select(StoredIat::as_select())
                .load(conn)
        })?;
        Ok(r)
    }
    .await;
    let rows = match stored {
        Ok(s) => s.into_iter().map(project_row).collect(),
        Err(e) => {
            tracing::error!(error = ?e, "admin: list dcr tokens failed");
            return render_admin_error(
                &state,
                "DCR tokens unavailable",
                "We couldn't list initial access tokens. Please try again in a moment.",
            );
        }
    };

    let revealed_token = match query.reveal.as_deref().filter(|s| !s.is_empty()) {
        Some(token) => {
            match flash::take_secret_reveal(&state.db, state.cfg.flash.reveal_ttl_seconds, token)
                .await
            {
                Some(SecretReveal::DcrInitialAccessToken { token }) => {
                    Some(token).filter(|s| !s.is_empty())
                }
                _ => None,
            }
        }
        None => None,
    };

    let chrome = ctx.chrome(&csrf);
    render(&DcrTokensListTemplate {
        chrome,
        admin_active: AdminSection::DcrTokens,
        rows,
        revealed_token,
    })
}

pub async fn new(admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let chrome = ctx.chrome(&csrf);
    render(&DcrTokenNewTemplate {
        chrome,
        admin_active: AdminSection::DcrTokens,
        error_message: String::new(),
        note: String::new(),
        ttl_hours: String::new(),
        max_uses: String::new(),
    })
}

#[derive(Debug, Deserialize)]
pub struct IssueForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    note: String,
    /// Blank → no expiry. Otherwise parsed as i64 hours.
    #[serde(default)]
    ttl_hours: String,
    /// Blank → unlimited uses. Otherwise parsed as i32 (positive).
    #[serde(default)]
    max_uses: String,
}

pub async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    csrf: Csrf,
    Form(form): Form<IssueForm>,
) -> Response {
    let ctx = admin.ctx;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    let rerender = |error_message: String| -> Response {
        let chrome = ctx.chrome(&csrf);
        render(&DcrTokenNewTemplate {
            chrome,
            admin_active: AdminSection::DcrTokens,
            error_message,
            note: form.note.clone(),
            ttl_hours: form.ttl_hours.clone(),
            max_uses: form.max_uses.clone(),
        })
    };

    let ttl_hours: Option<i64> = match form.ttl_hours.trim() {
        "" => None,
        s => match s.parse::<i64>() {
            Ok(n) if n > 0 => Some(n),
            _ => {
                return rerender(
                    "TTL must be a positive number of hours, or blank for no expiry.".to_string(),
                )
            }
        },
    };
    let max_uses: Option<i32> = match form.max_uses.trim() {
        "" => None,
        s => match s.parse::<i32>() {
            Ok(n) if n > 0 => Some(n),
            _ => {
                return rerender(
                    "Max uses must be a positive integer, or blank for unlimited.".to_string(),
                )
            }
        },
    };

    let raw_token = generate_token();
    let token_hash = hash_token(&raw_token);
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = ttl_hours.map(|h| (now + Duration::hours(h)).to_rfc3339());
    let note = form.note.trim().to_string();

    let id_for_insert = id.clone();
    let token_hash_for_insert = token_hash;
    let created_by = ctx.email.clone();
    let created_at_for_insert = created_at;
    let expires_at_for_insert = expires_at.clone();
    let note_for_insert = note.clone();
    let insert_result: anyhow::Result<()> = async {
        db_interact!(&state.db, |conn| {
            diesel::insert_into(iat::table)
                .values((
                    iat::id.eq(id_for_insert),
                    iat::token_hash.eq(token_hash_for_insert),
                    iat::created_by.eq(created_by),
                    iat::created_at.eq(created_at_for_insert),
                    iat::expires_at.eq(expires_at_for_insert),
                    iat::uses_remaining.eq(max_uses),
                    iat::note.eq(note_for_insert),
                ))
                .execute(conn)
        })?;
        Ok(())
    }
    .await;
    if let Err(e) = insert_result {
        tracing::error!(error = ?e, "admin: dcr IAT insert failed");
        return rerender(format!("Failed to issue token: {e}"));
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::OAUTH_CLIENT_DCR_IAT_ISSUED)
            .actor_admin(&ctx.identity_id, &ctx.email)
            .target(target_kind::DCR_IAT, id)
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "expires_at" => expires_at.unwrap_or_default(),
                "max_uses" => max_uses.map(|n| n.to_string()).unwrap_or_else(|| "unlimited".to_string()),
                "note" => note,
            )),
    )
    .await;

    // Reuse the existing `SecretReveal` channel — same single-use,
    // server-side store, redirect carries only an opaque token in the URL.
    let reveal = SecretReveal::DcrInitialAccessToken { token: raw_token };
    let reveal_token =
        match flash::store_secret_reveal(&state.db, state.cfg.flash.reveal_ttl_seconds, reveal)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = ?e, "admin: dcr IAT reveal store failed");
                return render_admin_error(
                    &state,
                    "Issue failed",
                    "We issued the token but couldn't stage it for one-shot display. \
                 The token has been recorded in audit; revoke it and issue a fresh one.",
                );
            }
        };
    let url = format!(
        "/admin/dcr-tokens?reveal={}",
        ory_client::apis::urlencode(&reveal_token)
    );
    Redirect::to(&url).into_response()
}

pub async fn revoke_confirm(Path(id): Path<String>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::DcrTokens,
        title: format!("Revoke DCR token {id}?"),
        body: "After revocation this initial access token can no longer be used to register clients. Already-issued OAuth2 clients are unaffected — they continue to work.".to_string(),
        action_url: format!("/admin/dcr-tokens/{}/revoke", ory_client::apis::urlencode(&id)),
        cancel_url: "/admin/dcr-tokens".to_string(),
        submit_label: "Revoke token",
    })
}

pub async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let ctx = admin.ctx;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    if !form.confirmed() {
        return Redirect::to("/admin/dcr-tokens").into_response();
    }

    let now = Utc::now().to_rfc3339();
    let id_for_update = id.clone();
    let update_result: anyhow::Result<usize> = async {
        let n = db_interact!(&state.db, |conn| {
            diesel::update(
                iat::table
                    .filter(iat::id.eq(id_for_update))
                    .filter(iat::revoked_at.is_null()),
            )
            .set(iat::revoked_at.eq(now))
            .execute(conn)
        })?;
        Ok(n)
    }
    .await;
    match update_result {
        Ok(0) => Redirect::to("/admin/dcr-tokens").into_response(),
        Ok(_) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::OAUTH_CLIENT_DCR_IAT_REVOKED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::DCR_IAT, id)
                    .with_ctx(&actx)
                    .critical(),
            )
            .await;
            Redirect::to("/admin/dcr-tokens").into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, "admin: revoke dcr iat failed");
            render_admin_error(
                &state,
                "Revoke failed",
                &format!("Could not revoke token: {e}"),
            )
        }
    }
}

/// 32 random bytes from `OsRng`, base64url-encoded with no padding.
/// Roughly 256 bits of entropy — comfortably beyond what a "bearer
/// token used once at the moment of client registration" needs.
fn generate_token() -> String {
    // `rand::rng()` is ThreadRng, which is seeded from the OS RNG and
    // reseeds periodically — fine for token generation. We don't need
    // `OsRng` directly here; the rest of the codebase uses the same
    // ThreadRng for client secrets and CSRF tokens.
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}
