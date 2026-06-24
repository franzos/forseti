//! `/admin/hosts/*` — enrollment of Linux hosts that consume Forseti's
//! POSIX/NSS resolver.
//!
//! Operators enroll a host (minting a one-shot secret), revoke it, and
//! rotate its secret here. The raw secret is revealed exactly once via the
//! same `SecretReveal` flash mechanism the DCR-token surface uses — only
//! `sha256(secret)` is persisted (see [`crate::oauth::register::hash_token`]).
//!
//! ## Scope
//!
//! This surface is **Forseti-tier only** — an operator concern, not an
//! org-owner one. It uses [`RequireAdmin`] (session + AAL2 +
//! `[admin].allowed_emails`) and does NOT honour the `?org=<slug>`
//! org-scoping convention used by the rest of `/admin/*`. Org owners who
//! land here via `?org=<slug>` get a 403 from `require_admin`.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use serde::Deserialize;
use uuid::Uuid;

use crate::admin::{render_admin_error, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent, SafeMetadata};
use crate::audit_metadata;
use crate::extractors::{Csrf, RequireAdmin};
use crate::flash::{self, SecretReveal};
use crate::format::humanise_timestamp;
use crate::oauth::register::hash_token;
use crate::page_chrome::PageChrome;
use crate::posix::db as posix_db;
use crate::render::render;
use crate::state::AppState;

// --- View models -----------------------------------------------------------

struct HostRow {
    id: String,
    hostname: String,
    allowed_gid: String,
    force_mfa: bool,
    created_at: String,
    created_at_pretty: String,
    last_seen_pretty: String,
}

fn project_row(r: posix_db::HostListRow) -> HostRow {
    let allowed_gid = match r.allowed_gid {
        Some(g) => g.to_string(),
        None => "any".to_string(),
    };
    let last_seen_pretty = match r.last_seen_at.as_deref().filter(|s| !s.is_empty()) {
        Some(ts) => humanise_timestamp(ts),
        None => "never".to_string(),
    };
    HostRow {
        id: r.id,
        hostname: r.hostname,
        allowed_gid,
        force_mfa: r.force_mfa != 0,
        created_at_pretty: humanise_timestamp(&r.created_at),
        created_at: r.created_at,
        last_seen_pretty,
    }
}

// --- Templates -------------------------------------------------------------

#[derive(askama::Template)]
#[template(path = "admin/hosts_list.html")]
struct HostsListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<HostRow>,
    /// One-shot reveal of a freshly minted `host_id:secret`. Read out of
    /// the `SecretReveal` flash store; `None` on plain refresh.
    revealed_credential: Option<String>,
}

#[derive(askama::Template)]
#[template(path = "admin/hosts_new.html")]
struct HostNewTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    error_message: String,
    hostname: String,
    allowed_gid: String,
    force_mfa: bool,
}

// --- Handlers --------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListQuery {
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

    let rows = match posix_db::list_hosts(&state.db).await {
        Ok(rows) => rows.into_iter().map(project_row).collect(),
        Err(e) => {
            tracing::error!(error = ?e, "admin: list hosts failed");
            return render_admin_error(
                &state,
                "Hosts unavailable",
                "We couldn't list enrolled hosts. Please try again in a moment.",
            );
        }
    };

    let revealed_credential = match query.reveal.as_deref().filter(|s| !s.is_empty()) {
        Some(token) => {
            match flash::take_secret_reveal(&state.db, state.cfg.flash.reveal_ttl_seconds, token)
                .await
            {
                Some(SecretReveal::HostSecret { host_id, secret }) if !secret.is_empty() => {
                    Some(format!("{host_id}:{secret}"))
                }
                _ => None,
            }
        }
        None => None,
    };

    let chrome = ctx.chrome(&csrf);
    render(&HostsListTemplate {
        chrome,
        admin_active: AdminSection::Hosts,
        rows,
        revealed_credential,
    })
}

pub async fn new(admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let chrome = ctx.chrome(&csrf);
    render(&HostNewTemplate {
        chrome,
        admin_active: AdminSection::Hosts,
        error_message: String::new(),
        hostname: String::new(),
        allowed_gid: String::new(),
        force_mfa: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct IssueForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    hostname: String,
    /// Blank → no gid restriction. Otherwise parsed as i32 (non-negative).
    #[serde(default)]
    allowed_gid: String,
    #[serde(default)]
    force_mfa: Option<String>,
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

    // TODO: enforcement lands with the resolver/PAM MFA task (M2); captured only for now.
    let force_mfa = form.force_mfa.is_some();
    let rerender = |error_message: String| -> Response {
        let chrome = ctx.chrome(&csrf);
        render(&HostNewTemplate {
            chrome,
            admin_active: AdminSection::Hosts,
            error_message,
            hostname: form.hostname.clone(),
            allowed_gid: form.allowed_gid.clone(),
            force_mfa,
        })
    };

    let hostname = form.hostname.trim().to_string();
    if hostname.is_empty() {
        return rerender("Hostname is required.".to_string());
    }
    let allowed_gid: Option<i32> = match form.allowed_gid.trim() {
        "" => None,
        s => match s.parse::<i32>() {
            Ok(n) if n >= 0 => Some(n),
            _ => {
                return rerender(
                    "Allowed GID must be a non-negative integer, or blank for any group."
                        .to_string(),
                )
            }
        },
    };

    let secret = generate_token();
    let secret_hash = hash_token(&secret);
    let host_id = Uuid::new_v4().to_string();

    if let Err(e) = posix_db::insert_host(
        &state.db,
        &host_id,
        &hostname,
        &secret_hash,
        allowed_gid,
        force_mfa,
        Some(&ctx.email),
    )
    .await
    {
        tracing::error!(error = ?e, "admin: host enroll insert failed");
        return rerender(format!("Failed to enroll host: {e}"));
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::HOST_ENROLLED)
            .actor_admin(&ctx.identity_id, &ctx.email)
            .target(target_kind::HOST, host_id.clone())
            .with_ctx(&actx)
            .metadata(host_audit_metadata(&hostname, allowed_gid)),
    )
    .await;

    let reveal = SecretReveal::HostSecret { host_id, secret };
    reveal_and_redirect(&state, reveal).await
}

pub async fn revoke_confirm(Path(id): Path<String>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Hosts,
        title: format!("Revoke host {id}?"),
        body: "After revocation this host can no longer authenticate to the resolver. Its secret stops working immediately. Re-enrolling mints a fresh host id and secret.".to_string(),
        action_url: format!("/admin/hosts/{}/revoke", ory_client::apis::urlencode(&id)),
        cancel_url: "/admin/hosts".to_string(),
        submit_label: "Revoke host",
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
        return Redirect::to("/admin/hosts").into_response();
    }

    let host = match posix_db::host_by_id(&state.db, &id).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = ?e, "admin: host lookup before revoke failed");
            return render_admin_error(
                &state,
                "Revoke failed",
                &format!("Could not revoke host: {e}"),
            );
        }
    };

    if let Err(e) = posix_db::delete_host(&state.db, &id).await {
        tracing::error!(error = ?e, "admin: host delete failed");
        return render_admin_error(
            &state,
            "Revoke failed",
            &format!("Could not revoke host: {e}"),
        );
    }

    if let Some(h) = host {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::HOST_REVOKED)
                .actor_admin(&ctx.identity_id, &ctx.email)
                .target(target_kind::HOST, id)
                .with_ctx(&actx)
                .metadata(host_audit_metadata(&h.hostname, h.allowed_gid))
                .critical(),
        )
        .await;
    }
    Redirect::to("/admin/hosts").into_response()
}

pub async fn rotate_confirm(Path(id): Path<String>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Hosts,
        title: format!("Rotate secret for host {id}?"),
        body: "A fresh secret is minted and revealed once. The old secret stops working immediately server-side, but already-connected clients keep using their cached secret until it expires (up to their configured TTL).".to_string(),
        action_url: format!("/admin/hosts/{}/rotate", ory_client::apis::urlencode(&id)),
        cancel_url: "/admin/hosts".to_string(),
        submit_label: "Rotate secret",
    })
}

pub async fn rotate(
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
        return Redirect::to("/admin/hosts").into_response();
    }

    let host = match posix_db::host_by_id(&state.db, &id).await {
        Ok(Some(h)) => h,
        Ok(None) => return render_admin_error(&state, "Rotate failed", "No such host."),
        Err(e) => {
            tracing::error!(error = ?e, "admin: host lookup before rotate failed");
            return render_admin_error(
                &state,
                "Rotate failed",
                &format!("Could not rotate secret: {e}"),
            );
        }
    };

    let secret = generate_token();
    let secret_hash = hash_token(&secret);
    match posix_db::rotate_host_secret(&state.db, &id, &secret_hash).await {
        Ok(0) => return render_admin_error(&state, "Rotate failed", "No such host."),
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = ?e, "admin: host secret rotate failed");
            return render_admin_error(
                &state,
                "Rotate failed",
                &format!("Could not rotate secret: {e}"),
            );
        }
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::HOST_SECRET_ROTATED)
            .actor_admin(&ctx.identity_id, &ctx.email)
            .target(target_kind::HOST, id.clone())
            .with_ctx(&actx)
            .metadata(host_audit_metadata(&host.hostname, host.allowed_gid)),
    )
    .await;

    let reveal = SecretReveal::HostSecret {
        host_id: id,
        secret,
    };
    reveal_and_redirect(&state, reveal).await
}

/// Stash the one-shot reveal and 303 to the list page carrying only the
/// opaque flash token. Shared by enroll + rotate.
async fn reveal_and_redirect(state: &AppState, reveal: SecretReveal) -> Response {
    let token =
        match flash::store_secret_reveal(&state.db, state.cfg.flash.reveal_ttl_seconds, reveal)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = ?e, "admin: host secret reveal store failed");
                return render_admin_error(
                    state,
                    "Reveal failed",
                    "The host secret was recorded but we couldn't stage it for one-shot display. \
                     Rotate the host's secret to mint a fresh one.",
                );
            }
        };
    let url = format!(
        "/admin/hosts?reveal={}",
        ory_client::apis::urlencode(&token)
    );
    Redirect::to(&url).into_response()
}

/// Audit metadata for host events. **Only** carries `hostname` + `allowed_gid`
/// — never the secret or its hash. `SafeMetadata` deny-lists credential keys
/// and panics in debug, so keeping secrets out is enforced both ways.
fn host_audit_metadata(hostname: &str, allowed_gid: Option<i32>) -> SafeMetadata {
    audit_metadata!(
        "hostname" => hostname.to_string(),
        "allowed_gid" => allowed_gid.map(|g| g.to_string()).unwrap_or_else(|| "any".to_string()),
    )
}

/// 32 random bytes from ThreadRng (OS-seeded), base64url-encoded, no padding.
/// Mirrors `dcr_tokens::generate_token` — ~256 bits, same generator the rest
/// of the codebase uses for client secrets and CSRF tokens.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_audit_metadata_builds_and_omits_secret() {
        let md = host_audit_metadata("web-01.example.com", Some(2000));
        let obj = md.as_value().as_object().expect("metadata is an object");
        assert_eq!(
            obj.get("hostname").and_then(|v| v.as_str()),
            Some("web-01.example.com")
        );
        assert_eq!(
            obj.get("allowed_gid").and_then(|v| v.as_str()),
            Some("2000")
        );
        assert!(!obj.contains_key("secret"));
        assert!(!obj.contains_key("secret_hash"));
        let json = md.as_value().to_string();
        assert!(!json.contains("secret"));
    }

    #[test]
    fn host_audit_metadata_handles_any_gid() {
        let md = host_audit_metadata("db-01", None);
        let obj = md.as_value().as_object().expect("metadata is an object");
        assert_eq!(obj.get("allowed_gid").and_then(|v| v.as_str()), Some("any"));
        assert!(!obj.contains_key("secret"));
    }
}
