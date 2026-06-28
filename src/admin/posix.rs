//! `/admin/posix/*`: provision a Kratos identity into a POSIX account,
//! manage its SSH keys, and enable / disable / delete it.
//!
//! This is the **only** place the license-aware seat cap is enforced.
//! Resolution of existing accounts (the NSS resolver) is never gated, so a
//! lapsed license must not lock people out of their own machines. New
//! provisioning is the gated write: see [`seat_available`].
//!
//! ## Scope
//!
//! Forseti-tier only ([`RequireAdmin`]: session + AAL2 +
//! `[admin].allowed_emails`). Does NOT honour `?org=<slug>`.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::admin::{render_admin_error, AdminSection, ConfirmForm, ConfirmTemplate};
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::commercial::license::{seat_cap_allows, Feature};
use crate::commercial::FeatureStatus;
use crate::extractors::{Csrf, RequireAdmin};
use crate::format::humanise_timestamp;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::posix::allocate::is_valid_username;
use crate::posix::db as posix_db;
use crate::render::render;
use crate::state::AppState;

/// The licensed `max_seats` raise applies only on a fully-Allowed license.
/// Provisioning is a hard POST, so GraceReadOnly falls back to the free cap.
fn seat_available(
    linux_auth: FeatureStatus,
    max_seats: Option<u32>,
    free_seats: u32,
    current: u32,
) -> bool {
    let cap = match linux_auth {
        FeatureStatus::Allowed => max_seats.unwrap_or(free_seats),
        FeatureStatus::GraceReadOnly | FeatureStatus::Locked => free_seats,
    };
    seat_cap_allows(Some(cap), current)
}

/// The effective seat cap in force now. Mirrors [`seat_available`]'s
/// arithmetic so the list page can show `N / cap`.
fn effective_cap(linux_auth: &FeatureStatus, max_seats: Option<u32>, free_seats: u32) -> u32 {
    match linux_auth {
        FeatureStatus::Allowed => max_seats.unwrap_or(free_seats),
        FeatureStatus::GraceReadOnly | FeatureStatus::Locked => free_seats,
    }
}

struct AccountRow {
    identity_id: String,
    username: String,
    uid: i32,
    gid: i32,
    enabled: bool,
    created_at: String,
    created_at_pretty: String,
}

fn project_row(a: posix_db::PosixAccount) -> AccountRow {
    AccountRow {
        identity_id: a.identity_id,
        username: a.username,
        uid: a.uid,
        gid: a.gid,
        enabled: a.enabled != 0,
        created_at_pretty: humanise_timestamp(&a.created_at),
        created_at: a.created_at,
    }
}

struct KeyRow {
    id: String,
    public_key: String,
    comment: String,
    created_at_pretty: String,
}

struct TeamRow {
    name: String,
    org_id: String,
}

struct HostRow {
    hostname: String,
    org_id: String,
}

#[derive(askama::Template)]
#[template(path = "admin/posix_list.html")]
struct PosixListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<AccountRow>,
    /// Enabled accounts (seats consumed).
    current: u32,
    /// Effective seat cap under the active license tier.
    cap: u32,
}

#[derive(askama::Template)]
#[template(path = "admin/posix_new.html")]
struct PosixNewTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    error_message: String,
    /// Authoritative identity UUID (hidden field); empty => step 1 (chooser).
    identity_id: String,
    /// Read-only display of the chosen identity's email.
    identity_email: String,
    /// Prefilled, editable username (suggested from the email on step 2).
    username: String,
    shell: String,
}

#[derive(askama::Template)]
#[template(path = "admin/posix_account.html")]
struct PosixAccountTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    account: AccountRow,
    email: String,
    keys: Vec<KeyRow>,
    teams: Vec<TeamRow>,
    hosts: Vec<HostRow>,
    error_message: String,
}

pub async fn list(State(state): State<AppState>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;

    let accounts = match posix_db::list_enabled_accounts(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "admin: list posix accounts failed");
            return render_admin_error(
                &state,
                "POSIX accounts unavailable",
                "We couldn't list POSIX accounts. Please try again in a moment.",
            );
        }
    };

    let linux_auth = state.license.feature(Feature::LinuxAuth);
    let max_seats = state.license.status().license().and_then(|l| l.max_seats);
    let cap = effective_cap(&linux_auth, max_seats, state.cfg.posix.free_seats);
    let current = accounts.iter().filter(|a| a.enabled != 0).count() as u32;

    let rows = accounts.into_iter().map(project_row).collect();
    let chrome = ctx.chrome(&csrf);
    render(&PosixListTemplate {
        chrome,
        admin_active: AdminSection::Posix,
        rows,
        current,
        cap,
    })
}

#[derive(Debug, Deserialize)]
pub struct NewQuery {
    #[serde(default)]
    identity_id: Option<String>,
}

pub async fn new(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<NewQuery>,
    admin: RequireAdmin,
    csrf: Csrf,
) -> Response {
    let ctx = admin.ctx;
    let raw = q.identity_id.as_deref().unwrap_or("").trim().to_string();

    let (identity_id, identity_email, username) = if raw.is_empty() {
        (String::new(), String::new(), String::new())
    } else {
        match ory::kratos::admin_get_identity_optional(&state.ory, &raw).await {
            Ok(Some(id)) => {
                let email = id
                    .traits
                    .as_ref()
                    .and_then(|t| t.get("email"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let suggested = suggest_username(&email);
                (raw, email, suggested)
            }
            _ => (String::new(), String::new(), String::new()),
        }
    };

    let chrome = ctx.chrome(&csrf);
    render(&PosixNewTemplate {
        chrome,
        admin_active: AdminSection::Posix,
        error_message: String::new(),
        identity_id,
        identity_email,
        username,
        shell: state.cfg.posix.default_shell.clone(),
    })
}

/// Derive a POSIX-safe username suggestion from an email local-part:
/// lowercase, keep [a-z0-9_-], drop leading digits/hyphens. Empty when
/// nothing usable remains (caller treats "" as "no suggestion").
fn suggest_username(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("");
    let mut s: String = local
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-')
        .take(32)
        .collect();
    while s
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || c == '-')
    {
        s.remove(0);
    }
    s
}

#[derive(Debug, Deserialize)]
pub struct ProvisionForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    identity_id: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    shell: String,
}

pub async fn provision(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    csrf: Csrf,
    Form(form): Form<ProvisionForm>,
) -> Response {
    let ctx = admin.ctx;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    let submitted = form.identity_id.trim().to_string();
    let username = form.username.trim().to_string();
    let shell = {
        let s = form.shell.trim();
        if s.is_empty() {
            state.cfg.posix.default_shell.clone()
        } else {
            s.to_string()
        }
    };

    let rerender = |error_message: String| -> Response {
        let chrome = ctx.chrome(&csrf);
        render(&PosixNewTemplate {
            chrome,
            admin_active: AdminSection::Posix,
            error_message,
            identity_id: submitted.clone(),
            identity_email: String::new(),
            username: username.clone(),
            shell: shell.clone(),
        })
    };

    if submitted.is_empty() {
        return rerender("Select a user first.".to_string());
    }
    if !is_valid_username(&username) {
        return rerender(
            "Username must be 1–32 chars, start with a lowercase letter or underscore, and \
             contain only lowercase letters, digits, '_' or '-'."
                .to_string(),
        );
    }

    // Resolve the submitted value to a canonical UUID; the target must exist,
    // else we'd create an orphan the reconcile sweep deletes.
    let identity_id = if crate::format::looks_like_uuid(&submitted) {
        match ory::kratos::admin_get_identity_optional(&state.ory, &submitted).await {
            Ok(Some(_)) => submitted.clone(),
            Ok(None) => return rerender(format!("No Kratos identity with ID '{submitted}'.")),
            Err(e) => {
                tracing::error!(error = ?e, identity = %submitted, "admin: identity lookup before provision failed");
                return rerender(
                    "Couldn't verify that identity against Kratos. Please try again.".to_string(),
                );
            }
        }
    } else {
        match ory::kratos::admin_find_identity_by_email(&state.ory, &submitted.to_lowercase()).await
        {
            Ok(Some((id, _verified))) => id.id,
            Ok(None) => return rerender(format!("No identity found for '{submitted}'.")),
            Err(e) => {
                tracing::error!(error = ?e, "admin: email resolve before provision failed");
                return rerender(
                    "Couldn't look up that email against Kratos. Please try again.".to_string(),
                );
            }
        }
    };

    let current = match posix_db::count_accounts(&state.db).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = ?e, "admin: count posix accounts failed");
            return rerender("Couldn't read the current seat count. Please try again.".to_string());
        }
    };
    let linux_auth = state.license.feature(Feature::LinuxAuth);
    let max_seats = state.license.status().license().and_then(|l| l.max_seats);
    let free = state.cfg.posix.free_seats;
    if !seat_available(linux_auth.clone(), max_seats, free, current) {
        let cap = effective_cap(&linux_auth, max_seats, free);
        return rerender(format!(
            "Seat cap reached ({current}/{cap}). A commercial Linux-authentication license \
             raises it — see /admin/license."
        ));
    }

    let home_dir = format!("{}/{}", state.cfg.posix.home_prefix, username);
    let account = match posix_db::provision_account(
        &state.db,
        &identity_id,
        &username,
        state.cfg.posix.uid_base,
        state.cfg.posix.gid_base,
        &shell,
        &home_dir,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            // A collision (username / identity / group-name) is a user error,
            // not a 500.
            tracing::info!(error = %e, identity_id, username, "admin: provision_account rejected");
            return rerender(format!("Could not provision account: {e}"));
        }
    };

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::POSIX_ACCOUNT_PROVISIONED)
            .actor_admin(&ctx.identity_id, &ctx.email)
            .target(target_kind::POSIX_ACCOUNT, identity_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "username" => account.username.clone(),
                "uid" => account.uid.to_string(),
            )),
    )
    .await;

    Redirect::to(&format!(
        "/admin/posix/{}",
        ory_client::apis::urlencode(&identity_id)
    ))
    .into_response()
}

pub async fn account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    admin: RequireAdmin,
    csrf: Csrf,
) -> Response {
    render_account(&state, &admin.ctx, &csrf, &id, String::new()).await
}

/// Shared render for the account detail page, reused by the add-key error
/// path so a bad key re-renders the page inline.
async fn render_account(
    state: &AppState,
    ctx: &crate::admin::AdminCtx,
    csrf: &Csrf,
    id: &str,
    error_message: String,
) -> Response {
    let account = match posix_db::account_by_identity(&state.db, id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return render_admin_error(
                state,
                "Account not found",
                "We couldn't find a POSIX account for that identity.",
            )
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: account lookup failed");
            return render_admin_error(
                state,
                "Account unavailable",
                "We couldn't load that account. Please try again in a moment.",
            );
        }
    };

    let email = match ory::kratos::admin_get_identity_optional(&state.ory, id).await {
        Ok(Some(i)) => i
            .traits
            .as_ref()
            .and_then(|t| t.get("email"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    };

    let keys = match posix_db::authorized_keys_for(&state.db, id).await {
        Ok(rows) => rows
            .into_iter()
            .map(|k| KeyRow {
                created_at_pretty: humanise_timestamp(&k.created_at),
                id: k.id,
                public_key: k.public_key,
                comment: k.comment,
            })
            .collect(),
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: list ssh keys failed");
            Vec::new()
        }
    };

    let teams = match crate::orgs::teams::teams_for_identity_any_org(&state.db, id).await {
        Ok(rows) => rows
            .into_iter()
            .map(|t| TeamRow {
                name: t.name,
                org_id: t.org_id,
            })
            .collect(),
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: list identity teams failed");
            Vec::new()
        }
    };

    let hosts = match posix_db::hosts_reachable_by(&state.db, id).await {
        Ok(rows) => rows
            .into_iter()
            .map(|h| HostRow {
                hostname: h.hostname,
                org_id: h.org_id,
            })
            .collect(),
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: list reachable hosts failed");
            Vec::new()
        }
    };

    let chrome = ctx.chrome(csrf);
    render(&PosixAccountTemplate {
        chrome,
        admin_active: AdminSection::Posix,
        account: project_row(account),
        email,
        keys,
        teams,
        hosts,
        error_message,
    })
}

#[derive(Debug, Deserialize)]
pub struct AddKeyForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    comment: String,
}

/// Accepted OpenSSH public-key prefixes. A cheap shape check so an obvious
/// paste error (private key, URL, base64 blob) doesn't land in authorized_keys.
fn looks_like_ssh_key(s: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ssh-ed25519",
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ];
    PREFIXES.iter().any(|p| s.starts_with(p))
}

pub async fn add_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    csrf: Csrf,
    Form(form): Form<AddKeyForm>,
) -> Response {
    let ctx = admin.ctx;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    let public_key = form.public_key.trim().to_string();
    let comment = form.comment.trim().to_string();
    if public_key.is_empty() || !looks_like_ssh_key(&public_key) {
        return render_account(
            &state,
            &ctx,
            &csrf,
            &id,
            "That doesn't look like an OpenSSH public key (expected a line starting with \
             ssh-ed25519, ssh-rsa, ecdsa-sha2-…, or sk-…)."
                .to_string(),
        )
        .await;
    }

    match posix_db::insert_ssh_key(&state.db, &id, &public_key, &comment, None).await {
        Ok(key_id) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::POSIX_SSH_KEY_ADDED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::POSIX_ACCOUNT, id.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!("key_id" => key_id)),
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: insert ssh key failed");
            return render_account(&state, &ctx, &csrf, &id, format!("Could not add key: {e}"))
                .await;
        }
    }

    Redirect::to(&format!(
        "/admin/posix/{}",
        ory_client::apis::urlencode(&id)
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RemoveKeyForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

pub async fn remove_key(
    State(state): State<AppState>,
    Path((id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    Form(form): Form<RemoveKeyForm>,
) -> Response {
    let ctx = admin.ctx;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = format!("/admin/posix/{}", ory_client::apis::urlencode(&id));
    match posix_db::delete_ssh_key(&state.db, &key_id).await {
        Ok(()) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::POSIX_SSH_KEY_REMOVED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::POSIX_ACCOUNT, id.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!("key_id" => key_id)),
            )
            .await;
            Redirect::to(&target).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, id, key_id, "admin: delete ssh key failed");
            render_admin_error(
                &state,
                "Remove key failed",
                &format!("Could not remove key: {e}"),
            )
        }
    }
}

pub async fn disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    Form(form): Form<crate::csrf::CsrfForm>,
) -> Response {
    set_enabled(&state, &admin.ctx, &actx, &headers, form, &id, false).await
}

pub async fn enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    Form(form): Form<crate::csrf::CsrfForm>,
) -> Response {
    set_enabled(&state, &admin.ctx, &actx, &headers, form, &id, true).await
}

async fn set_enabled(
    state: &AppState,
    ctx: &crate::admin::AdminCtx,
    actx: &AuditCtx,
    headers: &HeaderMap,
    form: crate::csrf::CsrfForm,
    id: &str,
    enabled: bool,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = format!("/admin/posix/{}", ory_client::apis::urlencode(id));
    match posix_db::set_account_enabled(&state.db, id, enabled).await {
        Ok(()) => {
            let act = if enabled {
                action::POSIX_ACCOUNT_ENABLED
            } else {
                action::POSIX_ACCOUNT_DISABLED
            };
            let _ = audit::log(
                &state.db,
                AuditEvent::new(act)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::POSIX_ACCOUNT, id.to_string())
                    .with_ctx(actx),
            )
            .await;
            Redirect::to(&target).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, id, enabled, "admin: set_account_enabled failed");
            render_admin_error(
                state,
                "Update failed",
                &format!("Could not update the account: {e}"),
            )
        }
    }
}

pub async fn delete_confirm(Path(id): Path<String>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let chrome = ctx.chrome(&csrf);
    render(&ConfirmTemplate {
        chrome,
        admin_active: AdminSection::Posix,
        title: "Delete POSIX account?".to_string(),
        body: "This removes the account, its primary group, group memberships, and every SSH \
               key — the Kratos identity itself is untouched. The action cannot be undone."
            .to_string(),
        action_url: format!("/admin/posix/{}/delete", ory_client::apis::urlencode(&id)),
        cancel_url: format!("/admin/posix/{}", ory_client::apis::urlencode(&id)),
        submit_label: "Delete account",
    })
}

pub async fn delete(
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
    let target = format!("/admin/posix/{}", ory_client::apis::urlencode(&id));
    if !form.confirmed() {
        return Redirect::to(&target).into_response();
    }
    match posix_db::delete_account_rows(&state.db, &id).await {
        Ok(()) => {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::POSIX_ACCOUNT_DELETED)
                    .actor_admin(&ctx.identity_id, &ctx.email)
                    .target(target_kind::POSIX_ACCOUNT, id)
                    .with_ctx(&actx)
                    .critical(),
            )
            .await;
            Redirect::to("/admin/posix").into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, id, "admin: delete posix account failed");
            render_admin_error(
                &state,
                "Delete failed",
                &format!("Could not delete account: {e}"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commercial::FeatureStatus::*;
    #[test]
    fn cap_consults_license_for_the_raise() {
        // Unlicensed/Locked: free_seats applies regardless of max_seats.
        assert!(!seat_available(Locked, Some(100), 3, 3));
        assert!(seat_available(Locked, Some(100), 3, 2));
        // Allowed: max_seats overrides free_seats.
        assert!(seat_available(Allowed, Some(100), 3, 50));
        assert!(seat_available(Allowed, None, 3, 2)); // no max_seats: still free cap
        assert!(!seat_available(Allowed, None, 3, 3));
        // GraceReadOnly: provisioning is a hard POST, so the free cap holds.
        assert!(!seat_available(GraceReadOnly, Some(100), 3, 3));
    }

    #[test]
    fn ssh_key_shape_check() {
        assert!(looks_like_ssh_key("ssh-ed25519 AAAA... user@host"));
        assert!(looks_like_ssh_key("ssh-rsa AAAA..."));
        assert!(looks_like_ssh_key("ecdsa-sha2-nistp256 AAAA..."));
        assert!(looks_like_ssh_key("sk-ssh-ed25519@openssh.com AAAA..."));
        assert!(!looks_like_ssh_key("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(!looks_like_ssh_key("not a key"));
        assert!(!looks_like_ssh_key(""));
    }

    #[test]
    fn username_suggestion_from_email() {
        assert_eq!(suggest_username("Alice.B@x.com"), "aliceb");
        assert_eq!(suggest_username("1bob@x"), "bob");
        assert_eq!(suggest_username("@x"), "");
    }
}
