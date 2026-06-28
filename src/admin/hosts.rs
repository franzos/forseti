//! `/admin/hosts/*`: enrollment of Linux hosts that consume Forseti's
//! POSIX/NSS resolver.
//!
//! Operators enroll a host (minting a one-shot secret), revoke it, and
//! rotate its secret here. The raw secret is revealed exactly once via the
//! same `SecretReveal` flash the DCR-token surface uses; only
//! `sha256(secret)` is persisted (see [`crate::oauth::register::hash_token`]).
//!
//! ## Scope
//!
//! **Forseti-tier only** ([`RequireAdmin`]: session + AAL2 +
//! `[admin].allowed_emails`); does NOT honour the `?org=<slug>` convention.

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

struct HostRow {
    id: String,
    hostname: String,
    teams: String,
    force_mfa: bool,
    created_at: String,
    created_at_pretty: String,
    last_seen_pretty: String,
}

/// A selectable org team rendered as a checkbox in the enroll/edit forms.
struct TeamChoice {
    id: String,
    name: String,
    checked: bool,
}

/// An org option in the enroll form's org `<select>`.
struct OrgChoice {
    id: String,
    name: String,
    selected: bool,
}

/// One org's teams, grouped under the org name in the enroll form.
struct OrgTeamGroup {
    org_name: String,
    teams: Vec<TeamChoice>,
}

fn project_row(r: posix_db::HostListRow, teams: String) -> HostRow {
    let last_seen_pretty = match r.last_seen_at.as_deref().filter(|s| !s.is_empty()) {
        Some(ts) => humanise_timestamp(ts),
        None => "never".to_string(),
    };
    HostRow {
        id: r.id,
        hostname: r.hostname,
        teams,
        force_mfa: r.force_mfa != 0,
        created_at_pretty: humanise_timestamp(&r.created_at),
        created_at: r.created_at,
        last_seen_pretty,
    }
}

#[derive(askama::Template)]
#[template(path = "admin/hosts_list.html")]
struct HostsListTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    rows: Vec<HostRow>,
    /// One-shot reveal of a freshly minted `host_id:secret`; `None` otherwise.
    revealed_credential: Option<String>,
}

#[derive(askama::Template)]
#[template(path = "admin/hosts_new.html")]
struct HostNewTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    error_message: String,
    hostname: String,
    orgs: Vec<OrgChoice>,
    team_groups: Vec<OrgTeamGroup>,
    /// True when at least one org has a team; gates the "no teams yet" hint.
    any_teams: bool,
    force_mfa: bool,
}

#[derive(askama::Template)]
#[template(path = "admin/hosts_edit.html")]
struct HostEditTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    error_message: String,
    id: String,
    hostname: String,
    /// Read-only: a host's org is fixed at enrollment, never editable here.
    org_name: String,
    teams: Vec<TeamChoice>,
    force_mfa: bool,
}

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

    let host_rows = match posix_db::list_hosts(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "admin: list hosts failed");
            return render_admin_error(
                &state,
                "Hosts unavailable",
                "We couldn't list enrolled hosts. Please try again in a moment.",
            );
        }
    };

    // team-id -> name map across every org, built once to avoid an N+1.
    let team_names: std::collections::HashMap<String, String> =
        match load_orgs_and_teams(&state).await {
            Ok((_, by_org)) => by_org
                .into_values()
                .flatten()
                .map(|t| (t.id, t.name))
                .collect(),
            Err(e) => {
                tracing::error!(error = ?e, "admin: list teams failed");
                return render_admin_error(
                    &state,
                    "Hosts unavailable",
                    "We couldn't resolve host scopes. Please try again in a moment.",
                );
            }
        };

    let mut rows = Vec::with_capacity(host_rows.len());
    for r in host_rows {
        let team_ids = match posix_db::host_allowed_team_ids(&state.db, &r.id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = ?e, "admin: host allowed teams failed");
                return render_admin_error(
                    &state,
                    "Hosts unavailable",
                    "We couldn't resolve host scopes. Please try again in a moment.",
                );
            }
        };
        let teams = if team_ids.is_empty() {
            "whole org".to_string()
        } else {
            team_ids
                .iter()
                .map(|t| team_names.get(t).cloned().unwrap_or_else(|| t.clone()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        rows.push(project_row(r, teams));
    }

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

pub async fn new(State(state): State<AppState>, admin: RequireAdmin, csrf: Csrf) -> Response {
    let ctx = admin.ctx;
    let (orgs, teams_by_org) = match load_orgs_and_teams(&state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "admin: load orgs/teams (new host) failed");
            return render_admin_error(
                &state,
                "Enroll unavailable",
                "We couldn't load organizations. Please try again in a moment.",
            );
        }
    };
    let selected_org = orgs
        .first()
        .map(|o| o.id.clone())
        .unwrap_or_else(|| crate::orgs::DEFAULT_ORG_ID.to_string());
    let groups = team_groups(&orgs, &teams_by_org, &[]);
    let any_teams = groups.iter().any(|g| !g.teams.is_empty());
    let chrome = ctx.chrome(&csrf);
    render(&HostNewTemplate {
        chrome,
        admin_active: AdminSection::Hosts,
        error_message: String::new(),
        hostname: String::new(),
        orgs: org_choices(&orgs, &selected_org),
        team_groups: groups,
        any_teams,
        force_mfa: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct IssueForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    hostname: String,
    /// The org this host belongs to. Immutable after enrollment.
    #[serde(default)]
    org_id: String,
    /// Repeated `team_ids=` checkbox values (`axum_extra::Form` collects them
    /// into a Vec). Empty → whole-org host (allows any org member).
    #[serde(default)]
    team_ids: Vec<String>,
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

    let force_mfa = form.force_mfa.is_some();
    let (orgs, teams_by_org) = match load_orgs_and_teams(&state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "admin: load orgs/teams (issue) failed");
            return render_admin_error(
                &state,
                "Enroll failed",
                "We couldn't load organizations. Please try again in a moment.",
            );
        }
    };
    let rerender = |error_message: String, team_ids: &[String]| -> Response {
        let groups = team_groups(&orgs, &teams_by_org, team_ids);
        let any_teams = groups.iter().any(|g| !g.teams.is_empty());
        let chrome = ctx.chrome(&csrf);
        render(&HostNewTemplate {
            chrome,
            admin_active: AdminSection::Hosts,
            error_message,
            hostname: form.hostname.clone(),
            orgs: org_choices(&orgs, &form.org_id),
            team_groups: groups,
            any_teams,
            force_mfa,
        })
    };

    let hostname = form.hostname.trim().to_string();
    if hostname.is_empty() {
        return rerender("Hostname is required.".to_string(), &form.team_ids);
    }
    if !orgs.iter().any(|o| o.id == form.org_id) {
        return rerender(
            "Pick an organization for this host.".to_string(),
            &form.team_ids,
        );
    }
    let valid: std::collections::HashSet<&str> = teams_by_org
        .get(&form.org_id)
        .map(|ts| ts.iter().map(|t| t.id.as_str()).collect())
        .unwrap_or_default();
    if let Some(bad) = form.team_ids.iter().find(|t| !valid.contains(t.as_str())) {
        return rerender(
            format!("Unknown team {bad}. Pick teams from the chosen organization."),
            &form.team_ids,
        );
    }

    let secret = generate_token();
    let secret_hash = hash_token(&secret);
    let host_id = Uuid::new_v4().to_string();

    if let Err(e) = posix_db::insert_host(
        &state.db,
        &host_id,
        &hostname,
        &secret_hash,
        &form.org_id,
        force_mfa,
        Some(&ctx.email),
    )
    .await
    {
        tracing::error!(error = ?e, "admin: host enroll insert failed");
        return rerender(format!("Failed to enroll host: {e}"), &form.team_ids);
    }
    for team_id in &form.team_ids {
        if let Err(e) =
            posix_db::find_or_create_team_gid(&state.db, team_id, state.cfg.posix.group_gid_base)
                .await
        {
            tracing::error!(error = ?e, "admin: team gid allocation (issue) failed");
            return rerender(format!("Failed to scope host: {e}"), &form.team_ids);
        }
    }
    if let Err(e) = posix_db::set_host_allowed_team_ids(&state.db, &host_id, &form.team_ids).await {
        tracing::error!(error = ?e, "admin: host allowed teams write failed");
        return rerender(format!("Failed to scope host: {e}"), &form.team_ids);
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::HOST_ENROLLED)
            .actor_admin(&ctx.identity_id, &ctx.email)
            .target(target_kind::HOST, host_id.clone())
            .with_ctx(&actx)
            .metadata(host_audit_metadata(&hostname, &form.team_ids)),
    )
    .await;

    let reveal = SecretReveal::HostSecret { host_id, secret };
    reveal_and_redirect(&state, reveal).await
}

pub async fn edit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    admin: RequireAdmin,
    csrf: Csrf,
) -> Response {
    let ctx = admin.ctx;
    let host = match posix_db::host_by_id(&state.db, &id).await {
        Ok(Some(h)) => h,
        Ok(None) => return render_admin_error(&state, "Edit failed", "No such host."),
        Err(e) => {
            tracing::error!(error = ?e, "admin: host lookup before edit failed");
            return render_admin_error(&state, "Edit failed", &format!("Could not load host: {e}"));
        }
    };
    let current = match posix_db::host_allowed_team_ids(&state.db, &id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "admin: host allowed teams (edit) failed");
            return render_admin_error(&state, "Edit failed", &format!("Could not load host: {e}"));
        }
    };
    let host_org = match posix_db::host_org_id(&state.db, &id).await {
        Ok(Some(o)) => o,
        Ok(None) => return render_admin_error(&state, "Edit failed", "No such host."),
        Err(e) => {
            tracing::error!(error = ?e, "admin: host org lookup (edit) failed");
            return render_admin_error(&state, "Edit failed", &format!("Could not load host: {e}"));
        }
    };
    let org_name = match org_display_name(&state, &host_org).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = ?e, "admin: org lookup (edit) failed");
            return render_admin_error(&state, "Edit failed", &format!("Could not load host: {e}"));
        }
    };
    let org_teams = match crate::orgs::teams::list_teams(&state.db, &host_org).await {
        Ok(ts) => ts,
        Err(e) => {
            tracing::error!(error = ?e, "admin: list teams (edit) failed");
            return render_admin_error(&state, "Edit failed", &format!("Could not load host: {e}"));
        }
    };
    let chrome = ctx.chrome(&csrf);
    render(&HostEditTemplate {
        chrome,
        admin_active: AdminSection::Hosts,
        error_message: String::new(),
        id: host.id,
        hostname: host.hostname,
        org_name,
        teams: team_choices(&org_teams, &current),
        force_mfa: host.force_mfa != 0,
    })
}

#[derive(Debug, Deserialize)]
pub struct EditForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    team_ids: Vec<String>,
    #[serde(default)]
    force_mfa: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actx: AuditCtx,
    admin: RequireAdmin,
    csrf: Csrf,
    Form(form): Form<EditForm>,
) -> Response {
    let ctx = admin.ctx;
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    let force_mfa = form.force_mfa.is_some();
    // Validate teams against the stored host org, never what the form claims.
    let host_org = match posix_db::host_org_id(&state.db, &id).await {
        Ok(Some(o)) => o,
        Ok(None) => return render_admin_error(&state, "Save failed", "No such host."),
        Err(e) => {
            tracing::error!(error = ?e, "admin: host org lookup (update) failed");
            return render_admin_error(
                &state,
                "Save failed",
                "We couldn't load the host. Please try again in a moment.",
            );
        }
    };
    let org_name = match org_display_name(&state, &host_org).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = ?e, "admin: org lookup (update) failed");
            return render_admin_error(
                &state,
                "Save failed",
                "We couldn't load the host. Please try again in a moment.",
            );
        }
    };
    let org_teams = match crate::orgs::teams::list_teams(&state.db, &host_org).await {
        Ok(ts) => ts,
        Err(e) => {
            tracing::error!(error = ?e, "admin: list teams (update) failed");
            return render_admin_error(
                &state,
                "Save failed",
                "We couldn't load org teams. Please try again in a moment.",
            );
        }
    };
    let rerender = |error_message: String, team_ids: &[String]| -> Response {
        let chrome = ctx.chrome(&csrf);
        render(&HostEditTemplate {
            chrome,
            admin_active: AdminSection::Hosts,
            error_message,
            id: id.clone(),
            hostname: form.hostname.clone(),
            org_name: org_name.clone(),
            teams: team_choices(&org_teams, team_ids),
            force_mfa,
        })
    };

    let hostname = form.hostname.trim().to_string();
    if hostname.is_empty() {
        return rerender("Hostname is required.".to_string(), &form.team_ids);
    }
    let valid: std::collections::HashSet<&str> = org_teams.iter().map(|t| t.id.as_str()).collect();
    if let Some(bad) = form.team_ids.iter().find(|t| !valid.contains(t.as_str())) {
        return rerender(
            format!("Unknown team {bad}. Pick from the host's org teams."),
            &form.team_ids,
        );
    }

    if let Err(e) = posix_db::update_host(&state.db, &id, &hostname, force_mfa).await {
        tracing::error!(error = ?e, "admin: host update failed");
        return rerender(format!("Failed to update host: {e}"), &form.team_ids);
    }
    for team_id in &form.team_ids {
        if let Err(e) =
            posix_db::find_or_create_team_gid(&state.db, team_id, state.cfg.posix.group_gid_base)
                .await
        {
            tracing::error!(error = ?e, "admin: team gid allocation (update) failed");
            return rerender(format!("Failed to scope host: {e}"), &form.team_ids);
        }
    }
    if let Err(e) = posix_db::set_host_allowed_team_ids(&state.db, &id, &form.team_ids).await {
        tracing::error!(error = ?e, "admin: host allowed teams update failed");
        return rerender(format!("Failed to scope host: {e}"), &form.team_ids);
    }

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::HOST_UPDATED)
            .actor_admin(&ctx.identity_id, &ctx.email)
            .target(target_kind::HOST, id)
            .with_ctx(&actx)
            .metadata(host_audit_metadata(&hostname, &form.team_ids)),
    )
    .await;

    Redirect::to("/admin/hosts").into_response()
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
    let team_ids = posix_db::host_allowed_team_ids(&state.db, &id)
        .await
        .unwrap_or_default();

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
                .metadata(host_audit_metadata(&h.hostname, &team_ids))
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

    let team_ids = posix_db::host_allowed_team_ids(&state.db, &id)
        .await
        .unwrap_or_default();
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::HOST_SECRET_ROTATED)
            .actor_admin(&ctx.identity_id, &ctx.email)
            .target(target_kind::HOST, id.clone())
            .with_ctx(&actx)
            .metadata(host_audit_metadata(&host.hostname, &team_ids)),
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

/// Load every org plus its teams, keyed by org id.
async fn load_orgs_and_teams(
    state: &AppState,
) -> anyhow::Result<(
    Vec<crate::orgs::db::Org>,
    std::collections::HashMap<String, Vec<crate::orgs::teams::Team>>,
)> {
    let orgs = crate::orgs::db::list_orgs(&state.db).await?;
    let mut by_org = std::collections::HashMap::with_capacity(orgs.len());
    for o in &orgs {
        let teams = crate::orgs::teams::list_teams(&state.db, &o.id).await?;
        by_org.insert(o.id.clone(), teams);
    }
    Ok((orgs, by_org))
}

/// Resolve an org's display name, falling back to its id if the row is gone.
async fn org_display_name(state: &AppState, org_id: &str) -> anyhow::Result<String> {
    Ok(crate::orgs::db::org_by_id(&state.db, org_id)
        .await?
        .map(|o| o.name)
        .unwrap_or_else(|| org_id.to_string()))
}

/// Project orgs into `<select>` options, marking `selected`.
fn org_choices(orgs: &[crate::orgs::db::Org], selected: &str) -> Vec<OrgChoice> {
    orgs.iter()
        .map(|o| OrgChoice {
            id: o.id.clone(),
            name: o.name.clone(),
            selected: o.id == selected,
        })
        .collect()
}

/// Group each org's teams into checkbox choices, marking `selected_teams`.
fn team_groups(
    orgs: &[crate::orgs::db::Org],
    teams_by_org: &std::collections::HashMap<String, Vec<crate::orgs::teams::Team>>,
    selected_teams: &[String],
) -> Vec<OrgTeamGroup> {
    orgs.iter()
        .map(|o| OrgTeamGroup {
            org_name: o.name.clone(),
            teams: teams_by_org
                .get(&o.id)
                .map(|ts| team_choices(ts, selected_teams))
                .unwrap_or_default(),
        })
        .collect()
}

/// Project org teams into checkbox choices, marking `selected`.
fn team_choices(org_teams: &[crate::orgs::teams::Team], selected: &[String]) -> Vec<TeamChoice> {
    org_teams
        .iter()
        .map(|t| TeamChoice {
            id: t.id.clone(),
            name: t.name.clone(),
            checked: selected.contains(&t.id),
        })
        .collect()
}

/// Audit metadata for host events. Carries only `hostname` + the scoped team
/// set, never the secret or its hash (also enforced by `SafeMetadata`).
fn host_audit_metadata(hostname: &str, team_ids: &[String]) -> SafeMetadata {
    let teams_str = if team_ids.is_empty() {
        "whole-org".to_string()
    } else {
        team_ids.join(",")
    };
    audit_metadata!(
        "hostname" => hostname.to_string(),
        "team_count" => team_ids.len().to_string(),
        "allowed_teams" => teams_str,
    )
}

/// 32 random bytes (~256 bits), base64url-encoded; mirrors
/// `dcr_tokens::generate_token`.
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
        let md = host_audit_metadata(
            "web-01.example.com",
            &["team-a".to_string(), "team-b".to_string()],
        );
        let obj = md.as_value().as_object().expect("metadata is an object");
        assert_eq!(
            obj.get("hostname").and_then(|v| v.as_str()),
            Some("web-01.example.com")
        );
        assert_eq!(
            obj.get("allowed_teams").and_then(|v| v.as_str()),
            Some("team-a,team-b")
        );
        assert_eq!(obj.get("team_count").and_then(|v| v.as_str()), Some("2"));
        assert!(!obj.contains_key("secret"));
        assert!(!obj.contains_key("secret_hash"));
        let json = md.as_value().to_string();
        assert!(!json.contains("secret"));
    }

    #[test]
    fn host_audit_metadata_handles_unscoped() {
        let md = host_audit_metadata("db-01", &[]);
        let obj = md.as_value().as_object().expect("metadata is an object");
        assert_eq!(
            obj.get("allowed_teams").and_then(|v| v.as_str()),
            Some("whole-org")
        );
        assert_eq!(obj.get("team_count").and_then(|v| v.as_str()), Some("0"));
        assert!(!obj.contains_key("secret"));
    }
}
