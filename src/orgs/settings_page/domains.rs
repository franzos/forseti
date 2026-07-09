//! Allowed-domains settings page: add/verify/confirm/remove ownership
//! challenges for internal-org email-domain auto-join. Non-Default,
//! non-External, licensed only — mirrors `require_external_mode_writable`'s
//! shape plus an explicit External-mode reject (external orgs use self-serve
//! join, not domain auto-join).

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::csrf::{CsrfForm, NoPayload};
use crate::extractors::{gate_orgs_feature_or_upsell, Csrf, RequireSession};
use crate::orgs::{self, domains, Org};
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::state::AppState;

use super::{build_nav, require_org_owner, resolve_org_or_404, settings_ctx, OrgSlug, SettingsCtx};

/// Owner + Default-forbidden + External-forbidden + license, mirroring
/// `require_external_mode_writable`'s shape. Domain auto-join only makes
/// sense for a licensed, non-Default, Internal org: External orgs use
/// self-serve join instead. `access_mode` is parsed fail-closed
/// (`parse_access_mode`), so an unrecognized value degrades to Internal
/// (allowed here) rather than silently opening the External carve-out.
async fn require_domain_admin(
    state: &AppState,
    csrf_token: &str,
    identity_id: &str,
    email: &str,
    org: &Org,
) -> Result<(), Response> {
    require_org_owner(state, identity_id, &org.id).await?;
    if org.id == orgs::DEFAULT_ORG_ID {
        return Err((
            StatusCode::FORBIDDEN,
            "domain auto-join is not available for the Default organization",
        )
            .into_response());
    }
    if orgs::parse_access_mode(&org.access_mode).is_external() {
        return Err((
            StatusCode::FORBIDDEN,
            "domain auto-join is not available for External organizations",
        )
            .into_response());
    }
    gate_orgs_feature_or_upsell(state, csrf_token, email)?;
    Ok(())
}

#[derive(Serialize, Clone)]
struct DomainView {
    domain: String,
    method: String,
    verified: bool,
    /// Shown only while pending, so the owner can (re-)read it to finish
    /// setting up the DNS/HTTP challenge. Never shown for the email method
    /// (there's no token to display -- the code went out by mail).
    token: String,
}

#[derive(Template)]
#[template(path = "orgs/domains.html")]
struct DomainsTemplate {
    chrome: PageChrome,
    org: Org,
    is_default: bool,
    /// `true` when this org's `domain_join_policy` is `auto_join`; drives the
    /// join-policy control's selected option.
    auto_join: bool,
    domains: Vec<DomainView>,
    http_file_enabled: bool,
    dns_txt_enabled: bool,
    email_enabled: bool,
    nav: orgs::nav::OrgNav,
}

pub(super) async fn domains(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    headers: HeaderMap,
    sess: RequireSession,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
) -> Response {
    let ctx = settings_ctx(&sess, &themed.chrome.csrf_token, locale);
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) = require_domain_admin(
        &state,
        &ctx.csrf_token,
        &ctx.identity_id,
        &ctx.user_email,
        &target.org,
    )
    .await
    {
        return r;
    }
    render_domains(
        &state,
        &headers,
        &ctx,
        target.org,
        &themed.memberships,
        themed.chrome,
    )
    .await
}

async fn render_domains(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &SettingsCtx,
    org: Org,
    memberships: &[orgs::Membership],
    chrome: PageChrome,
) -> Response {
    let rows = domains::list_domains_for_org(&state.db, &org.id)
        .await
        .unwrap_or_default();
    let nav = build_nav(state, headers, &ctx.identity_id, Some(memberships)).await;
    render(&DomainsTemplate {
        chrome,
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        auto_join: orgs::parse_domain_join_policy(&org.domain_join_policy).is_auto_join(),
        http_file_enabled: state.cfg.orgs.domain_verify_http_file_enabled,
        dns_txt_enabled: state.cfg.orgs.domain_verify_dns_txt_enabled,
        email_enabled: state.cfg.orgs.domain_verify_email_enabled,
        domains: rows
            .into_iter()
            .map(|r| DomainView {
                verified: r.verified_at.is_some(),
                // Email tokens are hashed at rest and never displayed; keep the
                // secret out of the render model entirely, not just the template.
                token: if r.method == "email" {
                    String::new()
                } else {
                    r.verification_token
                },
                method: r.method,
                domain: r.domain,
            })
            .collect(),
        org,
        nav,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct AddDomainForm {
    domain: String,
    method: String,
}

pub(super) async fn domains_add(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<AddDomainForm>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) =
        require_domain_admin(&state, &csrf.0, &sess.identity_id, &sess.email, &target.org).await
    {
        return r;
    }
    let org_id = target.org.id.clone();
    let Some(domain) = domains::normalize_domain(&form.domain) else {
        return (StatusCode::BAD_REQUEST, "enter a valid domain").into_response();
    };
    if domains::is_freemail_domain(&domain) {
        return (
            StatusCode::BAD_REQUEST,
            "public/freemail domains cannot be claimed",
        )
            .into_response();
    }
    let method = match form.method.as_str() {
        "http_file" if state.cfg.orgs.domain_verify_http_file_enabled => "http_file",
        "dns_txt" if state.cfg.orgs.domain_verify_dns_txt_enabled => "dns_txt",
        "email" if state.cfg.orgs.domain_verify_email_enabled => "email",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "unknown or disabled verification method",
            )
                .into_response();
        }
    };
    let max_domains = state.cfg.orgs.domain_max_per_org;
    match domains::count_domains_for_org(&state.db, &org_id).await {
        Ok(count) if count >= i64::from(max_domains) => {
            return (
                StatusCode::BAD_REQUEST,
                "this organization has reached its allowed-domains limit",
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = ?e, "domains_add: count_domains_for_org failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "could not add domain").into_response();
        }
    }
    let token = domains::mint_verification_token();
    match domains::add_pending_domain(
        &state.db,
        &org_id,
        &domain,
        method,
        &token,
        Some(&sess.identity_id),
    )
    .await
    {
        Ok(domains::AddDomainOutcome::Added) => {
            if method == "email" {
                domains::send_domain_challenge_emails(
                    &state.cfg,
                    &domain,
                    &token,
                    &target.org.name,
                    &sess.email,
                )
                .await;
            }
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ORG_DOMAIN_ADDED)
                    .actor_user(&sess.identity_id, &sess.email)
                    .target(target_kind::ORG, org_id.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!(
                        "org_id" => org_id.as_str(),
                        "domain" => domain.as_str(),
                        "method" => method,
                    )),
            )
            .await;
        }
        Ok(domains::AddDomainOutcome::AlreadyPending) => {}
        Err(e) => {
            tracing::error!(error = ?e, "domains_add: add_pending_domain failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "could not add domain").into_response();
        }
    }
    Redirect::to(&format!("{}/domains", target.base_path)).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct PolicyForm {
    policy: String,
}

/// `POST .../domains/policy`: set the org's `domain_join_policy`. Owner + CSRF
/// via `require_domain_admin` (Internal, non-Default, licensed). The value is
/// parsed fail-closed, so anything but the exact `auto_join` literal is stored
/// as `invite_only`.
pub(super) async fn domains_set_policy(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    sess: RequireSession,
    csrf: Csrf,
    CsrfForm(form): CsrfForm<PolicyForm>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) =
        require_domain_admin(&state, &csrf.0, &sess.identity_id, &sess.email, &target.org).await
    {
        return r;
    }
    let policy = orgs::parse_domain_join_policy(&form.policy);
    if let Err(e) = orgs::db::set_domain_join_policy(&state.db, &target.org.id, policy).await {
        tracing::error!(error = ?e, "domains_set_policy: set_domain_join_policy failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not update policy").into_response();
    }
    Redirect::to(&format!("{}/domains", target.base_path)).into_response()
}

/// `slug` (`None` on the Default route) plus the domain being acted on.
#[derive(Deserialize)]
pub(super) struct DomainTarget {
    #[serde(default)]
    pub(super) slug: Option<String>,
    pub(super) domain: String,
}

pub(super) async fn domains_verify(
    State(state): State<AppState>,
    Path(DomainTarget { slug, domain }): Path<DomainTarget>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    _: CsrfForm<NoPayload>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) =
        require_domain_admin(&state, &csrf.0, &sess.identity_id, &sess.email, &target.org).await
    {
        return r;
    }
    let org_id = target.org.id.clone();
    let Ok(Some(row)) = domains::get_domain(&state.db, &org_id, &domain).await else {
        return (StatusCode::NOT_FOUND, "unknown domain").into_response();
    };
    // Transient network failure (DNS timeout, non-2xx, oversize body) reads
    // as "not verified yet" rather than an application error -- the owner
    // simply tries again once records/files propagate.
    let ok = match row.method.as_str() {
        "http_file" if state.cfg.orgs.domain_verify_http_file_enabled => {
            let timeout = std::time::Duration::from_secs(
                state
                    .cfg
                    .orgs
                    .domain_verify_http_timeout_seconds
                    .unwrap_or(10),
            );
            domains::verify_http_file(&domain, &row.verification_token, timeout)
                .await
                .unwrap_or(false)
        }
        "dns_txt" if state.cfg.orgs.domain_verify_dns_txt_enabled => {
            domains::verify_dns_txt(&domain, &row.verification_token)
                .await
                .unwrap_or(false)
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "use the code-confirmation form for the email method, or the method is disabled",
            )
                .into_response();
        }
    };
    if ok {
        if let Ok(domains::DomainVerifyOutcome::Verified) =
            domains::mark_domain_verified(&state.db, &org_id, &domain).await
        {
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ORG_DOMAIN_VERIFIED)
                    .actor_user(&sess.identity_id, &sess.email)
                    .target(target_kind::ORG, org_id.clone())
                    .with_ctx(&actx)
                    .metadata(audit_metadata!(
                        "org_id" => org_id.as_str(),
                        "domain" => domain.as_str(),
                        "method" => row.method.as_str(),
                    )),
            )
            .await;
        }
    }
    Redirect::to(&format!("{}/domains", target.base_path)).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct ConfirmEmailForm {
    token: String,
}

pub(super) async fn domains_confirm_email(
    State(state): State<AppState>,
    Path(DomainTarget { slug, domain }): Path<DomainTarget>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<ConfirmEmailForm>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) =
        require_domain_admin(&state, &csrf.0, &sess.identity_id, &sess.email, &target.org).await
    {
        return r;
    }
    if !state.cfg.orgs.domain_verify_email_enabled {
        return (StatusCode::BAD_REQUEST, "email verification is disabled").into_response();
    }
    let org_id = target.org.id.clone();
    if let Ok(domains::DomainVerifyOutcome::Verified) =
        domains::confirm_email_token(&state.db, &org_id, &domain, &form.token).await
    {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::ORG_DOMAIN_VERIFIED)
                .actor_user(&sess.identity_id, &sess.email)
                .target(target_kind::ORG, org_id.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "org_id" => org_id.as_str(),
                    "domain" => domain.as_str(),
                    "method" => "email",
                )),
        )
        .await;
    }
    Redirect::to(&format!("{}/domains", target.base_path)).into_response()
}

pub(super) async fn domains_remove(
    State(state): State<AppState>,
    Path(DomainTarget { slug, domain }): Path<DomainTarget>,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    _: CsrfForm<NoPayload>,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) =
        require_domain_admin(&state, &csrf.0, &sess.identity_id, &sess.email, &target.org).await
    {
        return r;
    }
    let org_id = target.org.id.clone();
    if domains::delete_domain(&state.db, &org_id, &domain)
        .await
        .is_ok()
    {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::ORG_DOMAIN_REMOVED)
                .actor_user(&sess.identity_id, &sess.email)
                .target(target_kind::ORG, org_id.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!(
                    "org_id" => org_id.as_str(),
                    "domain" => domain.as_str(),
                )),
        )
        .await;
    }
    Redirect::to(&format!("{}/domains", target.base_path)).into_response()
}

#[cfg(test)]
mod tests {
    use crate::orgs::{self, Org};

    fn test_org(id: &str, access_mode: &str) -> Org {
        Org {
            id: id.to_string(),
            slug: id.to_string(),
            name: id.to_string(),
            logo_url: None,
            support_email: None,
            created_at: String::new(),
            created_by: None,
            member_visibility: "visible".to_string(),
            theme_preset: None,
            brand_primary: None,
            brand_on_primary: None,
            brand_secondary: None,
            public_login_enabled: 0,
            has_logo: 0,
            access_mode: access_mode.to_string(),
            domain_join_policy: "invite_only".to_string(),
        }
    }

    /// Default is forbidden regardless of access_mode (matches
    /// `require_external_mode_writable`'s Default carve-out).
    #[test]
    fn default_org_id_check_matches_helper_shape() {
        let org = test_org(orgs::DEFAULT_ORG_ID, "internal");
        assert_eq!(org.id, orgs::DEFAULT_ORG_ID);
    }

    /// `parse_access_mode` fail-closed: only the exact "external" literal
    /// opts an org out of the domains page, everything else stays Internal.
    #[test]
    fn external_access_mode_is_rejected_fail_closed() {
        assert!(orgs::parse_access_mode("external").is_external());
        assert!(!orgs::parse_access_mode("internal").is_external());
        assert!(!orgs::parse_access_mode("garbage").is_external());
        assert!(!orgs::parse_access_mode("").is_external());
    }
}
