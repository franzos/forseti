//! `/admin/license` — view current license, activate a new blob,
//! deactivate the current one. Forseti-owned; no Kratos settings flow
//! involved (the license is per-installation, not per-identity, which
//! is why this lives under `/admin/*` and not `/settings/*` — only the
//! deployment admin should activate or deactivate).
//!
//! The admin sidebar surfaces this link under "License" and the
//! dashboard banner deep-links here when the license is in grace or
//! expired (admins only — non-admins see the banner without the link).

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::admin::AdminSection;
use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::commercial::license::{classify, LicenseStatus};
use crate::commercial::{store, upsell, verify};
use crate::extractors::Csrf;
use crate::flash;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/license", get(settings_license))
        .route("/admin/license/activate", post(activate))
        .route("/admin/license/deactivate", post(deactivate))
}

/// Rendered view-model. Plain types so the template doesn't have to
/// deal with `Option<DateTime>` directly.
#[derive(Template)]
#[template(path = "commercial/license.html")]
struct LicenseSettingsTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    flash: String,
    /// "Unlicensed" | "Active" | "Grace" | "Expired" — keeps the template
    /// branching on a single string rather than four enum variants.
    state_label: &'static str,
    has_license: bool,
    customer: String,
    email: String,
    tier_label: String,
    issued_at: String,
    expires_at: String,
    is_lifetime: bool,
    features: Vec<String>,
    max_orgs_label: String,
    /// Non-empty when the current status is `Grace` or `Expired` — drives
    /// the colored banner at the top of the page.
    banner_kind: &'static str,
    banner_message: String,
    purchase_url: String,
}

pub(crate) async fn settings_license(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: crate::extractors::RequireAdmin,
    csrf: Csrf,
) -> Response {
    let secure = state.cfg.self_.is_https();
    let (flash_msg, clear_flash) = flash::take_flash(
        &headers,
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        "/admin/license",
        secure,
    );

    let status = state.license.status();
    let view = view_from_status(&status, &state, &flash_msg);

    let tpl = LicenseSettingsTemplate {
        chrome: PageChrome::from_parts(&state, admin.ctx.email, csrf.0),
        admin_active: AdminSection::License,
        flash: view.flash,
        state_label: view.state_label,
        has_license: view.has_license,
        customer: view.customer,
        email: view.email,
        tier_label: view.tier_label,
        issued_at: view.issued_at,
        expires_at: view.expires_at,
        is_lifetime: view.is_lifetime,
        features: view.features,
        max_orgs_label: view.max_orgs_label,
        banner_kind: view.banner_kind,
        banner_message: view.banner_message,
        purchase_url: view.purchase_url,
    };

    flash::attach_set_cookie(render(&tpl), clear_flash)
}

struct ViewData {
    flash: String,
    state_label: &'static str,
    has_license: bool,
    customer: String,
    email: String,
    tier_label: String,
    issued_at: String,
    expires_at: String,
    is_lifetime: bool,
    features: Vec<String>,
    max_orgs_label: String,
    banner_kind: &'static str,
    banner_message: String,
    purchase_url: String,
}

fn view_from_status(status: &LicenseStatus, state: &AppState, flash_msg: &str) -> ViewData {
    let purchase_url = upsell::effective_purchase_url(state);

    let (state_label, banner_kind, banner_message): (&'static str, &'static str, String) =
        match status {
            LicenseStatus::Unlicensed => ("Unlicensed", "", String::new()),
            LicenseStatus::Active(_) => ("Active", "", String::new()),
            LicenseStatus::Grace(l) => {
                let days_remaining = days_grace_remaining(l, state.license.grace_days());
                (
                    "Grace",
                    "warning",
                    format!(
                        "Your license expired but is still accepted for {days_remaining} more day{}. Renew before the grace period ends to keep premium features active.",
                        if days_remaining == 1 { "" } else { "s" }
                    ),
                )
            }
            LicenseStatus::Expired(_) => (
                "Expired",
                "danger",
                "Your license has expired and the grace period has ended. Premium features are locked until you renew.".into(),
            ),
        };

    if let Some(l) = status.license() {
        let features = l
            .features
            .iter()
            .map(|f| f.label().to_string())
            .collect::<Vec<_>>();
        ViewData {
            flash: flash_msg.to_string(),
            state_label,
            has_license: true,
            customer: l.customer.clone(),
            email: l.email.clone(),
            tier_label: "Business".to_string(),
            issued_at: l.issued_at.format("%Y-%m-%d").to_string(),
            expires_at: l
                .expires_at
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "Lifetime".into()),
            is_lifetime: l.expires_at.is_none(),
            features,
            max_orgs_label: l
                .max_orgs
                .map_or_else(|| "Unlimited".to_string(), |n| n.to_string()),
            banner_kind,
            banner_message,
            purchase_url,
        }
    } else {
        ViewData {
            flash: flash_msg.to_string(),
            state_label,
            has_license: false,
            customer: String::new(),
            email: String::new(),
            tier_label: String::new(),
            issued_at: String::new(),
            expires_at: String::new(),
            is_lifetime: false,
            features: Vec::new(),
            max_orgs_label: String::new(),
            banner_kind,
            banner_message,
            purchase_url,
        }
    }
}

fn days_grace_remaining(license: &crate::commercial::license::License, grace_days: i64) -> i64 {
    let now = chrono::Utc::now();
    let days_past = license
        .expires_at
        .map(|exp| (now - exp).num_days())
        .unwrap_or(0);
    (grace_days - days_past).max(0)
}

#[derive(Debug, Deserialize)]
struct ActivateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    blob: String,
}

async fn activate(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: crate::extractors::RequireAdmin,
    actx: AuditCtx,
    Form(form): Form<ActivateForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let actor_id = admin.ctx.identity_id;
    let actor_email = admin.ctx.email;

    let secure = state.cfg.self_.is_https();
    let (msg, ok, license_id, tier) = match verify::decode_and_verify(&form.blob) {
        Ok(license) => {
            let next = classify(
                license.clone(),
                state.license.grace_days(),
                chrono::Utc::now(),
            );
            match store::save(&state.db, &form.blob, &license).await {
                Ok(()) => {
                    state.license.swap(next);
                    (
                        "License activated.",
                        true,
                        license.license_id.clone(),
                        "business".to_string(),
                    )
                }
                Err(e) => {
                    tracing::error!(error = ?e, "license: persist failed");
                    (
                        "License signature verified, but we couldn't save it. Please try again.",
                        false,
                        String::new(),
                        String::new(),
                    )
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "license: activation rejected");
            (
                verify::user_message(&e),
                false,
                String::new(),
                String::new(),
            )
        }
    };

    if ok {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::LICENSE_ACTIVATED)
                .actor_user(&actor_id, &actor_email)
                .target(target_kind::LICENSE, license_id.clone())
                .with_ctx(&actx)
                .metadata(audit_metadata!("tier" => tier)),
        )
        .await;
    }

    let cookie = flash::store_flash(
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        "/admin/license",
        msg,
        secure,
    );
    flash::redirect_with_cookie("/admin/license", &cookie)
}

#[derive(Debug, Deserialize)]
struct DeactivateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

async fn deactivate(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: crate::extractors::RequireAdmin,
    actx: AuditCtx,
    Form(form): Form<DeactivateForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let actor_id = admin.ctx.identity_id;
    let actor_email = admin.ctx.email;
    let prior_id = state
        .license
        .status()
        .license()
        .map(|l| l.license_id.clone())
        .unwrap_or_default();

    let secure = state.cfg.self_.is_https();
    let (msg, ok) = match store::clear(&state.db).await {
        Ok(()) => {
            state.license.swap(LicenseStatus::Unlicensed);
            ("License deactivated.", true)
        }
        Err(e) => {
            tracing::error!(error = ?e, "license: deactivate failed");
            ("Could not deactivate the license. Please try again.", false)
        }
    };

    if ok && !prior_id.is_empty() {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::LICENSE_DEACTIVATED)
                .actor_user(&actor_id, &actor_email)
                .target(target_kind::LICENSE, prior_id)
                .with_ctx(&actx),
        )
        .await;
    }

    let cookie = flash::store_flash(
        &state.cookie_secret,
        state.cfg.flash.cookie_ttl_seconds,
        "/admin/license",
        msg,
        secure,
    );
    flash::redirect_with_cookie("/admin/license", &cookie)
}
