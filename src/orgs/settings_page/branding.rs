//! Branding page — logo URL + support email.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::extractors::{Csrf, RequireSession};
use crate::orgs::{self, Org};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::{
    build_nav, require_org_license, require_org_owner_with_license, resolve_org_or_404,
    settings_ctx, SettingsCtx,
};

#[derive(Template)]
#[template(path = "orgs/branding.html")]
struct BrandingTemplate {
    chrome: PageChrome,
    org: Org,
    is_default: bool,
    nav: orgs::nav::OrgNav,
}

pub(super) async fn branding(
    State(state): State<AppState>,
    slug: Option<String>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
) -> Response {
    let ctx = settings_ctx(&sess, &csrf);
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) = require_org_license(&state, &ctx.csrf_token, &ctx.user_email, &target.org.id) {
        return r;
    }
    render_branding(&state, &headers, &ctx, target.org).await
}

async fn render_branding(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &SettingsCtx,
    org: Org,
) -> Response {
    let nav = build_nav(state, headers, &ctx.identity_id).await;
    render(&BrandingTemplate {
        chrome: PageChrome::from_parts(state, ctx.user_email.clone(), ctx.csrf_token.clone()),
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        org,
        nav,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct BrandingForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    logo_url: String,
    support_email: String,
}

pub(super) async fn branding_save(
    State(state): State<AppState>,
    slug: Option<String>,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    Form(form): Form<BrandingForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let existing = target.org;
    let org_id = &existing.id;
    if let Err(r) =
        require_org_owner_with_license(&state, &csrf.0, &sess.identity_id, &sess.email, org_id)
            .await
    {
        return r;
    }
    let logo_url = form.logo_url.trim();
    let support_email = form.support_email.trim();

    // Validate logo_url: when present, must be a parseable https URL,
    // bounded in length, and not point at a loopback / RFC1918 / cloud
    // metadata host. Rejects `javascript:`, `data:`, `http://`, etc.;
    // also `https://169.254.169.254/...` and similar internal targets
    // because the browser fetches the value as `<img src>`, leaking
    // referer / cookies to an org-owner-chosen internal endpoint.
    // Re-uses `validate_webhook_url`'s private-IP filter so the rule
    // set stays in lockstep with the outbound-webhook SSRF guard.
    if !logo_url.is_empty() {
        if logo_url.len() > 2048 {
            return (
                StatusCode::BAD_REQUEST,
                "logo_url is too long (max 2048 chars)",
            )
                .into_response();
        }
        if let Err(e) = crate::webhook::validate_webhook_url(logo_url) {
            return (StatusCode::BAD_REQUEST, format!("logo_url rejected: {e}")).into_response();
        }
    }

    // Validate support_email: when present, basic shape check — exactly
    // one `@` with non-empty local + domain parts, total length ≤ 254
    // (RFC 5321 envelope cap), and no control / whitespace characters
    // anywhere in the string. Full RFC 5322 isn't needed for a display
    // field, but the control-char rejection closes a header-injection
    // shape in case the value is ever embedded into a `mailto:` or
    // email-header context.
    if !support_email.is_empty() {
        let bytes = support_email.as_bytes();
        let at_count = bytes.iter().filter(|b| **b == b'@').count();
        let has_bad_chars = support_email
            .chars()
            .any(|c| c.is_control() || c.is_whitespace());
        let valid = at_count == 1
            && support_email.len() <= 254
            && !has_bad_chars
            && support_email
                .split_once('@')
                .map(|(local, domain)| !local.is_empty() && !domain.is_empty())
                .unwrap_or(false);
        if !valid {
            return (
                StatusCode::BAD_REQUEST,
                "support_email is not a valid email",
            )
                .into_response();
        }
    }

    let logo_opt = if logo_url.is_empty() {
        None
    } else {
        Some(logo_url)
    };
    let email_opt = if support_email.is_empty() {
        None
    } else {
        Some(support_email)
    };
    if let Err(e) = orgs::update_branding(
        &state.db,
        org_id,
        &existing.name,
        &existing.slug,
        logo_opt,
        email_opt,
    )
    .await
    {
        tracing::error!(error = ?e, "branding_save: update_branding failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "save failed").into_response();
    }
    Redirect::to(&format!("{}/branding", target.base_path)).into_response()
}
