//! Branding page — logo URL + support email.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, RequireSession};
use crate::orgs::{self, Org};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

use super::{
    build_nav, require_org_license, require_org_owner_with_license, resolve_org_or_404,
    settings_ctx, OrgSlug, SettingsCtx,
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
    OrgSlug(slug): OrgSlug,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    let ctx = settings_ctx(&sess, &csrf, locale);
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
        chrome: PageChrome::from_parts(
            state,
            ctx.user_email.clone(),
            ctx.csrf_token.clone(),
            ctx.locale.clone(),
        ),
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        org,
        nav,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct BrandingForm {
    logo_url: String,
    support_email: String,
}

pub(super) async fn branding_save(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    sess: RequireSession,
    csrf: Csrf,
    CsrfForm(form): CsrfForm<BrandingForm>,
) -> Response {
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

    // logo_url renders as `<img src>`, so reject internal targets (loopback /
    // RFC1918 / cloud metadata) that would leak referer/cookies. Reuses
    // `validate_webhook_url`'s private-IP filter to stay in lockstep with the
    // outbound-webhook SSRF guard.
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

    // Basic shape check (one `@`, non-empty parts, <= 254). The control-char
    // rejection closes a header-injection shape if the value ever lands in a
    // `mailto:` or email header.
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
