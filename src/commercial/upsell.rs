//! Shared upsell template for gated features.
//!
//! Any call site that wants to soft-gate a feature (return the upsell
//! page instead of rendering the real handler) calls [`render_upsell`]
//! with the matched [`Feature`]. The template surfaces the feature
//! name, required tier, current license status (so we don't tell a
//! "Pro" customer to buy "Pro" again), and a CTA pointing at
//! `license.purchase_url`.
//!
//! The lock-badge partial (`partials/lock_badge.html`) consumes the same
//! data shape so navigation chrome stays consistent with the full
//! upsell page.

use askama::Template;
use axum::response::Response;

use crate::commercial::license::{Feature, LicenseStatus};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "commercial/upsell.html")]
struct UpsellTemplate {
    chrome: PageChrome,
    feature_label: String,
    required_tier_label: String,
    current_tier_label: String,
    purchase_url: String,
    /// True when the operator already holds a license that simply
    /// doesn't include this feature. Drives "Upgrade your plan" copy vs.
    /// "Get a license" copy.
    has_license: bool,
}

/// Build the upsell response for `feature`. Pass the request's CSRF token
/// so the top-nav logout form on the rendered page carries a valid token.
pub fn render_upsell(
    state: &AppState,
    csrf_token: &str,
    user_email: &str,
    feature: Feature,
) -> Response {
    const TIER_LABEL: &str = "Business";
    let status = state.license.status();
    let has_license = !matches!(*status, LicenseStatus::Unlicensed);
    let purchase_url = effective_purchase_url(state);

    render(&UpsellTemplate {
        chrome: PageChrome::from_parts(state, user_email.to_string(), csrf_token.to_string()),
        feature_label: feature.label().to_string(),
        required_tier_label: TIER_LABEL.to_string(),
        current_tier_label: TIER_LABEL.to_string(),
        purchase_url,
        has_license,
    })
}

/// Resolve `license.purchase_url` with the support-email fallback so the
/// template can render an actionable CTA even on a Forseti deployment that hasn't
/// configured a sales URL.
pub fn effective_purchase_url(state: &AppState) -> String {
    let cfg = &state.cfg.license;
    if !cfg.purchase_url.is_empty() {
        return cfg.purchase_url.clone();
    }
    if let Some(email) = &state.cfg.brand.support_email {
        if !email.is_empty() {
            return format!("mailto:{email}?subject=forseti%20commercial%20license");
        }
    }
    // Nothing configured. Render an inert "#" link rather than a broken
    // mailto — operators see the upsell page works but no destination
    // is set.
    "#".to_string()
}
