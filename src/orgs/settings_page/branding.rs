//! Branding page — logo URL + support email.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::config::BrandConfig;
use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, RequireSession};
use crate::orgs::{self, Org};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;
use crate::theming::{self, color::parse_color, derive, TokenOverrides};

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
    presets: &'static [&'static str],
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
        presets: theming::preset::ALL,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct BrandingForm {
    logo_url: String,
    support_email: String,
    theme_preset: String,
    brand_primary: String,
    brand_on_primary: String,
    brand_secondary: String,
    request_public_login: Option<String>,
}

/// Validated theme fields ready for `orgs::db::update_theme`.
#[derive(Debug)]
struct ThemeUpdate {
    preset: Option<String>,
    primary: Option<String>,
    on_primary: Option<String>,
    secondary: Option<String>,
    public_login_enabled: i32,
}

// Resolved pair, not submitted pair, so a preset-fallback on-primary is still contrast-checked.
fn validate_theme_form(
    form: &BrandingForm,
    brand: &BrandConfig,
) -> Result<ThemeUpdate, &'static str> {
    let preset_raw = form.theme_preset.trim();
    let preset = if preset_raw.is_empty() {
        None
    } else if theming::preset::ALL.contains(&preset_raw) {
        Some(preset_raw.to_string())
    } else {
        return Err("unknown theme preset");
    };

    // Require rgb-able (hex/rgb) colors: hsl parses but to_rgb can't, which would skip the
    // contrast gate and dark-variant derivation.
    let color_field = |raw: &str,
                       bad: &'static str,
                       kind: &'static str|
     -> Result<Option<String>, &'static str> {
        let v = raw.trim();
        if v.is_empty() {
            return Ok(None);
        }
        let Some(color) = parse_color(v) else {
            return Err(bad);
        };
        if derive::to_rgb(&color).is_none() {
            return Err(kind);
        }
        Ok(Some(v.to_string()))
    };
    let primary = color_field(
        &form.brand_primary,
        "brand_primary is not a valid color",
        "brand_primary must be a hex or rgb() color",
    )?;
    let on_primary = color_field(
        &form.brand_on_primary,
        "brand_on_primary is not a valid color",
        "brand_on_primary must be a hex or rgb() color",
    )?;
    let secondary = color_field(
        &form.brand_secondary,
        "brand_secondary is not a valid color",
        "brand_secondary must be a hex or rgb() color",
    )?;

    let tenant_overrides = TokenOverrides {
        preset: preset.clone(),
        primary: primary.as_deref().and_then(parse_color),
        on_primary: on_primary.as_deref().and_then(parse_color),
        secondary: secondary.as_deref().and_then(parse_color),
    };
    let resolved = theming::resolve(&tenant_overrides, &theming::global_overrides(brand));
    if let (Some(p), Some(o)) = (
        derive::to_rgb(&resolved.primary),
        derive::to_rgb(&resolved.on_primary),
    ) {
        if derive::contrast_ratio(p, o) < 4.5 {
            return Err("primary / text-on-primary contrast is too low (min 4.5:1)");
        }
    }

    let public_login_enabled = i32::from(form.request_public_login.is_some());
    Ok(ThemeUpdate {
        preset,
        primary,
        on_primary,
        secondary,
        public_login_enabled,
    })
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

    let theme = match validate_theme_form(&form, &state.cfg.brand) {
        Ok(t) => t,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

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
    if let Err(e) = orgs::db::update_theme(
        &state.db,
        org_id,
        theme.preset.as_deref(),
        theme.primary.as_deref(),
        theme.on_primary.as_deref(),
        theme.secondary.as_deref(),
        theme.public_login_enabled,
    )
    .await
    {
        tracing::error!(error = ?e, "branding_save: update_theme failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "save failed").into_response();
    }
    Redirect::to(&format!("{}/branding", target.base_path)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brand() -> BrandConfig {
        BrandConfig {
            name: String::new(),
            support_email: None,
            logo_url: None,
            consent_intro: String::new(),
            theme_preset: None,
            brand_primary: None,
            brand_on_primary: None,
            brand_secondary: None,
        }
    }

    fn form(
        preset: &str,
        primary: &str,
        on_primary: &str,
        secondary: &str,
        request_public_login: Option<&str>,
    ) -> BrandingForm {
        BrandingForm {
            logo_url: String::new(),
            support_email: String::new(),
            theme_preset: preset.to_string(),
            brand_primary: primary.to_string(),
            brand_on_primary: on_primary.to_string(),
            brand_secondary: secondary.to_string(),
            request_public_login: request_public_login.map(str::to_string),
        }
    }

    #[test]
    fn valid_colors_and_preset_pass_validation() {
        let f = form("midnight", "#123456", "#ffffff", "", None);
        let t = validate_theme_form(&f, &brand()).expect("should validate");
        assert_eq!(t.preset.as_deref(), Some("midnight"));
        assert_eq!(t.primary.as_deref(), Some("#123456"));
        assert_eq!(t.on_primary.as_deref(), Some("#ffffff"));
        assert_eq!(t.secondary, None);
        assert_eq!(t.public_login_enabled, 0);
    }

    #[test]
    fn empty_fields_all_become_none() {
        let f = form("", "", "", "", None);
        let t = validate_theme_form(&f, &brand()).expect("empty fields are allowed");
        assert_eq!(t.preset, None);
        assert_eq!(t.primary, None);
        assert_eq!(t.on_primary, None);
        assert_eq!(t.secondary, None);
    }

    #[test]
    fn invalid_color_is_rejected() {
        let f = form("", "not-a-color", "", "", None);
        let err = validate_theme_form(&f, &brand()).unwrap_err();
        assert_eq!(err, "brand_primary is not a valid color");
    }

    #[test]
    fn hsl_color_is_rejected_as_non_rgb_able() {
        let f = form("", "hsl(0,0%,100%)", "", "", None);
        let err = validate_theme_form(&f, &brand()).unwrap_err();
        assert_eq!(err, "brand_primary must be a hex or rgb() color");
    }

    #[test]
    fn unknown_preset_is_rejected() {
        let f = form("no-such-preset", "", "", "", None);
        let err = validate_theme_form(&f, &brand()).unwrap_err();
        assert_eq!(err, "unknown theme preset");
    }

    #[test]
    fn low_contrast_resolved_pair_is_rejected() {
        let f = form("", "#ffffff", "#ffffff", "", None);
        let err = validate_theme_form(&f, &brand()).unwrap_err();
        assert_eq!(
            err,
            "primary / text-on-primary contrast is too low (min 4.5:1)"
        );
    }

    #[test]
    fn primary_only_is_checked_against_resolved_preset_on_primary() {
        let f = form("default", "#fefefe", "", "", None);
        let err = validate_theme_form(&f, &brand()).unwrap_err();
        assert_eq!(
            err,
            "primary / text-on-primary contrast is too low (min 4.5:1)"
        );
    }

    #[test]
    fn request_public_login_present_sets_enabled_flag() {
        let f = form("", "", "", "", Some("on"));
        let t = validate_theme_form(&f, &brand()).expect("should validate");
        assert_eq!(t.public_login_enabled, 1);
    }

    #[test]
    fn request_public_login_absent_leaves_enabled_at_zero() {
        let f = form("", "", "", "", None);
        let t = validate_theme_form(&f, &brand()).expect("should validate");
        assert_eq!(t.public_login_enabled, 0);
    }
}
