//! Branding page — logo URL + support email.

use askama::Template;
use axum::extract::{Multipart, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::config::BrandConfig;
use crate::csrf::CsrfForm;
use crate::extractors::{forbid_response, Csrf, RequireSession};
use crate::orgs::{self, logo, Org};
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::state::AppState;
use crate::theming::{self, color::parse_color, derive, image, TokenOverrides};

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
    presets: Vec<PresetView>,
    /// Echoed form fields: stored values on GET, just-submitted values on a
    /// validation-error re-render so nothing the user typed is lost.
    values: BrandingFormValues,
    /// Non-empty on a validation-error re-render; drives the red error banner.
    error: String,
    /// Non-empty after a successful save (PRG flash); drives the success banner.
    flash: String,
}

/// Form-field values the branding template echoes back into the inputs.
struct BrandingFormValues {
    logo_url: String,
    support_email: String,
    theme_preset: String,
    brand_primary: String,
    brand_on_primary: String,
    brand_secondary: String,
    public_login_enabled: bool,
}

impl BrandingFormValues {
    fn from_org(org: &Org) -> Self {
        Self {
            logo_url: org.logo_url.clone().unwrap_or_default(),
            support_email: org.support_email.clone().unwrap_or_default(),
            theme_preset: org.theme_preset.clone().unwrap_or_default(),
            brand_primary: org
                .brand_primary
                .clone()
                .unwrap_or_else(|| "#000000".to_string()),
            brand_on_primary: org
                .brand_on_primary
                .clone()
                .unwrap_or_else(|| "#ffffff".to_string()),
            brand_secondary: org
                .brand_secondary
                .clone()
                .unwrap_or_else(|| "#555f73".to_string()),
            public_login_enabled: org.public_login_enabled == 1,
        }
    }

    // Colour inputs require a valid hex; an empty submitted value falls back to
    // the same defaults the GET path uses.
    fn from_form(form: &BrandingForm) -> Self {
        let color = |v: &str, default: &str| {
            let v = v.trim();
            if v.is_empty() {
                default.to_string()
            } else {
                v.to_string()
            }
        };
        Self {
            logo_url: form.logo_url.trim().to_string(),
            support_email: form.support_email.trim().to_string(),
            theme_preset: form.theme_preset.trim().to_string(),
            brand_primary: color(&form.brand_primary, "#000000"),
            brand_on_primary: color(&form.brand_on_primary, "#ffffff"),
            brand_secondary: color(&form.brand_secondary, "#555f73"),
            public_login_enabled: form.request_public_login.is_some(),
        }
    }
}

struct PresetView {
    name: &'static str,
    primary: String,
    on_primary: String,
    secondary: String,
}

pub(super) async fn branding(
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
    if let Err(r) = require_org_license(&state, &ctx.csrf_token, &ctx.user_email, &target.org.id) {
        return r;
    }
    let (flash, clear_flash) =
        state.take_flash(&headers, &format!("{}/branding", target.base_path));
    let values = BrandingFormValues::from_org(&target.org);
    let resp = render_branding(
        &state,
        &headers,
        &ctx,
        target.org,
        &themed.memberships,
        themed.chrome,
        values,
        String::new(),
        flash,
    )
    .await;
    crate::flash::attach_set_cookie(resp, clear_flash)
}

#[allow(clippy::too_many_arguments)]
async fn render_branding(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &SettingsCtx,
    org: Org,
    memberships: &[orgs::Membership],
    chrome: PageChrome,
    values: BrandingFormValues,
    error: String,
    flash: String,
) -> Response {
    let nav = build_nav(state, headers, &ctx.identity_id, Some(memberships)).await;
    render(&BrandingTemplate {
        chrome,
        is_default: org.id == orgs::DEFAULT_ORG_ID,
        org,
        nav,
        values,
        error,
        flash,
        presets: theming::preset::ALL
            .iter()
            .map(|&n| {
                let p = crate::theming::preset::lookup(n);
                PresetView {
                    name: n,
                    primary: p.primary.as_str().to_string(),
                    on_primary: p.on_primary.as_str().to_string(),
                    secondary: p.secondary.as_str().to_string(),
                }
            })
            .collect(),
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

fn public_login_toggle_action(old: i32, new: i32) -> Option<&'static str> {
    match (old, new) {
        (0, 1) => Some(action::ORG_PUBLIC_LOGIN_ENABLED),
        (1, 0) => Some(action::ORG_PUBLIC_LOGIN_DISABLED),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn branding_save(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    headers: HeaderMap,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
    CsrfForm(form): CsrfForm<BrandingForm>,
) -> Response {
    let ctx = settings_ctx(&sess, &themed.chrome.csrf_token, locale);
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

    // Validate all user input up front. On the first failure re-render the
    // branding page with an error banner and the just-submitted values echoed
    // back, rather than a raw 400 text page that loses the user's input.
    let validated: Result<ThemeUpdate, String> = (|| {
        // logo_url renders as `<img src>`, so reject internal targets (loopback
        // / RFC1918 / cloud metadata) that would leak referer/cookies. Reuses
        // `validate_webhook_url`'s private-IP filter to stay in lockstep with
        // the outbound-webhook SSRF guard.
        if !logo_url.is_empty() {
            if logo_url.len() > 2048 {
                return Err("logo_url is too long (max 2048 chars)".to_string());
            }
            if let Err(e) = crate::webhook::validate_webhook_url(logo_url) {
                return Err(format!("logo_url rejected: {e}"));
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
                return Err("support_email is not a valid email".to_string());
            }
        }
        validate_theme_form(&form, &state.cfg.brand).map_err(str::to_string)
    })();
    let theme = match validated {
        Ok(t) => t,
        Err(msg) => {
            let mut resp = render_branding(
                &state,
                &headers,
                &ctx,
                existing,
                &themed.memberships,
                themed.chrome,
                BrandingFormValues::from_form(&form),
                msg,
                String::new(),
            )
            .await;
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return resp;
        }
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
    let logo_set = logo_opt.is_some();
    let support_email_set = email_opt.is_some();
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
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_BRANDING_UPDATED)
            .actor_user(sess.identity_id.as_str(), sess.email.as_str())
            .target(target_kind::ORG, org_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "theme_preset" => theme.preset.as_deref().unwrap_or("none"),
                "logo_set" => logo_set,
                "support_email_set" => support_email_set,
            )),
    )
    .await;
    if let Some(toggle_action) =
        public_login_toggle_action(existing.public_login_enabled, theme.public_login_enabled)
    {
        let _ = audit::log(
            &state.db,
            AuditEvent::new(toggle_action)
                .actor_user(sess.identity_id.as_str(), sess.email.as_str())
                .target(target_kind::ORG, org_id.clone())
                .with_ctx(&actx),
        )
        .await;
    }
    let target_url = format!("{}/branding", target.base_path);
    let msg = crate::i18n::lookup(&ctx.locale, "flash-branding-saved");
    state.flash_redirect(&target_url, &msg)
}

const MAX_LOGO_BYTES: usize = 256 * 1024;

fn validate_logo(bytes: &[u8]) -> Result<&'static str, &'static str> {
    if bytes.len() > MAX_LOGO_BYTES {
        return Err("logo file exceeds 256 KB");
    }
    image::detect(bytes).ok_or("unsupported image type")
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn logo_upload(
    State(state): State<AppState>,
    OrgSlug(slug): OrgSlug,
    sess: RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    headers: HeaderMap,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    mut multipart: Multipart,
) -> Response {
    let target = match resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let org_id = target.org.id.clone();
    if let Err(r) =
        require_org_owner_with_license(&state, &csrf.0, &sess.identity_id, &sess.email, &org_id)
            .await
    {
        return r;
    }

    let mut csrf_token = String::new();
    let mut remove = false;
    let mut logo_bytes: Option<Vec<u8>> = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => return (StatusCode::BAD_REQUEST, "malformed multipart body").into_response(),
        };
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "_csrf" => {
                csrf_token = field.text().await.unwrap_or_default();
            }
            "remove" => {
                remove = field.text().await.unwrap_or_default() == "1";
            }
            "logo" => {
                let mut field = field;
                let mut bytes = Vec::new();
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            bytes.extend_from_slice(&chunk);
                            if bytes.len() > MAX_LOGO_BYTES {
                                return (StatusCode::BAD_REQUEST, "logo file exceeds 256 KB")
                                    .into_response();
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            return (StatusCode::BAD_REQUEST, "malformed multipart body")
                                .into_response()
                        }
                    }
                }
                if !bytes.is_empty() {
                    logo_bytes = Some(bytes);
                }
            }
            _ => {}
        }
    }

    if !crate::csrf::verify_csrf(&headers, &csrf_token) {
        return forbid_response();
    }

    if remove {
        if let Err(e) = logo::delete(&state.db, &org_id).await {
            tracing::error!(error = ?e, "logo_upload: delete failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "remove failed").into_response();
        }
        state.logo_cache.lock().await.remove(&org_id);
        let _ = audit::log(
            &state.db,
            AuditEvent::new(action::ORG_LOGO_REMOVED)
                .actor_user(sess.identity_id.as_str(), sess.email.as_str())
                .target(target_kind::ORG, org_id.clone())
                .with_ctx(&actx),
        )
        .await;
        let target_url = format!("{}/branding", target.base_path);
        let msg = crate::i18n::lookup(&locale, "flash-logo-removed");
        return state.flash_redirect(&target_url, &msg);
    }

    let Some(bytes) = logo_bytes else {
        return (StatusCode::BAD_REQUEST, "no logo file provided").into_response();
    };
    let content_type = match validate_logo(&bytes) {
        Ok(ct) => ct,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let etag = logo::etag_of(&bytes);
    if let Err(e) = logo::upsert(&state.db, &org_id, bytes, content_type, &etag).await {
        tracing::error!(error = ?e, "logo_upload: upsert failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "save failed").into_response();
    }
    state.logo_cache.lock().await.remove(&org_id);

    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_LOGO_UPLOADED)
            .actor_user(sess.identity_id.as_str(), sess.email.as_str())
            .target(target_kind::ORG, org_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!("content_type" => content_type)),
    )
    .await;

    let target_url = format!("{}/branding", target.base_path);
    let msg = crate::i18n::lookup(&locale, "flash-logo-updated");
    state.flash_redirect(&target_url, &msg)
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
            operator_trust_anchor: None,
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
    fn public_login_toggle_action_detects_enable() {
        assert_eq!(
            public_login_toggle_action(0, 1),
            Some(action::ORG_PUBLIC_LOGIN_ENABLED)
        );
    }

    #[test]
    fn public_login_toggle_action_detects_disable() {
        assert_eq!(
            public_login_toggle_action(1, 0),
            Some(action::ORG_PUBLIC_LOGIN_DISABLED)
        );
    }

    #[test]
    fn public_login_toggle_action_none_when_unchanged() {
        assert_eq!(public_login_toggle_action(0, 0), None);
        assert_eq!(public_login_toggle_action(1, 1), None);
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

    #[test]
    fn validate_logo_accepts_small_png() {
        let mut png = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        png.extend_from_slice(&[0u8; 32]);
        assert_eq!(validate_logo(&png), Ok("image/png"));
    }

    #[test]
    fn validate_logo_rejects_oversize() {
        let mut png = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        png.resize(8 + MAX_LOGO_BYTES + 1, 0);
        let err = validate_logo(&png).unwrap_err();
        assert_eq!(err, "logo file exceeds 256 KB");
    }

    #[test]
    fn validate_logo_rejects_non_image() {
        let err = validate_logo(b"<svg xmlns=...>").unwrap_err();
        assert_eq!(err, "unsupported image type");
    }
}
