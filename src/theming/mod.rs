pub mod brand_hint;
pub mod color;
pub mod derive;
pub mod image;
pub mod preset;

use color::Color;

#[derive(Debug, Clone, Default)]
pub struct TokenOverrides {
    pub preset: Option<String>,
    pub primary: Option<Color>,
    pub on_primary: Option<Color>,
    pub secondary: Option<Color>,
}

/// Invalid color strings become `None` rather than failing config load.
pub fn global_overrides(brand: &crate::config::BrandConfig) -> TokenOverrides {
    TokenOverrides {
        preset: brand.theme_preset.clone(),
        primary: brand.brand_primary.as_deref().and_then(color::parse_color),
        on_primary: brand
            .brand_on_primary
            .as_deref()
            .and_then(color::parse_color),
        secondary: brand
            .brand_secondary
            .as_deref()
            .and_then(color::parse_color),
    }
}

/// Re-parse an org's stored [`PublicBranding`](crate::orgs::db::PublicBranding)
/// colors into overrides. Single re-parse point shared by login, consent,
/// landing, and registration; invalid colors fail safe to `None` rather than
/// erroring, same as [`global_overrides`].
pub fn overrides_from_public(pb: &crate::orgs::db::PublicBranding) -> TokenOverrides {
    TokenOverrides {
        preset: pb.preset.clone(),
        primary: pb.primary.as_deref().and_then(color::parse_color),
        on_primary: pb.on_primary.as_deref().and_then(color::parse_color),
        secondary: pb.secondary.as_deref().and_then(color::parse_color),
    }
}

/// Re-parse a [`Membership`](crate::orgs::db::Membership)'s brand columns into
/// overrides for authenticated app chrome. Ungated: membership already proves
/// the caller belongs to the org, so `public_login_enabled` is irrelevant here.
pub fn overrides_from_membership(m: &crate::orgs::db::Membership) -> TokenOverrides {
    TokenOverrides {
        preset: m.theme_preset.clone(),
        primary: m.brand_primary.as_deref().and_then(color::parse_color),
        on_primary: m.brand_on_primary.as_deref().and_then(color::parse_color),
        secondary: m.brand_secondary.as_deref().and_then(color::parse_color),
    }
}

/// Re-parse an [`Org`](crate::orgs::db::Org)'s brand columns into overrides.
/// Ungated: the invite token itself is the authorization to see the target
/// org's brand, so no membership or opt-in check applies here.
pub fn overrides_from_org(org: &crate::orgs::db::Org) -> TokenOverrides {
    TokenOverrides {
        preset: org.theme_preset.clone(),
        primary: org.brand_primary.as_deref().and_then(color::parse_color),
        on_primary: org.brand_on_primary.as_deref().and_then(color::parse_color),
        secondary: org.brand_secondary.as_deref().and_then(color::parse_color),
    }
}

/// Theme `chrome` by the caller's active org, resolved strictly through
/// [`active_org`](crate::orgs::active_org) against the real membership slice.
/// The signed cookie is never used as a branding key on its own: a cookie
/// naming a non-member org falls back to the first membership, and the Default
/// org never themes the app.
pub fn apply_active_org_theme(
    chrome: crate::page_chrome::PageChrome,
    brand: &crate::config::BrandConfig,
    cookie_secret: &[u8],
    cookie_ttl_secs: u64,
    memberships: &[crate::orgs::db::Membership],
    headers: &axum::http::HeaderMap,
) -> crate::page_chrome::PageChrome {
    let Some(m) = crate::orgs::active_org(memberships, cookie_secret, cookie_ttl_secs, headers)
    else {
        return chrome;
    };
    if m.org_id == crate::orgs::DEFAULT_ORG_ID {
        return chrome;
    }
    let chrome = chrome.with_theme(resolve(
        &overrides_from_membership(&m),
        &global_overrides(brand),
    ));
    if m.has_logo == 1 {
        chrome.with_logo_slug(m.slug)
    } else {
        chrome
    }
}

/// Apply an org's public branding to a chrome, falling back to the global
/// theme wherever the org left a token unset. Also points the card icon at
/// the org's uploaded logo, if any.
pub fn theme_chrome_for_org(
    chrome: crate::page_chrome::PageChrome,
    brand: &crate::config::BrandConfig,
    pb: &crate::orgs::db::PublicBranding,
) -> crate::page_chrome::PageChrome {
    let chrome = chrome.with_theme(resolve(
        &overrides_from_public(pb),
        &global_overrides(brand),
    ));
    if pb.has_logo != 0 {
        chrome.with_logo_slug(pb.slug.clone())
    } else {
        chrome
    }
}

/// Look up `org_id`'s public branding and apply it to `chrome`, falling back
/// to the global theme when absent, unknown, or not opted in (enabled).
/// Shared by `/login` and `/oauth/consent` so both fail safe identically;
/// the gated reader is the only source of truth for opt-in.
pub async fn theme_chrome_for_org_id(
    db: &crate::db::DbPool,
    brand: &crate::config::BrandConfig,
    chrome: crate::page_chrome::PageChrome,
    org_id: Option<&str>,
) -> crate::page_chrome::PageChrome {
    let Some(org_id) = org_id.filter(|id| !id.is_empty()) else {
        return chrome;
    };
    match crate::orgs::db::public_branding_by_id(db, org_id).await {
        Ok(Some(pb)) => theme_chrome_for_org(chrome, brand, &pb),
        Ok(None) => chrome,
        Err(e) => {
            tracing::warn!(error = ?e, organization_id = org_id, "theming: public_branding_by_id failed; using global theme");
            chrome
        }
    }
}

pub struct ResolvedTheme {
    pub primary: Color,
    pub on_primary: Color,
    pub secondary: Color,
    pub primary_dark: Color,
    pub on_primary_dark: Color,
    pub secondary_dark: Color,
}

pub fn resolve(tenant: &TokenOverrides, global: &TokenOverrides) -> ResolvedTheme {
    let preset_name = tenant
        .preset
        .as_deref()
        .or(global.preset.as_deref())
        .unwrap_or("default");
    let base = preset::lookup(preset_name);
    let pick = |t: &Option<Color>, g: &Option<Color>, b: &Color| {
        t.clone().or_else(|| g.clone()).unwrap_or_else(|| b.clone())
    };
    let primary = pick(&tenant.primary, &global.primary, &base.primary);
    let on_primary = pick(&tenant.on_primary, &global.on_primary, &base.on_primary);
    let secondary = pick(&tenant.secondary, &global.secondary, &base.secondary);
    let primary_dark = derive::derive_dark_variant(&primary).unwrap_or_else(|| primary.clone());
    let secondary_dark =
        derive::derive_dark_variant(&secondary).unwrap_or_else(|| secondary.clone());
    let on_primary_dark = derive::derive_on_color(&primary_dark);
    ResolvedTheme {
        on_primary_dark,
        primary,
        on_primary,
        secondary,
        primary_dark,
        secondary_dark,
    }
}

impl ResolvedTheme {
    pub fn css_root(&self) -> String {
        format!(
            "--brand-primary:{};--brand-on-primary:{};--brand-secondary:{};",
            self.primary.as_str(),
            self.on_primary.as_str(),
            self.secondary.as_str()
        )
    }

    pub fn css_dark(&self) -> String {
        format!(
            "--brand-primary:{};--brand-on-primary:{};--brand-secondary:{};",
            self.primary_dark.as_str(),
            self.on_primary_dark.as_str(),
            self.secondary_dark.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theming::color::parse_color;

    fn ov(preset: Option<&str>, primary: Option<&str>) -> TokenOverrides {
        TokenOverrides {
            preset: preset.map(str::to_string),
            primary: primary.and_then(parse_color),
            on_primary: None,
            secondary: None,
        }
    }

    #[test]
    fn tenant_primary_wins_over_global_and_preset() {
        let r = resolve(
            &ov(None, Some("#123456")),
            &ov(Some("midnight"), Some("#abcdef")),
        );
        assert_eq!(r.primary.as_str(), "#123456");
    }

    #[test]
    fn falls_back_to_preset_then_default() {
        let r = resolve(&ov(Some("cyberpunk"), None), &ov(None, None));
        assert_eq!(
            r.primary.as_str(),
            preset::lookup("cyberpunk").primary.as_str()
        );
        let d = resolve(&ov(None, None), &ov(None, None));
        assert_eq!(
            d.primary.as_str(),
            preset::lookup("default").primary.as_str()
        );
    }

    #[test]
    fn css_blocks_emit_brand_vars() {
        let r = resolve(&ov(Some("cyberpunk"), None), &ov(None, None));
        assert!(r.css_root().contains("--brand-primary:"));
        assert!(r.css_dark().contains("--brand-primary:"));
    }

    #[test]
    fn all_builtin_presets_meet_aa_on_their_own_pair() {
        use crate::theming::derive::{contrast_ratio, to_rgb};
        for name in preset::ALL {
            let p = preset::lookup(name);
            let ratio = contrast_ratio(to_rgb(&p.primary).unwrap(), to_rgb(&p.on_primary).unwrap());
            assert!(
                ratio >= 4.5,
                "preset {name} primary/on-primary contrast {ratio} < 4.5"
            );
        }
    }

    #[test]
    fn global_overrides_validates_colors() {
        use crate::config::BrandConfig;

        let brand = BrandConfig {
            name: String::new(),
            support_email: None,
            logo_url: None,
            consent_intro: String::new(),
            theme_preset: None,
            brand_primary: Some("#123456".to_string()),
            brand_on_primary: None,
            brand_secondary: None,
            operator_trust_anchor: None,
        };
        let overrides = global_overrides(&brand);
        assert_eq!(overrides.primary, parse_color("#123456"));

        let invalid = BrandConfig {
            brand_primary: Some("red;}".to_string()),
            ..brand
        };
        assert_eq!(global_overrides(&invalid).primary, None);
    }

    #[test]
    fn overrides_from_public_validates_colors() {
        use crate::orgs::db::PublicBranding;

        let pb = PublicBranding {
            name: "Acme".to_string(),
            slug: "acme".to_string(),
            preset: Some("midnight".to_string()),
            primary: Some("#123456".to_string()),
            on_primary: None,
            secondary: Some("red;}".to_string()),
            has_logo: 0,
            access_mode: "internal".to_string(),
        };
        let overrides = overrides_from_public(&pb);
        assert_eq!(overrides.preset.as_deref(), Some("midnight"));
        assert_eq!(overrides.primary, parse_color("#123456"));
        assert_eq!(overrides.on_primary, None);
        assert_eq!(overrides.secondary, None);
    }

    fn membership(
        org_id: &str,
        slug: &str,
        primary: Option<&str>,
        has_logo: i32,
    ) -> crate::orgs::db::Membership {
        crate::orgs::db::Membership {
            org_id: org_id.to_string(),
            slug: slug.to_string(),
            name: slug.to_string(),
            role: "owner".to_string(),
            theme_preset: None,
            brand_primary: primary.map(str::to_string),
            brand_on_primary: None,
            brand_secondary: None,
            has_logo,
        }
    }

    fn brand_with_primary(primary: &str) -> crate::config::BrandConfig {
        crate::config::BrandConfig {
            name: String::new(),
            support_email: None,
            logo_url: None,
            consent_intro: String::new(),
            theme_preset: None,
            brand_primary: Some(primary.to_string()),
            brand_on_primary: None,
            brand_secondary: None,
            operator_trust_anchor: None,
        }
    }

    fn base_chrome(brand: &crate::config::BrandConfig) -> crate::page_chrome::PageChrome {
        crate::page_chrome::PageChrome::from_brand_with_admin(
            brand.clone(),
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        )
    }

    fn headers_active_org(org_id: &str, secret: &[u8], ttl: u64) -> axum::http::HeaderMap {
        let sc = crate::orgs::cookie::set_active_org_cookie(secret, ttl, org_id, false);
        let value = sc.split_once('=').unwrap().1.split(';').next().unwrap();
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            format!("forseti_active_org={value}").parse().unwrap(),
        );
        h
    }

    const THEME_SECRET: &[u8] = b"themed-chrome-test-secret";
    const THEME_TTL: u64 = 3600;

    #[test]
    fn overrides_from_membership_validates_colors() {
        let m = membership("o", "acme", Some("#123456"), 1);
        let m = crate::orgs::db::Membership {
            theme_preset: Some("midnight".to_string()),
            brand_secondary: Some("red;}".to_string()),
            ..m
        };
        let o = overrides_from_membership(&m);
        assert_eq!(o.preset.as_deref(), Some("midnight"));
        assert_eq!(o.primary, parse_color("#123456"));
        assert_eq!(o.on_primary, None);
        assert_eq!(o.secondary, None);
    }

    #[test]
    fn overrides_from_org_validates_colors() {
        use crate::orgs::db::Org;

        let org = Org {
            id: "o".to_string(),
            slug: "acme".to_string(),
            name: "Acme".to_string(),
            logo_url: None,
            support_email: None,
            created_at: String::new(),
            created_by: None,
            member_visibility: "members".to_string(),
            theme_preset: Some("midnight".to_string()),
            brand_primary: Some("#123456".to_string()),
            brand_on_primary: None,
            brand_secondary: Some("red;}".to_string()),
            public_login_enabled: 0,
            has_logo: 0,
            access_mode: "internal".to_string(),
            domain_join_policy: "invite_only".to_string(),
        };
        let o = overrides_from_org(&org);
        assert_eq!(o.preset.as_deref(), Some("midnight"));
        assert_eq!(o.primary, parse_color("#123456"));
        assert_eq!(o.on_primary, None);
        assert_eq!(o.secondary, None);
    }

    #[test]
    fn signed_nonmember_cookie_does_not_leak_branding() {
        let brand = brand_with_primary("#010203");
        let global_css = base_chrome(&brand).theme_css_root.clone();

        // The active-org cookie is validly signed but names an org the caller
        // is not a member of; the only membership is the Default org.
        let memberships = vec![membership(crate::orgs::DEFAULT_ORG_ID, "default", None, 0)];
        let headers = headers_active_org("evil-org", THEME_SECRET, THEME_TTL);
        let themed = apply_active_org_theme(
            base_chrome(&brand),
            &brand,
            THEME_SECRET,
            THEME_TTL,
            &memberships,
            &headers,
        );

        // What the chrome WOULD look like had the cookie's org been honoured.
        let leaked = apply_active_org_theme(
            base_chrome(&brand),
            &brand,
            THEME_SECRET,
            THEME_TTL,
            &[membership("evil-org", "evil", Some("#ff00ff"), 1)],
            &headers,
        );

        assert_eq!(themed.theme_css_root, global_css);
        assert!(themed.theme_css_root.contains("#010203"));
        assert_ne!(themed.theme_css_root, leaked.theme_css_root);
        assert!(themed.logo_slug.is_none());
    }

    #[test]
    fn default_org_active_uses_global_theme() {
        let brand = brand_with_primary("#010203");
        let global_css = base_chrome(&brand).theme_css_root.clone();
        // Default org carries brand columns yet must never theme the app.
        let memberships = vec![membership(
            crate::orgs::DEFAULT_ORG_ID,
            "default",
            Some("#ff00ff"),
            1,
        )];
        let headers = headers_active_org(crate::orgs::DEFAULT_ORG_ID, THEME_SECRET, THEME_TTL);
        let themed = apply_active_org_theme(
            base_chrome(&brand),
            &brand,
            THEME_SECRET,
            THEME_TTL,
            &memberships,
            &headers,
        );
        assert_eq!(themed.theme_css_root, global_css);
        assert!(themed.logo_slug.is_none());
    }

    #[test]
    fn nondefault_member_themes_and_sets_logo() {
        let brand = brand_with_primary("#010203");
        let memberships = vec![membership("acme", "acme", Some("#abcdef"), 1)];
        let headers = headers_active_org("acme", THEME_SECRET, THEME_TTL);
        let themed = apply_active_org_theme(
            base_chrome(&brand),
            &brand,
            THEME_SECRET,
            THEME_TTL,
            &memberships,
            &headers,
        );
        assert!(themed.theme_css_root.contains("#abcdef"));
        assert_eq!(themed.logo_slug.as_deref(), Some("acme"));
    }

    #[test]
    fn nondefault_member_without_logo_leaves_slug_unset() {
        let brand = brand_with_primary("#010203");
        let memberships = vec![membership("acme", "acme", Some("#abcdef"), 0)];
        let headers = headers_active_org("acme", THEME_SECRET, THEME_TTL);
        let themed = apply_active_org_theme(
            base_chrome(&brand),
            &brand,
            THEME_SECRET,
            THEME_TTL,
            &memberships,
            &headers,
        );
        assert!(themed.theme_css_root.contains("#abcdef"));
        assert!(themed.logo_slug.is_none());
    }

    #[test]
    fn all_builtin_presets_meet_aa_on_dark_pair() {
        use crate::theming::derive::{contrast_ratio, to_rgb};
        for name in preset::ALL {
            let r = resolve(
                &TokenOverrides {
                    preset: Some(name.to_string()),
                    ..Default::default()
                },
                &TokenOverrides::default(),
            );
            let ratio = contrast_ratio(
                to_rgb(&r.primary_dark).unwrap(),
                to_rgb(&r.on_primary_dark).unwrap(),
            );
            assert!(
                ratio >= 4.5,
                "preset {name} dark pair contrast {ratio} < 4.5"
            );
        }
    }
}
