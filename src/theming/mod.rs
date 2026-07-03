pub mod brand_hint;
pub mod color;
pub mod derive;
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

/// Apply an org's public branding to a chrome, falling back to the global
/// theme wherever the org left a token unset.
pub fn theme_chrome_for_org(
    chrome: crate::page_chrome::PageChrome,
    brand: &crate::config::BrandConfig,
    pb: &crate::orgs::db::PublicBranding,
) -> crate::page_chrome::PageChrome {
    chrome.with_theme(resolve(
        &overrides_from_public(pb),
        &global_overrides(brand),
    ))
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
            preset: Some("midnight".to_string()),
            primary: Some("#123456".to_string()),
            on_primary: None,
            secondary: Some("red;}".to_string()),
        };
        let overrides = overrides_from_public(&pb);
        assert_eq!(overrides.preset.as_deref(), Some("midnight"));
        assert_eq!(overrides.primary, parse_color("#123456"));
        assert_eq!(overrides.on_primary, None);
        assert_eq!(overrides.secondary, None);
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
