//! Forseti-owned appearance preference (System / Light / Dark).
//!
//! Stored in a plain (unsigned) `forseti_theme` cookie: a forged value only
//! changes the viewer's own palette, so there is no integrity requirement.
//! Read server-side into `PageChrome` and rendered onto `<html>` so explicit
//! Light/Dark never flash. Written client-side by `static/theme.js`.

use axum::http::HeaderMap;

const THEME_COOKIE: &str = "forseti_theme";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ThemePref {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePref {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ThemePref::System => "system",
            ThemePref::Light => "light",
            ThemePref::Dark => "dark",
        }
    }

    /// Class applied to `<html>`. Only Dark needs the class; Light and System
    /// render no class (System is resolved client-side against the OS).
    pub(crate) fn css_class(self) -> &'static str {
        match self {
            ThemePref::Dark => "dark",
            _ => "",
        }
    }

    fn from_str(s: &str) -> ThemePref {
        match s {
            "light" => ThemePref::Light,
            "dark" => ThemePref::Dark,
            _ => ThemePref::System,
        }
    }

    // Template active-state checks (Askama can't reference enum variants).
    pub(crate) fn is_system(self) -> bool {
        self == ThemePref::System
    }
    pub(crate) fn is_light(self) -> bool {
        self == ThemePref::Light
    }
    pub(crate) fn is_dark(self) -> bool {
        self == ThemePref::Dark
    }
}

/// Read the theme cookie, defaulting to `System` when absent/unknown.
pub(crate) fn read_theme_cookie(headers: &HeaderMap) -> ThemePref {
    crate::cookies::read_cookie(headers, THEME_COOKIE)
        .map(|v| ThemePref::from_str(&v))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, format!("forseti_theme={value}").parse().unwrap());
        h
    }

    #[test]
    fn from_str_round_trips_and_defaults() {
        assert_eq!(ThemePref::from_str("light"), ThemePref::Light);
        assert_eq!(ThemePref::from_str("dark"), ThemePref::Dark);
        assert_eq!(ThemePref::from_str("system"), ThemePref::System);
        assert_eq!(ThemePref::from_str("garbage"), ThemePref::System);
        assert_eq!(ThemePref::Dark.as_str(), "dark");
    }

    #[test]
    fn css_class_only_for_dark() {
        assert_eq!(ThemePref::Dark.css_class(), "dark");
        assert_eq!(ThemePref::Light.css_class(), "");
        assert_eq!(ThemePref::System.css_class(), "");
    }

    #[test]
    fn read_cookie_parses_and_defaults() {
        assert_eq!(read_theme_cookie(&headers_with("dark")), ThemePref::Dark);
        assert_eq!(
            read_theme_cookie(&headers_with("nonsense")),
            ThemePref::System
        );
        assert_eq!(read_theme_cookie(&HeaderMap::new()), ThemePref::System);
    }
}
