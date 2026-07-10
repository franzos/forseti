//! Display names and inline brand marks for upstream OIDC providers. Kratos
//! passes the raw provider id (e.g. `github`) with no display label or icon, so
//! login buttons and the linked-providers page resolve both here. Resolve to
//! concrete strings in Rust; templates never call these directly.

/// Human-facing provider name. Known ids get their canonical casing; unknown
/// ids fall back to a first-letter capitalisation of the id.
pub(crate) fn display_name(provider_id: &str) -> String {
    match provider_id {
        "github" => "GitHub".to_string(),
        "google" => "Google".to_string(),
        "microsoft" => "Microsoft".to_string(),
        "gitlab" => "GitLab".to_string(),
        "apple" => "Apple".to_string(),
        "facebook" => "Facebook".to_string(),
        other => capitalize_first(other),
    }
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Inline 18x18 brand mark for a provider, monochrome via `fill="currentColor"`
/// so it tracks the surrounding text colour. Unknown ids get a generic globe.
pub(crate) fn icon_svg(provider_id: &str) -> &'static str {
    match provider_id {
        "github" => GITHUB,
        "google" => GOOGLE,
        "microsoft" => MICROSOFT,
        _ => FALLBACK,
    }
}

const GITHUB: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>"#;

const GOOGLE: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12.24 10.4v3.32h4.62c-.2 1.2-.83 2.22-1.77 2.9v2.4h2.86c1.68-1.55 2.65-3.83 2.65-6.54 0-.63-.06-1.24-.16-1.82H12.24z"/><path d="M12.24 21c2.4 0 4.41-.8 5.88-2.16l-2.86-2.22c-.8.54-1.82.86-3.02.86-2.32 0-4.29-1.57-4.99-3.68H4.29v2.31C5.75 18.98 8.77 21 12.24 21z"/><path d="M7.25 13.8a5.4 5.4 0 0 1 0-3.44V8.05H4.29A8.96 8.96 0 0 0 3.34 12c0 1.45.35 2.82.95 4.03l2.96-2.23z"/><path d="M12.24 6.58c1.31 0 2.48.45 3.4 1.33l2.54-2.54C16.65 3.9 14.64 3 12.24 3 8.77 3 5.75 5.02 4.29 7.97l2.96 2.31c.7-2.11 2.67-3.7 4.99-3.7z"/></svg>"#;

const MICROSOFT: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M3 3h8.5v8.5H3V3zm9.5 0H21v8.5h-8.5V3zM3 12.5h8.5V21H3v-8.5zm9.5 0H21V21h-8.5v-8.5z"/></svg>"#;

const FALLBACK: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_known_ids() {
        assert_eq!(display_name("github"), "GitHub");
        assert_eq!(display_name("google"), "Google");
        assert_eq!(display_name("microsoft"), "Microsoft");
    }

    #[test]
    fn display_name_unknown_capitalises_first() {
        assert_eq!(display_name("okta"), "Okta");
        assert_eq!(display_name(""), "");
    }

    #[test]
    fn icon_svg_known_and_fallback() {
        assert_eq!(icon_svg("github"), GITHUB);
        // Unknown provider gets the generic globe mark.
        assert_eq!(icon_svg("okta"), FALLBACK);
    }
}
