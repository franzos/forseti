//! Public, themed legal pages: `/privacy`, `/terms`, `/imprint`.
//!
//! Instance-level (the operator is the GDPR data controller), not per-org.
//! Each doc is markdown: shipped English defaults embedded at compile time,
//! overridable per-locale by the operator via files in `[legal].dir` named
//! `{doc}.{locale}.md` (e.g. `privacy.de.md`). Resolution falls back
//! locale -> `en` file -> embedded default.
//!
//! Rendering uses comrak with `unsafe_ = false` (its default), so raw HTML in
//! the operator's markdown is dropped rather than emitted. This app ships no
//! CSP `script-src` backstop (`build_csp` omits it so WebAuthn/QR forms work),
//! so that safe default is load-bearing and must never be flipped.

use std::path::Path;
use std::sync::OnceLock;

use askama::Template;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;

use crate::config::ProxyConfig;
use crate::locale::default_locale;
use crate::page_chrome::{Chrome, PageChrome};
use crate::rate_limit;
use crate::render::render;
use crate::state::AppState;

/// Generous per-IP + global limits; the common (`dir`-unset) path is a memoized
/// string clone, the override path a single small file read under
/// `spawn_blocking`. Fixed constants, no config knobs, to keep config minimal.
const IP_RATE_PER_MINUTE: u32 = 120;
const IP_RATE_PER_HOUR: u32 = 1_200;
const GLOBAL_RATE_PER_MINUTE: u32 = 600;
const GLOBAL_RATE_PER_HOUR: u32 = 6_000;

#[derive(Debug, Clone, Copy)]
pub(crate) enum LegalDoc {
    Privacy,
    Terms,
    Imprint,
}

impl LegalDoc {
    fn slug(self) -> &'static str {
        match self {
            LegalDoc::Privacy => "privacy",
            LegalDoc::Terms => "terms",
            LegalDoc::Imprint => "imprint",
        }
    }

    /// i18n key for the page title / footer link.
    fn title_key(self) -> &'static str {
        match self {
            LegalDoc::Privacy => "legal-privacy-title",
            LegalDoc::Terms => "legal-terms-title",
            LegalDoc::Imprint => "legal-imprint-title",
        }
    }

    fn embedded_default(self) -> &'static str {
        match self {
            LegalDoc::Privacy => include_str!("../assets/legal/privacy.en.md"),
            LegalDoc::Terms => include_str!("../assets/legal/terms.en.md"),
            LegalDoc::Imprint => include_str!("../assets/legal/imprint.en.md"),
        }
    }

    /// Rendered HTML of the embedded English default, memoized so the common
    /// path (no `[legal].dir` configured) parses each doc's markdown once.
    fn rendered_default(self) -> &'static str {
        static PRIVACY: OnceLock<String> = OnceLock::new();
        static TERMS: OnceLock<String> = OnceLock::new();
        static IMPRINT: OnceLock<String> = OnceLock::new();
        let cell = match self {
            LegalDoc::Privacy => &PRIVACY,
            LegalDoc::Terms => &TERMS,
            LegalDoc::Imprint => &IMPRINT,
        };
        cell.get_or_init(|| render_html(self.embedded_default()))
    }
}

/// Render trusted operator markdown to HTML. `unsafe_` stays false, so raw HTML
/// blocks/inlines are replaced with `<!-- raw HTML omitted -->` rather than
/// rendered — see the module docs on why that safe default is load-bearing.
fn render_html(md: &str) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    comrak::markdown_to_html(md, &options)
}

/// Resolve a doc's HTML for `lang`, reading operator overrides from `dir` when
/// set: `{slug}.{lang}.md`, then `{slug}.en.md`, then the embedded default.
/// `lang` is always one of the fixed `SUPPORTED` subtags (alphabetic, no path
/// separators), so it can't traverse out of `dir`.
fn resolve_html(dir: Option<&Path>, doc: LegalDoc, lang: &str) -> String {
    if let Some(dir) = dir {
        let default = default_locale();
        let default_lang = default.language.as_str();
        let candidates: &[&str] = if lang == default_lang {
            &[default_lang]
        } else {
            &[lang, default_lang]
        };
        for candidate in candidates {
            let path = dir.join(format!("{}.{candidate}.md", doc.slug()));
            if let Ok(md) = std::fs::read_to_string(&path) {
                return render_html(&md);
            }
        }
    }
    doc.rendered_default().to_string()
}

/// Build the body HTML, doing disk I/O only when an override dir is configured
/// (and then off the async runtime via `spawn_blocking`).
async fn body_html(state: &AppState, doc: LegalDoc, lang: &str) -> String {
    match state.cfg.legal.dir.clone() {
        None => doc.rendered_default().to_string(),
        Some(dir) => {
            let lang = lang.to_string();
            tokio::task::spawn_blocking(move || resolve_html(Some(Path::new(&dir)), doc, &lang))
                .await
                .unwrap_or_else(|_| doc.rendered_default().to_string())
        }
    }
}

#[derive(Template)]
#[template(path = "legal.html")]
struct LegalTemplate {
    chrome: PageChrome,
    title: String,
    /// comrak output (`unsafe_ = false`); safe to render with `|safe`.
    body_html: String,
}

async fn render_doc(state: &AppState, chrome: PageChrome, doc: LegalDoc) -> Response {
    let title = chrome.t(doc.title_key());
    let body_html = body_html(state, doc, chrome.locale.language.as_str()).await;
    render(&LegalTemplate {
        chrome,
        title,
        body_html,
    })
}

async fn privacy(State(state): State<AppState>, Chrome(chrome): Chrome) -> Response {
    render_doc(&state, chrome, LegalDoc::Privacy).await
}

async fn terms(State(state): State<AppState>, Chrome(chrome): Chrome) -> Response {
    render_doc(&state, chrome, LegalDoc::Terms).await
}

async fn imprint(State(state): State<AppState>, Chrome(chrome): Chrome) -> Response {
    render_doc(&state, chrome, LegalDoc::Imprint).await
}

pub(crate) fn router(proxy_cfg: &ProxyConfig) -> Router<AppState> {
    let r = Router::new()
        .route("/privacy", get(privacy))
        .route("/terms", get(terms))
        .route("/imprint", get(imprint));
    rate_limit::dual_window_with_global(
        r,
        proxy_cfg.trust_forwarded_for,
        IP_RATE_PER_MINUTE,
        IP_RATE_PER_HOUR,
        GLOBAL_RATE_PER_MINUTE,
        GLOBAL_RATE_PER_HOUR,
        rate_limit::plain_text_error("legal"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_defaults_render_nonempty_html() {
        for doc in [LegalDoc::Privacy, LegalDoc::Terms, LegalDoc::Imprint] {
            let html = doc.rendered_default();
            assert!(html.contains("<h1"), "{} lacks an <h1>", doc.slug());
        }
    }

    #[test]
    fn dir_unset_serves_embedded_default() {
        let html = resolve_html(None, LegalDoc::Privacy, "de");
        assert_eq!(html, LegalDoc::Privacy.rendered_default());
    }

    #[test]
    fn locale_file_wins_over_en_and_default() {
        let dir = tempdir();
        std::fs::write(dir.join("privacy.de.md"), "# Datenschutz DE").unwrap();
        std::fs::write(dir.join("privacy.en.md"), "# Privacy EN").unwrap();
        let html = resolve_html(Some(&dir), LegalDoc::Privacy, "de");
        assert!(html.contains("Datenschutz DE"));
        assert!(!html.contains("Privacy EN"));
        cleanup(&dir);
    }

    #[test]
    fn falls_back_to_en_file_when_locale_missing() {
        let dir = tempdir();
        std::fs::write(dir.join("terms.en.md"), "# Terms EN only").unwrap();
        let html = resolve_html(Some(&dir), LegalDoc::Terms, "fr");
        assert!(html.contains("Terms EN only"));
        cleanup(&dir);
    }

    #[test]
    fn falls_back_to_embedded_when_no_file_present() {
        let dir = tempdir();
        let html = resolve_html(Some(&dir), LegalDoc::Imprint, "de");
        assert_eq!(html, LegalDoc::Imprint.rendered_default());
        cleanup(&dir);
    }

    #[test]
    fn raw_html_in_markdown_is_dropped_not_executed() {
        let html = render_html("hello\n\n<script>alert(1)</script>\n");
        assert!(!html.contains("<script"));
        assert!(html.contains("<!-- raw HTML omitted -->"));
    }

    // Exercises the real render pipeline: legal.html -> base.html -> the footer
    // partial, with i18n lookups on a live PageChrome. Catches template/i18n
    // wiring breakage a resolver-only test can't.
    #[test]
    fn template_renders_with_chrome_and_footer_links() {
        let brand = crate::config::BrandConfig {
            name: "Test".into(),
            support_email: None,
            logo_url: None,
            consent_intro: String::new(),
            theme_preset: None,
            brand_primary: None,
            brand_on_primary: None,
            brand_secondary: None,
            operator_trust_anchor: None,
        };
        let chrome = PageChrome::from_brand_with_admin(
            brand,
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        );
        let title = chrome.t(LegalDoc::Privacy.title_key());
        let html = LegalTemplate {
            chrome,
            title,
            body_html: LegalDoc::Privacy.rendered_default().to_string(),
        }
        .render()
        .expect("legal template renders");
        assert!(html.contains("Privacy Policy"));
        assert!(html.contains("class=\"legal-content"));
        assert!(html.contains("href=\"/privacy\""));
        assert!(html.contains("href=\"/terms\""));
        assert!(html.contains("href=\"/imprint\""));
    }

    // Minimal temp-dir helper: the crate carries no tempdir dev-dep, and this
    // avoids Date/rand (unavailable in some sandboxes) by keying on the module
    // path plus a per-call counter.
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("forseti-legal-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}
