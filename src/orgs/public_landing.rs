//! Public, themed landing page at `GET /o/{slug}` for orgs that opted into
//! public login (enabled). Unknown or disabled slugs render the
//! byte-identical global-theme fallback so the route can't be used to
//! enumerate orgs.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::Response;

use crate::config::BrandConfig;
use crate::db::DbPool;
use crate::orgs::db::public_branding_by_slug;
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::theming::{brand_hint::set_brand_hint, theme_chrome_for_org};

#[derive(Template)]
#[template(path = "orgs/public_landing.html")]
struct PublicLandingTemplate {
    chrome: PageChrome,
    /// `Some(org name)` when the slug resolved to an opted-in org; `None`
    /// (operator brand, no org-specific text) for unknown/disabled slugs.
    org_name: Option<String>,
}

/// Resolve the landing decision for `slug`: themed chrome + org name +
/// brand-hint cookie value when opted-in (enabled), otherwise the
/// untouched global-theme chrome with no cookie. Split out from [`landing`]
/// so the anti-enumeration branch is unit-testable without a full router.
async fn resolve(
    db: &DbPool,
    brand: &BrandConfig,
    cookie_secret: &[u8],
    secure: bool,
    slug: &str,
    chrome: PageChrome,
) -> (PageChrome, Option<String>, Option<String>) {
    match public_branding_by_slug(db, slug).await {
        Ok(Some(pb)) => {
            let org_name = pb.name.clone();
            let chrome = theme_chrome_for_org(chrome, brand, &pb);
            let cookie = set_brand_hint(cookie_secret, slug, secure);
            (chrome, Some(org_name), Some(cookie))
        }
        Ok(None) => (chrome, None, None),
        Err(e) => {
            tracing::warn!(error = ?e, slug, "public_landing: public_branding_by_slug failed; using global theme");
            (chrome, None, None)
        }
    }
}

pub(crate) async fn landing(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Chrome(chrome): Chrome,
) -> Response {
    let (chrome, org_name, cookie) = resolve(
        &state.db,
        &state.cfg.brand,
        &state.cookie_secret,
        state.cfg.self_.is_https(),
        &slug,
        chrome,
    )
    .await;
    let mut resp = render(&PublicLandingTemplate { chrome, org_name });
    if let Some(cookie) = cookie {
        if let Ok(v) = axum::http::HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    const TEST_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
    const SECRET: &[u8] = b"public-landing-test-secret";

    /// Single-connection `:memory:` pool, mirroring `orgs::db`'s test helper.
    async fn test_pool() -> DbPool {
        use deadpool_diesel::sqlite::{Manager, Pool, Runtime};
        let manager = Manager::new(":memory:", Runtime::Tokio1);
        let pool = Pool::builder(manager)
            .max_size(1)
            .build()
            .expect("build test sqlite pool");
        let conn = pool.get().await.expect("get test conn");
        conn.interact(|c: &mut diesel::sqlite::SqliteConnection| {
            c.run_pending_migrations(TEST_MIGRATIONS).map(|_| ())
        })
        .await
        .expect("interact panic")
        .expect("run test migrations");
        DbPool::Sqlite(pool)
    }

    fn brand() -> BrandConfig {
        BrandConfig {
            name: "Forseti".to_string(),
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

    fn chrome() -> PageChrome {
        PageChrome::from_brand_with_admin(
            brand(),
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn unknown_slug_yields_global_theme_no_org_name_no_cookie() {
        let db = test_pool().await;
        let default_css = chrome().theme_css_root;
        let (chrome, org_name, cookie) =
            resolve(&db, &brand(), SECRET, false, "nope", chrome()).await;
        assert_eq!(chrome.theme_css_root, default_css);
        assert!(org_name.is_none());
        assert!(cookie.is_none());
    }

    #[tokio::test]
    async fn disabled_slug_matches_unknown_slug_exactly() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .expect("create_org");
        crate::orgs::db::update_theme(&db, "o1", Some("midnight"), Some("#123456"), None, None, 0)
            .await
            .expect("update_theme");

        let unknown = resolve(&db, &brand(), SECRET, false, "nope", chrome()).await;
        let disabled = resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;

        assert_eq!(unknown.0.theme_css_root, disabled.0.theme_css_root);
        assert_eq!(unknown.0.theme_css_dark, disabled.0.theme_css_dark);
        assert_eq!(unknown.1, disabled.1);
        assert_eq!(unknown.2, disabled.2);
        assert!(disabled.1.is_none());
        assert!(disabled.2.is_none());
    }

    #[tokio::test]
    async fn enabled_slug_yields_org_theme_name_and_cookie() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme Corp", None)
            .await
            .expect("create_org");
        crate::orgs::db::update_theme(&db, "o1", Some("midnight"), Some("#123456"), None, None, 1)
            .await
            .expect("update_theme");

        let (chrome, org_name, cookie) =
            resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;

        assert!(chrome.theme_css_root.contains("#123456"));
        assert_eq!(org_name.as_deref(), Some("Acme Corp"));
        let cookie = cookie.expect("brand-hint cookie set for enabled org");
        assert!(cookie.starts_with("forseti_brand_hint="));
        assert!(cookie.contains("Path=/registration"));
        assert!(chrome.logo_slug.is_none());
    }

    #[tokio::test]
    async fn enabled_slug_with_logo_sets_logo_slug() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme Corp", None)
            .await
            .expect("create_org");
        crate::orgs::db::update_theme(&db, "o1", Some("midnight"), Some("#123456"), None, None, 1)
            .await
            .expect("update_theme");
        crate::orgs::logo::upsert(&db, "o1", b"fake-png".to_vec(), "image/png", "\"etag\"")
            .await
            .expect("upsert logo");

        let (chrome, _, _) = resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;

        assert_eq!(chrome.logo_slug.as_deref(), Some("acme"));
    }

    #[tokio::test]
    async fn enabled_slug_without_logo_leaves_logo_slug_none() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme Corp", None)
            .await
            .expect("create_org");
        crate::orgs::db::update_theme(&db, "o1", Some("midnight"), Some("#123456"), None, None, 1)
            .await
            .expect("update_theme");

        let (chrome, _, _) = resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;

        assert!(chrome.logo_slug.is_none());
    }
}
