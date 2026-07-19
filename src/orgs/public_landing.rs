//! Public, themed landing page at `GET /o/{slug}` for orgs that opted into
//! public login (enabled). Unknown or disabled slugs render the
//! byte-identical global-theme fallback so the route can't be used to
//! enumerate orgs.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;

use crate::config::{BrandConfig, OrgsConfig, ProxyConfig};
use crate::db::DbPool;
use crate::orgs::db::public_branding_by_slug;
use crate::orgs::parse_access_mode;
use crate::ory;
use crate::page_chrome::{Chrome, PageChrome};
use crate::rate_limit;
use crate::render::render;
use crate::state::AppState;
use crate::theming::{brand_hint::set_brand_hint, theme_chrome_for_org};

const DEFAULT_REGISTER_HREF: &str = "/registration";

/// Per-IP rate-limit defaults for `GET /o/{slug}`, used when
/// `[orgs].landing_ip_rate_per_*` is unset.
const DEFAULT_LANDING_IP_RATE_PER_MINUTE: u32 = 60;
const DEFAULT_LANDING_IP_RATE_PER_HOUR: u32 = 600;
/// Global (all-callers-share-one-bucket) defaults, shared across every slug.
const DEFAULT_LANDING_GLOBAL_RATE_PER_MINUTE: u32 = 300;
const DEFAULT_LANDING_GLOBAL_RATE_PER_HOUR: u32 = 3000;

pub(crate) fn router(orgs_cfg: &OrgsConfig, proxy_cfg: &ProxyConfig) -> Router<AppState> {
    let r = Router::new().route("/o/{slug}", get(landing));

    let per_minute = orgs_cfg
        .landing_ip_rate_per_minute
        .unwrap_or(DEFAULT_LANDING_IP_RATE_PER_MINUTE);
    let per_hour = orgs_cfg
        .landing_ip_rate_per_hour
        .unwrap_or(DEFAULT_LANDING_IP_RATE_PER_HOUR);
    let global_per_minute = orgs_cfg
        .landing_global_rate_per_minute
        .unwrap_or(DEFAULT_LANDING_GLOBAL_RATE_PER_MINUTE);
    let global_per_hour = orgs_cfg
        .landing_global_rate_per_hour
        .unwrap_or(DEFAULT_LANDING_GLOBAL_RATE_PER_HOUR);

    rate_limit::dual_window_with_global(
        r,
        proxy_cfg.trust_forwarded_for,
        per_minute,
        per_hour,
        global_per_minute,
        global_per_hour,
        rate_limit::plain_text_error("public_landing"),
    )
}

#[derive(Template)]
#[template(path = "orgs/public_landing.html")]
struct PublicLandingTemplate {
    chrome: PageChrome,
    /// `Some(org name)` when the slug resolved to an opted-in org; `None`
    /// (operator brand, no org-specific text) for unknown/disabled slugs.
    org_name: Option<String>,
    /// Registration CTA href: bound to `/join/confirm?org=<slug>` via Kratos
    /// registration when `slug` resolves live, else the plain link.
    register_href: String,
    /// Sign-in CTA, present only for a resolved (branded) org; `None` keeps the
    /// unknown/disabled fallback byte-identical.
    login_href: Option<String>,
}

/// Branded-login link for the landing page: `/login?organization_id=<slug>`.
/// The slug is accepted by the login pin (id-or-slug), so `/login` themes for
/// this org and returning members log in there.
fn login_href(slug: &str) -> String {
    format!(
        "/login?organization_id={}",
        ory_client::apis::urlencode(slug)
    )
}

/// Bind the registration CTA to `/join/confirm?org=<slug>` when `slug`
/// resolves to a live external+enabled org (`is_signup_org`); else the plain
/// `/registration` link (unchanged for internal orgs). The external+enabled
/// decision is taken from the branding row already fetched in [`resolve`], so
/// this never issues a second query.
fn register_href(
    self_url: &str,
    kratos_public_url: &str,
    slug: &str,
    is_signup_org: bool,
) -> String {
    if !is_signup_org {
        return DEFAULT_REGISTER_HREF.to_string();
    }
    let return_to = format!(
        "{}/join/confirm?org={}",
        self_url.trim_end_matches('/'),
        ory_client::apis::urlencode(slug)
    );
    ory::kratos::browser_init_url(
        ory::FlowKind::Registration,
        kratos_public_url,
        Some(&return_to),
    )
}

/// Resolve the landing decision for `slug`: themed chrome + org name +
/// brand-hint cookie value when opted-in (enabled), otherwise the
/// untouched global-theme chrome with no cookie. Split out from [`landing`]
/// so the anti-enumeration branch is unit-testable without a full router.
/// Returns `(chrome, org_name, brand_hint_cookie, is_signup_org)`.
/// `public_branding_by_slug` only returns a row for opted-in (enabled) orgs, so
/// a `Some` row that is `external` is exactly an external+enabled signup org.
async fn resolve(
    db: &DbPool,
    brand: &BrandConfig,
    cookie_secret: &[u8],
    secure: bool,
    slug: &str,
    chrome: PageChrome,
) -> (PageChrome, Option<String>, Option<String>, bool) {
    match public_branding_by_slug(db, slug).await {
        Ok(Some(pb)) => {
            let org_name = pb.name.clone();
            let is_signup_org = parse_access_mode(&pb.access_mode).is_external();
            let chrome = theme_chrome_for_org(chrome, brand, &pb);
            let cookie = set_brand_hint(cookie_secret, slug, secure);
            (chrome, Some(org_name), Some(cookie), is_signup_org)
        }
        Ok(None) => (chrome, None, None, false),
        Err(e) => {
            tracing::warn!(error = ?e, slug, "public_landing: public_branding_by_slug failed; using global theme");
            (chrome, None, None, false)
        }
    }
}

pub(crate) async fn landing(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Chrome(chrome): Chrome,
) -> Response {
    let (chrome, org_name, cookie, is_signup_org) = resolve(
        &state.db,
        &state.cfg.brand,
        &state.cookie_secret,
        state.cfg.self_.is_https(),
        &slug,
        chrome,
    )
    .await;
    let register_href = register_href(
        &state.cfg.self_.url,
        &state.cfg.kratos.public_url,
        &slug,
        is_signup_org,
    );
    let login_href = org_name.as_ref().map(|_| login_href(&slug));
    let mut resp = render(&PublicLandingTemplate {
        chrome,
        org_name,
        register_href,
        login_href,
    });
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
        let (chrome, org_name, cookie, _) =
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

        let (chrome, org_name, cookie, _) =
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

        let (chrome, _, _, _) = resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;

        assert_eq!(chrome.logo_slug.as_deref(), Some("acme"));
    }

    #[tokio::test]
    async fn external_enabled_slug_binds_register_href_to_join_confirm() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        crate::orgs::db::update_theme(&db, "o1", None, None, None, None, 1)
            .await
            .unwrap();
        crate::orgs::db::set_access_mode(&db, "o1", crate::orgs::AccessMode::External)
            .await
            .unwrap();
        let (_, _, _, is_signup_org) =
            resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;
        assert!(is_signup_org);
        let href = register_href(
            "http://localhost:3000",
            "http://kratos:4433",
            "acme",
            is_signup_org,
        );
        assert!(href.contains("return_to="));
        assert!(href.contains(&ory_client::apis::urlencode(
            "http://localhost:3000/join/confirm?org=acme"
        )));
    }

    #[tokio::test]
    async fn internal_slug_keeps_plain_registration_href() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .unwrap();
        crate::orgs::db::update_theme(&db, "o1", None, None, None, None, 1)
            .await
            .unwrap();
        let (_, _, _, is_signup_org) =
            resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;
        assert!(!is_signup_org);
        assert_eq!(
            register_href(
                "http://localhost:3000",
                "http://kratos:4433",
                "acme",
                is_signup_org,
            ),
            DEFAULT_REGISTER_HREF
        );
    }

    #[test]
    fn login_href_points_at_branded_login_by_slug() {
        assert_eq!(super::login_href("acme"), "/login?organization_id=acme");
        // ory_client::apis::urlencode is form-urlencoded (matches oauth/login.rs's use), so space -> `+`.
        assert_eq!(super::login_href("a b"), "/login?organization_id=a+b");
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

        let (chrome, _, _, _) = resolve(&db, &brand(), SECRET, false, "acme", chrome()).await;

        assert!(chrome.logo_slug.is_none());
    }
}
