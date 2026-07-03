//! Kratos registration flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::cookies;
use crate::csrf;
use crate::extractors::OptionalSession;
use crate::flow_view::*;
use crate::ory::kratos::FlowOutcome;
use crate::ory::{self, FlowKind};
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{render_error_boundary, safe_return_to, FlowQuery};

#[derive(Debug, Deserialize)]
pub(crate) struct PrefillQuery {
    pub(crate) prefill_email: Option<String>,
}

#[derive(Template)]
#[template(path = "registration.html")]
struct RegistrationTemplate {
    chrome: PageChrome,
    form: FlowFormView,
    /// WebAuthn / passkey helper script; without it the passkey enrollment
    /// button's `window.oryPasskeyRegistration` is undefined.
    webauthn_scripts: Vec<ScriptView>,
}

pub(crate) async fn registration(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    Query(prefill): Query<PrefillQuery>,
    headers: HeaderMap,
    session: OptionalSession,
    Chrome(chrome): Chrome,
) -> Response {
    let chrome = apply_brand_hint(
        &state.db,
        &state.cfg.brand,
        &state.cookie_secret,
        &headers,
        chrome,
    )
    .await;
    let cookie = cookies::cookie_header(&headers);
    // Explicit ?prefill_email= wins over the one-shot cookie dropped by
    // /claim-email/confirm, which we clear on render.
    let prefill_email = prefill
        .prefill_email
        .or_else(|| cookies::read_cookie(&headers, "forseti_prefill_email"));

    // Already-authenticated sessions skip /registration. An InsufficientAal
    // session routes through /login?aal=aal2 instead of landing on a protected
    // page (e.g. /admin/*) with an AAL1 session.
    match session {
        OptionalSession::Ok { .. } => {
            let target = safe_return_to(&state.cfg, query.return_to.as_deref().unwrap_or("/"));
            return Redirect::to(target).into_response();
        }
        OptionalSession::InsufficientAal => {
            let target = safe_return_to(&state.cfg, query.return_to.as_deref().unwrap_or("/"));
            return Redirect::to(&crate::auth::aal2_step_up_url(target)).into_response();
        }
        OptionalSession::None => {}
    }

    let flow_id = query.flow.as_deref();
    let init_url = || {
        ory::kratos::browser_init_url(
            FlowKind::Registration,
            &state.cfg.kratos.public_url,
            query.return_to.as_deref(),
        )
    };

    match ory::kratos::resolve_flow(&state.ory, FlowKind::Registration, flow_id, &cookie).await {
        FlowOutcome::Init => {
            let secure = state.cfg.self_.is_https();
            csrf::attach_csrf(
                Redirect::to(&init_url()).into_response(),
                Some(csrf::delete_csrf_cookie(secure)),
            )
        }
        FlowOutcome::Ready(flow) => {
            let mut resp = render_registration(
                chrome,
                &flow,
                query.return_to.as_deref(),
                prefill_email.as_deref(),
            );
            if prefill_email.is_some() {
                attach_prefill_clear_cookie(&mut resp, state.cfg.self_.is_https());
            }
            resp
        }
        FlowOutcome::Reinit | FlowOutcome::Privileged(_) => {
            Redirect::to(&init_url()).into_response()
        }
        FlowOutcome::Error(e) => {
            tracing::error!(error = ?e, ?flow_id, "failed to fetch Kratos registration flow");
            render_error_boundary(
                &state,
                &chrome.locale,
                &crate::i18n::lookup(&chrome.locale, "error-boundary-signup-title"),
                &crate::i18n::lookup(&chrome.locale, "error-boundary-auth-unavailable-body"),
                "/registration",
                crate::i18n::lookup(&chrome.locale, "error-boundary-cta-try-again"),
            )
            .into_response()
        }
    }
}

// Fail-safe: any missing/invalid step leaves the global theme.
async fn apply_brand_hint(
    db: &crate::db::DbPool,
    brand: &crate::config::BrandConfig,
    cookie_secret: &[u8],
    headers: &HeaderMap,
    chrome: PageChrome,
) -> PageChrome {
    let Some(slug) = crate::theming::brand_hint::read_brand_hint(headers, cookie_secret) else {
        return chrome;
    };
    match crate::orgs::db::public_branding_by_slug(db, &slug).await {
        Ok(Some(pb)) => crate::theming::theme_chrome_for_org(chrome, brand, &pb),
        _ => chrome,
    }
}

/// Clear the one-shot prefill cookie from `/claim-email/confirm`.
fn attach_prefill_clear_cookie(resp: &mut Response, secure: bool) {
    let secure_attr = if secure { "; Secure" } else { "" };
    let header = format!(
        "forseti_prefill_email=; Path=/registration; Max-Age=0; HttpOnly; SameSite=Lax{secure_attr}"
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&header) {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
}

fn render_registration(
    chrome: PageChrome,
    flow: &serde_json::Value,
    return_to: Option<&str>,
    prefill_email: Option<&str>,
) -> Response {
    let mut form = FlowFormView::from_flow(flow, FlowKind::Registration, return_to, &chrome.locale);
    // Overwrite the empty `traits.email` Kratos persists on flow init rather
    // than re-initialising the flow. Only mutates `value`, so the already-computed
    // `has_visible_default` (keyed on `input_type`) is unaffected.
    if let Some(email) = prefill_email.filter(|s| !s.is_empty()) {
        for group in [
            &mut form.groups.profile,
            &mut form.groups.password,
            &mut form.groups.default,
        ] {
            for node in group.iter_mut() {
                if node.name == "traits.email" && node.value.is_empty() {
                    node.value = email.to_string();
                }
            }
        }
    }
    let webauthn_scripts = collect_webauthn_scripts(flow);

    render(&RegistrationTemplate {
        chrome,
        form,
        webauthn_scripts,
    })
}

#[cfg(test)]
mod tests {
    use super::apply_brand_hint;
    use crate::config::BrandConfig;
    use crate::db::DbPool;
    use crate::page_chrome::PageChrome;
    use crate::theming::brand_hint::set_brand_hint;
    use axum::http::{header::COOKIE, HeaderMap};
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    const TEST_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
    const SECRET: &[u8] = b"registration-brand-hint-test-secret";

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

    fn chrome() -> PageChrome {
        PageChrome::from_brand_with_admin(
            brand(),
            String::new(),
            String::new(),
            false,
            "en".parse().unwrap(),
        )
    }

    fn headers_with_brand_hint(slug: &str) -> HeaderMap {
        let set_cookie = set_brand_hint(SECRET, slug, false);
        let value = set_cookie
            .split_once('=')
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            format!("forseti_brand_hint={value}").parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn enabled_org_brand_hint_applies_theme() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .expect("create_org");
        crate::orgs::db::update_theme(&db, "o1", Some("midnight"), Some("#123456"), None, None, 1)
            .await
            .expect("update_theme");

        let headers = headers_with_brand_hint("acme");
        let themed = apply_brand_hint(&db, &brand(), SECRET, &headers, chrome()).await;
        assert!(themed.theme_css_root.contains("#123456"));
    }

    #[tokio::test]
    async fn disabled_org_leaves_global_theme() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .expect("create_org");
        crate::orgs::db::update_theme(&db, "o1", Some("midnight"), Some("#123456"), None, None, 0)
            .await
            .expect("update_theme");

        let default_css = chrome().theme_css_root;
        let headers = headers_with_brand_hint("acme");
        let themed = apply_brand_hint(&db, &brand(), SECRET, &headers, chrome()).await;
        assert_eq!(themed.theme_css_root, default_css);
    }

    #[tokio::test]
    async fn unknown_slug_leaves_global_theme() {
        let db = test_pool().await;
        let default_css = chrome().theme_css_root;
        let headers = headers_with_brand_hint("nope");
        let themed = apply_brand_hint(&db, &brand(), SECRET, &headers, chrome()).await;
        assert_eq!(themed.theme_css_root, default_css);
    }

    #[tokio::test]
    async fn absent_cookie_leaves_global_theme() {
        let db = test_pool().await;
        let default_css = chrome().theme_css_root;
        let themed = apply_brand_hint(&db, &brand(), SECRET, &HeaderMap::new(), chrome()).await;
        assert_eq!(themed.theme_css_root, default_css);
    }
}
