//! Kratos login flow handler.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::cookies;
use crate::csrf;
use crate::extractors::OptionalSession;
use crate::flow_view::*;
use crate::ory::kratos::FlowOutcome;
use crate::ory::{self, FlowKind};
use crate::page_chrome::{Chrome, PageChrome};
use crate::render::render;
use crate::state::AppState;
use crate::{FlowQuery, render_error_boundary, safe_return_to};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    chrome: PageChrome,
    form: FlowFormView,
    /// WebAuthn / passkey helper scripts; without the `<script>` tag the
    /// trigger buttons' `window.oryWebAuthnLogin` etc. are undefined.
    webauthn_scripts: Vec<ScriptView>,
    /// AAL2 requested but no second factor enrolled: Kratos returns the
    /// challenge message with no input nodes, so the template shows a CTA to
    /// `/settings/2fa` instead of a blank form.
    aal2_unavailable: bool,
    /// The OAuth client this sign-in continues to, when it is vouched for.
    continue_to_app: Option<String>,
    /// Re-authentication or step-up for a signed-in user: there's no
    /// account to create, so the page doesn't offer it.
    reauth: bool,
}

pub(crate) async fn login(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    session: OptionalSession,
    Chrome(chrome): Chrome,
) -> Response {
    let chrome = crate::theming::theme_chrome_for_org_id(
        &state.db,
        &state.cfg.brand,
        chrome,
        query.organization_id.as_deref(),
    )
    .await;
    let cookie = cookies::cookie_header(&headers);
    let requested_aal = query.aal.as_deref().filter(|s| !s.is_empty());
    let refresh = matches!(query.refresh, Some(true));

    // Already signed in: bounce to `return_to` unless a step-up (`aal`
    // mismatch) or privileged re-auth (`refresh=true`) is in progress. Without
    // these carve-outs the user loops between /oauth/login and /login, or
    // livelocks at `privileged_session_max_age`. Both fall through to the
    // Kratos init redirect with the params preserved.
    if let Some(session) = session.ok() {
        let session_aal = ory::kratos::session_aal_string(session);
        let aal_mismatch = requested_aal.map(|a| a != session_aal).unwrap_or(false);
        // A flow ID present means Kratos baked `refresh=true` into the flow's
        // server-side context (not the URL), so always render it.
        if !refresh && !aal_mismatch && query.flow.is_none() {
            let target = safe_return_to(&state.cfg, query.return_to.as_deref().unwrap_or("/"));
            return Redirect::to(target).into_response();
        }
    }

    // Sanitize before forwarding to Kratos; don't lean on its
    // `allowed_return_urls` alone.
    let safe_return = query
        .return_to
        .as_deref()
        .map(|rt| safe_return_to(&state.cfg, rt));

    let flow_id = query.flow.as_deref();
    let init_url = || {
        ory::kratos::browser_init_url_with(
            FlowKind::Login,
            &state.cfg.kratos.public_url,
            safe_return,
            requested_aal,
            query.refresh,
        )
    };

    let secure = state.cfg.self_.is_https();
    let query_hint = query
        .login_hint
        .as_deref()
        .and_then(crate::auth::email_login_hint);
    match ory::kratos::resolve_flow(&state.ory, FlowKind::Login, flow_id, &cookie).await {
        FlowOutcome::Init => {
            let mut resp = csrf::attach_csrf(
                Redirect::to(&init_url()).into_response(),
                Some(csrf::delete_csrf_cookie(secure)),
            );
            // Kratos's init hop drops our query; the hint rides a cookie.
            if let Some(hint) = query_hint {
                crate::web::append_set_cookie(
                    &mut resp,
                    Some(crate::auth::hint_cookie(
                        LOGIN_HINT_COOKIE,
                        "/login",
                        Some(hint),
                        secure,
                    )),
                );
            }
            resp
        }
        FlowOutcome::Ready(flow) => {
            let app = crate::auth::continuing_app_name(
                &state,
                query.return_to.as_deref().or_else(|| flow_return_to(&flow)),
            )
            .await;
            let cookie_hint = cookies::read_cookie(&headers, LOGIN_HINT_COOKIE);
            let hint = query_hint.map(str::to_string).or_else(|| {
                cookie_hint
                    .as_deref()
                    .and_then(crate::auth::decode_hint_cookie)
            });
            let mut resp = render_login(
                chrome,
                &flow,
                query.return_to.as_deref(),
                app,
                hint.as_deref(),
            );
            if cookie_hint.is_some() {
                crate::web::append_set_cookie(
                    &mut resp,
                    Some(crate::auth::hint_cookie(
                        LOGIN_HINT_COOKIE,
                        "/login",
                        None,
                        secure,
                    )),
                );
            }
            crate::app::allow_form_action_to(
                &mut resp,
                &crate::oidc_providers::flow_auth_origins(&flow),
            );
            resp
        }
        FlowOutcome::Reinit | FlowOutcome::Privileged(_) => {
            Redirect::to(&init_url()).into_response()
        }
        FlowOutcome::Error(e) => {
            tracing::error!(error = ?e, ?flow_id, "failed to fetch Kratos login flow");
            render_error_boundary(
                &state,
                &chrome.locale,
                &crate::i18n::lookup(&chrome.locale, "error-boundary-signin-title"),
                &crate::i18n::lookup(&chrome.locale, "error-boundary-auth-unavailable-body"),
                "/login",
                crate::i18n::lookup(&chrome.locale, "error-boundary-cta-try-again"),
            )
            .into_response()
        }
    }
}

/// One-shot cookie carrying an OIDC `login_hint` across Kratos's init hop.
pub(crate) const LOGIN_HINT_COOKIE: &str = "forseti_login_hint";

fn render_login(
    chrome: PageChrome,
    flow: &serde_json::Value,
    return_to: Option<&str>,
    continue_to_app: Option<String>,
    login_hint: Option<&str>,
) -> Response {
    let mut form = FlowFormView::from_flow(flow, FlowKind::Login, return_to, &chrome.locale);
    // Prefill, never overwrite: a value Kratos echoes back (a failed attempt)
    // is what the user typed.
    if let Some(hint) = login_hint {
        for group in [
            &mut form.groups.default,
            &mut form.groups.password,
            &mut form.groups.other,
        ] {
            for node in group.iter_mut() {
                if node.name == "identifier" && node.value.is_empty() {
                    node.value = hint.to_string();
                }
            }
        }
    }
    let webauthn_scripts = collect_webauthn_scripts(flow);

    // AAL2 requested but no second factor available: Kratos emits the
    // challenge message with no actionable input, so surface a CTA to enrol
    // 2FA instead of a blank form.
    let requested_aal2 = flow
        .get("requested_aal")
        .and_then(|v| v.as_str())
        .map(|s| s == "aal2")
        .unwrap_or(false);
    let any_actionable_method = !form.groups.oidc.is_empty()
        || !form.groups.code.is_empty()
        || !form.groups.password.is_empty()
        || form
            .groups
            .other
            .iter()
            .any(|n| n.input_type != "hidden" && n.name != "method");
    let aal2_unavailable = requested_aal2 && !any_actionable_method;
    let reauth = requested_aal2 || flow.get("refresh").and_then(|v| v.as_bool()) == Some(true);

    render(&LoginTemplate {
        chrome,
        form,
        webauthn_scripts,
        aal2_unavailable,
        continue_to_app,
        reauth,
    })
}

#[cfg(test)]
mod tests {
    use crate::config::BrandConfig;
    use crate::db::DbPool;
    use crate::page_chrome::PageChrome;
    use crate::theming::theme_chrome_for_org_id;
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

    const TEST_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

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

    #[tokio::test]
    async fn absent_org_id_leaves_global_theme() {
        let db = test_pool().await;
        let default_css = chrome().theme_css_root;
        let themed = theme_chrome_for_org_id(&db, &brand(), chrome(), None).await;
        assert_eq!(themed.theme_css_root, default_css);
    }

    #[tokio::test]
    async fn unknown_org_id_leaves_global_theme() {
        let db = test_pool().await;
        let default_css = chrome().theme_css_root;
        let themed = theme_chrome_for_org_id(&db, &brand(), chrome(), Some("nope")).await;
        assert_eq!(themed.theme_css_root, default_css);
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
        let themed = theme_chrome_for_org_id(&db, &brand(), chrome(), Some("o1")).await;
        assert_eq!(themed.theme_css_root, default_css);
    }

    #[tokio::test]
    async fn enabled_org_applies_public_branding() {
        let db = test_pool().await;
        crate::orgs::db::create_org(&db, "o1", "acme", "Acme", None)
            .await
            .expect("create_org");
        crate::orgs::db::update_theme(&db, "o1", Some("midnight"), Some("#123456"), None, None, 1)
            .await
            .expect("update_theme");

        let themed = theme_chrome_for_org_id(&db, &brand(), chrome(), Some("o1")).await;
        assert!(themed.theme_css_root.contains("#123456"));
    }
}
