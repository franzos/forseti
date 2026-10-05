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
use crate::{FlowQuery, render_error_boundary, safe_return_to};

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
    /// The OAuth client this sign-up continues to, when it is vouched for.
    continue_to_app: Option<String>,
    /// Second step of the two-step flow: the address is in, a credential is
    /// being chosen. Kratos marks it with a `screen=previous` back button.
    credential_step: bool,
    /// Provider that signed the user in without a verified address Forseti
    /// will take, leaving Kratos asking for one.
    oidc_email_needed: Option<String>,
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

    let secure = state.cfg.self_.is_https();
    let query_hint = query
        .login_hint
        .as_deref()
        .and_then(crate::auth::email_login_hint);
    let hint_cookie_name = crate::auth::login::LOGIN_HINT_COOKIE;
    match ory::kratos::resolve_flow(&state.ory, FlowKind::Registration, flow_id, &cookie).await {
        FlowOutcome::Init => {
            let mut resp = csrf::attach_csrf(
                Redirect::to(&init_url()).into_response(),
                Some(csrf::delete_csrf_cookie(secure)),
            );
            if let Some(hint) = query_hint {
                crate::web::append_set_cookie(
                    &mut resp,
                    Some(crate::auth::hint_cookie(
                        hint_cookie_name,
                        "/registration",
                        Some(hint),
                        secure,
                    )),
                );
            }
            resp
        }
        FlowOutcome::Ready(flow) => {
            let return_to = query.return_to.as_deref().or_else(|| flow_return_to(&flow));
            let cookie_hint = cookies::read_cookie(&headers, hint_cookie_name);
            // An OIDC `login_hint` is the weakest source: an explicit prefill
            // or the invite's address wins.
            let prefill_email = match prefill_email {
                Some(email) => Some(email),
                None => invited_email(&state, return_to).await,
            }
            .or_else(|| query_hint.map(str::to_string))
            .or_else(|| {
                cookie_hint
                    .as_deref()
                    .and_then(crate::auth::decode_hint_cookie)
            });
            let app = crate::auth::continuing_app_name(
                &state,
                query.return_to.as_deref().or_else(|| flow_return_to(&flow)),
            )
            .await;
            let mut resp = render_registration(
                chrome,
                &flow,
                query.return_to.as_deref(),
                prefill_email.as_deref(),
                app,
            );
            if prefill_email.is_some() {
                attach_prefill_clear_cookie(&mut resp, secure);
            }
            if cookie_hint.is_some() {
                crate::web::append_set_cookie(
                    &mut resp,
                    Some(crate::auth::hint_cookie(
                        hint_cookie_name,
                        "/registration",
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

/// The invited address, when this sign-up is on its way to accept an open
/// invite (`return_to` = `/invite/finalize?token=…`). Read from the invite
/// row rather than carried in a cookie, so it can't outlive that one sign-up.
async fn invited_email(state: &AppState, return_to: Option<&str>) -> Option<String> {
    let token = invite_token_in(&state.cfg, return_to?)?;
    let invite = crate::orgs::fetch_invite(&state.db, &token).await.ok()??;
    (!invite.is_accepted() && !invite.is_expired(chrono::Utc::now())).then_some(invite.email)
}

/// `token` of a same-origin `/invite/finalize` return target.
fn invite_token_in(cfg: &crate::config::AppConfig, return_to: &str) -> Option<String> {
    let safe = safe_return_to(cfg, return_to);
    let url = url::Url::parse(&cfg.self_.url).ok()?.join(safe).ok()?;
    if url.path() != "/invite/finalize" {
        return None;
    }
    url.query_pairs()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.into_owned())
        .filter(|t| !t.is_empty())
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
    continue_to_app: Option<String>,
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
    let credential_step = form
        .groups
        .profile
        .iter()
        .any(|n| n.name == "screen" && n.value == "previous");
    // Kratos returns a provider sign-up whose mapper left `traits.email` unset
    // as the traits form with only the provider button to submit it.
    let oidc_email_needed = (form.groups.profile.is_empty() && form.groups.password.is_empty())
        .then(|| {
            form.groups
                .oidc
                .iter()
                .find(|n| n.input_type == "submit")
                .map(|n| n.provider_display.clone())
        })
        .flatten();

    // Forseti's own prompt explains the missing address; Kratos's raw
    // "Property email is missing." (4000002) would only repeat it badly.
    if oidc_email_needed.is_some() {
        drop_missing_property_messages(&mut form);
    }

    render(&RegistrationTemplate {
        chrome,
        form,
        webauthn_scripts,
        continue_to_app,
        credential_step,
        oidc_email_needed,
    })
}

/// Kratos's "Property {property} is missing." validation message.
const KRATOS_MISSING_PROPERTY: u64 = 4000002;

fn drop_missing_property_messages(form: &mut FlowFormView) {
    form.flow_messages
        .retain(|m| m.id != KRATOS_MISSING_PROPERTY);
    for group in [
        &mut form.groups.default,
        &mut form.groups.oidc,
        &mut form.groups.code,
        &mut form.groups.password,
        &mut form.groups.profile,
        &mut form.groups.other,
    ] {
        for node in group.iter_mut() {
            node.messages.retain(|m| m.id != KRATOS_MISSING_PROPERTY);
        }
    }
}

#[cfg(test)]
mod invite_prefill_tests {
    use super::invite_token_in;
    use crate::config::AppConfig;

    fn cfg() -> AppConfig {
        let mut cfg = AppConfig::test_fixture();
        cfg.self_.url = "https://id.example.com".into();
        cfg
    }

    #[test]
    fn reads_the_token_from_an_invite_return() {
        assert_eq!(
            invite_token_in(&cfg(), "https://id.example.com/invite/finalize?token=t1").as_deref(),
            Some("t1")
        );
    }

    #[test]
    fn ignores_other_targets() {
        assert_eq!(
            invite_token_in(&cfg(), "/oauth/login?login_challenge=c"),
            None
        );
        assert_eq!(
            invite_token_in(&cfg(), "https://evil.example/invite/finalize?token=t1"),
            None
        );
    }
}

#[cfg(test)]
mod tests {
    use super::apply_brand_hint;
    use crate::config::BrandConfig;
    use crate::db::DbPool;
    use crate::page_chrome::PageChrome;
    use crate::theming::brand_hint::set_brand_hint;
    use axum::http::{HeaderMap, header::COOKIE};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

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
