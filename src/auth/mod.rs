//! Public Kratos self-service flow handlers: registration, login, recovery,
//! verification, logout, and the `/error` landing page.

use axum::Router;
use axum::routing::{get, post};

use crate::config::{AuthConfig, ProxyConfig};
use crate::rate_limit;
use crate::state::AppState;

pub(crate) mod error;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod recovery;
pub(crate) mod registration;
pub(crate) mod verification;

/// Per-IP rate-limit defaults for `GET /registration`, used when
/// `[auth].registration_ip_rate_per_*` is unset. This bounds signup-page
/// renders, not account creation (the browser POSTs straight to Kratos), so
/// the per-IP window has to tolerate many legitimate users sharing one egress
/// IP behind a corporate NAT / CGNAT; the global bucket below is the real
/// abuse backstop.
const DEFAULT_REGISTRATION_IP_RATE_PER_MINUTE: u32 = 30;
const DEFAULT_REGISTRATION_IP_RATE_PER_HOUR: u32 = 300;
/// Global (all-callers-share-one-bucket) defaults, bounding total traffic
/// regardless of claimed source IP.
const DEFAULT_REGISTRATION_GLOBAL_RATE_PER_MINUTE: u32 = 120;
const DEFAULT_REGISTRATION_GLOBAL_RATE_PER_HOUR: u32 = 1200;

/// An OIDC `login_hint` worth showing: email-shaped, internationalised
/// addresses (RFC 6531) included. Anything else (the account switcher's
/// identity UUIDs) is ignored.
pub(crate) fn email_login_hint(raw: &str) -> Option<&str> {
    let ok = raw.len() <= 254
        && raw.contains('@')
        && !raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ',' | ';' | '"' | '\\'));
    ok.then_some(raw)
}

/// Bytes a hint cookie keeps as-is; everything else is percent-encoded, since
/// cookie values are limited to a US-ASCII subset (RFC 6265 §4.1.1).
const HINT_COOKIE_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'@')
    .remove(b'.')
    .remove(b'-')
    .remove(b'_')
    .remove(b'+');

/// One-shot cookie carrying a `login_hint` across Kratos's flow-init hop,
/// scoped to `path`. `None` value clears it.
pub(crate) fn hint_cookie(name: &str, path: &str, value: Option<&str>, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    match value {
        Some(v) => {
            let v = percent_encoding::utf8_percent_encode(v, HINT_COOKIE_ENCODE);
            format!("{name}={v}; Path={path}; Max-Age=600; HttpOnly; SameSite=Lax{secure_attr}")
        }
        None => format!("{name}=; Path={path}; Max-Age=0; HttpOnly; SameSite=Lax{secure_attr}"),
    }
}

/// The `login_hint` a [`hint_cookie`] carried, decoded and re-validated.
pub(crate) fn decode_hint_cookie(raw: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()?;
    email_login_hint(&decoded).map(str::to_string)
}

pub(crate) fn router(proxy_cfg: &ProxyConfig, auth_cfg: &AuthConfig) -> Router<AppState> {
    Router::new()
        .route("/login", get(login::login))
        .merge(registration_router(proxy_cfg, auth_cfg))
        .route("/recovery", get(recovery::recovery))
        .route("/verification", get(verification::verification))
        .route("/error", get(error::error_page))
        .route("/logout", post(logout::logout))
}

/// `GET /registration` under a paired per-IP + global rate limit. The browser
/// POSTs registration straight to Kratos's own public endpoint (Forseti never
/// sees it), so this only bounds page renders — see the operator guide.
fn registration_router(proxy_cfg: &ProxyConfig, auth_cfg: &AuthConfig) -> Router<AppState> {
    let r = Router::new().route("/registration", get(registration::registration));

    let per_minute = auth_cfg
        .registration_ip_rate_per_minute
        .unwrap_or(DEFAULT_REGISTRATION_IP_RATE_PER_MINUTE);
    let per_hour = auth_cfg
        .registration_ip_rate_per_hour
        .unwrap_or(DEFAULT_REGISTRATION_IP_RATE_PER_HOUR);
    let global_per_minute = auth_cfg
        .registration_global_rate_per_minute
        .unwrap_or(DEFAULT_REGISTRATION_GLOBAL_RATE_PER_MINUTE);
    let global_per_hour = auth_cfg
        .registration_global_rate_per_hour
        .unwrap_or(DEFAULT_REGISTRATION_GLOBAL_RATE_PER_HOUR);

    rate_limit::dual_window_with_global(
        r,
        proxy_cfg,
        per_minute,
        per_hour,
        global_per_minute,
        global_per_hour,
        rate_limit::plain_text_error("registration"),
    )
}

/// Canonical `/login?aal=aal2&return_to=…` step-up URL.
pub(crate) fn aal2_step_up_url(return_to: &str) -> String {
    format!(
        "/login?aal=aal2&return_to={}",
        ory_client::apis::urlencode(return_to)
    )
}

/// The app a login or registration flow continues to, named on the card so
/// the user knows where they are signing in. `client_name` is whatever the
/// registrant chose, so only an operator- or org-vouched client is named on
/// Forseti's own sign-in page; the rest stay generic.
pub(crate) async fn continuing_app_name(
    state: &AppState,
    return_to: Option<&str>,
) -> Option<String> {
    let challenge = login_challenge_in(&state.cfg, return_to?)?;
    let req = crate::ory::hydra::get_login_request(&state.ory, &challenge)
        .await
        .ok()?;
    let client = req.client;
    let row = crate::oauth_client_metadata::get(&state.db, client.client_id.as_deref()?)
        .await
        .ok()??;
    if !(row.is_admin_vouched() || row.is_org_vouched()) {
        return None;
    }
    client.client_name.filter(|n| !n.trim().is_empty())
}

/// `login_challenge` of a same-origin `/oauth/login` return target.
fn login_challenge_in(cfg: &crate::config::AppConfig, return_to: &str) -> Option<String> {
    let safe = crate::web::safe_return_to(cfg, return_to);
    let url = url::Url::parse(&cfg.self_.url).ok()?.join(safe).ok()?;
    if url.path() != "/oauth/login" {
        return None;
    }
    url.query_pairs()
        .find(|(k, _)| k == "login_challenge")
        .map(|(_, v)| v.into_owned())
        .filter(|c| !c.is_empty())
}

#[cfg(test)]
mod continuing_app_tests {
    use super::login_challenge_in;
    use crate::config::AppConfig;

    fn cfg() -> AppConfig {
        let mut cfg = AppConfig::test_fixture();
        cfg.self_.url = "https://id.example.com".into();
        cfg
    }

    #[test]
    fn reads_the_challenge_from_an_oauth_login_return() {
        assert_eq!(
            login_challenge_in(
                &cfg(),
                "https://id.example.com/oauth/login?login_challenge=abc"
            )
            .as_deref(),
            Some("abc")
        );
        assert_eq!(
            login_challenge_in(&cfg(), "/oauth/login?login_challenge=abc").as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn ignores_other_paths_and_foreign_origins() {
        assert_eq!(login_challenge_in(&cfg(), "/invite/finalize?token=t"), None);
        assert_eq!(
            login_challenge_in(
                &cfg(),
                "https://evil.example/oauth/login?login_challenge=abc"
            ),
            None
        );
        assert_eq!(login_challenge_in(&cfg(), "/oauth/login"), None);
    }
}

#[cfg(test)]
mod hint_cookie_tests {
    use super::{decode_hint_cookie, hint_cookie};

    fn cookie_value(set_cookie: &str) -> &str {
        let pair = set_cookie.split(';').next().unwrap();
        pair.split_once('=').unwrap().1
    }

    #[test]
    fn decode_hint_cookie_roundtrips_an_international_address() {
        for hint in ["jürgen@bücher.example", "a+tag@example.com"] {
            let set = hint_cookie("h", "/login", Some(hint), true);
            let value = cookie_value(&set);
            assert!(value.is_ascii(), "{value}");
            assert_eq!(decode_hint_cookie(value).as_deref(), Some(hint));
        }
    }

    #[test]
    fn undecodable_hint_cookie_is_ignored() {
        assert_eq!(decode_hint_cookie("%FF%FE@example.com"), None);
        assert_eq!(decode_hint_cookie("a%3Bb@example.com"), None);
        assert_eq!(decode_hint_cookie("no-at-sign"), None);
    }
}
