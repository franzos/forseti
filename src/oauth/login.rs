//! `/oauth/login` — Hydra's "who is this user?" redirect target.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::db::DbPool;
use crate::extractors::OptionalSession;
use crate::ory;
use crate::signed_cookie::unix_seconds_now;
use crate::state::AppState;

use super::reauth::{self, ReauthDecision, ReauthMark};

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthLoginQuery {
    login_challenge: String,
    #[serde(default)]
    skip_org_join: Option<String>,
}

/// `/oauth/login?login_challenge=...` — Hydra's "who is this user?" redirect
/// target. Resolves the Kratos session, checks the requested ACR, and either
/// accepts the challenge or bounces to `/login` with a `return_to` back here.
pub(crate) async fn oauth_login(
    State(state): State<AppState>,
    Query(query): Query<OAuthLoginQuery>,
    uri: Uri,
    headers: HeaderMap,
    session: OptionalSession,
) -> Response {
    let skip_org_join = query.skip_org_join.is_some();
    let challenge = query.login_challenge;
    let req = match ory::hydra::get_login_request(&state.ory, &challenge).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "hydra get_login_request failed");
            return Redirect::to("/error").into_response();
        }
    };

    let self_login_url = format!(
        "{}/oauth/login?login_challenge={}",
        state.cfg.self_.url.trim_end_matches('/'),
        ory_client::apis::urlencode(&challenge),
    );

    // Resolve the display locale for the login surface honoring ui_locales (D1).
    // Passed as ?lang= to the /login redirect so the Kratos login page renders
    // in the right language without the login handler needing the challenge.
    let ui_locales: Option<Vec<String>> = req
        .oidc_context
        .as_ref()
        .and_then(|ctx| ctx.ui_locales.clone());
    let headers_for_reauth = headers.clone();
    let login_locale = {
        let (mut p, _) = axum::http::Request::new(()).into_parts();
        p.uri = uri;
        p.headers = headers;
        crate::page_chrome::resolve_locale_for_flow(&p, &session, ui_locales.as_deref())
    };

    let session = match session {
        OptionalSession::Ok { session, .. } => *session,
        // InsufficientAal: we don't know the client's ACR ask yet, but the
        // outcome is the same either way (re-auth at AAL2), so route there.
        OptionalSession::InsufficientAal => {
            return Redirect::to(&crate::auth::aal2_step_up_url(&self_login_url)).into_response();
        }
        OptionalSession::None => {
            let url = anonymous_login_redirect_url(
                &self_login_url,
                login_locale.language.as_str(),
                req.request_url.as_str(),
            );
            return Redirect::to(&url).into_response();
        }
    };

    // RP-driven re-authentication (OIDC Core 3.1.2.1). Hydra forwards `prompt`
    // and `max_age` in `request_url` but acts on neither — it stamps
    // `auth_time` when we accept, so without this an RP asking for a fresh
    // authentication gets a "fresh" token off a days-old session.
    let reauth_cookie = reauth::reauth_mark_cookie(state.cfg.self_.is_https());
    let ask = reauth::parse_reauth_ask(req.request_url.as_str());
    let auth_time = reauth::session_auth_time(&session);
    let mut clear_reauth_mark = false;
    if !ask.is_empty() {
        let now_secs = unix_seconds_now();
        let now = chrono::Utc::now();
        let mark = reauth_cookie
            .decode(&state.cookie_secret, &headers_for_reauth, now_secs)
            .and_then(|b| serde_json::from_slice::<ReauthMark>(&b).ok())
            .filter(|m| m.c == challenge)
            .map(|m| reauth::Mark {
                prior_auth_time: reauth::parse_rfc3339(&m.t),
                bounced_at: reauth::parse_rfc3339(&m.b),
            });
        match reauth::decide(&ask, auth_time, now, mark) {
            ReauthDecision::Reauthenticate => {
                let payload = serde_json::to_vec(&ReauthMark {
                    c: challenge.clone(),
                    t: auth_time.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    b: now.to_rfc3339(),
                })
                .unwrap_or_default();
                let encoded = reauth_cookie.encode(&state.cookie_secret, &payload, now_secs);
                let url = format!(
                    "/login?refresh=true&return_to={}&lang={}",
                    ory_client::apis::urlencode(&self_login_url),
                    login_locale.language.as_str(),
                );
                let mut resp = Redirect::to(&url).into_response();
                crate::web::append_set_cookie(&mut resp, Some(reauth_cookie.set_header(&encoded)));
                return resp;
            }
            // The ask is satisfied; drop the mark once this flow finishes so
            // a later one on the same browser can't ride it. The in-flow
            // detours below (AAL2 step-up, the org-join interstitial) come
            // back to this same challenge, so they deliberately keep it —
            // clearing there would cost the user a second bounce.
            ReauthDecision::Proceed => clear_reauth_mark = mark.is_some(),
        }
    }

    // ACR / AAL step-up: if the client asks `acr_values=aal2` and the session
    // is weaker, force a fresh login at the requested AAL before accepting.
    let requested_acrs: Vec<String> = req
        .oidc_context
        .as_ref()
        .and_then(|ctx| ctx.acr_values.clone())
        .unwrap_or_default();
    let session_is_aal2 = ory::kratos::session_satisfies_aal2(&session);
    let session_aal = ory::kratos::session_aal_string(&session);
    if requested_acrs
        .iter()
        .any(|acr| acr == "aal2" && !session_is_aal2)
    {
        return Redirect::to(&crate::auth::aal2_step_up_url(&self_login_url)).into_response();
    }

    let subject = session
        .identity
        .as_ref()
        .map(|id| id.id.clone())
        .unwrap_or_default();
    if subject.is_empty() {
        tracing::error!("session missing identity.id");
        let mut resp = Redirect::to("/error").into_response();
        if clear_reauth_mark {
            crate::web::append_set_cookie(&mut resp, Some(reauth_cookie.clear_header()));
        }
        return resp;
    }

    // The SDK's `MethodEnum` has no `Display`; round-trip through serde to
    // recover the wire string (`"password"`, `"oidc"`, …), then map it onto
    // RFC 8176 so relying parties reading `amr` get the registered values
    // rather than Kratos's internal names.
    let amr: Vec<String> = session
        .authentication_methods
        .as_ref()
        .map(|methods| {
            let mut out: Vec<String> = Vec::new();
            for m in methods {
                let Some(kratos_name) = m.method.as_ref().and_then(|x| {
                    serde_json::to_value(x)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                }) else {
                    continue;
                };
                for value in amr_values(&kratos_name) {
                    if !out.contains(&value) {
                        out.push(value);
                    }
                }
            }
            out
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["pwd".to_string()]);

    // Optional `organization_id` (id or slug) from Hydra's `request_url`.
    // Members: pre-select via the active-org cookie. Eligible non-members:
    // redirect to the one-time /join/confirm interstitial (the write lives
    // there, behind CSRF), unless the user already declined this flow.
    let mut set_org_cookie: Option<String> = None;
    if let Some(raw) =
        parse_organization_id_param(req.request_url.as_str()).filter(|s| !s.is_empty())
    {
        match resolve_pin_action(&state.db, &subject, &raw, skip_org_join).await {
            PinAction::Cookie(org_id) => {
                set_org_cookie = Some(crate::orgs::cookie::set_active_org_pin_for_flow(
                    &state.cookie_secret,
                    state.cfg.orgs.active_org_cookie_ttl_seconds,
                    &org_id,
                    state.cfg.self_.is_https(),
                ));
            }
            PinAction::Interstitial { slug } => {
                let mut url = format!(
                    "/join/confirm?org={}&return_to={}",
                    ory_client::apis::urlencode(&slug),
                    ory_client::apis::urlencode(&self_login_url),
                );
                // Advisory attribution: the OAuth client that routed the user here
                // (`req.client` is non-optional on the login request; `client_id`
                // is `Option<String>`).
                if let Some(cid) = req.client.client_id.as_deref().filter(|s| !s.is_empty()) {
                    url.push_str(&format!("&client_id={}", ory_client::apis::urlencode(cid)));
                }
                return Redirect::to(&url).into_response();
            }
            PinAction::Ignore => tracing::info!(
                subject = %subject,
                organization_id = %raw,
                "oauth login: organization_id not applied (unknown, ineligible, or declined)",
            ),
        }
    }

    match ory::hydra::accept_login_request(
        &state.ory,
        &challenge,
        &subject,
        true,
        state.cfg.oauth.login_session_remember_for.unwrap_or(86400),
        amr,
        Some(session_aal),
    )
    .await
    {
        Ok(redirect) => {
            let mut resp = Redirect::to(&redirect.redirect_to).into_response();
            if let Some(cookie) = set_org_cookie
                && let Ok(v) = axum::http::HeaderValue::from_str(&cookie)
            {
                resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
            }
            if clear_reauth_mark {
                crate::web::append_set_cookie(&mut resp, Some(reauth_cookie.clear_header()));
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = ?e, "hydra accept_login_request failed");
            let mut resp = Redirect::to("/error").into_response();
            if clear_reauth_mark {
                crate::web::append_set_cookie(&mut resp, Some(reauth_cookie.clear_header()));
            }
            resp
        }
    }
}

/// Build the `/login` redirect for an anonymous visitor, forwarding
/// `organization_id` (if present on the original `/oauth2/auth` request) so
/// `/login` can theme itself from the org's public branding.
fn anonymous_login_redirect_url(self_login_url: &str, lang: &str, request_url: &str) -> String {
    let org_q = parse_organization_id_param(request_url)
        .filter(|id: &String| !id.is_empty())
        .map(|id| format!("&organization_id={}", ory_client::apis::urlencode(&id)))
        .unwrap_or_default();
    format!(
        "/login?return_to={}&lang={}{}",
        ory_client::apis::urlencode(self_login_url),
        lang,
        org_q,
    )
}

/// Map a Kratos authentication-method name onto RFC 8176 `amr` values.
///
/// Kratos's names are its own (`password`, `lookup_secret`, `code`); RFC 8176
/// defines the registered ones an RP can actually interpret. A method may
/// yield more than one value — a passkey is both possession-based and, in
/// practice, user-verifying, and `mfa` is what an RP checks for.
///
/// An unrecognised method passes through verbatim rather than being dropped:
/// a future Kratos method should be visible to the RP, not silently absent.
///
/// `mfa` marks a genuine second factor, and the PAM `force_mfa` allowlist
/// (`posix::device::SECOND_FACTOR_AMR`) reads these values off the id_token
/// Forseti mints here — so the two have to move together.
fn amr_values(kratos_method: &str) -> Vec<String> {
    let mapped: &[&str] = match kratos_method {
        "password" => &["pwd"],
        "oidc" => &["federated"],
        "totp" | "totp_v2" => &["otp", "mfa"],
        "lookup_secret" => &["otp", "mfa"],
        "webauthn" | "webauthn_v2" => &["hwk", "user", "mfa"],
        // A passkey is a primary credential here, not a step-up, so no `mfa`.
        "passkey" => &["hwk", "user"],
        "code" | "code_recovery" | "link_recovery" => &["otp"],
        _ => return vec![kratos_method.to_string()],
    };
    mapped.iter().map(|s| s.to_string()).collect()
}

/// Pull `organization_id=<id>` out of Hydra's `request_url` (the verbatim
/// `/oauth2/auth` URL the downstream app called).
pub(crate) fn parse_organization_id_param(request_url: &str) -> Option<String> {
    url::Url::parse(request_url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == "organization_id")
        .map(|(_, v)| v.into_owned())
}

/// What the `organization_id` pin resolves to for a signed-in subject.
enum PinAction {
    /// Already a member; set the active-org cookie for this org id.
    Cookie(String),
    /// Eligible external+public org, not yet a member: send to `/join/confirm`.
    Interstitial { slug: String },
    /// Unknown ref, ineligible non-member, or a declined pin: ignore.
    Ignore,
}

/// Resolve the pin (id or slug). Members -> cookie pre-select. Eligible
/// non-members -> the one-time join interstitial, unless `skip_join` (the
/// user already declined this flow). Everything else -> ignore. No write here.
async fn resolve_pin_action(db: &DbPool, subject: &str, raw: &str, skip_join: bool) -> PinAction {
    let Some(org) = crate::orgs::db::org_by_ref(db, raw).await.ok().flatten() else {
        return PinAction::Ignore;
    };
    if crate::orgs::is_member(db, subject, &org.id).await {
        return PinAction::Cookie(org.id);
    }
    if skip_join || !crate::orgs::join::is_signup_eligible(&org) {
        return PinAction::Ignore;
    }
    PinAction::Interstitial { slug: org.slug }
}

#[cfg(test)]
mod tests {
    use super::{anonymous_login_redirect_url, parse_organization_id_param};

    #[test]
    fn parses_valid_organization_id() {
        let url = "https://hydra.example.com/oauth2/auth?client_id=x&organization_id=acme";
        assert_eq!(parse_organization_id_param(url), Some("acme".to_string()));
    }

    #[test]
    fn missing_param_returns_none() {
        let url = "https://hydra.example.com/oauth2/auth?client_id=x";
        assert_eq!(parse_organization_id_param(url), None);
    }

    #[test]
    fn invalid_url_returns_none() {
        assert_eq!(parse_organization_id_param("not a url"), None);
        assert_eq!(parse_organization_id_param(""), None);
    }

    #[test]
    fn handles_percent_encoded_values() {
        let url = "https://hydra.example.com/oauth2/auth?organization_id=acme%2Dco";
        assert_eq!(
            parse_organization_id_param(url),
            Some("acme-co".to_string())
        );
    }

    #[test]
    fn amr_maps_kratos_methods_onto_rfc_8176() {
        use super::amr_values;
        assert_eq!(amr_values("password"), vec!["pwd"]);
        assert_eq!(amr_values("oidc"), vec!["federated"]);
        assert_eq!(amr_values("totp"), vec!["otp", "mfa"]);
        assert_eq!(amr_values("lookup_secret"), vec!["otp", "mfa"]);
        assert_eq!(amr_values("webauthn"), vec!["hwk", "user", "mfa"]);
    }

    #[test]
    fn a_passkey_is_not_marked_as_a_second_factor() {
        use super::amr_values;
        // It is a primary credential in this flow; `mfa` would let a passkey
        // login satisfy a `force_mfa` host on its own.
        assert!(!amr_values("passkey").contains(&"mfa".to_string()));
    }

    #[test]
    fn an_unknown_method_passes_through_rather_than_vanishing() {
        use super::amr_values;
        assert_eq!(amr_values("some_future_method"), vec!["some_future_method"]);
    }

    #[test]
    fn every_second_factor_method_yields_the_pam_allowlist_marker() {
        use super::amr_values;
        // The PAM `force_mfa` allowlist reads these values off the id_token,
        // so the mapping and the allowlist have to agree.
        for method in [
            "totp",
            "totp_v2",
            "lookup_secret",
            "webauthn",
            "webauthn_v2",
        ] {
            let values = amr_values(method);
            assert!(
                values
                    .iter()
                    .any(|v| crate::posix::device_second_factor_amr().contains(&v.as_str())),
                "{method} -> {values:?} satisfies no entry of SECOND_FACTOR_AMR"
            );
        }
    }

    #[test]
    fn anonymous_redirect_forwards_organization_id() {
        let request_url =
            "https://hydra.example.com/oauth2/auth?client_id=x&organization_id=acme-id";
        let url = anonymous_login_redirect_url("https://self/oauth/login", "en", request_url);
        assert!(url.starts_with("/login?return_to="));
        assert!(url.contains("organization_id=acme-id"));
    }

    #[test]
    fn anonymous_redirect_omits_organization_id_when_absent() {
        let request_url = "https://hydra.example.com/oauth2/auth?client_id=x";
        let url = anonymous_login_redirect_url("https://self/oauth/login", "en", request_url);
        assert!(!url.contains("organization_id"));
    }
}

#[cfg(test)]
mod pin_tests {
    use super::{PinAction, resolve_pin_action};
    use crate::orgs::db::{
        add_member_race_safe, create_org, set_access_mode, test_pool, update_theme,
    };
    use crate::orgs::{AccessMode, Role};

    async fn eligible_org(db: &crate::db::DbPool) {
        create_org(db, "o1", "acme", "Acme", None).await.unwrap();
        set_access_mode(db, "o1", AccessMode::External)
            .await
            .unwrap();
        update_theme(db, "o1", None, None, None, None, 1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn member_yields_cookie() {
        let db = test_pool().await;
        eligible_org(&db).await;
        add_member_race_safe(&db, "ident-1", "o1", Role::Member)
            .await
            .unwrap();
        assert!(
            matches!(resolve_pin_action(&db, "ident-1", "acme", false).await, PinAction::Cookie(id) if id == "o1")
        );
    }

    #[tokio::test]
    async fn eligible_nonmember_yields_interstitial() {
        let db = test_pool().await;
        eligible_org(&db).await;
        assert!(
            matches!(resolve_pin_action(&db, "ident-2", "o1", false).await, PinAction::Interstitial { slug } if slug == "acme")
        );
    }

    #[tokio::test]
    async fn skip_marker_ignores() {
        let db = test_pool().await;
        eligible_org(&db).await;
        assert!(matches!(
            resolve_pin_action(&db, "ident-3", "acme", true).await,
            PinAction::Ignore
        ));
    }

    #[tokio::test]
    async fn internal_org_ignored() {
        let db = test_pool().await;
        create_org(&db, "o2", "corp", "Corp", None).await.unwrap();
        update_theme(&db, "o2", None, None, None, None, 1)
            .await
            .unwrap();
        assert!(matches!(
            resolve_pin_action(&db, "ident-4", "corp", false).await,
            PinAction::Ignore
        ));
    }

    #[tokio::test]
    async fn unknown_ref_ignored() {
        let db = test_pool().await;
        assert!(matches!(
            resolve_pin_action(&db, "ident-5", "ghost", false).await,
            PinAction::Ignore
        ));
    }
}
