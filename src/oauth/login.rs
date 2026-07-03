//! `/oauth/login` — Hydra's "who is this user?" redirect target.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::extractors::OptionalSession;
use crate::ory;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthLoginQuery {
    login_challenge: String,
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
        return Redirect::to("/error").into_response();
    }

    // The SDK's `MethodEnum` has no `Display`; round-trip through serde to
    // recover the wire string (`"password"`, `"oidc"`, …) for the `amr` claim.
    let amr: Vec<String> = session
        .authentication_methods
        .as_ref()
        .map(|methods| {
            methods
                .iter()
                .filter_map(|m| {
                    m.method.as_ref().and_then(|x| {
                        serde_json::to_value(x)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_string))
                    })
                })
                .collect()
        })
        .unwrap_or_else(|| vec!["pwd".to_string()]);

    // Optional `organization_id=<id>` from Hydra's `request_url`: when the
    // user is a member, pre-select that org via the active-org cookie so
    // consent folds it into the `org` claim. Silent fallback otherwise.
    let pre_select_org_id = parse_organization_id_param(req.request_url.as_str())
        .filter(|org_id: &String| !org_id.is_empty());
    let mut set_org_cookie: Option<String> = None;
    if let Some(org_id) = pre_select_org_id {
        if crate::orgs::is_member(&state.db, &subject, &org_id).await {
            set_org_cookie = Some(crate::orgs::cookie::set_active_org_cookie(
                &state.cookie_secret,
                state.cfg.orgs.active_org_cookie_ttl_seconds,
                &org_id,
                state.cfg.self_.is_https(),
            ));
        } else {
            // TODO: emit an audit row here; for now a tracing::info! catches
            // the "wrong org_id pinned in the auth request" misuse pattern.
            tracing::info!(
                subject = %subject,
                organization_id = %org_id,
                "oauth login: requested organization_id is not a membership; ignoring",
            );
        }
    }

    match ory::hydra::accept_login_request(
        &state.ory,
        &challenge,
        &subject,
        true,
        amr,
        Some(session_aal),
    )
    .await
    {
        Ok(redirect) => {
            let mut resp = Redirect::to(&redirect.redirect_to).into_response();
            if let Some(cookie) = set_org_cookie {
                if let Ok(v) = axum::http::HeaderValue::from_str(&cookie) {
                    resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
                }
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = ?e, "hydra accept_login_request failed");
            Redirect::to("/error").into_response()
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

/// Pull `organization_id=<id>` out of Hydra's `request_url` (the verbatim
/// `/oauth2/auth` URL the downstream app called).
fn parse_organization_id_param(request_url: &str) -> Option<String> {
    url::Url::parse(request_url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == "organization_id")
        .map(|(_, v)| v.into_owned())
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
