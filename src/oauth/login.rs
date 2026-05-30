//! `/oauth/login` — Hydra's "who is this user?" redirect target.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::extractors::OptionalSession;
use crate::ory;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthLoginQuery {
    login_challenge: String,
}

/// `/oauth/login?login_challenge=...` — Hydra's redirect target for the
/// "who is this user?" step. We resolve the Kratos session, check whether
/// the requested ACR is satisfied, and either accept the challenge against
/// the current subject or bounce the user to `/login` (with a `return_to`
/// that comes right back here).
pub(crate) async fn oauth_login(
    State(state): State<AppState>,
    Query(query): Query<OAuthLoginQuery>,
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

    let session = match session {
        OptionalSession::Ok { session, .. } => *session,
        // OIDC step-up flows: if the client demands a higher ACR than the
        // session satisfies, we want to land on /login?aal=aal2. With an
        // InsufficientAal session we don't yet know the client's ACR
        // ask — but the result is the same either way (re-auth at AAL2),
        // so route there directly.
        OptionalSession::InsufficientAal => {
            return Redirect::to(&crate::auth::aal2_step_up_url(&self_login_url)).into_response();
        }
        OptionalSession::None => {
            let url = format!(
                "/login?return_to={}",
                ory_client::apis::urlencode(&self_login_url)
            );
            return Redirect::to(&url).into_response();
        }
    };

    // ACR / AAL step-up check. The OIDC client may pass `acr_values=aal2`
    // (or another stronger ACR). If the current session is weaker, force
    // a fresh login at the requested AAL before accepting.
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

    // The SDK's `MethodEnum` doesn't impl `Display`; round-trip through serde
    // to recover the wire-format string (`"password"`, `"oidc"`, …) that we
    // want to propagate as the `amr` claim.
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

    // Honour the optional `organization_id=<id>` auth-request parameter
    // by parsing it out of Hydra's `request_url` (the original
    // /oauth2/auth URL the client called). When the user is a member,
    // pre-select that org via the active-org cookie so the
    // upcoming consent step folds it into the `org` claim. Silent
    // fallback when the user isn't a member — the cookie keeps its
    // current value.
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
            // TODO(M5): emit a proper audit row here once the broader
            // audit pass lands. For now a tracing::info! is enough to
            // catch a "wrong org_id pinned in the auth request" misuse
            // pattern in operator logs.
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

/// Pull `organization_id=<id>` out of Hydra's `request_url`. Hydra
/// surfaces the original `/oauth2/auth` URL verbatim, so a downstream
/// app passing `?organization_id=acme` shows up in this string.
fn parse_organization_id_param(request_url: &str) -> Option<String> {
    url::Url::parse(request_url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == "organization_id")
        .map(|(_, v)| v.into_owned())
}

#[cfg(test)]
mod tests {
    use super::parse_organization_id_param;

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
        // Not a valid absolute URL — `url::Url::parse` rejects this.
        assert_eq!(parse_organization_id_param("not a url"), None);
        // Empty string also fails to parse.
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
}
