//! Reusable axum extractors consolidating the per-handler "resolve session / check admin / read CSRF" boilerplate,
//! turning the auth gate into a typed argument instead of a `match whoami` ladder. Call sites are migrated incrementally.

use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};

use crate::admin::{require_admin, require_admin_with_scope, AdminCtx};
use crate::commercial::license::{Feature, FeatureStatus};
use crate::commercial::upsell::render_upsell;
use crate::cookies;
use crate::csrf;
use crate::ory;
use crate::state::AppState;

/// Resolve the caller's Kratos session, or short-circuit with a `/login` redirect (current path as `return_to`).
/// Rejection is a fully-formed `Response`, so handlers use `?` against it.
pub(crate) struct RequireSession {
    pub(crate) session: ory::Session,
    pub(crate) identity_id: String,
    pub(crate) email: String,
}

/// Why [`resolve_session`] couldn't hand back a usable session. Each variant carries the artefact a caller
/// typically wants (a redirect, or the raw error), but callers may synthesise their own response.
pub(crate) enum SessionFailure {
    /// No session; embeds the `/login?return_to=<path>` redirect.
    NoSession(Redirect),
    /// Session exists but AAL is below what whoami required; embeds the `aal=aal2` step-up redirect.
    InsufficientAal(Redirect),
    /// Transport/upstream error talking to Kratos.
    KratosError(anyhow::Error),
}

/// Project a [`ory::kratos::WhoamiOutcome`] into the required-session shape, keeping the InsufficientAal / None mapping in one place.
fn required_session_from_outcome(
    outcome: ory::kratos::WhoamiOutcome,
    path: &str,
) -> Result<Box<ory::Session>, SessionFailure> {
    match outcome {
        ory::kratos::WhoamiOutcome::Ok(s) => Ok(s),
        ory::kratos::WhoamiOutcome::InsufficientAal => Err(SessionFailure::InsufficientAal(
            Redirect::to(&crate::auth::aal2_step_up_url(path)),
        )),
        ory::kratos::WhoamiOutcome::None => {
            let url = format!("/login?return_to={}", ory_client::apis::urlencode(path));
            Err(SessionFailure::NoSession(Redirect::to(&url)))
        }
    }
}

/// Single source of truth for the `match whoami` ladder: the resolved session or a [`SessionFailure`].
pub(crate) async fn resolve_session(
    state: &AppState,
    cookie: &str,
    path: &str,
) -> Result<Box<ory::Session>, SessionFailure> {
    let outcome = ory::kratos::whoami(&state.ory, (!cookie.is_empty()).then_some(cookie))
        .await
        .map_err(SessionFailure::KratosError)?;
    required_session_from_outcome(outcome, path)
}

/// Extractor wrapper around [`resolve_session`] consulting the middleware-cached whoami first to avoid a second Kratos round-trip.
async fn resolve_session_from_parts(
    state: &AppState,
    parts: &Parts,
    path: &str,
) -> Result<Box<ory::Session>, SessionFailure> {
    if let Some(outcome) = cached_whoami(&parts.extensions) {
        return required_session_from_outcome(outcome, path);
    }
    let cookie = cookies::cookie_header(&parts.headers);
    resolve_session(state, &cookie, path).await
}

impl<S> FromRequestParts<S> for RequireSession
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = app_state(parts, state).await;
        // Keep the query (e.g. `?flow=`) so a step-up return_to restores the exact
        // URL, since the post-recovery settings hand-off needs `?flow=` to survive.
        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| parts.uri.path())
            .to_string();
        let session = match resolve_session_from_parts(&app_state, parts, &path).await {
            Ok(s) => *s,
            Err(SessionFailure::InsufficientAal(r)) | Err(SessionFailure::NoSession(r)) => {
                return Err(r.into_response());
            }
            Err(SessionFailure::KratosError(e)) => {
                // Transport/5xx, not a real 401: redirecting to /login would sign the user out on a network
                // flap (and /login itself hits whoami, so we'd loop). Render an error page so the user can retry.
                tracing::error!(error = ?e, path, "RequireSession: whoami failed");
                return Err(crate::web::render_error_boundary(
                    &app_state,
                    crate::web::AUTH_UNAVAILABLE_TITLE,
                    crate::web::AUTH_UNAVAILABLE_BODY,
                    "/",
                    "Try again",
                ));
            }
        };

        let (identity_id, email) = crate::flow_view::session_principal(&session);

        Ok(RequireSession {
            session,
            identity_id,
            email,
        })
    }
}

/// Pull the middleware-cached whoami out of request extensions; `None` means fall back to a direct whoami call.
fn cached_whoami(extensions: &axum::http::Extensions) -> Option<ory::kratos::WhoamiOutcome> {
    extensions
        .get::<crate::orgs::middleware::CachedWhoami>()
        .map(|c| c.0.clone())
}

/// Pull the [`AppState`] out of any state `S` that exposes it (infallible here, so the `.expect` is centralised).
pub(crate) async fn app_state<S>(parts: &mut Parts, state: &S) -> AppState
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    State::<AppState>::from_request_parts(parts, state)
        .await
        .expect("AppState extractor is infallible")
        .0
}

/// Three-state session probe for handlers that don't want [`RequireSession`]'s eager redirect, with identity
/// fields pre-extracted. Use it when "no session" is valid, or to distinguish it from "insufficient AAL".
pub(crate) enum OptionalSession {
    /// No session cookie / Kratos returned no session.
    None,
    /// Session cookie resolves but AAL is below what whoami required.
    InsufficientAal,
    /// Valid session, with the identity fields pre-extracted.
    Ok {
        session: Box<ory::Session>,
        identity_id: String,
        email: String,
    },
}

impl OptionalSession {
    /// Borrow the session when [`OptionalSession::Ok`], else `None`.
    /// Convenience for the common "I only care about the Ok case" path.
    pub(crate) fn ok(&self) -> Option<&ory::Session> {
        match self {
            OptionalSession::Ok { session, .. } => Some(session),
            _ => None,
        }
    }

    /// Identity id when [`OptionalSession::Ok`], `None` otherwise.
    pub(crate) fn identity_id(&self) -> Option<&str> {
        match self {
            OptionalSession::Ok { identity_id, .. } => Some(identity_id),
            _ => None,
        }
    }

    /// Email when [`OptionalSession::Ok`], `None` otherwise.
    pub(crate) fn email(&self) -> Option<&str> {
        match self {
            OptionalSession::Ok { email, .. } => Some(email),
            _ => None,
        }
    }
}

/// Project a [`ory::kratos::WhoamiOutcome`] into [`OptionalSession`], pre-extracting identity fields on `Ok`.
fn optional_session_from_outcome(outcome: ory::kratos::WhoamiOutcome) -> OptionalSession {
    match outcome {
        ory::kratos::WhoamiOutcome::Ok(session) => {
            let (identity_id, email) = crate::flow_view::session_principal(&session);
            OptionalSession::Ok {
                session,
                identity_id,
                email,
            }
        }
        ory::kratos::WhoamiOutcome::InsufficientAal => OptionalSession::InsufficientAal,
        ory::kratos::WhoamiOutcome::None => OptionalSession::None,
    }
}

/// Free-function form of [`OptionalSession`] for helpers not running inside an extractor; consults the
/// middleware-cached whoami first, falling back to a direct [`ory::kratos::whoami`] on a cache miss.
pub(crate) async fn optional_session(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    extensions: &axum::http::Extensions,
) -> OptionalSession {
    if let Some(outcome) = cached_whoami(extensions) {
        return optional_session_from_outcome(outcome);
    }
    let cookie = cookies::cookie_header(headers);
    match ory::kratos::whoami(&state.ory, (!cookie.is_empty()).then_some(cookie.as_str())).await {
        Ok(outcome) => optional_session_from_outcome(outcome),
        Err(e) => {
            tracing::warn!(error = ?e, "optional_session: whoami transport error, treating as None");
            OptionalSession::None
        }
    }
}

impl<S> FromRequestParts<S> for OptionalSession
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = app_state(parts, state).await;
        Ok(optional_session(&app_state, &parts.headers, &parts.extensions).await)
    }
}

/// Admin gate equivalent of [`RequireSession`], chaining through [`crate::admin::require_admin`].
pub(crate) struct RequireAdmin {
    pub(crate) ctx: AdminCtx,
}

impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = app_state(parts, state).await;
        let path = parts.uri.path().to_string();
        let ctx = require_admin(&app_state, &parts.headers, &path).await?;
        Ok(RequireAdmin { ctx })
    }
}

/// Org-scoped admin gate wrapping [`crate::admin::require_admin_with_scope`]. Runs as an extractor (before
/// `Form` body extraction) so an in-body gate can't leak the form-field shape via the `Form` 422 to anon callers.
/// `?org=<slug>` empty/missing = Forseti-wide admin; present = owner role on that org.
pub(crate) struct RequireAdminScoped {
    pub(crate) ctx: AdminCtx,
    pub(crate) scope: crate::orgs::AdminScope,
}

impl<S> FromRequestParts<S> for RequireAdminScoped
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = app_state(parts, state).await;
        let path = parts.uri.path().to_string();
        let org_slug = parts.uri.query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "org")
                .map(|(_, v)| v.into_owned())
        });
        let csrf_token = parts
            .extensions
            .get::<csrf::CsrfToken>()
            .map(|t| t.0.clone())
            .unwrap_or_default();
        let (ctx, scope) = require_admin_with_scope(
            &app_state,
            &parts.headers,
            &path,
            org_slug.as_deref(),
            &csrf_token,
        )
        .await?;
        Ok(RequireAdminScoped { ctx, scope })
    }
}

/// License gate for the Organizations feature. Returns the [`FeatureStatus`]
/// on Allowed/GraceReadOnly so callers can vary on grace, and an upsell
/// `Response` on Locked.
#[allow(clippy::result_large_err)]
pub(crate) fn gate_orgs_feature_or_upsell(
    state: &AppState,
    csrf_token: &str,
    email: &str,
) -> Result<FeatureStatus, Response> {
    let status = state.license.feature(Feature::Orgs);
    if matches!(status, FeatureStatus::Locked) {
        return Err(render_upsell(state, csrf_token, email, Feature::Orgs));
    }
    Ok(status)
}

/// Expose the Forseti-issued CSRF token to handlers, read from request extensions (set by
/// [`crate::csrf::middleware`]) or the `forseti_csrf` cookie as fallback. Empty string when neither has a value.
pub(crate) struct Csrf(pub(crate) String);

impl<S> FromRequestParts<S> for Csrf
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(t) = parts.extensions.get::<csrf::CsrfToken>() {
            return Ok(Csrf(t.0.clone()));
        }
        let token = csrf::read_csrf_cookie(&parts.headers).unwrap_or_default();
        Ok(Csrf(token))
    }
}

pub(crate) fn forbid_response() -> Response {
    (axum::http::StatusCode::FORBIDDEN, "CSRF check failed").into_response()
}

/// Front every Forseti-owned POST: `Some(forbid_response())` on CSRF mismatch, `None` on pass.
pub(crate) fn verify_csrf_or_forbid(
    headers: &axum::http::HeaderMap,
    form_token: Option<&str>,
) -> Option<Response> {
    if !csrf::verify_csrf(headers, form_token.unwrap_or("")) {
        return Some(forbid_response());
    }
    None
}
