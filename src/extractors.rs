//! Reusable axum extractors that consolidate the per-handler
//! "resolve a session / check admin / read CSRF token" boilerplate.
//!
//! Phase 1 introduces the helpers but only migrates a handful of call sites
//! as proof. Subsequent phases sweep the rest of the handlers onto these
//! extractors so the auth gate appears as a typed argument rather than a
//! `match whoami` ladder at the top of every function.

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

/// Resolve the caller's Kratos session, or short-circuit with a redirect to
/// `/login` (preserving the current path as `return_to`). Mirrors the
/// `let session = match whoami { ... }` boilerplate that the settings and
/// orgs handlers all open-code today.
///
/// Rejection is a fully-formed `Response`, so handlers use `?` against it:
///
/// ```ignore
/// async fn handler(sess: RequireSession) -> Response { ... }
/// ```
pub(crate) struct RequireSession {
    pub(crate) session: ory::Session,
    pub(crate) identity_id: String,
    pub(crate) email: String,
}

/// Why [`resolve_session`] couldn't hand back a usable session. Each variant
/// carries the pre-built artefact a caller typically wants — a redirect for
/// the two anonymous-ish cases, the raw error for the transport-failure
/// case — but callers stay free to ignore them and synthesise their own
/// response (the admin gate does that for `KratosError`).
pub(crate) enum SessionFailure {
    /// No session at all. Embeds the canonical
    /// `/login?return_to=<path>` redirect.
    NoSession(Redirect),
    /// Session exists but AAL is below what Kratos's whoami required.
    /// Embeds the canonical `/login?aal=aal2&return_to=<path>` redirect.
    InsufficientAal(Redirect),
    /// Transport/upstream error talking to Kratos. The caller decides
    /// whether to surface this as a redirect (public surfaces) or as a
    /// 403 page (admin surfaces).
    KratosError(anyhow::Error),
}

/// Project a [`ory::kratos::WhoamiOutcome`] into the required-session shape.
/// Sibling of [`optional_session_from_outcome`] for the eager-redirect path;
/// both the direct-whoami and the middleware-cached path funnel through this
/// so the InsufficientAal / None mapping lives in one place.
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

/// Single source of truth for the `match whoami { ... }` ladder. Returns
/// either the resolved session or a [`SessionFailure`] the caller maps to
/// its preferred response shape.
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

/// Extractor-flavoured wrapper around [`resolve_session`]: consults the
/// middleware-cached whoami first (so handlers behind the orgs middleware
/// don't pay a second Kratos round-trip), and only on a cache miss falls
/// through to a direct `whoami` call. Both branches funnel through
/// [`required_session_from_outcome`] so the InsufficientAal / None mapping
/// is spelled out exactly once.
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
        let path = parts.uri.path().to_string();
        let session = match resolve_session_from_parts(&app_state, parts, &path).await {
            Ok(s) => *s,
            Err(SessionFailure::InsufficientAal(r)) | Err(SessionFailure::NoSession(r)) => {
                return Err(r.into_response());
            }
            Err(SessionFailure::KratosError(e)) => {
                // Transport / 5xx talking to Kratos — distinct from a real
                // 401. Redirecting to /login here would sign the user out on
                // a network flap (and /login itself hits whoami, so we'd
                // either loop or render a misleading "sign in" screen).
                // Render an error page instead so the user can retry once
                // Kratos is back.
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

/// Pull the middleware-cached whoami result out of request extensions, if
/// present. `None` means the orgs middleware didn't run for this route (or
/// the request carried no Kratos session cookie), so the caller should fall
/// back to a direct whoami call. Single source of truth for the
/// "consult middleware cache" half of every session-resolution fork.
fn cached_whoami(extensions: &axum::http::Extensions) -> Option<ory::kratos::WhoamiOutcome> {
    extensions
        .get::<crate::orgs::middleware::CachedWhoami>()
        .map(|c| c.0.clone())
}

/// Pull the [`AppState`] out of any state `S` that exposes it. The `State`
/// extractor is infallible for our setup, so this collapses the repeated
/// `.await.expect(...)` to one call site.
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

/// Three-state session probe for handlers that don't want the eager
/// redirect [`RequireSession`] performs. Mirrors [`ory::kratos::WhoamiOutcome`]
/// but pre-extracts the identity fields callers typically reach for, so
/// the open-coded `match whoami { Ok(Ok(s)) => ... }` ladder disappears
/// from every call site.
///
/// Use this when the handler must distinguish "no session" from
/// "session at insufficient AAL" (e.g. registration step-up routing,
/// oauth login ACR step-up), or when "no session" is a valid path
/// (e.g. anonymous invite landing, post-registration verification).
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

    /// Identity id when [`OptionalSession::Ok`], `None` otherwise. Callers that
    /// want empty-on-missing for display spell it `.identity_id().unwrap_or_default()`;
    /// audit actor fields must handle the `None` case explicitly.
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

/// Project a [`ory::kratos::WhoamiOutcome`] into the richer
/// [`OptionalSession`] shape (pre-extracting identity fields on `Ok`).
/// Shared by every entry point so the "Ok ⇒ split out identity_id/email"
/// stanza isn't duplicated three times.
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

/// Free-function form of [`OptionalSession`] for code paths that don't
/// run inside an axum extractor (helpers called deep inside a handler
/// body). Consults the middleware-cached whoami in `extensions` first
/// (mirroring [`OptionalSession`]'s extractor impl) and only falls back
/// to a direct [`ory::kratos::whoami`] call on a cache miss, so handlers
/// behind the orgs middleware don't pay a second Kratos round-trip.
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

/// Admin gate equivalent of [`RequireSession`]. Chains through
/// [`crate::admin::require_admin`] so every protected `/admin/*` route gets
/// the same redirect / forbidden semantics without re-stating them at the
/// top of every handler.
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

/// Org-scoped admin gate. Wraps [`crate::admin::require_admin_with_scope`]
/// so the auth + license + org-ownership check runs as an axum extractor
/// (i.e. *before* `Form<…>` body extraction). Without this, handlers that
/// did the gate in-body leaked their form-field shape via the 422 body the
/// `Form` extractor returns to unauthenticated callers.
///
/// The `?org=<slug>` query parameter is parsed from the request URI;
/// missing / empty means "Forseti-wide admin" (the `admin.allowed_emails`
/// path). Present means "org-scoped admin" (owner role on that org).
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

/// Expose the Forseti-issued CSRF token to handlers without re-reading the
/// cookie. The token is preferentially read from request extensions (set by
/// [`crate::csrf::middleware`]); for routes not behind that middleware it
/// falls back to the inbound `forseti_csrf` cookie. Returns an empty string
/// when neither source carries a value.
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

/// Short-hand for the `if !csrf::verify_csrf(&headers, form.csrf.as_deref().unwrap_or("")) { return 403 }`
/// pattern that fronts every Forseti-owned POST. Returns `Some(forbid_response())`
/// on mismatch, `None` on pass. The form's CSRF field is conventionally
/// `Option<String>`; callers pass `form.csrf.as_deref()`.
pub(crate) fn verify_csrf_or_forbid(
    headers: &axum::http::HeaderMap,
    form_token: Option<&str>,
) -> Option<Response> {
    if !csrf::verify_csrf(headers, form_token.unwrap_or("")) {
        return Some(forbid_response());
    }
    None
}
