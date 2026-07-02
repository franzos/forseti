//! `/oauth/device` — the browser-facing device-verification screen (RFC 8628).
//!
//! Hydra redirects the human here (`verification_uri`) with
//! `?device_challenge=…&user_code=…`. Correlation is by `user_code` against
//! Forseti's own `device_sessions` row, not Hydra context: the device-authz
//! request carries none and there's no get-device-request admin API. The
//! host-bound "did YOU start this login as `<username>` on `<hostname>`?"
//! prompt is the RFC 8628 §5.4 phishing mitigation.
//!
//! On confirm we POST `accept_user_code_request`, which drives the login +
//! consent leg (consent never auto-skips for the PAM client; see
//! `consent.rs`).

use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::csrf::CsrfForm;
use crate::extractors::RequireSession;
use crate::ory;
use crate::page_chrome::{Chrome, PageChrome, ReqLocale};
use crate::posix::db;
use crate::render::render;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct DeviceVerifyQuery {
    /// Absent when the user navigated to `/oauth/device` directly (bare
    /// code-entry form).
    #[serde(default)]
    device_challenge: Option<String>,
    #[serde(default)]
    user_code: Option<String>,
}

#[derive(Template)]
#[template(path = "oauth/device_verify.html")]
struct DeviceVerifyTemplate {
    chrome: PageChrome,
    device_challenge: String,
    user_code: String,
    /// Target + host from the device session. `None` when no session matches
    /// the `user_code`; the template then shows a plain code-entry prompt
    /// without the host-bound consent panel.
    target: Option<VerifyTarget>,
}

struct VerifyTarget {
    username: String,
    hostname: String,
    host_id: String,
}

#[derive(Template)]
#[template(path = "oauth/device_done.html")]
struct DeviceDoneTemplate {
    chrome: PageChrome,
    error: bool,
}

/// `GET /oauth/device` — render the verification screen, showing the host +
/// target account looked up by `user_code`. Gated behind a Kratos session
/// (RFC 8628 §3.3: the user authenticates at the verification URI) so the
/// host-bound `(username, hostname)` target is never disclosed to an
/// unauthenticated caller guessing user codes.
pub(crate) async fn device_verify(
    State(state): State<AppState>,
    _session: RequireSession,
    Query(query): Query<DeviceVerifyQuery>,
    Chrome(chrome): Chrome,
) -> Response {
    let user_code = query.user_code.unwrap_or_default();
    let device_challenge = query.device_challenge.unwrap_or_default();

    let target = if user_code.is_empty() {
        None
    } else {
        load_target(&state, &user_code).await
    };

    render(&DeviceVerifyTemplate {
        chrome,
        device_challenge,
        user_code,
        target,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeviceVerifyForm {
    device_challenge: String,
    user_code: String,
}

/// `POST /oauth/device` — accept the user code with Hydra, which then drives
/// login + consent. On success we follow Hydra's `redirect_to`.
pub(crate) async fn device_verify_submit(
    State(state): State<AppState>,
    _session: RequireSession,
    ReqLocale(locale): ReqLocale,
    CsrfForm(form): CsrfForm<DeviceVerifyForm>,
) -> Response {
    // Re-load by user_code so a tampered POST can't accept a code with no
    // backing session.
    if load_target(&state, &form.user_code).await.is_none() {
        return render(&DeviceDoneTemplate {
            chrome: anon_chrome(&state, locale),
            error: true,
        });
    }

    match ory::hydra::accept_user_code_request(&state.ory, &form.device_challenge, &form.user_code)
        .await
    {
        Ok(redirect) if !redirect.redirect_to.is_empty() => {
            Redirect::to(&redirect.redirect_to).into_response()
        }
        Ok(_) => Redirect::to("/oauth/device/done").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "device_verify: accept_user_code_request failed");
            render(&DeviceDoneTemplate {
                chrome: anon_chrome(&state, locale),
                error: true,
            })
        }
    }
}

/// `GET /oauth/device/done` — terminal "approved, return to your terminal"
/// page. `?error=1` renders the expired/failed variant.
#[derive(Debug, Deserialize)]
pub(crate) struct DeviceDoneQuery {
    #[serde(default)]
    error: Option<String>,
}

pub(crate) async fn device_done(
    Query(query): Query<DeviceDoneQuery>,
    Chrome(chrome): Chrome,
) -> Response {
    render(&DeviceDoneTemplate {
        chrome,
        error: query.error.is_some(),
    })
}

/// Look up the device session by `user_code` and project it to the host-bound
/// consent panel. `None` when no session matches.
async fn load_target(state: &AppState, user_code: &str) -> Option<VerifyTarget> {
    let session = match db::device_session_by_user_code(&state.db, user_code).await {
        Ok(Some(s)) => s,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "device_verify: session lookup failed");
            return None;
        }
    };
    // Fall back to the id if the host row is gone (revoked between init and
    // approval).
    let hostname = match db::host_by_id(&state.db, &session.host_id).await {
        Ok(Some(h)) => h.hostname,
        _ => session.host_id.clone(),
    };
    Some(VerifyTarget {
        username: session.requested_username,
        hostname,
        host_id: session.host_id,
    })
}

/// Anonymous chrome for the POST error path (the `Chrome` extractor isn't
/// available once the request body is consumed).
fn anon_chrome(state: &AppState, locale: crate::locale::LanguageIdentifier) -> PageChrome {
    PageChrome::from_parts(state, String::new(), String::new(), locale)
}
