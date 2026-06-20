//! `/settings/account` — danger zone (account self-deletion).
//!
//! The deletion is a saga over the Forseti-owned webhook outbox: every app
//! the user has consent grants with gets a signed delete notification.
//! See `TODO.md` §1 for the full design (state machine, retry policy,
//! reconciliation).
//!
//! Privileged-session enforcement reuses the same `?refresh=true` gate
//! that `/settings/password` uses — we initiate a Kratos settings flow
//! purely as a "is this session privileged?" probe, then proceed with
//! our own delete code. Kratos's admin delete doesn't enforce re-auth
//! itself, so we have to do it here.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::Form;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::csrf;
use crate::extractors::Csrf;
use crate::flow_view::session_email;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;
use crate::webhook;
use crate::FlowQuery;

use super::{fetch_settings_subpage, SettingsSection};

/// Card listing on `GET /settings/account/delete` so the user can see
/// *which* apps will receive the delete notification. Adds one Hydra
/// admin call to the render — cheap relative to the trust benefit.
#[derive(Debug, Clone)]
pub(crate) struct NotifiedApp {
    pub(crate) name: String,
}

#[derive(Template)]
#[template(path = "settings_account.html")]
struct SettingsAccountTemplate {
    chrome: PageChrome,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

#[derive(Template)]
#[template(path = "settings_account_delete_confirm.html")]
struct SettingsAccountDeleteConfirmTemplate {
    chrome: PageChrome,
    notified_apps: Vec<NotifiedApp>,
    /// Kratos settings flow id, threaded through the form action so the
    /// POST handler can re-run the same privileged-session check via
    /// `fetch_settings_subpage`. Without it, the POST would land with no
    /// `?flow=` and bounce through a fresh Kratos init, losing the form
    /// body.
    flow_id: String,
    referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

/// `GET /settings/account` — danger zone landing page. Only needs an
/// active session; the privileged-session check is deferred to the
/// confirm page.
pub(crate) async fn settings_account(
    State(state): State<AppState>,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    render(&SettingsAccountTemplate {
        chrome: PageChrome::from_parts(&state, sess.email, csrf.0),
        referrer_banner: banner.0,
    })
}

/// `GET /settings/account/delete` — confirm page. Gated behind the
/// privileged-session refresh window (via `fetch_settings_subpage`), so
/// landing here means the user has freshly re-authenticated.
pub(crate) async fn settings_account_delete(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    let (session, flow) =
        match fetch_settings_subpage(&state, &headers, &query, SettingsSection::Account, &sess)
            .await
        {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };

    let user_id = session
        .identity
        .as_ref()
        .map(|i| i.id.clone())
        .unwrap_or_default();
    let notified_apps = list_apps_to_notify(&state, &user_id).await;
    let flow_id = flow
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    render(&SettingsAccountDeleteConfirmTemplate {
        chrome: PageChrome::from_parts(&state, session_email(&session), csrf.0),
        notified_apps,
        flow_id,
        referrer_banner: banner.0,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteForm {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: Option<String>,
    /// Belt-and-braces: the form asks the user to type their email so a
    /// stray click can't trigger a destructive action.
    #[serde(default)]
    pub(crate) confirm_email: String,
}

/// `POST /settings/account/delete` — runs the outbox saga.
pub(crate) async fn settings_account_delete_submit(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }

    // Same privileged gate as the GET — if the privileged window lapsed
    // between confirm and submit, bounce back through `/login?refresh=true`.
    let session =
        match fetch_settings_subpage(&state, &headers, &query, SettingsSection::Account, &sess)
            .await
        {
            Ok((session, _)) => session,
            Err(resp) => return resp,
        };

    // Belt-and-braces: typed-email confirm must match the session's email.
    let session_email_str = session_email(&session);
    if !form
        .confirm_email
        .trim()
        .eq_ignore_ascii_case(&session_email_str)
    {
        tracing::warn!(
            actor = %session_email_str,
            "account.self_delete rejected: confirm_email mismatch"
        );
        return Redirect::to("/settings/account/delete").into_response();
    }

    run_delete_saga(&state, &session, &actx).await
}

async fn run_delete_saga(state: &AppState, session: &ory::Session, actx: &AuditCtx) -> Response {
    let Some(identity) = session.identity.as_ref() else {
        tracing::error!("session has no identity; refusing self-delete");
        return render_delete_failure(
            state,
            "Your session is in an unexpected state. Please sign in again and retry.",
        );
    };
    let user_id = identity.id.clone();
    let actor_email = session_email(session);
    let event_id = Uuid::new_v4();
    let deleted_at = Utc::now();

    tracing::info!(
        action = "account.self_delete.start",
        actor = %actor_email,
        event_id = %event_id,
        user_id = %user_id,
        "account self-delete: saga starting"
    );

    // Block before anything destructive: refuse to orphan an org whose
    // only owner is leaving while other members remain. Solo orgs (sole
    // owner, no other members) are not returned and delete normally.
    match crate::orgs::db::orgs_where_sole_owner_with_other_members(&state.db, &user_id).await {
        Ok(blocking) if !blocking.is_empty() => {
            let names = blocking
                .iter()
                .map(|(_, name)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            tracing::warn!(
                actor = %actor_email,
                user_id = %user_id,
                orgs = %names,
                "account self-delete blocked: sole owner of org(s) with other members"
            );
            return render_delete_failure(
                state,
                &format!(
                    "You're the only owner of {names}. Transfer ownership to another \
                     member before deleting your account."
                ),
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "sole-owner check failed; aborting before destructive call"
            );
            return render_delete_failure(
                state,
                "We couldn't verify your organization ownership. Nothing was changed; \
                 please try again in a moment.",
            );
        }
    }

    // Enumerate which apps need notification — every consent-granted
    // client with an `account_deletion_url` is a target. With SETs the
    // signing key is Forseti-owned (not per-client), so there's no
    // additional opt-in to mint.
    //
    // Bail BEFORE the destructive call if Hydra is unreachable. Letting
    // the saga proceed with an empty target list would destroy the
    // Kratos identity while leaving every integrator with a stale copy
    // and no notification — a silent compliance regression.
    let targets = match collect_webhook_targets(state, &user_id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                error = %e,
                event_id = %event_id,
                user_id = %user_id,
                "consent-session enumeration failed; aborting before destructive call"
            );
            return render_delete_failure(
                state,
                "We couldn't reach the consent service to notify your connected apps. \
                 Nothing was changed; please try again in a moment.",
            );
        }
    };
    let target_count = targets.len();

    // Saga step 4: enqueue PENDING rows. Empty `targets` short-circuits
    // and `enqueue_pending` writes nothing.
    if let Err(e) = webhook::enqueue_pending(
        &state.db,
        &state.signing_key,
        &state.cfg.self_.url,
        event_id,
        &user_id,
        deleted_at,
        &targets,
    )
    .await
    {
        tracing::error!(error = %e, event_id = %event_id, "outbox write failed; aborting saga");
        return render_delete_failure(
            state,
            "We couldn't prepare the delete notifications. Nothing was changed; please try again.",
        );
    }

    // Saga step 5: best-effort Hydra session revoke. Don't block on it.
    if let Err(e) = ory::hydra::revoke_consent_sessions_for_subject(&state.ory, &user_id).await {
        tracing::warn!(error = %e, "hydra revoke during self-delete failed (continuing)");
    }

    // Saga step 6: the destructive call. On failure, flip outbox to
    // ABORTED so the worker never sends and surface an error to the user.
    match ory::kratos::admin_delete_identity(&state.ory, &user_id).await {
        Ok(()) => {
            // Cascade: drop every org membership the now-deleted identity
            // held. Mirrors the admin-delete path so neither route leaves
            // ghost rows on the members page.
            match crate::orgs::db::remove_member_everywhere(&state.db, &user_id).await {
                Ok(n) if n > 0 => tracing::info!(
                    user_id = %user_id,
                    removed = n,
                    "self-delete: removed org memberships",
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = ?e,
                    user_id = %user_id,
                    "self-delete: org_members cleanup failed",
                ),
            }
            if let Err(e) = webhook::confirm_event(&state.db, event_id).await {
                tracing::error!(error = %e, event_id = %event_id, "outbox confirm failed; rows stay PENDING and will be reconciled at startup");
            }
            // Compliance-critical: account self-deletion must leave an
            // audit trail. Identity is already destroyed, so we can't
            // unwind on Err — but `audit::log` emits a structured
            // `audit_fallback` stderr line so the row stays recoverable
            // from log scrapes. Log loudly here too so operators see it
            // in their primary log stream.
            if let Err(e) = audit::log(
                &state.db,
                AuditEvent::new(action::ACCOUNT_SELF_DELETED)
                    .actor_user(&user_id, &actor_email)
                    .target(target_kind::IDENTITY, user_id.clone())
                    .with_ctx(actx)
                    .critical()
                    .metadata(audit_metadata!(
                        "event_id" => event_id.to_string(),
                        "webhook_targets" => target_count,
                    )),
            )
            .await
            {
                tracing::error!(
                    error = %e,
                    event_id = %event_id,
                    user_id = %user_id,
                    actor = %actor_email,
                    "CRITICAL audit row for account.self_deleted failed to persist; recover from audit_fallback stderr event"
                );
            }
            // Saga step 7: log out the browser. The Kratos identity is
            // gone server-side, but the browser still holds the Kratos
            // session cookie until it expires. Clear it explicitly so
            // the user doesn't briefly carry a stale cookie back to any
            // surface that hasn't yet observed the 401.
            let mut response = Redirect::to("/login?msg=account_deleted").into_response();
            let secure = state.cfg.self_.is_https();
            if let Ok(hv) = axum::http::HeaderValue::from_str(&clear_kratos_session_cookie(secure))
            {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, hv);
            }
            if let Ok(hv) = axum::http::HeaderValue::from_str(&csrf::delete_csrf_cookie(secure)) {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, hv);
            }
            response
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                actor = %actor_email,
                event_id = %event_id,
                user_id = %user_id,
                "kratos admin delete failed; aborting outbox"
            );
            if let Err(e2) = webhook::abort_event(&state.db, event_id).await {
                tracing::error!(error = %e2, event_id = %event_id, "outbox abort failed");
            }
            render_delete_failure(
                state,
                "We couldn't delete your account. Please try again in a moment.",
            )
        }
    }
}

/// Pull every consent grant for `user_id` and emit one webhook target
/// per (client_id, account_deletion_url) pair. The receiver verifies the
/// signed SET against Forseti's published JWKS — no shared-secret
/// minting needed any more.
///
/// Returns `Err` when the Hydra consent-session lookup itself fails.
/// Callers must treat this as fatal to the saga: silently proceeding
/// with an empty target list lets the destructive Kratos delete go
/// through while integrators never learn the user is gone. The confirm
/// page's `list_apps_to_notify` swallows the same failure deliberately —
/// rendering an incomplete app list on a read-only screen is acceptable;
/// dropping fan-out on the write path is not.
async fn collect_webhook_targets(
    state: &AppState,
    user_id: &str,
) -> anyhow::Result<Vec<webhook::WebhookTarget>> {
    let sessions = ory::hydra::list_consent_sessions_by_subject(&state.ory, user_id).await?;

    // De-duplicate by client_id — a user can have many consent sessions
    // with the same client (one per device / scope set).
    let mut seen: std::collections::HashSet<String> = Default::default();
    let mut targets = Vec::new();
    for sess in sessions {
        let Some(req) = sess.consent_request else {
            continue;
        };
        let Some(client) = req.client else { continue };
        let Some(client_id) = client.client_id else {
            continue;
        };
        if !seen.insert(client_id.clone()) {
            continue;
        }
        let Some(url) = deletion_url_from_metadata(client.metadata.as_ref()) else {
            continue;
        };
        targets.push(webhook::WebhookTarget { client_id, url });
    }
    Ok(targets)
}

/// For the confirm-page card list (names only, no secrets needed).
async fn list_apps_to_notify(state: &AppState, user_id: &str) -> Vec<NotifiedApp> {
    let sessions = match ory::hydra::list_consent_sessions_by_subject(&state.ory, user_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, user_id, "could not list consent sessions");
            return Vec::new();
        }
    };
    let mut seen: std::collections::HashSet<String> = Default::default();
    let mut apps = Vec::new();
    for sess in sessions {
        let Some(req) = sess.consent_request else {
            continue;
        };
        let Some(client) = req.client else { continue };
        let Some(client_id) = client.client_id else {
            continue;
        };
        if !seen.insert(client_id.clone()) {
            continue;
        }
        if deletion_url_from_metadata(client.metadata.as_ref()).is_none() {
            continue;
        }
        apps.push(NotifiedApp {
            name: client.client_name.unwrap_or(client_id),
        });
    }
    apps
}

/// Pull `metadata.forseti.account_deletion_url` from a Hydra client's
/// `metadata` blob. Hydra has no typed field for this — we park it
/// under our namespaced subobject so we don't collide with anything
/// the operator or other tooling stores there.
fn deletion_url_from_metadata(metadata: Option<&serde_json::Value>) -> Option<String> {
    metadata?
        .get("forseti")?
        .get("account_deletion_url")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn render_delete_failure(state: &AppState, body: &str) -> Response {
    crate::web::render_error_boundary(
        state,
        "Account deletion failed",
        body,
        "/settings/account",
        "Back to account",
    )
    .into_response()
}

/// Build a `Set-Cookie` header value that clears the Kratos session
/// cookie (`ory_kratos_session`) on the browser. The cookie attributes
/// (`Path=/`, `HttpOnly`, `SameSite=Lax`, optional `Secure`, plus a
/// past `Expires` to trigger eviction) match the shape Kratos itself
/// emits in the path-prefixed single-host topology recommended by
/// `docs/operator-guide-proxy.md` — same name + same path + same
/// domain, so the browser overwrites the existing cookie.
///
/// Expiry is signalled via `Expires=Thu, 01 Jan 1970 00:00:00 GMT`
/// (not `Max-Age=0`) for parity with `flash::clear_flash_cookie` —
/// avoids a `time` crate dep, and both browser semantics are
/// equivalent in practice.
///
/// In a split-origin deployment (Kratos on a separate host or subdomain
/// from Forseti) the browser scopes Kratos's cookie to Kratos's
/// origin, and this header is a no-op from Forseti — the stale
/// cookie sticks until the next request to Kratos returns 401 and
/// clears it server-side. Documented limitation; lives with the proxy
/// shape choice.
fn clear_kratos_session_cookie(secure: bool) -> String {
    let mut s = Cookie::build(("ory_kratos_session", ""))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .build()
        .to_string();
    // Past `Expires` mirrors what `clear_flash_cookie` does — fixed RFC
    // 1123 string in the epoch, no extra dep on a time-formatting crate.
    s.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    s
}
