//! Org invite mint + accept + email re-claim flows.
//!
//! The URL carries only the opaque `token`; the row carries the bound
//! `{ org_id, email, role, expires_at }`, so a leaked URL can't be replayed
//! after the row expires and gets pruned.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use rand::Rng;
use serde::Deserialize;
use std::str::FromStr;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, OptionalSession};
use crate::orgs::{self, Role};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/invite/accept",
            get(invite_accept_get).post(invite_accept_post),
        )
        .route("/invite/finalize", get(invite_finalize_get))
        .route(
            "/settings/organization/members/invite",
            post(post_invite_default),
        )
        .route(
            "/settings/organizations/{slug}/members/invite",
            post(post_invite_named),
        )
}

async fn post_invite_default(
    state: State<AppState>,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    form: CsrfForm<InviteForm>,
) -> Response {
    post_invite(state, None, sess, csrf, actx, form).await
}

async fn post_invite_named(
    state: State<AppState>,
    Path(slug): Path<String>,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    form: CsrfForm<InviteForm>,
) -> Response {
    post_invite(state, Some(slug), sess, csrf, actx, form).await
}

#[derive(Debug, Deserialize)]
struct InviteForm {
    email: String,
    role: Option<String>,
}

async fn post_invite(
    State(state): State<AppState>,
    slug: Option<String>,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<InviteForm>,
) -> Response {
    let target = match orgs::settings_page::resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    post_invite_for(state, csrf.0, sess, actx, target.org.id, form).await
}

#[allow(clippy::too_many_arguments)]
async fn post_invite_for(
    state: AppState,
    csrf_token: String,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    org_id: String,
    form: InviteForm,
) -> Response {
    let identity_id = sess.identity_id;
    let email_for_upsell = sess.email;
    if orgs::org_role(&state.db, &identity_id, &org_id).await != Some(Role::Owner) {
        return (StatusCode::FORBIDDEN, "owner role required").into_response();
    }
    // Named orgs require the license; Default org is OSS.
    if org_id != orgs::DEFAULT_ORG_ID {
        if let Err(r) =
            crate::extractors::gate_orgs_feature_or_upsell(&state, &csrf_token, &email_for_upsell)
        {
            return r;
        }
    }

    let email = form.email.trim().to_lowercase();
    if email.is_empty() || lettre::Address::from_str(&email).is_err() {
        return back_to_members(&state.db, &org_id, "Enter a valid email address")
            .await
            .into_response();
    }
    let role = match form.role.as_deref() {
        Some("owner") => Role::Owner,
        _ => Role::Member,
    };

    let token = random_invite_token();
    let ttl_days = state.cfg.orgs.invite_ttl_days;
    if let Err(e) = orgs::insert_invite(
        &state.db,
        &token,
        &org_id,
        &email,
        role,
        Some(&identity_id),
        ttl_days,
    )
    .await
    {
        tracing::error!(error = ?e, "invite insert failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "invite insert failed").into_response();
    }
    let role_str = match role {
        Role::Owner => "owner",
        Role::Member => "member",
    };
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_INVITE_CREATED)
            .actor_user(&identity_id, &email_for_upsell)
            .target(target_kind::ORG, org_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "email" => &email,
                "role" => role_str,
            )),
    )
    .await;

    let accept_url = format!(
        "{}/invite/accept?token={}",
        state.cfg.self_.url.trim_end_matches('/'),
        token
    );
    // Best-effort org-name/slug lookup; the invite token is valid regardless.
    let org = orgs::org_by_id(&state.db, &org_id).await.ok().flatten();
    let org_name = org
        .as_ref()
        .map(|o| o.name.clone())
        .unwrap_or_else(|| org_id.clone());
    if let Err(e) = send_invite_email(
        &email,
        &accept_url,
        &state.cfg,
        &org_name,
        &email_for_upsell,
        role_str,
    )
    .await
    {
        tracing::warn!(error = ?e, email = %email, "invite courier dispatch failed; token still valid");
    }

    let target = if org_id == orgs::DEFAULT_ORG_ID {
        "/settings/organization/members".to_string()
    } else {
        let slug = org.as_ref().map(|o| o.slug.as_str()).unwrap_or("default");
        format!("/settings/organizations/{}/members", slug)
    };
    Redirect::to(&target).into_response()
}

/// Bounce back to the org's members page, surfacing `msg` as an `?error=`
/// query param the template can render.
async fn back_to_members(db: &crate::db::DbPool, org_id: &str, msg: &str) -> Redirect {
    let base = if org_id == orgs::DEFAULT_ORG_ID {
        "/settings/organization/members".to_string()
    } else {
        let slug = orgs::org_by_id(db, org_id)
            .await
            .ok()
            .flatten()
            .map(|o| o.slug)
            .unwrap_or_else(|| "default".to_string());
        format!("/settings/organizations/{}/members", slug)
    };
    if msg.is_empty() {
        Redirect::to(&base)
    } else {
        Redirect::to(&format!(
            "{base}?error={}",
            ory_client::apis::urlencode(msg)
        ))
    }
}

#[derive(Debug, Deserialize)]
struct InviteAcceptQuery {
    token: Option<String>,
}

#[derive(Template)]
#[template(path = "invite/accept.html")]
struct InviteAcceptTemplate {
    chrome: PageChrome,
    org_name: String,
    invited_email: String,
    role: String,
    /// "Sign in to accept", "Register to accept", or "Accept" depending on
    /// session state.
    cta_label: String,
    cta_url: String,
    /// `true` renders the CSRF-protected POST form; `false` renders an `<a>`
    /// CTA (sign-out or register-first branches).
    can_accept_now: bool,
    /// Carried into the POST form. Empty when `can_accept_now == false`.
    token: String,
}

/// `GET /invite/accept?token=...`: idempotent confirmation page only; the
/// membership write is gated behind the POST handler so it's CSRF-protected.
///
/// 1. Anonymous → CTA to Kratos registration, `return_to=/invite/finalize`.
/// 2. Signed in + verified email matches → CSRF-protected POST form.
/// 3. Signed in as a different email → CTA to logout + re-sign-in.
async fn invite_accept_get(
    State(state): State<AppState>,
    Query(q): Query<InviteAcceptQuery>,
    Csrf(csrf_token): Csrf,
    session: OptionalSession,
) -> Response {
    let Some(token) = q.token.filter(|t| !t.is_empty()) else {
        return (StatusCode::BAD_REQUEST, "missing token").into_response();
    };
    let Ok(Some(invite)) = orgs::fetch_invite(&state.db, &token).await else {
        return render_invalid_invite(&state, &csrf_token, "Invite not found").into_response();
    };
    if invite.is_accepted() {
        return render_invalid_invite(&state, &csrf_token, "Invite already accepted")
            .into_response();
    }
    if invite.is_expired(chrono::Utc::now()) {
        return render_invalid_invite(&state, &csrf_token, "Invite expired").into_response();
    }

    let session = match session {
        OptionalSession::Ok { session, .. } => Some(*session),
        _ => None,
    };

    let org_name = orgs::org_by_id(&state.db, &invite.org_id)
        .await
        .ok()
        .flatten()
        .map(|o| o.name)
        .unwrap_or_else(|| "this organization".to_string());

    // Anonymous: send to registration, preserve token through finalize.
    let Some(session) = session else {
        let return_to = format!(
            "{}/invite/finalize?token={}",
            state.cfg.self_.url.trim_end_matches('/'),
            token
        );
        let reg_url = ory::kratos::browser_init_url(
            ory::FlowKind::Registration,
            &state.cfg.kratos.public_url,
            Some(&return_to),
        );
        return render(&InviteAcceptTemplate {
            chrome: PageChrome::from_parts(&state, String::new(), csrf_token.clone()),
            org_name,
            invited_email: invite.email.clone(),
            role: invite.role.clone(),
            cta_label: format!("Register as {} and accept", invite.email),
            cta_url: reg_url,
            can_accept_now: false,
            token: String::new(),
        });
    };

    let session_email = crate::flow_view::session_email(&session);
    if session_email.to_lowercase() == invite.email.to_lowercase() {
        // Force email verification before joining any org (spec mitigation #3).
        let verified = session
            .identity
            .as_ref()
            .and_then(|i| i.verifiable_addresses.as_ref())
            .map(|addrs| {
                addrs
                    .iter()
                    .any(|a| a.value.to_lowercase() == session_email.to_lowercase() && a.verified)
            })
            .unwrap_or(false);
        if !verified {
            return render_invalid_invite(
                &state,
                &csrf_token,
                "Please verify your email before accepting the invite",
            )
            .into_response();
        }
        return render(&InviteAcceptTemplate {
            chrome: PageChrome::from_parts(&state, session_email, csrf_token.clone()),
            org_name,
            invited_email: invite.email.clone(),
            role: invite.role.clone(),
            cta_label: format!("Join {}", invite.email),
            cta_url: String::new(),
            can_accept_now: true,
            token,
        });
    }

    // A different account is signed in: CTA signs out then re-routes to accept.
    render(&InviteAcceptTemplate {
        chrome: PageChrome::from_parts(&state, session_email, csrf_token),
        org_name,
        invited_email: invite.email.clone(),
        role: invite.role.clone(),
        cta_label: format!("Sign out and sign in as {}", invite.email),
        cta_url: format!(
            "/logout?return_to=/invite/accept?token={}",
            ory_client::apis::urlencode(&token)
        ),
        can_accept_now: false,
        token: String::new(),
    })
}

#[derive(Debug, Deserialize)]
struct InviteAcceptForm {
    token: String,
}

/// `POST /invite/accept` — explicit confirmation of an invite. Validates
/// CSRF, re-fetches the invite (so a state change between GET render
/// and POST is caught), verifies the session email still matches +
/// verified, then writes the membership row inside a transaction.
async fn invite_accept_post(
    State(state): State<AppState>,
    Csrf(csrf_token): Csrf,
    actx: AuditCtx,
    session: OptionalSession,
    CsrfForm(form): CsrfForm<InviteAcceptForm>,
) -> Response {
    if form.token.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing token").into_response();
    }
    let Ok(Some(invite)) = orgs::fetch_invite(&state.db, &form.token).await else {
        return render_invalid_invite(&state, &csrf_token, "Invite not found").into_response();
    };
    if invite.is_accepted() {
        return render_invalid_invite(&state, &csrf_token, "Invite already accepted")
            .into_response();
    }
    if invite.is_expired(chrono::Utc::now()) {
        return render_invalid_invite(&state, &csrf_token, "Invite expired").into_response();
    }
    let session = match session {
        OptionalSession::Ok { session, .. } => *session,
        _ => {
            return Redirect::to(&format!(
                "/invite/accept?token={}",
                ory_client::apis::urlencode(&form.token)
            ))
            .into_response();
        }
    };
    let session_email = crate::flow_view::session_email(&session);
    if session_email.to_lowercase() != invite.email.to_lowercase() {
        return render_invalid_invite(
            &state,
            &csrf_token,
            "Sign in as the invited address to accept this invite",
        )
        .into_response();
    }
    let verified = session
        .identity
        .as_ref()
        .and_then(|i| i.verifiable_addresses.as_ref())
        .map(|addrs| {
            addrs
                .iter()
                .any(|a| a.value.to_lowercase() == session_email.to_lowercase() && a.verified)
        })
        .unwrap_or(false);
    if !verified {
        return render_invalid_invite(
            &state,
            &csrf_token,
            "Please verify your email before accepting the invite",
        )
        .into_response();
    }
    let identity_id = session
        .identity
        .as_ref()
        .map(|i| i.id.clone())
        .unwrap_or_default();
    finalize_membership(
        &state,
        &csrf_token,
        &invite,
        &identity_id,
        &session_email,
        &actx,
    )
    .await
}

#[derive(Debug, Deserialize)]
struct InviteFinalizeQuery {
    token: Option<String>,
}

/// `/invite/finalize?token=...`: landing after Kratos registration. Writes
/// no state; bounces back to the GET confirmation page so the side-effecting
/// accept stays behind an explicit POST.
async fn invite_finalize_get(
    State(_state): State<AppState>,
    Query(q): Query<InviteFinalizeQuery>,
    _headers: HeaderMap,
) -> Response {
    let Some(token) = q.token.filter(|t| !t.is_empty()) else {
        return Redirect::to("/").into_response();
    };
    Redirect::to(&format!(
        "/invite/accept?token={}",
        ory_client::apis::urlencode(&token)
    ))
    .into_response()
}

async fn finalize_membership(
    state: &AppState,
    csrf_token: &str,
    invite: &orgs::OrgInvite,
    identity_id: &str,
    session_email: &str,
    actx: &AuditCtx,
) -> Response {
    let role: Role = match invite.role.parse() {
        Ok(r) => r,
        Err(_) => {
            tracing::error!(
                invite_token = %invite.token,
                role = %invite.role,
                "invite carries an unknown role; refusing to finalize",
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invitation is corrupt. Contact your administrator.",
            )
                .into_response();
        }
    };
    match crate::orgs::db::finalize_invite_txn(
        &state.db,
        &invite.token,
        &invite.org_id,
        identity_id,
        role,
    )
    .await
    {
        Ok(crate::orgs::db::InviteFinalizeOutcome::Accepted) => {
            let role_str = match role {
                Role::Owner => "owner",
                Role::Member => "member",
            };
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ORG_INVITE_ACCEPTED)
                    .actor_user(identity_id, session_email)
                    .target(target_kind::ORG, invite.org_id.clone())
                    .with_ctx(actx)
                    .metadata(audit_metadata!(
                        "email" => &invite.email,
                        "role" => role_str,
                    )),
            )
            .await;
            let _ = audit::log(
                &state.db,
                AuditEvent::new(action::ORG_MEMBER_ADDED)
                    .actor_user(identity_id, session_email)
                    .target(target_kind::IDENTITY, identity_id.to_string())
                    .with_ctx(actx)
                    .metadata(audit_metadata!(
                        "org_id" => &invite.org_id,
                        "role" => role_str,
                        "via" => "invite",
                    )),
            )
            .await;
            Redirect::to("/").into_response()
        }
        Ok(crate::orgs::db::InviteFinalizeOutcome::AlreadyAccepted) => {
            render_invalid_invite(state, csrf_token, "Invite already accepted").into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, "finalize_membership: txn failed");
            render_invalid_invite(state, csrf_token, "Could not accept invite").into_response()
        }
    }
}

fn random_invite_token() -> String {
    let bytes: [u8; 24] = rand::rng().random();
    hex::encode(bytes)
}

#[derive(Template)]
#[template(path = "invite/invalid.html")]
struct InvalidInviteTemplate {
    chrome: PageChrome,
    message: String,
}

fn render_invalid_invite(state: &AppState, csrf_token: &str, message: &str) -> Response {
    render(&InvalidInviteTemplate {
        chrome: PageChrome::from_parts(state, String::new(), csrf_token.to_string()),
        message: message.to_string(),
    })
}

/// Send the invite mail over SMTP via `lettre`. Kratos's admin API has no
/// one-off courier endpoint in v26+ (405), so Forseti mail uses its own
/// `[smtp]` transport.
pub async fn send_invite_email(
    recipient: &str,
    accept_url: &str,
    cfg: &crate::config::AppConfig,
    org_name: &str,
    inviter_email: &str,
    role: &str,
) -> anyhow::Result<()> {
    let (subject, body) = build_invite_email(
        &cfg.brand.name,
        org_name,
        inviter_email,
        role,
        accept_url,
        cfg.orgs.invite_ttl_days,
    );
    crate::mailer::send_text(&cfg.smtp, &cfg.self_, recipient, &subject, &body).await
}

/// Pure `(subject, body)` builder, split from [`send_invite_email`] so tests
/// can lock the strings without an SMTP transport.
pub(crate) fn build_invite_email(
    brand_name: &str,
    org_name: &str,
    inviter_email: &str,
    role: &str,
    accept_url: &str,
    ttl_days: i64,
) -> (String, String) {
    let subject = format!("{inviter_email} invited you to {org_name} on {brand_name}");
    let body = format!(
        "Hello,\n\n{inviter_email} has invited you to join \"{org_name}\" on {brand_name} as {role}.\n\nAccept the invite by visiting:\n\n  {accept_url}\n\nThis invite expires in {ttl_days} days.\n\nIf you weren't expecting this email, you can safely ignore it.\n",
    );
    (subject, body)
}

#[cfg(test)]
mod invite_email_tests {
    //! Locks the invite email's subject + body shape (inviter, org, brand, role).
    use super::build_invite_email;

    #[test]
    fn invite_email_renders_subject_with_all_context() {
        let (subject, _body) = build_invite_email(
            "PortalCo",
            "Acme Engineering",
            "alice@acme.example",
            "owner",
            "https://example.test/invite/accept?token=opaque",
            7,
        );
        assert_eq!(
            subject, "alice@acme.example invited you to Acme Engineering on PortalCo",
            "subject must carry inviter, org name, and brand name",
        );
    }

    #[test]
    fn invite_email_renders_body_with_role_and_accept_url() {
        let (_subject, body) = build_invite_email(
            "PortalCo",
            "Acme Engineering",
            "alice@acme.example",
            "owner",
            "https://example.test/invite/accept?token=opaque",
            7,
        );
        assert!(
            body.contains("alice@acme.example has invited you to join \"Acme Engineering\" on PortalCo as owner"),
            "body must spell out inviter / org / brand / role; got: {body}",
        );
        assert!(
            body.contains("https://example.test/invite/accept?token=opaque"),
            "body must embed the accept URL verbatim; got: {body}",
        );
        assert!(
            body.contains("This invite expires in 7 days"),
            "body must mention the TTL; got: {body}",
        );
    }

    #[test]
    fn invite_email_passes_member_role_through() {
        let (_subject, body) = build_invite_email(
            "PortalCo",
            "Acme",
            "bob@acme.example",
            "member",
            "https://example.test/invite/accept?token=xyz",
            7,
        );
        assert!(
            body.contains("as member"),
            "non-owner role must propagate; got: {body}",
        );
    }
}
