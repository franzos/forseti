//! Org invite mint + accept + email re-claim flows.
//!
//! Invite tokens are stored in `organization_invites` (URL handle in
//! `token`, payload in the row). Mirrors the `SecretReveal` shape: the
//! URL carries only the opaque token, the row carries the bound
//! `{ org_id, email, role, expires_at }` so a leaked URL can't be replayed
//! after the row expires + gets pruned.
//!
//! Default TTL: 7 days. Operator can dial up by overriding the constant
//! below in a follow-up (deferred — no operator has asked yet).

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::Form;
use rand::Rng;
use serde::Deserialize;
use std::str::FromStr;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
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
        // Member invites are owner-only and POST-only from the members
        // page; the handler verifies the owner role + CSRF before
        // minting the token + sending mail.
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
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    form: Form<InviteForm>,
) -> Response {
    post_invite(state, None, headers, sess, csrf, actx, form).await
}

async fn post_invite_named(
    state: State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    form: Form<InviteForm>,
) -> Response {
    post_invite(state, Some(slug), headers, sess, csrf, actx, form).await
}

#[derive(Debug, Deserialize)]
struct InviteForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    email: String,
    role: Option<String>,
}

async fn post_invite(
    State(state): State<AppState>,
    slug: Option<String>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: Csrf,
    actx: AuditCtx,
    Form(form): Form<InviteForm>,
) -> Response {
    let target = match orgs::settings_page::resolve_org_or_404(&state, slug.as_deref()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    post_invite_for(state, headers, csrf.0, sess, actx, target.org.id, form).await
}

#[allow(clippy::too_many_arguments)]
async fn post_invite_for(
    state: AppState,
    headers: HeaderMap,
    csrf_token: String,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    org_id: String,
    form: InviteForm,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
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
    // Best-effort lookup of org name for the mail body and slug for the
    // redirect. Falls back to the id/"default" if the row is unreachable
    // — the invite token is still valid either way.
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

/// Bounce back to the org's members page, surfacing `msg` as a
/// query-string error the template can render. Smaller-diff choice over
/// wiring this through the flash mechanism — the members handler can
/// pick the param up once it grows an error-banner branch.
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
    /// When `true` the page renders a POST form (CSRF-protected) that
    /// performs the membership write. When `false` the page renders an
    /// `<a>` CTA (e.g. for the "sign out and sign back in as ..." or
    /// "register first" branches). Keeps a single template handling
    /// every accept landing.
    can_accept_now: bool,
    /// Carried into the POST form so the handler can re-fetch the invite
    /// row. Empty when `can_accept_now == false`.
    token: String,
}

/// `GET /invite/accept?token=...`
///
/// Always idempotent — only ever renders a confirmation page. The
/// actual membership write is gated behind the POST handler below so
/// the destructive side-effect is CSRF-protected and tied to an
/// explicit user click.
///
/// Three branches drive the rendered page:
/// 1. Anonymous → CTA points to Kratos registration with a `return_to`
///    of `/invite/finalize?token=...`.
/// 2. Signed in + verified email matches the invite → render a CSRF-
///    protected POST form that performs the accept.
/// 3. Signed in but the invite is for a different email → CTA points
///    to logout, so the user can re-sign-in as the invited email.
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
        // Reject unverified identities (spec mitigation #3): force
        // verification before joining any org.
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
        // Render the CSRF-protected POST form. The button itself is the
        // single explicit confirmation step that triggers the
        // membership write.
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

    // Different account is currently signed in. Surface a CTA that signs
    // them out before re-routing through accept.
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
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    token: String,
}

/// `POST /invite/accept` — explicit confirmation of an invite. Validates
/// CSRF, re-fetches the invite (so a state change between GET render
/// and POST is caught), verifies the session email still matches +
/// verified, then writes the membership row inside a transaction.
async fn invite_accept_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Csrf(csrf_token): Csrf,
    actx: AuditCtx,
    session: OptionalSession,
    Form(form): Form<InviteAcceptForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
    }
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

/// `/invite/finalize?token=...` — landing after Kratos registration
/// completes via `return_to`.
///
/// This handler no longer writes any state; it just bounces back to
/// the GET confirmation page (`/invite/accept?token=...`) which the
/// user has to explicitly confirm by clicking the POST form button.
/// Keeping the write off the GET surface satisfies the
/// "GET-must-not-have-side-effects" rule the rest of Forseti
/// follows.
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

/// Send the invite mail directly over SMTP via `lettre`. Kratos's admin
/// API doesn't expose a one-off `POST /admin/courier/messages` endpoint
/// in v26+ (returns 405), so Forseti-originated mail rides its own
/// transport configured under `[smtp]`.
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

/// Pure helper that materialises the invite email's `(subject, body)`. Split
/// out from [`send_invite_email`] so unit tests can lock the exact strings
/// without standing up an SMTP transport.
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
    //! Locks the invite email's subject + body shape. Regression for the
    //! bug where the inviter, org name, brand, and role weren't all making
    //! it into the rendered email.
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
