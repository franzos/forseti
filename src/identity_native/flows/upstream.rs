//! Upstream sign-in: the provider submit on a flow (start) and the provider's redirect back
//! (callback). The browser carries a signed state cookie naming provider, flow kind, flow id and
//! `state`; the flow keeps `state` in its context until one callback consumes it.

use anyhow::Result;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::login::{INVALID_CREDENTIALS, NOT_VERIFIED};
use super::registration::{ACCOUNT_EXISTS, traits_of};
use super::settings::{self, NO_STRATEGY as SETTINGS_NO_STRATEGY};
use super::verification::{INVALID_CODE, address_problem};
use super::{
    Checked, Context, Dispatch, FINISHED, FlowRecord, PendingTraits, SAVE_ATTEMPTS, SEAL_UPSTREAM,
    Saved, Submission, SubmitOutcome, Submitted, kind_from_segment, new_flow, page_url,
};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::{Aal, FlowInit, FlowKind, browser_init_url};
use crate::identity_native::codes::Purpose;
use crate::identity_native::session::{self, Device, SessionRow};
use crate::identity_native::store::{
    self, CreateWithLink, IdentityRow, LinkDeleted, LinkInserted, NAME_MAX_CHARS,
};
use crate::identity_native::ui::Message;
use crate::identity_native::upstream::{CALLBACK_PATH, UpstreamUser};
use crate::identity_native::{NativeBackend, errors};
use crate::rate_limit::SharedBuckets;
use crate::signed_cookie::{SignedCookie, unix_seconds_now};

/// Forseti's own id: Kratos has no single message for a failed upstream sign-in.
const PROVIDER_FAILED: (u64, &str) = (
    9_000_002,
    "Signing in with the provider did not work. Please try again.",
);
const NO_STRATEGY: (u64, &str) = (
    4_010_002,
    "Could not find a strategy to log you in with. Did you fill out the form correctly?",
);

/// Kratos's id; its catalogue has no entry, so the text is shown as is.
const LAST_METHOD: (u64, &str) = (4_000_001, "Unable to remove the last sign-in method.");

const STATE_COOKIE_TTL_SECS: u64 = 600;

/// Clock skew allowed on `auth_time` either side, as the ID token's `iat` leeway.
const AUTH_TIME_SKEW_SECS: i64 = 60;

/// The state cookie; `secure` follows `[self].url`.
fn state_cookie(secure: bool) -> SignedCookie<'static> {
    SignedCookie {
        name: "forseti_upstream_state",
        salt: b"forseti::identity::upstream-state::v1",
        ttl_secs: STATE_COOKIE_TTL_SECS,
        secure,
        path: CALLBACK_PATH.trim_end_matches('/'),
    }
}

/// Payload of the state cookie: provider, flow kind, flow id, `state`.
#[derive(Serialize, Deserialize)]
struct StatePayload {
    p: String,
    k: String,
    f: String,
    s: String,
}

/// Query of `GET /self-service/methods/oidc/callback/{provider}`.
#[derive(Debug, Default, Deserialize)]
pub(in crate::identity_native) struct CallbackQuery {
    pub(in crate::identity_native) state: Option<String>,
    pub(in crate::identity_native) code: Option<String>,
    pub(in crate::identity_native) error: Option<String>,
    pub(in crate::identity_native) iss: Option<String>,
}

/// A submit for the upstream strategy: `method=oidc`, or no `method` with `provider`, `link` or
/// `unlink` (the provider buttons carry no `method`).
pub(super) fn is_upstream_submit(form: &super::Form) -> bool {
    match form.get("method") {
        Some(method) => method == "oidc",
        None => ["provider", "link", "unlink"]
            .iter()
            .any(|name| form.get(name).is_some()),
    }
}

fn error((id, text): (u64, &str)) -> Message {
    Message::error(id, text)
}

fn ct_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn return_to(flow: &FlowRecord) -> String {
    flow.row
        .return_to
        .clone()
        .unwrap_or_else(|| "/".to_string())
}

/// Save the flow with its messages and send the browser back to its page.
async fn page(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    message: Option<(u64, &str)>,
    audit: Vec<AuditEvent>,
) -> Result<Submitted> {
    if let Some(message) = message {
        flow.add_message(error(message));
    }
    let _ = flow.save(&backend.db).await?;
    let kind = flow.kind().unwrap_or(FlowKind::Login);
    Ok(Submitted::new(
        SubmitOutcome::Redirect {
            location: page_url(kind, &flow.row.id),
            set_cookies: Vec::new(),
        },
        audit,
    ))
}

fn expired() -> Submitted {
    SubmitOutcome::Redirect {
        location: errors::url(errors::FLOW_EXPIRED),
        set_cookies: Vec::new(),
    }
    .into()
}

/// `auth.login_failed` for an upstream attempt; `identity` when the provider account is linked.
fn failed_event(
    flow: &FlowRecord,
    provider: &str,
    identity: Option<&IdentityRow>,
    reason: &str,
) -> AuditEvent {
    let mut event = AuditEvent::new(action::AUTH_LOGIN_FAILED);
    if let Some(identity) = identity {
        event = event
            .actor_user(&identity.id, &identity.email)
            .target(target_kind::IDENTITY, &identity.id);
    }
    event
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => flow.row.id,
            "method" => "oidc",
            "provider" => provider,
        ))
        .failed(reason)
}

fn login_event(
    flow: &FlowRecord,
    provider: &str,
    identity: &IdentityRow,
    session_id: &str,
) -> AuditEvent {
    AuditEvent::new(action::AUTH_LOGIN)
        .actor_user(&identity.id, &identity.email)
        .target(target_kind::IDENTITY, &identity.id)
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => flow.row.id,
            "kratos_session_id" => session_id,
            "method" => "oidc",
            "provider" => provider,
            "refresh" => flow.row.refresh != 0,
        ))
}

/// A provider error, a failed exchange or a refused answer: [`PROVIDER_FAILED`] on the flow.
async fn provider_failed(
    backend: &NativeBackend,
    flow: FlowRecord,
    provider: &str,
    reason: &str,
) -> Result<Submitted> {
    let event = failed_event(&flow, provider, None, reason);
    page(backend, flow, Some(PROVIDER_FAILED), vec![event]).await
}

/// An upstream submit on a login, registration or settings flow that passed the checks.
pub(super) async fn start(
    backend: &NativeBackend,
    kind: FlowKind,
    mut s: Submission<'_>,
) -> Result<Submitted> {
    s.flow.clear_messages();
    match kind {
        FlowKind::Login if s.flow.row.refresh != 0 => refresh_start(backend, s).await,
        // A second-factor flow offers no provider.
        FlowKind::Login if s.session.is_some() => {
            page(backend, s.flow, Some(NO_STRATEGY), Vec::new()).await
        }
        FlowKind::Registration if s.flow.ctx.email_needed.is_some() => {
            email_needed_submit(backend, s).await
        }
        FlowKind::Settings => settings_start(backend, s).await,
        FlowKind::Login | FlowKind::Registration => {
            let provider = s.form.get("provider").unwrap_or_default().to_string();
            hop(backend, s.flow, &provider, false).await
        }
        FlowKind::Verification | FlowKind::Recovery => {
            page(backend, s.flow, Some(NO_STRATEGY), Vec::new()).await
        }
    }
}

/// Refresh through a provider: only an `oidc` one that is configured and linked to the session's
/// identity, asked for a fresh login.
async fn refresh_start(backend: &NativeBackend, s: Submission<'_>) -> Result<Submitted> {
    let Some(session) = s.session.as_ref() else {
        return Ok(expired());
    };
    let provider = s.form.get("provider").unwrap_or_default();
    let linked = backend.upstream.can_reauthenticate(provider)
        && store::links_of(&backend.db, &session.identity_id)
            .await?
            .iter()
            .any(|l| l.provider == provider);
    if !linked {
        return page(backend, s.flow, Some(INVALID_CREDENTIALS), Vec::new()).await;
    }
    let provider = provider.to_string();
    hop(backend, s.flow, &provider, true).await
}

/// The email-needed screen's submit: an address for a provider sign-up without one. The provider
/// named in the form is ignored; the one sealed on the flow counts. A free address gets a
/// verification flow bound to this browser, carrying the account, and a mailed code; nothing is
/// created before the code is entered.
async fn email_needed_submit(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    let sealed = pending_account(backend, &s.flow)
        .filter(|p| s.flow.ctx.email_needed.as_deref() == Some(p.provider.as_str()));
    let Some(account) = sealed else {
        return page(backend, s.flow, Some(PROVIDER_FAILED), Vec::new()).await;
    };
    let email = traits_of(s.form).email;
    s.flow.ctx.traits = Some(PendingTraits {
        email: email.clone(),
        ..PendingTraits::default()
    });
    if let Some(problem) = address_problem(&email) {
        s.flow.add_node_message("traits.email", problem);
        return page(backend, s.flow, None, Vec::new()).await;
    }
    // Answered as password registration answers it; the code step checks again and refuses an
    // allowlisted address.
    if store::row_by_email(&backend.db, &email).await?.is_some() {
        return page(backend, s.flow, Some(ACCOUNT_EXISTS), Vec::new()).await;
    }
    let mut verification = backend.verification_flow(
        &email,
        s.flow.row.binding.clone(),
        s.flow.row.return_to.as_deref(),
    );
    seal_account(backend, &mut verification, &account);
    verification.row.context =
        serde_json::to_string(&verification.ctx).expect("flow context serialises");
    if !s.flow.finish(&backend.db).await? {
        return Ok(expired());
    }
    backend.store_flow(&verification.row).await?;
    send_signup_code(backend, &verification.row.id, &email).await?;
    Ok(SubmitOutcome::Redirect {
        location: page_url(FlowKind::Verification, &verification.row.id),
        set_cookies: Vec::new(),
    }
    .into())
}

/// Mail a sign-up code to `email` unless the address is over its mail quota.
async fn send_signup_code(backend: &NativeBackend, flow_id: &str, email: &str) -> Result<()> {
    if backend.limiters.recipient.admit(&store::address_key(email)) {
        backend.send_signup_code(flow_id, email).await?;
    }
    Ok(())
}

/// A submit on a provider sign-up's verification flow, which [`check`](NativeBackend::check)
/// has bound to the starting browser. Without a code it mails a new one to the flow's address;
/// a correct code creates the identity with its link and signs it in.
pub(super) async fn signup_code_submit(
    backend: &NativeBackend,
    flow: FlowRecord,
    code: &str,
    device: Device<'_>,
) -> Result<Submitted> {
    let (Some(account), Some(email)) = (pending_account(backend, &flow), flow.ctx.email.clone())
    else {
        return page(backend, flow, Some(PROVIDER_FAILED), Vec::new()).await;
    };
    if code.is_empty() {
        if store::row_by_email(&backend.db, &email).await?.is_none() {
            send_signup_code(backend, &flow.row.id, &email).await?;
        }
        return page(backend, flow, None, Vec::new()).await;
    }
    let used = backend
        .use_code(&flow.row.id, Purpose::Verification, code)
        .await?;
    let proven =
        used.is_some_and(|u| u.identity_id.is_none() && u.address == store::email_norm(&email));
    if !proven {
        return page(backend, flow, Some(INVALID_CODE), Vec::new()).await;
    }
    let provider = account.provider.as_str();
    if backend.on_admin_allowlist(&email) {
        let event = failed_event(&flow, provider, None, "admin_allowlisted_email");
        return page(backend, flow, Some(ACCOUNT_EXISTS), vec![event]).await;
    }
    let created = store::create_with_link(
        &backend.db,
        &email,
        account.first.as_deref(),
        account.last.as_deref(),
        provider,
        &account.subject,
    )
    .await?;
    match created {
        CreateWithLink::Created(row) => signed_up(backend, flow, provider, &row, device).await,
        CreateWithLink::EmailTaken => {
            let event = failed_event(&flow, provider, None, "account_exists");
            page(backend, flow, Some(ACCOUNT_EXISTS), vec![event]).await
        }
        CreateWithLink::LinkTaken => provider_failed(backend, flow, provider, "link_taken").await,
    }
}

/// Settings `link=<id>` (a provider hop) or `unlink=<id>` (handled here). Both need the
/// privileged window; a never-verified identity links nothing.
async fn settings_start(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    let Some(session) = s.session.take() else {
        return Ok(expired());
    };
    let Some(row) = store::row_by_id(&backend.db, &session.identity_id).await? else {
        return Ok(expired());
    };
    s.flow.set_state("show_form");
    let field = |name| s.form.get(name).filter(|v| !v.is_empty());
    let (link, unlink) = (field("link"), field("unlink"));
    if link.is_none() && unlink.is_none() {
        return page(backend, s.flow, Some(SETTINGS_NO_STRATEGY), Vec::new()).await;
    }
    if !settings::privileged(backend, &session) {
        return Ok(settings::refresh_required(&s.flow));
    }
    if let Some(provider) = link {
        if row.first_verified_at.is_none() {
            return page(backend, s.flow, Some(NOT_VERIFIED), Vec::new()).await;
        }
        let provider = provider.to_string();
        return hop(backend, s.flow, &provider, false).await;
    }
    let provider = unlink.unwrap_or_default();
    if backend.upstream.kind(provider).is_none() {
        return page(backend, s.flow, Some(SETTINGS_NO_STRATEGY), Vec::new()).await;
    }
    let configured: Vec<&str> = backend.upstream.ids().collect();
    match store::delete_link(&backend.db, &row.id, provider, &configured).await? {
        LinkDeleted::Deleted => {
            let event = provider_event(
                action::IDENTITY_OIDC_UNLINKED,
                &s.flow,
                &session,
                &row,
                provider,
            );
            settings::saved(backend, s.flow, |_| {}, event, Vec::new(), None).await
        }
        LinkDeleted::LastMethod => page(backend, s.flow, Some(LAST_METHOD), Vec::new()).await,
        LinkDeleted::NotLinked => {
            page(backend, s.flow, Some(SETTINGS_NO_STRATEGY), Vec::new()).await
        }
    }
}

/// `identity.oidc.linked` or `identity.oidc.unlinked`, in the shape of the other settings rows.
fn provider_event(
    action: &'static str,
    flow: &FlowRecord,
    session: &SessionRow,
    row: &IdentityRow,
    provider: &str,
) -> AuditEvent {
    AuditEvent::new(action)
        .actor_user(&row.id, &row.email)
        .target(target_kind::IDENTITY, &row.id)
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => flow.row.id,
            "kratos_session_id" => session.id,
            "provider" => provider,
        ))
}

/// Send the browser to `provider` for `flow`: a fresh `state` and the hop's start time on the flow
/// (compare-and-swap save), the state cookie, and a 303 to the authorization endpoint.
/// `reauthenticate` asks the provider for a fresh login.
async fn hop(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    provider: &str,
    reauthenticate: bool,
) -> Result<Submitted> {
    if backend.upstream.kind(provider).is_none() {
        return page(backend, flow, Some(PROVIDER_FAILED), Vec::new()).await;
    }
    let state = hex::encode(super::super::random_bytes::<32>());
    let url = match backend
        .upstream
        .authorize_url(
            provider,
            &state,
            &backend.keys.upstream_pkce,
            reauthenticate,
        )
        .await
    {
        Ok(url) => url,
        Err(e) => {
            tracing::warn!(provider, error = e, "upstream: no authorization URL");
            return page(backend, flow, Some(PROVIDER_FAILED), Vec::new()).await;
        }
    };
    flow.ctx.oidc_state = Some(state.clone());
    flow.ctx.oidc_started_at = Some(chrono::Utc::now().timestamp());
    if flow.save(&backend.db).await? == Saved::Changed {
        // A concurrent submit changed the flow; the page shows its result and the user retries.
        return Ok(Submitted::new(
            SubmitOutcome::Redirect {
                location: page_url(flow.kind().unwrap_or(FlowKind::Login), &flow.row.id),
                set_cookies: Vec::new(),
            },
            Vec::new(),
        ));
    }
    let payload = StatePayload {
        p: provider.to_string(),
        k: flow.row.kind.clone(),
        f: flow.row.id.clone(),
        s: state,
    };
    let payload = serde_json::to_vec(&payload).expect("state payload serialises");
    let codec = state_cookie(backend.https);
    let mut cookie =
        codec.set_header(&codec.encode(&backend.cookie_secret, &payload, unix_seconds_now()));
    cookie.push_str(&format!("; Max-Age={STATE_COOKIE_TTL_SECS}"));
    Ok(Submitted::new(
        SubmitOutcome::Redirect {
            location: url.to_string(),
            set_cookies: vec![cookie],
        },
        Vec::new(),
    ))
}

/// A callback whose cookie, `state`, flow and replay checks passed.
struct Callback<'a> {
    flow: FlowRecord,
    provider: &'a str,
    /// The browser's session, for settings flows and refresh logins.
    session: Option<SessionRow>,
    device: Device<'a>,
    /// When the consumed hop started (unix seconds, server clock).
    hop_started_at: i64,
    /// The registration buckets a sign-up spends.
    creation: &'a SharedBuckets,
}

/// `Set-Cookie` that clears the state cookie.
pub(in crate::identity_native) fn clear_state_cookie(secure: bool) -> String {
    state_cookie(secure).clear_header()
}

impl NativeBackend {
    /// Whether `email` is on `[admin].allowed_emails`, as the admin gate or the store would
    /// match it.
    fn on_admin_allowlist(&self, email: &str) -> bool {
        let norm = store::email_norm(email);
        self.admin.is_admin(email)
            || self
                .admin
                .allowed_emails
                .iter()
                .any(|a| store::email_norm(a.trim()) == norm)
    }

    /// `GET /self-service/methods/oidc/callback/{provider}`. Nothing is exchanged, linked or signed
    /// in unless the state cookie verifies and names this provider, `state` matches it, the flow
    /// passes [`check`](NativeBackend::check), and the flow's stored `state` was consumed. `None`
    /// when the cookie or `state` did not verify; the state cookie is then left as it is.
    pub(in crate::identity_native) async fn upstream_callback(
        &self,
        provider: &str,
        query: &CallbackQuery,
        headers: &HeaderMap,
        device: Device<'_>,
        creation: &SharedBuckets,
    ) -> Result<Option<Dispatch>> {
        if self.upstream.kind(provider).is_none() {
            return Ok(None);
        }
        let Some(payload) = state_cookie(self.https)
            .decode(&self.cookie_secret, headers, unix_seconds_now())
            .and_then(|raw| serde_json::from_slice::<StatePayload>(&raw).ok())
        else {
            return Ok(None);
        };
        if payload.p != provider {
            return Ok(None);
        }
        let state = query.state.as_deref().unwrap_or_default();
        if state.is_empty() || !ct_eq(state, &payload.s) {
            return Ok(None);
        }
        let Some(kind) = kind_from_segment(&payload.k).filter(|k| {
            matches!(
                k,
                FlowKind::Login | FlowKind::Registration | FlowKind::Settings
            )
        }) else {
            return Ok(Some(Dispatch::Forged));
        };
        let cookie = crate::cookies::cookie_header(headers);
        let (mut flow, session) = match self.check(kind, &payload.f, &cookie, false).await? {
            Checked::Ok(found) => *found,
            Checked::Missing | Checked::Expired => return Ok(Some(Dispatch::Expired)),
            Checked::Foreign => return Ok(Some(Dispatch::Forged)),
            Checked::NoSession => {
                return Ok(Some(Dispatch::SignIn(format!(
                    "/login?return_to={}",
                    crate::web::urlencode("/settings")
                ))));
            }
            Checked::Aal2Required => {
                return Ok(Some(Dispatch::SignIn(crate::auth::aal2_step_up_url(
                    "/settings",
                ))));
            }
        };
        let Some(hop_started_at) = self.consume_state(&mut flow, state).await? else {
            return Ok(Some(Dispatch::Forged));
        };
        flow.clear_messages();
        let cb = Callback {
            flow,
            provider,
            session,
            device,
            hop_started_at,
            creation,
        };
        Ok(Some(self.answer(cb, query).await?))
    }

    /// Clear the flow's stored `state` and hop start time if `state` is the stored one, with a
    /// compare-and-swap save, so one callback at most gets past this point. Returns the hop's
    /// start time; `None` when nothing was consumed.
    async fn consume_state(&self, flow: &mut FlowRecord, state: &str) -> Result<Option<i64>> {
        for _ in 0..SAVE_ATTEMPTS {
            let stored = flow.ctx.oidc_state.as_deref();
            let (true, Some(started_at)) = (
                stored.is_some_and(|s| ct_eq(s, state)),
                flow.ctx.oidc_started_at,
            ) else {
                return Ok(None);
            };
            flow.ctx.oidc_state = None;
            flow.ctx.oidc_started_at = None;
            if flow.save_context(&self.db).await? == Saved::Done {
                return Ok(Some(started_at));
            }
            match self.load_flow(&flow.row.id).await? {
                Some(current) if current.row.state != FINISHED => *flow = current,
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// The provider's answer for a consumed `state`: the RFC 9207 `iss` check, its `error`, the
    /// code exchange, then the outcome for the flow.
    async fn answer(&self, cb: Callback<'_>, query: &CallbackQuery) -> Result<Dispatch> {
        let provider = cb.provider;
        // GitHub has no issuer identifier to compare an `iss` against.
        if let Some(issuer) = self.upstream.issuer(provider) {
            let iss_ok = match query.iss.as_deref() {
                Some(iss) => iss == issuer,
                None => match self.upstream.requires_iss(provider).await {
                    Ok(required) => !required,
                    Err(e) => {
                        tracing::warn!(provider, error = e, "upstream: discovery unavailable");
                        false
                    }
                },
            };
            if !iss_ok {
                return provider_failed(self, cb.flow, provider, "issuer_mismatch")
                    .await
                    .map(Dispatch::Done);
            }
        }
        if query.error.is_some() {
            return provider_failed(self, cb.flow, provider, "upstream_error")
                .await
                .map(Dispatch::Done);
        }
        let Some(code) = query.code.as_deref().filter(|c| !c.is_empty()) else {
            return provider_failed(self, cb.flow, provider, "upstream_error")
                .await
                .map(Dispatch::Done);
        };
        let state = query.state.as_deref().unwrap_or_default();
        let user = match self
            .upstream
            .exchange(provider, code, state, &self.keys.upstream_pkce)
            .await
        {
            Ok(user) => user,
            Err(e) => {
                tracing::warn!(provider, error = e, "upstream: code exchange failed");
                return provider_failed(self, cb.flow, provider, "exchange_failed")
                    .await
                    .map(Dispatch::Done);
            }
        };
        let done = match cb.flow.kind() {
            Some(FlowKind::Settings) => settings_callback(self, cb, user).await?,
            Some(FlowKind::Login) if cb.flow.row.refresh != 0 => {
                refresh_callback(self, cb, user).await?
            }
            Some(FlowKind::Login | FlowKind::Registration) if cb.session.is_none() => {
                match store::link_owner(&self.db, provider, &user.subject).await? {
                    Some(identity_id) => linked_sign_in(self, cb, &identity_id).await?,
                    None => return unlinked_sign_in(self, cb, user).await,
                }
            }
            _ => page(self, cb.flow, Some(NO_STRATEGY), Vec::new()).await?,
        };
        Ok(Dispatch::Done(done))
    }
}

/// Login or registration, the provider account is linked: sign in the identity it belongs to.
async fn linked_sign_in(
    backend: &NativeBackend,
    mut cb: Callback<'_>,
    identity_id: &str,
) -> Result<Submitted> {
    let provider = cb.provider;
    let Some(row) = store::row_by_id(&backend.db, identity_id).await? else {
        return provider_failed(backend, cb.flow, provider, "identity_missing").await;
    };
    if !store::is_active(&row) {
        let event = failed_event(&cb.flow, provider, Some(&row), "invalid_credentials");
        return page(backend, cb.flow, Some(INVALID_CREDENTIALS), vec![event]).await;
    }
    if row.first_verified_at.is_none() {
        let event = failed_event(&cb.flow, provider, Some(&row), "address_not_verified");
        return page(backend, cb.flow, Some(NOT_VERIFIED), vec![event]).await;
    }
    if !cb.flow.finish(&backend.db).await? {
        return Ok(expired());
    }
    let issued = backend
        .issue_session(&row.id, "oidc", Some(provider), Aal::Aal1, cb.device)
        .await?;
    let event = login_event(&cb.flow, provider, &row, &issued.id);
    Ok(Submitted::new(
        SubmitOutcome::Redirect {
            location: return_to(&cb.flow),
            set_cookies: vec![backend.session_set_cookie(&issued.token)],
        },
        vec![event],
    ))
}

/// Login or registration, no identity has this provider account: sign-up with the address the
/// provider asserts verified, a refusal when that address is taken or an admin's, or the
/// email-needed screen. An existing identity is never linked here. A sign-up from a login flow
/// spends the registration buckets first; over them nothing is created and the answer is a `429`.
async fn unlinked_sign_in(
    backend: &NativeBackend,
    cb: Callback<'_>,
    user: UpstreamUser,
) -> Result<Dispatch> {
    let provider = cb.provider;
    let account = PendingAccount {
        provider: provider.to_string(),
        subject: user.subject,
        first: bounded_name(user.first.as_deref()),
        last: bounded_name(user.last.as_deref()),
    };
    let Some(email) = user.email else {
        return email_needed(backend, cb.flow, &account)
            .await
            .map(Dispatch::Done);
    };
    if backend.on_admin_allowlist(&email) {
        return refuse(backend, cb.flow, provider, "admin_allowlisted_email")
            .await
            .map(Dispatch::Done);
    }
    // A registration flow's provider submit already went through the registration limiter.
    if cb.flow.kind() == Some(FlowKind::Login)
        && let Err(retry_after) = cb.creation.admit(cb.device.ip)
    {
        tracing::warn!(provider, flow_id = %cb.flow.row.id, "upstream: sign-up over the registration limit");
        return Ok(Dispatch::TooManyRequests(retry_after));
    }
    let created = store::create_with_link(
        &backend.db,
        &email,
        account.first.as_deref(),
        account.last.as_deref(),
        provider,
        &account.subject,
    )
    .await?;
    let done = match created {
        CreateWithLink::Created(row) => {
            signed_up(backend, cb.flow, provider, &row, cb.device).await?
        }
        CreateWithLink::EmailTaken => refuse(backend, cb.flow, provider, "account_exists").await?,
        // A concurrent callback linked this provider account first.
        CreateWithLink::LinkTaken => {
            provider_failed(backend, cb.flow, provider, "link_taken").await?
        }
    };
    Ok(Dispatch::Done(done))
}

/// A provider account waiting for an address, sealed on its flow with the flow id.
#[derive(Serialize, Deserialize)]
struct PendingAccount {
    #[serde(rename = "p")]
    provider: String,
    #[serde(rename = "s")]
    subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last: Option<String>,
}

fn seal_account(backend: &NativeBackend, flow: &mut FlowRecord, account: &PendingAccount) {
    let plain = serde_json::to_vec(account).expect("pending account serialises");
    flow.ctx.upstream = Some(backend.seal_for_flow(SEAL_UPSTREAM, &flow.row.id, &plain));
}

/// The provider account sealed on `flow`; `None` when it was sealed for another flow.
fn pending_account(backend: &NativeBackend, flow: &FlowRecord) -> Option<PendingAccount> {
    let sealed = flow.ctx.upstream.as_deref()?;
    let plain = backend.open_for_flow(SEAL_UPSTREAM, &flow.row.id, sealed)?;
    serde_json::from_slice(&plain).ok()
}

/// A provider name trimmed and cut to [`NAME_MAX_CHARS`]; `None` when empty.
fn bounded_name(name: Option<&str>) -> Option<String> {
    let name: String = name?.trim().chars().take(NAME_MAX_CHARS).collect();
    let name = name.trim_end();
    (!name.is_empty()).then(|| name.to_string())
}

/// A registration flow for the browser and `return_to` of `from`, prepared by `fill`, stored.
async fn registration_after(
    backend: &NativeBackend,
    from: &FlowRecord,
    fill: impl FnOnce(&mut FlowRecord),
) -> Result<FlowRecord> {
    let return_to = from.row.return_to.as_deref();
    let request_url = browser_init_url(
        &backend.self_url,
        FlowKind::Registration,
        FlowInit {
            return_to,
            ..FlowInit::default()
        },
    );
    let mut rec = new_flow(
        FlowKind::Registration,
        from.row.binding.clone(),
        None,
        None,
        false,
        return_to,
        request_url,
        Context::default(),
    );
    fill(&mut rec);
    rec.row.context = serde_json::to_string(&rec.ctx).expect("flow context serialises");
    backend.store_flow(&rec.row).await?;
    Ok(rec)
}

/// Spend `flow` and send the browser to a new registration flow prepared by `fill`.
async fn move_to_registration(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    fill: impl FnOnce(&mut FlowRecord),
    audit: Vec<AuditEvent>,
) -> Result<Submitted> {
    if !flow.finish(&backend.db).await? {
        return Ok(expired());
    }
    let next = registration_after(backend, &flow, fill).await?;
    Ok(Submitted::new(
        SubmitOutcome::Redirect {
            location: page_url(FlowKind::Registration, &next.row.id),
            set_cookies: Vec::new(),
        },
        audit,
    ))
}

/// The address is taken or an admin's: a new registration flow showing 4000007, nothing created.
async fn refuse(
    backend: &NativeBackend,
    flow: FlowRecord,
    provider: &str,
    reason: &str,
) -> Result<Submitted> {
    let event = failed_event(&flow, provider, None, reason);
    let fill = |next: &mut FlowRecord| next.add_message(error(ACCOUNT_EXISTS));
    move_to_registration(backend, flow, fill, vec![event]).await
}

/// No verified address: a new registration flow asking for one, the account sealed to it.
async fn email_needed(
    backend: &NativeBackend,
    flow: FlowRecord,
    account: &PendingAccount,
) -> Result<Submitted> {
    let fill = |next: &mut FlowRecord| {
        next.ctx.email_needed = Some(account.provider.clone());
        seal_account(backend, next, account);
    };
    move_to_registration(backend, flow, fill, Vec::new()).await
}

/// A new identity with its link exists: spend the flow, sign it in, audit both.
async fn signed_up(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    provider: &str,
    row: &IdentityRow,
    device: Device<'_>,
) -> Result<Submitted> {
    // The identity exists from here on, so later steps are best effort and the audit row is kept.
    if let Err(e) = flow.finish(&backend.db).await {
        tracing::error!(error = ?e, flow_id = %flow.row.id, "sign-up flow not marked finished");
    }
    let issued = backend
        .issue_session(&row.id, "oidc", Some(provider), Aal::Aal1, device)
        .await
        .inspect_err(|e| tracing::error!(error = ?e, identity_id = %row.id, "session for a new account not issued"))
        .ok();
    let mut audit = vec![
        AuditEvent::new(action::IDENTITY_CREATED)
            .actor_user(&row.id, &row.email)
            .target(target_kind::IDENTITY, &row.id)
            .metadata(crate::audit_metadata!(
                "source" => "native",
                "flow_id" => flow.row.id,
                "kratos_session_id" => issued.as_ref().map(|i| i.id.clone()),
                "method" => "oidc",
                "provider" => provider,
            )),
    ];
    let Some(issued) = issued else {
        return Ok(Submitted::new(
            SubmitOutcome::Redirect {
                location: "/login".to_string(),
                set_cookies: Vec::new(),
            },
            audit,
        ));
    };
    audit.push(login_event(&flow, provider, row, &issued.id));
    Ok(Submitted::new(
        SubmitOutcome::Redirect {
            location: return_to(&flow),
            set_cookies: vec![backend.session_set_cookie(&issued.token)],
        },
        audit,
    ))
}

/// Whether an `oidc` provider's `auth_time` shows a login made for this hop: no earlier than the
/// hop's start and no later than `now`, each by [`AUTH_TIME_SKEW_SECS`] on the server clock (OIDC
/// Core 3.1.2.1, `max_age=0`). A missing claim is not fresh.
fn fresh_login(auth_time: Option<i64>, hop_started_at: i64, now: i64) -> bool {
    auth_time.is_some_and(|at| {
        hop_started_at.saturating_sub(AUTH_TIME_SKEW_SECS) <= at
            && at <= now.saturating_add(AUTH_TIME_SKEW_SECS)
    })
}

/// Refresh login through a provider: the provider must be an `oidc` one, its account linked to the
/// session's identity, and it must report a fresh login. Success advances
/// `authenticated_at` on the same session and keeps its token and AAL, as a password refresh
/// does; anything else leaves the session as it was.
async fn refresh_callback(
    backend: &NativeBackend,
    mut cb: Callback<'_>,
    user: UpstreamUser,
) -> Result<Submitted> {
    let provider = cb.provider;
    let Some(session) = cb.session.take() else {
        return Ok(expired());
    };
    let Some(row) = store::row_by_id(&backend.db, &session.identity_id).await? else {
        return Ok(expired());
    };
    let owner = store::link_owner(&backend.db, provider, &user.subject).await?;
    let refused = if owner.as_deref() != Some(row.id.as_str()) {
        Some("not_linked")
    } else if !backend.upstream.can_reauthenticate(provider)
        || !fresh_login(
            user.auth_time,
            cb.hop_started_at,
            chrono::Utc::now().timestamp(),
        )
    {
        Some("stale_authentication")
    } else if !store::is_active(&row) {
        Some("invalid_credentials")
    } else {
        None
    };
    if let Some(reason) = refused {
        let event = failed_event(&cb.flow, provider, Some(&row), reason);
        return page(backend, cb.flow, Some(INVALID_CREDENTIALS), vec![event]).await;
    }
    if row.email_verified_at.is_none() {
        let event = failed_event(&cb.flow, provider, Some(&row), "address_not_verified");
        return page(backend, cb.flow, Some(NOT_VERIFIED), vec![event]).await;
    }
    if !cb.flow.finish(&backend.db).await?
        || !session::refresh(&backend.db, &session.id, "oidc", Some(provider), Aal::Aal1).await?
    {
        return Ok(expired());
    }
    let event = login_event(&cb.flow, provider, &row, &session.id);
    Ok(Submitted::new(
        SubmitOutcome::Redirect {
            location: return_to(&cb.flow),
            set_cookies: Vec::new(),
        },
        vec![event],
    ))
}

/// Settings link: the provider account joins the session's identity, which
/// [`check`](NativeBackend::check) has confirmed owns the flow. The privileged window and the
/// verified gate are checked again; the database refuses an account linked elsewhere and a
/// second link to one provider.
async fn settings_callback(
    backend: &NativeBackend,
    mut cb: Callback<'_>,
    user: UpstreamUser,
) -> Result<Submitted> {
    let provider = cb.provider;
    let Some(session) = cb.session.take() else {
        return Ok(expired());
    };
    let Some(row) = store::row_by_id(&backend.db, &session.identity_id).await? else {
        return Ok(expired());
    };
    cb.flow.set_state("show_form");
    // The window can lapse during the provider hop; a password change would be refused then too.
    if !settings::privileged(backend, &session) {
        return Ok(settings::refresh_required(&cb.flow));
    }
    if row.first_verified_at.is_none() {
        return page(backend, cb.flow, Some(NOT_VERIFIED), Vec::new()).await;
    }
    let writer = store::Writer {
        identity_id: &row.id,
        session_id: &session.id,
        verified_only: true,
    };
    match store::link_for(&backend.db, writer, provider, &user.subject).await? {
        Ok(LinkInserted::Linked) => {
            let event = provider_event(
                action::IDENTITY_OIDC_LINKED,
                &cb.flow,
                &session,
                &row,
                provider,
            );
            settings::saved(backend, cb.flow, |_| {}, event, Vec::new(), None).await
        }
        Ok(LinkInserted::Taken) => page(backend, cb.flow, Some(ACCOUNT_EXISTS), Vec::new()).await,
        Err(store::Refused::NotVerified) => {
            page(backend, cb.flow, Some(NOT_VERIFIED), Vec::new()).await
        }
        Err(store::Refused::SignedOut) => Ok(settings::signed_out()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::Form;
    use super::*;

    #[test]
    fn upstream_submits_are_recognised() {
        let form = |fields: &[(&str, &str)]| {
            Form(
                fields
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            )
        };
        assert!(is_upstream_submit(&form(&[("provider", "gh")])));
        assert!(is_upstream_submit(&form(&[
            ("method", "oidc"),
            ("provider", "gh")
        ])));
        assert!(is_upstream_submit(&form(&[("link", "gh")])));
        assert!(is_upstream_submit(&form(&[("unlink", "gh")])));
        assert!(!is_upstream_submit(&form(&[
            ("method", "password"),
            ("provider", "gh")
        ])));
        assert!(!is_upstream_submit(&form(&[("identifier", "a")])));
    }

    #[test]
    fn a_fresh_login_lies_between_the_hop_start_and_now_within_the_skew() {
        let started = 1_800_000_000;
        let now = started + 120;
        let fresh = |at| fresh_login(at, started, now);
        assert!(!fresh(None), "a missing auth_time is not fresh");
        assert!(fresh(Some(started)));
        assert!(fresh(Some(now)));
        assert!(fresh(Some(started - AUTH_TIME_SKEW_SECS)));
        assert!(!fresh(Some(started - AUTH_TIME_SKEW_SECS - 1)));
        assert!(
            !fresh(Some(started - AUTH_TIME_SKEW_SECS - 30)),
            "a login before the hop is not one made for it"
        );
        assert!(fresh(Some(now + AUTH_TIME_SKEW_SECS)));
        assert!(!fresh(Some(now + AUTH_TIME_SKEW_SECS + 1)));
        assert!(!fresh(Some(i64::MIN)));
        assert!(!fresh(Some(i64::MAX)));
    }

    #[test]
    fn provider_names_are_trimmed_and_cut_to_the_store_limit() {
        assert_eq!(bounded_name(None), None);
        assert_eq!(bounded_name(Some("  ")), None);
        assert_eq!(bounded_name(Some(" Ada ")).as_deref(), Some("Ada"));
        let long = "ä".repeat(NAME_MAX_CHARS + 1);
        assert_eq!(
            bounded_name(Some(&long)).unwrap().chars().count(),
            NAME_MAX_CHARS
        );
    }

    #[tokio::test]
    async fn the_admin_allowlist_matches_as_the_admin_gate_and_the_store_do() {
        let db = crate::db::test_pool().await;
        let mut cfg = crate::config::AppConfig::test_fixture();
        cfg.admin.allowed_emails = vec!["Root@X.test".into(), "Ädmin@x.test".into()];
        let backend = NativeBackend::new(&cfg, &db, &[0x42; 32]);
        for (email, listed) in [
            ("root@x.TEST", true),
            ("ädmin@X.test", true),
            ("root2@x.test", false),
        ] {
            assert_eq!(backend.on_admin_allowlist(email), listed, "{email}");
        }
    }

    #[tokio::test]
    async fn a_provider_account_linked_after_the_lookup_signs_nothing_in() {
        use crate::identity_native::flows::InitParams;
        use crate::identity_native::test_support::{
            Browser, DEVICE, messages, session_cookie, start,
        };
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let CreateWithLink::Created(winner) =
            store::create_with_link(&db, "first@x.test", None, None, "stub", "s")
                .await
                .unwrap()
        else {
            panic!("created");
        };
        let browser = Browser::new();
        let id = start(&backend, &browser, FlowKind::Login, InitParams::default()).await;
        let unlimited = SharedBuckets::default();
        let cb = Callback {
            flow: backend.load_flow(&id).await.unwrap().unwrap(),
            provider: "stub",
            session: None,
            device: DEVICE,
            hop_started_at: 0,
            creation: &unlimited,
        };
        let user = UpstreamUser {
            subject: "s".into(),
            email: Some("second@x.test".into()),
            first: None,
            last: None,
            auth_time: None,
        };
        let Dispatch::Done(done) = unlinked_sign_in(&backend, cb, user).await.unwrap() else {
            panic!("handled");
        };
        assert!(session_cookie(&done).is_none());
        assert_eq!(messages(&backend, &id).await.0, [9_000_002]);
        assert_eq!(
            store::link_owner(&db, "stub", "s").await.unwrap(),
            Some(winner.id)
        );
        assert!(
            store::row_by_email(&db, "second@x.test")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_refresh_callback_through_github_changes_nothing() {
        use crate::config::{OidcProviderConfig, OidcProviderKind};
        use crate::identity_native::flows::InitParams;
        use crate::identity_native::test_support::{
            Browser, DEVICE, audit_lines, identity_with_password, messages, session_cookie, start,
        };
        let db = crate::db::test_pool().await;
        let mut cfg = crate::config::AppConfig::test_fixture();
        cfg.identity.oidc_providers = vec![OidcProviderConfig {
            id: "gh".into(),
            kind: OidcProviderKind::Github,
            issuer: None,
            client_id: "forseti".into(),
            client_secret: Some("secret".into()),
            client_secret_env: None,
            scopes: None,
        }];
        let backend = NativeBackend::new(&cfg, &db, &[0x42; 32]);
        let identity = identity_with_password(&db, "gh@x.test", true).await;
        store::insert_link(&db, &identity, "gh", "4242")
            .await
            .unwrap();
        let issued = backend
            .issue_session(&identity, "password", None, Aal::Aal1, DEVICE)
            .await
            .unwrap();
        let mut browser = Browser::new();
        browser.session = Some(issued.token.clone());
        let refresh = InitParams {
            refresh: true,
            ..InitParams::default()
        };
        let id = start(&backend, &browser, FlowKind::Login, refresh).await;
        let held = session::find_live(&db, &issued.id).await.unwrap().unwrap();
        let before = held.authenticated_at.clone();
        let now = chrono::Utc::now().timestamp();
        let unlimited = SharedBuckets::default();
        let cb = Callback {
            flow: backend.load_flow(&id).await.unwrap().unwrap(),
            provider: "gh",
            session: Some(held),
            device: DEVICE,
            hop_started_at: now,
            creation: &unlimited,
        };
        let user = UpstreamUser {
            subject: "4242".into(),
            email: None,
            first: None,
            last: None,
            auth_time: Some(now),
        };
        let done = refresh_callback(&backend, cb, user).await.unwrap();
        assert!(session_cookie(&done).is_none());
        assert_eq!(messages(&backend, &id).await.0, [4_000_006]);
        let after = session::find_live(&db, &issued.id).await.unwrap().unwrap();
        assert_eq!(after.authenticated_at, before);
        let lines = audit_lines(&done);
        assert!(
            lines.len() == 1 && lines[0].contains("stale_authentication"),
            "{lines:?}"
        );
    }

    #[test]
    fn the_state_cookie_is_scoped_to_the_callback_path() {
        let line = state_cookie(true).set_header("v");
        assert!(line.contains("Path=/self-service/methods/oidc/callback"));
        assert!(
            line.contains("Secure") && line.contains("HttpOnly") && line.contains("SameSite=Lax")
        );
        let cleared = clear_state_cookie(true);
        assert!(cleared.starts_with("forseti_upstream_state=;") && cleared.contains("Secure"));
    }
}
