//! Login submits: password or passkey sign-in, refresh of a signed-in session, and the second
//! factor.

use anyhow::{Result, anyhow};
use webauthn_rs::prelude::AuthenticationResult;

use super::{FlowRecord, Submission, SubmitOutcome, Submitted};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::Aal;
use crate::identity_native::lookup::{self, LookupConfig};
use crate::identity_native::password::{self, HashError, PasswordConfig};
use crate::identity_native::session::{self, SessionRow, StepUp};
use crate::identity_native::store::keys::{self, Key, KeyKind, KeyUsed};
use crate::identity_native::store::{self, IdentityRow};
use crate::identity_native::totp::{self, TotpConfig};
use crate::identity_native::ui::Message;
use crate::identity_native::webauthn::{self, Refusal, Slot};
use crate::identity_native::{NativeBackend, errors};

/// Kratos's message ids and English texts for the outcomes below.
pub(super) const INVALID_CREDENTIALS: (u64, &str) = (
    4_000_006,
    "The provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number.",
);
pub(super) const NOT_VERIFIED: (u64, &str) = (
    4_000_010,
    "Account not active yet. Did you forget to verify your email address?",
);
const INVALID_TOTP: (u64, &str) = (
    4_000_008,
    "The provided authentication code is invalid, please try again.",
);
const INVALID_LOOKUP: (u64, &str) = (4_000_016, "The backup recovery code is not valid.");
const NO_STRATEGY: (u64, &str) = (
    4_010_002,
    "Could not find a strategy to log you in with. Did you fill out the form correctly?",
);
const THROTTLED: (u64, &str) = (
    9_000_001,
    "Too many sign-in attempts right now. Please try again in a few minutes.",
);

/// Read-compare-swap rounds before a contended credential update gives up.
const SWAP_ATTEMPTS: usize = 3;

/// A filled `passkey_login` picks the passkey whatever `method` says: the ceremony script submits
/// the form without a button.
pub(super) async fn submit(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    s.flow.clear_messages();
    let form = s.form;
    let passkey = form.get("passkey_login").filter(|v| !v.is_empty());
    match (s.session.take(), passkey) {
        (None, Some(response)) => passkey_login(backend, s, response).await,
        (None, None) => password_login(backend, s).await,
        (Some(session), Some(response)) if s.flow.row.refresh != 0 => {
            refresh_passkey(backend, s, session, response).await
        }
        (Some(session), _) if s.flow.row.refresh != 0 => refresh(backend, s, session).await,
        (Some(session), _) => second_factor(backend, s, session).await,
    }
}

fn error((id, text): (u64, &str)) -> Message {
    Message::error(id, text)
}

fn return_to(flow: &FlowRecord) -> String {
    flow.row
        .return_to
        .clone()
        .unwrap_or_else(|| "/".to_string())
}

/// Save the flow with its messages and show it again.
async fn page(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    audit: Vec<AuditEvent>,
) -> Result<Submitted> {
    let _ = flow.save(&backend.db).await?;
    Ok(Submitted::new(SubmitOutcome::Page, audit))
}

async fn reject(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    message: (u64, &str),
    audit: Vec<AuditEvent>,
) -> Result<Submitted> {
    flow.add_message(error(message));
    page(backend, flow, audit).await
}

/// The session behind the flow is gone; the browser starts over.
fn expired() -> Submitted {
    SubmitOutcome::Redirect {
        location: errors::url(errors::FLOW_EXPIRED),
        set_cookies: Vec::new(),
    }
    .into()
}

fn signed_in(location: String, set_cookies: Vec<String>, audit: Vec<AuditEvent>) -> Submitted {
    Submitted::new(
        SubmitOutcome::Redirect {
            location,
            set_cookies,
        },
        audit,
    )
}

fn login_event(
    flow: &FlowRecord,
    identity: &IdentityRow,
    session_id: &str,
    method: &str,
) -> AuditEvent {
    AuditEvent::new(action::AUTH_LOGIN)
        .actor_user(&identity.id, &identity.email)
        .target(target_kind::IDENTITY, &identity.id)
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => flow.row.id,
            "kratos_session_id" => session_id,
            "method" => method,
            "refresh" => flow.row.refresh != 0,
        ))
}

/// `identity` is `None` when the identifier names no account.
fn failed_event(
    flow: &FlowRecord,
    identity: Option<&IdentityRow>,
    method: &str,
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
            "method" => method,
        ))
        .failed(reason)
}

fn phc_of(config: Option<&str>) -> Result<Option<String>> {
    config
        .map(|c| {
            serde_json::from_str::<PasswordConfig>(c)
                .map(|p| p.hashed_password)
                .map_err(|e| anyhow!("password credential config is not valid: {e}"))
        })
        .transpose()
}

/// Whether `password` is the identity's; `None` when hashing is at capacity.
async fn password_matches(
    backend: &NativeBackend,
    password: &str,
    phc: Option<String>,
) -> Result<Option<bool>> {
    match password::verify(&backend.hash_permits, password.to_string(), phc).await {
        Ok(ok) => Ok(Some(ok)),
        Err(HashError::Busy) => Ok(None),
        Err(HashError::Failed(e)) => Err(e),
    }
}

/// `identifier` and `password`. Unknown accounts, wrong passwords, inactive identities and
/// over-long identifiers get the same answer after one Argon2 verify; an unverified address is
/// reported only once the password verified.
async fn password_login(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    if s.form.get("method") != Some("password") {
        return reject(backend, s.flow, NO_STRATEGY, Vec::new()).await;
    }
    let identifier = s
        .form
        .get("identifier")
        .unwrap_or_default()
        .trim()
        .to_string();
    let password = s.form.get("password").unwrap_or_default();
    if identifier.chars().count() > store::EMAIL_MAX_CHARS {
        s.flow.ctx.identifier = None;
        if password_matches(backend, password, None).await?.is_none() {
            return reject(backend, s.flow, THROTTLED, Vec::new()).await;
        }
        let event = failed_event(&s.flow, None, "password", "invalid_credentials");
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    }
    s.flow.ctx.identifier = Some(identifier.clone());
    if !backend
        .limiters
        .password
        .admit(&store::address_key(&identifier))
    {
        let event = failed_event(&s.flow, None, "password", "throttled");
        return reject(backend, s.flow, THROTTLED, vec![event]).await;
    }
    let target = store::login_target(&backend.db, &identifier).await?;
    let (row, config) = target.map_or((None, None), |(r, c)| (Some(r), c));
    let phc = phc_of(config.as_deref())?;
    let Some(matches) = password_matches(backend, password, phc).await? else {
        return reject(backend, s.flow, THROTTLED, Vec::new()).await;
    };
    let row = match row {
        Some(row) if matches && store::is_active(&row) => row,
        other => {
            let event = failed_event(&s.flow, other.as_ref(), "password", "invalid_credentials");
            return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
        }
    };
    if row.email_verified_at.is_none() {
        let event = failed_event(&s.flow, Some(&row), "password", "address_not_verified");
        return reject(backend, s.flow, NOT_VERIFIED, vec![event]).await;
    }
    if !s.flow.finish(&backend.db).await? {
        return Ok(expired());
    }
    let issued = backend
        .issue_session(&row.id, "password", None, Aal::Aal1, s.device)
        .await?;
    let event = login_event(&s.flow, &row, &issued.id, "password");
    Ok(signed_in(
        return_to(&s.flow),
        vec![backend.session_set_cookie(&issued.token)],
        vec![event],
    ))
}

/// Limiter key of an identity's passkey attempts, apart from its second-factor attempts.
fn passkey_budget(identity_id: &str) -> String {
    format!("passkey:{identity_id}")
}

/// A discoverable passkey assertion. Refusals before the signature verifies are anonymous; the
/// account's state is reported only after it.
async fn passkey_login(
    backend: &NativeBackend,
    mut s: Submission<'_>,
    response: &str,
) -> Result<Submitted> {
    let anonymous = |flow: &FlowRecord| failed_event(flow, None, "passkey", "invalid_credentials");
    let Some(rp) = backend.webauthn.as_ref() else {
        let event = anonymous(&s.flow);
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    };
    let Some(ceremony) = backend.take(&mut s.flow, Slot::Passkey).await? else {
        let event = anonymous(&s.flow);
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    };
    let claimed = match webauthn::identify_passkey(rp, response) {
        Ok((assertion, user)) => {
            let credential_id = assertion.get_credential_id().to_vec();
            keys::by_credential_id(&backend.db, &credential_id)
                .await?
                .filter(|r| {
                    r.kind == KeyKind::Passkey.as_str()
                        && uuid::Uuid::parse_str(&r.identity_id).is_ok_and(|id| id == user)
                })
                .map(|row| (assertion, row))
        }
        Err(_) => None,
    };
    let Some((assertion, row)) = claimed else {
        let event = anonymous(&s.flow);
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    };
    // Answers as a bad credential: a throttle message would confirm the credential exists.
    if !backend
        .limiters
        .second_factor
        .admit(&passkey_budget(&row.identity_id))
    {
        let event = failed_event(&s.flow, None, "passkey", "throttled");
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    }
    let Ok(Key::Passkey(passkey)) = row.key() else {
        // The parse error can quote the credential, so only the row id is logged.
        tracing::warn!(key = %row.id, "webauthn: stored key unreadable");
        let event = anonymous(&s.flow);
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    };
    let verified = webauthn::verify_passkey_login(rp, ceremony, &assertion, &passkey);
    if matches!(verified, Err(Refusal::Invalid)) {
        let event = anonymous(&s.flow);
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    }
    // The signature verified: the row's identity is the sender's.
    let identity = store::row_by_id(&backend.db, &row.identity_id).await?;
    let used = match verified {
        Ok(result) => applied(keys::apply_use(&backend.db, &row, &result).await?),
        Err(refusal) => Err(refusal),
    };
    let identity = match (used, identity) {
        (Ok(()), Some(identity)) if store::is_active(&identity) => identity,
        (used, identity) => {
            let reason = used.err().map_or("invalid_credentials", Refusal::reason);
            let event = failed_event(&s.flow, identity.as_ref(), "passkey", reason);
            return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
        }
    };
    if identity.email_verified_at.is_none() {
        let event = failed_event(&s.flow, Some(&identity), "passkey", "address_not_verified");
        return reject(backend, s.flow, NOT_VERIFIED, vec![event]).await;
    }
    if !s.flow.finish(&backend.db).await? {
        return Ok(expired());
    }
    let issued = backend
        .issue_session(&identity.id, "passkey", None, Aal::Aal1, s.device)
        .await?;
    let event = login_event(&s.flow, &identity, &issued.id, "passkey");
    Ok(signed_in(
        return_to(&s.flow),
        vec![backend.session_set_cookie(&issued.token)],
        vec![event],
    ))
}

/// The password of the session's identity again. Success advances `authenticated_at` on the same
/// session and keeps its token and AAL; a wrong password changes nothing.
async fn refresh(
    backend: &NativeBackend,
    s: Submission<'_>,
    session: SessionRow,
) -> Result<Submitted> {
    if s.form.get("method") != Some("password") {
        return reject(backend, s.flow, NO_STRATEGY, Vec::new()).await;
    }
    let Some(row) = store::row_by_id(&backend.db, &session.identity_id).await? else {
        return Ok(expired());
    };
    if !backend
        .limiters
        .password
        .admit(&store::address_key(&row.email))
    {
        let event = failed_event(&s.flow, Some(&row), "password", "throttled");
        return reject(backend, s.flow, THROTTLED, vec![event]).await;
    }
    let config = store::credential(&backend.db, &row.id, "password").await?;
    let phc = phc_of(config.as_ref().map(|c| c.config.as_str()))?;
    let password = s.form.get("password").unwrap_or_default();
    let Some(matches) = password_matches(backend, password, phc).await? else {
        return reject(backend, s.flow, THROTTLED, Vec::new()).await;
    };
    if !matches || !store::is_active(&row) {
        let event = failed_event(&s.flow, Some(&row), "password", "invalid_credentials");
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    }
    if row.email_verified_at.is_none() {
        let event = failed_event(&s.flow, Some(&row), "password", "address_not_verified");
        return reject(backend, s.flow, NOT_VERIFIED, vec![event]).await;
    }
    let mut flow = s.flow;
    if !flow.finish(&backend.db).await?
        || !session::refresh(&backend.db, &session.id, "password", None, Aal::Aal1).await?
    {
        return Ok(expired());
    }
    let event = login_event(&flow, &row, &session.id, "password");
    Ok(signed_in(return_to(&flow), Vec::new(), vec![event]))
}

/// One of the session identity's passkeys, as [`refresh`] takes its password.
async fn refresh_passkey(
    backend: &NativeBackend,
    mut s: Submission<'_>,
    session: SessionRow,
    response: &str,
) -> Result<Submitted> {
    let Some(row) = store::row_by_id(&backend.db, &session.identity_id).await? else {
        return Ok(expired());
    };
    if !backend
        .limiters
        .second_factor
        .admit(&passkey_budget(&row.id))
    {
        let event = failed_event(&s.flow, Some(&row), "passkey", "throttled");
        return reject(backend, s.flow, THROTTLED, vec![event]).await;
    }
    let used = match (
        backend.webauthn.as_ref(),
        backend.take(&mut s.flow, Slot::Passkey).await?,
    ) {
        (Some(rp), Some(ceremony)) => {
            match webauthn::verify_passkey_refresh(rp, ceremony, response) {
                Ok(result) => record_use(backend, &row.id, KeyKind::Passkey, &result).await?,
                Err(refusal) => Err(refusal),
            }
        }
        _ => Err(Refusal::Invalid),
    };
    if let Err(refusal) = used {
        let event = failed_event(&s.flow, Some(&row), "passkey", refusal.reason());
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    }
    if !store::is_active(&row) {
        let event = failed_event(&s.flow, Some(&row), "passkey", "invalid_credentials");
        return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
    }
    if row.email_verified_at.is_none() {
        let event = failed_event(&s.flow, Some(&row), "passkey", "address_not_verified");
        return reject(backend, s.flow, NOT_VERIFIED, vec![event]).await;
    }
    let mut flow = s.flow;
    if !flow.finish(&backend.db).await?
        || !session::refresh(&backend.db, &session.id, "passkey", None, Aal::Aal1).await?
    {
        return Ok(expired());
    }
    let event = login_event(&flow, &row, &session.id, "passkey");
    Ok(signed_in(return_to(&flow), Vec::new(), vec![event]))
}

/// For an identity with TOTP or a security key, a TOTP code, an unused lookup code or one of its
/// security keys raises the session to AAL2 and moves it to a new token. A filled `webauthn_login`
/// picks the key whatever `method` says: the ceremony script submits the form without a button.
/// Like the Ory build, a completed second factor writes no `auth.login` row of its own. A session
/// already at AAL2 has nothing to prove: a code would only advance `authenticated_at`, standing in
/// for the password a re-authentication needs.
async fn second_factor(
    backend: &NativeBackend,
    mut s: Submission<'_>,
    session: SessionRow,
) -> Result<Submitted> {
    if session.aal == Aal::Aal2.as_str() {
        return Ok(expired());
    }
    let identity_id = session.identity_id.clone();
    if !store::keys::has_second_factor(&backend.db, &identity_id).await? {
        return page(backend, s.flow, Vec::new()).await;
    }
    let key_response = s.form.get("webauthn_login").filter(|v| !v.is_empty());
    let method = match (key_response, s.form.get("method").unwrap_or_default()) {
        (Some(_), _) => "webauthn",
        (None, method @ ("totp" | "lookup_secret")) => method,
        _ => return reject(backend, s.flow, NO_STRATEGY, Vec::new()).await,
    };
    let Some(row) = store::row_by_id(&backend.db, &identity_id).await? else {
        return Ok(expired());
    };
    if !backend.limiters.second_factor.admit(&identity_id) {
        let event = failed_event(&s.flow, Some(&row), method, "throttled");
        return reject(backend, s.flow, THROTTLED, vec![event]).await;
    }
    if let Some(response) = key_response {
        if let Err(refusal) = use_key(backend, &mut s.flow, &identity_id, response).await? {
            let event = failed_event(&s.flow, Some(&row), method, refusal.reason());
            return reject(backend, s.flow, INVALID_CREDENTIALS, vec![event]).await;
        }
    } else {
        let (field, invalid) = match method {
            "totp" => ("totp_code", INVALID_TOTP),
            _ => ("lookup_secret", INVALID_LOOKUP),
        };
        let code = s.form.get(field).unwrap_or_default();
        let accepted = match method {
            "totp" => consume_totp(backend, &identity_id, code).await?,
            _ => consume_lookup(backend, &identity_id, code).await?,
        };
        if !accepted {
            let event = failed_event(&s.flow, Some(&row), method, "invalid_code");
            s.flow.add_node_message(field, error(invalid));
            return page(backend, s.flow, vec![event]).await;
        }
    }
    if !s.flow.finish(&backend.db).await? {
        return Ok(expired());
    }
    match session::step_up(&backend.db, &session, method, None, Aal::Aal2).await? {
        StepUp::Rotated(token) => Ok(signed_in(
            return_to(&s.flow),
            vec![backend.session_set_cookie(&token)],
            Vec::new(),
        )),
        // A concurrent step-up already rotated the token this browser now holds.
        StepUp::Superseded => {
            let raised = session::find_live(&backend.db, &session.id)
                .await?
                .is_some_and(|now| now.aal == Aal::Aal2.as_str());
            Ok(if raised {
                signed_in(return_to(&s.flow), Vec::new(), Vec::new())
            } else {
                expired()
            })
        }
        StepUp::NotLive => Ok(expired()),
    }
}

/// Accept `code` once: its step must be newer than the last accepted one, and the new step is
/// stored with a compare-and-swap so two requests cannot both use it.
async fn consume_totp(backend: &NativeBackend, identity_id: &str, code: &str) -> Result<bool> {
    for _ in 0..SWAP_ATTEMPTS {
        let Some(cred) = store::credential(&backend.db, identity_id, "totp").await? else {
            return Ok(false);
        };
        let mut config: TotpConfig = serde_json::from_str(&cred.config)
            .map_err(|e| anyhow!("TOTP credential config of {identity_id} is not valid: {e}"))?;
        let secret = config
            .open(&backend.keys.seal, identity_id)
            .ok_or_else(|| anyhow!("TOTP secret of {identity_id} does not open"))?;
        let Some(step) = totp::verify(&secret, code, totp::unix_now()) else {
            return Ok(false);
        };
        if !totp::step_is_fresh(step, config.last_used_step) {
            return Ok(false);
        }
        config.last_used_step = Some(step);
        let next = serde_json::to_string(&config)?;
        if store::swap_credential_config(&backend.db, &cred.id, cred.version, &next).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Mark the unused lookup code `code` matches as used, with a compare-and-swap.
async fn consume_lookup(backend: &NativeBackend, identity_id: &str, code: &str) -> Result<bool> {
    for _ in 0..SWAP_ATTEMPTS {
        let Some(cred) = store::credential(&backend.db, identity_id, "lookup_secret").await? else {
            return Ok(false);
        };
        let mut config: LookupConfig = serde_json::from_str(&cred.config)
            .map_err(|e| anyhow!("lookup credential config of {identity_id} is not valid: {e}"))?;
        let Some(index) =
            lookup::match_unused(&backend.keys.lookup_mac, identity_id, code, &config)
        else {
            return Ok(false);
        };
        config.codes[index].used_at = Some(crate::db::now_rfc3339());
        let next = serde_json::to_string(&config)?;
        if store::swap_credential_config(&backend.db, &cred.id, cred.version, &next).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Verify the security key assertion `response` against the flow's key ceremony, which is spent
/// first, and record the use on the key's current row.
async fn use_key(
    backend: &NativeBackend,
    flow: &mut FlowRecord,
    identity_id: &str,
    response: &str,
) -> Result<Result<(), Refusal>> {
    let Some(rp) = backend.webauthn.as_ref() else {
        return Ok(Err(Refusal::Invalid));
    };
    let Some(ceremony) = backend.take(flow, Slot::Key).await? else {
        return Ok(Err(Refusal::Invalid));
    };
    match webauthn::verify_key_login(rp, ceremony, response) {
        Ok(result) => record_use(backend, identity_id, KeyKind::Webauthn, &result).await,
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// Record the verified use `result` on its key's current row, which must be `identity_id`'s and
/// of `kind`.
async fn record_use(
    backend: &NativeBackend,
    identity_id: &str,
    kind: KeyKind,
    result: &AuthenticationResult,
) -> Result<Result<(), Refusal>> {
    // The ceremony holds the keys as they were when the page rendered.
    let row = keys::by_credential_id(&backend.db, result.cred_id().as_slice())
        .await?
        .filter(|r| r.identity_id == identity_id && r.kind == kind.as_str());
    let Some(row) = row else {
        return Ok(Err(Refusal::Invalid));
    };
    Ok(applied(keys::apply_use(&backend.db, &row, result).await?))
}

fn applied(used: KeyUsed) -> Result<(), Refusal> {
    match used {
        KeyUsed::Applied => Ok(()),
        KeyUsed::Replayed => Err(Refusal::Counter),
        KeyUsed::Gone => Err(Refusal::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::{Dispatch, Form, InitOutcome, InitParams};
    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::{FlowFetch, FlowKind, IdentityState, WhoamiOutcome};
    use crate::config::AppConfig;
    use crate::db::DbPool;
    use crate::identity_native::session::Device;
    use crate::identity_native::test_support::{
        PASSWORD, identity_with_password, plant_lookup_codes, plant_totp, totp_code,
    };

    const DEVICE: Device<'static> = Device {
        ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))),
        user_agent: Some("Mozilla/5.0 test"),
    };

    async fn setup() -> (DbPool, Arc<NativeBackend>) {
        setup_with(AppConfig::test_fixture()).await
    }

    async fn setup_with(cfg: AppConfig) -> (DbPool, Arc<NativeBackend>) {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::new(&cfg, &db, &[0x42; 32]);
        (db, backend)
    }

    /// A browser: its CSRF token and, once signed in, its session token.
    #[derive(Clone)]
    struct Browser {
        csrf: String,
        session: Option<String>,
    }

    impl Browser {
        fn new() -> Self {
            Self {
                csrf: uuid::Uuid::new_v4().to_string(),
                session: None,
            }
        }

        fn cookie(&self) -> String {
            match &self.session {
                Some(s) => format!("forseti_csrf={}; forseti_session={s}", self.csrf),
                None => format!("forseti_csrf={}", self.csrf),
            }
        }
    }

    async fn start(backend: &NativeBackend, browser: &Browser, params: InitParams<'_>) -> String {
        match backend
            .init_flow(FlowKind::Login, params, &browser.csrf, &browser.cookie())
            .await
            .unwrap()
        {
            InitOutcome::Created(id) => id,
            InitOutcome::Redirect(to) => panic!("no flow, redirected to {to}"),
        }
    }

    async fn send(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        fields: &[(&str, &str)],
    ) -> Dispatch {
        let form = Form(
            fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        );
        backend
            .submit_flow(FlowKind::Login, id, &form, &browser.cookie(), true, DEVICE)
            .await
            .unwrap()
    }

    async fn submit(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        fields: &[(&str, &str)],
    ) -> Submitted {
        match send(backend, browser, id, fields).await {
            Dispatch::Done(done) => done,
            other => panic!("submit not handled: {other:?}"),
        }
    }

    async fn password(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        identifier: &str,
        password: &str,
    ) -> Submitted {
        submit(
            backend,
            browser,
            id,
            &[
                ("method", "password"),
                ("identifier", identifier),
                ("password", password),
            ],
        )
        .await
    }

    /// The session token a successful submit sets.
    fn session_cookie(done: &Submitted) -> Option<String> {
        let SubmitOutcome::Redirect { set_cookies, .. } = &done.outcome else {
            return None;
        };
        set_cookies.iter().find_map(|c| {
            c.strip_prefix("forseti_session=")
                .map(|rest| rest.split(';').next().unwrap().to_string())
        })
    }

    fn location(done: &Submitted) -> &str {
        match &done.outcome {
            SubmitOutcome::Redirect { location, .. } => location,
            SubmitOutcome::Page => panic!("expected a redirect"),
        }
    }

    fn actions(done: &Submitted) -> Vec<String> {
        done.audit.iter().map(|e| format!("{e:?}")).collect()
    }

    /// Flow-level and node message ids saved on the flow.
    async fn messages(backend: &NativeBackend, id: &str) -> (Vec<u64>, Vec<(String, u64)>) {
        let rec = backend.load_flow(id).await.unwrap().unwrap();
        (
            rec.ctx.messages.iter().map(|m| m.id).collect(),
            rec.ctx
                .node_messages
                .iter()
                .map(|n| (n.node.clone(), n.message.id))
                .collect(),
        )
    }

    async fn whoami(backend: &NativeBackend, token: &str) -> WhoamiOutcome {
        backend
            .whoami(Some(&format!("forseti_session={token}")))
            .await
            .unwrap()
    }

    /// A signed-in browser for `email`, through the password form.
    async fn sign_in(backend: &NativeBackend, email: &str) -> Browser {
        let mut browser = Browser::new();
        let id = start(backend, &browser, InitParams::default()).await;
        let done = password(backend, &browser, &id, email, PASSWORD).await;
        browser.session = Some(session_cookie(&done).expect("signed in"));
        browser
    }

    fn aal2() -> InitParams<'static> {
        InitParams {
            return_to: Some("/settings"),
            aal2: true,
            refresh: false,
        }
    }

    #[tokio::test]
    async fn a_password_sign_in_issues_an_aal1_session_and_audits_it() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "Ann@Example.test", true).await;
        let browser = Browser::new();
        let id = start(
            &backend,
            &browser,
            InitParams {
                return_to: Some("/settings/profile"),
                ..InitParams::default()
            },
        )
        .await;
        let done = password(&backend, &browser, &id, " ann@example.TEST ", PASSWORD).await;
        assert_eq!(location(&done), "/settings/profile");
        let token = session_cookie(&done).expect("a session cookie");
        let WhoamiOutcome::Ok(session) = whoami(&backend, &token).await else {
            panic!("the new session is live");
        };
        assert_eq!(session.identity.unwrap().id, identity);
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal1));
        let methods = session.authentication_methods.unwrap();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].method.as_deref(), Some("password"));
        let device = &session.devices.unwrap()[0];
        assert_eq!(device.ip_address.as_deref(), Some("192.0.2.9"));

        let audit = actions(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("action: \"auth.login\""), "{}", audit[0]);
        assert!(audit[0].contains(&session.id));
        assert!(!audit[0].contains(PASSWORD) && !audit[0].contains(&token));

        let other = Browser::new();
        let id = start(&backend, &other, InitParams::default()).await;
        let done = password(&backend, &other, &id, "ann@example.test", PASSWORD).await;
        assert_eq!(location(&done), "/", "no return_to goes home");
    }

    #[tokio::test]
    async fn unknown_accounts_and_wrong_passwords_get_the_same_answer() {
        use crate::identity_native::password::argon2_runs;
        let (db, backend) = setup().await;
        identity_with_password(&db, "known@x.test", true).await;
        identity_with_password(&db, "pending@x.test", false).await;
        let off = identity_with_password(&db, "off@x.test", true).await;
        store::set_state(&db, &off, IdentityState::Inactive)
            .await
            .unwrap();
        let long = format!("{}@x.test", "a".repeat(320));
        let mut seen = Vec::new();
        for (identifier, pw) in [
            ("nobody@x.test", PASSWORD),
            ("known@x.test", "wrong horse battery"),
            ("pending@x.test", "wrong horse battery"),
            ("off@x.test", PASSWORD),
            ("", ""),
            (long.as_str(), PASSWORD),
        ] {
            let browser = Browser::new();
            let id = start(&backend, &browser, InitParams::default()).await;
            let before = argon2_runs::count(&backend.hash_permits);
            let done = password(&backend, &browser, &id, identifier, pw).await;
            assert_eq!(
                argon2_runs::count(&backend.hash_permits) - before,
                1,
                "one Argon2 verify for {identifier:.20}"
            );
            assert_eq!(done.outcome, SubmitOutcome::Page, "{identifier:.20}");
            let rec = backend.load_flow(&id).await.unwrap().unwrap();
            let echoed = (identifier.len() <= 320).then_some(identifier);
            assert_eq!(rec.ctx.identifier.as_deref(), echoed);
            let audit = actions(&done);
            assert!(audit[0].contains("auth.login_failed"));
            assert!(audit[0].contains("invalid_credentials"));
            assert!(pw.is_empty() || !audit[0].contains(pw));
            assert!(!audit[0].contains(&long));
            seen.push((rec.row.state, rec.ctx.messages, rec.ctx.node_messages));
        }
        assert_eq!(seen[0].1[0].id, 4_000_006);
        assert!(seen.iter().all(|s| *s == seen[0]), "{seen:?}");
    }

    #[tokio::test]
    async fn an_over_long_identifier_never_reaches_the_attempt_counter() {
        let mut cfg = AppConfig::test_fixture();
        cfg.identity.login_identifier_rate_per_15m = 1;
        let (_, backend) = setup_with(cfg).await;
        let long = format!("{}@x.test", "b".repeat(400));
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        for _ in 0..3 {
            password(&backend, &browser, &id, &long, PASSWORD).await;
            assert_eq!(
                messages(&backend, &id).await.0,
                [4_000_006],
                "never 9000001"
            );
        }
    }

    #[tokio::test]
    async fn an_unverified_address_is_reported_only_after_the_password_verified() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "late@x.test", false).await;
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        let done = password(&backend, &browser, &id, "late@x.test", PASSWORD).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(session_cookie(&done).is_none());
        assert_eq!(messages(&backend, &id).await.0, [4_000_010]);
        assert!(actions(&done)[0].contains("address_not_verified"));

        let done = password(&backend, &browser, &id, "late@x.test", "nope nope nope").await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [4_000_006]);
    }

    #[tokio::test]
    async fn an_inactive_identity_is_a_wrong_password() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "off@x.test", true).await;
        store::set_state(&db, &identity, IdentityState::Inactive)
            .await
            .unwrap();
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        let done = password(&backend, &browser, &id, "off@x.test", PASSWORD).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [4_000_006]);
    }

    #[tokio::test]
    async fn a_submit_without_the_password_method_is_no_attempt() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "m@x.test", true).await;
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        let done = submit(
            &backend,
            &browser,
            &id,
            &[("identifier", "m@x.test"), ("password", PASSWORD)],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [4_010_002]);
    }

    #[tokio::test]
    async fn totp_raises_the_session_to_aal2_and_a_code_works_once() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "t@x.test", true).await;
        let secret = plant_totp(&backend, &identity).await;
        let mut browser = sign_in(&backend, "t@x.test").await;
        let aal1 = browser.session.clone().unwrap();
        assert!(matches!(
            whoami(&backend, &aal1).await,
            WhoamiOutcome::InsufficientAal
        ));

        let id = start(&backend, &browser, aal2()).await;
        let code = totp_code(&secret, totp::unix_now());
        let done = submit(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        assert_eq!(location(&done), "/settings");
        assert!(done.audit.is_empty(), "the step-up writes no login row");
        let rotated = session_cookie(&done).expect("a new cookie");
        assert!(matches!(whoami(&backend, &aal1).await, WhoamiOutcome::None));
        let WhoamiOutcome::Ok(session) = whoami(&backend, &rotated).await else {
            panic!("the rotated token is live");
        };
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal2));
        browser.session = Some(rotated);

        let other = sign_in(&backend, "t@x.test").await;
        let id = start(&backend, &other, aal2()).await;
        let done = submit(
            &backend,
            &other,
            &id,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page, "a replayed code");
        assert_eq!(
            messages(&backend, &id).await.1,
            [("totp_code".to_string(), 4_000_008)]
        );
        assert!(actions(&done)[0].contains("invalid_code"));
        assert!(!actions(&done)[0].contains(&code));
        let next = totp_code(&secret, totp::unix_now() + totp::STEP_SECS);
        let done = submit(
            &backend,
            &other,
            &id,
            &[("method", "totp"), ("totp_code", &next)],
        )
        .await;
        assert!(session_cookie(&done).is_some(), "a newer step is accepted");
    }

    #[tokio::test]
    async fn a_totp_code_another_request_spent_mid_swap_is_refused_on_retry() {
        use diesel::RunQueryDsl as _;
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "race@x.test", true).await;
        let secret = plant_totp(&backend, &identity).await;
        let browser = sign_in(&backend, "race@x.test").await;
        let flow = start(&backend, &browser, aal2()).await;
        // A temp trigger plays the concurrent request: when this request swaps from version 0, the
        // same config (the same step spent) lands first and this swap matches no row.
        crate::identity_native::test_support::sql(&db, |c| {
            diesel::sql_query(
                "CREATE TEMP TRIGGER race BEFORE UPDATE OF config ON main.identity_credentials \
                 WHEN OLD.kind = 'totp' AND OLD.version = 0 BEGIN \
                 UPDATE identity_credentials SET config = NEW.config, version = OLD.version + 1 \
                 WHERE id = OLD.id; SELECT RAISE(IGNORE); END",
            )
            .execute(c)
        })
        .await;
        let code = totp_code(&secret, totp::unix_now());
        let done = submit(
            &backend,
            &browser,
            &flow,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        assert_eq!(
            done.outcome,
            SubmitOutcome::Page,
            "the retry sees the spent step"
        );
        assert_eq!(
            messages(&backend, &flow).await.1,
            [("totp_code".to_string(), 4_000_008)]
        );
        let cred = store::credential(&db, &identity, "totp")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cred.version, 1, "only the other writer's swap landed");
        assert!(matches!(
            whoami(&backend, browser.session.as_deref().unwrap()).await,
            WhoamiOutcome::InsufficientAal
        ));
    }

    #[tokio::test]
    async fn a_second_factor_on_an_aal2_session_is_refused() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "twice@x.test", true).await;
        let secret = plant_totp(&backend, &identity).await;
        let mut browser = sign_in(&backend, "twice@x.test").await;
        let first = start(&backend, &browser, aal2()).await;
        let spare = start(&backend, &browser, aal2()).await;
        let now = totp::unix_now();
        let code = totp_code(&secret, now);
        let done = submit(
            &backend,
            &browser,
            &first,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        browser.session = session_cookie(&done);
        let token = browser.session.clone().unwrap();
        let WhoamiOutcome::Ok(before) = whoami(&backend, &token).await else {
            panic!("live");
        };
        let old = "2026-01-01T00:00:00.000000+00:00";
        backdate(&db, &before.id, old).await.unwrap();

        let next = totp_code(&secret, now + totp::STEP_SECS);
        let done = submit(
            &backend,
            &browser,
            &spare,
            &[("method", "totp"), ("totp_code", &next)],
        )
        .await;
        assert_eq!(location(&done), "/error?id=self_service_flow_expired");
        let WhoamiOutcome::Ok(after) = whoami(&backend, &token).await else {
            panic!("live");
        };
        assert_eq!(
            after.authenticated_at.as_deref(),
            Some(old),
            "a code is no re-authentication"
        );
        let cred = store::credential(&db, &identity, "totp")
            .await
            .unwrap()
            .unwrap();
        let config: TotpConfig = serde_json::from_str(&cred.config).unwrap();
        assert_eq!(
            config.last_used_step,
            Some(totp::step_at(now)),
            "the next code is not spent"
        );
    }

    #[tokio::test]
    async fn a_completed_login_flow_cannot_be_submitted_again() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "once@x.test", true).await;
        let secret = plant_totp(&backend, &identity).await;
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        let done = password(&backend, &browser, &id, "once@x.test", PASSWORD).await;
        assert!(session_cookie(&done).is_some());
        let again = send(
            &backend,
            &browser,
            &id,
            &[
                ("method", "password"),
                ("identifier", "once@x.test"),
                ("password", PASSWORD),
            ],
        )
        .await;
        assert!(matches!(again, Dispatch::Expired), "{again:?}");
        assert!(matches!(
            backend
                .get_flow(FlowKind::Login, &id, &browser.cookie())
                .await
                .unwrap(),
            FlowFetch::Gone
        ));

        let mut signed_in = browser.clone();
        signed_in.session = session_cookie(&done);
        let step = start(&backend, &signed_in, aal2()).await;
        let now = totp::unix_now();
        let code = totp_code(&secret, now);
        let done = submit(
            &backend,
            &signed_in,
            &step,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        signed_in.session = session_cookie(&done);
        let next = totp_code(&secret, now + totp::STEP_SECS);
        let again = send(
            &backend,
            &signed_in,
            &step,
            &[("method", "totp"), ("totp_code", &next)],
        )
        .await;
        assert!(matches!(again, Dispatch::Expired), "{again:?}");
    }

    #[tokio::test]
    async fn a_lookup_code_works_once() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "l@x.test", true).await;
        plant_totp(&backend, &identity).await;
        let codes = plant_lookup_codes(&backend, &identity).await;
        let typed = codes[0].to_uppercase().replace('-', " ");

        let browser = sign_in(&backend, "l@x.test").await;
        let id = start(&backend, &browser, aal2()).await;
        let done = submit(
            &backend,
            &browser,
            &id,
            &[("method", "lookup_secret"), ("lookup_secret", &typed)],
        )
        .await;
        let token = session_cookie(&done).expect("accepted");
        let WhoamiOutcome::Ok(session) = whoami(&backend, &token).await else {
            panic!("live");
        };
        let methods: Vec<_> = session
            .authentication_methods
            .unwrap()
            .into_iter()
            .map(|m| m.method.unwrap())
            .collect();
        assert_eq!(methods, ["password", "lookup_secret"]);

        let other = sign_in(&backend, "l@x.test").await;
        let id = start(&backend, &other, aal2()).await;
        let done = submit(
            &backend,
            &other,
            &id,
            &[("method", "lookup_secret"), ("lookup_secret", &codes[0])],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(
            messages(&backend, &id).await.1,
            [("lookup_secret".to_string(), 4_000_016)]
        );
        let done = submit(
            &backend,
            &other,
            &id,
            &[("method", "lookup_secret"), ("lookup_secret", &codes[1])],
        )
        .await;
        assert!(session_cookie(&done).is_some());
    }

    #[tokio::test]
    async fn a_second_factor_needs_the_session_the_flow_was_made_for() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "own@x.test", true).await;
        let secret = plant_totp(&backend, &identity).await;
        identity_with_password(&db, "else@x.test", true).await;
        let owner = sign_in(&backend, "own@x.test").await;
        let id = start(&backend, &owner, aal2()).await;
        let code = totp_code(&secret, totp::unix_now());
        let fields = [("method", "totp"), ("totp_code", code.as_str())];

        let mut same_identity = owner.clone();
        same_identity.session = sign_in(&backend, "own@x.test").await.session;
        let mut other_identity = owner.clone();
        other_identity.session = sign_in(&backend, "else@x.test").await.session;
        let mut signed_out = owner.clone();
        signed_out.session = None;
        for (browser, want) in [
            (&same_identity, "forged"),
            (&other_identity, "forged"),
            (&signed_out, "expired"),
        ] {
            let got = match send(&backend, browser, &id, &fields).await {
                Dispatch::Forged => "forged",
                Dispatch::Expired => "expired",
                other => panic!("accepted: {other:?}"),
            };
            assert_eq!(got, want);
        }
        let done = submit(&backend, &owner, &id, &fields).await;
        assert!(session_cookie(&done).is_some(), "the code was not spent");
    }

    #[tokio::test]
    async fn a_second_factor_flow_without_totp_fails_cleanly() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "no2fa@x.test", true).await;
        let browser = sign_in(&backend, "no2fa@x.test").await;
        let id = start(&backend, &browser, aal2()).await;
        let done = submit(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_code", "123456")],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        let WhoamiOutcome::Ok(session) =
            whoami(&backend, browser.session.as_deref().unwrap()).await
        else {
            panic!("the session is untouched");
        };
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal1));
        let FlowFetch::Ok(flow) = backend
            .get_flow(FlowKind::Login, &id, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        assert_eq!(
            flow.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            [1_010_004]
        );
    }

    async fn backdate(db: &DbPool, session_id: &str, at: &str) -> anyhow::Result<()> {
        use crate::schema::identity_sessions;
        use diesel::prelude::*;
        let (id, at) = (session_id.to_string(), at.to_string());
        crate::db_interact!(db, |c| {
            diesel::update(identity_sessions::table.find(&id))
                .set(identity_sessions::authenticated_at.eq(&at))
                .execute(c)
        })?;
        Ok(())
    }

    #[tokio::test]
    async fn refresh_advances_authenticated_at_and_keeps_aal2() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "re@x.test", true).await;
        let secret = plant_totp(&backend, &identity).await;
        let mut browser = sign_in(&backend, "re@x.test").await;
        let id = start(&backend, &browser, aal2()).await;
        let code = totp_code(&secret, totp::unix_now());
        let done = submit(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        browser.session = session_cookie(&done);
        let token = browser.session.clone().unwrap();
        let WhoamiOutcome::Ok(before) = whoami(&backend, &token).await else {
            panic!("live");
        };
        let old = "2026-01-01T00:00:00.000000+00:00";
        backdate(&db, &before.id, old).await.unwrap();

        let refresh = InitParams {
            return_to: Some("http://localhost:3000/oauth/login?login_challenge=c"),
            aal2: false,
            refresh: true,
        };
        let id = start(&backend, &browser, refresh).await;
        let done = submit(
            &backend,
            &browser,
            &id,
            &[
                ("method", "password"),
                ("identifier", "re@x.test"),
                ("password", "wrong horse battery"),
            ],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [4_000_006]);
        let WhoamiOutcome::Ok(untouched) = whoami(&backend, &token).await else {
            panic!("live");
        };
        assert_eq!(untouched.authenticated_at.as_deref(), Some(old));

        let done = submit(
            &backend,
            &browser,
            &id,
            &[
                ("method", "password"),
                ("identifier", "someone-else@x.test"),
                ("password", PASSWORD),
            ],
        )
        .await;
        assert_eq!(
            location(&done),
            "http://localhost:3000/oauth/login?login_challenge=c"
        );
        assert!(session_cookie(&done).is_none(), "the token stays");
        assert!(actions(&done)[0].contains("auth.login"));
        let WhoamiOutcome::Ok(after) = whoami(&backend, &token).await else {
            panic!("live");
        };
        assert_eq!(after.id, before.id);
        assert_eq!(after.authenticator_assurance_level, Some(Aal::Aal2));
        assert!(after.authenticated_at.as_deref().unwrap() > old);
        let auth_time = crate::oauth::reauth::session_auth_time(&after).unwrap();
        assert!(auth_time > chrono::Utc::now() - chrono::Duration::minutes(1));
    }

    #[tokio::test]
    async fn password_attempts_are_throttled_per_address_whether_or_not_it_exists() {
        let mut cfg = AppConfig::test_fixture();
        cfg.identity.login_identifier_rate_per_15m = 2;
        let (db, backend) = setup_with(cfg).await;
        identity_with_password(&db, "busy@x.test", true).await;
        let mut throttled = Vec::new();
        for identifier in ["busy@x.test", "ghost@x.test"] {
            let browser = Browser::new();
            let id = start(&backend, &browser, InitParams::default()).await;
            for _ in 0..2 {
                password(&backend, &browser, &id, identifier, "wrong horse battery").await;
                assert_eq!(messages(&backend, &id).await.0, [4_000_006]);
            }
            let shouted = identifier.to_uppercase();
            let done = password(&backend, &browser, &id, &shouted, PASSWORD).await;
            assert_eq!(done.outcome, SubmitOutcome::Page);
            assert!(actions(&done)[0].contains("throttled"));
            let rec = backend.load_flow(&id).await.unwrap().unwrap();
            assert_eq!(rec.ctx.messages[0].id, 9_000_001);
            throttled.push((rec.ctx.messages, rec.ctx.node_messages));
        }
        assert_eq!(throttled[0], throttled[1]);

        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        identity_with_password(&db, "free@x.test", true).await;
        let done = password(&backend, &browser, &id, "free@x.test", PASSWORD).await;
        assert!(
            session_cookie(&done).is_some(),
            "other addresses are not affected"
        );
    }

    #[tokio::test]
    async fn second_factor_attempts_are_throttled_per_identity() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "guess@x.test", true).await;
        let secret = plant_totp(&backend, &identity).await;
        let browser = sign_in(&backend, "guess@x.test").await;
        let id = start(&backend, &browser, aal2()).await;
        let wrong = [
            ("method", "lookup_secret"),
            ("lookup_secret", "aaaa-bbbb-cccc"),
        ];
        for _ in 0..SECOND_FACTOR_LIMIT {
            submit(&backend, &browser, &id, &wrong).await;
        }
        let code = totp_code(&secret, totp::unix_now());
        let done = submit(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [9_000_001]);
    }

    const SECOND_FACTOR_LIMIT: usize = crate::identity_native::SECOND_FACTOR_ATTEMPTS;

    use serde_json::Value;

    use crate::identity_native::store::keys::{Key, KeyRow};
    use crate::identity_native::test_authenticator::Authenticator;
    use crate::identity_native::test_support::sql;
    use crate::schema::identity_webauthn_keys;

    const ORIGIN: &str = "http://localhost:3000";
    const RP_ID: &str = "localhost";

    /// A security key registered with the backend's relying party and stored for `identity`.
    async fn plant_security_key(backend: &NativeBackend, identity: &str) -> Authenticator {
        let rp = backend.webauthn.as_ref().unwrap();
        let mut token = Authenticator::security_key();
        let (options, state) = rp
            .start_securitykey_registration(uuid::Uuid::new_v4(), "k", "k", None, None, None)
            .unwrap();
        let response = token.register(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        let key = rp
            .finish_securitykey_registration(&serde_json::from_value(response).unwrap(), &state)
            .unwrap();
        keys::plant_key(&backend.db, identity, &Key::SecurityKey(key)).await;
        token
    }

    async fn key_row(db: &DbPool, identity: &str) -> KeyRow {
        keys::of_identity(db, identity).await.unwrap().remove(0)
    }

    async fn render(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
    ) -> crate::flow_view::Flow {
        let FlowFetch::Ok(flow) = backend
            .get_flow(FlowKind::Login, id, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        *flow
    }

    /// The request options the page shows in the node `name`; rendering mints them.
    async fn shown_options(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        name: &str,
    ) -> Value {
        let flow = render(backend, browser, id).await;
        let shown = flow
            .inputs
            .iter()
            .find(|(_, i)| i.name == name)
            .map(|(_, i)| i.value.clone())
            .unwrap_or_else(|| panic!("{name} shown"));
        serde_json::from_str(&shown).unwrap()
    }

    /// The request options the second-factor page shows.
    async fn key_options(backend: &NativeBackend, browser: &Browser, id: &str) -> Value {
        shown_options(backend, browser, id, "webauthn_login_trigger").await
    }

    /// Post `response` as `static/webauthn.js` does: the whole form, no button.
    async fn key_submit(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        response: &Value,
    ) -> Submitted {
        let response = response.to_string();
        submit(
            backend,
            browser,
            id,
            &[("lookup_secret", ""), ("webauthn_login", &response)],
        )
        .await
    }

    /// Answer the page's current options with `token` and post the response.
    async fn use_token(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        token: &mut Authenticator,
    ) -> Submitted {
        let options = key_options(backend, browser, id).await;
        let response = token.assert(RP_ID, ORIGIN, &options);
        key_submit(backend, browser, id, &response).await
    }

    fn method_names(session: &crate::backend::identity::Session) -> Vec<String> {
        session
            .authentication_methods
            .clone()
            .unwrap()
            .into_iter()
            .map(|m| m.method.unwrap())
            .collect()
    }

    /// Refused with 4000006 and one `auth.login_failed` row for `reason`; the session stays AAL1.
    async fn key_refused(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        done: &Submitted,
        reason: &str,
    ) {
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(session_cookie(done).is_none());
        assert_eq!(messages(backend, id).await.0, [4_000_006]);
        let audit = actions(done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("auth.login_failed"), "{}", audit[0]);
        assert!(audit[0].contains(r#"String("webauthn")"#), "{}", audit[0]);
        assert!(audit[0].contains(reason), "{}", audit[0]);
        assert!(matches!(
            whoami(backend, browser.session.as_deref().unwrap()).await,
            WhoamiOutcome::InsufficientAal
        ));
    }

    #[tokio::test]
    async fn a_security_key_raises_the_session_to_aal2_with_method_webauthn() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "k@x.test", true).await;
        let mut token = plant_security_key(&backend, &identity).await;
        let browser = sign_in(&backend, "k@x.test").await;
        let aal1 = browser.session.clone().unwrap();
        assert!(matches!(
            whoami(&backend, &aal1).await,
            WhoamiOutcome::InsufficientAal
        ));

        let id = start(&backend, &browser, aal2()).await;
        token.sign_count = 1;
        let done = use_token(&backend, &browser, &id, &mut token).await;
        assert_eq!(location(&done), "/settings");
        assert!(done.audit.is_empty(), "the step-up writes no login row");
        let rotated = session_cookie(&done).expect("a new cookie");
        assert!(matches!(whoami(&backend, &aal1).await, WhoamiOutcome::None));
        let WhoamiOutcome::Ok(session) = whoami(&backend, &rotated).await else {
            panic!("the rotated token is live");
        };
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal2));
        assert_eq!(method_names(&session), ["password", "webauthn"]);
        let row = key_row(&db, &identity).await;
        assert_eq!((row.sign_count, row.version), (1, 1));
    }

    #[tokio::test]
    async fn a_key_counter_that_does_not_advance_is_refused() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "c@x.test", true).await;
        let mut token = plant_security_key(&backend, &identity).await;
        let (first, second) = (
            sign_in(&backend, "c@x.test").await,
            sign_in(&backend, "c@x.test").await,
        );
        let stale = start(&backend, &first, aal2()).await;
        let stale_options = key_options(&backend, &first, &stale).await;
        let id = start(&backend, &second, aal2()).await;
        token.sign_count = 5;
        let done = use_token(&backend, &second, &id, &mut token).await;
        assert!(session_cookie(&done).is_some());

        // Minted before the use above, so only the stored counter catches this one.
        token.sign_count = 3;
        let response = token.assert(RP_ID, ORIGIN, &stale_options);
        let done = key_submit(&backend, &first, &stale, &response).await;
        key_refused(&backend, &first, &stale, &done, "counter").await;
        let row = key_row(&db, &identity).await;
        assert_eq!(row.sign_count, 5);
        let challenge = stale_options["publicKey"]["challenge"].as_str().unwrap();
        let audit = &actions(&done)[0];
        for material in [row.credential_id.as_str(), challenge] {
            assert!(!audit.contains(material), "{audit}");
        }

        let third = sign_in(&backend, "c@x.test").await;
        let id = start(&backend, &third, aal2()).await;
        let done = use_token(&backend, &third, &id, &mut token).await;
        key_refused(&backend, &third, &id, &done, "counter").await;
        assert_eq!(key_row(&db, &identity).await, row);
    }

    #[tokio::test]
    async fn another_identitys_key_is_refused() {
        let (db, backend) = setup().await;
        let ann = identity_with_password(&db, "ann@x.test", true).await;
        let mut ann_token = plant_security_key(&backend, &ann).await;
        let bob = identity_with_password(&db, "bob@x.test", true).await;
        let mut bob_token = plant_security_key(&backend, &bob).await;
        plant_totp(&backend, &bob).await;
        let browser = sign_in(&backend, "bob@x.test").await;

        let id = start(&backend, &browser, aal2()).await;
        ann_token.sign_count = 1;
        let done = use_token(&backend, &browser, &id, &mut ann_token).await;
        key_refused(&backend, &browser, &id, &done, "invalid_credentials").await;
        assert_eq!(key_row(&db, &ann).await.sign_count, 0);

        // Bob's credential moves to Ann after Bob's page sealed it.
        let options = key_options(&backend, &browser, &id).await;
        let row = key_row(&db, &bob).await;
        let (row_id, owner) = (row.id.clone(), ann.clone());
        sql(&db, move |c| {
            use diesel::prelude::*;
            diesel::update(identity_webauthn_keys::table.find(&row_id))
                .set(identity_webauthn_keys::identity_id.eq(&owner))
                .execute(c)
        })
        .await;
        bob_token.sign_count = 1;
        let response = bob_token.assert(RP_ID, ORIGIN, &options);
        let done = key_submit(&backend, &browser, &id, &response).await;
        key_refused(&backend, &browser, &id, &done, "invalid_credentials").await;
        let moved = keys::of_identity(&db, &ann).await.unwrap();
        assert!(moved.iter().any(|r| r.id == row.id && r.sign_count == 0));
    }

    #[tokio::test]
    async fn a_key_removed_or_no_longer_a_security_key_after_rendering_is_refused() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "gone@x.test", true).await;
        plant_totp(&backend, &identity).await;
        let browser = sign_in(&backend, "gone@x.test").await;
        for delete in [true, false] {
            let mut token = plant_security_key(&backend, &identity).await;
            let id = start(&backend, &browser, aal2()).await;
            let options = key_options(&backend, &browser, &id).await;
            let row_id = key_row(&db, &identity).await.id;
            sql(&db, move |c| {
                use diesel::prelude::*;
                let target = identity_webauthn_keys::table.find(&row_id);
                if delete {
                    diesel::delete(target).execute(c)
                } else {
                    diesel::update(target)
                        .set(identity_webauthn_keys::kind.eq("passkey"))
                        .execute(c)
                }
            })
            .await;
            token.sign_count = 1;
            let response = token.assert(RP_ID, ORIGIN, &options);
            let done = key_submit(&backend, &browser, &id, &response).await;
            key_refused(&backend, &browser, &id, &done, "invalid_credentials").await;
            if !delete {
                assert_eq!(key_row(&db, &identity).await.sign_count, 0);
            }
        }

        let id = start(&backend, &browser, aal2()).await;
        let mut token = Authenticator::security_key();
        let done = key_submit(
            &backend,
            &browser,
            &id,
            &token.assert(
                RP_ID,
                ORIGIN,
                &serde_json::json!({"publicKey": {"challenge": "AA"}}),
            ),
        )
        .await;
        key_refused(&backend, &browser, &id, &done, "invalid_credentials").await;
    }

    #[tokio::test]
    async fn key_attempts_share_the_second_factor_budget() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "budget@x.test", true).await;
        let mut token = plant_security_key(&backend, &identity).await;
        plant_lookup_codes(&backend, &identity).await;
        let browser = sign_in(&backend, "budget@x.test").await;
        let id = start(&backend, &browser, aal2()).await;
        let garbage = serde_json::json!({ "id": "x" });
        for attempt in 0..SECOND_FACTOR_LIMIT {
            if attempt % 2 == 0 {
                key_submit(&backend, &browser, &id, &garbage).await;
            } else {
                let wrong = [
                    ("method", "lookup_secret"),
                    ("lookup_secret", "aaaa-bbbb-cccc"),
                    ("webauthn_login", ""),
                ];
                submit(&backend, &browser, &id, &wrong).await;
            }
        }
        token.sign_count = 1;
        let done = use_token(&backend, &browser, &id, &mut token).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [9_000_001]);
        let audit = actions(&done);
        assert!(audit[0].contains("throttled") && audit[0].contains(r#"String("webauthn")"#));
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert!(
            rec.ctx.key_ceremony.is_some(),
            "a throttled attempt spends no challenge"
        );
        assert_eq!(key_row(&db, &identity).await.sign_count, 0);
        assert!(matches!(
            whoami(&backend, browser.session.as_deref().unwrap()).await,
            WhoamiOutcome::InsufficientAal
        ));
    }

    #[tokio::test]
    async fn a_key_only_identity_can_use_a_lookup_code() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "only@x.test", true).await;
        plant_security_key(&backend, &identity).await;
        let codes = plant_lookup_codes(&backend, &identity).await;
        let browser = sign_in(&backend, "only@x.test").await;
        let id = start(&backend, &browser, aal2()).await;
        key_options(&backend, &browser, &id).await;

        let done = submit(
            &backend,
            &browser,
            &id,
            &[("method", "webauthn"), ("webauthn_login", "")],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [4_010_002]);

        let done = submit(
            &backend,
            &browser,
            &id,
            &[
                ("method", "lookup_secret"),
                ("lookup_secret", &codes[0]),
                ("webauthn_login", ""),
            ],
        )
        .await;
        let token = session_cookie(&done).expect("accepted");
        let WhoamiOutcome::Ok(session) = whoami(&backend, &token).await else {
            panic!("live");
        };
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal2));
        assert_eq!(method_names(&session), ["password", "lookup_secret"]);
    }

    /// An identity without a password.
    async fn passwordless(db: &DbPool, email: &str, verified: bool) -> String {
        store::create(db, email, None, None, verified)
            .await
            .unwrap()
            .expect("address is free")
            .id
    }

    /// A passkey of `identity`, its user handle the identity id, registered with `rp` and stored.
    async fn plant_passkey_with(
        rp: &webauthn_rs::prelude::Webauthn,
        db: &DbPool,
        identity: &str,
    ) -> Authenticator {
        let mut token = Authenticator::passkey();
        let user = uuid::Uuid::parse_str(identity).unwrap();
        let (options, state) = rp.start_passkey_registration(user, "p", "p", None).unwrap();
        let response = token.register(RP_ID, ORIGIN, &webauthn::passkey_options(&options));
        let passkey = rp
            .finish_passkey_registration(&serde_json::from_value(response).unwrap(), &state)
            .unwrap();
        keys::plant_key(db, identity, &Key::Passkey(passkey)).await;
        token
    }

    async fn plant_passkey(backend: &NativeBackend, identity: &str) -> Authenticator {
        plant_passkey_with(backend.webauthn.as_ref().unwrap(), &backend.db, identity).await
    }

    /// Post `response` as `static/webauthn.js` does: the whole form, no button.
    async fn passkey_submit(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        response: &Value,
    ) -> Submitted {
        let response = response.to_string();
        submit(
            backend,
            browser,
            id,
            &[
                ("identifier", ""),
                ("password", ""),
                ("passkey_login", &response),
            ],
        )
        .await
    }

    /// Answer the page's current passkey options with `token`, as seen from `origin`.
    async fn use_passkey_from(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        token: &mut Authenticator,
        origin: &str,
    ) -> Submitted {
        let options = shown_options(backend, browser, id, "passkey_challenge").await;
        let response = token.assert(RP_ID, origin, &options);
        passkey_submit(backend, browser, id, &response).await
    }

    async fn use_passkey(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        token: &mut Authenticator,
    ) -> Submitted {
        use_passkey_from(backend, browser, id, token, ORIGIN).await
    }

    /// A browser signed in with `token` on the first login step.
    async fn passkey_sign_in(backend: &NativeBackend, token: &mut Authenticator) -> Browser {
        let mut browser = Browser::new();
        let id = start(backend, &browser, InitParams::default()).await;
        let done = use_passkey(backend, &browser, &id, token).await;
        browser.session = Some(session_cookie(&done).expect("signed in"));
        browser
    }

    /// Shown `message` with one `auth.login_failed` row for `reason`, attributed to `actor`.
    async fn passkey_refused(
        backend: &NativeBackend,
        id: &str,
        done: &Submitted,
        message: u64,
        reason: &str,
        actor: Option<&str>,
    ) {
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(session_cookie(done).is_none());
        assert_eq!(messages(backend, id).await.0, [message]);
        let audit = actions(done);
        assert_eq!(audit.len(), 1);
        let row = &audit[0];
        assert!(row.contains("auth.login_failed"), "{row}");
        assert!(row.contains(r#"String("passkey")"#), "{row}");
        assert!(row.contains(reason), "{row}");
        match actor {
            Some(actor) => assert!(row.contains(&format!("actor_id: Some({actor:?})")), "{row}"),
            None => assert!(row.contains("actor_id: None"), "{row}"),
        }
    }

    fn input_names(flow: &crate::flow_view::Flow) -> Vec<String> {
        flow.inputs.iter().map(|(_, i)| i.name.clone()).collect()
    }

    #[tokio::test]
    async fn a_passkey_signs_in_at_aal1_with_method_passkey() {
        let (db, backend) = setup().await;
        let identity = passwordless(&db, "pk@x.test", true).await;
        let mut token = plant_passkey(&backend, &identity).await;
        let browser = Browser::new();
        let id = start(
            &backend,
            &browser,
            InitParams {
                return_to: Some("/settings/profile"),
                ..InitParams::default()
            },
        )
        .await;
        let options = shown_options(&backend, &browser, &id, "passkey_challenge").await;
        let response = token.assert(RP_ID, ORIGIN, &options);
        let done = passkey_submit(&backend, &browser, &id, &response).await;
        assert_eq!(location(&done), "/settings/profile");
        let cookie = session_cookie(&done).expect("a session cookie");
        let WhoamiOutcome::Ok(session) = whoami(&backend, &cookie).await else {
            panic!("the new session is live");
        };
        assert_eq!(session.identity.as_ref().unwrap().id, identity);
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal1));
        assert_eq!(method_names(&session), ["passkey"]);

        let audit = actions(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("action: \"auth.login\""), "{}", audit[0]);
        assert!(audit[0].contains(r#"String("passkey")"#), "{}", audit[0]);
        assert!(audit[0].contains(&session.id));
        let row = keys::of_identity(&db, &identity).await.unwrap().remove(0);
        assert_eq!(row.version, 1, "the use is recorded");
        let challenge = options["publicKey"]["challenge"].as_str().unwrap();
        let handle = response["response"]["userHandle"].as_str().unwrap();
        for material in [row.credential_id.as_str(), challenge, handle, &cookie] {
            assert!(!audit[0].contains(material), "{}", audit[0]);
        }

        let again = send(&backend, &browser, &id, &[("passkey_login", "x")]).await;
        assert!(matches!(again, Dispatch::Expired), "{again:?}");
    }

    #[tokio::test]
    async fn a_passkey_sign_in_still_needs_the_second_factor() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "pk2@x.test", true).await;
        let mut token = plant_passkey(&backend, &identity).await;
        plant_totp(&backend, &identity).await;
        let browser = passkey_sign_in(&backend, &mut token).await;
        let session = browser.session.as_deref().unwrap();
        assert!(matches!(
            whoami(&backend, session).await,
            WhoamiOutcome::InsufficientAal
        ));
    }

    #[tokio::test]
    async fn a_user_handle_that_is_not_the_credentials_identity_is_refused() {
        let (db, backend) = setup().await;
        let ann = passwordless(&db, "ann@x.test", true).await;
        let mut token = plant_passkey(&backend, &ann).await;
        let bob = passwordless(&db, "bob@x.test", true).await;
        let ann_handle = token.user_handle.clone();
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        for handle in [
            Some(uuid::Uuid::parse_str(&bob).unwrap().as_bytes().to_vec()),
            Some(vec![7; 8]),
            None,
        ] {
            token.user_handle = handle;
            token.resident_key = token.user_handle.is_some();
            let done = use_passkey(&backend, &browser, &id, &mut token).await;
            passkey_refused(&backend, &id, &done, 4_000_006, "invalid_credentials", None).await;
        }
        let row = keys::of_identity(&db, &ann).await.unwrap().remove(0);
        assert_eq!(row.version, 0, "nothing is recorded");

        token.user_handle = ann_handle;
        token.resident_key = true;
        let done = use_passkey(&backend, &browser, &id, &mut token).await;
        assert!(session_cookie(&done).is_some(), "the owner's handle works");
    }

    #[tokio::test]
    async fn a_security_key_cannot_sign_in_as_a_passkey() {
        let (db, backend) = setup().await;
        let identity = passwordless(&db, "sk@x.test", true).await;
        let rp = backend.webauthn.as_ref().unwrap();
        let user = uuid::Uuid::parse_str(&identity).unwrap();
        let mut token = Authenticator::security_key();
        // A key that keeps the user handle and verifies the user, so only the kind tells it apart.
        token.resident_key = true;
        token.user_verified = true;
        let (options, state) = rp
            .start_securitykey_registration(user, "k", "k", None, None, None)
            .unwrap();
        let response = token.register(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        let key = rp
            .finish_securitykey_registration(&serde_json::from_value(response).unwrap(), &state)
            .unwrap();
        keys::plant_key(&db, &identity, &Key::SecurityKey(key)).await;

        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        token.sign_count = 1;
        let done = use_passkey(&backend, &browser, &id, &mut token).await;
        passkey_refused(&backend, &id, &done, 4_000_006, "invalid_credentials", None).await;
        assert_eq!(key_row(&db, &identity).await.sign_count, 0);
    }

    #[tokio::test]
    async fn inactive_and_unverified_identities_are_refused_only_after_verification() {
        let (db, backend) = setup().await;
        let off = passwordless(&db, "off@x.test", true).await;
        let mut off_token = plant_passkey(&backend, &off).await;
        store::set_state(&db, &off, IdentityState::Inactive)
            .await
            .unwrap();
        let late = passwordless(&db, "late@x.test", false).await;
        let mut late_token = plant_passkey(&backend, &late).await;
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;

        for token in [&mut off_token, &mut late_token] {
            let done = use_passkey_from(&backend, &browser, &id, token, "http://evil.test").await;
            passkey_refused(&backend, &id, &done, 4_000_006, "invalid_credentials", None).await;
        }

        let done = use_passkey(&backend, &browser, &id, &mut off_token).await;
        passkey_refused(
            &backend,
            &id,
            &done,
            4_000_006,
            "invalid_credentials",
            Some(&off),
        )
        .await;
        let done = use_passkey(&backend, &browser, &id, &mut late_token).await;
        passkey_refused(
            &backend,
            &id,
            &done,
            4_000_010,
            "address_not_verified",
            Some(&late),
        )
        .await;
        for identity in [&off, &late] {
            let row = keys::of_identity(&db, identity).await.unwrap().remove(0);
            assert_eq!(
                row.version, 1,
                "verified and recorded before the state check"
            );
        }
    }

    #[tokio::test]
    async fn passkey_attempts_count_per_identity_once_the_credential_matches() {
        let (db, backend) = setup().await;
        let identity = passwordless(&db, "count@x.test", true).await;
        let mut token = plant_passkey(&backend, &identity).await;
        let handle = token.user_handle.clone();
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;

        token.user_handle = Some(uuid::Uuid::new_v4().as_bytes().to_vec());
        for _ in 0..SECOND_FACTOR_LIMIT {
            let done = use_passkey(&backend, &browser, &id, &mut token).await;
            passkey_refused(&backend, &id, &done, 4_000_006, "invalid_credentials", None).await;
        }
        token.user_handle = handle;
        for _ in 0..SECOND_FACTOR_LIMIT {
            let done =
                use_passkey_from(&backend, &browser, &id, &mut token, "http://evil.test").await;
            passkey_refused(&backend, &id, &done, 4_000_006, "invalid_credentials", None).await;
        }
        let done = use_passkey(&backend, &browser, &id, &mut token).await;
        passkey_refused(&backend, &id, &done, 4_000_006, "throttled", None).await;
        assert_eq!(key_row(&db, &identity).await.version, 0);
        assert!(
            backend.limiters.second_factor.admit(&identity),
            "the second-factor step keeps its own budget"
        );
    }

    #[tokio::test]
    async fn a_passkey_counter_that_does_not_advance_is_refused() {
        let (db, backend) = setup().await;
        let identity = passwordless(&db, "ctr@x.test", true).await;
        let mut token = plant_passkey(&backend, &identity).await;
        token.sign_count = 4;
        passkey_sign_in(&backend, &mut token).await;
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        let done = use_passkey(&backend, &browser, &id, &mut token).await;
        passkey_refused(&backend, &id, &done, 4_000_006, "counter", Some(&identity)).await;
        assert_eq!(key_row(&db, &identity).await.sign_count, 4);
    }

    fn refresh_params() -> InitParams<'static> {
        InitParams {
            return_to: Some("http://localhost:3000/settings"),
            aal2: false,
            refresh: true,
        }
    }

    #[tokio::test]
    async fn a_passkey_refresh_opens_the_privileged_window_on_the_same_session() {
        use super::super::settings::privileged;
        let (db, backend) = setup().await;
        let identity = passwordless(&db, "re-pk@x.test", true).await;
        let mut token = plant_passkey(&backend, &identity).await;
        let other = passwordless(&db, "other@x.test", true).await;
        let mut other_token = plant_passkey(&backend, &other).await;
        let browser = passkey_sign_in(&backend, &mut token).await;
        let cookie = browser.session.clone().unwrap();
        let WhoamiOutcome::Ok(before) = whoami(&backend, &cookie).await else {
            panic!("live");
        };
        let old = "2026-01-01T00:00:00.000000+00:00";
        backdate(&db, &before.id, old).await.unwrap();
        let live = |db: &DbPool| {
            let (db, id) = (db.clone(), before.id.clone());
            async move { session::find_live(&db, &id).await.unwrap().unwrap() }
        };
        assert!(!privileged(&backend, &live(&db).await));

        let id = start(&backend, &browser, refresh_params()).await;
        let names = input_names(&render(&backend, &browser, &id).await);
        assert!(names.iter().any(|n| n == "passkey_challenge"), "{names:?}");
        assert!(!names.iter().any(|n| n == "password"), "{names:?}");

        let done = use_passkey(&backend, &browser, &id, &mut other_token).await;
        passkey_refused(
            &backend,
            &id,
            &done,
            4_000_006,
            "invalid_credentials",
            Some(&identity),
        )
        .await;
        assert_eq!(live(&db).await.authenticated_at, old);

        submit(
            &backend,
            &browser,
            &id,
            &[("method", "password"), ("password", PASSWORD)],
        )
        .await;
        assert_eq!(messages(&backend, &id).await.0, [4_000_006], "no password");

        let version = key_row(&db, &identity).await.version;
        let done = use_passkey(&backend, &browser, &id, &mut token).await;
        assert_eq!(location(&done), "http://localhost:3000/settings");
        assert!(session_cookie(&done).is_none(), "the token stays");
        let audit = actions(&done);
        assert!(audit[0].contains("action: \"auth.login\""), "{}", audit[0]);
        assert!(audit[0].contains(r#"String("passkey")"#), "{}", audit[0]);
        assert!(audit[0].contains("Bool(true)"), "{}", audit[0]);
        let WhoamiOutcome::Ok(after) = whoami(&backend, &cookie).await else {
            panic!("live");
        };
        assert_eq!(after.id, before.id);
        assert_eq!(after.authenticator_assurance_level, Some(Aal::Aal1));
        assert!(after.authenticated_at.as_deref().unwrap() > old);
        assert!(privileged(&backend, &live(&db).await));
        assert_eq!(
            key_row(&db, &identity).await.version,
            version + 1,
            "the use is recorded"
        );
    }

    #[tokio::test]
    async fn a_passkey_refresh_spends_the_passkey_budget_of_the_identity() {
        let (db, backend) = setup().await;
        let identity = passwordless(&db, "budget-pk@x.test", true).await;
        let mut token = plant_passkey(&backend, &identity).await;
        let browser = passkey_sign_in(&backend, &mut token).await;
        let id = start(&backend, &browser, refresh_params()).await;
        for _ in 1..SECOND_FACTOR_LIMIT {
            let done =
                use_passkey_from(&backend, &browser, &id, &mut token, "http://evil.test").await;
            passkey_refused(
                &backend,
                &id,
                &done,
                4_000_006,
                "invalid_credentials",
                Some(&identity),
            )
            .await;
        }
        let done = use_passkey(&backend, &browser, &id, &mut token).await;
        passkey_refused(
            &backend,
            &id,
            &done,
            9_000_001,
            "throttled",
            Some(&identity),
        )
        .await;
        assert!(
            backend
                .limiters
                .password
                .admit(&store::address_key("budget-pk@x.test")),
            "the address's password budget is untouched"
        );
    }

    #[tokio::test]
    async fn refresh_shows_the_password_form_unless_a_passkey_stands_in_for_it() {
        let (db, backend) = setup().await;
        let password_only = identity_with_password(&db, "pw@x.test", true).await;
        let both = identity_with_password(&db, "both@x.test", true).await;
        plant_passkey(&backend, &both).await;
        let passkey_only = passwordless(&db, "pk-only@x.test", true).await;
        plant_passkey(&backend, &passkey_only).await;
        let neither = passwordless(&db, "none@x.test", true).await;
        let unreadable = passwordless(&db, "bad@x.test", true).await;
        keys::plant(&db, &unreadable, KeyKind::Passkey).await;

        let mut cfg = AppConfig::test_fixture();
        cfg.self_.url = "http://127.0.0.1:3000".into();
        let no_rp = NativeBackend::new(&cfg, &db, &[0x42; 32]);
        assert!(no_rp.webauthn.is_none());

        for (backend, identity, password, passkey) in [
            (&backend, &password_only, true, false),
            (&backend, &both, true, true),
            (&backend, &passkey_only, false, true),
            (&backend, &neither, true, false),
            (&backend, &unreadable, true, false),
            (&no_rp, &passkey_only, true, false),
        ] {
            let issued = backend
                .issue_session(identity, "password", None, Aal::Aal1, DEVICE)
                .await
                .unwrap();
            let browser = Browser {
                csrf: uuid::Uuid::new_v4().to_string(),
                session: Some(issued.token),
            };
            let id = start(backend, &browser, refresh_params()).await;
            let flow = render(backend, &browser, &id).await;
            let names = input_names(&flow);
            let shows = |name: &str| names.iter().any(|n| n == name);
            assert_eq!(shows("password"), password, "{identity}: {names:?}");
            assert_eq!(shows("passkey_challenge"), passkey, "{identity}: {names:?}");
            assert!(shows("identifier"), "{identity}: {names:?}");
        }
    }

    #[tokio::test]
    async fn hashing_at_capacity_asks_to_try_again() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "full@x.test", true).await;
        let all = u32::try_from(backend.hash_permits.available_permits()).unwrap();
        let _held = backend.hash_permits.clone().acquire_many_owned(all).await;
        let browser = Browser::new();
        let id = start(&backend, &browser, InitParams::default()).await;
        let done = password(&backend, &browser, &id, "full@x.test", PASSWORD).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [9_000_001]);
    }
}
