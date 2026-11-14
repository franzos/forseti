//! Login submits: password sign-in, refresh of a signed-in session, and the second factor.

use anyhow::{Result, anyhow};

use super::{FlowRecord, Submission, SubmitOutcome, Submitted};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::Aal;
use crate::identity_native::lookup::{self, LookupConfig};
use crate::identity_native::password::{self, HashError, PasswordConfig};
use crate::identity_native::session::{self, SessionRow, StepUp};
use crate::identity_native::store::{self, IdentityRow};
use crate::identity_native::totp::{self, TotpConfig};
use crate::identity_native::ui::Message;
use crate::identity_native::{NativeBackend, errors};

/// Kratos's message ids and English texts for the outcomes below.
const INVALID_CREDENTIALS: (u64, &str) = (
    4_000_006,
    "The provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number.",
);
const NOT_VERIFIED: (u64, &str) = (
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

pub(super) async fn submit(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    s.flow.clear_messages();
    match s.session.take() {
        None => password_login(backend, s).await,
        Some(session) if s.flow.row.refresh != 0 => refresh(backend, s, session).await,
        Some(session) => second_factor(backend, s, session).await,
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

fn login_event(flow: &FlowRecord, identity: &IdentityRow, session_id: &str) -> AuditEvent {
    AuditEvent::new(action::AUTH_LOGIN)
        .actor_user(&identity.id, &identity.email)
        .target(target_kind::IDENTITY, &identity.id)
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => flow.row.id,
            "kratos_session_id" => session_id,
            "method" => "password",
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
        .issue_session(&row.id, "password", Aal::Aal1, s.device)
        .await?;
    let event = login_event(&s.flow, &row, &issued.id);
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
        || !session::refresh(&backend.db, &session.id, "password", Aal::Aal1).await?
    {
        return Ok(expired());
    }
    let event = login_event(&flow, &row, &session.id);
    Ok(signed_in(return_to(&flow), Vec::new(), vec![event]))
}

/// A TOTP code or an unused lookup code raises the session to AAL2 and moves it to a new token.
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
    if store::credential(&backend.db, &identity_id, "totp")
        .await?
        .is_none()
    {
        return page(backend, s.flow, Vec::new()).await;
    }
    let method = s.form.get("method").unwrap_or_default();
    let (field, invalid) = match method {
        "totp" => ("totp_code", INVALID_TOTP),
        "lookup_secret" => ("lookup_secret", INVALID_LOOKUP),
        _ => return reject(backend, s.flow, NO_STRATEGY, Vec::new()).await,
    };
    let Some(row) = store::row_by_id(&backend.db, &identity_id).await? else {
        return Ok(expired());
    };
    if !backend.limiters.second_factor.admit(&identity_id) {
        let event = failed_event(&s.flow, Some(&row), method, "throttled");
        return reject(backend, s.flow, THROTTLED, vec![event]).await;
    }
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
    if !s.flow.finish(&backend.db).await? {
        return Ok(expired());
    }
    match session::step_up(&backend.db, &session, method, Aal::Aal2).await? {
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
