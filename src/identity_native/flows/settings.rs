//! Settings submits: profile, password, TOTP enrolment and unlink, lookup codes. Every method but
//! a profile save that keeps the address needs a sign-in within the privileged window; the
//! dispatcher has already checked the session and its AAL.

use anyhow::{Result, anyhow};

use super::registration::{check_traits, traits_of};
use super::{
    AfterEffect, Context, FlowRecord, Form, SAVE_ATTEMPTS, Saved, Submission, SubmitOutcome,
    Submitted,
};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::Aal;
use crate::identity_native::codes::Purpose;
use crate::identity_native::password::{self, HashError, PasswordConfig, PolicyError};
use crate::identity_native::session::{self, SessionRow, StepUp};
use crate::identity_native::store::{self, IdentityRow, ProfileSaved};
use crate::identity_native::totp::{self, TotpConfig};
use crate::identity_native::ui::Message;
use crate::identity_native::{NativeBackend, errors, lookup};

const ACCOUNT_EXISTS: (u64, &str) = (
    4_000_007,
    "An account with the same identifier (email, phone, username, ...) exists already.",
);
const INVALID_TOTP: (u64, &str) = (
    4_000_008,
    "The provided authentication code is invalid, please try again.",
);
const NO_STRATEGY: (u64, &str) = (
    4_000_001,
    "Could not find a strategy to update your settings. Did you fill out the form correctly?",
);
const BUSY: (u64, &str) = (
    9_000_001,
    "Too many sign-in attempts right now. Please try again in a few minutes.",
);

pub(super) async fn submit(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    let session = s.session.take().ok_or_else(|| {
        anyhow!(
            "settings flow {} submitted without a session",
            s.flow.row.id
        )
    })?;
    let Some(row) = store::row_by_id(&backend.db, &session.identity_id).await? else {
        return Ok(expired());
    };
    s.flow.clear_messages();
    s.flow.set_state("show_form");
    let method = s.form.get("method").unwrap_or_default().to_string();
    let change = Change {
        backend,
        flow: s.flow,
        form: s.form,
        session,
        row,
    };
    match method.as_str() {
        "profile" => profile(change).await,
        "password" => change_password(change).await,
        "totp" => totp_method(change).await,
        "lookup_secret" => lookup_method(change).await,
        _ => change.reject(NO_STRATEGY).await,
    }
}

fn expired() -> Submitted {
    SubmitOutcome::Redirect {
        location: errors::url(errors::FLOW_EXPIRED),
        set_cookies: Vec::new(),
    }
    .into()
}

/// One settings submit: the flow, the form, the signed-in session and its identity.
struct Change<'a> {
    backend: &'a NativeBackend,
    flow: FlowRecord,
    form: &'a Form,
    session: SessionRow,
    row: IdentityRow,
}

impl Change<'_> {
    /// Whether the session signed in within the privileged window.
    fn privileged(&self) -> bool {
        chrono::DateTime::parse_from_rfc3339(&self.session.authenticated_at).is_ok_and(|at| {
            chrono::Utc::now() - at.with_timezone(&chrono::Utc)
                <= self.backend.settings.privileged_window()
        })
    }

    /// Send the browser to a password re-authentication that comes back to this page; nothing
    /// is applied or saved.
    fn refresh_required(&self) -> Submitted {
        let back = self
            .flow
            .row
            .return_to
            .clone()
            .unwrap_or_else(|| self.flow_page());
        SubmitOutcome::Redirect {
            location: format!(
                "/login?refresh=true&return_to={}",
                crate::web::urlencode(&back)
            ),
            set_cookies: Vec::new(),
        }
        .into()
    }

    fn flow_page(&self) -> String {
        format!(
            "/settings?flow={}",
            crate::web::urlencode(&self.flow.row.id)
        )
    }

    /// Save the flow with its messages and show it again.
    async fn page(mut self) -> Result<Submitted> {
        let _ = self.flow.save(&self.backend.db).await?;
        Ok(SubmitOutcome::Page.into())
    }

    async fn reject(mut self, (id, text): (u64, &str)) -> Result<Submitted> {
        self.flow.add_message(Message::error(id, text));
        self.page().await
    }

    /// Count an email or password change against the identity's quota.
    fn admit_change(&self) -> bool {
        self.backend.limiters.settings_changes.admit(&self.row.id)
    }

    /// The change is stored: apply `clear` to the flow context, mark the flow `success` and send
    /// the browser where Kratos does, the flow's `return_to` or else the flow itself. A
    /// concurrent save of the flow is reloaded and `clear` applied again.
    async fn saved(
        mut self,
        clear: fn(&mut Context),
        audit: AuditEvent,
        set_cookies: Vec<String>,
        after: Option<AfterEffect>,
    ) -> Result<Submitted> {
        let db = &self.backend.db;
        let mut landed = false;
        for _ in 0..SAVE_ATTEMPTS {
            clear(&mut self.flow.ctx);
            self.flow.set_state("success");
            if self.flow.save(db).await? == Saved::Done {
                landed = true;
                break;
            }
            let Some(mut current) = self.backend.load_flow(&self.flow.row.id).await? else {
                break;
            };
            current.clear_messages();
            self.flow = current;
        }
        if !landed {
            // The change itself is stored, so the browser and the audit row still get it.
            tracing::warn!(flow_id = %self.flow.row.id, "settings flow kept changing; success not recorded on it");
        }
        let location = self
            .flow
            .row
            .return_to
            .clone()
            .unwrap_or_else(|| self.flow_page());
        Ok(Submitted {
            outcome: SubmitOutcome::Redirect {
                location,
                set_cookies,
            },
            audit: vec![audit],
            after,
        })
    }

    /// An audit row in the shape the Kratos webhook writes, with the address it holds now.
    fn event(&self, action: &'static str, email: &str) -> AuditEvent {
        AuditEvent::new(action)
            .actor_user(&self.row.id, email)
            .target(target_kind::IDENTITY, &self.row.id)
            .metadata(crate::audit_metadata!(
                "source" => "native",
                "flow_id" => self.flow.row.id,
                "kratos_session_id" => self.session.id,
            ))
    }

    fn flag(&self, name: &str) -> bool {
        self.form.get(name).is_some_and(|v| !v.is_empty())
    }
}

/// Names, and the address when it changed. A new address needs the privileged window and mail
/// quota for it, loses its verified mark and is stored together with its verification code and
/// mail; the old one stops signing in at once.
async fn profile(mut c: Change<'_>) -> Result<Submitted> {
    let traits = traits_of(c.form);
    if !check_traits(&mut c.flow, &traits) {
        return c.page().await;
    }
    let first = Some(traits.first.as_str()).filter(|f| !f.is_empty());
    let last = Some(traits.last.as_str()).filter(|l| !l.is_empty());
    let backend = c.backend;
    let mut change = None;
    if store::email_norm(&traits.email) != c.row.email_norm {
        if !c.privileged() {
            return Ok(c.refresh_required());
        }
        if !c.admit_change()
            || !backend
                .limiters
                .recipient
                .admit(&store::address_key(&traits.email))
        {
            return c.reject(BUSY).await;
        }
        let verification = backend.verification_flow(&traits.email, None, None);
        let code = backend.mailed_code(
            &verification.row.id,
            Purpose::Verification,
            &c.row.id,
            &traits.email,
        );
        change = Some(store::AddressChange {
            email: traits.email.clone(),
            verification: verification.row,
            code,
        });
    }
    let new_address = change.is_some();
    match store::update_profile(&backend.db, &c.row.id, first, last, change).await? {
        ProfileSaved::Saved => {}
        ProfileSaved::Taken => return c.reject(ACCOUNT_EXISTS).await,
        ProfileSaved::Gone => return Ok(expired()),
    }
    let email = if new_address {
        backend.wake_mail();
        traits.email.clone()
    } else {
        c.row.email.clone()
    };
    let event = c.event(action::PROFILE_UPDATED, &email);
    c.saved(|_| {}, event, Vec::new(), None).await
}

/// A new password: policy, optional breach check, hash, then the credential is replaced. The
/// route ends the OP sessions of every other browser; identity sessions stay.
async fn change_password(mut c: Change<'_>) -> Result<Submitted> {
    if !c.privileged() {
        return Ok(c.refresh_required());
    }
    if !c.admit_change() {
        return c.reject(BUSY).await;
    }
    let password = c.form.get("password").unwrap_or_default().to_string();
    let min = c.backend.settings.password_min_length;
    let mut policy = password::check_policy(&password, &c.row.email, min);
    if policy.is_ok()
        && let Some(check) = &c.backend.breach_check
        && check.is_breached(&password).await
    {
        policy = Err(PolicyError::Breached);
    }
    if let Err(e) = policy {
        let (id, context, text) = e.message();
        c.flow
            .add_node_message("password", Message::error(id, text).with_context(context));
        return c.page().await;
    }
    let phc = match password::hash(&c.backend.hash_permits, password).await {
        Ok(phc) => phc,
        Err(HashError::Busy) => return c.reject(BUSY).await,
        Err(HashError::Failed(e)) => return Err(e),
    };
    let config = serde_json::to_string(&PasswordConfig {
        hashed_password: phc,
    })?;
    store::put_credential(&c.backend.db, &c.row.id, "password", &config).await?;
    let event = c.event(action::PASSWORD_CHANGED, &c.row.email);
    let after = AfterEffect::PasswordChanged {
        identity_id: c.row.id.clone(),
        session_id: c.session.id.clone(),
    };
    c.saved(|_| {}, event, Vec::new(), Some(after)).await
}

/// `totp_unlink` removes TOTP and the lookup codes with it; otherwise `totp_code` confirms the
/// pending secret, which becomes the credential and raises this session to AAL2.
async fn totp_method(mut c: Change<'_>) -> Result<Submitted> {
    if !c.privileged() {
        return Ok(c.refresh_required());
    }
    let backend = c.backend;
    let db = &backend.db;
    let enrolled = store::credential(db, &c.row.id, "totp").await?.is_some();
    if c.flag("totp_unlink") {
        if !enrolled {
            return c.reject(NO_STRATEGY).await;
        }
        store::delete_credentials(db, &c.row.id, &["totp", "lookup_secret"]).await?;
        let event = c.event(action::MFA_TOTP_DISABLED, &c.row.email);
        let clear = |ctx: &mut Context| {
            ctx.lookup_codes = None;
            ctx.pending_totp = None;
        };
        return c.saved(clear, event, Vec::new(), None).await;
    }
    if enrolled {
        return c.reject(NO_STRATEGY).await;
    }
    let secret = c.backend.pending_totp_secret(&mut c.flow).await?;
    let code = c.form.get("totp_code").unwrap_or_default();
    let Some(step) = totp::verify(&secret, code, totp::unix_now()) else {
        c.flow
            .add_node_message("totp_code", Message::error(INVALID_TOTP.0, INVALID_TOTP.1));
        return c.page().await;
    };
    let mut config = TotpConfig::new(&c.backend.keys.seal, &c.row.id, &secret);
    // The enrolment code is spent: login refuses this step and every earlier one.
    config.last_used_step = Some(step);
    let config = serde_json::to_string(&config)?;
    if !store::insert_credential(db, &c.row.id, "totp", &config).await? {
        return c.reject(NO_STRATEGY).await;
    }
    let event = c.event(action::MFA_TOTP_ENROLLED, &c.row.email);
    let set_cookies = match session::step_up(db, &c.session, "totp", Aal::Aal2).await? {
        StepUp::Rotated(token) => vec![c.backend.session_set_cookie(&token)],
        // A concurrent step-up already moved this browser to a new token.
        StepUp::Superseded => Vec::new(),
        StepUp::NotLive => {
            return Ok(Submitted {
                audit: vec![event],
                ..expired()
            });
        }
    };
    let clear = |ctx: &mut Context| ctx.pending_totp = None;
    c.saved(clear, event, set_cookies, None).await
}

/// Lookup codes, offered only with TOTP: regenerate shows fresh codes on the flow, confirm stores
/// them in place of any earlier set, disable deletes them.
async fn lookup_method(mut c: Change<'_>) -> Result<Submitted> {
    if !c.privileged() {
        return Ok(c.refresh_required());
    }
    let backend = c.backend;
    let db = &backend.db;
    if store::credential(db, &c.row.id, "totp").await?.is_none() {
        return c.reject(NO_STRATEGY).await;
    }
    if c.flag("lookup_secret_regenerate") {
        let codes = lookup::generate();
        c.backend.hold_generated_codes(&mut c.flow, &codes);
        return c.page().await;
    }
    let clear = |ctx: &mut Context| ctx.lookup_codes = None;
    if c.flag("lookup_secret_confirm") {
        let Some(codes) = c.backend.generated_codes(&c.flow) else {
            return c.reject(NO_STRATEGY).await;
        };
        // The codes leave the flow before they are stored, so one set is stored at most once and
        // a repeated confirm cannot bring back codes already used.
        clear(&mut c.flow.ctx);
        if c.flow.save(db).await? == Saved::Changed {
            return c.reject(NO_STRATEGY).await;
        }
        let config = lookup::config_for(&c.backend.keys.lookup_mac, &c.row.id, &codes);
        let config = serde_json::to_string(&config)?;
        store::put_credential(db, &c.row.id, "lookup_secret", &config).await?;
        let event = c.event(action::MFA_LOOKUP_REGENERATED, &c.row.email);
        return c.saved(clear, event, Vec::new(), None).await;
    }
    if c.flag("lookup_secret_disable") {
        store::delete_credentials(db, &c.row.id, &["lookup_secret"]).await?;
        let event = c.event(action::MFA_LOOKUP_DISABLED, &c.row.email);
        return c.saved(clear, event, Vec::new(), None).await;
    }
    c.reject(NO_STRATEGY).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use diesel::prelude::*;

    use super::super::{Dispatch, InitParams};
    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::{FlowFetch, FlowKind, WhoamiOutcome};
    use crate::db::DbPool;
    use crate::flow_view::Flow;
    use crate::identity_native::test_support::{
        Browser, DEVICE, PASSWORD, audit_lines, identity_with_password, messages,
        plant_lookup_codes, plant_totp, session_cookie, start, submit, totp_code,
    };
    use crate::schema::{identity_codes, identity_sessions};

    const PROFILE: &str = "http://localhost:3000/settings/profile";
    const PASSWORD_PAGE: &str = "http://localhost:3000/settings/password";
    const TWO_FA: &str = "http://localhost:3000/settings/2fa";
    const STRONG: &str = "violet staircase 42";

    async fn setup() -> (DbPool, Arc<NativeBackend>) {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        (db, backend)
    }

    /// A browser with a fresh AAL1 password session for `identity`.
    async fn signed_in(backend: &NativeBackend, identity: &str) -> Browser {
        let issued = backend
            .issue_session(identity, "password", Aal::Aal1, DEVICE)
            .await
            .unwrap();
        Browser {
            csrf: uuid::Uuid::new_v4().to_string(),
            session: Some(issued.token),
        }
    }

    async fn held(backend: &NativeBackend, browser: &Browser) -> SessionRow {
        session::find_live_by_token(&backend.db, browser.session.as_deref().unwrap())
            .await
            .unwrap()
            .expect("the browser's session is live")
    }

    /// Raise the browser's session to AAL2, as a TOTP step-up at login does.
    async fn stepped_up(backend: &NativeBackend, mut browser: Browser) -> Browser {
        let row = held(backend, &browser).await;
        let StepUp::Rotated(token) = session::step_up(&backend.db, &row, "totp", Aal::Aal2)
            .await
            .unwrap()
        else {
            panic!("a live session rotates");
        };
        browser.session = Some(token);
        browser
    }

    async fn open(backend: &NativeBackend, browser: &Browser, return_to: &str) -> String {
        let params = InitParams {
            return_to: Some(return_to),
            ..InitParams::default()
        };
        start(backend, browser, FlowKind::Settings, params).await
    }

    async fn page(backend: &NativeBackend, browser: &Browser, id: &str) -> Flow {
        match backend
            .get_flow(FlowKind::Settings, id, &browser.cookie())
            .await
            .unwrap()
        {
            FlowFetch::Ok(flow) => *flow,
            _ => panic!("settings flow {id} is not readable"),
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
            .submit_flow(
                FlowKind::Settings,
                id,
                &form,
                &browser.cookie(),
                true,
                DEVICE,
            )
            .await
            .unwrap()
    }

    async fn change(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        fields: &[(&str, &str)],
    ) -> Submitted {
        submit(backend, browser, FlowKind::Settings, id, fields).await
    }

    fn location(done: &Submitted) -> &str {
        match &done.outcome {
            SubmitOutcome::Redirect { location, .. } => location,
            SubmitOutcome::Page => panic!("expected a redirect"),
        }
    }

    fn refresh_login(back: &str) -> String {
        format!(
            "/login?refresh=true&return_to={}",
            crate::web::urlencode(back)
        )
    }

    /// Move the browser's sign-in outside the privileged window.
    async fn lapse(backend: &NativeBackend, browser: &Browser) {
        let id = held(backend, browser).await.id;
        let run = async {
            Ok::<usize, anyhow::Error>(crate::db_interact!(backend.db, |c| {
                diesel::update(identity_sessions::table.find(&id))
                    .set(identity_sessions::authenticated_at.eq("2026-01-01T00:00:00.000000+00:00"))
                    .execute(c)
            })?)
        };
        assert_eq!(run.await.unwrap(), 1);
    }

    /// A password sign-in through the login flow: the session cookie it set and the flow messages.
    async fn login(
        backend: &NativeBackend,
        email: &str,
        password: &str,
    ) -> (Option<String>, Vec<u64>) {
        let browser = Browser::new();
        let id = start(backend, &browser, FlowKind::Login, InitParams::default()).await;
        let done = submit(
            backend,
            &browser,
            FlowKind::Login,
            &id,
            &[
                ("method", "password"),
                ("identifier", email),
                ("password", password),
            ],
        )
        .await;
        (session_cookie(&done), messages(backend, &id).await.0)
    }

    async fn whoami(backend: &NativeBackend, browser: &Browser) -> WhoamiOutcome {
        backend.whoami(Some(&browser.cookie())).await.unwrap()
    }

    async fn has(backend: &NativeBackend, identity: &str, kind: &str) -> bool {
        store::credential(&backend.db, identity, kind)
            .await
            .unwrap()
            .is_some()
    }

    fn secret_of(flow: &Flow) -> Vec<u8> {
        let b32 = flow.totp_secret.as_deref().expect("a pending TOTP secret");
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, b32).unwrap()
    }

    #[tokio::test]
    async fn a_name_change_saves_without_a_recent_sign_in() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "ann@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        lapse(&backend, &browser).await;
        let id = open(&backend, &browser, PROFILE).await;
        let done = change(
            &backend,
            &browser,
            &id,
            &[
                ("method", "profile"),
                ("traits.email", "ann@x.test"),
                ("traits.name.first", " Ada "),
                ("traits.name.last", "Byron"),
            ],
        )
        .await;
        assert_eq!(location(&done), PROFILE);
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(
            (row.first_name.as_deref(), row.last_name.as_deref()),
            (Some("Ada"), Some("Byron"))
        );
        assert!(row.email_verified_at.is_some(), "the address is untouched");
        let flow = page(&backend, &browser, &id).await;
        assert_eq!(flow.state, "success");
        assert_eq!(flow.id, id, "the same flow, still submittable");
        assert!(flow.messages.iter().any(|m| m.id == 1_050_001));

        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("profile.updated"), "{}", audit[0]);
        assert!(audit[0].contains(&held(&backend, &browser).await.id));
        assert!(!audit[0].contains(browser.session.as_deref().unwrap()));

        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "profile"), ("traits.email", "")],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(
            messages(&backend, &id).await.1,
            [("traits.email".to_string(), 4_000_002)]
        );
        assert_eq!(page(&backend, &browser, &id).await.state, "show_form");
    }

    #[tokio::test]
    async fn an_email_change_needs_a_recent_sign_in_and_restarts_verification() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "old@x.test", true).await;
        identity_with_password(&db, "taken@x.test", true).await;
        let elsewhere = signed_in(&backend, &identity).await;
        let stale = signed_in(&backend, &identity).await;
        lapse(&backend, &stale).await;
        let fields = |email: &'static str| {
            [
                ("method", "profile"),
                ("traits.email", email),
                ("traits.name.first", "Ann"),
                ("traits.name.last", "Lee"),
            ]
        };

        let id = open(&backend, &stale, PROFILE).await;
        let done = change(&backend, &stale, &id, &fields("new@x.test")).await;
        assert_eq!(location(&done), refresh_login(PROFILE));
        assert!(done.audit.is_empty());
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(row.email, "old@x.test", "nothing applied");

        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PROFILE).await;
        let done = change(&backend, &browser, &id, &fields("TAKEN@x.test")).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [4_000_007]);
        assert!(done.audit.is_empty());
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(row.email, "old@x.test");

        // An outstanding code for the old address does not survive the change.
        let earlier = backend
            .create_verification_flow("old@x.test", None, None)
            .await
            .unwrap();
        backend
            .send_code(
                &earlier.row.id,
                Purpose::Verification,
                &identity,
                "old@x.test",
            )
            .await
            .unwrap();

        let done = change(&backend, &browser, &id, &fields("New@x.test")).await;
        assert_eq!(location(&done), PROFILE);
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(
            (row.email.as_str(), row.email_norm.as_str()),
            ("New@x.test", "new@x.test")
        );
        assert!(row.email_verified_at.is_none());
        let addresses: Vec<String> = {
            let identity = identity.clone();
            let run = async {
                Ok::<Vec<String>, anyhow::Error>(crate::db_interact!(db, |c| {
                    identity_codes::table
                        .filter(identity_codes::identity_id.eq(&identity))
                        .select(identity_codes::address)
                        .load(c)
                })?)
            };
            run.await.unwrap()
        };
        assert_eq!(addresses, ["new@x.test"], "only the new address has a code");
        let mail = backend.mailed("New@x.test").await;
        assert_eq!(mail.len(), 1);
        assert!(mail[0].subject.contains("verify"));

        assert_eq!(login(&backend, "old@x.test", PASSWORD).await.1, [4_000_006]);
        assert_eq!(
            login(&backend, "new@x.test", PASSWORD).await.1,
            [4_000_010],
            "the new address signs in once verified"
        );
        assert!(matches!(
            whoami(&backend, &elsewhere).await,
            WhoamiOutcome::Ok(_)
        ));

        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("profile.updated"));
        assert!(audit[0].contains("New@x.test"));
        assert!(!audit[0].contains(&mail[0].code));
    }

    #[tokio::test]
    async fn a_password_change_replaces_the_credential_and_leaves_other_sessions() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "pw@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let elsewhere = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PASSWORD_PAGE).await;
        let before = store::credential(&db, &identity, "password")
            .await
            .unwrap()
            .unwrap();

        for (password, message) in [("short", 4_000_032), ("pw@x.test1", 4_000_005)] {
            let done = change(
                &backend,
                &browser,
                &id,
                &[("method", "password"), ("password", password)],
            )
            .await;
            assert_eq!(done.outcome, SubmitOutcome::Page, "{password}");
            assert!(done.after.is_none() && done.audit.is_empty());
            assert_eq!(
                messages(&backend, &id).await.1,
                [("password".to_string(), message)],
                "{password}"
            );
        }
        let unchanged = store::credential(&db, &identity, "password")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.version, before.version);

        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "password"), ("password", STRONG)],
        )
        .await;
        assert_eq!(location(&done), PASSWORD_PAGE);
        assert_eq!(
            done.after,
            Some(AfterEffect::PasswordChanged {
                identity_id: identity.clone(),
                session_id: held(&backend, &browser).await.id,
            })
        );
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("password.changed"), "{}", audit[0]);
        assert!(audit[0].contains(&held(&backend, &browser).await.id));
        assert!(!audit[0].contains(STRONG) && !audit[0].contains(PASSWORD));

        assert_eq!(login(&backend, "pw@x.test", PASSWORD).await.1, [4_000_006]);
        assert!(login(&backend, "pw@x.test", STRONG).await.0.is_some());
        assert!(matches!(
            whoami(&backend, &elsewhere).await,
            WhoamiOutcome::Ok(_)
        ));
        assert!(matches!(
            whoami(&backend, &browser).await,
            WhoamiOutcome::Ok(_)
        ));
    }

    #[tokio::test]
    async fn a_lapsed_privileged_window_redirects_to_a_refresh_login_and_applies_nothing() {
        let (db, backend) = setup().await;
        let plain = identity_with_password(&db, "plain@x.test", true).await;
        let browser = signed_in(&backend, &plain).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let secret = secret_of(&page(&backend, &browser, &id).await);
        lapse(&backend, &browser).await;
        let code = totp_code(&secret, totp::unix_now());
        for fields in [
            vec![("method", "password"), ("password", STRONG)],
            vec![("method", "totp"), ("totp_code", code.as_str())],
        ] {
            let done = change(&backend, &browser, &id, &fields).await;
            assert_eq!(location(&done), refresh_login(TWO_FA));
            assert!(done.audit.is_empty() && done.after.is_none());
        }
        assert!(!has(&backend, &plain, "totp").await);
        assert_eq!(
            login(&backend, "plain@x.test", PASSWORD).await.1,
            Vec::<u64>::new()
        );

        let enrolled = identity_with_password(&db, "two@x.test", true).await;
        plant_totp(&backend, &enrolled).await;
        plant_lookup_codes(&backend, &enrolled).await;
        let browser = stepped_up(&backend, signed_in(&backend, &enrolled).await).await;
        let id = open(&backend, &browser, TWO_FA).await;
        lapse(&backend, &browser).await;
        for fields in [
            [("method", "totp"), ("totp_unlink", "true")],
            [
                ("method", "lookup_secret"),
                ("lookup_secret_regenerate", "true"),
            ],
            [
                ("method", "lookup_secret"),
                ("lookup_secret_disable", "true"),
            ],
        ] {
            let done = change(&backend, &browser, &id, &fields).await;
            assert_eq!(location(&done), refresh_login(TWO_FA));
        }
        assert!(has(&backend, &enrolled, "totp").await);
        assert!(has(&backend, &enrolled, "lookup_secret").await);
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert!(rec.ctx.lookup_codes.is_none());
    }

    #[tokio::test]
    async fn an_aal1_session_of_a_totp_identity_is_sent_to_step_up_and_changes_nothing() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "aal@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PASSWORD_PAGE).await;
        plant_totp(&backend, &identity).await;
        let before = store::credential(&db, &identity, "password")
            .await
            .unwrap()
            .unwrap();
        let got = send(
            &backend,
            &browser,
            &id,
            &[("method", "password"), ("password", STRONG)],
        )
        .await;
        let Dispatch::SignIn(to) = got else {
            panic!("not sent to step up: {got:?}");
        };
        assert_eq!(to, crate::auth::aal2_step_up_url("/settings"));
        let after = store::credential(&db, &identity, "password")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.version, before.version);
        assert!(matches!(
            backend
                .get_flow(FlowKind::Settings, &id, &browser.cookie())
                .await
                .unwrap(),
            FlowFetch::PrivilegedRequired(_)
        ));
    }

    #[tokio::test]
    async fn totp_enrolment_raises_the_session_and_spends_its_code() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "t@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let session_id = held(&backend, &browser).await.id;
        let id = open(&backend, &browser, TWO_FA).await;
        let shown = page(&backend, &browser, &id).await;
        let secret = secret_of(&shown);
        assert!(!shown.has_node("lookup_secret", "lookup_secret_regenerate"));

        let now = totp::unix_now();
        let valid: Vec<String> = [now - totp::STEP_SECS, now, now + totp::STEP_SECS]
            .iter()
            .map(|t| totp_code(&secret, *t))
            .collect();
        let wrong = (0..4)
            .map(|n| format!("{n:06}"))
            .find(|c| !valid.contains(c))
            .unwrap();
        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_code", &wrong)],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(
            messages(&backend, &id).await.1,
            [("totp_code".to_string(), 4_000_008)]
        );
        let again = page(&backend, &browser, &id).await;
        assert_eq!(
            again.totp_secret, shown.totp_secret,
            "the same secret to retry"
        );
        assert_eq!(again.totp_qr, shown.totp_qr);
        assert!(!has(&backend, &identity, "totp").await);

        let code = totp_code(&secret, now);
        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        assert_eq!(location(&done), TWO_FA);
        let token = session_cookie(&done).expect("the session moves to a new token");
        assert!(matches!(
            whoami(&backend, &browser).await,
            WhoamiOutcome::None
        ));
        let mut raised = browser.clone();
        raised.session = Some(token);
        let WhoamiOutcome::Ok(session) = whoami(&backend, &raised).await else {
            panic!("the new token is live");
        };
        assert_eq!(session.id, session_id);
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal2));
        assert!(has(&backend, &identity, "totp").await);
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("mfa.totp.enrolled"));
        let b32 = shown.totp_secret.unwrap();
        assert!(!audit[0].contains(&b32) && !audit[0].contains(&code));
        let stored = store::credential(&db, &identity, "totp")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.config.contains(&b32), "the stored secret is sealed");

        let enrolled = page(&backend, &raised, &id).await;
        assert!(enrolled.has_node("totp", "totp_unlink"));
        assert!(enrolled.totp_qr.is_none());
        assert!(enrolled.has_node("lookup_secret", "lookup_secret_regenerate"));

        // The enrolment code cannot step up a new sign-in.
        let (aal1, _) = login(&backend, "t@x.test", PASSWORD).await;
        let other = Browser {
            csrf: uuid::Uuid::new_v4().to_string(),
            session: aal1,
        };
        let step = start(
            &backend,
            &other,
            FlowKind::Login,
            InitParams {
                aal2: true,
                ..InitParams::default()
            },
        )
        .await;
        let done = submit(
            &backend,
            &other,
            FlowKind::Login,
            &step,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(
            messages(&backend, &step).await.1,
            [("totp_code".to_string(), 4_000_008)]
        );
    }

    #[tokio::test]
    async fn unlinking_totp_removes_the_lookup_codes_too() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "u@x.test", true).await;
        let old = plant_totp(&backend, &identity).await;
        plant_lookup_codes(&backend, &identity).await;
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let shown = page(&backend, &browser, &id).await;
        assert!(shown.has_node("lookup_secret", "lookup_secret_regenerate"));
        assert!(shown.has_node("lookup_secret", "lookup_secret_disable"));
        assert!(!shown.has_node("lookup_secret", "lookup_secret_reveal"));

        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_unlink", "true")],
        )
        .await;
        assert_eq!(location(&done), TWO_FA);
        assert!(session_cookie(&done).is_none());
        assert!(!has(&backend, &identity, "totp").await);
        assert!(!has(&backend, &identity, "lookup_secret").await);
        assert!(audit_lines(&done)[0].contains("mfa.totp.disabled"));
        assert_eq!(
            held(&backend, &browser).await.aal,
            "aal2",
            "the session keeps its AAL"
        );

        let after = page(&backend, &browser, &id).await;
        assert!(after.totp_qr.is_some());
        assert_ne!(secret_of(&after), old, "a fresh secret to enrol");
        assert!(!after.has_node("lookup_secret", "lookup_secret_regenerate"));
    }

    #[tokio::test]
    async fn lookup_codes_are_generated_confirmed_used_and_disabled() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "l@x.test", true).await;
        plant_totp(&backend, &identity).await;
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let regenerate = [
            ("method", "lookup_secret"),
            ("lookup_secret_regenerate", "true"),
        ];
        let confirm = [
            ("method", "lookup_secret"),
            ("lookup_secret_confirm", "true"),
        ];

        let done = change(&backend, &browser, &id, &confirm).await;
        assert_eq!(
            done.outcome,
            SubmitOutcome::Page,
            "nothing generated to confirm"
        );
        assert_eq!(messages(&backend, &id).await.0, [4_000_001]);

        let done = change(&backend, &browser, &id, &regenerate).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        assert!(
            !has(&backend, &identity, "lookup_secret").await,
            "nothing stored yet"
        );
        let shown = page(&backend, &browser, &id).await;
        assert_eq!(
            shown.lookup_codes.len(),
            crate::identity_native::lookup::COUNT
        );
        assert!(shown.has_node("lookup_secret", "lookup_secret_confirm"));
        let codes = shown.lookup_codes.clone();
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert!(!rec.row.context.contains(&codes[0]), "the codes are sealed");

        let done = change(&backend, &browser, &id, &confirm).await;
        assert_eq!(location(&done), TWO_FA);
        assert!(has(&backend, &identity, "lookup_secret").await);
        let audit = audit_lines(&done);
        assert!(audit[0].contains("mfa.lookup.regenerated"));
        assert!(codes.iter().all(|c| !audit[0].contains(c.as_str())));
        let confirmed = page(&backend, &browser, &id).await;
        assert!(confirmed.lookup_codes.is_empty(), "shown once");
        assert!(confirmed.has_node("lookup_secret", "lookup_secret_disable"));

        let (aal1, _) = login(&backend, "l@x.test", PASSWORD).await;
        let other = Browser {
            csrf: uuid::Uuid::new_v4().to_string(),
            session: aal1,
        };
        let step = start(
            &backend,
            &other,
            FlowKind::Login,
            InitParams {
                aal2: true,
                ..InitParams::default()
            },
        )
        .await;
        let done = submit(
            &backend,
            &other,
            FlowKind::Login,
            &step,
            &[("method", "lookup_secret"), ("lookup_secret", &codes[3])],
        )
        .await;
        assert!(
            session_cookie(&done).is_some(),
            "a confirmed code steps up a sign-in"
        );

        let done = change(
            &backend,
            &browser,
            &id,
            &[
                ("method", "lookup_secret"),
                ("lookup_secret_disable", "true"),
            ],
        )
        .await;
        assert_eq!(location(&done), TWO_FA);
        assert!(!has(&backend, &identity, "lookup_secret").await);
        assert!(has(&backend, &identity, "totp").await);
        assert!(audit_lines(&done)[0].contains("mfa.lookup.disabled"));
    }

    #[tokio::test]
    async fn lookup_actions_are_refused_without_totp() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "n@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, TWO_FA).await;
        for action in [
            "lookup_secret_regenerate",
            "lookup_secret_confirm",
            "lookup_secret_disable",
            "lookup_secret_reveal",
        ] {
            let done = change(
                &backend,
                &browser,
                &id,
                &[("method", "lookup_secret"), (action, "true")],
            )
            .await;
            assert_eq!(done.outcome, SubmitOutcome::Page, "{action}");
            assert_eq!(messages(&backend, &id).await.0, [4_000_001], "{action}");
        }
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert!(rec.ctx.lookup_codes.is_none());
        assert!(!has(&backend, &identity, "lookup_secret").await);
        assert!(
            !page(&backend, &browser, &id)
                .await
                .has_node("lookup_secret", "lookup_secret_regenerate")
        );
    }

    #[tokio::test]
    async fn email_and_password_changes_share_a_per_identity_cap() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "cap@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PASSWORD_PAGE).await;
        for _ in 0..crate::identity_native::SETTINGS_CHANGES - 1 {
            let done = change(
                &backend,
                &browser,
                &id,
                &[("method", "password"), ("password", "short")],
            )
            .await;
            assert_eq!(done.outcome, SubmitOutcome::Page);
            assert_eq!(
                messages(&backend, &id).await.1,
                [("password".to_string(), 4_000_032)]
            );
        }
        let profile = [
            ("method", "profile"),
            ("traits.email", "moved@x.test"),
            ("traits.name.first", "Ann"),
            ("traits.name.last", "Lee"),
        ];
        let done = change(&backend, &browser, &id, &profile).await;
        assert_eq!(
            location(&done),
            PASSWORD_PAGE,
            "the tenth change goes through"
        );
        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "password"), ("password", STRONG)],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty() && done.after.is_none());
        assert_eq!(messages(&backend, &id).await.0, [9_000_001]);
        assert_eq!(login(&backend, "moved@x.test", STRONG).await.1, [4_000_006]);

        let other = identity_with_password(&db, "free@x.test", true).await;
        let browser = signed_in(&backend, &other).await;
        let id = open(&backend, &browser, PASSWORD_PAGE).await;
        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "password"), ("password", "short")],
        )
        .await;
        assert_eq!(messages(&backend, &id).await.1[0].1, 4_000_032, "{done:?}");
    }

    #[tokio::test]
    async fn an_address_change_past_the_mail_quota_is_refused_and_nothing_is_saved() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "q@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PROFILE).await;
        let key = store::address_key("new@x.test");
        while backend.limiters.recipient.admit(&key) {}

        let done = change(
            &backend,
            &browser,
            &id,
            &[
                ("method", "profile"),
                ("traits.email", "NEW@x.test"),
                ("traits.name.first", "Changed"),
                ("traits.name.last", "Lee"),
            ],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [9_000_001]);
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(row.email, "q@x.test");
        assert_eq!(row.first_name.as_deref(), Some("Ann"), "names wait too");
        assert!(row.email_verified_at.is_some());
        assert!(backend.outbox_for("NEW@x.test").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_address_change_stores_its_flow_code_and_mail_or_none_of_them() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "tx@x.test", true).await;
        identity_with_password(&db, "held@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PROFILE).await;
        let fields = |email: &'static str| {
            [
                ("method", "profile"),
                ("traits.email", email),
                ("traits.name.first", "Ann"),
                ("traits.name.last", "Lee"),
            ]
        };
        let verification_flows = || async {
            crate::identity_native::test_support::sql(&db, |c| {
                use crate::schema::identity_flows;
                identity_flows::table
                    .filter(identity_flows::kind.eq("verification"))
                    .count()
                    .get_result::<i64>(c)
            })
            .await
        };

        let done = change(&backend, &browser, &id, &fields("held@x.test")).await;
        assert_eq!(messages(&backend, &id).await.0, [4_000_007], "{done:?}");
        assert_eq!(
            verification_flows().await,
            0,
            "rolled back with the address"
        );
        assert!(backend.outbox_for("held@x.test").await.unwrap().is_empty());

        let done = change(&backend, &browser, &id, &fields("fresh@x.test")).await;
        assert_eq!(location(&done), PROFILE);
        assert_eq!(verification_flows().await, 1);
        let mail = backend.mailed("fresh@x.test").await;
        assert_eq!(mail.len(), 1);
        let flow_id = mail[0]
            .body
            .split("flow=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .unwrap()
            .to_string();
        let rec = backend.load_flow(&flow_id).await.unwrap().unwrap();
        assert_eq!(rec.row.state, "sent_email");
        assert_eq!(rec.ctx.email.as_deref(), Some("fresh@x.test"));
        let used = backend
            .use_code(&flow_id, Purpose::Verification, &mail[0].code)
            .await
            .unwrap()
            .expect("the mailed code belongs to the stored flow");
        assert_eq!(used.address, "fresh@x.test");
    }

    /// A submit handed straight to a method, as the dispatcher would after its checks.
    async fn direct<'a>(
        backend: &'a NativeBackend,
        browser: &Browser,
        flow: FlowRecord,
        form: &'a Form,
        identity: &str,
    ) -> Change<'a> {
        Change {
            backend,
            flow,
            form,
            session: held(backend, browser).await,
            row: store::row_by_id(&backend.db, identity)
                .await
                .unwrap()
                .unwrap(),
        }
    }

    fn form(fields: &[(&str, &str)]) -> Form {
        Form(
            fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        )
    }

    #[tokio::test]
    async fn a_totp_credential_stored_for_a_session_revoked_meanwhile_is_audited() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "race@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let secret = secret_of(&page(&backend, &browser, &id).await);
        let flow = backend.load_flow(&id).await.unwrap().unwrap();
        let code = totp_code(&secret, totp::unix_now());
        let fields = form(&[("method", "totp"), ("totp_code", &code)]);
        let c = direct(&backend, &browser, flow, &fields, &identity).await;
        session::revoke(&db, &c.session.id, None).await.unwrap();

        let done = totp_method(c).await.unwrap();
        assert_eq!(location(&done), errors::url(errors::FLOW_EXPIRED));
        assert!(session_cookie(&done).is_none());
        assert!(has(&backend, &identity, "totp").await);
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("mfa.totp.enrolled"), "{}", audit[0]);
    }

    #[tokio::test]
    async fn a_success_save_that_loses_a_race_is_retried() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "retry@x.test", true).await;
        plant_totp(&backend, &identity).await;
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, TWO_FA).await;
        change(
            &backend,
            &browser,
            &id,
            &[
                ("method", "lookup_secret"),
                ("lookup_secret_regenerate", "true"),
            ],
        )
        .await;
        let stale = backend.load_flow(&id).await.unwrap().unwrap();
        assert!(stale.ctx.lookup_codes.is_some());
        let mut other = backend.load_flow(&id).await.unwrap().unwrap();
        other.add_message(Message::error(4_000_001, "from another request"));
        assert_eq!(other.save(&db).await.unwrap(), Saved::Done);

        let fields = form(&[]);
        let c = direct(&backend, &browser, stale, &fields, &identity).await;
        let event = AuditEvent::new(action::MFA_LOOKUP_DISABLED);
        let done = c
            .saved(|ctx| ctx.lookup_codes = None, event, Vec::new(), None)
            .await
            .unwrap();
        assert_eq!(location(&done), TWO_FA);
        let stored = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(stored.row.state, "success");
        assert!(stored.ctx.lookup_codes.is_none(), "the clear landed");
        assert!(stored.ctx.messages.is_empty());
    }

    #[tokio::test]
    async fn confirmed_lookup_codes_cannot_be_confirmed_again() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "once@x.test", true).await;
        plant_totp(&backend, &identity).await;
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let regenerate = [
            ("method", "lookup_secret"),
            ("lookup_secret_regenerate", "true"),
        ];
        let confirm = [
            ("method", "lookup_secret"),
            ("lookup_secret_confirm", "true"),
        ];
        change(&backend, &browser, &id, &regenerate).await;
        let stale = backend.load_flow(&id).await.unwrap().unwrap();

        let done = change(&backend, &browser, &id, &confirm).await;
        assert_eq!(location(&done), TWO_FA);
        let stored = store::credential(&db, &identity, "lookup_secret")
            .await
            .unwrap()
            .unwrap();

        let done = change(&backend, &browser, &id, &confirm).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [4_000_001]);

        let fields = form(&confirm);
        let c = direct(&backend, &browser, stale, &fields, &identity).await;
        let done = lookup_method(c).await.unwrap();
        assert_eq!(done.outcome, SubmitOutcome::Page, "a stale copy is refused");
        assert!(done.audit.is_empty());
        let after = store::credential(&db, &identity, "lookup_secret")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.version, stored.version, "the stored set is untouched");
    }

    #[tokio::test]
    async fn a_settings_flow_of_another_session_or_identity_is_refused() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "own@x.test", true).await;
        let other = identity_with_password(&db, "else@x.test", true).await;
        let owner = signed_in(&backend, &identity).await;
        let id = open(&backend, &owner, PASSWORD_PAGE).await;
        let fields = [("method", "password"), ("password", STRONG)];
        for browser in [
            signed_in(&backend, &identity).await,
            signed_in(&backend, &other).await,
        ] {
            let got = send(&backend, &browser, &id, &fields).await;
            assert!(matches!(got, Dispatch::Forged), "{got:?}");
        }
        let got = send(&backend, &Browser::new(), &id, &fields).await;
        assert!(matches!(got, Dispatch::SignIn(_)), "{got:?}");
        assert_eq!(
            login(&backend, "own@x.test", PASSWORD).await.1,
            Vec::<u64>::new()
        );
    }
}
