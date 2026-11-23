//! Settings submits: profile, password, TOTP enrolment and unlink, lookup codes, passkeys and
//! security keys. Every method but a profile save that keeps the address needs a sign-in within
//! the privileged window; the dispatcher has already checked the session and its AAL.

use anyhow::{Result, anyhow};

use super::login::NOT_VERIFIED;
use super::registration::{check_traits, traits_of};
use super::upstream::LAST_METHOD;
use super::verification::too_long;
use super::{
    AfterEffect, Context, FlowRecord, Form, SAVE_ATTEMPTS, Saved, Submission, SubmitOutcome,
    Submitted,
};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::Aal;
use crate::identity_native::codes::Purpose;
use crate::identity_native::password::{self, HashError, PasswordConfig, PolicyError};
use crate::identity_native::session::{self, SessionRow, StepUp};
use crate::identity_native::store::keys::{self, Key, KeyAdded, KeyKind, KeyRemoved, NewKey};
use crate::identity_native::store::{
    self, IdentityRow, NAME_MAX_CHARS, ProfileSaved, Refused, Writer,
};
use crate::identity_native::totp::{self, TotpConfig};
use crate::identity_native::ui::Message;
use crate::identity_native::webauthn::{self, PASSKEY_NAME, Slot};
use crate::identity_native::{NativeBackend, errors, lookup};

const ACCOUNT_EXISTS: (u64, &str) = (
    4_000_007,
    "An account with the same identifier (email, phone, username, ...) exists already.",
);
const INVALID_TOTP: (u64, &str) = (
    4_000_008,
    "The provided authentication code is invalid, please try again.",
);
pub(super) const NO_STRATEGY: (u64, &str) = (
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
        "webauthn" | "passkey" => keys_method(change).await,
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

/// The session ended between the flow check and the write; nothing was written.
pub(super) fn signed_out() -> Submitted {
    SubmitOutcome::Redirect {
        location: super::settings_sign_in(),
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

/// Whether `session` signed in within the privileged window.
pub(super) fn privileged(backend: &NativeBackend, session: &SessionRow) -> bool {
    chrono::DateTime::parse_from_rfc3339(&session.authenticated_at).is_ok_and(|at| {
        chrono::Utc::now() - at.with_timezone(&chrono::Utc) <= backend.settings.privileged_window()
    })
}

/// Send the browser to a re-authentication that comes back to the settings flow's page; nothing
/// is applied or saved.
pub(super) fn refresh_required(flow: &FlowRecord) -> Submitted {
    let back = flow
        .row
        .return_to
        .clone()
        .unwrap_or_else(|| flow_page(flow));
    SubmitOutcome::Redirect {
        location: format!(
            "/login?refresh=true&return_to={}",
            crate::web::urlencode(&back)
        ),
        set_cookies: Vec::new(),
    }
    .into()
}

fn flow_page(flow: &FlowRecord) -> String {
    format!("/settings?flow={}", crate::web::urlencode(&flow.row.id))
}

/// A settings change is stored: apply `clear` to the flow context, mark the flow `success` and
/// send the browser where Kratos does, the flow's `return_to` or else the flow itself. A
/// concurrent save of the flow is reloaded and `clear` applied again.
pub(super) async fn saved(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    clear: fn(&mut Context),
    audit: AuditEvent,
    set_cookies: Vec<String>,
    after: Option<AfterEffect>,
) -> Result<Submitted> {
    let db = &backend.db;
    let mut landed = false;
    for _ in 0..SAVE_ATTEMPTS {
        clear(&mut flow.ctx);
        flow.set_state("success");
        if flow.save(db).await? == Saved::Done {
            landed = true;
            break;
        }
        let Some(mut current) = backend.load_flow(&flow.row.id).await? else {
            break;
        };
        current.clear_messages();
        flow = current;
    }
    if !landed {
        // The change itself is stored, so the browser and the audit row still get it.
        tracing::warn!(flow_id = %flow.row.id, "settings flow kept changing; success not recorded on it");
    }
    let location = flow
        .row
        .return_to
        .clone()
        .unwrap_or_else(|| flow_page(&flow));
    Ok(Submitted {
        outcome: SubmitOutcome::Redirect {
            location,
            set_cookies,
        },
        audit: vec![audit],
        after,
    })
}

impl Change<'_> {
    fn privileged(&self) -> bool {
        privileged(self.backend, &self.session)
    }

    fn refresh_required(&self) -> Submitted {
        refresh_required(&self.flow)
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

    /// Count an email, password or key change against the identity's quota.
    fn admit_change(&self) -> bool {
        self.backend.limiters.settings_changes.admit(&self.row.id)
    }

    async fn saved(
        self,
        clear: fn(&mut Context),
        audit: AuditEvent,
        set_cookies: Vec<String>,
        after: Option<AfterEffect>,
    ) -> Result<Submitted> {
        saved(self.backend, self.flow, clear, audit, set_cookies, after).await
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

    /// [`Self::event`] with the key's kind.
    fn key_event(&self, action: &'static str, kind: KeyKind) -> AuditEvent {
        self.event(action, &self.row.email)
            .metadata(crate::audit_metadata!(
                "source" => "native",
                "flow_id" => self.flow.row.id,
                "kratos_session_id" => self.session.id,
                "kind" => kind.as_str(),
            ))
    }

    fn flag(&self, name: &str) -> bool {
        self.form.get(name).is_some_and(|v| !v.is_empty())
    }

    fn writer(&self, verified_only: bool) -> Writer<'_> {
        Writer {
            identity_id: &self.row.id,
            session_id: &self.session.id,
            verified_only,
        }
    }
}

/// Names, and a request for a new address when it changed. A new address needs the privileged
/// window and mail quota for it; the identity keeps its current address, verified mark and sign-in
/// until the code mailed to the new one is entered from a browser signed in as this identity.
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
        let verification = backend.address_change_flow(&traits.email, &c.row.id);
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
    match store::update_profile(&backend.db, c.writer(false), first, last, change).await? {
        ProfileSaved::Saved => {}
        ProfileSaved::Taken => return c.reject(ACCOUNT_EXISTS).await,
        ProfileSaved::Gone => return Ok(expired()),
        ProfileSaved::SignedOut => return Ok(signed_out()),
    }
    let mut event = c.event(action::PROFILE_UPDATED, &c.row.email);
    if new_address {
        backend.wake_mail();
        event = event.metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => c.flow.row.id,
            "kratos_session_id" => c.session.id,
            "address_change" => "requested",
        ));
    }
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
    let written =
        store::write_credential(&c.backend.db, c.writer(false), "password", &config, true);
    if written.await?.is_err() {
        return Ok(signed_out());
    }
    let event = c.event(action::PASSWORD_CHANGED, &c.row.email);
    let after = AfterEffect::PasswordChanged {
        identity_id: c.row.id.clone(),
        session_id: c.session.id.clone(),
    };
    c.saved(|_| {}, event, Vec::new(), Some(after)).await
}

/// `totp_unlink` removes TOTP, and the lookup codes with it unless a security key remains;
/// otherwise `totp_code` confirms the pending secret, which becomes the credential and raises this
/// session to AAL2.
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
        store::keys::remove_totp(db, &c.row.id).await?;
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
    if c.row.first_verified_at.is_none() {
        return c.reject(NOT_VERIFIED).await;
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
    match store::write_credential(db, c.writer(true), "totp", &config, false).await? {
        Ok(true) => {}
        Ok(false) => return c.reject(NO_STRATEGY).await,
        Err(Refused::NotVerified) => return c.reject(NOT_VERIFIED).await,
        Err(Refused::SignedOut) => return Ok(signed_out()),
    }
    let event = c.event(action::MFA_TOTP_ENROLLED, &c.row.email);
    let set_cookies = match session::step_up(db, &c.session, "totp", None, Aal::Aal2).await? {
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

/// Lookup codes, offered only with TOTP or a security key: regenerate shows fresh codes on the
/// flow, confirm stores them in place of any earlier set, disable deletes them.
async fn lookup_method(mut c: Change<'_>) -> Result<Submitted> {
    if !c.privileged() {
        return Ok(c.refresh_required());
    }
    let backend = c.backend;
    let db = &backend.db;
    if !store::keys::has_second_factor(db, &c.row.id).await? {
        return c.reject(NO_STRATEGY).await;
    }
    let generating = c.flag("lookup_secret_regenerate") || c.flag("lookup_secret_confirm");
    if generating && c.row.first_verified_at.is_none() {
        return c.reject(NOT_VERIFIED).await;
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
        match store::write_credential(db, c.writer(true), "lookup_secret", &config, true).await? {
            Ok(true) => {}
            Ok(false) => return c.reject(NO_STRATEGY).await,
            Err(Refused::NotVerified) => return c.reject(NOT_VERIFIED).await,
            Err(Refused::SignedOut) => return Ok(signed_out()),
        }
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

/// Stored name of a security key added with an empty name field.
const KEY_NAME: &str = "Security key";

/// One WebAuthn settings action and the field value it came with.
enum KeyAction<'f> {
    /// The browser's registration response.
    Add(KeyKind, &'f str),
    /// The key's row id.
    Remove(KeyKind, &'f str),
}

/// The one WebAuthn action field set; `None` when none or more than one is.
fn key_action(form: &Form) -> Option<KeyAction<'_>> {
    let set = |name| form.get(name).filter(|v| !v.is_empty());
    let mut actions = [
        set("webauthn_register").map(|v| KeyAction::Add(KeyKind::Webauthn, v)),
        set("passkey_settings_register").map(|v| KeyAction::Add(KeyKind::Passkey, v)),
        set("webauthn_remove").map(|v| KeyAction::Remove(KeyKind::Webauthn, v)),
        set("passkey_remove").map(|v| KeyAction::Remove(KeyKind::Passkey, v)),
    ]
    .into_iter()
    .flatten();
    let action = actions.next()?;
    actions.next().is_none().then_some(action)
}

/// Passkeys and security keys. The whole WebAuthn section posts `method=webauthn`, so the field
/// set picks the action: add a security key or a passkey, or remove one by row id.
async fn keys_method(c: Change<'_>) -> Result<Submitted> {
    let Some(action) = key_action(c.form) else {
        return c.reject(NO_STRATEGY).await;
    };
    if !c.privileged() {
        return Ok(c.refresh_required());
    }
    if !c.admit_change() {
        return c.reject(BUSY).await;
    }
    match action {
        KeyAction::Add(kind, response) => add_key(c, kind, response).await,
        KeyAction::Remove(kind, row_id) => remove_key(c, kind, row_id).await,
    }
}

/// A new key from the flow's registration ceremony for `kind`. The first security key raises
/// this session to AAL2.
async fn add_key(mut c: Change<'_>, kind: KeyKind, response: &str) -> Result<Submitted> {
    if c.row.first_verified_at.is_none() {
        return c.reject(NOT_VERIFIED).await;
    }
    let display_name = match kind {
        KeyKind::Passkey => PASSKEY_NAME.to_string(),
        KeyKind::Webauthn => {
            let typed = c
                .form
                .get("webauthn_register_displayname")
                .unwrap_or_default()
                .trim();
            let len = typed.chars().count();
            if len > NAME_MAX_CHARS {
                c.flow.add_node_message(
                    "webauthn_register_displayname",
                    too_long(NAME_MAX_CHARS, len),
                );
                return c.page().await;
            }
            if typed.is_empty() { KEY_NAME } else { typed }.to_string()
        }
    };
    let backend = c.backend;
    let Some(rp) = backend.webauthn.as_ref() else {
        return c.reject(NO_STRATEGY).await;
    };
    let slot = match kind {
        KeyKind::Passkey => Slot::Passkey,
        KeyKind::Webauthn => Slot::Key,
    };
    let Some(ceremony) = backend.take(&mut c.flow, slot).await? else {
        return c.reject(NO_STRATEGY).await;
    };
    let key = match kind {
        KeyKind::Passkey => webauthn::register_passkey(rp, ceremony, response)
            .filter(|(user, _)| uuid::Uuid::parse_str(&c.row.id).ok() == Some(*user))
            .map(|(_, passkey)| Key::Passkey(passkey)),
        KeyKind::Webauthn => webauthn::register_key(rp, ceremony, response).map(Key::SecurityKey),
    };
    let Some(key) = key else {
        return c.reject(NO_STRATEGY).await;
    };
    let db = &backend.db;
    match keys::add(db, c.writer(true), NewKey { display_name, key }).await? {
        KeyAdded::Added => {}
        KeyAdded::Taken => return c.reject(ACCOUNT_EXISTS).await,
        KeyAdded::Refused(Refused::NotVerified) => return c.reject(NOT_VERIFIED).await,
        KeyAdded::Refused(Refused::SignedOut) => return Ok(signed_out()),
    }
    let event = c.key_event(action::MFA_WEBAUTHN_ADDED, kind);
    let mut set_cookies = Vec::new();
    // An AAL1 session here means the identity had no second factor before this key.
    if kind == KeyKind::Webauthn && c.session.aal != "aal2" {
        match session::step_up(db, &c.session, "webauthn", None, Aal::Aal2).await? {
            StepUp::Rotated(token) => set_cookies.push(backend.session_set_cookie(&token)),
            StepUp::Superseded => {}
            StepUp::NotLive => {
                return Ok(Submitted {
                    audit: vec![event],
                    ..expired()
                });
            }
        }
    }
    c.saved(clear_ceremonies, event, set_cookies, None).await
}

/// Remove the identity's `kind` key `row_id`; the last way to sign in stays.
async fn remove_key(c: Change<'_>, kind: KeyKind, row_id: &str) -> Result<Submitted> {
    let backend = c.backend;
    let configured: Vec<&str> = backend.upstream.ids().collect();
    let removed = keys::remove(&backend.db, c.writer(false), kind, row_id, &configured).await?;
    match removed {
        KeyRemoved::Removed => {}
        KeyRemoved::NotFound => return c.reject(NO_STRATEGY).await,
        KeyRemoved::LastSignIn => return c.reject(LAST_METHOD).await,
        KeyRemoved::Refused(Refused::NotVerified) => return c.reject(NOT_VERIFIED).await,
        KeyRemoved::Refused(Refused::SignedOut) => return Ok(signed_out()),
    }
    let event = c.key_event(action::MFA_WEBAUTHN_REMOVED, kind);
    let clear: fn(&mut Context) = match kind {
        KeyKind::Passkey => clear_ceremonies,
        // Codes held for confirmation may have just lost the second factor they need.
        KeyKind::Webauthn => |ctx| {
            clear_ceremonies(ctx);
            ctx.lookup_codes = None;
        },
    };
    c.saved(clear, event, Vec::new(), None).await
}

/// The next render mints ceremonies whose exclusion lists match the keys stored now.
fn clear_ceremonies(ctx: &mut Context) {
    ctx.passkey_ceremony = None;
    ctx.key_ceremony = None;
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
            .issue_session(identity, "password", None, Aal::Aal1, DEVICE)
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
        let StepUp::Rotated(token) = session::step_up(&backend.db, &row, "totp", None, Aal::Aal2)
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
    async fn an_email_change_needs_a_recent_sign_in_and_waits_for_its_code() {
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

        // The old address is still the identity's, so its outstanding code stays usable.
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
            ("old@x.test", "old@x.test"),
            "the address waits for its code"
        );
        assert!(row.email_verified_at.is_some());
        let mut addresses: Vec<String> = {
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
        addresses.sort();
        assert_eq!(addresses, ["new@x.test", "old@x.test"]);
        let mail = backend.mailed("New@x.test").await;
        assert_eq!(mail.len(), 1);
        assert!(mail[0].subject.contains("verify"));

        assert!(login(&backend, "old@x.test", PASSWORD).await.0.is_some());
        assert_eq!(login(&backend, "new@x.test", PASSWORD).await.1, [4_000_006]);
        assert!(matches!(
            whoami(&backend, &elsewhere).await,
            WhoamiOutcome::Ok(_)
        ));

        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("profile.updated") && audit[0].contains("requested"));
        assert!(audit[0].contains("old@x.test") && !audit[0].contains("New@x.test"));
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

    /// Every settings write for `session_id`; the refusal each gives, or `None` when it stored.
    async fn try_writes(
        backend: &NativeBackend,
        identity: &str,
        session_id: &str,
    ) -> [Option<Refused>; 5] {
        let db = &backend.db;
        let writer = |verified_only| Writer {
            identity_id: identity,
            session_id,
            verified_only,
        };
        let credential = async |kind, verified_only, replace| {
            store::write_credential(db, writer(verified_only), kind, "{}", replace)
                .await
                .unwrap()
                .err()
        };
        let moved = format!("moved-{identity}@x.test");
        let verification = backend.verification_flow(&moved, None, None);
        let code = backend.mailed_code(
            &verification.row.id,
            Purpose::Verification,
            identity,
            &moved,
        );
        let change = store::AddressChange {
            email: moved,
            verification: verification.row,
            code,
        };
        let profile = match store::update_profile(db, writer(false), None, None, Some(change))
            .await
            .unwrap()
        {
            ProfileSaved::Saved => None,
            ProfileSaved::SignedOut => Some(Refused::SignedOut),
            other => panic!("{other:?}"),
        };
        let link = store::link_for(db, writer(true), "github", identity)
            .await
            .unwrap()
            .err();
        [
            credential("password", false, true).await,
            profile,
            credential("totp", true, false).await,
            credential("lookup_secret", true, true).await,
            link,
        ]
    }

    /// Password config, address, TOTP, lookup codes and links as stored now.
    async fn stored(
        backend: &NativeBackend,
        identity: &str,
    ) -> (String, String, bool, bool, usize) {
        let row = store::row_by_id(&backend.db, identity)
            .await
            .unwrap()
            .unwrap();
        let password = store::credential(&backend.db, identity, "password")
            .await
            .unwrap()
            .map(|c| c.config)
            .unwrap_or_default();
        (
            password,
            row.email,
            has(backend, identity, "totp").await,
            has(backend, identity, "lookup_secret").await,
            store::links_of(&backend.db, identity).await.unwrap().len(),
        )
    }

    #[tokio::test]
    async fn settings_writes_need_a_session_live_at_write_time() {
        let (db, backend) = setup().await;
        let revoked = identity_with_password(&db, "revoked@x.test", true).await;
        let session = held(&backend, &signed_in(&backend, &revoked).await)
            .await
            .id;
        let before = stored(&backend, &revoked).await;
        session::revoke_all(&db, &revoked, None).await.unwrap();
        assert_eq!(
            try_writes(&backend, &revoked, &session).await,
            [const { Some(Refused::SignedOut) }; 5]
        );
        assert_eq!(stored(&backend, &revoked).await, before);

        let expired = identity_with_password(&db, "expired@x.test", true).await;
        let session = held(&backend, &signed_in(&backend, &expired).await)
            .await
            .id;
        let before = stored(&backend, &expired).await;
        let id = session.clone();
        crate::identity_native::test_support::sql(&db, move |c| {
            diesel::update(identity_sessions::table.find(&id))
                .set(identity_sessions::expires_at.eq("2020-01-01T00:00:00.000000+00:00"))
                .execute(c)
        })
        .await;
        assert_eq!(
            try_writes(&backend, &expired, &session).await,
            [const { Some(Refused::SignedOut) }; 5]
        );
        assert_eq!(stored(&backend, &expired).await, before);

        // A recovery reset between the flow check and the write.
        let squatted = identity_with_password(&db, "reset@x.test", false).await;
        let session = held(&backend, &signed_in(&backend, &squatted).await)
            .await
            .id;
        let (_, reset) = store::verify_recovered(&db, &squatted, "reset@x.test")
            .await
            .unwrap()
            .unwrap();
        assert!(reset.is_some());
        let after_reset = stored(&backend, &squatted).await;
        assert_eq!(
            try_writes(&backend, &squatted, &session).await,
            [const { Some(Refused::SignedOut) }; 5]
        );
        assert_eq!(stored(&backend, &squatted).await, after_reset);
        assert!(after_reset.0.is_empty(), "no password");
    }

    #[tokio::test]
    async fn gated_settings_writes_need_a_verified_identity_at_write_time() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "gate@x.test", false).await;
        let session = held(&backend, &signed_in(&backend, &identity).await)
            .await
            .id;
        assert_eq!(
            try_writes(&backend, &identity, &session).await,
            [
                None,
                None,
                Some(Refused::NotVerified),
                Some(Refused::NotVerified),
                Some(Refused::NotVerified),
            ]
        );
        let (_, _, totp, lookup, links) = stored(&backend, &identity).await;
        assert_eq!((totp, lookup, links), (false, false, 0));

        let verified = identity_with_password(&db, "ok@x.test", true).await;
        let session = held(&backend, &signed_in(&backend, &verified).await)
            .await
            .id;
        assert_eq!(
            try_writes(&backend, &verified, &session).await,
            [const { None }; 5]
        );
        let (_, email, totp, lookup, links) = stored(&backend, &verified).await;
        assert_eq!(email, "ok@x.test", "an address change only starts");
        assert_eq!((totp, lookup, links), (true, true, 1));
    }

    #[tokio::test]
    async fn a_password_change_whose_session_ends_during_the_breach_check_stores_nothing() {
        let db = crate::db::test_pool().await;
        let mut built =
            NativeBackend::build(&crate::config::AppConfig::test_fixture(), &db, &[0x42; 32]);
        let identity = identity_with_password(&db, "race@x.test", true).await;
        let (stub_db, stub_identity) = (db.clone(), identity.clone());
        let range = axum::Router::new().route(
            "/range/{prefix}",
            axum::routing::get(move || {
                let (db, identity) = (stub_db.clone(), stub_identity.clone());
                async move {
                    session::revoke_all(&db, &identity, None).await.unwrap();
                    String::new()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, range).await.unwrap() });
        built.breach_check = Some(crate::identity_native::password::BreachCheck::at(format!(
            "http://{addr}"
        )));
        let backend = Arc::new(built);

        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PASSWORD_PAGE).await;
        let before = stored(&backend, &identity).await;
        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "password"), ("password", STRONG)],
        )
        .await;
        assert_eq!(location(&done), super::super::settings_sign_in());
        assert!(done.audit.is_empty() && done.after.is_none());
        assert_eq!(stored(&backend, &identity).await, before);
        assert!(login(&backend, "race@x.test", PASSWORD).await.0.is_some());
        assert!(login(&backend, "race@x.test", STRONG).await.0.is_none());
    }

    /// Ask for `to` on the profile page in `browser`; the change's verification flow and code.
    async fn request_address(
        backend: &NativeBackend,
        browser: &Browser,
        to: &str,
    ) -> (String, String) {
        let id = open(backend, browser, PROFILE).await;
        let done = change(
            backend,
            browser,
            &id,
            &[
                ("method", "profile"),
                ("traits.email", to),
                ("traits.name.first", "Bea"),
                ("traits.name.last", "Cole"),
            ],
        )
        .await;
        assert_eq!(location(&done), PROFILE);
        let mail = backend.mailed(to).await;
        let last = mail.last().expect("a code for the new address");
        let flow = last
            .body
            .split("flow=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .expect("the mail links the flow")
            .to_string();
        (flow, last.code.clone())
    }

    async fn verify(
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
                FlowKind::Verification,
                id,
                &form,
                &browser.cookie(),
                true,
                DEVICE,
            )
            .await
            .unwrap()
    }

    async fn enter_code(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        code: &str,
    ) -> Dispatch {
        verify(backend, browser, id, &[("method", "code"), ("code", code)]).await
    }

    async fn address(backend: &NativeBackend, identity: &str) -> (String, bool) {
        let row = store::row_by_id(&backend.db, identity)
            .await
            .unwrap()
            .unwrap();
        (row.email, row.email_verified_at.is_some())
    }

    fn wrong(code: &str) -> String {
        let n: u32 = code.parse().unwrap();
        format!("{:06}", (n + 1) % 1_000_000)
    }

    #[tokio::test]
    async fn an_address_change_waits_for_the_code_from_a_signed_in_browser() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "old@x.test", true).await;
        let first = store::row_by_id(&db, &identity)
            .await
            .unwrap()
            .unwrap()
            .first_verified_at;
        let browser = signed_in(&backend, &identity).await;
        let (flow, code) = request_address(&backend, &browser, "New@x.test").await;

        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(
            address(&backend, &identity).await,
            ("old@x.test".to_string(), true)
        );
        assert_eq!(row.first_name.as_deref(), Some("Bea"), "names save at once");
        let settings = open(&backend, &browser, PROFILE).await;
        let shown = page(&backend, &browser, &settings).await;
        let email = shown
            .inputs("profile")
            .find(|i| i.name == "traits.email")
            .unwrap();
        assert_eq!(email.value, "old@x.test", "the current address is shown");
        assert!(login(&backend, "old@x.test", PASSWORD).await.0.is_some());
        assert_eq!(login(&backend, "new@x.test", PASSWORD).await.1, [4_000_006]);

        let anonymous = Browser::new();
        let Dispatch::SignIn(to) = enter_code(&backend, &anonymous, &flow, &code).await else {
            panic!("the code needs a signed-in browser");
        };
        assert_eq!(
            to,
            format!(
                "/login?return_to={}",
                crate::web::urlencode(format!("/verification?flow={flow}"))
            )
        );
        let other = identity_with_password(&db, "other@x.test", true).await;
        let stranger = signed_in(&backend, &other).await;
        assert!(matches!(
            enter_code(&backend, &stranger, &flow, &code).await,
            Dispatch::Forged
        ));
        assert_eq!(
            address(&backend, &identity).await,
            ("old@x.test".to_string(), true)
        );

        let Dispatch::Done(done) = enter_code(&backend, &browser, &flow, &code).await else {
            panic!("the signed-in browser applies the change");
        };
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(
            backend.load_flow(&flow).await.unwrap().unwrap().row.state,
            "passed_challenge"
        );
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(
            (row.email.as_str(), row.email_norm.as_str()),
            ("New@x.test", "new@x.test")
        );
        assert!(row.email_verified_at.is_some());
        assert_eq!(row.first_verified_at, first, "the first proof stays");
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("verification.completed") && audit[0].contains("applied"));
        assert!(!audit[0].contains(&code));
        assert_eq!(login(&backend, "old@x.test", PASSWORD).await.1, [4_000_006]);
        assert!(login(&backend, "new@x.test", PASSWORD).await.0.is_some());

        let recovery = Browser::new();
        let rid = start(
            &backend,
            &recovery,
            FlowKind::Recovery,
            InitParams::default(),
        )
        .await;
        submit(
            &backend,
            &recovery,
            FlowKind::Recovery,
            &rid,
            &[("method", "code"), ("email", "old@x.test")],
        )
        .await;
        assert!(
            backend.mailed("old@x.test").await.is_empty(),
            "recovery for the old address finds no account"
        );
    }

    #[tokio::test]
    async fn a_squatter_cannot_move_to_an_address_it_does_not_control() {
        let (db, backend) = setup().await;
        let squatter = identity_with_password(&db, "squatter@x.test", true).await;
        plant_totp(&backend, &squatter).await;
        let browser = stepped_up(&backend, signed_in(&backend, &squatter).await).await;
        let (flow, code) = request_address(&backend, &browser, "victim@x.test").await;

        // The owner of the address follows the mail, signed out or signed in as themselves.
        assert!(matches!(
            enter_code(&backend, &Browser::new(), &flow, &code).await,
            Dispatch::SignIn(_)
        ));
        let bystander = identity_with_password(&db, "bystander@x.test", true).await;
        assert!(matches!(
            enter_code(
                &backend,
                &signed_in(&backend, &bystander).await,
                &flow,
                &code
            )
            .await,
            Dispatch::Forged
        ));
        assert_eq!(
            address(&backend, &squatter).await,
            ("squatter@x.test".to_string(), true)
        );
        assert!(
            store::row_by_email(&db, "victim@x.test")
                .await
                .unwrap()
                .is_none()
        );

        let victim = identity_with_password(&db, "victim@x.test", false).await;
        let recovery = Browser::new();
        let rid = start(
            &backend,
            &recovery,
            FlowKind::Recovery,
            InitParams::default(),
        )
        .await;
        submit(
            &backend,
            &recovery,
            FlowKind::Recovery,
            &rid,
            &[("method", "code"), ("email", "victim@x.test")],
        )
        .await;
        let recovery_mail = backend.mailed("victim@x.test").await;
        assert!(
            recovery_mail.iter().any(|m| m.subject.contains("recover")),
            "the address recovers on its own"
        );

        let Dispatch::Done(_) = enter_code(&backend, &browser, &flow, &code).await else {
            panic!("handled");
        };
        assert_eq!(
            messages(&backend, &flow).await.0,
            [4_000_007],
            "taken at apply time"
        );
        assert_eq!(
            address(&backend, &squatter).await,
            ("squatter@x.test".to_string(), true)
        );
        assert_eq!(
            address(&backend, &victim).await,
            ("victim@x.test".to_string(), false)
        );
    }

    #[tokio::test]
    async fn two_identities_racing_to_one_address_leave_one_moved_and_one_untouched() {
        let (db, backend) = setup().await;
        let a = identity_with_password(&db, "a@x.test", true).await;
        let b = identity_with_password(&db, "b@x.test", true).await;
        let (browser_a, browser_b) = (signed_in(&backend, &a).await, signed_in(&backend, &b).await);
        let (flow_a, code_a) = request_address(&backend, &browser_a, "same@x.test").await;
        let (flow_b, code_b) = request_address(&backend, &browser_b, "same@x.test").await;
        assert!(matches!(
            enter_code(&backend, &browser_a, &flow_a, &code_a).await,
            Dispatch::Done(_)
        ));
        assert!(matches!(
            enter_code(&backend, &browser_b, &flow_b, &code_b).await,
            Dispatch::Done(_)
        ));
        assert_eq!(messages(&backend, &flow_b).await.0, [4_000_007]);
        assert_eq!(
            address(&backend, &a).await,
            ("same@x.test".to_string(), true)
        );
        assert_eq!(address(&backend, &b).await, ("b@x.test".to_string(), true));
    }

    #[tokio::test]
    async fn a_second_change_supersedes_the_first_and_a_resend_goes_to_the_pending_address() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "me@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let (first, first_code) = request_address(&backend, &browser, "one@x.test").await;
        let (second, _) = request_address(&backend, &browser, "two@x.test").await;
        assert!(matches!(
            enter_code(&backend, &browser, &first, &first_code).await,
            Dispatch::Expired
        ));

        let resent = verify(
            &backend,
            &browser,
            &second,
            &[("method", "code"), ("email", "elsewhere@x.test")],
        )
        .await;
        assert!(matches!(resent, Dispatch::Done(_)));
        assert!(backend.mailed("elsewhere@x.test").await.is_empty());
        let mail = backend.mailed("two@x.test").await;
        assert_eq!(mail.len(), 2, "the resend goes to the pending address");
        let (old, new) = (mail[0].code.clone(), mail[1].code.clone());
        if old != new {
            enter_code(&backend, &browser, &second, &old).await;
            assert_eq!(messages(&backend, &second).await.0, [4_070_006]);
        }
        assert!(matches!(
            enter_code(&backend, &browser, &second, &new).await,
            Dispatch::Done(_)
        ));
        assert_eq!(
            address(&backend, &identity).await,
            ("two@x.test".to_string(), true)
        );
    }

    #[tokio::test]
    async fn wrong_codes_run_out_and_change_nothing() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "guess@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let (flow, code) = request_address(&backend, &browser, "target@x.test").await;
        for _ in 0..crate::identity_native::codes::CODE_ATTEMPTS {
            enter_code(&backend, &browser, &flow, &wrong(&code)).await;
        }
        enter_code(&backend, &browser, &flow, &code).await;
        assert_eq!(messages(&backend, &flow).await.0, [4_070_006]);
        assert_eq!(
            address(&backend, &identity).await,
            ("guess@x.test".to_string(), true)
        );
    }

    #[tokio::test]
    async fn a_deactivated_or_deleted_identity_is_not_moved() {
        let (db, backend) = setup().await;
        let off = identity_with_password(&db, "off@x.test", true).await;
        let browser = signed_in(&backend, &off).await;
        let (flow, code) = request_address(&backend, &browser, "off-new@x.test").await;
        store::set_state(&db, &off, crate::backend::identity::IdentityState::Inactive)
            .await
            .unwrap();
        assert!(matches!(
            enter_code(&backend, &browser, &flow, &code).await,
            Dispatch::SignIn(_)
        ));
        assert_eq!(address(&backend, &off).await.0, "off@x.test");

        let gone = identity_with_password(&db, "gone@x.test", true).await;
        let browser = signed_in(&backend, &gone).await;
        let (flow, code) = request_address(&backend, &browser, "gone-new@x.test").await;
        assert!(store::delete(&db, &gone).await.unwrap());
        assert!(matches!(
            enter_code(&backend, &browser, &flow, &code).await,
            Dispatch::Expired | Dispatch::SignIn(_)
        ));
        assert!(
            store::row_by_email(&db, "gone-new@x.test")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_never_verified_identity_cannot_enrol_totp() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "nv@x.test", false).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let secret = secret_of(&page(&backend, &browser, &id).await);
        let code = totp_code(&secret, totp::unix_now());
        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_code", &code)],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty() && session_cookie(&done).is_none());
        assert_eq!(messages(&backend, &id).await.0, [4_000_010]);
        assert!(!has(&backend, &identity, "totp").await);
        assert_eq!(held(&backend, &browser).await.aal, "aal1");
    }

    #[tokio::test]
    async fn a_never_verified_identity_cannot_generate_lookup_codes_but_can_remove_factors() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "nv-lookup@x.test", false).await;
        plant_totp(&backend, &identity).await;
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, TWO_FA).await;

        let done = change(
            &backend,
            &browser,
            &id,
            &[
                ("method", "lookup_secret"),
                ("lookup_secret_regenerate", "true"),
            ],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(messages(&backend, &id).await.0, [4_000_010]);
        assert!(page(&backend, &browser, &id).await.lookup_codes.is_empty());

        let mut rec = backend.load_flow(&id).await.unwrap().unwrap();
        backend.hold_generated_codes(&mut rec, &lookup::generate());
        assert_eq!(rec.save(&db).await.unwrap(), Saved::Done);
        let done = change(
            &backend,
            &browser,
            &id,
            &[
                ("method", "lookup_secret"),
                ("lookup_secret_confirm", "true"),
            ],
        )
        .await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [4_000_010]);
        assert!(!has(&backend, &identity, "lookup_secret").await);

        plant_lookup_codes(&backend, &identity).await;
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
        let done = change(
            &backend,
            &browser,
            &id,
            &[("method", "totp"), ("totp_unlink", "true")],
        )
        .await;
        assert_eq!(location(&done), TWO_FA);
        assert!(!has(&backend, &identity, "totp").await);
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
    async fn a_security_key_sends_an_aal1_session_to_step_up() {
        use crate::identity_native::flows::InitOutcome;
        use crate::identity_native::store::keys::{KeyKind, plant};
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "key@x.test", true).await;
        plant(&db, &identity, KeyKind::Passkey).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, PASSWORD_PAGE).await;

        plant(&db, &identity, KeyKind::Webauthn).await;
        let params = InitParams {
            return_to: Some(TWO_FA),
            ..InitParams::default()
        };
        let init = backend
            .init_flow(FlowKind::Settings, params, &browser.csrf, &browser.cookie())
            .await
            .unwrap();
        assert!(
            matches!(&init, InitOutcome::Redirect(to) if *to == crate::auth::aal2_step_up_url(TWO_FA)),
            "{init:?}"
        );
        assert!(matches!(
            backend
                .get_flow(FlowKind::Settings, &id, &browser.cookie())
                .await
                .unwrap(),
            FlowFetch::PrivilegedRequired(_)
        ));
        let got = send(
            &backend,
            &browser,
            &id,
            &[("method", "password"), ("password", STRONG)],
        )
        .await;
        assert!(
            matches!(&got, Dispatch::SignIn(to) if *to == crate::auth::aal2_step_up_url("/settings")),
            "{got:?}"
        );
    }

    #[tokio::test]
    async fn lookup_codes_are_offered_with_a_security_key_and_no_totp() {
        use crate::identity_native::store::keys::{KeyKind, plant};
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "lk@x.test", true).await;
        plant(&db, &identity, KeyKind::Passkey).await;
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, TWO_FA).await;
        assert!(
            !page(&backend, &browser, &id)
                .await
                .has_node("lookup_secret", "lookup_secret_regenerate"),
            "a passkey is no second factor"
        );

        plant(&db, &identity, KeyKind::Webauthn).await;
        let shown = page(&backend, &browser, &id).await;
        assert!(shown.has_node("lookup_secret", "lookup_secret_regenerate"));
        assert!(shown.totp_qr.is_some(), "TOTP stays on offer");
        let lookup = |action| [("method", "lookup_secret"), (action, "true")];
        change(&backend, &browser, &id, &lookup("lookup_secret_regenerate")).await;
        let codes = page(&backend, &browser, &id).await.lookup_codes;
        let done = change(&backend, &browser, &id, &lookup("lookup_secret_confirm")).await;
        assert_eq!(location(&done), TWO_FA);
        assert!(has(&backend, &identity, "lookup_secret").await);

        let (aal1, _) = login(&backend, "lk@x.test", PASSWORD).await;
        let other = Browser {
            csrf: uuid::Uuid::new_v4().to_string(),
            session: aal1,
        };
        let aal2 = InitParams {
            aal2: true,
            ..InitParams::default()
        };
        let step = start(&backend, &other, FlowKind::Login, aal2).await;
        let flow = match backend
            .get_flow(FlowKind::Login, &step, &other.cookie())
            .await
            .unwrap()
        {
            FlowFetch::Ok(flow) => *flow,
            _ => panic!("second-factor flow is readable"),
        };
        assert!(flow.has_node("lookup_secret", "lookup_secret"));
        assert!(!flow.has_node("totp", "totp_code"));
        let done = submit(
            &backend,
            &other,
            FlowKind::Login,
            &step,
            &[("method", "lookup_secret"), ("lookup_secret", &codes[0])],
        )
        .await;
        assert!(session_cookie(&done).is_some(), "a lookup code steps up");
    }

    #[tokio::test]
    async fn a_passkey_keeps_the_last_link_unlinkable() {
        use crate::config::{AppConfig, OidcProviderConfig, OidcProviderKind};
        use crate::identity_native::store::keys::{KeyKind, plant};
        let db = crate::db::test_pool().await;
        let mut cfg = AppConfig::test_fixture();
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
        let identity = store::create(&db, "link@x.test", None, None, true)
            .await
            .unwrap()
            .expect("address is free")
            .id;
        store::insert_link(&db, &identity, "gh", "1").await.unwrap();
        let sole = async || {
            backend
                .admin_get_identity_full(&identity)
                .await
                .unwrap()
                .sole_sign_in_is_oidc
        };
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, PROFILE).await;
        assert_eq!(sole().await, Some(true));
        assert!(
            !page(&backend, &browser, &id)
                .await
                .has_node("oidc", "unlink")
        );

        plant(&db, &identity, KeyKind::Webauthn).await;
        assert_eq!(sole().await, Some(true), "a security key is no way in");
        plant(&db, &identity, KeyKind::Passkey).await;
        assert_eq!(sole().await, Some(false));
        assert!(
            page(&backend, &browser, &id)
                .await
                .has_node("oidc", "unlink")
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
    async fn a_totp_enrolment_for_a_session_revoked_meanwhile_stores_nothing() {
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
        assert_eq!(location(&done), super::super::settings_sign_in());
        assert!(session_cookie(&done).is_none());
        assert!(!has(&backend, &identity, "totp").await);
        assert!(done.audit.is_empty());
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

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use crate::identity_native::store::keys::{KeyRow, plant};
    use crate::identity_native::test_authenticator::Authenticator;

    const ORIGIN: &str = "http://localhost:3000";
    const RP_ID: &str = "localhost";

    fn node_value(flow: &Flow, name: &str) -> Option<String> {
        flow.inputs
            .iter()
            .find(|(_, i)| i.name == name)
            .map(|(_, i)| i.value.clone())
    }

    /// The registration options the settings page shows for `kind`.
    async fn creation_options(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        kind: KeyKind,
    ) -> serde_json::Value {
        let node = match kind {
            KeyKind::Passkey => "passkey_create_data",
            KeyKind::Webauthn => "webauthn_register_trigger",
        };
        let flow = page(backend, browser, id).await;
        let shown = node_value(&flow, node).unwrap_or_else(|| panic!("{node} shown"));
        serde_json::from_str(&shown).unwrap()
    }

    /// Post `response` as `static/webauthn.js` does: the whole form, the other fields empty.
    async fn add(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        kind: KeyKind,
        response: &serde_json::Value,
        name: &str,
    ) -> Submitted {
        let response = response.to_string();
        let (key, passkey) = match kind {
            KeyKind::Webauthn => (response.as_str(), ""),
            KeyKind::Passkey => ("", response.as_str()),
        };
        change(
            backend,
            browser,
            id,
            &[
                ("method", "webauthn"),
                ("webauthn_register_displayname", name),
                ("webauthn_register", key),
                ("passkey_settings_register", passkey),
            ],
        )
        .await
    }

    /// Register `authenticator` against the page's current options for `kind` and post it.
    async fn enrol(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        kind: KeyKind,
        authenticator: &mut Authenticator,
    ) -> Submitted {
        let options = creation_options(backend, browser, id, kind).await;
        let response = authenticator.register(RP_ID, ORIGIN, &options);
        add(backend, browser, id, kind, &response, "").await
    }

    async fn remove(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        field: &str,
        row: &str,
    ) -> Submitted {
        change(
            backend,
            browser,
            id,
            &[
                ("method", "webauthn"),
                ("webauthn_register_displayname", ""),
                (field, row),
            ],
        )
        .await
    }

    async fn key_rows(backend: &NativeBackend, identity: &str) -> Vec<KeyRow> {
        keys::of_identity(&backend.db, identity).await.unwrap()
    }

    /// The submit was refused with `message`: shown again, nothing audited, no new token.
    async fn refused(backend: &NativeBackend, id: &str, done: &Submitted, message: u64) {
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty() && session_cookie(done).is_none());
        assert_eq!(messages(backend, id).await.0, [message]);
    }

    #[tokio::test]
    async fn a_security_key_and_a_passkey_are_added_from_the_settings_document() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "keys@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let session_id = held(&backend, &browser).await.id;
        let id = open(&backend, &browser, TWO_FA).await;

        let mut token = Authenticator::security_key();
        let options = creation_options(&backend, &browser, &id, KeyKind::Webauthn).await;
        let challenge = options["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let response = token.register(RP_ID, ORIGIN, &options);
        let done = add(
            &backend,
            &browser,
            &id,
            KeyKind::Webauthn,
            &response,
            "  YubiKey 5 ",
        )
        .await;
        assert_eq!(location(&done), TWO_FA);
        let rows = key_rows(&backend, &identity).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].kind.as_str(), rows[0].display_name.as_str()),
            ("webauthn", "YubiKey 5")
        );
        assert_eq!(
            rows[0].credential_id,
            URL_SAFE_NO_PAD.encode(&token.credential_id)
        );
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("mfa.webauthn.added"), "{}", audit[0]);
        assert!(
            audit[0].contains(r#""kind": String("webauthn")"#),
            "{}",
            audit[0]
        );
        let attestation = response["response"]["attestationObject"].as_str().unwrap();
        for material in [rows[0].credential_id.as_str(), &challenge, attestation] {
            assert!(!audit[0].contains(material), "{}", audit[0]);
        }

        // The first second factor raises this session to AAL2 on a new token.
        let token_cookie = session_cookie(&done).expect("the session moves to a new token");
        assert!(matches!(
            whoami(&backend, &browser).await,
            WhoamiOutcome::None
        ));
        let mut raised = browser.clone();
        raised.session = Some(token_cookie);
        let WhoamiOutcome::Ok(session) = whoami(&backend, &raised).await else {
            panic!("the new token is live");
        };
        assert_eq!(session.id, session_id);
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal2));

        let mut phone = Authenticator::passkey();
        let done = enrol(&backend, &raised, &id, KeyKind::Passkey, &mut phone).await;
        assert_eq!(location(&done), TWO_FA);
        assert!(
            session_cookie(&done).is_none(),
            "a passkey is no second factor"
        );
        assert_eq!(
            phone.user_handle.as_deref(),
            Some(&uuid::Uuid::parse_str(&identity).unwrap().as_bytes()[..]),
            "the user handle is the identity id"
        );
        let audit = audit_lines(&done);
        assert!(audit[0].contains("mfa.webauthn.added"), "{}", audit[0]);
        assert!(
            audit[0].contains(r#""kind": String("passkey")"#),
            "{}",
            audit[0]
        );

        let done = enrol(
            &backend,
            &raised,
            &id,
            KeyKind::Webauthn,
            &mut Authenticator::security_key(),
        )
        .await;
        assert_eq!(location(&done), TWO_FA);
        assert!(
            session_cookie(&done).is_none(),
            "an AAL2 session keeps its token"
        );

        let rows = key_rows(&backend, &identity).await;
        let names: Vec<(&str, &str)> = rows
            .iter()
            .map(|r| (r.kind.as_str(), r.display_name.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("webauthn", "YubiKey 5"),
                ("passkey", "Passkey"),
                ("webauthn", "Security key")
            ]
        );
        let shown = page(&backend, &raised, &id).await;
        let removable = |group: &str, field: &str| -> Vec<String> {
            shown
                .inputs(group)
                .filter(|i| i.name == field)
                .map(|i| i.value.clone())
                .collect()
        };
        assert_eq!(
            removable("webauthn", "webauthn_remove"),
            [rows[0].id.clone(), rows[2].id.clone()]
        );
        assert_eq!(removable("passkey", "passkey_remove"), [rows[1].id.clone()]);
        assert!(shown.has_node("lookup_secret", "lookup_secret_regenerate"));
    }

    #[tokio::test]
    async fn registrations_that_do_not_verify_or_are_taken_store_nothing() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "refuse@x.test", true).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let mut token = Authenticator::security_key();

        for (rp_id, origin) in [(RP_ID, "http://localhost:4000"), ("evil.test", ORIGIN)] {
            let options = creation_options(&backend, &browser, &id, KeyKind::Webauthn).await;
            let response = token.register(rp_id, origin, &options);
            let done = add(&backend, &browser, &id, KeyKind::Webauthn, &response, "").await;
            refused(&backend, &id, &done, 4_000_001).await;
            let rec = backend.load_flow(&id).await.unwrap().unwrap();
            assert!(rec.ctx.key_ceremony.is_none(), "the challenge is spent");
        }
        let options = creation_options(&backend, &browser, &id, KeyKind::Passkey).await;
        let response = Authenticator::passkey().register(RP_ID, "https://evil.test", &options);
        let done = add(&backend, &browser, &id, KeyKind::Passkey, &response, "").await;
        refused(&backend, &id, &done, 4_000_001).await;
        assert!(key_rows(&backend, &identity).await.is_empty());

        // A response answers its challenge once, and no later one.
        let options = creation_options(&backend, &browser, &id, KeyKind::Webauthn).await;
        let response = token.register(RP_ID, ORIGIN, &options);
        let done = add(&backend, &browser, &id, KeyKind::Webauthn, &response, "").await;
        assert_eq!(location(&done), TWO_FA);
        let raised = Browser {
            session: session_cookie(&done),
            ..browser.clone()
        };
        let done = add(&backend, &raised, &id, KeyKind::Webauthn, &response, "").await;
        refused(&backend, &id, &done, 4_000_001).await;
        creation_options(&backend, &raised, &id, KeyKind::Webauthn).await;
        let done = add(&backend, &raised, &id, KeyKind::Webauthn, &response, "").await;
        refused(&backend, &id, &done, 4_000_001).await;
        assert_eq!(key_rows(&backend, &identity).await.len(), 1);

        // The same authenticator credential offered to another identity.
        let other = identity_with_password(&db, "other@x.test", true).await;
        let theirs = signed_in(&backend, &other).await;
        let their_flow = open(&backend, &theirs, TWO_FA).await;
        let done = enrol(
            &backend,
            &theirs,
            &their_flow,
            KeyKind::Webauthn,
            &mut token,
        )
        .await;
        refused(&backend, &their_flow, &done, 4_000_007).await;
        assert!(key_rows(&backend, &other).await.is_empty());
        assert_eq!(held(&backend, &theirs).await.aal, "aal1");
        assert_eq!(key_rows(&backend, &identity).await.len(), 1);
    }

    #[tokio::test]
    async fn key_changes_outside_the_privileged_window_redirect_to_a_refresh() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "stale-keys@x.test", true).await;
        let planted = plant(&db, &identity, KeyKind::Passkey).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let options = creation_options(&backend, &browser, &id, KeyKind::Webauthn).await;
        let response = Authenticator::security_key().register(RP_ID, ORIGIN, &options);
        lapse(&backend, &browser).await;

        let done = add(&backend, &browser, &id, KeyKind::Webauthn, &response, "").await;
        assert_eq!(location(&done), refresh_login(TWO_FA));
        assert!(done.audit.is_empty() && session_cookie(&done).is_none());
        let done = remove(&backend, &browser, &id, "passkey_remove", &planted).await;
        assert_eq!(location(&done), refresh_login(TWO_FA));
        assert!(done.audit.is_empty());

        let rows = key_rows(&backend, &identity).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, planted);
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert!(rec.ctx.key_ceremony.is_some(), "the challenge is not spent");
    }

    #[tokio::test]
    async fn a_never_verified_identity_cannot_add_keys_but_can_remove_them() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "nv-keys@x.test", false).await;
        let browser = signed_in(&backend, &identity).await;
        let id = open(&backend, &browser, TWO_FA).await;
        for kind in [KeyKind::Webauthn, KeyKind::Passkey] {
            let done = enrol(
                &backend,
                &browser,
                &id,
                kind,
                &mut Authenticator::security_key(),
            )
            .await;
            refused(&backend, &id, &done, 4_000_010).await;
        }
        assert!(key_rows(&backend, &identity).await.is_empty());
        assert_eq!(held(&backend, &browser).await.aal, "aal1");

        let planted = plant(&db, &identity, KeyKind::Webauthn).await;
        let browser = stepped_up(&backend, browser).await;
        let id = open(&backend, &browser, TWO_FA).await;
        let done = remove(&backend, &browser, &id, "webauthn_remove", &planted).await;
        assert_eq!(location(&done), TWO_FA);
        assert!(key_rows(&backend, &identity).await.is_empty());
    }

    #[tokio::test]
    async fn key_removal_is_guarded_and_scoped_to_the_identity() {
        let (db, backend) = setup().await;
        let identity = store::create(&db, "passkey-only@x.test", None, None, true)
            .await
            .unwrap()
            .expect("address is free")
            .id;
        let passkey = plant(&db, &identity, KeyKind::Passkey).await;
        let key = plant(&db, &identity, KeyKind::Webauthn).await;
        plant_lookup_codes(&backend, &identity).await;
        let other = identity_with_password(&db, "bystander-keys@x.test", true).await;
        let theirs = plant(&db, &other, KeyKind::Webauthn).await;
        let browser = stepped_up(&backend, signed_in(&backend, &identity).await).await;
        let id = open(&backend, &browser, TWO_FA).await;

        let done = remove(&backend, &browser, &id, "passkey_remove", &passkey).await;
        refused(&backend, &id, &done, 4_000_001).await;
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(rec.ctx.messages[0].text, LAST_METHOD.1);

        for (field, row) in [
            ("webauthn_remove", theirs.as_str()),
            ("webauthn_remove", passkey.as_str()),
            ("passkey_remove", key.as_str()),
            ("webauthn_remove", "missing"),
        ] {
            let done = remove(&backend, &browser, &id, field, row).await;
            refused(&backend, &id, &done, 4_000_001).await;
        }
        let done = change(
            &backend,
            &browser,
            &id,
            &[
                ("method", "webauthn"),
                ("webauthn_remove", &key),
                ("passkey_remove", &passkey),
            ],
        )
        .await;
        refused(&backend, &id, &done, 4_000_001).await;
        let done = change(&backend, &browser, &id, &[("method", "webauthn")]).await;
        refused(&backend, &id, &done, 4_000_001).await;
        assert_eq!(key_rows(&backend, &identity).await.len(), 2);
        assert_eq!(key_rows(&backend, &other).await.len(), 1);

        let done = remove(&backend, &browser, &id, "webauthn_remove", &key).await;
        assert_eq!(location(&done), TWO_FA);
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("mfa.webauthn.removed"), "{}", audit[0]);
        assert!(
            audit[0].contains(r#""kind": String("webauthn")"#),
            "{}",
            audit[0]
        );
        assert!(
            !has(&backend, &identity, "lookup_secret").await,
            "the codes go with the last second factor"
        );
        let rows = key_rows(&backend, &identity).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, passkey);

        while backend.limiters.settings_changes.admit(&identity) {}
        let done = remove(&backend, &browser, &id, "passkey_remove", &passkey).await;
        refused(&backend, &id, &done, 9_000_001).await;
    }
}
