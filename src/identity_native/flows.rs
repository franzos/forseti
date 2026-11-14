//! Self-service flows: rows in `identity_flows`, the browser binding, the document each flow
//! shows, init, and the submit dispatcher. Per-kind submit logic lives in the submodules.

use anyhow::{Result, anyhow};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::session::{Device, SessionRow};
use super::ui::{self, Message, NodeMessage};
use super::{NativeBackend, store, totp};
use crate::audit::AuditEvent;
use crate::backend::identity::{FlowInit, FlowKind, Identity, IdentityState, browser_init_url};
use crate::db::DbPool;
use crate::db_interact;
use crate::schema::identity_flows;

mod login;
mod recovery;
mod registration;
mod settings;
mod verification;

/// Seal purposes for secrets kept in a flow's context; each is bound to the flow id.
const SEAL_PENDING_TOTP: &str = "flow-pending-totp";
const SEAL_LOOKUP_CODES: &str = "flow-lookup-codes";
const SEAL_PREFILL_CODE: &str = "flow-prefill-code";

/// Load-change-save rounds before a write that must land on a contended flow gives up.
const SAVE_ATTEMPTS: usize = 3;

/// State of a completed flow; a login, registration or recovery flow in it is spent.
const FINISHED: &str = "passed_challenge";

/// Login and registration flows live 10 minutes, the others 15.
fn lifespan(kind: FlowKind) -> chrono::Duration {
    match kind {
        FlowKind::Login | FlowKind::Registration => chrono::Duration::minutes(10),
        FlowKind::Verification | FlowKind::Recovery | FlowKind::Settings => {
            chrono::Duration::minutes(15)
        }
    }
}

/// The flow kind a `/self-service/<segment>` path names.
pub(super) fn kind_from_segment(segment: &str) -> Option<FlowKind> {
    [
        FlowKind::Login,
        FlowKind::Registration,
        FlowKind::Recovery,
        FlowKind::Verification,
        FlowKind::Settings,
    ]
    .into_iter()
    .find(|k| k.path_segment() == segment)
}

/// Lowercase hex SHA-256 of the browser's CSRF token, the form stored in `identity_flows.binding`.
fn binding_of(csrf_token: &str) -> String {
    hex::encode(Sha256::digest(csrf_token.as_bytes()))
}

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = identity_flows)]
pub(super) struct FlowRow {
    pub(super) id: String,
    pub(super) kind: String,
    pub(super) state: String,
    /// SHA-256 of the CSRF token of the browser that started the flow. NULL on settings flows,
    /// which are bound to `session_id`, and on unbound flows the first browser adopts.
    pub(super) binding: Option<String>,
    pub(super) identity_id: Option<String>,
    pub(super) session_id: Option<String>,
    pub(super) requested_aal: Option<String>,
    pub(super) refresh: i32,
    pub(super) return_to: Option<String>,
    pub(super) request_url: String,
    pub(super) context: String,
    /// Bumped by every [`FlowRecord::save`]; a save only lands on the version it loaded.
    pub(super) version: i32,
    pub(super) issued_at: String,
    pub(super) expires_at: String,
}

/// Registration traits entered on step 1.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct PendingTraits {
    pub(super) email: String,
    #[serde(default)]
    pub(super) first: String,
    #[serde(default)]
    pub(super) last: String,
}

/// `identity_flows.context`: what a flow carries between requests.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct Context {
    /// Flow-level messages from the last submit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) messages: Vec<Message>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) node_messages: Vec<NodeMessage>,
    /// Login identifier echoed after a failed attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) identifier: Option<String>,
    /// Registration traits, echoed on step 1 and carried through step 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) traits: Option<PendingTraits>,
    /// Registration is on step 2, choosing a password.
    #[serde(default)]
    pub(super) credential_step: bool,
    /// Address a verification or recovery code went to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) email: Option<String>,
    /// Settings flow handed over by a completed recovery.
    #[serde(default)]
    pub(super) recovery_handoff: bool,
    /// Recovery flow whose code an admin minted rather than mailed; it proves no mailbox.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) admin_code: bool,
    /// Sealed TOTP secret offered for enrolment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pending_totp: Option<String>,
    /// Sealed JSON list of freshly generated lookup codes, waiting for confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) lookup_codes: Option<String>,
    /// Sealed verification code from the mail link, prefilled into the form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) prefill_code: Option<String>,
    /// Binding of the browser that followed the mail link; only it sees the prefilled code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) prefill_binding: Option<String>,
}

/// A flow row with its parsed context. Submit functions change `state` and `ctx`, then [`save`].
///
/// [`save`]: FlowRecord::save
#[derive(Clone, Debug)]
pub(super) struct FlowRecord {
    pub(super) row: FlowRow,
    pub(super) ctx: Context,
}

impl FlowRecord {
    fn from_row(row: FlowRow) -> Result<Self> {
        let ctx = serde_json::from_str(&row.context)
            .map_err(|e| anyhow!("identity_flows.context of {} is not valid: {e}", row.id))?;
        Ok(Self { row, ctx })
    }

    pub(super) fn kind(&self) -> Option<FlowKind> {
        kind_from_segment(&self.row.kind)
    }

    fn is_expired(&self) -> bool {
        self.row.expires_at <= crate::db::now_rfc3339()
    }

    /// Drop the messages of the previous submit.
    pub(super) fn clear_messages(&mut self) {
        self.ctx.messages.clear();
        self.ctx.node_messages.clear();
    }

    pub(super) fn add_message(&mut self, message: Message) {
        self.ctx.messages.push(message);
    }

    /// A message shown under the input named `node`.
    pub(super) fn add_node_message(&mut self, node: &str, message: Message) {
        self.ctx.node_messages.push(NodeMessage {
            node: node.to_string(),
            message,
        });
    }

    /// Kratos state name: `choose_method`, `sent_email`, `passed_challenge`, `show_form`, `success`.
    pub(super) fn set_state(&mut self, state: &str) {
        self.row.state = state.to_string();
    }

    /// Persist `state` and the context, if no other request saved the flow since it was loaded.
    pub(super) async fn save(&mut self, db: &DbPool) -> Result<Saved> {
        self.write(db, true).await
    }

    /// [`save`](Self::save) without touching `state`.
    async fn save_context(&mut self, db: &DbPool) -> Result<Saved> {
        self.write(db, false).await
    }

    /// Mark a login, registration or recovery flow used, so it cannot be submitted again. `false`
    /// when another request finished it first.
    pub(super) async fn finish(&mut self, db: &DbPool) -> Result<bool> {
        let id = self.row.id.clone();
        let claimed = db_interact!(db, |c| {
            diesel::update(
                identity_flows::table
                    .find(&id)
                    .filter(identity_flows::state.ne(FINISHED)),
            )
            .set((
                identity_flows::state.eq(FINISHED),
                identity_flows::version.eq(identity_flows::version + 1),
            ))
            .execute(c)
        })?;
        if claimed > 0 {
            self.row.state = FINISHED.to_string();
        }
        Ok(claimed > 0)
    }

    async fn write(&mut self, db: &DbPool, with_state: bool) -> Result<Saved> {
        let context = serde_json::to_string(&self.ctx).expect("flow context serialises");
        let (id, version, next) = (self.row.id.clone(), self.row.version, self.row.version + 1);
        let state = with_state.then(|| self.row.state.clone());
        let ctx = context.clone();
        let updated = db_interact!(db, |c| {
            let target = identity_flows::table
                .find(&id)
                .filter(identity_flows::version.eq(version));
            match &state {
                Some(state) => diesel::update(target)
                    .set((
                        identity_flows::state.eq(state),
                        identity_flows::context.eq(&ctx),
                        identity_flows::version.eq(next),
                    ))
                    .execute(c),
                None => diesel::update(target)
                    .set((
                        identity_flows::context.eq(&ctx),
                        identity_flows::version.eq(next),
                    ))
                    .execute(c),
            }
        })?;
        if updated == 0 {
            return Ok(Saved::Changed);
        }
        self.row.context = context;
        self.row.version = next;
        Ok(Saved::Done)
    }
}

/// How a [`FlowRecord::save`] ended.
#[must_use]
#[derive(Debug, PartialEq)]
pub(super) enum Saved {
    Done,
    /// Another request saved the flow since it was loaded; nothing was written.
    Changed,
}

/// A submitted form body; the first value of a repeated field wins.
pub(super) struct Form(pub(super) Vec<(String, String)>);

impl Form {
    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A submit that passed the dispatcher's checks.
pub(super) struct Submission<'a> {
    pub(super) flow: FlowRecord,
    pub(super) form: &'a Form,
    /// The browser's live session; present for settings flows and for login flows started by a
    /// session (refresh and second factor), where it is that session.
    pub(super) session: Option<SessionRow>,
    pub(super) device: Device<'a>,
}

/// What a per-kind submit asks the route to do.
#[derive(Debug, PartialEq)]
pub(super) enum SubmitOutcome {
    /// Show the flow again at `/{kind}?flow=<id>`; its state and messages are saved on the flow.
    Page,
    /// Send the browser to `location`, setting each `Set-Cookie` value.
    Redirect {
        location: String,
        set_cookies: Vec<String>,
    },
}

/// A handled submit: the response to give, the audit rows the route writes with the request's
/// context, and work outside the identity store the route does afterwards.
#[derive(Debug)]
pub(super) struct Submitted {
    pub(super) outcome: SubmitOutcome,
    pub(super) audit: Vec<AuditEvent>,
    pub(super) after: Option<AfterEffect>,
}

impl Submitted {
    pub(super) fn new(outcome: SubmitOutcome, audit: Vec<AuditEvent>) -> Self {
        Self {
            outcome,
            audit,
            after: None,
        }
    }
}

impl From<SubmitOutcome> for Submitted {
    fn from(outcome: SubmitOutcome) -> Self {
        Self::new(outcome, Vec::new())
    }
}

/// Work a submit leaves to the route layer.
#[derive(Debug, PartialEq)]
pub(super) enum AfterEffect {
    /// The password changed: end the identity's OP sessions and grants in every browser but the
    /// one holding `session_id`.
    PasswordChanged {
        identity_id: String,
        session_id: String,
    },
}

/// The dispatcher's answer to a submit.
#[derive(Debug)]
pub(super) enum Dispatch {
    Done(Submitted),
    /// Unknown, expired or wrong-kind flow.
    Expired,
    /// Binding or CSRF mismatch.
    Forged,
    /// The submit needs a sign-in first; go to this URL.
    SignIn(String),
}

/// Start parameters of a browser flow, `return_to` already sanitised.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct InitParams<'a> {
    pub(super) return_to: Option<&'a str>,
    pub(super) aal2: bool,
    pub(super) refresh: bool,
}

#[derive(Debug, PartialEq)]
pub(super) enum InitOutcome {
    /// A new flow with this id.
    Created(String),
    /// No flow is needed; go here instead.
    Redirect(String),
}

/// How a browser's request relates to a stored flow.
enum Checked {
    /// The flow, and the browser's session for settings flows.
    Ok(Box<(FlowRecord, Option<SessionRow>)>),
    Missing,
    Expired,
    /// Another browser's flow, or a settings flow of another session.
    Foreign,
    /// A settings flow and no live session.
    NoSession,
    /// A settings flow of an identity with TOTP, on an AAL1 session.
    Aal2Required,
}

/// What `get_flow` reports.
pub(super) enum Found {
    Ready(Box<FlowRecord>),
    Gone,
    Aal2Required,
}

#[derive(Debug, PartialEq)]
pub(super) enum Logout {
    SignedOut,
    NoSession,
    BadToken,
}

/// The identity data a document shows.
struct Person {
    email: String,
    first: String,
    last: String,
    totp: bool,
    lookup: bool,
}

impl Person {
    fn of(identity: &Identity) -> Self {
        let traits = identity.traits.as_ref();
        let text = |ptr: &str| {
            traits
                .and_then(|t| t.pointer(ptr))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let has = |kind: &str| {
            identity
                .credentials
                .as_ref()
                .is_some_and(|c| c.contains_key(kind))
        };
        Self {
            email: text("/email"),
            first: text("/name/first"),
            last: text("/name/last"),
            totp: has("totp"),
            lookup: has("lookup_secret"),
        }
    }
}

/// A flow of `kind` in its first state, not stored yet.
#[allow(clippy::too_many_arguments)]
fn new_flow(
    kind: FlowKind,
    binding: Option<String>,
    owner: Option<&SessionRow>,
    requested_aal: Option<&str>,
    refresh: bool,
    return_to: Option<&str>,
    request_url: String,
    ctx: Context,
) -> FlowRecord {
    let now = chrono::Utc::now();
    let state = match kind {
        FlowKind::Settings => "show_form",
        _ => "choose_method",
    };
    let row = FlowRow {
        id: uuid::Uuid::new_v4().to_string(),
        kind: kind.path_segment().to_string(),
        state: state.to_string(),
        binding,
        identity_id: owner.map(|s| s.identity_id.clone()),
        session_id: owner.map(|s| s.id.clone()),
        requested_aal: requested_aal.map(str::to_string),
        refresh: i32::from(refresh),
        return_to: return_to.map(str::to_string),
        request_url,
        context: serde_json::to_string(&ctx).expect("flow context serialises"),
        version: 0,
        issued_at: crate::db::rfc3339(now),
        expires_at: crate::db::rfc3339(now + lifespan(kind)),
    };
    FlowRecord { row, ctx }
}

/// Per-kind submit for a flow that passed the checks.
async fn dispatch(backend: &NativeBackend, kind: FlowKind, s: Submission<'_>) -> Result<Submitted> {
    match kind {
        FlowKind::Login => login::submit(backend, s).await,
        FlowKind::Registration => registration::submit(backend, s).await,
        FlowKind::Verification => verification::submit(backend, s).await,
        FlowKind::Recovery => recovery::submit(backend, s).await,
        FlowKind::Settings => settings::submit(backend, s).await,
    }
}

impl NativeBackend {
    pub(super) async fn load_flow(&self, id: &str) -> Result<Option<FlowRecord>> {
        let id = id.to_string();
        let row: Option<FlowRow> = db_interact!(self.db, |c| {
            identity_flows::table
                .find(&id)
                .select(FlowRow::as_select())
                .first(c)
                .optional()
        })?;
        row.map(FlowRecord::from_row).transpose()
    }

    /// The live session the cookie carries, with its active identity.
    async fn browser_session(&self, cookie: &str) -> Result<Option<(SessionRow, Identity)>> {
        let Some(session) = self.current_session(Some(cookie)).await? else {
            return Ok(None);
        };
        let identity = store::get(&self.db, &session.identity_id).await?;
        Ok(identity
            .filter(|i| i.state == Some(IdentityState::Active))
            .map(|i| (session, i)))
    }

    /// The browser's Forseti CSRF token, from its cookie.
    fn csrf_token_of(&self, cookie: &str) -> Option<String> {
        crate::cookies::read_cookie_from(cookie, crate::csrf::csrf_cookie_name(self.https))
            .filter(|t| !t.is_empty())
    }

    fn seal_for_flow(&self, purpose: &str, flow_id: &str, plain: &[u8]) -> String {
        self.keys.seal.seal(purpose, flow_id, plain)
    }

    fn open_for_flow(&self, purpose: &str, flow_id: &str, sealed: &str) -> Option<Vec<u8>> {
        self.keys.seal.open(purpose, flow_id, sealed)
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_flow(
        &self,
        kind: FlowKind,
        binding: Option<String>,
        owner: Option<&SessionRow>,
        requested_aal: Option<&str>,
        refresh: bool,
        return_to: Option<&str>,
        request_url: String,
        ctx: Context,
    ) -> Result<FlowRecord> {
        let rec = new_flow(
            kind,
            binding,
            owner,
            requested_aal,
            refresh,
            return_to,
            request_url,
            ctx,
        );
        self.store_flow(&rec.row).await?;
        Ok(rec)
    }

    async fn store_flow(&self, row: &FlowRow) -> Result<()> {
        let insert = row.clone();
        db_interact!(self.db, |c| {
            diesel::insert_into(identity_flows::table)
                .values(&insert)
                .execute(c)
        })?;
        Ok(())
    }

    /// A settings flow for the session's identity, holding every group.
    pub(super) async fn create_settings_flow(
        &self,
        session: &SessionRow,
        return_to: Option<&str>,
        request_url: String,
        recovery_handoff: bool,
    ) -> Result<FlowRecord> {
        let ctx = Context {
            recovery_handoff,
            ..Context::default()
        };
        let mut rec = self
            .insert_flow(
                FlowKind::Settings,
                None,
                Some(session),
                None,
                false,
                return_to,
                request_url,
                ctx,
            )
            .await?;
        let has_totp = store::get(&self.db, &session.identity_id)
            .await?
            .is_some_and(|i| Person::of(&i).totp);
        if !has_totp {
            self.mint_pending_totp(&mut rec);
            // A concurrent change keeps its own state; the document mints a secret if none is stored.
            let _ = rec.save(&self.db).await?;
        }
        Ok(rec)
    }

    /// A verification flow in `sent_email` for `email`, as registration and an address change
    /// start it. The caller sends the code with [`NativeBackend::send_code`].
    pub(super) async fn create_verification_flow(
        &self,
        email: &str,
        binding: Option<String>,
        return_to: Option<&str>,
    ) -> Result<FlowRecord> {
        let rec = self.verification_flow(email, binding, return_to);
        self.store_flow(&rec.row).await?;
        Ok(rec)
    }

    /// [`create_verification_flow`](Self::create_verification_flow) without storing the flow.
    pub(super) fn verification_flow(
        &self,
        email: &str,
        binding: Option<String>,
        return_to: Option<&str>,
    ) -> FlowRecord {
        let request_url = browser_init_url(
            &self.self_url,
            FlowKind::Verification,
            FlowInit {
                return_to,
                ..FlowInit::default()
            },
        );
        let ctx = Context {
            email: Some(email.to_string()),
            ..Context::default()
        };
        let mut rec = new_flow(
            FlowKind::Verification,
            binding,
            None,
            None,
            false,
            return_to,
            request_url,
            ctx,
        );
        rec.set_state("sent_email");
        rec
    }

    /// Keep freshly generated lookup `codes` on the flow, sealed, until they are confirmed.
    fn hold_generated_codes(&self, rec: &mut FlowRecord, codes: &[String]) {
        let plain = serde_json::to_vec(codes).expect("a list of strings serialises");
        rec.ctx.lookup_codes = Some(self.seal_for_flow(SEAL_LOOKUP_CODES, &rec.row.id, &plain));
    }

    /// The lookup codes [`hold_generated_codes`](Self::hold_generated_codes) kept on the flow.
    fn generated_codes(&self, rec: &FlowRecord) -> Option<Vec<String>> {
        let sealed = rec.ctx.lookup_codes.as_deref()?;
        let plain = self.open_for_flow(SEAL_LOOKUP_CODES, &rec.row.id, sealed)?;
        serde_json::from_slice(&plain).ok()
    }

    fn mint_pending_totp(&self, rec: &mut FlowRecord) {
        let secret = totp::new_secret();
        rec.ctx.pending_totp = Some(self.seal_for_flow(SEAL_PENDING_TOTP, &rec.row.id, &secret));
    }

    /// The settings flow's pending TOTP secret, minted and stored when it has none.
    async fn pending_totp_secret(&self, rec: &mut FlowRecord) -> Result<Vec<u8>> {
        for _ in 0..SAVE_ATTEMPTS {
            let stored = rec
                .ctx
                .pending_totp
                .as_deref()
                .and_then(|s| self.open_for_flow(SEAL_PENDING_TOTP, &rec.row.id, s));
            if let Some(secret) = stored {
                return Ok(secret);
            }
            self.mint_pending_totp(rec);
            if rec.save(&self.db).await? == Saved::Changed {
                *rec = self
                    .load_flow(&rec.row.id)
                    .await?
                    .ok_or_else(|| anyhow!("settings flow {} disappeared", rec.row.id))?;
            }
        }
        Err(anyhow!(
            "pending TOTP secret of flow {} could not be stored",
            rec.row.id
        ))
    }

    /// Start a browser flow of `kind` for the browser holding `csrf_token`.
    pub(super) async fn init_flow(
        &self,
        kind: FlowKind,
        params: InitParams<'_>,
        csrf_token: &str,
        cookie: &str,
    ) -> Result<InitOutcome> {
        let request_url = browser_init_url(
            &self.self_url,
            kind,
            FlowInit {
                return_to: params.return_to,
                aal: params.aal2.then_some("aal2"),
                refresh: params.refresh,
            },
        );
        let home = || params.return_to.unwrap_or("/").to_string();
        let session = self.browser_session(cookie).await?;
        let binding = Some(binding_of(csrf_token));
        let created = |rec: FlowRecord| Ok::<_, anyhow::Error>(InitOutcome::Created(rec.row.id));
        match kind {
            FlowKind::Login => match &session {
                None => created(
                    self.insert_flow(
                        kind,
                        binding,
                        None,
                        Some("aal1"),
                        false,
                        params.return_to,
                        request_url,
                        Context::default(),
                    )
                    .await?,
                ),
                Some((s, _)) if params.aal2 && s.aal != "aal2" => created(
                    self.insert_flow(
                        kind,
                        binding,
                        Some(s),
                        Some("aal2"),
                        false,
                        params.return_to,
                        request_url,
                        Context::default(),
                    )
                    .await?,
                ),
                Some((s, _)) if params.refresh => created(
                    self.insert_flow(
                        kind,
                        binding,
                        Some(s),
                        Some("aal1"),
                        true,
                        params.return_to,
                        request_url,
                        Context::default(),
                    )
                    .await?,
                ),
                Some(_) => Ok(InitOutcome::Redirect(home())),
            },
            FlowKind::Registration | FlowKind::Recovery if session.is_some() => {
                Ok(InitOutcome::Redirect(home()))
            }
            FlowKind::Registration | FlowKind::Recovery | FlowKind::Verification => created(
                self.insert_flow(
                    kind,
                    binding,
                    None,
                    None,
                    false,
                    params.return_to,
                    request_url,
                    Context::default(),
                )
                .await?,
            ),
            FlowKind::Settings => {
                let target = params.return_to.unwrap_or("/settings");
                let Some((s, identity)) = &session else {
                    return Ok(InitOutcome::Redirect(format!(
                        "/login?return_to={}",
                        crate::web::urlencode(target)
                    )));
                };
                if Person::of(identity).totp && s.aal != "aal2" {
                    return Ok(InitOutcome::Redirect(crate::auth::aal2_step_up_url(target)));
                }
                created(
                    self.create_settings_flow(s, params.return_to, request_url, false)
                        .await?,
                )
            }
        }
    }

    /// The stored flow `id` as the browser holding `cookie` may use it. `adopt` binds an unbound
    /// flow to this browser; without it an unbound flow is readable by any browser.
    async fn check(&self, kind: FlowKind, id: &str, cookie: &str, adopt: bool) -> Result<Checked> {
        let Some(mut rec) = self.load_flow(id).await? else {
            return Ok(Checked::Missing);
        };
        if rec.kind() != Some(kind) {
            return Ok(Checked::Missing);
        }
        if rec.is_expired() {
            return Ok(Checked::Expired);
        }
        match kind {
            FlowKind::Settings => {
                let Some((session, identity)) = self.browser_session(cookie).await? else {
                    return Ok(Checked::NoSession);
                };
                if rec.row.session_id.as_deref() != Some(session.id.as_str())
                    || rec.row.identity_id.as_deref() != Some(identity.id.as_str())
                {
                    return Ok(Checked::Foreign);
                }
                if Person::of(&identity).totp && session.aal != "aal2" {
                    return Ok(Checked::Aal2Required);
                }
                Ok(Checked::Ok(Box::new((rec, Some(session)))))
            }
            // The code is the proof and no session is issued, so any browser may finish it.
            FlowKind::Verification => Ok(Checked::Ok(Box::new((rec, None)))),
            FlowKind::Login | FlowKind::Registration | FlowKind::Recovery => {
                if rec.row.state == FINISHED {
                    return Ok(Checked::Expired);
                }
                if rec.row.binding.is_none() {
                    // An admin-minted recovery flow carries no identity data until a code is
                    // used, so any browser may read it; the first submit takes it.
                    if adopt && !self.adopt(&mut rec, cookie).await? {
                        return Ok(Checked::Expired);
                    }
                } else if !self.binding_matches(&rec, cookie) {
                    // Another browser took the admin's link first: for this one it is used up.
                    if rec.ctx.admin_code {
                        return Ok(Checked::Expired);
                    }
                    return Ok(Checked::Foreign);
                }
                // Refresh and second-factor flows belong to the session that started them.
                let Some(owner) = rec.row.session_id.clone() else {
                    return Ok(Checked::Ok(Box::new((rec, None))));
                };
                let Some((session, identity)) = self.browser_session(cookie).await? else {
                    return Ok(Checked::Expired);
                };
                if session.id != owner
                    || rec.row.identity_id.as_deref() != Some(identity.id.as_str())
                {
                    return Ok(Checked::Foreign);
                }
                Ok(Checked::Ok(Box::new((rec, Some(session)))))
            }
        }
    }

    /// Whether the browser's CSRF token is the flow's binding.
    fn binding_matches(&self, rec: &FlowRecord, cookie: &str) -> bool {
        let Some(token) = self.csrf_token_of(cookie) else {
            return false;
        };
        let mine = binding_of(&token);
        rec.row
            .binding
            .as_deref()
            .is_some_and(|b| bool::from(b.as_bytes().ct_eq(mine.as_bytes())))
    }

    /// Bind the unbound flow `rec` to the browser holding `cookie`; the first browser wins.
    /// `false` when the browser has no CSRF token or another browser took the flow.
    async fn adopt(&self, rec: &mut FlowRecord, cookie: &str) -> Result<bool> {
        let Some(token) = self.csrf_token_of(cookie) else {
            return Ok(false);
        };
        let (id, claim) = (rec.row.id.clone(), binding_of(&token));
        let bound = claim.clone();
        let adopted = db_interact!(self.db, |c| {
            diesel::update(
                identity_flows::table
                    .find(&id)
                    .filter(identity_flows::binding.is_null()),
            )
            .set(identity_flows::binding.eq(&bound))
            .execute(c)
        })?;
        if adopted == 0 {
            let Some(current) = self.load_flow(&rec.row.id).await? else {
                return Ok(false);
            };
            rec.row.binding = current.row.binding;
            return Ok(self.binding_matches(rec, cookie));
        }
        rec.row.binding = Some(claim);
        Ok(true)
    }

    /// A flow for the browser's GET of `/{kind}?flow=<id>`; a GET never binds a flow.
    pub(super) async fn browser_flow(
        &self,
        kind: FlowKind,
        id: &str,
        cookie: &str,
    ) -> Result<Found> {
        Ok(match self.check(kind, id, cookie, false).await? {
            Checked::Ok(found) => Found::Ready(Box::new(found.0)),
            Checked::Aal2Required => Found::Aal2Required,
            Checked::Missing | Checked::Expired | Checked::Foreign | Checked::NoSession => {
                Found::Gone
            }
        })
    }

    /// The Kratos-shaped document of a flow, its `csrf_token` node carrying the cookie's token.
    pub(super) async fn flow_document(&self, rec: &mut FlowRecord, cookie: &str) -> Result<Value> {
        let kind = rec
            .kind()
            .ok_or_else(|| anyhow!("identity_flows.kind {:?} is unknown", rec.row.kind))?;
        let csrf = self.csrf_token_of(cookie).unwrap_or_default();
        let person = match &rec.row.identity_id {
            Some(id) => store::get(&self.db, id).await?.map(|i| Person::of(&i)),
            None => None,
        };
        let person = person.unwrap_or(Person {
            email: String::new(),
            first: String::new(),
            last: String::new(),
            totp: false,
            lookup: false,
        });

        let mut pending: Option<(String, String)> = None;
        if matches!(kind, FlowKind::Settings) && !person.totp {
            let secret = self.pending_totp_secret(rec).await?;
            let b32 = totp::encode_secret(&secret);
            let qr = totp::qr_data_uri(&totp::key_uri(&self.totp_issuer, &person.email, &b32))?;
            pending = Some((qr, b32));
        }
        let shown_codes = self.generated_codes(rec).unwrap_or_default();
        let link_browser = rec.ctx.prefill_binding.as_deref().is_some_and(|b| {
            let mine = binding_of(&csrf);
            !csrf.is_empty() && bool::from(b.as_bytes().ct_eq(mine.as_bytes()))
        });
        let prefill = rec
            .ctx
            .prefill_code
            .as_deref()
            .filter(|_| link_browser)
            .and_then(|s| self.open_for_flow(SEAL_PREFILL_CODE, &rec.row.id, s))
            .and_then(|plain| String::from_utf8(plain).ok())
            .unwrap_or_default();
        let continue_to = rec
            .row
            .return_to
            .clone()
            .unwrap_or_else(|| format!("{}/", self.self_url));
        let ctx = &rec.ctx;
        let row = &rec.row;
        let email = ctx.email.as_deref().unwrap_or_default();
        let traits = ctx
            .traits
            .as_ref()
            .map_or_else(ui::Traits::default, |t| ui::Traits {
                email: &t.email,
                first: &t.first,
                last: &t.last,
            });
        let code = match row.state.as_str() {
            "sent_email" => ui::Code::SentEmail {
                email,
                code: &prefill,
            },
            "passed_challenge" => ui::Code::PassedChallenge {
                email,
                continue_to: &continue_to,
            },
            _ => ui::Code::ChooseMethod,
        };
        let screen = match kind {
            FlowKind::Login if row.refresh != 0 => ui::Screen::Login(ui::Login::Refresh {
                identifier: &person.email,
            }),
            FlowKind::Login if row.requested_aal.as_deref() == Some("aal2") => {
                ui::Screen::Login(ui::Login::SecondFactor {
                    totp: person.totp,
                    lookup: person.lookup,
                })
            }
            FlowKind::Login => ui::Screen::Login(ui::Login::Password {
                identifier: ctx.identifier.as_deref().unwrap_or_default(),
            }),
            FlowKind::Registration if ctx.credential_step => {
                ui::Screen::Registration(ui::Registration::Password(traits))
            }
            FlowKind::Registration => ui::Screen::Registration(ui::Registration::Profile(traits)),
            FlowKind::Verification => ui::Screen::Verification(code),
            FlowKind::Recovery => ui::Screen::Recovery(code),
            FlowKind::Settings => {
                let totp = match &pending {
                    Some((qr, secret)) => ui::Totp::Pending { qr, secret },
                    None => ui::Totp::Enrolled,
                };
                let lookup = match &ctx.lookup_codes {
                    _ if !person.totp => ui::Lookup::Unavailable,
                    Some(_) => ui::Lookup::Generated(&shown_codes),
                    None if person.lookup => ui::Lookup::Confirmed,
                    None => ui::Lookup::Offer,
                };
                let handoff = ctx.recovery_handoff.then(|| {
                    let issued = chrono::DateTime::parse_from_rfc3339(&row.issued_at)
                        .map_or_else(|_| chrono::Utc::now(), |t| t.with_timezone(&chrono::Utc));
                    ui::Handoff {
                        until: issued + self.settings.privileged_window(),
                        window_minutes: self.settings.privileged_session_minutes,
                    }
                });
                ui::Screen::Settings(ui::Settings {
                    traits: ui::Traits {
                        email: &person.email,
                        first: &person.first,
                        last: &person.last,
                    },
                    totp,
                    lookup,
                    saved: row.state == "success",
                    handoff,
                })
            }
        };
        let meta = ui::Meta {
            id: &row.id,
            kind,
            request_url: &row.request_url,
            return_to: row.return_to.as_deref(),
            issued_at: &row.issued_at,
            expires_at: &row.expires_at,
            csrf_token: &csrf,
            requested_aal: row.requested_aal.as_deref(),
            refresh: row.refresh != 0,
        };
        let notes = ui::Notes {
            flow: &ctx.messages,
            nodes: &ctx.node_messages,
        };
        Ok(ui::document(&meta, &screen, notes))
    }

    /// Check a submit to `/self-service/{kind}?flow=<id>` and hand it to the per-kind function.
    pub(super) async fn submit_flow(
        &self,
        kind: FlowKind,
        id: &str,
        form: &Form,
        cookie: &str,
        csrf_valid: bool,
        device: Device<'_>,
    ) -> Result<Dispatch> {
        let (flow, session) = match self.check(kind, id, cookie, csrf_valid).await? {
            Checked::Ok(found) => *found,
            Checked::Missing | Checked::Expired => return Ok(Dispatch::Expired),
            Checked::Foreign => return Ok(Dispatch::Forged),
            Checked::NoSession => {
                return Ok(Dispatch::SignIn(format!(
                    "/login?return_to={}",
                    crate::web::urlencode("/settings")
                )));
            }
            Checked::Aal2Required => {
                return Ok(Dispatch::SignIn(crate::auth::aal2_step_up_url("/settings")));
            }
        };
        if !csrf_valid {
            return Ok(Dispatch::Forged);
        }
        let submission = Submission {
            flow,
            form,
            session,
            device,
        };
        Ok(Dispatch::Done(dispatch(self, kind, submission).await?))
    }

    /// Ask for a verification code for `email` on a fresh verification flow, as an email submit
    /// would; `Err` when the flow is not at `choose_method`.
    pub(super) async fn request_verification_for_known(
        &self,
        flow_id: &str,
        email: &str,
    ) -> Result<()> {
        verification::request_for_known(self, flow_id, email).await
    }

    /// An admin-minted recovery code on a new unbound flow, and the link to it.
    pub(super) async fn admin_recovery_code(
        &self,
        identity_id: &str,
    ) -> Result<crate::backend::identity::RecoveryCode> {
        recovery::admin_code(self, identity_id).await
    }

    /// Keep the code of a verification mail link so the form shows it filled in, to the browser
    /// holding `csrf_token` only. A later link-follow replaces code and browser.
    pub(super) async fn prefill_verification_code(
        &self,
        id: &str,
        code: &str,
        csrf_token: &str,
    ) -> Result<()> {
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) || csrf_token.is_empty() {
            return Ok(());
        }
        for _ in 0..SAVE_ATTEMPTS {
            let Some(mut rec) = self.load_flow(id).await? else {
                return Ok(());
            };
            if rec.kind() != Some(FlowKind::Verification) || rec.is_expired() {
                return Ok(());
            }
            rec.ctx.prefill_code = Some(self.seal_for_flow(SEAL_PREFILL_CODE, id, code.as_bytes()));
            rec.ctx.prefill_binding = Some(binding_of(csrf_token));
            if rec.save_context(&self.db).await? == Saved::Done {
                return Ok(());
            }
        }
        Ok(())
    }

    /// End the cookie's session when `token` is its logout token.
    pub(super) async fn logout(&self, cookie: &str, token: &str) -> Result<Logout> {
        if let Some(session) = self.verify_logout(cookie, token).await? {
            super::session::revoke(&self.db, &session.id, None).await?;
            return Ok(Logout::SignedOut);
        }
        if self.current_session(Some(cookie)).await?.is_none() {
            return Ok(Logout::NoSession);
        }
        Ok(Logout::BadToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::FlowFetch;

    #[test]
    fn segments_name_the_kinds() {
        for kind in [
            FlowKind::Login,
            FlowKind::Registration,
            FlowKind::Recovery,
            FlowKind::Verification,
            FlowKind::Settings,
        ] {
            assert_eq!(kind_from_segment(kind.path_segment()), Some(kind));
        }
        assert_eq!(kind_from_segment("logout"), None);
    }

    #[test]
    fn an_empty_context_is_an_empty_object() {
        assert_eq!(
            serde_json::to_string(&Context::default()).unwrap(),
            r#"{"credential_step":false,"recovery_handoff":false}"#
        );
        let parsed: Context = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, Context::default());
    }

    #[tokio::test]
    async fn an_unbound_flow_is_readable_by_any_browser_and_a_read_binds_nothing() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let rec = backend
            .insert_flow(
                FlowKind::Recovery,
                None,
                None,
                None,
                false,
                None,
                "http://localhost:3000/self-service/recovery/browser".into(),
                Context::default(),
            )
            .await
            .unwrap();
        let id = rec.row.id;
        for cookie in ["", "forseti_csrf=first", "forseti_csrf=second"] {
            assert!(matches!(
                backend
                    .get_flow(FlowKind::Recovery, &id, cookie)
                    .await
                    .unwrap(),
                FlowFetch::Ok(_)
            ));
        }
        let stored = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(stored.row.binding, None);
    }

    #[tokio::test]
    async fn messages_saved_on_a_flow_show_in_its_document() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let token = "browser-token";
        let mut rec = backend
            .insert_flow(
                FlowKind::Login,
                Some(binding_of(token)),
                None,
                Some("aal1"),
                false,
                None,
                "http://localhost:3000/self-service/login/browser".into(),
                Context::default(),
            )
            .await
            .unwrap();
        rec.ctx.identifier = Some("ann@example.com".into());
        rec.add_message(Message::error(
            4_000_006,
            "The provided credentials are invalid.",
        ));
        rec.add_node_message("password", Message::error(4_000_005, "too weak"));
        assert_eq!(rec.save(&db).await.unwrap(), Saved::Done);

        let cookie = format!("forseti_csrf={token}");
        let FlowFetch::Ok(flow) = backend
            .get_flow(FlowKind::Login, &rec.row.id, &cookie)
            .await
            .unwrap()
        else {
            panic!("flow readable by its browser");
        };
        assert_eq!(
            flow.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            [4_000_006]
        );
        let identifier = flow
            .inputs("default")
            .find(|i| i.name == "identifier")
            .unwrap();
        assert_eq!(identifier.value, "ann@example.com");
        let password = flow
            .inputs("password")
            .find(|i| i.name == "password")
            .unwrap();
        assert_eq!(password.messages[0].id, 4_000_005);

        rec.clear_messages();
        assert_eq!(rec.save(&db).await.unwrap(), Saved::Done);
        let FlowFetch::Ok(flow) = backend
            .get_flow(FlowKind::Login, &rec.row.id, &cookie)
            .await
            .unwrap()
        else {
            panic!("flow readable by its browser");
        };
        assert!(flow.messages.is_empty());
    }

    #[tokio::test]
    async fn a_save_lands_only_on_the_version_it_loaded() {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        let rec = backend
            .insert_flow(
                FlowKind::Verification,
                Some(binding_of("t")),
                None,
                None,
                false,
                None,
                "http://localhost:3000/self-service/verification/browser".into(),
                Context::default(),
            )
            .await
            .unwrap();
        let id = rec.row.id.clone();
        let mut first = backend.load_flow(&id).await.unwrap().unwrap();
        let mut second = backend.load_flow(&id).await.unwrap().unwrap();
        first.set_state("sent_email");
        first.ctx.email = Some("a@x.test".into());
        assert_eq!(first.save(&db).await.unwrap(), Saved::Done);
        second.set_state("passed_challenge");
        assert_eq!(second.save(&db).await.unwrap(), Saved::Changed);
        let stored = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(stored.row.state, "sent_email");
        assert_eq!(stored.ctx.email.as_deref(), Some("a@x.test"));
        assert_eq!(stored.row.version, 1);
        assert_eq!(
            first.save(&db).await.unwrap(),
            Saved::Done,
            "the winner saves again"
        );

        backend
            .prefill_verification_code(&id, "123456", "link-browser")
            .await
            .unwrap();
        let stored = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(
            stored.row.state, "sent_email",
            "the prefill writes no state"
        );
        assert_eq!(stored.row.version, 3);
        assert_eq!(
            stored.ctx.prefill_binding.as_deref(),
            Some(binding_of("link-browser").as_str())
        );
        assert_eq!(first.save(&db).await.unwrap(), Saved::Changed);
    }
}
