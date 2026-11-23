//! Registration submits: traits on step 1, a password or a passkey on step 2, then the account, a
//! session and the verification screen.

use anyhow::Result;

use super::verification::{address_problem, too_long};
use super::{FlowRecord, Form, PendingTraits, Submission, SubmitOutcome, Submitted};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::Aal;
use crate::identity_native::NativeBackend;
use crate::identity_native::codes::Purpose;
use crate::identity_native::password::{self, HashError, PasswordConfig, PolicyError};
use crate::identity_native::session::Issued;
use crate::identity_native::store::keys::{Key, NewKey};
use crate::identity_native::store::{
    self, CreateWithCredential, FirstCredential, IdentityRow, NAME_MAX_CHARS,
};
use crate::identity_native::ui::Message;
use crate::identity_native::webauthn::{self, PASSKEY_NAME, Slot};

pub(super) const ACCOUNT_EXISTS: (u64, &str) = (
    4_000_007,
    "An account with the same identifier (email, phone, username, ...) exists already.",
);
const NO_STRATEGY: (u64, &str) = (
    4_040_002,
    "Could not find a strategy to sign you up with. Did you fill out the form correctly?",
);
const BUSY: (u64, &str) = (
    9_000_001,
    "Too many sign-in attempts right now. Please try again in a few minutes.",
);

pub(super) async fn submit(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    s.flow.clear_messages();
    if s.form.get("screen") == Some("previous") {
        s.flow.ctx.credential_step = false;
        return page(backend, s.flow).await;
    }
    // The ceremony script submits the form without a button, so no `method` comes with it.
    if let Some(response) = s.form.get("passkey_register").filter(|v| !v.is_empty()) {
        return passkey_signup(backend, s, response).await;
    }
    match s.form.get("method") {
        Some("profile") => profile(backend, s).await,
        Some("password") => credential(backend, s).await,
        _ => {
            s.flow
                .add_message(Message::error(NO_STRATEGY.0, NO_STRATEGY.1));
            page(backend, s.flow).await
        }
    }
}

async fn page(backend: &NativeBackend, mut flow: FlowRecord) -> Result<Submitted> {
    let _ = flow.save(&backend.db).await?;
    Ok(SubmitOutcome::Page.into())
}

/// The `traits.*` fields of a submitted form, trimmed.
pub(super) fn traits_of(form: &Form) -> PendingTraits {
    let field = |name: &str| form.get(name).unwrap_or_default().trim().to_string();
    PendingTraits {
        email: field("traits.email"),
        first: field("traits.name.first"),
        last: field("traits.name.last"),
    }
}

/// Put Kratos's schema messages for `traits` on the flow's trait nodes; `false` when any failed.
pub(super) fn check_traits(flow: &mut FlowRecord, traits: &PendingTraits) -> bool {
    let before = flow.ctx.node_messages.len();
    if let Some(problem) = address_problem(&traits.email) {
        flow.add_node_message("traits.email", problem);
    }
    for (node, value) in [
        ("traits.name.first", &traits.first),
        ("traits.name.last", &traits.last),
    ] {
        let len = value.chars().count();
        if len > NAME_MAX_CHARS {
            flow.add_node_message(node, too_long(NAME_MAX_CHARS, len));
        }
    }
    flow.ctx.node_messages.len() == before
}

/// Step 1: validate and keep the traits, then ask for a password.
async fn profile(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    let traits = traits_of(s.form);
    s.flow.ctx.credential_step = check_traits(&mut s.flow, &traits);
    s.flow.ctx.traits = Some(traits);
    // The passkey registration names the address, which may have changed.
    s.flow.ctx.passkey_ceremony = None;
    page(backend, s.flow).await
}

/// What [`finish`] managed to set up for a new account.
struct Created {
    session: Option<Issued>,
    verification_flow: Option<String>,
}

/// The traits step 1 accepted; `None` while the flow is not on step 2.
fn accepted_traits(flow: &FlowRecord) -> Option<PendingTraits> {
    flow.ctx.traits.clone().filter(|_| flow.ctx.credential_step)
}

async fn reject(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    (id, text): (u64, &str),
) -> Result<Submitted> {
    flow.add_message(Message::error(id, text));
    page(backend, flow).await
}

/// Step 2 with a passkey: the flow's registration ceremony, then the account with the
/// ceremony's user handle as its id, as [`credential`] does with a password.
async fn passkey_signup(
    backend: &NativeBackend,
    mut s: Submission<'_>,
    response: &str,
) -> Result<Submitted> {
    let Some(traits) = accepted_traits(&s.flow) else {
        return reject(backend, s.flow, NO_STRATEGY).await;
    };
    let Some(rp) = backend.webauthn.as_ref() else {
        return reject(backend, s.flow, NO_STRATEGY).await;
    };
    let Some(ceremony) = backend.take(&mut s.flow, Slot::Passkey).await? else {
        return reject(backend, s.flow, NO_STRATEGY).await;
    };
    let Some((user, passkey)) = webauthn::register_passkey(rp, ceremony, response) else {
        return reject(backend, s.flow, NO_STRATEGY).await;
    };
    let key = NewKey {
        display_name: PASSKEY_NAME.to_string(),
        key: Key::Passkey(passkey),
    };
    let credential = FirstCredential::Passkey {
        user,
        key: Box::new(key),
    };
    create_account(backend, s, &traits, credential, "passkey").await
}

/// Step 2: the password, then the account in one transaction, a session, and a verification flow
/// with its code mailed.
async fn credential(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    let Some(traits) = accepted_traits(&s.flow) else {
        return reject(backend, s.flow, NO_STRATEGY).await;
    };
    let password = s.form.get("password").unwrap_or_default().to_string();
    let min = backend.settings.password_min_length;
    let mut policy = password::check_policy(&password, &traits.email, min);
    if policy.is_ok()
        && let Some(check) = &backend.breach_check
        && check.is_breached(&password).await
    {
        policy = Err(PolicyError::Breached);
    }
    if let Err(e) = policy {
        let (id, context, text) = e.message();
        s.flow
            .add_node_message("password", Message::error(id, text).with_context(context));
        return page(backend, s.flow).await;
    }
    let phc = match password::hash(&backend.hash_permits, password).await {
        Ok(phc) => phc,
        Err(HashError::Busy) => {
            s.flow.add_message(Message::error(BUSY.0, BUSY.1));
            return page(backend, s.flow).await;
        }
        Err(HashError::Failed(e)) => return Err(e),
    };
    let config = serde_json::to_string(&PasswordConfig {
        hashed_password: phc,
    })?;
    create_account(
        backend,
        s,
        &traits,
        FirstCredential::Password(config),
        "password",
    )
    .await
}

/// The account from `traits` and its first `credential` in one transaction, then a session for
/// `method`, the `identity.created` row, and the verification screen.
async fn create_account(
    backend: &NativeBackend,
    mut s: Submission<'_>,
    traits: &PendingTraits,
    credential: FirstCredential,
    method: &'static str,
) -> Result<Submitted> {
    let first = Some(traits.first.as_str()).filter(|f| !f.is_empty());
    let last = Some(traits.last.as_str()).filter(|l| !l.is_empty());
    let created =
        store::create_with_first_credential(&backend.db, &traits.email, first, last, credential)
            .await?;
    let row = match created {
        CreateWithCredential::Created(row) => *row,
        CreateWithCredential::AddressTaken => {
            s.flow.ctx.credential_step = false;
            return reject(backend, s.flow, ACCOUNT_EXISTS).await;
        }
        // `ACCOUNT_EXISTS` means the address here; a taken credential id answers as a failed ceremony.
        CreateWithCredential::KeyTaken => return reject(backend, s.flow, NO_STRATEGY).await,
    };
    // The account exists from here on: every later step is best effort, so the audit row and a
    // response are given even when one fails.
    if let Err(e) = s.flow.finish(&backend.db).await {
        tracing::error!(error = ?e, flow_id = %s.flow.row.id, "registration flow not marked finished");
    }
    let created = finish(backend, &s, &row, method).await;
    let event = AuditEvent::new(action::IDENTITY_CREATED)
        .actor_user(&row.id, &row.email)
        .target(target_kind::IDENTITY, &row.id)
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => s.flow.row.id,
            "kratos_session_id" => created.session.as_ref().map(|i| i.id.clone()),
            "method" => method,
        ));
    let location = match &created.verification_flow {
        Some(id) => format!("/verification?flow={}", crate::web::urlencode(id)),
        None => "/login".to_string(),
    };
    let set_cookies = created
        .session
        .iter()
        .map(|i| backend.session_set_cookie(&i.token))
        .collect();
    Ok(Submitted::new(
        SubmitOutcome::Redirect {
            location,
            set_cookies,
        },
        vec![event],
    ))
}

/// Sign the new identity in and put the verification screen, with its code mailed, in front of it.
/// Each step that fails is logged and left out; resend on the verification page mails a new code.
async fn finish(
    backend: &NativeBackend,
    s: &Submission<'_>,
    row: &IdentityRow,
    method: &str,
) -> Created {
    let session = backend
        .issue_session(&row.id, method, None, Aal::Aal1, s.device)
        .await
        .inspect_err(|e| tracing::error!(error = ?e, identity_id = %row.id, "session for a new account not issued"))
        .ok();
    let verification = backend
        .create_verification_flow(
            &row.email,
            s.flow.row.binding.clone(),
            s.flow.row.return_to.as_deref(),
        )
        .await
        .inspect_err(|e| tracing::error!(error = ?e, identity_id = %row.id, "verification flow for a new account not created"))
        .ok();
    if let Some(flow) = &verification
        && let Err(e) = backend
            .send_code(&flow.row.id, Purpose::Verification, &row.id, &row.email)
            .await
    {
        tracing::error!(error = ?e, identity_id = %row.id, "verification code for a new account not queued");
    }
    Created {
        session,
        verification_flow: verification.map(|f| f.row.id),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use diesel::prelude::*;

    use super::super::InitParams;
    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::{FlowFetch, FlowKind, WhoamiOutcome};
    use crate::config::AppConfig;
    use crate::db::DbPool;
    use crate::identity_native::password::BreachCheck;
    use crate::identity_native::test_support::{
        Browser, audit_lines, identity_with_password, messages, session_cookie, start, submit,
    };
    use crate::schema::{identities, identity_credentials};

    const STRONG: &str = "violet staircase 42";

    async fn setup() -> (DbPool, Arc<NativeBackend>) {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        (db, backend)
    }

    async fn begin(backend: &NativeBackend, browser: &Browser, return_to: Option<&str>) -> String {
        let params = InitParams {
            return_to,
            ..InitParams::default()
        };
        start(backend, browser, FlowKind::Registration, params).await
    }

    async fn step_one(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        email: &str,
    ) -> Submitted {
        submit(
            backend,
            browser,
            FlowKind::Registration,
            id,
            &[
                ("method", "profile"),
                ("traits.email", email),
                ("traits.name.first", "Ada"),
                ("traits.name.last", "Lovelace"),
            ],
        )
        .await
    }

    async fn step_two(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        password: &str,
    ) -> Submitted {
        submit(
            backend,
            browser,
            FlowKind::Registration,
            id,
            &[
                ("method", "password"),
                ("password", password),
                ("traits.email", "ignored@x.test"),
            ],
        )
        .await
    }

    async fn counts(db: &DbPool) -> (i64, i64) {
        let run = async {
            Ok::<(i64, i64), anyhow::Error>(crate::db_interact!(db, |c| {
                Ok::<_, diesel::result::Error>((
                    identities::table.count().get_result(c)?,
                    identity_credentials::table.count().get_result(c)?,
                ))
            })?)
        };
        run.await.unwrap()
    }

    async fn on_step_two(backend: &NativeBackend, id: &str) -> bool {
        backend
            .load_flow(id)
            .await
            .unwrap()
            .unwrap()
            .ctx
            .credential_step
    }

    #[tokio::test]
    async fn two_steps_create_the_account_sign_it_in_and_show_verification() {
        let (db, backend) = setup().await;
        let browser = Browser::new();
        let back = "http://localhost:3000/invite/finalize?token=t";
        let id = begin(&backend, &browser, Some(back)).await;
        let done = step_one(&backend, &browser, &id, " New@X.test ").await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(on_step_two(&backend, &id).await);
        let FlowFetch::Ok(page) = backend
            .get_flow(FlowKind::Registration, &id, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        let hidden: Vec<(&str, &str, &str)> = page
            .inputs("default")
            .map(|i| (i.name.as_str(), i.input_type.as_str(), i.value.as_str()))
            .collect();
        assert!(hidden.contains(&("traits.email", "hidden", "New@X.test")));
        assert!(page.has_node("profile", "screen"));
        assert_eq!(counts(&db).await, (0, 0), "nothing stored before step 2");

        let done = step_two(&backend, &browser, &id, STRONG).await;
        let SubmitOutcome::Redirect { location, .. } = &done.outcome else {
            panic!("redirected");
        };
        let verification = location
            .strip_prefix("/verification?flow=")
            .expect("to the verification screen")
            .to_string();
        let token = session_cookie(&done).expect("signed in");
        let WhoamiOutcome::Ok(session) = backend
            .whoami(Some(&format!("forseti_session={token}")))
            .await
            .unwrap()
        else {
            panic!("the new session is live");
        };
        let identity = session.identity.unwrap();
        assert_eq!(identity.traits.as_ref().unwrap()["email"], "New@X.test");
        assert_eq!(identity.traits.as_ref().unwrap()["name"]["first"], "Ada");
        assert!(!identity.verifiable_addresses.as_ref().unwrap()[0].verified);
        assert!(identity.credentials.unwrap().contains_key("password"));
        assert_eq!(
            session.authentication_methods.unwrap()[0].method.as_deref(),
            Some("password")
        );

        let rec = backend.load_flow(&verification).await.unwrap().unwrap();
        assert_eq!(rec.row.state, "sent_email");
        assert_eq!(rec.row.return_to.as_deref(), Some(back));
        assert_eq!(rec.ctx.email.as_deref(), Some("New@X.test"));
        let registration = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(rec.row.binding, registration.row.binding);

        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("identity.created"), "{}", audit[0]);
        assert!(audit[0].contains(r#"String("password")"#), "{}", audit[0]);
        assert!(audit[0].contains(&identity.id));
        assert!(!audit[0].contains(STRONG) && !audit[0].contains(&token));

        let mail = backend.mailed("New@X.test").await;
        assert_eq!(mail.len(), 1);
        submit(
            &backend,
            &browser,
            FlowKind::Verification,
            &verification,
            &[("method", "code"), ("code", &mail[0].code)],
        )
        .await;
        let FlowFetch::Ok(page) = backend
            .get_flow(FlowKind::Verification, &verification, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        assert_eq!(page.state, "passed_challenge");
        assert!(
            page.form_action.starts_with(back),
            "continues to the invite"
        );
    }

    #[tokio::test]
    async fn a_completed_registration_flow_is_spent() {
        let (_, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "done@x.test").await;
        let done = step_two(&backend, &browser, &id, STRONG).await;
        assert!(session_cookie(&done).is_some());
        let form = super::super::Form(vec![("method".into(), "profile".into())]);
        let again = backend
            .submit_flow(
                FlowKind::Registration,
                &id,
                &form,
                &browser.cookie(),
                true,
                crate::identity_native::test_support::DEVICE,
            )
            .await
            .unwrap();
        assert!(
            matches!(again, super::super::Dispatch::Expired),
            "{again:?}"
        );
        assert!(matches!(
            backend
                .get_flow(FlowKind::Registration, &id, &browser.cookie())
                .await
                .unwrap(),
            FlowFetch::Gone
        ));
    }

    #[tokio::test]
    async fn the_back_button_returns_to_step_one_with_the_traits() {
        let (_, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "back@x.test").await;
        submit(
            &backend,
            &browser,
            FlowKind::Registration,
            &id,
            &[("screen", "previous"), ("traits.email", "back@x.test")],
        )
        .await;
        assert!(!on_step_two(&backend, &id).await);
        let FlowFetch::Ok(page) = backend
            .get_flow(FlowKind::Registration, &id, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        let email = page
            .inputs("default")
            .find(|i| i.name == "traits.email")
            .unwrap();
        assert_eq!(
            (email.input_type.as_str(), email.value.as_str()),
            ("email", "back@x.test")
        );
        assert!(!page.has_node("profile", "screen"));
    }

    #[tokio::test]
    async fn a_taken_address_gives_4000007_and_stores_nothing() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "taken@x.test", true).await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "TAKEN@x.test").await;
        let done = step_two(&backend, &browser, &id, STRONG).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(session_cookie(&done).is_none() && done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [4_000_007]);
        assert!(
            !on_step_two(&backend, &id).await,
            "back on step 1 to change it"
        );
        assert_eq!(counts(&db).await, (1, 1));
        assert!(backend.mailed("TAKEN@x.test").await.is_empty());
    }

    #[tokio::test]
    async fn weak_passwords_are_refused_and_store_nothing() {
        let (db, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "ann.smith@example.com").await;
        for (password, message) in [("short", 4_000_032), ("ann.smith@example.co", 4_000_005)] {
            let done = step_two(&backend, &browser, &id, password).await;
            assert_eq!(done.outcome, SubmitOutcome::Page, "{password}");
            assert_eq!(
                messages(&backend, &id).await.1,
                [("password".to_string(), message)],
                "{password}"
            );
            assert!(on_step_two(&backend, &id).await);
        }
        assert_eq!(counts(&db).await, (0, 0));
    }

    #[tokio::test]
    async fn a_breached_password_is_refused_when_the_check_is_on() {
        let suffix = {
            let sha1 = hex::encode_upper(aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                STRONG.as_bytes(),
            ));
            sha1[5..].to_string()
        };
        let body = format!("{suffix}:3\r\n");
        let app = axum::Router::new().route(
            "/range/{prefix}",
            axum::routing::get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let db = crate::db::test_pool().await;
        let mut built = NativeBackend::build(&AppConfig::test_fixture(), &db, &[0x42; 32]);
        built.breach_check = Some(BreachCheck::at(format!("http://{addr}")));
        let backend = Arc::new(built);
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "pwned@x.test").await;
        let done = step_two(&backend, &browser, &id, STRONG).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        let note = &rec.ctx.node_messages[0];
        assert_eq!(
            (note.node.as_str(), note.message.id),
            ("password", 4_000_005)
        );
        assert!(note.message.text.contains("data breaches"));
        assert_eq!(counts(&db).await, (0, 0));

        let done = step_two(&backend, &browser, &id, "another fine phrase").await;
        assert!(
            session_cookie(&done).is_some(),
            "an unlisted password passes"
        );
    }

    #[tokio::test]
    async fn step_one_checks_the_address() {
        let (_, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        let long = format!("{}@x.test", "a".repeat(320));
        for (email, message) in [
            ("", 4_000_002),
            ("not-an-address", 4_000_001),
            (long.as_str(), 4_000_001),
        ] {
            step_one(&backend, &browser, &id, email).await;
            assert_eq!(
                messages(&backend, &id).await.1,
                [("traits.email".to_string(), message)],
                "{email}"
            );
            assert!(!on_step_two(&backend, &id).await);
        }
        let done = step_two(&backend, &browser, &id, STRONG).await;
        assert_eq!(
            done.outcome,
            SubmitOutcome::Page,
            "no step 2 without step 1"
        );
        assert!(session_cookie(&done).is_none());
        assert_eq!(messages(&backend, &id).await.0, [4_040_002]);
        assert_eq!(counts(&backend.db).await, (0, 0));
        submit(
            &backend,
            &browser,
            FlowKind::Registration,
            &id,
            &[("traits.email", "a@x.test")],
        )
        .await;
        assert_eq!(messages(&backend, &id).await.0, [4_040_002]);
    }

    #[tokio::test]
    async fn step_one_refuses_addresses_a_mail_provider_could_read_as_another_recipient() {
        let (_, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        for email in [
            "x<victim@corp.com>",
            "a@x.test,victim@corp.com",
            "a@x.test;b@x.test",
            "\"a b\"@x.test",
            "a@[127.0.0.1]",
            "a\u{7}@x.test",
        ] {
            step_one(&backend, &browser, &id, email).await;
            assert_eq!(
                messages(&backend, &id).await.1,
                [("traits.email".to_string(), 4_000_001)],
                "{email:?}"
            );
            assert!(!on_step_two(&backend, &id).await);
        }
        assert!(
            store::create(&backend.db, "x<victim@corp.com>", None, None, true)
                .await
                .is_err(),
            "the store refuses it too"
        );
    }

    /// Make every insert into `table` (matching `when`) fail.
    async fn break_inserts(db: &DbPool, table: &'static str, when: &'static str) {
        crate::identity_native::test_support::sql(db, move |c| {
            diesel::sql_query(format!(
                "CREATE TRIGGER broken BEFORE INSERT ON {table} {when} BEGIN SELECT RAISE(ABORT, 'broken'); END"
            ))
            .execute(c)
        })
        .await;
    }

    async fn audit_of_created(done: &Submitted) -> String {
        let audit = audit_lines(done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("identity.created"), "{}", audit[0]);
        audit[0].clone()
    }

    #[tokio::test]
    async fn a_mail_that_cannot_be_queued_still_signs_in_audits_and_shows_verification() {
        let (db, backend) = setup().await;
        break_inserts(&db, "identity_mail_outbox", "").await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "nomail@x.test").await;
        let done = step_two(&backend, &browser, &id, STRONG).await;
        audit_of_created(&done).await;
        assert!(session_cookie(&done).is_some());
        let SubmitOutcome::Redirect { location, .. } = &done.outcome else {
            panic!("redirected");
        };
        let verification = location
            .strip_prefix("/verification?flow=")
            .expect("to the verification screen")
            .to_string();
        assert_eq!(counts(&db).await, (1, 1));
        assert!(backend.mailed("nomail@x.test").await.is_empty());

        crate::identity_native::test_support::sql(&db, |c| {
            diesel::sql_query("DROP TRIGGER broken").execute(c)
        })
        .await;
        submit(
            &backend,
            &browser,
            FlowKind::Verification,
            &verification,
            &[("method", "code"), ("email", "nomail@x.test")],
        )
        .await;
        assert_eq!(
            backend.mailed("nomail@x.test").await.len(),
            1,
            "resend mails a code"
        );
    }

    #[tokio::test]
    async fn without_a_verification_flow_the_new_account_is_audited_and_sent_to_login() {
        let (db, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "noflow@x.test").await;
        break_inserts(&db, "identity_flows", "WHEN NEW.kind = 'verification'").await;
        let done = step_two(&backend, &browser, &id, STRONG).await;
        let line = audit_of_created(&done).await;
        assert!(!line.contains(STRONG));
        let SubmitOutcome::Redirect { location, .. } = &done.outcome else {
            panic!("redirected");
        };
        assert_eq!(location, "/login");
        assert!(session_cookie(&done).is_some(), "still signed in");
        assert_eq!(counts(&db).await, (1, 1));
    }

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;

    use crate::identity_native::store::keys;
    use crate::identity_native::test_authenticator::Authenticator;
    use crate::identity_native::test_support::{sql, totp_code};
    use crate::identity_native::totp;
    use crate::schema::{identity_sessions, identity_webauthn_keys};

    const ORIGIN: &str = "http://localhost:3000";
    const RP_ID: &str = "localhost";

    async fn key_count(db: &DbPool) -> i64 {
        sql(db, |c| identity_webauthn_keys::table.count().get_result(c)).await
    }

    async fn page_of(
        backend: &NativeBackend,
        browser: &Browser,
        kind: FlowKind,
        id: &str,
    ) -> crate::flow_view::Flow {
        let FlowFetch::Ok(flow) = backend.get_flow(kind, id, &browser.cookie()).await.unwrap()
        else {
            panic!("{kind:?} flow {id} is readable");
        };
        *flow
    }

    /// The options the page shows in the node `name`; rendering mints them.
    async fn shown(
        backend: &NativeBackend,
        browser: &Browser,
        kind: FlowKind,
        id: &str,
        name: &str,
    ) -> Value {
        let flow = page_of(backend, browser, kind, id).await;
        let value = flow
            .inputs
            .iter()
            .find(|(_, i)| i.name == name)
            .map(|(_, i)| i.value.clone())
            .unwrap_or_else(|| panic!("{name} shown"));
        serde_json::from_str(&value).unwrap()
    }

    /// Post a registration `response` as `static/webauthn.js` does: the whole form, no button.
    async fn passkey_post(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        response: &str,
        extra: &[(&str, &str)],
    ) -> Submitted {
        let mut fields = vec![
            ("traits.email", "ignored@x.test"),
            ("passkey_register", response),
        ];
        fields.extend_from_slice(extra);
        submit(backend, browser, FlowKind::Registration, id, &fields).await
    }

    /// Answer step 2's passkey options with `token` and post the response; the options too.
    async fn passkey_step(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        token: &mut Authenticator,
    ) -> (Value, Submitted) {
        let options = shown(
            backend,
            browser,
            FlowKind::Registration,
            id,
            "passkey_create_data",
        )
        .await;
        let response = token.register(RP_ID, ORIGIN, &options).to_string();
        let done = passkey_post(backend, browser, id, &response, &[("password", "")]).await;
        (options, done)
    }

    fn verification_of(done: &Submitted) -> String {
        let SubmitOutcome::Redirect { location, .. } = &done.outcome else {
            panic!("redirected");
        };
        location
            .strip_prefix("/verification?flow=")
            .expect("to the verification screen")
            .to_string()
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

    async fn whoami(backend: &NativeBackend, browser: &Browser) -> WhoamiOutcome {
        backend.whoami(Some(&browser.cookie())).await.unwrap()
    }

    #[tokio::test]
    async fn a_passkey_sign_up_creates_the_account_with_the_sealed_user_handle() {
        let (db, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "Pk@X.test").await;
        let mut token = Authenticator::passkey();
        let (options, done) = passkey_step(&backend, &browser, &id, &mut token).await;
        let verification = verification_of(&done);
        let cookie = session_cookie(&done).expect("signed in");
        let signed_in = Browser {
            csrf: browser.csrf.clone(),
            session: Some(cookie.clone()),
        };
        let WhoamiOutcome::Ok(session) = whoami(&backend, &signed_in).await else {
            panic!("the new session is live");
        };
        let identity = session.identity.clone().unwrap();
        let handle = options["publicKey"]["user"]["id"].as_str().unwrap();
        let user = uuid::Uuid::from_slice(&URL_SAFE_NO_PAD.decode(handle).unwrap()).unwrap();
        assert_eq!(identity.id, user.to_string(), "the user handle is the id");
        assert_eq!(identity.traits.as_ref().unwrap()["email"], "Pk@X.test");
        assert!(!identity.verifiable_addresses.as_ref().unwrap()[0].verified);
        let credentials = identity.credentials.unwrap();
        assert!(credentials.contains_key("passkey") && !credentials.contains_key("password"));
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal1));
        assert_eq!(method_names(&session), ["passkey"]);

        let rows = keys::of_identity(&db, &identity.id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].kind.as_str(), rows[0].display_name.as_str()),
            ("passkey", "Passkey")
        );
        assert_eq!(
            rows[0].credential_id,
            URL_SAFE_NO_PAD.encode(&token.credential_id)
        );
        assert_eq!(counts(&db).await, (1, 0), "no password credential");

        let rec = backend.load_flow(&verification).await.unwrap().unwrap();
        assert_eq!(rec.row.state, "sent_email");
        assert_eq!(rec.ctx.email.as_deref(), Some("Pk@X.test"));
        assert_eq!(backend.mailed("Pk@X.test").await.len(), 1);

        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("identity.created"), "{}", audit[0]);
        assert!(audit[0].contains(r#"String("passkey")"#), "{}", audit[0]);
        assert!(audit[0].contains(&identity.id));
        let challenge = options["publicKey"]["challenge"].as_str().unwrap();
        for material in [rows[0].credential_id.as_str(), challenge, handle, &cookie] {
            assert!(!audit[0].contains(material), "{}", audit[0]);
        }
    }

    #[tokio::test]
    async fn a_passkey_sign_up_with_a_taken_address_answers_as_a_password_one_and_stores_nothing() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "taken@x.test", true).await;
        let mut answers = Vec::new();
        for passkey in [false, true] {
            let browser = Browser::new();
            let id = begin(&backend, &browser, None).await;
            step_one(&backend, &browser, &id, "TAKEN@x.test").await;
            let done = if passkey {
                passkey_step(&backend, &browser, &id, &mut Authenticator::passkey())
                    .await
                    .1
            } else {
                step_two(&backend, &browser, &id, STRONG).await
            };
            assert_eq!(done.outcome, SubmitOutcome::Page);
            assert!(session_cookie(&done).is_none() && done.audit.is_empty());
            answers.push((
                messages(&backend, &id).await,
                on_step_two(&backend, &id).await,
            ));
        }
        assert_eq!(answers[0], answers[1]);
        assert_eq!(answers[1], ((vec![4_000_007], Vec::new()), false));
        assert_eq!(counts(&db).await, (1, 1));
        assert_eq!(key_count(&db).await, 0);
        assert!(backend.mailed("TAKEN@x.test").await.is_empty());
    }

    #[tokio::test]
    async fn a_passkey_sign_up_needs_step_one_and_a_fresh_ceremony_and_wins_over_a_password() {
        let (db, backend) = setup().await;
        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        let done = passkey_post(&backend, &browser, &id, "{}", &[]).await;
        assert_eq!(done.outcome, SubmitOutcome::Page, "not before step 1");
        assert_eq!(messages(&backend, &id).await.0, [4_040_002]);

        step_one(&backend, &browser, &id, "fresh@x.test").await;
        let mut token = Authenticator::passkey();
        let spent = shown(
            &backend,
            &browser,
            FlowKind::Registration,
            &id,
            "passkey_create_data",
        )
        .await;
        let elsewhere = token
            .register(RP_ID, "http://evil.test", &spent)
            .to_string();
        passkey_post(&backend, &browser, &id, &elsewhere, &[]).await;
        assert_eq!(messages(&backend, &id).await.0, [4_040_002], "wrong origin");
        assert!(on_step_two(&backend, &id).await);

        let replayed = token.register(RP_ID, ORIGIN, &spent).to_string();
        passkey_post(&backend, &browser, &id, &replayed, &[]).await;
        assert_eq!(messages(&backend, &id).await.0, [4_040_002], "spent");
        passkey_post(&backend, &browser, &id, "not json", &[]).await;
        assert_eq!(messages(&backend, &id).await.0, [4_040_002]);
        assert_eq!((counts(&db).await, key_count(&db).await), ((0, 0), 0));

        let options = shown(
            &backend,
            &browser,
            FlowKind::Registration,
            &id,
            "passkey_create_data",
        )
        .await;
        assert_ne!(
            options["publicKey"]["challenge"],
            spent["publicKey"]["challenge"]
        );
        let response = token.register(RP_ID, ORIGIN, &options).to_string();
        let both = [("method", "password"), ("password", STRONG)];
        let done = passkey_post(&backend, &browser, &id, &response, &both).await;
        let cookie = session_cookie(&done).expect("signed in");
        let WhoamiOutcome::Ok(session) = backend
            .whoami(Some(&format!("forseti_session={cookie}")))
            .await
            .unwrap()
        else {
            panic!("live");
        };
        assert_eq!(method_names(&session), ["passkey"]);
        assert_eq!(
            (counts(&db).await, key_count(&db).await),
            ((1, 0), 1),
            "the password is ignored"
        );
    }

    #[tokio::test]
    async fn a_passkey_registered_already_creates_nothing() {
        let (db, backend) = setup().await;
        let mut token = Authenticator::passkey();
        let first = Browser::new();
        let id = begin(&backend, &first, None).await;
        step_one(&backend, &first, &id, "first@x.test").await;
        assert!(session_cookie(&passkey_step(&backend, &first, &id, &mut token).await.1).is_some());

        let browser = Browser::new();
        let id = begin(&backend, &browser, None).await;
        step_one(&backend, &browser, &id, "second@x.test").await;
        let done = passkey_step(&backend, &browser, &id, &mut token).await.1;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(session_cookie(&done).is_none() && done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [4_040_002]);
        assert!(on_step_two(&backend, &id).await, "the address was fine");
        assert_eq!((counts(&db).await, key_count(&db).await), ((1, 0), 1));
        assert!(backend.mailed("second@x.test").await.is_empty());

        let taken = store::row_by_email(&db, "first@x.test")
            .await
            .unwrap()
            .unwrap()
            .id;
        let rp = backend.webauthn.as_ref().unwrap();
        let user = uuid::Uuid::parse_str(&taken).unwrap();
        let (options, state) = rp.start_passkey_registration(user, "p", "p", None).unwrap();
        let response = Authenticator::passkey().register(
            RP_ID,
            ORIGIN,
            &crate::identity_native::webauthn::passkey_options(&options),
        );
        let passkey = rp
            .finish_passkey_registration(&serde_json::from_value(response).unwrap(), &state)
            .unwrap();
        let credential = FirstCredential::Passkey {
            user,
            key: Box::new(NewKey {
                display_name: PASSKEY_NAME.to_string(),
                key: Key::Passkey(passkey),
            }),
        };
        assert!(matches!(
            store::create_with_first_credential(&db, "third@x.test", None, None, credential)
                .await
                .unwrap(),
            CreateWithCredential::KeyTaken
        ));
        assert_eq!(
            (counts(&db).await, key_count(&db).await),
            ((1, 0), 1),
            "a user handle that is an identity id already"
        );
    }

    /// Answer the login page's passkey options with `token` and post the response.
    async fn passkey_login(
        backend: &NativeBackend,
        browser: &Browser,
        id: &str,
        token: &mut Authenticator,
    ) -> Submitted {
        let options = shown(backend, browser, FlowKind::Login, id, "passkey_challenge").await;
        let response = token.assert(RP_ID, ORIGIN, &options).to_string();
        submit(
            backend,
            browser,
            FlowKind::Login,
            id,
            &[
                ("identifier", ""),
                ("password", ""),
                ("passkey_login", &response),
            ],
        )
        .await
    }

    #[tokio::test]
    async fn a_passkey_only_account_verifies_signs_in_reauthenticates_adds_totp_and_recovers() {
        let (db, backend) = setup().await;
        let email = "only@x.test";
        let mut token = Authenticator::passkey();
        let registering = Browser::new();
        let id = begin(&backend, &registering, None).await;
        step_one(&backend, &registering, &id, email).await;
        let done = passkey_step(&backend, &registering, &id, &mut token)
            .await
            .1;
        let verification = verification_of(&done);
        let registered = Browser {
            csrf: registering.csrf.clone(),
            session: session_cookie(&done),
        };
        let code = backend.mailed(email).await[0].code.clone();
        submit(
            &backend,
            &registered,
            FlowKind::Verification,
            &verification,
            &[("method", "code"), ("code", &code)],
        )
        .await;
        let row = store::row_by_email(&db, email).await.unwrap().unwrap();
        assert!(row.first_verified_at.is_some(), "verified");
        let identity = row.id;

        let mut browser = Browser::new();
        let login = start(&backend, &browser, FlowKind::Login, InitParams::default()).await;
        let done = passkey_login(&backend, &browser, &login, &mut token).await;
        browser.session = Some(session_cookie(&done).expect("signed in with the passkey"));
        let WhoamiOutcome::Ok(session) = whoami(&backend, &browser).await else {
            panic!("live");
        };
        assert_eq!(session.identity.as_ref().unwrap().id, identity);
        assert_eq!(method_names(&session), ["passkey"]);

        let old = "2026-01-01T00:00:00.000000+00:00";
        let session_id = session.id.clone();
        sql(&db, move |c| {
            diesel::update(identity_sessions::table.find(&session_id))
                .set(identity_sessions::authenticated_at.eq(old))
                .execute(c)
        })
        .await;
        let two_fa = "http://localhost:3000/settings/2fa";
        let refresh = start(
            &backend,
            &browser,
            FlowKind::Login,
            InitParams {
                return_to: Some(two_fa),
                aal2: false,
                refresh: true,
            },
        )
        .await;
        let done = passkey_login(&backend, &browser, &refresh, &mut token).await;
        let SubmitOutcome::Redirect { location, .. } = &done.outcome else {
            panic!("re-authenticated");
        };
        assert_eq!(location, two_fa);
        let WhoamiOutcome::Ok(refreshed) = whoami(&backend, &browser).await else {
            panic!("the same token stays live");
        };
        assert_eq!(refreshed.id, session.id);
        assert!(refreshed.authenticated_at.as_deref().unwrap() > old);

        let params = InitParams {
            return_to: Some(two_fa),
            ..InitParams::default()
        };
        let settings = start(&backend, &browser, FlowKind::Settings, params).await;
        let page = page_of(&backend, &browser, FlowKind::Settings, &settings).await;
        let b32 = page.totp_secret.expect("a pending TOTP secret");
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &b32).unwrap();
        let now = totp::unix_now();
        let done = submit(
            &backend,
            &browser,
            FlowKind::Settings,
            &settings,
            &[("method", "totp"), ("totp_code", &totp_code(&secret, now))],
        )
        .await;
        assert!(audit_lines(&done)[0].contains("mfa.totp.enrolled"));
        browser.session = Some(session_cookie(&done).expect("raised to AAL2"));
        let WhoamiOutcome::Ok(raised) = whoami(&backend, &browser).await else {
            panic!("live");
        };
        assert_eq!(raised.authenticator_assurance_level, Some(Aal::Aal2));

        let lost = Browser::new();
        let recovery = start(&backend, &lost, FlowKind::Recovery, InitParams::default()).await;
        submit(
            &backend,
            &lost,
            FlowKind::Recovery,
            &recovery,
            &[("method", "code"), ("email", email)],
        )
        .await;
        let code = backend.mailed(email).await.last().unwrap().code.clone();
        let done = submit(
            &backend,
            &lost,
            FlowKind::Recovery,
            &recovery,
            &[("method", "code"), ("code", &code)],
        )
        .await;
        assert!(audit_lines(&done)[0].contains("password.recovered"));
        let SubmitOutcome::Redirect { location, .. } = &done.outcome else {
            panic!("recovered");
        };
        let handoff = location
            .strip_prefix("/settings?flow=")
            .expect("to the settings handoff")
            .to_string();
        let mut lost = Browser {
            csrf: lost.csrf.clone(),
            session: session_cookie(&done),
        };
        assert!(matches!(
            whoami(&backend, &lost).await,
            WhoamiOutcome::InsufficientAal
        ));
        let aal2 = start(
            &backend,
            &lost,
            FlowKind::Login,
            InitParams {
                aal2: true,
                ..InitParams::default()
            },
        )
        .await;
        let next = totp_code(&secret, now + totp::STEP_SECS);
        let done = submit(
            &backend,
            &lost,
            FlowKind::Login,
            &aal2,
            &[("method", "totp"), ("totp_code", &next)],
        )
        .await;
        lost.session = Some(session_cookie(&done).expect("the recovery session at AAL2"));
        let page = page_of(&backend, &lost, FlowKind::Settings, &handoff).await;
        assert!(page.recovery_handoff && page.has_node("password", "password"));
        let done = submit(
            &backend,
            &lost,
            FlowKind::Settings,
            &handoff,
            &[("method", "password"), ("password", STRONG)],
        )
        .await;
        assert!(audit_lines(&done)[0].contains("password.changed"));

        let fresh = Browser::new();
        let login = start(&backend, &fresh, FlowKind::Login, InitParams::default()).await;
        let done = submit(
            &backend,
            &fresh,
            FlowKind::Login,
            &login,
            &[
                ("method", "password"),
                ("identifier", email),
                ("password", STRONG),
            ],
        )
        .await;
        assert!(session_cookie(&done).is_some(), "the new password signs in");
        let fresh = Browser::new();
        let login = start(&backend, &fresh, FlowKind::Login, InitParams::default()).await;
        let done = passkey_login(&backend, &fresh, &login, &mut token).await;
        assert!(
            session_cookie(&done).is_some(),
            "the passkey still signs in"
        );
        assert_eq!(key_count(&db).await, 1);
    }
}
