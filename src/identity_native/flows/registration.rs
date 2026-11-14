//! Registration submits: traits on step 1, a password on step 2, then the account, a session and
//! the verification screen.

use anyhow::Result;

use super::verification::{address_problem, too_long};
use super::{FlowRecord, Form, PendingTraits, Submission, SubmitOutcome, Submitted};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::Aal;
use crate::identity_native::NativeBackend;
use crate::identity_native::codes::Purpose;
use crate::identity_native::password::{self, HashError, PasswordConfig, PolicyError};
use crate::identity_native::session::Issued;
use crate::identity_native::store::{self, IdentityRow};
use crate::identity_native::ui::Message;

const NAME_MAX_CHARS: usize = 256;

const ACCOUNT_EXISTS: (u64, &str) = (
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
    page(backend, s.flow).await
}

/// What [`finish`] managed to set up for a new account.
struct Created {
    session: Option<Issued>,
    verification_flow: Option<String>,
}

/// Step 2: the password, then the account in one transaction, a session, and a verification flow
/// with its code mailed.
async fn credential(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    let traits = s.flow.ctx.traits.clone();
    let Some(traits) = traits.filter(|_| s.flow.ctx.credential_step) else {
        s.flow
            .add_message(Message::error(NO_STRATEGY.0, NO_STRATEGY.1));
        return page(backend, s.flow).await;
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
    let first = Some(traits.first.as_str()).filter(|f| !f.is_empty());
    let last = Some(traits.last.as_str()).filter(|l| !l.is_empty());
    let Some(row) =
        store::create_with_password(&backend.db, &traits.email, first, last, &config).await?
    else {
        s.flow.ctx.credential_step = false;
        s.flow
            .add_message(Message::error(ACCOUNT_EXISTS.0, ACCOUNT_EXISTS.1));
        return page(backend, s.flow).await;
    };
    // The account exists from here on: every later step is best effort, so the audit row and a
    // response are given even when one fails.
    if let Err(e) = s.flow.finish(&backend.db).await {
        tracing::error!(error = ?e, flow_id = %s.flow.row.id, "registration flow not marked finished");
    }
    let created = finish(backend, &s, &row).await;
    let event = AuditEvent::new(action::IDENTITY_CREATED)
        .actor_user(&row.id, &row.email)
        .target(target_kind::IDENTITY, &row.id)
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => s.flow.row.id,
            "kratos_session_id" => created.session.as_ref().map(|i| i.id.clone()),
            "method" => "password",
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
async fn finish(backend: &NativeBackend, s: &Submission<'_>, row: &IdentityRow) -> Created {
    let session = backend
        .issue_session(&row.id, "password", Aal::Aal1, s.device)
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
}
