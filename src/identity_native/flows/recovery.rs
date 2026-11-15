//! Recovery submits: an address asks for a code, a code signs the identity in and hands over to
//! the password page. Also the admin-minted code, on a flow the first browser to submit on it
//! takes.

use anyhow::{Result, anyhow};

use super::verification::{address_problem, page, request_code};
use super::{AfterEffect, Context, FlowRecord, Saved, Submission, SubmitOutcome, Submitted};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::{Aal, FlowInit, FlowKind, RecoveryCode, browser_init_url};
use crate::identity_native::codes::{Purpose, UsedCode};
use crate::identity_native::session::{self, Device, Issued};
use crate::identity_native::store::{self, IdentityRow};
use crate::identity_native::ui::Message;
use crate::identity_native::{NativeBackend, errors};

/// Kratos's message for a wrong, used, expired or exhausted recovery code.
const INVALID_CODE: (u64, &str) = (
    4_060_006,
    "The recovery code is invalid or has already been used. Please try again.",
);

pub(super) async fn submit(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    s.flow.clear_messages();
    let code = s.form.get("code").map(str::trim).unwrap_or_default();
    let email = s.form.get("email").map(str::trim).unwrap_or_default();
    if !code.is_empty() {
        return check_code(backend, s.flow, code, s.device).await;
    }
    if let Some(problem) = address_problem(email) {
        s.flow.add_node_message("email", problem);
        return page(backend, s.flow).await;
    }
    // A mailed code proves the mailbox even on a flow an admin started.
    s.flow.ctx.admin_code = false;
    request_code(backend, &mut s.flow, email, Purpose::Recovery).await?;
    page(backend, s.flow).await
}

async fn check_code(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    code: &str,
    device: Device<'_>,
) -> Result<Submitted> {
    let used = backend
        .use_code(&flow.row.id, Purpose::Recovery, code)
        .await?;
    let recovered = match used {
        Some(used) => recovered_identity(backend, &flow, &used).await?,
        None => None,
    };
    let Some((row, reset)) = recovered else {
        flow.add_message(Message::error(INVALID_CODE.0, INVALID_CODE.1));
        return page(backend, flow).await;
    };
    let after = reset.map(|_| AfterEffect::AccountReset {
        identity_id: row.id.clone(),
    });
    let issued = match finish_and_issue(backend, &mut flow, &row, device).await {
        Ok(issued) => issued,
        // The reset is stored, so its audit row and OAuth after-effect must still go out.
        Err(e) if reset.is_some() => {
            tracing::error!(error = ?e, flow_id = %flow.row.id, "recovery session not issued after reset");
            None
        }
        Err(e) => return Err(e),
    };
    let event = recovered_event(&row, &flow.row.id, issued.as_ref(), reset);
    let Some(issued) = issued else {
        return Ok(Submitted {
            outcome: SubmitOutcome::Redirect {
                location: errors::url(errors::FLOW_EXPIRED),
                set_cookies: Vec::new(),
            },
            audit: reset.map(|_| event).into_iter().collect(),
            after,
        });
    };
    let location = match handoff(backend, &issued, &flow.row.id).await {
        Ok(settings) => format!("/settings?flow={}", crate::web::urlencode(&settings)),
        Err(e) => {
            // The session works without the handoff; the password page starts its own flow.
            tracing::error!(error = ?e, flow_id = %flow.row.id, "recovery handoff flow not created");
            "/settings/password".to_string()
        }
    };
    Ok(Submitted {
        outcome: SubmitOutcome::Redirect {
            location,
            set_cookies: vec![backend.session_set_cookie(&issued.token)],
        },
        audit: vec![event],
        after,
    })
}

/// Spend the flow and sign the identity in; `None` when the flow changed underneath.
async fn finish_and_issue(
    backend: &NativeBackend,
    flow: &mut FlowRecord,
    row: &IdentityRow,
    device: Device<'_>,
) -> Result<Option<Issued>> {
    if !flow.finish(&backend.db).await? {
        return Ok(None);
    }
    let issued = backend
        .issue_session(&row.id, "code_recovery", None, Aal::Aal1, device)
        .await?;
    Ok(Some(issued))
}

/// The `password.recovered` row; a reset adds what it removed.
fn recovered_event(
    row: &IdentityRow,
    flow_id: &str,
    issued: Option<&Issued>,
    reset: Option<store::Reset>,
) -> AuditEvent {
    let mut pairs = vec![
        ("source", serde_json::json!("native")),
        ("flow_id", serde_json::json!(flow_id)),
    ];
    if let Some(issued) = issued {
        pairs.push(("kratos_session_id", serde_json::json!(issued.id)));
    }
    if let Some(reset) = reset {
        pairs.extend([
            ("unverified_reset", serde_json::json!(true)),
            ("sessions_revoked", serde_json::json!(reset.sessions)),
            ("methods_removed", serde_json::json!(reset.credentials)),
            ("links_removed", serde_json::json!(reset.links)),
            (
                "offline_access_removed",
                serde_json::json!(reset.offline_secrets),
            ),
        ]);
    }
    AuditEvent::new(action::PASSWORD_RECOVERED)
        .actor_user(&row.id, &row.email)
        .target(target_kind::IDENTITY, &row.id)
        .metadata(crate::audit::SafeMetadata::from_pairs(&pairs))
}

/// The active identity a used code recovers, still holding the address the code was bound to,
/// and the reset done to it. A mailed code proved that mailbox, so the address is marked
/// verified, as Kratos does for self-service recovery codes, and a never-verified identity loses
/// whatever was set up on it before; an admin-minted code proved nothing and changes nothing.
async fn recovered_identity(
    backend: &NativeBackend,
    flow: &FlowRecord,
    used: &UsedCode,
) -> Result<Option<(IdentityRow, Option<store::Reset>)>> {
    let Some(identity_id) = used.identity_id.as_deref() else {
        return Ok(None);
    };
    let Some(row) = store::row_by_id(&backend.db, identity_id).await? else {
        return Ok(None);
    };
    if !store::is_active(&row) || row.email_norm != used.address {
        return Ok(None);
    }
    if flow.ctx.admin_code {
        return Ok(Some((row, None)));
    }
    store::verify_recovered(&backend.db, &row.id, &row.email).await
}

/// The settings flow a completed recovery hands over to, on the password page; its id.
async fn handoff(backend: &NativeBackend, issued: &Issued, recovery_flow: &str) -> Result<String> {
    let session = session::find_live(&backend.db, &issued.id)
        .await?
        .ok_or_else(|| anyhow!("recovery session {} is not live", issued.id))?;
    let request_url = format!(
        "{}/self-service/recovery?flow={}",
        backend.self_url,
        crate::web::urlencode(recovery_flow)
    );
    let settings = backend
        .create_settings_flow(&session, None, request_url, true)
        .await?;
    Ok(settings.row.id)
}

/// `admin_create_recovery_code`: an unbound recovery flow waiting for a code, the code (not
/// mailed), and the link to it; the first browser to submit on the flow takes it. Earlier
/// recovery codes of the identity stop working.
pub(super) async fn admin_code(backend: &NativeBackend, identity_id: &str) -> Result<RecoveryCode> {
    let row = store::row_by_id(&backend.db, identity_id)
        .await?
        .ok_or_else(|| anyhow!("identity {identity_id} not found"))?;
    if !store::is_active(&row) {
        anyhow::bail!("identity {identity_id} is inactive; activate it before issuing a code");
    }
    backend
        .retire_identity_codes(identity_id, Purpose::Recovery)
        .await?;
    let request_url = browser_init_url(&backend.self_url, FlowKind::Recovery, FlowInit::default());
    let ctx = Context {
        admin_code: true,
        ..Context::default()
    };
    let mut flow = backend
        .insert_flow(
            FlowKind::Recovery,
            None,
            None,
            None,
            false,
            None,
            request_url,
            ctx,
        )
        .await?;
    flow.set_state("sent_email");
    if flow.save(&backend.db).await? == Saved::Changed {
        anyhow::bail!(
            "new recovery flow {} changed before its first save",
            flow.row.id
        );
    }
    let code = backend
        .issue_code(&flow.row.id, Purpose::Recovery, &row.id, &row.email)
        .await?;
    Ok(RecoveryCode {
        recovery_code: code,
        recovery_link: format!(
            "{}/self-service/recovery?flow={}",
            backend.self_url,
            crate::web::urlencode(&flow.row.id)
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use diesel::prelude::*;

    use super::super::{AfterEffect, Dispatch, Form, InitParams};
    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::{FlowFetch, IdentityState, PrivilegedReason, WhoamiOutcome};
    use crate::db::DbPool;
    use crate::identity_native::codes::CODE_ATTEMPTS;
    use crate::identity_native::session::StepUp;
    use crate::identity_native::test_support::{
        Browser, DEVICE, PASSWORD, audit_lines, identity_with_password, messages,
        plant_lookup_codes, plant_totp, session_cookie, sql, start, submit,
    };
    use crate::schema::{identity_codes, identity_mail_outbox};

    const NEW_PASSWORD: &str = "violet staircase 42";

    async fn setup() -> (DbPool, Arc<NativeBackend>) {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        (db, backend)
    }

    async fn flow(backend: &NativeBackend, browser: &Browser) -> String {
        start(backend, browser, FlowKind::Recovery, InitParams::default()).await
    }

    async fn ask(backend: &NativeBackend, browser: &Browser, id: &str, email: &str) -> Submitted {
        submit(
            backend,
            browser,
            FlowKind::Recovery,
            id,
            &[("method", "code"), ("email", email)],
        )
        .await
    }

    async fn enter(backend: &NativeBackend, browser: &Browser, id: &str, code: &str) -> Submitted {
        submit(
            backend,
            browser,
            FlowKind::Recovery,
            id,
            &[("method", "code"), ("code", code)],
        )
        .await
    }

    async fn dispatch(
        backend: &NativeBackend,
        browser: &Browser,
        kind: FlowKind,
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
            .submit_flow(kind, id, &form, &browser.cookie(), true, DEVICE)
            .await
            .unwrap()
    }

    fn other(code: &str) -> String {
        let n: u32 = code.parse().unwrap();
        format!("{:06}", (n + 1) % 1_000_000)
    }

    fn location(done: &Submitted) -> &str {
        match &done.outcome {
            SubmitOutcome::Redirect { location, .. } => location,
            SubmitOutcome::Page => panic!("expected a redirect"),
        }
    }

    /// The browser after a successful code submit: signed in with the cookie it was given.
    fn signed_in(browser: &Browser, done: &Submitted) -> Browser {
        Browser {
            csrf: browser.csrf.clone(),
            session: Some(session_cookie(done).expect("a session cookie")),
        }
    }

    fn handoff_id(done: &Submitted) -> String {
        location(done)
            .strip_prefix("/settings?flow=")
            .expect("to the settings handoff")
            .to_string()
    }

    async fn settings_page(backend: &NativeBackend, browser: &Browser, id: &str) -> FlowFetch {
        backend
            .get_flow(FlowKind::Settings, id, &browser.cookie())
            .await
            .unwrap()
    }

    async fn verified(db: &DbPool, email: &str) -> bool {
        store::row_by_email(db, email)
            .await
            .unwrap()
            .unwrap()
            .email_verified_at
            .is_some()
    }

    async fn attempts(db: &DbPool, flow_id: &str) -> i32 {
        let flow_id = flow_id.to_string();
        sql(db, move |c| {
            identity_codes::table
                .filter(identity_codes::flow_id.eq(&flow_id))
                .select(identity_codes::attempts)
                .first(c)
        })
        .await
    }

    async fn outbox_rows(db: &DbPool) -> i64 {
        sql(db, |c| identity_mail_outbox::table.count().get_result(c)).await
    }

    /// A password sign-in through the login flow; the session cookie it set and the flow messages.
    async fn login(backend: &NativeBackend, email: &str, password: &str) -> (bool, Vec<u64>) {
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
        (
            session_cookie(&done).is_some(),
            messages(backend, &id).await.0,
        )
    }

    /// Recover `email` in a fresh browser: the browser, the recovery flow and the code submit.
    async fn recover(backend: &NativeBackend, email: &str) -> (Browser, String, Submitted) {
        let browser = Browser::new();
        let id = flow(backend, &browser).await;
        ask(backend, &browser, &id, email).await;
        let code = backend.mailed(email).await.last().unwrap().code.clone();
        let done = enter(backend, &browser, &id, &code).await;
        (browser, id, done)
    }

    #[tokio::test]
    async fn a_mailed_code_signs_in_and_hands_over_to_the_password_page() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "Lost@X.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        let done = ask(&backend, &browser, &id, " lost@x.TEST ").await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(rec.row.state, "sent_email");
        let mail = backend.mailed("Lost@X.test").await;
        assert_eq!(mail.len(), 1, "sent to the stored address");
        let code = mail[0].code.clone();
        assert_eq!(
            mail[0].subject,
            format!("Use code {code} to recover access to your account")
        );
        assert_eq!(mail[0].body, format!("{code}\n"), "the code only, no link");
        let FlowFetch::Ok(page) = backend
            .get_flow(FlowKind::Recovery, &id, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        assert_eq!(page.messages[0].id, 1_060_003);
        assert!(page.inputs("code").any(|i| i.name == "code"));

        let done = enter(&backend, &browser, &id, &other(&code)).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [4_060_006]);
        assert_eq!(attempts(&db, &id).await, 1);

        let done = enter(&backend, &browser, &id, &format!(" {code} ")).await;
        let settings = handoff_id(&done);
        let recovered = signed_in(&browser, &done);
        let WhoamiOutcome::Ok(session) = backend.whoami(Some(&recovered.cookie())).await.unwrap()
        else {
            panic!("the recovery session is live");
        };
        assert_eq!(session.authenticator_assurance_level, Some(Aal::Aal1));
        let methods = session.authentication_methods.clone().unwrap();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].method.as_deref(), Some("code_recovery"));
        assert_eq!(session.identity.unwrap().id, identity);
        assert!(
            verified(&db, "lost@x.test").await,
            "the code proved the mailbox"
        );

        let FlowFetch::Ok(handoff) = settings_page(&backend, &recovered, &settings).await else {
            panic!("the handoff flow is readable by the recovered session");
        };
        assert!(handoff.recovery_handoff);
        assert_eq!(handoff.messages[0].id, 1_060_001);
        assert!(handoff.has_node("password", "password"));
        let row = backend.load_flow(&settings).await.unwrap().unwrap().row;
        assert_eq!(row.session_id.as_deref(), Some(session.id.as_str()));
        assert!(row.request_url.contains("/self-service/recovery"));

        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("password.recovered"), "{}", audit[0]);
        assert!(audit[0].contains(&id) && audit[0].contains(&session.id));
        assert!(!audit[0].contains(&code));
        assert!(!audit[0].contains(recovered.session.as_deref().unwrap()));
    }

    #[tokio::test]
    async fn the_spent_flow_cannot_be_used_again() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "spent@x.test", true).await;
        let (browser, id, done) = recover(&backend, "spent@x.test").await;
        handoff_id(&done);
        let code = backend.mailed("spent@x.test").await[0].code.clone();
        let again = dispatch(
            &backend,
            &browser,
            FlowKind::Recovery,
            &id,
            &[("method", "code"), ("code", &code)],
        )
        .await;
        assert!(matches!(again, Dispatch::Expired), "{again:?}");
        let resend = dispatch(
            &backend,
            &browser,
            FlowKind::Recovery,
            &id,
            &[("method", "code"), ("email", "spent@x.test")],
        )
        .await;
        assert!(matches!(resend, Dispatch::Expired), "{resend:?}");
        assert!(matches!(
            backend
                .get_flow(FlowKind::Recovery, &id, &browser.cookie())
                .await
                .unwrap(),
            FlowFetch::Gone
        ));
        assert_eq!(backend.mailed("spent@x.test").await.len(), 1);
    }

    #[tokio::test]
    async fn another_browser_cannot_use_the_flow() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "mine@x.test", true).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "mine@x.test").await;
        let code = backend.mailed("mine@x.test").await[0].code.clone();
        let thief = Browser::new();
        let stolen = dispatch(
            &backend,
            &thief,
            FlowKind::Recovery,
            &id,
            &[("method", "code"), ("code", &code)],
        )
        .await;
        assert!(matches!(stolen, Dispatch::Forged), "{stolen:?}");
        assert!(matches!(
            backend
                .get_flow(FlowKind::Recovery, &id, &thief.cookie())
                .await
                .unwrap(),
            FlowFetch::Gone
        ));
        assert_eq!(attempts(&db, &id).await, 0, "the code was not touched");
        let done = enter(&backend, &browser, &id, &code).await;
        handoff_id(&done);
    }

    #[tokio::test]
    async fn unknown_inactive_and_active_addresses_get_the_same_answer() {
        let (db, backend) = setup().await;
        let inactive = identity_with_password(&db, "gone@x.test", true).await;
        store::set_state(&db, &inactive, IdentityState::Inactive)
            .await
            .unwrap();
        identity_with_password(&db, "here@x.test", false).await;
        let mut answers = Vec::new();
        for email in ["nobody@x.test", "gone@x.test", "here@x.test"] {
            let browser = Browser::new();
            let id = flow(&backend, &browser).await;
            let done = ask(&backend, &browser, &id, email).await;
            let rec = backend.load_flow(&id).await.unwrap().unwrap();
            answers.push((
                format!("{:?}", done.outcome),
                done.audit.len(),
                rec.row.state,
                rec.ctx.messages,
                rec.ctx.node_messages,
            ));
        }
        assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
        assert_eq!(answers[0].2, "sent_email");
        assert!(backend.mailed("nobody@x.test").await.is_empty());
        assert!(backend.mailed("gone@x.test").await.is_empty());
        assert_eq!(
            backend.mailed("here@x.test").await.len(),
            1,
            "an unverified address can recover"
        );
        let codes: i64 = sql(&db, |c| identity_codes::table.count().get_result(c)).await;
        assert_eq!(codes, 1);
    }

    #[tokio::test]
    async fn malformed_and_missing_addresses_are_refused_on_the_email_node() {
        let (_, backend) = setup().await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        let long = format!("{}@x.test", "a".repeat(320));
        for (email, message) in [
            ("", 4_000_002),
            ("x<victim@corp.com>", 4_000_001),
            (long.as_str(), 4_000_001),
        ] {
            ask(&backend, &browser, &id, email).await;
            assert_eq!(
                messages(&backend, &id).await.1,
                [("email".to_string(), message)],
                "{email:?}"
            );
            assert_eq!(
                backend.load_flow(&id).await.unwrap().unwrap().row.state,
                "choose_method"
            );
        }
    }

    #[tokio::test]
    async fn after_five_guesses_even_the_right_code_fails() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "guess@x.test", true).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "guess@x.test").await;
        let code = backend.mailed("guess@x.test").await[0].code.clone();
        for _ in 0..CODE_ATTEMPTS {
            enter(&backend, &browser, &id, &other(&code)).await;
        }
        let done = enter(&backend, &browser, &id, &code).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(session_cookie(&done).is_none());
        assert_eq!(messages(&backend, &id).await.0, [4_060_006]);
    }

    #[tokio::test]
    async fn an_expired_code_fails() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "late@x.test", true).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "late@x.test").await;
        let code = backend.mailed("late@x.test").await[0].code.clone();
        let flow_id = id.clone();
        sql(&db, move |c| {
            diesel::update(identity_codes::table.filter(identity_codes::flow_id.eq(&flow_id)))
                .set(identity_codes::expires_at.eq("2020-01-01T00:00:00.000000+00:00"))
                .execute(c)
        })
        .await;
        let done = enter(&backend, &browser, &id, &code).await;
        assert!(session_cookie(&done).is_none());
        assert_eq!(messages(&backend, &id).await.0, [4_060_006]);
    }

    #[tokio::test]
    async fn a_resend_supersedes_the_earlier_code() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "again@x.test", true).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "again@x.test").await;
        ask(&backend, &browser, &id, "again@x.test").await;
        let mail = backend.mailed("again@x.test").await;
        assert_eq!(mail.len(), 2);
        let (old, new) = (mail[0].code.clone(), mail[1].code.clone());
        if old != new {
            let done = enter(&backend, &browser, &id, &old).await;
            assert!(session_cookie(&done).is_none());
            assert_eq!(messages(&backend, &id).await.0, [4_060_006]);
        }
        let done = enter(&backend, &browser, &id, &new).await;
        handoff_id(&done);
    }

    #[tokio::test]
    async fn an_identity_disabled_after_the_mail_is_not_recovered() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "off@x.test", true).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "off@x.test").await;
        let code = backend.mailed("off@x.test").await[0].code.clone();
        store::set_state(&db, &identity, IdentityState::Inactive)
            .await
            .unwrap();
        let done = enter(&backend, &browser, &id, &code).await;
        assert!(session_cookie(&done).is_none() && done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [4_060_006]);
    }

    #[tokio::test]
    async fn the_handoff_sets_a_new_password_and_the_old_one_stops_working() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "reset@x.test", true).await;
        let other_session = backend
            .issue_session(&identity, "password", None, Aal::Aal1, DEVICE)
            .await
            .unwrap();
        let (browser, _, done) = recover(&backend, "reset@x.test").await;
        let settings = handoff_id(&done);
        let recovered = signed_in(&browser, &done);
        let changed = submit(
            &backend,
            &recovered,
            FlowKind::Settings,
            &settings,
            &[("method", "password"), ("password", NEW_PASSWORD)],
        )
        .await;
        assert_eq!(location(&changed), format!("/settings?flow={settings}"));
        assert!(audit_lines(&changed)[0].contains("password.changed"));
        let session_id = session::find_live_by_token(&db, recovered.session.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .id;
        assert_eq!(
            changed.after,
            Some(AfterEffect::PasswordChanged {
                identity_id: identity.clone(),
                session_id,
            })
        );
        let FlowFetch::Ok(page) = settings_page(&backend, &recovered, &settings).await else {
            panic!("readable");
        };
        assert_eq!(page.state, "success");
        assert!(page.recovery_handoff);

        assert_eq!(
            login(&backend, "reset@x.test", PASSWORD).await.1,
            [4_000_006]
        );
        assert!(login(&backend, "reset@x.test", NEW_PASSWORD).await.0);
        assert!(
            session::find_live(&db, &other_session.id)
                .await
                .unwrap()
                .is_some(),
            "other identity sessions stay, as with the configured Kratos"
        );
    }

    #[tokio::test]
    async fn recovery_does_not_skip_the_second_factor() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "2fa@x.test", true).await;
        plant_totp(&backend, &identity).await;
        let (browser, _, done) = recover(&backend, "2fa@x.test").await;
        let settings = handoff_id(&done);
        let recovered = signed_in(&browser, &done);
        assert!(matches!(
            backend.whoami(Some(&recovered.cookie())).await.unwrap(),
            WhoamiOutcome::InsufficientAal
        ));
        assert!(matches!(
            settings_page(&backend, &recovered, &settings).await,
            FlowFetch::PrivilegedRequired(PrivilegedReason::Aal2Required)
        ));
        let blocked = dispatch(
            &backend,
            &recovered,
            FlowKind::Settings,
            &settings,
            &[("method", "password"), ("password", NEW_PASSWORD)],
        )
        .await;
        let Dispatch::SignIn(to) = blocked else {
            panic!("the password form needs the second factor: {blocked:?}");
        };
        assert!(to.starts_with("/login?aal=aal2"), "{to}");
        assert!(login(&backend, "2fa@x.test", PASSWORD).await.0, "unchanged");

        let held = session::find_live_by_token(&db, recovered.session.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap();
        let StepUp::Rotated(token) = session::step_up(&db, &held, "totp", None, Aal::Aal2)
            .await
            .unwrap()
        else {
            panic!("a live session rotates");
        };
        let stepped = Browser {
            csrf: browser.csrf.clone(),
            session: Some(token),
        };
        let FlowFetch::Ok(page) = settings_page(&backend, &stepped, &settings).await else {
            panic!("the handoff flow survives the token rotation");
        };
        assert!(page.recovery_handoff);
        let changed = submit(
            &backend,
            &stepped,
            FlowKind::Settings,
            &settings,
            &[("method", "password"), ("password", NEW_PASSWORD)],
        )
        .await;
        assert!(audit_lines(&changed)[0].contains("password.changed"));
    }

    #[tokio::test]
    async fn an_admin_code_needs_no_mail_and_the_first_submitting_browser_keeps_the_flow() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "help@x.test", false).await;
        let minted = backend.admin_create_recovery_code(&identity).await.unwrap();
        assert_eq!(minted.recovery_code.len(), 6);
        let id = minted
            .recovery_link
            .strip_prefix("http://localhost:3000/self-service/recovery?flow=")
            .expect("a link to the hop")
            .to_string();
        let row = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(row.row.binding, None);
        assert_eq!(row.row.state, "sent_email");
        assert!(row.ctx.admin_code);
        assert_eq!(outbox_rows(&db).await, 0, "nothing is mailed");

        let first = Browser::new();
        let second = Browser::new();
        for reader in ["", second.cookie().as_str(), first.cookie().as_str()] {
            assert!(matches!(
                backend
                    .get_flow(FlowKind::Recovery, &id, reader)
                    .await
                    .unwrap(),
                FlowFetch::Ok(_)
            ));
        }
        assert_eq!(
            backend.load_flow(&id).await.unwrap().unwrap().row.binding,
            None,
            "reading binds nothing"
        );

        let wrong = enter(&backend, &first, &id, &other(&minted.recovery_code)).await;
        assert!(session_cookie(&wrong).is_none());
        assert_eq!(attempts(&db, &id).await, 1);
        assert_eq!(messages(&backend, &id).await.0, [4_060_006]);
        assert!(
            backend
                .load_flow(&id)
                .await
                .unwrap()
                .unwrap()
                .row
                .binding
                .is_some()
        );

        let late = dispatch(
            &backend,
            &second,
            FlowKind::Recovery,
            &id,
            &[("method", "code"), ("code", &minted.recovery_code)],
        )
        .await;
        assert!(matches!(late, Dispatch::Expired), "{late:?}");
        assert_eq!(attempts(&db, &id).await, 1, "the code was not touched");

        let done = enter(&backend, &first, &id, &minted.recovery_code).await;
        let settings = handoff_id(&done);
        let recovered = signed_in(&first, &done);
        assert!(matches!(
            settings_page(&backend, &recovered, &settings).await,
            FlowFetch::Ok(_)
        ));
        assert!(audit_lines(&done)[0].contains("password.recovered"));
        assert!(
            !verified(&db, "help@x.test").await,
            "an admin code proves no mailbox"
        );
        assert!(backend.admin_create_recovery_code("missing").await.is_err());
    }

    #[tokio::test]
    async fn an_unbound_flow_needs_a_valid_csrf_token_to_be_taken() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "csrf@x.test", true).await;
        let minted = backend.admin_create_recovery_code(&identity).await.unwrap();
        let id = minted
            .recovery_link
            .rsplit("flow=")
            .next()
            .unwrap()
            .to_string();
        let browser = Browser::new();
        let form = Form(vec![
            ("method".to_string(), "code".to_string()),
            ("code".to_string(), minted.recovery_code.clone()),
        ]);
        let forged = backend
            .submit_flow(
                FlowKind::Recovery,
                &id,
                &form,
                &browser.cookie(),
                false,
                DEVICE,
            )
            .await
            .unwrap();
        assert!(matches!(forged, Dispatch::Forged), "{forged:?}");
        assert_eq!(
            backend.load_flow(&id).await.unwrap().unwrap().row.binding,
            None
        );
        let cookieless = backend
            .submit_flow(FlowKind::Recovery, &id, &form, "", true, DEVICE)
            .await
            .unwrap();
        assert!(matches!(cookieless, Dispatch::Expired), "{cookieless:?}");
        assert_eq!(attempts(&db, &id).await, 0);
        handoff_id(&enter(&backend, &browser, &id, &minted.recovery_code).await);
    }

    #[tokio::test]
    async fn an_admin_code_is_refused_for_an_inactive_identity() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "off-admin@x.test", true).await;
        store::set_state(&db, &identity, IdentityState::Inactive)
            .await
            .unwrap();
        let err = backend
            .admin_create_recovery_code(&identity)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("inactive"), "{err}");
        let flows: i64 = sql(&db, |c| {
            crate::schema::identity_flows::table.count().get_result(c)
        })
        .await;
        assert_eq!(flows, 0, "no flow or code is left behind");
    }

    /// What a squatter can have set up on an account: a password, TOTP, lookup codes, a provider
    /// link with its first-seen row, an offline passphrase and a signed-in browser. That browser.
    async fn squatted(backend: &NativeBackend, identity: &str) -> Browser {
        let id = identity.to_string();
        sql(&backend.db, move |c| {
            diesel::insert_into(crate::schema::offline_secrets::table)
                .values((
                    crate::schema::offline_secrets::identity_id.eq(&id),
                    crate::schema::offline_secrets::verifier.eq("v"),
                    crate::schema::offline_secrets::algo_version.eq(1),
                    crate::schema::offline_secrets::created_at.eq("2026-01-01T00:00:00Z"),
                    crate::schema::offline_secrets::updated_at.eq("2026-01-01T00:00:00Z"),
                ))
                .execute(c)
        })
        .await;
        plant_totp(backend, identity).await;
        plant_lookup_codes(backend, identity).await;
        assert_eq!(
            store::insert_link(&backend.db, identity, "github", identity)
                .await
                .unwrap(),
            store::LinkInserted::Linked
        );
        crate::settings::oidc_links_db::upsert_seen(&backend.db, identity, "github")
            .await
            .unwrap();
        let issued = backend
            .issue_session(identity, "password", None, Aal::Aal2, DEVICE)
            .await
            .unwrap();
        let browser = Browser {
            session: Some(issued.token),
            ..Browser::new()
        };
        assert!(signed_in_now(backend, &browser).await);
        browser
    }

    async fn signed_in_now(backend: &NativeBackend, browser: &Browser) -> bool {
        matches!(
            backend.whoami(Some(&browser.cookie())).await.unwrap(),
            WhoamiOutcome::Ok(_)
        )
    }

    /// Which of password, TOTP, lookup codes, a link, a first-seen row and an offline passphrase
    /// the identity still has.
    async fn left(backend: &NativeBackend, identity: &str) -> [bool; 6] {
        let db = &backend.db;
        let has = async |kind| {
            store::credential(db, identity, kind)
                .await
                .unwrap()
                .is_some()
        };
        [
            has("password").await,
            has("totp").await,
            has("lookup_secret").await,
            !store::links_of(db, identity).await.unwrap().is_empty(),
            !crate::settings::oidc_links_db::list_for_identity(db, identity)
                .await
                .unwrap()
                .is_empty(),
            {
                let id = identity.to_string();
                sql(db, move |c| {
                    crate::schema::offline_secrets::table
                        .find(&id)
                        .count()
                        .get_result::<i64>(c)
                })
                .await
                    == 1
            },
        ]
    }

    #[tokio::test]
    async fn a_mailed_code_resets_a_never_verified_account_before_signing_in() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "squat@x.test", false).await;
        let squatter = squatted(&backend, &identity).await;
        let minted = backend.admin_create_recovery_code(&identity).await.unwrap();

        let (browser, id, done) = recover(&backend, "squat@x.test").await;
        assert!(
            !signed_in_now(&backend, &squatter).await,
            "the earlier session ended"
        );
        assert_eq!(left(&backend, &identity).await, [false; 6]);
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert!(row.email_verified_at.is_some() && row.first_verified_at.is_some());
        assert_eq!(
            done.after,
            Some(AfterEffect::AccountReset {
                identity_id: identity.clone()
            })
        );
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        for part in [
            "password.recovered",
            "\"unverified_reset\": Bool(true)",
            "\"sessions_revoked\": Number(1)",
            "\"methods_removed\": Number(3)",
            "\"links_removed\": Number(1)",
            "\"offline_access_removed\": Number(1)",
            id.as_str(),
        ] {
            assert!(audit[0].contains(part), "{part}: {}", audit[0]);
        }

        let recovered = signed_in(&browser, &done);
        let WhoamiOutcome::Ok(session) = backend.whoami(Some(&recovered.cookie())).await.unwrap()
        else {
            panic!("the recovery session is live at AAL1, no second factor is left");
        };
        assert_eq!(session.identity.unwrap().id, identity);
        let live: i64 = {
            let identity = identity.clone();
            sql(&db, move |c| {
                crate::schema::identity_sessions::table
                    .filter(crate::schema::identity_sessions::identity_id.eq(&identity))
                    .filter(crate::schema::identity_sessions::revoked_at.is_null())
                    .count()
                    .get_result(c)
            })
            .await
        };
        assert_eq!(live, 1, "the recovery session is the only one");

        let admin_flow = minted.recovery_link.rsplit("flow=").next().unwrap();
        let stale = enter(&backend, &Browser::new(), admin_flow, &minted.recovery_code).await;
        assert!(
            session_cookie(&stale).is_none(),
            "the earlier admin code is gone"
        );
        assert_eq!(messages(&backend, admin_flow).await.0, [4_060_006]);

        let settings = handoff_id(&done);
        let FlowFetch::Ok(handoff) = settings_page(&backend, &recovered, &settings).await else {
            panic!("the handoff flow is readable");
        };
        assert!(handoff.has_node("password", "password"));
        let changed = submit(
            &backend,
            &recovered,
            FlowKind::Settings,
            &settings,
            &[("method", "password"), ("password", NEW_PASSWORD)],
        )
        .await;
        assert!(audit_lines(&changed)[0].contains("password.changed"));
        assert_eq!(
            login(&backend, "squat@x.test", PASSWORD).await.1,
            [4_000_006]
        );
        assert!(login(&backend, "squat@x.test", NEW_PASSWORD).await.0);

        let (_, _, again) = recover(&backend, "squat@x.test").await;
        assert_eq!(again.after, None, "a verified account is reset once");
        assert!(!audit_lines(&again)[0].contains("unverified_reset"));
        assert!(left(&backend, &identity).await[0], "the new password stays");
    }

    #[tokio::test]
    async fn a_reset_drops_a_pending_address_change() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "owner@x.test", false).await;
        let squatter = backend
            .issue_session(&identity, "password", None, Aal::Aal1, DEVICE)
            .await
            .unwrap();
        let change = backend.address_change_flow("squatter@x.test", &identity);
        let code = backend.mailed_code(
            &change.row.id,
            Purpose::Verification,
            &identity,
            "squatter@x.test",
        );
        let writer = store::Writer {
            identity_id: &identity,
            session_id: &squatter.id,
            verified_only: false,
        };
        let pending = store::AddressChange {
            email: "squatter@x.test".to_string(),
            verification: change.row.clone(),
            code,
        };
        assert_eq!(
            store::update_profile(&db, writer, None, None, Some(pending))
                .await
                .unwrap(),
            store::ProfileSaved::Saved
        );
        let mailed_code = backend.mailed("squatter@x.test").await[0].code.clone();

        let (browser, _, done) = recover(&backend, "owner@x.test").await;
        assert!(done.after.is_some(), "the reset ran");
        assert!(backend.load_flow(&change.row.id).await.unwrap().is_none());
        let owner = signed_in(&browser, &done);
        for fields in [
            vec![("method", "code"), ("email", "squatter@x.test")],
            vec![("method", "code"), ("code", mailed_code.as_str())],
        ] {
            let answer = dispatch(
                &backend,
                &owner,
                FlowKind::Verification,
                &change.row.id,
                &fields,
            )
            .await;
            assert!(matches!(answer, Dispatch::Expired), "{answer:?}");
        }
        assert_eq!(
            backend.mailed("squatter@x.test").await.len(),
            1,
            "no resend"
        );
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert_eq!(row.email, "owner@x.test");
        assert!(row.email_verified_at.is_some());
    }

    #[tokio::test]
    async fn an_admin_code_resets_nothing() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "admin-squat@x.test", false).await;
        let squatter = squatted(&backend, &identity).await;
        let minted = backend.admin_create_recovery_code(&identity).await.unwrap();
        let id = minted.recovery_link.rsplit("flow=").next().unwrap();
        let done = enter(&backend, &Browser::new(), id, &minted.recovery_code).await;
        handoff_id(&done);
        assert_eq!(done.after, None);
        assert!(!audit_lines(&done)[0].contains("unverified_reset"));
        assert!(signed_in_now(&backend, &squatter).await);
        assert_eq!(left(&backend, &identity).await, [true; 6]);
        let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
        assert!(row.email_verified_at.is_none() && row.first_verified_at.is_none());
    }

    #[tokio::test]
    async fn a_verified_account_resets_nothing_even_mid_email_change() {
        let (db, backend) = setup().await;
        let verified = identity_with_password(&db, "kept@x.test", true).await;
        let changing = identity_with_password(&db, "moved@x.test", true).await;
        {
            let changing = changing.clone();
            sql(&db, move |c| {
                diesel::update(crate::schema::identities::table.find(&changing))
                    .set(crate::schema::identities::email_verified_at.eq(None::<String>))
                    .execute(c)
            })
            .await;
        }
        for (identity, email) in [(verified, "kept@x.test"), (changing, "moved@x.test")] {
            let first = store::row_by_id(&db, &identity)
                .await
                .unwrap()
                .unwrap()
                .first_verified_at;
            assert!(first.is_some());
            let squatter = squatted(&backend, &identity).await;
            let (_, _, done) = recover(&backend, email).await;
            handoff_id(&done);
            assert_eq!(done.after, None, "{email}");
            assert!(!audit_lines(&done)[0].contains("unverified_reset"));
            assert!(signed_in_now(&backend, &squatter).await, "{email}");
            assert_eq!(left(&backend, &identity).await, [true; 6], "{email}");
            let row = store::row_by_id(&db, &identity).await.unwrap().unwrap();
            assert!(row.email_verified_at.is_some(), "{email}");
            assert_eq!(row.first_verified_at, first, "{email}");
        }
    }

    #[tokio::test]
    async fn a_new_admin_code_retires_the_earlier_ones() {
        let (db, backend) = setup().await;
        let identity = identity_with_password(&db, "twice@x.test", true).await;
        let old = backend.admin_create_recovery_code(&identity).await.unwrap();
        let old_id = old
            .recovery_link
            .rsplit("flow=")
            .next()
            .unwrap()
            .to_string();
        let new = backend.admin_create_recovery_code(&identity).await.unwrap();
        let new_id = new
            .recovery_link
            .rsplit("flow=")
            .next()
            .unwrap()
            .to_string();
        let browser = Browser::new();
        let stale = enter(&backend, &browser, &old_id, &old.recovery_code).await;
        assert!(session_cookie(&stale).is_none());
        assert_eq!(messages(&backend, &old_id).await.0, [4_060_006]);
        handoff_id(&enter(&backend, &Browser::new(), &new_id, &new.recovery_code).await);
    }
}
