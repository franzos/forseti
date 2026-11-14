//! Verification submits: an address asks for a code, a code verifies the address.

use anyhow::{Result, anyhow};
use serde_json::json;

use super::{FlowRecord, SAVE_ATTEMPTS, Saved, Submission, SubmitOutcome, Submitted};
use crate::audit::{AuditEvent, action, target_kind};
use crate::backend::identity::FlowKind;
use crate::identity_native::NativeBackend;
use crate::identity_native::codes::Purpose;
use crate::identity_native::store;
use crate::identity_native::ui::Message;

/// Kratos's message for a wrong, used, expired or exhausted code.
const INVALID_CODE: (u64, &str) = (
    4_070_006,
    "The verification code is invalid or has already been used. Please try again.",
);

pub(super) async fn submit(backend: &NativeBackend, mut s: Submission<'_>) -> Result<Submitted> {
    s.flow.clear_messages();
    if s.flow.row.state == "passed_challenge" {
        return page(backend, s.flow).await;
    }
    let code = s.form.get("code").map(str::trim).unwrap_or_default();
    let email = s.form.get("email").map(str::trim).unwrap_or_default();
    if !code.is_empty() {
        return check_code(backend, s.flow, code).await;
    }
    if let Some(problem) = address_problem(email) {
        s.flow.add_node_message("email", problem);
        return page(backend, s.flow).await;
    }
    request_code(backend, &mut s.flow, email, Purpose::Verification).await?;
    page(backend, s.flow).await
}

/// Kratos's "Property {property} is missing." under the input.
pub(super) fn missing(property: &str) -> Message {
    Message::error(4_000_002, format!("Property {property} is missing."))
        .with_context(json!({ "property": property }))
}

/// Kratos's schema message for a missing, over-long or malformed address. Characters that let a
/// mail provider read the address as something else are refused here too.
pub(super) fn address_problem(email: &str) -> Option<Message> {
    let len = email.chars().count();
    if email.is_empty() {
        Some(missing("email"))
    } else if len > store::EMAIL_MAX_CHARS {
        Some(too_long(store::EMAIL_MAX_CHARS, len))
    } else if !store::is_mailable(email) {
        Some(Message::error(
            4_000_001,
            format!("{email:?} is not valid \"email\""),
        ))
    } else {
        None
    }
}

/// Kratos's pass-through validation message for an over-long value.
pub(super) fn too_long(max: usize, actual: usize) -> Message {
    Message::error(
        4_000_001,
        format!("length must be <= {max}, but got {actual}"),
    )
}

/// Save and show the flow; a concurrent change shows that change instead.
pub(super) async fn page(backend: &NativeBackend, mut flow: FlowRecord) -> Result<Submitted> {
    let _ = flow.save(&backend.db).await?;
    Ok(SubmitOutcome::Page.into())
}

/// Move the flow to `sent_email` for `email` and mail a code when the address belongs to an
/// active identity that can use it (for verification, one whose address is not verified yet) and
/// the address is under its mail quota. Every address gets the same answer. A request that mails
/// nothing retires the flow's earlier code, so a code never outlives the address shown with it.
pub(super) async fn request_code(
    backend: &NativeBackend,
    flow: &mut FlowRecord,
    email: &str,
    purpose: Purpose,
) -> Result<()> {
    flow.ctx.email = Some(email.to_string());
    flow.set_state("sent_email");
    let wanted = |row: &store::IdentityRow| {
        store::is_active(row) && (purpose == Purpose::Recovery || row.email_verified_at.is_none())
    };
    let target = if backend.limiters.recipient.admit(&store::address_key(email)) {
        store::row_by_email(&backend.db, email)
            .await?
            .filter(wanted)
    } else {
        None
    };
    match target {
        Some(row) => {
            backend
                .send_code(&flow.row.id, purpose, &row.id, &row.email)
                .await
        }
        None => backend.retire_code(&flow.row.id, purpose).await,
    }
}

async fn check_code(
    backend: &NativeBackend,
    mut flow: FlowRecord,
    code: &str,
) -> Result<Submitted> {
    let used = backend
        .use_code(&flow.row.id, Purpose::Verification, code)
        .await?;
    let verified = match used {
        Some(used) => store::mark_verified(&backend.db, &used.identity_id, &used.address).await?,
        None => None,
    };
    let Some(row) = verified else {
        flow.add_message(Message::error(INVALID_CODE.0, INVALID_CODE.1));
        return page(backend, flow).await;
    };
    let flow_id = flow.row.id.clone();
    passed(backend, flow).await?;
    let event = AuditEvent::new(action::VERIFICATION_COMPLETED)
        .actor_user(&row.id, &row.email)
        .target(target_kind::IDENTITY, &row.id)
        .metadata(crate::audit_metadata!(
            "source" => "native",
            "flow_id" => flow_id,
        ));
    Ok(Submitted::new(SubmitOutcome::Page, vec![event]))
}

/// The address is verified whatever else changed on the flow, so the state lands even when the
/// first save lost a race.
async fn passed(backend: &NativeBackend, mut flow: FlowRecord) -> Result<()> {
    for _ in 0..SAVE_ATTEMPTS {
        flow.clear_messages();
        flow.set_state("passed_challenge");
        if flow.save(&backend.db).await? == Saved::Done {
            return Ok(());
        }
        flow = backend
            .load_flow(&flow.row.id)
            .await?
            .ok_or_else(|| anyhow!("verification flow {} disappeared", flow.row.id))?;
    }
    Err(anyhow!("verification flow {} kept changing", flow.row.id))
}

/// `verify_known_email`: the signed-in browser's flow at `choose_method` asks for a code for the
/// session's address, as an email submit would.
pub(super) async fn request_for_known(
    backend: &NativeBackend,
    flow_id: &str,
    email: &str,
) -> Result<()> {
    let mut flow = backend
        .load_flow(flow_id)
        .await?
        .ok_or_else(|| anyhow!("verification flow {flow_id} not found"))?;
    if flow.kind() != Some(FlowKind::Verification)
        || flow.is_expired()
        || flow.row.state != "choose_method"
    {
        return Err(anyhow!("flow {flow_id} is not a fresh verification flow"));
    }
    flow.clear_messages();
    request_code(backend, &mut flow, email, Purpose::Verification).await?;
    match flow.save(&backend.db).await? {
        Saved::Done => Ok(()),
        Saved::Changed => Err(anyhow!("verification flow {flow_id} changed concurrently")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use diesel::prelude::*;

    use super::super::InitParams;
    use super::*;
    use crate::backend::IdentityBackend;
    use crate::backend::identity::FlowFetch;
    use crate::db::DbPool;
    use crate::identity_native::codes::CODE_ATTEMPTS;
    use crate::identity_native::test_support::{
        Browser, audit_lines, identity_with_password, messages, start, submit,
    };
    use crate::schema::{identities, identity_codes};

    async fn setup() -> (DbPool, Arc<NativeBackend>) {
        let db = crate::db::test_pool().await;
        let backend = NativeBackend::for_test(&db);
        (db, backend)
    }

    async fn flow(backend: &NativeBackend, browser: &Browser) -> String {
        start(
            backend,
            browser,
            FlowKind::Verification,
            InitParams::default(),
        )
        .await
    }

    async fn ask(backend: &NativeBackend, browser: &Browser, id: &str, email: &str) -> Submitted {
        submit(
            backend,
            browser,
            FlowKind::Verification,
            id,
            &[("method", "code"), ("email", email)],
        )
        .await
    }

    async fn enter(backend: &NativeBackend, browser: &Browser, id: &str, code: &str) -> Submitted {
        submit(
            backend,
            browser,
            FlowKind::Verification,
            id,
            &[("method", "code"), ("code", code)],
        )
        .await
    }

    async fn state(backend: &NativeBackend, id: &str) -> String {
        backend.load_flow(id).await.unwrap().unwrap().row.state
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
        let run = async {
            Ok::<i32, anyhow::Error>(crate::db_interact!(db, |c| {
                identity_codes::table
                    .filter(identity_codes::flow_id.eq(&flow_id))
                    .select(identity_codes::attempts)
                    .first(c)
            })?)
        };
        run.await.unwrap()
    }

    fn other(code: &str) -> String {
        let n: u32 = code.parse().unwrap();
        format!("{:06}", (n + 1) % 1_000_000)
    }

    #[tokio::test]
    async fn a_mailed_code_verifies_the_address_and_a_wrong_one_counts_an_attempt() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "Ver@X.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        let done = ask(&backend, &browser, &id, " ver@x.TEST ").await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(state(&backend, &id).await, "sent_email");
        let mail = backend.mailed("Ver@X.test").await;
        assert_eq!(mail.len(), 1, "sent to the stored address");
        let code = mail[0].code.clone();
        assert_eq!(code.len(), 6);
        assert_eq!(
            mail[0].subject,
            format!("Use code {code} to verify your account")
        );
        assert!(
            mail[0]
                .body
                .contains(&format!("verification?flow={id}&code={code}"))
        );

        let done = enter(&backend, &browser, &id, &other(&code)).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert!(done.audit.is_empty());
        assert_eq!(messages(&backend, &id).await.0, [4_070_006]);
        assert_eq!(attempts(&db, &id).await, 1);
        assert!(!verified(&db, "ver@x.test").await);

        let done = enter(&backend, &browser, &id, &format!(" {code} ")).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(state(&backend, &id).await, "passed_challenge");
        assert!(messages(&backend, &id).await.0.is_empty());
        assert!(verified(&db, "ver@x.test").await);
        let audit = audit_lines(&done);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].contains("verification.completed"), "{}", audit[0]);
        assert!(!audit[0].contains(&code));

        let FlowFetch::Ok(page) = backend
            .get_flow(FlowKind::Verification, &id, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        assert_eq!(page.state, "passed_challenge");
        assert!(page.has_node("code", "continue"));
        assert_eq!(page.messages[0].id, 1_080_002);

        let done = enter(&backend, &browser, &id, &code).await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(
            state(&backend, &id).await,
            "passed_challenge",
            "nothing to redo"
        );
    }

    #[tokio::test]
    async fn unknown_verified_and_pending_addresses_get_the_same_answer() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "done@x.test", true).await;
        identity_with_password(&db, "pending@x.test", false).await;
        let mut answers = Vec::new();
        for email in ["nobody@x.test", "done@x.test", "pending@x.test"] {
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
        assert!(backend.mailed("done@x.test").await.is_empty());
        assert_eq!(backend.mailed("pending@x.test").await.len(), 1);
        let codes: i64 = {
            let run = async {
                Ok::<i64, anyhow::Error>(crate::db_interact!(db, |c| {
                    identity_codes::table.count().get_result(c)
                })?)
            };
            run.await.unwrap()
        };
        assert_eq!(codes, 1, "only the pending address got a code");
    }

    #[tokio::test]
    async fn after_five_guesses_even_the_right_code_fails() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "guess@x.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "guess@x.test").await;
        let code = backend.mailed("guess@x.test").await[0].code.clone();
        for _ in 0..CODE_ATTEMPTS {
            enter(&backend, &browser, &id, &other(&code)).await;
        }
        assert_eq!(attempts(&db, &id).await, CODE_ATTEMPTS);
        enter(&backend, &browser, &id, &code).await;
        assert_eq!(messages(&backend, &id).await.0, [4_070_006]);
        assert_eq!(state(&backend, &id).await, "sent_email");
        assert!(!verified(&db, "guess@x.test").await);
    }

    #[tokio::test]
    async fn an_expired_code_fails() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "late@x.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "late@x.test").await;
        let code = backend.mailed("late@x.test").await[0].code.clone();
        let flow_id = id.clone();
        let run = async {
            Ok::<usize, anyhow::Error>(crate::db_interact!(db, |c| {
                diesel::update(identity_codes::table.filter(identity_codes::flow_id.eq(&flow_id)))
                    .set(identity_codes::expires_at.eq("2020-01-01T00:00:00.000000+00:00"))
                    .execute(c)
            })?)
        };
        assert_eq!(run.await.unwrap(), 1);
        enter(&backend, &browser, &id, &code).await;
        assert_eq!(messages(&backend, &id).await.0, [4_070_006]);
        assert!(!verified(&db, "late@x.test").await);
    }

    #[tokio::test]
    async fn a_resend_retires_the_earlier_code() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "again@x.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "again@x.test").await;
        // The resend button posts the address it carries next to the hidden method.
        ask(&backend, &browser, &id, "again@x.test").await;
        let mail = backend.mailed("again@x.test").await;
        assert_eq!(mail.len(), 2);
        let (old, new) = (mail[0].code.clone(), mail[1].code.clone());
        if old != new {
            enter(&backend, &browser, &id, &old).await;
            assert_eq!(messages(&backend, &id).await.0, [4_070_006]);
            assert!(!verified(&db, "again@x.test").await);
        }
        enter(&backend, &browser, &id, &new).await;
        assert!(verified(&db, "again@x.test").await);
    }

    #[tokio::test]
    async fn the_recipient_quota_keeps_the_neutral_answer_and_sends_nothing() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "busy@x.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        for _ in 0..crate::identity_native::RECIPIENT_MAILS {
            ask(&backend, &browser, &id, "busy@x.test").await;
        }
        assert_eq!(backend.mailed("busy@x.test").await.len(), 5);
        let other = Browser::new();
        let next = flow(&backend, &other).await;
        let done = ask(&backend, &other, &next, "BUSY@x.test").await;
        assert_eq!(done.outcome, SubmitOutcome::Page);
        assert_eq!(state(&backend, &next).await, "sent_email");
        assert_eq!(messages(&backend, &next).await, (vec![], vec![]));
        assert_eq!(
            backend.mailed("busy@x.test").await.len(),
            5,
            "no sixth mail"
        );
    }

    #[tokio::test]
    async fn a_submit_without_code_or_address_asks_for_the_address() {
        let (_, backend) = setup().await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        submit(
            &backend,
            &browser,
            FlowKind::Verification,
            &id,
            &[("method", "code")],
        )
        .await;
        assert_eq!(
            messages(&backend, &id).await.1,
            [("email".to_string(), 4_000_002)]
        );
        assert_eq!(state(&backend, &id).await, "choose_method");
    }

    /// Move the identity to `email` without going through settings, so its codes survive.
    async fn readdress(db: &DbPool, identity: &str, email: &'static str) {
        let identity = identity.to_string();
        let run = async {
            Ok::<usize, anyhow::Error>(crate::db_interact!(db, |c| {
                diesel::update(identities::table.find(&identity))
                    .set((
                        identities::email.eq(email),
                        identities::email_norm.eq(email),
                    ))
                    .execute(c)
            })?)
        };
        run.await.unwrap();
    }

    #[tokio::test]
    async fn a_code_for_an_address_since_changed_verifies_nothing() {
        let (db, backend) = setup().await;
        let attacker = identity_with_password(&db, "mine@x.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "mine@x.test").await;
        let code = backend.mailed("mine@x.test").await[0].code.clone();

        readdress(&db, &attacker, "victim@x.test").await;
        let mut rec = backend.load_flow(&id).await.unwrap().unwrap();
        rec.ctx.email = Some("victim@x.test".into());
        assert_eq!(rec.save(&db).await.unwrap(), Saved::Done);
        enter(&backend, &browser, &id, &code).await;
        assert_eq!(
            messages(&backend, &id).await.0,
            [4_070_006],
            "the code verifies the address it was mailed to, not the one the flow shows"
        );
        assert!(!verified(&db, "victim@x.test").await);
    }

    #[tokio::test]
    async fn an_address_request_that_mails_nothing_retires_the_flows_code() {
        let (db, backend) = setup().await;
        let attacker = identity_with_password(&db, "mine@x.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        ask(&backend, &browser, &id, "mine@x.test").await;
        let code = backend.mailed("mine@x.test").await[0].code.clone();

        readdress(&db, &attacker, "victim@x.test").await;
        for _ in 0..crate::identity_native::RECIPIENT_MAILS {
            let other = Browser::new();
            let next = flow(&backend, &other).await;
            ask(&backend, &other, &next, "victim@x.test").await;
        }
        let mailed = backend.mailed("victim@x.test").await.len();
        ask(&backend, &browser, &id, "victim@x.test").await;
        assert_eq!(
            backend.mailed("victim@x.test").await.len(),
            mailed,
            "over the quota"
        );
        assert_eq!(attempts_left(&db, &id).await, None, "the old code is gone");
        enter(&backend, &browser, &id, &code).await;
        assert_eq!(messages(&backend, &id).await.0, [4_070_006]);
        assert!(!verified(&db, "victim@x.test").await);
    }

    async fn attempts_left(db: &DbPool, flow_id: &str) -> Option<i32> {
        let flow_id = flow_id.to_string();
        let run = async {
            Ok::<Option<i32>, anyhow::Error>(crate::db_interact!(db, |c| {
                identity_codes::table
                    .filter(identity_codes::flow_id.eq(&flow_id))
                    .select(identity_codes::attempts)
                    .first(c)
                    .optional()
            })?)
        };
        run.await.unwrap().map(|used| CODE_ATTEMPTS - used)
    }

    #[tokio::test]
    async fn an_over_long_address_is_refused_and_counts_nothing() {
        let (_, backend) = setup().await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        let long = format!("{}@x.test", "a".repeat(320));
        ask(&backend, &browser, &id, &long).await;
        assert_eq!(
            messages(&backend, &id).await.1,
            [("email".to_string(), 4_000_001)]
        );
        let rec = backend.load_flow(&id).await.unwrap().unwrap();
        assert_eq!(rec.row.state, "choose_method");
        assert_eq!(rec.ctx.email, None);
    }

    #[tokio::test]
    async fn verify_known_email_moves_a_fresh_flow_to_code_entry() {
        let (db, backend) = setup().await;
        identity_with_password(&db, "known@x.test", false).await;
        let browser = Browser::new();
        let id = flow(&backend, &browser).await;
        let FlowFetch::Ok(page) = backend
            .get_flow(FlowKind::Verification, &id, &browser.cookie())
            .await
            .unwrap()
        else {
            panic!("readable");
        };
        backend
            .verify_known_email(&page, "known@x.test", &browser.cookie())
            .await
            .unwrap();
        assert_eq!(state(&backend, &id).await, "sent_email");
        assert_eq!(backend.mailed("known@x.test").await.len(), 1);
        assert!(
            backend
                .verify_known_email(&page, "known@x.test", &browser.cookie())
                .await
                .is_err(),
            "only from choose_method"
        );
        assert_eq!(backend.mailed("known@x.test").await.len(), 1);
    }
}
