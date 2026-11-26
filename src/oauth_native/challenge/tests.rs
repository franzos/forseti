use std::sync::Arc;

use super::*;
use crate::backend::OAuthBackend;
use crate::backend::oauth::{ConsentRequest, LoginRequest, OAuthClient};
use crate::oauth_native::challenge;
use crate::oauth_native::test_support::*;
use crate::oauth_native::test_support::{accept_consent, accept_login, resume, to_consent};

const FIXTURE_CLIENT: &str = include_str!("../../ory/fixtures/hydra/client.json");
const FIXTURE_LOGIN: &str = include_str!("../../ory/fixtures/hydra/login_request.json");
const FIXTURE_CONSENT: &str = include_str!("../../ory/fixtures/hydra/consent_request.json");

fn query_of(url: &str) -> String {
    url::Url::parse(url).unwrap().query().unwrap().to_string()
}

/// The Hydra fixtures' authorization request, replayed against the native server.
#[tokio::test]
async fn login_and_consent_requests_carry_what_the_hydra_fixtures_carry() {
    let o = backend().await;
    let fixture_client: OAuthClient = serde_json::from_str(FIXTURE_CLIENT).unwrap();
    o.create_client(fixture_client).await.unwrap();
    let hydra_login: LoginRequest = serde_json::from_str(FIXTURE_LOGIN).unwrap();
    let raw = query_of(&hydra_login.request_url);
    let s = start_raw(&o, &raw, None).await;

    let native = o.get_login_request(&s.challenge).await.unwrap();
    assert_eq!(
        native.request_url,
        format!("{}/oauth2/authorize?{raw}", o.issuer)
    );
    assert_eq!(native.requested_scope, hydra_login.requested_scope);
    assert_eq!(native.oidc_context, hydra_login.oidc_context);
    assert_eq!(native.skip, hydra_login.skip);
    assert_eq!(native.subject, hydra_login.subject);
    assert_eq!(native.client.client_id, hydra_login.client.client_id);
    assert_eq!(native.client.metadata, hydra_login.client.metadata);
    assert_eq!(
        native.client.redirect_uris,
        hydra_login.client.redirect_uris
    );
    let sid = native.session_id.clone().unwrap();
    assert!(uuid::Uuid::parse_str(&sid).is_ok(), "{sid}");

    let hydra_consent: ConsentRequest = serde_json::from_str(FIXTURE_CONSENT).unwrap();
    let consent = to_consent(&o, &s, "fixture-subject-1", true).await;
    let native = o.get_consent_request(&consent).await.unwrap();
    assert_eq!(
        native.request_url,
        Some(format!("{}/oauth2/authorize?{raw}", o.issuer))
    );
    assert_eq!(native.requested_scope, hydra_consent.requested_scope);
    assert_eq!(
        native.requested_access_token_audience,
        hydra_consent.requested_access_token_audience
    );
    assert_eq!(native.oidc_context, hydra_consent.oidc_context);
    assert_eq!(native.skip, hydra_consent.skip);
    assert_eq!(native.subject, hydra_consent.subject);
    assert_eq!(native.consent_request_id.as_deref(), Some(s.id.as_str()));
    assert_eq!(native.login_session_id, Some(sid));
    let client = native.client.unwrap();
    let hydra_client = hydra_consent.client.unwrap();
    assert_eq!(client.client_id, hydra_client.client_id);
    assert_eq!(client.skip_consent, hydra_client.skip_consent);
    assert_eq!(client.metadata, hydra_client.metadata);
}

#[tokio::test]
async fn login_accept_answers_with_a_resume_url_and_every_replay_is_refused() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    assert!(
        r.redirect_to.starts_with(&format!(
            "{}/oauth2/auth/resume/{}?verifier=",
            o.issuer, s.id
        )),
        "{}",
        r.redirect_to
    );
    let after = flow_state(&o.db, &s.id).await;
    assert_eq!(after.0, "login_accepted");

    let used = Some(ChallengeError::Used);
    assert_eq!(
        refusal(&accept_login(&o, &s, "alice", true).await.unwrap_err()),
        used
    );
    assert_eq!(
        refusal(&accept_login(&o, &s, "bob", true).await.unwrap_err()),
        used
    );
    let rejected = o
        .reject_login_request(&s.challenge, "access_denied", "x")
        .await;
    assert_eq!(refusal(&rejected.unwrap_err()), used);
    assert_eq!(
        refusal(&o.get_login_request(&s.challenge).await.unwrap_err()),
        used
    );
    assert_eq!(flow_state(&o.db, &s.id).await, after);
    assert_eq!(
        refusal(&o.get_login_request("unknown").await.unwrap_err()),
        Some(ChallengeError::Unknown)
    );
}

#[tokio::test]
async fn accept_after_reject_is_refused() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    o.reject_login_request(&s.challenge, "login_required", "The user is not signed in.")
        .await
        .unwrap();
    let after = flow_state(&o.db, &s.id).await;
    assert_eq!(after.0, "rejected");
    let e = accept_login(&o, &s, "alice", true).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Used));
    let e = o
        .reject_login_request(&s.challenge, "x", "y")
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Used));
    assert_eq!(flow_state(&o.db, &s.id).await, after);
}

#[tokio::test]
async fn an_expired_request_reads_as_unknown_and_takes_no_transition() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    expire_flow(&o.db, &s.id).await;
    let unknown = Some(ChallengeError::Unknown);
    assert_eq!(
        refusal(&o.get_login_request(&s.challenge).await.unwrap_err()),
        unknown
    );
    assert_eq!(
        refusal(&accept_login(&o, &s, "alice", true).await.unwrap_err()),
        unknown
    );
    let e = o
        .reject_login_request(&s.challenge, "x", "y")
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), unknown);
    assert_eq!(flow_state(&o.db, &s.id).await.0, "login");

    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    expire_flow(&o.db, &s.id).await;
    assert_eq!(
        refusal(&o.get_consent_request(&consent).await.unwrap_err()),
        unknown
    );
    let e = accept_consent(&o, &consent, &["openid"], &[], true)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), unknown);
    assert_eq!(flow_state(&o.db, &s.id).await.0, "consent");
}

#[tokio::test]
async fn consent_transitions_refuse_replays_and_early_calls() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    // Before the login is accepted there is no consent challenge; the login one is not one.
    let e = accept_consent(&o, &s.challenge, &["openid"], &[], true)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    let state = flow_state(&o.db, &s.id).await;
    let e = accept_consent(&o, &s.challenge, &["openid"], &[], true)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    assert_eq!(flow_state(&o.db, &s.id).await, state);

    let consent = match resume(&o, &s, &r).await.unwrap() {
        Resumed::Consent { challenge, .. } => challenge,
        other => panic!("{other:?}"),
    };
    let accepted = accept_consent(&o, &consent, &["openid"], &[], true)
        .await
        .unwrap();
    let after = flow_state(&o.db, &s.id).await;
    assert_eq!(after.0, "consent_accepted");
    let used = Some(ChallengeError::Used);
    let e = accept_consent(&o, &consent, &["openid", "email"], &[], true)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), used);
    let e = o
        .reject_consent_request(&consent, "access_denied", "x")
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), used);
    assert_eq!(
        refusal(&o.get_consent_request(&consent).await.unwrap_err()),
        used
    );
    assert_eq!(flow_state(&o.db, &s.id).await, after);
    assert_eq!(grant_count(&o.db, "alice").await, 1);
    assert!(matches!(
        resume(&o, &s, &accepted).await.unwrap(),
        Resumed::Code { .. }
    ));
}

#[tokio::test]
async fn a_verifier_is_consumed_once_and_only_by_the_bound_browser() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    let verifier = verifier_of(&r);
    let before = flow_state(&o.db, &s.id).await;

    let mut asked = None;
    let e = challenge::resume(&o.db, &s.id, &verifier, |id| {
        asked = Some(id.to_string());
        false
    })
    .await
    .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unbound));
    assert_eq!(asked.as_deref(), Some(s.id.as_str()));
    assert_eq!(flow_state(&o.db, &s.id).await, before);

    // A path naming another request is refused even when its binding is present.
    let other = start(&o, "app", "").await;
    let e = challenge::resume(&o.db, &other.id, &verifier, |_| true)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unbound));
    assert_eq!(flow_state(&o.db, &s.id).await, before);
    assert!(matches!(
        resume(&o, &s, &r).await.unwrap(),
        Resumed::Consent { .. }
    ));
    let (state, verifier_hash, _) = flow_state(&o.db, &s.id).await;
    assert_eq!((state.as_str(), verifier_hash), ("consent", None));
    let e = resume(&o, &s, &r).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    let e = challenge::resume(&o.db, &s.id, "never-issued", |_| true)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
}

#[tokio::test]
async fn resuming_twice_after_consent_issues_one_code() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    let r = accept_consent(&o, &consent, &["openid"], &[], true)
        .await
        .unwrap();
    assert!(matches!(
        resume(&o, &s, &r).await.unwrap(),
        Resumed::Code { .. }
    ));
    let e = resume(&o, &s, &r).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    assert_eq!(code_count(&o.db).await, 1);
    assert_eq!(flow_state(&o.db, &s.id).await.0, "done");
}

#[tokio::test]
async fn an_expired_verifier_is_refused() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    expire_flow(&o.db, &s.id).await;
    let e = resume(&o, &s, &r).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    assert_eq!(flow_state(&o.db, &s.id).await.0, "login_accepted");
}

#[tokio::test]
async fn a_remembered_login_accepts_only_its_own_subject() {
    let o = backend().await;
    register(&o, "app").await;
    let first = start(&o, "app", "").await;
    to_consent(&o, &first, "alice", true).await;
    let sid = sid_of(&o.db, &first.id).await;
    let session = sessions::find(&o.db, &sid).await.unwrap().unwrap();

    let s = start_raw(&o, &raw_query("app", ""), Some(&session)).await;
    let req = o.get_login_request(&s.challenge).await.unwrap();
    assert!(req.skip);
    assert_eq!(req.subject, "alice");
    assert_eq!(req.session_id.as_deref(), Some(sid.as_str()));
    let before = flow_state(&o.db, &s.id).await;
    for other in ["bob", ""] {
        let e = accept_login(&o, &s, other, true).await.unwrap_err();
        assert!(
            matches!(
                refusal(&e),
                Some(ChallengeError::SubjectMismatch | ChallengeError::EmptySubject)
            ),
            "{e}"
        );
        assert_eq!(flow_state(&o.db, &s.id).await, before);
    }
    accept_login(&o, &s, "alice", true).await.unwrap();
}

#[tokio::test]
async fn consent_accept_checks_the_grant_against_the_request() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    let before = flow_state(&o.db, &s.id).await;
    let many: Vec<String> = (0..21).map(|i| format!("https://r{i}.example")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    for (scope, audience, want) in [
        (
            &["openid", "profile"][..],
            &[][..],
            ChallengeError::ScopeNotRequested,
        ),
        (
            &["openid", "admin"][..],
            &[][..],
            ChallengeError::ScopeNotRequested,
        ),
        (&["email"][..], &[][..], ChallengeError::OpenidRequired),
        (&[][..], &[][..], ChallengeError::OpenidRequired),
        (&["openid"][..], &many[..], ChallengeError::AudienceTooLarge),
    ] {
        let e = accept_consent(&o, &consent, scope, audience, true)
            .await
            .unwrap_err();
        assert_eq!(refusal(&e), Some(want), "{scope:?}");
        assert_eq!(flow_state(&o.db, &s.id).await, before);
    }
    assert_eq!(grant_count(&o.db, "alice").await, 0);

    let r = accept_consent(
        &o,
        &consent,
        &["openid", "email", "openid"],
        &many[..20],
        true,
    )
    .await
    .unwrap();
    let code = match resume(&o, &s, &r).await.unwrap() {
        Resumed::Code { code, .. } => code,
        other => panic!("{other:?}"),
    };
    let row = code_row(&o.db, &code).await.unwrap();
    assert_eq!(row.2, r#"["openid","email"]"#);
    assert_eq!(
        serde_json::from_str::<Vec<String>>(&row.3).unwrap().len(),
        20
    );
}

#[tokio::test]
async fn rejected_requests_deliver_the_handlers_error() {
    let o = backend().await;
    register(&o, "app").await;

    let s = start(&o, "app", "&response_mode=form_post").await;
    let r = o
        .reject_login_request(&s.challenge, "login_required", "The user is not signed in.")
        .await
        .unwrap();
    match resume(&o, &s, &r).await.unwrap() {
        Resumed::Error {
            flow_id,
            delivery,
            error,
            description,
            nav,
        } => {
            assert_eq!(flow_id, s.id);
            assert_eq!(error, "login_required");
            assert_eq!(description, "The user is not signed in.");
            assert_eq!(nav, Navigation::Document);
            assert_eq!(delivery.redirect_uri, REDIRECT);
            assert_eq!(delivery.mode, ResponseMode::FormPost);
            assert_eq!(delivery.state.as_deref(), Some("xyz"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(flow_state(&o.db, &s.id).await.0, "done");
    assert!(resume(&o, &s, &r).await.is_err());

    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    let r = o
        .reject_consent_request(
            &consent,
            "access_denied",
            "The resource owner denied the request.",
        )
        .await
        .unwrap();
    match resume(&o, &s, &r).await.unwrap() {
        Resumed::Error { error, nav, .. } => {
            assert_eq!(error, "access_denied");
            assert_eq!(nav, Navigation::Redirect);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(grant_count(&o.db, "alice").await, 0);
    assert_eq!(code_count(&o.db).await, 0);
}

#[tokio::test]
async fn the_code_carries_the_request_and_the_login() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "&nonce=n-1").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    let r = accept_consent(&o, &consent, &["openid", "email"], &[API], true)
        .await
        .unwrap();
    let (delivery, code) = match resume(&o, &s, &r).await.unwrap() {
        Resumed::Code {
            flow_id,
            delivery,
            code,
        } => {
            assert_eq!(flow_id, s.id);
            (delivery, code)
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(delivery.redirect_uri, REDIRECT);
    assert_eq!(delivery.state.as_deref(), Some("xyz"));
    assert_eq!(code.len(), 43);
    let (grant_id, auth_time, scope, audience, family_id, expires_at) =
        code_row(&o.db, &code).await.unwrap();
    assert_eq!(grant_id, s.id);
    assert!(uuid::Uuid::parse_str(&family_id).is_ok());
    assert_eq!(scope, r#"["openid","email"]"#);
    assert_eq!(audience, format!(r#"["{API}"]"#));
    let ttl = crate::oauth_native::parse_time(&expires_at).unwrap()
        - crate::oauth_native::parse_time(&auth_time).unwrap();
    assert!((595..=600).contains(&ttl.num_seconds()), "{ttl}");
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn concurrent_accept_and_resume_each_win_once_on_postgres() {
    let setup = crate::db::test_postgres_pool().await;
    let o = backend_on(&setup).await;
    let client_id = format!("race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("subject-{}", uuid::Uuid::new_v4().simple());
    register(&o, &client_id).await;
    let s = start(&o, &client_id, "").await;

    let a = backend_on(&crate::db::test_postgres_pool().await).await;
    let b = backend_on(&crate::db::test_postgres_pool().await).await;
    let (ra, rb) = tokio::join!(
        accept_login(&a, &s, &subject, true),
        accept_login(&b, &s, &subject, true)
    );
    let accepted: Vec<RedirectTo> = [ra, rb].into_iter().filter_map(Result::ok).collect();

    let resumed = match accepted.first() {
        Some(r) => {
            let (xa, xb) = tokio::join!(resume(&a, &s, r), resume(&b, &s, r));
            [xa, xb].into_iter().filter(Result::is_ok).count()
        }
        None => 0,
    };
    let state = flow_state(&setup, &s.id).await.0;

    o.delete_client(&client_id).await.unwrap();
    o.revoke_login_sessions_for_subject(&subject).await.unwrap();
    assert_eq!(accepted.len(), 1);
    assert_eq!(resumed, 1);
    assert_eq!(state, "consent");
}

/// The row was read while live; the expiry passes before the conditional update runs.
#[tokio::test]
async fn a_resume_whose_request_expires_after_the_read_changes_nothing() {
    let o = backend().await;
    register(&o, "app").await;
    let stale = |verifier: String| {
        let o = o.clone();
        async move {
            let hash = token_hash(&verifier);
            let row = find(&o.db, Lookup::Verifier(hash.clone()))
                .await
                .unwrap()
                .unwrap();
            expire_flow(&o.db, &row.id).await;
            let before = flow_state(&o.db, &row.id).await;
            let result = match row.state.as_str() {
                LOGIN_ACCEPTED => super::to_consent(&o.db, row.clone(), hash).await,
                CONSENT_ACCEPTED => issue_code(&o.db, row.clone(), hash, Utc::now()).await,
                REJECTED => deliver_rejection(&o.db, row.clone(), hash).await,
                other => panic!("{other}"),
            };
            assert_eq!(refusal(&result.unwrap_err()), Some(ChallengeError::Used));
            assert_eq!(flow_state(&o.db, &row.id).await, before);
        }
    };

    let s = start(&o, "app", "").await;
    stale(verifier_of(
        &accept_login(&o, &s, "alice", true).await.unwrap(),
    ))
    .await;

    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    stale(verifier_of(
        &accept_consent(&o, &consent, &["openid"], &[], true)
            .await
            .unwrap(),
    ))
    .await;
    assert_eq!(code_count(&o.db).await, 0);

    let s = start(&o, "app", "").await;
    let r = o
        .reject_login_request(&s.challenge, "login_required", "x")
        .await
        .unwrap();
    stale(verifier_of(&r)).await;
}

/// The `skip` a fresh request of `client_id` for `subject` reports at consent.
async fn next_skip(o: &NativeOAuth, client_id: &str, subject: &str) -> Option<bool> {
    let s = start(o, client_id, "").await;
    let consent = to_consent(o, &s, subject, true).await;
    o.get_consent_request(&consent).await.unwrap().skip
}

async fn register_skip_consent(o: &NativeOAuth, id: &str, on: bool) {
    o.create_client(OAuthClient {
        skip_consent: Some(on),
        ..client(id)
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_automatic_accept_is_marked_and_never_lets_a_later_request_skip() {
    let o = backend().await;
    register_skip_consent(&o, "app", true).await;
    let id = finish_auto(&o, "app", "alice").await;
    assert_eq!(grant_flags(&o.db, &id).await, (1, 0, 1));
    assert_eq!(next_skip(&o, "app", "alice").await, Some(false));
    set_skip_consent(&o, "app", false).await;
    assert_eq!(next_skip(&o, "app", "alice").await, Some(false));

    let listed = o.list_consent_sessions_by_subject("alice").await.unwrap();
    assert!(
        listed
            .iter()
            .any(|s| s.consent_request_id.as_deref() == Some(id.as_str()))
    );
}

#[tokio::test]
async fn the_mark_follows_the_handlers_decision_not_the_client_at_accept() {
    let o = backend().await;
    // The handler chose the automatic path; the operator turns `skip_consent` off before accept.
    register_skip_consent(&o, "flipped-off", true).await;
    let s = start(&o, "flipped-off", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    set_skip_consent(&o, "flipped-off", false).await;
    accept_auto(&o, &consent).await;
    assert_eq!(grant_flags(&o.db, &s.id).await, (1, 0, 1));
    assert_eq!(next_skip(&o, "flipped-off", "alice").await, Some(false));

    // The user approved on the screen; the operator turns `skip_consent` on before accept.
    register_skip_consent(&o, "flipped-on", false).await;
    let s = start(&o, "flipped-on", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    set_skip_consent(&o, "flipped-on", true).await;
    accept_consent(&o, &consent, &["openid", "email"], &[API], true)
        .await
        .unwrap();
    assert_eq!(grant_flags(&o.db, &s.id).await, (1, 0, 0));
    assert_eq!(next_skip(&o, "flipped-on", "alice").await, Some(true));
}

#[tokio::test]
async fn a_user_approved_grant_keeps_skipping_after_automatic_ones() {
    let o = backend().await;
    register_skip_consent(&o, "app", false).await;
    let (confirmed, _) = finish(&o, "app", "bob", true).await;
    assert_eq!(grant_flags(&o.db, &confirmed).await, (1, 0, 0));
    set_skip_consent(&o, "app", true).await;
    let s = start(&o, "app", "&prompt=consent").await;
    let consent = to_consent(&o, &s, "bob", true).await;
    accept_auto(&o, &consent).await;
    assert_eq!(grant_flags(&o.db, &s.id).await, (1, 0, 1));
    set_skip_consent(&o, "app", false).await;
    assert_eq!(next_skip(&o, "app", "bob").await, Some(true));
}

#[tokio::test]
async fn an_automatic_accept_of_a_skipped_request_is_stored_skipped_not_auto() {
    let o = backend().await;
    register_skip_consent(&o, "app", true).await;
    finish(&o, "app", "alice", true).await;
    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    assert_eq!(
        o.get_consent_request(&consent).await.unwrap().skip,
        Some(true)
    );
    accept_auto(&o, &consent).await;
    assert_eq!(grant_flags(&o.db, &s.id).await, (1, 1, 0));
}

const SECRET: &[u8] = &[0x42; 32];
const FLOW_A: &str = "0b9a3c1e-6f2d-4e8a-9c3b-1d2e3f4a5b6c";
const FLOW_B: &str = "7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f";

/// The `name=value` a browser stores from a `Set-Cookie` line.
fn stored(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
}

fn jar(cookies: &[String]) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::COOKIE,
        cookies.join("; ").parse().unwrap(),
    );
    h
}

fn value_of(set_cookie: &str) -> String {
    stored(set_cookie).split_once('=').unwrap().1.to_string()
}

#[test]
fn a_binding_is_scoped_to_its_flows_resume_path() {
    let set = bind(SECRET, FLOW_A, true);
    assert!(set.starts_with("forseti_flow="), "{set}");
    let path = format!("Path=/oauth2/auth/resume/{FLOW_A}");
    for attr in [
        "HttpOnly",
        "SameSite=Lax",
        path.as_str(),
        "Secure",
        "Max-Age=1800",
    ] {
        assert!(set.contains(attr), "{attr}: {set}");
    }
    let headers = jar(&[stored(&set)]);
    assert!(is_bound(SECRET, &headers, FLOW_A));
    assert!(!is_bound(SECRET, &headers, FLOW_B), "A's value on B's path");
    assert!(!is_bound(&[0x43; 32], &headers, FLOW_A));
    assert!(!is_bound(SECRET, &jar(&[]), FLOW_A));

    let other_name = jar(&[format!("forseti_op={}", value_of(&set))]);
    assert!(!is_bound(SECRET, &other_name, FLOW_A));
}

#[test]
fn an_expired_binding_is_not_bound() {
    let path = resume_path(FLOW_A);
    let old = binding_cookie(&path, false).encode(
        SECRET,
        &[],
        unix_seconds_now() - FLOW_TTL_SECS.unsigned_abs() - 1,
    );
    assert!(!is_bound(
        SECRET,
        &jar(&[format!("forseti_flow={old}")]),
        FLOW_A
    ));
}

#[test]
fn any_valid_value_among_same_named_cookies_binds() {
    let set = bind(SECRET, FLOW_A, false);
    let junk = "forseti_flow=1.00.00".to_string();
    let other_flow = stored(&bind(SECRET, FLOW_B, false));
    let headers = jar(&[junk.clone(), other_flow, stored(&set), junk]);
    assert!(is_bound(SECRET, &headers, FLOW_A));
}

#[test]
fn unbind_clears_the_flows_cookie_on_its_path() {
    let clear = unbind(FLOW_A, true);
    assert!(clear.starts_with("forseti_flow=;"), "{clear}");
    let path = format!("Path=/oauth2/auth/resume/{FLOW_A}");
    for attr in [path.as_str(), "Secure", "Expires=Thu, 01 Jan 1970"] {
        assert!(clear.contains(attr), "{attr}: {clear}");
    }
}

// --- Device requests ---------------------------------------------------------------------

const DEV: &str = "dev";

async fn device_backend() -> Arc<NativeOAuth> {
    let o = backend().await;
    o.create_client(device_client(DEV, clients::AUTH_BASIC))
        .await
        .unwrap();
    o
}

/// A device request of [`DEV`] for `scope` and `alice`, login accepted and resumed: the device
/// code, the request and the consent challenge.
async fn device_consent_for(o: &NativeOAuth, scope: &[&str]) -> (String, Started, String) {
    let a = start_device(o, DEV, scope).await;
    let s = accept_device(o, &a.user_code).await.unwrap();
    let r = accept_login(o, &s, "alice", true).await.unwrap();
    let consent = match device_resume(o, &s, &r).await.unwrap() {
        Resumed::Consent {
            challenge,
            remembered,
        } => {
            assert_eq!(remembered, None, "a device request never sets forseti_op");
            challenge
        }
        other => panic!("{other:?}"),
    };
    (a.device_code, s, consent)
}

async fn device_consent(o: &NativeOAuth) -> (String, Started, String) {
    device_consent_for(o, &["openid", "offline_access"]).await
}

/// Resumes a device request with a binding predicate that must not be asked.
async fn device_resume(o: &NativeOAuth, s: &Started, r: &RedirectTo) -> anyhow::Result<Resumed> {
    challenge::resume(&o.db, &s.id, &verifier_of(r), |_| {
        panic!("a device request has no binding to check")
    })
    .await
}

#[tokio::test]
async fn a_device_request_goes_from_pending_to_accepted_to_approved() {
    let o = device_backend().await;
    let a = start_device(&o, DEV, &["openid", "offline_access"]).await;
    assert_eq!(device_row(&o.db, &a.device_code).await.0, "pending");
    let (device_expires_at, typed) = (
        device_row(&o.db, &a.device_code).await.2,
        a.user_code.to_lowercase().replace('-', ""),
    );

    let s = accept_device(&o, &typed).await.unwrap();
    let (status, flow_id, _) = device_row(&o.db, &a.device_code).await;
    assert_eq!(
        (status.as_str(), flow_id.as_deref()),
        ("accepted", Some(s.id.as_str()))
    );
    let row = find(&o.db, Lookup::Login(token_hash(&s.challenge)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.response_mode.as_str(), row.redirect_uri.as_str()),
        (DEVICE, "")
    );
    assert_eq!((row.code_challenge, row.nonce), (None, None));
    assert_eq!(row.client_id, DEV);
    assert_eq!(
        row.expires_at, device_expires_at,
        "the request ends with the device code"
    );
    let login = o.get_login_request(&s.challenge).await.unwrap();
    assert!(!login.skip);
    assert_eq!(login.subject, "");
    assert_eq!(login.request_url, format!("{}/oauth/device", o.issuer));
    assert_eq!(
        login.requested_scope,
        Some(strings(&["openid", "offline_access"]))
    );
    let sid = login.session_id.unwrap();

    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    let consent = match device_resume(&o, &s, &r).await.unwrap() {
        Resumed::Consent {
            challenge,
            remembered,
        } => {
            assert_eq!(remembered, None);
            challenge
        }
        other => panic!("{other:?}"),
    };
    let r = accept_consent(&o, &consent, &["openid"], &[], false)
        .await
        .unwrap();
    assert_eq!(device_row(&o.db, &a.device_code).await.0, "accepted");
    assert!(device_code_row(&o.db, &a.device_code).await.is_none());
    assert!(matches!(
        device_resume(&o, &s, &r).await.unwrap(),
        Resumed::Device { approved: true }
    ));
    assert_eq!(device_row(&o.db, &a.device_code).await.0, "approved");
    assert_eq!(flow_state(&o.db, &s.id).await.0, "done");

    let code = device_code_row(&o.db, &a.device_code).await.unwrap();
    assert_eq!(code.grant_id, s.id);
    assert_eq!(code.client_id, DEV);
    assert_eq!(code.subject, "alice");
    assert_eq!(
        code.session_id, sid,
        "the ID token's sid is the login session"
    );
    assert_eq!(code.redirect_uri, "");
    assert_eq!((&code.code_challenge, &code.nonce), (&None, &None));
    assert_eq!(code.scope, r#"["openid"]"#);
    assert!(code.expires_at <= device_expires_at, "{code:?}");
    assert!(
        crate::oauth_native::sessions::find(&o.db, &sid)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_rejected_device_request_denies_the_device_code() {
    let o = device_backend().await;
    let (device_code, s, consent) = device_consent(&o).await;
    let r = o
        .reject_consent_request(&consent, "access_denied", "x")
        .await
        .unwrap();
    assert_eq!(device_row(&o.db, &device_code).await.0, "accepted");
    assert!(matches!(
        device_resume(&o, &s, &r).await.unwrap(),
        Resumed::Device { approved: false }
    ));
    assert_eq!(device_row(&o.db, &device_code).await.0, "denied");
    assert!(device_code_row(&o.db, &device_code).await.is_none());

    // A rejected login denies too.
    let a = start_device(&o, DEV, &["openid"]).await;
    let s = accept_device(&o, &a.user_code).await.unwrap();
    let r = o
        .reject_login_request(&s.challenge, "login_required", "x")
        .await
        .unwrap();
    assert!(matches!(
        device_resume(&o, &s, &r).await.unwrap(),
        Resumed::Device { approved: false }
    ));
    assert_eq!(device_row(&o.db, &a.device_code).await.0, "denied");
}

#[tokio::test]
async fn a_user_code_is_accepted_once() {
    let o = device_backend().await;
    let a = start_device(&o, DEV, &["openid"]).await;
    let first = accept_device(&o, &a.user_code).await.unwrap();
    let after = device_row(&o.db, &a.device_code).await;
    for again in [a.user_code.clone(), a.user_code.to_lowercase()] {
        let e = o.accept_user_code_request("", &again).await.unwrap_err();
        assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    }
    assert_eq!(device_row(&o.db, &a.device_code).await, after);
    assert_eq!(flow_count(&o.db, DEV).await, 1);
    assert!(o.get_login_request(&first.challenge).await.is_ok());

    for unknown in ["BCDF-GHJK", "not a code", ""] {
        let e = o.accept_user_code_request("", unknown).await.unwrap_err();
        assert_eq!(refusal(&e), Some(ChallengeError::Unknown), "{unknown:?}");
    }
    // Denied and approved codes stay refused.
    let (device_code, s, consent) = device_consent(&o).await;
    let r = accept_consent(&o, &consent, &["openid"], &[], false)
        .await
        .unwrap();
    device_resume(&o, &s, &r).await.unwrap();
    let user_code: String = {
        let hash = token_hash(&device_code);
        let r: anyhow::Result<String> = async {
            Ok(crate::db_interact!(o.db, |c| {
                oauth_device_codes::table
                    .find(hash)
                    .select(oauth_device_codes::user_code)
                    .first(c)
            })?)
        }
        .await;
        r.unwrap()
    };
    assert!(o.accept_user_code_request("", &user_code).await.is_err());
}

#[tokio::test]
async fn every_device_transition_refuses_a_replay() {
    let o = device_backend().await;
    let a = start_device(&o, DEV, &["openid"]).await;
    let s = accept_device(&o, &a.user_code).await.unwrap();
    let used = Some(ChallengeError::Used);

    let login = accept_login(&o, &s, "alice", true).await.unwrap();
    assert_eq!(
        refusal(&accept_login(&o, &s, "alice", true).await.unwrap_err()),
        used
    );
    let consent = match device_resume(&o, &s, &login).await.unwrap() {
        Resumed::Consent { challenge, .. } => challenge,
        other => panic!("{other:?}"),
    };
    let e = device_resume(&o, &s, &login).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));

    let accepted = accept_consent(&o, &consent, &["openid"], &[], false)
        .await
        .unwrap();
    let e = accept_consent(&o, &consent, &["openid"], &[], false)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), used);
    let e = o
        .reject_consent_request(&consent, "access_denied", "x")
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), used);

    assert!(matches!(
        device_resume(&o, &s, &accepted).await.unwrap(),
        Resumed::Device { approved: true }
    ));
    let e = device_resume(&o, &s, &accepted).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    assert_eq!(device_row(&o.db, &a.device_code).await.0, "approved");
    assert_eq!(code_count(&o.db).await, 1);

    // The denial path: the verifier of a rejection is used once and the row stays denied.
    let (device_code, s, consent) = device_consent(&o).await;
    let rejected = o
        .reject_consent_request(&consent, "access_denied", "x")
        .await
        .unwrap();
    device_resume(&o, &s, &rejected).await.unwrap();
    let e = device_resume(&o, &s, &rejected).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    let e = accept_consent(&o, &consent, &["openid"], &[], false)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), used);
    assert_eq!(device_row(&o.db, &device_code).await.0, "denied");
    assert_eq!(code_count(&o.db).await, 1);
}

#[tokio::test]
async fn resume_without_a_binding_works_only_for_a_device_request() {
    let o = device_backend().await;
    register(&o, "app").await;

    // A device request resumes without asking the predicate (`device_resume` panics if asked).
    let (_, s, _) = device_consent(&o).await;
    assert_eq!(flow_state(&o.db, &s.id).await.0, "consent");

    // The path must still name the verifier's request.
    let a = start_device(&o, DEV, &["openid"]).await;
    let s = accept_device(&o, &a.user_code).await.unwrap();
    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    let other = start(&o, "app", "").await;
    let e = challenge::resume(&o.db, &other.id, &verifier_of(&r), |_| true)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unbound));
    assert_eq!(flow_state(&o.db, &s.id).await.0, "login_accepted");

    // A code request is refused without its binding, and a remembered login sets forseti_op.
    let s = start(&o, "app", "").await;
    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    let e = challenge::resume(&o.db, &s.id, &verifier_of(&r), |_| false)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unbound));
    match resume(&o, &s, &r).await.unwrap() {
        Resumed::Consent { remembered, .. } => assert!(remembered.is_some()),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_device_request_always_shows_the_consent_screen() {
    let o = backend().await;
    // Operator-skipped, and registered for the code grant too, with a remembered grant from it.
    o.create_client(OAuthClient {
        grant_types: Some(strings(&[
            "authorization_code",
            crate::oauth_native::device::DEVICE_CODE_GRANT,
        ])),
        skip_consent: Some(true),
        ..client(DEV)
    })
    .await
    .unwrap();
    let (granted, _) = finish(&o, DEV, "alice", true).await;
    assert_eq!(grant_flags(&o.db, &granted).await, (1, 0, 0));
    assert_eq!(next_skip(&o, DEV, "alice").await, Some(true));

    let (device_code, s, consent) = device_consent_for(&o, &["openid"]).await;
    let req = o.get_consent_request(&consent).await.unwrap();
    assert_eq!(req.skip, Some(false));
    assert_eq!(req.client.unwrap().skip_consent, Some(false));

    let before = flow_state(&o.db, &s.id).await;
    let auto = o
        .accept_consent_on(
            GrantPath::Auto,
            &consent,
            strings(&["openid"]),
            vec![],
            serde_json::json!({}),
            serde_json::Map::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(refusal(&auto), Some(ChallengeError::ConsentRequired));
    assert_eq!(flow_state(&o.db, &s.id).await, before);
    assert_eq!(device_row(&o.db, &device_code).await.0, "accepted");

    // A remembered device grant lets no later device request skip either.
    let r = accept_consent(&o, &consent, &["openid"], &[], true)
        .await
        .unwrap();
    device_resume(&o, &s, &r).await.unwrap();
    let (_, _, consent) = device_consent_for(&o, &["openid"]).await;
    assert_eq!(
        o.get_consent_request(&consent).await.unwrap().skip,
        Some(false)
    );
}

#[tokio::test]
async fn an_expired_device_code_can_be_neither_accepted_nor_approved() {
    let o = device_backend().await;
    let a = start_device(&o, DEV, &["openid"]).await;
    expire_device(&o.db, &a.device_code).await;
    let e = o
        .accept_user_code_request("", &a.user_code)
        .await
        .unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    assert_eq!(device_row(&o.db, &a.device_code).await.0, "pending");
    assert_eq!(flow_count(&o.db, DEV).await, 0);

    // Expired after consent: the request ends, nothing is stored, the row is left accepted.
    let (device_code, s, consent) = device_consent(&o).await;
    let r = accept_consent(&o, &consent, &["openid"], &[], false)
        .await
        .unwrap();
    expire_device(&o.db, &device_code).await;
    assert!(matches!(
        device_resume(&o, &s, &r).await.unwrap(),
        Resumed::Device { approved: false }
    ));
    assert_eq!(device_row(&o.db, &device_code).await.0, "accepted");
    assert!(device_code_row(&o.db, &device_code).await.is_none());

    // Expired before a rejection is delivered: not denied either.
    let (device_code, s, consent) = device_consent(&o).await;
    let r = o
        .reject_consent_request(&consent, "access_denied", "x")
        .await
        .unwrap();
    expire_device(&o.db, &device_code).await;
    device_resume(&o, &s, &r).await.unwrap();
    assert_eq!(device_row(&o.db, &device_code).await.0, "accepted");
}

#[tokio::test]
async fn a_revoked_grant_denies_the_device_code() {
    let o = device_backend().await;
    let (device_code, s, consent) = device_consent(&o).await;
    let r = accept_consent(&o, &consent, &["openid"], &[], false)
        .await
        .unwrap();
    o.revoke_consent_sessions_by_request_id(&s.id)
        .await
        .unwrap();
    assert!(matches!(
        device_resume(&o, &s, &r).await.unwrap(),
        Resumed::Device { approved: false }
    ));
    assert_eq!(device_row(&o.db, &device_code).await.0, "denied");
    assert!(device_code_row(&o.db, &device_code).await.is_none());
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn concurrent_accepts_of_one_user_code_win_once_on_postgres() {
    const ROUNDS: usize = 10;
    let setup = crate::db::test_postgres_pool().await;
    let o = backend_on(&setup).await;
    let client_id = format!("device-accept-{}", uuid::Uuid::new_v4().simple());
    o.create_client(device_client(&client_id, clients::AUTH_NONE))
        .await
        .unwrap();
    let a = backend_on(&crate::db::test_postgres_pool().await).await;
    let b = backend_on(&crate::db::test_postgres_pool().await).await;

    let mut wins = Vec::new();
    let mut flows = Vec::new();
    for _ in 0..ROUNDS {
        let issued = start_device(&o, &client_id, &["openid"]).await;
        let (ra, rb) = tokio::join!(
            a.accept_user_code_request("", &issued.user_code),
            b.accept_user_code_request("", &issued.user_code)
        );
        wins.push([ra, rb].iter().filter(|r| r.is_ok()).count());
        flows.push(device_row(&setup, &issued.device_code).await);
    }
    let stored = flow_count(&setup, &client_id).await;

    o.delete_client(&client_id).await.unwrap();
    assert!(wins.iter().all(|w| *w == 1), "{wins:?}");
    assert!(
        flows
            .iter()
            .all(|(status, flow_id, _)| status == "accepted" && flow_id.is_some()),
        "{flows:?}"
    );
    assert_eq!(stored, i64::try_from(ROUNDS).unwrap());
}
