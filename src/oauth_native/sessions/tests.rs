use axum::http::header::COOKIE;

use super::*;
use crate::backend::OAuthBackend;
use crate::oauth_native::authorize::{LoginStep, Prompt, login_step};
use crate::oauth_native::challenge::{ChallengeError, Resumed};
use crate::oauth_native::test_support::*;

/// The `remembered` half of the resume after a login accepted with `remember`/`remember_for`.
async fn login(
    o: &crate::oauth_native::NativeOAuth,
    subject: &str,
    remember: bool,
    remember_for: i64,
) -> (Started, Option<(String, i64)>) {
    let s = start(o, "app", "").await;
    let r = o
        .accept_login_request(&s.challenge, subject, remember, remember_for, vec![], None)
        .await
        .unwrap();
    match resume(o, &s, &r).await.unwrap() {
        Resumed::Consent { remembered, .. } => (s, remembered),
        other => panic!("{other:?}"),
    }
}

fn skippable(session: &LoginSession) -> bool {
    matches!(
        login_step(
            &Prompt::default(),
            None,
            Utc::now(),
            Some(&session.snapshot())
        ),
        LoginStep::Skip { .. }
    )
}

#[tokio::test]
async fn remembered_and_unremembered_logins() {
    let o = backend().await;
    register(&o, "app").await;

    let (s, remembered) = login(&o, "alice", true, 3600).await;
    let sid = sid_of(&o.db, &s.id).await;
    assert_eq!(remembered, Some((sid.clone(), 3600)));
    let session = find(&o.db, &sid).await.unwrap().unwrap();
    assert!(session.remember);
    assert_eq!(session.subject, "alice");
    let window = (session.expires_at - session.auth_time).num_seconds();
    assert!((3599..=3600).contains(&window), "{window}");
    assert!(skippable(&session));

    let (s, remembered) = login(&o, "alice", false, 3600).await;
    assert_eq!(remembered, None);
    let session = find(&o.db, &sid_of(&o.db, &s.id).await)
        .await
        .unwrap()
        .unwrap();
    assert!(!session.remember);
    assert!(!skippable(&session));
}

#[tokio::test]
async fn remember_for_zero_or_over_the_cap_means_the_cap() {
    assert_eq!(remember_window(0), REMEMBER_CAP_SECS);
    assert_eq!(remember_window(-5), REMEMBER_CAP_SECS);
    assert_eq!(remember_window(REMEMBER_CAP_SECS + 1), REMEMBER_CAP_SECS);
    assert_eq!(remember_window(i64::MAX), REMEMBER_CAP_SECS);
    assert_eq!(remember_window(86_400), 86_400);

    let o = backend().await;
    register(&o, "app").await;
    for asked in [0, i64::MAX] {
        let (s, remembered) = login(&o, "alice", true, asked).await;
        assert_eq!(remembered.map(|r| r.1), Some(REMEMBER_CAP_SECS), "{asked}");
        let session = find(&o.db, &sid_of(&o.db, &s.id).await)
            .await
            .unwrap()
            .unwrap();
        let window = (session.expires_at - session.auth_time).num_seconds();
        assert!((REMEMBER_CAP_SECS - 1..=REMEMBER_CAP_SECS).contains(&window));
    }
}

#[tokio::test]
async fn a_sid_is_never_rebound_to_another_subject() {
    let o = backend().await;
    register(&o, "app").await;
    let (first, _) = login(&o, "alice", true, 3600).await;
    let sid = sid_of(&o.db, &first.id).await;

    let s = start(&o, "app", "").await;
    set_flow_sid(&o.db, &s.id, &sid).await;
    let before = flow_state(&o.db, &s.id).await;
    let e = accept_login(&o, &s, "bob", true).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::SidTaken));
    assert_eq!(flow_state(&o.db, &s.id).await, before);
    assert_eq!(find(&o.db, &sid).await.unwrap().unwrap().subject, "alice");
}

#[tokio::test]
async fn a_skipped_login_reuses_the_sid_and_keeps_auth_time() {
    let o = backend().await;
    register(&o, "app").await;
    let (first, _) = login(&o, "alice", true, 3600).await;
    let sid = sid_of(&o.db, &first.id).await;
    let session = find(&o.db, &sid).await.unwrap().unwrap();

    let s = start_raw(&o, &raw_query("app", ""), Some(&session)).await;
    assert_eq!(sid_of(&o.db, &s.id).await, sid);
    let consent = to_consent(&o, &s, "alice", true).await;
    let req = o.get_consent_request(&consent).await.unwrap();
    assert_eq!(req.login_session_id.as_deref(), Some(sid.as_str()));
    let r = accept_consent(&o, &consent, &["openid"], &[], true)
        .await
        .unwrap();
    let code = match resume(&o, &s, &r).await.unwrap() {
        Resumed::Code { code, .. } => code,
        other => panic!("{other:?}"),
    };
    let auth_time = code_row(&o.db, &code).await.unwrap().1;
    assert_eq!(auth_time, crate::db::rfc3339(session.auth_time));
    assert_eq!(find(&o.db, &sid).await.unwrap().unwrap(), session);
}

#[tokio::test]
async fn a_skipped_login_does_not_set_the_cookie_again() {
    let o = backend().await;
    register(&o, "app").await;
    let (first, _) = login(&o, "alice", true, 3600).await;
    let session = find(&o.db, &sid_of(&o.db, &first.id).await)
        .await
        .unwrap()
        .unwrap();
    let s = start_raw(&o, &raw_query("app", ""), Some(&session)).await;
    let r = accept_login(&o, &s, "alice", true).await.unwrap();
    match resume(&o, &s, &r).await.unwrap() {
        Resumed::Consent { remembered, .. } => assert_eq!(remembered, None),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_expired_session_is_not_skippable_and_refuses_a_skipped_accept() {
    let o = backend().await;
    register(&o, "app").await;
    let (first, _) = login(&o, "alice", true, 3600).await;
    let sid = sid_of(&o.db, &first.id).await;
    let session = find(&o.db, &sid).await.unwrap().unwrap();
    let s = start_raw(&o, &raw_query("app", ""), Some(&session)).await;

    expire_session(&o.db, &sid).await;
    let expired = find(&o.db, &sid).await.unwrap().unwrap();
    assert!(!skippable(&expired));
    let e = accept_login(&o, &s, "alice", true).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::SessionGone));
}

#[tokio::test]
async fn both_revokes_delete_and_a_revoked_sid_is_not_skippable() {
    let o = backend().await;
    register(&o, "app").await;
    let (a1, _) = login(&o, "alice", true, 3600).await;
    let (a2, _) = login(&o, "alice", false, 3600).await;
    let (b1, _) = login(&o, "bob", true, 3600).await;
    let (a1, a2, b1) = (
        sid_of(&o.db, &a1.id).await,
        sid_of(&o.db, &a2.id).await,
        sid_of(&o.db, &b1.id).await,
    );

    o.revoke_login_session_by_sid(&a1).await.unwrap();
    assert!(find(&o.db, &a1).await.unwrap().is_none());
    assert!(find(&o.db, &a2).await.unwrap().is_some());
    o.revoke_login_session_by_sid(&a1).await.unwrap();

    o.revoke_login_sessions_for_subject("alice").await.unwrap();
    assert!(find(&o.db, &a2).await.unwrap().is_none());
    assert!(find(&o.db, &b1).await.unwrap().is_some());
}

fn cookie_headers(set_cookie: &str) -> HeaderMap {
    let pair = set_cookie.split(';').next().unwrap();
    let mut h = HeaderMap::new();
    h.insert(COOKIE, pair.parse().unwrap());
    h
}

#[test]
fn the_op_cookie_round_trips_and_refuses_tampering_and_other_keys() {
    let secret = [0x42; 32];
    let set = set_op_cookie(&secret, "sid-1", 3600, true);
    assert!(set.starts_with("forseti_op="), "{set}");
    for attr in [
        "HttpOnly",
        "SameSite=Lax",
        "Path=/oauth2",
        "Secure",
        "Max-Age=3600",
    ] {
        assert!(set.contains(attr), "{attr}: {set}");
    }
    assert!(!set_op_cookie(&secret, "sid-1", 3600, false).contains("Secure"));
    assert_eq!(
        read_op_cookie(&secret, &cookie_headers(&set)).as_deref(),
        Some("sid-1")
    );
    assert_eq!(read_op_cookie(&[0x43; 32], &cookie_headers(&set)), None);

    let pair = set.split(';').next().unwrap();
    let mut tampered = pair.to_string();
    let last = tampered.pop().unwrap();
    tampered.push(if last == '0' { '1' } else { '0' });
    assert_eq!(read_op_cookie(&secret, &cookie_headers(&tampered)), None);
    let foreign = set.replace(&hex::encode("sid-1"), &hex::encode("sid-2"));
    assert_eq!(read_op_cookie(&secret, &cookie_headers(&foreign)), None);

    let clear = clear_op_cookie(true);
    assert!(clear.contains("forseti_op=;") && clear.contains("Expires=Thu, 01 Jan 1970"));
}

#[tokio::test]
async fn revoking_a_session_drops_its_unredeemed_codes_and_keeps_the_grant() {
    let o = backend().await;
    register(&o, "app").await;
    let (first, first_code) = finish(&o, "app", "alice", true).await;
    let (_, second_code) = finish(&o, "app", "alice", true).await;
    let (_, bob_code) = finish(&o, "app", "bob", true).await;

    o.revoke_login_session_by_sid(&sid_of(&o.db, &first).await)
        .await
        .unwrap();
    assert!(code_row(&o.db, &first_code).await.is_none());
    assert!(code_row(&o.db, &second_code).await.is_some());
    assert_eq!(grant_count(&o.db, "alice").await, 2);

    o.revoke_login_sessions_for_subject("alice").await.unwrap();
    assert!(code_row(&o.db, &second_code).await.is_none());
    assert!(code_row(&o.db, &bob_code).await.is_some());
    assert_eq!(grant_count(&o.db, "alice").await, 2);
}
