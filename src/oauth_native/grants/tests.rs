use serde_json::json;

use super::*;
use crate::backend::OAuthBackend;
use crate::oauth_native::challenge::Resumed;
use crate::oauth_native::test_support::*;

/// A grant from a request whose consent the server reported as skipped.
async fn finish_skipped(
    o: &crate::oauth_native::NativeOAuth,
    client_id: &str,
    subject: &str,
) -> (String, String) {
    let s = start(o, client_id, "").await;
    let consent = to_consent(o, &s, subject, true).await;
    assert_eq!(
        o.get_consent_request(&consent).await.unwrap().skip,
        Some(true)
    );
    let r = accept_consent(o, &consent, &["openid", "email"], &[API], true)
        .await
        .unwrap();
    match resume(o, &s, &r).await.unwrap() {
        Resumed::Code { code, .. } => (s.id, code),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn lists_only_remembered_unskipped_grants_in_the_hydra_shape() {
    let o = backend().await;
    register(&o, "app").await;
    register(&o, "other").await;
    let (forgotten, _) = finish(&o, "app", "alice", false).await;
    let (kept, _) = finish(&o, "app", "alice", true).await;
    let (skipped, _) = finish_skipped(&o, "app", "alice").await;
    let (second, _) = finish(&o, "other", "alice", true).await;
    finish(&o, "app", "bob", true).await;

    let listed = o.list_consent_sessions_by_subject("alice").await.unwrap();
    let ids: Vec<&str> = listed
        .iter()
        .map(|s| s.consent_request_id.as_deref().unwrap())
        .collect();
    assert_eq!(ids, [second.as_str(), kept.as_str()]);
    assert!(!ids.contains(&forgotten.as_str()) && !ids.contains(&skipped.as_str()));

    let s = &listed[1];
    assert_eq!(s.grant_scope, Some(strings(&["openid", "email"])));
    assert_eq!(s.grant_access_token_audience, Some(strings(&[API])));
    assert_eq!(s.remember, Some(true));
    let handled_at = s.handled_at.as_deref().unwrap();
    assert!(
        crate::oauth_native::parse_time(handled_at).is_ok(),
        "{handled_at}"
    );
    let req = s.consent_request.as_ref().unwrap();
    assert_eq!(req.consent_request_id.as_deref(), Some(kept.as_str()));
    assert_eq!(req.subject.as_deref(), Some("alice"));
    let sid = sid_of(&o.db, &kept).await;
    assert_eq!(req.login_session_id.as_deref(), Some(sid.as_str()));
    let client = req.client.as_ref().unwrap();
    assert_eq!(client.client_id.as_deref(), Some("app"));
    assert_eq!(client.client_name.as_deref(), Some("App app"));
    assert_eq!(
        client.metadata,
        Some(json!({"forseti": {"client_type": "web_app"}}))
    );
    assert_eq!(client.client_secret, None);

    let by_sid = o
        .list_consent_sessions_by_login_session("alice", &sid)
        .await
        .unwrap();
    let ids: Vec<_> = by_sid
        .iter()
        .filter_map(|s| s.consent_request_id.clone())
        .collect();
    assert_eq!(ids, std::slice::from_ref(&kept));
    assert!(
        o.list_consent_sessions_by_login_session("bob", &sid)
            .await
            .unwrap()
            .is_empty()
    );
    let forgotten_sid = sid_of(&o.db, &forgotten).await;
    assert!(
        o.list_consent_sessions_by_login_session("alice", &forgotten_sid)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn consent_skip_needs_a_covering_remembered_unskipped_grant() {
    let o = backend().await;
    let app = register(&o, "app").await;
    let skip = |scope: &[&str], audience: &[&str], prompt_consent: bool| {
        let (o, app) = (o.clone(), app.clone());
        let (scope, audience) = (strings(scope), strings(audience));
        async move {
            consent_skip(
                &o.db,
                "alice",
                &app,
                REDIRECT,
                &scope,
                &audience,
                prompt_consent,
            )
            .await
            .unwrap()
        }
    };

    assert!(!skip(&["openid"], &[], false).await);
    finish(&o, "app", "alice", false).await;
    assert!(!skip(&["openid"], &[], false).await, "not remembered");

    finish(&o, "app", "alice", true).await;
    assert!(skip(&["openid"], &[], false).await);
    assert!(skip(&["openid", "email"], &[API], false).await);
    assert!(
        !skip(&["openid", "email"], &[API], true).await,
        "prompt=consent"
    );
    assert!(
        !skip(&["openid", "profile"], &[], false).await,
        "scope not covered"
    );
    assert!(
        !skip(&["openid"], &["https://other.example"], false).await,
        "audience not covered"
    );
    assert!(
        !consent_skip(
            &o.db,
            "bob",
            &app,
            REDIRECT,
            &strings(&["openid"]),
            &[],
            false
        )
        .await
        .unwrap()
    );

    let mut public = app.clone();
    public.token_endpoint_auth_method = Some(AUTH_NONE.to_string());
    for (uri, want) in [
        ("myapp:/cb", false),
        ("http://app.example/cb", false),
        ("http://127.0.0.1:5000/cb", true),
        ("https://app.example/cb", true),
    ] {
        let got = consent_skip(
            &o.db,
            "alice",
            &public,
            uri,
            &strings(&["openid"]),
            &[],
            false,
        )
        .await
        .unwrap();
        assert_eq!(got, want, "{uri}");
    }
}

#[tokio::test]
async fn a_skipped_grant_never_makes_the_next_consent_skip() {
    let o = backend().await;
    let app = register(&o, "app").await;
    finish(&o, "app", "alice", true).await;
    finish_skipped(&o, "app", "alice").await;
    // Revoking the remembered grant leaves only the skipped one.
    let remembered = o.list_consent_sessions_by_subject("alice").await.unwrap();
    for s in remembered {
        o.revoke_consent_sessions_by_request_id(s.consent_request_id.as_deref().unwrap())
            .await
            .unwrap();
    }
    assert_eq!(grant_count(&o.db, "alice").await, 1);
    let got = consent_skip(
        &o.db,
        "alice",
        &app,
        REDIRECT,
        &strings(&["openid"]),
        &[],
        false,
    )
    .await
    .unwrap();
    assert!(!got);
}

#[tokio::test]
async fn an_auto_grant_is_listed_but_no_basis_for_consent_skip() {
    let o = backend().await;
    register(&o, "app").await;
    let id = finish_auto(&o, "app", "alice").await;
    assert_eq!(grant_flags(&o.db, &id).await.2, 1);
    for on in [true, false] {
        set_skip_consent(&o, "app", on).await;
        let app = clients::get(&o.db, "app").await.unwrap().unwrap();
        let skip = consent_skip(
            &o.db,
            "alice",
            &app,
            REDIRECT,
            &strings(&["openid"]),
            &[],
            false,
        )
        .await
        .unwrap();
        assert!(!skip, "skip_consent {on}");
    }

    let by_subject = o.list_consent_sessions_by_subject("alice").await.unwrap();
    assert_eq!(by_subject.len(), 1);
    assert_eq!(
        by_subject[0].consent_request_id.as_deref(),
        Some(id.as_str())
    );
    let sid = sid_of(&o.db, &id).await;
    let by_sid = o
        .list_consent_sessions_by_login_session("alice", &sid)
        .await
        .unwrap();
    assert_eq!(by_sid.len(), 1);
    o.revoke_consent_sessions_for_subject("alice")
        .await
        .unwrap();
    assert_eq!(grant_count(&o.db, "alice").await, 0);
}

#[tokio::test]
async fn every_revoke_deletes_all_grants_of_its_key_and_their_codes() {
    let o = backend().await;
    register(&o, "app").await;
    register(&o, "other").await;
    let mut codes = Vec::new();
    for (client, subject, remember) in [
        ("app", "alice", true),
        ("app", "alice", false),
        ("other", "alice", true),
        ("app", "bob", true),
    ] {
        codes.push(finish(&o, client, subject, remember).await);
    }
    codes.push(finish_skipped(&o, "app", "alice").await);
    assert_eq!(code_count(&o.db).await, 5);

    o.revoke_consent_sessions_by_request_id(&codes[2].0)
        .await
        .unwrap();
    assert!(code_row(&o.db, &codes[2].1).await.is_none());
    assert_eq!(grant_count(&o.db, "alice").await, 3);
    o.revoke_consent_sessions_by_request_id("unknown")
        .await
        .unwrap();

    o.revoke_consent_sessions_for_client("alice", "app")
        .await
        .unwrap();
    assert_eq!(grant_count(&o.db, "alice").await, 0);
    for i in [0, 1, 4] {
        assert!(code_row(&o.db, &codes[i].1).await.is_none(), "{i}");
    }
    assert!(code_row(&o.db, &codes[3].1).await.is_some());

    finish(&o, "other", "bob", false).await;
    o.revoke_consent_sessions_for_subject("bob").await.unwrap();
    assert_eq!(grant_count(&o.db, "bob").await, 0);
    assert_eq!(code_count(&o.db).await, 0);
}

#[tokio::test]
async fn deleting_a_client_removes_its_requests_grants_and_codes() {
    let o = backend().await;
    register(&o, "app").await;
    register(&o, "other").await;
    finish(&o, "app", "alice", true).await;
    finish(&o, "app", "alice", false).await;
    start(&o, "app", "").await;
    let (_, kept) = finish(&o, "other", "alice", true).await;
    assert_eq!(flow_count(&o.db, "app").await, 3);

    o.delete_client("app").await.unwrap();
    assert_eq!(flow_count(&o.db, "app").await, 0);
    assert_eq!(grant_count(&o.db, "alice").await, 1);
    assert_eq!(code_count(&o.db).await, 1);
    assert!(code_row(&o.db, &kept).await.is_some());
}

#[tokio::test]
async fn a_grant_revoked_before_the_code_is_issued_ends_the_request() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    let r = accept_consent(&o, &consent, &["openid"], &[], true)
        .await
        .unwrap();
    o.revoke_consent_sessions_for_subject("alice")
        .await
        .unwrap();
    match resume(&o, &s, &r).await.unwrap() {
        Resumed::Error { error, .. } => assert_eq!(error, "access_denied"),
        other => panic!("{other:?}"),
    }
    assert_eq!(code_count(&o.db).await, 0);
    assert_eq!(flow_state(&o.db, &s.id).await.0, "done");
}

#[tokio::test]
async fn requested_resources_must_be_in_the_remembered_audience_to_skip() {
    let o = backend().await;
    register(&o, "app").await;
    let s = start(&o, "app", "").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    let r = accept_consent(&o, &consent, &["openid", "email"], &[], true)
        .await
        .unwrap();
    assert!(matches!(
        resume(&o, &s, &r).await.unwrap(),
        Resumed::Code { .. }
    ));

    let skip_for = |extra: String| {
        let o = o.clone();
        async move {
            let s = start(&o, "app", &extra).await;
            let consent = to_consent(&o, &s, "alice", true).await;
            o.get_consent_request(&consent).await.unwrap().skip
        }
    };
    let other = format!(
        "&resource={}",
        crate::web::urlencode("https://other-api.example")
    );
    let api = format!("&resource={}", crate::web::urlencode(API));
    assert_eq!(skip_for(String::new()).await, Some(true));
    assert_eq!(skip_for(other.clone()).await, Some(false));
    assert_eq!(skip_for(api.clone()).await, Some(false));

    // `prompt=consent` keeps this grant from being recorded as a skipped one.
    let s = start(&o, "app", "&prompt=consent").await;
    let consent = to_consent(&o, &s, "alice", true).await;
    let r = accept_consent(&o, &consent, &["openid", "email"], &[API], true)
        .await
        .unwrap();
    assert!(matches!(
        resume(&o, &s, &r).await.unwrap(),
        Resumed::Code { .. }
    ));
    assert_eq!(skip_for(api.clone()).await, Some(true));
    assert_eq!(skip_for(format!("{api}{other}")).await, Some(false));
}
