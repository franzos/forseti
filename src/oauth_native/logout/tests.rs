use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::backend::OAuthBackend;
use crate::backend::oauth::OAuthClient;
use crate::config::AppConfig;
use crate::oauth::op_sessions::{self, GrantRevocation};
use crate::oauth_native::challenge::Resumed;
use crate::oauth_native::jwt::{BACKCHANNEL_LOGOUT_EVENT, LOGOUT_TOKEN_TTL_SECS, Typ};
use crate::oauth_native::test_support::*;
use crate::oauth_native::{DELIVERY_DRAIN, keys};

const POST_LOGOUT: &str = "https://app.example/bye";

/// How a [`Sink`] answers a back-channel POST.
#[derive(Clone, Copy)]
enum Answer {
    Status(u16),
    After(Duration),
}

/// A local `backchannel_logout_uri`; records every `logout_token` on arrival.
struct Sink {
    url: String,
    tokens: Arc<Mutex<Vec<String>>>,
}

impl Sink {
    async fn start(answer: Answer) -> Self {
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let seen = tokens.clone();
        let app = axum::Router::new().route(
            "/bc",
            axum::routing::post(
                move |axum::extract::Form(form): axum::extract::Form<
                    std::collections::HashMap<String, String>,
                >| {
                    let seen = seen.clone();
                    async move {
                        if let Some(t) = form.get("logout_token") {
                            seen.lock().unwrap().push(t.clone());
                        }
                        match answer {
                            Answer::Status(s) => StatusCode::from_u16(s).unwrap(),
                            Answer::After(d) => {
                                tokio::time::sleep(d).await;
                                StatusCode::OK
                            }
                        }
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://127.0.0.1:{port}/bc"),
            tokens,
        }
    }

    fn tokens(&self) -> Vec<String> {
        self.tokens.lock().unwrap().clone()
    }
}

/// A backend on `db` with its keys loaded; `hatch` is `[oauth.cimd].allow_private_targets`.
async fn backend_with(db: &DbPool, hatch: bool) -> Arc<NativeOAuth> {
    let mut cfg = AppConfig::test_fixture();
    cfg.oauth.cimd.allow_private_targets = hatch;
    let o = NativeOAuth::new(&cfg, db, &[0x42; 32]);
    o.init().await.unwrap();
    o
}

async fn hatched() -> Arc<NativeOAuth> {
    backend_with(&crate::db::test_pool().await, true).await
}

async fn register_with(o: &NativeOAuth, id: &str, backchannel: Option<&str>) {
    o.create_client(OAuthClient {
        backchannel_logout_uri: backchannel.map(str::to_string),
        post_logout_redirect_uris: Some(vec![POST_LOGOUT.to_string()]),
        ..client(id)
    })
    .await
    .unwrap();
}

/// `subject` signs in once and grants `client_ids` in that one login session; its `sid`.
async fn signed_in(o: &NativeOAuth, subject: &str, client_ids: &[&str]) -> String {
    let (flow, _) = finish(o, client_ids[0], subject, true).await;
    let sid = sid_of(&o.db, &flow).await;
    let session = sessions::find(&o.db, &sid).await.unwrap().unwrap();
    for id in &client_ids[1..] {
        let s = start_raw(o, &raw_query(id, ""), Some(&session)).await;
        let consent = to_consent(o, &s, subject, true).await;
        let r = accept_consent(o, &consent, &["openid", "email"], &[API], true)
            .await
            .unwrap();
        assert!(matches!(
            resume(o, &s, &r).await.unwrap(),
            Resumed::Code { .. }
        ));
    }
    sid
}

/// An ID token for `client_id` as this server signs them, expiring `exp_in` seconds from now.
fn id_token(o: &NativeOAuth, client_id: &str, subject: &str, sid: &str, exp_in: i64) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": o.issuer, "sub": subject, "aud": [client_id], "iat": now, "exp": now + exp_in,
        "sid": sid, "auth_time": now,
    });
    jwt::sign(&o.keys().unwrap(), Typ::IdToken, &claims).unwrap()
}

fn with_hint(hint: &str) -> Params {
    Params {
        id_token_hint: Some(hint.to_string()),
        ..Params::default()
    }
}

async fn opened(o: &NativeOAuth, params: &Params, cookie_sid: Option<&str>) -> String {
    open(o, params, cookie_sid).await.unwrap().unwrap()
}

async fn refused(o: &NativeOAuth, params: &Params, cookie_sid: Option<&str>) -> Refused {
    open(o, params, cookie_sid).await.unwrap().unwrap_err()
}

async fn audit_rows(db: &DbPool) -> Vec<crate::audit::AuditRow> {
    use crate::schema::audit_events;
    let load = async {
        Ok::<_, anyhow::Error>(db_interact!(db, |c| {
            audit_events::table
                .select(crate::audit::AuditRow::as_select())
                .order(audit_events::created_at)
                .load(c)
        })?)
    };
    load.await.unwrap()
}

async fn delivery_failures(db: &DbPool) -> Vec<crate::audit::AuditRow> {
    audit_rows(db)
        .await
        .into_iter()
        .filter(|r| r.action == action::OAUTH_BACKCHANNEL_LOGOUT_FAILED)
        .collect()
}

fn decode(segment: &str) -> Value {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

// --- the logout request ------------------------------------------------------------------

#[tokio::test]
async fn a_hint_opens_a_request_the_page_reads_as_app_initiated() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let challenge = opened(
        &o,
        &with_hint(&id_token(&o, "app", "alice", &sid, 3600)),
        None,
    )
    .await;
    let req = o.get_logout_request(&challenge).await.unwrap();
    assert_eq!(req.client.unwrap().client_id.as_deref(), Some("app"));
    assert_eq!(req.rp_initiated, Some(true));
    assert_eq!(req.sid.as_deref(), Some(sid.as_str()));
    assert_eq!(req.subject.as_deref(), Some("alice"));
}

#[tokio::test]
async fn an_expired_hint_is_accepted() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let expired = id_token(&o, "app", "alice", &sid, -7200);
    assert!(
        o.verify_jwt(&expired, Typ::IdToken, Some("app"))
            .await
            .is_err()
    );
    opened(&o, &with_hint(&expired), None).await;
}

#[tokio::test]
async fn only_id_tokens_this_server_issued_are_hints() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let now = Utc::now().timestamp();
    let keys = o.keys().unwrap();
    let foreign = keys::load_or_bootstrap(
        &crate::db::test_pool().await,
        &crate::seal::SealKey::new(&[7; 32]),
    )
    .await
    .unwrap();
    let base = json!({
        "iss": o.issuer, "sub": "alice", "aud": ["app"], "iat": now, "exp": now + 3600,
        "sid": sid,
    });
    let with = |k: &str, v: Value| {
        let mut c = base.clone();
        c[k] = v;
        c
    };
    let without = |k: &str| {
        let mut c = base.clone();
        c.as_object_mut().unwrap().remove(k);
        c
    };
    let valid = jwt::sign(&keys, Typ::IdToken, &base).unwrap();
    let (signed, _) = valid.rsplit_once('.').unwrap();
    let cases = [
        (
            "unknown key",
            jwt::sign(&foreign, Typ::IdToken, &base).unwrap(),
        ),
        (
            "other issuer",
            jwt::sign(
                &keys,
                Typ::IdToken,
                &with("iss", json!("https://other.example")),
            )
            .unwrap(),
        ),
        (
            "access token",
            jwt::sign(&keys, Typ::AccessToken, &base).unwrap(),
        ),
        (
            "logout token",
            jwt::sign(&keys, Typ::Logout, &base).unwrap(),
        ),
        ("tampered", format!("{signed}.AAAA")),
        ("garbage", "not-a-jwt".to_string()),
        (
            "no sid",
            jwt::sign(&keys, Typ::IdToken, &without("sid")).unwrap(),
        ),
        (
            "no sub",
            jwt::sign(&keys, Typ::IdToken, &without("sub")).unwrap(),
        ),
        (
            "two audiences",
            jwt::sign(&keys, Typ::IdToken, &with("aud", json!(["app", "other"]))).unwrap(),
        ),
    ];
    for (what, hint) in cases {
        assert_eq!(
            refused(&o, &with_hint(&hint), Some(&sid)).await,
            Refused::InvalidHint,
            "{what}"
        );
    }
    opened(&o, &with_hint(&valid), None).await;
    let single = jwt::sign(&keys, Typ::IdToken, &with("aud", json!("app"))).unwrap();
    opened(&o, &with_hint(&single), None).await;
}

#[tokio::test]
async fn client_id_must_be_the_hints_audience() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    register_with(&o, "other", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let hint = id_token(&o, "app", "alice", &sid, 3600);
    let named = |client_id: &str| Params {
        client_id: Some(client_id.to_string()),
        ..with_hint(&hint)
    };
    assert_eq!(
        refused(&o, &named("other"), None).await,
        Refused::ClientMismatch
    );
    opened(&o, &named("app"), None).await;
}

#[tokio::test]
async fn post_logout_redirect_uri_is_honoured_only_with_a_hint_and_while_registered() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let hint = id_token(&o, "app", "alice", &sid, 3600);
    let to = |uri: &str, hint: Option<&str>| Params {
        id_token_hint: hint.map(str::to_string),
        post_logout_redirect_uri: Some(uri.to_string()),
        state: Some("s 1&x".to_string()),
        ..Params::default()
    };
    let signed_out = format!("{}/signed-out", o.issuer);

    assert_eq!(
        refused(&o, &to("https://app.example/elsewhere", Some(&hint)), None).await,
        Refused::UnregisteredRedirect
    );
    assert_eq!(
        refused(&o, &to(POST_LOGOUT, None), Some(&sid)).await,
        Refused::RedirectWithoutHint
    );

    let challenge = opened(&o, &to(POST_LOGOUT, Some(&hint)), None).await;
    let r = o.accept_logout_request(&challenge).await.unwrap();
    assert_eq!(r.redirect_to, format!("{POST_LOGOUT}?state=s+1%26x"));

    let sid = signed_in(&o, "alice", &["app"]).await;
    let hint = id_token(&o, "app", "alice", &sid, 3600);
    let challenge = opened(&o, &to(POST_LOGOUT, Some(&hint)), None).await;
    o.update_client(
        "app",
        OAuthClient {
            post_logout_redirect_uris: Some(vec![]),
            ..client("app")
        },
    )
    .await
    .unwrap();
    let r = o.accept_logout_request(&challenge).await.unwrap();
    assert_eq!(r.redirect_to, signed_out, "removed before accept");

    let sid = signed_in(&o, "alice", &["app"]).await;
    let only_state = Params {
        state: Some("kept".to_string()),
        ..with_hint(&id_token(&o, "app", "alice", &sid, 3600))
    };
    let challenge = opened(&o, &only_state, None).await;
    let r = o.accept_logout_request(&challenge).await.unwrap();
    assert_eq!(r.redirect_to, signed_out, "state without a redirect URI");
}

#[tokio::test]
async fn a_post_logout_redirect_uri_of_a_deleted_client_is_not_honoured() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let params = Params {
        post_logout_redirect_uri: Some(POST_LOGOUT.to_string()),
        ..with_hint(&id_token(&o, "app", "alice", &sid, 3600))
    };
    let challenge = opened(&o, &params, None).await;
    o.delete_client("app").await.unwrap();
    let req = o.get_logout_request(&challenge).await.unwrap();
    assert!(req.client.is_none());
    assert_eq!(req.rp_initiated, Some(true));
    let r = o.accept_logout_request(&challenge).await.unwrap();
    assert_eq!(r.redirect_to, format!("{}/signed-out", o.issuer));
    assert_eq!(
        refused(&o, &params, None).await,
        Refused::UnregisteredRedirect
    );
}

#[tokio::test]
async fn without_a_hint_the_op_cookie_names_the_session() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let named = Params {
        client_id: Some("app".to_string()),
        ..Params::default()
    };
    let challenge = opened(&o, &named, Some(&sid)).await;
    let req = o.get_logout_request(&challenge).await.unwrap();
    assert!(req.client.is_none());
    assert_eq!(req.rp_initiated, Some(false));
    assert_eq!(req.sid.as_deref(), Some(sid.as_str()));
    assert_eq!(req.subject.as_deref(), Some("alice"));

    assert_eq!(
        refused(&o, &Params::default(), None).await,
        Refused::NoSession
    );
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert_eq!(
        refused(&o, &Params::default(), Some(&sid)).await,
        Refused::NoSession
    );
}

#[tokio::test]
async fn a_hint_names_the_session_whatever_the_cookie_says() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let alice = signed_in(&o, "alice", &["app"]).await;
    let bob = signed_in(&o, "bob", &["app"]).await;
    let hint = id_token(&o, "app", "alice", &alice, 3600);
    let challenge = opened(&o, &with_hint(&hint), Some(&bob)).await;
    let req = o.get_logout_request(&challenge).await.unwrap();
    assert_eq!(req.subject.as_deref(), Some("alice"));
    assert_eq!(req.sid.as_deref(), Some(alice.as_str()));
}

async fn browser_sid(o: &NativeOAuth, challenge: &str) -> Option<String> {
    pending(&o.db, challenge).await.unwrap().browser_sid
}

/// The `sid` of every logout token `sink` received, sorted.
fn announced(sink: &Sink) -> Vec<String> {
    let mut sids: Vec<String> = sink
        .tokens()
        .iter()
        .map(|t| {
            decode(t.split('.').nth(1).unwrap())["sid"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    sids.sort();
    sids
}

fn sorted<const N: usize>(mut sids: [&str; N]) -> Vec<String> {
    sids.sort_unstable();
    sids.map(str::to_string).to_vec()
}

#[tokio::test]
async fn a_hint_for_another_session_also_ends_the_browsers_session_once() {
    let o = hatched().await;
    let (sink_a, sink_b) = (
        Sink::start(Answer::Status(200)).await,
        Sink::start(Answer::Status(200)).await,
    );
    register_with(&o, "a", Some(&sink_a.url)).await;
    register_with(&o, "b", Some(&sink_b.url)).await;
    let hinted = signed_in(&o, "alice", &["a"]).await;
    let browser = signed_in(&o, "alice", &["a", "b"]).await;
    let other = signed_in(&o, "alice", &["a"]).await;
    let grants = grant_count(&o.db, "alice").await;
    let hint = id_token(&o, "a", "alice", &hinted, 3600);
    let challenge = opened(&o, &with_hint(&hint), Some(&browser)).await;
    assert_eq!(
        browser_sid(&o, &challenge).await.as_deref(),
        Some(&*browser)
    );
    let req = o.get_logout_request(&challenge).await.unwrap();
    assert_eq!(req.sid.as_deref(), Some(hinted.as_str()));

    o.accept_logout_request(&challenge).await.unwrap();
    for sid in [&hinted, &browser] {
        assert!(sessions::find(&o.db, sid).await.unwrap().is_none());
    }
    assert!(sessions::find(&o.db, &other).await.unwrap().is_some());
    assert_eq!(grant_count(&o.db, "alice").await, grants);
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(announced(&sink_a), sorted([&hinted, &browser]));
    assert_eq!(announced(&sink_b), [browser.as_str()]);

    let e = o.accept_logout_request(&challenge).await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Used));
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink_a.tokens().len(), 2);
    assert_eq!(sink_b.tokens().len(), 1);
}

#[tokio::test]
async fn a_cookie_of_another_subject_is_neither_stored_nor_ended() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let alice = signed_in(&o, "alice", &["app"]).await;
    let bob = signed_in(&o, "bob", &["app"]).await;
    let hint = id_token(&o, "app", "alice", &alice, 3600);
    let challenge = opened(&o, &with_hint(&hint), Some(&bob)).await;
    assert_eq!(browser_sid(&o, &challenge).await, None);

    o.accept_logout_request(&challenge).await.unwrap();
    assert!(sessions::find(&o.db, &bob).await.unwrap().is_some());
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(announced(&sink), [alice]);
}

#[tokio::test]
async fn a_cookie_naming_the_hints_session_or_no_session_stores_nothing() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let hint = with_hint(&id_token(&o, "app", "alice", &sid, 3600));
    for cookie in [None, Some("no-such-sid"), Some(sid.as_str())] {
        let challenge = opened(&o, &hint, cookie).await;
        assert_eq!(browser_sid(&o, &challenge).await, None, "{cookie:?}");
    }

    let challenge = opened(&o, &hint, Some(&sid)).await;
    o.accept_logout_request(&challenge).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(announced(&sink), [sid]);
}

#[tokio::test]
async fn a_browser_session_that_changed_subject_or_vanished_before_accept_is_skipped() {
    use crate::schema::oauth_login_sessions;
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;

    let hinted = signed_in(&o, "alice", &["app"]).await;
    let browser = signed_in(&o, "alice", &["app"]).await;
    let hint = with_hint(&id_token(&o, "app", "alice", &hinted, 3600));
    let challenge = opened(&o, &hint, Some(&browser)).await;
    let sid = browser.clone();
    let now_bob = async {
        Ok::<_, anyhow::Error>(db_interact!(o.db, |c| {
            diesel::update(oauth_login_sessions::table.find(sid))
                .set(oauth_login_sessions::subject.eq("bob"))
                .execute(c)
        })?)
    };
    now_bob.await.unwrap();
    o.accept_logout_request(&challenge).await.unwrap();
    assert!(sessions::find(&o.db, &browser).await.unwrap().is_some());
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(announced(&sink), [hinted.as_str()]);

    let hinted2 = signed_in(&o, "alice", &["app"]).await;
    let gone = signed_in(&o, "alice", &["app"]).await;
    let hint = with_hint(&id_token(&o, "app", "alice", &hinted2, 3600));
    let challenge = opened(&o, &hint, Some(&gone)).await;
    assert_eq!(browser_sid(&o, &challenge).await.as_deref(), Some(&*gone));
    o.revoke_login_session_by_sid(&gone).await.unwrap();
    o.accept_logout_request(&challenge).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(announced(&sink), sorted([&hinted, &hinted2, &gone]));
}

#[tokio::test]
async fn a_failed_end_of_the_browsers_session_leaves_the_request_usable() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let hinted = signed_in(&o, "alice", &["app"]).await;
    let browser = signed_in(&o, "alice", &["app"]).await;
    let hint = with_hint(&id_token(&o, "app", "alice", &hinted, 3600));
    let challenge = opened(&o, &hint, Some(&browser)).await;
    exec(
        &o.db,
        format!(
            "CREATE TRIGGER block_session_delete BEFORE DELETE ON oauth_login_sessions \
             WHEN OLD.sid = '{browser}' BEGIN SELECT RAISE(ABORT, 'blocked'); END"
        ),
    )
    .await;
    assert!(o.accept_logout_request(&challenge).await.is_err());
    assert!(sessions::find(&o.db, &hinted).await.unwrap().is_none());
    o.get_logout_request(&challenge).await.unwrap();

    exec(&o.db, "DROP TRIGGER block_session_delete").await;
    o.accept_logout_request(&challenge).await.unwrap();
    assert!(sessions::find(&o.db, &browser).await.unwrap().is_none());
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(announced(&sink), sorted([&hinted, &browser]));
}

#[tokio::test]
async fn a_hint_whose_session_is_gone_still_confirms_and_redirects() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let hint = id_token(&o, "app", "alice", &sid, 3600);
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink.tokens().len(), 1);

    let params = Params {
        post_logout_redirect_uri: Some(POST_LOGOUT.to_string()),
        ..with_hint(&hint)
    };
    let challenge = opened(&o, &params, None).await;
    let r = o.accept_logout_request(&challenge).await.unwrap();
    assert_eq!(r.redirect_to, POST_LOGOUT);
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink.tokens().len(), 1, "nothing is announced twice");
}

#[tokio::test]
async fn accept_ends_the_session_keeps_grants_and_consumes_the_request_once() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let grants = grant_count(&o.db, "alice").await;
    let challenge = opened(
        &o,
        &with_hint(&id_token(&o, "app", "alice", &sid, 3600)),
        None,
    )
    .await;

    o.accept_logout_request(&challenge).await.unwrap();
    assert!(sessions::find(&o.db, &sid).await.unwrap().is_none());
    assert_eq!(grant_count(&o.db, "alice").await, grants);
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink.tokens().len(), 1);

    for e in [
        o.accept_logout_request(&challenge).await.unwrap_err(),
        o.get_logout_request(&challenge).await.unwrap_err(),
    ] {
        assert_eq!(refusal(&e), Some(ChallengeError::Used));
    }
    let e = o.get_logout_request("no-such-challenge").await.unwrap_err();
    assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
}

#[tokio::test]
async fn an_expired_request_can_neither_be_read_nor_accepted() {
    let o = hatched().await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let challenge = opened(
        &o,
        &with_hint(&id_token(&o, "app", "alice", &sid, 3600)),
        None,
    )
    .await;
    let past = rfc3339(Utc::now() - chrono::Duration::seconds(1));
    let expired = async {
        Ok::<_, anyhow::Error>(db_interact!(o.db, |c| {
            diesel::update(oauth_logout_requests::table)
                .set(oauth_logout_requests::expires_at.eq(past))
                .execute(c)
        })?)
    };
    expired.await.unwrap();
    for e in [
        o.get_logout_request(&challenge).await.unwrap_err(),
        o.accept_logout_request(&challenge).await.unwrap_err(),
    ] {
        assert_eq!(refusal(&e), Some(ChallengeError::Unknown));
    }
    assert!(sessions::find(&o.db, &sid).await.unwrap().is_some());
}

#[tokio::test]
async fn a_hint_signed_by_a_retired_or_a_freshly_rotated_key_verifies() {
    let db = crate::db::test_pool().await;
    let o = backend_with(&db, true).await;
    register_with(&o, "app", None).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let before = id_token(&o, "app", "alice", &sid, 3600);

    let elsewhere = backend_with(&db, true).await;
    let rotated = elsewhere.rotate_key().await.unwrap();
    elsewhere.reload_keys().await.unwrap();
    let after = id_token(&elsewhere, "app", "alice", &sid, 3600);
    let kid = |t: &str| jsonwebtoken::decode_header(t).unwrap().kid.unwrap();
    assert_eq!(kid(&before), rotated.retired);
    assert_eq!(kid(&after), rotated.active);

    opened(&o, &with_hint(&after), None).await;
    o.reload_keys().await.unwrap();
    opened(&o, &with_hint(&before), None).await;
}

#[test]
fn parameters_parse_once_each_and_empty_values_are_absent() {
    let p = Params::parse(
        b"id_token_hint=h&client_id=&post_logout_redirect_uri=https%3A%2F%2Fa%2Fb&state=x+y\
          &ui_locales=de&logout_hint=a",
    )
    .unwrap();
    assert_eq!(
        p,
        Params {
            id_token_hint: Some("h".to_string()),
            client_id: None,
            post_logout_redirect_uri: Some("https://a/b".to_string()),
            state: Some("x y".to_string()),
        }
    );
    for raw in [
        &b"state=a&state=b"[..],
        b"id_token_hint=a&id_token_hint=",
        b"ui_locales=a&ui_locales=b",
    ] {
        assert_eq!(Params::parse(raw), Err(Refused::RepeatedParameter));
    }
    let state = |n: usize| format!("state={}", "s".repeat(n)).into_bytes();
    assert!(Params::parse(&state(MAX_STATE_BYTES)).is_ok());
    assert_eq!(
        Params::parse(&state(MAX_STATE_BYTES + 1)),
        Err(Refused::StateTooLong)
    );
    let big = format!("logout_hint={}", "a".repeat(MAX_REQUEST_BYTES)).into_bytes();
    assert_eq!(Params::parse(&big), Err(Refused::TooLarge));
}

#[tokio::test]
async fn the_endpoint_answers_the_confirmation_page_or_the_error_page() {
    let (app, state) = token_app().await;
    let o = &state.oauth;
    o.update_client(
        "basic",
        OAuthClient {
            post_logout_redirect_uris: Some(vec![POST_LOGOUT.to_string()]),
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            ..offline_client("basic")
        },
    )
    .await
    .unwrap();
    let sid = signed_in(o, "alice", &["basic"]).await;
    let hint = id_token(o, "basic", "alice", &sid, 3600);
    let location = |resp: &axum::response::Response| {
        resp.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    };
    let send = |req: Request<axum::body::Body>| {
        let app = app.clone();
        async move { app.oneshot(with_peer(req)).await.unwrap() }
    };
    let query = format!(
        "id_token_hint={hint}&post_logout_redirect_uri={}&state=xyz",
        crate::web::urlencode(POST_LOGOUT)
    );

    let resp = send(
        Request::get(format!("{LOGOUT_PATH}?{query}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    let page = format!("{ISSUER}/oauth/logout?logout_challenge=");
    assert!(location(&resp).starts_with(&page), "{}", location(&resp));

    let resp = send(
        Request::post(LOGOUT_PATH)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(query.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // A base64url challenge is its own URL encoding.
    let challenge = location(&resp)[page.len()..].to_string();
    let r = o.accept_logout_request(&challenge).await.unwrap();
    assert_eq!(r.redirect_to, format!("{POST_LOGOUT}?state=xyz"));

    let unregistered = format!(
        "id_token_hint={hint}&post_logout_redirect_uri={}",
        crate::web::urlencode("https://evil.example/")
    );
    for uri in [
        format!("{LOGOUT_PATH}?{unregistered}"),
        format!("{LOGOUT_PATH}?id_token_hint=junk"),
        format!("{LOGOUT_PATH}?state=a&state=b"),
        LOGOUT_PATH.to_string(),
    ] {
        let resp = send(
            Request::get(uri.as_str())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{uri}");
        assert_eq!(location(&resp), "/error", "{uri}");
    }

    let with_cookie = |sid: &str| {
        let cookie = sessions::set_op_cookie(&o.cookie_secret, sid, 3600, false);
        Request::get(LOGOUT_PATH)
            .header(header::COOKIE, cookie.split(';').next().unwrap())
            .body(axum::body::Body::empty())
            .unwrap()
    };
    assert_eq!(location(&send(with_cookie(&sid)).await), "/error", "ended");
    let live = signed_in(o, "alice", &["basic"]).await;
    let resp = send(with_cookie(&live)).await;
    assert!(location(&resp).starts_with(&page), "{}", location(&resp));
}

#[tokio::test]
async fn an_oversized_request_or_state_lands_on_the_error_page_and_stores_nothing() {
    let (app, state) = token_app().await;
    let o = &state.oauth;
    let sid = signed_in(o, "alice", &["basic"]).await;
    let hint = id_token(o, "basic", "alice", &sid, 3600);
    let send = |req: Request<axum::body::Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(with_peer(req)).await.unwrap();
            resp.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .to_string()
        }
    };
    let get = |query: String| {
        Request::get(format!("{LOGOUT_PATH}?{query}"))
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let post = |body: String| {
        Request::post(LOGOUT_PATH)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body))
            .unwrap()
    };
    let padded = format!(
        "id_token_hint={hint}&ui_locales={}",
        "a".repeat(MAX_REQUEST_BYTES)
    );
    let long_state = format!(
        "id_token_hint={hint}&state={}",
        "s".repeat(MAX_STATE_BYTES + 1)
    );
    for req in [
        get(padded.clone()),
        post(padded),
        get(long_state.clone()),
        post(long_state),
    ] {
        assert_eq!(send(req).await, "/error");
    }
    assert_eq!(logout_rows(&o.db).await, 0);

    let max_state = format!("id_token_hint={hint}&state={}", "s".repeat(MAX_STATE_BYTES));
    assert_ne!(send(get(max_state)).await, "/error");
    assert_eq!(logout_rows(&o.db).await, 1);
}

async fn logout_rows(db: &DbPool) -> i64 {
    let count = async {
        Ok::<_, anyhow::Error>(db_interact!(db, |c| {
            oauth_logout_requests::table.count().get_result::<i64>(c)
        })?)
    };
    count.await.unwrap()
}

#[tokio::test]
async fn a_private_use_scheme_post_logout_redirect_uri_is_refused_and_nothing_ends() {
    const APP_URI: &str = "com.example.app:/logout";
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    o.create_client(OAuthClient {
        backchannel_logout_uri: Some(sink.url.clone()),
        post_logout_redirect_uris: Some(vec![APP_URI.to_string(), POST_LOGOUT.to_string()]),
        ..client("app")
    })
    .await
    .unwrap();
    let sid = signed_in(&o, "alice", &["app"]).await;
    let hint = id_token(&o, "app", "alice", &sid, 3600);
    let to = |uri: &str| Params {
        post_logout_redirect_uri: Some(uri.to_string()),
        ..with_hint(&hint)
    };
    assert_eq!(
        refused(&o, &to(APP_URI), None).await,
        Refused::RedirectScheme
    );
    assert_eq!(logout_rows(&o.db).await, 0);
    assert!(sessions::find(&o.db, &sid).await.unwrap().is_some());

    // A stored row with such a URI, however it got there, still ends on `/signed-out`.
    let challenge = opened(&o, &to(POST_LOGOUT), None).await;
    let set = async {
        Ok::<_, anyhow::Error>(db_interact!(o.db, |c| {
            diesel::update(oauth_logout_requests::table)
                .set(oauth_logout_requests::post_logout_redirect_uri.eq(Some(APP_URI)))
                .execute(c)
        })?)
    };
    set.await.unwrap();
    let r = o.accept_logout_request(&challenge).await.unwrap();
    assert_eq!(r.redirect_to, format!("{}/signed-out", o.issuer));
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink.tokens().len(), 1);
}

#[tokio::test]
async fn a_skipped_grant_older_than_a_day_still_names_its_client_while_the_session_lives() {
    use crate::schema::oauth_consent_grants;
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let aged = rfc3339(Utc::now() - chrono::Duration::days(2));
    let age = async {
        Ok::<_, anyhow::Error>(db_interact!(o.db, |c| {
            diesel::update(oauth_consent_grants::table)
                .set((
                    oauth_consent_grants::skipped.eq(1),
                    oauth_consent_grants::handled_at.eq(aged),
                ))
                .execute(c)
        })?)
    };
    age.await.unwrap();

    crate::oauth_native::maintenance::prune(&o.db, Utc::now())
        .await
        .unwrap();
    assert_eq!(grant_count(&o.db, "alice").await, 1);
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    let [token] = sink.tokens().try_into().unwrap();
    assert_eq!(
        decode(token.split('.').nth(1).unwrap())["sid"],
        sid.as_str()
    );

    let pruned = crate::oauth_native::maintenance::prune(&o.db, Utc::now())
        .await
        .unwrap();
    assert_eq!(pruned.grants, 1);
    assert_eq!(grant_count(&o.db, "alice").await, 0);
}

// --- back-channel delivery ---------------------------------------------------------------

#[tokio::test]
async fn ending_a_session_posts_one_logout_token_per_client_with_a_back_channel_uri() {
    let o = hatched().await;
    let (sink_a, sink_b) = (
        Sink::start(Answer::Status(200)).await,
        Sink::start(Answer::Status(204)).await,
    );
    register_with(&o, "a", Some(&sink_a.url)).await;
    register_with(&o, "b", Some(&sink_b.url)).await;
    register_with(&o, "quiet", None).await;
    let sid = signed_in(&o, "alice", &["a", "b", "quiet"]).await;
    let other = signed_in(&o, "alice", &["a"]).await;

    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    let keys = o.keys().unwrap();
    for (sink, client_id) in [(&sink_a, "a"), (&sink_b, "b")] {
        let [token] = sink.tokens().try_into().unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some(keys.signing().kid.as_str()));
        let claims = jwt::verify(&keys, &o.issuer, &token, Typ::Logout, Some(client_id)).unwrap();
        assert_eq!(claims, decode(token.split('.').nth(1).unwrap()));
        let mut names: Vec<&str> = claims
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["aud", "events", "exp", "iat", "iss", "jti", "sid", "sub"]
        );
        assert_eq!(claims["iss"], o.issuer.as_str());
        assert_eq!(claims["aud"], json!([client_id]));
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["sid"], sid.as_str());
        assert_eq!(claims["events"], json!({ BACKCHANNEL_LOGOUT_EVENT: {} }));
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            LOGOUT_TOKEN_TTL_SECS
        );
        assert!(uuid::Uuid::parse_str(claims["jti"].as_str().unwrap()).is_ok());
        assert!(claims.get("nonce").is_none());
        for typ in [Typ::IdToken, Typ::AccessToken] {
            assert!(
                jwt::verify(&keys, &o.issuer, &token, typ, None).is_err(),
                "{typ:?}"
            );
            assert!(o.verify_jwt(&token, typ, None).await.is_err(), "{typ:?}");
        }
        assert!(o.verify_hint(&token).await.is_err());
    }
    assert!(delivery_failures(&o.db).await.is_empty());

    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink_a.tokens().len(), 1);
    assert!(sessions::find(&o.db, &other).await.unwrap().is_some());
}

#[tokio::test]
async fn a_logout_token_is_neither_an_id_token_nor_an_access_token_and_the_reverse() {
    let o = hatched().await;
    let keys = o.keys().unwrap();
    let now = Utc::now().timestamp();
    let claims =
        json!({ "iss": o.issuer, "sub": "s", "aud": ["app"], "iat": now, "exp": now + 60 });
    for (signed_as, refused_as) in [
        (Typ::Logout, Typ::IdToken),
        (Typ::Logout, Typ::AccessToken),
        (Typ::IdToken, Typ::Logout),
        (Typ::AccessToken, Typ::Logout),
    ] {
        let token = jwt::sign(&keys, signed_as, &claims).unwrap();
        assert!(
            jwt::verify(&keys, &o.issuer, &token, refused_as, None).is_err(),
            "{signed_as:?} as {refused_as:?}"
        );
        assert!(jwt::verify(&keys, &o.issuer, &token, signed_as, None).is_ok());
    }
}

#[tokio::test]
async fn a_failed_delivery_is_logged_and_audited_without_the_token() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(500)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);

    let [token] = sink.tokens().try_into().unwrap();
    let [row] = delivery_failures(&o.db).await.try_into().unwrap();
    assert!(!row.succeeded());
    assert_eq!(row.severity, "warning");
    assert_eq!(row.target_kind.as_deref(), Some("oauth_client"));
    assert_eq!(row.target_id.as_deref(), Some("app"));
    let metadata: Value = serde_json::from_str(&row.metadata).unwrap();
    assert_eq!(metadata["host"], "127.0.0.1");
    assert_eq!(metadata["client_id"], "app");
    assert_eq!(metadata["error"], "answered 500");
    let written = serde_json::to_string(&row).unwrap();
    assert!(!written.contains(&token) && !written.contains(token.split('.').nth(1).unwrap()));
    assert!(!written.contains("/bc"), "{written}");
}

#[tokio::test]
async fn the_subject_wide_revoke_sends_none() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    o.revoke_login_sessions_for_subject("alice").await.unwrap();
    assert!(sessions::find(&o.db, &sid).await.unwrap().is_none());
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert!(sink.tokens().is_empty());
}

#[tokio::test]
async fn a_private_target_is_refused_without_the_hatch() {
    let o = backend_with(&crate::db::test_pool().await, false).await;
    let sink = Sink::start(Answer::Status(200)).await;
    let https = sink.url.replacen("http://", "https://", 1);
    register_with(&o, "plain", Some(&sink.url)).await;
    register_with(&o, "loopback", Some(&https)).await;
    let sid = signed_in(&o, "alice", &["plain", "loopback"]).await;
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert!(sink.tokens().is_empty());
    let mut errors: Vec<(String, String)> = delivery_failures(&o.db)
        .await
        .into_iter()
        .map(|r| {
            let m: Value = serde_json::from_str(&r.metadata).unwrap();
            (
                r.target_id.unwrap(),
                m["error"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    errors.sort();
    assert_eq!(
        errors,
        [
            (
                "loopback".to_string(),
                "backchannel_logout_uri host must not be a private or special-use IP".to_string()
            ),
            (
                "plain".to_string(),
                "backchannel_logout_uri must use https://".to_string()
            ),
        ]
    );
}

async fn exec(db: &DbPool, sql: impl Into<String>) {
    let sql: String = sql.into();
    let run = async {
        Ok::<_, anyhow::Error>(db_interact!(db, |c| { diesel::sql_query(sql).execute(c) })?)
    };
    run.await.unwrap();
}

/// `alice` signed in as `sid` from browser `ks-1`, recorded as the handlers record it.
async fn recorded(o: &NativeOAuth, sid: &str) {
    op_sessions::record(&o.db, sid, "alice", "ks-1", 86_400)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_detached_row_retry_sends_nothing_a_second_time() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let (grant, _) = finish(&o, "app", "alice", true).await;
    let sid = sid_of(&o.db, &grant).await;
    recorded(&o, &sid).await;
    op_sessions::record_consent(&o.db, &grant, &sid, "alice", "app")
        .await
        .unwrap();
    exec(
        &o.db,
        "CREATE TRIGGER block_grant_delete BEFORE DELETE ON oauth_consent_grants \
         BEGIN SELECT RAISE(ABORT, 'blocked'); END",
    )
    .await;

    assert!(
        op_sessions::end_sid(&o.db, &o, &sid, GrantRevocation::Revoke)
            .await
            .is_err()
    );
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink.tokens().len(), 1);

    exec(&o.db, "DROP TRIGGER block_grant_delete").await;
    assert!(
        op_sessions::end_op_sessions_for_subject(
            &o.db,
            &o,
            "alice",
            Some("ks-2"),
            GrantRevocation::Revoke
        )
        .await
    );
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(grant_count(&o.db, "alice").await, 0);
    assert_eq!(sink.tokens().len(), 1);
}

#[tokio::test]
async fn a_cli_deletion_delivers_before_the_drain_returns() {
    let o = hatched().await;
    let sink = Sink::start(Answer::After(Duration::from_millis(300))).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    recorded(&o, &sid).await;
    assert_eq!(
        op_sessions::end_op_sessions_before_deletion(&o.db, &o, "alice").await,
        op_sessions::SubjectEnd::Done
    );
    let started = Instant::now();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(sink.tokens().len(), 1);
    assert!(delivery_failures(&o.db).await.is_empty());
}

#[tokio::test]
async fn the_session_end_does_not_wait_for_the_client() {
    let o = hatched().await;
    let sink = Sink::start(Answer::After(Duration::from_secs(1))).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    let request = o.revoke_login_session_by_sid(&sid);
    tokio::time::timeout(Duration::from_millis(500), request)
        .await
        .expect("the session end returns before the client answers")
        .unwrap();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink.tokens().len(), 1);
    assert!(delivery_failures(&o.db).await.is_empty());
}

#[tokio::test]
async fn the_drain_is_bounded_and_a_hanging_client_times_out() {
    assert!(DELIVERY_DRAIN > DELIVERY_TIMEOUT);
    let o = hatched().await;
    let sink = Sink::start(Answer::After(Duration::from_secs(3600))).await;
    register_with(&o, "app", Some(&sink.url)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;

    o.revoke_login_session_by_sid(&sid).await.unwrap();
    let started = Instant::now();
    assert!(!o.drain_deliveries(Duration::from_millis(200)).await);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        delivery_failures(&o.db).await.is_empty(),
        "aborted, not failed"
    );

    let sid = signed_in(&o, "alice", &["app"]).await;
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    let started = Instant::now();
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    let took = started.elapsed();
    assert!(
        took >= DELIVERY_TIMEOUT && took < DELIVERY_DRAIN,
        "{took:?}"
    );
    let [row] = delivery_failures(&o.db).await.try_into().unwrap();
    let metadata: Value = serde_json::from_str(&row.metadata).unwrap();
    assert_eq!(metadata["error"], "timed out");
}

#[tokio::test]
async fn finished_deliveries_are_reaped_on_the_next_spawn() {
    let o = hatched().await;
    let sink = Sink::start(Answer::Status(200)).await;
    register_with(&o, "app", Some(&sink.url)).await;
    for round in 1..=5 {
        let sid = signed_in(&o, "alice", &["app"]).await;
        o.revoke_login_session_by_sid(&sid).await.unwrap();
        while sink.tokens().len() < round {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let sid = signed_in(&o, "alice", &["app"]).await;
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    assert_eq!(o.deliveries.lock().unwrap().len(), 1);
    assert!(o.drain_deliveries(DELIVERY_DRAIN).await);
    assert_eq!(sink.tokens().len(), 6);
}

#[tokio::test]
async fn the_logout_migration_runs_on_a_fresh_sqlite_database() {
    let db = crate::db::test_pool().await;
    let load = async {
        Ok::<_, anyhow::Error>(db_interact!(db, |c| {
            diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>(
                "name FROM pragma_table_info('oauth_logout_requests')",
            ))
            .load::<String>(c)
        })?)
    };
    let columns: Vec<String> = load.await.unwrap();
    assert_eq!(
        columns,
        [
            "id",
            "challenge_hash",
            "client_id",
            "sid",
            "browser_sid",
            "subject",
            "post_logout_redirect_uri",
            "oauth_state",
            "accepted_at",
            "created_at",
            "expires_at"
        ]
    );
}

// --- Postgres ----------------------------------------------------------------------------

/// Three backends on separate Postgres pools sharing one key set, loaded off a SQLite pool so the
/// shared key table is left alone.
async fn postgres_backends() -> (Arc<NativeOAuth>, Arc<NativeOAuth>, Arc<NativeOAuth>) {
    let keys = Arc::new(
        keys::load_or_bootstrap(
            &crate::db::test_pool().await,
            &crate::seal::SealKey::new(&[1; 32]),
        )
        .await
        .unwrap(),
    );
    let mut cfg = AppConfig::test_fixture();
    cfg.oauth.cimd.allow_private_targets = true;
    let mut out = Vec::new();
    for _ in 0..3 {
        let o = NativeOAuth::new(&cfg, &crate::db::test_postgres_pool().await, &[0x42; 32]);
        o.keys.store(Some(keys.clone()));
        out.push(o);
    }
    let (c, b, a) = (out.pop(), out.pop(), out.pop());
    (a.unwrap(), b.unwrap(), c.unwrap())
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn concurrent_ends_of_one_session_send_once_on_postgres() {
    const ROUNDS: usize = 10;
    let (o, a, b) = postgres_backends().await;
    let sink = Sink::start(Answer::Status(200)).await;
    let client_id = format!("bc-race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("subject-{}", uuid::Uuid::new_v4().simple());
    register_with(&o, &client_id, Some(&sink.url)).await;

    let mut sids = Vec::new();
    for _ in 0..ROUNDS {
        let sid = signed_in(&o, &subject, &[&client_id]).await;
        let (ra, rb) = tokio::join!(
            a.revoke_login_session_by_sid(&sid),
            b.revoke_login_session_by_sid(&sid)
        );
        ra.unwrap();
        rb.unwrap();
        sids.push(sid);
    }
    assert!(a.drain_deliveries(DELIVERY_DRAIN).await);
    assert!(b.drain_deliveries(DELIVERY_DRAIN).await);

    o.delete_client(&client_id).await.unwrap();
    let mut sent: Vec<String> = sink
        .tokens()
        .iter()
        .map(|t| {
            decode(t.split('.').nth(1).unwrap())["sid"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    sent.sort();
    sids.sort();
    assert_eq!(sent, sids);
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn concurrent_accepts_of_one_logout_request_succeed_once_on_postgres() {
    const ROUNDS: usize = 10;
    let (o, a, b) = postgres_backends().await;
    let sink = Sink::start(Answer::Status(200)).await;
    let client_id = format!("logout-race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("subject-{}", uuid::Uuid::new_v4().simple());
    register_with(&o, &client_id, Some(&sink.url)).await;

    let (mut wins, mut sids) = (Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        let sid = signed_in(&o, &subject, &[&client_id]).await;
        let browser = signed_in(&o, &subject, &[&client_id]).await;
        let challenge = opened(
            &o,
            &with_hint(&id_token(&o, &client_id, &subject, &sid, 3600)),
            Some(&browser),
        )
        .await;
        let (ra, rb) = tokio::join!(
            a.accept_logout_request(&challenge),
            b.accept_logout_request(&challenge)
        );
        wins.push([ra, rb].iter().filter(|r| r.is_ok()).count());
        sids.extend([sid, browser]);
    }
    assert!(a.drain_deliveries(DELIVERY_DRAIN).await);
    assert!(b.drain_deliveries(DELIVERY_DRAIN).await);

    o.delete_client(&client_id).await.unwrap();
    assert!(wins.iter().all(|w| *w == 1), "{wins:?}");
    sids.sort();
    assert_eq!(announced(&sink), sids);
}
