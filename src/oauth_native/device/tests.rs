use axum::http::Request;
use base64::Engine as _;
use tower::ServiceExt;

use super::*;
use crate::backend::OAuthBackend;
use crate::oauth_native::jwt;
use crate::oauth_native::test_support::*;
use crate::oauth_native::token_endpoint::TOKEN_PATH;

/// The device client: confidential by Basic, the device and refresh grants.
const DEV: &str = "dev";
const DEV_SECRET: &str = "dev-secret";
/// The public device client.
const DEV_PUB: &str = "dev-pub";

/// [`token_app`] plus [`DEV`] and [`DEV_PUB`].
async fn app() -> (axum::Router, AppState) {
    let (app, state) = token_app().await;
    for (id, method) in [(DEV, clients::AUTH_BASIC), (DEV_PUB, clients::AUTH_NONE)] {
        state
            .oauth
            .create_client(device_client(id, method))
            .await
            .unwrap();
    }
    (app, state)
}

async fn registered(o: &NativeOAuth, id: &str) -> OAuthClient {
    clients::get(&o.db, id).await.unwrap().unwrap()
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn post(app: &axum::Router, path: &str, pairs: &[(&str, &str)], basic: bool) -> Answer {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut req =
        Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if basic {
        let raw = base64::engine::general_purpose::STANDARD.encode(format!("{DEV}:{DEV_SECRET}"));
        req = req.header(header::AUTHORIZATION, format!("Basic {raw}"));
    }
    let resp = app
        .clone()
        .oneshot(with_peer(req.body(Body::from(body)).unwrap()))
        .await
        .unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    Answer {
        status,
        headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn assert_no_store(a: &Answer) {
    assert_eq!(a.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(a.headers[header::PRAGMA], "no-cache");
}

fn assert_error(a: &Answer, status: StatusCode, error: &str) {
    assert_eq!(a.status, status, "{}", a.body);
    assert_eq!(a.body["error"], error, "{}", a.body);
    assert_no_store(a);
}

/// A device authorization of [`DEV`] by Basic; the response body.
async fn authorize_dev(app: &axum::Router, scope: &str) -> Value {
    let a = post(app, DEVICE_AUTHORIZATION_PATH, &[("scope", scope)], true).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    a.body
}

async fn poll_dev(app: &axum::Router, device_code: &str) -> Answer {
    let pairs = [
        ("grant_type", DEVICE_CODE_GRANT),
        ("device_code", device_code),
    ];
    post(app, TOKEN_PATH, &pairs, true).await
}

/// `(user_code, client_id, scope, status, interval_secs, created_at, expires_at)` by device code.
async fn stored(
    db: &DbPool,
    device_code: &str,
) -> Option<(String, String, String, String, i32, String, String)> {
    let hash = token_hash(device_code);
    let r: Result<_> = async {
        Ok(db_interact!(db, |c| {
            oauth_device_codes::table
                .find(hash)
                .select((
                    oauth_device_codes::user_code,
                    oauth_device_codes::client_id,
                    oauth_device_codes::scope,
                    oauth_device_codes::status,
                    oauth_device_codes::interval_secs,
                    oauth_device_codes::created_at,
                    oauth_device_codes::expires_at,
                ))
                .first(c)
                .optional()
        })?)
    }
    .await;
    r.unwrap()
}

async fn device_count(db: &DbPool) -> i64 {
    let r: Result<i64> = async {
        Ok(db_interact!(db, |c| {
            oauth_device_codes::table.count().get_result(c)
        })?)
    }
    .await;
    r.unwrap()
}

async fn set_status(db: &DbPool, device_code: &str, status: &'static str) {
    let hash = token_hash(device_code);
    let r: Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(oauth_device_codes::table.find(hash))
                .set(oauth_device_codes::status.eq(status))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
}

async fn create_at(o: &NativeOAuth, client_id: &str, now: DateTime<Utc>) -> DeviceAuthorization {
    let client = registered(o, client_id).await;
    create(&o.db, ISSUER, &client, &strings(&["openid"]), now)
        .await
        .unwrap()
}

async fn poll_at(
    o: &NativeOAuth,
    client_id: &str,
    device_code: &str,
    now: DateTime<Utc>,
) -> Polled {
    let client = registered(o, client_id).await;
    poll(&o.db, &client, device_code, &[], now).await.unwrap()
}

fn refusal(r: Result<DeviceAuthorization>) -> Refused {
    *r.unwrap_err().downcast_ref::<Refused>().unwrap()
}

#[test]
fn a_user_code_is_two_groups_of_four_consonants() {
    assert_eq!(USER_CODE_ALPHABET.len(), 20);
    let mut letters: Vec<u8> = USER_CODE_ALPHABET.to_vec();
    letters.sort_unstable();
    letters.dedup();
    assert_eq!(letters.len(), 20);
    assert!(
        letters
            .iter()
            .all(|b| b.is_ascii_uppercase() && !b"AEIOUY".contains(b))
    );
    for _ in 0..500 {
        let code = user_code();
        let (head, tail) = code.split_once('-').unwrap();
        assert_eq!((head.len(), tail.len()), (4, 4), "{code}");
        assert!(
            format!("{head}{tail}")
                .bytes()
                .all(|b| USER_CODE_ALPHABET.contains(&b)),
            "{code}"
        );
    }
}

#[test]
fn a_typed_user_code_is_brought_to_its_stored_form() {
    for typed in [
        "BCDF-GHJK",
        "bcdf-ghjk",
        "BCDFGHJK",
        "bcdfghjk",
        " BCDF GHJK ",
        "bc-df-gh-jk",
        "--BcDf--gHjK--",
        "BCDF\tGHJK\n",
    ] {
        assert_eq!(
            normalize_user_code(typed).as_deref(),
            Some("BCDF-GHJK"),
            "{typed:?}"
        );
    }
    for refused in [
        "",
        "BCDF-GHJ",
        "BCDF-GHJKL",
        "ABCD-EFGH",
        "BCDF-GHJ1",
        "BCDF_GHJK",
        "BCDF-GHJ\u{0130}",
        "BCDF-GHJ%",
    ] {
        assert_eq!(normalize_user_code(refused), None, "{refused:?}");
    }
    for _ in 0..100 {
        let code = user_code();
        assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
    }
}

async fn get(app: &axum::Router, uri: &str) -> Response {
    let req = Request::get(uri).body(Body::empty()).unwrap();
    app.clone().oneshot(with_peer(req)).await.unwrap()
}

fn location(resp: &Response) -> String {
    resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

fn param(url: &str, name: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

/// Path and query of an absolute `url`, for sending it to the router.
fn local(url: &str) -> String {
    let u = url::Url::parse(url).unwrap();
    format!("{}?{}", u.path(), u.query().unwrap_or_default())
}

/// A device authorization of [`DEV`] accepted as typed and its login accepted for `alice`, with a
/// browser that holds no cookie resumed to the consent handler: the device code, the `sid` and
/// the consent challenge.
async fn to_device_consent(app: &axum::Router, o: &NativeOAuth) -> (String, String, String) {
    let body = authorize_dev(app, "openid offline_access").await;
    let device_code = body["device_code"].as_str().unwrap().to_string();
    let typed = body["user_code"]
        .as_str()
        .unwrap()
        .replace('-', " ")
        .to_lowercase();
    let login = o.accept_user_code_request("", &typed).await.unwrap();
    assert!(
        login
            .redirect_to
            .starts_with(&format!("{ISSUER}/oauth/login?login_challenge=")),
        "{}",
        login.redirect_to
    );
    let challenge = param(&login.redirect_to, "login_challenge");
    let req = o.get_login_request(&challenge).await.unwrap();
    assert!(!req.skip);
    let sid = req.session_id.unwrap();
    let resume = o
        .accept_login_request(
            &challenge,
            "alice",
            true,
            86_400,
            strings(&["pwd"]),
            Some("aal1".to_string()),
        )
        .await
        .unwrap()
        .redirect_to;
    let resp = get(app, &local(&resume)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "no forseti_op, no binding"
    );
    let to = location(&resp);
    assert!(
        to.starts_with(&format!("{ISSUER}/oauth/consent?consent_challenge=")),
        "{to}"
    );
    let consent = param(&to, "consent_challenge");
    let req = o.get_consent_request(&consent).await.unwrap();
    assert_eq!(req.skip, Some(false));
    assert_eq!(req.client.unwrap().skip_consent, Some(false));
    assert_eq!(
        req.requested_scope,
        Some(strings(&["openid", "offline_access"]))
    );
    (device_code, sid, consent)
}

#[tokio::test]
async fn a_device_authorization_approved_in_the_browser_redeems_at_the_token_endpoint() {
    let (app, state) = app().await;
    let o = &state.oauth;
    let (device_code, sid, consent) = to_device_consent(&app, o).await;
    let a = poll_dev(&app, &device_code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "authorization_pending");

    let resume = o
        .accept_consent_request(
            &consent,
            strings(&["openid", "offline_access"]),
            vec![],
            false,
            json!({"email": "alice@example.com"}),
            serde_json::Map::new(),
        )
        .await
        .unwrap()
        .redirect_to;
    let resp = get(&app, &local(&resume)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(location(&resp), format!("{ISSUER}/oauth/device/done"));
    assert!(resp.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(location(&get(&app, &local(&resume)).await), "/error");

    // The poll interval counts from the pending poll above.
    let earlier = rfc3339(Utc::now() - chrono::Duration::seconds(10));
    let hash = token_hash(&device_code);
    let r: Result<usize> = async {
        Ok(db_interact!(o.db, |c| {
            diesel::update(oauth_device_codes::table.find(hash))
                .set(oauth_device_codes::last_polled_at.eq(Some(earlier)))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
    let a = poll_dev(&app, &device_code).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["scope"], "openid offline_access");
    assert!(a.body["refresh_token"].is_string());
    let id = o
        .verify_jwt(
            a.body["id_token"].as_str().unwrap(),
            Typ::IdToken,
            Some(DEV),
        )
        .await
        .unwrap();
    assert_eq!(
        (id["sub"].as_str(), id["sid"].as_str()),
        (Some("alice"), Some(sid.as_str()))
    );
    assert_eq!(id["acr"], "aal1");
    let a = poll_dev(&app, &device_code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
}

#[tokio::test]
async fn a_device_authorization_denied_in_the_browser_polls_access_denied() {
    let (app, state) = app().await;
    let o = &state.oauth;
    let (device_code, _, consent) = to_device_consent(&app, o).await;
    let resume = o
        .reject_consent_request(
            &consent,
            "access_denied",
            "The resource owner denied the request.",
        )
        .await
        .unwrap()
        .redirect_to;
    let resp = get(&app, &local(&resume)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        format!("{ISSUER}/oauth/device/done?error=1")
    );
    assert!(resp.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(stored(&o.db, &device_code).await.unwrap().3, DENIED);
    let a = poll_dev(&app, &device_code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "access_denied");
}

#[tokio::test]
async fn the_migration_creates_the_table_on_a_fresh_database() {
    let (_, state) = app().await;
    let o = &state.oauth;
    let now = Utc::now();
    let a = create_at(o, DEV, now).await;
    let row = stored(&o.db, &a.device_code).await.unwrap();
    assert_eq!(row.1, DEV);
    // Every column, the nullable ones included, reads back.
    let hash = token_hash(&a.device_code);
    let r: Result<(Option<String>, Option<String>)> = async {
        Ok(db_interact!(o.db, |c| {
            oauth_device_codes::table
                .find(hash)
                .select((
                    oauth_device_codes::flow_id,
                    oauth_device_codes::last_polled_at,
                ))
                .first(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), (None, None));
    // The client owns its device rows.
    o.delete_client(DEV).await.unwrap();
    assert_eq!(device_count(&o.db).await, 0);
}

#[tokio::test]
async fn device_authorization_answers_rfc_8628_and_stores_the_code_hashed() {
    let (app, state) = app().await;
    let before = Utc::now();
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("scope", "openid offline_access")],
        true,
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_no_store(&a);
    assert_eq!(a.headers[header::CONTENT_TYPE], "application/json");
    let mut members: Vec<&String> = a.body.as_object().unwrap().keys().collect();
    members.sort();
    assert_eq!(
        members,
        [
            "device_code",
            "expires_in",
            "interval",
            "user_code",
            "verification_uri",
            "verification_uri_complete"
        ]
    );
    let device_code = a.body["device_code"].as_str().unwrap();
    let user_code = a.body["user_code"].as_str().unwrap();
    assert!(device_code.len() >= 43);
    assert_eq!(a.body["verification_uri"], format!("{ISSUER}/oauth/device"));
    assert_eq!(
        a.body["verification_uri_complete"],
        format!("{ISSUER}/oauth/device?user_code={user_code}")
    );
    assert_eq!(a.body["expires_in"], 600);
    assert_eq!(a.body["interval"], 5);

    let (stored_user_code, client_id, scope, status, interval, created_at, expires_at) =
        stored(&state.db, device_code).await.unwrap();
    assert_eq!(stored_user_code, user_code);
    assert_eq!(client_id, DEV);
    assert_eq!(scope, r#"["openid","offline_access"]"#);
    assert_eq!(status, "pending");
    assert_eq!(interval, 5);
    let created = parse_time(&created_at).unwrap();
    assert!(created >= before - chrono::Duration::seconds(1));
    assert_eq!(
        (parse_time(&expires_at).unwrap() - created).num_seconds(),
        600
    );

    // A public client names itself.
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("client_id", DEV_PUB), ("scope", "openid")],
        false,
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("client_id", DEV_PUB)],
        false,
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(device_count(&state.db).await, 3);
}

#[tokio::test]
async fn device_authorization_refusals() {
    let (app, state) = app().await;
    // `post` is registered for the code and refresh grants only.
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("client_id", "post"), ("client_secret", "post-secret")],
        false,
    )
    .await;
    assert_error(&a, StatusCode::BAD_REQUEST, "unauthorized_client");
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("scope", "openid admin")],
        true,
    )
    .await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_scope");
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("client_id", DEV), ("client_secret", "wrong")],
        false,
    )
    .await;
    assert_error(&a, StatusCode::UNAUTHORIZED, "invalid_client");
    // A confidential client without its secret.
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("client_id", DEV)],
        false,
    )
    .await;
    assert_error(&a, StatusCode::UNAUTHORIZED, "invalid_client");
    let a = post(&app, DEVICE_AUTHORIZATION_PATH, &[], false).await;
    assert_error(&a, StatusCode::UNAUTHORIZED, "invalid_client");
    let a = post(
        &app,
        DEVICE_AUTHORIZATION_PATH,
        &[("scope", "openid"), ("scope", "openid")],
        true,
    )
    .await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");
    assert_eq!(device_count(&state.db).await, 0);
}

#[tokio::test]
async fn each_client_has_at_most_1000_undecided_authorizations() {
    let (app, state) = app().await;
    let o = &state.oauth;
    let now = Utc::now();
    let (now_s, later) = (rfc3339(now), rfc3339(now + chrono::Duration::seconds(600)));
    let past = rfc3339(now - chrono::Duration::seconds(1));
    let rows: Vec<NewDevice> = (0..MAX_UNDECIDED_PER_CLIENT + 2)
        .map(|i| NewDevice {
            device_code_hash: format!("h-{i}"),
            user_code: format!("u-{i}"),
            client_id: DEV.to_string(),
            scope: "[]".to_string(),
            status: match i {
                0 => APPROVED,
                1 => DENIED,
                2 => ACCEPTED,
                _ => PENDING,
            }
            .to_string(),
            interval_secs: INTERVAL_SECS,
            created_at: now_s.clone(),
            expires_at: later.clone(),
        })
        .collect();
    let seeded = rows.len();
    let r: Result<usize> = async {
        Ok(db_interact!(o.db, |c| {
            diesel::insert_into(oauth_device_codes::table)
                .values(&rows)
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), seeded);
    // 1000 undecided (one accepted, 999 pending) beside an approved and a denied row.
    let refused = create(&o.db, ISSUER, &registered(o, DEV).await, &[], now).await;
    assert_eq!(refusal(refused), Refused::TooManyPending);

    let expire_one: Result<usize> = async {
        Ok(db_interact!(o.db, |c| {
            diesel::update(oauth_device_codes::table.find("h-5"))
                .set(oauth_device_codes::expires_at.eq(past))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(expire_one.unwrap(), 1);
    create_at(o, DEV, now).await;
    let refused = create(&o.db, ISSUER, &registered(o, DEV).await, &[], now).await;
    assert_eq!(refusal(refused), Refused::TooManyPending);
    // Another client has its own budget.
    create_at(o, DEV_PUB, now).await;
    let a = post(&app, DEVICE_AUTHORIZATION_PATH, &[], true).await;
    assert_error(&a, StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
}

#[tokio::test]
async fn user_codes_are_unique_among_stored_rows() {
    let (_, state) = app().await;
    let o = &state.oauth;
    let now = Utc::now();
    let first = create_at(o, DEV, now).await;
    let row = |hash: &str| NewDevice {
        device_code_hash: hash.to_string(),
        user_code: first.user_code.clone(),
        client_id: DEV_PUB.to_string(),
        scope: "[]".to_string(),
        status: PENDING.to_string(),
        interval_secs: INTERVAL_SECS,
        created_at: rfc3339(now),
        expires_at: rfc3339(now + chrono::Duration::seconds(600)),
    };
    let taken = insert(&o.db, row("other"), &rfc3339(now)).await.unwrap();
    assert!(matches!(
        taken,
        Err(DieselError::DatabaseError(
            DatabaseErrorKind::UniqueViolation,
            _
        ))
    ));
    // An expired row keeps its user code until it is pruned.
    let later = now + chrono::Duration::seconds(700);
    let taken = insert(&o.db, row("later"), &rfc3339(later)).await.unwrap();
    assert!(taken.is_err());

    let mut codes: Vec<String> = Vec::new();
    for _ in 0..50 {
        codes.push(create_at(o, DEV_PUB, now).await.user_code);
    }
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 50);
}

#[tokio::test]
async fn polling_faster_than_the_interval_is_slow_down_and_raises_it_for_good() {
    let (_, state) = app().await;
    let o = &state.oauth;
    let t0 = Utc::now();
    let secs = chrono::Duration::seconds;
    let a = create_at(o, DEV, t0).await;
    let code = a.device_code.as_str();

    assert!(matches!(poll_at(o, DEV, code, t0).await, Polled::Pending));
    assert!(matches!(
        poll_at(o, DEV, code, t0 + secs(1)).await,
        Polled::SlowDown
    ));
    assert_eq!(stored(&o.db, code).await.unwrap().4, 10);
    // The raised interval counts from the slow_down poll.
    assert!(matches!(
        poll_at(o, DEV, code, t0 + secs(10)).await,
        Polled::SlowDown
    ));
    assert_eq!(stored(&o.db, code).await.unwrap().4, 15);
    assert!(matches!(
        poll_at(o, DEV, code, t0 + secs(25)).await,
        Polled::Pending
    ));
    assert!(matches!(
        poll_at(o, DEV, code, t0 + secs(40)).await,
        Polled::Pending
    ));
    assert_eq!(stored(&o.db, code).await.unwrap().4, 15);
    // An accepted request is still undecided.
    set_status(&o.db, code, ACCEPTED).await;
    assert!(matches!(
        poll_at(o, DEV, code, t0 + secs(41)).await,
        Polled::SlowDown
    ));
    assert!(matches!(
        poll_at(o, DEV, code, t0 + secs(61)).await,
        Polled::Pending
    ));
}

#[tokio::test]
async fn the_token_endpoint_answers_the_rfc_8628_errors() {
    let (app, state) = app().await;
    let body = authorize_dev(&app, "openid").await;
    let code = body["device_code"].as_str().unwrap();

    let a = poll_dev(&app, code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "authorization_pending");
    let a = poll_dev(&app, code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "slow_down");

    set_status(&state.db, code, DENIED).await;
    let a = poll_dev(&app, code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "access_denied");

    let a = poll_dev(&app, "unknown").await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
    let a = post(&app, TOKEN_PATH, &[("grant_type", DEVICE_CODE_GRANT)], true).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_request");
    // Another client's device code.
    let pairs = [
        ("grant_type", DEVICE_CODE_GRANT),
        ("device_code", code),
        ("client_id", DEV_PUB),
    ];
    let a = post(&app, TOKEN_PATH, &pairs, false).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
    // A client without the device grant.
    let pairs = [
        ("grant_type", DEVICE_CODE_GRANT),
        ("device_code", code),
        ("client_id", "pub"),
    ];
    let a = post(&app, TOKEN_PATH, &pairs, false).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "unauthorized_client");
}

#[tokio::test]
async fn an_expired_device_code_answers_expired_token_whatever_its_status() {
    let (app, state) = app().await;
    let o = &state.oauth;
    let then = Utc::now() - chrono::Duration::seconds(601);
    for status in [PENDING, ACCEPTED, APPROVED, DENIED] {
        let a = create_at(o, DEV, then).await;
        if status == APPROVED {
            approve_device(o, &a.device_code, "alice", &["openid"]).await;
        } else {
            set_status(&o.db, &a.device_code, status).await;
        }
        let answer = poll_dev(&app, &a.device_code).await;
        assert_error(&answer, StatusCode::BAD_REQUEST, "expired_token");
    }
}

#[tokio::test]
async fn an_approved_device_code_redeems_once() {
    let (app, state) = app().await;
    let o = &state.oauth;
    let body = authorize_dev(&app, "openid offline_access").await;
    let code = body["device_code"].as_str().unwrap();
    let grant_id = approve_device(o, code, "alice", &["openid", "offline_access"]).await;

    let a = poll_dev(&app, code).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_no_store(&a);
    assert_eq!(a.body["scope"], "openid offline_access");
    let refresh_token = a.body["refresh_token"].as_str().unwrap().to_string();
    let id_token = a.body["id_token"].as_str().unwrap();
    let claims = verify_id_token(o, id_token, ISSUER, DEV, 60).await.unwrap();
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.acr.as_deref(), Some("aal1"));
    assert_eq!(claims.amr, strings(&["pwd"]));
    let access = o
        .verify_jwt(
            a.body["access_token"].as_str().unwrap(),
            Typ::AccessToken,
            None,
        )
        .await
        .unwrap();
    assert_eq!(access["gid"], grant_id.as_str());
    assert_eq!(access["client_id"], DEV);

    // A second redemption is a replay: refused, and the refresh token goes with its family.
    let a = poll_dev(&app, code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
    let pairs = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
    ];
    let a = post(&app, TOKEN_PATH, &pairs, true).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
}

#[tokio::test]
async fn an_approved_code_whose_grant_was_revoked_is_invalid_grant() {
    let (app, state) = app().await;
    let o = &state.oauth;
    let body = authorize_dev(&app, "openid").await;
    let code = body["device_code"].as_str().unwrap();
    let grant_id = approve_device(o, code, "alice", &["openid"]).await;
    o.revoke_consent_sessions_by_request_id(&grant_id)
        .await
        .unwrap();
    let a = poll_dev(&app, code).await;
    assert_error(&a, StatusCode::BAD_REQUEST, "invalid_grant");
}

/// `claims` over the defaults of an ID token for [`DEV`], signed by the active key.
fn id_token_with(o: &NativeOAuth, claims: &[(&str, Value)]) -> String {
    let now = Utc::now().timestamp();
    let mut all = json!({
        "iss": ISSUER, "sub": "alice", "aud": [DEV], "iat": now, "exp": now + 600,
    });
    for (k, v) in claims {
        all[*k] = v.clone();
    }
    jwt::sign(&o.keys().unwrap(), Typ::IdToken, &all).unwrap()
}

#[tokio::test]
async fn verify_id_token_checks_issuer_audience_and_iat() {
    let (_, state) = app().await;
    let o = &state.oauth;
    let now = Utc::now().timestamp();
    let ok = id_token_with(o, &[]);
    assert_eq!(
        verify_id_token(o, &ok, ISSUER, DEV, 60).await.unwrap().sub,
        "alice"
    );
    let one = id_token_with(o, &[("aud", json!(DEV))]);
    assert!(verify_id_token(o, &one, ISSUER, DEV, 60).await.is_ok());
    // The ID token claims as the trait sees them.
    let claims = o.verify_id_token(&ok, ISSUER, DEV, 60).await.unwrap();
    assert_eq!(
        (claims.acr, claims.amr, claims.auth_time),
        (None, vec![], None)
    );

    let refused = [
        (id_token_with(o, &[]), "https://other.example", DEV),
        (id_token_with(o, &[]), ISSUER, DEV_PUB),
        (
            id_token_with(o, &[("aud", json!([DEV, DEV_PUB]))]),
            ISSUER,
            DEV,
        ),
        (id_token_with(o, &[("aud", json!([DEV_PUB]))]), ISSUER, DEV),
        (
            id_token_with(o, &[("iss", json!("https://other.example"))]),
            "https://other.example",
            DEV,
        ),
        (id_token_with(o, &[("iat", json!(now - 61))]), ISSUER, DEV),
        (id_token_with(o, &[("iat", json!(now + 120))]), ISSUER, DEV),
        (id_token_with(o, &[("exp", json!(now - 120))]), ISSUER, DEV),
        (id_token_with(o, &[("sub", Value::Null)]), ISSUER, DEV),
    ];
    for (i, (token, issuer, client_id)) in refused.iter().enumerate() {
        assert!(
            verify_id_token(o, token, issuer, client_id, 60)
                .await
                .is_err(),
            "case {i}"
        );
    }
    let all = json!({"iss": ISSUER, "sub": "alice", "aud": [DEV], "iat": now, "exp": now + 600});
    let access_typed = jwt::sign(&o.keys().unwrap(), Typ::AccessToken, &all).unwrap();
    assert!(
        verify_id_token(o, &access_typed, ISSUER, DEV, 60)
            .await
            .is_err()
    );
    assert!(
        verify_id_token(o, "not.a.jwt", ISSUER, DEV, 60)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_trait_methods_run_the_same_rules_in_process() {
    let (_, state) = app().await;
    let o = &state.oauth;
    let pam = crate::oauth::device::pam_client_model("forseti-linux-pam", "pam-secret");
    o.create_client(pam).await.unwrap();
    let pam_id = "forseti-linux-pam";

    let a = o
        .device_authorization(pam_id, "pam-secret", "openid")
        .await
        .unwrap();
    assert_eq!(a.verification_uri, format!("{ISSUER}/oauth/device"));
    assert_eq!((a.expires_in, a.interval), (600, 5));
    assert!(
        o.device_authorization(pam_id, "wrong", "openid")
            .await
            .is_err()
    );
    assert!(
        o.device_authorization(pam_id, "pam-secret", "openid email")
            .await
            .is_err()
    );
    assert!(o.device_authorization(DEV_PUB, "", "openid").await.is_err());
    assert!(
        o.device_authorization("basic", "basic-secret", "openid")
            .await
            .is_err()
    );

    let poll = |code: String| async move {
        o.poll_device_token(pam_id, "pam-secret", &code)
            .await
            .unwrap()
    };
    assert!(matches!(
        poll(a.device_code.clone()).await,
        DeviceTokenOutcome::Pending
    ));
    assert!(matches!(
        poll(a.device_code.clone()).await,
        DeviceTokenOutcome::SlowDown
    ));
    assert!(matches!(
        o.poll_device_token(pam_id, "wrong", &a.device_code)
            .await
            .unwrap(),
        DeviceTokenOutcome::Expired
    ));
    assert!(matches!(
        poll("unknown".to_string()).await,
        DeviceTokenOutcome::Expired
    ));
    assert!(matches!(
        o.poll_device_token("basic", "basic-secret", &a.device_code)
            .await
            .unwrap(),
        DeviceTokenOutcome::Expired
    ));

    approve_device(o, &a.device_code, "alice", &["openid"]).await;
    let DeviceTokenOutcome::Token(tokens) = poll(a.device_code.clone()).await else {
        panic!("expected tokens");
    };
    assert_eq!(tokens.expires_in, ACCESS_TOKEN_TTL_SECS);
    let id_token = tokens.id_token.as_deref().unwrap();
    let claims = o
        .verify_id_token(id_token, o.issuer(), pam_id, 60)
        .await
        .unwrap();
    assert_eq!(claims.sub, "alice");
    assert!(
        o.verify_id_token(id_token, "https://hydra.example", pam_id, 60)
            .await
            .is_err()
    );
    // Consumed: a replay is a dead flow.
    assert!(matches!(
        poll(a.device_code.clone()).await,
        DeviceTokenOutcome::Expired
    ));

    let denied = o
        .device_authorization(pam_id, "pam-secret", "openid")
        .await
        .unwrap();
    set_status(&o.db, &denied.device_code, DENIED).await;
    assert!(matches!(
        poll(denied.device_code).await,
        DeviceTokenOutcome::Denied
    ));
    // Only a pending user code can be accepted.
    assert!(o.accept_user_code_request("c", &a.user_code).await.is_err());
}

#[tokio::test]
async fn the_device_authorization_endpoint_is_rate_limited() {
    let (app, _) = app().await;
    let send = || async {
        let req = Request::post(DEVICE_AUTHORIZATION_PATH)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(with_peer(req)).await.unwrap()
    };
    for _ in 0..300 {
        assert_eq!(send().await.status(), StatusCode::BAD_REQUEST);
    }
    let resp = send().await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn concurrent_polls_of_an_approved_device_code_redeem_once_on_postgres() {
    const ROUNDS: usize = 10;
    let setup = crate::db::test_postgres_pool().await;
    let o = backend_on(&setup).await;
    let client_id = format!("device-race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("subject-{}", uuid::Uuid::new_v4().simple());
    o.create_client(device_client(&client_id, clients::AUTH_NONE))
        .await
        .unwrap();
    let client = registered(&o, &client_id).await;
    let a = backend_on(&crate::db::test_postgres_pool().await).await;
    let b = backend_on(&crate::db::test_postgres_pool().await).await;

    let mut wins = Vec::new();
    for _ in 0..ROUNDS {
        let issued = create(&o.db, ISSUER, &client, &strings(OFFLINE), Utc::now())
            .await
            .unwrap();
        approve_device(&o, &issued.device_code, &subject, OFFLINE).await;
        let now = Utc::now();
        let (ra, rb) = tokio::join!(
            poll(&a.db, &client, &issued.device_code, &[], now),
            poll(&b.db, &client, &issued.device_code, &[], now)
        );
        let won = [ra, rb]
            .into_iter()
            .filter(|r| matches!(r, Ok(Polled::Issued(_))))
            .count();
        wins.push(won);
    }

    o.delete_client(&client_id).await.unwrap();
    assert!(wins.iter().all(|w| *w == 1), "{wins:?}");
}
