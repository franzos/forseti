use chrono::{Duration, TimeZone, Utc};

use super::*;

const REDIRECT: &str = "https://app.example/cb";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const BASE: [(&str, &str); 5] = [
    ("client_id", "app"),
    ("redirect_uri", REDIRECT),
    ("response_type", "code"),
    ("scope", "openid"),
    ("state", "xyz"),
];

fn client() -> OAuthClient {
    OAuthClient {
        client_id: Some("app".to_string()),
        redirect_uris: Some(vec![REDIRECT.to_string()]),
        scope: Some("openid email offline_access".to_string()),
        audience: Some(vec![
            "stackpit-web".to_string(),
            "https://api.example".to_string(),
        ]),
        token_endpoint_auth_method: Some("client_secret_basic".to_string()),
        ..OAuthClient::default()
    }
}

fn public_client() -> OAuthClient {
    OAuthClient {
        token_endpoint_auth_method: Some(AUTH_NONE.to_string()),
        ..client()
    }
}

fn encode(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// `BASE` with `changes` applied: an existing name is replaced, a new one appended, and an empty
/// value removes the name.
fn params(changes: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = BASE
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    for (k, v) in changes {
        out.retain(|(name, _)| name != k);
        if !v.is_empty() {
            out.push(((*k).to_string(), (*v).to_string()));
        }
    }
    out
}

fn raw(changes: &[(&str, &str)]) -> String {
    let p = params(changes);
    let refs: Vec<(&str, &str)> = p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    encode(&refs)
}

fn check(c: &OAuthClient, raw: &str) -> Result<AuthorizeRequest, AuthorizeError> {
    validate(&AuthorizeQuery::parse(raw), Some(c))
}

fn ok(changes: &[(&str, &str)]) -> AuthorizeRequest {
    check(&client(), &raw(changes)).unwrap_or_else(|e| panic!("{changes:?}: {e:?}"))
}

fn page(c: &OAuthClient, raw: &str) -> PageError {
    match check(c, raw) {
        Err(AuthorizeError::Page(e)) => e,
        other => panic!("{raw}: expected a page error, got {other:?}"),
    }
}

fn redirected(c: &OAuthClient, raw: &str) -> RedirectError {
    match check(c, raw) {
        Err(AuthorizeError::Redirect(e)) => e,
        other => panic!("{raw}: expected a redirect error, got {other:?}"),
    }
}

fn code(changes: &[(&str, &str)]) -> ErrorCode {
    redirected(&client(), &raw(changes)).error
}

fn client_with_redirects(uris: &[&str]) -> OAuthClient {
    OAuthClient {
        redirect_uris: Some(uris.iter().map(|u| (*u).to_string()).collect()),
        ..client()
    }
}

fn redirect_result(registered: &[&str], requested: &str) -> Result<String, PageError> {
    let c = client_with_redirects(registered);
    match check(&c, &raw(&[("redirect_uri", requested)])) {
        Ok(r) => Ok(r.delivery.redirect_uri),
        Err(AuthorizeError::Page(e)) => Err(e),
        Err(e) => panic!("{requested}: {e:?}"),
    }
}

#[test]
fn accepts_a_minimal_code_request() {
    let r = ok(&[]);
    assert_eq!(r.client_id, "app");
    assert_eq!(
        r.delivery,
        Delivery {
            redirect_uri: REDIRECT.to_string(),
            mode: ResponseMode::Query,
            state: Some("xyz".to_string()),
        }
    );
    assert_eq!(r.scope, ["openid"]);
    assert_eq!(r.code_challenge, None);
    assert_eq!(r.prompt, Prompt::default());
}

#[test]
fn redirect_uri_table() {
    use PageError::{InvalidRedirectUri as Invalid, UnregisteredRedirectUri as Unreg};
    let https = ["https://app.example/cb"];
    let lh = ["http://localhost:8080/cb"];
    let v4 = ["http://127.0.0.1:8080/cb"];
    let v6 = ["http://[::1]:8080/cb"];
    let cases: &[(&[&str], &str, Result<(), PageError>)] = &[
        (&https, "https://app.example/cb", Ok(())),
        (&https, "https://app.example/cb/", Err(Unreg)),
        (&https, "https://APP.example/cb", Err(Unreg)),
        (&https, "https://app.example/CB", Err(Unreg)),
        (&https, "https://app.example:443/cb", Err(Unreg)),
        (&https, "https://app.example/cb?x=1", Err(Unreg)),
        (&https, "https://app.example/%63b", Err(Unreg)),
        (
            &["https://app.example/a%2Fb"],
            "https://app.example/a/b",
            Err(Unreg),
        ),
        (
            &["https://app.example/a%2Fb"],
            "https://app.example/a%2fb",
            Err(Unreg),
        ),
        (&https, "https://other.example/cb", Err(Unreg)),
        (&https, "https://app.example/cb#frag", Err(Invalid)),
        (&https, "https://app.example/cb#", Err(Invalid)),
        (&https, "https://user@app.example/cb", Err(Invalid)),
        (&https, "https://user:pw@app.example/cb", Err(Invalid)),
        (&https, "https://@app.example/cb", Err(Invalid)),
        (&https, "/cb", Err(Invalid)),
        (&lh, "http://localhost:8080/cb", Ok(())),
        (&lh, "http://localhost:51234/cb", Ok(())),
        (&lh, "http://localhost/cb", Ok(())),
        (&["http://localhost/cb"], "http://localhost:9/cb", Ok(())),
        (&lh, "http://localhost:51234/other", Err(Unreg)),
        (&lh, "http://localhost:51234/cb?x=1", Err(Unreg)),
        (&lh, "http://localhost:/cb", Err(Unreg)),
        (&lh, "http://localhost:99999/cb", Err(Invalid)),
        (&lh, "http://localhost:+80/cb", Err(Invalid)),
        (&lh, "http://LOCALHOST:51234/cb", Err(Unreg)),
        (&lh, "http://127.0.0.1:51234/cb", Err(Unreg)),
        (&lh, "http://localhost:51234/cb#x", Err(Invalid)),
        (&lh, "http://u@localhost:51234/cb", Err(Invalid)),
        (&v4, "http://127.0.0.1:1/cb", Ok(())),
        (&v6, "http://[::1]:1/cb", Ok(())),
        (&v6, "http://[::1]/cb", Ok(())),
        (
            &["https://localhost:8080/cb"],
            "https://localhost:9/cb",
            Err(Unreg),
        ),
        (
            &["https://127.0.0.1:8080/cb"],
            "https://127.0.0.1:9/cb",
            Err(Unreg),
        ),
        (
            &["http://localhost.evil.com:8080/cb"],
            "http://localhost.evil.com:9/cb",
            Err(Unreg),
        ),
        (&lh, "http://localhost.evil.com:8080/cb", Err(Unreg)),
        (
            &["http://127.0.0.1.evil.com:8080/cb"],
            "http://127.0.0.1.evil.com:9/cb",
            Err(Unreg),
        ),
        (&["http://127.1:8080/cb"], "http://127.1:9/cb", Err(Unreg)),
        (&v4, "http://127.1:8080/cb", Err(Unreg)),
        (
            &["http://[::1%25eth0]:8080/cb"],
            "http://[::1%25eth0]:9/cb",
            Err(Invalid),
        ),
        (&v6, "http://[::1%25eth0]:8080/cb", Err(Invalid)),
        (
            &[
                "https://a.example/cb",
                "com.example.app:/oauth",
                "http://localhost:1/cb",
            ],
            "com.example.app:/oauth",
            Ok(()),
        ),
        (
            &[
                "https://a.example/cb",
                "com.example.app:/oauth",
                "http://localhost:1/cb",
            ],
            "http://localhost:2/cb",
            Ok(()),
        ),
        (
            &["https://a.example/cb", "com.example.app:/oauth"],
            "https://b.example/cb",
            Err(Unreg),
        ),
        (&[], "https://app.example/cb", Err(Unreg)),
    ];
    for (registered, requested, want) in cases {
        let got = redirect_result(registered, requested);
        match want {
            Ok(()) => assert_eq!(got.as_deref(), Ok(*requested), "{registered:?} {requested}"),
            Err(e) => assert_eq!(got, Err(*e), "{registered:?} {requested}"),
        }
    }
}

#[test]
fn missing_redirect_uri_and_unknown_client_stay_on_the_error_page() {
    assert_eq!(
        page(&client(), &raw(&[("redirect_uri", "")])),
        PageError::MissingRedirectUri
    );
    let unknown = OAuthClient {
        client_id: Some("other".to_string()),
        ..client()
    };
    assert_eq!(page(&unknown, &raw(&[])), PageError::UnknownClient);
    assert_eq!(
        page(&client(), &raw(&[("client_id", "")])),
        PageError::UnknownClient
    );
    assert_eq!(
        validate(&AuthorizeQuery::parse(&raw(&[])), None),
        Err(AuthorizeError::Page(PageError::UnknownClient))
    );
}

#[test]
fn pkce() {
    let public = public_client();
    let with = |changes: &[(&str, &str)]| raw(changes);
    let s256 = [
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];

    let r = check(&public, &with(&s256)).unwrap();
    assert_eq!(r.code_challenge.as_deref(), Some(CHALLENGE));

    let refused: &[&[(&str, &str)]] = &[
        &[],
        &[("code_challenge", CHALLENGE)],
        &[
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "plain"),
        ],
        &[
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "s256"),
        ],
        &[("code_challenge_method", "S256")],
        &[
            ("code_challenge", &CHALLENGE[..42]),
            ("code_challenge_method", "S256"),
        ],
        &[
            ("code_challenge", &format!("{CHALLENGE}A")),
            ("code_challenge_method", "S256"),
        ],
        &[
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
            ),
            ("code_challenge_method", "S256"),
        ],
        &[
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw=cM",
            ),
            ("code_challenge_method", "S256"),
        ],
    ];
    for changes in refused {
        for c in [&public, &client()] {
            if changes.is_empty() && c == &client() {
                continue;
            }
            let e = redirected(c, &with(changes));
            assert_eq!(e.error, ErrorCode::InvalidRequest, "{changes:?}");
        }
    }

    let confidential = check(&client(), &with(&[])).unwrap();
    assert_eq!(confidential.code_challenge, None);
    let confidential = check(&client(), &with(&s256)).unwrap();
    assert_eq!(confidential.code_challenge.as_deref(), Some(CHALLENGE));
}

#[test]
fn response_type_variants() {
    assert_eq!(code(&[("response_type", "")]), ErrorCode::InvalidRequest);
    for rt in [
        "token",
        "id_token",
        "code id_token",
        "code token",
        "none",
        "CODE",
    ] {
        assert_eq!(
            code(&[("response_type", rt)]),
            ErrorCode::UnsupportedResponseType,
            "{rt}"
        );
    }
}

#[test]
fn the_client_must_be_registered_for_the_code_flow() {
    let with = |grants: Option<&[&str]>, responses: Option<&[&str]>| OAuthClient {
        grant_types: grants.map(|g| g.iter().map(|s| (*s).to_string()).collect()),
        response_types: responses.map(|r| r.iter().map(|s| (*s).to_string()).collect()),
        ..client()
    };
    for c in [
        with(None, None),
        with(Some(&[]), Some(&[])),
        with(
            Some(&["refresh_token", "authorization_code"]),
            Some(&["code"]),
        ),
    ] {
        assert!(check(&c, &raw(&[])).is_ok(), "{c:?}");
    }
    for c in [
        with(Some(&["client_credentials"]), None),
        with(
            Some(&["urn:ietf:params:oauth:grant-type:device_code"]),
            None,
        ),
        with(Some(&["authorization_code"]), Some(&["token"])),
    ] {
        let e = redirected(&c, &raw(&[]));
        assert_eq!(e.error, ErrorCode::UnauthorizedClient, "{c:?}");
        assert_eq!(e.error.as_str(), "unauthorized_client");
        assert_eq!(e.delivery.redirect_uri, REDIRECT);
        assert_eq!(e.delivery.state.as_deref(), Some("xyz"));
    }
}

#[test]
fn scope() {
    assert_eq!(ok(&[("scope", "openid email")]).scope, ["openid", "email"]);
    assert_eq!(
        ok(&[("scope", "openid openid  email")]).scope,
        ["openid", "email"]
    );
    assert!(ok(&[("scope", "")]).scope.is_empty());
    assert_eq!(code(&[("scope", "openid groups")]), ErrorCode::InvalidScope);
    assert_eq!(code(&[("scope", "OPENID")]), ErrorCode::InvalidScope);
    let no_scope = OAuthClient {
        scope: None,
        ..client()
    };
    assert_eq!(
        redirected(&no_scope, &raw(&[])).error,
        ErrorCode::InvalidScope
    );
}

#[test]
fn request_objects_are_refused() {
    assert_eq!(
        code(&[("request", "eyJ.e30.x")]),
        ErrorCode::RequestNotSupported
    );
    assert_eq!(
        code(&[("request_uri", "urn:ietf:params:oauth:request_uri:x")]),
        ErrorCode::RequestUriNotSupported
    );
}

#[test]
fn prompt() {
    assert_eq!(
        ok(&[("prompt", "login consent")]).prompt,
        Prompt {
            login: true,
            consent: true,
            ..Prompt::default()
        }
    );
    assert!(ok(&[("prompt", "none")]).prompt.none);
    assert!(ok(&[("prompt", "create")]).prompt.create);
    for p in ["none login", "consent none", "none create"] {
        assert_eq!(code(&[("prompt", p)]), ErrorCode::InvalidRequest, "{p}");
    }
    assert!(ok(&[("prompt", "select_account")]).prompt.select_account);
    assert_eq!(
        ok(&[("prompt", "select_account login")]).prompt,
        Prompt {
            login: true,
            select_account: true,
            ..Prompt::default()
        }
    );
    assert_eq!(
        code(&[("prompt", "none select_account")]),
        ErrorCode::InvalidRequest
    );
    for p in ["select-account", "login bogus", "NONE", "registration"] {
        assert_eq!(code(&[("prompt", p)]), ErrorCode::InvalidRequest, "{p}");
    }
}

#[test]
fn max_age() {
    assert_eq!(ok(&[("max_age", "0")]).max_age, Some(0));
    assert_eq!(ok(&[("max_age", "3600")]).max_age, Some(3600));
    assert_eq!(
        ok(&[("max_age", "99999999999999999999999")]).max_age,
        Some(u64::MAX)
    );
    for v in ["-1", "abc", "1.5", "+5", " 5"] {
        assert_eq!(code(&[("max_age", v)]), ErrorCode::InvalidRequest, "{v}");
    }
}

#[test]
fn audience() {
    assert_eq!(
        ok(&[("audience", "stackpit-web")]).audience,
        ["stackpit-web"]
    );
    let spaced = ok(&[("audience", "stackpit-web https://api.example")]);
    assert_eq!(spaced.audience, ["stackpit-web", "https://api.example"]);
    let repeated = format!(
        "{}&audience=stackpit-web&audience=https%3A%2F%2Fapi.example&audience=stackpit-web",
        raw(&[])
    );
    assert_eq!(
        check(&client(), &repeated).unwrap().audience,
        ["stackpit-web", "https://api.example"]
    );
    assert_eq!(code(&[("audience", "other")]), ErrorCode::InvalidRequest);
    assert_eq!(
        code(&[("audience", "stackpit-web other")]),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        code(&[("audience", "https://api.example/")]),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn resource() {
    let several = format!(
        "{}&resource=https%3A%2F%2Fmcp.example%2Fmcp&resource=urn%3Aexample%3Aapi",
        raw(&[])
    );
    assert_eq!(
        check(&client(), &several).unwrap().resource,
        ["https://mcp.example/mcp", "urn:example:api"]
    );
    for v in [
        "/mcp",
        "mcp.example",
        "https://mcp.example/mcp#x",
        "https://mcp.example/#",
        "https://mcp.example/ mcp",
        " https://mcp.example/mcp",
        "https://mcp.example/mcp\t",
        "https://mcp.example/\nmcp",
        "https://mcp.example/\u{7f}mcp",
        "https://mcp.example/\u{0}mcp",
    ] {
        assert_eq!(code(&[("resource", v)]), ErrorCode::InvalidTarget, "{v}");
    }
}

#[test]
fn response_mode_and_error_delivery() {
    assert_eq!(
        ok(&[("response_mode", "form_post")]).delivery.mode,
        ResponseMode::FormPost
    );
    assert_eq!(
        ok(&[("response_mode", "query")]).delivery.mode,
        ResponseMode::Query
    );
    for m in ["fragment", "jwt", "FORM_POST"] {
        let e = redirected(&client(), &raw(&[("response_mode", m)]));
        assert_eq!(e.error, ErrorCode::InvalidRequest, "{m}");
        assert_eq!(e.delivery.mode, ResponseMode::Query, "{m}");
    }
    let loopback = client_with_redirects(&["http://127.0.0.1:1/cb"]);
    let r = check(
        &loopback,
        &raw(&[
            ("redirect_uri", "http://127.0.0.1:2/cb"),
            ("response_mode", "form_post"),
        ]),
    )
    .unwrap();
    assert_eq!(r.delivery.mode, ResponseMode::FormPost);
    for uri in ["com.example.app:/oauth", "myapp:/cb"] {
        let app = client_with_redirects(&[uri]);
        let e = redirected(
            &app,
            &raw(&[("redirect_uri", uri), ("response_mode", "form_post")]),
        );
        assert_eq!(e.error, ErrorCode::InvalidRequest, "{uri}");
        assert_eq!(e.delivery.mode, ResponseMode::Query, "{uri}");
        assert_eq!(e.delivery.redirect_uri, uri);
    }
    let e = redirected(
        &client(),
        &raw(&[("response_mode", "form_post"), ("response_type", "token")]),
    );
    assert_eq!(e.delivery.mode, ResponseMode::FormPost);
    assert_eq!(e.delivery.state.as_deref(), Some("xyz"));
    assert_eq!(e.delivery.redirect_uri, REDIRECT);

    let e = redirected(
        &client(),
        &raw(&[("state", ""), ("response_type", "token")]),
    );
    assert_eq!(e.delivery.state, None);
}

#[test]
fn duplicates() {
    let base = raw(&[]);
    let page_cases = [
        (
            "client_id",
            "app",
            PageError::DuplicateParameter("client_id"),
        ),
        (
            "redirect_uri",
            REDIRECT,
            PageError::DuplicateParameter("redirect_uri"),
        ),
    ];
    for (name, value, want) in page_cases {
        let q = format!("{base}&{}", encode(&[(name, value)]));
        assert_eq!(page(&client(), &q), want, "{name}");
    }
    // A duplicate client_id is refused even when the second copy differs.
    let q = format!("{base}&client_id=other");
    assert_eq!(
        page(&client(), &q),
        PageError::DuplicateParameter("client_id")
    );

    let late = [
        ("response_type", "code"),
        ("scope", "openid"),
        ("nonce", "n"),
        ("code_challenge", CHALLENGE),
        ("prompt", "login"),
        ("max_age", "5"),
        ("login_hint", "a"),
        ("request", "x"),
    ];
    for (name, value) in late {
        let q = format!(
            "{base}&{}&{}",
            encode(&[(name, value)]),
            encode(&[(name, value)])
        );
        let e = redirected(&client(), &q);
        assert_eq!(e.error, ErrorCode::InvalidRequest, "{name}");
        assert_eq!(e.delivery.state.as_deref(), Some("xyz"), "{name}");
    }

    let e = redirected(&client(), &format!("{base}&state=again"));
    assert_eq!(e.error, ErrorCode::InvalidRequest);
    assert_eq!(e.delivery.state, None);

    let e = redirected(
        &client(),
        &format!("{base}&response_mode=form_post&response_mode=form_post"),
    );
    assert_eq!(e.error, ErrorCode::InvalidRequest);
    assert_eq!(e.delivery.mode, ResponseMode::Query);

    // An empty copy still makes a duplicate.
    for (name, want) in [("client_id", "app"), ("redirect_uri", REDIRECT)] {
        for q in [
            format!("{base}&{name}="),
            format!("{name}=&{base}"),
            format!("{base}&{name}=&{name}="),
        ] {
            assert_eq!(
                page(&client(), &q),
                PageError::DuplicateParameter(name),
                "{q}"
            );
        }
        let alone = raw(&[(name, "")]);
        assert!(
            matches!(
                check(
                    &client(),
                    &format!("{alone}&{name}=&{}", encode(&[(name, want)]))
                ),
                Err(AuthorizeError::Page(PageError::DuplicateParameter(_)))
            ),
            "{name}"
        );
    }
    for q in [
        format!("{base}&idp_hint=&idp_hint=x"),
        format!("{base}&nonce=&nonce=n"),
        format!("{base}&state="),
    ] {
        assert_eq!(
            redirected(&client(), &q).error,
            ErrorCode::InvalidRequest,
            "{q}"
        );
    }
    // A lone empty value is omitted.
    let r = check(&client(), &format!("{base}&idp_hint=&nonce=")).unwrap();
    assert_eq!((r.idp_hint, r.nonce), (None, None));
    assert!(
        check(
            &client(),
            &format!("{base}&audience=stackpit-web&audience=stackpit-web")
        )
        .is_ok()
    );
}

#[test]
fn carries_what_the_handlers_read() {
    let r = ok(&[
        ("nonce", "n-1"),
        ("acr_values", "aal2 aal1"),
        ("login_hint", "alice@example.com"),
        ("ui_locales", "de en"),
        ("display", "popup"),
        ("id_token_hint", "eyJ.e30.sig"),
        ("idp_hint", "github"),
    ]);
    assert_eq!(r.nonce.as_deref(), Some("n-1"));
    assert_eq!(r.display.as_deref(), Some("popup"));
    assert_eq!(r.id_token_hint.as_deref(), Some("eyJ.e30.sig"));
    assert_eq!(r.idp_hint.as_deref(), Some("github"));
    assert_eq!(
        r.oidc_context(),
        OidcContext {
            acr_values: Some(vec!["aal2".to_string(), "aal1".to_string()]),
            login_hint: Some("alice@example.com".to_string()),
            ui_locales: Some(vec!["de".to_string(), "en".to_string()]),
        }
    );
    assert_eq!(ok(&[]).oidc_context(), OidcContext::default());
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 24, 12, 0, 0).unwrap()
}

fn session(auth_age_secs: i64) -> LoginSessionSnapshot {
    LoginSessionSnapshot {
        sid: "sid-1".to_string(),
        auth_time: now() - Duration::seconds(auth_age_secs),
        remember: true,
        expires_at: now() + Duration::hours(1),
    }
}

/// Name, prompt, `max_age`, session, expected step.
type SkipCase<'a> = (
    &'a str,
    Prompt,
    Option<u64>,
    Option<&'a LoginSessionSnapshot>,
    LoginStep,
);

#[test]
fn skip_decision_table() {
    let none = Prompt {
        none: true,
        ..Prompt::default()
    };
    let login = Prompt {
        login: true,
        ..Prompt::default()
    };
    let create = Prompt {
        create: true,
        ..Prompt::default()
    };
    let consent = Prompt {
        consent: true,
        ..Prompt::default()
    };
    let plain = Prompt::default();
    let fresh = session(60);
    let skip = LoginStep::Skip {
        sid: "sid-1".to_string(),
        auth_time: fresh.auth_time,
    };
    let expired = LoginSessionSnapshot {
        expires_at: now(),
        ..fresh.clone()
    };
    let forgotten = LoginSessionSnapshot {
        remember: false,
        ..fresh.clone()
    };
    let cases: &[SkipCase] = &[
        ("no session", plain, None, None, LoginStep::ShowLogin),
        ("skippable", plain, None, Some(&fresh), skip.clone()),
        ("prompt=consent", consent, None, Some(&fresh), skip.clone()),
        ("expired", plain, None, Some(&expired), LoginStep::ShowLogin),
        (
            "not remembered",
            plain,
            None,
            Some(&forgotten),
            LoginStep::ShowLogin,
        ),
        (
            "prompt=login",
            login,
            None,
            Some(&fresh),
            LoginStep::ShowLogin,
        ),
        ("max_age met", plain, Some(60), Some(&fresh), skip.clone()),
        (
            "max_age exceeded",
            plain,
            Some(59),
            Some(&fresh),
            LoginStep::ShowLogin,
        ),
        (
            "max_age=0",
            plain,
            Some(0),
            Some(&session(0)),
            LoginStep::ShowLogin,
        ),
        ("none, skippable", none, None, Some(&fresh), skip.clone()),
        (
            "none, no session",
            none,
            None,
            None,
            LoginStep::LoginRequired,
        ),
        (
            "none, expired",
            none,
            None,
            Some(&expired),
            LoginStep::LoginRequired,
        ),
        (
            "none, max_age",
            none,
            Some(1),
            Some(&fresh),
            LoginStep::LoginRequired,
        ),
        (
            "create, session",
            create,
            None,
            Some(&fresh),
            LoginStep::Register,
        ),
        ("create, none", create, None, None, LoginStep::Register),
    ];
    for (name, prompt, max_age, s, want) in cases {
        assert_eq!(&login_step(prompt, *max_age, now(), *s), want, "{name}");
    }
}

#[test]
fn request_url_uses_the_issuer_and_the_raw_query() {
    let raw = "client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid+email&x=%7e";
    assert_eq!(
        request_url("https://id.example.com", raw),
        "https://id.example.com/oauth2/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid+email&x=%7e"
    );
    assert_eq!(
        request_url("https://id.example.com", ""),
        "https://id.example.com/oauth2/authorize"
    );
}
