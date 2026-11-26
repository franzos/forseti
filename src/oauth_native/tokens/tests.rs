use std::sync::Arc;

use super::*;
use crate::backend::OAuthBackend;
use crate::backend::oauth::OAuthClient;
use crate::oauth_native::NativeOAuth;
use crate::oauth_native::test_support::*;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn pkce_query(verifier: &str) -> String {
    format!(
        "&code_challenge={}&code_challenge_method=S256",
        challenge_of(verifier)
    )
}

fn exchange<'a>(client_id: &'a str, code: &'a str) -> CodeExchange<'a> {
    CodeExchange {
        client_id,
        code,
        redirect_uri: Some(REDIRECT),
        code_verifier: None,
        resource: &[],
        refresh_allowed: true,
    }
}

fn rotate<'a>(client_id: &'a str, refresh_token: &'a str) -> RefreshExchange<'a> {
    RefreshExchange {
        client_id,
        refresh_token,
        scope: None,
        resource: &[],
    }
}

fn refused(r: Result<Issued>) -> Invalid {
    let e = r.unwrap_err();
    *e.downcast_ref::<Invalid>()
        .unwrap_or_else(|| panic!("not a refusal: {e:#}"))
}

async fn offline_backend() -> Arc<NativeOAuth> {
    let o = backend().await;
    o.create_client(offline_client("app")).await.unwrap();
    o
}

async fn redeem(o: &NativeOAuth, x: &CodeExchange<'_>) -> Result<Issued> {
    redeem_code(&o.db, x, Utc::now()).await
}

async fn rotate_now(o: &NativeOAuth, x: &RefreshExchange<'_>) -> Result<Issued> {
    refresh(&o.db, x, Utc::now()).await
}

/// A redeemed offline code: the grant id, the code and the refresh token.
async fn offline_tokens(o: &NativeOAuth) -> (String, String, String) {
    let (grant_id, code) = code_with(o, "app", "alice", OFFLINE, &[API], "").await;
    let issued = redeem(o, &exchange("app", &code)).await.unwrap();
    (grant_id, code, issued.refresh_token.unwrap())
}

async fn refresh_rows(db: &DbPool) -> Vec<RefreshRow> {
    let r: Result<Vec<RefreshRow>> = async {
        Ok(db_interact!(db, |c| {
            oauth_refresh_tokens::table
                .order(oauth_refresh_tokens::created_at)
                .select(RefreshRow::as_select())
                .load(c)
        })?)
    }
    .await;
    r.unwrap()
}

async fn code_used(db: &DbPool, code: &str) -> bool {
    let hash = token_hash(code);
    let r: Result<Option<String>> = async {
        Ok(db_interact!(db, |c| {
            oauth_authorization_codes::table
                .find(hash)
                .select(oauth_authorization_codes::used_at)
                .first(c)
        })?)
    }
    .await;
    r.unwrap().is_some()
}

async fn expire_code(db: &DbPool, code: &str) {
    let (hash, past) = (
        token_hash(code),
        rfc3339(Utc::now() - chrono::Duration::seconds(1)),
    );
    let r: Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(oauth_authorization_codes::table.find(hash))
                .set(oauth_authorization_codes::expires_at.eq(past))
                .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
}

async fn expire_refresh(db: &DbPool, token: &str) {
    let (hash, past) = (
        token_hash(token),
        rfc3339(Utc::now() - chrono::Duration::seconds(1)),
    );
    let r: Result<usize> = async {
        Ok(db_interact!(db, |c| {
            diesel::update(
                oauth_refresh_tokens::table.filter(oauth_refresh_tokens::token_hash.eq(hash)),
            )
            .set(oauth_refresh_tokens::expires_at.eq(past))
            .execute(c)
        })?)
    }
    .await;
    assert_eq!(r.unwrap(), 1);
}

#[tokio::test]
async fn a_code_redeems_once_and_carries_the_grant() {
    let o = offline_backend().await;
    let (grant_id, code) = code_with(
        &o,
        "app",
        "alice",
        &["openid", "email"],
        &[API],
        "&nonce=n-1",
    )
    .await;
    let issued = redeem(&o, &exchange("app", &code)).await.unwrap();
    assert_eq!(issued.grant.id, grant_id);
    assert_eq!(issued.grant.subject, "alice");
    assert_eq!(issued.scope, strings(&["openid", "email"]));
    assert_eq!(issued.audience, strings(&[API]));
    assert_eq!(issued.nonce.as_deref(), Some("n-1"));
    assert_eq!(issued.acr.as_deref(), Some("aal1"));
    assert_eq!(issued.amr, strings(&["pwd"]));
    assert_eq!(issued.session_id, sid_of(&o.db, &grant_id).await);
    assert!(issued.refresh_token.is_none());
    assert!(code_used(&o.db, &code).await);

    assert_eq!(
        refused(redeem(&o, &exchange("app", &code)).await),
        Invalid::Grant
    );
    assert_eq!(
        refused(redeem(&o, &exchange("app", "unknown")).await),
        Invalid::Grant
    );
}

#[tokio::test]
async fn a_replayed_code_deletes_its_family() {
    let o = offline_backend().await;
    let (_, code, refresh_token) = offline_tokens(&o).await;
    let rotated = rotate_now(&o, &rotate("app", &refresh_token))
        .await
        .unwrap()
        .refresh_token
        .unwrap();
    assert_eq!(refresh_rows(&o.db).await.len(), 2);

    assert_eq!(
        refused(redeem(&o, &exchange("app", &code)).await),
        Invalid::Grant
    );
    assert!(refresh_rows(&o.db).await.is_empty());
    assert_eq!(
        refused(rotate_now(&o, &rotate("app", &rotated)).await),
        Invalid::Grant
    );
}

#[tokio::test]
async fn a_failed_earlier_check_leaves_the_code_redeemable() {
    let o = offline_backend().await;
    o.create_client(offline_client("other")).await.unwrap();
    let extra = pkce_query(VERIFIER);
    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[API], &extra).await;
    let (_, earlier, refresh_token) = offline_tokens(&o).await;

    let wrong_client = exchange("other", &code);
    let wrong_redirect = CodeExchange {
        redirect_uri: Some("https://app.example/other"),
        code_verifier: Some(VERIFIER),
        ..exchange("app", &code)
    };
    let other_verifier = "x".repeat(43);
    let wrong_verifier = CodeExchange {
        code_verifier: Some(&other_verifier),
        ..exchange("app", &code)
    };
    for x in [wrong_client, wrong_redirect, wrong_verifier] {
        assert_eq!(refused(redeem(&o, &x).await), Invalid::Grant);
        assert!(!code_used(&o.db, &code).await);
    }
    // Another client replaying a used code does not reach its family either.
    assert_eq!(
        refused(redeem(&o, &exchange("other", &earlier)).await),
        Invalid::Grant
    );
    assert_eq!(refresh_rows(&o.db).await.len(), 1);

    let ok = CodeExchange {
        code_verifier: Some(VERIFIER),
        ..exchange("app", &code)
    };
    assert!(redeem(&o, &ok).await.unwrap().refresh_token.is_some());
    assert!(rotate_now(&o, &rotate("app", &refresh_token)).await.is_ok());
}

#[tokio::test]
async fn an_expired_code_is_refused() {
    let o = offline_backend().await;
    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[API], "").await;
    expire_code(&o.db, &code).await;
    assert_eq!(
        refused(redeem(&o, &exchange("app", &code)).await),
        Invalid::Grant
    );
    assert!(!code_used(&o.db, &code).await);
    assert!(refresh_rows(&o.db).await.is_empty());
}

#[tokio::test]
async fn pkce_matrix() {
    let o = offline_backend().await;
    let extra = pkce_query(VERIFIER);
    let (_, code) = code_with(&o, "app", "alice", &["openid"], &[], &extra).await;
    let short = &VERIFIER[..42];
    let long = "a".repeat(129);
    let bad_charset = format!("{}+", &VERIFIER[..42]);
    let wrong = "x".repeat(43);
    for verifier in [
        None,
        Some(wrong.as_str()),
        Some(short),
        Some(long.as_str()),
        Some(bad_charset.as_str()),
    ] {
        let x = CodeExchange {
            code_verifier: verifier,
            ..exchange("app", &code)
        };
        assert_eq!(
            refused(redeem(&o, &x).await),
            Invalid::Grant,
            "{verifier:?}"
        );
    }
    let ok = CodeExchange {
        code_verifier: Some(VERIFIER),
        ..exchange("app", &code)
    };
    assert!(redeem(&o, &ok).await.is_ok());

    // 128 unreserved characters are a valid verifier.
    let max = "a-._~".repeat(26)[..128].to_string();
    let (_, code) = code_with(&o, "app", "alice", &["openid"], &[], &pkce_query(&max)).await;
    let x = CodeExchange {
        code_verifier: Some(&max),
        ..exchange("app", &code)
    };
    assert!(redeem(&o, &x).await.is_ok());

    let (_, code) = code_with(&o, "app", "alice", &["openid"], &[], "").await;
    let x = CodeExchange {
        code_verifier: Some(VERIFIER),
        ..exchange("app", &code)
    };
    assert_eq!(refused(redeem(&o, &x).await), Invalid::Grant);
    assert!(redeem(&o, &exchange("app", &code)).await.is_ok());
}

#[tokio::test]
async fn the_redirect_uri_must_match_byte_for_byte() {
    let o = offline_backend().await;
    let (_, code) = code_with(&o, "app", "alice", &["openid"], &[], "").await;
    for uri in [
        None,
        Some("https://app.example/cb/"),
        Some("https://APP.example/cb"),
        Some("https://app.example/cb?x=1"),
        Some("https://app.example/c%62"),
    ] {
        let x = CodeExchange {
            redirect_uri: uri,
            ..exchange("app", &code)
        };
        assert_eq!(refused(redeem(&o, &x).await), Invalid::Grant, "{uri:?}");
    }
    assert!(redeem(&o, &exchange("app", &code)).await.is_ok());
}

#[tokio::test]
async fn refresh_rotates_along_a_chain() {
    let o = offline_backend().await;
    let (grant_id, _, first) = offline_tokens(&o).await;
    let mut current = first;
    for _ in 0..3 {
        let issued = rotate_now(&o, &rotate("app", &current)).await.unwrap();
        assert_eq!(issued.grant.id, grant_id);
        assert_eq!(issued.scope, strings(OFFLINE));
        assert_eq!(issued.audience, strings(&[API]));
        assert!(issued.nonce.is_none());
        let next = issued.refresh_token.unwrap();
        assert_ne!(next, current);
        current = next;
    }
    let rows = refresh_rows(&o.db).await;
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|r| r.family_id == rows[0].family_id));
    assert_eq!(rows.iter().filter(|r| r.used_at.is_none()).count(), 1);
    let newest = rows.iter().find(|r| r.used_at.is_none()).unwrap();
    assert_eq!(newest.token_hash, token_hash(&current));
    let ttl = parse_time(&newest.expires_at).unwrap() - parse_time(&newest.created_at).unwrap();
    assert_eq!(ttl.num_seconds(), REFRESH_TOKEN_TTL_SECS);
    assert_eq!(newest.auth_time, rows[0].auth_time);
    assert!(rows.iter().all(|r| r.token_hash.len() == 64));
}

#[tokio::test]
async fn a_replayed_refresh_token_deletes_its_family() {
    let o = offline_backend().await;
    let (_, _, first) = offline_tokens(&o).await;
    let second = rotate_now(&o, &rotate("app", &first))
        .await
        .unwrap()
        .refresh_token
        .unwrap();
    let third = rotate_now(&o, &rotate("app", &second))
        .await
        .unwrap()
        .refresh_token
        .unwrap();
    // An unrelated family survives.
    let (_, _, other) = offline_tokens(&o).await;

    assert_eq!(
        refused(rotate_now(&o, &rotate("app", &first)).await),
        Invalid::Grant
    );
    assert_eq!(
        refused(rotate_now(&o, &rotate("app", &third)).await),
        Invalid::Grant
    );
    assert_eq!(refresh_rows(&o.db).await.len(), 1);
    assert!(rotate_now(&o, &rotate("app", &other)).await.is_ok());
}

#[tokio::test]
async fn another_client_cannot_refresh_or_consume() {
    let o = offline_backend().await;
    o.create_client(offline_client("other")).await.unwrap();
    let (_, _, token) = offline_tokens(&o).await;
    assert_eq!(
        refused(rotate_now(&o, &rotate("other", &token)).await),
        Invalid::Grant
    );
    assert!(refresh_rows(&o.db).await[0].used_at.is_none());
    assert!(rotate_now(&o, &rotate("app", &token)).await.is_ok());
    // A used token presented by another client does not reach the family.
    assert!(rotate_now(&o, &rotate("other", &token)).await.is_err());
    assert_eq!(refresh_rows(&o.db).await.len(), 2);
}

#[tokio::test]
async fn an_expired_refresh_token_is_refused() {
    let o = offline_backend().await;
    let (_, _, token) = offline_tokens(&o).await;
    expire_refresh(&o.db, &token).await;
    assert_eq!(
        refused(rotate_now(&o, &rotate("app", &token)).await),
        Invalid::Grant
    );
    assert!(refresh_rows(&o.db).await[0].used_at.is_none());
}

#[tokio::test]
async fn a_narrower_scope_applies_to_the_response_only() {
    let o = offline_backend().await;
    let (_, _, token) = offline_tokens(&o).await;
    let wider = strings(&["openid", "profile"]);
    let x = RefreshExchange {
        scope: Some(&wider),
        ..rotate("app", &token)
    };
    assert_eq!(refused(rotate_now(&o, &x).await), Invalid::Scope);
    assert!(refresh_rows(&o.db).await[0].used_at.is_none());

    let narrow = strings(&["openid"]);
    let x = RefreshExchange {
        scope: Some(&narrow),
        ..rotate("app", &token)
    };
    let issued = rotate_now(&o, &x).await.unwrap();
    assert_eq!(issued.scope, narrow);
    let next = issued.refresh_token.unwrap();
    let rows = refresh_rows(&o.db).await;
    assert_eq!(rows[1].scope, rows[0].scope);
    assert_eq!(
        rotate_now(&o, &rotate("app", &next)).await.unwrap().scope,
        strings(OFFLINE)
    );
}

#[tokio::test]
async fn a_narrower_resource_applies_to_the_response_only() {
    let o = offline_backend().await;
    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[API], "").await;
    let unknown = strings(&["https://other.example"]);
    let x = CodeExchange {
        resource: &unknown,
        ..exchange("app", &code)
    };
    assert_eq!(refused(redeem(&o, &x).await), Invalid::Target);
    assert!(!code_used(&o.db, &code).await);
    let api = strings(&[API]);
    let x = CodeExchange {
        resource: &api,
        ..exchange("app", &code)
    };
    let token = redeem(&o, &x).await.unwrap().refresh_token.unwrap();

    let x = RefreshExchange {
        resource: &unknown,
        ..rotate("app", &token)
    };
    assert_eq!(refused(rotate_now(&o, &x).await), Invalid::Target);
    let x = RefreshExchange {
        resource: &api,
        ..rotate("app", &token)
    };
    let issued = rotate_now(&o, &x).await.unwrap();
    assert_eq!(issued.audience, api);

    // An empty granted audience narrows to nothing.
    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[], "").await;
    let x = CodeExchange {
        resource: &api,
        ..exchange("app", &code)
    };
    assert_eq!(refused(redeem(&o, &x).await), Invalid::Target);
}

#[tokio::test]
async fn a_resource_matches_the_granted_form_canonically() {
    const MCP: &str = "https://mcp.example/mcp";
    let o = offline_backend().await;
    for form in [
        MCP,
        "https://mcp.example/mcp/",
        "https://MCP.example/mcp",
        "https://mcp.example:443/mcp",
        " https://mcp.example/mcp",
    ] {
        let requested = strings(&[form]);
        let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[MCP, API], "").await;
        let x = CodeExchange {
            resource: &requested,
            ..exchange("app", &code)
        };
        let issued = redeem(&o, &x).await.unwrap();
        assert_eq!(issued.audience, strings(&[MCP]), "{form}");
        let token = issued.refresh_token.unwrap();
        let x = RefreshExchange {
            resource: &requested,
            ..rotate("app", &token)
        };
        assert_eq!(
            rotate_now(&o, &x).await.unwrap().audience,
            strings(&[MCP]),
            "{form}"
        );
    }
    // A granted form with a trailing slash is matched the same way.
    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &["https://api.example/"], "").await;
    let api = strings(&[API]);
    let x = CodeExchange {
        resource: &api,
        ..exchange("app", &code)
    };
    assert_eq!(
        redeem(&o, &x).await.unwrap().audience,
        strings(&["https://api.example/"])
    );

    for other in [
        "https://mcp.example/other",
        "https://mcp.example/mcp/x",
        "http://mcp.example/mcp",
        "https://mcp.example:8443/mcp",
        "mcp.example/mcp",
    ] {
        let requested = strings(&[other]);
        let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[MCP], "").await;
        let x = CodeExchange {
            resource: &requested,
            ..exchange("app", &code)
        };
        assert_eq!(refused(redeem(&o, &x).await), Invalid::Target, "{other}");
        assert!(!code_used(&o.db, &code).await);
        let token = redeem(&o, &exchange("app", &code))
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        let x = RefreshExchange {
            resource: &requested,
            ..rotate("app", &token)
        };
        assert_eq!(
            refused(rotate_now(&o, &x).await),
            Invalid::Target,
            "{other}"
        );
    }
}

#[tokio::test]
async fn a_refresh_token_needs_offline_and_the_grant_type() {
    let o = offline_backend().await;
    let (_, code) = code_with(&o, "app", "alice", &["openid", "email"], &[], "").await;
    assert!(
        redeem(&o, &exchange("app", &code))
            .await
            .unwrap()
            .refresh_token
            .is_none()
    );

    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[], "").await;
    let x = CodeExchange {
        refresh_allowed: false,
        ..exchange("app", &code)
    };
    assert!(redeem(&o, &x).await.unwrap().refresh_token.is_none());

    o.update_client(
        "app",
        OAuthClient {
            scope: Some("openid offline".to_string()),
            ..offline_client("app")
        },
    )
    .await
    .unwrap();
    let (_, code) = code_with(&o, "app", "alice", &["openid", "offline"], &[], "").await;
    assert!(
        redeem(&o, &exchange("app", &code))
            .await
            .unwrap()
            .refresh_token
            .is_some()
    );
    assert_eq!(refresh_rows(&o.db).await.len(), 1);
}

#[tokio::test]
async fn a_revoked_grant_takes_its_codes_and_refresh_tokens() {
    let o = offline_backend().await;
    let (grant_id, code) = code_with(&o, "app", "alice", OFFLINE, &[], "").await;
    o.revoke_consent_sessions_by_request_id(&grant_id)
        .await
        .unwrap();
    assert_eq!(
        refused(redeem(&o, &exchange("app", &code)).await),
        Invalid::Grant
    );

    let (grant_id, _, token) = offline_tokens(&o).await;
    o.revoke_consent_sessions_by_request_id(&grant_id)
        .await
        .unwrap();
    assert!(refresh_rows(&o.db).await.is_empty());
    assert_eq!(
        refused(rotate_now(&o, &rotate("app", &token)).await),
        Invalid::Grant
    );

    for revoke in 0..2 {
        let (_, _, token) = offline_tokens(&o).await;
        match revoke {
            0 => o
                .revoke_consent_sessions_for_subject("alice")
                .await
                .unwrap(),
            _ => o
                .revoke_consent_sessions_for_client("alice", "app")
                .await
                .unwrap(),
        }
        assert!(rotate_now(&o, &rotate("app", &token)).await.is_err());
        assert!(refresh_rows(&o.db).await.is_empty());
    }
}

#[tokio::test]
async fn a_deleted_client_takes_its_refresh_tokens() {
    let o = offline_backend().await;
    offline_tokens(&o).await;
    o.delete_client("app").await.unwrap();
    assert!(refresh_rows(&o.db).await.is_empty());
}

#[tokio::test]
async fn ending_login_sessions_keeps_refresh_tokens() {
    let o = offline_backend().await;
    let (grant_id, _, token) = offline_tokens(&o).await;
    let (_, pending) = code_with(&o, "app", "alice", OFFLINE, &[], "").await;
    let sid = sid_of(&o.db, &grant_id).await;
    o.revoke_login_session_by_sid(&sid).await.unwrap();
    let token = rotate_now(&o, &rotate("app", &token))
        .await
        .unwrap()
        .refresh_token
        .unwrap();
    o.revoke_login_sessions_for_subject("alice").await.unwrap();
    assert!(rotate_now(&o, &rotate("app", &token)).await.is_ok());
    assert_eq!(
        refused(redeem(&o, &exchange("app", &pending)).await),
        Invalid::Grant
    );
}

/// A device code of a new client `dev`, approved for `alice` with [`OFFLINE`].
async fn approved_device_code(o: &NativeOAuth) -> String {
    use crate::oauth_native::device::{self, DEVICE_CODE_GRANT};
    let client = o
        .create_client(OAuthClient {
            grant_types: Some(strings(&[DEVICE_CODE_GRANT, "refresh_token"])),
            redirect_uris: None,
            ..client("dev")
        })
        .await
        .unwrap();
    let issued = device::create(&o.db, ISSUER, &client, &strings(OFFLINE), Utc::now())
        .await
        .unwrap();
    approve_device(o, &issued.device_code, "alice", OFFLINE).await;
    issued.device_code
}

async fn redeem_device(o: &NativeOAuth, client_id: &str, secret: &str) -> Result<Issued> {
    redeem_device_code(&o.db, client_id, &token_hash(secret), &[], true, Utc::now()).await
}

#[tokio::test]
async fn a_device_code_is_refused_at_the_code_grant_and_a_code_at_the_device_grant() {
    let o = offline_backend().await;
    let device_code = approved_device_code(&o).await;
    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[], "").await;

    for redirect_uri in [Some(REDIRECT), Some(""), None] {
        let x = CodeExchange {
            redirect_uri,
            ..exchange("dev", &device_code)
        };
        assert_eq!(refused(redeem(&o, &x).await), Invalid::Grant);
    }
    assert!(!code_used(&o.db, &device_code).await);
    assert_eq!(
        refused(redeem_device(&o, "app", &code).await),
        Invalid::Grant
    );
    assert!(!code_used(&o.db, &code).await);

    let from_device = redeem_device(&o, "dev", &device_code).await.unwrap();
    assert!(from_device.nonce.is_none());
    let device_refresh = from_device.refresh_token.unwrap();
    let code_refresh = redeem(&o, &exchange("app", &code))
        .await
        .unwrap()
        .refresh_token
        .unwrap();

    // A used secret at the other grant is refused before the replay rule, so no family goes.
    assert_eq!(
        refused(redeem(&o, &exchange("dev", &device_code)).await),
        Invalid::Grant
    );
    assert_eq!(
        refused(redeem_device(&o, "app", &code).await),
        Invalid::Grant
    );
    assert_eq!(refresh_rows(&o.db).await.len(), 2);

    // Replayed at its own grant, each deletes its own family only.
    assert_eq!(
        refused(redeem_device(&o, "dev", &device_code).await),
        Invalid::Grant
    );
    assert_eq!(
        refused(rotate_now(&o, &rotate("dev", &device_refresh)).await),
        Invalid::Grant
    );
    assert!(rotate_now(&o, &rotate("app", &code_refresh)).await.is_ok());
    assert_eq!(
        refused(redeem(&o, &exchange("app", &code)).await),
        Invalid::Grant
    );
    assert!(refresh_rows(&o.db).await.is_empty());
}

#[tokio::test]
async fn a_device_code_of_another_client_changes_nothing() {
    let o = offline_backend().await;
    let device_code = approved_device_code(&o).await;
    assert_eq!(
        refused(redeem_device(&o, "app", &device_code).await),
        Invalid::Grant
    );
    assert!(!code_used(&o.db, &device_code).await);
    assert!(redeem_device(&o, "dev", &device_code).await.is_ok());
}

#[tokio::test]
async fn concurrent_redeems_of_one_code_or_token_win_once_on_sqlite() {
    let o = offline_backend().await;
    let (_, code) = code_with(&o, "app", "alice", OFFLINE, &[], "").await;
    let x = exchange("app", &code);
    let (a, b) = tokio::join!(redeem(&o, &x), redeem(&o, &x));
    assert_eq!([a, b].into_iter().filter(Result::is_ok).count(), 1);

    let (_, _, token) = offline_tokens(&o).await;
    let x = rotate("app", &token);
    let (a, b) = tokio::join!(rotate_now(&o, &x), rotate_now(&o, &x));
    assert_eq!([a, b].into_iter().filter(Result::is_ok).count(), 1);
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn concurrent_redeems_of_one_code_or_token_win_once_on_postgres() {
    let setup = crate::db::test_postgres_pool().await;
    let o = backend_on(&setup).await;
    let client_id = format!("race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("subject-{}", uuid::Uuid::new_v4().simple());
    o.create_client(offline_client(&client_id)).await.unwrap();
    let (_, code) = code_with(&o, &client_id, &subject, OFFLINE, &[], "").await;
    let (_, second_code) = code_with(&o, &client_id, &subject, OFFLINE, &[], "").await;
    let token = redeem(&o, &exchange(&client_id, &second_code))
        .await
        .unwrap()
        .refresh_token
        .unwrap();

    let a = backend_on(&crate::db::test_postgres_pool().await).await;
    let b = backend_on(&crate::db::test_postgres_pool().await).await;
    let x = exchange(&client_id, &code);
    let (ra, rb) = tokio::join!(redeem(&a, &x), redeem(&b, &x));
    let codes_won = [ra, rb].into_iter().filter(Result::is_ok).count();
    let x = rotate(&client_id, &token);
    let (ra, rb) = tokio::join!(rotate_now(&a, &x), rotate_now(&b, &x));
    let refreshes_won = [ra, rb].into_iter().filter(Result::is_ok).count();

    o.delete_client(&client_id).await.unwrap();
    o.revoke_login_sessions_for_subject(&subject).await.unwrap();
    assert_eq!(codes_won, 1);
    assert_eq!(refreshes_won, 1);
}

/// Refresh tokens of `family_id` that are unused and unexpired.
async fn usable_in_family(db: &DbPool, family_id: &str) -> i64 {
    let (family_id, now) = (family_id.to_string(), rfc3339(Utc::now()));
    let r: Result<i64> = async {
        Ok(db_interact!(db, |c| {
            oauth_refresh_tokens::table
                .filter(oauth_refresh_tokens::family_id.eq(family_id))
                .filter(oauth_refresh_tokens::used_at.is_null())
                .filter(oauth_refresh_tokens::expires_at.gt(now))
                .count()
                .get_result(c)
        })?)
    }
    .await;
    r.unwrap()
}

async fn family_of(db: &DbPool, token: &str) -> String {
    let hash = token_hash(token);
    let r: Result<String> = async {
        Ok(db_interact!(db, |c| {
            oauth_refresh_tokens::table
                .filter(oauth_refresh_tokens::token_hash.eq(hash))
                .select(oauth_refresh_tokens::family_id)
                .first(c)
        })?)
    }
    .await;
    r.unwrap()
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn a_replay_racing_a_rotation_leaves_no_usable_token_on_postgres() {
    const ROUNDS: usize = 30;
    let setup = crate::db::test_postgres_pool().await;
    let o = backend_on(&setup).await;
    let client_id = format!("race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("subject-{}", uuid::Uuid::new_v4().simple());
    o.create_client(offline_client(&client_id)).await.unwrap();
    let a = backend_on(&crate::db::test_postgres_pool().await).await;
    let b = backend_on(&crate::db::test_postgres_pool().await).await;

    let mut leaks = Vec::new();
    for round in 0..ROUNDS {
        let (_, code) = code_with(&o, &client_id, &subject, OFFLINE, &[], "").await;
        let used = redeem(&o, &exchange(&client_id, &code))
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        let newest = rotate_now(&o, &rotate(&client_id, &used))
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        let family = family_of(&setup, &newest).await;
        let (x_rotate, x_replay) = (rotate(&client_id, &newest), rotate(&client_id, &used));
        let (rotated, replayed) = if round % 2 == 0 {
            tokio::join!(rotate_now(&a, &x_rotate), rotate_now(&b, &x_replay))
        } else {
            let (replayed, rotated) =
                tokio::join!(rotate_now(&b, &x_replay), rotate_now(&a, &x_rotate));
            (rotated, replayed)
        };
        assert!(replayed.is_err());
        let usable = usable_in_family(&setup, &family).await;
        if usable != 0 {
            leaks.push((round, rotated.is_ok(), usable));
        }
    }

    o.delete_client(&client_id).await.unwrap();
    o.revoke_login_sessions_for_subject(&subject).await.unwrap();
    assert!(
        leaks.is_empty(),
        "usable tokens left after a replay: {leaks:?}"
    );
}

#[tokio::test]
#[ignore = "needs FORSETI_TEST_POSTGRES_URL"]
async fn a_rotation_racing_a_family_revoke_leaves_nothing_in_force_on_postgres() {
    use crate::oauth_native::grants;
    const ROUNDS: usize = 30;
    let setup = crate::db::test_postgres_pool().await;
    let o = backend_on(&setup).await;
    let client_id = format!("race-{}", uuid::Uuid::new_v4().simple());
    let subject = format!("subject-{}", uuid::Uuid::new_v4().simple());
    o.create_client(offline_client(&client_id)).await.unwrap();
    let a = backend_on(&crate::db::test_postgres_pool().await).await;
    let b = backend_on(&crate::db::test_postgres_pool().await).await;

    let mut leaks = Vec::new();
    for round in 0..ROUNDS {
        let (grant_id, code) = code_with(&o, &client_id, &subject, OFFLINE, &[], "").await;
        let token = redeem(&o, &exchange(&client_id, &code))
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        let family = family_of(&setup, &token).await;
        let x = rotate(&client_id, &token);
        let rotation = rotate_now(&a, &x);
        let revoke = revoke_refresh(&b.db, &client_id, &token, Utc::now());
        let (rotated, revoked) = if round % 2 == 0 {
            tokio::join!(rotation, revoke)
        } else {
            let (revoked, rotated) = tokio::join!(revoke, rotation);
            (rotated, revoked)
        };
        assert!(revoked.unwrap(), "round {round}: the revoke found nothing");
        let usable = usable_in_family(&setup, &family).await;
        let grant_revoked = grants::find(&setup, &grant_id)
            .await
            .unwrap()
            .unwrap()
            .tokens_revoked_at
            .is_some();
        if usable != 0 || !grant_revoked {
            leaks.push((round, rotated.is_ok(), usable, grant_revoked));
        }
    }

    o.delete_client(&client_id).await.unwrap();
    o.revoke_login_sessions_for_subject(&subject).await.unwrap();
    assert!(
        leaks.is_empty(),
        "tokens in force after a family revoke: {leaks:?}"
    );
}
