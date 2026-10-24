//! `/settings/account/export`: the account export download.

use crate::common::*;
use rusqlite::params;
use serde_json::Value;

const EXPORT_FORMAT: &str = "gofranz-account-export";
const EXPORT_FORMAT_VERSION: u64 = 1;
const TOP_LEVEL_KEYS: &[&str] = &[
    "format",
    "format_version",
    "product",
    "exported_at",
    "account",
    "identities",
    "sessions",
    "billing",
    "audit",
    "data",
];
const DATA_KEYS: &[&str] = &[
    "hydra_consents",
    "hydra_local",
    "orgs",
    "profile",
    "username_history",
    "oidc_links",
    "saml_links",
    "posix",
    "offline_secret",
];
const ORGS_KEYS: &[&str] = &["memberships", "teams", "invites"];
const POSIX_KEYS: &[&str] = &[
    "account",
    "ssh_keys",
    "group_members",
    "host_logins",
    "device_sessions",
];
const SECRET_KEYS: &[&str] = &[
    "verifier",
    "secret_hash",
    "password",
    "hashed_password",
    "config",
    "totp_url",
    "token",
    "code",
    "initial_access_token",
    "client_code_hash",
    "device_code",
    "user_code",
    "private_key",
    "secret",
];

fn assert_no_secret_keys(v: &Value, path: &str) {
    match v {
        Value::Object(map) => {
            for (k, v) in map {
                assert!(
                    !SECRET_KEYS.contains(&k.as_str()),
                    "secret key `{k}` exported at {path}"
                );
                assert_no_secret_keys(v, &format!("{path}.{k}"));
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                assert_no_secret_keys(item, &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

fn extract_form_csrf(html: &str) -> Option<String> {
    let needle = "name=\"_csrf\"";
    let idx = html.find(needle)?;
    let after = &html[idx + needle.len()..];
    let elem = &after[..after.find('>').unwrap_or(after.len())];
    let value_start = elem.find("value=\"")? + "value=\"".len();
    let tail = &elem[value_start..];
    Some(tail[..tail.find('"')?].to_string())
}

fn db() -> rusqlite::Connection {
    rusqlite::Connection::open(forseti_db_path()).expect("open forseti.db")
}

fn offline_verifier(identity_id: &str) -> Option<String> {
    db().query_row(
        "SELECT verifier FROM offline_secrets WHERE identity_id = ?1",
        params![identity_id],
        |r| r.get(0),
    )
    .ok()
}

/// Rows the suite has no shared seed helper for, written straight into the
/// portal DB. Every secret-bearing column gets a recognisable marker so the
/// test can assert it never reaches the document.
struct Seeded {
    invite_token: String,
    device_code: String,
    client_code_hash: String,
}

fn seed_export_rows(identity_id: &str, email: &str, host_id: &str, seed: u128) -> Seeded {
    let invite_token = format!("invite-token-SECRET-{seed}");
    seed_org_invite(&invite_token, email, None);
    seed_oidc_link(identity_id, "github");
    seed_saml_link(
        "default",
        email,
        identity_id,
        &format!("idp-subject-{seed}"),
    );
    let device_code = format!("device-code-SECRET-{seed}");
    let client_code_hash = format!("client-code-hash-SECRET-{seed}");
    seed_device_session(
        &device_code,
        &format!("UC-{}", seed % 1_000_000),
        host_id,
        "exportuser",
        identity_id,
        &client_code_hash,
    );
    Seeded {
        invite_token,
        device_code,
        client_code_hash,
    }
}

fn delete_export_rows(identity_id: &str, email: &str) {
    let conn = db();
    for (sql, arg) in [
        (
            "DELETE FROM organization_invites WHERE LOWER(email) = LOWER(?1)",
            email,
        ),
        ("DELETE FROM oidc_links WHERE identity_id = ?1", identity_id),
        ("DELETE FROM saml_links WHERE identity_id = ?1", identity_id),
    ] {
        conn.execute(sql, params![arg])
            .unwrap_or_else(|e| panic!("cleanup `{sql}`: {e}"));
    }
}

/// GET the export, check the download headers, return the raw body and the
/// parsed document.
async fn download_export(user: &RegisteredUser) -> (String, Value) {
    let res = user
        .client
        .get(format!("{PORTAL}/settings/account/export"))
        .send()
        .await
        .expect("GET /settings/account/export");
    assert_eq!(res.status().as_u16(), 200, "export: {}", res.status());
    let header = |name: &str| {
        res.headers()
            .get(name)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let disposition = header("content-disposition");
    assert!(
        disposition.starts_with("attachment; filename=\"forseti-export-")
            && disposition.ends_with(".json\""),
        "content-disposition: {disposition}"
    );
    assert!(
        header("content-type").starts_with("application/json"),
        "content-type: {}",
        header("content-type")
    );
    assert!(
        header("cache-control").contains("no-store"),
        "cache-control: {}",
        header("cache-control")
    );
    assert_eq!(header("x-content-type-options"), "nosniff");
    let text = res.text().await.expect("export body");
    let export: Value = serde_json::from_str(&text).expect("export parses as JSON");
    (text, export)
}

#[tokio::test]
async fn account_export_downloads_the_envelope() {
    assert!(portal_reachable().await);
    let user = register_test_user("acct-export").await;
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let id = (seed % 90_000) as i64;

    // Profile through the portal; the dashboard carries a CSRF token.
    let res = user
        .client
        .get(format!("{PORTAL}/"))
        .send()
        .await
        .expect("GET /");
    let csrf = extract_form_csrf(&res.text().await.expect("dashboard body"))
        .expect("_csrf on the dashboard");
    let res = user
        .client
        .post(format!("{PORTAL}/settings/profile/extended"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("bio", "Export test bio"),
            ("location", "Berlin"),
            ("pronouns", ""),
            ("website", ""),
            ("avatar_url", ""),
            ("links", ""),
        ])
        .send()
        .await
        .expect("POST /settings/profile/extended");
    assert!(res.status().is_success(), "profile save: {}", res.status());

    // Offline passphrase through the portal; a fresh registration is inside
    // the privileged window, so the probe lands on the page with `?flow=`.
    let res = user
        .client
        .get(format!("{PORTAL}/settings/offline-access"))
        .send()
        .await
        .expect("GET /settings/offline-access");
    assert!(
        res.status().is_success(),
        "offline-access page: {}",
        res.status()
    );
    let save_url = res.url().clone();
    assert!(
        save_url.path().starts_with("/settings/offline-access"),
        "expected the offline-access page, got {save_url}"
    );
    let csrf = extract_form_csrf(&res.text().await.expect("offline-access body"))
        .expect("_csrf on offline-access page");
    let res = user
        .client
        .post(save_url)
        .form(&[
            ("_csrf", csrf.as_str()),
            ("passphrase", "export-test-passphrase-2026"),
        ])
        .send()
        .await
        .expect("POST /settings/offline-access");
    assert!(
        res.status().is_success(),
        "offline passphrase save: {}",
        res.status()
    );
    let verifier = offline_verifier(&user.identity_id).expect("offline verifier stored");
    assert!(verifier.starts_with("$argon2id$"), "verifier: {verifier}");

    // Rows the shared helpers make cheap: a team membership in the default
    // org, a POSIX account (with its user group membership and one SSH key),
    // a host with a login record, plus the rows seeded locally above.
    let team_id = format!("team-export-{id}");
    seed_team(
        &team_id,
        "default",
        &format!("Export Team {id}"),
        &format!("export-team-{id}"),
        None,
    );
    add_team_member(&team_id, &user.identity_id);
    let username = format!("exportuser{id}");
    let (uid, gid) = (700_000 + id, 700_000 + id);
    seed_posix_account(&user.identity_id, &username, uid, gid);
    let host_id = format!("host-export-{id}");
    let hostname = format!("export-{id}.example.test");
    seed_host_enrollment(&host_id, &hostname, &format!("host-secret-{id}"), "default");
    seed_host_account_login(&host_id, &user.identity_id);
    let seeded = seed_export_rows(&user.identity_id, &user.email, &host_id, seed);

    let (text, export) = download_export(&user).await;
    for marker in [
        verifier.as_str(),
        seeded.invite_token.as_str(),
        seeded.device_code.as_str(),
        seeded.client_code_hash.as_str(),
    ] {
        assert!(!text.contains(marker), "secret `{marker}` exported");
    }

    assert_eq!(export["format"], EXPORT_FORMAT);
    assert_eq!(export["format_version"], EXPORT_FORMAT_VERSION);
    assert_eq!(export["product"], "forseti");
    assert!(
        chrono::DateTime::parse_from_rfc3339(export["exported_at"].as_str().unwrap_or_default())
            .is_ok(),
        "exported_at: {}",
        export["exported_at"]
    );
    for key in TOP_LEVEL_KEYS {
        assert!(export.get(key).is_some(), "top-level key `{key}` missing");
    }
    for key in DATA_KEYS {
        assert!(
            export["data"].get(key).is_some(),
            "data key `{key}` missing"
        );
    }
    for key in ORGS_KEYS {
        assert!(
            export["data"]["orgs"].get(key).is_some(),
            "orgs key `{key}` missing"
        );
    }
    for key in POSIX_KEYS {
        assert!(
            export["data"]["posix"].get(key).is_some(),
            "posix key `{key}` missing"
        );
    }
    assert_no_secret_keys(&export, "$");

    assert_eq!(export["account"]["id"], user.identity_id.as_str());
    assert_eq!(export["account"]["traits"]["email"], user.email.as_str());
    assert!(export["account"].get("metadata_admin").is_none());
    assert!(
        export["account"]["credentials"]
            .as_array()
            .is_some_and(|c| c.iter().any(|c| c["type"] == "password")),
        "password credential metadata missing: {}",
        export["account"]["credentials"]
    );
    assert!(export["billing"].is_null());
    assert!(
        export["sessions"].as_array().is_some_and(|s| !s.is_empty()),
        "the current session should be listed"
    );
    assert_eq!(export["data"]["profile"]["bio"], "Export test bio");
    assert_eq!(export["data"]["profile"]["location"], "Berlin");
    assert_eq!(export["data"]["offline_secret"]["set"], true);
    assert_eq!(export["data"]["offline_secret"]["algo_version"], 1);

    let orgs = &export["data"]["orgs"];
    assert!(
        orgs["memberships"].as_array().is_some_and(|m| m
            .iter()
            .any(|m| m["org_id"] == "default" && m["role"].is_string())),
        "default-org membership missing: {}",
        orgs["memberships"]
    );
    let team = orgs["teams"]
        .as_array()
        .and_then(|t| t.iter().find(|t| t["id"] == team_id.as_str()))
        .unwrap_or_else(|| panic!("team membership missing: {}", orgs["teams"]));
    assert_eq!(team["org_id"], "default");
    assert_eq!(team["slug"], format!("export-team-{id}"));
    assert_eq!(team["source"], "manual");
    assert!(team["added_at"].is_string());
    let invite = orgs["invites"]
        .as_array()
        .and_then(|i| i.iter().find(|i| i["org_id"] == "default"))
        .unwrap_or_else(|| panic!("invite missing: {}", orgs["invites"]));
    assert_eq!(invite["email"], user.email.as_str());
    assert_eq!(invite["role"], "member");
    assert!(invite.get("token").is_none());

    let oidc = &export["data"]["oidc_links"][0];
    assert_eq!(oidc["provider"], "github");
    assert!(oidc["first_seen_at"].is_string());
    let saml = &export["data"]["saml_links"][0];
    assert_eq!(saml["org_id"], "default");
    assert_eq!(saml["idp_subject"], format!("idp-subject-{seed}"));
    assert!(saml.get("identity_id").is_none());

    let posix = &export["data"]["posix"];
    assert_eq!(posix["account"]["username"], username.as_str());
    assert_eq!(posix["account"]["uid"], uid);
    assert_eq!(
        posix["ssh_keys"][0]["public_key"],
        "ssh-ed25519 AAAATEST test@fixture"
    );
    assert_eq!(posix["group_members"][0]["gid"], gid);
    assert!(posix["group_members"][0]["added_at"].is_string());
    assert_eq!(posix["host_logins"][0]["host_id"], host_id.as_str());
    assert_eq!(posix["host_logins"][0]["hostname"], hostname.as_str());
    assert!(posix["host_logins"][0]["last_login_at"].is_string());
    let device = &posix["device_sessions"][0];
    assert_eq!(device["host_id"], host_id.as_str());
    assert_eq!(device["requested_username"], "exportuser");
    assert_eq!(device["status"], "approved");
    assert!(device.get("device_code").is_none() && device.get("user_code").is_none());

    let secret_set = export["audit"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["event"] == "posix.offline.secret_set"))
        .unwrap_or_else(|| {
            panic!(
                "audit row for the offline secret missing: {}",
                export["audit"]
            )
        });
    assert_eq!(secret_set["role"], "both");
    assert_eq!(secret_set["actor_id"], user.identity_id.as_str());
    assert_eq!(secret_set["actor_email"], user.email.as_str());

    // The first export wrote its own audit row; the second document carries it.
    let (_, second) = download_export(&user).await;
    let exported = second["audit"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["event"] == "account.exported"))
        .unwrap_or_else(|| panic!("account.exported row missing: {}", second["audit"]));
    assert_eq!(exported["role"], "both");
    assert_eq!(exported["actor_id"], user.identity_id.as_str());
    assert_eq!(exported["actor_email"], user.email.as_str());
    assert_eq!(
        exported["metadata"]["audit_rows"],
        export["audit"].as_array().map_or(0, Vec::len)
    );

    delete_offline_secret(&user.identity_id);
    delete_export_rows(&user.identity_id, &user.email);
    delete_device_sessions_for_host(&host_id);
    delete_host_account_logins(&host_id);
    delete_host_enrollment(&host_id);
    delete_team(&team_id);
    user.cleanup().await;
}

#[tokio::test]
async fn account_export_redirects_anonymous_to_login() {
    let client = manual_redirect_client();
    let res = client
        .get(format!("{PORTAL}/settings/account/export"))
        .send()
        .await
        .expect("GET /settings/account/export anon");
    assert_eq!(res.status().as_u16(), 303);
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.contains("/login"),
        "anonymous export should redirect to /login; got {loc}"
    );
}
