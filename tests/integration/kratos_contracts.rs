//! Assorted Kratos-side contract tests that don't fit the flow-specific
//! files: the admin recovery-code reveal, the `/error` landing page (which
//! fetches Kratos self-service errors), and the full set of Kratos webhook
//! event actions the audit receiver ingests, and the `metadata_admin` JSON
//! Patch shapes. All drive the real playground.

use crate::common::*;
use serde_json::Value;

/// Admin "Generate recovery code" must mint a code via Kratos
/// (`admin_create_recovery_code`) and surface it through the one-shot reveal
/// on the identity page. Guards the admin-initiated recovery path.
#[tokio::test]
async fn admin_recovery_code_reveal_round_trip() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(admin) = try_admin_signed_in_client().await else {
        eprintln!("Skipping admin_recovery_code_reveal_round_trip: admin env-vars not set");
        return;
    };

    let victim = register_test_user("admin-recovery").await;

    // CSRF from the identity page (same admin jar the POST uses).
    let res = admin
        .get(format!("{PORTAL}/admin/identities/{}", victim.identity_id))
        .send()
        .await
        .expect("GET identity show");
    assert_eq!(res.status().as_u16(), 200);
    let body = res.text().await.unwrap_or_default();
    let csrf = extract_input_value(&body, "_csrf").expect("_csrf on identity page");

    // POST recovery — handler stores a SecretReveal and redirects to the show
    // page with ?reveal=<token>; the admin client auto-follows and renders it.
    let res = admin
        .post(format!(
            "{PORTAL}/admin/identities/{}/recovery",
            victim.identity_id
        ))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .expect("POST admin recovery");
    assert!(
        res.status().is_success(),
        "recovery status {}",
        res.status()
    );
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("Recovery code (shown once)"),
        "the one-shot reveal must render the freshly-minted recovery code"
    );

    victim.cleanup().await;
}

/// The `/error?id=<id>` landing page fetches the Kratos self-service error
/// envelope (`get_self_service_error`). A stale/unknown id resolves to the
/// "link expired" copy; either way the page must render 200 with the
/// back-to-sign-in CTA rather than 500. Guards the Kratos error-fetch path.
#[tokio::test]
async fn error_landing_fetches_kratos_self_service_error() {
    assert!(portal_reachable().await);
    let client = browser_client();

    // A syntactically-valid but unknown error id — drives the Kratos call,
    // which 404s → Ok(None) → "Link expired".
    let bogus = uuid::Uuid::new_v4().to_string();
    let res = client
        .get(format!("{PORTAL}/error?id={bogus}"))
        .send()
        .await
        .expect("GET /error?id=");
    assert_eq!(
        res.status().as_u16(),
        200,
        "error page must render, not 500"
    );
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("Back to sign in"),
        "error page should render the sign-in CTA"
    );
}

/// Every Kratos webhook action the receiver maps must be accepted (204) and
/// land an audit row. `bug_regressions.rs` covers `profile.updated` +
/// `mfa.webauthn.added`; this sweeps the remaining event types so a Kratos
/// upgrade renaming any of them (or reshaping the payload) fails loudly.
#[tokio::test]
async fn kratos_webhook_all_known_actions_land_audit_rows() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }

    // The full action set the receiver recognises (src/audit/kratos_webhook.rs).
    let actions = [
        "identity.created",
        "password.changed",
        "password.recovered",
        "verification.completed",
        "auth.login",
        "auth.login_failed",
        "mfa.totp.enrolled",
        "mfa.totp.disabled",
        "mfa.lookup.regenerated",
        "mfa.webauthn.added",
        "mfa.webauthn.removed",
        "profile.updated",
    ];

    for action in actions {
        // Fresh actor per action so the audit lookup can't collide.
        let actor_id = uuid::Uuid::new_v4().to_string();
        let actor_email = format!("wh-{action}-{actor_id}@example.test");
        let status = post_kratos_webhook(action, &actor_id, &actor_email).await;
        assert_eq!(
            status.as_u16(),
            204,
            "action `{action}` must be accepted with 204"
        );
        assert!(
            audit_row_exists(action, &actor_id),
            "action `{action}` must land an audit_events row (target_id={actor_id})"
        );
    }
}

async fn patch_identity(identity_id: &str, patch: Value) -> reqwest::StatusCode {
    browser_client()
        .patch(format!("{KRATOS_ADMIN}/admin/identities/{identity_id}"))
        .json(&patch)
        .send()
        .await
        .expect("PATCH identity transport")
        .status()
}

async fn metadata_admin(identity_id: &str) -> Value {
    let identity: Value = browser_client()
        .get(format!("{KRATOS_ADMIN}/admin/identities/{identity_id}"))
        .send()
        .await
        .expect("GET identity transport")
        .json()
        .await
        .expect("identity body");
    identity
        .get("metadata_admin")
        .cloned()
        .unwrap_or(Value::Null)
}

/// Kratos accepts the JSON Patch shapes `ory::kratos::metadata_admin_patch`
/// emits: `add` of the whole object onto null, `add` and `remove` of one
/// escaped key that leave siblings alone, and a 4xx for `remove` of an
/// absent key (why the builder emits no op there).
#[tokio::test]
async fn kratos_metadata_admin_key_patch_shapes() {
    let email = unique_email("metadata-admin-patch");
    let id = kratos_admin_create_identity(&email).await;

    let outcome = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        assert_eq!(metadata_admin(&id).await, Value::Null);

        let status = patch_identity(
            &id,
            serde_json::json!([{"op": "add", "path": "/metadata_admin", "value": {"a/b": "u:1:x"}}]),
        )
        .await;
        assert!(status.is_success(), "add onto null: {status}");
        assert_eq!(metadata_admin(&id).await, serde_json::json!({"a/b": "u:1:x"}));

        let status = patch_identity(
            &id,
            serde_json::json!([{"op": "add", "path": "/metadata_admin/sibling", "value": "keep"}]),
        )
        .await;
        assert!(status.is_success(), "add sibling: {status}");
        let status = patch_identity(
            &id,
            serde_json::json!([{"op": "add", "path": "/metadata_admin/a~1b", "value": "u:1:y"}]),
        )
        .await;
        assert!(status.is_success(), "replace via add: {status}");
        assert_eq!(
            metadata_admin(&id).await,
            serde_json::json!({"a/b": "u:1:y", "sibling": "keep"})
        );

        let status = patch_identity(
            &id,
            serde_json::json!([{"op": "remove", "path": "/metadata_admin/a~1b"}]),
        )
        .await;
        assert!(status.is_success(), "remove: {status}");
        assert_eq!(metadata_admin(&id).await, serde_json::json!({"sibling": "keep"}));

        let status = patch_identity(
            &id,
            serde_json::json!([{"op": "remove", "path": "/metadata_admin/a~1b"}]),
        )
        .await;
        assert!(status.is_client_error(), "remove absent: {status}");
        assert_eq!(metadata_admin(&id).await, serde_json::json!({"sibling": "keep"}));
    }))
    .await;

    delete_test_identity(&id).await.expect("cleanup identity");
    if let Err(p) = outcome {
        std::panic::resume_unwind(p);
    }
}
