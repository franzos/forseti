//! AAL2 (two-factor) enforcement on Forseti's protected surfaces.
//!
//! The playground runs Kratos with both `whoami.required_aal` and
//! `settings.required_aal` at `highest_available`. Under that knob Kratos
//! returns a 403 from `/sessions/whoami` for an AAL1 session belonging to an
//! identity that *has* a second factor — Forseti's `RequireSession` maps that
//! to a 303 → `/login?aal=aal2&return_to=…` step-up. A password-only identity
//! (no second factor) still resolves AAL1-OK and is never bounced.
//!
//! These tests drive the seeded admin (`admin@example.com`, TOTP enrolled,
//! NO recovery codes) as the "has a second factor" principal, so they're
//! env-gated on `FORSETI_ADMIN_TEST_*` exactly like the admin suite and skip
//! gracefully when those aren't wired up.

use crate::common::*;

/// Routes guarded by `RequireSession` that must bounce an AAL1 session with a
/// second factor up to AAL2.
const GUARDED_PATHS: &[&str] = &["/", "/settings", "/settings/2fa", "/settings/account"];

/// Case 1 — a user WITH a second factor on an AAL1 session is bounced to the
/// `aal=aal2` step-up for every guarded surface.
#[tokio::test]
async fn aal1_session_with_second_factor_is_bounced_to_step_up() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(creds) = admin_test_credentials() else {
        eprintln!(
            "Skipping aal1_session_with_second_factor_is_bounced_to_step_up: \
FORSETI_ADMIN_TEST_* not set."
        );
        return;
    };
    // AAL1-only admin session on a manual-redirect client so we can inspect
    // the 303 itself rather than following it into Kratos's init.
    let manual = manual_redirect_client();
    password_login_aal1(&manual, &creds.email, &creds.password).await;

    for path in GUARDED_PATHS {
        let res = manual
            .get(format!("{PORTAL}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"));
        assert_eq!(
            res.status().as_u16(),
            303,
            "AAL1 session with a second factor must be bounced from {path}; got {}",
            res.status()
        );
        let loc = res
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        assert!(
            loc.starts_with("/login") && loc.contains("aal=aal2"),
            "{path} step-up must point at /login?aal=aal2…; got {loc}"
        );
        let return_to = extract_query_param(loc, "return_to").unwrap_or_default();
        assert!(
            return_to.contains(path),
            "{path} step-up must preserve return_to=<path>; got return_to={return_to}"
        );
    }
}

/// Case 2 — after stepping up to AAL2 the dashboard renders (200) and
/// `/settings/2fa` is reachable through the Kratos settings bootstrap.
#[tokio::test]
async fn aal2_session_reaches_dashboard_and_2fa_settings() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = try_admin_signed_in_client().await else {
        eprintln!(
            "Skipping aal2_session_reaches_dashboard_and_2fa_settings: \
FORSETI_ADMIN_TEST_* not set or sign-in failed."
        );
        return;
    };

    let res = client
        .get(format!("{PORTAL}/"))
        .send()
        .await
        .expect("GET / at AAL2");
    assert_eq!(
        res.status().as_u16(),
        200,
        "dashboard must render once the session is AAL2"
    );

    let res = client
        .get(format!("{PORTAL}/settings/2fa"))
        .send()
        .await
        .expect("GET /settings/2fa at AAL2");
    assert!(
        res.status().is_success(),
        "/settings/2fa must be reachable at AAL2; got {}",
        res.status()
    );
    assert_eq!(
        res.url().path(),
        "/settings/2fa",
        "should land on /settings/2fa after the Kratos settings bootstrap"
    );
}

/// Case 3 — a user WITHOUT any second factor on an AAL1 session reaches the
/// dashboard (200). Enforcement must not catch password-only users.
#[tokio::test]
async fn aal1_session_without_second_factor_reaches_dashboard() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let email = unique_email("aal2-no-mfa");
    let password = "Sup3rSecret-NoMfa-Password!";
    let identity_id = kratos_admin_create_password_identity(&email, password).await;

    let client = browser_client();
    password_login_aal1(&client, &email, password).await;

    let res = client
        .get(format!("{PORTAL}/"))
        .send()
        .await
        .expect("GET / as password-only user");
    assert_eq!(
        res.status().as_u16(),
        200,
        "password-only AAL1 session must NOT be bounced; got {}",
        res.status()
    );
    assert_eq!(
        res.url().path(),
        "/",
        "password-only user should stay on the dashboard, not be redirected to /login"
    );

    let _ = delete_test_identity(&identity_id).await;
}

/// Case 4 — the step-up redirect preserves the original query string. Guards
/// the post-recovery settings hand-off (`?flow=` must survive into
/// `return_to`).
#[tokio::test]
async fn step_up_return_to_preserves_query_string() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(creds) = admin_test_credentials() else {
        eprintln!(
            "Skipping step_up_return_to_preserves_query_string: FORSETI_ADMIN_TEST_* not set."
        );
        return;
    };
    let client = manual_redirect_client();
    password_login_aal1(&client, &creds.email, &creds.password).await;

    let res = client
        .get(format!("{PORTAL}/settings?flow=ABC123"))
        .send()
        .await
        .expect("GET /settings?flow=ABC123 at AAL1");
    assert_eq!(
        res.status().as_u16(),
        303,
        "AAL1 second-factor user must be bounced from /settings?flow=…"
    );
    let loc = res
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let return_to = extract_query_param(loc, "return_to").unwrap_or_default();
    // `return_to` is itself URL-encoded; decoding it once yields the original
    // path+query, so `flow=ABC123` re-appears verbatim.
    assert!(
        return_to.contains("flow=ABC123"),
        "step-up return_to must round-trip the original ?flow= query; got return_to={return_to} \
         (full location {loc})"
    );
    assert!(
        return_to.contains("/settings"),
        "step-up return_to must point back at /settings; got return_to={return_to}"
    );
}

/// Case 5 — at AAL2, `/settings/2fa` for a device-factor identity with no
/// `lookup_secret` recovery codes renders the self-lockout warning. The
/// seeded admin is exactly this shape (TOTP, no codes).
///
/// Shared-state caveat: a concurrent test could enrol recovery codes on the
/// admin. The suite runs single-threaded and nothing else touches the admin's
/// recovery codes, so the "warning present" assertion is reliable. We do NOT
/// assert the inverse (warning absent after enrolment) because self-service
/// TOTP/lookup enrolment isn't programmatically reliable here (see
/// `common.rs` notes) and would mutate the seeded admin for later runs.
#[tokio::test]
async fn aal2_2fa_settings_warns_when_recovery_codes_missing() {
    if !portal_reachable().await {
        eprintln!("portal not reachable; skipping");
        return;
    }
    let Some(client) = try_admin_signed_in_client().await else {
        eprintln!(
            "Skipping aal2_2fa_settings_warns_when_recovery_codes_missing: \
FORSETI_ADMIN_TEST_* not set or sign-in failed."
        );
        return;
    };

    let res = client
        .get(format!("{PORTAL}/settings/2fa"))
        .send()
        .await
        .expect("GET /settings/2fa at AAL2");
    assert!(res.status().is_success(), "/settings/2fa status");
    let body = res.text().await.unwrap_or_default();
    assert!(
        body.contains("No recovery codes") && body.contains("locked out"),
        "a device factor with no recovery codes must surface the self-lockout warning; \
         got {} chars",
        body.len()
    );
}
