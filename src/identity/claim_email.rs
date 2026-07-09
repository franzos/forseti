//! Hand-rolled "claim this email" flow.
//!
//! When registration fails because an unverified identity already exists
//! with the requested email, the user can navigate to `/claim-email` and
//! kick off a verification-by-code dance:
//!
//! 1. GET `/claim-email` renders a form asking for the email + the new
//!    password they intend to use for the replacement account.
//! 2. POST `/claim-email` looks up the conflicting identity via Kratos
//!    admin, refuses if it's already verified, mints a 6-digit code into
//!    a `secret_reveals` row, and emails it via Kratos courier.
//! 3. GET `/claim-email/confirm?token=<...>` renders a code-entry form.
//! 4. POST `/claim-email/confirm` validates the code → deletes the old
//!    unverified identity → redirects to Kratos registration with the
//!    same email pre-filled.
//!
//! Kratos doesn't ship this UX out of the box.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use rand::Rng;
use serde::Deserialize;

use crate::admin::actions::{delete_identity_audited, DeleteActor, DeleteReason};
use crate::audit_metadata;
use crate::config::{ClaimEmailConfig, ProxyConfig};
use crate::csrf::CsrfForm;
use crate::extractors::Csrf;
use crate::flash::{self, SecretReveal};
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::rate_limit;
use crate::render::render;
use crate::state::AppState;

/// Maximum wrong-code submissions per minted claim before the
/// `secret_reveals` row is hard-deleted and the user has to mint a fresh
/// code. Bounded low because the codes are 6 digits (≈20-bit entropy) —
/// without this an attacker can grind to ≈50% odds inside the TTL
/// window. The user gets four genuine retries before reset (counter
/// starts at 0, deletes when `attempts + 1 >= MAX`).
const MAX_CLAIM_CODE_ATTEMPTS: i32 = 5;

/// Construct the claim-email sub-router with per-IP rate limits
/// attached. Rate-limit values come from `[claim_email]` in config
/// (defaults 5/min + 30/hour); see `crate::config::ClaimEmailConfig`
/// for the rationale.
pub(crate) fn router(proxy_cfg: &ProxyConfig, claim_cfg: &ClaimEmailConfig) -> Router<AppState> {
    let r = Router::new()
        .route("/claim-email", get(claim_get).post(claim_post))
        .route("/claim-email/confirm", get(confirm_get).post(confirm_post));

    rate_limit::dual_window(
        r,
        proxy_cfg.trust_forwarded_for,
        claim_cfg.rate_limit_per_minute,
        claim_cfg.rate_limit_per_hour,
        rate_limit::plain_text_error("claim-email"),
    )
}

#[derive(Template)]
#[template(path = "identity/claim_email.html")]
struct ClaimEmailTemplate {
    chrome: PageChrome,
    error: Option<String>,
    /// Set after a successful POST — drives the "If an unverified account
    /// exists..." info banner. Returned for both the "found unverified"
    /// and "not found / already verified" branches so the response shape
    /// can't be used to enumerate the identity store.
    info: Option<String>,
}

async fn claim_get(
    State(state): State<AppState>,
    csrf: Csrf,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    render(&ClaimEmailTemplate {
        chrome: PageChrome::from_parts(&state, String::new(), csrf.0, locale),
        error: None,
        info: None,
    })
}

#[derive(Debug, Deserialize)]
struct ClaimForm {
    email: String,
}

async fn claim_post(
    State(state): State<AppState>,
    csrf: Csrf,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<ClaimForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    if !crate::mailer::is_valid_email(&email) {
        let msg = crate::i18n::lookup(&locale, "claim-error-invalid-email");
        return render_claim_error(&state, &csrf.0, locale, &msg);
    }

    // Always redirect to /claim-email/confirm with a token, regardless of
    // whether an actionable unverified identity exists. The decoy-token
    // branch (no match / verified / admin-allowlisted) hands the user a
    // random 32-hex string the confirm form will treat as expired on
    // submit — making the response indistinguishable from the
    // "real claim minted" branch.
    //
    // SMTP delivery is fire-and-forget for the same reason: SMTP latency
    // is the loudest timing signal between branches. The legitimate user
    // gets the email asynchronously; the attacker can't time the delivery.
    let identities = ory::kratos::list_identities(&state.ory, 50, None, Some(&email))
        .await
        .unwrap_or_default();
    let unverified = identities.iter().find(|i| {
        i.verifiable_addresses
            .as_ref()
            .map(|addrs| {
                addrs
                    .iter()
                    .any(|a| a.value.to_lowercase() == email && !a.verified)
            })
            .unwrap_or(false)
    });
    let verified_exists = identities.iter().any(|i| {
        i.verifiable_addresses
            .as_ref()
            .map(|addrs| {
                addrs
                    .iter()
                    .any(|a| a.value.to_lowercase() == email && a.verified)
            })
            .unwrap_or(false)
    });

    let token = match unverified {
        Some(target) if !state.cfg.admin.is_admin(&email) => {
            let code = mint_six_digit_code();
            let reveal = SecretReveal::ClaimEmailCode {
                code: code.clone(),
                identity_id: target.id.clone(),
            };
            let reveal_ttl = state.cfg.flash.reveal_ttl_seconds;
            match flash::store_secret_reveal(&state.db, reveal_ttl, reveal).await {
                Ok(t) => {
                    let cfg = state.cfg.clone();
                    let db = state.db.clone();
                    let token_for_task = t.clone();
                    let email_for_task = email.clone();
                    tokio::spawn(async move {
                        if let Err(e) = send_claim_email_code(&email_for_task, &code, &cfg).await {
                            tracing::warn!(
                                error = ?e,
                                "claim-email: courier dispatch failed; consuming reveal",
                            );
                            let _ =
                                flash::take_secret_reveal(&db, reveal_ttl, &token_for_task).await;
                        }
                    });
                    tracing::info!(email = %email, state = "found-unverified", "claim-email: minted claim code");
                    t
                }
                Err(e) => {
                    // Storage failed — fall through to a decoy token so the
                    // response shape is preserved. The user will hit the
                    // expired-code path on submit and can retry.
                    tracing::error!(error = ?e, "claim-email: stage reveal failed; serving decoy");
                    decoy_token()
                }
            }
        }
        Some(target) => {
            // Admin-allowlisted email: refuse silently.
            tracing::warn!(
                email = %email,
                target_identity = %target.id,
                "claim-email: refused — target email is in admin.allowed_emails",
            );
            decoy_token()
        }
        None => {
            let state_label = if verified_exists {
                "found-verified"
            } else {
                "not-found"
            };
            tracing::info!(
                email = %email,
                state = state_label,
                "claim-email: no actionable unverified identity; serving decoy",
            );
            decoy_token()
        }
    };

    Redirect::to(&format!("/claim-email/confirm?token={}", token)).into_response()
}

/// Random 32-hex-char string that intentionally does not correspond to a
/// stored `secret_reveals` row. The confirm POST treats unknown tokens
/// as expired, so the user-visible UX matches a real-but-stale claim.
fn decoy_token() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::rng().random();
    hex::encode(bytes)
}

fn render_claim_error(
    state: &AppState,
    csrf_token: &str,
    locale: crate::locale::LanguageIdentifier,
    msg: &str,
) -> Response {
    render(&ClaimEmailTemplate {
        chrome: PageChrome::from_parts(state, String::new(), csrf_token.to_string(), locale),
        error: Some(msg.to_string()),
        info: None,
    })
}

#[derive(Template)]
#[template(path = "identity/claim_email_confirm.html")]
struct ClaimConfirmTemplate {
    chrome: PageChrome,
    token: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfirmQuery {
    token: Option<String>,
}

async fn confirm_get(
    State(state): State<AppState>,
    Query(q): Query<ConfirmQuery>,
    csrf: Csrf,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    let Some(token) = q.token.filter(|t| !t.is_empty()) else {
        return Redirect::to("/claim-email").into_response();
    };
    render(&ClaimConfirmTemplate {
        chrome: PageChrome::from_parts(&state, String::new(), csrf.0, locale),
        token,
        error: None,
    })
}

#[derive(Debug, Deserialize)]
struct ConfirmForm {
    token: String,
    code: String,
}

async fn confirm_post(
    State(state): State<AppState>,
    csrf: Csrf,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<ConfirmForm>,
) -> Response {
    // Peek (don't consume yet) so a mistyped code doesn't waste the
    // reveal — we want the user to be able to retry inside the same
    // mint. The row is bumped + auto-deleted on repeated wrong attempts
    // (see `MAX_CLAIM_CODE_ATTEMPTS`); only a correct submission
    // consumes via `take_secret_reveal` below.
    let reveal_ttl = state.cfg.flash.reveal_ttl_seconds;
    let (expected_code, target_identity) =
        match flash::peek_secret_reveal(&state.db, reveal_ttl, &form.token).await {
            Some((SecretReveal::ClaimEmailCode { code, identity_id }, _attempts)) => {
                (code, identity_id)
            }
            Some(_) | None => {
                return render_claim_confirm_error(
                    &state,
                    &csrf.0,
                    locale.clone(),
                    &form.token,
                    &crate::i18n::lookup(&locale, "claim-error-code-expired"),
                );
            }
        };
    if expected_code.is_empty() || target_identity.is_empty() {
        // Fully consume the broken row before bouncing the user.
        let _ = flash::take_secret_reveal(&state.db, reveal_ttl, &form.token).await;
        return render_claim_confirm_error(
            &state,
            &csrf.0,
            locale.clone(),
            &form.token,
            &crate::i18n::lookup(&locale, "claim-error-invalid-token"),
        );
    }
    // Hash both sides before ct_eq, mirroring the webhook bearer path:
    // subtle's slice impl short-circuits on unequal lengths, which would
    // leak a length oracle. Fixed-length digests dodge that.
    use sha2::Digest;
    let presented_hash = sha2::Sha256::digest(form.code.trim().as_bytes());
    let expected_hash = sha2::Sha256::digest(expected_code.as_bytes());
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        presented_hash.as_slice(),
        expected_hash.as_slice(),
    )) {
        // Wrong code. Bump the per-row attempt counter; the row is
        // hard-deleted once `attempts + 1 >= MAX_CLAIM_CODE_ATTEMPTS`.
        // Either way the user has to type the right code on the next
        // try — but exhaustion forces them to mint a fresh claim.
        //
        // On DB failure we refuse the submission rather than fabricate
        // "exhausted": the row is unchanged, so claiming exhaustion
        // would let the same (correct) code be redeemed on a future
        // submission once the DB recovers — even though we just told
        // the user to start over. Better to surface the transient
        // failure honestly.
        let exhausted = match flash::bump_secret_reveal_attempts(
            &state.db,
            &form.token,
            MAX_CLAIM_CODE_ATTEMPTS,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "claim-email: attempt counter bump failed");
                return render_claim_confirm_error(
                    &state,
                    &csrf.0,
                    locale.clone(),
                    &form.token,
                    &crate::i18n::lookup(&locale, "claim-error-service-unavailable"),
                );
            }
        };
        let key = if exhausted {
            "claim-error-too-many-attempts"
        } else {
            "claim-error-code-mismatch"
        };
        let msg = crate::i18n::lookup(&locale, key);
        return render_claim_confirm_error(&state, &csrf.0, locale.clone(), &form.token, &msg);
    }
    // Code matched — consume the reveal exactly once. Anything below
    // this point operates on a token that's already gone from the DB.
    let _ = flash::take_secret_reveal(&state.db, reveal_ttl, &form.token).await;

    // Look up the email-of-record on the doomed identity for the audit
    // row before we delete it. Best-effort: failures here don't block
    // the delete because the audit row's actor_email is for human
    // display, not authorization.
    //
    // Critically, also re-check the verified state here. Between
    // `claim_post` minting the code and the user submitting it, the
    // legitimate owner could have walked through `/verification` and
    // verified the address — at which point we must refuse to delete.
    // Without this check there's a TOCTOU window: code in flight,
    // owner verifies, claimer enters the code, identity goes away.
    let (target_email, now_verified, target_email_is_admin) =
        match ory::kratos::admin_get_identity(&state.ory, &target_identity).await {
            Ok(id) => {
                let email_of_record = id
                    .traits
                    .and_then(|t| t.get("email").and_then(|v| v.as_str()).map(str::to_string))
                    .unwrap_or_default();
                let any_verified = id
                    .verifiable_addresses
                    .as_ref()
                    .map(|addrs| addrs.iter().any(|a| a.verified))
                    .unwrap_or(false);
                let is_admin = state.cfg.admin.is_admin(&email_of_record);
                (email_of_record, any_verified, is_admin)
            }
            Err(_) => (String::new(), false, false),
        };
    if now_verified || target_email_is_admin {
        tracing::warn!(
            target_identity = %target_identity,
            email = %target_email,
            now_verified,
            target_email_is_admin,
            "claim-email: refused at confirm — identity verified or in admin allowlist",
        );
        return render_claim_confirm_error(
            &state,
            &csrf.0,
            locale.clone(),
            &form.token,
            &crate::i18n::lookup(&locale, "claim-error-no-longer-claimable"),
        );
    }

    // Code matched. Delete the unverified identity (+ critical audit row)
    // via the shared admin action so the recipe lives in one place.
    let metadata = audit_metadata!(
        "reclaim_email" => target_email.clone(),
        "deleted_identity_id" => target_identity.clone(),
    );
    if let Err(e) = delete_identity_audited(
        &state,
        &target_identity,
        DeleteActor::User {
            identity_id: &target_identity,
            email: &target_email,
        },
        DeleteReason::EmailReclaim,
        metadata,
        None,
    )
    .await
    {
        tracing::error!(error = ?e, "claim-email: delete identity failed");
        return render_claim_confirm_error(
            &state,
            &csrf.0,
            locale.clone(),
            &form.token,
            &crate::i18n::lookup(&locale, "claim-error-release-failed"),
        );
    }

    // Land the user on /registration with the just-released email pre-
    // filled. Two channels: a query param (used when the flow id is
    // already in the URL) AND a short-lived cookie (used after Kratos's
    // browser-init round-trip drops the query string). Cookie scope is
    // /registration so it never leaks to other surfaces.
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let secure = state.cfg.self_.is_https();
    // No Max-Age — session cookie, consumed and cleared by the
    // registration handler on next render.
    let cookie = Cookie::build(("forseti_prefill_email", target_email.clone()))
        .path("/registration")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .build();
    let redirect_url = format!(
        "/registration?prefill_email={}",
        ory_client::apis::urlencode(target_email)
    );
    let mut resp = Redirect::to(&redirect_url).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&cookie.to_string()) {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
    resp
}

fn render_claim_confirm_error(
    state: &AppState,
    csrf_token: &str,
    locale: crate::locale::LanguageIdentifier,
    token: &str,
    msg: &str,
) -> Response {
    render(&ClaimConfirmTemplate {
        chrome: PageChrome::from_parts(state, String::new(), csrf_token.to_string(), locale),
        token: token.to_string(),
        error: Some(msg.to_string()),
    })
}

fn mint_six_digit_code() -> String {
    let mut rng = rand::rng();
    let n: u32 = rng.random_range(0..1_000_000);
    format!("{:06}", n)
}

/// Send the email-claim verification code via polymail. Mirrors the org
/// invite mailer — bypasses Kratos's courier because the admin API
/// doesn't expose a one-off send endpoint.
pub async fn send_claim_email_code(
    recipient: &str,
    code: &str,
    cfg: &crate::config::AppConfig,
) -> anyhow::Result<()> {
    let brand_name = &cfg.brand.name;
    let subject = format!("Confirm your email for {brand_name}");
    let body = format!(
        "Hello,\n\nSomeone is trying to register an account on {brand_name} using this email address. The existing account that owns this address hasn't completed verification yet.\n\nIf this was you, enter the following code to claim the email:\n\n  {code}\n\nThe code expires in 15 minutes. If you didn't request this, ignore this email — the existing unverified account will remain in place.\n",
    );
    crate::mailer::send_text(cfg.email.as_ref(), &cfg.self_, recipient, &subject, &body).await
}
