//! `/oauth/consent` — Hydra's consent challenge handler (GET renders or
//! auto-grants; POST processes the allow/deny decision and folds identity
//! traits into the id_token claims).

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{self, AuditCtx, AuditEvent, action, severity, target_kind};
use crate::audit_metadata;
use crate::csrf::CsrfForm;
use crate::extractors::{Csrf, OptionalSession};
use crate::locale::LanguageIdentifier;
use crate::oauth_client_metadata;
use crate::ory;
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

/// View-model for a single requested OAuth2 scope on the consent screen.
struct ConsentScopeView {
    name: String,
    description: String,
    /// `true` when un-checking would break the protocol (only `openid`); the
    /// template disables the checkbox and emits a hidden duplicate so it's
    /// still POSTed.
    required: bool,
}

/// One remembered account offered in the consent-screen chooser.
struct ConsentAccountView {
    id: String,
    label: String,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    chrome: PageChrome,
    consent_intro: String,
    client_name: String,
    /// Subject email for the "Signed in as ..." line. Distinct from the
    /// chrome's `user_email`: consent runs out-of-band from the Kratos session
    /// cookie, so we look up the subject directly via the admin API.
    subject_email: String,
    challenge: String,
    scopes: Vec<ConsentScopeView>,
    /// True when an admin verified the client, or no `oauth_client_metadata`
    /// row exists (legacy clients default to verified). Drives the consent
    /// badge: verified shows a checkmark, unverified a caution banner.
    verified: bool,
    /// Client id, for the logo URL. Empty when Hydra didn't give us one,
    /// which also forces `has_logo` false.
    client_id: String,
    /// True when an operator uploaded a logo for this client. Independent of
    /// `verified`: an unverified client still shows its logo, the caution
    /// banner carries the trust signal.
    has_logo: bool,
    /// Other accounts remembered on this device (current subject excluded);
    /// each offers a one-click switch via the OAuth restart.
    known_accounts: Vec<ConsentAccountView>,
    /// The client_id URL's host for a `source='cimd'` client — the primary
    /// identity (`client_name` then carries it too). Empty for non-CIMD
    /// clients or when the client_id fails URL parse; both render as before.
    /// Also suppresses the verification badge, which never applies to CIMD.
    cimd_host: String,
    /// The CIMD document's self-asserted `client_name`, demoted to a
    /// secondary line. Empty when absent or outside the CIMD rendering.
    cimd_client_name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthConsentQuery {
    consent_challenge: String,
}

pub(crate) async fn oauth_consent(
    State(state): State<AppState>,
    Query(query): Query<OAuthConsentQuery>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    csrf: Csrf,
    session: OptionalSession,
    actx: AuditCtx,
) -> Response {
    let challenge = query.consent_challenge;
    let req = match ory::hydra::get_consent_request(&state.ory, &challenge).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "hydra get_consent_request failed");
            return Redirect::to("/error").into_response();
        }
    };

    // Compute display locale honoring ui_locales (D1): ?lang= > ui_locales > cookie > trait > Accept-Language > en.
    let ui_locales: Option<Vec<String>> = req
        .oidc_context
        .as_ref()
        .and_then(|ctx| ctx.ui_locales.clone());
    let locale = {
        let (mut p, _) = axum::http::Request::new(()).into_parts();
        p.uri = uri;
        p.headers = headers.clone();
        crate::page_chrome::resolve_locale_for_flow(&p, &session, ui_locales.as_deref())
    };

    let requested_scope = req.requested_scope.clone().unwrap_or_default();
    let requested_audience = req
        .requested_access_token_audience
        .clone()
        .unwrap_or_default();
    let subject = req.subject.clone().unwrap_or_default();

    let client_skip_consent = req
        .client
        .as_ref()
        .and_then(|c| c.skip_consent)
        .unwrap_or(false);
    let hydra_skip = req.skip.unwrap_or(false);

    // Verification lookup must run before the auto-grant decision: an
    // unverified client shows the caution banner on every consent, so neither
    // Hydra `skip` nor client-side `skip_consent` may bypass it. Missing row
    // defaults to verified (legacy / admin-created); DCR clients always carry
    // an "unverified" row.
    let client_id_lookup = req
        .client
        .as_ref()
        .and_then(|c| c.client_id.as_deref())
        .unwrap_or_default();
    let (verified, is_cimd) = if client_id_lookup.is_empty() {
        (true, false)
    } else {
        match oauth_client_metadata::get(&state.db, client_id_lookup).await {
            Ok(Some(row)) => (
                row.is_verified(),
                row.source == oauth_client_metadata::source::CIMD,
            ),
            Ok(None) => (true, false),
            Err(e) => {
                // Fail closed: a DB blip must not silently auto-grant a
                // DCR-registered client that hasn't been admin-reviewed.
                tracing::error!(
                    error = ?e,
                    client_id = %client_id_lookup,
                    "consent: oauth_client_metadata lookup failed; treating client as unverified"
                );
                let ev = AuditEvent::new(action::CONSENT_VERIFICATION_LOOKUP_FAILED)
                    .target(target_kind::OAUTH_CLIENT, client_id_lookup.to_string())
                    .with_ctx(&actx)
                    .severity(severity::WARNING)
                    .failed(e.to_string());
                let _ = audit::log(&state.db, ev).await;
                (false, false)
            }
        }
    };

    // Linux-PAM device-auth never auto-skips consent: the host+account
    // binding must be shown, so a stray `skip_consent` or remembered grant
    // must not bypass it. Guard sits above the skip tree.
    let is_pam_client =
        !client_id_lookup.is_empty() && client_id_lookup == state.cfg.posix.pam_client_id;

    // Auto-grant path (remembered consent or trusted client). Unverified
    // clients never auto-grant, and CIMD clients never skip regardless of
    // verification: their identity is a fetched URL, so the host must be
    // shown on every consent (spec invariant D.5).
    if !is_pam_client && verified && !is_cimd && (hydra_skip || client_skip_consent) {
        if let Some(rejected) =
            reject_unless_session_subject(&state, &challenge, &subject, &session).await
        {
            return rejected;
        }
        let request_url = req.request_url.as_deref().unwrap_or_default();
        let requested_org_id =
            crate::oauth::login::parse_organization_id_param(request_url).filter(|s| !s.is_empty());
        return finalize_consent(
            &state,
            &challenge,
            client_id_lookup,
            &subject,
            requested_scope,
            requested_audience,
            request_url,
            false,
            &headers,
            requested_org_id.as_deref(),
            locale,
        )
        .await
        .into_response();
    }

    let self_asserted_name = req
        .client
        .as_ref()
        .and_then(|c| c.client_name.clone().filter(|n| !n.is_empty()));
    // CIMD identity: the client_id is a URL whose host is what its operator
    // provably controls, so the host renders primary and the document's
    // self-asserted client_name is demoted to a secondary line. A parse
    // failure falls back to the regular rendering.
    let cimd_host = if is_cimd {
        url::Url::parse(client_id_lookup)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let (client_name, cimd_client_name) = if cimd_host.is_empty() {
        (
            self_asserted_name
                .or_else(|| req.client.as_ref().and_then(|c| c.client_id.clone()))
                .unwrap_or_else(|| "this application".to_string()),
            String::new(),
        )
    } else {
        (cimd_host.clone(), self_asserted_name.unwrap_or_default())
    };

    let scopes: Vec<ConsentScopeView> = requested_scope
        .iter()
        .map(|s| ConsentScopeView {
            name: s.clone(),
            description: state
                .cfg
                .oauth
                .scope_descriptions
                .get(s)
                .cloned()
                .or_else(|| {
                    // Built-in scope: look up the locale-aware description.
                    // Unknown scopes (no default_scope_description entry) fall through to the raw name.
                    // Operator-supplied scope_descriptions (above) stay English per spec decision D3.
                    super::default_scope_description(s)
                        .map(|_| crate::i18n::lookup(&locale, &format!("consent-scope-{s}")))
                })
                .unwrap_or_else(|| s.clone()),
            // `openid` is mandatory: Hydra rejects the accept if it's missing
            // from `grant_scope`, so the template disables the checkbox and
            // emits a hidden duplicate to keep it in the POST.
            required: s == "openid",
        })
        .collect();

    // Subject email for the "Signed in as ..." line. Via the admin API
    // because the Kratos session cookie isn't guaranteed in scope here, and
    // we already trust `subject` from Hydra.
    let subject_email = match ory::kratos::admin_get_identity(&state.ory, &subject).await {
        Ok(id) => id
            .traits
            .and_then(|t| t.get("email").and_then(|v| v.as_str()).map(str::to_string))
            .unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = ?e, subject, "failed to fetch identity for consent display");
            String::new()
        }
    };

    // Operator-uploaded, so it's safe to show before the user has decided;
    // a probe failure just falls back to the generic icon.
    let has_logo = !client_id_lookup.is_empty()
        && crate::client_logo::exists(&state.db, client_id_lookup)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = ?e,
                    client_id = %client_id_lookup,
                    "consent: client logo probe failed; falling back to the generic icon"
                );
                false
            });

    let known_ids = crate::accounts::cookie::read_known_account_ids(
        &headers,
        &state.cookie_secret,
        state.cfg.accounts.known_accounts_cookie_ttl_seconds,
    );
    let known_accounts: Vec<ConsentAccountView> = crate::accounts::resolve(&state, &known_ids)
        .await
        .into_iter()
        .filter(|a| a.id != subject)
        .map(|a| ConsentAccountView {
            id: a.id,
            label: if a.email.is_empty() {
                a.display_name.clone()
            } else {
                a.email.clone()
            },
        })
        .collect();

    // Theme from the active-org cookie, same source `finalize_consent` reads
    // for the `org` claim; falls back to the global theme when absent or the
    // org hasn't opted in (enabled), gated by `public_branding_by_id`.
    let active_org_id = crate::orgs::cookie::read_active_org_cookie(
        &headers,
        &state.cookie_secret,
        state.cfg.orgs.active_org_cookie_ttl_seconds,
    );
    let chrome = crate::theming::theme_chrome_for_org_id(
        &state.db,
        &state.cfg.brand,
        PageChrome::from_parts(&state, subject_email.clone(), csrf.0, locale),
        active_org_id.as_deref(),
    )
    .await;

    let mut resp = render(&ConsentTemplate {
        chrome,
        consent_intro: state.cfg.brand.consent_intro.clone(),
        client_name,
        subject_email,
        challenge,
        scopes,
        verified,
        client_id: client_id_lookup.to_string(),
        has_logo,
        known_accounts,
        cimd_host,
        cimd_client_name,
    });
    // Granting consent navigates portal -> Hydra -> this client's redirect_uri,
    // and `form-action` is enforced across that whole chain. Hydra registered
    // and validated these URIs; without them the browser blocks the last hop
    // and the user is left on an apparently inert page.
    if let Some(uris) = req.client.as_ref().and_then(|c| c.redirect_uris.as_ref()) {
        crate::app::allow_form_action_to(&mut resp, uris);
    }
    resp
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthConsentForm {
    consent_challenge: String,
    // Defaulted so a body without a submitter (e.g. the switch-account form
    // posted with no button) yields a friendly error, not a raw 422.
    #[serde(default)]
    decision: String,
    /// `Vec` because the field repeats once per granted scope.
    #[serde(default, rename = "grant_scope")]
    grant_scope: Vec<String>,
    remember: Option<String>,
    remember_account: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsentSwitchForm {
    consent_challenge: String,
    identity_id: String,
}

/// Restart the same OAuth flow with prompt=login so the downstream app still completes after a session switch.
pub(crate) async fn consent_switch(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<ConsentSwitchForm>,
) -> Response {
    switch_account(
        &state,
        &headers,
        &actx,
        &form.consent_challenge,
        Some(&form.identity_id),
    )
    .await
}

pub(crate) async fn oauth_consent_submit(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    session: OptionalSession,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<OAuthConsentForm>,
) -> Response {
    if form.decision == "switch_account" {
        return switch_account(&state, &headers, &actx, &form.consent_challenge, None).await;
    }

    let remember = form.remember.as_deref() == Some("true");

    if form.decision == "deny" {
        // Best-effort subject + client for the audit row; a failure here
        // doesn't block the reject.
        let (subject, client_id) =
            match ory::hydra::get_consent_request(&state.ory, &form.consent_challenge).await {
                Ok(r) => (
                    r.subject.clone().unwrap_or_default(),
                    r.client
                        .as_ref()
                        .and_then(|c| c.client_id.clone())
                        .unwrap_or_default(),
                ),
                Err(_) => (String::new(), String::new()),
            };
        let actor_email = lookup_identity_email(&state, &subject).await;
        match ory::hydra::reject_consent_request(
            &state.ory,
            &form.consent_challenge,
            "access_denied",
            "The resource owner denied the request.",
        )
        .await
        {
            Ok(redirect) => {
                let mut ev = AuditEvent::new(action::OAUTH_CONSENT_DENIED).with_ctx(&actx);
                if !subject.is_empty() {
                    ev = ev.actor_user(&subject, &actor_email);
                }
                if !client_id.is_empty() {
                    ev = ev.target(target_kind::OAUTH_CLIENT, client_id);
                }
                let _ = audit::log(&state.db, ev).await;
                return Redirect::to(&redirect.redirect_to).into_response();
            }
            Err(e) => {
                tracing::error!(error = ?e, "hydra reject_consent_request failed");
                return Redirect::to("/error").into_response();
            }
        }
    }

    // Only "accept" reaches the grant path; "deny" and "switch_account" are
    // handled above. Anything else (empty from a submitterless POST, or a
    // tampered value) is a friendly error, never an implicit grant.
    if form.decision != "accept" {
        tracing::warn!(decision = %form.decision, "consent: unrecognized decision; redirecting to error");
        return Redirect::to("/error").into_response();
    }

    let req = match ory::hydra::get_consent_request(&state.ory, &form.consent_challenge).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "hydra get_consent_request failed during accept");
            return Redirect::to("/error").into_response();
        }
    };

    let subject = req.subject.clone().unwrap_or_default();
    if let Some(rejected) =
        reject_unless_session_subject(&state, &form.consent_challenge, &subject, &session).await
    {
        return rejected;
    }

    let client_id = req
        .client
        .as_ref()
        .and_then(|c| c.client_id.clone())
        .unwrap_or_default();
    let requested_audience = req
        .requested_access_token_audience
        .clone()
        .unwrap_or_default();
    // Snapshot for the lazy `resource_url` capture below. `request_url` is
    // the original `/oauth2/auth` URL where RFC 8707 clients send
    // `?resource=<url>`; `requested_audience` is the fallback for clients
    // that used Hydra's non-standard `audience=` param instead.
    let request_url = req.request_url.clone().unwrap_or_default();
    let captured_audience = requested_audience.clone();
    let grant_scope = intersect_requested_scope(
        form.grant_scope,
        &req.requested_scope.clone().unwrap_or_default(),
    );
    let grant_scope_for_audit = grant_scope.clone();

    // Re-compute the consent locale from the same inputs the GET handler used
    // so the locale claim fallback is consistent between both code paths.
    let consent_locale = {
        let ui_locales: Option<Vec<String>> = req
            .oidc_context
            .as_ref()
            .and_then(|ctx| ctx.ui_locales.clone());
        let (mut p, _) = axum::http::Request::new(()).into_parts();
        p.uri = uri;
        p.headers = headers.clone();
        crate::page_chrome::resolve_locale_for_flow(&p, &session, ui_locales.as_deref())
    };

    let requested_org_id =
        crate::oauth::login::parse_organization_id_param(&request_url).filter(|s| !s.is_empty());
    let outcome = finalize_consent(
        &state,
        &form.consent_challenge,
        &client_id,
        &subject,
        grant_scope,
        requested_audience,
        &request_url,
        remember,
        &headers,
        requested_org_id.as_deref(),
        consent_locale,
    )
    .await;

    let (mut redirect, groups_count, groups_truncated) = match outcome {
        FinalizeOutcome::Granted {
            redirect,
            groups_count,
            groups_truncated,
        } => (redirect, groups_count, groups_truncated),
        FinalizeOutcome::RedirectedToError { redirect } => return redirect,
    };

    if form.remember_account.as_deref() == Some("true") && !subject.is_empty() {
        let ttl = state.cfg.accounts.known_accounts_cookie_ttl_seconds;
        let ids =
            crate::accounts::cookie::read_known_account_ids(&headers, &state.cookie_secret, ttl);
        let next = crate::accounts::cookie::add_mru(
            ids,
            &subject,
            crate::accounts::cookie::KNOWN_ACCOUNTS_CAP,
        );
        let set_cookie = crate::accounts::cookie::set_known_accounts_cookie(
            &state.cookie_secret,
            ttl,
            &next,
            state.cfg.self_.is_https(),
        );
        crate::web::append_set_cookie(&mut redirect, Some(set_cookie));
    }

    let actor_email = lookup_identity_email(&state, &subject).await;
    let mut ev = AuditEvent::new(action::OAUTH_CONSENT_GRANTED)
        .actor_user(&subject, &actor_email)
        .with_ctx(&actx)
        .metadata(audit_metadata!(
            "scope" => grant_scope_for_audit.join(" "),
            "remember" => remember,
            "groups_count" => groups_count as i64,
            "groups_truncated" => groups_truncated,
        ));
    if !client_id.is_empty() {
        ev = ev.target(target_kind::OAUTH_CLIENT, client_id.clone());
    }
    let _ = audit::log(&state.db, ev).await;

    // Lazy provenance: record the resource URL being granted, if any, when
    // the row doesn't already carry one. First-writer-wins (see
    // `upsert_resource_url_if_missing`). Fires for every client.
    if !client_id.is_empty()
        && let Some(url) = extract_resource_url(request_url.as_str(), captured_audience.as_slice())
        && let Err(e) =
            oauth_client_metadata::upsert_resource_url_if_missing(&state.db, &client_id, &url).await
    {
        tracing::error!(
            error = ?e,
            client_id = %client_id,
            "consent: failed to capture resource_url provenance",
        );
    }
    redirect
}

/// Gate every grant path on "the consent subject IS the signed-in identity":
/// a consent link bound to one subject and opened by another would otherwise
/// mint tokens for the link's owner while the clicking user believes they
/// authorised their own account (CWE-384 at the relying party). Returns the
/// `access_denied` rejection response on mismatch, `None` when the grant may
/// proceed. An empty subject never passes.
async fn reject_unless_session_subject(
    state: &AppState,
    challenge: &str,
    subject: &str,
    session: &OptionalSession,
) -> Option<Response> {
    // InsufficientAal means a session exists we couldn't read here; treating
    // it as "no subject" keeps the mismatch check conservative.
    let session_subject = session.identity_id().unwrap_or_default();
    if subject_is_signed_in(session_subject, subject) {
        return None;
    }
    tracing::warn!(
        consent_subject = %subject,
        session_subject = %session_subject,
        "rejecting consent: session subject mismatch"
    );
    match ory::hydra::reject_consent_request(
        &state.ory,
        challenge,
        "access_denied",
        "Consent subject does not match the signed-in identity.",
    )
    .await
    {
        Ok(redirect) => Some(Redirect::to(&redirect.redirect_to).into_response()),
        Err(e) => {
            tracing::error!(error = ?e, "hydra reject_consent_request (mismatch) failed");
            Some(Redirect::to("/error").into_response())
        }
    }
}

/// The grant predicate behind [`reject_unless_session_subject`]: an empty
/// consent subject, or one that isn't the session's identity, never grants.
fn subject_is_signed_in(session_subject: &str, consent_subject: &str) -> bool {
    !consent_subject.is_empty() && session_subject == consent_subject
}

/// Drop granted scopes the client never asked for. The consent checkboxes are
/// only a UI affordance, so a tampered POST must not widen the grant past the
/// challenge's `requested_scope` (RFC 6749 §3.3).
fn intersect_requested_scope(granted: Vec<String>, requested: &[String]) -> Vec<String> {
    granted
        .into_iter()
        .filter(|s| requested.iter().any(|r| r == s))
        .collect()
}

/// Tear down the Kratos session and restart the OAuth flow with
/// `prompt=login` so the user lands on `/login` to authenticate as someone
/// else. Teardown is best-effort; the user may already be signed out.
async fn switch_account(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    actx: &AuditCtx,
    challenge: &str,
    login_hint: Option<&str>,
) -> Response {
    let req = match ory::hydra::get_consent_request(&state.ory, challenge).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "hydra get_consent_request failed during account switch");
            return Redirect::to("/error").into_response();
        }
    };
    let subject = req.subject.clone().unwrap_or_default();
    let client_id = req
        .client
        .as_ref()
        .and_then(|c| c.client_id.clone())
        .unwrap_or_default();
    let request_url = req.request_url.clone().unwrap_or_default();

    let cookie = crate::cookies::cookie_header(headers);
    ory::kratos::tear_down_session(&state.ory, &cookie).await;

    let actor_email = lookup_identity_email(state, &subject).await;
    let mut ev = AuditEvent::new(action::OAUTH_ACCOUNT_SWITCH).with_ctx(actx);
    if !subject.is_empty() {
        ev = ev.actor_user(&subject, &actor_email);
    }
    if !client_id.is_empty() {
        ev = ev.target(target_kind::OAUTH_CLIENT, client_id);
    }
    let _ = audit::log(&state.db, ev).await;

    match with_prompt_login(&request_url, login_hint) {
        Some(target) => Redirect::to(&target).into_response(),
        None => Redirect::to("/login").into_response(),
    }
}

/// Pick a single resource-URL to stamp on
/// `oauth_client_metadata.resource_url`. RFC 8707 clients send
/// `?resource=<url>` on the auth URL (Hydra's `request_url`); others use
/// Hydra's non-standard `audience=`, which falls back to the first
/// `requested_access_token_audience` entry. `None` when neither yields a
/// value. Not normalised or validated: this is "what we observed".
fn extract_resource_url(request_url: &str, requested_audience: &[String]) -> Option<String> {
    resource_params(request_url).into_iter().next().or_else(|| {
        requested_audience
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(str::to_string)
    })
}

/// Every RFC 8707 `resource` value on the original `/oauth2/auth` URL, in the
/// order the client sent them (§2 permits more than one). Trimmed but
/// otherwise verbatim — canonicalisation is the caller's business.
fn resource_params(request_url: &str) -> Vec<String> {
    let Ok(url) = url::Url::parse(request_url) else {
        return Vec::new();
    };
    url.query_pairs()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

/// The audiences a consent is allowed to grant, from the union of both
/// carriers: Hydra/fosite fills `requested_access_token_audience` from its
/// non-standard `audience=` form parameter, and RFC 8707 clients put
/// `resource=` on the auth URL (which fosite ignores entirely, so an MCP client
/// would otherwise get `aud: []`).
///
/// A requested value is granted when it is on `allowed` — the enabled
/// `resource_registry` rows (see [`crate::resource_registry::list_enabled`]) —
/// or on `registered` — the client's own registered `audience`, passed in only
/// when Forseti knows an operator wrote that record (see
/// [`operator_written_audiences`]). Default deny: everything else is dropped.
///
/// Both arms compare verbatim first, because an audience is an opaque
/// identifier and need not be a URI (Stackpit's web SSO uses a bare hostname,
/// which no amount of canonicalisation can match). The canonical comparison is
/// the fallback, so an RFC 8707 §2 resource still matches its allow-list entry
/// across a trailing slash or fragment.
fn resolve_granted_audience(
    client_id: &str,
    requested_audience: &[String],
    request_url: &str,
    allowed: &[String],
    registered: &[String],
) -> Vec<String> {
    let allowed_canonical: Vec<String> = allowed
        .iter()
        .filter_map(|a| crate::oauth::canonical_resource(a))
        .collect();
    let mut granted: Vec<String> = Vec::new();
    for raw in requested_audience
        .iter()
        .cloned()
        .chain(resource_params(request_url))
    {
        let raw = raw.trim();
        let permitted_verbatim =
            registered.iter().any(|r| r == raw) || allowed.iter().any(|a| a.trim() == raw);
        let resolved = if permitted_verbatim {
            raw.to_string()
        } else {
            match crate::oauth::canonical_resource(raw) {
                Some(resource) if allowed_canonical.contains(&resource) => resource,
                _ => {
                    tracing::warn!(
                        client_id,
                        requested = %raw,
                        "consent: dropping requested audience; neither operator-registered on the \
                         client nor an enabled resource registry entry",
                    );
                    continue;
                }
            }
        };
        if !granted.contains(&resolved) {
            tracing::info!(client_id, audience = %resolved, "consent: granting access-token audience");
            granted.push(resolved);
        }
    }
    granted
}

/// The client's registered `audience`, but only for a client Forseti knows an
/// operator created (`oauth_client_metadata.source = 'admin'`). Empty for
/// anything else, which leaves the allow-list as the only policy.
///
/// A DCR client can rewrite its own Hydra record — including `audience` —
/// through RFC 7592 with the registration access token Hydra mints for it, so
/// `source = 'dcr'` is caller-controlled. A client with no row at all is
/// ambiguous: it may be an operator's out-of-band `hydra create client`, or it
/// may have registered straight at Hydra's own `/oauth2/register`, which is
/// publicly routed in this deployment and equally caller-controlled. Forseti
/// can't tell those apart, so it doesn't guess. Operators of out-of-band
/// clients register the audience at `/admin/resources` instead.
async fn operator_written_audiences(state: &AppState, client_id: &str) -> Vec<String> {
    match oauth_client_metadata::get(&state.db, client_id).await {
        Ok(Some(row)) if row.source == oauth_client_metadata::source::ADMIN => {}
        Ok(_) => return Vec::new(),
        Err(e) => {
            tracing::error!(
                error = ?e,
                client_id,
                "consent: client metadata lookup failed; ignoring the client's registered audience",
            );
            return Vec::new();
        }
    }
    match ory::hydra::get_client(&state.ory, client_id).await {
        Ok(c) => c.audience.unwrap_or_default(),
        Err(e) => {
            tracing::warn!(
                error = ?e,
                client_id,
                "consent: client lookup failed; falling back to the resource allow-list alone",
            );
            Vec::new()
        }
    }
}

/// Rebuild the original `/oauth2/auth` URL forcing `prompt=login` (merged into
/// any existing space-delimited `prompt`, deduped) so the restarted flow
/// re-authenticates, optionally adding `login_hint`. `None` if `request_url` is
/// empty or unparseable.
fn with_prompt_login(request_url: &str, login_hint: Option<&str>) -> Option<String> {
    if request_url.is_empty() {
        return None;
    }
    let mut url = url::Url::parse(request_url).ok()?;

    let mut prompts: Vec<String> = Vec::new();
    let mut preserved: Vec<(String, String)> = Vec::new();
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "prompt" => prompts.extend(v.split(' ').filter(|s| !s.is_empty()).map(str::to_string)),
            "login_hint" => {} // replaced below when a hint is supplied
            _ => preserved.push((k.into_owned(), v.into_owned())),
        }
    }
    if !prompts.iter().any(|p| p == "login") {
        prompts.push("login".to_string());
    }

    {
        let mut qp = url.query_pairs_mut();
        qp.clear();
        qp.extend_pairs(preserved);
        qp.append_pair("prompt", &prompts.join(" "));
        if let Some(hint) = login_hint.filter(|h| !h.is_empty()) {
            qp.append_pair("login_hint", hint);
        }
    }
    Some(url.into())
}

/// Best-effort identity email for the audit row. Empty `subject` or a
/// lookup failure returns an empty string; the email is display-only.
async fn lookup_identity_email(state: &AppState, subject: &str) -> String {
    if subject.is_empty() {
        return String::new();
    }
    match ory::kratos::admin_get_identity(&state.ory, subject).await {
        Ok(id) => id
            .traits
            .and_then(|t| t.get("email").and_then(|v| v.as_str()).map(str::to_string))
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Tagged result of `finalize_consent`: the caller must know whether Hydra
/// accepted before emitting `OAUTH_CONSENT_GRANTED` or capturing provenance.
enum FinalizeOutcome {
    Granted {
        redirect: Response,
        groups_count: usize,
        groups_truncated: bool,
    },
    RedirectedToError {
        redirect: Response,
    },
}

impl FinalizeOutcome {
    fn into_response(self) -> Response {
        match self {
            FinalizeOutcome::Granted { redirect, .. } => redirect,
            FinalizeOutcome::RedirectedToError { redirect } => redirect,
        }
    }
}

/// Resolve the active-org membership for the id_token claims. A pinned
/// `requested_org_id` (from the auth request's `organization_id`) wins: the
/// matching membership if the subject has one, else `None` (suppress the
/// `org`/`groups` claims rather than assert a different tenant). Without a
/// pin, `cookie_choice` (active-org cookie ∩ memberships, else first) is used.
fn resolve_claim_active_org(
    requested_org_id: Option<&str>,
    memberships: &[crate::orgs::Membership],
    cookie_choice: Option<&crate::orgs::Membership>,
) -> Option<crate::orgs::Membership> {
    match requested_org_id {
        Some(req_org) if !req_org.is_empty() => {
            memberships.iter().find(|m| m.org_id == req_org).cloned()
        }
        _ => cookie_choice.cloned(),
    }
}

/// Build the id_token claims from identity traits + granted scopes, then
/// accept the consent challenge. Shared by the auto-grant and Allow paths.
/// `requested_org_id` (the auth request's `organization_id`, if any) pins the
/// `org`/`groups` claims to that org; see `resolve_claim_active_org`.
/// `request_url` is the original `/oauth2/auth` URL, the carrier of RFC 8707
/// `resource=`; the audience policy lives here so no grant path can miss it.
// Cohesive consent-finalization inputs; splitting into a struct adds no clarity.
#[allow(clippy::too_many_arguments)]
async fn finalize_consent(
    state: &AppState,
    challenge: &str,
    client_id: &str,
    subject: &str,
    grant_scope: Vec<String>,
    requested_audience: Vec<String>,
    request_url: &str,
    remember: bool,
    headers: &axum::http::HeaderMap,
    requested_org_id: Option<&str>,
    consent_locale: LanguageIdentifier,
) -> FinalizeOutcome {
    // Both policy arms are fetched lazily: skipped entirely when nothing was
    // requested, so a consent with no audience carrier costs no extra
    // round-trips. `registered` is reused for the write below.
    let audience_requested =
        !requested_audience.is_empty() || !resource_params(request_url).is_empty();
    let registered = if client_id.is_empty() || !audience_requested {
        Vec::new()
    } else {
        operator_written_audiences(state, client_id).await
    };
    let allowed = if audience_requested {
        // Fail closed: an unreadable registry denies every requested audience.
        match crate::resource_registry::list_enabled(&state.db).await {
            Ok(resources) => resources,
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    client_id,
                    "consent: resource registry read failed; denying all requested audiences",
                );
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let grant_audience = resolve_granted_audience(
        client_id,
        &requested_audience,
        request_url,
        &allowed,
        &registered,
    );
    if !client_id.is_empty()
        && let Err(e) =
            ory::hydra::add_client_audiences(&state.ory, client_id, &registered, &grant_audience)
                .await
    {
        tracing::error!(
            error = ?e,
            client_id,
            "consent: could not register the granted audience on the client; the refresh grant will fail",
        );
    }
    // Fan out identity + org memberships in parallel; the membership fetch
    // is skipped unless the grant scope consumes it.
    let needs_org_claims = grant_scope
        .iter()
        .any(|s| s == "org" || s == "orgs" || s == "groups");
    let identity_fut = ory::kratos::admin_get_identity(&state.ory, subject);
    let (identity_res, memberships) = if needs_org_claims {
        let memberships_fut = crate::orgs::list_memberships_limited(
            &state.db,
            subject,
            crate::orgs::nav::ORGS_CLAIM_CAP as i64 + 1,
        );
        let (id_res, mem_res) = tokio::join!(identity_fut, memberships_fut);
        (id_res, mem_res.unwrap_or_default())
    } else {
        (identity_fut.await, Vec::new())
    };
    let orgs_truncated = memberships.len() > crate::orgs::nav::ORGS_CLAIM_CAP;
    let memberships = {
        let mut m = memberships;
        m.truncate(crate::orgs::nav::ORGS_CLAIM_CAP);
        m
    };
    if orgs_truncated {
        tracing::warn!(
            subject,
            kept = memberships.len(),
            "consent: orgs claim truncated to cap"
        );
    }
    let identity = match identity_res {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::warn!(error = ?e, subject, "admin_get_identity failed; id_token will be minimal");
            None
        }
    };
    let cookie_choice = crate::orgs::cookie::read_active_org_cookie(
        headers,
        &state.cookie_secret,
        state.cfg.orgs.active_org_cookie_ttl_seconds,
    )
    .and_then(|id| memberships.iter().find(|m| m.org_id == id).cloned())
    .or_else(|| memberships.first().cloned());
    // The pin may be an id or a slug; resolve to a canonical id so the org/
    // groups claims match either form. No membership write here.
    let canonical_pin = match requested_org_id.filter(|s| !s.is_empty()) {
        Some(raw) => crate::orgs::db::org_by_ref(&state.db, raw)
            .await
            .ok()
            .flatten()
            .map(|o| o.id),
        None => None,
    };
    let active = resolve_claim_active_org(
        canonical_pin.as_deref(),
        &memberships,
        cookie_choice.as_ref(),
    );
    if let Some(req_org) = requested_org_id.filter(|s| !s.is_empty())
        && active.is_none()
    {
        tracing::info!(
            subject,
            organization_id = %req_org,
            "consent: requested organization_id is not a membership; suppressing org claim",
        );
    }

    // Pre-fetch the Forseti-owned profile only when the feature is on and a
    // consuming scope is granted; skips the DB hit otherwise.
    let profile_needed = state.cfg.profiles.enabled
        && grant_scope
            .iter()
            .any(|s| s == "profile" || s == "extended_profile");
    let profile = if profile_needed {
        Some(
            crate::profiles::fetch(&state.db, subject)
                .await
                .unwrap_or_default(),
        )
    } else {
        None
    };

    // Team slugs for the `groups` claim, scoped to the active org. Only when
    // the scope is granted and an active org resolved; a DB error degrades to
    // empty, consistent with the memberships fetch above.
    let wants_groups = grant_scope.iter().any(|s| s == "groups");
    let (group_slugs, groups_truncated) = if wants_groups {
        match active.as_ref() {
            Some(m) => {
                match crate::orgs::teams::group_slugs_for_identity(&state.db, &m.org_id, subject)
                    .await
                {
                    Ok(raw) => project_group_slugs(&raw, crate::orgs::teams::GROUPS_CLAIM_CAP),
                    Err(e) => {
                        tracing::warn!(error = ?e, subject, "consent: group_slugs fetch failed; groups will be empty");
                        (Vec::new(), false)
                    }
                }
            }
            None => (Vec::new(), false),
        }
    } else {
        (Vec::new(), false)
    };
    if groups_truncated {
        tracing::warn!(
            subject,
            kept = group_slugs.len(),
            "consent: groups claim truncated to cap"
        );
    }

    let id_token_session = build_id_token_claims(
        identity.as_ref(),
        &grant_scope,
        &memberships,
        active.as_ref(),
        profile.as_ref(),
        &group_slugs,
        groups_truncated,
        orgs_truncated,
        &consent_locale,
    );

    match ory::hydra::accept_consent_request(
        &state.ory,
        challenge,
        grant_scope,
        grant_audience,
        remember,
        id_token_session,
    )
    .await
    {
        Ok(redirect) => FinalizeOutcome::Granted {
            redirect: Redirect::to(&redirect.redirect_to).into_response(),
            groups_count: group_slugs.len(),
            groups_truncated,
        },
        Err(e) => {
            tracing::error!(error = ?e, "hydra accept_consent_request failed");
            FinalizeOutcome::RedirectedToError {
                redirect: Redirect::to("/error").into_response(),
            }
        }
    }
}

/// Sort, de-dup, and cap team slugs for the `groups` claim. Returns the final
/// slug list and whether the input exceeded `cap` (drives `groups_truncated`).
fn project_group_slugs(raw: &[String], cap: usize) -> (Vec<String>, bool) {
    let mut slugs: Vec<String> = raw.to_vec();
    slugs.sort();
    slugs.dedup();
    let truncated = slugs.len() > cap;
    slugs.truncate(cap);
    (slugs, truncated)
}

/// Fold identity traits into id_token claims, scoped by granted scope.
/// `email` adds `email`/`email_verified`; `profile` adds
/// `name`/`picture`/`website`/`locale`/`preferred_username`/`updated_at`;
/// `extended_profile` adds `bio`/`pronouns`/`links`; `org` adds the active-org
/// object; `orgs` adds the (capped) membership list; "groups" adds the active-org team slugs.
#[allow(clippy::too_many_arguments)]
fn build_id_token_claims(
    identity: Option<&ory::Identity>,
    grant_scope: &[String],
    memberships: &[crate::orgs::Membership],
    active_org: Option<&crate::orgs::Membership>,
    profile: Option<&crate::profiles::Profile>,
    group_slugs: &[String],
    groups_truncated: bool,
    orgs_truncated: bool,
    consent_locale: &LanguageIdentifier,
) -> serde_json::Value {
    let scopes: std::collections::HashSet<&str> = grant_scope.iter().map(String::as_str).collect();
    let mut claims = serde_json::Map::new();

    if scopes.contains("org")
        && let Some(m) = active_org
    {
        if let Ok(role) = m.role.parse::<crate::orgs::Role>() {
            claims.insert(
                "org".to_string(),
                serde_json::json!({
                    "id": m.org_id,
                    "slug": m.slug,
                    "role": role.as_str(),
                    "name": m.name,
                }),
            );
        } else {
            tracing::warn!(
                org_id = %m.org_id,
                role = %m.role,
                "consent: skipping `org` claim for membership with unknown role",
            );
        }
    }
    if scopes.contains("orgs") {
        let arr: Vec<serde_json::Value> = memberships
            .iter()
            .filter_map(|m| {
                let role = m
                    .role
                    .parse::<crate::orgs::Role>()
                    .map_err(|_| {
                        tracing::warn!(
                            org_id = %m.org_id,
                            role = %m.role,
                            "consent: skipping `orgs[]` entry for membership with unknown role",
                        );
                    })
                    .ok()?;
                Some(serde_json::json!({
                    "id": m.org_id,
                    "slug": m.slug,
                    "role": role.as_str(),
                    "name": m.name,
                }))
            })
            .collect();
        claims.insert("orgs".to_string(), serde_json::Value::Array(arr));
        if orgs_truncated {
            claims.insert("orgs_truncated".to_string(), serde_json::Value::Bool(true));
        }
    }

    if scopes.contains("groups") {
        claims.insert(
            "groups".to_string(),
            serde_json::Value::Array(
                group_slugs
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        if groups_truncated {
            claims.insert(
                "groups_truncated".to_string(),
                serde_json::Value::Bool(true),
            );
        }
    }

    let Some(identity) = identity else {
        return serde_json::Value::Object(claims);
    };
    let traits = identity.traits.as_ref();

    if scopes.contains("email") {
        if let Some(email) = traits.and_then(|t| t.get("email")).and_then(|v| v.as_str()) {
            claims.insert(
                "email".to_string(),
                serde_json::Value::String(email.to_string()),
            );
        }
        if let Some(addrs) = identity.verifiable_addresses.as_ref() {
            // Verified if any verifiable address matching traits.email is
            // verified; falls back to `false` when unclear.
            let email = traits.and_then(|t| t.get("email")).and_then(|v| v.as_str());
            let verified = match email {
                Some(e) => addrs
                    .iter()
                    .any(|a| a.value.eq_ignore_ascii_case(e) && a.verified),
                None => addrs.iter().any(|a| a.verified),
            };
            claims.insert(
                "email_verified".to_string(),
                serde_json::Value::Bool(verified),
            );
        }
    }

    if scopes.contains("profile") {
        if let Some(name) = traits.and_then(|t| t.get("name")) {
            // Identity schema stores `name` as a string or `{first, last}`;
            // flatten both into a `name` claim.
            if let Some(s) = name.as_str() {
                if !s.is_empty() {
                    claims.insert("name".to_string(), serde_json::Value::String(s.to_string()));
                }
            } else if let Some(obj) = name.as_object() {
                let first = obj.get("first").and_then(|v| v.as_str()).unwrap_or("");
                let last = obj.get("last").and_then(|v| v.as_str()).unwrap_or("");
                let joined = format!("{first} {last}").trim().to_string();
                if !joined.is_empty() {
                    claims.insert("name".to_string(), serde_json::Value::String(joined));
                }
                if !first.is_empty() {
                    claims.insert(
                        "given_name".to_string(),
                        serde_json::Value::String(first.to_string()),
                    );
                }
                if !last.is_empty() {
                    claims.insert(
                        "family_name".to_string(),
                        serde_json::Value::String(last.to_string()),
                    );
                }
            }
        }
        if let Some(p) = profile {
            if let Some(url) = p.avatar_url.as_deref().filter(|s| !s.is_empty()) {
                claims.insert(
                    "picture".to_string(),
                    serde_json::Value::String(url.to_string()),
                );
            }
            if let Some(w) = p.website.as_deref().filter(|s| !s.is_empty()) {
                claims.insert(
                    "website".to_string(),
                    serde_json::Value::String(w.to_string()),
                );
            }
            // Omitted rather than defaulted when unset: OIDC Core 5.3.2 wants
            // an absent claim over an empty one, and synthesising the email
            // here would leak it past the `email` scope and hand RPs an
            // email-shaped value they'd key accounts on.
            if let Some(u) = p.username.as_deref().filter(|s| !s.is_empty()) {
                claims.insert(
                    "preferred_username".to_string(),
                    serde_json::Value::String(u.to_string()),
                );
            }
            // Drift signal for RPs that cached an earlier handle.
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&p.updated_at) {
                claims.insert(
                    "updated_at".to_string(),
                    serde_json::Value::Number(t.timestamp().into()),
                );
            }
        }
        // locale claim (D2): preferred_language trait if supported, else the
        // negotiated consent locale. Emitted deliberately here; not forwarded
        // by the Kratos->Hydra mapper.
        let locale_val = traits
            .and_then(|t| t.get("preferred_language"))
            .and_then(|v| v.as_str())
            .and_then(crate::locale::from_query_or_cookie)
            .map(|l| l.to_string())
            .unwrap_or_else(|| consent_locale.to_string());
        claims.insert("locale".to_string(), serde_json::Value::String(locale_val));
    }

    if scopes.contains("extended_profile")
        && let Some(p) = profile
    {
        if let Some(bio) = p.bio.as_deref().filter(|s| !s.is_empty()) {
            claims.insert(
                "bio".to_string(),
                serde_json::Value::String(bio.to_string()),
            );
        }
        if let Some(pronouns) = p.pronouns.as_deref().filter(|s| !s.is_empty()) {
            claims.insert(
                "pronouns".to_string(),
                serde_json::Value::String(pronouns.to_string()),
            );
        }
        if !p.links.is_empty() {
            let arr: Vec<serde_json::Value> = p
                .links
                .iter()
                .map(|l| serde_json::json!({"label": l.label, "url": l.url}))
                .collect();
            claims.insert("links".to_string(), serde_json::Value::Array(arr));
        }
    }

    serde_json::Value::Object(claims)
}

#[cfg(test)]
mod tests {
    use super::{
        build_id_token_claims, extract_resource_url, intersect_requested_scope,
        project_group_slugs, resolve_claim_active_org, resolve_granted_audience, resource_params,
        subject_is_signed_in, with_prompt_login,
    };
    use crate::ory;

    fn en() -> crate::locale::LanguageIdentifier {
        crate::locale::default_locale()
    }

    fn de() -> crate::locale::LanguageIdentifier {
        "de".parse().unwrap()
    }

    fn prompt_values(url: &str) -> Vec<String> {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .filter(|(k, _)| k == "prompt")
            .flat_map(|(_, v)| v.split(' ').map(str::to_string).collect::<Vec<_>>())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn query_value(url: &str, key: &str) -> Option<String> {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    #[test]
    fn subject_matches_signed_in_identity() {
        assert!(subject_is_signed_in("id-1", "id-1"));
    }

    #[test]
    fn foreign_consent_subject_is_rejected() {
        // Victim signed in as id-2 clicking Allow on a challenge bound to id-1.
        assert!(!subject_is_signed_in("id-2", "id-1"));
    }

    #[test]
    fn anonymous_caller_never_grants() {
        assert!(!subject_is_signed_in("", "id-1"));
    }

    #[test]
    fn empty_consent_subject_never_grants() {
        assert!(!subject_is_signed_in("", ""));
        assert!(!subject_is_signed_in("id-1", ""));
    }

    #[test]
    fn grant_scope_drops_unrequested_scopes() {
        let requested = vec!["openid".to_string(), "email".to_string()];
        let granted = vec![
            "openid".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
        ];
        assert_eq!(
            intersect_requested_scope(granted, &requested),
            vec!["openid".to_string(), "email".to_string()]
        );
    }

    #[test]
    fn grant_scope_keeps_a_subset() {
        let requested = vec!["openid".to_string(), "email".to_string()];
        assert_eq!(
            intersect_requested_scope(vec!["openid".to_string()], &requested),
            vec!["openid".to_string()]
        );
    }

    #[test]
    fn grant_scope_empty_stays_empty() {
        let requested = vec!["openid".to_string()];
        assert!(intersect_requested_scope(Vec::new(), &requested).is_empty());
        assert!(intersect_requested_scope(vec!["openid".to_string()], &[]).is_empty());
    }

    #[test]
    fn with_prompt_login_appends_when_absent() {
        let out = with_prompt_login("https://h/oauth2/auth?client_id=x", None).unwrap();
        assert_eq!(prompt_values(&out), vec!["login".to_string()]);
        assert_eq!(query_value(&out, "login_hint"), None);
    }

    #[test]
    fn with_prompt_login_preserves_other_prompts() {
        let out = with_prompt_login("https://h/oauth2/auth?prompt=consent", None).unwrap();
        let mut got = prompt_values(&out);
        got.sort();
        assert_eq!(got, vec!["consent".to_string(), "login".to_string()]);
    }

    #[test]
    fn with_prompt_login_dedups_existing_login() {
        let out = with_prompt_login("https://h/oauth2/auth?prompt=login", None).unwrap();
        assert_eq!(prompt_values(&out), vec!["login".to_string()]);
    }

    #[test]
    fn with_prompt_login_appends_login_hint() {
        let out = with_prompt_login("https://h/oauth2/auth?client_id=x", Some("uuid-123")).unwrap();
        assert_eq!(query_value(&out, "login_hint").as_deref(), Some("uuid-123"));
        assert_eq!(prompt_values(&out), vec!["login".to_string()]);
    }

    #[test]
    fn with_prompt_login_empty_returns_none() {
        assert_eq!(with_prompt_login("", None), None);
    }

    #[test]
    fn with_prompt_login_unparseable_returns_none() {
        assert_eq!(with_prompt_login("not a url", None), None);
    }

    #[test]
    fn extract_resource_url_picks_rfc8707_resource_param() {
        let request_url = "https://hydra.example.com/oauth2/auth?client_id=x&resource=https%3A%2F%2Fapi.example.com";
        let audience = vec![];
        assert_eq!(
            extract_resource_url(request_url, &audience),
            Some("https://api.example.com".to_string())
        );
    }

    #[test]
    fn extract_resource_url_falls_back_to_requested_audience() {
        let request_url = "https://hydra.example.com/oauth2/auth?client_id=x";
        let audience = vec!["https://api.example.com".to_string()];
        assert_eq!(
            extract_resource_url(request_url, &audience),
            Some("https://api.example.com".to_string())
        );
    }

    #[test]
    fn extract_resource_url_prefers_resource_when_both_present() {
        let request_url = "https://hydra.example.com/oauth2/auth?resource=https%3A%2F%2Fa.example";
        let audience = vec!["https://b.example".to_string()];
        assert_eq!(
            extract_resource_url(request_url, &audience),
            Some("https://a.example".to_string())
        );
    }

    #[test]
    fn extract_resource_url_neither_present_returns_none() {
        let request_url = "https://hydra.example.com/oauth2/auth?client_id=x";
        let audience: Vec<String> = vec![];
        assert_eq!(extract_resource_url(request_url, &audience), None);
    }

    #[test]
    fn extract_resource_url_empty_request_url_uses_audience() {
        let audience = vec!["https://api.example.com".to_string()];
        assert_eq!(
            extract_resource_url("", &audience),
            Some("https://api.example.com".to_string())
        );
    }

    #[test]
    fn extract_resource_url_skips_empty_audience_entries() {
        let audience = vec!["".to_string(), "  ".to_string(), "https://api".to_string()];
        assert_eq!(
            extract_resource_url("", &audience),
            Some("https://api".to_string())
        );
    }

    #[test]
    fn extract_resource_url_handles_unparseable_url() {
        // Non-URL request_url with no `resource=` falls through to audience.
        let audience = vec!["https://api".to_string()];
        assert_eq!(
            extract_resource_url("garbage", &audience),
            Some("https://api".to_string())
        );
    }

    #[test]
    fn extract_resource_url_trims_resource_value() {
        let request_url =
            "https://hydra.example.com/oauth2/auth?resource=%20%20https%3A%2F%2Fapi%20";
        assert_eq!(
            extract_resource_url(request_url, &[]),
            Some("https://api".to_string())
        );
    }

    const MCP: &str = "https://stackpit.gofranz.com/mcp";

    fn auth_url(query: &str) -> String {
        format!("https://hydra.example.com/oauth2/auth?client_id=x&{query}")
    }

    fn resource_query(resource: &str) -> String {
        let encoded: String = url::form_urlencoded::byte_serialize(resource.as_bytes()).collect();
        format!("resource={encoded}")
    }

    #[test]
    fn resource_params_returns_every_value_in_order() {
        let url = auth_url(&format!(
            "{}&{}",
            resource_query("https://a.example/x"),
            resource_query("https://b.example/y")
        ));
        assert_eq!(
            resource_params(&url),
            vec![
                "https://a.example/x".to_string(),
                "https://b.example/y".to_string()
            ]
        );
    }

    #[test]
    fn resource_params_drops_blanks_and_unparseable_urls() {
        assert!(resource_params(&auth_url("resource=&resource=%20%20")).is_empty());
        assert!(resource_params("").is_empty());
        assert!(resource_params("garbage").is_empty());
    }

    /// A client with nothing on its registered `audience` — the allow-list is
    /// the only policy in play.
    fn granted(requested_audience: &[&str], query: &str, allowed: &[&str]) -> Vec<String> {
        granted_for(requested_audience, query, allowed, &[])
    }

    fn granted_for(
        requested_audience: &[&str],
        query: &str,
        allowed: &[&str],
        registered: &[&str],
    ) -> Vec<String> {
        let owned = |xs: &[&str]| xs.iter().map(|s| (*s).to_string()).collect::<Vec<String>>();
        resolve_granted_audience(
            "client-1",
            &owned(requested_audience),
            &auth_url(query),
            &owned(allowed),
            &owned(registered),
        )
    }

    #[test]
    fn allowed_resource_is_granted_as_audience() {
        assert_eq!(granted(&[], &resource_query(MCP), &[MCP]), vec![MCP]);
    }

    #[test]
    fn unlisted_resource_is_ignored() {
        assert!(
            granted(&[], &resource_query("https://evil.example/mcp"), &[MCP]).is_empty(),
            "attacker-chosen audience must not be minted"
        );
    }

    #[test]
    fn resource_is_ignored_when_no_allow_list_is_configured() {
        assert!(granted(&[], &resource_query(MCP), &[]).is_empty());
    }

    #[test]
    fn multiple_resources_grant_only_the_allowed_ones() {
        let query = format!(
            "{}&{}&{}",
            resource_query(MCP),
            resource_query("https://evil.example/mcp"),
            resource_query("https://other.example/api")
        );
        assert_eq!(
            granted(&[], &query, &[MCP, "https://other.example/api"]),
            vec![MCP.to_string(), "https://other.example/api".to_string()]
        );
    }

    #[test]
    fn trailing_slash_matches_either_side_and_grants_the_bare_form() {
        // Client sends the slash, operator configured it without.
        assert_eq!(
            granted(
                &[],
                &resource_query("https://stackpit.gofranz.com/mcp/"),
                &[MCP]
            ),
            vec![MCP]
        );
        // ...and the other way round.
        assert_eq!(
            granted(
                &[],
                &resource_query(MCP),
                &["https://stackpit.gofranz.com/mcp/"]
            ),
            vec![MCP]
        );
    }

    #[test]
    fn unlisted_audience_parameter_is_dropped() {
        // Hydra's non-standard `audience=` arrives as
        // `requested_access_token_audience`; with anonymous DCR the caller also
        // writes the client record fosite validates it against, so it is not a
        // permission.
        assert!(
            granted(
                &["https://not-on-the-allowlist.example.com/mcp"],
                "scope=openid",
                &[MCP]
            )
            .is_empty()
        );
    }

    #[test]
    fn audience_parameter_is_dropped_when_no_allow_list_is_configured() {
        assert!(granted(&["https://stackpit.gofranz.com"], "scope=openid", &[]).is_empty());
    }

    #[test]
    fn allowed_audience_parameter_is_granted() {
        assert_eq!(granted(&[MCP], "scope=openid", &[MCP]), vec![MCP]);
    }

    #[test]
    fn a_dcr_clients_own_record_is_never_policy() {
        // `operator_written_audiences` hands the resolver an empty `registered`
        // for every client Forseti didn't see an operator create, so a record
        // the client wrote itself (RFC 7592 PUT with its registration access
        // token, or a registration straight at Hydra) buys it nothing.
        let self_written = "http://127.0.0.1:3333/mcp";
        assert!(
            granted_for(&[self_written], "scope=openid", &[MCP], &[]).is_empty(),
            "a self-written audience must not be minted"
        );
        assert!(
            granted_for(&[], &resource_query(self_written), &[MCP], &[]).is_empty(),
            "...by either carrier"
        );
    }

    #[test]
    fn non_uri_allow_list_entry_is_matched_verbatim() {
        // The remedy for a client created outside Forseti: an audience
        // identifier that isn't a URI can still be listed by the operator.
        assert_eq!(
            granted_for(&["stackpit-web"], "scope=openid", &["stackpit-web"], &[]),
            vec!["stackpit-web"]
        );
    }

    #[test]
    fn bare_hostname_audience_registered_on_the_client_is_granted() {
        // Stackpit's web SSO sends `audience=stackpit.gofranz.com` — an
        // identifier, not a URI, so it never survives canonicalisation. An
        // operator-created client carries it on its record, which is the grant.
        assert_eq!(
            granted_for(
                &["stackpit.gofranz.com"],
                "scope=openid",
                &[],
                &["stackpit.gofranz.com"]
            ),
            vec!["stackpit.gofranz.com"]
        );
        assert_eq!(
            granted_for(&["stackpit-web"], "scope=openid", &[], &["stackpit-web"]),
            vec!["stackpit-web"]
        );
    }

    #[test]
    fn bare_hostname_audience_is_dropped_when_not_registered() {
        assert!(
            granted_for(
                &["stackpit.gofranz.com"],
                "scope=openid",
                &[MCP],
                &["something-else"]
            )
            .is_empty()
        );
    }

    #[test]
    fn registered_audience_is_compared_verbatim() {
        // No canonicalisation on this arm, so a near-miss is still a miss.
        assert!(
            granted_for(&["stackpit-web "], "scope=openid", &[], &["stackpit-webb"]).is_empty()
        );
        // ...and the trimmed form of the same request matches.
        assert_eq!(
            granted_for(&["stackpit-web "], "scope=openid", &[], &["stackpit-web"]),
            vec!["stackpit-web"]
        );
    }

    #[test]
    fn registered_audience_grants_a_uri_the_allow_list_omits() {
        // An operator-written record is policy in its own right; fosite already
        // refuses any `audience=` outside it.
        assert_eq!(
            granted_for(
                &["https://internal.example/api"],
                "scope=openid",
                &[MCP],
                &["https://internal.example/api"]
            ),
            vec!["https://internal.example/api"]
        );
    }

    #[test]
    fn registered_resource_is_granted_via_the_rfc_8707_carrier() {
        assert_eq!(
            granted_for(&[], &resource_query(MCP), &[], &[MCP]),
            vec![MCP]
        );
    }

    #[test]
    fn allow_list_still_grants_what_the_record_does_not_carry_yet() {
        // The DCR path: first consent grants from the allow-list, and the
        // record is patched afterwards so the refresh grant keeps working.
        assert_eq!(
            granted_for(&[], &resource_query(MCP), &[MCP], &[]),
            vec![MCP]
        );
    }

    #[test]
    fn both_carriers_are_unioned_and_filtered() {
        let query = format!(
            "{}&{}",
            resource_query(MCP),
            resource_query("https://evil.example/mcp")
        );
        assert_eq!(
            granted(
                &["https://other.example/api", "https://evil.example/api"],
                &query,
                &[MCP, "https://other.example/api"]
            ),
            vec!["https://other.example/api".to_string(), MCP.to_string()]
        );
    }

    #[test]
    fn repeated_resource_is_granted_once() {
        let query = format!(
            "{}&{}",
            resource_query(MCP),
            resource_query("https://stackpit.gofranz.com/mcp/")
        );
        assert_eq!(granted(&[MCP], &query, &[MCP]), vec![MCP]);
    }

    #[test]
    fn unparseable_requested_audience_is_dropped() {
        assert!(granted(&["not a uri", ""], "scope=openid", &[MCP]).is_empty());
    }

    #[test]
    fn project_group_slugs_sorts_dedups_caps() {
        let raw = vec!["sre".to_string(), "platform".to_string(), "sre".to_string()];
        let (out, truncated) = project_group_slugs(&raw, 10);
        assert_eq!(out, vec!["platform".to_string(), "sre".to_string()]);
        assert!(!truncated);

        let many: Vec<String> = (0..5).map(|i| format!("t{i}")).collect();
        let (capped, was_trunc) = project_group_slugs(&many, 3);
        assert_eq!(
            capped,
            vec!["t0".to_string(), "t1".to_string(), "t2".to_string()]
        );
        assert!(was_trunc);
    }

    #[test]
    fn groups_claim_absent_without_scope() {
        let v = build_id_token_claims(
            None,
            &["openid".to_string()],
            &[],
            None,
            None,
            &["platform".to_string()],
            false,
            false,
            &en(),
        );
        assert!(v.get("groups").is_none());
    }

    #[test]
    fn groups_claim_empty_array_when_granted_no_teams() {
        let v = build_id_token_claims(
            None,
            &["openid".to_string(), "groups".to_string()],
            &[],
            None,
            None,
            &[],
            false,
            false,
            &en(),
        );
        assert_eq!(v.get("groups").unwrap(), &serde_json::json!([]));
        assert!(v.get("groups_truncated").is_none());
    }

    #[test]
    fn groups_claim_emits_slugs_and_truncation_flag() {
        let slugs = vec!["platform".to_string(), "sre".to_string()];
        let v = build_id_token_claims(
            None,
            &["groups".to_string()],
            &[],
            None,
            None,
            &slugs,
            true,
            false,
            &en(),
        );
        assert_eq!(
            v.get("groups").unwrap(),
            &serde_json::json!(["platform", "sre"])
        );
        assert_eq!(
            v.get("groups_truncated").unwrap(),
            &serde_json::Value::Bool(true)
        );
    }

    fn sample_memberships(n: usize) -> Vec<crate::orgs::Membership> {
        (0..n)
            .map(|i| crate::orgs::Membership {
                org_id: format!("org-{i}"),
                slug: format!("org-{i}"),
                name: format!("Org {i}"),
                role: "member".to_string(),
                theme_preset: None,
                brand_primary: None,
                brand_on_primary: None,
                brand_secondary: None,
                has_logo: 0,
            })
            .collect()
    }

    fn mem(org_id: &str) -> crate::orgs::Membership {
        crate::orgs::Membership {
            org_id: org_id.to_string(),
            slug: org_id.to_string(),
            name: org_id.to_string(),
            role: "member".to_string(),
            theme_preset: None,
            brand_primary: None,
            brand_on_primary: None,
            brand_secondary: None,
            has_logo: 0,
        }
    }

    #[test]
    fn pinned_org_selects_matching_membership() {
        let ms = vec![mem("a"), mem("b")];
        let got = resolve_claim_active_org(Some("b"), &ms, Some(&ms[0]));
        assert_eq!(got.map(|m| m.org_id), Some("b".to_string()));
    }

    #[test]
    fn pinned_org_not_a_member_suppresses_claim() {
        let ms = vec![mem("a"), mem("b")];
        // requested "z": not a member -> None, even though a cookie_choice exists.
        assert!(resolve_claim_active_org(Some("z"), &ms, Some(&ms[0])).is_none());
    }

    #[test]
    fn no_pin_uses_cookie_choice() {
        let ms = vec![mem("a"), mem("b")];
        let got = resolve_claim_active_org(None, &ms, Some(&ms[1]));
        assert_eq!(got.map(|m| m.org_id), Some("b".to_string()));
    }

    #[test]
    fn empty_pin_uses_cookie_choice() {
        let ms = vec![mem("a")];
        let got = resolve_claim_active_org(Some(""), &ms, Some(&ms[0]));
        assert_eq!(got.map(|m| m.org_id), Some("a".to_string()));
    }

    #[test]
    fn resolve_claim_active_org_pins_by_canonical_id() {
        let m = mem("o1");
        assert_eq!(
            super::resolve_claim_active_org(Some("o1"), std::slice::from_ref(&m), None)
                .map(|x| x.org_id),
            Some("o1".to_string())
        );
        // An unresolved slug would not match an id -> suppressed:
        assert!(
            super::resolve_claim_active_org(Some("acme"), std::slice::from_ref(&m), None).is_none()
        );
    }

    #[test]
    fn member_less_identity_suppresses_org_claim() {
        // A brand-new identity can hit consent before the floor middleware adds
        // Default: zero memberships must suppress `org`, not default or panic.
        let active = resolve_claim_active_org(None, &[], None);
        assert!(active.is_none());
        let v = build_id_token_claims(
            None,
            &["openid".to_string(), "org".to_string(), "orgs".to_string()],
            &[],
            active.as_ref(),
            None,
            &[],
            false,
            false,
            &en(),
        );
        assert!(v.get("org").is_none());
        assert_eq!(v.get("orgs").unwrap(), &serde_json::json!([]));
    }

    #[test]
    fn orgs_truncated_absent_when_under_cap() {
        let memberships = sample_memberships(3);
        let v = build_id_token_claims(
            None,
            &["orgs".into()],
            &memberships,
            None,
            None,
            &[],
            false,
            false,
            &en(),
        );
        assert!(v.get("orgs_truncated").is_none());
        assert_eq!(v["orgs"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn orgs_truncated_true_when_over_cap() {
        let v = build_id_token_claims(
            None,
            &["orgs".into()],
            &[],
            None,
            None,
            &[],
            false,
            true,
            &en(),
        );
        assert_eq!(
            v.get("orgs_truncated").unwrap(),
            &serde_json::Value::Bool(true)
        );
    }

    fn bare_identity() -> ory::Identity {
        ory::Identity {
            id: "id".to_string(),
            traits: Some(serde_json::json!({"email": "x@example.com"})),
            ..ory::Identity::new(
                "id".to_string(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
        }
    }

    #[test]
    fn preferred_username_omitted_when_unset() {
        // Absent, not defaulted to the email: a synthesised email-shaped
        // handle is what RPs key accounts on (OIDC Core 5.7).
        let profile = crate::profiles::Profile {
            updated_at: "2026-07-31T10:00:00+00:00".to_string(),
            ..Default::default()
        };
        let v = build_id_token_claims(
            Some(&bare_identity()),
            &["openid".to_string(), "profile".to_string()],
            &[],
            None,
            Some(&profile),
            &[],
            false,
            false,
            &en(),
        );
        assert!(v.get("preferred_username").is_none());
        assert_eq!(v.get("updated_at").unwrap(), &serde_json::json!(1785492000));
    }

    #[test]
    fn preferred_username_emitted_under_profile_scope() {
        let profile = crate::profiles::Profile {
            username: Some("j.doe".to_string()),
            updated_at: "2026-07-31T10:00:00+00:00".to_string(),
            ..Default::default()
        };
        let v = build_id_token_claims(
            Some(&bare_identity()),
            &["openid".to_string(), "profile".to_string()],
            &[],
            None,
            Some(&profile),
            &[],
            false,
            false,
            &en(),
        );
        assert_eq!(
            v.get("preferred_username").unwrap(),
            &serde_json::json!("j.doe")
        );
    }

    #[test]
    fn preferred_username_absent_without_profile_scope() {
        let profile = crate::profiles::Profile {
            username: Some("j.doe".to_string()),
            ..Default::default()
        };
        let v = build_id_token_claims(
            Some(&bare_identity()),
            &["openid".to_string(), "email".to_string()],
            &[],
            None,
            Some(&profile),
            &[],
            false,
            false,
            &en(),
        );
        assert!(v.get("preferred_username").is_none());
        assert!(v.get("updated_at").is_none());
    }

    #[test]
    fn locale_claim_absent_without_profile_scope() {
        // identity with preferred_language set, but profile not granted
        let mut traits = serde_json::Map::new();
        traits.insert("preferred_language".to_string(), serde_json::json!("de"));
        let identity = ory::Identity {
            id: "id".to_string(),
            traits: Some(serde_json::Value::Object(traits)),
            ..ory::Identity::new(
                "id".to_string(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
        };
        let v = build_id_token_claims(
            Some(&identity),
            &["openid".to_string(), "email".to_string()],
            &[],
            None,
            None,
            &[],
            false,
            false,
            &en(),
        );
        assert!(v.get("locale").is_none());
    }

    #[test]
    fn locale_claim_from_preferred_language_trait() {
        // preferred_language="de" wins over consent_locale="en"
        let mut traits = serde_json::Map::new();
        traits.insert("email".to_string(), serde_json::json!("x@example.com"));
        traits.insert("preferred_language".to_string(), serde_json::json!("de"));
        let identity = ory::Identity {
            id: "id".to_string(),
            traits: Some(serde_json::Value::Object(traits)),
            ..ory::Identity::new(
                "id".to_string(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
        };
        let v = build_id_token_claims(
            Some(&identity),
            &["openid".to_string(), "profile".to_string()],
            &[],
            None,
            None,
            &[],
            false,
            false,
            &en(),
        );
        assert_eq!(v.get("locale").unwrap().as_str().unwrap(), "de");
    }

    #[test]
    fn locale_claim_falls_back_to_consent_locale() {
        // no preferred_language trait; consent_locale="de" is used
        let mut traits = serde_json::Map::new();
        traits.insert("email".to_string(), serde_json::json!("x@example.com"));
        let identity = ory::Identity {
            id: "id".to_string(),
            traits: Some(serde_json::Value::Object(traits)),
            ..ory::Identity::new(
                "id".to_string(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
        };
        let v = build_id_token_claims(
            Some(&identity),
            &["openid".to_string(), "profile".to_string()],
            &[],
            None,
            None,
            &[],
            false,
            false,
            &de(),
        );
        assert_eq!(v.get("locale").unwrap().as_str().unwrap(), "de");
    }

    #[test]
    fn locale_claim_unsupported_trait_falls_back_to_consent_locale() {
        // preferred_language="ja" is not supported; consent_locale="de" is used
        let mut traits = serde_json::Map::new();
        traits.insert("preferred_language".to_string(), serde_json::json!("ja"));
        let identity = ory::Identity {
            id: "id".to_string(),
            traits: Some(serde_json::Value::Object(traits)),
            ..ory::Identity::new(
                "id".to_string(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
        };
        let v = build_id_token_claims(
            Some(&identity),
            &["profile".to_string()],
            &[],
            None,
            None,
            &[],
            false,
            false,
            &de(),
        );
        assert_eq!(v.get("locale").unwrap().as_str().unwrap(), "de");
    }
}
