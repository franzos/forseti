//! `/oauth/consent` — Hydra's consent challenge handler (GET renders or
//! auto-grants; POST processes the allow/deny decision and folds identity
//! traits into the id_token claims).

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::audit::{self, action, severity, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::extractors::{Csrf, OptionalSession};
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
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthConsentQuery {
    consent_challenge: String,
}

pub(crate) async fn oauth_consent(
    State(state): State<AppState>,
    Query(query): Query<OAuthConsentQuery>,
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
    let verified = if client_id_lookup.is_empty() {
        true
    } else {
        match oauth_client_metadata::get(&state.db, client_id_lookup).await {
            Ok(Some(row)) => row.is_verified(),
            Ok(None) => true,
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
                false
            }
        }
    };

    // Linux-PAM device-auth never auto-skips consent: the host+account
    // binding must be shown, so a stray `skip_consent` or remembered grant
    // must not bypass it. Guard sits above the skip tree.
    let is_pam_client =
        !client_id_lookup.is_empty() && client_id_lookup == state.cfg.posix.pam_client_id;

    // Auto-grant path (remembered consent or trusted client). Verify the
    // active Kratos session matches Hydra's claimed subject first: a crafted
    // consent link tied to one identity could otherwise auto-grant tokens
    // while a different identity is signed in. Mismatch rejects with
    // `access_denied`. Unverified clients never auto-grant.
    if !is_pam_client && verified && (hydra_skip || client_skip_consent) {
        // InsufficientAal means a session exists we couldn't read here;
        // treating it as "no subject" keeps the mismatch check conservative.
        let session_subject = session.identity_id().unwrap_or_default();
        if session_subject != subject || subject.is_empty() {
            tracing::warn!(
                consent_subject = %subject,
                session_subject = %session_subject,
                "rejecting auto-grant: session subject mismatch"
            );
            match ory::hydra::reject_consent_request(
                &state.ory,
                &challenge,
                "access_denied",
                "Consent subject does not match the signed-in identity.",
            )
            .await
            {
                Ok(redirect) => return Redirect::to(&redirect.redirect_to).into_response(),
                Err(e) => {
                    tracing::error!(error = ?e, "hydra reject_consent_request (mismatch) failed");
                    return Redirect::to("/error").into_response();
                }
            }
        }
        return finalize_consent(
            &state,
            &challenge,
            &subject,
            requested_scope,
            requested_audience,
            false,
            &headers,
        )
        .await
        .into_response();
    }

    let client_name = req
        .client
        .as_ref()
        .and_then(|c| c.client_name.clone().filter(|n| !n.is_empty()))
        .or_else(|| req.client.as_ref().and_then(|c| c.client_id.clone()))
        .unwrap_or_else(|| "this application".to_string());

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
                .or_else(|| super::default_scope_description(s).map(str::to_string))
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

    render(&ConsentTemplate {
        chrome: PageChrome::from_parts(&state, subject_email.clone(), csrf.0),
        consent_intro: state.cfg.brand.consent_intro.clone(),
        client_name,
        subject_email,
        challenge,
        scopes,
        verified,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct OAuthConsentForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    consent_challenge: String,
    decision: String,
    /// `Vec` because the field repeats once per granted scope.
    #[serde(default, rename = "grant_scope")]
    grant_scope: Vec<String>,
    remember: Option<String>,
}

pub(crate) async fn oauth_consent_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    actx: AuditCtx,
    Form(form): Form<OAuthConsentForm>,
) -> Response {
    if let Some(resp) = crate::extractors::verify_csrf_or_forbid(&headers, form.csrf.as_deref()) {
        return resp;
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

    let req = match ory::hydra::get_consent_request(&state.ory, &form.consent_challenge).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "hydra get_consent_request failed during accept");
            return Redirect::to("/error").into_response();
        }
    };

    let subject = req.subject.clone().unwrap_or_default();
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
    let grant_scope_for_audit = form.grant_scope.clone();

    let outcome = finalize_consent(
        &state,
        &form.consent_challenge,
        &subject,
        form.grant_scope,
        requested_audience,
        remember,
        &headers,
    )
    .await;

    let redirect = match outcome {
        FinalizeOutcome::Granted { redirect } => redirect,
        FinalizeOutcome::RedirectedToError { redirect } => return redirect,
    };

    let actor_email = lookup_identity_email(&state, &subject).await;
    let mut ev = AuditEvent::new(action::OAUTH_CONSENT_GRANTED)
        .actor_user(&subject, &actor_email)
        .with_ctx(&actx)
        .metadata(audit_metadata!(
            "scope" => grant_scope_for_audit.join(" "),
            "remember" => remember,
        ));
    if !client_id.is_empty() {
        ev = ev.target(target_kind::OAUTH_CLIENT, client_id.clone());
    }
    let _ = audit::log(&state.db, ev).await;

    // Lazy provenance: record the resource URL being granted, if any, when
    // the row doesn't already carry one. First-writer-wins (see
    // `upsert_resource_url_if_missing`). Fires for every client.
    if !client_id.is_empty() {
        if let Some(url) = extract_resource_url(request_url.as_str(), captured_audience.as_slice())
        {
            if let Err(e) =
                oauth_client_metadata::upsert_resource_url_if_missing(&state.db, &client_id, &url)
                    .await
            {
                tracing::error!(
                    error = ?e,
                    client_id = %client_id,
                    "consent: failed to capture resource_url provenance",
                );
            }
        }
    }
    redirect
}

/// Pick a single resource-URL to stamp on
/// `oauth_client_metadata.resource_url`. RFC 8707 clients send
/// `?resource=<url>` on the auth URL (Hydra's `request_url`); others use
/// Hydra's non-standard `audience=`, which falls back to the first
/// `requested_access_token_audience` entry. `None` when neither yields a
/// value. Not normalised or validated: this is "what we observed".
fn extract_resource_url(request_url: &str, requested_audience: &[String]) -> Option<String> {
    // RFC 8707 §2 allows multiple `resource=` values; take the first.
    if !request_url.is_empty() {
        if let Ok(url) = url::Url::parse(request_url) {
            if let Some(resource) = url
                .query_pairs()
                .find(|(k, _)| k == "resource")
                .map(|(_, v)| v.into_owned())
            {
                let trimmed = resource.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    requested_audience
        .iter()
        .map(|s| s.trim())
        .find(|s| !s.is_empty())
        .map(str::to_string)
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
    Granted { redirect: Response },
    RedirectedToError { redirect: Response },
}

impl FinalizeOutcome {
    fn into_response(self) -> Response {
        match self {
            FinalizeOutcome::Granted { redirect } => redirect,
            FinalizeOutcome::RedirectedToError { redirect } => redirect,
        }
    }
}

/// Build the id_token claims from identity traits + granted scopes, then
/// accept the consent challenge. Shared by the auto-grant and Allow paths.
async fn finalize_consent(
    state: &AppState,
    challenge: &str,
    subject: &str,
    grant_scope: Vec<String>,
    grant_audience: Vec<String>,
    remember: bool,
    headers: &axum::http::HeaderMap,
) -> FinalizeOutcome {
    // Fan out identity + org memberships in parallel; the membership fetch
    // is skipped unless the grant scope consumes it.
    let needs_org_claims = grant_scope.iter().any(|s| s == "org" || s == "orgs");
    let identity_fut = ory::kratos::admin_get_identity(&state.ory, subject);
    let (identity_res, memberships) = if needs_org_claims {
        let memberships_fut = crate::orgs::list_memberships_limited(
            &state.db,
            subject,
            crate::orgs::nav::ORGS_CLAIM_CAP as i64,
        );
        let (id_res, mem_res) = tokio::join!(identity_fut, memberships_fut);
        (id_res, mem_res.unwrap_or_default())
    } else {
        (identity_fut.await, Vec::new())
    };
    let identity = match identity_res {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::warn!(error = ?e, subject, "admin_get_identity failed; id_token will be minimal");
            None
        }
    };
    let active = crate::orgs::cookie::read_active_org_cookie(
        headers,
        &state.cookie_secret,
        state.cfg.orgs.active_org_cookie_ttl_seconds,
    )
    .and_then(|id| memberships.iter().find(|m| m.org_id == id).cloned())
    .or_else(|| memberships.first().cloned());

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

    let id_token_session = build_id_token_claims(
        identity.as_ref(),
        &grant_scope,
        &memberships,
        active.as_ref(),
        profile.as_ref(),
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
        },
        Err(e) => {
            tracing::error!(error = ?e, "hydra accept_consent_request failed");
            FinalizeOutcome::RedirectedToError {
                redirect: Redirect::to("/error").into_response(),
            }
        }
    }
}

/// Fold identity traits into id_token claims, scoped by granted scope.
/// `email` adds `email`/`email_verified`; `profile` adds `name`/`picture`/`website`;
/// `extended_profile` adds `bio`/`pronouns`/`links`; `org` adds the active-org
/// object; `orgs` adds the (capped) membership list.
fn build_id_token_claims(
    identity: Option<&ory::Identity>,
    grant_scope: &[String],
    memberships: &[crate::orgs::Membership],
    active_org: Option<&crate::orgs::Membership>,
    profile: Option<&crate::profiles::Profile>,
) -> serde_json::Value {
    let scopes: std::collections::HashSet<&str> = grant_scope.iter().map(String::as_str).collect();
    let mut claims = serde_json::Map::new();

    if scopes.contains("org") {
        if let Some(m) = active_org {
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
                Some(e) => addrs.iter().any(|a| a.value == e && a.verified),
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
        }
    }

    if scopes.contains("extended_profile") {
        if let Some(p) = profile {
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
    }

    serde_json::Value::Object(claims)
}

#[cfg(test)]
mod tests {
    use super::extract_resource_url;

    #[test]
    fn extract_resource_url_picks_rfc8707_resource_param() {
        let request_url =
            "https://hydra.example.com/oauth2/auth?client_id=x&resource=https%3A%2F%2Fapi.example.com";
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
}
