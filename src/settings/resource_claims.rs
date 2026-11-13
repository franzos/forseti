//! `/settings/resource-claims`: link the value of a self-service resource
//! claim by signing in at the row's upstream issuer. The verified value lands
//! in `metadata_admin`, which consent copies into access tokens.

use askama::Template;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::audit::{self, AuditCtx, AuditEvent, action, target_kind};
use crate::backend::IdentityBackend;
use crate::claim_template;
use crate::csrf::{CsrfForm, NoPayload};
use crate::extractors::{OptionalSession, RequireSession};
use crate::flash;
use crate::locale::LanguageIdentifier;
use crate::oidc_rp;
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::render::render;
use crate::render_error_boundary;
use crate::resource_registry::{self, Row, SelfService};
use crate::signed_cookie::{SignedCookie, unix_seconds_now};
use crate::state::AppState;

const PAGE: &str = "/settings/resource-claims";

/// Link starts per identity, on top of the per-IP limit on the route.
static START_QUOTA: std::sync::LazyLock<crate::rate_limit::KeyedQuota> =
    std::sync::LazyLock::new(|| {
        crate::rate_limit::KeyedQuota::new(std::time::Duration::from_secs(600), 10)
    });

/// What one link round trip is bound to. The PKCE verifier and nonce are
/// derived from `state`, so nothing here is secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkState {
    #[serde(rename = "s")]
    pub(crate) state: String,
    #[serde(rename = "i")]
    pub(crate) identity_id: String,
    #[serde(rename = "r")]
    pub(crate) row_id: i64,
    /// The submitted value; empty when the template has no `{uuid}`.
    #[serde(rename = "v")]
    pub(crate) value: String,
}

// The callback is a top-level GET from the issuer, which `SameSite=Lax` lets through.
fn link_cookie(secure: bool) -> SignedCookie<'static> {
    SignedCookie {
        name: "forseti_claim_link",
        salt: b"forseti::resource_claim_link::v1",
        ttl_secs: 600,
        secure,
        path: PAGE,
    }
}

/// `Set-Cookie` value carrying `link`.
pub(crate) fn encode_link(secret: &[u8], secure: bool, link: &LinkState, now: u64) -> String {
    let codec = link_cookie(secure);
    // Serializing a struct of strings and an integer cannot fail.
    let payload = serde_json::to_vec(link).unwrap_or_default();
    codec.set_header(&codec.encode(secret, &payload, now))
}

/// The verified link state from the request's cookie, if any.
pub(crate) fn decode_link(
    secret: &[u8],
    secure: bool,
    headers: &HeaderMap,
    now: u64,
) -> Option<LinkState> {
    link_cookie(secure)
        .decode(secret, headers, now)
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// `Set-Cookie` value that clears the link cookie.
pub(crate) fn clear_link(secure: bool) -> String {
    link_cookie(secure).clear_header()
}

/// The single redirect URI registered at every upstream app.
pub(crate) fn redirect_uri(self_url: &str) -> String {
    format!("{}{PAGE}/callback", self_url.trim_end_matches('/'))
}

pub(crate) struct ResourceClaimView {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) resource: String,
    pub(crate) claim: String,
    /// The value template, shown as the input placeholder.
    pub(crate) template: String,
    pub(crate) needs_value: bool,
    pub(crate) has_value: bool,
}

#[derive(Template)]
#[template(path = "settings_resource_claims.html")]
pub(crate) struct SettingsResourceClaimsTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) rows: Vec<ResourceClaimView>,
    pub(crate) flash: String,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

/// Enabled self-service rows `identity_id` may see.
async fn visible_rows(state: &AppState, identity_id: &str) -> anyhow::Result<Vec<Row>> {
    let rows = resource_registry::list_self_service(&state.db).await?;
    resource_registry::visible_to(&state.db, identity_id, rows).await
}

pub(crate) async fn settings_resource_claims(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
) -> Response {
    let unavailable = || {
        render_error_boundary(
            &state,
            &locale,
            &crate::i18n::lookup(&locale, "error-boundary-settings-title"),
            &crate::i18n::lookup(&locale, "error-boundary-auth-unavailable-body"),
            "/settings",
            crate::i18n::lookup(&locale, "error-boundary-cta-back-to-settings"),
        )
        .into_response()
    };

    let rows = match visible_rows(&state, &sess.identity_id).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "resource claims: registry lookup failed");
            return unavailable();
        }
    };
    let identity = if rows.is_empty() {
        None
    } else {
        match state.identity.admin_get_identity(&sess.identity_id).await {
            Ok(identity) => Some(identity),
            Err(e) => {
                tracing::error!(error = ?e, "resource claims: identity lookup failed");
                return unavailable();
            }
        }
    };

    let mut issuers = Vec::new();
    let mut views = Vec::new();
    for row in rows {
        let Some(ss) = row.self_service() else {
            continue;
        };
        let template = match claim_template::Template::parse(&ss.template) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(resource = %row.resource, error = e, "resource claims: bad template");
                continue;
            }
        };
        let has_value = identity
            .as_ref()
            .is_some_and(|i| i.metadata_admin_has_key(&ss.claim));
        issuers.push(ss.issuer);
        views.push(ResourceClaimView {
            id: row.id,
            name: if row.display_name.is_empty() {
                row.resource.clone()
            } else {
                row.display_name
            },
            resource: row.resource,
            claim: ss.claim,
            template: ss.template,
            needs_value: template.has_uuid(),
            has_value,
        });
    }

    let (flash_msg, clear_flash) = state.take_flash(&headers, PAGE);
    let mut resp = render(&SettingsResourceClaimsTemplate {
        chrome: themed.chrome,
        rows: views,
        flash: flash_msg,
        referrer_banner: banner.0,
    });
    // Start POSTs 303 to the issuer, which `form-action` checks too.
    crate::app::allow_form_action_to(&mut resp, &issuers);
    flash::attach_set_cookie(resp, clear_flash)
}

/// The row `id` if it is enabled, has self-service configured and is visible
/// to `identity_id`. Every refusal looks the same to the caller.
async fn usable_row(state: &AppState, identity_id: &str, id: i64) -> Option<(Row, SelfService)> {
    let row = match resource_registry::get(&state.db, id).await {
        Ok(Some(row)) if row.enabled => row,
        Ok(_) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "resource claims: registry lookup failed");
            return None;
        }
    };
    let ss = row.self_service()?;
    match resource_registry::visible_to(&state.db, identity_id, vec![row]).await {
        Ok(mut rows) => rows.pop().map(|row| (row, ss)),
        Err(e) => {
            tracing::error!(error = ?e, "resource claims: visibility lookup failed");
            None
        }
    }
}

/// Who and what a link attempt concerns, for its audit rows.
#[derive(Default)]
struct Attempt {
    /// The signed-in identity, else the link cookie's.
    identity_id: String,
    /// `(id, email)` of the signed-in identity.
    actor: Option<(String, String)>,
    row_id: Option<i64>,
    resource: String,
    claim: String,
    upstream_sub: String,
}

impl Attempt {
    fn signed_in(identity_id: &str, email: &str, row_id: Option<i64>) -> Self {
        Self {
            identity_id: identity_id.to_string(),
            actor: Some((identity_id.to_string(), email.to_string())),
            row_id,
            ..Self::default()
        }
    }

    fn set_row(&mut self, row: &Row, ss: &SelfService) {
        self.row_id = Some(row.id);
        self.resource.clone_from(&row.resource);
        self.claim.clone_from(&ss.claim);
    }

    /// The audit event for this attempt; `failure` marks it failed with
    /// that reason.
    fn event(
        &self,
        action: &'static str,
        actx: &AuditCtx,
        failure: Option<&'static str>,
    ) -> AuditEvent {
        let mut pairs = vec![
            ("resource_id", serde_json::json!(self.row_id)),
            ("resource", serde_json::json!(self.resource)),
            ("claim", serde_json::json!(self.claim)),
        ];
        if !self.upstream_sub.is_empty() {
            pairs.push(("upstream_sub", serde_json::json!(self.upstream_sub)));
        }
        if let Some(reason) = failure {
            pairs.push(("reason", serde_json::json!(reason)));
        }
        let mut ev = AuditEvent::new(action)
            .with_ctx(actx)
            .metadata(audit::SafeMetadata::from_pairs(&pairs));
        if let Some(reason) = failure {
            ev = ev.failed(reason);
        }
        if let Some((id, email)) = &self.actor {
            ev = ev.actor_user(id, email);
        }
        if !self.identity_id.is_empty() {
            ev = ev.target(target_kind::IDENTITY, self.identity_id.clone());
        }
        ev
    }
}

/// Audit a failed link and flash `flash_key` on the list page.
async fn link_failed(
    state: &AppState,
    actx: &AuditCtx,
    locale: &LanguageIdentifier,
    attempt: &Attempt,
    reason: &'static str,
    flash_key: &str,
) -> Response {
    let ev = attempt.event(action::RESOURCE_CLAIM_LINK_FAILED, actx, Some(reason));
    let _ = audit::log(&state.db, ev).await;
    state.flash_redirect(PAGE, &crate::i18n::lookup(locale, flash_key))
}

#[derive(Debug, Deserialize)]
pub(crate) struct StartForm {
    #[serde(default)]
    pub(crate) value: String,
}

/// Bind a fresh `state` to this identity, row and value in the link cookie
/// and send the browser to the issuer's authorization endpoint.
pub(crate) async fn settings_resource_claims_start(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    sess: RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<StartForm>,
) -> Response {
    let mut attempt = Attempt::signed_in(&sess.identity_id, &sess.email, Some(id));
    let fail = |attempt: Attempt, reason, flash_key| {
        let (state, actx, locale) = (&state, &actx, &locale);
        async move { link_failed(state, actx, locale, &attempt, reason, flash_key).await }
    };
    if !START_QUOTA.admit(&sess.identity_id) {
        return fail(attempt, "rate_limited", "flash-claim-rate-limited").await;
    }
    let Some((row, ss)) = usable_row(&state, &sess.identity_id, id).await else {
        return fail(attempt, "not_available", "flash-claim-not-available").await;
    };
    attempt.set_row(&row, &ss);
    let Ok(template) = claim_template::Template::parse(&ss.template) else {
        return fail(attempt, "template_invalid", "flash-claim-not-available").await;
    };
    let value = if template.has_uuid() {
        let value = form.value.trim();
        if template.matches(value).is_none() {
            return fail(attempt, "invalid_value", "flash-claim-invalid-value").await;
        }
        value.to_string()
    } else {
        String::new()
    };

    let allow_private = state.cfg.oauth.cimd.allow_private_targets;
    let provider = match oidc_rp::discovery::discover(&ss.issuer, allow_private).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(resource = %row.resource, error = e, "resource claims: discovery failed");
            return fail(
                attempt,
                "discovery_failed",
                "flash-claim-issuer-unreachable",
            )
            .await;
        }
    };

    let link = LinkState {
        state: oidc_rp::random_urlsafe(32),
        identity_id: sess.identity_id.clone(),
        row_id: row.id,
        value,
    };
    let key = oidc_rp::link_key(&state.cookie_secret);
    let pkce = oidc_rp::derive_pkce(&key, &link.state);
    let url = oidc_rp::authorize_url(
        &provider.authorization_endpoint,
        &ss.client_id,
        &redirect_uri(&state.cfg.self_.url),
        &link.state,
        &oidc_rp::derive_nonce(&key, &link.state),
        &pkce.challenge,
    );
    let cookie = encode_link(
        &state.cookie_secret,
        state.cfg.self_.is_https(),
        &link,
        unix_seconds_now(),
    );
    let mut resp = Redirect::to(url.as_str()).into_response();
    crate::web::append_set_cookie(&mut resp, Some(cookie));
    resp
}

/// Query of the issuer's redirect back. `error_description` is never read.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CallbackQuery {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
    /// RFC 9207 issuer identification.
    #[serde(default)]
    iss: Option<String>,
}

/// The issuer's redirect back. Every outcome clears the link cookie.
pub(crate) async fn settings_resource_claims_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    session: OptionalSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
    let secure = state.cfg.self_.is_https();
    let link = decode_link(&state.cookie_secret, secure, &headers, unix_seconds_now());
    let query = query.map(|Query(q)| q).unwrap_or_default();
    let mut resp = finish_link(&state, session, &actx, &locale, link, query).await;
    crate::web::append_set_cookie(&mut resp, Some(clear_link(secure)));
    resp
}

/// Verify the upstream sign-in against the link cookie and the row as it is
/// now, then write the rendered value.
async fn finish_link(
    state: &AppState,
    session: OptionalSession,
    actx: &AuditCtx,
    locale: &LanguageIdentifier,
    link: Option<LinkState>,
    query: CallbackQuery,
) -> Response {
    let fail = |attempt: Attempt, reason, flash_key| async move {
        link_failed(state, actx, locale, &attempt, reason, flash_key).await
    };
    // Only a verified cookie earns an audit row, so anonymous loops can't flood the log.
    let Some(link) = link else {
        tracing::info!(
            reason = "link_missing",
            "resource claims: callback without a valid link cookie"
        );
        return state.flash_redirect(
            PAGE,
            &crate::i18n::lookup(locale, "flash-claim-start-again"),
        );
    };
    // No bounce through login: the code would sit in the return URL.
    let OptionalSession::Ok {
        identity_id, email, ..
    } = session
    else {
        let attempt = Attempt {
            identity_id: link.identity_id,
            row_id: Some(link.row_id),
            ..Attempt::default()
        };
        return fail(attempt, "no_session", "flash-claim-start-again").await;
    };
    let mut attempt = Attempt::signed_in(&identity_id, &email, None);
    attempt.row_id = Some(link.row_id);
    let state_ok = query
        .state
        .as_deref()
        .is_some_and(|s| bool::from(s.as_bytes().ct_eq(link.state.as_bytes())));
    if !state_ok {
        return fail(attempt, "state_mismatch", "flash-claim-start-again").await;
    }
    if link.identity_id != identity_id {
        return fail(attempt, "identity_mismatch", "flash-claim-start-again").await;
    }
    if query.error.is_some() {
        return fail(attempt, "upstream_error", "flash-claim-failed").await;
    }
    let Some(code) = query.code.filter(|c| !c.is_empty()) else {
        return fail(attempt, "code_missing", "flash-claim-failed").await;
    };

    // One read supplies the claim, issuer, client id and template.
    let Some((row, ss)) = usable_row(state, &identity_id, link.row_id).await else {
        return fail(attempt, "not_available", "flash-claim-not-available").await;
    };
    attempt.set_row(&row, &ss);
    let Ok(template) = claim_template::Template::parse(&ss.template) else {
        return fail(attempt, "template_invalid", "flash-claim-not-available").await;
    };
    let uuid = match (template.has_uuid(), template.matches(&link.value)) {
        (true, Some(Some(uuid))) => Some(uuid),
        (false, _) if link.value.is_empty() => None,
        _ => return fail(attempt, "invalid_value", "flash-claim-failed").await,
    };

    let allow_private = state.cfg.oauth.cimd.allow_private_targets;
    let provider = match oidc_rp::discovery::discover(&ss.issuer, allow_private).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(resource = %row.resource, error = e, "resource claims: discovery failed");
            return fail(
                attempt,
                "discovery_failed",
                "flash-claim-issuer-unreachable",
            )
            .await;
        }
    };
    if query
        .iss
        .as_ref()
        .is_some_and(|iss| *iss != provider.issuer)
    {
        return fail(attempt, "issuer_mismatch", "flash-claim-failed").await;
    }
    let key = oidc_rp::link_key(&state.cookie_secret);
    let pkce = oidc_rp::derive_pkce(&key, &link.state);
    let id_token = match oidc_rp::discovery::exchange_code(
        &provider,
        &ss.client_id,
        &redirect_uri(&state.cfg.self_.url),
        &code,
        &pkce.verifier,
        allow_private,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(resource = %row.resource, error = e, "resource claims: code exchange failed");
            return fail(attempt, "exchange_failed", "flash-claim-failed").await;
        }
    };
    let jwks = match oidc_rp::discovery::fetch_jwks(&provider.jwks_uri, allow_private).await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(resource = %row.resource, error = e, "resource claims: JWKS fetch failed");
            return fail(attempt, "jwks_failed", "flash-claim-failed").await;
        }
    };
    let now = i64::try_from(unix_seconds_now()).unwrap_or(i64::MAX);
    let nonce = oidc_rp::derive_nonce(&key, &link.state);
    let sub = match oidc_rp::id_token::verify(
        &id_token,
        &jwks,
        &provider.issuer,
        &ss.client_id,
        &nonce,
        now,
    ) {
        Ok(sub) => sub,
        Err(e) => {
            tracing::warn!(resource = %row.resource, error = e, "resource claims: ID token rejected");
            return fail(attempt, "id_token_invalid", "flash-claim-failed").await;
        }
    };
    attempt.upstream_sub.clone_from(&sub);

    let Ok(value) = template.render(&sub, uuid) else {
        return fail(attempt, "sub_unrenderable", "flash-claim-failed").await;
    };
    if template.has_uuid() && value != link.value {
        return fail(attempt, "value_mismatch", "flash-claim-mismatch").await;
    }
    if let Err(e) = state
        .identity
        .admin_set_metadata_admin_key(&identity_id, &ss.claim, &value)
        .await
    {
        tracing::error!(error = ?e, "resource claims: metadata_admin write failed");
        return fail(attempt, "write_failed", "flash-claim-failed").await;
    }
    let _ = audit::log(
        &state.db,
        attempt
            .event(action::RESOURCE_CLAIM_LINKED, actx, None)
            .critical(),
    )
    .await;
    state.flash_redirect(PAGE, &crate::i18n::lookup(locale, "flash-claim-linked"))
}

/// Drop the identity's value for row `id`'s self-service claim.
pub(crate) async fn settings_resource_claims_remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    sess: RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    _: CsrfForm<NoPayload>,
) -> Response {
    let flash = |key: &str| state.flash_redirect(PAGE, &crate::i18n::lookup(&locale, key));
    let Some((row, ss)) = usable_row(&state, &sess.identity_id, id).await else {
        return flash("flash-claim-not-available");
    };
    match state
        .identity
        .admin_remove_metadata_admin_key(&sess.identity_id, &ss.claim)
        .await
    {
        Ok(true) => {
            let mut attempt = Attempt::signed_in(&sess.identity_id, &sess.email, None);
            attempt.set_row(&row, &ss);
            let _ = audit::log(
                &state.db,
                attempt
                    .event(action::RESOURCE_CLAIM_REMOVED, &actx, None)
                    .critical(),
            )
            .await;
            flash("flash-claim-removed")
        }
        Ok(false) => flash("flash-claim-nothing-to-remove"),
        Err(e) => {
            tracing::error!(error = ?e, "resource claims: metadata_admin remove failed");
            flash("flash-claim-remove-failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    fn link() -> LinkState {
        LinkState {
            state: "st".to_string(),
            identity_id: "id-1".to_string(),
            row_id: 7,
            value: "u:42:0b6f7d3c-1a2b-4c3d-8e9f-0a1b2c3d4e5f".to_string(),
        }
    }

    fn request_with(set_cookie: &str) -> HeaderMap {
        let pair = set_cookie.split(';').next().expect("name=value");
        let mut h = HeaderMap::new();
        h.insert(COOKIE, pair.parse().expect("header value"));
        h
    }

    #[test]
    fn link_cookie_round_trips() {
        let set = encode_link(b"secret", true, &link(), 1_000);
        assert!(set.starts_with("forseti_claim_link="), "{set}");
        assert!(set.contains("Path=/settings/resource-claims"), "{set}");
        assert!(set.contains("SameSite=Lax"), "{set}");
        assert!(set.contains("HttpOnly") && set.contains("Secure"), "{set}");
        let h = request_with(&set);
        assert_eq!(decode_link(b"secret", true, &h, 1_599), Some(link()));
    }

    #[test]
    fn link_cookie_rejects_expiry_and_another_key() {
        let h = request_with(&encode_link(b"secret", false, &link(), 1_000));
        assert_eq!(decode_link(b"secret", false, &h, 1_601), None);
        assert_eq!(decode_link(b"other", false, &h, 1_001), None);
    }

    #[test]
    fn redirect_uri_is_fixed_under_the_page() {
        assert_eq!(
            redirect_uri("https://id.example.com/"),
            "https://id.example.com/settings/resource-claims/callback"
        );
    }
}
