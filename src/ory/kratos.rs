//! Kratos self-service wrappers.

use super::*;
use ory_client::apis::{courier_api, frontend_api, identity_api, metadata_api, Error as OryError};

/// Outcome of a `/sessions/whoami` call.
///
/// Kratos returns 401 ("no session at all") and 403 ("session exists but
/// doesn't satisfy required AAL") for two very different states. The
/// previous version of this wrapper collapsed both into `Ok(None)`, which
/// made every protected handler bounce to `/login` with no step-up hint —
/// /login then saw the existing session and short-circuited back to the
/// protected route, livelocking AAL2-enrolled users. The enum keeps the
/// two cases distinct so callers can route the AAL2-needs-step-up case to
/// `/login?aal=aal2&return_to=...` instead.
#[derive(Clone, Debug)]
pub enum WhoamiOutcome {
    /// No session at all (401). Caller should send the user to /login.
    None,
    /// Session exists but doesn't satisfy the AAL Kratos requires.
    /// Caller should send the user to `/login?aal=aal2&return_to=...`.
    InsufficientAal,
    /// Session is valid and satisfies Kratos's whoami AAL requirement.
    Ok(Box<Session>),
}

/// `true` iff the session's authenticator assurance level is `aal2`.
/// Avoids the `session.authenticator_assurance_level.map(|a|
/// a.to_string()).unwrap_or("aal1") != "aal2"` dance every admin /
/// step-up gate would otherwise re-derive. A missing AAL is treated as
/// AAL1 — failing closed.
pub(crate) fn session_satisfies_aal2(session: &Session) -> bool {
    matches!(
        session.authenticator_assurance_level,
        Some(AuthenticatorAssuranceLevel::Aal2)
    )
}

/// The session's authenticator assurance level as a string, defaulting to
/// `"aal1"` when Kratos omits it — failing closed. Use when the raw string is
/// needed (e.g. comparing against a requested `aal`); prefer
/// [`session_satisfies_aal2`] for a plain AAL2 check.
pub(crate) fn session_aal_string(session: &Session) -> String {
    session
        .authenticator_assurance_level
        .as_ref()
        .map(|aal| aal.to_string())
        .unwrap_or_else(|| "aal1".to_string())
}

/// Resolve the current session via `/sessions/whoami` with the user's
/// forwarded `Cookie` header. See [`WhoamiOutcome`] for the three
/// outcomes; `Err` is reserved for transport / unexpected upstream
/// failures.
pub async fn whoami(clients: &OryClients, cookie: Option<&str>) -> Result<WhoamiOutcome> {
    match frontend_api::to_session(&clients.kratos_public, None, cookie, None).await {
        Ok(session) => Ok(WhoamiOutcome::Ok(Box::new(session))),
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::UNAUTHORIZED => {
            Ok(WhoamiOutcome::None)
        }
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::FORBIDDEN => {
            // 403 = session exists, AAL too low. Kratos's body carries
            // `details.redirect_browser_to` with the right aal= query
            // param but we don't need to parse it — the AAL gate above
            // each protected route already knows what AAL it requires.
            Ok(WhoamiOutcome::InsufficientAal)
        }
        Err(e) => Err(anyhow::anyhow!("kratos whoami failed: {e}")),
    }
}

/// Fetch an existing self-service flow by ID, forwarding the user's cookies
/// (Kratos uses them to validate the flow's continuity cookie). Returns
/// [`FlowFetch::Gone`] for 404/410 so the caller can restart cleanly, and
/// [`FlowFetch::PrivilegedRequired`] for 403 responses carrying
/// `session_refresh_required` / `session_aal2_required` (settings flows).
///
/// We don't use `ory_client::apis::frontend_api::get_*_flow` directly here.
/// The SDK deserializes into the typed flow models, whose `UiNodeAttributes`
/// is `#[serde(tag = "node_type")]`. Serde consumes the discriminator
/// before handing the remainder to the variant struct, but the inner
/// `UiNodeInputAttributes` also declares a required `node_type` field —
/// so deserialization always fails with `missing field 'node_type'` against
/// every real Kratos response. Until that's fixed upstream we fetch raw
/// JSON and let the handler project it into its own view-models.
///
/// See: <https://github.com/ory/sdk/issues/381>
pub async fn get_flow(
    clients: &OryClients,
    kind: FlowKind,
    flow_id: &str,
    cookie: &str,
) -> Result<FlowFetch> {
    let url = format!(
        "{}/self-service/{}/flows",
        clients.kratos_public.base_path.trim_end_matches('/'),
        kind.path_segment(),
    );
    let mut req = clients
        .kratos_public
        .client
        .get(&url)
        .query(&[("id", flow_id)]);
    if !cookie.is_empty() {
        req = req.header(reqwest::header::COOKIE, cookie);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_flow transport error: {e}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Ok(FlowFetch::Gone);
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        // 403 may carry `session_refresh_required` / `session_aal2_required`
        // on settings flows; parse the `error.id` here so handlers can
        // branch on the typed reason without touching JSON. Non-settings
        // flows collapse to Gone (same effect as a stale flow).
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if matches!(kind, FlowKind::Settings) {
            let reason_id = body
                .pointer("/error/id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reason = if reason_id == "session_aal2_required" {
                PrivilegedReason::Aal2Required
            } else {
                // `session_refresh_required` is the default; an unknown
                // id falls into the same bucket — refresh is the safer
                // catch-all for "session no longer sufficient".
                PrivilegedReason::SessionRefresh
            };
            return Ok(FlowFetch::PrivilegedRequired(reason));
        }
        return Ok(FlowFetch::Gone);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "kratos get_flow ({}) returned {status}: {body}",
            kind.path_segment()
        ));
    }

    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_flow body decode failed: {e}"))?;
    Ok(FlowFetch::Ok(Box::new(value)))
}

/// Build the URL the browser should be redirected to in order to start a new
/// Kratos browser flow of the given `kind`. Kratos will create the flow,
/// set its continuity cookie, and 303-redirect back to Forseti's UI URL
/// with `?flow=<id>`.
///
/// `return_to` is forwarded so a successful completion lands on the
/// originally requested page. `aal` / `refresh` are only meaningful on
/// login flows; passing them on other kinds is harmless (Kratos ignores
/// unknown query params) but typically not desired.
pub fn browser_init_url(kind: FlowKind, public_url: &str, return_to: Option<&str>) -> String {
    browser_init_url_with(kind, public_url, return_to, None, None)
}

/// Like [`browser_init_url`] but with optional `aal` and `refresh` query
/// parameters. Used by the `/login` handler to forward AAL step-up
/// (`aal=aal2`) and privileged-session refresh (`refresh=true`) requests
/// through to Kratos.
pub fn browser_init_url_with(
    kind: FlowKind,
    public_url: &str,
    return_to: Option<&str>,
    aal: Option<&str>,
    refresh: Option<bool>,
) -> String {
    let base = public_url.trim_end_matches('/');
    let segment = kind.path_segment();
    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(rt) = return_to {
        if !rt.is_empty() {
            params.push(("return_to", rt.to_string()));
        }
    }
    if let Some(a) = aal {
        if !a.is_empty() {
            params.push(("aal", a.to_string()));
        }
    }
    if matches!(refresh, Some(true)) {
        params.push(("refresh", "true".to_string()));
    }
    if params.is_empty() {
        return format!("{base}/self-service/{segment}/browser");
    }
    let qs: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, ory_client::apis::urlencode(v)))
        .collect();
    format!("{base}/self-service/{segment}/browser?{}", qs.join("&"))
}

/// Fetch the JSON body for a Kratos self-service error (e.g. `flows.error.ui_url`
/// redirects users to `/error?id=<error_id>`). Returns the raw JSON so the
/// view can pull `error.code` / `error.message` without coupling to a
/// potentially-broken SDK model.
pub async fn get_self_service_error(
    clients: &OryClients,
    error_id: &str,
) -> Result<Option<serde_json::Value>> {
    let url = format!(
        "{}/self-service/errors",
        clients.kratos_public.base_path.trim_end_matches('/'),
    );
    let resp = clients
        .kratos_public
        .client
        .get(&url)
        .query(&[("id", error_id)])
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_self_service_error transport error: {e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Ok(None);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "kratos get_self_service_error returned {status}: {body}"
        ));
    }
    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_self_service_error decode failed: {e}"))?;
    Ok(Some(value))
}

/// Admin lookup by identity ID. Hits the Kratos admin API which returns
/// the typed `Identity` model — no `ui.nodes` involved, so the SDK
/// deserializer works fine here.
pub async fn admin_get_identity(clients: &OryClients, id: &str) -> Result<Identity> {
    identity_api::get_identity(&clients.kratos_admin, id, None)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin get_identity failed: {e}"))
}

/// Like [`admin_get_identity`] but maps a typed 404 to `Ok(None)` instead
/// of an error. Used by the webhook reconciler so transport failures
/// can't be mistaken for "identity gone" via stringified-error matching.
pub async fn admin_get_identity_optional(
    clients: &OryClients,
    id: &str,
) -> Result<Option<Identity>> {
    match identity_api::get_identity(&clients.kratos_admin, id, None).await {
        Ok(identity) => Ok(Some(identity)),
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::NOT_FOUND => {
            Ok(None)
        }
        Err(e) => Err(anyhow::anyhow!("kratos admin get_identity failed: {e}")),
    }
}

/// Build the public-API logout-initiation URL. Hitting this with the
/// user's cookies returns a `LogoutFlow` whose `logout_url` includes the
/// `logout_token`. Following that URL destroys the session and 303s the
/// browser to `selfservice.flows.logout.after.default_browser_return_url`
/// (i.e. `/login`).
pub fn logout_browser_url(public_url: &str) -> String {
    format!(
        "{}/self-service/logout/browser",
        public_url.trim_end_matches('/')
    )
}

/// List the current identity's active sessions, as seen by Kratos. Uses
/// the public API with the user's forwarded cookie so Kratos resolves
/// the caller from their session — no admin credentials required. The
/// `Session` model has no `ui.nodes`, so the typed SDK call works here.
pub async fn list_my_sessions(clients: &OryClients, cookie: Option<&str>) -> Result<Vec<Session>> {
    frontend_api::list_my_sessions(&clients.kratos_public, None, None, None, None, None, cookie)
        .await
        .map_err(|e| anyhow::anyhow!("kratos list_my_sessions failed: {e}"))
}

/// Revoke a single session by ID. Kratos refuses to delete the *current*
/// session via this endpoint (it returns 400) — callers should treat the
/// current session row as non-revokable in the UI.
pub async fn revoke_session(clients: &OryClients, id: &str, cookie: Option<&str>) -> Result<()> {
    frontend_api::disable_my_session(&clients.kratos_public, id, None, cookie)
        .await
        .map_err(|e| anyhow::anyhow!("kratos disable_my_session failed: {e}"))
}

/// Revoke every session except the one currently making the request.
/// Kratos enforces "except current" itself. Returns the deletion count
/// from Kratos (kept loosely-typed as it's just an informational return).
pub async fn revoke_other_sessions(clients: &OryClients, cookie: Option<&str>) -> Result<u64> {
    let count = frontend_api::disable_my_other_sessions(&clients.kratos_public, None, cookie)
        .await
        .map_err(|e| anyhow::anyhow!("kratos disable_my_other_sessions failed: {e}"))?;
    Ok(count.count.unwrap_or(0).max(0) as u64)
}

/// Admin-API lookup of an identity's session history. Used by the
/// dashboard's "Recent Activity" sidebar as a stand-in for a real audit
/// log (Kratos doesn't expose a queryable event stream in this version).
pub async fn list_identity_sessions(
    clients: &OryClients,
    identity_id: &str,
) -> Result<Vec<Session>> {
    identity_api::list_identity_sessions(
        &clients.kratos_admin,
        identity_id,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin list_identity_sessions failed: {e}"))
}

// --- Admin surface ---------------------------------------------------

/// Paginated identity list via the Kratos admin API. `page_size` clamps
/// at Kratos's own ceiling (500); `page_token` comes from the previous
/// page's `Link: <...>; rel="next"` header — we don't surface paging
/// headers in the SDK return, so for now the admin UI paginates with
/// `?page=N` token-style and Kratos handles ordering.
pub async fn list_identities(
    clients: &OryClients,
    page_size: i64,
    page_token: Option<&str>,
    credentials_identifier: Option<&str>,
) -> Result<Vec<Identity>> {
    identity_api::list_identities(
        &clients.kratos_admin,
        None,
        None,
        Some(page_size),
        page_token,
        None,
        None,
        credentials_identifier,
        None,
        None,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin list_identities failed: {e}"))
}

/// Bulk admin-API lookup. Uses the upstream `ids` query parameter so N
/// identities resolve in one round-trip rather than N. Returns identities
/// in whatever order Kratos chose; callers that need a specific order
/// should sort after the fact.
pub async fn admin_list_identities_by_ids(
    clients: &OryClients,
    ids: Vec<String>,
) -> Result<Vec<Identity>> {
    admin_list_identities_by_ids_inner(clients, ids, None).await
}

/// Like [`admin_list_identities_by_ids`] but asks Kratos to include
/// credential metadata in each row (mirrors [`admin_get_identity_full`]).
pub async fn admin_list_identities_by_ids_full(
    clients: &OryClients,
    ids: Vec<String>,
) -> Result<Vec<Identity>> {
    admin_list_identities_by_ids_inner(
        clients,
        ids,
        Some(vec![
            "password".to_string(),
            "totp".to_string(),
            "webauthn".to_string(),
            "lookup_secret".to_string(),
            "oidc".to_string(),
        ]),
    )
    .await
}

async fn admin_list_identities_by_ids_inner(
    clients: &OryClients,
    ids: Vec<String>,
    include_credential: Option<Vec<String>>,
) -> Result<Vec<Identity>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let per_page = ids.len() as i64;
    identity_api::list_identities(
        &clients.kratos_admin,
        Some(per_page),
        None,
        None,
        None,
        None,
        Some(ids),
        None,
        None,
        include_credential,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin list_identities by ids failed: {e}"))
}

/// Like [`admin_get_identity`] but asks Kratos to include the identity's
/// credentials in the response (passwords are still hashed/redacted —
/// this surfaces which methods are configured, not the secrets).
pub async fn admin_get_identity_full(clients: &OryClients, id: &str) -> Result<Identity> {
    identity_api::get_identity(
        &clients.kratos_admin,
        id,
        Some(vec![
            "password".to_string(),
            "totp".to_string(),
            "webauthn".to_string(),
            "lookup_secret".to_string(),
            "oidc".to_string(),
        ]),
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin get_identity_full failed: {e}"))
}

/// Set an identity's state (`active` / `inactive`). Update goes through
/// `update_identity` since Kratos has no dedicated state-toggle endpoint;
/// we round-trip the existing schema_id + traits to avoid clobbering
/// other fields.
pub async fn admin_update_identity_state(
    clients: &OryClients,
    id: &str,
    state: ory_client::models::update_identity_body::StateEnum,
) -> Result<Identity> {
    let current = admin_get_identity(clients, id).await?;
    let traits = current.traits.unwrap_or(serde_json::Value::Null);
    let body = UpdateIdentityBody {
        credentials: None,
        external_id: None,
        metadata_admin: None,
        metadata_public: None,
        region: None,
        schema_id: current.schema_id,
        state,
        traits,
    };
    identity_api::update_identity(&clients.kratos_admin, id, Some(body))
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin update_identity (state) failed: {e}"))
}

/// Permanently delete an identity. Cascades to sessions and verifiable
/// addresses on the Kratos side.
pub async fn admin_delete_identity(clients: &OryClients, id: &str) -> Result<()> {
    identity_api::delete_identity(&clients.kratos_admin, id)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin delete_identity failed: {e}"))
}

/// List the ids of every identity schema registered with Kratos. The admin
/// configuration page surfaces these so operators can see which schemas
/// drive registration / profile shape. Paging args are all `None` — Kratos
/// returns the full set in one page for any realistic deployment.
pub async fn list_identity_schemas(clients: &OryClients) -> Result<Vec<String>> {
    let schemas =
        identity_api::list_identity_schemas(&clients.kratos_admin, None, None, None, None)
            .await
            .map_err(|e| anyhow::anyhow!("kratos list_identity_schemas failed: {e}"))?;
    Ok(schemas.into_iter().map(|s| s.id).collect())
}

/// Generate a one-shot recovery code for an identity. Returns the plaintext
/// code + a recovery link; admin UI shows both once and the operator hands
/// the code to the user out-of-band.
pub async fn admin_create_recovery_code(
    clients: &OryClients,
    identity_id: &str,
) -> Result<RecoveryCodeForIdentity> {
    let body = CreateRecoveryCodeForIdentityBody::new(identity_id.to_string());
    identity_api::create_recovery_code_for_identity(&clients.kratos_admin, Some(body))
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin create_recovery_code failed: {e}"))
}

/// Mint a one-shot magic recovery link for an identity. Unlike the code
/// variant, the link is a Kratos *public* URL — a browser GET redeems it
/// directly: Kratos validates the token, issues a privileged session
/// (cookie set natively), and redirects to `return_to`. This is the only
/// OSS path from "server-side authenticated" (e.g. a validated SAML
/// assertion) to a real browser session.
pub async fn admin_create_recovery_link(
    clients: &OryClients,
    identity_id: &str,
    expires_in: &str,
    return_to: Option<&str>,
) -> Result<String> {
    let mut body = CreateRecoveryLinkForIdentityBody::new(identity_id.to_string());
    body.expires_in = Some(expires_in.to_string());
    let link = identity_api::create_recovery_link_for_identity(
        &clients.kratos_admin,
        return_to,
        Some(body),
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin create_recovery_link failed: {e}"))?;
    Ok(link.recovery_link)
}

/// JIT-provision an identity with a pre-verified email (SAML SSO: the
/// corporate IdP asserted the address, so re-verification is pointless).
/// Returns `Ok(None)` on 409 — the email already belongs to another
/// identity — so the SSO callback can render a block page instead of a 500.
pub async fn admin_create_identity_verified(
    clients: &OryClients,
    schema_id: &str,
    email: &str,
    first: &str,
    last: &str,
) -> Result<Option<Identity>> {
    let traits = serde_json::json!({
        "email": email,
        "name": { "first": first, "last": last },
    });
    let mut body = CreateIdentityBody::new(schema_id.to_string(), traits);
    let addr = VerifiableIdentityAddress::new(
        "completed".to_string(),
        email.to_string(),
        true,
        ory_client::models::verifiable_identity_address::ViaEnum::Email,
    );
    body.verifiable_addresses = Some(vec![addr]);
    match identity_api::create_identity(&clients.kratos_admin, Some(body)).await {
        Ok(identity) => Ok(Some(identity)),
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::CONFLICT => {
            Ok(None)
        }
        Err(e) => Err(anyhow::anyhow!("kratos admin create_identity failed: {e}")),
    }
}

/// Find an identity whose verifiable addresses include `email`, returning
/// it together with whether that address is verified. Uses the
/// `credentials_identifier` filter (matches password/oidc/code identifiers) —
/// good enough for the link-on-first-SSO-login path; SAML-created
/// identities are found via Forseti's `saml_links` table instead.
pub async fn admin_find_identity_by_email(
    clients: &OryClients,
    email: &str,
) -> Result<Option<(Identity, bool)>> {
    let matches = list_identities(clients, 10, None, Some(email)).await?;
    for identity in matches {
        let verified = identity
            .verifiable_addresses
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|a| {
                a.via == ory_client::models::verifiable_identity_address::ViaEnum::Email
                    && a.value.eq_ignore_ascii_case(email)
            })
            .map(|a| a.verified);
        if let Some(verified) = verified {
            return Ok(Some((identity, verified)));
        }
    }
    Ok(None)
}

/// List every session across all identities (admin view). Kratos
/// paginates with `page_token`; we surface that to the caller as
/// best-effort pass-through. Passes `expand=identity` so each row
/// carries the owning identity (email + id) — without this the SDK
/// returns `session.identity = None` and the admin UI can't surface
/// who owns each session.
pub async fn admin_list_all_sessions(
    clients: &OryClients,
    page_size: i64,
    page_token: Option<&str>,
    active: Option<bool>,
) -> Result<Vec<Session>> {
    identity_api::list_sessions(
        &clients.kratos_admin,
        Some(page_size),
        page_token,
        active,
        Some(vec!["identity".to_string(), "devices".to_string()]),
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin list_sessions failed: {e}"))
}

/// Revoke a single session by ID via the admin API. Unlike the public
/// `disable_my_session`, this can revoke anyone's session, including the
/// admin's own — callers should warn before that happens.
pub async fn admin_revoke_session(clients: &OryClients, id: &str) -> Result<()> {
    identity_api::disable_session(&clients.kratos_admin, id)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin disable_session failed: {e}"))
}

/// Fetch a single session by ID via the admin API, with the owning
/// identity expanded so callers can verify org-scope ownership before
/// performing destructive actions on the session.
pub async fn admin_get_session(clients: &OryClients, id: &str) -> Result<Session> {
    identity_api::get_session(
        &clients.kratos_admin,
        id,
        Some(vec!["identity".to_string()]),
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin get_session failed: {e}"))
}

/// List courier messages. Used by the admin status page to surface
/// pending / failed counts. `status` filters server-side.
pub async fn list_courier_messages(
    clients: &OryClients,
    page_size: i64,
    status: Option<CourierMessageStatus>,
) -> Result<Vec<Message>> {
    courier_api::list_courier_messages(&clients.kratos_admin, Some(page_size), None, status, None)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin list_courier_messages failed: {e}"))
}

/// Hit Kratos's `/health/alive` probe (admin URL). The SDK doesn't expose
/// a typed wrapper for this — we hit the raw endpoint and treat any
/// 2xx as healthy. Used by the admin status page only.
pub async fn health_alive(clients: &OryClients) -> Result<()> {
    probe_health(&clients.kratos_admin, "/health/alive").await
}

/// Hit Kratos's `/health/ready` probe. Stricter than alive — also
/// checks downstream dependencies (DB).
pub async fn health_ready(clients: &OryClients) -> Result<()> {
    probe_health(&clients.kratos_admin, "/health/ready").await
}

/// Fetch the Kratos build version. Surfaced on the admin status page so
/// operators can sanity-check which release they're talking to.
pub async fn version(clients: &OryClients) -> Result<String> {
    let v = metadata_api::get_version(&clients.kratos_admin)
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_version failed: {e}"))?;
    Ok(v.version)
}

/// Fire the single-use `logout_url` server-side to destroy the Kratos
/// session without following the post-logout redirect. Used by callers
/// (e.g. the OAuth2 RP-initiated logout flow) that need to tear down the
/// session but route the browser to a different post-logout target than
/// Kratos's default.
///
/// Errors from the transport bubble; non-success HTTP statuses are
/// considered fire-and-forget — we don't surface them because the caller
/// has already committed to the next redirect.
pub async fn hit_logout_url(clients: &OryClients, url: &str, cookie: Option<&str>) -> Result<()> {
    let mut req = clients.kratos_public.client.get(url);
    if let Some(c) = cookie {
        req = req.header(ory_reqwest::header::COOKIE, c);
    }
    req.send()
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("kratos logout failed: {e}"))
}

/// Fetch the Kratos logout flow's `logout_url` (already containing the
/// single-use `logout_token`). Caller is expected to redirect the browser
/// to that URL — Kratos will clear the session cookie and bounce to
/// `/login`. Returns `Ok(None)` if no session cookie is present.
pub async fn fetch_logout_url(clients: &OryClients, cookie: &str) -> Result<Option<String>> {
    if cookie.is_empty() {
        return Ok(None);
    }
    let url = logout_browser_url(&clients.kratos_public.base_path);
    let resp = clients
        .kratos_public
        .client
        .get(&url)
        .header(reqwest::header::COOKIE, cookie)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos fetch_logout_url transport error: {e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(None);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "kratos fetch_logout_url returned {status}: {body}"
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("kratos fetch_logout_url decode failed: {e}"))?;
    Ok(body
        .get("logout_url")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}
