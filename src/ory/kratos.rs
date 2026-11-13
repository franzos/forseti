//! Kratos self-service wrappers.

use super::*;
use ory_client::apis::{Error as OryError, courier_api, frontend_api, identity_api, metadata_api};

use crate::backend::identity::{
    CourierStatus, FlowOutcome, IdentityState, RecoveryCode, SelfServiceError, WhoamiOutcome,
};
use crate::flow_view::Flow;

fn sessions(batch: Vec<ory_client::models::Session>) -> Vec<Session> {
    batch.into_iter().map(Session::from).collect()
}

fn identities(batch: Vec<ory_client::models::Identity>) -> Vec<Identity> {
    batch.into_iter().map(Identity::from).collect()
}

/// Resolve the current session via `/sessions/whoami` with the user's
/// forwarded `Cookie` header. See [`WhoamiOutcome`] for the three
/// outcomes (Kratos 401 is `None`, 403 is `InsufficientAal`); `Err` is
/// reserved for transport / unexpected upstream failures.
pub async fn whoami(clients: &OryClients, cookie: Option<&str>) -> Result<WhoamiOutcome> {
    match frontend_api::to_session(&clients.kratos_public, None, cookie, None).await {
        Ok(session) => Ok(WhoamiOutcome::Ok(Box::new(session.into()))),
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::UNAUTHORIZED => {
            Ok(WhoamiOutcome::None)
        }
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::FORBIDDEN => {
            // 403 = session exists, AAL too low; the per-route gate already knows the required AAL, so no body parse needed.
            Ok(WhoamiOutcome::InsufficientAal)
        }
        Err(e) => Err(anyhow::anyhow!("kratos whoami failed: {e}")),
    }
}

/// Fetch a self-service flow by ID, forwarding the user's cookies (continuity-cookie validation). 404/410 map
/// to [`FlowFetch::Gone`]; a settings 403 maps to [`FlowFetch::PrivilegedRequired`].
///
/// Fetches raw JSON rather than the SDK's typed `get_*_flow` because `UiNodeAttributes` is `#[serde(tag =
/// "node_type")]` while the inner `UiNodeInputAttributes` also requires `node_type`, so every real response
/// fails with `missing field 'node_type'`. See <https://github.com/ory/sdk/issues/381>.
pub async fn get_flow(
    clients: &OryClients,
    kind: FlowKind,
    flow_id: &str,
    cookie: &str,
) -> Result<FlowFetch> {
    let url = format!(
        "{}/self-service/{}/flows",
        clients.kratos_public.base_path.trim_end_matches('/'),
        path_segment(kind),
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
        // On settings flows, parse `error.id` into a typed reason; other flows collapse to Gone (like a stale flow).
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if matches!(kind, FlowKind::Settings) {
            let reason_id = body
                .pointer("/error/id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reason = if reason_id == "session_aal2_required" {
                PrivilegedReason::Aal2Required
            } else {
                // Refresh is the safe catch-all for "session no longer sufficient".
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
            path_segment(kind)
        ));
    }

    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_flow body decode failed: {e}"))?;
    Ok(FlowFetch::Ok(Box::new(flow_json::project(&value))))
}

/// Kratos path whose API flow carries the `oidc` provider nodes; probed
/// without cookies, so it never touches a browser session.
const OIDC_PROVIDER_PROBE_PATH: &str = "/self-service/login/api";

/// Upstream provider ids Kratos offers, read off a fresh API login flow
/// (Kratos has no endpoint that lists them). Each call creates one flow.
pub async fn probe_oidc_provider_ids(clients: &OryClients) -> Result<Vec<String>> {
    let url = format!(
        "{}{OIDC_PROVIDER_PROBE_PATH}",
        clients.kratos_public.base_path.trim_end_matches('/'),
    );
    let resp = clients
        .kratos_public
        .client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos provider probe transport error: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!("kratos provider probe returned {status}"));
    }
    let flow: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("kratos provider probe body decode failed: {e}"))?;
    Ok(flow_json::project(&flow).oidc_provider_ids())
}

/// Resolve the `?flow=` id into a [`FlowOutcome`]: `None` short-circuits to
/// [`FlowOutcome::Init`]; otherwise [`get_flow`] runs and its [`FlowFetch`]
/// (or transport error) is mapped to the matching variant.
pub async fn resolve_flow(
    clients: &OryClients,
    kind: FlowKind,
    flow_id: Option<&str>,
    cookie: &str,
) -> FlowOutcome {
    let Some(flow_id) = flow_id else {
        return FlowOutcome::Init;
    };
    match get_flow(clients, kind, flow_id, cookie).await {
        Ok(FlowFetch::Ok(flow)) => FlowOutcome::Ready(flow),
        Ok(FlowFetch::Gone) => FlowOutcome::Reinit,
        Ok(FlowFetch::PrivilegedRequired(reason)) => FlowOutcome::Privileged(reason),
        Err(e) => FlowOutcome::Error(e),
    }
}

/// Submit `method=code&email=…` to a verification flow's form action, so the
/// browser lands straight on code entry. `Err` on a missing action or CSRF
/// token, transport failure, or any non-2xx, so callers can fall through to
/// rendering the form unchanged.
pub async fn verify_known_email(
    clients: &OryClients,
    flow: &Flow,
    email: &str,
    cookie: &str,
) -> Result<()> {
    if flow.form_action.is_empty() {
        return Err(anyhow::anyhow!("verification flow missing ui.action"));
    }
    let csrf = flow
        .csrf_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("verification flow missing csrf_token node"))?;
    let body = serde_json::json!({
        "method": "code",
        "email": email,
        "csrf_token": csrf,
    });
    submit_flow(clients, &flow.form_action, &body, cookie).await
}

/// POST a self-service flow submission to its `ui.action`, forwarding the
/// user's cookie. `Err` on transport failure or any non-2xx.
async fn submit_flow(
    clients: &OryClients,
    action: &str,
    body: &serde_json::Value,
    cookie: &str,
) -> Result<()> {
    let resp = clients
        .kratos_public
        .client
        .post(action)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::COOKIE, cookie)
        .json(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos submit_flow transport error: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "kratos submit_flow returned {status}: {body}"
        ));
    }
    Ok(())
}

/// Build the browser redirect URL that starts a new Kratos browser flow; Kratos creates the flow, sets its
/// continuity cookie, and 303s back to Forseti with `?flow=<id>`. `return_to` lands the user back on the
/// original page; optional `aal` step-up and `refresh` are forwarded to Kratos.
pub fn browser_init_url_with(
    kind: FlowKind,
    public_url: &str,
    return_to: Option<&str>,
    aal: Option<&str>,
    refresh: Option<bool>,
) -> String {
    let base = public_url.trim_end_matches('/');
    let segment = path_segment(kind);
    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(rt) = return_to
        && !rt.is_empty()
    {
        params.push(("return_to", rt.to_string()));
    }
    if let Some(a) = aal
        && !a.is_empty()
    {
        params.push(("aal", a.to_string()));
    }
    if matches!(refresh, Some(true)) {
        params.push(("refresh", "true".to_string()));
    }
    if params.is_empty() {
        return format!("{base}/self-service/{segment}/browser");
    }
    let qs: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, crate::web::urlencode(v)))
        .collect();
    format!("{base}/self-service/{segment}/browser?{}", qs.join("&"))
}

/// Fetch a Kratos self-service error (the `/error?id=...` landing) as raw JSON, avoiding the SDK model.
pub async fn get_self_service_error(
    clients: &OryClients,
    error_id: &str,
) -> Result<Option<SelfServiceError>> {
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
    Ok(Some(self_service_error(&value)))
}

/// Older Kratos versions put the error at the top level, newer ones wrap it
/// under `error.{id,message,reason,...}`. Handle both.
fn self_service_error(body: &serde_json::Value) -> SelfServiceError {
    let inner = body.get("error").unwrap_or(body);
    let str_at = |key: &str| inner.get(key).and_then(|v| v.as_str()).map(str::to_string);
    SelfServiceError {
        id: str_at("id"),
        message: str_at("message"),
        reason: str_at("reason"),
    }
}

/// Admin lookup by identity ID. Hits the Kratos admin API which returns
/// the typed `Identity` model (no `ui.nodes` involved, so the SDK deserializer works fine here).
pub async fn admin_get_identity(clients: &OryClients, id: &str) -> Result<Identity> {
    sdk_get_identity(clients, id).await.map(Identity::from)
}

/// SDK-typed lookup for read-modify-write helpers, so nothing is flattened on the way back to Kratos.
async fn sdk_get_identity(clients: &OryClients, id: &str) -> Result<ory_client::models::Identity> {
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
        Ok(identity) => Ok(Some(identity.into())),
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
/// the caller from their session (no admin credentials required). The
/// `Session` model has no `ui.nodes`, so the typed SDK call works here.
pub async fn list_my_sessions(clients: &OryClients, cookie: Option<&str>) -> Result<Vec<Session>> {
    frontend_api::list_my_sessions(&clients.kratos_public, None, None, None, None, None, cookie)
        .await
        .map(sessions)
        .map_err(|e| anyhow::anyhow!("kratos list_my_sessions failed: {e}"))
}

/// Revoke a single session by ID. Kratos refuses to delete the *current*
/// session via this endpoint (it returns 400), so callers treat the current session row as non-revokable in the UI.
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
    .map(sessions)
    .map_err(|e| anyhow::anyhow!("kratos admin list_identity_sessions failed: {e}"))
}

const SESSION_LIST_PAGE_SIZE: i64 = 250;
const SESSION_LIST_MAX_PAGES: usize = 50;

/// Every session of an identity, following `Link: rel="next"` until
/// exhausted. The SDK helper drops the Link header, so this goes through the
/// raw client like [`super::hydra::list_consent_sessions_by_subject`].
pub async fn list_identity_sessions_all(
    clients: &OryClients,
    identity_id: &str,
) -> Result<Vec<Session>> {
    let cfg = &clients.kratos_admin;
    let base = format!(
        "{}/admin/identities/{}/sessions",
        cfg.base_path.trim_end_matches('/'),
        crate::web::urlencode(identity_id)
    );
    let mut out: Vec<Session> = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..SESSION_LIST_MAX_PAGES {
        let mut req = cfg
            .client
            .get(&base)
            .query(&[("page_size", SESSION_LIST_PAGE_SIZE.to_string())]);
        if let Some(tok) = page_token.as_deref() {
            req = req.query(&[("page_token", tok)]);
        }
        if let Some(token) = cfg.bearer_access_token.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("kratos list_identity_sessions transport: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "kratos list_identity_sessions returned {status}: {body}"
            ));
        }
        let next = super::hydra::next_link(resp.headers());
        let batch: Vec<ory_client::models::Session> = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("kratos list_identity_sessions decode: {e}"))?;
        let batch_empty = batch.is_empty();
        out.extend(sessions(batch));
        match next {
            Some(tok) if !batch_empty => page_token = Some(tok),
            _ => return Ok(out),
        }
    }
    Err(anyhow::anyhow!(
        "kratos session listing exceeded {SESSION_LIST_MAX_PAGES} pages"
    ))
}

/// The ids of the identity's active, unexpired sessions. Kratos applies the
/// expiry in its `active` filter.
pub async fn active_session_ids(
    clients: &OryClients,
    identity_id: &str,
) -> Result<std::collections::HashSet<String>> {
    let active = identity_api::list_identity_sessions(
        &clients.kratos_admin,
        identity_id,
        None,
        None,
        Some(1000),
        None,
        Some(true),
    )
    .await
    .map_err(|e| anyhow::anyhow!("kratos admin list_identity_sessions failed: {e}"))?;
    Ok(active.into_iter().map(|s| s.id).collect())
}

/// Whether `kratos_session_id` is one of the identity's active sessions.
pub async fn is_session_active(
    clients: &OryClients,
    identity_id: &str,
    kratos_session_id: &str,
) -> Result<bool> {
    Ok(active_session_ids(clients, identity_id)
        .await?
        .contains(kratos_session_id))
}

/// Admin lookup of one session with its identity expanded.
pub async fn admin_get_session(clients: &OryClients, id: &str) -> Result<Session> {
    identity_api::get_session(
        &clients.kratos_admin,
        id,
        Some(vec!["identity".to_string()]),
    )
    .await
    .map(Session::from)
    .map_err(|e| anyhow::anyhow!("kratos admin get_session failed: {e}"))
}

// --- Admin surface ---------------------------------------------------

/// Paginated identity list via the Kratos admin API. `page_token` comes from the previous page's `Link` header.
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
    .map(identities)
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
    .map(identities)
    .map_err(|e| anyhow::anyhow!("kratos admin list_identities by ids failed: {e}"))
}

/// Like [`admin_get_identity`] but asks Kratos to include the identity's
/// credentials in the response (passwords stay hashed/redacted; this surfaces which methods are configured, not the secrets).
pub async fn admin_get_identity_full(clients: &OryClients, id: &str) -> Result<Identity> {
    identity_api::get_identity(&clients.kratos_admin, id, Some(full_credential_types()))
        .await
        .map(Identity::from)
        .map_err(|e| anyhow::anyhow!("kratos admin get_identity_full failed: {e}"))
}

/// [`admin_get_identity_full`] with a typed 404 mapped to `Ok(None)`.
pub async fn admin_get_identity_full_optional(
    clients: &OryClients,
    id: &str,
) -> Result<Option<Identity>> {
    match identity_api::get_identity(&clients.kratos_admin, id, Some(full_credential_types())).await
    {
        Ok(identity) => Ok(Some(identity.into())),
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::NOT_FOUND => {
            Ok(None)
        }
        Err(e) => Err(anyhow::anyhow!(
            "kratos admin get_identity_full failed: {e}"
        )),
    }
}

fn full_credential_types() -> Vec<String> {
    ["password", "totp", "webauthn", "lookup_secret", "oidc"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Set the `preferred_language` trait on an identity without clobbering other
/// fields. Round-trips schema_id + full traits (mirroring
/// [`admin_update_identity_state`]) and defaults to `Active` since a
/// self-service caller is by definition active.
pub async fn admin_set_identity_language(
    clients: &OryClients,
    id: &str,
    lang: &str,
) -> Result<Identity> {
    let current = sdk_get_identity(clients, id).await?;
    let mut traits = match current.traits.unwrap_or(serde_json::Value::Null) {
        serde_json::Value::Null => serde_json::Value::Object(serde_json::Map::new()),
        t => t,
    };
    if let serde_json::Value::Object(ref mut map) = traits {
        map.insert("preferred_language".to_string(), serde_json::json!(lang));
    }
    let body = UpdateIdentityBody {
        credentials: None,
        external_id: current.external_id,
        metadata_admin: current.metadata_admin,
        metadata_public: current.metadata_public,
        region: None,
        schema_id: current.schema_id,
        state: ory_client::models::update_identity_body::StateEnum::Active,
        traits,
    };
    identity_api::update_identity(&clients.kratos_admin, id, Some(body))
        .await
        .map(Identity::from)
        .map_err(|e| anyhow::anyhow!("kratos admin set_identity_language failed: {e}"))
}

/// Set an identity's state (`active` / `inactive`). Update goes through
/// `update_identity` since Kratos has no dedicated state-toggle endpoint;
/// we round-trip the existing schema_id + traits to avoid clobbering
/// other fields.
pub async fn admin_update_identity_state(
    clients: &OryClients,
    id: &str,
    state: IdentityState,
) -> Result<Identity> {
    let current = sdk_get_identity(clients, id).await?;
    let traits = current.traits.unwrap_or(serde_json::Value::Null);
    let body = UpdateIdentityBody {
        credentials: None,
        external_id: current.external_id,
        metadata_admin: current.metadata_admin,
        metadata_public: current.metadata_public,
        region: None,
        schema_id: current.schema_id,
        state: state.into(),
        traits,
    };
    identity_api::update_identity(&clients.kratos_admin, id, Some(body))
        .await
        .map(Identity::from)
        .map_err(|e| anyhow::anyhow!("kratos admin update_identity (state) failed: {e}"))
}

/// JSON Patch (RFC 6902) that sets (`Some`) or removes (`None`) one key of
/// `metadata_admin` and leaves every other key alone. `current` is the
/// identity's `metadata_admin` as last read; removing an absent key yields no
/// ops.
fn metadata_admin_patch(
    current: Option<&serde_json::Value>,
    key: &str,
    value: Option<&str>,
) -> std::result::Result<Vec<ory_client::models::JsonPatch>, &'static str> {
    use ory_client::models::{JsonPatch, json_patch::OpEnum};
    let object = match current {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(map)) => Some(map),
        Some(_) => return Err("metadata_admin is not an object"),
    };
    let key_path = format!(
        "/metadata_admin/{}",
        key.replace('~', "~0").replace('/', "~1")
    );
    let op = match (object, value) {
        (None, Some(v)) => JsonPatch {
            from: None,
            op: OpEnum::Add,
            path: "/metadata_admin".to_string(),
            value: Some(Some(serde_json::json!({ key: v }))),
        },
        (Some(_), Some(v)) => JsonPatch {
            from: None,
            op: OpEnum::Add,
            path: key_path,
            value: Some(Some(serde_json::Value::String(v.to_string()))),
        },
        (Some(map), None) if map.contains_key(key) => JsonPatch::new(OpEnum::Remove, key_path),
        (_, None) => return Ok(Vec::new()),
    };
    Ok(vec![op])
}

async fn patch_metadata_admin_key(
    clients: &OryClients,
    id: &str,
    key: &str,
    value: Option<&str>,
) -> Result<bool> {
    let identity = sdk_get_identity(clients, id).await?;
    let current = identity.metadata_admin.as_ref().and_then(|m| m.as_ref());
    let was_set = crate::backend::identity::metadata_has_key(current, key);
    let patch = metadata_admin_patch(current, key, value).map_err(anyhow::Error::msg)?;
    if !patch.is_empty() {
        identity_api::patch_identity(&clients.kratos_admin, id, Some(patch))
            .await
            .map_err(|e| {
                anyhow::anyhow!("kratos admin patch_identity (metadata_admin) failed: {e}")
            })?;
    }
    Ok(was_set)
}

/// Write `metadata_admin.<key>`, creating the object when it is null.
pub async fn admin_set_metadata_admin_key(
    clients: &OryClients,
    id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    patch_metadata_admin_key(clients, id, key, Some(value))
        .await
        .map(|_| ())
}

/// Drop `metadata_admin.<key>`; returns whether it held a non-null value.
pub async fn admin_remove_metadata_admin_key(
    clients: &OryClients,
    id: &str,
    key: &str,
) -> Result<bool> {
    patch_metadata_admin_key(clients, id, key, None).await
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
/// drive registration / profile shape. Paging args are all `None`; Kratos returns the full set in one page.
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
) -> Result<RecoveryCode> {
    let body = CreateRecoveryCodeForIdentityBody::new(identity_id.to_string());
    identity_api::create_recovery_code_for_identity(&clients.kratos_admin, Some(body))
        .await
        .map(RecoveryCode::from)
        .map_err(|e| anyhow::anyhow!("kratos admin create_recovery_code failed: {e}"))
}

/// Mint a one-shot magic recovery link: a Kratos public URL a browser GET redeems into a privileged session.
/// The only OSS path from "server-side authenticated" (e.g. a validated SAML assertion) to a real browser session.
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
/// Returns `Ok(None)` on 409 (the email already belongs to another identity) so the SSO callback can render a block page instead of a 500.
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
    let addr = ory_client::models::VerifiableIdentityAddress::new(
        "completed".to_string(),
        email.to_string(),
        true,
        ory_client::models::verifiable_identity_address::ViaEnum::Email,
    );
    body.verifiable_addresses = Some(vec![addr]);
    match identity_api::create_identity(&clients.kratos_admin, Some(body)).await {
        Ok(identity) => Ok(Some(identity.into())),
        Err(OryError::ResponseError(resp)) if resp.status == reqwest::StatusCode::CONFLICT => {
            Ok(None)
        }
        Err(e) => Err(anyhow::anyhow!("kratos admin create_identity failed: {e}")),
    }
}

/// Find an identity whose verifiable addresses include `email`, with that address's verified flag. Uses the
/// `credentials_identifier` filter; SAML-created identities are found via Forseti's `saml_links` table instead.
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
            .find(|a| a.via == "email" && a.value.eq_ignore_ascii_case(email))
            .map(|a| a.verified);
        if let Some(verified) = verified {
            return Ok(Some((identity, verified)));
        }
    }
    Ok(None)
}

/// List every session across all identities (admin view). Passes `expand=identity` so each row carries its
/// owner (otherwise `session.identity = None` and the admin UI can't show who owns each session).
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
    .map(sessions)
    .map_err(|e| anyhow::anyhow!("kratos admin list_sessions failed: {e}"))
}

/// Revoke a single session by ID via the admin API. Unlike the public
/// `disable_my_session`, this can revoke anyone's session, including the
/// admin's own, so callers should warn before that happens.
pub async fn admin_revoke_session(clients: &OryClients, id: &str) -> Result<()> {
    identity_api::disable_session(&clients.kratos_admin, id)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin disable_session failed: {e}"))
}

/// Number of courier messages in `status`, counted over the first page only,
/// so the result is capped at `page_size`. Admin status page only.
pub async fn courier_backlog(
    clients: &OryClients,
    status: CourierStatus,
    page_size: i64,
) -> Result<u64> {
    courier_api::list_courier_messages(
        &clients.kratos_admin,
        Some(page_size),
        None,
        Some(status.into()),
        None,
    )
    .await
    .map(|msgs| msgs.len() as u64)
    .map_err(|e| anyhow::anyhow!("kratos admin list_courier_messages failed: {e}"))
}

/// Hit Kratos's `/health/alive` probe (admin URL). The SDK doesn't expose
/// a typed wrapper for this, so we hit the raw endpoint and treat any 2xx as healthy. Admin status page only.
pub async fn health_alive(clients: &OryClients) -> Result<()> {
    probe_health(&clients.kratos_admin, "/health/alive").await
}

/// Hit Kratos's `/health/ready` probe. Stricter than alive: also checks downstream dependencies (DB).
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

/// Best-effort Kratos session teardown: fetch the logout URL for the cookie's
/// session and hit it server-side. No-op when the cookie is empty. Callers that
/// need a guarantee the session is gone must re-check `whoami` afterwards.
pub async fn tear_down_session(clients: &OryClients, cookie: &str) {
    if cookie.is_empty() {
        return;
    }
    if let Ok(Some(url)) = fetch_logout_url(clients, cookie).await {
        let _ = hit_logout_url(clients, &url, Some(cookie)).await;
    }
}

/// Fire the single-use `logout_url` server-side to destroy the session without following the post-logout
/// redirect (for callers routing the browser elsewhere). Transport errors bubble; non-2xx are fire-and-forget.
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
/// to that URL; Kratos clears the session cookie and bounces to `/login`. `Ok(None)` if no session cookie is present.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ory_client::models::json_patch::OpEnum;
    use serde_json::json;

    fn ops(
        current: Option<serde_json::Value>,
        key: &str,
        value: Option<&str>,
    ) -> Vec<serde_json::Value> {
        metadata_admin_patch(current.as_ref(), key, value)
            .expect("patch")
            .iter()
            .map(|op| serde_json::to_value(op).unwrap())
            .collect()
    }

    #[test]
    fn self_service_error_reads_wrapped_and_top_level_shapes() {
        let wrapped = json!({"id": "e1", "error": {
            "id": "self_service_flow_expired", "message": "expired", "reason": "too old"
        }});
        assert_eq!(
            self_service_error(&wrapped),
            SelfServiceError {
                id: Some("self_service_flow_expired".into()),
                message: Some("expired".into()),
                reason: Some("too old".into()),
            }
        );
        let top = json!({"id": "security_csrf_violation", "message": 5});
        assert_eq!(
            self_service_error(&top),
            SelfServiceError {
                id: Some("security_csrf_violation".into()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn set_on_absent_or_null_adds_the_object() {
        let want = vec![json!({"op": "add", "path": "/metadata_admin", "value": {"aud": "u:1:x"}})];
        assert_eq!(ops(None, "aud", Some("u:1:x")), want);
        assert_eq!(ops(Some(json!(null)), "aud", Some("u:1:x")), want);
    }

    #[test]
    fn set_on_object_adds_only_the_key() {
        let current = json!({"other": "keep", "aud": "old"});
        assert_eq!(
            ops(Some(current.clone()), "aud", Some("new")),
            vec![json!({"op": "add", "path": "/metadata_admin/aud", "value": "new"})]
        );
        assert_eq!(
            ops(Some(json!({})), "aud", Some("v")),
            vec![json!({"op": "add", "path": "/metadata_admin/aud", "value": "v"})]
        );
    }

    #[test]
    fn non_object_is_refused() {
        for current in [json!(["aud"]), json!("aud"), json!(1), json!(true)] {
            assert!(metadata_admin_patch(Some(&current), "aud", Some("v")).is_err());
            assert!(metadata_admin_patch(Some(&current), "aud", None).is_err());
        }
    }

    #[test]
    fn remove_present_key() {
        let patch = metadata_admin_patch(Some(&json!({"aud": "v", "x": 1})), "aud", None).unwrap();
        assert_eq!(patch.len(), 1);
        assert_eq!(patch[0].op, OpEnum::Remove);
        assert_eq!(patch[0].path, "/metadata_admin/aud");
        assert_eq!(
            serde_json::to_value(&patch[0]).unwrap(),
            json!({"op": "remove", "path": "/metadata_admin/aud"})
        );
    }

    #[test]
    fn remove_absent_is_no_op() {
        assert!(ops(None, "aud", None).is_empty());
        assert!(ops(Some(json!(null)), "aud", None).is_empty());
        assert!(ops(Some(json!({"other": 1})), "aud", None).is_empty());
    }

    #[test]
    fn pointer_escapes_tilde_before_slash() {
        let current = json!({"a/b~c": "v"});
        assert_eq!(
            ops(Some(current.clone()), "a/b~c", Some("w")),
            vec![json!({"op": "add", "path": "/metadata_admin/a~1b~0c", "value": "w"})]
        );
        assert_eq!(
            ops(Some(current), "a/b~c", None),
            vec![json!({"op": "remove", "path": "/metadata_admin/a~1b~0c"})]
        );
        assert_eq!(
            ops(Some(json!({})), "~1", Some("w"))[0]["path"],
            "/metadata_admin/~01"
        );
    }

    #[test]
    fn set_on_null_keeps_the_raw_key() {
        assert_eq!(ops(None, "a/b", Some("v"))[0]["value"], json!({"a/b": "v"}));
    }

    #[test]
    fn has_key_ignores_null_and_absent() {
        let mut identity = Identity::default();
        assert!(!identity.metadata_admin_has_key("aud"));
        identity.metadata_admin = Some(json!(null));
        assert!(!identity.metadata_admin_has_key("aud"));
        identity.metadata_admin = Some(json!({"aud": null}));
        assert!(!identity.metadata_admin_has_key("aud"));
        identity.metadata_admin = Some(json!(["aud"]));
        assert!(!identity.metadata_admin_has_key("aud"));
        identity.metadata_admin = Some(json!({"aud": "v"}));
        assert!(identity.metadata_admin_has_key("aud"));
    }
}
