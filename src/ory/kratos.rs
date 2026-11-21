//! Kratos public and admin API calls over plain HTTP.
//!
//! Bodies are the private structs in `kratos_wire`. Paths, methods and query
//! names follow the Ory API spec (`/sessions/...` and `/self-service/...` on
//! the public endpoint, `/admin/...` on the admin one). Failures of the
//! spec'd calls read `kratos <operation> failed: error in <reqwest|serde|response>: ...`.

use reqwest::Method;
use reqwest::header::COOKIE;

use super::kratos_wire as wire;
use super::*;

use crate::backend::identity::{
    CourierStatus, FlowFetch, FlowKind, FlowOutcome, Identity, IdentityState, PrivilegedReason,
    RecoveryCode, SelfServiceError, Session, WhoamiOutcome,
};
use crate::flow_view::Flow;
use crate::web::urlencode;

fn sessions(batch: Vec<wire::Session>) -> Vec<Session> {
    batch.into_iter().map(Session::from).collect()
}

fn identities(batch: Vec<wire::Identity>) -> Vec<Identity> {
    batch.into_iter().map(Identity::from).collect()
}

fn identity_path(id: &str) -> String {
    format!("/admin/identities/{}", urlencode(id))
}

fn with_cookie(req: reqwest::RequestBuilder, cookie: Option<&str>) -> reqwest::RequestBuilder {
    match cookie {
        Some(c) => req.header(COOKIE, c),
        None => req,
    }
}

/// Resolve the current session via `/sessions/whoami` with the user's
/// forwarded `Cookie` header. See [`WhoamiOutcome`] for the three
/// outcomes (Kratos 401 is `None`, 403 is `InsufficientAal`); `Err` is
/// reserved for transport / unexpected upstream failures.
pub async fn whoami(clients: &KratosClients, cookie: Option<&str>) -> Result<WhoamiOutcome> {
    let req = clients
        .kratos_public
        .request(Method::GET, "/sessions/whoami");
    match send_json::<wire::Session>(with_cookie(req, cookie)).await {
        Ok(session) => Ok(WhoamiOutcome::Ok(Box::new(session.into()))),
        Err(CallError::Status(s)) if s == StatusCode::UNAUTHORIZED => Ok(WhoamiOutcome::None),
        Err(CallError::Status(s)) if s == StatusCode::FORBIDDEN => {
            // 403 = session exists, AAL too low; the per-route gate already knows the required AAL, so no body parse needed.
            Ok(WhoamiOutcome::InsufficientAal)
        }
        Err(e) => Err(anyhow::anyhow!("kratos whoami failed: {e}")),
    }
}

/// Fetch a self-service flow by ID, forwarding the user's cookies (continuity-cookie validation). 404/410 map
/// to [`FlowFetch::Gone`]; a settings 403 maps to [`FlowFetch::PrivilegedRequired`].
///
/// Fetched as raw JSON and projected by [`crate::flow_json::project`]: Kratos's `ui.nodes` attributes are
/// a union keyed by `node_type`, which the projection reads without a typed model.
pub async fn get_flow(
    clients: &KratosClients,
    kind: FlowKind,
    flow_id: &str,
    cookie: &str,
) -> Result<FlowFetch> {
    let url = format!(
        "{}/self-service/{}/flows",
        clients.kratos_public.base.trim_end_matches('/'),
        kind.path_segment(),
    );
    let mut req = clients
        .kratos_public
        .http
        .get(&url)
        .query(&[("id", flow_id)]);
    if !cookie.is_empty() {
        req = req.header(COOKIE, cookie);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_flow transport error: {e}"))?;

    let status = resp.status();
    if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
        return Ok(FlowFetch::Gone);
    }
    if status == StatusCode::FORBIDDEN {
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
            kind.path_segment()
        ));
    }

    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_flow body decode failed: {e}"))?;
    Ok(FlowFetch::Ok(Box::new(crate::flow_json::project(&value))))
}

/// Kratos path whose API flow carries the `oidc` provider nodes; probed
/// without cookies, so it never touches a browser session.
const OIDC_PROVIDER_PROBE_PATH: &str = "/self-service/login/api";

/// Upstream provider ids Kratos offers, read off a fresh API login flow
/// (Kratos has no endpoint that lists them). Each call creates one flow.
pub async fn probe_oidc_provider_ids(clients: &KratosClients) -> Result<Vec<String>> {
    let url = format!(
        "{}{OIDC_PROVIDER_PROBE_PATH}",
        clients.kratos_public.base.trim_end_matches('/'),
    );
    let resp = clients
        .kratos_public
        .http
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
    Ok(crate::flow_json::project(&flow).oidc_provider_ids())
}

/// Resolve the `?flow=` id into a [`FlowOutcome`]: `None` short-circuits to
/// [`FlowOutcome::Init`]; otherwise [`get_flow`] runs and its [`FlowFetch`]
/// (or transport error) is mapped to the matching variant.
pub async fn resolve_flow(
    clients: &KratosClients,
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
    clients: &KratosClients,
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
    clients: &KratosClients,
    action: &str,
    body: &serde_json::Value,
    cookie: &str,
) -> Result<()> {
    let resp = clients
        .kratos_public
        .http
        .post(action)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(COOKIE, cookie)
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

/// Fetch a Kratos self-service error (the `/error?id=...` landing) as raw JSON.
pub async fn get_self_service_error(
    clients: &KratosClients,
    error_id: &str,
) -> Result<Option<SelfServiceError>> {
    let url = format!(
        "{}/self-service/errors",
        clients.kratos_public.base.trim_end_matches('/'),
    );
    let resp = clients
        .kratos_public
        .http
        .get(&url)
        .query(&[("id", error_id)])
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_self_service_error transport error: {e}"))?;
    let status = resp.status();
    if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
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

/// `GET /admin/identities/{id}`, asking for the given credential types.
async fn fetch_identity(
    clients: &KratosClients,
    id: &str,
    include_credential: &[&str],
) -> Result<wire::Identity, CallError> {
    let query: Vec<(&str, &str)> = include_credential
        .iter()
        .map(|c| ("include_credential", *c))
        .collect();
    let req = clients
        .kratos_admin
        .request(Method::GET, &identity_path(id))
        .query(&query);
    send_json(req).await
}

/// Admin lookup by identity ID.
pub async fn admin_get_identity(clients: &KratosClients, id: &str) -> Result<Identity> {
    read_identity(clients, id).await.map(Identity::from)
}

/// The identity as Kratos sent it, for read-modify-write helpers, so nothing is flattened on the way back.
async fn read_identity(clients: &KratosClients, id: &str) -> Result<wire::Identity> {
    fetch_identity(clients, id, &[])
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin get_identity failed: {e}"))
}

/// Like [`admin_get_identity`] but maps a typed 404 to `Ok(None)` instead
/// of an error. Used by the webhook reconciler so transport failures
/// can't be mistaken for "identity gone" via stringified-error matching.
pub async fn admin_get_identity_optional(
    clients: &KratosClients,
    id: &str,
) -> Result<Option<Identity>> {
    match fetch_identity(clients, id, &[]).await {
        Ok(identity) => Ok(Some(identity.into())),
        Err(e) if e.is_not_found() => Ok(None),
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
/// the caller from their session (no admin credentials required).
pub async fn list_my_sessions(
    clients: &KratosClients,
    cookie: Option<&str>,
) -> Result<Vec<Session>> {
    let req = clients.kratos_public.request(Method::GET, "/sessions");
    send_json(with_cookie(req, cookie))
        .await
        .map(sessions)
        .map_err(|e| anyhow::anyhow!("kratos list_my_sessions failed: {e}"))
}

/// Revoke a single session by ID. Kratos refuses to delete the *current*
/// session via this endpoint (it returns 400), so callers treat the current session row as non-revokable in the UI.
pub async fn revoke_session(clients: &KratosClients, id: &str, cookie: Option<&str>) -> Result<()> {
    let req = clients
        .kratos_public
        .request(Method::DELETE, &format!("/sessions/{}", urlencode(id)));
    send(with_cookie(req, cookie))
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("kratos disable_my_session failed: {e}"))
}

/// Revoke every session except the one currently making the request.
/// Kratos enforces "except current" itself. Returns the deletion count
/// from Kratos (kept loosely-typed as it's just an informational return).
pub async fn revoke_other_sessions(clients: &KratosClients, cookie: Option<&str>) -> Result<u64> {
    let req = clients.kratos_public.request(Method::DELETE, "/sessions");
    let count: wire::DeleteMySessionsCount = send_json(with_cookie(req, cookie))
        .await
        .map_err(|e| anyhow::anyhow!("kratos disable_my_other_sessions failed: {e}"))?;
    Ok(count.count.unwrap_or(0).max(0) as u64)
}

fn identity_sessions_path(identity_id: &str) -> String {
    format!("{}/sessions", identity_path(identity_id))
}

/// Admin-API lookup of an identity's session history. Used by the
/// dashboard's "Recent Activity" sidebar as a stand-in for a real audit
/// log (Kratos doesn't expose a queryable event stream in this version).
pub async fn list_identity_sessions(
    clients: &KratosClients,
    identity_id: &str,
) -> Result<Vec<Session>> {
    let req = clients
        .kratos_admin
        .request(Method::GET, &identity_sessions_path(identity_id));
    send_json(req)
        .await
        .map(sessions)
        .map_err(|e| anyhow::anyhow!("kratos admin list_identity_sessions failed: {e}"))
}

const SESSION_LIST_PAGE_SIZE: i64 = 250;
const SESSION_LIST_MAX_PAGES: usize = 50;

/// Every session of an identity, following `Link: rel="next"` until
/// exhausted, like [`super::HydraBackend::list_consent_sessions_by_subject`].
pub async fn list_identity_sessions_all(
    clients: &KratosClients,
    identity_id: &str,
) -> Result<Vec<Session>> {
    let ep = &clients.kratos_admin;
    let base = format!(
        "{}{}",
        ep.base.trim_end_matches('/'),
        identity_sessions_path(identity_id)
    );
    let mut out: Vec<Session> = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..SESSION_LIST_MAX_PAGES {
        let mut req = ep
            .http
            .get(&base)
            .query(&[("page_size", SESSION_LIST_PAGE_SIZE.to_string())]);
        if let Some(tok) = page_token.as_deref() {
            req = req.query(&[("page_token", tok)]);
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
        let batch: Vec<wire::Session> = resp
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
    clients: &KratosClients,
    identity_id: &str,
) -> Result<std::collections::HashSet<String>> {
    let req = clients
        .kratos_admin
        .request(Method::GET, &identity_sessions_path(identity_id))
        .query(&[("page_size", "1000"), ("active", "true")]);
    let active: Vec<wire::Session> = send_json(req)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin list_identity_sessions failed: {e}"))?;
    Ok(active.into_iter().map(|s| s.id).collect())
}

/// Whether `kratos_session_id` is one of the identity's active sessions.
pub async fn is_session_active(
    clients: &KratosClients,
    identity_id: &str,
    kratos_session_id: &str,
) -> Result<bool> {
    Ok(active_session_ids(clients, identity_id)
        .await?
        .contains(kratos_session_id))
}

fn session_path(id: &str) -> String {
    format!("/admin/sessions/{}", urlencode(id))
}

/// Admin lookup of one session with its identity expanded.
pub async fn admin_get_session(clients: &KratosClients, id: &str) -> Result<Session> {
    let req = clients
        .kratos_admin
        .request(Method::GET, &session_path(id))
        .query(&[("expand", "identity")]);
    send_json::<wire::Session>(req)
        .await
        .map(Session::from)
        .map_err(|e| anyhow::anyhow!("kratos admin get_session failed: {e}"))
}

// --- Admin surface ---------------------------------------------------

/// Paginated identity list via the Kratos admin API. `page_token` comes from the previous page's `Link` header.
pub async fn list_identities(
    clients: &KratosClients,
    page_size: i64,
    page_token: Option<&str>,
    credentials_identifier: Option<&str>,
) -> Result<Vec<Identity>> {
    let mut req = clients
        .kratos_admin
        .request(Method::GET, "/admin/identities")
        .query(&[("page_size", page_size.to_string())]);
    if let Some(tok) = page_token {
        req = req.query(&[("page_token", tok)]);
    }
    if let Some(identifier) = credentials_identifier {
        req = req.query(&[("credentials_identifier", identifier)]);
    }
    send_json(req)
        .await
        .map(identities)
        .map_err(|e| anyhow::anyhow!("kratos admin list_identities failed: {e}"))
}

/// Bulk admin-API lookup. Uses the upstream `ids` query parameter so N
/// identities resolve in one round-trip rather than N. Returns identities
/// in whatever order Kratos chose; callers that need a specific order
/// should sort after the fact.
pub async fn admin_list_identities_by_ids(
    clients: &KratosClients,
    ids: Vec<String>,
) -> Result<Vec<Identity>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut query: Vec<(&str, &str)> = Vec::with_capacity(ids.len() + 1);
    let per_page = ids.len().to_string();
    query.push(("per_page", &per_page));
    query.extend(ids.iter().map(|id| ("ids", id.as_str())));
    let req = clients
        .kratos_admin
        .request(Method::GET, "/admin/identities")
        .query(&query);
    send_json(req)
        .await
        .map(identities)
        .map_err(|e| anyhow::anyhow!("kratos admin list_identities by ids failed: {e}"))
}

const FULL_CREDENTIAL_TYPES: &[&str] = &["password", "totp", "webauthn", "lookup_secret", "oidc"];

/// Like [`admin_get_identity`] but asks Kratos to include the identity's
/// credentials in the response (passwords stay hashed/redacted; this surfaces which methods are configured, not the secrets).
pub async fn admin_get_identity_full(clients: &KratosClients, id: &str) -> Result<Identity> {
    fetch_identity(clients, id, FULL_CREDENTIAL_TYPES)
        .await
        .map(Identity::from)
        .map_err(|e| anyhow::anyhow!("kratos admin get_identity_full failed: {e}"))
}

/// [`admin_get_identity_full`] with a typed 404 mapped to `Ok(None)`.
pub async fn admin_get_identity_full_optional(
    clients: &KratosClients,
    id: &str,
) -> Result<Option<Identity>> {
    match fetch_identity(clients, id, FULL_CREDENTIAL_TYPES).await {
        Ok(identity) => Ok(Some(identity.into())),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(anyhow::anyhow!(
            "kratos admin get_identity_full failed: {e}"
        )),
    }
}

/// `PUT /admin/identities/{id}`: Kratos replaces the identity with `body`.
async fn update_identity(
    clients: &KratosClients,
    id: &str,
    body: &wire::UpdateIdentityBody,
) -> Result<Identity, CallError> {
    let req = clients
        .kratos_admin
        .request(Method::PUT, &identity_path(id))
        .json(body);
    send_json::<wire::Identity>(req).await.map(Identity::from)
}

/// The update body that writes `current` back with new `state` and `traits`.
fn update_body(
    current: wire::Identity,
    state: IdentityState,
    traits: serde_json::Value,
) -> wire::UpdateIdentityBody {
    wire::UpdateIdentityBody {
        external_id: current.external_id,
        metadata_admin: current.metadata_admin,
        metadata_public: current.metadata_public,
        schema_id: current.schema_id,
        state,
        traits,
    }
}

/// Set the `preferred_language` trait on an identity without clobbering other
/// fields. Round-trips schema_id + full traits (mirroring
/// [`admin_update_identity_state`]) and defaults to `Active` since a
/// self-service caller is by definition active.
pub async fn admin_set_identity_language(
    clients: &KratosClients,
    id: &str,
    lang: &str,
) -> Result<Identity> {
    let mut current = read_identity(clients, id).await?;
    let mut traits = match current.traits.take().unwrap_or(serde_json::Value::Null) {
        serde_json::Value::Null => serde_json::Value::Object(serde_json::Map::new()),
        t => t,
    };
    if let serde_json::Value::Object(ref mut map) = traits {
        map.insert("preferred_language".to_string(), serde_json::json!(lang));
    }
    let body = update_body(current, IdentityState::Active, traits);
    update_identity(clients, id, &body)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin set_identity_language failed: {e}"))
}

/// Set an identity's state (`active` / `inactive`). Update goes through
/// `update_identity` since Kratos has no dedicated state-toggle endpoint;
/// we round-trip the existing schema_id + traits to avoid clobbering
/// other fields.
pub async fn admin_update_identity_state(
    clients: &KratosClients,
    id: &str,
    state: IdentityState,
) -> Result<Identity> {
    let mut current = read_identity(clients, id).await?;
    let traits = current.traits.take().unwrap_or(serde_json::Value::Null);
    let body = update_body(current, state, traits);
    update_identity(clients, id, &body)
        .await
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
) -> std::result::Result<Vec<wire::JsonPatchOp>, &'static str> {
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
        (None, Some(v)) => wire::JsonPatchOp {
            op: "add",
            path: "/metadata_admin".to_string(),
            value: Some(serde_json::json!({ key: v })),
        },
        (Some(_), Some(v)) => wire::JsonPatchOp {
            op: "add",
            path: key_path,
            value: Some(serde_json::Value::String(v.to_string())),
        },
        (Some(map), None) if map.contains_key(key) => wire::JsonPatchOp {
            op: "remove",
            path: key_path,
            value: None,
        },
        (_, None) => return Ok(Vec::new()),
    };
    Ok(vec![op])
}

async fn patch_metadata_admin_key(
    clients: &KratosClients,
    id: &str,
    key: &str,
    value: Option<&str>,
) -> Result<bool> {
    let identity = read_identity(clients, id).await?;
    let current = identity.metadata_admin.as_ref().and_then(|m| m.as_ref());
    let was_set = crate::backend::identity::metadata_has_key(current, key);
    let patch = metadata_admin_patch(current, key, value).map_err(anyhow::Error::msg)?;
    if !patch.is_empty() {
        let req = clients
            .kratos_admin
            .request(Method::PATCH, &identity_path(id))
            .json(&patch);
        send_json::<wire::Identity>(req).await.map_err(|e| {
            anyhow::anyhow!("kratos admin patch_identity (metadata_admin) failed: {e}")
        })?;
    }
    Ok(was_set)
}

/// Write `metadata_admin.<key>`, creating the object when it is null.
pub async fn admin_set_metadata_admin_key(
    clients: &KratosClients,
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
    clients: &KratosClients,
    id: &str,
    key: &str,
) -> Result<bool> {
    patch_metadata_admin_key(clients, id, key, None).await
}

/// Permanently delete an identity. Cascades to sessions and verifiable
/// addresses on the Kratos side.
pub async fn admin_delete_identity(clients: &KratosClients, id: &str) -> Result<()> {
    let req = clients
        .kratos_admin
        .request(Method::DELETE, &identity_path(id));
    send(req)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("kratos admin delete_identity failed: {e}"))
}

/// List the ids of every identity schema registered with Kratos. The admin
/// configuration page surfaces these so operators can see which schemas
/// drive registration / profile shape. Unpaged; Kratos returns the full set in one page.
pub async fn list_identity_schemas(clients: &KratosClients) -> Result<Vec<String>> {
    let req = clients.kratos_admin.request(Method::GET, "/schemas");
    let schemas: Vec<wire::IdentitySchemaContainer> = send_json(req)
        .await
        .map_err(|e| anyhow::anyhow!("kratos list_identity_schemas failed: {e}"))?;
    Ok(schemas.into_iter().map(|s| s.id).collect())
}

/// Generate a one-shot recovery code for an identity. Returns the plaintext
/// code + a recovery link; admin UI shows both once and the operator hands
/// the code to the user out-of-band.
pub async fn admin_create_recovery_code(
    clients: &KratosClients,
    identity_id: &str,
) -> Result<RecoveryCode> {
    let req = clients
        .kratos_admin
        .request(Method::POST, "/admin/recovery/code")
        .json(&wire::RecoveryCodeBody { identity_id });
    send_json::<wire::RecoveryCodeForIdentity>(req)
        .await
        .map(RecoveryCode::from)
        .map_err(|e| anyhow::anyhow!("kratos admin create_recovery_code failed: {e}"))
}

/// Mint a one-shot magic recovery link: a Kratos public URL a browser GET redeems into a privileged session.
/// The only OSS path from "server-side authenticated" (e.g. a validated SAML assertion) to a real browser session.
pub async fn admin_create_recovery_link(
    clients: &KratosClients,
    identity_id: &str,
    expires_in: &str,
    return_to: Option<&str>,
) -> Result<String> {
    let mut req = clients
        .kratos_admin
        .request(Method::POST, "/admin/recovery/link");
    if let Some(rt) = return_to {
        req = req.query(&[("return_to", rt)]);
    }
    let req = req.json(&wire::RecoveryLinkBody {
        expires_in,
        identity_id,
    });
    let link: wire::RecoveryLinkForIdentity = send_json(req)
        .await
        .map_err(|e| anyhow::anyhow!("kratos admin create_recovery_link failed: {e}"))?;
    Ok(link.recovery_link)
}

/// `POST /admin/identities`.
pub(super) async fn create_identity(
    clients: &KratosClients,
    body: &wire::CreateIdentityBody<'_>,
) -> Result<wire::Identity, CallError> {
    let req = clients
        .kratos_admin
        .request(Method::POST, "/admin/identities")
        .json(body);
    send_json(req).await
}

/// JIT-provision an identity with a pre-verified email (SAML SSO: the
/// corporate IdP asserted the address, so re-verification is pointless).
/// Returns `Ok(None)` on 409 (the email already belongs to another identity) so the SSO callback can render a block page instead of a 500.
pub async fn admin_create_identity_verified(
    clients: &KratosClients,
    schema_id: &str,
    email: &str,
    first: &str,
    last: &str,
) -> Result<Option<Identity>> {
    let body = wire::CreateIdentityBody {
        schema_id,
        traits: serde_json::json!({
            "email": email,
            "name": { "first": first, "last": last },
        }),
        verifiable_addresses: Some(vec![wire::NewAddress {
            status: "completed",
            value: email,
            verified: true,
            via: "email",
        }]),
    };
    match create_identity(clients, &body).await {
        Ok(identity) => Ok(Some(identity.into())),
        Err(CallError::Status(s)) if s == StatusCode::CONFLICT => Ok(None),
        Err(e) => Err(anyhow::anyhow!("kratos admin create_identity failed: {e}")),
    }
}

/// Find an identity whose verifiable addresses include `email`, with that address's verified flag. Uses the
/// `credentials_identifier` filter; SAML-created identities are found via Forseti's `saml_links` table instead.
pub async fn admin_find_identity_by_email(
    clients: &KratosClients,
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
    clients: &KratosClients,
    page_size: i64,
    page_token: Option<&str>,
    active: Option<bool>,
) -> Result<Vec<Session>> {
    let mut req = clients
        .kratos_admin
        .request(Method::GET, "/admin/sessions")
        .query(&[("page_size", page_size.to_string())]);
    if let Some(tok) = page_token {
        req = req.query(&[("page_token", tok)]);
    }
    if let Some(active) = active {
        req = req.query(&[("active", active.to_string())]);
    }
    let req = req.query(&[("expand", "identity"), ("expand", "devices")]);
    send_json(req)
        .await
        .map(sessions)
        .map_err(|e| anyhow::anyhow!("kratos admin list_sessions failed: {e}"))
}

/// Revoke a single session by ID via the admin API. Unlike the public
/// `disable_my_session`, this can revoke anyone's session, including the
/// admin's own, so callers should warn before that happens.
pub async fn admin_revoke_session(clients: &KratosClients, id: &str) -> Result<()> {
    let req = clients
        .kratos_admin
        .request(Method::DELETE, &session_path(id));
    send(req)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("kratos admin disable_session failed: {e}"))
}

/// Number of courier messages in `status`, counted over the first page only,
/// so the result is capped at `page_size`. Admin status page only.
pub async fn courier_backlog(
    clients: &KratosClients,
    status: CourierStatus,
    page_size: i64,
) -> Result<u64> {
    let status = match status {
        CourierStatus::Queued => "queued",
        CourierStatus::Abandoned => "abandoned",
    };
    let req = clients
        .kratos_admin
        .request(Method::GET, "/admin/courier/messages")
        .query(&[("page_size", page_size.to_string())])
        .query(&[("status", status)]);
    send_json::<Vec<wire::Message>>(req)
        .await
        .map(|msgs| msgs.len() as u64)
        .map_err(|e| anyhow::anyhow!("kratos admin list_courier_messages failed: {e}"))
}

/// Hit Kratos's `/health/alive` probe (admin URL) and treat any 2xx as healthy. Admin status page only.
pub async fn health_alive(clients: &KratosClients) -> Result<()> {
    clients.kratos_admin.probe_health("/health/alive").await
}

/// Hit Kratos's `/health/ready` probe. Stricter than alive: also checks downstream dependencies (DB).
pub async fn health_ready(clients: &KratosClients) -> Result<()> {
    clients.kratos_admin.probe_health("/health/ready").await
}

/// Fetch the Kratos build version. Surfaced on the admin status page so
/// operators can sanity-check which release they're talking to.
pub async fn version(clients: &KratosClients) -> Result<String> {
    let req = clients.kratos_admin.request(Method::GET, "/version");
    let v: wire::GetVersion200Response = send_json(req)
        .await
        .map_err(|e| anyhow::anyhow!("kratos get_version failed: {e}"))?;
    Ok(v.version)
}

/// Best-effort Kratos session teardown: fetch the logout URL for the cookie's
/// session and hit it server-side. No-op when the cookie is empty. Callers that
/// need a guarantee the session is gone must re-check `whoami` afterwards.
pub async fn tear_down_session(clients: &KratosClients, cookie: &str) {
    if cookie.is_empty() {
        return;
    }
    if let Ok(Some(url)) = fetch_logout_url(clients, cookie).await {
        let _ = hit_logout_url(clients, &url, Some(cookie)).await;
    }
}

/// Fire the single-use `logout_url` server-side to destroy the session, for callers routing the browser
/// elsewhere than the post-logout redirect. Transport errors bubble; non-2xx are fire-and-forget.
pub async fn hit_logout_url(
    clients: &KratosClients,
    url: &str,
    cookie: Option<&str>,
) -> Result<()> {
    with_cookie(clients.kratos_public.http.get(url), cookie)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("kratos logout failed: {e}"))
}

/// Fetch the Kratos logout flow's `logout_url` (already containing the
/// single-use `logout_token`). Caller is expected to redirect the browser
/// to that URL; Kratos clears the session cookie and bounces to `/login`. `Ok(None)` if no session cookie is present.
pub async fn fetch_logout_url(clients: &KratosClients, cookie: &str) -> Result<Option<String>> {
    if cookie.is_empty() {
        return Ok(None);
    }
    let url = logout_browser_url(&clients.kratos_public.base);
    let resp = clients
        .kratos_public
        .http
        .get(&url)
        .header(COOKIE, cookie)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kratos fetch_logout_url transport error: {e}"))?;
    let status = resp.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
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
mod tests;
