//! Authorization request validation (RFC 6749 section 4.1.1, OIDC Core 3.1.2.1, RFC 7636,
//! RFC 8707) and the login-skip decision. Pure: the client and the login session are inputs.

use chrono::{DateTime, Utc};

use super::clients::{AUTH_NONE, has_whitespace_or_control};
use crate::backend::oauth::{OAuthClient, OidcContext};

pub(crate) const AUTHORIZE_PATH: &str = "/oauth2/authorize";

/// RFC 8707 defines `resource` as repeatable; Hydra's `audience` is sent both ways.
const REPEATABLE: [&str; 2] = ["audience", "resource"];

const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// Length of a base64url SHA-256 digest without padding.
const S256_CHALLENGE_LEN: usize = 43;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ResponseMode {
    #[default]
    Query,
    FormPost,
}

/// Where and how an authorization response goes back to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Delivery {
    /// The request's `redirect_uri`, already matched against the registration.
    pub(crate) redirect_uri: String,
    pub(crate) mode: ResponseMode,
    pub(crate) state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorCode {
    InvalidRequest,
    UnsupportedResponseType,
    InvalidScope,
    RequestNotSupported,
    RequestUriNotSupported,
    InvalidTarget,
    LoginRequired,
    UnauthorizedClient,
}

impl ErrorCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::InvalidTarget => "invalid_target",
            Self::LoginRequired => "login_required",
            Self::UnauthorizedClient => "unauthorized_client",
        }
    }
}

/// Failures that leave no trustworthy `redirect_uri`; shown on Forseti's `/error` page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageError {
    /// `client_id` missing or not registered.
    UnknownClient,
    MissingRedirectUri,
    /// Not an absolute URI, or carries a fragment or userinfo.
    InvalidRedirectUri,
    UnregisteredRedirectUri,
    /// `client_id` or `redirect_uri` sent more than once.
    DuplicateParameter(&'static str),
}

/// A failure answered at the client's `redirect_uri` (RFC 6749 section 4.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedirectError {
    pub(crate) delivery: Delivery,
    pub(crate) error: ErrorCode,
    /// Fixed ASCII text; never echoes request input.
    pub(crate) description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthorizeError {
    Page(PageError),
    Redirect(RedirectError),
}

/// The `prompt` set (OIDC Core 3.1.2.1, Initiating User Registration 4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Prompt {
    pub(crate) none: bool,
    pub(crate) login: bool,
    pub(crate) consent: bool,
    pub(crate) create: bool,
    /// Accepted as Hydra does, not acted on and not advertised.
    pub(crate) select_account: bool,
}

/// A validated authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizeRequest {
    pub(crate) client_id: String,
    pub(crate) delivery: Delivery,
    /// Deduplicated, in request order.
    pub(crate) scope: Vec<String>,
    /// An `S256` challenge.
    pub(crate) code_challenge: Option<String>,
    pub(crate) prompt: Prompt,
    pub(crate) max_age: Option<u64>,
    pub(crate) nonce: Option<String>,
    pub(crate) acr_values: Vec<String>,
    pub(crate) login_hint: Option<String>,
    pub(crate) ui_locales: Vec<String>,
    pub(crate) display: Option<String>,
    pub(crate) id_token_hint: Option<String>,
    pub(crate) idp_hint: Option<String>,
    /// Each on the client's `audience`.
    pub(crate) audience: Vec<String>,
    /// Absolute URIs as sent; granting them is the consent handler's call.
    pub(crate) resource: Vec<String>,
}

impl AuthorizeRequest {
    pub(crate) fn oidc_context(&self) -> OidcContext {
        let non_empty = |v: &Vec<String>| (!v.is_empty()).then(|| v.clone());
        OidcContext {
            acr_values: non_empty(&self.acr_values),
            login_hint: self.login_hint.clone(),
            ui_locales: non_empty(&self.ui_locales),
        }
    }
}

/// The decoded parameters of an authorization request.
#[derive(Debug, Clone, Default)]
pub(crate) struct AuthorizeQuery {
    pairs: Vec<(String, String)>,
}

impl AuthorizeQuery {
    /// Parses one raw `application/x-www-form-urlencoded` string: the query of a GET, or the body
    /// alone of a POST, never a merge of both. Empty values count as omitted (RFC 6749 section
    /// 3.1) but still count towards duplicates.
    pub(crate) fn parse(raw: &str) -> Self {
        let pairs = url::form_urlencoded::parse(raw.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        Self { pairs }
    }

    /// The `client_id` to look up, when sent exactly once.
    pub(crate) fn client_id(&self) -> Option<&str> {
        (self.count("client_id") == 1)
            .then(|| self.get("client_id"))
            .flatten()
    }

    /// Every decoded pair, in request order.
    pub(crate) fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// Whether a parameter that may appear once appears more than once.
    pub(crate) fn has_duplicate(&self) -> bool {
        self.first_duplicate().is_some()
    }

    fn count(&self, name: &str) -> usize {
        self.pairs.iter().filter(|(k, _)| k == name).count()
    }

    fn get<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        self.all(name).next()
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.pairs
            .iter()
            .filter(move |(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| v.as_str())
    }

    fn first_duplicate(&self) -> Option<&str> {
        self.pairs
            .iter()
            .map(|(k, _)| k.as_str())
            .find(|k| !REPEATABLE.contains(k) && self.count(k) > 1)
    }
}

/// Validates `query` for `client`, the registration found under [`AuthorizeQuery::client_id`].
pub(crate) fn validate(
    query: &AuthorizeQuery,
    client: Option<&OAuthClient>,
) -> Result<AuthorizeRequest, AuthorizeError> {
    use ErrorCode::{
        InvalidRequest, InvalidScope, InvalidTarget, RequestNotSupported, RequestUriNotSupported,
        UnauthorizedClient, UnsupportedResponseType,
    };

    if query.count("client_id") > 1 {
        return Err(AuthorizeError::Page(PageError::DuplicateParameter(
            "client_id",
        )));
    }
    let client_id = query.client_id();
    let Some(client) =
        client.filter(|c| client_id.is_some() && c.client_id.as_deref() == client_id)
    else {
        return Err(AuthorizeError::Page(PageError::UnknownClient));
    };
    let redirect_uri = checked_redirect_uri(query, client).map_err(AuthorizeError::Page)?;

    let state = (query.count("state") == 1)
        .then(|| query.get("state").map(str::to_string))
        .flatten();
    let mut delivery = Delivery {
        redirect_uri,
        mode: ResponseMode::Query,
        state,
    };
    let fail = |delivery: &Delivery, error, description| {
        Err(AuthorizeError::Redirect(RedirectError {
            delivery: delivery.clone(),
            error,
            description,
        }))
    };

    if query.count("response_mode") > 1 {
        return fail(&delivery, InvalidRequest, "response_mode is repeated");
    }
    delivery.mode = match query.get("response_mode") {
        None | Some("query") => ResponseMode::Query,
        Some("form_post")
            if url::Url::parse(&delivery.redirect_uri)
                .is_ok_and(|u| matches!(u.scheme(), "http" | "https")) =>
        {
            ResponseMode::FormPost
        }
        Some("form_post") => {
            return fail(
                &delivery,
                InvalidRequest,
                "response_mode=form_post needs an http or https redirect_uri",
            );
        }
        Some(_) => return fail(&delivery, InvalidRequest, "unsupported response_mode"),
    };
    if query.has_duplicate() {
        return fail(&delivery, InvalidRequest, "a parameter is repeated");
    }
    if query.get("request").is_some() {
        return fail(
            &delivery,
            RequestNotSupported,
            "request objects are not supported",
        );
    }
    if query.get("request_uri").is_some() {
        return fail(
            &delivery,
            RequestUriNotSupported,
            "request_uri is not supported",
        );
    }
    match query.get("response_type") {
        None => return fail(&delivery, InvalidRequest, "response_type is missing"),
        Some("code") => {}
        Some(_) => {
            return fail(
                &delivery,
                UnsupportedResponseType,
                "only response_type=code is supported",
            );
        }
    }
    if !registered_or(client.grant_types.as_deref(), "authorization_code")
        || !registered_or(client.response_types.as_deref(), "code")
    {
        return fail(
            &delivery,
            UnauthorizedClient,
            "the client is not registered for the authorization code flow",
        );
    }

    let scope = space_list(query.get("scope"));
    let allowed = space_list(client.scope.as_deref());
    if !scope.iter().all(|s| allowed.contains(s)) {
        return fail(
            &delivery,
            InvalidScope,
            "a requested scope is not allowed for this client",
        );
    }

    let public = client.token_endpoint_auth_method.as_deref() == Some(AUTH_NONE);
    let code_challenge = match (
        query.get("code_challenge"),
        query.get("code_challenge_method"),
    ) {
        (None, None) if public => {
            return fail(
                &delivery,
                InvalidRequest,
                "PKCE is required for public clients",
            );
        }
        (None, None) => None,
        (None, Some(_)) => return fail(&delivery, InvalidRequest, "code_challenge is missing"),
        (Some(_), m) if m != Some("S256") => {
            return fail(
                &delivery,
                InvalidRequest,
                "code_challenge_method must be S256",
            );
        }
        (Some(c), _) if !is_s256_challenge(c) => {
            return fail(&delivery, InvalidRequest, "code_challenge is malformed");
        }
        (Some(c), _) => Some(c.to_string()),
    };

    let Some(prompt) = parse_prompt(query.get("prompt")) else {
        return fail(&delivery, InvalidRequest, "unsupported prompt value");
    };
    if prompt.none && (prompt.login || prompt.consent || prompt.create || prompt.select_account) {
        return fail(
            &delivery,
            InvalidRequest,
            "prompt=none can't be combined with other values",
        );
    }
    let max_age = match query.get("max_age") {
        None => None,
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            Some(v.parse::<u64>().unwrap_or(u64::MAX))
        }
        Some(_) => {
            return fail(
                &delivery,
                InvalidRequest,
                "max_age must be a non-negative integer",
            );
        }
    };

    let registered_audience = client.audience.as_deref().unwrap_or_default();
    let mut audience: Vec<String> = Vec::new();
    for value in query.all("audience").flat_map(|v| v.split(' ')) {
        if value.is_empty() || audience.iter().any(|a| a == value) {
            continue;
        }
        if !registered_audience.iter().any(|a| a == value) {
            return fail(
                &delivery,
                InvalidRequest,
                "a requested audience is not allowed for this client",
            );
        }
        audience.push(value.to_string());
    }

    let mut resource: Vec<String> = Vec::new();
    for value in query.all("resource") {
        if value.contains('#')
            || has_whitespace_or_control(value)
            || url::Url::parse(value).is_err()
        {
            return fail(
                &delivery,
                InvalidTarget,
                "resource must be an absolute URI without a fragment",
            );
        }
        if !resource.iter().any(|r| r == value) {
            resource.push(value.to_string());
        }
    }

    let owned = |name| query.get(name).map(str::to_string);
    Ok(AuthorizeRequest {
        client_id: client_id.unwrap_or_default().to_string(),
        delivery,
        scope,
        code_challenge,
        prompt,
        max_age,
        nonce: owned("nonce"),
        acr_values: space_list(query.get("acr_values")),
        login_hint: owned("login_hint"),
        ui_locales: space_list(query.get("ui_locales")),
        display: owned("display"),
        id_token_hint: owned("id_token_hint"),
        idp_hint: owned("idp_hint"),
        audience,
        resource,
    })
}

fn checked_redirect_uri(query: &AuthorizeQuery, client: &OAuthClient) -> Result<String, PageError> {
    if query.count("redirect_uri") > 1 {
        return Err(PageError::DuplicateParameter("redirect_uri"));
    }
    let Some(requested) = query.get("redirect_uri") else {
        return Err(PageError::MissingRedirectUri);
    };
    if !is_acceptable_redirect_uri(requested) {
        return Err(PageError::InvalidRedirectUri);
    }
    let registered = client.redirect_uris.as_deref().unwrap_or_default();
    if registered
        .iter()
        .any(|r| redirect_uri_matches(requested, r))
    {
        Ok(requested.to_string())
    } else {
        Err(PageError::UnregisteredRedirectUri)
    }
}

fn is_acceptable_redirect_uri(raw: &str) -> bool {
    // `Url` drops an empty userinfo (`http://@host/`), so the authority is checked as sent.
    let authority_has_userinfo = raw
        .split_once("://")
        .is_some_and(|(_, rest)| split_authority(rest).0.contains('@'));
    !raw.contains('#')
        && !authority_has_userinfo
        && url::Url::parse(raw).is_ok_and(|u| u.username().is_empty() && u.password().is_none())
}

/// Byte-exact match, except the port of an `http` loopback URI (RFC 8252 section 7.3,
/// RFC 9700 section 2.1).
fn redirect_uri_matches(requested: &str, registered: &str) -> bool {
    if requested == registered {
        return true;
    }
    let (Some(req), Some(reg)) = (
        requested.strip_prefix("http://"),
        registered.strip_prefix("http://"),
    ) else {
        return false;
    };
    let (req_authority, req_rest) = split_authority(req);
    let (reg_authority, reg_rest) = split_authority(reg);
    match (loopback_host(req_authority), loopback_host(reg_authority)) {
        (Some(a), Some(b)) => a == b && req_rest == reg_rest,
        _ => false,
    }
}

fn split_authority(after_scheme: &str) -> (&str, &str) {
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    after_scheme.split_at(end)
}

/// The literal loopback host of `host[:port]`, compared as written so `127.1` or a zone id
/// never qualifies.
fn loopback_host(authority: &str) -> Option<&'static str> {
    LOOPBACK_HOSTS.into_iter().find(|host| {
        authority.strip_prefix(host).is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty()
                        && port.bytes().all(|b| b.is_ascii_digit())
                        && port.parse::<u16>().is_ok()
                })
        })
    })
}

/// Whether `registered` names `value`; an empty or missing list stands for `value` alone, as
/// fosite defaults a client's grant and response types.
fn registered_or(registered: Option<&[String]>, value: &str) -> bool {
    match registered {
        None | Some([]) => true,
        Some(list) => list.iter().any(|v| v == value),
    }
}

fn is_s256_challenge(c: &str) -> bool {
    c.len() == S256_CHALLENGE_LEN
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A space-delimited list, deduplicated in order.
pub(super) fn space_list(raw: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in raw.unwrap_or_default().split(' ') {
        if !item.is_empty() && !out.iter().any(|o| o == item) {
            out.push(item.to_string());
        }
    }
    out
}

/// `None` on a value outside `prompt_values_supported` (Initiating User Registration 4.1).
fn parse_prompt(raw: Option<&str>) -> Option<Prompt> {
    let mut prompt = Prompt::default();
    for value in raw.unwrap_or_default().split(' ') {
        match value {
            "" => {}
            "none" => prompt.none = true,
            "login" => prompt.login = true,
            "consent" => prompt.consent = true,
            "create" => prompt.create = true,
            "select_account" => prompt.select_account = true,
            _ => return None,
        }
    }
    Some(prompt)
}

/// A remembered OP login session, as loaded from the `forseti_op` cookie and its row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoginSessionSnapshot {
    pub(crate) sid: String,
    pub(crate) auth_time: DateTime<Utc>,
    pub(crate) remember: bool,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoginStep {
    /// Reuse the session's `sid` and `auth_time`.
    Skip {
        sid: String,
        auth_time: DateTime<Utc>,
    },
    /// Show the login handler under a fresh `sid`.
    ShowLogin,
    /// `prompt=create`: send the browser to `/oauth/register`.
    Register,
    /// `prompt=none` without a skippable session.
    LoginRequired,
}

pub(crate) fn login_step(
    prompt: &Prompt,
    max_age: Option<u64>,
    now: DateTime<Utc>,
    session: Option<&LoginSessionSnapshot>,
) -> LoginStep {
    if prompt.create {
        return LoginStep::Register;
    }
    let within_max_age = |auth_time: DateTime<Utc>| match max_age {
        None => true,
        Some(0) => false,
        Some(max) => {
            let age = (now - auth_time).num_seconds();
            !u64::try_from(age).is_ok_and(|age| age > max)
        }
    };
    match session {
        Some(s)
            if s.remember && s.expires_at > now && !prompt.login && within_max_age(s.auth_time) =>
        {
            LoginStep::Skip {
                sid: s.sid.clone(),
                auth_time: s.auth_time,
            }
        }
        _ if prompt.none => LoginStep::LoginRequired,
        _ => LoginStep::ShowLogin,
    }
}

/// The `request_url` handed to the login and consent handlers: the configured issuer, never the
/// Host header, plus the raw query as received.
pub(crate) fn request_url(issuer: &str, raw_query: &str) -> String {
    if raw_query.is_empty() {
        format!("{issuer}{AUTHORIZE_PATH}")
    } else {
        format!("{issuer}{AUTHORIZE_PATH}?{raw_query}")
    }
}

#[cfg(test)]
mod tests;
