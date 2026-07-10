use std::path::{Path, PathBuf};

use serde_yaml_ng::Value;
use toml_edit::DocumentMut;

use crate::cli::{CheckArgs, PathArgs};

use super::catalog;
use super::init::is_dev_smtp;
use super::yamlutil::{dig, dig_bool, dig_str, is_placeholder, load_yaml, secret_entries};

const DEFAULT_KRATOS: &str = "infra/kratos/kratos.yml";
const DEFAULT_HYDRA: &str = "infra/hydra/hydra.yml";

const ENV_KRATOS: &str = "FORSETI_KRATOS_CONFIG";
const ENV_HYDRA: &str = "FORSETI_HYDRA_CONFIG";

/// Known-bad literal shipped in the playground `kratos.yml`'s `web_hook`
/// auth values. Shared with the `rotate` subcommand (a later task).
pub(crate) const PLACEHOLDER_TOKENS: &[&str] = &["dev-playground-token-change-me"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Severity {
    Ok,
    Warn,
    Fail,
}

impl Severity {
    fn marker(self) -> &'static str {
        match self {
            Severity::Ok => "[ OK ]",
            Severity::Warn => "[WARN]",
            Severity::Fail => "[FAIL]",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Finding {
    pub(crate) severity: Severity,
    pub(crate) key: String,
    pub(crate) current: String,
    pub(crate) recommended: String,
    pub(crate) impact: String,
}

impl Finding {
    pub(crate) fn ok(key: &str, current: impl Into<String>) -> Self {
        Finding {
            severity: Severity::Ok,
            key: key.to_string(),
            current: current.into(),
            recommended: String::new(),
            impact: String::new(),
        }
    }

    pub(crate) fn warn(
        key: &str,
        current: impl Into<String>,
        recommended: &str,
        impact: &str,
    ) -> Self {
        Finding {
            severity: Severity::Warn,
            key: key.to_string(),
            current: current.into(),
            recommended: recommended.to_string(),
            impact: impact.to_string(),
        }
    }

    pub(crate) fn fail(
        key: &str,
        current: impl Into<String>,
        recommended: &str,
        impact: &str,
    ) -> Self {
        Finding {
            severity: Severity::Fail,
            key: key.to_string(),
            current: current.into(),
            recommended: recommended.to_string(),
            impact: impact.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Check logic operates on parsed Values so it's testable without the FS.
// ---------------------------------------------------------------------------

pub(crate) fn check_kratos(root: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    // session.whoami.required_aal
    match dig_str(root, &["session", "whoami", "required_aal"]) {
        Some("highest_available") => {
            findings.push(Finding::ok(
                "session.whoami.required_aal",
                "highest_available",
            ));
        }
        other => findings.push(Finding::warn(
            "session.whoami.required_aal",
            other.unwrap_or("<unset>"),
            "highest_available",
            "2FA not enforced at login — users with a second factor won't be prompted to use it.",
        )),
    }

    // selfservice.flows.settings.required_aal: the critical one.
    match dig_str(root, &["selfservice", "flows", "settings", "required_aal"]) {
        Some("highest_available") => {
            findings.push(Finding::ok(
                "selfservice.flows.settings.required_aal",
                "highest_available",
            ));
        }
        other => findings.push(Finding::fail(
            "selfservice.flows.settings.required_aal",
            other.unwrap_or("<unset>"),
            "highest_available",
            "an AAL1 session (password-only login, or an email-recovery session) can open settings and REMOVE a second factor — full 2FA bypass.",
        )),
    }

    // selfservice.methods.lookup_secret.enabled
    match dig_bool(root, &["selfservice", "methods", "lookup_secret", "enabled"]) {
        Some(true) => findings.push(Finding::ok(
            "selfservice.methods.lookup_secret.enabled",
            "true",
        )),
        other => findings.push(Finding::warn(
            "selfservice.methods.lookup_secret.enabled",
            other.map_or("<unset>".to_string(), |b| b.to_string()),
            "true",
            "no recovery-code break-glass; a user who loses their device and forgets their password is locked out (admin-only recovery).",
        )),
    }

    // webauthn passwordless: only relevant when webauthn is enabled.
    if dig_bool(root, &["selfservice", "methods", "webauthn", "enabled"]) == Some(true) {
        let passwordless = dig_bool(
            root,
            &[
                "selfservice",
                "methods",
                "webauthn",
                "config",
                "passwordless",
            ],
        );
        match passwordless {
            Some(false) | None => findings.push(Finding::ok(
                "selfservice.methods.webauthn.config.passwordless",
                passwordless.map_or("<unset>".to_string(), |b| b.to_string()),
            )),
            Some(true) => findings.push(Finding::warn(
                "selfservice.methods.webauthn.config.passwordless",
                "true",
                "false",
                "webauthn is configured passwordless (first-factor); it won't act as a second factor for AAL2.",
            )),
        }
    }

    // selfservice.flows.recovery.enabled
    match dig_bool(root, &["selfservice", "flows", "recovery", "enabled"]) {
        Some(true) => findings.push(Finding::ok("selfservice.flows.recovery.enabled", "true")),
        other => findings.push(Finding::warn(
            "selfservice.flows.recovery.enabled",
            other.map_or("<unset>".to_string(), |b| b.to_string()),
            "true",
            "self-service account recovery disabled.",
        )),
    }

    // courier.smtp.connection_uri
    match dig_str(root, &["courier", "smtp", "connection_uri"]) {
        Some(uri) if !is_dev_smtp(uri) => {
            findings.push(Finding::ok("courier.smtp.connection_uri", redact_uri(uri)));
        }
        other => findings.push(Finding::warn(
            "courier.smtp.connection_uri",
            other.map_or("<unset>".to_string(), redact_uri),
            "a production SMTP URI",
            "courier SMTP unset or pointing at a dev mailbox; recovery/verification mail won't reach users.",
        )),
    }

    findings.extend(check_secret_lists(root, false));
    findings.extend(check_flow_hooks(root));
    findings.extend(check_hook_tokens(root));

    findings.extend(placeholder_findings(root, &findings));
    findings
}

pub(crate) fn check_hydra(root: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(check_secret_lists(root, true));

    // urls.issuer or urls.self.issuer
    let issuer =
        dig_str(root, &["urls", "self", "issuer"]).or_else(|| dig_str(root, &["urls", "issuer"]));
    match issuer {
        Some(u) if !is_placeholder(u) => {
            findings.push(Finding::ok("urls.self.issuer", u));
        }
        other => findings.push(Finding::warn(
            "urls.self.issuer",
            other.unwrap_or("<unset>"),
            "Hydra's public issuer URL",
            "issuer unset or placeholder; id_token `iss` claims won't validate.",
        )),
    }

    // urls.login / urls.consent / urls.logout: should point at Forseti.
    for endpoint in ["login", "consent", "logout"] {
        match dig_str(root, &["urls", endpoint]) {
            Some(u) if !is_placeholder(u) => {
                findings.push(Finding::ok(&format!("urls.{endpoint}"), u));
            }
            other => findings.push(Finding::warn(
                &format!("urls.{endpoint}"),
                other.unwrap_or("<unset>"),
                "a Forseti /oauth/* URL",
                "endpoint unset; Hydra won't hand the flow to Forseti.",
            )),
        }
    }

    findings.extend(placeholder_findings(root, &findings));
    findings
}

/// Prefix path to OIDC providers; `check_oidc_providers` validates specific
/// fields within this subtree (client_id, client_secret, microsoft_tenant,
/// mapper_url), so the generic scan must skip only those to avoid double-reporting.
const OIDC_PROVIDERS_PATH: &str = "selfservice.methods.oidc.config.providers";

/// Fields within each OIDC provider that `check_oidc_providers` validates.
/// The generic placeholder scan must skip only these, allowing it to catch
/// other placeholder-bearing fields (e.g. hand-filled issuer_url).
const OIDC_PROVIDER_FIELDS: &[&str] = &[
    "client_id",
    "client_secret",
    "microsoft_tenant",
    "mapper_url",
];

/// Scan every scalar for a leftover `CHANGEME` placeholder (case-insensitive
/// — `config-init` always emits it upper-case, but a hand-edited file might
/// not) or the literal dev-playground hook token, and FAIL on each. `already`
/// covers keys the specific checks handled; a specific finding whose key is a
/// prefix of the scalar's path (e.g. `secrets.cipher` vs the scalar at
/// `secrets.cipher[0]`) suppresses the generic one so we don't double-report.
/// Within the OIDC providers subtree, only the four fields that
/// `check_oidc_providers` explicitly validates are skipped; other fields are
/// checked generically (e.g. issuer_url).
pub(crate) fn placeholder_findings(root: &Value, already: &[Finding]) -> Vec<Finding> {
    let mut out = Vec::new();
    walk_placeholders(root, &mut String::new(), &mut |path, value| {
        // Skip only OIDC provider fields that check_oidc_providers handles.
        if path.starts_with(&format!("{OIDC_PROVIDERS_PATH}[")) {
            if let Some(last_field) = path.rsplit('.').next() {
                if OIDC_PROVIDER_FIELDS.contains(&last_field) {
                    return;
                }
            }
        }
        let covered = already
            .iter()
            .any(|f| path == f.key || path.starts_with(&format!("{}[", f.key)));
        let is_changeme = value.to_ascii_uppercase().contains("CHANGEME");
        let is_dev_token = PLACEHOLDER_TOKENS.iter().any(|t| value.contains(t));
        if (is_changeme || is_dev_token) && !covered {
            out.push(Finding::fail(
                path,
                value,
                "a real value",
                "unfilled placeholder left by `config-init` — supply a real value.",
            ));
        }
    });
    out
}

fn walk_placeholders(value: &Value, path: &mut String, emit: &mut impl FnMut(&str, &str)) {
    match value {
        Value::String(s) => emit(path, s),
        Value::Mapping(map) => {
            for (k, v) in map {
                let Some(key) = k.as_str() else { continue };
                let base = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk_placeholders(v, path, emit);
                path.truncate(base);
            }
        }
        Value::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                let base = path.len();
                use std::fmt::Write as _;
                let _ = write!(path, "[{i}]");
                walk_placeholders(v, path, emit);
                path.truncate(base);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Secrets: full-list checks (every entry, not just the first).
// ---------------------------------------------------------------------------

enum SecretRule {
    MinLen(usize),
    ExactLen(usize),
}

impl SecretRule {
    fn recommended(&self) -> String {
        match self {
            SecretRule::MinLen(n) => format!(">={n} random chars"),
            SecretRule::ExactLen(n) => format!("exactly {n} chars"),
        }
    }

    fn satisfied(&self, s: &str) -> bool {
        match self {
            SecretRule::MinLen(n) => s.len() >= *n,
            SecretRule::ExactLen(n) => s.len() == *n,
        }
    }
}

/// Kratos ships `secrets.cookie` (>=16 chars) and `secrets.cipher` (exactly
/// 32 — the xchacha20-poly1305 key size); Hydra ships `secrets.system`
/// (>=16). Every entry is checked, not just the first, since a stale or
/// short entry anywhere in the rotation list is still a live weakness. A
/// list longer than 3 gets a WARN nudging the operator to prune it.
pub(crate) fn check_secret_lists(root: &Value, hydra: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    if hydra {
        findings.extend(check_secret_list(
            root,
            &["secrets", "system"],
            "secrets.system",
            SecretRule::MinLen(16),
            "Hydra system secret",
        ));
    } else {
        findings.extend(check_secret_list(
            root,
            &["secrets", "cookie"],
            "secrets.cookie",
            SecretRule::MinLen(16),
            "Kratos secrets",
        ));
        findings.extend(check_secret_list(
            root,
            &["secrets", "cipher"],
            "secrets.cipher",
            SecretRule::ExactLen(32),
            "Kratos secrets",
        ));
    }
    findings
}

fn check_secret_list(
    root: &Value,
    path: &[&str],
    base_key: &str,
    rule: SecretRule,
    label: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = secret_entries(root, path);
    let impact =
        format!("{label} missing/placeholder/invalid length — sessions/encryption are insecure.");

    if entries.is_empty() {
        findings.push(Finding::fail(
            base_key,
            "<unset/placeholder>",
            &rule.recommended(),
            &impact,
        ));
        return findings;
    }

    for (idx, s) in entries.iter().enumerate() {
        let key = if idx == 0 {
            base_key.to_string()
        } else {
            format!("{base_key}[{idx}]")
        };
        if is_placeholder(s) {
            findings.push(Finding::fail(
                &key,
                "<unset/placeholder>",
                &rule.recommended(),
                &impact,
            ));
        } else if !rule.satisfied(s) {
            findings.push(Finding::fail(
                &key,
                format!("<set, {} chars>", s.len()),
                &rule.recommended(),
                &impact,
            ));
        } else {
            let current = match rule {
                SecretRule::ExactLen(n) => format!("<set, {n} chars>"),
                SecretRule::MinLen(_) => "<set>".to_string(),
            };
            findings.push(Finding::ok(&key, current));
        }
    }

    if entries.len() > 3 {
        findings.push(Finding::warn(
            &format!("{base_key}.count"),
            format!("<{} entries>", entries.len()),
            "<=3 entries",
            "a long rotation list makes bookkeeping harder and raises the odds a stale or compromised entry lingers; prune old entries once rotation completes.",
        ));
    }

    findings
}

// ---------------------------------------------------------------------------
// OIDC upstream providers.
// ---------------------------------------------------------------------------

/// `client_id`/`client_secret` placeholders, `microsoft_tenant: common`
/// (accepts any tenant, not just yours), and `mapper_url` shape/existence,
/// per configured provider. `config_dir` is the directory `kratos.yml`
/// lives in on disk — `mapper_url` is a `file://` path as Kratos's
/// container sees it; the mapper file itself lives alongside kratos.yml.
pub(crate) fn check_oidc_providers(root: &Value, config_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(providers) = dig(
        root,
        &["selfservice", "methods", "oidc", "config", "providers"],
    )
    .and_then(Value::as_sequence) else {
        return findings;
    };

    for (idx, provider) in providers.iter().enumerate() {
        let id = dig_str(provider, &["id"]).unwrap_or("<unnamed>");
        let base = format!("selfservice.methods.oidc.config.providers[{idx}]");

        for field in ["client_id", "client_secret"] {
            let key = format!("{base}.{field}");
            match dig_str(provider, &[field]) {
                Some(v) if !is_placeholder(v) => findings.push(Finding::ok(&key, "<set>")),
                other => findings.push(Finding::fail(
                    &key,
                    other.unwrap_or("<unset>"),
                    "a real value from the provider's OAuth app",
                    &format!(
                        "provider `{id}` has no usable `{field}` — sign-in with {id} will fail at the OAuth handshake."
                    ),
                )),
            }
        }

        if let Some(tenant) = dig_str(provider, &["microsoft_tenant"]) {
            let key = format!("{base}.microsoft_tenant");
            if tenant == "common" {
                findings.push(Finding::fail(
                    &key,
                    "common",
                    "a specific tenant ID (or `organizations`/`consumers` if intentional)",
                    "`common` accepts sign-in from ANY Azure AD tenant or personal Microsoft account — any organization's users can authenticate, not just yours.",
                ));
            } else {
                findings.push(Finding::ok(&key, tenant));
            }
        }

        findings.extend(check_mapper_url(provider, &base, config_dir));
    }

    findings
}

fn check_mapper_url(provider: &Value, base: &str, config_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mapper_key = format!("{base}.mapper_url");

    let Some(url) = dig_str(provider, &["mapper_url"]) else {
        findings.push(Finding::fail(
            &mapper_key,
            "<unset>",
            "a file:// URL to a jsonnet identity mapper",
            "without a mapper, Kratos can't translate this provider's claims into identity traits.",
        ));
        return findings;
    };

    let Some(rest) = url.strip_prefix("file://") else {
        findings.push(Finding::fail(
            &mapper_key,
            url,
            "a file:// URL",
            "mapper_url must be a `file://` path readable inside the Kratos container; other schemes aren't supported by the reference deployment.",
        ));
        return findings;
    };
    findings.push(Finding::ok(&mapper_key, url));

    let basename = rest.rsplit('/').next().unwrap_or(rest);
    let mapper_path = config_dir.join(basename);
    match std::fs::read_to_string(&mapper_path) {
        Ok(content) => {
            if content.contains("email") && !content.contains("email_verified") {
                findings.push(Finding::warn(
                    &format!("{mapper_key}.email_verified"),
                    "emits `email` without `email_verified`",
                    "guard the trait with `claims.email_verified`",
                    "an upstream provider that allows unverified emails lets an attacker claim any address and take over the matching Forseti account — this is a real account-takeover vector, not a cosmetic one.",
                ));
            }
        }
        Err(_) => {
            findings.push(Finding::fail(
                &format!("{mapper_key}.file"),
                mapper_path.display().to_string(),
                "an existing mapper file next to kratos.yml",
                "the referenced OIDC identity mapper file is missing on disk — Kratos will fail to start (or reject the flow) when this provider is used.",
            ));
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Post-oidc-login hooks.
// ---------------------------------------------------------------------------

/// When `oidc` is enabled, both `login` and `registration` need an
/// `after.oidc` hook (at minimum `session`) or a successful upstream
/// sign-in never establishes a Kratos session.
pub(crate) fn check_flow_hooks(root: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    if dig_bool(root, &["selfservice", "methods", "oidc", "enabled"]) != Some(true) {
        return findings;
    }

    for flow in ["login", "registration"] {
        let key = format!("selfservice.flows.{flow}.after.oidc.hooks");
        let has_hooks = dig(
            root,
            &["selfservice", "flows", flow, "after", "oidc", "hooks"],
        )
        .and_then(Value::as_sequence)
        .is_some_and(|seq| !seq.is_empty());
        if has_hooks {
            findings.push(Finding::ok(&key, "<configured>"));
        } else {
            findings.push(Finding::fail(
                &key,
                "<unset>",
                "at least one hook (e.g. `session`)",
                &format!(
                    "oidc is enabled but the {flow} flow has no `after.oidc` hooks — a successful upstream sign-in won't establish (or complete) a Kratos session."
                ),
            ));
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// web_hook auth tokens.
// ---------------------------------------------------------------------------

/// Every `web_hook`'s `api_key` / `Authorization` bearer value, paired with
/// its dotted/bracketed path, in document order. Path strings match
/// `walk_placeholders`'s convention exactly so a FAIL emitted here suppresses
/// the generic placeholder scan's duplicate at the same scalar.
fn collect_hook_tokens(root: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut path = String::new();
    walk_hook_tokens(root, &mut path, &mut out);
    out
}

fn walk_hook_tokens(value: &Value, path: &mut String, out: &mut Vec<(String, String)>) {
    match value {
        Value::Mapping(map) => {
            if dig_str(value, &["auth", "type"]) == Some("api_key")
                && dig_str(value, &["auth", "config", "name"]) == Some("Authorization")
            {
                if let Some(v) = dig_str(value, &["auth", "config", "value"]) {
                    let base = path.len();
                    if !path.is_empty() {
                        path.push('.');
                    }
                    path.push_str("auth.config.value");
                    out.push((path.clone(), v.to_string()));
                    path.truncate(base);
                }
            }
            for (k, v) in map {
                let Some(key) = k.as_str() else { continue };
                let base = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk_hook_tokens(v, path, out);
                path.truncate(base);
            }
        }
        Value::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                let base = path.len();
                use std::fmt::Write as _;
                let _ = write!(path, "[{i}]");
                walk_hook_tokens(v, path, out);
                path.truncate(base);
            }
        }
        _ => {}
    }
}

fn strip_bearer(v: &str) -> String {
    v.strip_prefix("Bearer ").unwrap_or(v).to_string()
}

/// The first `web_hook`'s `api_key`/`Authorization` bearer value in document
/// order, with the `Bearer ` scheme prefix stripped.
pub(crate) fn extract_hook_token(root: &Value) -> Option<String> {
    collect_hook_tokens(root)
        .into_iter()
        .next()
        .map(|(_, v)| strip_bearer(&v))
}

/// FAILs every `web_hook` whose bearer token is still the public
/// dev-playground literal.
pub(crate) fn check_hook_tokens(root: &Value) -> Vec<Finding> {
    collect_hook_tokens(root)
        .into_iter()
        .filter_map(|(path, raw)| {
            let token = strip_bearer(&raw);
            PLACEHOLDER_TOKENS.contains(&token.as_str()).then(|| {
                Finding::fail(
                    &path,
                    "<dev-playground-token-change-me>",
                    "a real per-deployment secret",
                    "this hook still carries the public dev-playground bearer token from the repo; anyone can forge audit webhook calls to Forseti's /internal/audit/kratos receiver.",
                )
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// config.toml cross-link: the audit webhook accept list vs. kratos.yml.
// ---------------------------------------------------------------------------

/// `[audit].webhook_token` as written in `config.toml` — either a bare
/// string or an array (the rotation accept-list form).
pub(crate) fn webhook_token_entries(doc: &DocumentMut) -> Vec<String> {
    let Some(item) = doc
        .get("audit")
        .and_then(|audit| audit.get("webhook_token"))
    else {
        return Vec::new();
    };
    if let Some(s) = item.as_str() {
        return vec![s.to_string()];
    }
    if let Some(arr) = item.as_array() {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    Vec::new()
}

pub(crate) fn load_forseti_toml(path: &Path) -> anyhow::Result<DocumentMut> {
    let display = path.display();
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{display}: {e}"))?;
    text.parse::<DocumentMut>()
        .map_err(|e| anyhow::anyhow!("{display}: invalid TOML: {e}"))
}

/// Cross-checks kratos.yml's `web_hook` bearer token against `config.toml`'s
/// `[audit].webhook_token` accept list. FAILs on a mismatch (the receiver
/// will 401 every Kratos event), WARNs when the accept list has more than
/// one entry (a rotation left mid-flight). No findings when kratos.yml has
/// no `web_hook` to compare against — nothing to cross-check.
pub(crate) fn check_forseti_crosslink(kratos: &Value, doc: &DocumentMut) -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = webhook_token_entries(doc);
    let Some(hook_token) = extract_hook_token(kratos) else {
        return findings;
    };

    if entries.is_empty() {
        findings.push(Finding::fail(
            "audit.webhook_token",
            "<unset>",
            "matching kratos.yml's web_hook Authorization value",
            "the audit receiver's accept list is empty; every Kratos webhook call will 401.",
        ));
    } else if !entries.iter().any(|t| t == &hook_token) {
        findings.push(Finding::fail(
            "audit.webhook_token",
            "<kratos hook token not in accept list>",
            "add kratos.yml's hook token to [audit].webhook_token",
            "kratos.yml's web_hook Authorization value isn't accepted by Forseti's /internal/audit/kratos receiver — audit events will 401.",
        ));
    } else {
        findings.push(Finding::ok(
            "audit.webhook_token",
            format!(
                "<{} accept-list entries, kratos hook token present>",
                entries.len()
            ),
        ));
    }

    if entries.len() > 1 {
        findings.push(Finding::warn(
            "audit.webhook_token.rotation",
            format!("<{} entries>", entries.len()),
            "prune to a single entry once rotation completes",
            "rotation in progress, restart + prune pending",
        ));
    }

    findings
}

/// Strip any `user:pass@` userinfo so credentials never hit stdout/CI logs.
pub(crate) fn redact_uri(uri: &str) -> String {
    if let Some((scheme, rest)) = uri.split_once("://") {
        if let Some((_userinfo, host)) = rest.split_once('@') {
            return format!("{scheme}://***@{host}");
        }
    }
    uri.to_string()
}

// ---------------------------------------------------------------------------
// Rendering + dispatch.
// ---------------------------------------------------------------------------

pub(crate) fn print_finding(f: &Finding) {
    if f.severity == Severity::Ok {
        println!("  {} {} = {}", f.severity.marker(), f.key, f.current);
    } else {
        println!(
            "  {} {} = {} (recommended: {})\n         {}",
            f.severity.marker(),
            f.key,
            f.current,
            f.recommended,
            f.impact
        );
    }
}

/// Resolve a config file path by precedence: explicit `--flag` (clap already
/// merged the env var into this), then the dev default (only if it exists on
/// disk). A flag-supplied path is honoured even if missing (the caller
/// surfaces a "file not found" error on read), but a non-existent default is
/// treated as "no source", returning `Err` so we never silently lint a
/// phantom file.
pub(crate) fn resolve_config_path(
    flag: Option<&Path>,
    default: &str,
    label: &str,
    flag_name: &str,
    env_name: &str,
) -> Result<(PathBuf, String), String> {
    if let Some(p) = flag.filter(|p| !p.as_os_str().is_empty()) {
        return Ok((
            p.to_path_buf(),
            format!("from {flag_name} (or ${env_name})"),
        ));
    }
    if Path::new(default).exists() {
        return Ok((PathBuf::from(default), "dev default".to_string()));
    }
    Err(format!(
        "No {label} config found. Pass {flag_name} <path> or set ${env_name}."
    ))
}

const DEFAULT_FORSETI_TOML: &str = "config.toml";

/// `config.toml` is optional for `check`/`status`: a flag/env value is
/// honoured even if missing (the caller reports the read error), but with
/// neither set we only use the dev default when it actually exists on disk
/// — no finding at all when there's no config.toml to check against.
pub(crate) fn resolve_forseti_toml_path(flag: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = flag.filter(|p| !p.as_os_str().is_empty()) {
        return Some(p.to_path_buf());
    }
    Path::new(DEFAULT_FORSETI_TOML)
        .exists()
        .then(|| PathBuf::from(DEFAULT_FORSETI_TOML))
}

pub(crate) fn check(args: &CheckArgs) -> i32 {
    let strict = args.strict;

    let kratos = resolve_config_path(
        args.paths.kratos.as_deref(),
        DEFAULT_KRATOS,
        "Kratos",
        "--kratos",
        ENV_KRATOS,
    );
    let hydra = resolve_config_path(
        args.paths.hydra.as_deref(),
        DEFAULT_HYDRA,
        "Hydra",
        "--hydra",
        ENV_HYDRA,
    );

    let mut total_warn = 0usize;
    let mut total_fail = 0usize;

    let forseti_doc = match resolve_forseti_toml_path(args.paths.forseti_config.as_deref()) {
        Some(p) => match load_forseti_toml(&p) {
            Ok(doc) => Some(doc),
            Err(e) => {
                total_fail += 1;
                println!("== Forseti config ({}) ==", p.display());
                println!("  {} could not read/parse: {e}", Severity::Fail.marker());
                println!();
                None
            }
        },
        None => None,
    };

    for (label, resolved, checker) in [
        ("Kratos", kratos, check_kratos as fn(&Value) -> Vec<Finding>),
        ("Hydra", hydra, check_hydra as fn(&Value) -> Vec<Finding>),
    ] {
        let (path, source) = match resolved {
            Ok(r) => r,
            Err(msg) => {
                total_fail += 1;
                println!("== {label} ==");
                println!("  {} {msg}", Severity::Fail.marker());
                println!();
                continue;
            }
        };

        println!("== {label} ({} — {source}) ==", path.display());
        match load_yaml(&path) {
            Ok(root) => {
                let mut findings = checker(&root);
                if label == "Kratos" {
                    let config_dir = path
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."));
                    findings.extend(check_oidc_providers(&root, config_dir));
                    if let Some(doc) = &forseti_doc {
                        findings.extend(check_forseti_crosslink(&root, doc));
                    }
                }
                for f in &findings {
                    match f.severity {
                        Severity::Warn => total_warn += 1,
                        Severity::Fail => total_fail += 1,
                        Severity::Ok => {}
                    }
                }
                for f in &findings {
                    print_finding(f);
                }
            }
            Err(e) => {
                total_fail += 1;
                println!("  {} could not read/parse: {e}", Severity::Fail.marker());
            }
        }
        println!();
    }

    println!("Summary: {total_fail} FAIL, {total_warn} WARN");
    if total_fail > 0 || (strict && total_warn > 0) {
        1
    } else {
        0
    }
}

fn state_marker(state: &str) -> &'static str {
    match state {
        "ok" => "[ OK ]",
        "missing" => "[MISS]",
        "placeholder" => "[PLHD]",
        "dev" => "[ DEV]",
        "warn" => "[WARN]",
        "fail" => "[FAIL]",
        "rotation-pending" => "[ROTP]",
        _ => "[ ?? ]",
    }
}

/// `config status [--json]`: same file resolution as `check` (kratos/hydra
/// required-resolvable, forseti.toml optional), rendered either as a text
/// table grouped by `Setting.group` or as JSON. Exits non-zero only when
/// kratos.yml/hydra.yml can't be resolved/read — the settings themselves
/// are reported regardless of their state.
pub(crate) fn status(paths: &PathArgs, json: bool) -> i32 {
    let kratos_path = match resolve_config_path(
        paths.kratos.as_deref(),
        DEFAULT_KRATOS,
        "Kratos",
        "--kratos",
        ENV_KRATOS,
    ) {
        Ok((p, _)) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };
    let hydra_path = match resolve_config_path(
        paths.hydra.as_deref(),
        DEFAULT_HYDRA,
        "Hydra",
        "--hydra",
        ENV_HYDRA,
    ) {
        Ok((p, _)) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    let kratos_root = match load_yaml(&kratos_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: {e}", kratos_path.display());
            return 1;
        }
    };
    let hydra_root = match load_yaml(&hydra_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: {e}", hydra_path.display());
            return 1;
        }
    };

    let forseti_doc = resolve_forseti_toml_path(paths.forseti_config.as_deref())
        .and_then(|p| load_forseti_toml(&p).ok());

    let config_dir = kratos_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let statuses = catalog::status_of(&kratos_root, &hydra_root, forseti_doc.as_ref(), config_dir);

    if json {
        match serde_json::to_string_pretty(&statuses) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
        return 0;
    }

    let mut current_group: Option<&str> = None;
    for setting in catalog::SETTINGS {
        let Some(s) = statuses.iter().find(|s| s.key == setting.key) else {
            continue;
        };
        if current_group != Some(setting.group) {
            if current_group.is_some() {
                println!();
            }
            println!("== {} ==", setting.group);
            current_group = Some(setting.group);
        }
        println!(
            "  {} {:<24} {:<32} [{}] {}",
            state_marker(&s.state),
            setting.key,
            setting.title,
            setting.targets.join(", "),
            s.detail
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Value {
        serde_yaml_ng::from_str(yaml).expect("test yaml parses")
    }

    fn severity_of(findings: &[Finding], key: &str) -> Option<Severity> {
        findings.iter().find(|f| f.key == key).map(|f| f.severity)
    }

    #[test]
    fn resolve_flag_wins_over_default() {
        // clap already merges flag > env before this function runs; it only
        // adds the exists-check on the default.
        let (path, source) = resolve_config_path(
            Some(Path::new("/flag/kratos.yml")),
            DEFAULT_KRATOS,
            "Kratos",
            "--kratos",
            ENV_KRATOS,
        )
        .expect("flag resolves");
        assert_eq!(path, PathBuf::from("/flag/kratos.yml"));
        assert_eq!(source, format!("from --kratos (or ${ENV_KRATOS})"));
    }

    #[test]
    fn resolve_default_used_when_it_exists() {
        // Cargo runs tests from the crate root, where infra/ exists.
        let (path, source) =
            resolve_config_path(None, DEFAULT_KRATOS, "Kratos", "--kratos", ENV_KRATOS)
                .expect("dev default exists at crate root");
        assert_eq!(path, PathBuf::from(DEFAULT_KRATOS));
        assert_eq!(source, "dev default");
    }

    #[test]
    fn resolve_nothing_found_is_err() {
        let err = resolve_config_path(None, "does/not/exist.yml", "Kratos", "--kratos", ENV_KRATOS)
            .expect_err("missing everything should error");
        assert!(err.contains("--kratos"));
        assert!(err.contains(ENV_KRATOS));
    }

    #[test]
    fn settings_aal_wrong_is_fail() {
        let v = parse(
            r#"
selfservice:
  flows:
    settings:
      required_aal: aal1
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "selfservice.flows.settings.required_aal"),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn whoami_aal_wrong_is_warn() {
        let v = parse(
            r#"
session:
  whoami:
    required_aal: aal1
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "session.whoami.required_aal"),
            Some(Severity::Warn)
        );
    }

    #[test]
    fn lookup_secret_disabled_is_warn() {
        let v = parse(
            r#"
selfservice:
  methods:
    lookup_secret:
      enabled: false
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "selfservice.methods.lookup_secret.enabled"),
            Some(Severity::Warn)
        );
    }

    #[test]
    fn cipher_wrong_length_is_fail() {
        let v = parse(
            r#"
secrets:
  cipher:
    - too-short
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "secrets.cipher"),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn webauthn_passwordless_true_is_warn() {
        let v = parse(
            r#"
selfservice:
  methods:
    webauthn:
      enabled: true
      config:
        passwordless: true
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(
                &findings,
                "selfservice.methods.webauthn.config.passwordless"
            ),
            Some(Severity::Warn)
        );
    }

    #[test]
    fn good_kratos_has_no_warn_or_fail() {
        let v = parse(
            r#"
session:
  whoami:
    required_aal: highest_available
selfservice:
  flows:
    settings:
      required_aal: highest_available
    recovery:
      enabled: true
  methods:
    lookup_secret:
      enabled: true
    webauthn:
      enabled: true
      config:
        passwordless: false
secrets:
  cookie:
    - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  cipher:
    - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
courier:
  smtp:
    connection_uri: smtps://user:pass@smtp.example.com:465
"#,
        );
        let findings = check_kratos(&v);
        let bad: Vec<_> = findings
            .iter()
            .filter(|f| f.severity != Severity::Ok)
            .collect();
        assert!(bad.is_empty(), "expected all OK, got: {bad:?}");
    }

    #[test]
    fn generic_scan_fails_on_leftover_changeme() {
        let v = parse(
            r#"
session:
  whoami:
    required_aal: highest_available
selfservice:
  flows:
    settings:
      required_aal: highest_available
    recovery:
      enabled: true
  methods:
    lookup_secret:
      enabled: true
    webauthn:
      enabled: true
      config:
        passwordless: false
        rp:
          id: CHANGEME_RP_ID
secrets:
  cookie:
    - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  cipher:
    - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
courier:
  smtp:
    connection_uri: smtps://user:pass@smtp.example.com:465
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "selfservice.methods.webauthn.config.rp.id"),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn smtp_placeholder_not_double_reported() {
        // A CHANGEME SMTP URI is covered by the specific SMTP check (WARN); the
        // generic scan must not also emit a FAIL for the same key path.
        let v = parse(
            r#"
courier:
  smtp:
    connection_uri: CHANGEME_SMTP_URI
"#,
        );
        let findings = check_kratos(&v);
        let smtp: Vec<_> = findings
            .iter()
            .filter(|f| f.key == "courier.smtp.connection_uri")
            .collect();
        assert_eq!(smtp.len(), 1, "exactly one finding for the SMTP key");
        assert_eq!(smtp[0].severity, Severity::Warn);
    }

    #[test]
    fn cipher_changeme_produces_exactly_one_finding() {
        let v = parse(
            r#"
secrets:
  cipher:
    - CHANGEME_KRATOS_CIPHER
"#,
        );
        let findings = check_kratos(&v);
        let cipher: Vec<_> = findings
            .iter()
            .filter(|f| f.key.starts_with("secrets.cipher"))
            .collect();
        assert_eq!(
            cipher.len(),
            1,
            "expected one cipher finding, got: {cipher:?}"
        );
        assert_eq!(cipher[0].severity, Severity::Fail);
    }

    #[test]
    fn oidc_provider_changeme_client_id_produces_exactly_one_finding() {
        // client_id/client_secret placeholders are check_oidc_providers's job;
        // the generic placeholder walk (run inside check_kratos) must skip the
        // providers subtree entirely so the two don't both FAIL the same key.
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: google
            provider: google
            client_id: CHANGEME_GOOGLE_CLIENT_ID
            client_secret: real-secret
            mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
"#,
        );
        let mut findings = check_kratos(&v);
        findings.extend(check_oidc_providers(&v, Path::new("/nonexistent")));
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.key == "selfservice.methods.oidc.config.providers[0].client_id")
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one finding for client_id, got: {matches:?}"
        );
        assert_eq!(matches[0].severity, Severity::Fail);
    }

    #[test]
    fn oidc_provider_issuer_url_and_client_id_placeholders_produce_one_each() {
        // issuer_url is NOT handled by check_oidc_providers, so the generic
        // placeholder walk must catch it. The fix narrows the skip to only the
        // four fields check_oidc_providers validates (client_id, client_secret,
        // microsoft_tenant, mapper_url), allowing issuer_url to be checked.
        // A provider with both should yield exactly one finding per field.
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: custom
            provider: generic
            client_id: CHANGEME_CUSTOM_CLIENT_ID
            client_secret: real-secret
            issuer_url: CHANGEME_ISSUER
            mapper_url: file:///etc/config/kratos/oidc.custom.jsonnet
"#,
        );
        let mut findings = check_kratos(&v);
        findings.extend(check_oidc_providers(&v, Path::new("/nonexistent")));

        let issuer_matches: Vec<_> = findings
            .iter()
            .filter(|f| f.key == "selfservice.methods.oidc.config.providers[0].issuer_url")
            .collect();
        assert_eq!(
            issuer_matches.len(),
            1,
            "expected exactly one finding for issuer_url, got: {issuer_matches:?}"
        );
        assert_eq!(issuer_matches[0].severity, Severity::Fail);

        let client_id_matches: Vec<_> = findings
            .iter()
            .filter(|f| f.key == "selfservice.methods.oidc.config.providers[0].client_id")
            .collect();
        assert_eq!(
            client_id_matches.len(),
            1,
            "expected exactly one finding for client_id, got: {client_id_matches:?}"
        );
        assert_eq!(client_id_matches[0].severity, Severity::Fail);
    }

    #[test]
    fn cookie_changeme_produces_exactly_one_finding() {
        let v = parse(
            r#"
secrets:
  cookie:
    - CHANGEME_KRATOS_COOKIE
"#,
        );
        let findings = check_kratos(&v);
        let cookie: Vec<_> = findings
            .iter()
            .filter(|f| f.key.starts_with("secrets.cookie"))
            .collect();
        assert_eq!(
            cookie.len(),
            1,
            "expected one cookie finding, got: {cookie:?}"
        );
        assert_eq!(cookie[0].severity, Severity::Fail);
    }

    #[test]
    fn smtp_placeholder_host_warns() {
        let v = parse(
            r#"
courier:
  smtp:
    connection_uri: smtp://placeholder-smtp:1025
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "courier.smtp.connection_uri"),
            Some(Severity::Warn),
        );
    }

    #[test]
    fn short_secret_fails() {
        let v = parse(
            r#"
secrets:
  cookie:
    - short
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "secrets.cookie"),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn empty_flag_value_falls_through() {
        let err = resolve_config_path(
            Some(Path::new("")),
            "does/not/exist.yml",
            "Kratos",
            "--kratos",
            ENV_KRATOS,
        )
        .expect_err("empty flag must fall through to error");
        assert!(err.contains("--kratos"));
    }

    fn unique_tmp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("forseti-check-{}-{label}", std::process::id()))
    }

    // -----------------------------------------------------------------
    // Placeholder scan: now case-insensitive + dev token literal.
    // -----------------------------------------------------------------

    #[test]
    fn lowercase_changeme_is_now_caught() {
        let v = parse(
            r#"
selfservice:
  methods:
    webauthn:
      enabled: true
      config:
        rp:
          id: changeme_rp_id
"#,
        );
        let findings = check_kratos(&v);
        assert_eq!(
            severity_of(&findings, "selfservice.methods.webauthn.config.rp.id"),
            Some(Severity::Fail)
        );
    }

    // -----------------------------------------------------------------
    // check_secret_lists: full-list checks.
    // -----------------------------------------------------------------

    #[test]
    fn second_cipher_entry_of_wrong_length_fails() {
        let v = parse(
            r#"
secrets:
  cipher:
    - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    - too-short
"#,
        );
        let findings = check_secret_lists(&v, false);
        assert_eq!(severity_of(&findings, "secrets.cipher"), Some(Severity::Ok));
        assert_eq!(
            severity_of(&findings, "secrets.cipher[1]"),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn more_than_three_secret_entries_warns() {
        let v = parse(
            r#"
secrets:
  system:
    - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    - cccccccccccccccccccccccccccccccc
    - dddddddddddddddddddddddddddddddd
"#,
        );
        let findings = check_secret_lists(&v, true);
        assert_eq!(
            severity_of(&findings, "secrets.system.count"),
            Some(Severity::Warn)
        );
    }

    // -----------------------------------------------------------------
    // check_oidc_providers.
    // -----------------------------------------------------------------

    #[test]
    fn microsoft_tenant_common_fails() {
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: microsoft
            provider: microsoft
            client_id: real-client-id
            client_secret: real-client-secret
            microsoft_tenant: common
            mapper_url: file:///etc/config/kratos/oidc.microsoft.jsonnet
"#,
        );
        let findings = check_oidc_providers(&v, Path::new("/nonexistent"));
        assert_eq!(
            severity_of(
                &findings,
                "selfservice.methods.oidc.config.providers[0].microsoft_tenant"
            ),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn provider_placeholder_client_id_fails() {
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: google
            provider: google
            client_id: CHANGEME_GOOGLE_CLIENT_ID
            client_secret: real-secret
            mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
"#,
        );
        let findings = check_oidc_providers(&v, Path::new("/nonexistent"));
        assert_eq!(
            severity_of(
                &findings,
                "selfservice.methods.oidc.config.providers[0].client_id"
            ),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn mapper_url_without_file_scheme_fails() {
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: google
            provider: google
            client_id: real-id
            client_secret: real-secret
            mapper_url: https://example.com/mapper.jsonnet
"#,
        );
        let findings = check_oidc_providers(&v, Path::new("/nonexistent"));
        assert_eq!(
            severity_of(
                &findings,
                "selfservice.methods.oidc.config.providers[0].mapper_url"
            ),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn mapper_url_missing_file_fails() {
        let dir = unique_tmp_dir("mapper-missing");
        std::fs::create_dir_all(&dir).unwrap();
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: google
            provider: google
            client_id: real-id
            client_secret: real-secret
            mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
"#,
        );
        let findings = check_oidc_providers(&v, &dir);
        assert_eq!(
            severity_of(
                &findings,
                "selfservice.methods.oidc.config.providers[0].mapper_url.file"
            ),
            Some(Severity::Fail)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mapper_without_email_verified_guard_warns() {
        let dir = unique_tmp_dir("mapper-unsafe");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("oidc.google.jsonnet"),
            "local claims = std.extVar('claims');\n{ identity: { traits: { email: claims.email } } }\n",
        )
        .unwrap();
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: google
            provider: google
            client_id: real-id
            client_secret: real-secret
            mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
"#,
        );
        let findings = check_oidc_providers(&v, &dir);
        assert_eq!(
            severity_of(
                &findings,
                "selfservice.methods.oidc.config.providers[0].mapper_url.email_verified"
            ),
            Some(Severity::Warn)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mapper_with_email_verified_guard_is_clean() {
        let dir = unique_tmp_dir("mapper-safe");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("oidc.google.jsonnet"),
            "local claims = std.extVar('claims');\n{ identity: { traits: { email: if claims.email_verified then claims.email else null } } }\n",
        )
        .unwrap();
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: google
            provider: google
            client_id: real-id
            client_secret: real-secret
            mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
"#,
        );
        let findings = check_oidc_providers(&v, &dir);
        assert!(
            findings.iter().all(|f| f.severity != Severity::Warn),
            "expected no WARN, got: {findings:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------
    // check_flow_hooks.
    // -----------------------------------------------------------------

    #[test]
    fn enabled_oidc_without_after_hooks_fails() {
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      enabled: true
  flows:
    login:
      after: {}
    registration:
      after: {}
"#,
        );
        let findings = check_flow_hooks(&v);
        assert_eq!(
            severity_of(&findings, "selfservice.flows.login.after.oidc.hooks"),
            Some(Severity::Fail)
        );
        assert_eq!(
            severity_of(&findings, "selfservice.flows.registration.after.oidc.hooks"),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn enabled_oidc_with_after_hooks_is_ok() {
        let v = parse(
            r#"
selfservice:
  methods:
    oidc:
      enabled: true
  flows:
    login:
      after:
        oidc:
          hooks:
            - hook: session
    registration:
      after:
        oidc:
          hooks:
            - hook: session
"#,
        );
        let findings = check_flow_hooks(&v);
        assert_eq!(
            severity_of(&findings, "selfservice.flows.login.after.oidc.hooks"),
            Some(Severity::Ok)
        );
    }

    #[test]
    fn oidc_disabled_produces_no_flow_hook_findings() {
        let v = parse("selfservice:\n  methods:\n    oidc:\n      enabled: false\n");
        assert!(check_flow_hooks(&v).is_empty());
    }

    // -----------------------------------------------------------------
    // check_hook_tokens / extract_hook_token.
    // -----------------------------------------------------------------

    const HOOK_FIXTURE: &str = r#"
selfservice:
  flows:
    settings:
      after:
        password:
          hooks:
            - hook: web_hook
              config:
                url: http://host.docker.internal:8081/internal/audit/kratos?action=password.changed
                auth:
                  type: api_key
                  config:
                    name: Authorization
                    value: "Bearer dev-playground-token-change-me"
                    in: header
"#;

    #[test]
    fn dev_token_fails() {
        let v = parse(HOOK_FIXTURE);
        let findings = check_hook_tokens(&v);
        assert_eq!(
            severity_of(
                &findings,
                "selfservice.flows.settings.after.password.hooks[0].config.auth.config.value"
            ),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn dev_token_is_suppressed_from_generic_scan() {
        let v = parse(HOOK_FIXTURE);
        let findings = check_kratos(&v);
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.key.contains("auth.config.value"))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one finding for the hook token, got: {matches:?}"
        );
    }

    #[test]
    fn extract_hook_token_strips_bearer_prefix() {
        let v = parse(HOOK_FIXTURE);
        assert_eq!(
            extract_hook_token(&v).as_deref(),
            Some("dev-playground-token-change-me")
        );
    }

    #[test]
    fn extract_hook_token_none_when_absent() {
        let v = parse("selfservice: {}\n");
        assert_eq!(extract_hook_token(&v), None);
    }

    #[test]
    fn real_hook_token_does_not_fail() {
        let v = parse(
            r#"
selfservice:
  flows:
    settings:
      after:
        password:
          hooks:
            - hook: web_hook
              config:
                auth:
                  type: api_key
                  config:
                    name: Authorization
                    value: "Bearer a-real-per-deployment-secret"
"#,
        );
        assert!(check_hook_tokens(&v).is_empty());
    }

    // -----------------------------------------------------------------
    // config.toml cross-link.
    // -----------------------------------------------------------------

    fn toml_doc(s: &str) -> DocumentMut {
        s.parse().expect("test toml parses")
    }

    #[test]
    fn kratos_token_missing_from_accept_list_fails() {
        let kratos = parse(HOOK_FIXTURE);
        let doc = toml_doc("[audit]\nwebhook_token = \"some-other-token\"\n");
        let findings = check_forseti_crosslink(&kratos, &doc);
        assert_eq!(
            severity_of(&findings, "audit.webhook_token"),
            Some(Severity::Fail)
        );
    }

    #[test]
    fn two_entry_accept_list_warns_rotation_pending() {
        let kratos = parse(HOOK_FIXTURE);
        let doc = toml_doc(
            "[audit]\nwebhook_token = [\"dev-playground-token-change-me\", \"new-token\"]\n",
        );
        let findings = check_forseti_crosslink(&kratos, &doc);
        assert_eq!(
            severity_of(&findings, "audit.webhook_token"),
            Some(Severity::Ok)
        );
        assert_eq!(
            severity_of(&findings, "audit.webhook_token.rotation"),
            Some(Severity::Warn)
        );
    }

    #[test]
    fn matching_single_entry_accept_list_is_ok() {
        let kratos = parse(HOOK_FIXTURE);
        let doc = toml_doc("[audit]\nwebhook_token = \"dev-playground-token-change-me\"\n");
        let findings = check_forseti_crosslink(&kratos, &doc);
        assert_eq!(
            severity_of(&findings, "audit.webhook_token"),
            Some(Severity::Ok)
        );
        assert!(!findings.iter().any(|f| f.key.ends_with(".rotation")));
    }

    #[test]
    fn crosslink_is_empty_when_kratos_has_no_hooks() {
        let kratos = parse("selfservice: {}\n");
        let doc = toml_doc("[audit]\nwebhook_token = \"whatever\"\n");
        assert!(check_forseti_crosslink(&kratos, &doc).is_empty());
    }

    #[test]
    fn webhook_token_entries_reads_string_and_array_forms() {
        let single = toml_doc("[audit]\nwebhook_token = \"a\"\n");
        assert_eq!(webhook_token_entries(&single), vec!["a".to_string()]);

        let many = toml_doc("[audit]\nwebhook_token = [\"a\", \"b\"]\n");
        assert_eq!(
            webhook_token_entries(&many),
            vec!["a".to_string(), "b".to_string()]
        );

        let absent = toml_doc("[other]\nkey = \"x\"\n");
        assert!(webhook_token_entries(&absent).is_empty());
    }

    #[test]
    fn load_forseti_toml_reads_a_real_file() {
        let dir = unique_tmp_dir("forseti-toml");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "[audit]\nwebhook_token = \"a\"\n").unwrap();

        let doc = load_forseti_toml(&path).expect("reads and parses");
        assert_eq!(webhook_token_entries(&doc), vec!["a".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_forseti_toml_errors_on_missing_file() {
        let err = load_forseti_toml(Path::new("/does/not/exist/config.toml")).unwrap_err();
        assert!(err.to_string().contains("does/not/exist"));
    }
}
