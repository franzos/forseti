//! `config-check` / `config-init` operator subcommands. Kratos's API exposes
//! no live settings (only a version + opaque hash), so these lint/generate the
//! config FILES directly.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use rand::distr::Alphanumeric;
use rand::Rng;
use serde_yaml_ng::Value;

const DEFAULT_KRATOS: &str = "infra/kratos/kratos.yml";
const DEFAULT_HYDRA: &str = "infra/hydra/hydra.yml";

const ENV_KRATOS: &str = "FORSETI_KRATOS_CONFIG";
const ENV_HYDRA: &str = "FORSETI_HYDRA_CONFIG";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Severity {
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
struct Finding {
    severity: Severity,
    key: String,
    current: String,
    recommended: String,
    impact: String,
}

impl Finding {
    fn ok(key: &str, current: impl Into<String>) -> Self {
        Finding {
            severity: Severity::Ok,
            key: key.to_string(),
            current: current.into(),
            recommended: String::new(),
            impact: String::new(),
        }
    }

    fn warn(key: &str, current: impl Into<String>, recommended: &str, impact: &str) -> Self {
        Finding {
            severity: Severity::Warn,
            key: key.to_string(),
            current: current.into(),
            recommended: recommended.to_string(),
            impact: impact.to_string(),
        }
    }

    fn fail(key: &str, current: impl Into<String>, recommended: &str, impact: &str) -> Self {
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
// YAML navigation helpers (mirror how the codebase walks serde_json::Value).
// ---------------------------------------------------------------------------

fn dig<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = root;
    for key in path {
        cur = cur.get(*key)?;
    }
    Some(cur)
}

fn dig_str<'a>(root: &'a Value, path: &[&str]) -> Option<&'a str> {
    dig(root, path).and_then(Value::as_str)
}

fn dig_bool(root: &Value, path: &[&str]) -> Option<bool> {
    dig(root, path).and_then(Value::as_bool)
}

/// A YAML string that is empty, missing, or an obvious placeholder isn't a
/// real secret/URL. Case-insensitive substring match against known tells.
fn is_placeholder(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    const TELLS: &[&str] = &[
        "change-me",
        "changeme",
        "change_me",
        "please-change",
        "not-secure",
        "not-a-secret",
        "secret-here",
        "your-secret",
        "example-secret",
        "todo",
    ];
    TELLS.iter().any(|t| lower.contains(t))
}

/// Kratos `secrets.*` are sequences of strings. Pull the first entry.
fn first_secret<'a>(root: &'a Value, path: &[&str]) -> Option<&'a str> {
    match dig(root, path) {
        Some(Value::Sequence(seq)) => seq.first().and_then(Value::as_str),
        Some(Value::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Check logic — operates on parsed Values so it's testable without the FS.
// ---------------------------------------------------------------------------

fn check_kratos(root: &Value) -> Vec<Finding> {
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

    // selfservice.flows.settings.required_aal — the critical one.
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

    // webauthn passwordless — only relevant when webauthn is enabled.
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

    // secrets.cookie
    match first_secret(root, &["secrets", "cookie"]) {
        Some(s) if !is_placeholder(s) && s.len() >= 16 => {
            findings.push(Finding::ok("secrets.cookie", "<set>"));
        }
        _ => findings.push(Finding::fail(
            "secrets.cookie",
            "<unset/placeholder>",
            ">=16 random chars",
            "Kratos secrets missing/placeholder/invalid length — sessions/encryption are insecure.",
        )),
    }

    // secrets.cipher — must be exactly 32 chars.
    match first_secret(root, &["secrets", "cipher"]) {
        Some(s) if !is_placeholder(s) && s.len() == 32 => {
            findings.push(Finding::ok("secrets.cipher", "<set, 32 chars>"));
        }
        Some(s) if s.len() != 32 => findings.push(Finding::fail(
            "secrets.cipher",
            format!("<set, {} chars>", s.len()),
            "exactly 32 chars",
            "Kratos secrets missing/placeholder/invalid length — sessions/encryption are insecure.",
        )),
        _ => findings.push(Finding::fail(
            "secrets.cipher",
            "<unset/placeholder>",
            "exactly 32 chars",
            "Kratos secrets missing/placeholder/invalid length — sessions/encryption are insecure.",
        )),
    }

    findings.extend(placeholder_findings(root, &findings));
    findings
}

fn check_hydra(root: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    // secrets.system
    match first_secret(root, &["secrets", "system"]) {
        Some(s) if !is_placeholder(s) && s.len() >= 16 => {
            findings.push(Finding::ok("secrets.system", "<set>"));
        }
        _ => findings.push(Finding::fail(
            "secrets.system",
            "<unset/placeholder>",
            ">=16 random chars",
            "Hydra system secret missing/placeholder — token signing/encryption are insecure.",
        )),
    }

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

    // urls.login / urls.consent / urls.logout — should point at Forseti.
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

/// Scan every scalar for a leftover `CHANGEME` placeholder and FAIL on each.
/// `already` covers keys the specific checks handled; a specific finding whose
/// key is a prefix of the scalar's path (e.g. `secrets.cipher` vs the scalar at
/// `secrets.cipher[0]`) suppresses the generic one so we don't double-report.
fn placeholder_findings(root: &Value, already: &[Finding]) -> Vec<Finding> {
    let mut out = Vec::new();
    walk_placeholders(root, &mut String::new(), &mut |path, value| {
        let covered = already
            .iter()
            .any(|f| path == f.key || path.starts_with(&format!("{}[", f.key)));
        if value.contains("CHANGEME") && !covered {
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

/// Dev mailboxes: the playground mailcrab, or any obvious test placeholder.
fn is_dev_smtp(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    lower.contains("mailslurper")
        || lower.contains("mailcrab")
        || lower.contains("test")
        || lower.contains("change-me")
        || lower.contains("changeme")
        || lower.contains("placeholder")
}

/// Strip any `user:pass@` userinfo so credentials never hit stdout/CI logs.
fn redact_uri(uri: &str) -> String {
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

fn print_finding(f: &Finding) {
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

fn parse_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            // Don't swallow the next flag as this one's value (`--x --force`).
            return it
                .next()
                .map(String::as_str)
                .filter(|v| !v.starts_with("--"));
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v);
        }
    }
    None
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

/// Resolve a config file path by precedence: explicit `--flag`, then env var,
/// then the dev default (only if it exists on disk). A path from the flag or
/// env is honoured even if missing (the caller surfaces a "file not found"
/// error on read) — but a non-existent default is treated as "no source",
/// returning `Err` so we never silently lint a phantom file.
fn resolve_config_path(
    flag: Option<&str>,
    env_value: Option<String>,
    default: &str,
    label: &str,
    flag_name: &str,
    env_name: &str,
) -> Result<(PathBuf, String), String> {
    if let Some(p) = flag.filter(|s| !s.is_empty()) {
        return Ok((PathBuf::from(p), format!("from {flag_name}")));
    }
    if let Some(p) = env_value.filter(|s| !s.is_empty()) {
        return Ok((PathBuf::from(p), format!("from ${env_name}")));
    }
    if Path::new(default).exists() {
        return Ok((PathBuf::from(default), "dev default".to_string()));
    }
    Err(format!(
        "No {label} config found. Pass {flag_name} <path> or set ${env_name}."
    ))
}

pub(crate) fn check(args: &[String]) -> i32 {
    if wants_help(args) {
        print_check_help();
        return 0;
    }

    let strict = has_flag(args, "--strict");

    let kratos = resolve_config_path(
        parse_flag(args, "--kratos"),
        std::env::var(ENV_KRATOS).ok(),
        DEFAULT_KRATOS,
        "Kratos",
        "--kratos",
        ENV_KRATOS,
    );
    let hydra = resolve_config_path(
        parse_flag(args, "--hydra"),
        std::env::var(ENV_HYDRA).ok(),
        DEFAULT_HYDRA,
        "Hydra",
        "--hydra",
        ENV_HYDRA,
    );

    let mut total_warn = 0usize;
    let mut total_fail = 0usize;

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
                let findings = checker(&root);
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

fn print_check_help() {
    println!(
        "forseti config-check — lint Kratos + Hydra config FILES against Forseti's recommendations

USAGE: forseti config-check [OPTIONS]

OPTIONS:
  --kratos <path>   Kratos config file
  --hydra <path>    Hydra config file
  --strict          also exit non-zero on WARN (not just FAIL)
  -h, --help        print this help

CONFIG DISCOVERY (per file, highest precedence first):
  1. --kratos / --hydra flag
  2. ${ENV_KRATOS} / ${ENV_HYDRA} env var
  3. dev default ({DEFAULT_KRATOS} / {DEFAULT_HYDRA}) — only if it exists
  If none resolves to a file, config-check errors and exits non-zero.

EXIT CODES:
  0  no FAIL (and no WARN under --strict)
  1  any FAIL, or any WARN under --strict, or no config source found"
    );
}

fn load_yaml(path: &Path) -> anyhow::Result<Value> {
    let display = path.display();
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{display}: {e}"))?;
    let value: Value = serde_yaml_ng::from_str(&text)
        .map_err(|e| anyhow::anyhow!("{display}: invalid YAML: {e}"))?;
    Ok(value)
}

// ---------------------------------------------------------------------------
// config-init — generate a recommended Kratos + Hydra config.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InitInputs {
    forseti_url: Option<String>,
    kratos_public_url: Option<String>,
    kratos_admin_url: Option<String>,
    hydra_public_url: Option<String>,
    hydra_admin_url: Option<String>,
    kratos_db_dsn: Option<String>,
    hydra_db_dsn: Option<String>,
    smtp_uri: Option<String>,
}

/// Quote an operator value as a safe single-line YAML double-quoted scalar so
/// it can't break out of scalar position and inject sibling keys. Hand-rolled
/// because serde_yaml_ng emits a multi-line block scalar for newline-bearing
/// strings, which would be invalid inline; `validate_inputs` rejects those
/// anyway, but the escaping keeps this robust on its own.
fn yaml_scalar(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Reject operator values carrying control chars or newlines before they reach
/// the templated YAML — single-line URLs/DSNs/SMTP URIs never need them, and
/// they're the vector for scalar-breakout key injection.
fn reject_control_chars(label: &str, value: &str) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err(format!(
            "invalid value for {label}: control characters not allowed"
        ));
    }
    Ok(())
}

/// CSPRNG-backed alphanumeric secret of exactly `len` chars. `rand::rng()` is
/// `ThreadRng`, seeded from the OS RNG — same source the rest of the crate
/// uses for tokens (`csrf.rs`, `dcr_tokens.rs`).
fn random_secret(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// A required connection value: either the operator's flag, or a loud
/// `CHANGEME_*` placeholder that `config-check` will FAIL on.
fn or_placeholder(opt: &Option<String>, thing: &str) -> (String, bool) {
    match opt {
        Some(v) => (v.clone(), false),
        None => (format!("CHANGEME_{thing}"), true),
    }
}

fn trim_trailing_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// WebAuthn `rp.id` is the deployment host. Derive it from `--forseti-url`'s
/// host; `None` when the URL is absent, unparseable, or host-less.
fn rp_id_from(forseti_url: Option<&str>) -> Option<String> {
    let raw = forseti_url?;
    url::Url::parse(raw).ok()?.host_str().map(str::to_string)
}

/// Reject any operator-supplied value carrying control chars before it reaches
/// the templated YAML (scalar-breakout injection vector).
fn validate_inputs(inputs: &InitInputs) -> Result<(), String> {
    let checks = [
        ("--forseti-url", &inputs.forseti_url),
        ("--kratos-public-url", &inputs.kratos_public_url),
        ("--kratos-admin-url", &inputs.kratos_admin_url),
        ("--hydra-public-url", &inputs.hydra_public_url),
        ("--hydra-admin-url", &inputs.hydra_admin_url),
        ("--kratos-db-dsn", &inputs.kratos_db_dsn),
        ("--hydra-db-dsn", &inputs.hydra_db_dsn),
        ("--smtp-uri", &inputs.smtp_uri),
    ];
    for (label, opt) in checks {
        if let Some(v) = opt {
            reject_control_chars(label, v)?;
        }
    }
    Ok(())
}

/// Build both config files as strings (`missing` lists CHANGEME placeholders).
/// Caller validates inputs via `validate_inputs`; values are interpolated as
/// quoted YAML scalars. Separated from I/O so the round-trip test can lint it.
fn render_configs(inputs: &InitInputs) -> (String, String, Vec<String>) {
    let mut missing = Vec::new();
    let mut note_missing = |placeheld: bool, what: &str| {
        if placeheld {
            missing.push(what.to_string());
        }
    };

    let (forseti, ph) = or_placeholder(&inputs.forseti_url, "FORSETI_URL");
    note_missing(ph, "--forseti-url (Forseti public base URL)");
    let forseti = trim_trailing_slash(&forseti).to_string();

    // Single-host: forseti-url's host is the rp.id; multi-subdomain operators narrow it by hand.
    let rp_id =
        rp_id_from(inputs.forseti_url.as_deref()).unwrap_or_else(|| "CHANGEME_RP_ID".into());
    note_missing(
        rp_id == "CHANGEME_RP_ID",
        "webauthn rp.id (registrable domain)",
    );

    let (kratos_public, ph) = or_placeholder(&inputs.kratos_public_url, "KRATOS_PUBLIC_URL");
    note_missing(ph, "--kratos-public-url");
    let kratos_public = trim_trailing_slash(&kratos_public).to_string();

    let (kratos_admin, ph) = or_placeholder(&inputs.kratos_admin_url, "KRATOS_ADMIN_URL");
    note_missing(ph, "--kratos-admin-url");
    let kratos_admin = trim_trailing_slash(&kratos_admin).to_string();

    let (hydra_public, ph) = or_placeholder(&inputs.hydra_public_url, "HYDRA_PUBLIC_URL");
    note_missing(ph, "--hydra-public-url");
    let hydra_public = trim_trailing_slash(&hydra_public).to_string();

    let (_hydra_admin, ph) = or_placeholder(&inputs.hydra_admin_url, "HYDRA_ADMIN_URL");
    note_missing(ph, "--hydra-admin-url");

    let (kratos_dsn, ph) = or_placeholder(&inputs.kratos_db_dsn, "KRATOS_DB_DSN");
    note_missing(ph, "--kratos-db-dsn");

    let (hydra_dsn, ph) = or_placeholder(&inputs.hydra_db_dsn, "HYDRA_DB_DSN");
    note_missing(ph, "--hydra-db-dsn");

    let (smtp, ph) = or_placeholder(&inputs.smtp_uri, "SMTP_URI");
    note_missing(ph, "--smtp-uri");

    // Generated secrets — never placeholders.
    let kratos_cookie = random_secret(32);
    let kratos_cipher = random_secret(32);
    let pairwise_salt = random_secret(32);
    let hydra_system = random_secret(32);
    let hydra_cookie = random_secret(32);

    let kratos = render_kratos(KratosTemplate {
        dsn: &kratos_dsn,
        public_base_url: &kratos_public,
        admin_base_url: &kratos_admin,
        forseti_url: &forseti,
        smtp_uri: &smtp,
        cookie_secret: &kratos_cookie,
        cipher_secret: &kratos_cipher,
        rp_id: &rp_id,
    });

    let hydra = render_hydra(HydraTemplate {
        dsn: &hydra_dsn,
        public_url: &hydra_public,
        forseti_url: &forseti,
        system_secret: &hydra_system,
        cookie_secret: &hydra_cookie,
        pairwise_salt: &pairwise_salt,
    });

    (kratos, hydra, missing)
}

struct KratosTemplate<'a> {
    dsn: &'a str,
    public_base_url: &'a str,
    admin_base_url: &'a str,
    forseti_url: &'a str,
    smtp_uri: &'a str,
    cookie_secret: &'a str,
    cipher_secret: &'a str,
    rp_id: &'a str,
}

fn render_kratos(t: KratosTemplate) -> String {
    let f = t.forseti_url;
    let dsn = yaml_scalar(t.dsn);
    let public_base_url = yaml_scalar(&format!("{}/", t.public_base_url));
    let admin_base_url = yaml_scalar(&format!("{}/", t.admin_base_url));
    let forseti = yaml_scalar(f);
    let forseti_root = yaml_scalar(&format!("{f}/"));
    let forseti_error = yaml_scalar(&format!("{f}/error"));
    let forseti_settings = yaml_scalar(&format!("{f}/settings"));
    let forseti_recovery = yaml_scalar(&format!("{f}/recovery"));
    let forseti_verification = yaml_scalar(&format!("{f}/verification"));
    let forseti_login = yaml_scalar(&format!("{f}/login"));
    let forseti_registration = yaml_scalar(&format!("{f}/registration"));
    let smtp_uri = yaml_scalar(t.smtp_uri);
    let cookie_secret = yaml_scalar(t.cookie_secret);
    let cipher_secret = yaml_scalar(t.cipher_secret);
    let rp_id = yaml_scalar(t.rp_id);
    format!(
        r#"version: v1.3.0

dsn: {dsn}

# `highest_available` forces any identity with a second factor enrolled to
# complete AAL2 before whoami returns a session — Kratos answers 403, which
# Forseti maps to a `/login?aal=aal2` step-up. Settings ALSO requires AAL2
# (see `selfservice.flows.settings.required_aal` below) so an AAL1 session
# (password-only login, or an email-recovery session) can't strip a second
# factor and defeat 2FA. Lost-device users step up with a `lookup_secret`
# recovery code (which satisfies AAL2) to manage their factors.
session:
  whoami:
    required_aal: highest_available

serve:
  public:
    base_url: {public_base_url}
    cors:
      enabled: true
      allowed_origins:
        - {forseti}
      allowed_methods: [POST, GET, PUT, PATCH, DELETE]
      allowed_headers: [Authorization, Cookie, Content-Type]
      exposed_headers: [Content-Type, Set-Cookie]
  admin:
    base_url: {admin_base_url}

selfservice:
  default_browser_return_url: {forseti_root}
  allowed_return_urls:
    - {forseti}

  methods:
    password:
      enabled: true
    link:
      enabled: true
      config:
        lifespan: 15m
    totp:
      enabled: true
      config:
        issuer: forseti
    lookup_secret:
      enabled: true
    webauthn:
      enabled: true
      config:
        # `passwordless: false` keeps WebAuthn as a SECOND factor (AAL2).
        # Flipping it to true makes it a first-factor login and it will NOT
        # satisfy the AAL2 step-up.
        passwordless: false
        rp:
          id: {rp_id}
          display_name: forseti
          origins:
            - {forseti}

  flows:
    error:
      ui_url: {forseti_error}

    settings:
      ui_url: {forseti_settings}
      privileged_session_max_age: 15m
      # AAL2 required for settings changes once the identity has a second
      # factor. Otherwise an AAL1 session (password-only login, or an email
      # recovery session) could open the settings flow and REMOVE the second
      # factor, defeating 2FA entirely. With enforcement on, the user is
      # already AAL2 by the time they reach settings (they stepped up at
      # login), so this adds no extra prompt for normal use — it only blocks
      # an un-stepped-up session from touching credentials.
      required_aal: highest_available

    recovery:
      enabled: true
      ui_url: {forseti_recovery}
      after:
        default_browser_return_url: {forseti_root}

    verification:
      enabled: true
      ui_url: {forseti_verification}
      after:
        default_browser_return_url: {forseti_root}

    logout:
      after:
        default_browser_return_url: {forseti_login}

    login:
      ui_url: {forseti_login}
      lifespan: 10m

    registration:
      lifespan: 10m
      ui_url: {forseti_registration}
      after:
        password:
          hooks:
            - hook: session

log:
  level: info
  format: text
  leak_sensitive_values: false

secrets:
  cookie:
    - {cookie_secret}
  cipher:
    - {cipher_secret}

ciphers:
  algorithm: xchacha20-poly1305

hashers:
  algorithm: bcrypt
  bcrypt:
    cost: 12

identity:
  default_schema_id: default
  schemas:
    - id: default
      url: file:///etc/config/kratos/identity.schema.json

courier:
  smtp:
    connection_uri: {smtp_uri}
"#,
    )
}

struct HydraTemplate<'a> {
    dsn: &'a str,
    public_url: &'a str,
    forseti_url: &'a str,
    system_secret: &'a str,
    cookie_secret: &'a str,
    pairwise_salt: &'a str,
}

fn render_hydra(t: HydraTemplate) -> String {
    let f = t.forseti_url;
    let dsn = yaml_scalar(t.dsn);
    let public_url = yaml_scalar(t.public_url);
    let forseti_consent = yaml_scalar(&format!("{f}/oauth/consent"));
    let forseti_login = yaml_scalar(&format!("{f}/oauth/login"));
    let forseti_logout = yaml_scalar(&format!("{f}/oauth/logout"));
    let forseti_register = yaml_scalar(&format!("{f}/oauth2/register"));
    let system_secret = yaml_scalar(t.system_secret);
    let cookie_secret = yaml_scalar(t.cookie_secret);
    let pairwise_salt = yaml_scalar(t.pairwise_salt);
    format!(
        r#"dsn: {dsn}

serve:
  cookies:
    same_site_mode: Lax

urls:
  self:
    # Issuer must be reachable under the same hostname from BOTH the browser
    # and any resource servers so the `iss` claim in id_tokens validates
    # everywhere.
    issuer: {public_url}
  consent: {forseti_consent}
  login:   {forseti_login}
  logout:  {forseti_logout}

secrets:
  system:
    - {system_secret}
  cookie:
    - {cookie_secret}

oidc:
  subject_identifiers:
    supported_types: [pairwise, public]
    pairwise:
      salt: {pairwise_salt}

  # Dynamic Client Registration (RFC 7591). The portal advertises *itself* as
  # the registration_endpoint and gates inbound requests with an Initial
  # Access Token before forwarding to Hydra. See `src/oauth/register.rs`.
  dynamic_client_registration:
    enabled: true
    default_scope:
      - openid
      - offline
      - offline_access

webfinger:
  oidc_discovery:
    # Points at the portal, not Hydra — the portal validates an Initial
    # Access Token before forwarding to Hydra.
    client_registration_url: {forseti_register}

oauth2:
  expose_internal_errors: false
  # MCP 2025-06-18 requires PKCE with S256 for public clients.
  pkce:
    enforced_for_public_clients: true

# Access tokens are JWTs by default. Resource servers validate locally against
# Hydra's JWKS. Flip to `opaque` if you need immediate revocation (and route
# every RS to the admin API on :4445).
strategies:
  access_token: jwt

ttl:
  access_token: 5m
"#,
    )
}

/// Write `contents` to `path` truncating any existing file, owner-only (0600)
/// on Unix so the embedded secrets aren't world-readable. The `--force`
/// overwrite path reopens with truncate, re-applying the mode.
#[cfg(unix)]
fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // .mode() only applies to a fresh file; reapply for the --force overwrite path.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

pub(crate) fn init(args: &[String]) -> i32 {
    if wants_help(args) {
        print_init_help();
        return 0;
    }

    let inputs = InitInputs {
        forseti_url: parse_flag(args, "--forseti-url").map(String::from),
        kratos_public_url: parse_flag(args, "--kratos-public-url").map(String::from),
        kratos_admin_url: parse_flag(args, "--kratos-admin-url").map(String::from),
        hydra_public_url: parse_flag(args, "--hydra-public-url").map(String::from),
        hydra_admin_url: parse_flag(args, "--hydra-admin-url").map(String::from),
        kratos_db_dsn: parse_flag(args, "--kratos-db-dsn").map(String::from),
        hydra_db_dsn: parse_flag(args, "--hydra-db-dsn").map(String::from),
        smtp_uri: parse_flag(args, "--smtp-uri").map(String::from),
    };

    if let Err(e) = validate_inputs(&inputs) {
        eprintln!("error: {e}");
        return 1;
    }

    let kratos_out = parse_flag(args, "--kratos-out").unwrap_or("kratos.yml");
    let hydra_out = parse_flag(args, "--hydra-out").unwrap_or("hydra.yml");
    let force = has_flag(args, "--force");

    for path in [kratos_out, hydra_out] {
        if Path::new(path).exists() && !force {
            eprintln!("error: {path} already exists — pass --force to overwrite");
            return 1;
        }
    }

    let (kratos_yaml, hydra_yaml, missing) = render_configs(&inputs);

    // Files embed CSPRNG secrets + DB/SMTP passwords — write owner-only (0600).
    if let Err(e) = write_secret_file(kratos_out, &kratos_yaml) {
        eprintln!("error: writing {kratos_out}: {e}");
        return 1;
    }
    if let Err(e) = write_secret_file(hydra_out, &hydra_yaml) {
        eprintln!("error: writing {hydra_out}: {e}");
        return 1;
    }

    println!("Wrote {kratos_out}");
    println!("Wrote {hydra_out}");
    println!();
    println!("Secrets were auto-generated with a CSPRNG. Review and store them securely;");
    println!("they are embedded in the files above and grant full session/token control.");

    if !missing.is_empty() {
        let mut warn = String::new();
        let _ = writeln!(
            warn,
            "\nINCOMPLETE: the following were not supplied and are CHANGEME_* placeholders."
        );
        let _ = writeln!(warn, "Fill them in before deploying:");
        for m in &missing {
            let _ = writeln!(warn, "  - {m}");
        }
        eprintln!("{warn}");
    }

    println!();
    println!("Verify with: forseti config-check --kratos {kratos_out} --hydra {hydra_out}");
    0
}

fn print_init_help() {
    println!(
        "forseti config-init — generate a recommended Kratos + Hydra config pair

USAGE: forseti config-init [OPTIONS]

Secrets are minted from a CSPRNG; the security recommendations are baked in
regardless of input. Refuses to overwrite an existing output file without
--force. Anything not supplied is written as a loud CHANGEME_* placeholder
that config-check will FAIL on. The webauthn rp.id is derived from the host
of --forseti-url (left as CHANGEME_RP_ID if that flag is absent).

CONNECTION OPTIONS:
  --forseti-url <url>        Forseti public base URL
  --kratos-public-url <url>  Kratos public base URL
  --kratos-admin-url <url>   Kratos admin base URL
  --hydra-public-url <url>   Hydra public issuer URL
  --hydra-admin-url <url>    Hydra admin base URL
  --kratos-db-dsn <dsn>      Kratos database DSN
  --hydra-db-dsn <dsn>       Hydra database DSN
  --smtp-uri <uri>           courier SMTP connection URI

OUTPUT OPTIONS:
  --kratos-out <path>        Kratos output file (default: kratos.yml)
  --hydra-out <path>         Hydra output file (default: hydra.yml)
  --force                    overwrite existing output files
  -h, --help                 print this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Value {
        serde_yaml_ng::from_str(yaml).expect("test yaml parses")
    }

    fn severity_of<'a>(findings: &'a [Finding], key: &str) -> Option<Severity> {
        findings.iter().find(|f| f.key == key).map(|f| f.severity)
    }

    #[test]
    fn resolve_flag_wins_over_env_and_default() {
        let (path, source) = resolve_config_path(
            Some("/flag/kratos.yml"),
            Some("/env/kratos.yml".to_string()),
            DEFAULT_KRATOS,
            "Kratos",
            "--kratos",
            ENV_KRATOS,
        )
        .expect("flag resolves");
        assert_eq!(path, PathBuf::from("/flag/kratos.yml"));
        assert_eq!(source, "from --kratos");
    }

    #[test]
    fn resolve_env_used_when_no_flag() {
        let (path, source) = resolve_config_path(
            None,
            Some("/env/kratos.yml".to_string()),
            DEFAULT_KRATOS,
            "Kratos",
            "--kratos",
            ENV_KRATOS,
        )
        .expect("env resolves");
        assert_eq!(path, PathBuf::from("/env/kratos.yml"));
        assert_eq!(source, format!("from ${ENV_KRATOS}"));
    }

    #[test]
    fn resolve_default_used_when_it_exists() {
        // Cargo runs tests from the crate root, where infra/ exists.
        let (path, source) =
            resolve_config_path(None, None, DEFAULT_KRATOS, "Kratos", "--kratos", ENV_KRATOS)
                .expect("dev default exists at crate root");
        assert_eq!(path, PathBuf::from(DEFAULT_KRATOS));
        assert_eq!(source, "dev default");
    }

    #[test]
    fn resolve_nothing_found_is_err() {
        let err = resolve_config_path(
            None,
            None,
            "does/not/exist.yml",
            "Kratos",
            "--kratos",
            ENV_KRATOS,
        )
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
    fn generated_config_passes_own_linter() {
        let inputs = InitInputs {
            forseti_url: Some("https://accounts.example.com".to_string()),
            kratos_public_url: Some("https://accounts.example.com/kratos".to_string()),
            kratos_admin_url: Some("http://kratos:4434".to_string()),
            hydra_public_url: Some("https://accounts.example.com/hydra".to_string()),
            hydra_admin_url: Some("http://hydra:4445".to_string()),
            kratos_db_dsn: Some("postgres://k:secret@db:5432/kratos".to_string()),
            hydra_db_dsn: Some("postgres://h:secret@db:5432/hydra".to_string()),
            smtp_uri: Some("smtps://user:pass@smtp.example.com:465".to_string()),
        };

        let (kratos_yaml, hydra_yaml, missing) = render_configs(&inputs);
        assert!(
            missing.is_empty(),
            "full inputs should leave nothing missing"
        );

        let kratos_v: Value = serde_yaml_ng::from_str(&kratos_yaml).expect("kratos yaml parses");
        let hydra_v: Value = serde_yaml_ng::from_str(&hydra_yaml).expect("hydra yaml parses");

        let bad_k: Vec<_> = check_kratos(&kratos_v)
            .into_iter()
            .filter(|f| f.severity != Severity::Ok)
            .collect();
        let bad_h: Vec<_> = check_hydra(&hydra_v)
            .into_iter()
            .filter(|f| f.severity != Severity::Ok)
            .collect();

        assert!(bad_k.is_empty(), "kratos findings: {bad_k:?}");
        assert!(bad_h.is_empty(), "hydra findings: {bad_h:?}");
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
    fn rp_id_derived_from_forseti_url() {
        assert_eq!(
            rp_id_from(Some("https://accounts.example.com/sub/path")).as_deref(),
            Some("accounts.example.com")
        );
        assert_eq!(rp_id_from(None), None);
        assert_eq!(rp_id_from(Some("not a url")), None);
    }

    #[test]
    fn validate_inputs_rejects_newline_in_smtp_uri() {
        let inputs = InitInputs {
            smtp_uri: Some("smtp://h:1025\nrequired_aal: aal1".to_string()),
            ..Default::default()
        };
        let err = validate_inputs(&inputs).expect_err("newline must be rejected");
        assert!(err.contains("--smtp-uri"), "err: {err}");
        assert!(err.contains("control characters"), "err: {err}");
    }

    #[test]
    fn malicious_value_cannot_inject_sibling_key() {
        // Even if validation were bypassed, the quoting must keep the value in
        // scalar position so settings.required_aal stays highest_available.
        let smtp = "smtp://h:1025\nselfservice:\n  flows:\n    settings:\n      required_aal: aal1";
        let kratos = render_kratos(KratosTemplate {
            dsn: "postgres://x",
            public_base_url: "https://k",
            admin_base_url: "http://k:4434",
            forseti_url: "https://f",
            smtp_uri: smtp,
            cookie_secret: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            cipher_secret: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            rp_id: "f",
        });
        let v: Value = serde_yaml_ng::from_str(&kratos).expect("yaml parses");
        assert_eq!(
            dig_str(&v, &["selfservice", "flows", "settings", "required_aal"]),
            Some("highest_available"),
        );
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
    fn parse_flag_does_not_swallow_next_flag() {
        let args = vec!["--forseti-url".to_string(), "--force".to_string()];
        assert_eq!(parse_flag(&args, "--forseti-url"), None);
        assert!(has_flag(&args, "--force"));
        let args = vec!["--forseti-url=https://f".to_string()];
        assert_eq!(parse_flag(&args, "--forseti-url"), Some("https://f"));
    }

    #[test]
    fn empty_flag_value_falls_through() {
        let err = resolve_config_path(
            Some(""),
            None,
            "does/not/exist.yml",
            "Kratos",
            "--kratos",
            ENV_KRATOS,
        )
        .expect_err("empty flag must fall through to error");
        assert!(err.contains("--kratos"));
    }

    #[cfg(unix)]
    #[test]
    fn init_writes_files_0600_and_refuses_overwrite() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("forseti-init-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kratos = dir.join("kratos.yml");
        let hydra = dir.join("hydra.yml");
        let ks = kratos.to_str().unwrap().to_string();
        let hs = hydra.to_str().unwrap().to_string();

        let base = vec![
            "--forseti-url".to_string(),
            "https://accounts.example.com".to_string(),
            "--kratos-out".to_string(),
            ks.clone(),
            "--hydra-out".to_string(),
            hs.clone(),
        ];
        assert_eq!(init(&base), 0);
        let mode = std::fs::metadata(&kratos).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "kratos.yml must be 0600, got {mode:o}");

        // Without --force a second run refuses and leaves the file untouched.
        let before = std::fs::read_to_string(&kratos).unwrap();
        assert_eq!(init(&base), 1);
        assert_eq!(std::fs::read_to_string(&kratos).unwrap(), before);

        // With --force it overwrites and keeps 0600.
        let mut forced = base.clone();
        forced.push("--force".to_string());
        assert_eq!(init(&forced), 0);
        let mode = std::fs::metadata(&kratos).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn init_renders_rp_id_from_forseti_url() {
        let inputs = InitInputs {
            forseti_url: Some("https://accounts.example.com".to_string()),
            ..Default::default()
        };
        let (kratos_yaml, _hydra, _missing) = render_configs(&inputs);
        let v: Value = serde_yaml_ng::from_str(&kratos_yaml).expect("kratos yaml parses");
        assert_eq!(
            dig_str(
                &v,
                &["selfservice", "methods", "webauthn", "config", "rp", "id"]
            ),
            Some("accounts.example.com")
        );
    }
}
