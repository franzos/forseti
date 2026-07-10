use std::path::{Path, PathBuf};

use serde_yaml_ng::Value;

use crate::cli::CheckArgs;

use super::init::is_dev_smtp;
use super::yamlutil::{dig_bool, dig_str, first_secret, is_placeholder, load_yaml};

const DEFAULT_KRATOS: &str = "infra/kratos/kratos.yml";
const DEFAULT_HYDRA: &str = "infra/hydra/hydra.yml";

const ENV_KRATOS: &str = "FORSETI_KRATOS_CONFIG";
const ENV_HYDRA: &str = "FORSETI_HYDRA_CONFIG";

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

    // secrets.cipher: must be exactly 32 chars.
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

pub(crate) fn check_hydra(root: &Value) -> Vec<Finding> {
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

/// Scan every scalar for a leftover `CHANGEME` placeholder and FAIL on each.
/// `already` covers keys the specific checks handled; a specific finding whose
/// key is a prefix of the scalar's path (e.g. `secrets.cipher` vs the scalar at
/// `secrets.cipher[0]`) suppresses the generic one so we don't double-report.
pub(crate) fn placeholder_findings(root: &Value, already: &[Finding]) -> Vec<Finding> {
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
}
