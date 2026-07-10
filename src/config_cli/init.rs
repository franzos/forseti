use std::fmt::Write as _;
use std::path::Path;

use crate::cli::InitArgs;

use super::yamlutil::{random_secret, reject_control_chars, yaml_scalar};

// ---------------------------------------------------------------------------
// config-init: generate a recommended Kratos + Hydra config.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct InitInputs {
    forseti_url: Option<String>,
    kratos_public_url: Option<String>,
    kratos_admin_url: Option<String>,
    hydra_public_url: Option<String>,
    hydra_admin_url: Option<String>,
    kratos_db_dsn: Option<String>,
    hydra_db_dsn: Option<String>,
    smtp_uri: Option<String>,
}

/// A required connection value: either the operator's flag, or a loud
/// `CHANGEME_*` placeholder that `config-check` will FAIL on.
pub(crate) fn or_placeholder(opt: &Option<String>, thing: &str) -> (String, bool) {
    match opt {
        Some(v) => (v.clone(), false),
        None => (format!("CHANGEME_{thing}"), true),
    }
}

pub(crate) fn trim_trailing_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// WebAuthn `rp.id` is the deployment host. Derive it from `--forseti-url`'s
/// host; `None` when the URL is absent, unparseable, or host-less.
pub(crate) fn rp_id_from(forseti_url: Option<&str>) -> Option<String> {
    let raw = forseti_url?;
    url::Url::parse(raw).ok()?.host_str().map(str::to_string)
}

/// Dev mailboxes: the playground mailcrab, or any obvious test placeholder.
pub(crate) fn is_dev_smtp(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    lower.contains("mailslurper")
        || lower.contains("mailcrab")
        || lower.contains("test")
        || lower.contains("change-me")
        || lower.contains("changeme")
        || lower.contains("placeholder")
}

/// Reject any operator-supplied value carrying control chars before it reaches
/// the templated YAML (scalar-breakout injection vector).
pub(crate) fn validate_inputs(inputs: &InitInputs) -> Result<(), String> {
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
pub(crate) fn render_configs(inputs: &InitInputs) -> (String, String, Vec<String>) {
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

    // Generated secrets, never placeholders.
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
pub(crate) fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
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
pub(crate) fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

pub(crate) fn init(args: &InitArgs) -> i32 {
    let inputs = InitInputs {
        forseti_url: args.forseti_url.clone(),
        kratos_public_url: args.kratos_public_url.clone(),
        kratos_admin_url: args.kratos_admin_url.clone(),
        hydra_public_url: args.hydra_public_url.clone(),
        hydra_admin_url: args.hydra_admin_url.clone(),
        kratos_db_dsn: args.kratos_db_dsn.clone(),
        hydra_db_dsn: args.hydra_db_dsn.clone(),
        smtp_uri: args.smtp_uri.clone(),
    };

    if let Err(e) = validate_inputs(&inputs) {
        eprintln!("error: {e}");
        return 1;
    }

    let kratos_out = args.kratos_out.as_str();
    let hydra_out = args.hydra_out.as_str();
    let force = args.force;

    for path in [kratos_out, hydra_out] {
        if Path::new(path).exists() && !force {
            eprintln!("error: {path} already exists — pass --force to overwrite");
            return 1;
        }
    }

    let (kratos_yaml, hydra_yaml, missing) = render_configs(&inputs);

    // Files embed CSPRNG secrets + DB/SMTP passwords; write owner-only (0600).
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml_ng::Value;

    use crate::config_cli::check::{check_hydra, check_kratos, Severity};
    use crate::config_cli::yamlutil::dig_str;

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

        let build = |force: bool| InitArgs {
            forseti_url: Some("https://accounts.example.com".to_string()),
            kratos_public_url: None,
            kratos_admin_url: None,
            hydra_public_url: None,
            hydra_admin_url: None,
            kratos_db_dsn: None,
            hydra_db_dsn: None,
            smtp_uri: None,
            smtp_from_address: None,
            smtp_from_name: None,
            kratos_out: ks.clone(),
            hydra_out: hs.clone(),
            force,
        };

        assert_eq!(init(&build(false)), 0);
        let mode = std::fs::metadata(&kratos).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "kratos.yml must be 0600, got {mode:o}");

        // Without --force a second run refuses and leaves the file untouched.
        let before = std::fs::read_to_string(&kratos).unwrap();
        assert_eq!(init(&build(false)), 1);
        assert_eq!(std::fs::read_to_string(&kratos).unwrap(), before);

        // With --force it overwrites and keeps 0600.
        assert_eq!(init(&build(true)), 0);
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
