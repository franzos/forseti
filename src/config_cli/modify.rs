//! The guarded write pipeline (`write_yaml`) plus `config oidc enable/disable`.
//! The mapper bodies here are pinned and reviewed: they only ever emit an
//! `email` trait when the upstream marks it verified, which is what stops the
//! unverified-email account-takeover class. `write_yaml` re-serializes the
//! whole document, so it confirms before dropping comments and always prints a
//! secret-redacted diff.

use std::io::{ErrorKind, IsTerminal as _, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_yaml_ng::{Mapping, Value};
use toml_edit::DocumentMut;

use crate::cli::{OidcCmd, PathArgs, SecretSourceArgs, SmtpCmd};

use super::check::{
    check_hydra, check_kratos, check_oidc_providers, extract_hook_token, redact_uri,
    resolve_config_path, resolve_forseti_toml_path, webhook_token_entries, Finding, Severity,
    DEFAULT_FORSETI_TOML, DEFAULT_HYDRA, DEFAULT_KRATOS, ENV_HYDRA, ENV_KRATOS, PLACEHOLDER_TOKENS,
};
use super::io::{
    atomic_write, backup, fingerprint, is_git_tracked, list_backups, lock_config_dir, read_secret,
    redacted_diff, resolve_target, SecretSource, Target,
};
use super::yamlutil::{
    dig, dig_mut, dig_mut_or_insert, dig_str, load_yaml, random_secret, reject_control_chars,
    secret_entries,
};

// ---------------------------------------------------------------------------
// Pinned identity mappers.
// ---------------------------------------------------------------------------

/// The reviewed jsonnet mapper. The `[if ... else null]` key means the `email`
/// trait is only ever written when the upstream sets `email_verified` — an
/// unverified address never lands as a trait, so it can't be used to claim the
/// matching Forseti account. Google/GitHub/Microsoft share the exact body.
pub(crate) const MAPPER_GOOGLE: &str = r#"local claims = std.extVar('claims');
{
  identity: {
    traits: {
      [if 'email' in claims && claims.email_verified then 'email' else null]: claims.email,
    },
  },
}
"#;
pub(crate) const MAPPER_GITHUB: &str = MAPPER_GOOGLE;
pub(crate) const MAPPER_MICROSOFT: &str = MAPPER_GOOGLE;

/// The pinned mapper body for a provider. Providers without a dedicated pin
/// fall back to the shared body (the three supported providers are identical).
pub(crate) fn pinned_mapper(provider: &str) -> &'static str {
    match provider {
        "github" => MAPPER_GITHUB,
        "microsoft" => MAPPER_MICROSOFT,
        _ => MAPPER_GOOGLE,
    }
}

/// Whether `provider` is one Forseti ships a pinned mapper for. Used by the
/// linter to decide whether a mapper-vs-pinned hash mismatch is meaningful.
pub(crate) fn known_pinned_provider(provider: &str) -> bool {
    matches!(provider, "google" | "github" | "microsoft")
}

const SUPPORTED_PROVIDERS: &[&str] = &["google", "github", "microsoft"];

// ---------------------------------------------------------------------------
// Context + outcomes.
// ---------------------------------------------------------------------------

/// An injectable line-oriented input, carrying both a `read_line` and the
/// TTY-ness the confirm prompts gate on. Every blocking prompt in this module
/// reads through this rather than `std::io::stdin()` directly, so the menu can
/// route them through its own scriptable input and tests can feed answers.
pub(crate) trait LineSource {
    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize>;
    fn is_terminal(&self) -> bool;
}

/// The plain-CLI line source: the process's real stdin. Locks fresh per call
/// (never held open) so it composes with anything else reading stdin.
pub(crate) struct StdinLines;

impl LineSource for StdinLines {
    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        std::io::stdin().read_line(buf)
    }
    fn is_terminal(&self) -> bool {
        std::io::stdin().is_terminal()
    }
}

/// `std::io::empty()` as a non-interactive line source (immediate EOF, never a
/// TTY): the default in tests that never reach a prompt, and the shape a
/// non-TTY CLI run behaves like.
impl LineSource for std::io::Empty {
    fn read_line(&mut self, _buf: &mut String) -> std::io::Result<usize> {
        Ok(0)
    }
    fn is_terminal(&self) -> bool {
        false
    }
}

pub(crate) struct ModifyCtx {
    pub kratos: Target,
    pub hydra: Target,
    // Resolved for menu reuse; the oidc actions only touch kratos.
    pub forseti: Option<Target>,
    pub dry_run: bool,
    pub yes: bool,
    pub out: Box<dyn Write>,
    /// Where blocking confirm/enter/typed-phrase prompts read their answer.
    pub input: Box<dyn LineSource>,
}

pub(crate) enum WriteOutcome {
    DryRun,
    Written { check_failed: bool },
}

pub(crate) struct OidcEnableInput {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub microsoft_tenant: Option<String>,
    pub keep_mapper: bool,
}

// ---------------------------------------------------------------------------
// Small Value builders.
// ---------------------------------------------------------------------------

fn mapping(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Mapping::new();
    for (k, v) in pairs {
        m.insert(Value::String(k.to_string()), v);
    }
    Value::Mapping(m)
}

fn string_seq(items: &[&str]) -> Value {
    Value::Sequence(
        items
            .iter()
            .map(|s| Value::String((*s).to_string()))
            .collect(),
    )
}

/// The first `{hook: web_hook, config: {...}}` node's `config` mapping,
/// cloned. Init-generated configs may carry no audit web_hooks at all, so this
/// is optional (callers fall back to a bare `session` hook).
fn first_web_hook_config(v: &Value) -> Option<Value> {
    match v {
        Value::Mapping(map) => {
            if dig_str(v, &["hook"]) == Some("web_hook") {
                if let Some(cfg) = v.get("config") {
                    return Some(cfg.clone());
                }
            }
            map.iter().find_map(|(_, val)| first_web_hook_config(val))
        }
        Value::Sequence(seq) => seq.iter().find_map(first_web_hook_config),
        _ => None,
    }
}

/// Clone an audit `web_hook` config and rewrite its `?action=` query so the
/// url/body/auth stay identical to the existing hooks while pointing at the
/// oidc flow's action.
fn web_hook_entry(config: &Value, action: &str) -> Value {
    let mut cfg = config.clone();
    if let Some(slot) = dig_mut(&mut cfg, &["url"]) {
        if let Some(url) = slot.as_str() {
            let new = match url.split_once("?action=") {
                Some((base, _)) => format!("{base}?action={action}"),
                None => format!("{url}?action={action}"),
            };
            *slot = Value::String(new);
        }
    }
    mapping(vec![
        ("hook", Value::String("web_hook".into())),
        ("config", cfg),
    ])
}

// ---------------------------------------------------------------------------
// Pure mutations (tested without I/O).
// ---------------------------------------------------------------------------

/// All input validation for `oidc enable`, run with no side effects so callers
/// can gate mapper-file writes and other side effects on it up front.
fn validate_oidc_enable_input(input: &OidcEnableInput) -> Result<(), String> {
    let provider = input.provider.as_str();
    if !SUPPORTED_PROVIDERS.contains(&provider) {
        return Err(format!(
            "unknown provider `{provider}`; expected one of google, github, microsoft"
        ));
    }
    if provider == "microsoft" {
        match input.microsoft_tenant.as_deref() {
            None | Some("") => {
                return Err(
                    "microsoft requires --microsoft-tenant (a specific tenant ID; `common` is refused)"
                        .to_string(),
                );
            }
            Some("common") => {
                return Err(
                    "microsoft_tenant `common` accepts sign-in from ANY Azure AD tenant or personal \
                     Microsoft account (the nOAuth account-takeover class); set a specific tenant ID \
                     (or `organizations`/`consumers` if that is genuinely intended)."
                        .to_string(),
                );
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Applies the enable mutation to `root`. Returns whether the no-`web_hook`
/// fallback was used (the caller-visible signal to warn about the audit gap).
fn apply_oidc_enable(
    root: &mut Value,
    input: &OidcEnableInput,
    mapper_url: &str,
) -> Result<bool, String> {
    validate_oidc_enable_input(input)?;
    let provider = input.provider.as_str();
    let tenant = if provider == "microsoft" {
        // validated above: Some, non-empty, not "common".
        input.microsoft_tenant.clone()
    } else {
        None
    };

    *dig_mut_or_insert(root, &["selfservice", "methods", "oidc", "enabled"]) = Value::Bool(true);

    let scope = if provider == "github" {
        string_seq(&["user:email"])
    } else {
        string_seq(&["openid", "email", "profile"])
    };
    let mut pairs = vec![
        ("id", Value::String(provider.to_string())),
        ("provider", Value::String(provider.to_string())),
        ("client_id", Value::String(input.client_id.clone())),
        ("client_secret", Value::String(input.client_secret.clone())),
        ("mapper_url", Value::String(mapper_url.to_string())),
        ("scope", scope),
    ];
    if let Some(t) = tenant {
        pairs.push(("microsoft_tenant", Value::String(t)));
    }
    let entry = mapping(pairs);

    let providers = dig_mut_or_insert(
        root,
        &["selfservice", "methods", "oidc", "config", "providers"],
    );
    if !providers.is_sequence() {
        *providers = Value::Sequence(Vec::new());
    }
    let providers_seq = providers
        .as_sequence_mut()
        .expect("just ensured a sequence");
    providers_seq.retain(|p| dig_str(p, &["id"]) != Some(provider));
    providers_seq.push(entry);

    let template = first_web_hook_config(root);
    let session = || mapping(vec![("hook", Value::String("session".into()))]);
    let used_fallback = template.is_none();
    match &template {
        Some(cfg) => {
            *dig_mut_or_insert(
                root,
                &[
                    "selfservice",
                    "flows",
                    "registration",
                    "after",
                    "oidc",
                    "hooks",
                ],
            ) = Value::Sequence(vec![session(), web_hook_entry(cfg, "registration.oidc")]);
            *dig_mut_or_insert(
                root,
                &["selfservice", "flows", "login", "after", "oidc", "hooks"],
            ) = Value::Sequence(vec![web_hook_entry(cfg, "login.oidc")]);
        }
        None => {
            // Kratos's login flow doesn't accept the `session` hook (registration-only;
            // login accepts web_hook/revoke_active_sessions/require_verified_address), so
            // without a web_hook template the login flow gets no `after.oidc` node at all.
            *dig_mut_or_insert(
                root,
                &[
                    "selfservice",
                    "flows",
                    "registration",
                    "after",
                    "oidc",
                    "hooks",
                ],
            ) = Value::Sequence(vec![session()]);
            if let Some(after) = dig_mut(root, &["selfservice", "flows", "login", "after"])
                .and_then(Value::as_mapping_mut)
            {
                after.remove("oidc");
            }
        }
    }

    Ok(used_fallback)
}

/// Remove the provider named `id`. Returns whether the method is now empty (the
/// caller-visible signal that `enabled` was flipped off and both `after.oidc`
/// hook nodes were removed).
fn apply_oidc_disable(root: &mut Value, id: &str) -> Result<bool, String> {
    let Some(seq) = dig_mut(
        root,
        &["selfservice", "methods", "oidc", "config", "providers"],
    )
    .and_then(Value::as_sequence_mut) else {
        return Err(format!(
            "no OIDC providers configured; nothing to disable for `{id}`"
        ));
    };
    let before = seq.len();
    seq.retain(|p| dig_str(p, &["id"]) != Some(id));
    if seq.len() == before {
        return Err(format!("no OIDC provider with id `{id}` is configured"));
    }
    let now_empty = seq.is_empty();

    if now_empty {
        *dig_mut_or_insert(root, &["selfservice", "methods", "oidc", "enabled"]) =
            Value::Bool(false);
        for flow in ["login", "registration"] {
            if let Some(after) = dig_mut(root, &["selfservice", "flows", flow, "after"])
                .and_then(Value::as_mapping_mut)
            {
                after.remove("oidc");
            }
        }
    }
    Ok(now_empty)
}

// ---------------------------------------------------------------------------
// Audit webhook token rotation: kratos.yml hook rewriting + config.toml
// accept-list editing.
// ---------------------------------------------------------------------------

/// Rewrite every audit `web_hook` node's bearer token to `new_token`. Matches
/// structurally — a mapping with `hook: web_hook` and a `config.auth` shaped
/// `{type: api_key, config: {name: Authorization, value: ...}}` — so a plain
/// string that happens to contain the old token elsewhere in the document
/// (a comment-like note, an unrelated field) is never touched. Returns the
/// number of nodes rewritten.
pub(crate) fn rewrite_hook_tokens(root: &mut Value, new_token: &str) -> usize {
    let mut count = 0;
    walk_rewrite_hook_tokens(root, new_token, &mut count);
    count
}

fn walk_rewrite_hook_tokens(value: &mut Value, new_token: &str, count: &mut usize) {
    if value.is_mapping() {
        let is_hook_token_node = dig_str(value, &["hook"]) == Some("web_hook")
            && dig_str(value, &["config", "auth", "type"]) == Some("api_key")
            && dig_str(value, &["config", "auth", "config", "name"]) == Some("Authorization");
        if is_hook_token_node {
            if let Some(slot) = dig_mut(value, &["config", "auth", "config", "value"]) {
                *slot = Value::String(format!("Bearer {new_token}"));
                *count += 1;
            }
        }
    }
    match value {
        Value::Mapping(map) => {
            for (_, v) in map.iter_mut() {
                walk_rewrite_hook_tokens(v, new_token, count);
            }
        }
        Value::Sequence(seq) => {
            for v in seq.iter_mut() {
                walk_rewrite_hook_tokens(v, new_token, count);
            }
        }
        _ => {}
    }
}

/// `[audit].webhook_token` as currently written in `config.toml`. Delegates to
/// `check::webhook_token_entries` (same string-or-array parsing the linter and
/// `config status` use) so there's exactly one reader of that shape.
pub(crate) fn toml_get_webhook_tokens(doc: &DocumentMut) -> Vec<String> {
    webhook_token_entries(doc)
}

/// Write `[audit].webhook_token` back: a single entry becomes a bare string,
/// more than one becomes an array (the rotation accept-list form). Mutates the
/// existing `[audit]` table in place — `toml_edit` is lossless, so any
/// comments elsewhere in the document (including on this key) survive.
pub(crate) fn toml_set_webhook_tokens(doc: &mut DocumentMut, tokens: &[String]) {
    use toml_edit::{value, Array};
    let item = if tokens.len() == 1 {
        value(tokens[0].as_str())
    } else {
        let mut arr = Array::new();
        for t in tokens {
            arr.push(t.as_str());
        }
        value(arr)
    };
    doc["audit"]["webhook_token"] = item;
}

/// Minimal `config.toml` skeleton offered when `rotate webhook-token` finds no
/// config.toml at all: just enough of `[self]`/`[internal]`/`[audit]` for the
/// audit receiver to be configurable. NOT a complete bootable config — it's
/// missing `[kratos]`/`[hydra]`/`[brand]`, which Forseti also requires at
/// boot; the operator still needs to fill those in (see config.example.toml).
pub(crate) fn minimal_config_toml() -> &'static str {
    r#"[self]
url = "CHANGEME_FORSETI_URL"
bind = "0.0.0.0:3000"

[internal]
bind = "127.0.0.1:8081"

[audit]
webhook_token = ""
ip_salt = ""
audit_retention_days = 90
"#
}

// ---------------------------------------------------------------------------
// Prompts + runbook.
// ---------------------------------------------------------------------------

/// Renders `question` to `ctx.out` (flushed) *before* blocking on
/// `ctx.input`, so the operator always sees what they're answering. The
/// not-a-TTY guard reads the same injectable input's terminal state, so the
/// menu (a real TTY, or a scripted one under test) is never falsely refused.
fn prompt_yes_no(ctx: &mut ModifyCtx, question: &str) -> anyhow::Result<bool> {
    if !ctx.input.is_terminal() {
        anyhow::bail!("{question}: stdin is not a TTY; pass --yes to proceed non-interactively");
    }
    write!(ctx.out, "{question} [y/N]: ")?;
    ctx.out.flush()?;
    let mut line = String::new();
    ctx.input.read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub(crate) fn print_runbook(out: &mut dyn Write, services: &[&str], extra: &[&str]) {
    let _ = writeln!(out, "\nNext steps:");
    for s in services {
        let _ = writeln!(out, "  - restart {s}");
    }
    for e in extra {
        let _ = writeln!(out, "  - {e}");
    }
}

fn marker(sev: Severity) -> &'static str {
    match sev {
        Severity::Ok => "[ OK ]",
        Severity::Warn => "[WARN]",
        Severity::Fail => "[FAIL]",
    }
}

/// Every `client_secret` under `selfservice.methods.oidc.config.providers[*]`.
fn harvest_client_secrets(root: &Value) -> Vec<String> {
    dig(
        root,
        &["selfservice", "methods", "oidc", "config", "providers"],
    )
    .and_then(Value::as_sequence)
    .into_iter()
    .flatten()
    .filter_map(|p| dig_str(p, &["client_secret"]))
    .map(str::to_string)
    .collect()
}

// ---------------------------------------------------------------------------
// The guarded write pipeline.
// ---------------------------------------------------------------------------

pub(crate) fn write_yaml(
    ctx: &mut ModifyCtx,
    target: &Target,
    old_text: &str,
    new_root: &Value,
    secrets: &[&str],
) -> anyhow::Result<WriteOutcome> {
    let new_text = serde_yaml_ng::to_string(new_root)?;
    let label = target.path.display().to_string();

    // The diff must never leak a provider's client_secret, including ones the
    // caller didn't explicitly pass in (e.g. a provider being removed, or the
    // one being replaced on re-enable): harvest every client_secret from both
    // documents and union it with whatever the caller already knows about.
    let mut harvested: Vec<String> = secrets.iter().map(|s| (*s).to_string()).collect();
    if let Ok(old_root) = serde_yaml_ng::from_str::<Value>(old_text) {
        harvested.extend(harvest_client_secrets(&old_root));
    }
    harvested.extend(harvest_client_secrets(new_root));
    harvested.sort();
    harvested.dedup();
    let all_secrets: Vec<&str> = harvested.iter().map(String::as_str).collect();

    // Re-serializing drops every comment; confirm before we do that.
    let has_comments = old_text.lines().any(|l| l.trim_start().starts_with('#'));
    if has_comments && !ctx.yes && !ctx.dry_run {
        writeln!(
            ctx.out,
            "note: {label} contains comments; rewriting it drops ALL comments."
        )?;
        if !prompt_yes_no(ctx, "Proceed and drop comments?")? {
            anyhow::bail!("aborted: {label} left unchanged");
        }
    }

    if is_git_tracked(&target.path) {
        writeln!(
            ctx.out,
            "warning: {label} is tracked by git; writing it will show up as a local change. \
             Backups land as {label}.bak.<ts>; add `*.bak.*` to .gitignore to avoid committing them."
        )?;
    }

    write!(
        ctx.out,
        "{}",
        redacted_diff(&label, old_text, &new_text, &all_secrets)
    )?;

    if ctx.dry_run {
        writeln!(ctx.out, "(dry-run: no changes written to {label})")?;
        return Ok(WriteOutcome::DryRun);
    }

    let dir = target
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _lock = lock_config_dir(dir)?;
    if let Some(bak) = backup(target)? {
        writeln!(ctx.out, "backed up {label} to {}", bak.display())?;
    }
    atomic_write(target, new_text.as_bytes())?;
    writeln!(ctx.out, "wrote {label}")?;

    let check_failed = post_write_check(ctx, target);
    Ok(WriteOutcome::Written { check_failed })
}

/// Re-read the just-written file from disk and run the check that fits this
/// target, printing any non-OK finding. Returns whether any FAIL landed.
fn post_write_check(ctx: &mut ModifyCtx, target: &Target) -> bool {
    let root = match load_yaml(&target.path) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(
                ctx.out,
                "  [FAIL] re-reading {}: {e}",
                target.path.display()
            );
            return true;
        }
    };
    let config_dir = target
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let findings: Vec<Finding> = if target.path == ctx.kratos.path {
        let mut f = check_kratos(&root);
        f.extend(check_oidc_providers(&root, config_dir));
        f
    } else if target.path == ctx.hydra.path {
        check_hydra(&root)
    } else {
        Vec::new()
    };

    let _ = writeln!(
        ctx.out,
        "post-write check ({label}):",
        label = target.path.display()
    );
    let mut check_failed = false;
    for f in &findings {
        if f.severity == Severity::Ok {
            continue;
        }
        if f.severity == Severity::Fail {
            check_failed = true;
        }
        let _ = writeln!(
            ctx.out,
            "  {} {} = {}",
            marker(f.severity),
            f.key,
            f.current
        );
    }
    if !check_failed {
        let _ = writeln!(ctx.out, "  no new FAILs");
    }
    check_failed
}

/// `config.toml`'s own guarded write: backup + atomic write via `io.rs`, a
/// secret-redacted diff — but unlike `write_yaml`, no comment-drop confirm.
/// `toml_edit::DocumentMut` only rewrites the keys actually mutated, so every
/// other comment in the file survives regardless.
fn write_toml(
    ctx: &mut ModifyCtx,
    target: &Target,
    old_text: &str,
    doc: &DocumentMut,
    secrets: &[&str],
) -> anyhow::Result<WriteOutcome> {
    let new_text = doc.to_string();
    let label = target.path.display().to_string();

    if is_git_tracked(&target.path) {
        writeln!(
            ctx.out,
            "warning: {label} is tracked by git; writing it will show up as a local change. \
             Backups land as {label}.bak.<ts>; add `*.bak.*` to .gitignore to avoid committing them."
        )?;
    }

    write!(
        ctx.out,
        "{}",
        redacted_diff(&label, old_text, &new_text, secrets)
    )?;

    if ctx.dry_run {
        writeln!(ctx.out, "(dry-run: no changes written to {label})")?;
        return Ok(WriteOutcome::DryRun);
    }

    let dir = target
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _lock = lock_config_dir(dir)?;
    if let Some(bak) = backup(target)? {
        writeln!(ctx.out, "backed up {label} to {}", bak.display())?;
    }
    atomic_write(target, new_text.as_bytes())?;
    writeln!(ctx.out, "wrote {label}")?;
    Ok(WriteOutcome::Written {
        check_failed: false,
    })
}

// ---------------------------------------------------------------------------
// Mapper file handling.
// ---------------------------------------------------------------------------

fn handle_mapper(
    ctx: &mut ModifyCtx,
    mapper_file: &Path,
    provider: &str,
    keep_mapper: bool,
) -> anyhow::Result<()> {
    let pinned = pinned_mapper(provider);
    match std::fs::read_to_string(mapper_file) {
        Ok(existing) => {
            if fingerprint(&existing) == fingerprint(pinned) {
                writeln!(
                    ctx.out,
                    "mapper {} already matches Forseti's pinned body; leaving it.",
                    mapper_file.display()
                )?;
            } else if keep_mapper {
                writeln!(
                    ctx.out,
                    "warning: mapper {} differs from the pinned body; keeping it (--keep-mapper). \
                     Review it — a mapper that emits `email` without gating on `email_verified` is \
                     an account-takeover vector.",
                    mapper_file.display()
                )?;
            } else {
                anyhow::bail!(
                    "mapper {} exists and differs from Forseti's pinned body. A mapper that emits \
                     `email` without gating on `email_verified` lets an attacker take over accounts. \
                     Pass --keep-mapper to keep your reviewed version, or remove the file to \
                     regenerate the pinned one.",
                    mapper_file.display()
                );
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if ctx.dry_run {
                writeln!(
                    ctx.out,
                    "(dry-run: would write the pinned mapper to {})",
                    mapper_file.display()
                )?;
            } else {
                atomic_write(
                    &Target {
                        path: mapper_file.to_path_buf(),
                    },
                    pinned.as_bytes(),
                )?;
                writeln!(
                    ctx.out,
                    "wrote pinned mapper to {} (0600)",
                    mapper_file.display()
                )?;
            }
        }
        Err(e) => anyhow::bail!("{}: {e}", mapper_file.display()),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Composed actions.
// ---------------------------------------------------------------------------

pub(crate) fn oidc_enable(ctx: &mut ModifyCtx, input: OidcEnableInput) -> anyhow::Result<i32> {
    // Validate everything before any side effect (mapper file write, YAML
    // write): a rejected tenant or provider must never leave a stray mapper
    // or prompt the operator for a change that's about to be refused anyway.
    validate_oidc_enable_input(&input).map_err(|e| anyhow::anyhow!(e))?;

    let old_text = std::fs::read_to_string(&ctx.kratos.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.kratos.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.kratos.path.display()))?;

    let config_dir = ctx
        .kratos
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mapper_file = config_dir.join(format!("oidc.{}.jsonnet", input.provider));
    let mapper_url = format!("file:///etc/config/kratos/oidc.{}.jsonnet", input.provider);

    let mapper_existed_before = mapper_file.exists();

    let result = (|| -> anyhow::Result<i32> {
        handle_mapper(ctx, &mapper_file, &input.provider, input.keep_mapper)?;

        let used_fallback =
            apply_oidc_enable(&mut root, &input, &mapper_url).map_err(|e| anyhow::anyhow!(e))?;
        if used_fallback {
            writeln!(
                ctx.out,
                "warning: no audit web_hook template found in this kratos.yml, so OIDC \
                 login/registration events will NOT reach Forseti's audit log; see \
                 docs/operator-guide.md."
            )?;
        }

        if input.provider == "github" {
            writeln!(
                ctx.out,
                "note: GitHub only returns an email when the `user:email` scope is granted, and \
                 its claims don't reliably carry `email_verified`; Forseti treats GitHub emails \
                 as unverified until the user verifies through Forseti's own flow."
            )?;
        }

        let target = Target {
            path: ctx.kratos.path.clone(),
        };
        let outcome = write_yaml(ctx, &target, &old_text, &root, &[&input.client_secret])?;
        match outcome {
            WriteOutcome::DryRun => Ok(0),
            WriteOutcome::Written { check_failed } => {
                if check_failed {
                    writeln!(ctx.out, "fix the FAIL above before restarting Kratos.")?;
                    Ok(1)
                } else {
                    let l1 = "Kratos reloads its config file automatically; verify with: forseti \
                              config check";
                    let l2 = format!("changed: {}", target.path.display());
                    let l3 = format!("changed: {}", mapper_file.display());
                    print_runbook(&mut *ctx.out, &["Kratos"], &[l1, &l2, &l3]);
                    Ok(0)
                }
            }
        }
    })();

    // write_yaml failing or the operator declining its comment-drop prompt
    // must not leave behind a mapper this run created.
    if result.is_err() && !mapper_existed_before && mapper_file.exists() {
        std::fs::remove_file(&mapper_file).ok();
    }
    result
}

pub(crate) async fn oidc_disable(
    ctx: &mut ModifyCtx,
    id: &str,
    kratos_admin_url: Option<&str>,
) -> anyhow::Result<i32> {
    let old_text = std::fs::read_to_string(&ctx.kratos.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.kratos.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.kratos.path.display()))?;

    match count_identities(kratos_admin_url, id).await {
        Some(n) => writeln!(
            ctx.out,
            "about {n} identit{} similar to `{id}` in Kratos may be affected.",
            if n == 1 { "y" } else { "ies" }
        )?,
        None => writeln!(
            ctx.out,
            "could not count affected identities (best-effort probe)."
        )?,
    }

    if !ctx.yes && !ctx.dry_run && !prompt_yes_no(ctx, &format!("Disable OIDC provider `{id}`?"))? {
        writeln!(ctx.out, "aborted; no changes made.")?;
        return Ok(1);
    }
    // The confirmation above already covers dropping comments on rewrite;
    // don't ask again in write_yaml's comment-drop prompt.
    ctx.yes = true;

    apply_oidc_disable(&mut root, id).map_err(|e| anyhow::anyhow!(e))?;

    let target = Target {
        path: ctx.kratos.path.clone(),
    };
    let outcome = write_yaml(ctx, &target, &old_text, &root, &[])?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { check_failed } => {
            if check_failed {
                writeln!(ctx.out, "fix the FAIL above before restarting Kratos.")?;
                Ok(1)
            } else {
                let l1 =
                    "Kratos reloads its config file automatically; verify with: forseti config check";
                let l2 = format!("changed: {}", target.path.display());
                print_runbook(&mut *ctx.out, &["Kratos"], &[l1, &l2]);
                Ok(0)
            }
        }
    }
}

/// Best-effort count of identities whose credentials look like `id`. Any error
/// (unresolvable admin URL, network failure, unexpected body) yields `None`; it
/// never blocks the disable.
async fn count_identities(admin_url: Option<&str>, id: &str) -> Option<usize> {
    let base = admin_url?.trim_end_matches('/');
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("credentials_identifier_similar", id)
        .append_pair("per_page", "1")
        .finish();
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .get(format!("{base}/admin/identities?{query}"))
        .send()
        .await
        .ok()?;
    if let Some(total) = resp
        .headers()
        .get("x-total-count")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        return Some(total);
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    body.as_array().map(Vec::len)
}

// ---------------------------------------------------------------------------
// config rotate/prune webhook-token.
// ---------------------------------------------------------------------------

/// Where `config.toml` lives for this run: the operator-resolved target from
/// `ctx.forseti` when one exists (flag/env/dev-default-that-exists), else the
/// dev default path even though it doesn't exist yet — unlike
/// `resolve_forseti_toml_path` (used by `check`/`status`, which treat a
/// missing default as "nothing to check"), rotate needs a concrete path to
/// offer creating.
fn forseti_toml_target(ctx: &ModifyCtx) -> anyhow::Result<Target> {
    if let Some(t) = &ctx.forseti {
        return Ok(Target {
            path: t.path.clone(),
        });
    }
    // A nonexistent path is never a symlink, so `follow_symlink` doesn't matter here.
    resolve_target(Path::new(DEFAULT_FORSETI_TOML), false)
}

/// figment layers env vars over `config.toml`, so a live
/// `FORSETI_AUDIT__WEBHOOK_TOKEN` (or a `$FORSETI_CONFIG_PATH` pointed
/// somewhere else) would silently override whatever this command writes.
fn warn_env_shadow(ctx: &mut ModifyCtx, toml_path: &Path) -> anyhow::Result<()> {
    if std::env::var_os("FORSETI_AUDIT__WEBHOOK_TOKEN").is_some() {
        writeln!(
            ctx.out,
            "warning: $FORSETI_AUDIT__WEBHOOK_TOKEN is set; it overrides [audit].webhook_token \
             at boot, so Forseti won't see the accept list this command writes until it's unset."
        )?;
    }
    if let Some(env_path) = std::env::var_os("FORSETI_CONFIG_PATH") {
        if Path::new(&env_path) != toml_path {
            writeln!(
                ctx.out,
                "warning: $FORSETI_CONFIG_PATH ({}) differs from the config.toml being edited \
                 ({}); Forseti will load the env path, not this one.",
                Path::new(&env_path).display(),
                toml_path.display()
            )?;
        }
    }
    Ok(())
}

/// `config.toml` is missing: offer to create it from `minimal_config_toml()`
/// when interactive, otherwise refuse with instructions. Returns the "old"
/// text for the guarded write's diff — nothing is written to disk here; the
/// caller's `write_toml` call performs the actual (backed-up, atomic) first
/// write.
fn bootstrap_config_toml(
    ctx: &mut ModifyCtx,
    target: &Target,
    interactive: bool,
) -> anyhow::Result<String> {
    let label = target.path.display();
    if !interactive {
        anyhow::bail!(
            "{label} does not exist. Create it (see config.example.toml for a full template), \
             or re-run this command from an interactive terminal without --yes to be offered a \
             minimal skeleton."
        );
    }
    writeln!(ctx.out, "{label} does not exist.")?;
    if !prompt_yes_no(
        ctx,
        "Create it from a minimal [self]/[internal]/[audit] skeleton?",
    )? {
        anyhow::bail!("aborted: {label} not created");
    }
    Ok(minimal_config_toml().to_string())
}

/// `config rotate webhook-token`. New token = `random_secret(48)`; the
/// "current" token comes from kratos.yml's first `web_hook` when one exists,
/// else (a kratos.yml with no audit hooks at all — every `config-init`
/// output) from config.toml's own accept list, so the command still has
/// something to rotate.
///
/// A placeholder/unset current token is replaced in one pass (both files, no
/// staged accept list — there's no live secret to protect a rotation window
/// for). Otherwise config.toml's accept list is staged `[new, old]` first;
/// interactive mode waits for the operator to restart Forseti before
/// rewriting kratos.yml, non-interactive writes both back-to-back and warns
/// about the resulting audit-loss window. When kratos.yml has no hooks, only
/// config.toml changes either way.
pub(crate) fn rotate_webhook_token(ctx: &mut ModifyCtx, interactive: bool) -> anyhow::Result<i32> {
    let kratos_old_text = std::fs::read_to_string(&ctx.kratos.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.kratos.path.display()))?;
    let mut kratos_root: Value = serde_yaml_ng::from_str(&kratos_old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.kratos.path.display()))?;

    let toml_target = forseti_toml_target(ctx)?;
    warn_env_shadow(ctx, &toml_target.path)?;

    let toml_old_text = match std::fs::read_to_string(&toml_target.path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            bootstrap_config_toml(ctx, &toml_target, interactive)?
        }
        Err(e) => return Err(anyhow::anyhow!("{}: {e}", toml_target.path.display())),
    };
    let mut toml_doc: DocumentMut = toml_old_text
        .parse()
        .map_err(|e| anyhow::anyhow!("{}: invalid TOML: {e}", toml_target.path.display()))?;

    let kratos_hook_token = extract_hook_token(&kratos_root);
    let toml_entries = toml_get_webhook_tokens(&toml_doc);
    let new_token = random_secret(48);

    // The "current" token, and whether it's a placeholder/unset (=> replace
    // in one pass, no staging). When kratos.yml has no hooks, both come from
    // config.toml's own accept list instead.
    let (current, placeholder_or_unset) = match &kratos_hook_token {
        Some(t) => (Some(t.clone()), PLACEHOLDER_TOKENS.contains(&t.as_str())),
        None => {
            let first = toml_entries.first().cloned();
            let unset_like = match &first {
                None => true,
                Some(s) if s.is_empty() => true,
                Some(s) => PLACEHOLDER_TOKENS.contains(&s.as_str()),
            };
            (first, unset_like)
        }
    };

    let mut secret_pool: Vec<String> = vec![new_token.clone()];
    secret_pool.extend(current.clone());
    secret_pool.extend(toml_entries.iter().cloned());
    let secrets: Vec<&str> = secret_pool.iter().map(String::as_str).collect();

    if kratos_hook_token.is_none() {
        writeln!(
            ctx.out,
            "note: {} carries no audit web_hook nodes; nothing to rewrite there.",
            ctx.kratos.path.display()
        )?;
    }

    let new_accept_list: Vec<String> = if placeholder_or_unset {
        vec![new_token.clone()]
    } else {
        vec![
            new_token.clone(),
            current
                .clone()
                .expect("non-placeholder branch always has a current token"),
        ]
    };
    toml_set_webhook_tokens(&mut toml_doc, &new_accept_list);
    let toml_outcome = write_toml(ctx, &toml_target, &toml_old_text, &toml_doc, &secrets)?;

    let mut kratos_written = false;
    let mut check_failed = false;

    if kratos_hook_token.is_some() {
        // A dry-run never writes and never prompts: staging text about a
        // restart that won't happen (and blocking on Enter for it) would
        // both contradict --dry-run's contract.
        if !placeholder_or_unset && !ctx.dry_run {
            if interactive {
                writeln!(
                    ctx.out,
                    "\nrestart Forseti now so it accepts both the new and old webhook tokens, \
                     then press Enter to continue..."
                )?;
                ctx.out.flush()?;
                let mut line = String::new();
                ctx.input.read_line(&mut line)?;
            } else {
                writeln!(
                    ctx.out,
                    "warning: non-interactive rotation writes config.toml and kratos.yml \
                     back-to-back; until Forseti is restarted to reload config.toml, audit \
                     webhook calls carrying the new token will 401. Restart Forseti as soon as \
                     possible after this command returns."
                )?;
            }
        }

        let n = rewrite_hook_tokens(&mut kratos_root, &new_token);
        writeln!(
            ctx.out,
            "rewrote {n} audit hook token(s) in {}",
            ctx.kratos.path.display()
        )?;
        let outcome = write_yaml(
            ctx,
            &Target {
                path: ctx.kratos.path.clone(),
            },
            &kratos_old_text,
            &kratos_root,
            &secrets,
        )?;
        if let WriteOutcome::Written { check_failed: f } = outcome {
            kratos_written = true;
            check_failed = f;
        }
    }

    if matches!(toml_outcome, WriteOutcome::DryRun) {
        writeln!(ctx.out, "\n(dry run: nothing written, no restart required)")?;
        return Ok(0);
    }

    let mut extra = vec![format!("changed: {}", toml_target.path.display())];
    if kratos_written {
        extra.push(format!("changed: {}", ctx.kratos.path.display()));
        extra.push(
            "Kratos reloads its config file automatically; verify with: forseti config check"
                .to_string(),
        );
    }
    if !placeholder_or_unset {
        extra.push(
            "once every service has reloaded, run `forseti config prune webhook-token` to drop \
             the old token from config.toml's accept list."
                .to_string(),
        );
    }
    extra.push(
        "`forseti config check`/`config status` report rotation-pending while the accept list \
         has more than one entry."
            .to_string(),
    );
    let extra_refs: Vec<&str> = extra.iter().map(String::as_str).collect();

    if check_failed {
        writeln!(ctx.out, "fix the FAIL above before restarting Kratos.")?;
        print_runbook(&mut *ctx.out, &["Forseti"], &extra_refs);
        return Ok(1);
    }

    print_runbook(&mut *ctx.out, &["Forseti"], &extra_refs);
    Ok(0)
}

/// `config prune webhook-token`. Drops every accept-list entry except the one
/// kratos.yml currently presents, refusing when that token isn't in the
/// accept list at all (pruning would then leave Kratos unable to
/// authenticate). When kratos.yml has no audit hooks, there's no way to
/// verify which token it would present, so prune refuses unless the accept
/// list already has at most one entry (nothing to prune either way).
pub(crate) fn prune_webhook_token(ctx: &mut ModifyCtx) -> anyhow::Result<i32> {
    let kratos_text = std::fs::read_to_string(&ctx.kratos.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.kratos.path.display()))?;
    let kratos_root: Value = serde_yaml_ng::from_str(&kratos_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.kratos.path.display()))?;

    let toml_target = forseti_toml_target(ctx)?;
    warn_env_shadow(ctx, &toml_target.path)?;
    let toml_old_text = std::fs::read_to_string(&toml_target.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", toml_target.path.display()))?;
    let mut toml_doc: DocumentMut = toml_old_text
        .parse()
        .map_err(|e| anyhow::anyhow!("{}: invalid TOML: {e}", toml_target.path.display()))?;

    let entries = toml_get_webhook_tokens(&toml_doc);
    let kratos_token = extract_hook_token(&kratos_root);

    let Some(kratos_token) = kratos_token else {
        if entries.len() <= 1 {
            writeln!(
                ctx.out,
                "{} has no audit web_hook nodes and the accept list already has {} entr{}; \
                 nothing to prune.",
                ctx.kratos.path.display(),
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" }
            )?;
            return Ok(0);
        }
        anyhow::bail!(
            "{} has no audit web_hook nodes, so there's no way to verify which token Kratos \
             presents; refusing to prune config.toml's {}-entry accept list. Add a web_hook (or \
             edit [audit].webhook_token by hand) first.",
            ctx.kratos.path.display(),
            entries.len()
        );
    };

    if entries == [kratos_token.clone()] {
        writeln!(
            ctx.out,
            "config.toml's accept list already contains only the token kratos.yml presents; \
             nothing to prune."
        )?;
        return Ok(0);
    }

    if !entries.iter().any(|t| t == &kratos_token) {
        anyhow::bail!(
            "kratos.yml's current hook token isn't in config.toml's accept list; pruning would \
             leave Kratos unable to authenticate to the audit receiver at all. Rotate first, \
             restart Kratos, then prune."
        );
    }

    let mut secret_pool = entries.clone();
    secret_pool.push(kratos_token.clone());
    let secrets: Vec<&str> = secret_pool.iter().map(String::as_str).collect();

    toml_set_webhook_tokens(&mut toml_doc, std::slice::from_ref(&kratos_token));
    let outcome = write_toml(ctx, &toml_target, &toml_old_text, &toml_doc, &secrets)?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { .. } => {
            print_runbook(
                &mut *ctx.out,
                &[],
                &[
                    "config.toml's accept list is now a single entry.",
                    "`forseti config check` should no longer report rotation-pending.",
                ],
            );
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------------------
// config rotate/prune kratos-secrets, hydra-system, pairwise-salt.
// ---------------------------------------------------------------------------

/// Prepends `new_secret` to the list at `path`, turning a bare scalar into a
/// 1-element list first. Kratos/Hydra's rotation convention: the first entry
/// signs/encrypts new values, every entry remains valid to verify/decrypt.
pub(crate) fn rotate_secret_list(
    root: &mut Value,
    path: &[&str],
    new_secret: String,
) -> Result<(), String> {
    let mut entries: Vec<String> = secret_entries(root, path)
        .into_iter()
        .map(str::to_string)
        .collect();
    entries.insert(0, new_secret);
    *dig_mut_or_insert(root, path) =
        Value::Sequence(entries.into_iter().map(Value::String).collect());
    Ok(())
}

/// Keeps only `entries[0]`. Errors when the list has a single entry (or is a
/// bare scalar): there's nothing to prune.
pub(crate) fn prune_secret_list(root: &mut Value, path: &[&str]) -> Result<(), String> {
    let entries: Vec<String> = secret_entries(root, path)
        .into_iter()
        .map(str::to_string)
        .collect();
    if entries.len() <= 1 {
        return Err(format!(
            "{} has only {} entr{}; nothing to prune",
            path.join("."),
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        ));
    }
    let Some(slot) = dig_mut(root, path) else {
        return Err(format!("{}: not found", path.join(".")));
    };
    *slot = Value::Sequence(vec![Value::String(entries[0].clone())]);
    Ok(())
}

/// `config rotate kratos-secrets [--cookie] [--cipher]`. Neither flag rotates
/// both. Every existing cookie/cipher value is pulled into the redaction set
/// regardless of which list is rotated, since both remain live secrets in the
/// diff either way.
pub(crate) fn rotate_kratos_secrets(
    ctx: &mut ModifyCtx,
    cookie: bool,
    cipher: bool,
) -> anyhow::Result<i32> {
    let (do_cookie, do_cipher) = if !cookie && !cipher {
        (true, true)
    } else {
        (cookie, cipher)
    };

    let old_text = std::fs::read_to_string(&ctx.kratos.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.kratos.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.kratos.path.display()))?;

    let mut secret_pool: Vec<String> = secret_entries(&root, &["secrets", "cookie"])
        .into_iter()
        .chain(secret_entries(&root, &["secrets", "cipher"]))
        .map(str::to_string)
        .collect();

    let mut changed = Vec::new();
    if do_cookie {
        let new_secret = random_secret(32);
        secret_pool.push(new_secret.clone());
        rotate_secret_list(&mut root, &["secrets", "cookie"], new_secret)
            .map_err(|e| anyhow::anyhow!(e))?;
        changed.push("secrets.cookie");
    }
    if do_cipher {
        let new_secret = random_secret(32);
        secret_pool.push(new_secret.clone());
        rotate_secret_list(&mut root, &["secrets", "cipher"], new_secret)
            .map_err(|e| anyhow::anyhow!(e))?;
        changed.push("secrets.cipher");
    }

    if !ctx.yes && !ctx.dry_run {
        let question = format!(
            "Rotate {} in {}? The old value(s) stay valid for verify/decrypt until pruned.",
            changed.join(", "),
            ctx.kratos.path.display()
        );
        if !prompt_yes_no(ctx, &question)? {
            writeln!(ctx.out, "aborted; no changes made.")?;
            return Ok(1);
        }
        // Already confirmed above; don't ask a second time in write_yaml's comment-drop prompt.
        ctx.yes = true;
    }

    let target = Target {
        path: ctx.kratos.path.clone(),
    };
    let secrets: Vec<&str> = secret_pool.iter().map(String::as_str).collect();
    let outcome = write_yaml(ctx, &target, &old_text, &root, &secrets)?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { check_failed } => {
            if check_failed {
                writeln!(ctx.out, "fix the FAIL above before restarting Kratos.")?;
                Ok(1)
            } else {
                let l1 =
                    "Kratos reloads its config file automatically; verify with: forseti config check";
                let l2 = format!("changed: {}", target.path.display());
                print_runbook(&mut *ctx.out, &["Kratos"], &[l1, &l2]);
                Ok(0)
            }
        }
    }
}

/// `config prune kratos-secrets [--cookie] [--cipher]`. Neither flag sweeps
/// both lists, pruning only the ones that actually have >1 entry (silently
/// skipping the rest); an explicit `--cookie`/`--cipher` errors if that
/// specific list has nothing to prune.
pub(crate) fn prune_kratos_secrets(
    ctx: &mut ModifyCtx,
    cookie: bool,
    cipher: bool,
) -> anyhow::Result<i32> {
    let (want_cookie, want_cipher, explicit) = if !cookie && !cipher {
        (true, true, false)
    } else {
        (cookie, cipher, true)
    };

    let old_text = std::fs::read_to_string(&ctx.kratos.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.kratos.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.kratos.path.display()))?;

    let secret_pool: Vec<String> = secret_entries(&root, &["secrets", "cookie"])
        .into_iter()
        .chain(secret_entries(&root, &["secrets", "cipher"]))
        .map(str::to_string)
        .collect();

    let mut pruned: Vec<&str> = Vec::new();
    for (want, path, label) in [
        (want_cookie, &["secrets", "cookie"][..], "secrets.cookie"),
        (want_cipher, &["secrets", "cipher"][..], "secrets.cipher"),
    ] {
        if !want {
            continue;
        }
        match prune_secret_list(&mut root, path) {
            Ok(()) => pruned.push(label),
            Err(e) if explicit => return Err(anyhow::anyhow!(e)),
            Err(_) => {} // sweep mode: this particular list has nothing to prune
        }
    }

    if pruned.is_empty() {
        writeln!(
            ctx.out,
            "nothing to prune: the selected secrets list(s) already have a single entry."
        )?;
        return Ok(0);
    }

    if pruned.contains(&"secrets.cookie") {
        writeln!(
            ctx.out,
            "note: prune secrets.cookie only after the max session lifetime has elapsed since \
             rotation; a leaked old cookie secret can still forge sessions while it's listed."
        )?;
    }

    if !ctx.yes && !ctx.dry_run {
        let question = format!(
            "Prune {} in {}? Removed entries stop verifying/decrypting immediately.",
            pruned.join(", "),
            ctx.kratos.path.display()
        );
        if !prompt_yes_no(ctx, &question)? {
            writeln!(ctx.out, "aborted; no changes made.")?;
            return Ok(1);
        }
        ctx.yes = true;
    }

    let target = Target {
        path: ctx.kratos.path.clone(),
    };
    let secrets: Vec<&str> = secret_pool.iter().map(String::as_str).collect();
    let outcome = write_yaml(ctx, &target, &old_text, &root, &secrets)?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { check_failed } => {
            if check_failed {
                writeln!(ctx.out, "fix the FAIL above before restarting Kratos.")?;
                Ok(1)
            } else {
                let l1 =
                    "Kratos reloads its config file automatically; verify with: forseti config check";
                let l2 = format!("changed: {}", target.path.display());
                print_runbook(&mut *ctx.out, &["Kratos"], &[l1, &l2]);
                Ok(0)
            }
        }
    }
}

/// `config rotate hydra-system`. Hydra does NOT hot-reload, and the runbook
/// says so explicitly, unlike Kratos's rotations.
pub(crate) fn rotate_hydra_system(ctx: &mut ModifyCtx) -> anyhow::Result<i32> {
    let old_text = std::fs::read_to_string(&ctx.hydra.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.hydra.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.hydra.path.display()))?;

    let mut secret_pool: Vec<String> = secret_entries(&root, &["secrets", "system"])
        .into_iter()
        .map(str::to_string)
        .collect();
    let new_secret = random_secret(32);
    secret_pool.push(new_secret.clone());

    rotate_secret_list(&mut root, &["secrets", "system"], new_secret)
        .map_err(|e| anyhow::anyhow!(e))?;

    if !ctx.yes && !ctx.dry_run {
        let question = format!(
            "Rotate secrets.system in {}? The old value stays valid for decryption until pruned; \
             Hydra must be restarted for the new value to take effect.",
            ctx.hydra.path.display()
        );
        if !prompt_yes_no(ctx, &question)? {
            writeln!(ctx.out, "aborted; no changes made.")?;
            return Ok(1);
        }
        ctx.yes = true;
    }

    let target = Target {
        path: ctx.hydra.path.clone(),
    };
    let secrets: Vec<&str> = secret_pool.iter().map(String::as_str).collect();
    let outcome = write_yaml(ctx, &target, &old_text, &root, &secrets)?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { check_failed } => {
            if check_failed {
                writeln!(ctx.out, "fix the FAIL above before restarting Hydra.")?;
                Ok(1)
            } else {
                let l1 = "Hydra does NOT hot-reload its config; the new secret takes effect only \
                          once Hydra is restarted.";
                let l2 = format!("changed: {}", target.path.display());
                print_runbook(&mut *ctx.out, &["Hydra"], &[l1, &l2]);
                Ok(0)
            }
        }
    }
}

/// `config prune hydra-system`.
pub(crate) fn prune_hydra_system(ctx: &mut ModifyCtx) -> anyhow::Result<i32> {
    let old_text = std::fs::read_to_string(&ctx.hydra.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.hydra.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.hydra.path.display()))?;

    let secret_pool: Vec<String> = secret_entries(&root, &["secrets", "system"])
        .into_iter()
        .map(str::to_string)
        .collect();

    prune_secret_list(&mut root, &["secrets", "system"]).map_err(|e| anyhow::anyhow!(e))?;

    if !ctx.yes && !ctx.dry_run {
        let question = format!(
            "Prune secrets.system in {}? The removed value stops decrypting immediately.",
            ctx.hydra.path.display()
        );
        if !prompt_yes_no(ctx, &question)? {
            writeln!(ctx.out, "aborted; no changes made.")?;
            return Ok(1);
        }
        ctx.yes = true;
    }

    let target = Target {
        path: ctx.hydra.path.clone(),
    };
    let secrets: Vec<&str> = secret_pool.iter().map(String::as_str).collect();
    let outcome = write_yaml(ctx, &target, &old_text, &root, &secrets)?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { check_failed } => {
            if check_failed {
                writeln!(ctx.out, "fix the FAIL above before restarting Hydra.")?;
                Ok(1)
            } else {
                let l1 = "Hydra does NOT hot-reload its config; the pruned list takes effect only \
                          once Hydra is restarted.";
                let l2 = format!("changed: {}", target.path.display());
                print_runbook(&mut *ctx.out, &["Hydra"], &[l1, &l2]);
                Ok(0)
            }
        }
    }
}

pub(crate) const SALT_CONFIRM_PHRASE: &str = "change every pairwise subject";

/// Hydra's admin base URL, if hydra.yml carries one. The reference templates
/// (`config-init`, the playground `infra/hydra/hydra.yml`) don't write one:
/// Hydra's admin port is normally supplied out-of-band (CLI flag/env), so
/// this is a best-effort probe that's expected to miss most of the time; the
/// pairwise-client count degrades silently when it does.
fn hydra_admin_url(root: &Value) -> Option<String> {
    dig_str(root, &["serve", "admin", "base_url"])
        .or_else(|| dig_str(root, &["urls", "admin"]))
        .map(str::to_string)
}

/// Best-effort count of clients with `subject_type == "pairwise"`. Any error
/// (unresolvable admin URL, network failure, unexpected body) yields `None`;
/// it never blocks the rotation.
async fn count_pairwise_clients(admin_url: Option<&str>) -> Option<usize> {
    let base = admin_url?.trim_end_matches('/');
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .get(format!("{base}/admin/clients?limit=500"))
        .send()
        .await
        .ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;
    let clients = body.as_array()?;
    Some(
        clients
            .iter()
            .filter(|c| {
                c.get("subject_type").and_then(serde_json::Value::as_str) == Some("pairwise")
            })
            .count(),
    )
}

/// `config rotate pairwise-salt`. A scalar overwrite, not a rotation list:
/// there is no prune step, and the old salt is gone the moment this is
/// confirmed. Every pairwise `sub` Hydra has ever issued changes permanently.
/// `--yes` never satisfies the gate: interactive mode requires typing
/// [`SALT_CONFIRM_PHRASE`] verbatim, non-interactive requires
/// `confirmed_flag` (`--i-understand-subs-change`).
pub(crate) async fn rotate_pairwise_salt(
    ctx: &mut ModifyCtx,
    confirmed_flag: bool,
    interactive: bool,
) -> anyhow::Result<i32> {
    let old_text = std::fs::read_to_string(&ctx.hydra.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.hydra.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.hydra.path.display()))?;

    let old_salt =
        dig_str(&root, &["oidc", "subject_identifiers", "pairwise", "salt"]).map(str::to_string);

    writeln!(
        ctx.out,
        "warning: the pairwise salt derives every pairwise subject identifier Hydra has ever \
         issued, per client. Rotating it changes ALL of them, permanently; there is no prune \
         step, the old salt is gone as soon as this is confirmed. Any downstream app matching \
         users by their old pairwise `sub` will see what looks like a brand-new account."
    )?;

    if !ctx.dry_run {
        match count_pairwise_clients(hydra_admin_url(&root).as_deref()).await {
            Some(n) => writeln!(
                ctx.out,
                "{n} pairwise client{} configured in Hydra will be affected.",
                if n == 1 { "" } else { "s" }
            )?,
            None => writeln!(
                ctx.out,
                "could not query Hydra for pairwise clients (best-effort probe)."
            )?,
        }

        if interactive {
            write!(ctx.out, "Type `{SALT_CONFIRM_PHRASE}` to confirm: ")?;
            ctx.out.flush()?;
            let mut line = String::new();
            ctx.input.read_line(&mut line)?;
            if line.trim() != SALT_CONFIRM_PHRASE {
                writeln!(ctx.out, "aborted; no changes made.")?;
                return Ok(1);
            }
        } else if !confirmed_flag {
            anyhow::bail!(
                "rotating the pairwise salt is irreversible and changes every pairwise subject; \
                 pass --i-understand-subs-change to proceed non-interactively (--yes does not \
                 satisfy this gate)."
            );
        }
        // Confirmed above; don't ask again in write_yaml's comment-drop prompt.
        ctx.yes = true;
    }

    let new_salt = random_secret(32);
    *dig_mut_or_insert(
        &mut root,
        &["oidc", "subject_identifiers", "pairwise", "salt"],
    ) = Value::String(new_salt.clone());

    let mut secret_pool = vec![new_salt];
    secret_pool.extend(old_salt);
    let secrets: Vec<&str> = secret_pool.iter().map(String::as_str).collect();

    let target = Target {
        path: ctx.hydra.path.clone(),
    };
    let outcome = write_yaml(ctx, &target, &old_text, &root, &secrets)?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { check_failed } => {
            if check_failed {
                writeln!(ctx.out, "fix the FAIL above before restarting Hydra.")?;
                Ok(1)
            } else {
                let l1 = "Hydra does NOT hot-reload its config; the new pairwise salt takes \
                          effect only once Hydra is restarted.";
                let l2 = format!("changed: {}", target.path.display());
                print_runbook(&mut *ctx.out, &["Hydra"], &[l1, &l2]);
                Ok(0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// config smtp set.
// ---------------------------------------------------------------------------

/// `config smtp set`. `uri`/`from_address`/`from_name` are each optional, but
/// at least one must be given. `uri` is treated as a secret (it embeds
/// `user:pass`), so it's fed into `write_yaml`'s redaction set and echoed back
/// only through [`redact_uri`] — the raw value never lands in this function's
/// output.
pub(crate) fn smtp_set(
    ctx: &mut ModifyCtx,
    uri: Option<String>,
    from_address: Option<String>,
    from_name: Option<String>,
) -> anyhow::Result<i32> {
    if uri.is_none() && from_address.is_none() && from_name.is_none() {
        anyhow::bail!(
            "nothing to set: pass a URI source (--uri-env/--uri-file/--uri-stdin) and/or \
             --from-address/--from-name"
        );
    }

    if let Some(u) = &uri {
        reject_control_chars("SMTP URI", u).map_err(|e| anyhow::anyhow!(e))?;
        let parsed = url::Url::parse(u).map_err(|e| anyhow::anyhow!("invalid SMTP URI: {e}"))?;
        if !matches!(parsed.scheme(), "smtp" | "smtps") {
            anyhow::bail!(
                "invalid SMTP URI: scheme must be smtp:// or smtps:// (got `{}`)",
                parsed.scheme()
            );
        }
    }
    if let Some(addr) = &from_address {
        reject_control_chars("--from-address", addr).map_err(|e| anyhow::anyhow!(e))?;
    }
    if let Some(name) = &from_name {
        reject_control_chars("--from-name", name).map_err(|e| anyhow::anyhow!(e))?;
    }

    let old_text = std::fs::read_to_string(&ctx.kratos.path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ctx.kratos.path.display()))?;
    let mut root: Value = serde_yaml_ng::from_str(&old_text)
        .map_err(|e| anyhow::anyhow!("{}: invalid YAML: {e}", ctx.kratos.path.display()))?;

    if let Some(u) = &uri {
        writeln!(
            ctx.out,
            "setting courier.smtp.connection_uri to {}",
            redact_uri(u)
        )?;
        *dig_mut_or_insert(&mut root, &["courier", "smtp", "connection_uri"]) =
            Value::String(u.clone());
    }
    if let Some(addr) = &from_address {
        *dig_mut_or_insert(&mut root, &["courier", "smtp", "from_address"]) =
            Value::String(addr.clone());
    }
    if let Some(name) = &from_name {
        *dig_mut_or_insert(&mut root, &["courier", "smtp", "from_name"]) =
            Value::String(name.clone());
    }

    let target = Target {
        path: ctx.kratos.path.clone(),
    };
    let secrets: Vec<&str> = uri.as_deref().into_iter().collect();
    let outcome = write_yaml(ctx, &target, &old_text, &root, &secrets)?;
    match outcome {
        WriteOutcome::DryRun => Ok(0),
        WriteOutcome::Written { check_failed } => {
            if check_failed {
                writeln!(ctx.out, "fix the FAIL above before restarting Kratos.")?;
                Ok(1)
            } else {
                let l1 =
                    "Kratos reloads its config file automatically; verify with: forseti config check";
                let l2 = format!("changed: {}", target.path.display());
                print_runbook(&mut *ctx.out, &["Kratos"], &[l1, &l2]);
                Ok(0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// config restore.
// ---------------------------------------------------------------------------

/// The `<file>.bak.<unix-secs>` suffix, parsed back out of a backup path.
fn backup_timestamp(path: &Path) -> Option<u64> {
    path.file_name()?
        .to_str()?
        .rsplit_once(".bak.")?
        .1
        .parse()
        .ok()
}

/// Every `client_secret`/rotation-list/hook-token/SMTP-URI value in a parsed
/// YAML doc, best-effort. Mirrors the secret shapes the various `rotate_*`
/// actions already treat as sensitive, so a restore diff redacts them the same
/// way a normal write would.
fn harvest_yaml_secrets(text: &str) -> Vec<String> {
    let Ok(root) = serde_yaml_ng::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = harvest_client_secrets(&root);
    for path in [
        &["secrets", "cookie"][..],
        &["secrets", "cipher"][..],
        &["secrets", "system"][..],
    ] {
        out.extend(secret_entries(&root, path).into_iter().map(str::to_string));
    }
    out.extend(extract_hook_token(&root));
    if let Some(uri) = dig_str(&root, &["courier", "smtp", "connection_uri"]) {
        out.push(uri.to_string());
    }
    out
}

/// `[audit].webhook_token` entries from a parsed TOML doc, best-effort.
fn harvest_toml_secrets(text: &str) -> Vec<String> {
    text.parse::<DocumentMut>()
        .map(|doc| toml_get_webhook_tokens(&doc))
        .unwrap_or_default()
}

/// The union of every secret shape restore knows how to find in either the
/// current file or the backup being restored, from both sides of the diff —
/// a value present only in one (e.g. a since-removed provider) still needs
/// redacting.
fn harvest_restore_secrets(old_text: &str, new_text: &str) -> Vec<String> {
    let mut out = harvest_yaml_secrets(old_text);
    out.extend(harvest_yaml_secrets(new_text));
    out.extend(harvest_toml_secrets(old_text));
    out.extend(harvest_toml_secrets(new_text));
    out.sort();
    out.dedup();
    out
}

/// Restore a single target from `backup_path`, verbatim: the backup's raw
/// bytes are copied byte-for-byte, never re-serialized through
/// `serde_yaml_ng`/`toml_edit`, so any comments or formatting the backup
/// carries survive intact. This is the deliberate opposite of `write_yaml`'s
/// comment-drop behavior — restoring comments is the point, not a loss to
/// confirm — so this bypasses `write_yaml`/`write_toml` entirely rather than
/// routing through them.
fn restore_file(
    ctx: &mut ModifyCtx,
    target: &Target,
    backup_path: &Path,
) -> anyhow::Result<WriteOutcome> {
    let label = target.path.display().to_string();
    let old_bytes = std::fs::read(&target.path).unwrap_or_default();
    let new_bytes = std::fs::read(backup_path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", backup_path.display()))?;
    let old_text = String::from_utf8_lossy(&old_bytes).into_owned();
    let new_text = String::from_utf8_lossy(&new_bytes).into_owned();

    let secrets = harvest_restore_secrets(&old_text, &new_text);
    let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();

    write!(
        ctx.out,
        "{}",
        redacted_diff(&label, &old_text, &new_text, &secret_refs)
    )?;

    if ctx.dry_run {
        writeln!(ctx.out, "(dry-run: no changes written to {label})")?;
        return Ok(WriteOutcome::DryRun);
    }

    let dir = target
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _lock = lock_config_dir(dir)?;
    if let Some(bak) = backup(target)? {
        writeln!(ctx.out, "backed up current {label} to {}", bak.display())?;
    }
    atomic_write(target, &new_bytes)?;
    writeln!(ctx.out, "restored {label} from {}", backup_path.display())?;

    Ok(WriteOutcome::Written {
        check_failed: false,
    })
}

struct RestoreCandidate {
    label: &'static str,
    target: Target,
    backups: Vec<PathBuf>,
}

/// `config restore [--from <unix-secs>]`. Targets are kratos.yml, hydra.yml,
/// and config.toml (when resolvable, same as `check`/`status`); any target
/// with no backups at all is skipped with a note, not an error. `--from`
/// picks that generation for every remaining target — a target that has
/// backups but not that specific one is a hard error (listing what's
/// available) so a restore never silently mixes generations across files.
/// Without `--from`, an interactive terminal is offered each target's newest
/// backup one at a time; non-interactively (or under `--yes`) it's an error
/// telling the operator to pass `--from`. `--dry-run` always previews the
/// newest backup per target without prompting, since nothing is written.
pub(crate) fn restore(ctx: &mut ModifyCtx, from: Option<&str>) -> anyhow::Result<i32> {
    let from_ts: Option<u64> =
        match from {
            Some(s) => Some(s.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("--from must be a unix-seconds timestamp, got `{s}`")
            })?),
            None => None,
        };

    let mut candidates = vec![
        (
            "Kratos",
            Target {
                path: ctx.kratos.path.clone(),
            },
        ),
        (
            "Hydra",
            Target {
                path: ctx.hydra.path.clone(),
            },
        ),
    ];
    if let Some(t) = &ctx.forseti {
        candidates.push((
            "Forseti config.toml",
            Target {
                path: t.path.clone(),
            },
        ));
    }

    let mut participants = Vec::new();
    for (label, target) in candidates {
        let backups = list_backups(&target)?;
        if backups.is_empty() {
            writeln!(
                ctx.out,
                "note: no backups for {label} ({}); skipping.",
                target.path.display()
            )?;
            continue;
        }
        participants.push(RestoreCandidate {
            label,
            target,
            backups,
        });
    }

    if participants.is_empty() {
        writeln!(
            ctx.out,
            "no backups found for any target; nothing to restore."
        )?;
        return Ok(0);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for p in &participants {
        writeln!(ctx.out, "== {} ({}) ==", p.label, p.target.path.display())?;
        for (i, bak) in p.backups.iter().enumerate() {
            let ts = backup_timestamp(bak).unwrap_or(0);
            let age = now.saturating_sub(ts);
            let size = std::fs::metadata(bak).map(|m| m.len()).unwrap_or(0);
            writeln!(
                ctx.out,
                "  [{i}] {} ({age}s ago, {size} bytes)",
                bak.display()
            )?;
        }
    }

    let interactive = std::io::stdin().is_terminal() && !ctx.yes;
    if from_ts.is_none() && !ctx.dry_run && !interactive {
        anyhow::bail!("pass --from <timestamp>");
    }

    let mut selections: Vec<(&RestoreCandidate, PathBuf)> = Vec::new();
    for p in &participants {
        if let Some(ts) = from_ts {
            match p
                .backups
                .iter()
                .find(|b| backup_timestamp(b.as_path()) == Some(ts))
            {
                Some(bak) => selections.push((p, bak.clone())),
                None => {
                    let available: Vec<String> = p
                        .backups
                        .iter()
                        .filter_map(|b| backup_timestamp(b.as_path()))
                        .map(|t| t.to_string())
                        .collect();
                    anyhow::bail!(
                        "{} has no backup at --from {ts}; available: {}",
                        p.target.path.display(),
                        available.join(", ")
                    );
                }
            }
            continue;
        }
        if ctx.dry_run {
            selections.push((p, p.backups[0].clone()));
            continue;
        }
        let bak = p.backups[0].clone();
        let ts = backup_timestamp(&bak).unwrap_or(0);
        let question = format!(
            "Restore {} ({}) to the backup from {ts}?",
            p.label,
            p.target.path.display()
        );
        if prompt_yes_no(ctx, &question)? {
            selections.push((p, bak));
        } else {
            writeln!(ctx.out, "skipped {} (no changes)", p.label)?;
        }
    }

    if selections.is_empty() {
        writeln!(ctx.out, "nothing selected; no changes made.")?;
        return Ok(0);
    }

    let mut any_dry_run = false;
    let mut any_check_failed = false;
    let mut changed = Vec::new();
    for (p, backup_path) in &selections {
        let outcome = restore_file(ctx, &p.target, backup_path)?;
        match outcome {
            WriteOutcome::DryRun => any_dry_run = true,
            WriteOutcome::Written { .. } => {
                changed.push(format!("changed: {}", p.target.path.display()));
                let is_yaml = p.target.path == ctx.kratos.path || p.target.path == ctx.hydra.path;
                if is_yaml && post_write_check(ctx, &p.target) {
                    any_check_failed = true;
                }
            }
        }
    }

    if any_dry_run {
        return Ok(0);
    }

    changed.push("run `forseti config check` to verify the restored state.".to_string());
    let extra: Vec<&str> = changed.iter().map(String::as_str).collect();
    print_runbook(&mut *ctx.out, &[], &extra);

    if any_check_failed {
        writeln!(
            ctx.out,
            "fix the FAIL above before restarting affected services."
        )?;
        Ok(1)
    } else {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// CLI entry.
// ---------------------------------------------------------------------------

fn secret_source(args: &SecretSourceArgs) -> SecretSource {
    if let Some(name) = &args.client_secret_env {
        SecretSource::Env(name.clone())
    } else if let Some(path) = &args.client_secret_file {
        SecretSource::File(path.clone())
    } else if args.client_secret_stdin {
        SecretSource::Stdin
    } else {
        SecretSource::Prompt("client_secret")
    }
}

fn build_ctx(paths: &PathArgs) -> anyhow::Result<ModifyCtx> {
    let (kratos_path, _) = resolve_config_path(
        paths.kratos.as_deref(),
        DEFAULT_KRATOS,
        "Kratos",
        "--kratos",
        ENV_KRATOS,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let (hydra_path, _) = resolve_config_path(
        paths.hydra.as_deref(),
        DEFAULT_HYDRA,
        "Hydra",
        "--hydra",
        ENV_HYDRA,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    Ok(ModifyCtx {
        kratos: resolve_target(&kratos_path, paths.follow_symlink)?,
        hydra: resolve_target(&hydra_path, paths.follow_symlink)?,
        forseti: resolve_forseti_toml_path(paths.forseti_config.as_deref())
            .and_then(|p| resolve_target(&p, paths.follow_symlink).ok()),
        dry_run: paths.dry_run,
        yes: paths.yes,
        out: Box::new(std::io::stdout()),
        input: Box::new(StdinLines),
    })
}

pub(crate) async fn run_oidc(cmd: OidcCmd, paths: &PathArgs) -> i32 {
    match cmd {
        OidcCmd::Enable {
            provider,
            client_id,
            secret,
            microsoft_tenant,
            keep_mapper,
        } => {
            if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
                eprintln!(
                    "error: unknown provider `{provider}`; expected google, github, or microsoft"
                );
                return 2;
            }
            let Some(client_id) = client_id else {
                eprintln!("error: missing --client-id");
                return 2;
            };
            let client_secret = match read_secret(secret_source(&secret)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let mut ctx = match build_ctx(paths) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let input = OidcEnableInput {
                provider,
                client_id,
                client_secret,
                microsoft_tenant,
                keep_mapper,
            };
            match oidc_enable(&mut ctx, input) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        OidcCmd::Disable { id } => {
            let mut ctx = match build_ctx(paths) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let admin_url = std::fs::read_to_string(&ctx.kratos.path)
                .ok()
                .and_then(|t| serde_yaml_ng::from_str::<Value>(&t).ok())
                .and_then(|r| dig_str(&r, &["serve", "admin", "base_url"]).map(str::to_string));
            match oidc_disable(&mut ctx, &id, admin_url.as_deref()).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
    }
}

pub(crate) fn run_rotate_webhook_token(paths: &PathArgs) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let interactive = std::io::stdin().is_terminal() && !ctx.yes;
    match rotate_webhook_token(&mut ctx, interactive) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

pub(crate) fn run_prune_webhook_token(paths: &PathArgs) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match prune_webhook_token(&mut ctx) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

pub(crate) fn run_rotate_kratos_secrets(paths: &PathArgs, cookie: bool, cipher: bool) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rotate_kratos_secrets(&mut ctx, cookie, cipher) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

pub(crate) fn run_prune_kratos_secrets(paths: &PathArgs, cookie: bool, cipher: bool) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match prune_kratos_secrets(&mut ctx, cookie, cipher) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

pub(crate) fn run_rotate_hydra_system(paths: &PathArgs) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rotate_hydra_system(&mut ctx) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

pub(crate) fn run_prune_hydra_system(paths: &PathArgs) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match prune_hydra_system(&mut ctx) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// `interactive` is derived from stdin's own TTY state, not `ctx.yes`: the
/// pairwise-salt gate is deliberately immune to `--yes` (see
/// `rotate_pairwise_salt`).
pub(crate) async fn run_rotate_pairwise_salt(paths: &PathArgs, confirmed: bool) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let interactive = std::io::stdin().is_terminal();
    match rotate_pairwise_salt(&mut ctx, confirmed, interactive).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// Maps `SmtpCmd::Set`'s at-most-one URI source flags to a `SecretSource`.
/// `None` when none were given — unlike `secret_source` (oidc's mandatory
/// client secret), there's no interactive-prompt fallback here: with no URI
/// flag, `smtp set` simply leaves the URI untouched (see `smtp_set`).
fn smtp_uri_source(
    uri_env: Option<String>,
    uri_file: Option<std::path::PathBuf>,
    uri_stdin: bool,
) -> Option<SecretSource> {
    if let Some(name) = uri_env {
        Some(SecretSource::Env(name))
    } else if let Some(path) = uri_file {
        Some(SecretSource::File(path))
    } else if uri_stdin {
        Some(SecretSource::Stdin)
    } else {
        None
    }
}

pub(crate) fn run_smtp(cmd: SmtpCmd, paths: &PathArgs) -> i32 {
    let SmtpCmd::Set {
        uri_env,
        uri_file,
        uri_stdin,
        from_address,
        from_name,
    } = cmd;

    let uri = match smtp_uri_source(uri_env, uri_file, uri_stdin) {
        Some(src) => match read_secret(src) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        },
        None => None,
    };

    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match smtp_set(&mut ctx, uri, from_address, from_name) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

pub(crate) fn run_restore(paths: &PathArgs, from: Option<String>) -> i32 {
    let mut ctx = match build_ctx(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match restore(&mut ctx, from.as_deref()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_cli::check::check_secret_lists;
    use crate::config_cli::init::{render_configs, InitInputs};
    use crate::config_cli::yamlutil::{dig, dig_bool};
    use std::path::PathBuf;

    fn render_default_kratos() -> Value {
        let (k, _, _) = render_configs(&InitInputs::default());
        serde_yaml_ng::from_str(&k).expect("kratos yaml parses")
    }

    fn playground_kratos() -> Value {
        let text = std::fs::read_to_string("infra/kratos/kratos.yml").expect("playground kratos");
        serde_yaml_ng::from_str(&text).expect("kratos yaml parses")
    }

    fn enable_input(provider: &str, tenant: Option<&str>) -> OidcEnableInput {
        OidcEnableInput {
            provider: provider.into(),
            client_id: "cid".into(),
            client_secret: "sec".into(),
            microsoft_tenant: tenant.map(str::to_string),
            keep_mapper: false,
        }
    }

    fn unique_tmp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("forseti-modify-{}-{label}", std::process::id()))
    }

    #[test]
    fn enable_github_shapes_the_yaml() {
        // render_default_kratos ships no web_hook, so this exercises the
        // no-audit-hook fallback: registration keeps `session`, login gets no
        // `after.oidc` node at all (Kratos's login flow doesn't accept the
        // `session` hook).
        let mut root = render_default_kratos();
        let used_fallback = apply_oidc_enable(
            &mut root,
            &enable_input("github", None),
            "file:///etc/config/kratos/oidc.github.jsonnet",
        )
        .unwrap();
        assert!(used_fallback, "default kratos.yml has no web_hook template");

        assert_eq!(
            dig_bool(&root, &["selfservice", "methods", "oidc", "enabled"]),
            Some(true)
        );
        let reg_hooks = dig(
            &root,
            &[
                "selfservice",
                "flows",
                "registration",
                "after",
                "oidc",
                "hooks",
            ],
        )
        .and_then(Value::as_sequence)
        .unwrap();
        assert_eq!(reg_hooks.len(), 1);
        assert_eq!(dig_str(&reg_hooks[0], &["hook"]), Some("session"));
        assert!(
            dig(&root, &["selfservice", "flows", "login", "after", "oidc"]).is_none(),
            "login flow must not get an after.oidc node without a web_hook template"
        );

        // github scope is user:email only.
        let scope = dig(
            &root,
            &["selfservice", "methods", "oidc", "config", "providers"],
        )
        .and_then(Value::as_sequence)
        .and_then(|s| s.first())
        .and_then(|p| dig(p, &["scope"]))
        .and_then(Value::as_sequence)
        .unwrap();
        assert_eq!(scope.len(), 1);
        assert_eq!(scope[0].as_str(), Some("user:email"));

        // Only the not-yet-written mapper file may FAIL.
        let findings = check_oidc_providers(&root, Path::new("."));
        assert!(
            findings
                .iter()
                .all(|f| f.severity != Severity::Fail || f.key.contains("mapper")),
            "unexpected non-mapper FAIL: {findings:?}"
        );
    }

    #[test]
    fn enable_clones_web_hook_on_playground_config() {
        let mut root = playground_kratos();
        let used_fallback = apply_oidc_enable(
            &mut root,
            &enable_input("google", None),
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();
        assert!(!used_fallback, "playground kratos.yml ships a web_hook");

        let reg = dig(
            &root,
            &[
                "selfservice",
                "flows",
                "registration",
                "after",
                "oidc",
                "hooks",
            ],
        )
        .and_then(Value::as_sequence)
        .unwrap();
        // session + a cloned web_hook.
        assert_eq!(reg.len(), 2);
        let url = dig(&reg[1], &["config", "url"])
            .and_then(Value::as_str)
            .unwrap();
        assert!(url.ends_with("?action=registration.oidc"), "url: {url}");
        assert!(url.contains("/internal/audit/kratos"), "url: {url}");
    }

    #[test]
    fn disable_last_provider_removes_method_and_hooks() {
        let mut root = playground_kratos();
        apply_oidc_enable(
            &mut root,
            &enable_input("google", None),
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();
        let empty = apply_oidc_disable(&mut root, "google").unwrap();
        assert!(empty, "removing the only provider empties the method");

        assert_eq!(
            dig_bool(&root, &["selfservice", "methods", "oidc", "enabled"]),
            Some(false)
        );
        assert!(dig(&root, &["selfservice", "flows", "login", "after", "oidc"]).is_none());
        assert!(dig(
            &root,
            &["selfservice", "flows", "registration", "after", "oidc"]
        )
        .is_none());
    }

    #[test]
    fn disable_keeps_method_when_other_provider_remains() {
        let mut root = playground_kratos();
        apply_oidc_enable(
            &mut root,
            &enable_input("google", None),
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();
        apply_oidc_enable(
            &mut root,
            &enable_input("github", None),
            "file:///etc/config/kratos/oidc.github.jsonnet",
        )
        .unwrap();
        let empty = apply_oidc_disable(&mut root, "google").unwrap();
        assert!(!empty);
        assert_eq!(
            dig_bool(&root, &["selfservice", "methods", "oidc", "enabled"]),
            Some(true)
        );
    }

    #[test]
    fn disable_unknown_provider_errors() {
        let mut root = playground_kratos();
        apply_oidc_enable(
            &mut root,
            &enable_input("google", None),
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();
        assert!(apply_oidc_disable(&mut root, "github").is_err());
    }

    #[test]
    fn microsoft_common_tenant_refused() {
        let mut root = render_default_kratos();
        let err = apply_oidc_enable(
            &mut root,
            &enable_input("microsoft", Some("common")),
            "file:///etc/config/kratos/oidc.microsoft.jsonnet",
        )
        .unwrap_err();
        assert!(err.contains("common"), "err: {err}");
    }

    #[test]
    fn microsoft_without_tenant_refused() {
        let mut root = render_default_kratos();
        assert!(apply_oidc_enable(
            &mut root,
            &enable_input("microsoft", None),
            "file:///etc/config/kratos/oidc.microsoft.jsonnet",
        )
        .is_err());
    }

    #[test]
    fn microsoft_specific_tenant_is_written() {
        let mut root = render_default_kratos();
        apply_oidc_enable(
            &mut root,
            &enable_input("microsoft", Some("tenant-123")),
            "file:///etc/config/kratos/oidc.microsoft.jsonnet",
        )
        .unwrap();
        let provider = dig(
            &root,
            &["selfservice", "methods", "oidc", "config", "providers"],
        )
        .and_then(Value::as_sequence)
        .and_then(|s| s.first())
        .unwrap();
        assert_eq!(dig_str(provider, &["microsoft_tenant"]), Some("tenant-123"));
    }

    #[test]
    fn re_enabling_replaces_the_same_provider() {
        let mut root = playground_kratos();
        apply_oidc_enable(
            &mut root,
            &enable_input("google", None),
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();
        let mut second = enable_input("google", None);
        second.client_id = "cid2".into();
        apply_oidc_enable(
            &mut root,
            &second,
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();

        let providers = dig(
            &root,
            &["selfservice", "methods", "oidc", "config", "providers"],
        )
        .and_then(Value::as_sequence)
        .unwrap();
        assert_eq!(providers.len(), 1, "same id must replace, not duplicate");
        assert_eq!(dig_str(&providers[0], &["client_id"]), Some("cid2"));
    }

    #[test]
    fn mapper_mismatch_requires_keep_mapper() {
        let dir = unique_tmp_dir("mapper-mismatch");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("kratos.yml"), "selfservice: {}\n").unwrap();
        std::fs::write(
            dir.join("oidc.github.jsonnet"),
            "local claims = std.extVar('claims');\n{ identity: { traits: { email: claims.email } } }\n",
        )
        .unwrap();

        let mut c1 = ModifyCtx {
            kratos: Target {
                path: dir.join("kratos.yml"),
            },
            hydra: Target {
                path: dir.join("hydra.yml"),
            },
            forseti: None,
            dry_run: true,
            yes: true,
            out: Box::new(std::io::sink()),
            input: Box::new(std::io::empty()),
        };
        let err = oidc_enable(
            &mut c1,
            OidcEnableInput {
                provider: "github".into(),
                client_id: "cid".into(),
                client_secret: "sec".into(),
                microsoft_tenant: None,
                keep_mapper: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("differs"), "err: {err}");

        // With --keep-mapper it proceeds (dry-run, so no write).
        let mut c2 = ModifyCtx {
            kratos: Target {
                path: dir.join("kratos.yml"),
            },
            hydra: Target {
                path: dir.join("hydra.yml"),
            },
            forseti: None,
            dry_run: true,
            yes: true,
            out: Box::new(std::io::sink()),
            input: Box::new(std::io::empty()),
        };
        assert!(oidc_enable(
            &mut c2,
            OidcEnableInput {
                provider: "github".into(),
                client_id: "cid".into(),
                client_secret: "sec".into(),
                microsoft_tenant: None,
                keep_mapper: true,
            },
        )
        .is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = unique_tmp_dir("dry-run");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos = dir.join("kratos.yml");
        std::fs::copy("infra/kratos/kratos.yml", &kratos).unwrap();
        let before = std::fs::read_to_string(&kratos).unwrap();

        let mut ctx = ModifyCtx {
            kratos: Target {
                path: kratos.clone(),
            },
            hydra: Target {
                path: dir.join("hydra.yml"),
            },
            forseti: None,
            dry_run: true,
            yes: false,
            out: Box::new(std::io::sink()),
            input: Box::new(std::io::empty()),
        };
        oidc_enable(
            &mut ctx,
            OidcEnableInput {
                provider: "github".into(),
                client_id: "x".into(),
                client_secret: "dummysecret".into(),
                microsoft_tenant: None,
                keep_mapper: false,
            },
        )
        .unwrap();

        assert_eq!(std::fs::read_to_string(&kratos).unwrap(), before);
        assert!(
            !dir.join("oidc.github.jsonnet").exists(),
            "mapper must not be written on dry-run"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_pinned_mapper_lands_0600_and_matches() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = unique_tmp_dir("mapper-write");
        std::fs::create_dir_all(&dir).unwrap();
        let mapper = dir.join("oidc.google.jsonnet");

        let mut ctx = ModifyCtx {
            kratos: Target {
                path: dir.join("kratos.yml"),
            },
            hydra: Target {
                path: dir.join("hydra.yml"),
            },
            forseti: None,
            dry_run: false,
            yes: true,
            out: Box::new(std::io::sink()),
            input: Box::new(std::io::empty()),
        };
        handle_mapper(&mut ctx, &mapper, "google", false).unwrap();

        let mode = std::fs::metadata(&mapper).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&mapper).unwrap(), MAPPER_GOOGLE);

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Review-round fixes: secret redaction union, audited-hook fallback,
    // validate-before-side-effects.
    // -----------------------------------------------------------------------

    #[derive(Clone)]
    struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("test capture mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn captured_ctx(
        kratos: PathBuf,
        hydra: PathBuf,
        dry_run: bool,
        yes: bool,
    ) -> (ModifyCtx, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ctx = ModifyCtx {
            kratos: Target { path: kratos },
            hydra: Target { path: hydra },
            forseti: None,
            dry_run,
            yes,
            out: Box::new(CapturingWriter(buf.clone())),
            input: Box::new(std::io::empty()),
        };
        (ctx, buf)
    }

    fn captured_text(buf: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).expect("captured output is UTF-8")
    }

    #[tokio::test]
    async fn disable_redacts_removed_provider_secret_in_diff() {
        const FIXTURE_SECRET: &str = "fixture-old-secret-abcXYZ";
        let dir = unique_tmp_dir("disable-redact");
        std::fs::create_dir_all(&dir).unwrap();

        let mut root = playground_kratos();
        apply_oidc_enable(
            &mut root,
            &OidcEnableInput {
                provider: "google".into(),
                client_id: "cid".into(),
                client_secret: FIXTURE_SECRET.into(),
                microsoft_tenant: None,
                keep_mapper: false,
            },
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();
        std::fs::write(
            dir.join("kratos.yml"),
            serde_yaml_ng::to_string(&root).unwrap(),
        )
        .unwrap();

        let (mut ctx, buf) =
            captured_ctx(dir.join("kratos.yml"), dir.join("hydra.yml"), true, true);
        oidc_disable(&mut ctx, "google", None).await.unwrap();

        let out = captured_text(&buf);
        assert!(out.contains("<redacted"), "out: {out}");
        assert!(!out.contains(FIXTURE_SECRET), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn re_enable_redacts_the_old_secret_too() {
        const OLD_SECRET: &str = "fixture-old-secret-111";
        const NEW_SECRET: &str = "fixture-new-secret-222";
        let dir = unique_tmp_dir("reenable-redact");
        std::fs::create_dir_all(&dir).unwrap();

        let mut root = playground_kratos();
        apply_oidc_enable(
            &mut root,
            &OidcEnableInput {
                provider: "google".into(),
                client_id: "cid".into(),
                client_secret: OLD_SECRET.into(),
                microsoft_tenant: None,
                keep_mapper: false,
            },
            "file:///etc/config/kratos/oidc.google.jsonnet",
        )
        .unwrap();
        std::fs::write(
            dir.join("kratos.yml"),
            serde_yaml_ng::to_string(&root).unwrap(),
        )
        .unwrap();

        let (mut ctx, buf) =
            captured_ctx(dir.join("kratos.yml"), dir.join("hydra.yml"), true, true);
        oidc_enable(
            &mut ctx,
            OidcEnableInput {
                provider: "google".into(),
                client_id: "cid2".into(),
                client_secret: NEW_SECRET.into(),
                microsoft_tenant: None,
                keep_mapper: false,
            },
        )
        .unwrap();

        let out = captured_text(&buf);
        assert!(out.contains("<redacted"), "out: {out}");
        assert!(!out.contains(OLD_SECRET), "old secret leaked; out: {out}");
        assert!(!out.contains(NEW_SECRET), "new secret leaked; out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn enable_fallback_warns_and_login_gets_no_after_oidc() {
        let dir = unique_tmp_dir("fallback-warn");
        std::fs::create_dir_all(&dir).unwrap();
        let (k, _, _) = render_configs(&InitInputs::default());
        let kratos_path = dir.join("kratos.yml");
        std::fs::write(&kratos_path, &k).unwrap();

        let (mut ctx, buf) = captured_ctx(kratos_path.clone(), dir.join("hydra.yml"), false, true);
        oidc_enable(
            &mut ctx,
            OidcEnableInput {
                provider: "github".into(),
                client_id: "cid".into(),
                client_secret: "sec".into(),
                microsoft_tenant: None,
                keep_mapper: false,
            },
        )
        .unwrap();

        let out = captured_text(&buf);
        assert!(
            out.contains("no audit web_hook template"),
            "warning missing from output: {out}"
        );
        assert!(out.contains("docs/operator-guide.md"), "out: {out}");

        let written = std::fs::read_to_string(&kratos_path).unwrap();
        let root: Value = serde_yaml_ng::from_str(&written).unwrap();
        let reg_hooks = dig(
            &root,
            &[
                "selfservice",
                "flows",
                "registration",
                "after",
                "oidc",
                "hooks",
            ],
        )
        .and_then(Value::as_sequence)
        .unwrap();
        assert_eq!(reg_hooks.len(), 1);
        assert_eq!(dig_str(&reg_hooks[0], &["hook"]), Some("session"));
        assert!(
            dig(&root, &["selfservice", "flows", "login", "after", "oidc"]).is_none(),
            "login flow must not get an after.oidc node without a web_hook template"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn microsoft_common_tenant_leaves_no_mapper_file() {
        let dir = unique_tmp_dir("common-tenant-no-mapper");
        std::fs::create_dir_all(&dir).unwrap();
        let (k, _, _) = render_configs(&InitInputs::default());
        let kratos_path = dir.join("kratos.yml");
        std::fs::write(&kratos_path, &k).unwrap();
        let mapper_path = dir.join("oidc.microsoft.jsonnet");

        let mut ctx = ModifyCtx {
            kratos: Target { path: kratos_path },
            hydra: Target {
                path: dir.join("hydra.yml"),
            },
            forseti: None,
            dry_run: false,
            yes: true,
            out: Box::new(std::io::sink()),
            input: Box::new(std::io::empty()),
        };
        let err = oidc_enable(
            &mut ctx,
            OidcEnableInput {
                provider: "microsoft".into(),
                client_id: "cid".into(),
                client_secret: "sec".into(),
                microsoft_tenant: Some("common".into()),
                keep_mapper: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("common"), "err: {err}");
        assert!(
            !mapper_path.exists(),
            "tenant validation must run before the mapper is ever written"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enable_aborted_write_removes_freshly_created_mapper() {
        // No TTY in the test harness: write_yaml's comment-drop prompt bails
        // the same way a `no` answer would, so this doubles as the "user
        // declined" rollback path.
        let dir = unique_tmp_dir("abort-removes-mapper");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        std::fs::copy("infra/kratos/kratos.yml", &kratos_path).unwrap();
        let mapper_path = dir.join("oidc.github.jsonnet");

        let mut ctx = ModifyCtx {
            kratos: Target { path: kratos_path },
            hydra: Target {
                path: dir.join("hydra.yml"),
            },
            forseti: None,
            dry_run: false,
            yes: false,
            out: Box::new(std::io::sink()),
            input: Box::new(std::io::empty()),
        };
        let err = oidc_enable(
            &mut ctx,
            OidcEnableInput {
                provider: "github".into(),
                client_id: "cid".into(),
                client_secret: "sec".into(),
                microsoft_tenant: None,
                keep_mapper: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("TTY"), "err: {err}");
        assert!(
            !mapper_path.exists(),
            "a mapper created this run must be removed when the write is aborted"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // rotate/prune webhook-token.
    // -----------------------------------------------------------------------

    fn kratos_with_token(token: &str) -> String {
        format!(
            r#"session:
  whoami:
    required_aal: highest_available
selfservice:
  flows:
    settings:
      required_aal: highest_available
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
                    value: "Bearer {token}"
                    in: header
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
"#
        )
    }

    fn config_toml_with(webhook_token_literal: &str) -> String {
        format!(
            "[audit]\nwebhook_token = {webhook_token_literal}\nip_salt = \"\"\naudit_retention_days = 90\n"
        )
    }

    fn rotate_ctx(
        kratos: PathBuf,
        forseti: PathBuf,
        yes: bool,
    ) -> (ModifyCtx, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ctx = ModifyCtx {
            kratos: Target { path: kratos },
            hydra: Target {
                path: PathBuf::from("/nonexistent/hydra.yml"),
            },
            forseti: Some(Target { path: forseti }),
            dry_run: false,
            yes,
            out: Box::new(CapturingWriter(buf.clone())),
            input: Box::new(std::io::empty()),
        };
        (ctx, buf)
    }

    fn toml_webhook_item_is_string(text: &str) -> bool {
        let doc: DocumentMut = text.parse().expect("resulting config.toml parses");
        doc["audit"]["webhook_token"].as_str().is_some()
    }

    fn toml_webhook_array(text: &str) -> Vec<String> {
        let doc: DocumentMut = text.parse().expect("resulting config.toml parses");
        toml_get_webhook_tokens(&doc)
    }

    // -- rewrite_hook_tokens: structural match only --------------------------

    #[test]
    fn rewrite_hook_tokens_matches_structurally_only() {
        let raw = std::fs::read_to_string("infra/kratos/kratos.yml").expect("playground kratos");
        let hook_count = raw.matches("hook: web_hook").count();

        let mut text = raw.clone();
        // A plain string mentioning the old token, and a mapping shaped like a
        // hook's auth block but under a non-`web_hook` hook: neither is a
        // `web_hook` node, so both must survive rewrite_hook_tokens untouched.
        text.push_str(
            r#"
extra:
  plain_string_mentioning_token: "see dev-playground-token-change-me in the runbook"
  not_a_hook:
    hook: not_web_hook
    config:
      auth:
        type: api_key
        config:
          name: Authorization
          value: "Bearer dev-playground-token-change-me"
"#,
        );
        let mut root: Value = serde_yaml_ng::from_str(&text).expect("fixture yaml parses");

        let n = rewrite_hook_tokens(&mut root, "brand-new-token-value");
        assert_eq!(
            n, hook_count,
            "must rewrite exactly the real web_hook nodes"
        );

        let rendered = serde_yaml_ng::to_string(&root).unwrap();
        assert_eq!(
            rendered.matches("brand-new-token-value").count(),
            hook_count,
            "every real hook must carry the new token"
        );
        // The decoy plain string and the decoy non-web_hook mapping both keep
        // the old literal — 2 survivors, not rewritten.
        assert_eq!(
            rendered.matches("dev-playground-token-change-me").count(),
            2
        );
    }

    #[test]
    fn rewrite_hook_tokens_on_hookless_kratos_is_a_noop() {
        let mut root = render_default_kratos();
        assert_eq!(rewrite_hook_tokens(&mut root, "whatever"), 0);
    }

    // -- toml_set_webhook_tokens: shape + losslessness -----------------------

    #[test]
    fn toml_set_webhook_tokens_single_becomes_string_multi_becomes_array() {
        let mut doc: DocumentMut = "[audit]\nwebhook_token = \"old\"\n".parse().unwrap();
        toml_set_webhook_tokens(&mut doc, &["only-one".to_string()]);
        assert_eq!(doc["audit"]["webhook_token"].as_str(), Some("only-one"));

        toml_set_webhook_tokens(&mut doc, &["new".to_string(), "old".to_string()]);
        assert_eq!(
            toml_get_webhook_tokens(&doc),
            vec!["new".to_string(), "old".to_string()]
        );
    }

    #[test]
    fn toml_set_webhook_tokens_preserves_an_unrelated_comment() {
        let mut doc: DocumentMut =
            "# a note the operator left behind\n[audit]\nwebhook_token = \"old\"\n"
                .parse()
                .unwrap();
        toml_set_webhook_tokens(&mut doc, &["new".to_string()]);
        let rendered = doc.to_string();
        assert!(
            rendered.contains("# a note the operator left behind"),
            "rendered: {rendered}"
        );
        assert_eq!(toml_get_webhook_tokens(&doc), vec!["new".to_string()]);
    }

    #[test]
    fn minimal_config_toml_parses_and_has_an_audit_table() {
        let doc: DocumentMut = minimal_config_toml().parse().expect("valid toml");
        assert!(doc.contains_table("audit"));
        assert!(doc.contains_table("internal"));
        assert!(doc.contains_table("self"));
    }

    // -- rotate_webhook_token: placeholder => replace in one pass ------------

    #[test]
    fn rotate_placeholder_current_token_replaces_in_one_pass() {
        let dir = unique_tmp_dir("rotate-placeholder");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(
            &kratos_path,
            kratos_with_token("dev-playground-token-change-me"),
        )
        .unwrap();
        std::fs::write(
            &toml_path,
            config_toml_with("\"dev-playground-token-change-me\""),
        )
        .unwrap();

        let (mut ctx, buf) = rotate_ctx(kratos_path.clone(), toml_path.clone(), true);
        let code = rotate_webhook_token(&mut ctx, false).expect("rotate succeeds");
        assert_eq!(code, 0);

        let new_toml = std::fs::read_to_string(&toml_path).unwrap();
        assert!(
            toml_webhook_item_is_string(&new_toml),
            "placeholder rotation must leave a single string, not an accept-list array"
        );
        let tokens = toml_webhook_array(&new_toml);
        assert_eq!(tokens.len(), 1);
        assert_ne!(tokens[0], "dev-playground-token-change-me");

        let new_kratos = std::fs::read_to_string(&kratos_path).unwrap();
        assert!(!new_kratos.contains("dev-playground-token-change-me"));
        assert!(new_kratos.contains(&tokens[0]));

        let out = captured_text(&buf);
        assert!(!out.contains(&tokens[0]), "new token leaked: {out}");
        assert!(
            !out.contains("dev-playground-token-change-me"),
            "old token leaked unredacted: {out}"
        );
        assert!(out.contains("<redacted"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- rotate_webhook_token: staged accept list -----------------------------

    #[test]
    fn rotate_staged_non_placeholder_yields_two_entry_list_new_first() {
        let dir = unique_tmp_dir("rotate-staged");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(&kratos_path, kratos_with_token("real-prod-token-xyz")).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"real-prod-token-xyz\"")).unwrap();

        let (mut ctx, buf) = rotate_ctx(kratos_path.clone(), toml_path.clone(), true);
        // Non-interactive: writes both back-to-back and warns about the window.
        let code = rotate_webhook_token(&mut ctx, false).expect("rotate succeeds");
        assert_eq!(code, 0);

        let new_toml = std::fs::read_to_string(&toml_path).unwrap();
        let tokens = toml_webhook_array(&new_toml);
        assert_eq!(tokens.len(), 2, "staged rotation must yield a 2-entry list");
        assert_eq!(tokens[1], "real-prod-token-xyz", "old token stays second");
        assert_ne!(tokens[0], "real-prod-token-xyz", "new token comes first");

        let new_kratos = std::fs::read_to_string(&kratos_path).unwrap();
        assert!(
            new_kratos.contains(&tokens[0]),
            "kratos.yml gets the new token"
        );
        assert!(!new_kratos.contains("real-prod-token-xyz"));

        let out = captured_text(&buf);
        assert!(
            out.contains("audit-loss") || out.contains("401"),
            "non-interactive staged rotation must warn about the window: {out}"
        );
        assert!(
            !out.contains("real-prod-token-xyz"),
            "old token leaked: {out}"
        );
        assert!(!out.contains(&tokens[0]), "new token leaked: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_staged_interactive_waits_then_rewrites_kratos() {
        // No TTY in the test harness, so stdin reads EOF immediately — this
        // exercises the "press Enter" wait without actually blocking.
        let dir = unique_tmp_dir("rotate-staged-interactive");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(&kratos_path, kratos_with_token("real-prod-token-xyz")).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"real-prod-token-xyz\"")).unwrap();

        let (mut ctx, buf) = rotate_ctx(kratos_path.clone(), toml_path.clone(), true);
        let code = rotate_webhook_token(&mut ctx, true).expect("rotate succeeds");
        assert_eq!(code, 0);

        let new_toml = std::fs::read_to_string(&toml_path).unwrap();
        let tokens = toml_webhook_array(&new_toml);
        assert_eq!(tokens.len(), 2);

        let new_kratos = std::fs::read_to_string(&kratos_path).unwrap();
        assert!(new_kratos.contains(&tokens[0]));

        let out = captured_text(&buf);
        assert!(out.contains("press Enter"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_dry_run_with_non_placeholder_token_never_prompts_or_writes() {
        // A LineSource that panics if read: proves the dry-run path never
        // reaches the staged-restart Enter-wait, which would otherwise block
        // on it (or, under a scripted input, silently consume a line).
        struct PanicOnRead;
        impl LineSource for PanicOnRead {
            fn read_line(&mut self, _buf: &mut String) -> std::io::Result<usize> {
                panic!("dry-run must never read from input");
            }
            fn is_terminal(&self) -> bool {
                true
            }
        }

        let dir = unique_tmp_dir("rotate-dry-run-non-placeholder");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(&kratos_path, kratos_with_token("real-prod-token-xyz")).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"real-prod-token-xyz\"")).unwrap();
        let kratos_before = std::fs::read_to_string(&kratos_path).unwrap();
        let toml_before = std::fs::read_to_string(&toml_path).unwrap();

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut ctx = ModifyCtx {
            kratos: Target {
                path: kratos_path.clone(),
            },
            hydra: Target {
                path: PathBuf::from("/nonexistent/hydra.yml"),
            },
            forseti: Some(Target {
                path: toml_path.clone(),
            }),
            dry_run: true,
            yes: false,
            out: Box::new(CapturingWriter(buf.clone())),
            input: Box::new(PanicOnRead),
        };
        let code = rotate_webhook_token(&mut ctx, true).expect("dry-run rotate succeeds");
        assert_eq!(code, 0);

        assert_eq!(
            std::fs::read_to_string(&kratos_path).unwrap(),
            kratos_before,
            "dry-run must not write kratos.yml"
        );
        assert_eq!(
            std::fs::read_to_string(&toml_path).unwrap(),
            toml_before,
            "dry-run must not write config.toml"
        );

        let out = captured_text(&buf);
        assert!(
            !out.contains("press Enter"),
            "dry-run must not stage the interactive restart wait: {out}"
        );
        assert!(
            !out.contains("Restart Forseti as soon as"),
            "dry-run must not print the non-interactive restart warning either: {out}"
        );
        assert!(
            !out.contains("Next steps:"),
            "dry-run must not print the runbook: {out}"
        );
        assert!(out.contains("dry run"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- rotate_webhook_token: hook-less kratos.yml ---------------------------

    #[test]
    fn rotate_hookless_kratos_rotates_config_toml_only() {
        let dir = unique_tmp_dir("rotate-hookless");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        let (k, _, _) = render_configs(&InitInputs::default());
        std::fs::write(&kratos_path, &k).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"existing-real-token\"")).unwrap();
        let kratos_before = std::fs::read_to_string(&kratos_path).unwrap();

        let (mut ctx, buf) = rotate_ctx(kratos_path.clone(), toml_path.clone(), true);
        let code = rotate_webhook_token(&mut ctx, false).expect("rotate succeeds");
        assert_eq!(code, 0);

        assert_eq!(
            std::fs::read_to_string(&kratos_path).unwrap(),
            kratos_before,
            "a hook-less kratos.yml must not be rewritten"
        );

        let new_toml = std::fs::read_to_string(&toml_path).unwrap();
        let tokens = toml_webhook_array(&new_toml);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[1], "existing-real-token");

        let out = captured_text(&buf);
        assert!(
            out.contains("no audit web_hook nodes"),
            "must explain why kratos.yml wasn't touched: {out}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_hookless_kratos_with_placeholder_toml_replaces_in_one_pass() {
        let dir = unique_tmp_dir("rotate-hookless-placeholder");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        let (k, _, _) = render_configs(&InitInputs::default());
        std::fs::write(&kratos_path, &k).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"\"")).unwrap();

        let (mut ctx, _buf) = rotate_ctx(kratos_path.clone(), toml_path.clone(), true);
        let code = rotate_webhook_token(&mut ctx, false).expect("rotate succeeds");
        assert_eq!(code, 0);

        let new_toml = std::fs::read_to_string(&toml_path).unwrap();
        assert!(toml_webhook_item_is_string(&new_toml));
        let tokens = toml_webhook_array(&new_toml);
        assert_eq!(tokens.len(), 1);
        assert!(!tokens[0].is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- prune_webhook_token ---------------------------------------------------

    #[test]
    fn prune_refuses_when_kratos_token_not_in_accept_list() {
        let dir = unique_tmp_dir("prune-refuse");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(&kratos_path, kratos_with_token("T1")).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"T2\"")).unwrap();

        let (mut ctx, _buf) = rotate_ctx(kratos_path, toml_path.clone(), true);
        let err = prune_webhook_token(&mut ctx).unwrap_err();
        assert!(err.to_string().contains("accept list"), "err: {err}");

        // Refusal must not touch config.toml.
        let after = std::fs::read_to_string(&toml_path).unwrap();
        assert!(after.contains("\"T2\""));
    }

    #[test]
    fn prune_succeeds_and_trims_to_the_single_kratos_token() {
        let dir = unique_tmp_dir("prune-success");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(&kratos_path, kratos_with_token("T1")).unwrap();
        std::fs::write(&toml_path, config_toml_with("[\"T2\", \"T1\"]")).unwrap();

        let (mut ctx, buf) = rotate_ctx(kratos_path, toml_path.clone(), true);
        let code = prune_webhook_token(&mut ctx).expect("prune succeeds");
        assert_eq!(code, 0);

        let after = std::fs::read_to_string(&toml_path).unwrap();
        assert!(toml_webhook_item_is_string(&after));
        assert_eq!(toml_webhook_array(&after), vec!["T1".to_string()]);

        let out = captured_text(&buf);
        assert!(!out.contains("T1") || out.contains("<redacted"));
    }

    #[test]
    fn prune_hookless_kratos_with_multiple_entries_refuses() {
        let dir = unique_tmp_dir("prune-hookless-refuse");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        let (k, _, _) = render_configs(&InitInputs::default());
        std::fs::write(&kratos_path, &k).unwrap();
        std::fs::write(&toml_path, config_toml_with("[\"T2\", \"T1\"]")).unwrap();

        let (mut ctx, _buf) = rotate_ctx(kratos_path, toml_path, true);
        let err = prune_webhook_token(&mut ctx).unwrap_err();
        assert!(err.to_string().contains("no audit web_hook"), "err: {err}");
    }

    #[test]
    fn prune_hookless_kratos_with_single_entry_is_a_noop() {
        let dir = unique_tmp_dir("prune-hookless-noop");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        let (k, _, _) = render_configs(&InitInputs::default());
        std::fs::write(&kratos_path, &k).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"only-one\"")).unwrap();
        let before = std::fs::read_to_string(&toml_path).unwrap();

        let (mut ctx, buf) = rotate_ctx(kratos_path, toml_path.clone(), true);
        let code = prune_webhook_token(&mut ctx).expect("noop, not a refusal");
        assert_eq!(code, 0);
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), before);

        let out = captured_text(&buf);
        assert!(out.contains("nothing to prune"), "out: {out}");
    }

    // -- env shadow warnings ----------------------------------------------------

    #[test]
    fn rotate_warns_when_env_shadows_the_webhook_token() {
        let dir = unique_tmp_dir("rotate-env-shadow");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(&kratos_path, kratos_with_token("real-prod-token-xyz")).unwrap();
        std::fs::write(&toml_path, config_toml_with("\"real-prod-token-xyz\"")).unwrap();

        // SAFETY: test-only env var, unique name, single-threaded within this test's scope.
        unsafe {
            std::env::set_var("FORSETI_AUDIT__WEBHOOK_TOKEN", "shadow");
        }
        let (mut ctx, buf) = rotate_ctx(kratos_path, toml_path, true);
        rotate_webhook_token(&mut ctx, false).expect("rotate succeeds");
        unsafe {
            std::env::remove_var("FORSETI_AUDIT__WEBHOOK_TOKEN");
        }

        let out = captured_text(&buf);
        assert!(out.contains("FORSETI_AUDIT__WEBHOOK_TOKEN"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- config.toml bootstrap --------------------------------------------------

    #[test]
    fn rotate_non_interactive_missing_config_toml_errors_with_guidance() {
        let dir = unique_tmp_dir("rotate-missing-toml");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let toml_path = dir.join("config.toml"); // never created
        std::fs::write(&kratos_path, kratos_with_token("real-prod-token-xyz")).unwrap();

        let (mut ctx, _buf) = rotate_ctx(kratos_path, toml_path, true);
        let err = rotate_webhook_token(&mut ctx, false).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "err: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // rotate/prune kratos-secrets + hydra-system + pairwise-salt.
    // -----------------------------------------------------------------------

    const COOKIE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CIPHER_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SYSTEM_A: &str = "cccccccccccccccccccccccccccccccc";
    const SALT_A: &str = "dddddddddddddddddddddddddddddddd";

    fn kratos_scalar_secrets() -> String {
        format!("secrets:\n  cookie: {COOKIE_A}\n  cipher: {CIPHER_A}\n")
    }

    /// A `check_kratos`-clean fixture (mirrors `check.rs`'s
    /// `good_kratos_has_no_warn_or_fail`): rotate/prune tests assert `code ==
    /// 0`, so any FAIL findings here would be noise unrelated to the secret
    /// being exercised, not `render_configs(&InitInputs::default())`'s
    /// CHANGEME placeholders.
    fn kratos_good_fixture() -> String {
        format!(
            r#"session:
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
    - {COOKIE_A}
  cipher:
    - {CIPHER_A}
courier:
  smtp:
    connection_uri: smtps://user:pass@smtp.example.com:465
"#
        )
    }

    /// A `check_hydra`-clean fixture, for the same reason as
    /// `kratos_good_fixture`.
    fn hydra_good_fixture() -> String {
        format!(
            r#"secrets:
  system:
    - {SYSTEM_A}
urls:
  self:
    issuer: https://hydra.example.com
  login: https://forseti.example.com/oauth/login
  consent: https://forseti.example.com/oauth/consent
  logout: https://forseti.example.com/oauth/logout
oidc:
  subject_identifiers:
    pairwise:
      salt: {SALT_A}
"#
        )
    }

    fn kratos_hydra_fixture(dir: &Path) -> (PathBuf, PathBuf) {
        let kratos_path = dir.join("kratos.yml");
        let hydra_path = dir.join("hydra.yml");
        std::fs::write(&kratos_path, kratos_good_fixture()).unwrap();
        std::fs::write(&hydra_path, hydra_good_fixture()).unwrap();
        (kratos_path, hydra_path)
    }

    // -- rotate_secret_list / prune_secret_list: pure mutations -------------

    #[test]
    fn rotate_secret_list_turns_scalar_cookie_into_two_entry_list_new_first() {
        let mut root: Value = serde_yaml_ng::from_str(&kratos_scalar_secrets()).unwrap();
        rotate_secret_list(
            &mut root,
            &["secrets", "cookie"],
            "newcookie1111111111111111111111".to_string(),
        )
        .unwrap();
        let entries = secret_entries(&root, &["secrets", "cookie"]);
        assert_eq!(entries, vec!["newcookie1111111111111111111111", COOKIE_A]);
    }

    #[test]
    fn rotate_secret_list_accumulates_and_check_warns_past_three_entries() {
        let mut root: Value = serde_yaml_ng::from_str(&kratos_scalar_secrets()).unwrap();
        rotate_secret_list(&mut root, &["secrets", "cookie"], random_secret(32)).unwrap();
        assert_eq!(secret_entries(&root, &["secrets", "cookie"]).len(), 2);

        rotate_secret_list(&mut root, &["secrets", "cookie"], random_secret(32)).unwrap();
        assert_eq!(secret_entries(&root, &["secrets", "cookie"]).len(), 3);
        let findings = check_secret_lists(&root, false);
        assert!(
            !findings.iter().any(|f| f.key == "secrets.cookie.count"),
            "3 entries must not warn yet: {findings:?}"
        );

        rotate_secret_list(&mut root, &["secrets", "cookie"], random_secret(32)).unwrap();
        assert_eq!(secret_entries(&root, &["secrets", "cookie"]).len(), 4);
        let findings = check_secret_lists(&root, false);
        assert!(
            findings
                .iter()
                .any(|f| f.key == "secrets.cookie.count" && f.severity == Severity::Warn),
            "4 entries must warn: {findings:?}"
        );
    }

    #[test]
    fn cipher_rotation_entries_all_pass_check_secret_lists() {
        let mut root: Value = serde_yaml_ng::from_str(&kratos_scalar_secrets()).unwrap();
        rotate_secret_list(&mut root, &["secrets", "cipher"], random_secret(32)).unwrap();
        let findings = check_secret_lists(&root, false);
        let cipher_bad: Vec<_> = findings
            .iter()
            .filter(|f| f.key.starts_with("secrets.cipher") && f.severity != Severity::Ok)
            .collect();
        assert!(cipher_bad.is_empty(), "{cipher_bad:?}");
    }

    #[test]
    fn prune_secret_list_keeps_only_first_entry() {
        let mut root: Value =
            serde_yaml_ng::from_str("secrets:\n  cookie:\n    - new\n    - old\n").unwrap();
        prune_secret_list(&mut root, &["secrets", "cookie"]).unwrap();
        assert_eq!(secret_entries(&root, &["secrets", "cookie"]), vec!["new"]);
    }

    #[test]
    fn prune_secret_list_errors_on_single_entry_list() {
        let mut root: Value = serde_yaml_ng::from_str("secrets:\n  cookie:\n    - only\n").unwrap();
        let err = prune_secret_list(&mut root, &["secrets", "cookie"]).unwrap_err();
        assert!(err.contains("nothing to prune"), "err: {err}");
    }

    #[test]
    fn prune_secret_list_errors_on_bare_scalar() {
        let mut root: Value = serde_yaml_ng::from_str(&kratos_scalar_secrets()).unwrap();
        let err = prune_secret_list(&mut root, &["secrets", "cookie"]).unwrap_err();
        assert!(err.contains("nothing to prune"), "err: {err}");
    }

    // -- rotate_kratos_secrets ------------------------------------------------

    #[test]
    fn rotate_kratos_secrets_cookie_only_grows_cookie_leaves_cipher() {
        let dir = unique_tmp_dir("rotate-kratos-cookie-only");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let before: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&kratos_path).unwrap()).unwrap();
        let cipher_before = secret_entries(&before, &["secrets", "cipher"])[0].to_string();

        let (mut ctx, buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        let code = rotate_kratos_secrets(&mut ctx, true, false).expect("rotate succeeds");
        assert_eq!(code, 0);

        let root: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&kratos_path).unwrap()).unwrap();
        let cookie = secret_entries(&root, &["secrets", "cookie"]);
        assert_eq!(cookie.len(), 2, "cookie must grow to 2 entries");
        assert_eq!(
            secret_entries(&root, &["secrets", "cipher"]),
            vec![cipher_before.as_str()],
            "cipher must be untouched"
        );

        let out = captured_text(&buf);
        assert!(!out.contains(cookie[0]), "new cookie leaked: {out}");
        assert!(!out.contains(cookie[1]), "old cookie leaked: {out}");
        assert!(out.contains("<redacted"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_kratos_secrets_neither_flag_rotates_both_lists() {
        let dir = unique_tmp_dir("rotate-kratos-both");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);

        let (mut ctx, _buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        let code = rotate_kratos_secrets(&mut ctx, false, false).expect("rotate succeeds");
        assert_eq!(code, 0);

        let root: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&kratos_path).unwrap()).unwrap();
        assert_eq!(secret_entries(&root, &["secrets", "cookie"]).len(), 2);
        assert_eq!(secret_entries(&root, &["secrets", "cipher"]).len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- prune_kratos_secrets ---------------------------------------------------

    #[test]
    fn prune_kratos_secrets_explicit_flag_errors_on_single_entry() {
        let dir = unique_tmp_dir("prune-kratos-explicit-error");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);

        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path, false, true);
        let err = prune_kratos_secrets(&mut ctx, true, false).unwrap_err();
        assert!(err.to_string().contains("nothing to prune"), "err: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_kratos_secrets_sweep_reports_nothing_when_both_single_entry() {
        let dir = unique_tmp_dir("prune-kratos-sweep-noop");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let before = std::fs::read_to_string(&kratos_path).unwrap();

        let (mut ctx, buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        let code = prune_kratos_secrets(&mut ctx, false, false).expect("sweep noop, not an error");
        assert_eq!(code, 0);
        assert_eq!(std::fs::read_to_string(&kratos_path).unwrap(), before);

        let out = captured_text(&buf);
        assert!(out.contains("nothing to prune"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_kratos_secrets_after_rotation_keeps_only_first_entry_and_warns_cookie_guidance() {
        // Starts from an already-rotated (2-entry) state directly rather than
        // chaining a real rotate call: two guarded writes to the same target
        // within the same wall-clock second would collide on the backup
        // ring's second-granularity filename.
        let dir = unique_tmp_dir("prune-kratos-after-rotate");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let rotated = kratos_good_fixture().replace(
            &format!("cookie:\n    - {COOKIE_A}"),
            &format!("cookie:\n    - new-cookie-2222222222222222222\n    - {COOKIE_A}"),
        );
        std::fs::write(&kratos_path, &rotated).unwrap();

        let (mut ctx, buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        let code = prune_kratos_secrets(&mut ctx, false, false).expect("prune succeeds");
        assert_eq!(code, 0);

        let after_prune: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&kratos_path).unwrap()).unwrap();
        assert_eq!(
            secret_entries(&after_prune, &["secrets", "cookie"]),
            vec!["new-cookie-2222222222222222222"]
        );
        assert_eq!(
            secret_entries(&after_prune, &["secrets", "cipher"]).len(),
            1
        );

        let out = captured_text(&buf);
        assert!(out.contains("max session lifetime"), "out: {out}");
        assert!(!out.contains(COOKIE_A), "pruned secret leaked: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- rotate_hydra_system / prune_hydra_system --------------------------

    #[test]
    fn rotate_hydra_system_grows_system_list_new_first() {
        let dir = unique_tmp_dir("rotate-hydra-system");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let before: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&hydra_path).unwrap()).unwrap();
        let system_before = secret_entries(&before, &["secrets", "system"])[0].to_string();

        let (mut ctx, buf) = captured_ctx(kratos_path, hydra_path.clone(), false, true);
        let code = rotate_hydra_system(&mut ctx).expect("rotate succeeds");
        assert_eq!(code, 0);

        let root: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&hydra_path).unwrap()).unwrap();
        let system = secret_entries(&root, &["secrets", "system"]);
        assert_eq!(system.len(), 2);
        assert_eq!(system[1], system_before);
        assert_ne!(system[0], system_before);

        let out = captured_text(&buf);
        assert!(!out.contains(system[0]), "new secret leaked: {out}");
        assert!(!out.contains(system[1]), "old secret leaked: {out}");
        assert!(
            out.contains("does NOT hot-reload"),
            "runbook must warn Hydra needs a restart: {out}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_hydra_system_errors_on_single_entry() {
        let dir = unique_tmp_dir("prune-hydra-single");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);

        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path, false, true);
        let err = prune_hydra_system(&mut ctx).unwrap_err();
        assert!(err.to_string().contains("nothing to prune"), "err: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_hydra_system_after_rotation_keeps_only_first_entry() {
        // Starts from an already-rotated (2-entry) state directly; see the
        // comment on the kratos-secrets equivalent above for why.
        let dir = unique_tmp_dir("prune-hydra-after-rotate");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let rotated = hydra_good_fixture().replace(
            &format!("system:\n    - {SYSTEM_A}"),
            &format!("system:\n    - new-system-3333333333333333333\n    - {SYSTEM_A}"),
        );
        std::fs::write(&hydra_path, &rotated).unwrap();

        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path.clone(), false, true);
        let code = prune_hydra_system(&mut ctx).expect("prune succeeds");
        assert_eq!(code, 0);

        let after_prune: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&hydra_path).unwrap()).unwrap();
        assert_eq!(
            secret_entries(&after_prune, &["secrets", "system"]),
            vec!["new-system-3333333333333333333"]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- rotate_pairwise_salt -------------------------------------------------

    #[tokio::test]
    async fn rotate_pairwise_salt_non_interactive_without_flag_errors_and_writes_nothing() {
        let dir = unique_tmp_dir("pairwise-no-flag");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let before = std::fs::read_to_string(&hydra_path).unwrap();

        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path.clone(), false, true);
        let err = rotate_pairwise_salt(&mut ctx, false, false)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("--i-understand-subs-change"),
            "err: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&hydra_path).unwrap(),
            before,
            "a refused rotation must not write"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rotate_pairwise_salt_yes_alone_does_not_satisfy_the_gate() {
        // captured_ctx's `yes = true` mirrors --yes; the salt gate must ignore it.
        let dir = unique_tmp_dir("pairwise-yes-insufficient");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);

        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path, false, true);
        let err = rotate_pairwise_salt(&mut ctx, false, false)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("--i-understand-subs-change"),
            "err: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rotate_pairwise_salt_with_flag_overwrites_scalar_not_a_list() {
        let dir = unique_tmp_dir("pairwise-with-flag");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let before: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&hydra_path).unwrap()).unwrap();
        let salt_before = dig_str(
            &before,
            &["oidc", "subject_identifiers", "pairwise", "salt"],
        )
        .unwrap()
        .to_string();

        let (mut ctx, buf) = captured_ctx(kratos_path, hydra_path.clone(), false, true);
        let code = rotate_pairwise_salt(&mut ctx, true, false)
            .await
            .expect("rotate succeeds");
        assert_eq!(code, 0);

        let root: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&hydra_path).unwrap()).unwrap();
        let salt_node = dig(&root, &["oidc", "subject_identifiers", "pairwise", "salt"]).unwrap();
        assert!(
            salt_node.is_string(),
            "salt must stay a scalar overwrite, not become a rotation list"
        );
        let new_salt = salt_node.as_str().unwrap();
        assert_ne!(new_salt, salt_before);

        let out = captured_text(&buf);
        assert!(!out.contains(&salt_before), "old salt leaked: {out}");
        assert!(!out.contains(new_salt), "new salt leaked: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rotate_pairwise_salt_interactive_wrong_phrase_aborts_without_writing() {
        // No TTY in the test harness: stdin reads EOF immediately, so the typed
        // line is empty and never matches SALT_CONFIRM_PHRASE; this exercises
        // the decline path the same way other interactive prompts do here.
        let dir = unique_tmp_dir("pairwise-interactive-wrong");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let before = std::fs::read_to_string(&hydra_path).unwrap();

        let (mut ctx, buf) = captured_ctx(kratos_path, hydra_path.clone(), false, true);
        let code = rotate_pairwise_salt(&mut ctx, false, true)
            .await
            .expect("declined, not an error");
        assert_eq!(code, 1);
        assert_eq!(std::fs::read_to_string(&hydra_path).unwrap(), before);

        let out = captured_text(&buf);
        assert!(
            out.contains(SALT_CONFIRM_PHRASE),
            "prompt must show the exact phrase: {out}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rotate_pairwise_salt_probe_degrades_silently_without_admin_url() {
        // The reference hydra.yml templates carry no admin base_url, so the
        // best-effort probe must miss without blocking the rotation.
        let dir = unique_tmp_dir("pairwise-probe-degrade");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);

        let (mut ctx, buf) = captured_ctx(kratos_path, hydra_path, false, true);
        let code = rotate_pairwise_salt(&mut ctx, true, false)
            .await
            .expect("rotate succeeds");
        assert_eq!(code, 0);

        let out = captured_text(&buf);
        assert!(out.contains("could not query Hydra"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // config smtp set + config restore.
    // -----------------------------------------------------------------------

    #[test]
    fn smtp_set_writes_all_three_keys() {
        let dir = unique_tmp_dir("smtp-set-all");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);

        let (mut ctx, buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        let code = smtp_set(
            &mut ctx,
            Some("smtps://newuser:newpass@smtp.new.example.com:465".to_string()),
            Some("no-reply@example.com".to_string()),
            Some("Example Accounts".to_string()),
        )
        .unwrap();
        assert_eq!(code, 0);

        let root: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&kratos_path).unwrap()).unwrap();
        assert_eq!(
            dig_str(&root, &["courier", "smtp", "connection_uri"]),
            Some("smtps://newuser:newpass@smtp.new.example.com:465")
        );
        assert_eq!(
            dig_str(&root, &["courier", "smtp", "from_address"]),
            Some("no-reply@example.com")
        );
        assert_eq!(
            dig_str(&root, &["courier", "smtp", "from_name"]),
            Some("Example Accounts")
        );

        let out = captured_text(&buf);
        assert!(!out.contains("newuser:newpass"), "raw URI leaked: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn smtp_set_confirmation_echoes_redact_uri_never_raw_uri() {
        let dir = unique_tmp_dir("smtp-set-redact");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);

        let (mut ctx, buf) = captured_ctx(kratos_path, hydra_path, false, true);
        smtp_set(
            &mut ctx,
            Some("smtps://opuser:oppass@smtp.new.example.com:465".to_string()),
            None,
            None,
        )
        .unwrap();

        let out = captured_text(&buf);
        assert!(!out.contains("opuser:oppass"), "raw URI leaked: {out}");
        assert!(
            out.contains("smtps://***@smtp.new.example.com:465"),
            "confirmation must echo the redact_uri form: {out}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn smtp_set_only_from_fields_when_no_uri_given() {
        let dir = unique_tmp_dir("smtp-set-from-only");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let before: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&kratos_path).unwrap()).unwrap();

        let (mut ctx, _buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        let code = smtp_set(
            &mut ctx,
            None,
            Some("no-reply@example.com".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(code, 0);

        let root: Value =
            serde_yaml_ng::from_str(&std::fs::read_to_string(&kratos_path).unwrap()).unwrap();
        assert_eq!(
            dig_str(&root, &["courier", "smtp", "connection_uri"]),
            dig_str(&before, &["courier", "smtp", "connection_uri"]),
            "the URI must be untouched when only --from-address is given"
        );
        assert_eq!(
            dig_str(&root, &["courier", "smtp", "from_address"]),
            Some("no-reply@example.com")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn smtp_set_nothing_given_errors() {
        let dir = unique_tmp_dir("smtp-set-nothing");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path, false, true);

        let err = smtp_set(&mut ctx, None, None, None).unwrap_err();
        assert!(err.to_string().contains("nothing to set"), "err: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn smtp_set_rejects_control_char_uri() {
        let dir = unique_tmp_dir("smtp-set-control-char");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path, false, true);

        let err = smtp_set(
            &mut ctx,
            Some("smtp://h:1025\nselfservice:\n  flows: {}\n".to_string()),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("control characters"), "err: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn smtp_set_rejects_non_smtp_scheme() {
        let dir = unique_tmp_dir("smtp-set-bad-scheme");
        std::fs::create_dir_all(&dir).unwrap();
        let (kratos_path, hydra_path) = kratos_hydra_fixture(&dir);
        let (mut ctx, _buf) = captured_ctx(kratos_path, hydra_path, false, true);

        let err = smtp_set(
            &mut ctx,
            Some("https://smtp.example.com".to_string()),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("smtp"), "err: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Writes a `<file_name>.bak.<secs>` backup directly (mirrors `io.rs`'s own
    /// tests) so restore tests control exactly which generations exist without
    /// depending on wall-clock second boundaries the way the real `backup()`
    /// (used only for the restore's own pre-overwrite snapshot) does.
    fn write_backup(dir: &Path, file_name: &str, secs: u64, content: &str) -> PathBuf {
        let path = dir.join(format!("{file_name}.bak.{secs}"));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn restore_round_trip_preserves_bytes_verbatim() {
        let dir = unique_tmp_dir("restore-verbatim");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let hydra_path = dir.join("hydra.yml"); // no backups: must be skipped, not restored.

        let v1 = "# a comment the operator left behind\ncourier:\n  smtp:\n    connection_uri: smtp://v1:1025\n";
        write_backup(&dir, "kratos.yml", 1_000, v1);
        std::fs::write(
            &kratos_path,
            "courier:\n  smtp:\n    connection_uri: smtp://v2:1025\n",
        )
        .unwrap();

        let (mut ctx, buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        // This minimal fixture isn't check_kratos-clean (no session/settings
        // AAL etc.), so the post-write check may legitimately report FAILs
        // (exit code 1); this test only cares that the bytes round-trip.
        restore(&mut ctx, Some("1000")).unwrap();

        let restored = std::fs::read_to_string(&kratos_path).unwrap();
        assert_eq!(
            restored, v1,
            "restore must copy the backup's bytes verbatim, comments included"
        );

        let out = captured_text(&buf);
        assert!(out.contains("no backups for Hydra"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_backs_up_current_state_before_overwriting() {
        let dir = unique_tmp_dir("restore-backs-up-current");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let hydra_path = dir.join("hydra.yml");

        let v1 = "courier:\n  smtp:\n    connection_uri: smtp://v1:1025\n";
        let v2 = "courier:\n  smtp:\n    connection_uri: smtp://v2:1025\n";
        write_backup(&dir, "kratos.yml", 1_000, v1);
        std::fs::write(&kratos_path, v2).unwrap();

        let (mut ctx, _buf) = captured_ctx(kratos_path.clone(), hydra_path, false, true);
        restore(&mut ctx, Some("1000")).unwrap();

        let target = Target {
            path: kratos_path.clone(),
        };
        let backups = list_backups(&target).unwrap();
        let v2_backup = backups
            .iter()
            .any(|p| std::fs::read_to_string(p).unwrap() == v2);
        assert!(
            v2_backup,
            "the pre-restore state (v2) must be backed up before restoring v1"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_from_unknown_suffix_errors_listing_available() {
        let dir = unique_tmp_dir("restore-unknown-suffix");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let current = "courier:\n  smtp:\n    connection_uri: smtp://v2:1025\n";
        std::fs::write(&kratos_path, current).unwrap();
        write_backup(&dir, "kratos.yml", 1_000, "v1");
        write_backup(&dir, "kratos.yml", 2_000, "v1b");

        let (mut ctx, _buf) = captured_ctx(kratos_path.clone(), dir.join("hydra.yml"), false, true);
        let err = restore(&mut ctx, Some("9999")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("9999"), "msg: {msg}");
        assert!(
            msg.contains("1000") && msg.contains("2000"),
            "msg should list the available suffixes: {msg}"
        );

        assert_eq!(
            std::fs::read_to_string(&kratos_path).unwrap(),
            current,
            "a rejected --from must leave every target untouched"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_non_interactive_without_from_errors() {
        let dir = unique_tmp_dir("restore-non-interactive");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        std::fs::write(&kratos_path, "x: 1\n").unwrap();
        write_backup(&dir, "kratos.yml", 1_000, "x: 0\n");

        let (mut ctx, _buf) = captured_ctx(kratos_path, dir.join("hydra.yml"), false, true);
        let err = restore(&mut ctx, None).unwrap_err();
        assert!(err.to_string().contains("--from"), "err: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_dry_run_writes_nothing() {
        let dir = unique_tmp_dir("restore-dry-run");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        std::fs::write(&kratos_path, "x: 1\n").unwrap();
        write_backup(&dir, "kratos.yml", 1_000, "x: 0\n");

        let (mut ctx, buf) = captured_ctx(kratos_path.clone(), dir.join("hydra.yml"), true, false);
        let code = restore(&mut ctx, None).unwrap();
        assert_eq!(code, 0);
        assert_eq!(std::fs::read_to_string(&kratos_path).unwrap(), "x: 1\n");

        let out = captured_text(&buf);
        assert!(out.contains("dry-run"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_skips_targets_with_no_backups_at_all() {
        let dir = unique_tmp_dir("restore-skip-empty");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let hydra_path = dir.join("hydra.yml");
        std::fs::write(&kratos_path, "x: 1\n").unwrap();
        std::fs::write(&hydra_path, "y: 1\n").unwrap();

        let (mut ctx, buf) = captured_ctx(kratos_path, hydra_path, false, true);
        let code = restore(&mut ctx, None).unwrap();
        assert_eq!(code, 0);

        let out = captured_text(&buf);
        assert!(
            out.contains("no backups found for any target"),
            "out: {out}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_redacts_smtp_uri_in_diff() {
        let dir = unique_tmp_dir("restore-redact-smtp");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let old_uri = "smtps://olduser:oldpass@smtp.example.com:465";
        let new_uri = "smtps://newuser:newpass@smtp.example.com:465";
        write_backup(
            &dir,
            "kratos.yml",
            1_000,
            &format!("courier:\n  smtp:\n    connection_uri: {old_uri}\n"),
        );
        std::fs::write(
            &kratos_path,
            format!("courier:\n  smtp:\n    connection_uri: {new_uri}\n"),
        )
        .unwrap();

        let (mut ctx, buf) = captured_ctx(kratos_path, dir.join("hydra.yml"), true, true);
        restore(&mut ctx, Some("1000")).unwrap();

        let out = captured_text(&buf);
        assert!(!out.contains("olduser:oldpass"), "old creds leaked: {out}");
        assert!(!out.contains("newuser:newpass"), "new creds leaked: {out}");
        assert!(out.contains("<redacted"), "out: {out}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_includes_config_toml_when_resolvable() {
        let dir = unique_tmp_dir("restore-toml");
        std::fs::create_dir_all(&dir).unwrap();
        let kratos_path = dir.join("kratos.yml");
        let hydra_path = dir.join("hydra.yml");
        let toml_path = dir.join("config.toml");
        std::fs::write(&kratos_path, "x: 1\n").unwrap();
        std::fs::write(&hydra_path, "y: 1\n").unwrap();
        std::fs::write(&toml_path, "[audit]\nwebhook_token = \"new\"\n").unwrap();
        write_backup(
            &dir,
            "config.toml",
            1_000,
            "[audit]\nwebhook_token = \"old\"\n",
        );

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut ctx = ModifyCtx {
            kratos: Target { path: kratos_path },
            hydra: Target { path: hydra_path },
            forseti: Some(Target {
                path: toml_path.clone(),
            }),
            dry_run: false,
            yes: true,
            out: Box::new(CapturingWriter(buf.clone())),
            input: Box::new(std::io::empty()),
        };

        let code = restore(&mut ctx, Some("1000")).unwrap();
        assert_eq!(code, 0);
        assert_eq!(
            std::fs::read_to_string(&toml_path).unwrap(),
            "[audit]\nwebhook_token = \"old\"\n"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
