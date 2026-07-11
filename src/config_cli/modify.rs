//! The guarded write pipeline (`write_yaml`) plus `config oidc enable/disable`.
//! The mapper bodies here are pinned and reviewed: they only ever emit an
//! `email` trait when the upstream marks it verified, which is what stops the
//! unverified-email account-takeover class. `write_yaml` re-serializes the
//! whole document, so it confirms before dropping comments and always prints a
//! secret-redacted diff.

use std::io::{ErrorKind, IsTerminal as _, Write};
use std::path::Path;

use serde_yaml_ng::{Mapping, Value};
use toml_edit::DocumentMut;

use crate::cli::{OidcCmd, PathArgs, SecretSourceArgs};

use super::check::{
    check_hydra, check_kratos, check_oidc_providers, extract_hook_token, resolve_config_path,
    resolve_forseti_toml_path, webhook_token_entries, Finding, Severity, DEFAULT_FORSETI_TOML,
    DEFAULT_HYDRA, DEFAULT_KRATOS, ENV_HYDRA, ENV_KRATOS, PLACEHOLDER_TOKENS,
};
use super::io::{
    atomic_write, backup, fingerprint, is_git_tracked, lock_config_dir, read_secret, redacted_diff,
    resolve_target, SecretSource, Target,
};
use super::yamlutil::{dig, dig_mut, dig_mut_or_insert, dig_str, load_yaml, random_secret};

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

pub(crate) struct ModifyCtx {
    pub kratos: Target,
    pub hydra: Target,
    // Resolved for menu reuse; the oidc actions only touch kratos.
    #[allow(dead_code)]
    pub forseti: Option<Target>,
    pub dry_run: bool,
    pub yes: bool,
    pub out: Box<dyn Write>,
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

fn prompt_yes_no(out: &mut dyn Write, question: &str) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("{question}: stdin is not a TTY; pass --yes to proceed non-interactively");
    }
    write!(out, "{question} [y/N]: ")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
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
        if !prompt_yes_no(&mut *ctx.out, "Proceed and drop comments?")? {
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

    if !ctx.yes
        && !ctx.dry_run
        && !prompt_yes_no(&mut *ctx.out, &format!("Disable OIDC provider `{id}`?"))?
    {
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
    let resp = reqwest::Client::new()
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
        &mut *ctx.out,
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
        if !placeholder_or_unset {
            if interactive {
                writeln!(
                    ctx.out,
                    "\nrestart Forseti now so it accepts both the new and old webhook tokens, \
                     then press Enter to continue..."
                )?;
                ctx.out.flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
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

#[cfg(test)]
mod tests {
    use super::*;
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
    // Task 8: rotate/prune webhook-token.
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
}
