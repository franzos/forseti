//! The guarded write pipeline (`write_yaml`) plus `config oidc enable/disable`.
//! The mapper bodies here are pinned and reviewed: they only ever emit an
//! `email` trait when the upstream marks it verified, which is what stops the
//! unverified-email account-takeover class. `write_yaml` re-serializes the
//! whole document, so it confirms before dropping comments and always prints a
//! secret-redacted diff.

use std::io::{ErrorKind, IsTerminal as _, Write};
use std::path::Path;

use serde_yaml_ng::{Mapping, Value};

use crate::cli::{OidcCmd, PathArgs, SecretSourceArgs};

use super::check::{
    check_hydra, check_kratos, check_oidc_providers, resolve_config_path,
    resolve_forseti_toml_path, Finding, Severity, DEFAULT_HYDRA, DEFAULT_KRATOS, ENV_HYDRA,
    ENV_KRATOS,
};
use super::io::{
    atomic_write, backup, fingerprint, is_git_tracked, lock_config_dir, read_secret, redacted_diff,
    resolve_target, SecretSource, Target,
};
use super::yamlutil::{dig, dig_mut, dig_mut_or_insert, dig_str, load_yaml};

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
}
