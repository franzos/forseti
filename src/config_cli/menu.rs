//! `forseti config` with no subcommand: an interactive menu over the same
//! read (`catalog`/`check`) and write (`modify`) primitives every other
//! `config` subcommand uses — this module is wiring + rendering only, no new
//! mutation logic. All prompts/echo go through [`MenuIo`] so the whole loop
//! is scriptable under test.
//!
//! `[c]heck`/`[i]nit`/`[s]tatus` delegate to `check::check`/`init::init`/
//! `check::status`, which print via `println!`/`eprintln!` straight to the
//! process's real stdout/stderr rather than through `MenuIo::output`. In
//! production that's the same stream either way; under test it means those
//! three actions aren't capturable through the scripted `MenuIo` buffer (not
//! exercised by this module's tests as a result).

use std::cell::RefCell;
use std::future::Future;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde_yaml_ng::Value;
use toml_edit::DocumentMut;

use crate::cli::{CheckArgs, InitArgs, PathArgs};

use super::catalog::{self, Setting, SettingStatus};
use super::check::{
    self, load_forseti_toml, resolve_config_path, resolve_forseti_toml_path, state_marker,
    DEFAULT_HYDRA, DEFAULT_KRATOS, ENV_HYDRA, ENV_KRATOS,
};
use super::init;
use super::io::{read_secret, resolve_target, SecretSource};
use super::modify::{self, ModifyCtx, OidcEnableInput};
use super::yamlutil::{dig_str, load_yaml};

// ---------------------------------------------------------------------------
// MenuIo: every prompt/echo goes through this so the loop is scriptable.
// ---------------------------------------------------------------------------

pub(crate) struct MenuIo<'a> {
    pub input: &'a mut dyn BufRead,
    pub output: &'a mut dyn Write,
    pub is_tty: bool,
    /// Factory for the `SecretSource` a hidden-value prompt (client_secret,
    /// SMTP URI) uses. Defaults to `SecretSource::Prompt`, which refuses
    /// outside a real TTY — tests override this to avoid touching the
    /// terminal at all.
    pub secret_source: Box<dyn Fn(&'static str) -> SecretSource>,
}

impl<'a> MenuIo<'a> {
    pub(crate) fn new(input: &'a mut dyn BufRead, output: &'a mut dyn Write, is_tty: bool) -> Self {
        MenuIo {
            input,
            output,
            is_tty,
            secret_source: Box::new(SecretSource::Prompt),
        }
    }
}

// ---------------------------------------------------------------------------
// `Stdin`/`Stdout` each guard a single process-wide, non-reentrant `Mutex`.
// A `StdinLock`/`StdoutLock` held for the menu's whole lifetime would
// deadlock the instant a delegated action tries to lock the same stream
// again on this thread — `prompt_yes_no` and the other confirm prompts in
// modify.rs read `std::io::stdin()` directly, and `check::check`/`init::
// init`/`check::status` (the `[c]`/`[i]`/`[s]` actions) print via `println!`/
// `eprintln!`, which lock `std::io::stdout()` internally. These wrappers
// lock fresh per call and drop immediately after, so nothing is held open
// across a delegated call — the underlying buffer is still the same
// process-wide one, so no data is lost between calls.
pub(crate) struct RealStdin;

impl Read for RealStdin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::stdin().lock().read(buf)
    }
}

impl BufRead for RealStdin {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        unreachable!("menu.rs only ever calls read_line on MenuIo::input")
    }
    fn consume(&mut self, _amt: usize) {}
    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        std::io::stdin().lock().read_line(buf)
    }
}

pub(crate) struct RealStdout;

impl Write for RealStdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().lock().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().lock().flush()
    }
}

// ---------------------------------------------------------------------------
// A `Box<dyn Write>` for `ModifyCtx::out` (which requires `'static`) that
// forwards into `MenuIo::output` (which is borrowed, non-'static) after the
// action completes. Mirrors the `CapturingWriter` pattern already used by
// modify.rs's own tests.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SharedBuf(Rc<RefCell<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs a future to completion from this (synchronous) menu loop. The whole
/// menu already blocks its thread on interactive terminal reads, so blocking
/// it further for `oidc_disable`/`rotate_pairwise_salt`'s network probes is
/// no additional cost; `block_in_place` is required to nest a `block_on`
/// inside the multi-threaded runtime `main` already runs under.
fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

pub(crate) fn run_menu(io: &mut MenuIo, paths: &PathArgs) -> i32 {
    let kratos_path = match resolve_config_path(
        paths.kratos.as_deref(),
        DEFAULT_KRATOS,
        "Kratos",
        "--kratos",
        ENV_KRATOS,
    ) {
        Ok((p, _)) => p,
        Err(msg) => {
            let _ = writeln!(io.output, "{msg}");
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
            let _ = writeln!(io.output, "{msg}");
            return 1;
        }
    };

    loop {
        let (kratos_root, hydra_root, forseti_doc, forseti_path) =
            match load_state(&kratos_path, &hydra_path, paths) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(io.output, "error: {e}");
                    return 1;
                }
            };
        let config_dir = kratos_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let statuses =
            catalog::status_of(&kratos_root, &hydra_root, forseti_doc.as_ref(), config_dir);

        render_header(
            io,
            &kratos_path,
            &hydra_path,
            forseti_path.as_deref(),
            forseti_doc.is_some(),
        );
        render_settings(io, &statuses);
        let _ = writeln!(io.output, "\n[c] check  [i] init  [s] status  [q] quit");

        let Some(cmd) = prompt(io, None) else {
            return 0; // EOF
        };

        if cmd.eq_ignore_ascii_case("q") {
            return 0;
        }
        if cmd.eq_ignore_ascii_case("c") {
            check::check(&CheckArgs {
                paths: paths.clone(),
                strict: false,
            });
            continue;
        }
        if cmd.eq_ignore_ascii_case("i") {
            init::init(&InitArgs {
                forseti_url: None,
                kratos_public_url: None,
                kratos_admin_url: None,
                hydra_public_url: None,
                hydra_admin_url: None,
                kratos_db_dsn: None,
                hydra_db_dsn: None,
                smtp_uri: None,
                smtp_from_address: None,
                smtp_from_name: None,
                kratos_out: kratos_path.display().to_string(),
                hydra_out: hydra_path.display().to_string(),
                force: false,
            });
            continue;
        }
        if cmd.eq_ignore_ascii_case("s") {
            check::status(paths, false);
            continue;
        }
        if let Ok(idx) = cmd.parse::<usize>() {
            if idx >= 1 && idx <= catalog::SETTINGS.len() {
                let setting = &catalog::SETTINGS[idx - 1];
                let status = statuses.iter().find(|s| s.key == setting.key);
                run_detail(io, paths, &kratos_path, setting, status);
                continue;
            }
        }
        let _ = writeln!(io.output, "unknown command: {cmd}");
    }
}

fn load_state(
    kratos_path: &Path,
    hydra_path: &Path,
    paths: &PathArgs,
) -> anyhow::Result<(Value, Value, Option<DocumentMut>, Option<PathBuf>)> {
    let kratos_root = load_yaml(kratos_path)?;
    let hydra_root = load_yaml(hydra_path)?;
    let forseti_path = resolve_forseti_toml_path(paths.forseti_config.as_deref());
    let forseti_doc = match &forseti_path {
        Some(p) => load_forseti_toml(p).ok(),
        None => None,
    };
    Ok((kratos_root, hydra_root, forseti_doc, forseti_path))
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

fn render_header(
    io: &mut MenuIo,
    kratos_path: &Path,
    hydra_path: &Path,
    forseti_path: Option<&Path>,
    forseti_ok: bool,
) {
    let forseti_desc = match (forseti_path, forseti_ok) {
        (Some(p), true) => p.display().to_string(),
        (Some(p), false) => format!("{} (unreadable)", p.display()),
        (None, _) => "(absent)".to_string(),
    };
    let _ = writeln!(io.output, "forseti config");
    let _ = writeln!(io.output, "  kratos.yml:  {}", kratos_path.display());
    let _ = writeln!(io.output, "  hydra.yml:   {}", hydra_path.display());
    let _ = writeln!(io.output, "  config.toml: {forseti_desc}");
}

fn render_settings(io: &mut MenuIo, statuses: &[SettingStatus]) {
    let mut current_group: Option<&str> = None;
    for (i, setting) in catalog::SETTINGS.iter().enumerate() {
        let Some(s) = statuses.iter().find(|s| s.key == setting.key) else {
            continue;
        };
        if current_group != Some(setting.group) {
            let _ = writeln!(io.output);
            let _ = writeln!(io.output, "== {} ==", setting.group);
            current_group = Some(setting.group);
        }
        let _ = writeln!(
            io.output,
            "  {:>2}) {} {:<32} {}",
            i + 1,
            state_marker(&s.state),
            setting.title,
            s.detail
        );
    }
}

/// A prompt line; `label` is `None` for the bare `> ` menu/detail prompt,
/// `Some` for a labelled field prompt (`client_id: `, ...). Returns `None` on
/// EOF/read error — every caller treats that as "stop, don't mutate".
fn prompt(io: &mut MenuIo, label: Option<&str>) -> Option<String> {
    if io.is_tty {
        match label {
            Some(l) => {
                let _ = write!(io.output, "{l}: ");
            }
            None => {
                let _ = write!(io.output, "> ");
            }
        }
        let _ = io.output.flush();
    }
    let mut line = String::new();
    match io.input.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

// ---------------------------------------------------------------------------
// Detail view: description + state, then an explicit action choice. Never
// falls straight into a mutation from the numbered selection.
// ---------------------------------------------------------------------------

fn detail_actions_line(key: &str) -> &'static str {
    match key {
        "oidc.google" | "oidc.github" | "oidc.microsoft" => {
            "[e] enable/edit  [d] disable  [b] back"
        }
        "audit.webhook-token" => "[r] rotate  [p] prune  [b] back",
        "kratos.secrets" => "[r] rotate  [p] prune  [b] back",
        "hydra.system" => {
            "[r] rotate system secret  [x] rotate pairwise salt  [p] prune system secret  [b] back"
        }
        "kratos.courier-smtp" => "[e] edit  [b] back",
        _ => "[b] back",
    }
}

fn run_detail(
    io: &mut MenuIo,
    paths: &PathArgs,
    kratos_path: &Path,
    setting: &Setting,
    status: Option<&SettingStatus>,
) {
    loop {
        let _ = writeln!(io.output);
        let _ = writeln!(io.output, "== {} ({}) ==", setting.title, setting.key);
        let _ = writeln!(io.output, "{}", setting.description);
        if let Some(s) = status {
            let _ = writeln!(io.output, "state: {} - {}", s.state, s.detail);
        }
        let _ = writeln!(io.output, "\n{}", detail_actions_line(setting.key));

        let Some(cmd) = prompt(io, None) else {
            return; // EOF
        };
        let cmd = cmd.to_ascii_lowercase();

        match (setting.key, cmd.as_str()) {
            (_, "b") => return,
            ("oidc.google" | "oidc.github" | "oidc.microsoft", "e") => {
                run_oidc_enable(io, paths, setting.key.trim_start_matches("oidc."));
                return;
            }
            ("oidc.google" | "oidc.github" | "oidc.microsoft", "d") => {
                run_oidc_disable(
                    io,
                    paths,
                    kratos_path,
                    setting.key.trim_start_matches("oidc."),
                );
                return;
            }
            ("kratos.courier-smtp", "e") => {
                run_smtp_edit(io, paths);
                return;
            }
            ("audit.webhook-token", "r") => {
                run_ctx_action(io, paths, |ctx| modify::rotate_webhook_token(ctx, true));
                return;
            }
            ("audit.webhook-token", "p") => {
                run_ctx_action(io, paths, modify::prune_webhook_token);
                return;
            }
            ("kratos.secrets", "r") => {
                run_ctx_action(io, paths, |ctx| {
                    modify::rotate_kratos_secrets(ctx, false, false)
                });
                return;
            }
            ("kratos.secrets", "p") => {
                run_ctx_action(io, paths, |ctx| {
                    modify::prune_kratos_secrets(ctx, false, false)
                });
                return;
            }
            ("hydra.system", "r") => {
                run_ctx_action(io, paths, modify::rotate_hydra_system);
                return;
            }
            ("hydra.system", "p") => {
                run_ctx_action(io, paths, modify::prune_hydra_system);
                return;
            }
            ("hydra.system", "x") => {
                run_pairwise_rotate(io, paths);
                return;
            }
            _ => {
                let _ = writeln!(io.output, "unknown action: {cmd}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Action wrappers: build a `ModifyCtx` whose `out` forwards into
// `io.output`, run the (already-implemented) modify.rs function, flush
// captured output, and on error print exactly one extra line. A modify fn
// returning `Ok(1)` (a post-write FAIL) already printed its own findings and
// "fix the FAIL above..." line into that captured output — nothing more to
// add here. `dry_run`/`yes` are always false: the menu's own y/N prompts
// are the confirmation step.
// ---------------------------------------------------------------------------

fn build_menu_ctx(paths: &PathArgs, out: SharedBuf) -> anyhow::Result<ModifyCtx> {
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
        dry_run: false,
        yes: false,
        out: Box::new(out),
    })
}

fn run_ctx_action(
    io: &mut MenuIo,
    paths: &PathArgs,
    f: impl FnOnce(&mut ModifyCtx) -> anyhow::Result<i32>,
) {
    let buf = Rc::new(RefCell::new(Vec::new()));
    let result = build_menu_ctx(paths, SharedBuf(buf.clone())).and_then(|mut ctx| f(&mut ctx));
    let _ = io.output.write_all(&buf.borrow());
    if let Err(e) = result {
        let _ = writeln!(io.output, "error: {e}");
    }
}

fn run_oidc_enable(io: &mut MenuIo, paths: &PathArgs, provider: &str) {
    let Some(client_id) = prompt(io, Some("client_id")) else {
        return; // EOF
    };
    if client_id.is_empty() {
        let _ = writeln!(io.output, "error: client_id must not be empty");
        return;
    }

    let client_secret = match read_secret((io.secret_source)("client_secret")) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(io.output, "error: {e}");
            return;
        }
    };

    let microsoft_tenant = if provider == "microsoft" {
        let Some(t) = prompt(io, Some("microsoft_tenant")) else {
            return; // EOF
        };
        Some(t)
    } else {
        None
    };

    let input = OidcEnableInput {
        provider: provider.to_string(),
        client_id,
        client_secret,
        microsoft_tenant,
        keep_mapper: false,
    };
    run_ctx_action(io, paths, |ctx| modify::oidc_enable(ctx, input));
}

fn run_oidc_disable(io: &mut MenuIo, paths: &PathArgs, kratos_path: &Path, id: &str) {
    let admin_url = std::fs::read_to_string(kratos_path)
        .ok()
        .and_then(|t| serde_yaml_ng::from_str::<Value>(&t).ok())
        .and_then(|r| dig_str(&r, &["serve", "admin", "base_url"]).map(str::to_string));

    let buf = Rc::new(RefCell::new(Vec::new()));
    let result = match build_menu_ctx(paths, SharedBuf(buf.clone())) {
        Ok(mut ctx) => block_on(modify::oidc_disable(&mut ctx, id, admin_url.as_deref())),
        Err(e) => Err(e),
    };
    let _ = io.output.write_all(&buf.borrow());
    if let Err(e) = result {
        let _ = writeln!(io.output, "error: {e}");
    }
}

fn run_pairwise_rotate(io: &mut MenuIo, paths: &PathArgs) {
    let buf = Rc::new(RefCell::new(Vec::new()));
    let result = match build_menu_ctx(paths, SharedBuf(buf.clone())) {
        Ok(mut ctx) => block_on(modify::rotate_pairwise_salt(&mut ctx, false, true)),
        Err(e) => Err(e),
    };
    let _ = io.output.write_all(&buf.borrow());
    if let Err(e) = result {
        let _ = writeln!(io.output, "error: {e}");
    }
}

fn run_smtp_edit(io: &mut MenuIo, paths: &PathArgs) {
    let Some(ans) = prompt(io, Some("set SMTP connection URI? [y/N]")) else {
        return; // EOF
    };
    let uri = if matches!(ans.to_ascii_lowercase().as_str(), "y" | "yes") {
        match read_secret((io.secret_source)("smtp_uri")) {
            Ok(s) => Some(s),
            Err(e) => {
                let _ = writeln!(io.output, "error: {e}");
                return;
            }
        }
    } else {
        None
    };

    let Some(from_address) = prompt(io, Some("from_address (blank to skip)")) else {
        return; // EOF
    };
    let from_address = (!from_address.is_empty()).then_some(from_address);

    let Some(from_name) = prompt(io, Some("from_name (blank to skip)")) else {
        return; // EOF
    };
    let from_name = (!from_name.is_empty()).then_some(from_name);

    if uri.is_none() && from_address.is_none() && from_name.is_none() {
        let _ = writeln!(io.output, "nothing to set.");
        return;
    }

    run_ctx_action(io, paths, |ctx| {
        modify::smtp_set(ctx, uri, from_address, from_name)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn menu_io<'a>(input: &'a mut dyn BufRead, output: &'a mut dyn Write) -> MenuIo<'a> {
        MenuIo::new(input, output, true)
    }

    fn nonexistent_forseti_toml() -> PathBuf {
        PathBuf::from("/nonexistent-forseti-config-for-menu-tests.toml")
    }

    fn unique_tmp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("forseti-menu-{}-{label}", std::process::id()))
    }

    #[test]
    fn menu_renders_all_settings_and_quits_on_q() {
        let mut input = Cursor::new(b"q\n".to_vec());
        let mut output = Vec::new();
        let mut io = menu_io(&mut input, &mut output);
        let paths = PathArgs {
            kratos: Some(PathBuf::from("infra/kratos/kratos.yml")),
            hydra: Some(PathBuf::from("infra/hydra/hydra.yml")),
            forseti_config: Some(nonexistent_forseti_toml()),
            dry_run: false,
            yes: false,
            follow_symlink: false,
        };

        let code = run_menu(&mut io, &paths);
        assert_eq!(code, 0);

        let text = String::from_utf8(output).unwrap();
        for setting in catalog::SETTINGS {
            assert!(
                text.contains(setting.title),
                "missing {}: {text}",
                setting.title
            );
        }
        assert!(
            text.contains("config.toml:") && text.contains("(unreadable)"),
            "text: {text}"
        );
        assert!(text.contains("[q] quit"), "text: {text}");
    }

    #[test]
    fn selecting_setting_shows_detail_then_back() {
        let mut input = Cursor::new(b"1\nb\nq\n".to_vec());
        let mut output = Vec::new();
        let mut io = menu_io(&mut input, &mut output);
        let paths = PathArgs {
            kratos: Some(PathBuf::from("infra/kratos/kratos.yml")),
            hydra: Some(PathBuf::from("infra/hydra/hydra.yml")),
            forseti_config: Some(nonexistent_forseti_toml()),
            dry_run: false,
            yes: false,
            follow_symlink: false,
        };

        let code = run_menu(&mut io, &paths);
        assert_eq!(code, 0);

        let text = String::from_utf8(output).unwrap();
        assert!(
            text.contains("upstream OIDC client of Google"),
            "text: {text}"
        );
        assert!(text.contains("[e] enable/edit"), "text: {text}");
    }

    #[test]
    fn scripted_github_enable_writes_provider() {
        let dir = unique_tmp_dir("github-enable");
        std::fs::create_dir_all(&dir).unwrap();
        let (k, h, _) = init::render_configs(&init::InitInputs::default());
        let kratos = dir.join("kratos.yml");
        let hydra = dir.join("hydra.yml");
        std::fs::write(&kratos, &k).unwrap();
        std::fs::write(&hydra, &h).unwrap();

        // SAFETY: test-only env var, unique name, no other thread touches it.
        unsafe {
            std::env::set_var("FORSETI_TEST_MENU_SECRET", "a-real-secret");
        }

        let mut input = Cursor::new(b"2\ne\ncid\n".to_vec());
        let mut output = Vec::new();
        let mut io = menu_io(&mut input, &mut output);
        io.secret_source = Box::new(|_| SecretSource::Env("FORSETI_TEST_MENU_SECRET".to_string()));
        let paths = PathArgs {
            kratos: Some(kratos.clone()),
            hydra: Some(hydra),
            forseti_config: Some(nonexistent_forseti_toml()),
            dry_run: false,
            yes: false,
            follow_symlink: false,
        };

        let code = run_menu(&mut io, &paths);
        assert_eq!(code, 0);

        unsafe {
            std::env::remove_var("FORSETI_TEST_MENU_SECRET");
        }

        let _written = load_yaml(&kratos).expect("kratos.yml still parses");
        let text = std::fs::read_to_string(&kratos).unwrap();
        assert!(text.contains("id: github"), "kratos.yml: {text}");
        assert!(text.contains("client_id: cid"), "kratos.yml: {text}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn eof_exits_cleanly() {
        let mut input = Cursor::new(Vec::new());
        let mut output = Vec::new();
        let mut io = menu_io(&mut input, &mut output);
        let paths = PathArgs {
            kratos: Some(PathBuf::from("infra/kratos/kratos.yml")),
            hydra: Some(PathBuf::from("infra/hydra/hydra.yml")),
            forseti_config: Some(nonexistent_forseti_toml()),
            dry_run: false,
            yes: false,
            follow_symlink: false,
        };

        let code = run_menu(&mut io, &paths);
        assert_eq!(code, 0);
    }
}
