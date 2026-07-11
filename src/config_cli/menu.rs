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
use std::io::Write;
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
use super::modify::{self, LineSource, ModifyCtx, OidcEnableInput};
use super::yamlutil::{dig_str, load_yaml};

// ---------------------------------------------------------------------------
// MenuIo: every prompt/echo goes through this so the loop is scriptable.
//
// `input`/`output` are shared, `'static` handles (`Rc<RefCell<_>>` behind a
// thin forwarding wrapper) rather than borrowed references, precisely so the
// same sink/source can be handed to the `ModifyCtx` a delegated action runs
// under. That's what lets a delegated confirm prompt render its question to
// the operator's terminal *before* it blocks on the answer, and read that
// answer from the same (scriptable) input the menu itself uses — in
// production both are the process's stdout/stdin; under test both are a
// shared capture buffer / scripted line source.
// ---------------------------------------------------------------------------

/// A cloneable `Write` over a shared sink. Each write goes straight through to
/// the underlying stream, so a menu write and a delegated `ModifyCtx::out`
/// write (both clones of the same handle) interleave in call order.
#[derive(Clone)]
pub(crate) struct SharedWriter(Rc<RefCell<dyn Write>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

/// A cloneable `LineSource` over a shared input, mirroring `SharedWriter`.
#[derive(Clone)]
pub(crate) struct SharedInput(Rc<RefCell<dyn LineSource>>);

impl LineSource for SharedInput {
    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.0.borrow_mut().read_line(buf)
    }
    fn is_terminal(&self) -> bool {
        self.0.borrow().is_terminal()
    }
}

pub(crate) struct MenuIo {
    pub input: SharedInput,
    pub output: SharedWriter,
    pub is_tty: bool,
    /// Factory for the `SecretSource` a hidden-value prompt (client_secret,
    /// SMTP URI) uses. Defaults to `SecretSource::Prompt`, which refuses
    /// outside a real TTY — tests override this to avoid touching the
    /// terminal at all.
    pub secret_source: Box<dyn Fn(&'static str) -> SecretSource>,
}

impl MenuIo {
    pub(crate) fn new(
        input: Rc<RefCell<dyn LineSource>>,
        output: Rc<RefCell<dyn Write>>,
        is_tty: bool,
    ) -> Self {
        MenuIo {
            input: SharedInput(input),
            output: SharedWriter(output),
            is_tty,
            secret_source: Box::new(SecretSource::Prompt),
        }
    }
}

// ---------------------------------------------------------------------------
// `Stdout` guards a single process-wide, non-reentrant `Mutex`. A held
// `StdoutLock` would deadlock the instant a delegated action locks the same
// stream again on this thread (`check::check`/`init::init`/`check::status`
// print via `println!`/`eprintln!`). This wrapper locks fresh per call and
// drops immediately after, so nothing is held open across a delegated call —
// the underlying buffer is the same process-wide one, so no data is lost.
pub(crate) struct RealStdout;

impl Write for RealStdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().lock().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().lock().flush()
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
// Action wrappers: build a `ModifyCtx` sharing the menu's own stdout/stdin
// handles, run the (already-implemented) modify.rs function, and on error
// print exactly one extra line. Because `out`/`input` are the same shared
// handles the menu uses (not a deferred buffer), a delegated confirm prompt
// renders its question before it blocks on the answer. A modify fn returning
// `Ok(1)` (a post-write FAIL) already printed its own findings and "fix the
// FAIL above..." line — nothing more to add here. `dry_run`/`yes` are always
// false: the delegated y/N prompts are the confirmation step.
// ---------------------------------------------------------------------------

fn build_menu_ctx(
    paths: &PathArgs,
    out: SharedWriter,
    input: SharedInput,
) -> anyhow::Result<ModifyCtx> {
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
        input: Box::new(input),
    })
}

fn run_ctx_action(
    io: &mut MenuIo,
    paths: &PathArgs,
    f: impl FnOnce(&mut ModifyCtx) -> anyhow::Result<i32>,
) {
    let result =
        build_menu_ctx(paths, io.output.clone(), io.input.clone()).and_then(|mut ctx| f(&mut ctx));
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

    let result = match build_menu_ctx(paths, io.output.clone(), io.input.clone()) {
        Ok(mut ctx) => block_on(modify::oidc_disable(&mut ctx, id, admin_url.as_deref())),
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        let _ = writeln!(io.output, "error: {e}");
    }
}

fn run_pairwise_rotate(io: &mut MenuIo, paths: &PathArgs) {
    let result = match build_menu_ctx(paths, io.output.clone(), io.input.clone()) {
        Ok(mut ctx) => block_on(modify::rotate_pairwise_salt(&mut ctx, false, true)),
        Err(e) => Err(e),
    };
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
    use crate::config_cli::yamlutil::secret_entries;
    use std::io::{BufRead as _, Cursor};

    /// A scripted line source that reports itself as a TTY, so the confirm
    /// prompts proceed instead of bailing.
    struct ScriptedLines(Cursor<Vec<u8>>);

    impl ScriptedLines {
        fn new(bytes: &[u8]) -> Self {
            ScriptedLines(Cursor::new(bytes.to_vec()))
        }
    }

    impl LineSource for ScriptedLines {
        fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
            self.0.read_line(buf)
        }
        fn is_terminal(&self) -> bool {
            true
        }
    }

    /// A scripted line source that snapshots the shared output buffer at the
    /// moment each answer is read, so a test can prove the prompt's question
    /// was already on screen before the read blocked.
    struct RecordingLines {
        lines: std::collections::VecDeque<String>,
        out: Rc<RefCell<Vec<u8>>>,
        snapshots: Rc<RefCell<Vec<String>>>,
    }

    impl LineSource for RecordingLines {
        fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
            let seen = String::from_utf8_lossy(&self.out.borrow()).into_owned();
            self.snapshots.borrow_mut().push(seen);
            match self.lines.pop_front() {
                Some(line) => {
                    buf.push_str(&line);
                    Ok(line.len())
                }
                None => Ok(0),
            }
        }
        fn is_terminal(&self) -> bool {
            true
        }
    }

    /// Builds a menu wired to a scripted input and a capture buffer; returns
    /// the menu and the shared output so the test can read what was rendered.
    fn menu_io(input: &[u8]) -> (MenuIo, Rc<RefCell<Vec<u8>>>) {
        let inp: Rc<RefCell<dyn LineSource>> = Rc::new(RefCell::new(ScriptedLines::new(input)));
        let out = Rc::new(RefCell::new(Vec::<u8>::new()));
        let io = MenuIo::new(inp, out.clone(), true);
        (io, out)
    }

    fn captured(out: &Rc<RefCell<Vec<u8>>>) -> String {
        String::from_utf8(out.borrow().clone()).unwrap()
    }

    fn nonexistent_forseti_toml() -> PathBuf {
        PathBuf::from("/nonexistent-forseti-config-for-menu-tests.toml")
    }

    fn unique_tmp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("forseti-menu-{}-{label}", std::process::id()))
    }

    #[test]
    fn menu_renders_all_settings_and_quits_on_q() {
        let (mut io, out) = menu_io(b"q\n");
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

        let text = captured(&out);
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
        let (mut io, out) = menu_io(b"1\nb\nq\n");
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

        let text = captured(&out);
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

        let (mut io, _out) = menu_io(b"2\ne\ncid\n");
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

    /// The confirm-bearing flow the review flagged: rotating kratos-secrets
    /// from the menu must render its `[y/N]` question to the operator's
    /// terminal BEFORE it blocks reading the answer, route that answer through
    /// the same scriptable input, and actually land the rotation.
    #[test]
    fn scripted_rotate_kratos_secrets_renders_confirm_before_blocking() {
        let dir = unique_tmp_dir("rotate-kratos");
        std::fs::create_dir_all(&dir).unwrap();
        let (k, h, _) = init::render_configs(&init::InitInputs::default());
        let kratos = dir.join("kratos.yml");
        let hydra = dir.join("hydra.yml");
        std::fs::write(&kratos, &k).unwrap();
        std::fs::write(&hydra, &h).unwrap();

        let before = secret_entries(&load_yaml(&kratos).unwrap(), &["secrets", "cookie"]).len();

        let idx = catalog::SETTINGS
            .iter()
            .position(|s| s.key == "kratos.secrets")
            .expect("kratos.secrets is a catalog setting")
            + 1;

        // Select the setting, choose [r]otate, answer the confirm `y`, quit.
        let script = format!("{idx}\nr\ny\nq\n");
        let out = Rc::new(RefCell::new(Vec::<u8>::new()));
        let snapshots = Rc::new(RefCell::new(Vec::<String>::new()));
        let input = RecordingLines {
            lines: script.lines().map(|l| format!("{l}\n")).collect(),
            out: out.clone(),
            snapshots: snapshots.clone(),
        };
        let inp: Rc<RefCell<dyn LineSource>> = Rc::new(RefCell::new(input));
        let mut io = MenuIo::new(inp, out.clone(), true);

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

        // The snapshot taken at the confirm read must already carry the full
        // question + `[y/N]:` prompt. A deferred writer (the bug being fixed)
        // would leave that snapshot without the question.
        let snaps = snapshots.borrow();
        let confirm = snaps
            .iter()
            .find(|s| s.contains("[y/N]:"))
            .unwrap_or_else(|| panic!("no confirm question rendered before any read: {snaps:?}"));
        assert!(
            confirm.contains("Rotate secrets.cookie, secrets.cipher in"),
            "confirm question missing from the pre-read snapshot: {confirm}"
        );

        // The rotation actually landed: cookie list gained the new secret.
        let after = secret_entries(&load_yaml(&kratos).unwrap(), &["secrets", "cookie"]).len();
        assert_eq!(after, before + 1, "rotation should prepend a cookie secret");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn eof_exits_cleanly() {
        let (mut io, _out) = menu_io(b"");
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
