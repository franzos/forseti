#![allow(dead_code)] // consumed by the modify/menu tasks; remove with the last of them

use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng as _;
use sha2::{Digest as _, Sha256};

const BACKUP_RING_SIZE: usize = 3;

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct Target {
    pub path: PathBuf,
}

/// Canonicalize `path`'s parent directory (resolving any symlinks in it), then
/// join the final component back on without resolving it: a symlinked final
/// component is rejected unless `follow_symlink` is set, in which case the
/// fully resolved path is used instead. A nonexistent file under an existing
/// parent directory is fine (the config-init case).
pub(crate) fn resolve_target(path: &Path, follow_symlink: bool) -> anyhow::Result<Target> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let canon_parent = parent
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("{}: {e}", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{}: not a file path", path.display()))?;
    let candidate = canon_parent.join(file_name);

    match fs::symlink_metadata(&candidate) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if follow_symlink {
                let resolved = candidate
                    .canonicalize()
                    .map_err(|e| anyhow::anyhow!("{}: {e}", candidate.display()))?;
                Ok(Target { path: resolved })
            } else {
                Err(anyhow::anyhow!(
                    "{}: refusing to operate on a symlink (pass --follow-symlink to override)",
                    candidate.display()
                ))
            }
        }
        _ => Ok(Target { path: candidate }),
    }
}

// ---------------------------------------------------------------------------
// Directory locking
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct LockGuard(File);

/// Advisory `flock(2)` on `<dir>/.forseti-config.lock`. Locks are per open
/// file description (unlike `fcntl` record locks, which are per-process and
/// wouldn't conflict with a second open by the same process), so a second
/// in-process acquisition correctly fails. Releases automatically when the
/// guard (and its `File`) drops and the fd closes.
pub(crate) fn lock_config_dir(dir: &Path) -> anyhow::Result<LockGuard> {
    let lock_path = dir.join(".forseti-config.lock");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false) // the lock file carries no payload; never discard it on open
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", lock_path.display()))?;

    // SAFETY: `file` is a valid, open fd owned by this scope for the flock call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(anyhow::anyhow!("another forseti config modify is running"));
    }
    Ok(LockGuard(file))
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

fn backup_prefix(target: &Target) -> anyhow::Result<(PathBuf, String)> {
    let dir = target
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let file_name = target
        .path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{}: not a file path", target.path.display()))?
        .to_string_lossy()
        .into_owned();
    Ok((dir, file_name))
}

/// Copy `target` to `<file>.bak.<unix-secs>`, chmod 0600, then prune the ring
/// to the newest `BACKUP_RING_SIZE`. No-op (`Ok(None)`) when `target` doesn't
/// exist yet.
pub(crate) fn backup(target: &Target) -> anyhow::Result<Option<PathBuf>> {
    if !target.path.exists() {
        return Ok(None);
    }
    let (dir, file_name) = backup_prefix(target)?;
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
        .as_secs();
    let backup_path = dir.join(format!("{file_name}.bak.{secs}"));

    // Create backup with 0o600 mode at open time to avoid transient wider exposure
    let mut src = File::open(&target.path)?;
    let mut dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&backup_path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", backup_path.display()))?;
    std::io::copy(&mut src, &mut dst)?;

    let ring = list_backups(target)?; // newest first
    for stale in ring.into_iter().skip(BACKUP_RING_SIZE) {
        fs::remove_file(stale).ok();
    }
    Ok(Some(backup_path))
}

/// All `<file>.bak.<unix-secs>` backups for `target`, newest first.
pub(crate) fn list_backups(target: &Target) -> anyhow::Result<Vec<PathBuf>> {
    let (dir, file_name) = backup_prefix(target)?;
    let prefix = format!("{file_name}.bak.");

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("{}: {e}", dir.display())),
    };

    let mut backups: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(suffix) = name.strip_prefix(&prefix) {
            if let Ok(secs) = suffix.parse::<u64>() {
                backups.push((secs, entry.path()));
            }
        }
    }
    backups.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(backups.into_iter().map(|(_, p)| p).collect())
}

// ---------------------------------------------------------------------------
// Atomic writes
// ---------------------------------------------------------------------------

fn random_hex_suffix() -> String {
    let n: u32 = rand::rng().random();
    format!("{n:08x}")
}

/// Write `contents` to `target` via a randomized `O_EXCL` 0600 temp file in
/// the same directory (so the final rename is same-filesystem/atomic),
/// fsync, then rename over the target. The final mode matches the
/// pre-existing target's mode, or 0600 if there was none. Stale
/// `.<name>.tmp.*` files for this target (left by a prior crashed write) are
/// removed first.
pub(crate) fn atomic_write(target: &Target, contents: &[u8]) -> anyhow::Result<()> {
    let dir = target
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = target
        .path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{}: not a file path", target.path.display()))?
        .to_string_lossy()
        .into_owned();

    let stale_prefix = format!(".{file_name}.tmp.");
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&stale_prefix)
            {
                fs::remove_file(entry.path()).ok();
            }
        }
    }

    let final_mode = fs::metadata(&target.path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o600);

    let tmp_path = dir.join(format!(".{file_name}.tmp.{}", random_hex_suffix()));
    let mut tmp = OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", tmp_path.display()))?;
    tmp.write_all(contents)?;
    tmp.sync_all()?;
    drop(tmp);

    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(final_mode))?;
    fs::rename(&tmp_path, &target.path).map_err(|e| {
        anyhow::anyhow!(
            "renaming {} to {}: {e}",
            tmp_path.display(),
            target.path.display()
        )
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Secret input
// ---------------------------------------------------------------------------

pub(crate) enum SecretSource {
    Env(String),
    File(PathBuf),
    Stdin,
    Prompt(&'static str),
}

/// Read a secret from the given source, trimming trailing whitespace
/// (`Env`/`File`/`Stdin`) so a stray trailing newline from `echo` or an
/// editor doesn't become part of the value.
///
/// `Prompt` refuses when stdin isn't a TTY (script/CI context) rather than
/// silently hanging or reading garbage, and points the caller at the
/// `--*-stdin` alternative. `rpassword::prompt_password` saves and restores
/// the terminal's echo state around the blocking read, but that restore runs
/// only on normal return — see the crate-level note in this module's report
/// for the SIGINT-mid-prompt limitation; no signal handler is installed here.
pub(crate) fn read_secret(src: SecretSource) -> anyhow::Result<String> {
    match src {
        SecretSource::Env(name) => {
            let v = std::env::var(&name)
                .map_err(|_| anyhow::anyhow!("environment variable {name} is not set"))?;
            Ok(v.trim_end().to_string())
        }
        SecretSource::File(path) => {
            warn_if_readable_by_others(&path);
            let v = fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            Ok(v.trim_end().to_string())
        }
        SecretSource::Stdin => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf.trim_end().to_string())
        }
        SecretSource::Prompt(label) => {
            if !std::io::stdin().is_terminal() {
                anyhow::bail!("{label}: stdin is not a TTY; use --*-stdin instead");
            }
            let v = rpassword::prompt_password(format!("{label}: "))?;
            Ok(v.trim_end().to_string())
        }
    }
}

fn warn_if_readable_by_others(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {} is readable by group/other (mode {:o}); consider chmod 600",
                path.display(),
                mode & 0o777
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Fingerprinting & redaction
// ---------------------------------------------------------------------------

pub(crate) fn fingerprint(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(digest)[..8].to_string()
}

fn redact_secrets(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        let marker = format!(
            "<redacted sha256[:8]={}, len={}>",
            fingerprint(secret),
            secret.len()
        );
        out = out.replace(*secret, &marker);
    }
    out
}

/// Unified diff of `old` vs `new`, with every occurrence of each `secrets`
/// value replaced by a fingerprint marker in BOTH sides before diffing, so
/// no raw secret value ever reaches the diff (or a printed preview of it).
pub(crate) fn redacted_diff(label: &str, old: &str, new: &str, secrets: &[&str]) -> String {
    let redacted_old = redact_secrets(old, secrets);
    let redacted_new = redact_secrets(new, secrets);
    let diff = similar::TextDiff::from_lines(&redacted_old, &redacted_new);
    let mut unified = diff.unified_diff();
    unified.header(label, label);
    unified.to_string()
}

// ---------------------------------------------------------------------------
// git tracking
// ---------------------------------------------------------------------------

/// True when `git ls-files --error-unmatch <path>` succeeds, run with cwd set
/// to `path`'s directory. Any error (not a repo, git missing, not tracked)
/// is treated as "not tracked" — this only feeds an operator-facing warning.
pub(crate) fn is_git_tracked(path: &Path) -> bool {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(file_name) = path.file_name() else {
        return false;
    };
    std::process::Command::new("git")
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg(file_name)
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_tmp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("forseti-io-{}-{label}", std::process::id()))
    }

    #[test]
    fn atomic_write_preserves_existing_mode() {
        let dir = unique_tmp_dir("atomic-preserve");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yml");
        fs::write(&file, b"old").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let target = resolve_target(&file, false).unwrap();
        atomic_write(&target, b"new content").unwrap();

        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "atomic_write must preserve the pre-existing mode"
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), "new content");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_write_creates_as_0600_when_target_absent() {
        let dir = unique_tmp_dir("atomic-fresh");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yml");

        let target = resolve_target(&file, false).unwrap();
        atomic_write(&target, b"fresh").unwrap();

        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "atomic_write must create as 0600 when there's no prior file"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backup_creates_0600_bak_file() {
        let dir = unique_tmp_dir("backup-mode");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yml");
        fs::write(&file, b"secret-content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let target = Target { path: file.clone() };
        let backup_path = backup(&target)
            .unwrap()
            .expect("existing target must back up");
        assert!(
            backup_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("config.yml.bak."),
            "unexpected backup name: {backup_path:?}"
        );
        let mode = fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backup_noops_when_target_missing() {
        let dir = unique_tmp_dir("backup-missing");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yml");
        let target = Target { path: file };
        assert_eq!(backup(&target).unwrap(), None);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backup_prunes_ring_to_newest_three() {
        let dir = unique_tmp_dir("backup-prune");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yml");
        fs::write(&file, b"content").unwrap();
        let target = Target { path: file.clone() };

        // Seed 3 synthetic older backups so the pruning path doesn't depend on
        // real wall-clock gaps between unix-second-granularity timestamps.
        for secs in [1_000u64, 1_001, 1_002] {
            fs::write(dir.join(format!("config.yml.bak.{secs}")), b"old").unwrap();
        }

        let created = backup(&target).unwrap().expect("target exists");
        assert!(created.exists());

        let remaining = list_backups(&target).unwrap();
        assert_eq!(remaining.len(), 3, "ring must keep exactly 3 backups");
        assert!(
            !remaining.iter().any(|p| p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(".bak.1000")),
            "oldest backup (.bak.1000) must be pruned"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_backups_orders_newest_first() {
        let dir = unique_tmp_dir("list-order");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yml");
        fs::write(&file, b"content").unwrap();
        let target = Target { path: file.clone() };

        for secs in [500u64, 700, 600] {
            fs::write(dir.join(format!("config.yml.bak.{secs}")), b"x").unwrap();
        }

        let backups = list_backups(&target).unwrap();
        let names: Vec<_> = backups
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "config.yml.bak.700".to_string(),
                "config.yml.bak.600".to_string(),
                "config.yml.bak.500".to_string(),
            ]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_target_rejects_symlink_without_flag() {
        let dir = unique_tmp_dir("resolve-symlink");
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.yml");
        fs::write(&real, b"x").unwrap();
        let link = dir.join("link.yml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = resolve_target(&link, false).unwrap_err();
        assert!(err.to_string().contains("symlink"), "err: {err}");

        let ok = resolve_target(&link, true).unwrap();
        assert_eq!(ok.path, real.canonicalize().unwrap());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_target_allows_nonexistent_file_with_existing_parent() {
        let dir = unique_tmp_dir("resolve-init");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("not-yet.yml");

        let target = resolve_target(&file, false).unwrap();
        assert_eq!(target.path.file_name().unwrap(), "not-yet.yml");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn redacted_diff_hides_secret_value() {
        let old = "token: abc123\nother: line\n";
        let new = "token: xyz789\nother: line\n";
        let diff = redacted_diff("kratos.yml", old, new, &["abc123", "xyz789"]);
        assert!(diff.contains("<redacted"), "diff: {diff}");
        assert!(!diff.contains("abc123"), "diff: {diff}");
        assert!(!diff.contains("xyz789"), "diff: {diff}");
    }

    #[test]
    fn fingerprint_is_8_hex_chars() {
        let fp = fingerprint("x");
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "fp: {fp}");
    }

    #[test]
    fn read_secret_env_trims_trailing_whitespace() {
        // SAFETY: test-only; this env var name is unique to this test and no
        // other thread in the test binary touches it concurrently.
        unsafe {
            std::env::set_var("FORSETI_TEST_IO_SECRET", "tok\n");
        }
        let v = read_secret(SecretSource::Env("FORSETI_TEST_IO_SECRET".to_string())).unwrap();
        assert_eq!(v, "tok");
        unsafe {
            std::env::remove_var("FORSETI_TEST_IO_SECRET");
        }
    }

    #[test]
    fn read_secret_env_missing_is_an_error() {
        let err = read_secret(SecretSource::Env(
            "FORSETI_TEST_IO_SECRET_MISSING".to_string(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("FORSETI_TEST_IO_SECRET_MISSING"));
    }

    #[test]
    fn lock_config_dir_second_acquisition_in_process_fails() {
        let dir = unique_tmp_dir("lock");
        fs::create_dir_all(&dir).unwrap();

        let _guard = lock_config_dir(&dir).unwrap();
        let err = lock_config_dir(&dir).unwrap_err();
        assert_eq!(err.to_string(), "another forseti config modify is running");

        drop(_guard);
        // Once released, a fresh acquisition must succeed again.
        let _guard2 = lock_config_dir(&dir).unwrap();

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_git_tracked_false_outside_a_repo() {
        let dir = unique_tmp_dir("git-tracked");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yml");
        fs::write(&file, b"x").unwrap();
        assert!(!is_git_tracked(&file));

        fs::remove_dir_all(&dir).ok();
    }
}
