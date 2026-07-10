use std::path::Path;

use rand::distr::Alphanumeric;
use rand::Rng;
use serde_yaml_ng::Value;

// ---------------------------------------------------------------------------
// YAML navigation helpers (mirror how the codebase walks serde_json::Value).
// ---------------------------------------------------------------------------

pub(crate) fn dig<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = root;
    for key in path {
        cur = cur.get(*key)?;
    }
    Some(cur)
}

pub(crate) fn dig_str<'a>(root: &'a Value, path: &[&str]) -> Option<&'a str> {
    dig(root, path).and_then(Value::as_str)
}

pub(crate) fn dig_bool(root: &Value, path: &[&str]) -> Option<bool> {
    dig(root, path).and_then(Value::as_bool)
}

/// A YAML string that is empty, missing, or an obvious placeholder isn't a
/// real secret/URL. Case-insensitive substring match against known tells.
pub(crate) fn is_placeholder(s: &str) -> bool {
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
pub(crate) fn first_secret<'a>(root: &'a Value, path: &[&str]) -> Option<&'a str> {
    match dig(root, path) {
        Some(Value::Sequence(seq)) => seq.first().and_then(Value::as_str),
        Some(Value::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

pub(crate) fn load_yaml(path: &Path) -> anyhow::Result<Value> {
    let display = path.display();
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{display}: {e}"))?;
    let value: Value = serde_yaml_ng::from_str(&text)
        .map_err(|e| anyhow::anyhow!("{display}: invalid YAML: {e}"))?;
    Ok(value)
}

/// Quote an operator value as a safe single-line YAML double-quoted scalar so
/// it can't break out of scalar position and inject sibling keys. Hand-rolled
/// because serde_yaml_ng emits a multi-line block scalar for newline-bearing
/// strings, which would be invalid inline; `validate_inputs` rejects those
/// anyway, but the escaping keeps this robust on its own.
pub(crate) fn yaml_scalar(s: &str) -> String {
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
/// the templated YAML (single-line URLs/DSNs/SMTP URIs never need them), and
/// they're the vector for scalar-breakout key injection.
pub(crate) fn reject_control_chars(label: &str, value: &str) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err(format!(
            "invalid value for {label}: control characters not allowed"
        ));
    }
    Ok(())
}

/// CSPRNG-backed alphanumeric secret of exactly `len` chars. `rand::rng()` is
/// `ThreadRng`, seeded from the OS RNG, the same source the rest of the crate
/// uses for tokens (`csrf.rs`, `dcr_tokens.rs`).
pub(crate) fn random_secret(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
