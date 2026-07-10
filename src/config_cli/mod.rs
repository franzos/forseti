//! `config-check` / `config-init` operator subcommands. Kratos's API exposes
//! no live settings (only a version + opaque hash), so these lint/generate the
//! config FILES directly.

mod check;
mod init;
mod yamlutil;

pub(crate) use check::check;
pub(crate) use check::redact_uri;
pub(crate) use init::init;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flag_does_not_swallow_next_flag() {
        let args = vec!["--forseti-url".to_string(), "--force".to_string()];
        assert_eq!(parse_flag(&args, "--forseti-url"), None);
        assert!(has_flag(&args, "--force"));
        let args = vec!["--forseti-url=https://f".to_string()];
        assert_eq!(parse_flag(&args, "--forseti-url"), Some("https://f"));
    }
}
