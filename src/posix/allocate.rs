//! Pure POSIX-name validation + monotonic id allocation. No DB here so the
//! policy is unit-testable in isolation; callers feed the existing-id slice
//! from a SELECT (inside their transaction).

use crate::orgs::teams::Team;

/// NSS-safe group name for a team: its slug if POSIX-valid, else `team-<id>`.
pub fn posix_group_name(t: &Team) -> String {
    if is_valid_username(&t.slug) {
        t.slug.clone()
    } else {
        format!("team-{}", t.id)
    }
}

/// POSIX portable username: `[a-z_][a-z0-9_-]*`, 1..=32 chars. Stricter than
/// useradd's default on purpose: these names flow into NSS.
pub fn is_valid_username(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first == b'_') {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A login shell fit to hand the NSS resolver: an absolute path, no control
/// characters, no whitespace. The NUL is the pointed one - the shell is a
/// field of every `passwd` entry, and a NUL in there is what makes the C-side
/// buffer writer panic across the ABI into sshd or sudo. The resolver drops
/// such an entry now, but nothing should be able to store one in the first
/// place. Length matches the username cap's order of magnitude; real shells
/// are far shorter.
pub fn is_valid_shell(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.starts_with('/')
        && !s.contains("//")
        && !s.ends_with('/')
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Next free id: `max(existing) + 1`, or `base` when none allocated at/above
/// base. `existing` need not be sorted; ids below `base` are ignored.
#[allow(dead_code)] // pure helper; DB allocation currently goes through sequences::next_in_band.
pub fn next_id(base: u32, existing: &[u32]) -> u32 {
    match existing.iter().copied().filter(|&id| id >= base).max() {
        Some(m) => m + 1,
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_shells_are_absolute_and_clean() {
        assert!(is_valid_shell("/bin/bash"));
        assert!(is_valid_shell("/usr/sbin/nologin"));
        assert!(is_valid_shell("/bin/sh"));
    }

    #[test]
    fn invalid_shells_are_refused() {
        assert!(!is_valid_shell(""));
        assert!(!is_valid_shell("bash"), "must be absolute");
        assert!(!is_valid_shell("/bin/"), "trailing slash");
        assert!(!is_valid_shell("/bin//bash"), "empty path segment");
        assert!(!is_valid_shell("/bin/my shell"), "whitespace");
        assert!(!is_valid_shell("/bin/sh\n/bin/evil"), "newline");
        // The one that aborts sshd if it reaches the NSS buffer writer.
        assert!(!is_valid_shell("/bin/sh\0/bin/evil"), "interior NUL");
        assert!(!is_valid_shell(&format!("/bin/{}", "a".repeat(300))));
    }

    #[test]
    fn valid_posix_names() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("a_b-c1"));
        assert!(is_valid_username("_svc"));
    }
    #[test]
    fn invalid_posix_names() {
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("1alice")); // leading digit
        assert!(!is_valid_username("Alice")); // uppercase
        assert!(!is_valid_username("a b")); // space
        assert!(!is_valid_username(&"x".repeat(33))); // >32
    }
    #[test]
    fn next_id_is_max_plus_one_or_base() {
        assert_eq!(next_id(1_000_000, &[]), 1_000_000);
        assert_eq!(next_id(1_000_000, &[1_000_000, 1_000_002]), 1_000_003);
        // ids below base are ignored: base still wins
        assert_eq!(next_id(1_000_000, &[5, 10]), 1_000_000);
    }
}
