//! Pure POSIX-name validation + monotonic id allocation. No DB here so the
//! policy is unit-testable in isolation; callers feed the existing-id slice
//! from a SELECT (inside their transaction).

/// POSIX portable username: `[a-z_][a-z0-9_-]*`, 1..=32 chars. Stricter than
/// useradd's default on purpose — these names flow into NSS.
#[allow(dead_code)] // used by posix::db provisioning (later task)
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

/// Next free id: `max(existing) + 1`, or `base` when none allocated at/above
/// base. `existing` need not be sorted; ids below `base` are ignored.
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
