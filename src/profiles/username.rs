//! Validation for the user-chosen handle emitted as the OIDC
//! `preferred_username` claim.
//!
//! OIDC Core 5.1 permits any JSON string here, including `@`, `/` and
//! whitespace, and 5.7 tells RPs the value is neither unique nor stable. RPs
//! ignore that: Forgejo derives the local username from this claim and, with
//! `ACCOUNT_LINKING = auto`, uses it to match an existing account. So the
//! charset below is deliberately narrower than the spec allows — no `@`, so a
//! handle can never be mistaken for an email address.

/// Matches Forgejo's own limit; anything longer is truncated RP-side.
pub const MAX_LEN: usize = 39;
pub const MIN_LEN: usize = 2;

/// Handles nobody may claim: role words an RP might treat as privileged, and
/// the vendor names already denied to self-registered clients.
const RESERVED: &[&str] = &[
    "abuse",
    "admin",
    "administrator",
    "api",
    "billing",
    "forseti",
    "hostmaster",
    "hydra",
    "kratos",
    "login",
    "mailer-daemon",
    "no-reply",
    "noreply",
    "oauth",
    "openid",
    "ory",
    "portal",
    "postmaster",
    "root",
    "security",
    "support",
    "system",
    "webmaster",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameError {
    TooShort,
    TooLong,
    Charset,
    Edges,
    Repeat,
    Reserved,
}

/// Validate a handle, returning it trimmed in the casing the user typed.
/// Uniqueness is keyed on [`fold`], not on this value.
pub fn validate(raw: &str) -> Result<String, UsernameError> {
    let t = raw.trim();
    if t.chars().count() < MIN_LEN {
        return Err(UsernameError::TooShort);
    }
    if t.chars().count() > MAX_LEN {
        return Err(UsernameError::TooLong);
    }
    let sep = |c: char| c == '.' || c == '_' || c == '-';
    if !t.chars().all(|c| c.is_ascii_alphanumeric() || sep(c)) {
        return Err(UsernameError::Charset);
    }
    let first = t.chars().next().unwrap_or_default();
    let last = t.chars().next_back().unwrap_or_default();
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(UsernameError::Edges);
    }
    if t.as_bytes()
        .windows(2)
        .any(|w| sep(w[0] as char) && sep(w[1] as char))
    {
        return Err(UsernameError::Repeat);
    }
    if RESERVED.contains(&fold(t).as_str()) {
        return Err(UsernameError::Reserved);
    }
    Ok(t.to_string())
}

/// The uniqueness key, stored alongside the display form in
/// `member_profiles.username_lc` and carried by the tombstone table.
pub fn fold(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{UsernameError, fold, validate};

    #[test]
    fn accepts_ordinary_handles() {
        for ok in ["franz", "j.doe", "a-b_c", "user123", "ab"] {
            assert_eq!(validate(ok).as_deref(), Ok(ok), "{ok}");
        }
    }

    #[test]
    fn trims_but_preserves_casing() {
        assert_eq!(validate("  FranzG  ").as_deref(), Ok("FranzG"));
        assert_eq!(fold("FranzG"), "franzg");
    }

    #[test]
    fn rejects_email_shaped_input() {
        assert_eq!(validate("franz@example.com"), Err(UsernameError::Charset));
    }

    #[test]
    fn rejects_non_ascii_and_whitespace() {
        assert_eq!(validate("frаnz"), Err(UsernameError::Charset)); // cyrillic а
        assert_eq!(validate("franz g"), Err(UsernameError::Charset));
        assert_eq!(validate("franz\u{200b}g"), Err(UsernameError::Charset));
    }

    #[test]
    fn rejects_separator_edges_and_runs() {
        assert_eq!(validate("-franz"), Err(UsernameError::Edges));
        assert_eq!(validate("franz."), Err(UsernameError::Edges));
        assert_eq!(validate("fr..anz"), Err(UsernameError::Repeat));
    }

    #[test]
    fn rejects_reserved_regardless_of_casing() {
        assert_eq!(validate("Admin"), Err(UsernameError::Reserved));
        assert_eq!(validate("ROOT"), Err(UsernameError::Reserved));
    }

    #[test]
    fn enforces_length_bounds() {
        assert_eq!(validate("a"), Err(UsernameError::TooShort));
        assert_eq!(validate(&"a".repeat(40)), Err(UsernameError::TooLong));
        assert!(validate(&"a".repeat(39)).is_ok());
    }
}
