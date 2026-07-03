//! Strict validation of tenant CSS color values before they reach a pre-auth inline <style>.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Color(String);

impl Color {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn parse_color(input: &str) -> Option<Color> {
    let s = input.trim();
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    // Defence in depth: reject breakout bytes up front so a grammar slip can't leak one.
    if s.bytes().any(|b| {
        !b.is_ascii()
            || b.is_ascii_control()
            || matches!(
                b,
                b'{' | b'}' | b';' | b'\\' | b'<' | b'>' | b'@' | b'/' | b'*' | b'"' | b'\''
            )
    }) {
        return None;
    }
    if is_hex(s) || is_functional(s) {
        Some(Color(s.to_string()))
    } else {
        None
    }
}

fn is_hex(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('#') else {
        return false;
    };
    matches!(rest.len(), 3 | 4 | 6 | 8) && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_functional(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let (is_hsl, open) = if let Some(i) = lower.strip_prefix("rgba(").map(|_| 5) {
        (false, i)
    } else if lower.strip_prefix("rgb(").is_some() {
        (false, 4)
    } else if lower.strip_prefix("hsla(").is_some() {
        (true, 5)
    } else if lower.strip_prefix("hsl(").is_some() {
        (true, 4)
    } else {
        return false;
    };
    let Some(inner) = s[open..].strip_suffix(')') else {
        return false;
    };
    if inner.contains('(') || inner.contains(')') {
        return false;
    }
    let args: Vec<&str> = inner.split(',').map(str::trim).collect();
    if !(args.len() == 3 || args.len() == 4) {
        return false;
    }
    // For hsl, args 2 and 3 (s,l) must be percentages; hue is a plain number.
    args.iter().enumerate().all(|(i, a)| {
        if is_hsl && (i == 1 || i == 2) {
            a.strip_suffix('%').map(is_number).unwrap_or(false)
        } else {
            is_number(a) || a.strip_suffix('%').map(is_number).unwrap_or(false)
        }
    })
}

/// Non-empty run of ASCII digits with at most one dot, no sign, no exponent.
fn is_number(a: &str) -> bool {
    if a.is_empty() {
        return false;
    }
    let mut seen_dot = false;
    let mut seen_digit = false;
    for b in a.bytes() {
        match b {
            b'0'..=b'9' => seen_digit = true,
            b'.' if !seen_dot => seen_dot = true,
            _ => return false,
        }
    }
    seen_digit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_hex_and_functional() {
        for ok in [
            "#000",
            "#ffffff",
            "#12ab34",
            "#12ab34cd",
            "rgb(1,2,3)",
            "rgba(1, 2, 3, 0.5)",
            "hsl(210, 50%, 40%)",
            "hsla(210,50%,40%,0.5)",
        ] {
            assert!(parse_color(ok).is_some(), "should accept {ok}");
        }
    }

    #[test]
    fn rejects_css_breakouts_and_functions() {
        for bad in [
            "red",                    // bare keyword not allowed (allowlist is hex/functional)
            "#12",                    // wrong hex length
            "#gggggg",                // non-hex digits
            "red;}body{display:none", // declaration breakout
            "url(https://evil/x)",    // exfil channel
            "var(--x)",               // indirection
            "image-set(1)",
            "expression(1)",
            "#fff/*c*/",      // comment
            "rgb(1,2,3)\\",   // trailing backslash
            "rgb(1,2,3) }",   // brace
            "  ",             // empty
            "hsl(210,50,40)", // missing % on s/l
        ] {
            assert!(parse_color(bad).is_none(), "should reject {bad:?}");
        }
    }

    #[test]
    fn rejects_overlong_and_nonascii() {
        assert!(parse_color(&"#".repeat(200)).is_none());
        assert!(parse_color("rgb(1,2,3)é").is_none());
    }
}
