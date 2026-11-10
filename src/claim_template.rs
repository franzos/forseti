//! Value template for self-service resource claims: literals from the
//! claim-value set `[A-Za-z0-9_.:-]`, exactly one `{sub}` and at most one
//! `{uuid}` (canonical lowercase), e.g. `u:{sub}:{uuid}`.

const MAX_TEMPLATE_LEN: usize = 128;
const MAX_VALUE_LEN: usize = 255;
const UUID_LEN: usize = 36;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Lit(String),
    Sub,
    Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    parts: Vec<Part>,
}

fn is_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-')
}

fn is_canonical_uuid(s: &str) -> bool {
    s.len() == UUID_LEN
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

impl Template {
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.len() > MAX_TEMPLATE_LEN {
            return Err("template must be at most 128 characters");
        }
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut rest = raw;
        while let Some(c) = rest.chars().next() {
            if c == '{' {
                let part = if rest.starts_with("{sub}") {
                    Part::Sub
                } else if rest.starts_with("{uuid}") {
                    Part::Uuid
                } else {
                    return Err("template placeholders are {sub} and {uuid}");
                };
                if parts.contains(&part) {
                    return Err("template may contain each placeholder once");
                }
                if !lit.is_empty() {
                    parts.push(Part::Lit(std::mem::take(&mut lit)));
                }
                rest = &rest[if part == Part::Sub { 5 } else { 6 }..];
                parts.push(part);
            } else if is_value_char(c) {
                lit.push(c);
                rest = &rest[c.len_utf8()..];
            } else {
                return Err("template literals must be in [A-Za-z0-9_.:-]");
            }
        }
        if !lit.is_empty() {
            parts.push(Part::Lit(lit));
        }
        if !parts.contains(&Part::Sub) {
            return Err("template must contain {sub}");
        }
        Ok(Self { parts })
    }

    pub(crate) fn has_uuid(&self) -> bool {
        self.parts.contains(&Part::Uuid)
    }

    /// Matches the whole `value`. `None`: no match. `Some(uuid)`: the
    /// `{uuid}` slice of `value`, or `None` inside when the template has none.
    pub(crate) fn matches<'v>(&self, value: &'v str) -> Option<Option<&'v str>> {
        if value.len() > MAX_VALUE_LEN || !value.chars().all(is_value_char) {
            return None;
        }
        // Everything but `{sub}` has a fixed length, so `{sub}` takes the rest
        // and the split is unambiguous even when sub contains literal chars.
        let fixed: usize = self
            .parts
            .iter()
            .map(|p| match p {
                Part::Lit(l) => l.len(),
                Part::Sub => 0,
                Part::Uuid => UUID_LEN,
            })
            .sum();
        let sub_len = value.len().checked_sub(fixed).filter(|&n| n > 0)?;
        let mut uuid = None;
        let mut rest = value;
        for part in &self.parts {
            let len = match part {
                Part::Lit(l) => l.len(),
                Part::Sub => sub_len,
                Part::Uuid => UUID_LEN,
            };
            let (head, tail) = rest.split_at(len);
            match part {
                Part::Lit(l) if head != l => return None,
                Part::Uuid if !is_canonical_uuid(head) => return None,
                Part::Uuid => uuid = Some(head),
                _ => {}
            }
            rest = tail;
        }
        Some(uuid)
    }

    /// Renders with a verified `sub`. `uuid` is required exactly when the
    /// template has `{uuid}`.
    pub(crate) fn render(&self, sub: &str, uuid: Option<&str>) -> Result<String, &'static str> {
        if sub.is_empty() {
            return Err("sub is empty");
        }
        match (self.has_uuid(), uuid) {
            (true, Some(u)) if is_canonical_uuid(u) => {}
            (true, Some(_)) => return Err("uuid is not canonical lowercase"),
            (true, None) => return Err("uuid is required"),
            (false, Some(_)) => return Err("template has no {uuid}"),
            (false, None) => {}
        }
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Lit(l) => out.push_str(l),
                Part::Sub => out.push_str(sub),
                Part::Uuid => out.push_str(uuid.unwrap_or_default()),
            }
        }
        if !out.chars().all(is_value_char) {
            return Err("value is outside [A-Za-z0-9_.:-]");
        }
        if out.len() > MAX_VALUE_LEN {
            return Err("value exceeds 255 characters");
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

    #[test]
    fn forgejo_template_matches_and_renders() {
        let t = Template::parse("u:{sub}:{uuid}").unwrap();
        assert!(t.has_uuid());
        let value = format!("u:42:{UUID}");
        assert_eq!(t.matches(&value), Some(Some(UUID)));
        assert_eq!(t.render("42", Some(UUID)).unwrap(), value);
    }

    #[test]
    fn sub_containing_literal_chars_still_splits() {
        let t = Template::parse("u:{sub}:{uuid}").unwrap();
        let value = format!("u:a:b:{UUID}");
        assert_eq!(t.matches(&value), Some(Some(UUID)));
        assert_eq!(t.render("a:b", Some(UUID)).unwrap(), value);
    }

    #[test]
    fn adjacent_placeholders_split_on_fixed_uuid() {
        let t = Template::parse("{sub}{uuid}").unwrap();
        assert_eq!(t.matches(&format!("x{UUID}")), Some(Some(UUID)));
        assert_eq!(t.matches(UUID), None);
    }

    #[test]
    fn sub_only_template() {
        let t = Template::parse("{sub}").unwrap();
        assert!(!t.has_uuid());
        assert_eq!(t.matches("12345"), Some(None));
        assert_eq!(t.matches(""), None);
        assert_eq!(t.render("12345", None).unwrap(), "12345");
        assert!(t.render("12345", Some(UUID)).is_err());
    }

    #[test]
    fn rejects_non_matching_values() {
        let t = Template::parse("u:{sub}:{uuid}").unwrap();
        assert_eq!(t.matches(&format!("v:42:{UUID}")), None);
        assert_eq!(t.matches(&format!("u::{UUID}")), None);
        assert_eq!(t.matches(&format!("u:42:{UUID}x")), None);
        assert_eq!(t.matches(&format!("u:4 2:{UUID}")), None);
        assert_eq!(t.matches("u:42:"), None);
        assert_eq!(t.matches(&format!("u:42:{}", "0".repeat(36))), None);
    }

    #[test]
    fn uppercase_uuid_refused() {
        let t = Template::parse("u:{sub}:{uuid}").unwrap();
        let upper = UUID.to_ascii_uppercase();
        assert_eq!(t.matches(&format!("u:42:{upper}")), None);
        assert!(t.render("42", Some(&upper)).is_err());
        assert!(t.render("42", None).is_err());
    }

    #[test]
    fn malformed_templates() {
        for raw in [
            "",
            "u:{uuid}",
            "{sub}{sub}",
            "{sub}:{uuid}:{uuid}",
            "{sub}{id}",
            "{sub",
            "{sub}}",
            "u/{sub}",
            "u {sub}",
            "ü{sub}",
            &format!("{}{{sub}}", "a".repeat(124)),
        ] {
            assert!(Template::parse(raw).is_err(), "should reject: {raw:?}");
        }
        assert!(Template::parse(&format!("{}{{sub}}", "a".repeat(123))).is_ok());
    }

    #[test]
    fn render_refuses_sub_outside_charset() {
        let t = Template::parse("u:{sub}:{uuid}").unwrap();
        assert!(t.render("a@b", Some(UUID)).is_err());
        assert!(t.render("a|b", Some(UUID)).is_err());
        assert!(t.render("", Some(UUID)).is_err());
    }

    #[test]
    fn render_refuses_overlong_value() {
        let t = Template::parse("{sub}").unwrap();
        assert!(t.render(&"a".repeat(255), None).is_ok());
        assert!(t.render(&"a".repeat(256), None).is_err());
        assert_eq!(t.matches(&"a".repeat(256)), None);
    }
}
