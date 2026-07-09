//! Forseti-owned mail transport for org-invite + claim-email mail (Kratos's courier handles its own
//! self-service mail). Forseti sends directly because Kratos v26 has no usable one-off
//! `POST /admin/courier/messages` (returns 405). Provider selection + credentials come from
//! polymail's `ProviderConfig`, flattened under `[email]`; see `config::EmailConfig`.

use anyhow::Result;
use polymail::{Address, Body, Email};

use crate::config::{EmailConfig, SelfConfig};

/// Send a plaintext mail. When `cfg` is `None` (no `[email]` section) or
/// `cfg.enabled` is false, logs the recipient/subject and returns Ok; callers
/// proceed and the underlying token/code remains accessible via the DB for dev
/// hand-delivery.
pub async fn send_text(
    cfg: Option<&EmailConfig>,
    self_cfg: &SelfConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<()> {
    let Some(cfg) = cfg.filter(|c| c.enabled) else {
        tracing::info!(
            recipient = recipient,
            subject = subject,
            "email disabled; would-be mail dropped (token/code still valid via DB)"
        );
        return Ok(());
    };

    let from_address = cfg.from_address.clone().unwrap_or_else(|| {
        let host = url::Url::parse(&self_cfg.url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "localhost".to_string());
        format!("noreply@{host}")
    });

    let from = match cfg.from_name.as_deref().filter(|n| !n.is_empty()) {
        Some(name) => Address::with_name(from_address, name),
        None => Address::new(from_address),
    };

    let email = Email::builder(from, subject, Body::Text(body.to_string()))
        .to(recipient)
        .build()
        .map_err(|e| anyhow::anyhow!("compose mail failed: {e}"))?;

    let mailer = cfg
        .provider
        .clone()
        .build()
        .map_err(|e| anyhow::anyhow!("email provider build failed: {e}"))?;

    mailer
        .send(&email)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("email send failed: {e}"))
}

/// Pragmatic addr-spec check for user-submitted addresses (replaces lettre's
/// parser, which no longer sits in the tree). Requires exactly one `@`, a
/// non-empty local part, a dotted domain with non-empty labels, and no
/// whitespace or control characters. Not full RFC 5321, but enough to reject
/// the obvious garbage a form can submit; the real bounce check is delivery.
pub fn is_valid_email(addr: &str) -> bool {
    let Some((local, domain)) = addr.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return false;
    }
    if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let mut labels = domain.split('.').peekable();
    let has_dot = domain.contains('.');
    has_dot && labels.all(|l| !l.is_empty())
}

#[cfg(test)]
mod tests {
    use super::is_valid_email;

    #[test]
    fn accepts_ordinary_addresses() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("a.b+tag@sub.example.co.uk"));
    }

    #[test]
    fn rejects_malformed_addresses() {
        for bad in [
            "",
            "no-at-sign",
            "@example.com",
            "user@",
            "user@localhost",
            "user@@example.com",
            "user@exa mple.com",
            "user @example.com",
            "user@example..com",
        ] {
            assert!(!is_valid_email(bad), "should reject {bad:?}");
        }
    }
}
