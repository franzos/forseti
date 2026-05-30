//! Forseti-owned SMTP transport for invite + claim-email mail.
//!
//! Kratos's courier handles its own self-service mail (verification,
//! recovery, MFA enrolment). Forseti-originated mail — org invites and
//! the hand-rolled claim-email verification — goes through this module.
//! The split exists because Kratos v26 doesn't expose a usable one-off
//! `POST /admin/courier/messages` endpoint (returns 405), so Forseti
//! speaks SMTP directly under `[smtp]` config.

use std::time::Duration;

use anyhow::Result;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::{SelfConfig, SmtpConfig, SmtpScheme};

/// Send a plaintext mail. When `cfg.enabled` is false, logs the
/// recipient/subject and returns Ok — callers proceed and the underlying
/// token/code remains accessible via the DB for dev hand-delivery.
pub async fn send_text(
    cfg: &SmtpConfig,
    self_cfg: &SelfConfig,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<()> {
    if !cfg.enabled {
        tracing::info!(
            recipient = recipient,
            subject = subject,
            "smtp disabled; would-be mail dropped (token/code still valid via DB)"
        );
        return Ok(());
    }

    let from_address = if cfg.from.is_empty() {
        let host = url::Url::parse(&self_cfg.url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "localhost".to_string());
        format!("noreply@{host}")
    } else {
        cfg.from.clone()
    };

    let from: Mailbox = from_address
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid [smtp].from value '{from_address}': {e}"))?;
    let to: Mailbox = recipient
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid recipient '{recipient}': {e}"))?;

    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| anyhow::anyhow!("compose mail failed: {e}"))?;

    let mut builder = match cfg.scheme {
        SmtpScheme::Plaintext => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host).tls(Tls::None)
        }
        SmtpScheme::Starttls | SmtpScheme::Smtps => {
            let mut tls = TlsParameters::builder(cfg.host.clone());
            if cfg.skip_tls_verify {
                warn_insecure_tls();
                tls = tls
                    .dangerous_accept_invalid_certs(true)
                    .dangerous_accept_invalid_hostnames(true);
            }
            let tls = tls
                .build()
                .map_err(|e| anyhow::anyhow!("smtp tls params: {e}"))?;
            // Both branches start from `builder_dangerous` so we can
            // override host/port without lettre's `relay` defaulting to
            // 25/465. The TLS variant is wired explicitly per scheme.
            let kind = if matches!(cfg.scheme, SmtpScheme::Smtps) {
                Tls::Wrapper(tls)
            } else {
                Tls::Required(tls)
            };
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host).tls(kind)
        }
    };
    builder = builder
        .port(cfg.port)
        .timeout(Some(Duration::from_secs(15)));
    if !cfg.username.is_empty() {
        builder = builder.credentials(Credentials::new(
            cfg.username.clone(),
            cfg.password.to_string(),
        ));
    }
    let transport = builder.build();

    transport
        .send(message)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("smtp send failed: {e}"))
}

/// Warn once that TLS verification is disabled on a TLS scheme. Only reached
/// for STARTTLS/SMTPS with `[smtp].skip_tls_verify = true` — plaintext is
/// insecure by definition and doesn't warrant the warning. `Once` keeps it
/// to a single line no matter how many mails go out.
fn warn_insecure_tls() {
    use std::sync::Once;
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            "[smtp].skip_tls_verify is set on a TLS scheme: SMTP certificate and \
             hostname verification are DISABLED. A MITM on the SMTP path can then \
             capture credentials and the contents of invite / claim-email mail. \
             Unset skip_tls_verify in production."
        );
    });
}
