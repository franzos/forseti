//! The `forseti-linux-pam` confidential OAuth client (RFC 8628 device grant)
//! and the create-if-absent helper the `posix-init-client` CLI drives.
//!
//! This is the client Forseti authenticates as when it relays a Linux host's
//! PAM device-auth through Hydra. It is **confidential** — a leaked
//! `device_code` is useless without Forseti's client credential — and it
//! NEVER skips consent (the consent screen is where the host+account binding
//! is shown to the approver; see R1).
//!
//! Auth method: `client_secret_basic` for v1. R12 prefers `private_key_jwt`,
//! but the JWKS/keystore plumbing is heavier than this pass warrants.
//! TODO(R12): move to `private_key_jwt` (client publishes a JWKS, Forseti
//! holds the private key) so there's no shared secret at rest.

use crate::config::PosixConfig;
use crate::ory::hydra;
use crate::ory::OryClients;
use anyhow::Result;
use ory_client::models::OAuth2Client;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Build the desired `forseti-linux-pam` client model. `secret` is the
/// plaintext to set; Hydra hashes it on store. Scope is `openid` only —
/// the device path needs `sub`/`acr`/`amr` from the id_token, nothing more.
fn pam_client_model(client_id: &str, secret: &str) -> OAuth2Client {
    let mut c = OAuth2Client::new();
    c.client_id = Some(client_id.to_string());
    c.client_name = Some("Forseti Linux PAM (device auth)".to_string());
    c.client_secret = Some(secret.to_string());
    c.grant_types = Some(vec![DEVICE_CODE_GRANT.to_string()]);
    // Device grant issues id+access tokens via the token endpoint; no
    // authorization-code response type is needed, but Hydra requires the
    // `code` response type registered for the login/consent leg the device
    // flow drives internally.
    c.response_types = Some(vec!["code".to_string(), "id_token".to_string()]);
    c.scope = Some("openid".to_string());
    c.token_endpoint_auth_method = Some("client_secret_basic".to_string());
    // The binding renders on the verification + consent screens; consent
    // MUST NOT auto-skip (R1). Belt-and-suspenders alongside the
    // client_id-keyed guard in consent.rs.
    c.skip_consent = Some(false);
    c
}

/// Outcome of [`ensure_pam_client`] so the CLI can report precisely and
/// reveal a freshly-minted secret exactly once.
pub enum EnsureOutcome {
    /// Client already existed; left untouched (never overwrite operator changes).
    AlreadyExists,
    /// Client was created. Carries the plaintext secret to reveal once —
    /// either the operator-supplied one or a freshly minted CSPRNG secret.
    Created { secret: String },
}

/// Create the `forseti-linux-pam` client if it doesn't already exist.
///
/// Best-effort, idempotent, **never overwrites** an existing client (an
/// operator may have rotated the secret or tuned the model). Returns
/// [`EnsureOutcome::AlreadyExists`] without touching Hydra when the client
/// is present. NOT called at boot — only by the `posix-init-client` verb
/// (R1 / Decision 8).
pub async fn ensure_pam_client(ory: &OryClients, posix: &PosixConfig) -> Result<EnsureOutcome> {
    let client_id = &posix.pam_client_id;

    // GET → if present, leave it. Hydra returns 404 for an unknown client;
    // the wrapper maps that to an Err, so treat a successful GET as "exists"
    // and any error as "probably absent, try to create" — but a create that
    // collides will itself error, keeping us from clobbering.
    if hydra::get_client(ory, client_id).await.is_ok() {
        return Ok(EnsureOutcome::AlreadyExists);
    }

    // Use the operator-supplied secret if configured; otherwise mint one and
    // reveal it once.
    let (secret, minted) = match posix.pam_client_secret.as_deref() {
        Some(s) if !s.is_empty() => (s.to_string(), false),
        _ => (generate_secret(), true),
    };

    let model = pam_client_model(client_id, &secret);
    hydra::create_client(ory, model).await?;

    // Reveal the secret only when WE minted it. An operator-supplied secret
    // is already in their config; echoing it back adds nothing.
    if minted {
        Ok(EnsureOutcome::Created { secret })
    } else {
        Ok(EnsureOutcome::Created {
            secret: String::new(),
        })
    }
}

/// 40 alphanumerics ≈ 238 bits — same shape as Hydra's own client secrets.
fn generate_secret() -> String {
    use rand::distr::Alphanumeric;
    use rand::Rng;
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_model_is_confidential_device_grant() {
        let c = pam_client_model("forseti-linux-pam", "s3cret");
        assert_eq!(c.client_id.as_deref(), Some("forseti-linux-pam"));
        assert_eq!(
            c.grant_types.as_deref(),
            Some(&[DEVICE_CODE_GRANT.to_string()][..])
        );
        assert_eq!(c.scope.as_deref(), Some("openid"));
        assert_eq!(c.skip_consent, Some(false));
        assert_eq!(
            c.token_endpoint_auth_method.as_deref(),
            Some("client_secret_basic")
        );
    }

    #[test]
    fn generated_secret_has_expected_entropy() {
        let s = generate_secret();
        assert_eq!(s.len(), 40);
        assert!(s.chars().all(|ch| ch.is_ascii_alphanumeric()));
    }
}
