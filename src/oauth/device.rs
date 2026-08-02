//! The `forseti-linux-pam` confidential OAuth client (RFC 8628 device grant)
//! and the create-if-absent helper the `posix-init-client` CLI drives.
//!
//! This is the client Forseti authenticates as when relaying a Linux host's
//! PAM device-auth through Hydra. Confidential (a leaked `device_code` is
//! useless without Forseti's credential) and it never skips consent (the
//! consent screen carries the host+account binding).
//!
//! Auth method: `client_secret_basic`.
//! TODO: move to `private_key_jwt` (client publishes a JWKS, Forseti holds
//! the private key) so there's no shared secret at rest.

use crate::config::PosixConfig;
use crate::ory::OryClients;
use crate::ory::hydra;
use anyhow::Result;
use ory_client::models::OAuth2Client;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The one `token_endpoint_auth_method` that makes a client public. Everything
/// else Hydra accepts (`client_secret_basic`/`_post`, `private_key_jwt`, the
/// mTLS methods) requires a credential at the token endpoint.
const PUBLIC_AUTH_METHOD: &str = "none";

/// Whether `method` still requires a credential at Hydra's token endpoint. An
/// empty value is confidential: OIDC Core defaults an omitted method to
/// `client_secret_basic`.
///
/// This must hold for the PAM client. Forseti hands each host an opaque code of
/// its own and redeems Hydra's `device_code` itself (see
/// [`crate::posix::device`]); downgrading the client to `none` would make that
/// `device_code` redeemable by anyone who obtained it, collapsing the whole
/// binding in `evaluate_binding` back to "possession of a code".
pub fn is_confidential_auth_method(method: &str) -> bool {
    !method.trim().eq_ignore_ascii_case(PUBLIC_AUTH_METHOD)
}

/// Boot-time check that Hydra still reports the PAM client as confidential.
///
/// Deliberately three-valued: `Ok(())` when it's confidential *or* when we
/// can't tell (Hydra still starting, client not provisioned yet), and `Err`
/// only when Hydra positively reports a public client. A transient Hydra
/// outage must not stop the portal booting.
pub async fn pam_client_is_public(ory: &OryClients, posix: &PosixConfig) -> bool {
    match hydra::get_client(ory, &posix.pam_client_id).await {
        Ok(c) => !is_confidential_auth_method(
            c.token_endpoint_auth_method.as_deref().unwrap_or_default(),
        ),
        Err(_) => false,
    }
}

/// Build the `forseti-linux-pam` client model. `secret` is the plaintext
/// Hydra hashes on store. Scope is `openid` only: the device path needs just
/// `sub`/`acr`/`amr` from the id_token.
fn pam_client_model(client_id: &str, secret: &str) -> OAuth2Client {
    let mut c = OAuth2Client::new();
    c.client_id = Some(client_id.to_string());
    c.client_name = Some("Forseti Linux PAM (device auth)".to_string());
    c.client_secret = Some(secret.to_string());
    c.grant_types = Some(vec![DEVICE_CODE_GRANT.to_string()]);
    // Hydra requires the `code` response type registered for the login/consent
    // leg the device flow drives internally.
    c.response_types = Some(vec!["code".to_string(), "id_token".to_string()]);
    c.scope = Some("openid".to_string());
    c.token_endpoint_auth_method = Some("client_secret_basic".to_string());
    // Consent must not auto-skip; belt-and-suspenders alongside the
    // client_id-keyed guard in consent.rs.
    c.skip_consent = Some(false);
    c
}

/// Outcome of [`ensure_pam_client`].
pub enum EnsureOutcome {
    /// Client already existed; left untouched.
    AlreadyExists,
    /// Client was created. Carries the plaintext secret to reveal once.
    Created { secret: String },
}

/// Create the `forseti-linux-pam` client if absent. Idempotent and never
/// overwrites an existing client (the operator may have rotated the secret or
/// tuned the model). Not called at boot, only by the `posix-init-client` verb.
pub async fn ensure_pam_client(ory: &OryClients, posix: &PosixConfig) -> Result<EnsureOutcome> {
    let client_id = &posix.pam_client_id;

    // A successful GET means "exists"; an error means "probably absent, try
    // to create" (a colliding create errors, so we can't clobber).
    if hydra::get_client(ory, client_id).await.is_ok() {
        return Ok(EnsureOutcome::AlreadyExists);
    }

    let (secret, minted) = match posix.pam_client_secret.as_deref() {
        Some(s) if !s.is_empty() => (s.to_string(), false),
        _ => (generate_secret(), true),
    };

    let model = pam_client_model(client_id, &secret);
    hydra::create_client(ory, model).await?;

    // Reveal only a minted secret; an operator-supplied one is already in
    // their config.
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
    use rand::RngExt;
    use rand::distr::Alphanumeric;
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
    fn only_none_counts_as_a_public_auth_method() {
        assert!(is_confidential_auth_method("client_secret_basic"));
        assert!(is_confidential_auth_method("client_secret_post"));
        assert!(is_confidential_auth_method("private_key_jwt"));
        // Omitted → Hydra applies the OIDC default, which is confidential.
        assert!(is_confidential_auth_method(""));
        assert!(!is_confidential_auth_method("none"));
        // Casing/whitespace must not smuggle a downgrade past the guard.
        assert!(!is_confidential_auth_method("None"));
        assert!(!is_confidential_auth_method(" none "));
    }

    #[test]
    fn generated_secret_has_expected_entropy() {
        let s = generate_secret();
        assert_eq!(s.len(), 40);
        assert!(s.chars().all(|ch| ch.is_ascii_alphanumeric()));
    }
}
