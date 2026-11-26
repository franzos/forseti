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

#[cfg(feature = "oauth-native")]
use crate::backend::OAuthBackend;
use crate::backend::OAuthImpl;
use crate::backend::oauth::OAuthClient;
use crate::config::PosixConfig;
use anyhow::Result;

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

fn is_public_client(c: &OAuthClient) -> bool {
    !is_confidential_auth_method(c.token_endpoint_auth_method.as_deref().unwrap_or_default())
}

/// Boot-time check that Hydra still reports the PAM client as confidential.
///
/// `Ok(true)` only when Hydra positively reports a public client; `Ok(false)`
/// when it's confidential *or* when we can't tell (Hydra still starting,
/// client not provisioned yet). A transient Hydra outage must not stop the
/// portal booting, so this never returns `Err`.
#[cfg(feature = "oauth-ory")]
pub async fn pam_client_is_public(oauth: &OAuthImpl, posix: &PosixConfig) -> Result<bool, String> {
    match oauth.get_client(&posix.pam_client_id).await {
        Ok(c) => Ok(is_public_client(&c)),
        Err(_) => Ok(false),
    }
}

/// Boot-time check that the local client store reports the PAM client as
/// confidential. A missing client is `Ok(false)` (not provisioned yet); a
/// failed read is `Err`, as the store is the local database.
#[cfg(feature = "oauth-native")]
pub async fn pam_client_is_public(oauth: &OAuthImpl, posix: &PosixConfig) -> Result<bool, String> {
    match oauth.get_client_opt(&posix.pam_client_id).await {
        Ok(Some(c)) => Ok(is_public_client(&c)),
        Ok(None) => Ok(false),
        Err(e) => Err(format!(
            "could not read OAuth client '{}' to check that it is confidential: {e}",
            posix.pam_client_id
        )),
    }
}

/// Build the `forseti-linux-pam` client model. `secret` is the plaintext
/// Hydra hashes on store. Scope is `openid` only: the device path needs just
/// `sub`/`acr`/`amr` from the id_token.
pub(crate) fn pam_client_model(client_id: &str, secret: &str) -> OAuthClient {
    OAuthClient {
        client_id: Some(client_id.to_string()),
        client_name: Some("Forseti Linux PAM (device auth)".to_string()),
        client_secret: Some(secret.to_string()),
        grant_types: Some(vec![DEVICE_CODE_GRANT.to_string()]),
        // Hydra requires the `code` response type registered for the login/consent
        // leg the device flow drives internally.
        response_types: Some(vec!["code".to_string(), "id_token".to_string()]),
        scope: Some("openid".to_string()),
        token_endpoint_auth_method: Some("client_secret_basic".to_string()),
        // Consent must not auto-skip; belt-and-suspenders alongside the
        // client_id-keyed guard in consent.rs.
        skip_consent: Some(false),
        ..OAuthClient::default()
    }
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
pub async fn ensure_pam_client(oauth: &OAuthImpl, posix: &PosixConfig) -> Result<EnsureOutcome> {
    let client_id = &posix.pam_client_id;

    // A successful GET means "exists"; an error means "probably absent, try
    // to create" (a colliding create errors, so we can't clobber).
    if oauth.get_client(client_id).await.is_ok() {
        return Ok(EnsureOutcome::AlreadyExists);
    }

    let (secret, minted) = match posix.pam_client_secret.as_deref() {
        Some(s) if !s.is_empty() => (s.to_string(), false),
        _ => (generate_secret(), true),
    };

    let model = pam_client_model(client_id, &secret);
    oauth.create_client(model).await?;

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
pub(crate) fn generate_secret() -> String {
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

    #[cfg(feature = "oauth-ory")]
    #[tokio::test]
    async fn hydra_guard_passes_while_hydra_is_unreachable() {
        let mut cfg = crate::config::AppConfig::test_fixture();
        cfg.hydra.admin_url = "http://127.0.0.1:9".to_string();
        cfg.hydra.public_url = "http://127.0.0.1:9".to_string();
        let db = crate::db::test_pool().await;
        let oauth = crate::backend::build_oauth(&cfg, &db, &[]);
        assert_eq!(pam_client_is_public(&oauth, &cfg.posix).await, Ok(false));
    }

    #[cfg(feature = "oauth-native")]
    #[tokio::test]
    async fn native_guard_passes_a_missing_client_and_fails_on_a_store_error() {
        use diesel::RunQueryDsl;
        let cfg = crate::config::AppConfig::test_fixture();
        let db = crate::db::test_pool().await;
        let oauth = crate::backend::build_oauth(&cfg, &db, &[0x42; 32]);
        assert_eq!(pam_client_is_public(&oauth, &cfg.posix).await, Ok(false));

        oauth
            .create_client(OAuthClient {
                client_id: Some(cfg.posix.pam_client_id.clone()),
                redirect_uris: Some(vec!["https://app.example/cb".to_string()]),
                scope: Some("openid".to_string()),
                token_endpoint_auth_method: Some(PUBLIC_AUTH_METHOD.to_string()),
                ..OAuthClient::default()
            })
            .await
            .unwrap();
        assert_eq!(pam_client_is_public(&oauth, &cfg.posix).await, Ok(true));

        let dropped: anyhow::Result<usize> = async {
            Ok(crate::db_interact!(db, |c| {
                diesel::sql_query("DROP TABLE oauth_clients").execute(c)
            })?)
        }
        .await;
        dropped.unwrap();
        let err = pam_client_is_public(&oauth, &cfg.posix).await.unwrap_err();
        assert!(err.contains(&cfg.posix.pam_client_id), "{err}");
    }

    #[test]
    fn generated_secret_has_expected_entropy() {
        let s = generate_secret();
        assert_eq!(s.len(), 40);
        assert!(s.chars().all(|ch| ch.is_ascii_alphanumeric()));
    }
}
