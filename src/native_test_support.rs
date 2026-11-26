//! Entry points the integration suite uses to seed a native Forseti's database.

#[cfg(feature = "identity-native")]
pub use crate::identity_native::seed::{cookie_secret, password_config, token_hash, totp_config};
#[cfg(feature = "oauth-native")]
pub use crate::oauth_native::clients::hash_secret;
