//! Entry points the `fuzz/` crate drives. Everything else stays crate-private.

pub use crate::client_ip::forwarded_client_ip;
pub use crate::config_cli::yamlutil::{parse_yaml, to_yaml, yaml_scalar};
pub use crate::csrf::{token_is_valid, url_origin};
pub use crate::format::{humanise_timestamp, humanise_user_agent};
pub use crate::locale::{default_locale, from_accept_language, from_query_or_cookie};
pub use crate::signed_cookie::SignedCookie;
pub use crate::web::{safe_external_uri, safe_return_to_for_origin};
