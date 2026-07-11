//! `config-check` / `config-init` operator subcommands. Kratos's API exposes
//! no live settings (only a version + opaque hash), so these lint/generate the
//! config FILES directly.

mod catalog;
mod check;
mod init;
mod io;
mod modify;
mod yamlutil;

pub(crate) use check::check;
pub(crate) use check::redact_uri;
pub(crate) use check::status;
pub(crate) use init::init;
pub(crate) use modify::run_oidc;
pub(crate) use modify::run_prune_hydra_system;
pub(crate) use modify::run_prune_kratos_secrets;
pub(crate) use modify::run_prune_webhook_token;
pub(crate) use modify::run_restore;
pub(crate) use modify::run_rotate_hydra_system;
pub(crate) use modify::run_rotate_kratos_secrets;
pub(crate) use modify::run_rotate_pairwise_salt;
pub(crate) use modify::run_rotate_webhook_token;
pub(crate) use modify::run_smtp;
