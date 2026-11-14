//! `config-check` / `config-init` operator subcommands. Kratos's API exposes
//! no live settings (only a version + opaque hash), so these lint/generate the
//! config FILES directly. Only `yamlutil` is built with `identity-native`.

#[cfg(feature = "identity-ory")]
mod catalog;
#[cfg(feature = "identity-ory")]
mod check;
#[cfg(feature = "identity-ory")]
mod init;
#[cfg(feature = "identity-ory")]
mod io;
#[cfg(feature = "identity-ory")]
mod menu;
#[cfg(feature = "identity-ory")]
mod modify;
pub(crate) mod yamlutil;

#[cfg(feature = "identity-ory")]
pub(crate) use {
    check::{check, redact_uri, status},
    init::init,
    menu::{MenuIo, RealStdout, run_menu},
    modify::{
        LineSource, StdinLines, run_oidc, run_prune_hydra_system, run_prune_kratos_secrets,
        run_prune_webhook_token, run_restore, run_rotate_hydra_system, run_rotate_kratos_secrets,
        run_rotate_pairwise_salt, run_rotate_webhook_token, run_smtp,
    },
};
