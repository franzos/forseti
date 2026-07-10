//! `config-check` / `config-init` operator subcommands. Kratos's API exposes
//! no live settings (only a version + opaque hash), so these lint/generate the
//! config FILES directly.

mod catalog;
mod check;
mod init;
mod io;
mod yamlutil;

pub(crate) use check::check;
pub(crate) use check::redact_uri;
pub(crate) use check::status;
pub(crate) use init::init;
