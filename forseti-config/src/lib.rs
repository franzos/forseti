//! `forseti-config`: lint, generate and edit the Kratos, Hydra and Forseti
//! config files. Kratos's API exposes no live settings (only a version +
//! opaque hash), so this works on the config FILES directly.

mod catalog;
mod check;
mod cli;
mod init;
mod io;
mod menu;
mod modify;
mod yamlutil;

pub use yamlutil::{parse_yaml, to_yaml, yaml_scalar};

use cli::{Cli, ConfigCmd, PruneCmd, RotateCmd};

/// Claims Forseti and Hydra put in ID tokens, advertised through Hydra's
/// `webfinger.oidc_discovery.supported_claims`.
pub(crate) const SUPPORTED_CLAIMS: [&str; 26] = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "picture",
    "website",
    "preferred_username",
    "locale",
    "updated_at",
    "org",
    "orgs",
    "groups",
    "bio",
    "pronouns",
    "links",
];

/// Parse the command line and run it; returns the process exit code. Bare
/// `forseti-config` drops into the interactive menu when stdin is a TTY;
/// otherwise it prints the help and returns 2.
pub async fn run() -> i32 {
    use clap::{CommandFactory as _, Parser as _};
    use std::io::{IsTerminal as _, Write as _};

    let Cli { cmd, paths } = Cli::parse();
    match cmd {
        Some(ConfigCmd::Check(args)) => check::check(&args),
        Some(ConfigCmd::Init(args)) => init::init(&args),
        Some(ConfigCmd::Status { json }) => check::status(&paths, json),
        Some(ConfigCmd::Oidc { cmd }) => modify::run_oidc(cmd, &paths).await,
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::WebhookToken,
        }) => modify::run_rotate_webhook_token(&paths),
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::KratosSecrets { cookie, cipher },
        }) => modify::run_rotate_kratos_secrets(&paths, cookie, cipher),
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::HydraSystem,
        }) => modify::run_rotate_hydra_system(&paths),
        Some(ConfigCmd::Rotate {
            cmd: RotateCmd::PairwiseSalt { confirmed },
        }) => modify::run_rotate_pairwise_salt(&paths, confirmed).await,
        Some(ConfigCmd::Prune {
            cmd: PruneCmd::WebhookToken,
        }) => modify::run_prune_webhook_token(&paths),
        Some(ConfigCmd::Prune {
            cmd: PruneCmd::KratosSecrets { cookie, cipher },
        }) => modify::run_prune_kratos_secrets(&paths, cookie, cipher),
        Some(ConfigCmd::Prune {
            cmd: PruneCmd::HydraSystem,
        }) => modify::run_prune_hydra_system(&paths),
        Some(ConfigCmd::Restore { from }) => modify::run_restore(&paths, from),
        Some(ConfigCmd::Smtp { cmd }) => modify::run_smtp(cmd, &paths),
        None if std::io::stdin().is_terminal() => {
            use std::cell::RefCell;
            use std::rc::Rc;
            let input: Rc<RefCell<dyn modify::LineSource>> =
                Rc::new(RefCell::new(modify::StdinLines));
            let output: Rc<RefCell<dyn std::io::Write>> = Rc::new(RefCell::new(menu::RealStdout));
            let mut io = menu::MenuIo::new(input, output, true);
            menu::run_menu(&mut io, &paths)
        }
        None => {
            let _ = writeln!(std::io::stderr(), "{}", Cli::command().render_help());
            2
        }
    }
}

/// Repo-root file for tests; cargo runs them from this crate's directory.
#[cfg(test)]
pub(crate) fn repo_file(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(rel)
}
