use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "forseti",
    version,
    about = "identity + OAuth2/OIDC frontend for Ory Kratos & Hydra"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    AuditPrune,
    UnverifiedPrune,
    PosixReconcile,
    PosixInitClient,
    Config(ConfigArgs),
    #[command(name = "config-check", hide = true)]
    ConfigCheckAlias(CheckArgs),
    #[command(name = "config-init", hide = true)]
    ConfigInitAlias(InitArgs),
}

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub cmd: Option<ConfigCmd>, // None => interactive menu (Task 11; until then: print help, exit 2)
    #[command(flatten)]
    pub paths: PathArgs,
}

#[derive(Args, Clone)]
pub struct PathArgs {
    #[arg(
        long = "kratos",
        alias = "kratos-config",
        env = "FORSETI_KRATOS_CONFIG",
        global = true
    )]
    pub kratos: Option<PathBuf>,
    #[arg(
        long = "hydra",
        alias = "hydra-config",
        env = "FORSETI_HYDRA_CONFIG",
        global = true
    )]
    pub hydra: Option<PathBuf>,
    #[arg(long = "forseti-config", env = "FORSETI_CONFIG_PATH", global = true)]
    pub forseti_config: Option<PathBuf>,
    #[arg(long, global = true)]
    pub dry_run: bool,
    #[arg(long, global = true)]
    pub yes: bool,
    #[arg(long, global = true)]
    pub follow_symlink: bool,
}

#[derive(Subcommand)]
pub enum ConfigCmd {
    Status {
        #[arg(long)]
        json: bool,
    },
    Check(CheckArgs),
    Init(InitArgs),
    Oidc {
        #[command(subcommand)]
        cmd: OidcCmd,
    },
    Rotate {
        #[command(subcommand)]
        cmd: RotateCmd,
    },
    Prune {
        #[command(subcommand)]
        cmd: PruneCmd,
    },
    Restore {
        #[arg(long)]
        from: Option<String>,
    },
    Smtp {
        #[command(subcommand)]
        cmd: SmtpCmd,
    },
}

#[derive(Args)]
pub struct CheckArgs {
    #[command(flatten)]
    pub paths: PathArgs,
    // Not in the Task 2 interface block; kept to preserve existing config-check behavior.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args)]
pub struct InitArgs {
    #[arg(long)]
    pub forseti_url: Option<String>,
    #[arg(long)]
    pub kratos_public_url: Option<String>,
    #[arg(long)]
    pub kratos_admin_url: Option<String>,
    #[arg(long)]
    pub hydra_public_url: Option<String>,
    #[arg(long)]
    pub hydra_admin_url: Option<String>,
    #[arg(long)]
    pub kratos_db_dsn: Option<String>,
    #[arg(long)]
    pub hydra_db_dsn: Option<String>,
    #[arg(long)]
    pub smtp_uri: Option<String>,
    #[arg(long)]
    pub smtp_from_address: Option<String>,
    #[arg(long)]
    pub smtp_from_name: Option<String>,
    #[arg(long, default_value = "kratos.yml")]
    pub kratos_out: String,
    #[arg(long, default_value = "hydra.yml")]
    pub hydra_out: String,
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Args)]
pub struct SecretSourceArgs {
    // at most one; none => interactive prompt fallback, enforced post-parse
    #[arg(long, group = "secret_src")]
    pub client_secret_env: Option<String>,
    #[arg(long, group = "secret_src")]
    pub client_secret_file: Option<PathBuf>,
    #[arg(long, group = "secret_src")]
    pub client_secret_stdin: bool,
}

#[derive(Subcommand)]
pub enum OidcCmd {
    Enable {
        provider: String, // validated post-parse: google|github|microsoft
        #[arg(long)]
        client_id: Option<String>, // Option so the menu can prompt; non-interactive requires it post-parse
        #[command(flatten)]
        secret: SecretSourceArgs,
        #[arg(long)]
        microsoft_tenant: Option<String>, // required iff provider == microsoft, post-parse
        #[arg(long)]
        keep_mapper: bool,
    },
    Disable {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum RotateCmd {
    WebhookToken,
    KratosSecrets {
        #[arg(long)]
        cookie: bool,
        #[arg(long)]
        cipher: bool,
    },
    HydraSystem,
    PairwiseSalt {
        #[arg(long = "i-understand-subs-change")]
        confirmed: bool,
    },
}

#[derive(Subcommand)]
pub enum PruneCmd {
    WebhookToken,
    KratosSecrets {
        #[arg(long)]
        cookie: bool,
        #[arg(long)]
        cipher: bool,
    },
    HydraSystem,
}

#[derive(Subcommand)]
pub enum SmtpCmd {
    Set {
        #[arg(long, group = "uri_src")]
        uri_env: Option<String>,
        #[arg(long, group = "uri_src")]
        uri_file: Option<PathBuf>,
        #[arg(long, group = "uri_src")]
        uri_stdin: bool,
        #[arg(long)]
        from_address: Option<String>,
        #[arg(long)]
        from_name: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn config_check_alias_accepts_documented_spellings() {
        let cli = Cli::try_parse_from([
            "forseti",
            "config-check",
            "--kratos",
            "k.yml",
            "--hydra",
            "h.yml",
        ])
        .unwrap();
        let Some(Cmd::ConfigCheckAlias(a)) = cli.cmd else {
            panic!("wrong variant")
        };
        assert_eq!(a.paths.kratos.unwrap().to_str().unwrap(), "k.yml");
    }

    #[test]
    fn kratos_config_alias_also_accepted() {
        Cli::try_parse_from(["forseti", "config", "check", "--kratos-config", "k.yml"]).unwrap();
    }

    #[test]
    fn secret_source_flags_are_mutually_exclusive() {
        let err = Cli::try_parse_from([
            "forseti",
            "config",
            "oidc",
            "enable",
            "github",
            "--client-secret-env",
            "A",
            "--client-secret-stdin",
        ]);
        assert!(err.is_err());
    }

    #[test]
    fn unknown_subcommand_errors() {
        assert!(Cli::try_parse_from(["forseti", "confi-check"]).is_err());
    }

    #[test]
    fn bare_invocation_parses_to_server() {
        assert!(Cli::try_parse_from(["forseti"]).unwrap().cmd.is_none());
    }

    #[test]
    fn smtp_uri_source_flags_are_mutually_exclusive() {
        let err = Cli::try_parse_from([
            "forseti",
            "config",
            "smtp",
            "set",
            "--uri-env",
            "A",
            "--uri-stdin",
        ]);
        assert!(err.is_err());
    }

    #[test]
    fn smtp_set_parses_with_no_uri_source() {
        let cli = Cli::try_parse_from(["forseti", "config", "smtp", "set", "--from-name", "Foo"])
            .unwrap();
        let Some(Cmd::Config(a)) = cli.cmd else {
            panic!("wrong variant")
        };
        let Some(ConfigCmd::Smtp {
            cmd: SmtpCmd::Set {
                uri_env, from_name, ..
            },
        }) = a.cmd
        else {
            panic!("wrong variant")
        };
        assert!(uri_env.is_none());
        assert_eq!(from_name.as_deref(), Some("Foo"));
    }

    #[test]
    fn restore_from_parses() {
        let cli = Cli::try_parse_from(["forseti", "config", "restore", "--from", "12345"]).unwrap();
        let Some(Cmd::Config(a)) = cli.cmd else {
            panic!("wrong variant")
        };
        let Some(ConfigCmd::Restore { from }) = a.cmd else {
            panic!("wrong variant")
        };
        assert_eq!(from.as_deref(), Some("12345"));
    }

    #[test]
    fn secret_source_may_be_omitted_for_interactive_prompt() {
        let cli = Cli::try_parse_from([
            "forseti",
            "config",
            "oidc",
            "enable",
            "github",
            "--client-id",
            "x",
        ])
        .unwrap();
        let Some(Cmd::Config(a)) = cli.cmd else {
            panic!("wrong variant")
        };
        let Some(ConfigCmd::Oidc {
            cmd: OidcCmd::Enable { secret, .. },
        }) = a.cmd
        else {
            panic!("wrong variant")
        };
        assert!(
            secret.client_secret_env.is_none()
                && secret.client_secret_file.is_none()
                && !secret.client_secret_stdin
        );
    }
}
