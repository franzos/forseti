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
    /// Delete audit-log rows older than [audit].audit_retention_days
    AuditPrune,
    /// Delete identities older than [identity].unverified_ttl_days that still have an unverified address
    UnverifiedPrune,
    /// Drop POSIX accounts, offline secrets and device sessions whose Kratos identity is gone
    PosixReconcile,
    /// Create the Hydra OAuth2 client the POSIX/PAM device flow logs in with
    PosixInitClient,
    /// Inspect and edit the Kratos, Hydra and Forseti config files
    Config(ConfigArgs),
    #[command(name = "config-check", hide = true)]
    ConfigCheckAlias(CheckArgs),
    #[command(name = "config-init", hide = true)]
    ConfigInitAlias(InitArgs),
}

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub cmd: Option<ConfigCmd>, // None => interactive menu when stdin is a TTY; else help + exit 2
    #[command(flatten)]
    pub paths: PathArgs,
}

#[derive(Args, Clone)]
pub struct PathArgs {
    /// Path to kratos.yml (defaults to infra/kratos/kratos.yml when it exists)
    #[arg(
        long = "kratos",
        alias = "kratos-config",
        env = "FORSETI_KRATOS_CONFIG",
        global = true
    )]
    pub kratos: Option<PathBuf>,
    /// Path to hydra.yml (defaults to infra/hydra/hydra.yml when it exists)
    #[arg(
        long = "hydra",
        alias = "hydra-config",
        env = "FORSETI_HYDRA_CONFIG",
        global = true
    )]
    pub hydra: Option<PathBuf>,
    /// Path to Forseti's config.toml (defaults to ./config.toml when it exists)
    #[arg(long = "forseti-config", env = "FORSETI_CONFIG_PATH", global = true)]
    pub forseti_config: Option<PathBuf>,
    /// Show what would change without writing any file
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// Answer confirmation prompts with yes (never satisfies the pairwise-salt gate)
    #[arg(long, global = true)]
    pub yes: bool,
    /// Write through a symlinked config file instead of refusing
    #[arg(long, global = true)]
    pub follow_symlink: bool,
}

#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Report the current state of every tracked setting across the config files
    Status {
        /// Emit the settings table as JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Lint the config files for misconfiguration, placeholders and weak secrets
    Check(CheckArgs),
    /// Generate a fresh kratos.yml and hydra.yml with CSPRNG secrets
    Init(InitArgs),
    /// Enable or disable a social sign-in provider
    Oidc {
        #[command(subcommand)]
        cmd: OidcCmd,
    },
    /// Roll a secret, keeping the old one accepted where the format allows it
    Rotate {
        #[command(subcommand)]
        cmd: RotateCmd,
    },
    /// Drop superseded secrets left behind by a rotation
    Prune {
        #[command(subcommand)]
        cmd: PruneCmd,
    },
    /// Restore config files from the backups written by earlier edits
    Restore {
        /// Restore the generation with this unix-seconds timestamp for every target
        #[arg(long)]
        from: Option<String>,
    },
    /// Configure the SMTP server Kratos sends mail through
    Smtp {
        #[command(subcommand)]
        cmd: SmtpCmd,
    },
}

#[derive(Args)]
pub struct CheckArgs {
    #[command(flatten)]
    pub paths: PathArgs,
    // Kept to preserve existing config-check behavior.
    /// Exit non-zero on warnings, not just failures
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args)]
pub struct InitArgs {
    /// Public base URL Forseti is served at; also the WebAuthn rp.id host
    #[arg(long)]
    pub forseti_url: Option<String>,
    /// Kratos public API base URL
    #[arg(long)]
    pub kratos_public_url: Option<String>,
    /// Kratos admin API base URL
    #[arg(long)]
    pub kratos_admin_url: Option<String>,
    /// Hydra public API base URL
    #[arg(long)]
    pub hydra_public_url: Option<String>,
    /// Hydra admin API base URL
    #[arg(long)]
    pub hydra_admin_url: Option<String>,
    /// Kratos database DSN
    #[arg(long)]
    pub kratos_db_dsn: Option<String>,
    /// Hydra database DSN
    #[arg(long)]
    pub hydra_db_dsn: Option<String>,
    /// SMTP connection URI Kratos sends mail through
    #[arg(long)]
    pub smtp_uri: Option<String>,
    /// From address on Kratos's outgoing mail
    #[arg(long)]
    pub smtp_from_address: Option<String>,
    /// From name on Kratos's outgoing mail
    #[arg(long)]
    pub smtp_from_name: Option<String>,
    /// Where to write the generated Kratos config
    #[arg(long, default_value = "kratos.yml")]
    pub kratos_out: String,
    /// Where to write the generated Hydra config
    #[arg(long, default_value = "hydra.yml")]
    pub hydra_out: String,
    /// Overwrite the output files if they already exist
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Args)]
pub struct SecretSourceArgs {
    // at most one; none => interactive prompt fallback, enforced post-parse
    /// Read the client secret from this environment variable
    #[arg(long, group = "secret_src")]
    pub client_secret_env: Option<String>,
    /// Read the client secret from this file
    #[arg(long, group = "secret_src")]
    pub client_secret_file: Option<PathBuf>,
    /// Read the client secret from stdin
    #[arg(long, group = "secret_src")]
    pub client_secret_stdin: bool,
}

/// Apple's `.p8` signing key. Apple has no client secret: Kratos mints one as
/// a JWT from this key, so it travels on its own flag group rather than
/// through `SecretSourceArgs`. No prompt fallback — a PEM doesn't survive a
/// masked single-line read, so one of these is required for `apple`.
#[derive(Clone, Args)]
pub struct AppleKeySourceArgs {
    // at most one; none => rejected post-parse for apple
    /// Read Apple's .p8 signing key from this environment variable
    #[arg(long, group = "apple_key_src")]
    pub apple_private_key_env: Option<String>,
    /// Read Apple's .p8 signing key from this file
    #[arg(long, group = "apple_key_src")]
    pub apple_private_key_file: Option<PathBuf>,
    /// Read Apple's .p8 signing key from stdin
    #[arg(long, group = "apple_key_src")]
    pub apple_private_key_stdin: bool,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once at startup; boxing costs clap's derive
pub enum OidcCmd {
    /// Add a social sign-in provider to kratos.yml and write its Jsonnet mapper
    Enable {
        /// Provider to enable: google, github, microsoft or apple
        provider: String, // validated post-parse: google|github|microsoft|apple
        /// OAuth2 client id issued by the provider (prompted for when omitted interactively)
        #[arg(long)]
        client_id: Option<String>, // Option so the menu can prompt; non-interactive requires it post-parse
        #[command(flatten)]
        secret: SecretSourceArgs,
        /// Specific Entra tenant id; required for microsoft (common/organizations are refused)
        #[arg(long)]
        microsoft_tenant: Option<String>, // required iff provider == microsoft, post-parse
        /// Apple developer team id; required for apple
        #[arg(long)]
        apple_team_id: Option<String>, // required iff provider == apple, post-parse
        /// Apple key id matching the .p8 signing key; required for apple
        #[arg(long)]
        apple_key_id: Option<String>, // required iff provider == apple, post-parse
        #[command(flatten)]
        apple_key: AppleKeySourceArgs,
        /// Keep an existing customised mapper instead of regenerating the pinned one
        #[arg(long)]
        keep_mapper: bool,
    },
    /// Remove a social sign-in provider from kratos.yml
    Disable {
        /// Provider id as it appears in kratos.yml
        id: String,
    },
}

#[derive(Subcommand)]
pub enum RotateCmd {
    /// Issue a new audit webhook token, staging it alongside the current one
    WebhookToken,
    /// Prepend a fresh Kratos cookie and/or cipher secret, keeping the old ones valid
    KratosSecrets {
        /// Rotate only the cookie secrets
        #[arg(long)]
        cookie: bool,
        /// Rotate only the cipher secrets
        #[arg(long)]
        cipher: bool,
    },
    /// Prepend a fresh Hydra system secret (Hydra needs a restart to pick it up)
    HydraSystem,
    /// Replace Hydra's pairwise salt; every pairwise sub ever issued changes
    PairwiseSalt {
        /// Required non-interactively; interactive mode asks for a typed confirmation instead
        #[arg(long = "i-understand-subs-change")]
        confirmed: bool,
    },
}

#[derive(Subcommand)]
pub enum PruneCmd {
    /// Drop every accepted audit webhook token except the one kratos.yml presents
    WebhookToken,
    /// Drop all but the newest Kratos cookie and/or cipher secret
    KratosSecrets {
        /// Prune only the cookie secrets
        #[arg(long)]
        cookie: bool,
        /// Prune only the cipher secrets
        #[arg(long)]
        cipher: bool,
    },
    /// Drop all but the newest Hydra system secret
    HydraSystem,
}

#[derive(Subcommand)]
pub enum SmtpCmd {
    /// Set the SMTP URI and/or from address and name in kratos.yml
    Set {
        /// Read the SMTP URI from this environment variable
        #[arg(long, group = "uri_src")]
        uri_env: Option<String>,
        /// Read the SMTP URI from this file
        #[arg(long, group = "uri_src")]
        uri_file: Option<PathBuf>,
        /// Read the SMTP URI from stdin
        #[arg(long, group = "uri_src")]
        uri_stdin: bool,
        /// From address on outgoing mail
        #[arg(long)]
        from_address: Option<String>,
        /// From name on outgoing mail
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
    fn apple_key_source_flags_are_mutually_exclusive() {
        let err = Cli::try_parse_from([
            "forseti",
            "config",
            "oidc",
            "enable",
            "apple",
            "--apple-private-key-file",
            "AuthKey.p8",
            "--apple-private-key-stdin",
        ]);
        assert!(err.is_err());
    }

    #[test]
    fn apple_enable_parses_the_full_flag_set() {
        let cli = Cli::try_parse_from([
            "forseti",
            "config",
            "oidc",
            "enable",
            "apple",
            "--client-id",
            "com.example.accounts.service",
            "--apple-team-id",
            "ABCDE12345",
            "--apple-key-id",
            "XYZ9876543",
            "--apple-private-key-file",
            "AuthKey.p8",
        ])
        .unwrap();
        let Some(Cmd::Config(c)) = cli.cmd else {
            panic!("wrong variant")
        };
        let Some(ConfigCmd::Oidc {
            cmd:
                OidcCmd::Enable {
                    apple_team_id,
                    apple_key_id,
                    apple_key,
                    ..
                },
        }) = c.cmd
        else {
            panic!("wrong variant")
        };
        assert_eq!(apple_team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(apple_key_id.as_deref(), Some("XYZ9876543"));
        assert_eq!(
            apple_key.apple_private_key_file.unwrap().to_str().unwrap(),
            "AuthKey.p8"
        );
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
