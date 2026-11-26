use clap::{Parser, Subcommand};

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
    /// Delete one identity: notify consented apps, remove its rows, clear references to it
    DeleteIdentity {
        /// Kratos identity id
        id: String,
        /// Skip the confirmation prompt (required when stdin is not a terminal)
        #[arg(long)]
        yes: bool,
        /// Delete even if the identity is the only owner of an organization with other members, or its OAuth sessions could not all be ended
        #[arg(long)]
        force: bool,
    },
    /// Drop POSIX accounts, offline secrets and device sessions whose Kratos identity is gone
    PosixReconcile,
    /// Create the Hydra OAuth2 client the POSIX/PAM device flow logs in with
    PosixInitClient,
    /// Retire the active OAuth signing key and generate a new one; retired keys stay published
    #[cfg(feature = "oauth-native")]
    RotateOauthKey,
    /// Stamp every Hydra client Forseti has no trust row for as operator-created.
    /// Run this ONCE before upgrading, while a missing row still reads as verified.
    ReconcileClientMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn unknown_subcommand_errors() {
        assert!(Cli::try_parse_from(["forseti", "confi-check"]).is_err());
    }

    #[test]
    fn rotate_oauth_key_exists_only_on_the_native_oauth_build() {
        let parsed = Cli::try_parse_from(["forseti", "rotate-oauth-key"]);
        assert_eq!(parsed.is_ok(), cfg!(feature = "oauth-native"));
    }

    #[test]
    fn bare_invocation_parses_to_server() {
        assert!(Cli::try_parse_from(["forseti"]).unwrap().cmd.is_none());
    }
}
