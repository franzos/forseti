//! sshd `AuthorizedKeysCommand` helper. Given a username (sshd passes `%u`), it
//! asks forseti-unixd for that user's keys and prints them one per line.
//!
//! ALWAYS exits 0 (fail-open): if the daemon is down, malformed, or the user has
//! no Forseti keys, it prints nothing and lets sshd fall through to other auth
//! methods. A non-zero exit would only make sshd log noise and risks blocking
//! other methods. Failures get a one-line stderr note (stderr doesn't affect
//! AuthorizedKeysCommand parsing).
//!
//! ## sshd wiring
//!
//! ```text
//! AuthorizedKeysCommand /path/to/forseti_ssh_authorizedkeys %u
//! AuthorizedKeysCommandUser forseti
//! ```
//!
//! Requirements:
//! - sshd refuses to run the command unless it AND every parent directory is
//!   root-owned and not group/world-writable. A `/gnu/store/...` path satisfies
//!   this on Guix.
//! - `AuthorizedKeysCommandUser` must be a real, low-privilege account.
//! - The user must already resolve via NSS for sshd to accept the keys.
//!
//! Fail-open means: Forseti keys are simply unavailable when the daemon is down;
//! other auth methods still apply.

use forseti_unix_proto::{ClientRequest, ClientResponse};
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/run/forseti/unixd.sock";
const TIMEOUT: Duration = Duration::from_secs(2);

fn main() {
    let username = match std::env::args().nth(1) {
        Some(u) if !u.is_empty() => u,
        _ => {
            eprintln!("forseti_ssh_authorizedkeys: usage: forseti_ssh_authorizedkeys <username>");
            return; // exit 0 — nothing to print
        }
    };

    let socket =
        std::env::var("FORSETI_UNIXD_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());

    let req = ClientRequest::SshKeys(username);
    match forseti_unix_client::query(&socket, &req, TIMEOUT) {
        Some(ClientResponse::SshKeys(keys)) => {
            // print() not eprintln so each key lands on stdout for sshd.
            let mut out = String::new();
            for key in keys {
                out.push_str(&key);
                out.push('\n');
            }
            print!("{out}");
        }
        Some(_other) => {
            eprintln!("forseti_ssh_authorizedkeys: unexpected response from daemon; no keys");
        }
        None => {
            eprintln!("forseti_ssh_authorizedkeys: daemon unavailable; no keys (fail-open)");
        }
    }
    // implicit exit 0
}
