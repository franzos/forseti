//! `pam_forseti.so` — the Forseti device-auth PAM module.
//!
//! A thin, libc-only cdylib that PAM dlopens into `sshd`/`login`. It runs the
//! OAuth 2.0 Device Authorization Grant conversation by talking ONLY to the
//! local `forseti-unixd` daemon over its Unix socket (`PamRequest`/`PamResponse`);
//! it never sees OAuth tokens — the daemon returns `pending | success | denied`.
//!
//! Lockout-safety is paramount (this loads into pre-auth sshd):
//! - non-interactive callers (no tty) → `PAM_IGNORE`, never start a device flow.
//! - non-Forseti users → daemon says `Unknown` → `PAM_IGNORE` → falls to `pam_unix`.
//! - daemon unreachable (auth) → `PAM_AUTHINFO_UNAVAIL` → falls to the next module.
//! - daemon unreachable (account) → fail closed: local accounts get `PAM_IGNORE`
//!   (pam_unix handles them), NSS-only users get `PAM_AUTHINFO_UNAVAIL` so the
//!   control map's `authinfo_unavail=die` denies the login.
//! - the poll loop is wall-clock + attempt bounded (< sshd `LoginGraceTime`).
//! - the conversation always shows state and always has a cancel point.
//!
//! See `core.rs` for the testable poll-driver; this file is just the FFI glue.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]

pub mod core;
pub mod pam;

use std::ffi::CStr;
use std::time::{Duration, Instant};

use forseti_unix_proto::{PamRequest, PamResponse};

use crate::core::{
    decide_account_unreachable, has_local_shadow_entry, map_account_response, Conversation, Daemon,
};
use crate::pam::constants::{PamFlag, PamMessageStyle, PamResultCode};
use crate::pam::conv::PamConv;
use crate::pam::module::{PamHandle, PamHooks};

const DEFAULT_SOCKET: &str = "/run/forseti/unixd.sock";

/// Per-call socket timeout. Each request/response is a sub-ms local round-trip;
/// the long inter-poll wait happens in `core::run_device_auth`, never here. Kept
/// short so a wedged daemon can't pin the PAM stack.
const CALL_TIMEOUT: Duration = Duration::from_secs(3);

fn socket_path() -> String {
    std::env::var("FORSETI_UNIXD_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

/// Real conversation seam over a `PamConv`.
struct PamConvChannel<'a> {
    conv: &'a PamConv,
}

impl Conversation for PamConvChannel<'_> {
    fn send(&self, style: PamMessageStyle, msg: &str) -> Result<Option<String>, PamResultCode> {
        self.conv.send(style, msg)
    }
}

/// Real daemon seam over the blocking socket client (fail-soft `None`).
struct SocketDaemon {
    socket: String,
}

impl Daemon for SocketDaemon {
    fn query(&self, req: &PamRequest) -> Option<PamResponse> {
        forseti_unix_client::query_pam(&self.socket, req, CALL_TIMEOUT)
    }
}

pub struct PamForseti;

impl PamHooks for PamForseti {
    fn sm_authenticate(pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let username = match pamh.get_user() {
            Ok(u) => u,
            Err(e) => return e,
        };

        // No-tty fast-fail (R8): never start a device flow for a non-interactive
        // caller. Treat a missing tty AND a tty lookup error as "no tty".
        let tty = pamh.get_tty().unwrap_or(None);
        if !crate::core::has_usable_tty(tty.as_deref()) {
            return PamResultCode::PAM_IGNORE;
        }

        let conv = match pamh.get_conv() {
            Ok(c) => c,
            Err(e) => return e,
        };

        let channel = PamConvChannel { conv };
        let daemon = SocketDaemon {
            socket: socket_path(),
        };

        crate::core::run_device_auth(
            &channel,
            &daemon,
            &username,
            Instant::now,
            // Real sleep drives the poll cadence between AuthPoll round-trips.
            std::thread::sleep,
        )
    }

    fn acct_mgmt(pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let username = match pamh.get_user() {
            Ok(u) => u,
            Err(e) => return e,
        };

        let daemon = SocketDaemon {
            socket: socket_path(),
        };
        match daemon.query(&PamRequest::AccountAllowed {
            username: username.clone(),
        }) {
            Some(resp) => map_account_response(&resp),
            // Daemon unreachable: fail closed for NSS-only users, but let local
            // accounts through pam_unix so an outage can't lock out admins.
            None => decide_account_unreachable(&username, has_local_shadow_entry),
        }
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn sm_open_session(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // No-op: pam_mkhomedir handles home dir creation in the stack.
        PamResultCode::PAM_SUCCESS
    }

    fn sm_close_session(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn sm_chauthtok(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}

pam_hooks!(PamForseti);
