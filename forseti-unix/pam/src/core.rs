//! Lockout-safety-critical PAM logic, factored away from the FFI so it can be
//! unit-tested without a live PAM stack.
//!
//! Two seams are abstracted: [`Conversation`] (the PAM prompt/info channel) and
//! [`Daemon`] (the `query_pam` socket round-trip). The real module wires them to
//! `PamConv` and `forseti_unix_client::query_pam`; tests wire them to mocks.

use std::time::{Duration, Instant};

use forseti_unix_proto::{PamRequest, PamResponse};

use crate::pam::constants::{
    PamMessageStyle, PamResultCode, PAM_ERROR_MSG, PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON,
    PAM_TEXT_INFO,
};

/// Offline passphrase attempts before giving up. The daemon-side lockout is the
/// real throttle; this only bounds the PAM-side conversation so a wedged tty
/// can't loop forever.
pub const MAX_OFFLINE_ATTEMPTS: u32 = 3;

/// Hard wall-clock ceiling on the approval poll loop. The loop never *starts* a
/// poll+sleep cycle once the remaining budget can't cover one, so total real
/// time stays below this bound and well under sshd's `LoginGraceTime` (default
/// 120s; R8) — an abandoned session can't pin a daemon device flow.
pub const MAX_POLL_WALL_CLOCK: Duration = Duration::from_secs(90);

/// Hard ceiling on poll iterations — a belt-and-braces bound paired with the
/// wall-clock cap in case a misbehaving conversation returns instantly.
pub const MAX_POLL_ATTEMPTS: u32 = 240;

/// The PAM conversation channel (prompts + info/error messages). Returns the
/// user's reply for prompt styles; `Ok(None)` for info/error or an empty reply.
/// `Err` carries the PAM code from a failed/aborted conversation (e.g. EOF).
pub trait Conversation {
    fn send(&self, style: PamMessageStyle, msg: &str) -> Result<Option<String>, PamResultCode>;
}

/// One device-auth socket round-trip. `None` ⇒ daemon unreachable / any error
/// (fail-soft), exactly the `query_pam` contract.
pub trait Daemon {
    fn query(&self, req: &PamRequest) -> Option<PamResponse>;
}

/// The device-code instruction line shown via `PAM_TEXT_INFO`.
pub fn device_code_message(verification_uri: &str, user_code: &str) -> String {
    format!("To log in: visit {verification_uri} and enter code {user_code}")
}

/// No-tty fast-fail decision (R8): a non-interactive caller (cron/script, no
/// tty) must never start a device flow. `true` ⇒ proceed; `false` ⇒ `PAM_IGNORE`.
///
/// An empty tty string is treated as absent (some stacks set "" rather than null).
pub fn has_usable_tty(tty: Option<&str>) -> bool {
    matches!(tty, Some(t) if !t.is_empty())
}

/// Map the daemon's account-check response to a PAM code (R5/R6).
///
/// - `Success`            → `PAM_SUCCESS`  (a known, allowed Forseti account)
/// - `Denied`             → `PAM_PERM_DENIED` (known but not permitted here)
/// - `Unknown` / other    → `PAM_IGNORE`   (daemon is up but this isn't a Forseti
///   account — fall through to `pam_unix`)
///
/// The daemon-unreachable (`None`) path is NOT handled here: it needs a local
/// shadow lookup to fail closed safely — see [`decide_account_unreachable`].
pub fn map_account_response(resp: &PamResponse) -> PamResultCode {
    match resp {
        PamResponse::Success => PamResultCode::PAM_SUCCESS,
        PamResponse::Denied { .. } => PamResultCode::PAM_PERM_DENIED,
        _ => PamResultCode::PAM_IGNORE,
    }
}

/// Decide the account-check result when the daemon is unreachable (fail-closed).
///
/// A daemon outage must not lock out genuine local admins (root et al.) yet must
/// not let an NSS-only Forseti account in unchecked. `is_local_user` classifies
/// the caller by inspecting `/etc/shadow` (see [`has_local_shadow_entry`]):
///
/// - local account (real shadow hash) → `PAM_IGNORE` so `pam_unix` handles them.
/// - NSS-only / unknown               → `PAM_AUTHINFO_UNAVAIL` so the control
///   map's `authinfo_unavail=die` fails the login closed.
pub fn decide_account_unreachable(username: &str, is_local_user: impl Fn(&str) -> bool) -> PamResultCode {
    if is_local_user(username) {
        PamResultCode::PAM_IGNORE
    } else {
        PamResultCode::PAM_AUTHINFO_UNAVAIL
    }
}

/// `true` if `username` has a real `/etc/shadow` entry with an actual password
/// hash (a genuine local account, not an NSS-only Forseti user).
///
/// Locked/placeholder fields (empty, or only `*`/`!`/`x`) are NOT real hashes.
/// Must run as root (the account phase does) for `getspnam` to see shadow.
pub fn has_local_shadow_entry(username: &str) -> bool {
    use std::ffi::{CStr, CString};

    let Ok(name) = CString::new(username) else {
        return false; // embedded NUL ⇒ treat as not-local ⇒ fail closed
    };

    // SAFETY: `name` outlives the call; `getspnam` returns a pointer to a static
    // buffer which we read immediately and never retain.
    let hash = unsafe {
        let spwd = libc::getspnam(name.as_ptr());
        if spwd.is_null() || (*spwd).sp_pwdp.is_null() {
            return false;
        }
        CStr::from_ptr((*spwd).sp_pwdp)
    };

    let pwd = hash.to_bytes();
    !pwd.is_empty() && pwd.iter().any(|&b| b != b'*' && b != b'!' && b != b'x')
}

/// Human-facing copy for a denial reason from the daemon.
fn denial_text(reason: &str) -> String {
    match reason {
        "mfa_required" => "Denied: this host requires 2FA (AAL2).".to_string(),
        "" => "Denied.".to_string(),
        other => format!("Denied: {other}"),
    }
}

/// Run `pam_sm_authenticate`'s device conversation + bounded poll-driver.
///
/// Lockout-safety invariants (all enforced here):
/// - no-tty → `PAM_IGNORE` (handled by the caller before this runs).
/// - daemon unreachable at any step → `PAM_AUTHINFO_UNAVAIL` (fall to next module).
/// - `Unknown` from `AuthBegin` → `PAM_IGNORE` (non-Forseti user, no delay).
/// - the loop is bounded by both wall-clock and attempt count regardless of user
///   input, and every `Pending` re-emits visible state + a prompt (the cancel point).
/// - EOF/Ctrl-C on the prompt (conversation `Err`) → treated as cancel → `PAM_AUTH_ERR`.
pub fn run_device_auth<C, D>(
    conv: &C,
    daemon: &D,
    username: &str,
    now: impl Fn() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> PamResultCode
where
    C: Conversation,
    D: Daemon,
{
    let begin = daemon.query(&PamRequest::AuthBegin {
        username: username.to_string(),
    });

    let (session_id, verification_uri, user_code, interval) = match begin {
        None => return PamResultCode::PAM_AUTHINFO_UNAVAIL,
        Some(PamResponse::Unknown) => return PamResultCode::PAM_IGNORE,
        // Server unreachable but the daemon holds a usable offline credential:
        // switch to the local passphrase conversation. NEVER reached for the
        // daemon-down (None) or non-Forseti (Unknown) cases above.
        Some(PamResponse::OfflineAvailable) => {
            return run_offline_auth(conv, daemon, username)
        }
        Some(PamResponse::ShowDeviceCode {
            session_id,
            verification_uri,
            user_code,
            interval,
            ..
        }) => (session_id, verification_uri, user_code, interval),
        Some(PamResponse::Denied { reason }) => {
            let _ = conv.send(PAM_ERROR_MSG, &denial_text(&reason));
            return PamResultCode::PAM_AUTH_ERR;
        }
        // Success/Pending are not valid first responses; treat as unavailable.
        Some(_) => return PamResultCode::PAM_AUTHINFO_UNAVAIL,
    };

    // Show the code, then a prompt that doubles as the SSH info-text flush and
    // the user's cancel point.
    if conv
        .send(PAM_TEXT_INFO, &device_code_message(&verification_uri, &user_code))
        .is_err()
    {
        return PamResultCode::PAM_AUTH_ERR;
    }

    let poll_interval = Duration::from_secs(u64::from(interval.max(1)));
    let started = now();
    let mut attempts: u32 = 0;

    loop {
        // Cancel point: EOF/Ctrl-C surfaces as Err here → abort.
        if conv
            .send(
                PAM_PROMPT_ECHO_ON,
                "Approve in your browser, then press Enter — or Ctrl-C to cancel: ",
            )
            .is_err()
        {
            return PamResultCode::PAM_AUTH_ERR;
        }

        attempts = attempts.saturating_add(1);

        match daemon.query(&PamRequest::AuthPoll {
            session_id: session_id.clone(),
        }) {
            Some(PamResponse::Success) => return PamResultCode::PAM_SUCCESS,
            Some(PamResponse::Denied { reason }) => {
                let _ = conv.send(PAM_ERROR_MSG, &denial_text(&reason));
                return PamResultCode::PAM_AUTH_ERR;
            }
            Some(PamResponse::Pending) => {
                // fall through to bound checks + re-prompt
            }
            // Unreachable (None) or any unexpected variant: fail-open to next module.
            _ => return PamResultCode::PAM_AUTHINFO_UNAVAIL,
        }

        // Don't start a poll+sleep cycle that could push past the hard ceiling.
        let remaining = MAX_POLL_WALL_CLOCK.saturating_sub(now().duration_since(started));
        if attempts >= MAX_POLL_ATTEMPTS || remaining <= poll_interval {
            let _ = conv.send(PAM_ERROR_MSG, "Timed out waiting for approval.");
            return PamResultCode::PAM_AUTH_ERR;
        }

        let _ = conv.send(PAM_TEXT_INFO, "Still waiting for approval…");
        sleep(poll_interval);
    }
}

/// Offline-passphrase conversation, entered only when `AuthBegin` returned
/// `OfflineAvailable` (daemon up, server unreachable, usable cred present).
///
/// Bounded by [`MAX_OFFLINE_ATTEMPTS`]; the daemon-side lockout is the real
/// throttle. Maps `OfflineSuccess` → `PAM_SUCCESS`, `OfflineDenied` → an error
/// message + `PAM_AUTH_ERR`, and a daemon that goes away mid-conversation
/// (`None`) → `PAM_AUTHINFO_UNAVAIL`. EOF/Ctrl-C on the prompt → `PAM_AUTH_ERR`.
pub fn run_offline_auth<C, D>(conv: &C, daemon: &D, username: &str) -> PamResultCode
where
    C: Conversation,
    D: Daemon,
{
    for _ in 0..MAX_OFFLINE_ATTEMPTS {
        let secret = match conv.send(PAM_PROMPT_ECHO_OFF, "Offline passphrase: ") {
            Ok(Some(s)) => s,
            // Empty reply: treat as a (doomed) attempt rather than aborting.
            Ok(None) => String::new(),
            // EOF/Ctrl-C → cancel.
            Err(_) => return PamResultCode::PAM_AUTH_ERR,
        };

        match daemon.query(&PamRequest::OfflineAuthStep {
            username: username.to_string(),
            secret,
        }) {
            Some(PamResponse::OfflineSuccess) => return PamResultCode::PAM_SUCCESS,
            Some(PamResponse::OfflineDenied { reason }) => {
                let _ = conv.send(PAM_ERROR_MSG, &offline_denial_text(&reason));
                // A locked-out user won't recover within this conversation; stop.
                if reason == "locked_out" {
                    return PamResultCode::PAM_AUTH_ERR;
                }
                // else: loop for another attempt (bounded above).
            }
            // Daemon vanished mid-conversation → fall to the next module.
            _ => return PamResultCode::PAM_AUTHINFO_UNAVAIL,
        }
    }
    PamResultCode::PAM_AUTH_ERR
}

/// Human-facing copy for an offline-denial reason from the daemon.
fn offline_denial_text(reason: &str) -> String {
    match reason {
        "locked_out" => "Too many attempts; the offline credential is locked.".to_string(),
        "bad_passphrase" => "Incorrect offline passphrase.".to_string(),
        "expired" | "max_lifetime" => {
            "The offline credential has expired; reconnect to log in.".to_string()
        }
        _ => "Offline passphrase rejected.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn tty_decision() {
        assert!(has_usable_tty(Some("pts/0")));
        assert!(!has_usable_tty(None));
        assert!(!has_usable_tty(Some("")));
    }

    #[test]
    fn device_code_string() {
        assert_eq!(
            device_code_message("https://idp/device", "WDJB-MJHT"),
            "To log in: visit https://idp/device and enter code WDJB-MJHT"
        );
    }

    #[test]
    fn account_mapping() {
        assert_eq!(
            map_account_response(&PamResponse::Success),
            PamResultCode::PAM_SUCCESS
        );
        assert_eq!(
            map_account_response(&PamResponse::Denied {
                reason: "x".into()
            }),
            PamResultCode::PAM_PERM_DENIED
        );
        assert_eq!(
            map_account_response(&PamResponse::Unknown),
            PamResultCode::PAM_IGNORE
        );
    }

    #[test]
    fn unreachable_local_user_ignored() {
        // Real /etc/shadow entry ⇒ let pam_unix handle them ⇒ outage doesn't lock out.
        assert_eq!(
            decide_account_unreachable("root", |_| true),
            PamResultCode::PAM_IGNORE
        );
    }

    #[test]
    fn unreachable_nss_only_fails_closed() {
        // No shadow entry ⇒ NSS-only Forseti user ⇒ authinfo_unavail=die.
        assert_eq!(
            decide_account_unreachable("alice", |_| false),
            PamResultCode::PAM_AUTHINFO_UNAVAIL
        );
    }

    #[test]
    fn mfa_denial_copy() {
        assert!(denial_text("mfa_required").contains("2FA"));
        assert_eq!(denial_text(""), "Denied.");
        assert_eq!(denial_text("account disabled"), "Denied: account disabled");
    }

    // --- poll-driver loop tests via mock seams ---

    struct MockConv {
        // Conversation returns Err once we reach this prompt count (simulates Ctrl-C/EOF).
        cancel_at_prompt: Option<usize>,
        prompts: RefCell<usize>,
    }
    impl MockConv {
        fn never_cancels() -> Self {
            Self {
                cancel_at_prompt: None,
                prompts: RefCell::new(0),
            }
        }
        fn cancel_at(n: usize) -> Self {
            Self {
                cancel_at_prompt: Some(n),
                prompts: RefCell::new(0),
            }
        }
    }
    impl Conversation for MockConv {
        fn send(&self, style: PamMessageStyle, _msg: &str) -> Result<Option<String>, PamResultCode> {
            if style == PAM_PROMPT_ECHO_ON {
                let mut p = self.prompts.borrow_mut();
                *p += 1;
                if Some(*p) == self.cancel_at_prompt {
                    return Err(PamResultCode::PAM_CONV_ERR);
                }
                Ok(Some(String::new()))
            } else {
                Ok(None)
            }
        }
    }

    struct MockDaemon {
        responses: RefCell<Vec<Option<PamResponse>>>,
    }
    impl MockDaemon {
        fn new(responses: Vec<Option<PamResponse>>) -> Self {
            Self {
                responses: RefCell::new(responses),
            }
        }
    }
    impl Daemon for MockDaemon {
        fn query(&self, _req: &PamRequest) -> Option<PamResponse> {
            let mut r = self.responses.borrow_mut();
            if r.is_empty() {
                None
            } else {
                r.remove(0)
            }
        }
    }

    fn show_code() -> PamResponse {
        PamResponse::ShowDeviceCode {
            session_id: "s1".into(),
            verification_uri: "https://idp/device".into(),
            user_code: "ABCD-1234".into(),
            interval: 1,
            expires_in: 600,
        }
    }

    #[test]
    fn unknown_user_is_ignored_no_flow() {
        let conv = MockConv::never_cancels();
        let daemon = MockDaemon::new(vec![Some(PamResponse::Unknown)]);
        let code = run_device_auth(&conv, &daemon, "bob", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_IGNORE);
    }

    #[test]
    fn unreachable_daemon_is_unavail() {
        let conv = MockConv::never_cancels();
        let daemon = MockDaemon::new(vec![None]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTHINFO_UNAVAIL);
    }

    #[test]
    fn pending_then_success() {
        let conv = MockConv::never_cancels();
        let daemon = MockDaemon::new(vec![
            Some(show_code()),
            Some(PamResponse::Pending),
            Some(PamResponse::Success),
        ]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_SUCCESS);
    }

    #[test]
    fn denied_maps_to_auth_err() {
        let conv = MockConv::never_cancels();
        let daemon = MockDaemon::new(vec![
            Some(show_code()),
            Some(PamResponse::Denied {
                reason: "mfa_required".into(),
            }),
        ]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTH_ERR);
    }

    #[test]
    fn cancel_on_prompt_aborts() {
        // First prompt (before the first poll) returns Err → cancel.
        let conv = MockConv::cancel_at(1);
        let daemon = MockDaemon::new(vec![Some(show_code()), Some(PamResponse::Pending)]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTH_ERR);
    }

    // --- offline-auth conversation tests ---

    /// Conversation that replies to the offline passphrase prompt with a queued
    /// secret (or `None` to simulate EOF/cancel on that prompt).
    struct OfflineConv {
        secrets: RefCell<Vec<Option<String>>>,
    }
    impl OfflineConv {
        fn new(secrets: Vec<Option<String>>) -> Self {
            Self {
                secrets: RefCell::new(secrets),
            }
        }
    }
    impl Conversation for OfflineConv {
        fn send(&self, style: PamMessageStyle, _msg: &str) -> Result<Option<String>, PamResultCode> {
            if style == PAM_PROMPT_ECHO_OFF {
                let mut s = self.secrets.borrow_mut();
                match if s.is_empty() { None } else { Some(s.remove(0)) } {
                    Some(Some(secret)) => Ok(Some(secret)),
                    // Queued None ⇒ simulate Ctrl-C/EOF on the prompt.
                    Some(None) => Err(PamResultCode::PAM_CONV_ERR),
                    None => Ok(Some(String::new())),
                }
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn offline_available_then_correct_passphrase_succeeds() {
        let conv = OfflineConv::new(vec![Some("correct horse battery".into())]);
        let daemon = MockDaemon::new(vec![
            Some(PamResponse::OfflineAvailable),
            Some(PamResponse::OfflineSuccess),
        ]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_SUCCESS);
    }

    #[test]
    fn offline_wrong_passphrase_denied_maps_to_auth_err() {
        // Daemon offers offline, then denies every (bounded) attempt.
        let conv = OfflineConv::new(vec![
            Some("nope1".into()),
            Some("nope2".into()),
            Some("nope3".into()),
        ]);
        let daemon = MockDaemon::new(vec![
            Some(PamResponse::OfflineAvailable),
            Some(PamResponse::OfflineDenied {
                reason: "bad_passphrase".into(),
            }),
            Some(PamResponse::OfflineDenied {
                reason: "bad_passphrase".into(),
            }),
            Some(PamResponse::OfflineDenied {
                reason: "bad_passphrase".into(),
            }),
        ]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTH_ERR);
    }

    #[test]
    fn offline_bad_passphrase_then_correct_succeeds() {
        // A bad_passphrase denial re-prompts within the attempt bound; the
        // second (correct) try succeeds.
        let conv = OfflineConv::new(vec![Some("nope".into()), Some("correct".into())]);
        let daemon = MockDaemon::new(vec![
            Some(PamResponse::OfflineAvailable),
            Some(PamResponse::OfflineDenied {
                reason: "bad_passphrase".into(),
            }),
            Some(PamResponse::OfflineSuccess),
        ]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_SUCCESS);
    }

    #[test]
    fn offline_denial_copy() {
        assert_eq!(offline_denial_text("bad_passphrase"), "Incorrect offline passphrase.");
        assert!(offline_denial_text("locked_out").contains("locked"));
        assert!(offline_denial_text("expired").contains("expired"));
    }

    #[test]
    fn offline_locked_out_stops_immediately() {
        let conv = OfflineConv::new(vec![Some("x".into())]);
        let daemon = MockDaemon::new(vec![
            Some(PamResponse::OfflineAvailable),
            Some(PamResponse::OfflineDenied {
                reason: "locked_out".into(),
            }),
        ]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTH_ERR);
    }

    #[test]
    fn offline_available_then_daemon_gone_is_unavail() {
        // OfflineAvailable, then the daemon vanishes on the OfflineAuthStep.
        let conv = OfflineConv::new(vec![Some("x".into())]);
        let daemon = MockDaemon::new(vec![Some(PamResponse::OfflineAvailable), None]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTHINFO_UNAVAIL);
    }

    #[test]
    fn daemon_down_at_begin_stays_fail_closed_no_offline() {
        // M4 invariant: a None at AuthBegin (daemon down) is PAM_AUTHINFO_UNAVAIL
        // and must NEVER attempt the offline conversation. The conv records no
        // passphrase prompt because run_offline_auth is never entered.
        let conv = OfflineConv::new(vec![Some("should-not-be-read".into())]);
        let daemon = MockDaemon::new(vec![None]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTHINFO_UNAVAIL);
        // The queued secret was never consumed → offline was not attempted.
        assert_eq!(conv.secrets.borrow().len(), 1);
    }

    #[test]
    fn offline_prompt_cancel_aborts() {
        // EOF/Ctrl-C on the passphrase prompt → PAM_AUTH_ERR, no daemon step.
        let conv = OfflineConv::new(vec![None]);
        let daemon = MockDaemon::new(vec![Some(PamResponse::OfflineAvailable)]);
        let code = run_device_auth(&conv, &daemon, "alice", Instant::now, |_| {});
        assert_eq!(code, PamResultCode::PAM_AUTH_ERR);
    }

    #[test]
    fn wall_clock_cap_bounds_the_loop() {
        // Daemon stays Pending forever; a virtual clock jumps past the cap. The
        // loop must terminate with PAM_AUTH_ERR rather than spin indefinitely.
        struct PendingDaemon {
            first: RefCell<Option<PamResponse>>,
        }
        impl Daemon for PendingDaemon {
            fn query(&self, _req: &PamRequest) -> Option<PamResponse> {
                if let Some(r) = self.first.borrow_mut().take() {
                    Some(r)
                } else {
                    Some(PamResponse::Pending)
                }
            }
        }
        let daemon = PendingDaemon {
            first: RefCell::new(Some(show_code())),
        };
        let conv = MockConv::never_cancels();

        let base = Instant::now();
        let elapsed = RefCell::new(Duration::ZERO);
        let now = || base + *elapsed.borrow();
        let sleep = |d: Duration| {
            *elapsed.borrow_mut() += d + Duration::from_secs(1);
        };
        let code = run_device_auth(&conv, &daemon, "alice", now, sleep);
        assert_eq!(code, PamResultCode::PAM_AUTH_ERR);
    }
}
