//! What the daemon parses out of Forseti's host-authed `/posix/v1/device/*`
//! responses.
//!
//! Unlike the rest of this crate these types cross a boundary the two sides
//! build separately: `forseti-unix` and `forseti` are different workspaces with
//! their own lockfiles, so nothing makes the server's `Serialize` and the
//! daemon's `Deserialize` agree. They already disagreed once — the server
//! never emitted `device_code`, and the daemon required it, which no test on
//! either side could see. Forseti takes a dev-dependency on this crate and
//! decodes its own live responses into these structs, so that gap fails a test
//! instead of a login.
//!
//! Deserialize-only and non-exhaustive on purpose: the daemon reads what it
//! needs and ignores the rest, so the server stays free to add fields.

use serde::Deserialize;

/// Success body of `POST /posix/v1/device/init`.
#[derive(Debug, Deserialize)]
pub struct InitResponse {
    /// RFC 8628 §3.2's field name, but Forseti's own opaque code — Hydra's is
    /// the confidential client's grant credential and never leaves the server.
    /// Only this value is redeemable at `device/poll`.
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u32,
    pub expires_in: u32,
}

/// Body of `POST /posix/v1/device/poll`. `status` is one of
/// `pending | approved | denied | expired`.
#[derive(Debug, Deserialize)]
pub struct PollResponse {
    pub status: String,
    /// Present on `pending`: the server owns the daemon's backoff.
    #[serde(default)]
    pub interval: Option<u32>,
    /// Coarse denial tag on `denied`; never a code or token.
    #[serde(default)]
    pub reason: Option<String>,
}
