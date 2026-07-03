//! `POST /oauth2/register` — Forseti-fronted Dynamic Client Registration
//! proxy (RFC 7591).
//!
//! Why Forseti sits here: Hydra's own DCR endpoint is fully anonymous when
//! enabled (no token, allowlist, or CIDR). Claude Code refuses any AS that
//! doesn't advertise `registration_endpoint` in discovery, so DCR has to be
//! on, but exposing Hydra's `/oauth2/register` bare invites abuse. Forseti:
//!
//! 1. Advertises itself (not Hydra) as the `registration_endpoint`.
//! 2. Accepts anonymous registrations by default (Claude clients can't
//!    present an IAT). The safety mechanism is the verification badge:
//!    anonymous DCR clients land `unverified` and the consent screen shows a
//!    caution banner until an operator promotes them. A `Bearer` header is
//!    optional, but a malformed/invalid one is rejected with 401 rather than
//!    silently falling through, so attackers can't probe IATs without an
//!    audit trail.
//! 3. Strips `metadata.forseti.*` from the incoming body so a caller can't
//!    pre-seed trust-boundary fields on the Hydra client (see
//!    [`crate::oauth_client_metadata`]).
//! 4. Forwards the sanitised body to Hydra and returns its response. The
//!    `registration_access_token` is Hydra-validated, so follow-up RFC 7592
//!    calls bypass Forseti; this proxy only gates the initial registration.
//! 5. On success, INSERTs an `oauth_client_metadata` row (`source = "dcr"`,
//!    `verification = "unverified"`). An INSERT failure logs loudly and still
//!    returns success; the audit row captures the gap for reconciliation.
//!
//! IAT issuance + revocation lives in `src/admin/dcr_tokens.rs`.

mod handler;
mod iat;
pub(crate) mod reserved_names;

pub(crate) use handler::{rate_limit_error_response, register};
pub(crate) use iat::hash_token;
#[allow(unused_imports)]
pub use reserved_names::RESERVED_NAMES_DEFAULT;
