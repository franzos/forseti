//! Account-deletion webhook fan-out — outbox saga + background worker.
//!
//! Rows are written `PENDING` *before* the destructive Kratos call. Once
//! Kratos confirms the identity is gone, they flip to `CONFIRMED` and a
//! background worker drains them with retry/backoff. The full state
//! machine lives in [`outbox`]; signing in [`signing`]; the worker loop
//! and reconciler scheduler in [`worker`]; the JWKS endpoint in [`jwks`];
//! the SSRF target-URL guard in [`validate`].
//!
//! Every payload is a compact-serialised RFC 8417 Security Event Token
//! (SET) signed EdDSA (RFC 8037, Ed25519) against the Forseti-owned key,
//! following the Google Cross-Account Protection / RISC convention so
//! integrators can reuse existing RISC handlers. See [`signing`] for the
//! claims shape.

mod jwks;
mod outbox;
mod signing;
mod validate;
mod worker;

/// RISC event-type URIs we emit. Follows
/// <https://schemas.openid.net/secevent/risc/event-type/> so integrators
/// already wired up to Google's Cross-Account Protection can reuse
/// receivers.
pub mod event_type {
    pub const ACCOUNT_PURGED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/account-purged";
}

pub use jwks::jwks_endpoint;
pub use outbox::{
    abort_event, confirm_event, dead_letter_count, discard_dead, enqueue_pending, find_by_id,
    list_dead, reconcile_pending, requeue_dead, WebhookTarget,
};
pub use signing::SigningKey;
pub use validate::validate_webhook_url;
pub use worker::{spawn_reconcile, spawn_worker, WorkerHandle};
