//! `POST /oauth2/register` — Forseti-fronted Dynamic Client Registration
//! proxy (RFC 7591).
//!
//! Why Forseti sits here: Hydra's own DCR endpoint is fully anonymous
//! when `enabled: true`. There is no Hydra-side gate (no token, no
//! allowlist, no CIDR) — verified against Hydra v26.2.0
//! `client/handler.go`. Claude Code refuses any authorization server that
//! doesn't advertise `registration_endpoint` in its discovery document
//! (anthropics/claude-code#38102), even when a `client_id` is
//! pre-configured. So DCR has to be on — but exposing Hydra's
//! `/oauth2/register` bare in production is an open invitation for
//! abuse.
//!
//! Forseti therefore:
//!
//! 1. Advertises itself (rather than Hydra) as the `registration_endpoint`
//!    in `infra/hydra/hydra.yml`'s `client_registration_url`.
//! 2. **Accepts anonymous registrations by default.** Claude Code /
//!    Desktop / claude.ai do DCR without any way to present an Initial
//!    Access Token, so requiring one would lock them out entirely. The
//!    safety mechanism is the verification badge — anonymous DCR clients
//!    always land as `unverified` and the consent screen renders a
//!    caution banner until an operator reviews and promotes them via
//!    `/admin/clients/{id}/verify`. An `Authorization: Bearer <token>`
//!    header is **optional**: when present and valid, the registration
//!    is bound to that IAT (uses_remaining + daily counter enforced,
//!    audit row keyed off the IAT actor); when absent, the registration
//!    proceeds anonymously (audit actor = `system`). A malformed or
//!    invalid `Authorization` header is rejected with 401 — we never
//!    silently fall through to anonymous, because that would let an
//!    attacker probe IATs without leaving a `dcr_rejected` audit row.
//! 3. **Strips any `metadata.forseti.*` keys from the incoming body** —
//!    a malicious caller must not be able to pre-seed trust-boundary
//!    fields (`verification`, `source`, `dcr_iat_id`, etc.) on the
//!    Hydra client. Provenance + verification state live in the
//!    Forseti-owned `oauth_client_metadata` table; see
//!    [`crate::oauth_client_metadata`] for why.
//! 4. Forwards the (sanitised) body to Hydra's `POST /oauth2/register`
//!    and returns Hydra's response untouched. The
//!    `registration_access_token` Hydra issues is Hydra-validated, so
//!    follow-up `GET/PUT/DELETE /oauth2/register/{id}` calls bypass the
//!    Forseti — clients hit Hydra directly. This proxy only gates the
//!    *initial* registration.
//! 5. On Hydra success, INSERTs a row into `oauth_client_metadata`
//!    with `source = "dcr"`, `verification = "unverified"`, and the
//!    IAT id (or NULL for anonymous) + registration timestamp. If that
//!    INSERT fails (Hydra already committed), we log loudly and still
//!    return success — the audit row captures the gap so an operator
//!    can reconcile.
//!
//! IAT issuance + revocation lives in `src/admin/dcr_tokens.rs`.

mod handler;
mod iat;
mod reserved_names;

pub(crate) use handler::{rate_limit_error_response, register};
pub(crate) use iat::hash_token;
#[allow(unused_imports)]
pub use reserved_names::RESERVED_NAMES_DEFAULT;
