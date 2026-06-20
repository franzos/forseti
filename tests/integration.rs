//! Integration test entry point.
//!
//! These tests drive the running portal at <http://127.0.0.1:3000> against
//! the live playground stack (Kratos :4433/:4434, Hydra :4444/:4445,
//! Mailcrab :4436) via plain `reqwest` calls — no Playwright, no browser.
//!
//! Prerequisites — **start these in another terminal before running**:
//!
//! ```sh
//! podman-compose -f infra/docker-compose.yml up -d
//! make run     # or: cargo run --release   (portal at :3000)
//! ```
//!
//! Run:
//!
//! ```sh
//! cargo test --test integration -- --test-threads=1
//! ```
//!
//! `--test-threads=1` is REQUIRED. The tests share Kratos / Hydra / Mailcrab
//! state — running concurrently produces non-deterministic failures (email
//! inbox contention, recovery flow code mix-ups, …). Each test still creates
//! its own identity with a timestamp-prefixed email to avoid colliding with
//! identities left behind by previous runs.
//!
//! Modules are declared inline so cargo finds `tests/integration/<name>.rs`
//! files directly (rather than treating `tests/integration/mod.rs` as the
//! root, which would clash with `tests/integration.rs`).

#[path = "integration/common.rs"]
mod common;

#[path = "integration/aal2_enforcement.rs"]
mod aal2_enforcement;

#[path = "integration/account_delete.rs"]
mod account_delete;

#[path = "integration/admin.rs"]
mod admin;

#[path = "integration/bug_regressions.rs"]
mod bug_regressions;

#[path = "integration/dcr.rs"]
mod dcr;

#[path = "integration/login.rs"]
mod login;

#[path = "integration/logout.rs"]
mod logout;

#[path = "integration/oauth.rs"]
mod oauth;

#[path = "integration/recovery.rs"]
mod recovery;

#[path = "integration/regressions.rs"]
mod regressions;

#[path = "integration/registration.rs"]
mod registration;

#[path = "integration/saml.rs"]
mod saml;

#[path = "integration/settings.rs"]
mod settings;

#[path = "integration/verification.rs"]
mod verification;
