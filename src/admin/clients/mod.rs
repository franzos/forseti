//! `/admin/clients/*` — Hydra OAuth2 client CRUD.
//!
//! Hydra issues clients via its admin API. We use the typed SDK calls (the
//! Kratos `ui.nodes` deserialization bug doesn't affect Hydra responses).
//! Secrets are shown exactly once on creation / rotation; subsequent views
//! display only the metadata fields.
//!
//! Creation is wizard-style: `GET /admin/clients/new` first shows an
//! application-type picker (Web app / Native / MCP / M2M / Custom). Picking
//! a card lands the operator on the same single-page form, but with the
//! right grant types, scopes, and auth method already filled in for that
//! preset. The preset is stamped to `metadata.forseti.client_type` so the
//! show page and list filter can read it back.

mod form;
mod handlers;
mod presets;
mod projection;
mod scope;

pub(crate) use handlers::{
    create, delete, delete_confirm, list, new, rotate, rotate_confirm, show, unverify,
    unverify_confirm, update, verify,
};
