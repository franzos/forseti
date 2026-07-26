//! `/admin/clients/*` HTTP handlers.
//!
//! Split by lifecycle: [`list`] (index), [`create`] (new picker + form +
//! create POST), [`show`] (detail + update POST), [`secret`] (rotate),
//! [`verify`] (verification toggle), [`logo`] (consent-screen logo),
//! [`delete`]. Each handler's template lives alongside it.

mod create;
mod delete;
mod list;
mod logo;
mod secret;
mod show;
mod verify;

pub(crate) use create::{create, new};
pub(crate) use delete::{delete, delete_confirm};
pub(crate) use list::list;
pub(crate) use logo::logo_upload;
pub(crate) use secret::{rotate, rotate_confirm};
pub(crate) use show::{show, update};
pub(crate) use verify::{unverify, unverify_confirm, verify};
