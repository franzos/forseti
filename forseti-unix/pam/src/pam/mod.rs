//! Hand-vendored minimal PAM FFI (kanidm-style; no bindgen). Only the surface
//! the Forseti device-auth module needs: constants, the conversation channel,
//! the module handle/accessors, and the `pam_hooks!` entrypoint macro.

pub mod constants;
pub mod conv;
#[doc(hidden)]
pub mod macros;
pub mod module;
