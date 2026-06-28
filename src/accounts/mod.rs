//! Device-local "remembered accounts" chooser (Tier 1): a signed cookie of
//! identity UUIDs, with labels resolved server-side. One live session at a
//! time; switching is logout + fresh login.

pub(crate) mod cookie;
