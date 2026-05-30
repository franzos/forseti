//! Shared projection of a Kratos [`ory::Session`] into the row shape
//! consumed by `templates/partials/session_meta.html`.
//!
//! Used by `/settings/sessions` (the user-facing list) and the
//! `/admin/identities/:id` detail page — both render the same
//! device-icon + multi-line metadata block. Keeping one struct + one
//! projection function ensures the two pages can't drift on
//! humanised-field rules.

use crate::format::{humanise_timestamp, humanise_user_agent};
use crate::ory;

/// Per-session view-model. `is_current` is `true` only for the row whose
/// cookie made the request — the partial reads it through a `show_current`
/// gate (false for admin views, true for the user's own sessions list).
pub(crate) struct SessionView {
    pub(crate) id: String,
    /// Raw UA string, kept as the source of truth for hover tooltips.
    pub(crate) user_agent: String,
    /// Humanised "Chrome on Linux" form. Empty when no UA was reported.
    pub(crate) user_agent_pretty: String,
    pub(crate) ip_address: String,
    pub(crate) location: String,
    pub(crate) authenticated_at: String,
    /// Relative form of `authenticated_at` ("8h ago"). Full timestamp on hover.
    pub(crate) authenticated_at_pretty: String,
    pub(crate) expires_at: String,
    /// Relative form of `expires_at` ("in 16h"). Full timestamp on hover.
    pub(crate) expires_at_pretty: String,
    pub(crate) is_current: bool,
}

impl SessionView {
    /// Project a Kratos session into the template row. `is_current` should
    /// be `true` only when this session corresponds to the request's own
    /// cookie (always `false` from admin views).
    pub(crate) fn from_kratos(s: &ory::Session, is_current: bool) -> Self {
        let device = s
            .devices
            .as_ref()
            .and_then(|d| d.first())
            .cloned()
            .unwrap_or_default();
        // Friendly placeholders for sessions Kratos returned without
        // device/timestamp info — rare in practice but the partial
        // renders "Signed in " with an empty pretty value, which looks
        // broken.
        let user_agent = device
            .user_agent
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Unknown device".to_string());
        let user_agent_pretty = humanise_user_agent(&user_agent);
        let authenticated_at = s
            .authenticated_at
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "—".to_string());
        let expires_at = s
            .expires_at
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "—".to_string());
        SessionView {
            id: s.id.clone(),
            user_agent,
            user_agent_pretty,
            ip_address: device.ip_address.unwrap_or_default(),
            location: device.location.unwrap_or_default(),
            authenticated_at_pretty: humanise_timestamp(&authenticated_at),
            authenticated_at,
            expires_at_pretty: humanise_timestamp(&expires_at),
            expires_at,
            is_current,
        }
    }
}
