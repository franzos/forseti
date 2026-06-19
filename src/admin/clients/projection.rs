//! Hydra wire → Forseti view-model projection for OAuth2 clients.

use crate::format::humanise_timestamp;
use crate::oauth_client_metadata;
use crate::ory;

use super::presets::Preset;

/// Compact list-row projection of a Hydra client. Templates iterate over
/// these rather than the full SDK model to keep the column set predictable.
pub(super) struct ClientRow {
    pub id: String,
    pub name: String,
    pub grant_types: String,
    pub redirect_uris: String,
    /// Raw ISO timestamp preserved for `title=` hover.
    pub created_at: String,
    pub created_at_pretty: String,
    /// Preset slug from `metadata.forseti.client_type`; empty for clients
    /// created before the picker shipped.
    pub client_type: String,
    /// Human label for the preset ("MCP server" etc.), or empty.
    pub client_type_label: String,
    /// True when the Forseti row's `source == "dcr"`. Surfaced as a
    /// separate badge from the preset one — a self-registered client
    /// may also carry a preset slug, but the provenance is the more
    /// important signal for operators.
    pub self_registered: bool,
    /// True when the Forseti row's `verification == "verified"`, or when
    /// no Forseti row exists for this client (legacy clients created
    /// before `oauth_client_metadata` shipped are implicitly trusted —
    /// they came in through the admin UI, which is the act of vouching).
    pub verified: bool,
    /// Admin email / sub recorded at the time of verification. Empty when
    /// the client is unverified (or was never explicitly verified).
    pub verified_by: String,
    /// RFC 3339 timestamp of the verification. Empty when unset.
    pub verified_at: String,
    /// App-template logo filename (cosmetic), resolved from the stamped
    /// `template_slug`. None → no logo tile on the row.
    pub logo: Option<&'static str>,
    /// Light-theme logo variant; None falls back to `logo`.
    pub logo_dark: Option<&'static str>,
}

/// Read `metadata.forseti.client_type` off a Hydra client. Returns the raw
/// slug ("mcp" etc.) or empty if not stamped. Clients created before this
/// feature shipped won't have it.
pub(super) fn read_client_type(c: &ory::OAuth2Client) -> String {
    c.metadata
        .as_ref()
        .and_then(|m| m.get("forseti"))
        .and_then(|p| p.get("client_type"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Read `metadata.forseti.require_pkce` as a bool. Defaults to false.
pub(super) fn read_require_pkce(c: &ory::OAuth2Client) -> bool {
    c.metadata
        .as_ref()
        .and_then(|m| m.get("forseti"))
        .and_then(|p| p.get("require_pkce"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Project a Hydra client into a `ClientRow`, merging in the matching
/// Forseti-side metadata row when present. A missing Forseti row produces
/// the legacy defaults (`verified = true`, `self_registered = false`).
pub(super) fn project_row(
    c: &ory::OAuth2Client,
    meta: Option<&oauth_client_metadata::Row>,
) -> ClientRow {
    let created_at = c.created_at.clone().unwrap_or_default();
    let client_type = read_client_type(c);
    let client_type_label = Preset::from_slug(&client_type)
        .map(|p| p.label().to_string())
        .unwrap_or_default();
    let (self_registered, verified, verified_by, verified_at) = match meta {
        Some(m) => (
            m.is_self_registered(),
            m.is_verified(),
            m.verified_by.clone().unwrap_or_default(),
            m.verified_at.clone().unwrap_or_default(),
        ),
        // Legacy default: no Forseti row → treat as verified, not
        // self-registered. See the module doc on
        // `oauth_client_metadata` for the rationale.
        None => (false, true, String::new(), String::new()),
    };
    let (logo, logo_dark) = meta
        .and_then(|m| m.template_slug.as_deref())
        .and_then(crate::admin::clients::app_templates::AppTemplate::from_slug)
        .map(|t| (t.logo, t.logo_dark))
        .unwrap_or((None, None));
    ClientRow {
        id: c.client_id.clone().unwrap_or_default(),
        name: c.client_name.clone().unwrap_or_default(),
        grant_types: c.grant_types.clone().unwrap_or_default().join(", "),
        redirect_uris: c.redirect_uris.clone().unwrap_or_default().join(", "),
        created_at_pretty: humanise_timestamp(&created_at),
        created_at,
        client_type,
        client_type_label,
        self_registered,
        verified,
        verified_by,
        verified_at,
        logo,
        logo_dark,
    }
}
