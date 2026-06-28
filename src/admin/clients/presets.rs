//! Application-type presets surfaced on the `/admin/clients/new` picker.
//!
//! Every preset still produces the same `OAuth2Client` — Hydra has no
//! notion of "MCP client". The slug travels as a hidden form input and
//! gets stamped into `metadata.forseti.client_type` so the show page,
//! list filter, and audit log can identify the operator's original
//! intent.

/// Picker card, one per preset on `/admin/clients/new`. Cards link to
/// `?type=<slug>`. `slug`/`label` come from [`Preset`]; only `blurb` is
/// card-specific.
#[derive(Clone)]
pub(super) struct ClientTypeCard {
    pub(super) slug: &'static str,
    pub(super) label: &'static str,
    pub(super) blurb: &'static str,
}

/// Cards for the `/admin/clients/new` picker, in [`Preset::ALL`] order.
/// `slug` and `label` are pulled from the enum so they can't drift; the
/// picker label intentionally reads differently from [`Preset::label`]
/// (longer, friendlier copy), so it stays card-side here.
pub(super) fn picker_cards() -> Vec<ClientTypeCard> {
    Preset::ALL
        .iter()
        .map(|&p| ClientTypeCard {
            slug: p.slug(),
            label: p.picker_label(),
            blurb: p.picker_blurb(),
        })
        .collect()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum Preset {
    WebApp,
    Native,
    Mcp,
    M2M,
    Custom,
}

impl Preset {
    /// Every variant, in picker / list-filter display order.
    pub(super) const ALL: [Preset; 5] = [
        Self::WebApp,
        Self::Native,
        Self::Mcp,
        Self::M2M,
        Self::Custom,
    ];

    /// Long-form label shown on the `/admin/clients/new` picker card.
    /// Distinct from [`Self::label`] — the picker copy is friendlier.
    pub(super) fn picker_label(self) -> &'static str {
        match self {
            Self::WebApp => "Web app",
            Self::Native => "Native, SPA, or mobile",
            Self::Mcp => "MCP server",
            Self::M2M => "Machine-to-machine",
            Self::Custom => "Custom",
        }
    }

    /// One-line description shown under the picker label.
    pub(super) fn picker_blurb(self) -> &'static str {
        match self {
            Self::WebApp => {
                "Server-rendered apps and BFFs. Authorization code + refresh, confidential secret."
            }
            Self::Native => {
                "Browsers, desktop, and mobile clients. Public + PKCE, no secret stored on the device."
            }
            Self::Mcp => {
                "Model Context Protocol resource servers (Claude Desktop, claude.ai, ChatGPT). Public + PKCE with an audience allow-list."
            }
            Self::M2M => "Backend services authenticating as themselves. Client credentials grant only.",
            Self::Custom => "Escape hatch — every field exposed, no opinions. For unusual combinations.",
        }
    }

    pub(super) fn from_slug(s: &str) -> Option<Self> {
        match s {
            "web_app" => Some(Self::WebApp),
            "native" => Some(Self::Native),
            "mcp" => Some(Self::Mcp),
            "m2m" => Some(Self::M2M),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    pub(super) fn slug(self) -> &'static str {
        match self {
            Self::WebApp => "web_app",
            Self::Native => "native",
            Self::Mcp => "mcp",
            Self::M2M => "m2m",
            Self::Custom => "custom",
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::WebApp => "Web app",
            Self::Native => "Native / SPA / mobile",
            Self::Mcp => "MCP server",
            Self::M2M => "Machine-to-machine",
            Self::Custom => "Custom",
        }
    }

    pub(super) fn defaults(self) -> PresetDefaults {
        match self {
            Self::WebApp => PresetDefaults {
                grant_types: &["authorization_code", "refresh_token"],
                response_types: "code",
                scope: "openid email profile offline_access",
                token_endpoint_auth_method: "client_secret_post",
                require_pkce: false,
                audience_visible: false,
                redirect_uri_hint: "https://app.example.com/auth/callback",
                backchannel_logout_uri_hint: "https://app.example.com/auth/backchannel-logout",
                frontchannel_logout_uri_hint: "https://app.example.com/auth/frontchannel-logout",
            },
            Self::Native => PresetDefaults {
                grant_types: &["authorization_code", "refresh_token"],
                response_types: "code",
                scope: "openid email profile offline_access",
                token_endpoint_auth_method: "none",
                require_pkce: true,
                audience_visible: false,
                redirect_uri_hint: "http://127.0.0.1:PORT/cb\nmyapp://callback",
                // Native / SPA clients usually can't receive back-channel
                // (server-to-server) logout POSTs and don't iframe-host
                // the front-channel URL — leave blank.
                backchannel_logout_uri_hint: "",
                frontchannel_logout_uri_hint: "",
            },
            Self::Mcp => PresetDefaults {
                grant_types: &["authorization_code", "refresh_token"],
                response_types: "code",
                scope: "openid email profile offline_access",
                token_endpoint_auth_method: "none",
                require_pkce: true,
                audience_visible: true,
                redirect_uri_hint:
                    "http://127.0.0.1:PORT/oauth/callback\nhttps://claude.ai/api/mcp/auth_callback",
                // MCP servers don't host an end-user session — logout
                // fan-out is not meaningful for them.
                backchannel_logout_uri_hint: "",
                frontchannel_logout_uri_hint: "",
            },
            Self::M2M => PresetDefaults {
                grant_types: &["client_credentials"],
                response_types: "token",
                // M2M has no user, no openid. Operator fills custom scopes.
                scope: "",
                token_endpoint_auth_method: "client_secret_post",
                require_pkce: false,
                audience_visible: false,
                redirect_uri_hint: "",
                // No end-user session — logout fan-out does not apply.
                backchannel_logout_uri_hint: "",
                frontchannel_logout_uri_hint: "",
            },
            Self::Custom => PresetDefaults {
                grant_types: &["authorization_code", "refresh_token"],
                response_types: "code",
                scope: "openid email profile offline_access",
                token_endpoint_auth_method: "client_secret_post",
                require_pkce: false,
                audience_visible: true,
                redirect_uri_hint: "",
                backchannel_logout_uri_hint: "",
                frontchannel_logout_uri_hint: "",
            },
        }
    }
}

pub(super) struct PresetDefaults {
    pub(super) grant_types: &'static [&'static str],
    pub(super) response_types: &'static str,
    pub(super) scope: &'static str,
    pub(super) token_endpoint_auth_method: &'static str,
    pub(super) require_pkce: bool,
    /// Whether the audience textarea is rendered on the form by default.
    /// All presets can still set it manually; this just controls initial
    /// visibility so the form isn't visually overwhelming for use cases
    /// (Web app, M2M) where audience is rarely needed.
    pub(super) audience_visible: bool,
    /// Newline-separated placeholder lines shown under the redirect-URI
    /// textarea. Empty for presets that don't need redirects (M2M) or
    /// can't suggest a meaningful default (Custom).
    pub(super) redirect_uri_hint: &'static str,
    /// Placeholder for the OIDC back-channel logout URI. Empty for
    /// presets where back-channel logout isn't typically used
    /// (Native, MCP, M2M, Custom) — the field still renders so an
    /// operator can fill it in on edit, but without a suggested value.
    pub(super) backchannel_logout_uri_hint: &'static str,
    /// Placeholder for the OIDC front-channel logout URI. Same
    /// rationale as [`Self::backchannel_logout_uri_hint`].
    pub(super) frontchannel_logout_uri_hint: &'static str,
}
