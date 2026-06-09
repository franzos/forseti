//! Curated "popular app" templates for the `/admin/clients/new` picker.
//!
//! A template layers on top of a [`Preset`]: it inherits the technical
//! defaults (grant/response types) from `base_preset.defaults()` and
//! overrides the app-specific bits — concrete redirect URIs (with the
//! literal `YOUR_DOMAIN` / `PROVIDER_NAME` placeholders the operator
//! find-replaces), scope, auth method, PKCE, and logout/webhook URLs.
//!
//! Templates are a form-seeding convenience only — the chosen app is NOT
//! persisted on the Hydra client. `metadata.forseti.client_type` still
//! carries the *base preset* slug (e.g. "web_app"), so the show-page badge
//! and list filter keep working unchanged.

use super::presets::Preset;

/// One curated app template. All fields are `&'static` — the table is a
/// compile-time constant.
#[derive(Clone)]
pub(super) struct AppTemplate {
    pub(super) slug: &'static str,
    pub(super) label: &'static str,
    /// Technical defaults inherited from this preset (response types, the
    /// stamped `client_type`). Grant types come from `grant_types` below.
    pub(super) base_preset: Preset,
    /// Default client name pre-filled into the form.
    pub(super) client_name: &'static str,
    /// Grant types for this app — overrides the base preset. Apps that don't
    /// use refresh tokens MUST omit `refresh_token` here (Hydra won't issue
    /// one without `offline_access` in scope, so a stray grant just misleads).
    pub(super) grant_types: &'static [&'static str],
    /// Concrete redirect URIs, newline-joined into the textarea value.
    pub(super) redirect_uris: &'static [&'static str],
    pub(super) post_logout_redirect_uris: &'static [&'static str],
    pub(super) backchannel_logout_uri: Option<&'static str>,
    /// Overrides the base preset scope.
    pub(super) scope: &'static str,
    pub(super) token_endpoint_auth_method: &'static str,
    pub(super) require_pkce: bool,
    /// Force the audience textarea visible (Hydra `audience` allow-list
    /// quirk — Stackpit/Formshive). Independent of the base preset.
    pub(super) audience_visible: bool,
    /// Pre-fill the account-deletion webhook URL (Formshive).
    pub(super) account_deletion_url: Option<&'static str>,
    /// Operator guidance banner on the *form* (PROVIDER_NAME, version notes).
    pub(super) note: Option<&'static str>,
    /// Specific caveat about OIDC logout fan-out for apps that DO support
    /// back-channel logout but need extra setup (opt-in toggle, placeholder).
    /// Apps with no `backchannel_logout_uri` get a generic "leave blank"
    /// note instead (see `logout_guidance`).
    pub(super) logout_note: Option<&'static str>,
    /// Required next step surfaced on the *reveal banner* after creation
    /// (e.g. "add this client's ID to the audience allow-list"). Travels in
    /// `SecretReveal::ClientCreated` so it lands where the operator does.
    pub(super) post_create_note: Option<&'static str>,
}

/// Shown on the form for any template that doesn't pre-fill a back-channel
/// logout URI — i.e. the app doesn't receive OIDC logout notifications.
const LOGOUT_UNSUPPORTED_NOTE: &str = "This app doesn't receive OIDC logout notifications, so you can usually leave the fields below blank - unless you've wired up a custom integration or the app added support after this template was written.";

impl AppTemplate {
    pub(super) fn from_slug(slug: &str) -> Option<&'static AppTemplate> {
        Self::ALL.iter().find(|t| t.slug == slug)
    }

    /// Redirect URIs joined for the form textarea (one per line).
    pub(super) fn redirect_uris_joined(&self) -> String {
        self.redirect_uris.join("\n")
    }

    pub(super) fn post_logout_joined(&self) -> String {
        self.post_logout_redirect_uris.join("\n")
    }

    /// Guidance line for the OIDC logout fan-out fieldset: a specific caveat
    /// if set, otherwise a generic "leave blank" note for apps with no
    /// back-channel URI, otherwise nothing (supported + pre-filled, no caveat).
    pub(super) fn logout_guidance(&self) -> Option<&'static str> {
        if let Some(n) = self.logout_note {
            Some(n)
        } else if self.backchannel_logout_uri.is_none() {
            Some(LOGOUT_UNSUPPORTED_NOTE)
        } else {
            None
        }
    }

    pub(super) const ALL: &'static [AppTemplate] = &[
        // --- Franz's apps ---
        AppTemplate {
            slug: "stackpit",
            label: "Stackpit",
            base_preset: Preset::WebApp,
            client_name: "Stackpit",
            grant_types: &["authorization_code", "refresh_token"],
            redirect_uris: &["https://YOUR_DOMAIN/web/auth/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: Some("https://YOUR_DOMAIN/web/auth/backchannel-logout"),
            scope: "openid email profile offline_access",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: true,
            account_deletion_url: None,
            note: Some("Add Stackpit's web audience (e.g. stackpit-web) to the audience allow-list below — it must match auth.oauth.web_audience."),
            logout_note: None,
            post_create_note: Some("Before logging in, add Stackpit's web audience to this client's audience allow-list (edit form below) — auth fails without it."),
        },
        AppTemplate {
            slug: "formshive",
            label: "Formshive",
            base_preset: Preset::WebApp,
            client_name: "Formshive",
            grant_types: &["authorization_code", "refresh_token"],
            redirect_uris: &["https://YOUR_DOMAIN/v1/auth/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: Some("https://YOUR_DOMAIN/v1/auth/oidc/backchannel-logout"),
            scope: "openid email profile offline_access",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: true,
            account_deletion_url: Some("https://YOUR_DOMAIN/v1/auth/oidc/account-deletion-webhook"),
            note: Some("Formshive sends audience=<client_id> on the auth request — add this client's ID to the audience allow-list after creation."),
            logout_note: None,
            post_create_note: Some("Required: add THIS client's ID (shown above) to its own audience allow-list (edit form below). Formshive sends audience=<client_id> and login fails until you do."),
        },
        AppTemplate {
            slug: "liwan",
            label: "Liwan",
            base_preset: Preset::WebApp,
            client_name: "Liwan",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/api/dashboard/auth/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            account_deletion_url: None,
            note: None,
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "gitlab",
            label: "GitLab",
            base_preset: Preset::WebApp,
            client_name: "GitLab",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/users/auth/openid_connect/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Add 'groups' to the scope if you map GitLab roles from a groups claim (requires the claim to be populated provider-side)."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "matrix",
            label: "Matrix Synapse",
            base_preset: Preset::WebApp,
            client_name: "Matrix Synapse",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/_synapse/client/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: Some("https://YOUR_DOMAIN/_synapse/client/oidc/backchannel_logout"),
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Synapse needs a user_mapping_provider with at least localpart_template; the back-channel URI only applies when backchannel_logout_enabled: true."),
            logout_note: Some("Back-channel logout is supported but opt-in: the URI below is pre-filled, but you must set backchannel_logout_enabled: true for the provider in Synapse. Front-channel logout isn't supported."),
            post_create_note: None,
        },
        // --- Clean fixed-path apps ---
        AppTemplate {
            slug: "nextcloud",
            label: "Nextcloud",
            base_preset: Preset::WebApp,
            client_name: "Nextcloud",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/apps/user_oidc/code"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: Some(
                "https://YOUR_DOMAIN/apps/user_oidc/backchannel-logout/PROVIDER_NAME",
            ),
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: true,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("For the user_oidc app (not oidc_login). Disable server-side encryption — it is incompatible with OIDC."),
            logout_note: Some("Back-channel logout is supported: the URI below is pre-filled — replace PROVIDER_NAME with your user_oidc provider identifier. Front-channel logout isn't supported."),
            post_create_note: None,
        },
        AppTemplate {
            slug: "grafana",
            label: "Grafana",
            base_preset: Preset::WebApp,
            client_name: "Grafana",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/login/generic_oauth"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Grafana requires an email claim. For refresh tokens, add 'offline_access' to the scope here AND add refresh_token to the grant types, then set use_refresh_token=true in Grafana."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "open_webui",
            label: "Open WebUI",
            base_preset: Preset::WebApp,
            client_name: "Open WebUI",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/oauth/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: Some("https://YOUR_DOMAIN/oauth/backchannel-logout"),
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Add 'groups' to the scope for OAuth role management — the groups claim must be populated provider-side (Kratos schema + Hydra mapping)."),
            logout_note: Some("Back-channel logout is supported: the URI below is pre-filled, but you must set ENABLE_OAUTH_BACKCHANNEL_LOGOUT=true in Open WebUI. Front-channel logout isn't supported."),
            post_create_note: None,
        },
        AppTemplate {
            slug: "outline",
            label: "Outline",
            base_preset: Preset::WebApp,
            client_name: "Outline",
            grant_types: &["authorization_code", "refresh_token"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/oidc.callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile offline_access",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Note the dot in /auth/oidc.callback. offline_access is required — Outline errors without refresh tokens."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "immich",
            label: "Immich",
            base_preset: Preset::WebApp,
            client_name: "Immich",
            grant_types: &["authorization_code"],
            // Custom-scheme mobile URIs (app.immich:///…) are rejected by
            // Hydra (HTTPS-only by default), so we ship Immich's built-in
            // HTTPS relay instead — the operator can add the custom scheme
            // manually if their Hydra allows it.
            redirect_uris: &[
                "https://YOUR_DOMAIN/auth/login",
                "https://YOUR_DOMAIN/user-settings",
                "https://YOUR_DOMAIN/api/oauth/mobile-redirect",
            ],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Three redirect URIs: web login, settings refresh, and the mobile relay. For native mobile via a custom scheme, Hydra must be configured to allow non-HTTPS redirects."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "mastodon",
            label: "Mastodon",
            base_preset: Preset::WebApp,
            client_name: "Mastodon",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/auth/openid_connect/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("The double auth/auth is intentional (Devise mount + strategy name)."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "argocd",
            label: "Argo CD",
            base_preset: Preset::WebApp,
            client_name: "Argo CD",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile groups",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("The 'groups' claim drives RBAC but must be populated provider-side (Kratos schema + Hydra mapping) — it isn't issued by default. The CLI needs a separate public client at http://localhost:8085/auth/callback."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "harbor",
            label: "Harbor",
            base_preset: Preset::WebApp,
            client_name: "Harbor",
            grant_types: &["authorization_code", "refresh_token"],
            redirect_uris: &["https://YOUR_DOMAIN/c/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile groups offline_access",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("offline_access is needed for the Docker/Helm CLI secret to keep working past ID-token expiry. The groups claim must be populated provider-side."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "miniflux",
            label: "Miniflux",
            base_preset: Preset::WebApp,
            client_name: "Miniflux",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/oauth2/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: None,
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "bookstack",
            label: "BookStack",
            base_preset: Preset::WebApp,
            client_name: "BookStack",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/oidc/callback"],
            post_logout_redirect_uris: &[
                "https://YOUR_DOMAIN",
                "https://YOUR_DOMAIN/login",
            ],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            account_deletion_url: None,
            note: None,
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "portainer",
            label: "Portainer",
            base_preset: Preset::WebApp,
            client_name: "Portainer",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile groups",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("The redirect is Portainer's web UI base URL (no trailing slash, no callback path) — it must match the Redirect URL field in Portainer's OAuth settings exactly. Portainer sends credentials in the request body (client_secret_post). 'groups' (team sync) needs a provider-side groups claim."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "proxmox",
            label: "Proxmox VE",
            base_preset: Preset::WebApp,
            client_name: "Proxmox VE",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN:8006"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email groups",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Redirect is the PVE web UI base (port 8006 by default; adjust if proxied on 443). Sources disagree on the trailing slash — if login fails with redirect_uri_mismatch, try adding one. 'groups' needs a provider-side groups claim for permission sync."),
            logout_note: None,
            post_create_note: None,
        },
        // --- PROVIDER_NAME placeholder apps ---
        AppTemplate {
            slug: "gitea",
            label: "Gitea",
            base_preset: Preset::WebApp,
            client_name: "Gitea",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/user/oauth2/PROVIDER_NAME/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with the authentication-source name you set in Gitea (Site Admin → Authentication Sources)."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "forgejo",
            label: "Forgejo",
            base_preset: Preset::WebApp,
            client_name: "Forgejo",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/user/oauth2/PROVIDER_NAME/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with the authentication-source name you set in Forgejo."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "paperless_ngx",
            label: "Paperless-ngx",
            base_preset: Preset::WebApp,
            client_name: "Paperless-ngx",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/accounts/oidc/PROVIDER_NAME/login/callback/"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with your provider_id. The trailing slash is required."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "vikunja",
            label: "Vikunja",
            base_preset: Preset::WebApp,
            client_name: "Vikunja",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/openid/PROVIDER_NAME"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with the (lowercased) provider key from auth.openid.providers in config.yml."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "jellyfin",
            label: "Jellyfin (SSO plugin)",
            base_preset: Preset::WebApp,
            client_name: "Jellyfin",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/sso/OID/redirect/PROVIDER_NAME"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email groups",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: true,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("Uses the third-party jellyfin-plugin-sso. Replace PROVIDER_NAME with the provider name set in the plugin (case-sensitive). The groups claim (for role mapping) must be populated provider-side."),
            logout_note: None,
            post_create_note: None,
        },
        AppTemplate {
            slug: "hedgedoc",
            label: "HedgeDoc (1.x)",
            base_preset: Preset::WebApp,
            client_name: "HedgeDoc",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/oauth2/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            account_deletion_url: None,
            note: Some("This is the HedgeDoc 1.x path. HedgeDoc 2.x uses /api/private/auth/oidc/<name>/callback instead."),
            logout_note: None,
            post_create_note: None,
        },
    ];
}

/// Picker card for the "Popular apps" group. `slug` links to
/// `?template=<slug>`; `note_short` is an optional one-liner under the label.
#[derive(Clone)]
pub(crate) struct AppCard {
    pub(crate) slug: &'static str,
    pub(crate) label: &'static str,
    /// First letter, upper-cased — drives the text-only tile (no logo assets).
    pub(crate) initial: char,
}

pub(crate) fn app_template_cards() -> Vec<AppCard> {
    AppTemplate::ALL
        .iter()
        .map(|t| AppCard {
            slug: t.slug,
            label: t.label,
            initial: t.label.chars().next().unwrap_or('?').to_ascii_uppercase(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::clients::presets::Preset;

    #[test]
    fn cards_cover_every_template_in_order() {
        let cards = app_template_cards();
        assert_eq!(cards.len(), AppTemplate::ALL.len());
        assert_eq!(cards[0].slug, AppTemplate::ALL[0].slug);
        assert_eq!(cards[0].label, AppTemplate::ALL[0].label);
    }

    #[test]
    fn slugs_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in AppTemplate::ALL {
            assert!(seen.insert(t.slug), "duplicate template slug: {}", t.slug);
        }
    }

    #[test]
    fn from_slug_roundtrips_every_entry() {
        for t in AppTemplate::ALL {
            let got = AppTemplate::from_slug(t.slug).expect("known slug resolves");
            assert_eq!(got.slug, t.slug);
        }
        assert!(AppTemplate::from_slug("does-not-exist").is_none());
    }

    #[test]
    fn every_template_has_label_and_redirects() {
        for t in AppTemplate::ALL {
            assert!(!t.label.is_empty(), "{} missing label", t.slug);
            assert!(
                !t.redirect_uris.is_empty(),
                "{} has no redirect URIs",
                t.slug
            );
            for uri in t.redirect_uris {
                assert!(
                    uri.contains("YOUR_DOMAIN") || uri.contains("://"),
                    "{} redirect URI looks malformed: {uri}",
                    t.slug
                );
            }
        }
    }

    #[test]
    fn scopes_start_with_openid() {
        for t in AppTemplate::ALL {
            assert!(
                t.scope.split_whitespace().next() == Some("openid"),
                "{} scope must start with openid: {:?}",
                t.slug,
                t.scope
            );
        }
    }

    #[test]
    fn base_preset_is_resolvable() {
        // Sanity: every base preset is a real Preset variant.
        for t in AppTemplate::ALL {
            let _ = t.base_preset; // type-checked; compile-time guarantee
            assert!(matches!(
                t.base_preset,
                Preset::WebApp | Preset::Native | Preset::Mcp | Preset::M2M | Preset::Custom
            ));
        }
    }

    #[test]
    fn refresh_token_grant_implies_offline_access_scope() {
        // Hydra won't issue a refresh token without offline_access in scope,
        // so a refresh_token grant on a template lacking it is misleading.
        for t in AppTemplate::ALL {
            if t.grant_types.contains(&"refresh_token") {
                assert!(
                    t.scope.split_whitespace().any(|s| s == "offline_access"),
                    "{} has refresh_token grant but no offline_access scope",
                    t.slug
                );
            }
        }
    }

    #[test]
    fn logout_guidance_matches_support() {
        // Supported + pre-filled, no caveat → no note.
        assert!(AppTemplate::from_slug("stackpit")
            .unwrap()
            .logout_guidance()
            .is_none());
        // Supported but needs setup → specific note.
        assert!(AppTemplate::from_slug("matrix")
            .unwrap()
            .logout_guidance()
            .unwrap()
            .contains("opt-in"));
        assert!(AppTemplate::from_slug("nextcloud")
            .unwrap()
            .backchannel_logout_uri
            .is_some());
        assert!(AppTemplate::from_slug("open_webui")
            .unwrap()
            .backchannel_logout_uri
            .is_some());
        // Unsupported → generic note.
        assert_eq!(
            AppTemplate::from_slug("mastodon")
                .unwrap()
                .logout_guidance(),
            Some(LOGOUT_UNSUPPORTED_NOTE)
        );
    }

    #[test]
    fn every_grant_set_starts_with_authorization_code() {
        for t in AppTemplate::ALL {
            assert!(
                t.grant_types.contains(&"authorization_code"),
                "{} missing authorization_code grant",
                t.slug
            );
        }
    }
}
