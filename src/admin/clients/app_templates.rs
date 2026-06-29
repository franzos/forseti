//! Curated "popular app" templates for the `/admin/clients/new` picker.
//!
//! A template layers on top of a [`Preset`]: it inherits the technical
//! defaults from `base_preset.defaults()` and overrides app-specific bits
//! (redirect URIs with `YOUR_DOMAIN` / `PROVIDER_NAME` placeholders, scope,
//! auth method, PKCE, logout/webhook URLs).
//!
//! Templates are form-seeding only; the chosen app is NOT persisted on the
//! Hydra client. `metadata.forseti.client_type` carries the base preset slug
//! so the show-page badge and list filter keep working.
//!
//! The template slug IS persisted Forseti-side in
//! `oauth_client_metadata.template_slug`, purely cosmetically (drives the app
//! logo). It is NOT trust state; nothing reads it for an authorization decision.

use super::presets::Preset;

/// One curated app template. All fields are `&'static`.
#[derive(Clone)]
pub(super) struct AppTemplate {
    pub(super) slug: &'static str,
    pub(super) label: &'static str,
    /// Technical defaults inherited from this preset (grant types come from
    /// `grant_types` below).
    pub(super) base_preset: Preset,
    pub(super) client_name: &'static str,
    /// Apps that don't use refresh tokens MUST omit `refresh_token` here:
    /// Hydra won't issue one without `offline_access` in scope, so a stray
    /// grant just misleads.
    pub(super) grant_types: &'static [&'static str],
    pub(super) redirect_uris: &'static [&'static str],
    pub(super) post_logout_redirect_uris: &'static [&'static str],
    pub(super) backchannel_logout_uri: Option<&'static str>,
    pub(super) scope: &'static str,
    pub(super) token_endpoint_auth_method: &'static str,
    pub(super) require_pkce: bool,
    /// Force the audience textarea visible (Hydra `audience` allow-list quirk).
    pub(super) audience_visible: bool,
    /// After creation, add the client's own client_id to its audience
    /// allow-list (rusty-common `audience=client_id` pattern). The id is
    /// Hydra-generated, so this happens via a follow-up update.
    pub(super) self_audience: bool,
    pub(super) account_deletion_url: Option<&'static str>,
    /// Operator guidance banner on the form (PROVIDER_NAME, version notes).
    pub(super) note: Option<&'static str>,
    /// Caveat for apps that support back-channel logout but need extra setup.
    /// Apps with no `backchannel_logout_uri` get a generic note (see
    /// `logout_guidance`).
    pub(super) logout_note: Option<&'static str>,
    /// Required next step surfaced on the reveal banner after creation. Travels
    /// in `SecretReveal::ClientCreated`.
    pub(super) post_create_note: Option<&'static str>,
    /// Logo filename in static/logos/. None falls back to a letter tile.
    pub(super) logo: Option<&'static str>,
    /// Light variant for the dark theme; None uses `logo` in both themes.
    pub(super) logo_dark: Option<&'static str>,
}

/// Shown on the form for any template that doesn't pre-fill a back-channel
/// logout URI — i.e. the app doesn't receive OIDC logout notifications.
const LOGOUT_UNSUPPORTED_NOTE: &str = "This app doesn't receive OIDC logout notifications, so you can usually leave the fields below blank - unless you've wired up a custom integration or the app added support after this template was written.";

impl AppTemplate {
    pub(super) fn from_slug(slug: &str) -> Option<&'static AppTemplate> {
        Self::ALL.iter().find(|t| t.slug == slug)
    }

    pub(super) fn redirect_uris_joined(&self) -> String {
        self.redirect_uris.join("\n")
    }

    pub(super) fn post_logout_joined(&self) -> String {
        self.post_logout_redirect_uris.join("\n")
    }

    /// OIDC logout fan-out guidance: specific caveat if set, else a generic
    /// note for apps with no back-channel URI, else nothing.
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Add Stackpit's web audience (e.g. stackpit-web) to the audience allow-list below — it must match auth.oauth.web_audience."),
            logout_note: None,
            post_create_note: Some("Before logging in, add Stackpit's web audience to this client's audience allow-list (edit form below) — auth fails without it."),
            logo: Some("stackpit.svg"),
            logo_dark: None,
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
            self_audience: true,
            account_deletion_url: Some("https://YOUR_DOMAIN/v1/auth/oidc/account-deletion-webhook"),
            note: Some("Formshive sends audience=<client_id> on the auth request — Forseti adds this client's ID to the audience allow-list automatically on creation."),
            logout_note: None,
            post_create_note: Some("Fallback only: if creation couldn't set it, add THIS client's ID (shown above) to its own audience allow-list (edit form below) — Formshive sends audience=<client_id> and login fails without it."),
            logo: Some("formshive.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: None,
            logout_note: None,
            post_create_note: None,
            logo: Some("liwan.svg"),
            logo_dark: Some("liwan-light.svg"),
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Add 'groups' to the scope if you map GitLab roles from a groups claim. Forseti populates it from the user's active-org teams."),
            logout_note: None,
            post_create_note: None,
            logo: Some("gitlab.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Synapse needs a user_mapping_provider with at least localpart_template; the back-channel URI only applies when backchannel_logout_enabled: true."),
            logout_note: Some("Back-channel logout is supported but opt-in: the URI below is pre-filled, but you must set backchannel_logout_enabled: true for the provider in Synapse. Front-channel logout isn't supported."),
            post_create_note: None,
            logo: Some("matrix.svg"),
            logo_dark: None,
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
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("For the user_oidc app (not oidc_login). Disable server-side encryption — it is incompatible with OIDC."),
            logout_note: Some("Back-channel logout is supported: the URI below is pre-filled — replace PROVIDER_NAME with your user_oidc provider identifier. Front-channel logout isn't supported."),
            post_create_note: None,
            logo: Some("nextcloud.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Grafana requires an email claim. For refresh tokens, add 'offline_access' to the scope here AND add refresh_token to the grant types, then set use_refresh_token=true in Grafana."),
            logout_note: None,
            post_create_note: None,
            logo: Some("grafana.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Add 'groups' to the scope for OAuth role management. Forseti populates the groups claim from the user's active-org teams."),
            logout_note: Some("Back-channel logout is supported: the URI below is pre-filled, but you must set ENABLE_OAUTH_BACKCHANNEL_LOGOUT=true in Open WebUI. Front-channel logout isn't supported."),
            post_create_note: None,
            logo: Some("open_webui.svg"),
            logo_dark: Some("open_webui-light.svg"),
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Note the dot in /auth/oidc.callback. offline_access is required — Outline errors without refresh tokens."),
            logout_note: None,
            post_create_note: None,
            logo: Some("outline.svg"),
            logo_dark: Some("outline-light.svg"),
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Three redirect URIs: web login, settings refresh, and the mobile relay. For native mobile via a custom scheme, Hydra must be configured to allow non-HTTPS redirects."),
            logout_note: None,
            post_create_note: None,
            logo: Some("immich.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("The double auth/auth is intentional (Devise mount + strategy name)."),
            logout_note: None,
            post_create_note: None,
            logo: Some("mastodon.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("The 'groups' claim drives RBAC and is populated by Forseti from the user's active-org teams. The CLI needs a separate public client at http://localhost:8085/auth/callback."),
            logout_note: None,
            post_create_note: None,
            logo: Some("argocd.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "parseable",
            label: "Parseable",
            base_preset: Preset::WebApp,
            client_name: "Parseable",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/api/v1/o/code"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email groups",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Configure Parseable with P_OIDC_ISSUER, P_OIDC_CLIENT_ID, P_OIDC_CLIENT_SECRET, and P_ORIGIN_URI; the redirect is <P_ORIGIN_URI>/api/v1/o/code. The 'groups' claim is populated by Forseti from the user's active-org team slugs; create a role in Parseable whose name matches each team slug you want to grant."),
            logout_note: None,
            post_create_note: None,
            logo: Some("parseable.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("offline_access is needed for the Docker/Helm CLI secret to keep working past ID-token expiry. The groups claim is populated by Forseti from the user's active-org teams."),
            logout_note: None,
            post_create_note: None,
            logo: Some("harbor.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: None,
            logout_note: None,
            post_create_note: None,
            logo: Some("miniflux.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: None,
            logout_note: None,
            post_create_note: None,
            logo: Some("bookstack.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("The redirect is Portainer's web UI base URL (no trailing slash, no callback path); it must match the Redirect URL field in Portainer's OAuth settings exactly. Portainer sends credentials in the request body (client_secret_post). 'groups' (team sync) is populated by Forseti from the user's active-org teams."),
            logout_note: None,
            post_create_note: None,
            logo: Some("portainer.svg"),
            logo_dark: None,
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
            // Proxmox uses a plain code flow (no code_challenge) — don't require PKCE.
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Redirect is the PVE web UI base (port 8006 by default; adjust if proxied on 443). Sources disagree on the trailing slash; if login fails with redirect_uri_mismatch, try adding one. 'groups' is populated by Forseti from the user's active-org teams for permission sync."),
            logout_note: None,
            post_create_note: None,
            logo: Some("proxmox.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with the authentication-source name you set in Gitea (Site Admin → Authentication Sources)."),
            logout_note: None,
            post_create_note: None,
            logo: Some("gitea.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with the authentication-source name you set in Forgejo."),
            logout_note: None,
            post_create_note: None,
            logo: Some("forgejo.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with your provider_id. The trailing slash is required."),
            logout_note: None,
            post_create_note: None,
            logo: Some("paperless_ngx.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with the (lowercased) provider key from auth.openid.providers in config.yml."),
            logout_note: None,
            post_create_note: None,
            logo: Some("vikunja.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("Uses the third-party jellyfin-plugin-sso. Replace PROVIDER_NAME with the provider name set in the plugin (case-sensitive). The groups claim (for role mapping) is populated by Forseti from the user's active-org teams."),
            logout_note: None,
            post_create_note: None,
            logo: Some("jellyfin.svg"),
            logo_dark: None,
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
            self_audience: false,
            account_deletion_url: None,
            note: Some("This is the HedgeDoc 1.x path. HedgeDoc 2.x uses /api/private/auth/oidc/<name>/callback instead."),
            logout_note: None,
            post_create_note: None,
            logo: Some("hedgedoc.svg"),
            logo_dark: None,
        },
        // --- Second wave: more popular OIDC relying parties ---
        AppTemplate {
            slug: "vaultwarden",
            label: "Vaultwarden",
            base_preset: Preset::WebApp,
            client_name: "Vaultwarden",
            grant_types: &["authorization_code", "refresh_token"],
            redirect_uris: &["https://YOUR_DOMAIN/identity/connect/oidc-signin"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile offline_access",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Native SSO (free, unlike upstream Bitwarden) since v1.35.0 — set SSO_ENABLED=true. PKCE is on by default. Desktop/mobile clients also need the bitwarden://sso-callback scheme allow-listed; works cleanly only at the domain root."),
            logout_note: None,
            post_create_note: None,
            logo: Some("vaultwarden.svg"),
            logo_dark: Some("vaultwarden-light.svg"),
        },
        AppTemplate {
            slug: "discourse",
            label: "Discourse",
            base_preset: Preset::WebApp,
            client_name: "Discourse",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Core discourse-openid-connect plugin. Register the callback with NO trailing slash. Set the client id/secret + discovery URL in Discourse site settings."),
            logout_note: None,
            post_create_note: None,
            logo: Some("discourse.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "superset",
            label: "Apache Superset",
            base_preset: Preset::WebApp,
            client_name: "Apache Superset",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/oauth-authorized/PROVIDER_NAME"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Replace PROVIDER_NAME with the `name` in your OAUTH_PROVIDERS entry (the path is hard-coded in Flask-AppBuilder). You usually need a custom SupersetSecurityManager oauth_user_info() to map claims and roles."),
            logout_note: None,
            post_create_note: None,
            logo: Some("superset.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "wordpress",
            label: "WordPress",
            base_preset: Preset::WebApp,
            client_name: "WordPress",
            grant_types: &["authorization_code"],
            redirect_uris: &[
                "https://YOUR_DOMAIN/wp-admin/admin-ajax.php?action=openid-connect-authorize",
                "https://YOUR_DOMAIN/openid-connect-authorize",
            ],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("OpenID Connect Generic plugin. The default callback carries a query string some IdPs reject — enable 'Alternate Redirect URI' in the plugin and use the second URL, then flush permalinks."),
            logout_note: None,
            post_create_note: None,
            logo: Some("wordpress.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "penpot",
            label: "Penpot",
            base_preset: Preset::WebApp,
            client_name: "Penpot",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/api/auth/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Set enable-login-with-oidc plus PENPOT_OIDC_BASE_URI (with trailing slash) and PENPOT_PUBLIC_URI. Containerized setups may need manual endpoint overrides for internal-vs-browser hostnames."),
            logout_note: None,
            post_create_note: None,
            logo: Some("penpot.svg"),
            logo_dark: Some("penpot-light.svg"),
        },
        AppTemplate {
            slug: "netbox",
            label: "NetBox",
            base_preset: Preset::WebApp,
            client_name: "NetBox",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/oauth/complete/oidc/"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("python-social-auth generic OIDC backend (REMOTE_AUTH_BACKEND = oidc). The trailing slash is required; the SSO button shows literally 'oidc'. Group sync needs a custom pipeline."),
            logout_note: None,
            post_create_note: None,
            logo: Some("netbox.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "jenkins",
            label: "Jenkins",
            base_preset: Preset::WebApp,
            client_name: "Jenkins",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/securityRealm/finishLogin"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            // oic-auth has PKCE off by default — match that; enable it both sides to opt in.
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("oic-auth plugin. The callback path is fixed — match http/https exactly. Back-channel logout needs the separate oidc-backchannel-logout plugin (/oidc-backchannel/logout)."),
            logout_note: None,
            post_create_note: None,
            logo: Some("jenkins.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "rocketchat",
            label: "Rocket.Chat",
            base_preset: Preset::WebApp,
            client_name: "Rocket.Chat",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/_oauth/PROVIDER_NAME"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Admin → Custom OAuth; replace PROVIDER_NAME with the (lowercased) unique name you give the service. Set the token + identity (userinfo) paths — an ID token alone isn't enough. Roles/groups need a claim mapping."),
            logout_note: None,
            post_create_note: None,
            logo: Some("rocketchat.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "seafile",
            label: "Seafile",
            base_preset: Preset::WebApp,
            client_name: "Seafile",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/oauth/callback/"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Generic OAuth2 in the free CE (ENABLE_OAUTH). The trailing slash is required. Set OAUTH_ATTRIBUTE_MAP to map email or accounts get blank emails. Single global IdP."),
            logout_note: None,
            post_create_note: None,
            logo: Some("seafile.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "actual_budget",
            label: "Actual Budget",
            base_preset: Preset::WebApp,
            client_name: "Actual Budget",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/openid/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Set authMethod=openid with discovery. The ID token must be RS256. Heads-up: the first user to log in via OIDC becomes the irreversible server owner — log in as the intended owner first."),
            logout_note: None,
            post_create_note: None,
            logo: Some("actual_budget.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "audiobookshelf",
            label: "Audiobookshelf",
            base_preset: Preset::WebApp,
            client_name: "Audiobookshelf",
            grant_types: &["authorization_code"],
            redirect_uris: &[
                "https://YOUR_DOMAIN/auth/openid/callback",
                "https://YOUR_DOMAIN/auth/openid/mobile-redirect",
            ],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Register both the web callback and the mobile relay. The UserInfo signing algorithm must be unsigned ('none') or login fails. A groups claim for role mapping is optional."),
            logout_note: None,
            post_create_note: None,
            logo: Some("audiobookshelf.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "mealie",
            label: "Mealie",
            base_preset: Preset::WebApp,
            client_name: "Mealie",
            grant_types: &["authorization_code"],
            redirect_uris: &[
                "https://YOUR_DOMAIN/login",
                "https://YOUR_DOMAIN/login?direct=1",
            ],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("The callback is /login (not a /callback route); register both /login and /login?direct=1 (logout). PKCE (S256) is required. Behind a proxy set --forwarded-allow-ips or the redirect reverts to http. This is the v2 config."),
            logout_note: None,
            post_create_note: None,
            logo: Some("mealie.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "matomo",
            label: "Matomo",
            base_preset: Preset::WebApp,
            client_name: "Matomo",
            grant_types: &["authorization_code"],
            redirect_uris: &[
                "https://YOUR_DOMAIN/index.php?module=LoginOIDC&action=callback&provider=oidc",
            ],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email",
            token_endpoint_auth_method: "client_secret_post",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("LoginOIDC plugin. The callback is a query-string URL — strict setups need a web-server rewrite. provider=oidc is the default. No PKCE."),
            logout_note: None,
            post_create_note: None,
            logo: Some("matomo.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "rancher",
            label: "Rancher",
            base_preset: Preset::WebApp,
            client_name: "Rancher",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/verify-auth"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: true,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Generic OIDC provider; the web origin is your base URL. For Keycloak 17+ the auto-discovered endpoints wrongly include /auth — override them. A groups + audience claim mapping drives RBAC."),
            logout_note: None,
            post_create_note: None,
            logo: Some("rancher.svg"),
            logo_dark: None,
        },
        // --- Paid / enterprise-tier OIDC (templated, but flagged in the note) ---
        AppTemplate {
            slug: "openproject",
            label: "OpenProject",
            base_preset: Preset::WebApp,
            client_name: "OpenProject",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/oidc-PROVIDER_NAME/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: Some(
                "https://YOUR_DOMAIN/auth/oidc-PROVIDER_NAME/backchannel-logout",
            ),
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("OIDC requires an OpenProject Enterprise license. Replace PROVIDER_NAME with your provider slug — the callback becomes e.g. /auth/oidc-keycloak/callback."),
            logout_note: Some("Back-channel logout is supported: the URI below is pre-filled — replace PROVIDER_NAME to match your provider slug."),
            post_create_note: None,
            logo: Some("openproject.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "plane",
            label: "Plane",
            base_preset: Preset::WebApp,
            client_name: "Plane",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/auth/oidc/callback/"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("OIDC requires a paid Plane tier (Pro/Business), configured via the God-Mode admin UI. The trailing slash on the callback is exact. Logout goes through the IdP end-session endpoint."),
            logout_note: None,
            post_create_note: None,
            logo: Some("plane.svg"),
            logo_dark: None,
        },
        AppTemplate {
            slug: "mattermost",
            label: "Mattermost",
            base_preset: Preset::WebApp,
            client_name: "Mattermost",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/signup/openid/complete"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid profile email",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Generic OIDC requires a paid Mattermost tier (Entry/Professional/Enterprise). The free GitLab connector won't work against Forseti — it expects GitLab's API shape, not OIDC. OIDC and LDAP are mutually exclusive in Mattermost."),
            logout_note: None,
            post_create_note: None,
            logo: Some("mattermost.svg"),
            logo_dark: Some("mattermost-light.svg"),
        },
        AppTemplate {
            slug: "atlassian",
            label: "Atlassian Data Center",
            base_preset: Preset::WebApp,
            client_name: "Atlassian Data Center",
            grant_types: &["authorization_code"],
            redirect_uris: &["https://YOUR_DOMAIN/plugins/servlet/oidc/callback"],
            post_logout_redirect_uris: &[],
            backchannel_logout_uri: None,
            scope: "openid email profile",
            token_endpoint_auth_method: "client_secret_basic",
            require_pkce: false,
            audience_visible: false,
            self_audience: false,
            account_deletion_url: None,
            note: Some("Proprietary, paid Data Center tier only. The native 'SSO for Atlassian Data Center' app uses the SAME callback for Jira, Confluence, Bitbucket and Bamboo. Reverse-proxy proxyName/proxyPort must match the base URL. Do NOT use the miniOrange /plugins/servlet/oauth/callback path."),
            logout_note: None,
            post_create_note: None,
            logo: Some("atlassian.svg"),
            logo_dark: None,
        },
    ];
}

/// Picker card for the "Popular apps" group. `slug` links to `?template=<slug>`.
#[derive(Clone)]
pub(crate) struct AppCard {
    pub(crate) slug: &'static str,
    pub(crate) label: &'static str,
    /// First letter, upper-cased; drives the text-only tile when no logo.
    pub(crate) initial: char,
    pub(crate) logo: Option<&'static str>,
    pub(crate) logo_dark: Option<&'static str>,
}

pub(crate) fn app_template_cards() -> Vec<AppCard> {
    AppTemplate::ALL
        .iter()
        .map(|t| AppCard {
            slug: t.slug,
            label: t.label,
            initial: t.label.chars().next().unwrap_or('?').to_ascii_uppercase(),
            logo: t.logo,
            logo_dark: t.logo_dark,
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
        for t in AppTemplate::ALL {
            let _ = t.base_preset;
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
        assert!(AppTemplate::from_slug("stackpit")
            .unwrap()
            .logout_guidance()
            .is_none());
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
        assert_eq!(
            AppTemplate::from_slug("mastodon")
                .unwrap()
                .logout_guidance(),
            Some(LOGOUT_UNSUPPORTED_NOTE)
        );
    }

    #[test]
    fn every_template_has_an_svg_logo() {
        for t in AppTemplate::ALL {
            let logo = t
                .logo
                .unwrap_or_else(|| panic!("{} missing a logo", t.slug));
            assert!(logo.ends_with(".svg"), "{} logo not an svg: {logo}", t.slug);
        }
    }

    #[test]
    fn liwan_has_a_dark_variant() {
        // Liwan's mark is monochrome black; needs a light variant for the dark theme.
        let liwan = AppTemplate::from_slug("liwan").unwrap();
        assert_eq!(liwan.logo, Some("liwan.svg"));
        assert_eq!(liwan.logo_dark, Some("liwan-light.svg"));
    }

    #[test]
    fn logo_dark_implies_logo() {
        for t in AppTemplate::ALL {
            if t.logo_dark.is_some() {
                assert!(t.logo.is_some(), "{} has logo_dark but no logo", t.slug);
            }
        }
    }

    #[test]
    fn cards_copy_logo_from_templates() {
        let cards = app_template_cards();
        let gitlab = cards.iter().find(|c| c.slug == "gitlab").unwrap();
        assert_eq!(gitlab.logo, Some("gitlab.svg"));
        let stackpit = cards.iter().find(|c| c.slug == "stackpit").unwrap();
        assert_eq!(stackpit.logo, Some("stackpit.svg"));
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
