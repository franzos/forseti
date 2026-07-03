//! Runtime configuration for Forseti.
//!
//! Loaded from `config.toml` at the repo root (or `$FORSETI_CONFIG_PATH` if set),
//! with environment-variable overrides under the `FORSETI_` prefix using a
//! double-underscore separator (e.g. `FORSETI_KRATOS__PUBLIC_URL`).

use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub kratos: KratosConfig,
    pub hydra: HydraConfig,
    #[serde(rename = "self")]
    pub self_: SelfConfig,
    pub brand: BrandConfig,
    /// Dashboard "Your apps" cards. Optional; section is omitted when empty.
    #[serde(default)]
    pub apps: Vec<AppEntry>,
    /// OAuth2 scope descriptions surfaced on the consent screen.
    #[serde(default)]
    pub oauth: OAuthConfig,
    /// Admin-surface configuration. An empty allowlist closes `/admin/*` until the operator opts in.
    #[serde(default)]
    pub admin: AdminConfig,
    /// Forseti-owned database. Defaulted so a fresh checkout boots against a local sqlite file.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Audit log configuration. Usable on defaults except `webhook_token`, required for the Kratos receiver.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Internal HTTP listener for machine-to-machine endpoints; separate so the trust boundary is set at the network layer.
    #[serde(default)]
    pub internal: InternalConfig,
    /// Commercial-tier license gate. All fields optional; OSS ships unlicensed with an upsell on gated features.
    #[serde(default)]
    pub license: LicenseConfig,
    /// Identity-management knobs (today only the `unverified-prune` TTL).
    #[serde(default)]
    pub identity: IdentityConfig,
    /// SMTP for Forseti-originated mail (invite + claim-email); Kratos's courier handles its own self-service mail.
    /// When `enabled = false` the send sites log + skip, leaving the token/code in the DB for hand-delivery in dev.
    #[serde(default)]
    pub smtp: SmtpConfig,
    /// Forseti-owned member profiles. Off by default; leave off where org-mates shouldn't see each other's data.
    #[serde(default)]
    pub profiles: ProfilesConfig,
    /// Outbound webhook signing (account-deletion fan-out). Payloads are RFC 8417 SETs (EdDSA/Ed25519); key auto-generated on first boot.
    #[serde(default)]
    pub webhook: WebhookConfig,
    /// Per-IP rate limits for `/claim-email` + `/claim-email/confirm`.
    #[serde(default)]
    pub claim_email: ClaimEmailConfig,
    /// Per-IP rate limits for `/handoff*` plus referrer-cookie TTL; caps probing of which `client_id`s exist in Hydra.
    #[serde(default)]
    pub handoff: HandoffConfig,
    /// One-shot flash cookie + `secret_reveals` row TTLs.
    #[serde(default)]
    pub flash: FlashConfig,
    /// Organizations subsystem knobs (active-org cookie TTL, invite expiry).
    #[serde(default)]
    pub orgs: OrgsConfig,
    /// Accounts subsystem knobs (known-accounts device-chooser cookie TTL).
    #[serde(default)]
    pub accounts: AccountsConfig,
    /// SAML SSO bridge. `None` (default) = feature fully off.
    #[serde(default)]
    pub saml: Option<SamlConfig>,
    /// Whether Forseti sits behind a reverse proxy that strips and re-adds forwarded-for headers.
    /// Consumed by the audit middleware (client IP) and the per-IP rate limiters.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Operator-supplied secret material (today only `cookie_secret`).
    #[serde(default)]
    pub security: SecurityConfig,
    /// POSIX account materialisation (Linux auth): uid/gid bands, shell, home prefix, free-tier seat cap.
    #[serde(default)]
    #[allow(dead_code)]
    pub posix: PosixConfig,
}

/// Operator-supplied secrets. `cookie_secret` seeds the HMAC keys for every Forseti-signed cookie;
/// hex string (`openssl rand -hex 32`) or raw bytes, falling back to a per-boot ephemeral key when unset.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub cookie_secret: Option<String>,
}

/// Deployment-shape proxy trust. Flip on only when the upstream
/// reverse proxy strips client-sent forwarded-for headers before
/// re-adding its own. See `docs/operator-guide-proxy.md`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub trust_forwarded_for: bool,
}

/// POSIX account materialisation knobs. Drives uid/gid allocation and
/// the default shell/home shape when Forseti backs a Linux host's auth.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PosixConfig {
    /// First uid handed out; accounts allocate monotonically from here.
    pub uid_base: u32,
    /// First gid handed out for auto-created primary/org groups.
    pub gid_base: u32,
    /// Size of the user uid band starting at `uid_base`.
    #[serde(default = "default_user_uid_size")]
    #[allow(dead_code)] // uid-band ceiling not yet enforced
    pub user_uid_size: u32,
    /// Size of the user-private gid band starting at `gid_base`.
    #[serde(default = "default_user_gid_size")]
    pub user_gid_size: u32,
    /// Base of the team-gid band. MUST be disjoint from the user gid band.
    #[serde(default = "default_group_gid_base")]
    pub group_gid_base: u32,
    /// Size of the team-gid band.
    #[serde(default = "default_group_gid_size")]
    pub group_gid_size: u32,
    pub default_shell: String,
    /// Home dir is `{home_prefix}/{username}` unless overridden per account.
    pub home_prefix: String,
    /// Free-tier seat cap when no commercial `max_seats` applies.
    pub free_seats: u32,
    /// Confidential OAuth client id Forseti drives the RFC 8628 device grant
    /// as for Linux PAM auth. Created (if absent) by `posix-init-client`.
    pub pam_client_id: String,
    /// Client secret for `pam_client_id`. `None` = let `posix-init-client` mint one (revealed once).
    pub pam_client_secret: Option<String>,
    /// Wall-clock cap (seconds) on a device-auth poll loop. Kept below sshd's `LoginGraceTime` (120s) so an abandoned flow can't pin the login.
    pub device_poll_cap_secs: u64,
    /// `iat` freshness window (seconds) for the device id_token; a replay guard layered on top of `exp`.
    pub id_token_iat_window_secs: u64,
    /// `auth_time` freshness window (seconds) for `force_mfa` hosts; an hours-old AAL2 session shouldn't grant root.
    pub mfa_auth_time_window_secs: u64,
    /// Expected `iss` on the device id_token. Hydra's `urls.self.issuer` can differ from `[hydra].public_url`
    /// (e.g. `host.containers.internal` vs `localhost`); `None` falls back to `[hydra].public_url`.
    #[serde(default)]
    pub hydra_issuer: Option<String>,
    /// Master switch for offline auth. Off hides the offline-passphrase surface and provisions no verifiers.
    pub offline_auth_enabled: bool,
    /// TTL (hours) on each provisioned offline verifier; bounds the offline window on a partitioned host.
    pub offline_ttl_hours: u64,
    /// Hard cap (hours) on offline-credential use measured from the last successful online auth, regardless of TTL refreshes.
    pub offline_max_lifetime_hours: u64,
    /// Server-side floor on offline passphrase length; never below [`posix::offline::OFFLINE_MIN_LEN`] (8).
    pub offline_min_len: usize,
}

impl Default for PosixConfig {
    fn default() -> Self {
        Self {
            uid_base: 1_000_000,
            gid_base: 2_000_000, // disjoint from uid space so uids/gids never numerically collide
            user_uid_size: 1_000_000,
            user_gid_size: 1_000_000,
            group_gid_base: 3_000_000,
            group_gid_size: 1_000_000,
            default_shell: "/bin/sh".to_string(), // Guix has no /bin/bash
            home_prefix: "/home".to_string(),
            free_seats: 25,
            pam_client_id: "forseti-linux-pam".to_string(),
            pam_client_secret: None,
            device_poll_cap_secs: 90,
            id_token_iat_window_secs: 120,
            mfa_auth_time_window_secs: 300,
            hydra_issuer: None,
            offline_auth_enabled: true,
            offline_ttl_hours: 24,
            offline_max_lifetime_hours: 168,
            offline_min_len: 8,
        }
    }
}

fn default_user_uid_size() -> u32 {
    1_000_000
}
fn default_user_gid_size() -> u32 {
    1_000_000
}
fn default_group_gid_base() -> u32 {
    3_000_000
}
fn default_group_gid_size() -> u32 {
    1_000_000
}

impl PosixConfig {
    /// Hard invariant: the user-private gid band and the team-gid band must be
    /// disjoint intervals, else a team gid could numerically collide with a user
    /// gid on a host (cross-group ownership collision).
    pub fn validate_bands(&self) -> anyhow::Result<()> {
        let user_gid_end = self.gid_base.saturating_add(self.user_gid_size);
        let team_gid_end = self.group_gid_base.saturating_add(self.group_gid_size);
        let disjoint = user_gid_end <= self.group_gid_base || team_gid_end <= self.gid_base;
        anyhow::ensure!(
            disjoint,
            "posix gid bands overlap: user [{}, {}) vs team [{}, {})",
            self.gid_base,
            user_gid_end,
            self.group_gid_base,
            team_gid_end
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KratosConfig {
    /// Browser-facing public API, e.g. `http://127.0.0.1:4433`.
    pub public_url: String,
    /// Server-only admin API, e.g. `http://kratos:4434`.
    pub admin_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HydraConfig {
    pub public_url: String,
    pub admin_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SelfConfig {
    /// Forseti's own externally reachable URL (used for `return_to` round-trips).
    pub url: String,
}

impl SelfConfig {
    /// Whether Forseti is served over HTTPS externally. Drives cookie
    /// hardening (`Secure` attribute) so the dev playground over plain HTTP
    /// keeps working while production deployments don't leak cookies over
    /// unencrypted transport.
    pub fn is_https(&self) -> bool {
        self.url.starts_with("https://")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrandConfig {
    #[serde(default = "default_brand_name")]
    pub name: String,
    #[allow(dead_code)]
    pub support_email: Option<String>,
    pub logo_url: Option<String>,
    /// Intro paragraph rendered on `/oauth/consent` above the scope list.
    #[serde(default = "default_consent_intro")]
    pub consent_intro: String,
    #[serde(default)]
    pub theme_preset: Option<String>,
    #[serde(default)]
    pub brand_primary: Option<String>,
    #[serde(default)]
    pub brand_on_primary: Option<String>,
    #[serde(default)]
    pub brand_secondary: Option<String>,
}

fn default_brand_name() -> String {
    "Forseti".to_string()
}

fn default_consent_intro() -> String {
    "The application below is requesting access to your account.".to_string()
}

/// One card on the dashboard "Your apps" section. Configured per deployment.
#[derive(Debug, Clone, Deserialize)]
pub struct AppEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub url: String,
}

/// OAuth2 bridge settings (consent UI copy in particular).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OAuthConfig {
    /// Map of scope name → human-readable description for the consent screen.
    /// Unknown scopes fall back to the raw scope name.
    #[serde(default)]
    pub scope_descriptions: std::collections::HashMap<String, String>,
    /// DCR `client_name` denylist. Case-insensitive substring match against
    /// the posted `client_name`. Operators replace the list entirely; if
    /// the key is absent from `config.toml`, the code-baked defaults in
    /// `crate::oauth::register::RESERVED_NAMES_DEFAULT` are used.
    #[serde(default)]
    pub dcr_reserved_names: Option<Vec<String>>,
    /// Per-IP rate limit on `POST /oauth2/register`, max requests per minute. In-memory, per-process.
    /// `None` falls back to the code-side default (10). Set to `0` to disable the per-minute bucket.
    #[serde(default)]
    pub dcr_ip_rate_per_minute: Option<u32>,
    /// Per-IP rate limit on `POST /oauth2/register`, max requests per hour, in parallel with the per-minute bucket.
    /// `None` falls back to 100. Set to `0` to disable the per-hour bucket.
    #[serde(default)]
    pub dcr_ip_rate_per_hour: Option<u32>,
    /// Per-IAT registration cap over a rolling 24-hour window opened by
    /// the first successful use. Counts successful registrations only
    /// (failed lookups, reserved-name rejects, Hydra failures don't
    /// count). `None` falls back to 50. Set to `0` to disable.
    #[serde(default)]
    pub dcr_iat_daily_limit: Option<u32>,
    /// Per-IP rate limit on `/oauth/device` (the RFC 8628 verification screen),
    /// max requests per minute. The screen is session-gated; this is
    /// defence-in-depth against grinding low-entropy user codes. `None` falls
    /// back to the code-side default (20). Set to `0` to disable the bucket.
    #[serde(default)]
    pub device_verify_ip_rate_per_minute: Option<u32>,
    /// Per-IP rate limit on `/oauth/device`, max requests per hour, in parallel
    /// with the per-minute bucket. `None` falls back to 120. Set to `0` to
    /// disable the per-hour bucket.
    #[serde(default)]
    pub device_verify_ip_rate_per_hour: Option<u32>,
}

/// Admin-surface gating: emails allowed through `/admin/*`; everyone else gets 403 even with a valid session.
/// AAL2 is enforced separately at the route guard. A config allowlist (not a Kratos role) keeps admin membership
/// in version-controllable declarative config; adding an admin needs a config reload, not a DB write.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AdminConfig {
    /// Lowercased on read; matched case-insensitively against the session's
    /// `traits.email`. Empty list = nobody is an admin.
    #[serde(default)]
    pub allowed_emails: Vec<String>,
}

impl AdminConfig {
    /// Case-insensitive membership test. Empty list → always false.
    pub fn is_admin(&self, email: &str) -> bool {
        if email.is_empty() {
            return false;
        }
        let needle = email.to_lowercase();
        self.allowed_emails
            .iter()
            .any(|e| e.to_lowercase() == needle)
    }
}

/// Forseti-owned database, separate from the Kratos/Hydra Postgres. The URL scheme picks the backend
/// (`sqlite://...` or `postgres://...`); default sqlite at `./forseti.db` for self-hoster ergonomics.
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// `sqlite://path/to/file.db` or `postgres://user:pass@host/db`.
    #[serde(default = "default_database_url")]
    pub url: String,
    /// Operator opt-out for the boot-time migration run. Set to `true` (env:
    /// `FORSETI_DATABASE__SKIP_MIGRATIONS=1`) when schema changes are gated
    /// through a deploy pipeline rather than the running binary.
    #[serde(default)]
    pub skip_migrations: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            skip_migrations: false,
        }
    }
}

fn default_database_url() -> String {
    "sqlite://./forseti.db".to_string()
}

/// Backend selector parsed from the URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

impl DatabaseConfig {
    /// Pick the backend from the URL scheme. Falls back to sqlite on parse
    /// failure (matches the default URL shape).
    pub fn backend(&self) -> DatabaseBackend {
        if self.url.starts_with("postgres://") || self.url.starts_with("postgresql://") {
            DatabaseBackend::Postgres
        } else {
            DatabaseBackend::Sqlite
        }
    }

    /// Best-effort check for "this deployment looks production-shaped" used
    /// to warn about the multi-instance sqlite footgun. True iff Forseti's
    /// own URL is https AND the host is not localhost / 127.0.0.1 / RFC1918.
    /// Can't auto-detect actual instance count, only deployment shape.
    pub fn looks_like_production(self_url: &str) -> bool {
        let Ok(parsed) = url::Url::parse(self_url) else {
            return false;
        };
        if parsed.scheme() != "https" {
            return false;
        }
        let Some(host) = parsed.host() else {
            return false;
        };
        match host {
            url::Host::Domain(name) => {
                if name == "localhost" {
                    return false;
                }
                true
            }
            url::Host::Ipv4(v4) => {
                if v4.is_loopback() || v4.is_private() {
                    return false;
                }
                true
            }
            url::Host::Ipv6(v6) => {
                if v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local() {
                    return false;
                }
                // Note: 2001:db8::/32 (documentation prefix) is intentionally
                // NOT treated as non-prod: it's reserved for examples, not
                // private deployments.
                true
            }
        }
    }
}

/// Audit log configuration.
///
/// `webhook_token` gates the `/internal/audit/kratos` receiver and must match the Kratos config;
/// Forseti refuses to boot when empty. `ip_salt` is optional (derived from `self.url` via `audit::ip_salt()`
/// when unset). `audit_retention_days` is the `audit-prune` default.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default)]
    pub webhook_token: String,
    #[serde(default)]
    pub ip_salt: Option<String>,
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: i64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            webhook_token: String::new(),
            ip_salt: None,
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

/// Internal listener (today: the audit webhook receiver). Default `127.0.0.1:8081` keeps it host-local;
/// containerised deployments override `bind` so Kratos in another container can reach it.
#[derive(Debug, Clone, Deserialize)]
pub struct InternalConfig {
    #[serde(default = "default_internal_bind")]
    pub bind: String,
}

impl Default for InternalConfig {
    fn default() -> Self {
        Self {
            bind: default_internal_bind(),
        }
    }
}

fn default_internal_bind() -> String {
    "127.0.0.1:8081".to_string()
}

/// SMTP connection scheme picking lettre's transport builder: plaintext via `builder_dangerous`,
/// STARTTLS/SMTPS via the typed `relay`/`starttls_relay` so a TLS slip is an init error.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SmtpScheme {
    #[default]
    Plaintext,
    Starttls,
    Smtps,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    /// When false, Forseti logs the would-be recipient/subject and
    /// returns without contacting the SMTP server. Useful in tests and
    /// for OSS deployments that don't have an SMTP relay handy.
    #[serde(default)]
    pub enabled: bool,
    /// SMTP server hostname.
    #[serde(default = "default_smtp_host")]
    pub host: String,
    /// SMTP server port. Plaintext SMTP defaults to 1025 (Mailcrab dev),
    /// production deployments typically use 587 (STARTTLS) or 465 (SMTPS).
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// Connection scheme: `plaintext`, `starttls`, or `smtps`.
    #[serde(default)]
    pub scheme: SmtpScheme,
    /// From address. Falls back to `noreply@<self.url host>` when empty.
    #[serde(default)]
    pub from: String,
    /// Optional credentials. Empty username means no auth.
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: Redacted,
    /// Accept self-signed / invalid TLS certs. Set to false in production.
    #[serde(default)]
    pub skip_tls_verify: bool,
}

/// String newtype whose `Debug` prints `[redacted]` so secrets can't leak
/// through a struct's derived `Debug`. Deref to `&str` keeps read sites
/// ergonomic.
#[derive(Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct Redacted(pub String);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl std::ops::Deref for Redacted {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<String> for Redacted {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_smtp_host(),
            port: default_smtp_port(),
            scheme: SmtpScheme::default(),
            from: String::new(),
            username: String::new(),
            password: Redacted::default(),
            skip_tls_verify: false,
        }
    }
}

fn default_smtp_host() -> String {
    "127.0.0.1".to_string()
}
fn default_smtp_port() -> u16 {
    1025
}
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProfilesConfig {
    /// Gates the extended-profile form, the public `/users/{id}` view, the roster link, and the `extended_profile` scope.
    #[serde(default)]
    pub enabled: bool,
}

fn default_audit_retention_days() -> i64 {
    90
}

/// Commercial-tier configuration. The grace window is fixed ([`crate::commercial::GRACE_DAYS`]); the
/// signed license blob lives in the `forseti_license` table and activates at `/admin/license`, not here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LicenseConfig {
    /// "Upgrade" CTA URL on the upsell page and lock badges; empty falls back to a `brand.support_email` mailto.
    #[serde(default)]
    pub purchase_url: String,
}

/// SAML SSO bridge (commercial, opt-in). Absent = `/sso/*` unmounted, zero SAML footprint. The bridge
/// (Jackson / Ory Polis) is operator-deployed; Forseti only orchestrates against it. See `docs/commercial/saml.md`.
#[derive(Debug, Clone, Deserialize)]
pub struct SamlConfig {
    /// Browser-facing base URL of the Jackson instance, e.g.
    /// `https://sso.example.com` or `http://127.0.0.1:5225` in dev.
    pub jackson_url: String,
    /// Server-to-server base URL override (container-network address).
    /// Defaults to `jackson_url`.
    #[serde(default)]
    pub jackson_internal_url: Option<String>,
    /// One of Jackson's `JACKSON_API_KEYS` values; authorises connection CRUD.
    pub jackson_api_key: Redacted,
    /// Jackson's `CLIENT_SECRET_VERIFIER`; the OAuth2 client_secret paired
    /// with the dynamic `tenant=…&product=…` client_id.
    pub client_secret_verifier: Redacted,
    /// Kratos identity schema for JIT-provisioned identities.
    #[serde(default = "default_saml_schema_id")]
    pub identity_schema_id: String,
    /// SP entity id handed to the customer's IdP admin; must match Jackson's
    /// `samlAudience`. `None` ⇒ Jackson's default (`sp_entity_id()`).
    #[serde(default)]
    pub sp_entity_id: Option<String>,
}

/// Jackson's default `samlAudience`: the SP entity id the customer's IdP admin configures when `[saml].sp_entity_id` is unset.
pub const DEFAULT_SP_ENTITY_ID: &str = "https://saml.boxyhq.com";

impl SamlConfig {
    pub fn internal_url(&self) -> &str {
        self.jackson_internal_url
            .as_deref()
            .unwrap_or(&self.jackson_url)
    }

    /// Configured SP entity id or Jackson's default. Single source of the
    /// default so the admin page and operator docs can't drift.
    pub fn sp_entity_id(&self) -> &str {
        self.sp_entity_id.as_deref().unwrap_or(DEFAULT_SP_ENTITY_ID)
    }
}

fn default_saml_schema_id() -> String {
    "default".to_string()
}

/// Identity-management knobs, defaulted so OSS ships sane values without `[identity]`.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// `unverified-prune` window: identities with an unverified address and `created_at` older than this many days are deleted.
    /// Default 7 keeps an unverified squatter from blocking the legitimate owner; dial up for slower onboarding.
    #[serde(default = "default_unverified_ttl_days")]
    pub unverified_ttl_days: i64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            unverified_ttl_days: default_unverified_ttl_days(),
        }
    }
}

fn default_unverified_ttl_days() -> i64 {
    7
}

/// Outbound-webhook signing. One Ed25519 key signs every account-lifecycle SET (`src/webhook.rs`);
/// receivers verify via `/.well-known/webhook-jwks.json`. A missing `signing_key_path` is auto-generated `0600` on boot.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    #[serde(default = "default_webhook_signing_key_path")]
    pub signing_key_path: String,
    /// Worker poll interval (seconds); trades delivery latency against DB pressure.
    #[serde(default = "default_webhook_tick_seconds")]
    pub tick_seconds: u64,
    /// Maximum delivery attempts before a row is dead-lettered.
    #[serde(default = "default_webhook_max_attempts")]
    pub max_attempts: i32,
    /// Hard age cap (hours); a row older than this is dead-lettered regardless of `max_attempts` (clock skew / dead receivers).
    #[serde(default = "default_webhook_max_age_hours")]
    pub max_age_hours: i64,
    /// Exponential-backoff ceiling (seconds). Retries grow as `60s * 2^attempts`, capped here, with +-25% jitter.
    #[serde(default = "default_webhook_backoff_cap_seconds")]
    pub backoff_cap_seconds: i64,
    /// Claim lease on an outbox row (seconds). A worker crashing between claim and send frees the row after this window.
    #[serde(default = "default_webhook_claim_lease_seconds")]
    pub claim_lease_seconds: i64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            signing_key_path: default_webhook_signing_key_path(),
            tick_seconds: default_webhook_tick_seconds(),
            max_attempts: default_webhook_max_attempts(),
            max_age_hours: default_webhook_max_age_hours(),
            backoff_cap_seconds: default_webhook_backoff_cap_seconds(),
            claim_lease_seconds: default_webhook_claim_lease_seconds(),
        }
    }
}

fn default_webhook_signing_key_path() -> String {
    "data/webhook-signing-key.pem".to_string()
}

fn default_webhook_tick_seconds() -> u64 {
    5
}

fn default_webhook_max_attempts() -> i32 {
    12
}

fn default_webhook_max_age_hours() -> i64 {
    72
}

fn default_webhook_backoff_cap_seconds() -> i64 {
    6 * 60 * 60
}

fn default_webhook_claim_lease_seconds() -> i64 {
    60
}

/// Per-IP rate limits for the `/claim-email` flow. The per-mint attempt cap bounds one mint; this caps
/// repeated minting so the ~20-bit confirm code can't be ground in parallel. Dial up in dev so integration
/// tests sharing the loopback bucket don't 429.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimEmailConfig {
    #[serde(default = "default_claim_email_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_claim_email_per_hour")]
    pub rate_limit_per_hour: u32,
}

impl Default for ClaimEmailConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: default_claim_email_per_minute(),
            rate_limit_per_hour: default_claim_email_per_hour(),
        }
    }
}

fn default_claim_email_per_minute() -> u32 {
    5
}

fn default_claim_email_per_hour() -> u32 {
    30
}

/// Per-IP rate limits for `/handoff*`. The handler hits Hydra's admin API on every entry; this caps
/// probing of which `client_id`s exist. Defaults stay well above any legitimate once-per-session pattern.
#[derive(Debug, Clone, Deserialize)]
pub struct HandoffConfig {
    #[serde(default = "default_handoff_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_handoff_per_hour")]
    pub rate_limit_per_hour: u32,
    /// TTL for the signed `forseti_app_referrer` cookie driving the "Return to <App>" banner.
    #[serde(default = "default_handoff_referrer_ttl_seconds")]
    pub referrer_cookie_ttl_seconds: u64,
}

impl Default for HandoffConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: default_handoff_per_minute(),
            rate_limit_per_hour: default_handoff_per_hour(),
            referrer_cookie_ttl_seconds: default_handoff_referrer_ttl_seconds(),
        }
    }
}

fn default_handoff_per_minute() -> u32 {
    30
}

fn default_handoff_per_hour() -> u32 {
    300
}

fn default_handoff_referrer_ttl_seconds() -> u64 {
    60 * 60
}

/// Flash cookie + secret-reveal TTLs. Both default to 60s: enough to follow a redirect, short enough that a navigated-away admin loses the reveal.
#[derive(Debug, Clone, Deserialize)]
pub struct FlashConfig {
    #[serde(default = "default_flash_cookie_ttl_seconds")]
    pub cookie_ttl_seconds: u64,
    #[serde(default = "default_flash_reveal_ttl_seconds")]
    pub reveal_ttl_seconds: u64,
}

impl Default for FlashConfig {
    fn default() -> Self {
        Self {
            cookie_ttl_seconds: default_flash_cookie_ttl_seconds(),
            reveal_ttl_seconds: default_flash_reveal_ttl_seconds(),
        }
    }
}

fn default_flash_cookie_ttl_seconds() -> u64 {
    60
}

fn default_flash_reveal_ttl_seconds() -> u64 {
    60
}

/// Accounts subsystem TTLs: `known_accounts_cookie_ttl_seconds` is the validity
/// of the signed `forseti_known_accounts` device chooser cookie.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountsConfig {
    #[serde(default = "default_known_accounts_cookie_ttl_seconds")]
    pub known_accounts_cookie_ttl_seconds: u64,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self {
            known_accounts_cookie_ttl_seconds: default_known_accounts_cookie_ttl_seconds(),
        }
    }
}

// 90 days: a device-convenience list, intentionally longer-lived than the
// short active-org selection cookie.
fn default_known_accounts_cookie_ttl_seconds() -> u64 {
    60 * 60 * 24 * 90
}

/// Organizations subsystem TTLs: `active_org_cookie_ttl_seconds` (signed `forseti_active_org` cookie validity)
/// and `invite_ttl_days` (how long a minted invitation stays claimable).
#[derive(Debug, Clone, Deserialize)]
pub struct OrgsConfig {
    #[serde(default = "default_active_org_cookie_ttl_seconds")]
    pub active_org_cookie_ttl_seconds: u64,
    #[serde(default = "default_invite_ttl_days")]
    pub invite_ttl_days: i64,
}

impl Default for OrgsConfig {
    fn default() -> Self {
        Self {
            active_org_cookie_ttl_seconds: default_active_org_cookie_ttl_seconds(),
            invite_ttl_days: default_invite_ttl_days(),
        }
    }
}

fn default_active_org_cookie_ttl_seconds() -> u64 {
    60 * 60 * 24 * 30
}

fn default_invite_ttl_days() -> i64 {
    7
}

/// Sanity ceilings for rate-limit knobs: a typo like `per_window = 1_000_000` is clamped at load with a warn, so it can't silently disable protection.
const RATE_LIMIT_PER_MINUTE_CEILING: u32 = 1_000;
const RATE_LIMIT_PER_HOUR_CEILING: u32 = 10_000;
const RATE_LIMIT_PER_DAY_CEILING: u32 = 100_000;

fn clamp_rate(field: &str, value: u32, ceiling: u32) -> u32 {
    if value > ceiling {
        tracing::warn!(
            field = field,
            configured = value,
            ceiling = ceiling,
            "rate-limit value exceeds ceiling; clamping (operator misconfig?)"
        );
        ceiling
    } else {
        value
    }
}

impl AppConfig {
    /// Load config from `config.toml` (or `$FORSETI_CONFIG_PATH`) plus `FORSETI_*` env overrides.
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("FORSETI_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());
        let mut cfg: AppConfig = Figment::new()
            .merge(Toml::file(&path))
            .merge(Env::prefixed("FORSETI_").split("__"))
            .extract()?;
        cfg.clamp_rate_limits();
        Ok(cfg)
    }

    /// Clamp every rate-limit-bearing knob to its sanity ceiling.
    /// `0` is preserved (it's the documented "disable bucket" sentinel).
    fn clamp_rate_limits(&mut self) {
        self.claim_email.rate_limit_per_minute = clamp_rate(
            "claim_email.rate_limit_per_minute",
            self.claim_email.rate_limit_per_minute,
            RATE_LIMIT_PER_MINUTE_CEILING,
        );
        self.claim_email.rate_limit_per_hour = clamp_rate(
            "claim_email.rate_limit_per_hour",
            self.claim_email.rate_limit_per_hour,
            RATE_LIMIT_PER_HOUR_CEILING,
        );
        self.handoff.rate_limit_per_minute = clamp_rate(
            "handoff.rate_limit_per_minute",
            self.handoff.rate_limit_per_minute,
            RATE_LIMIT_PER_MINUTE_CEILING,
        );
        self.handoff.rate_limit_per_hour = clamp_rate(
            "handoff.rate_limit_per_hour",
            self.handoff.rate_limit_per_hour,
            RATE_LIMIT_PER_HOUR_CEILING,
        );
        if let Some(v) = self.oauth.dcr_ip_rate_per_minute {
            self.oauth.dcr_ip_rate_per_minute = Some(clamp_rate(
                "oauth.dcr_ip_rate_per_minute",
                v,
                RATE_LIMIT_PER_MINUTE_CEILING,
            ));
        }
        if let Some(v) = self.oauth.dcr_ip_rate_per_hour {
            self.oauth.dcr_ip_rate_per_hour = Some(clamp_rate(
                "oauth.dcr_ip_rate_per_hour",
                v,
                RATE_LIMIT_PER_HOUR_CEILING,
            ));
        }
        if let Some(v) = self.oauth.dcr_iat_daily_limit {
            self.oauth.dcr_iat_daily_limit = Some(clamp_rate(
                "oauth.dcr_iat_daily_limit",
                v,
                RATE_LIMIT_PER_DAY_CEILING,
            ));
        }
        if let Some(v) = self.oauth.device_verify_ip_rate_per_minute {
            self.oauth.device_verify_ip_rate_per_minute = Some(clamp_rate(
                "oauth.device_verify_ip_rate_per_minute",
                v,
                RATE_LIMIT_PER_MINUTE_CEILING,
            ));
        }
        if let Some(v) = self.oauth.device_verify_ip_rate_per_hour {
            self.oauth.device_verify_ip_rate_per_hour = Some(clamp_rate(
                "oauth.device_verify_ip_rate_per_hour",
                v,
                RATE_LIMIT_PER_HOUR_CEILING,
            ));
        }
    }
}

#[cfg(test)]
impl AppConfig {
    /// Reusable test config: every sub-config from its `Default`, with the
    /// four no-default sections (kratos/hydra/self/brand) stubbed. Mutate the
    /// fields a given test cares about rather than hand-building the literal.
    pub(crate) fn test_fixture() -> Self {
        Self {
            kratos: KratosConfig {
                public_url: "http://kratos:4433".into(),
                admin_url: "http://kratos:4434".into(),
            },
            hydra: HydraConfig {
                public_url: "http://hydra:4444".into(),
                admin_url: "http://hydra:4445".into(),
            },
            self_: SelfConfig {
                url: "http://localhost:3000".into(),
            },
            brand: BrandConfig {
                name: "Test".into(),
                support_email: None,
                logo_url: None,
                consent_intro: String::new(),
                theme_preset: None,
                brand_primary: None,
                brand_on_primary: None,
                brand_secondary: None,
            },
            apps: Vec::new(),
            oauth: OAuthConfig::default(),
            admin: AdminConfig::default(),
            database: DatabaseConfig::default(),
            audit: AuditConfig::default(),
            internal: InternalConfig::default(),
            license: LicenseConfig::default(),
            identity: IdentityConfig::default(),
            smtp: SmtpConfig::default(),
            profiles: ProfilesConfig::default(),
            webhook: WebhookConfig::default(),
            claim_email: ClaimEmailConfig::default(),
            handoff: HandoffConfig::default(),
            flash: FlashConfig::default(),
            orgs: OrgsConfig::default(),
            accounts: AccountsConfig::default(),
            saml: None,
            proxy: ProxyConfig::default(),
            security: SecurityConfig::default(),
            posix: PosixConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_cfg(emails: &[&str]) -> AdminConfig {
        AdminConfig {
            allowed_emails: emails.iter().map(|s| s.to_string()).collect(),
        }
    }

    // --- AdminConfig::is_admin ---------------------------------------------

    #[test]
    fn is_admin_exact_match() {
        let cfg = admin_cfg(&["admin@example.com"]);
        assert!(cfg.is_admin("admin@example.com"));
    }

    #[test]
    fn is_admin_case_insensitive() {
        let cfg = admin_cfg(&["Admin@Example.com"]);
        assert!(cfg.is_admin("admin@example.com"));
        assert!(cfg.is_admin("ADMIN@EXAMPLE.COM"));
    }

    #[test]
    fn is_admin_rejects_non_member() {
        let cfg = admin_cfg(&["admin@example.com"]);
        assert!(!cfg.is_admin("user@example.com"));
    }

    #[test]
    fn is_admin_empty_email_false() {
        let cfg = admin_cfg(&["admin@example.com"]);
        assert!(!cfg.is_admin(""));
    }

    #[test]
    fn is_admin_empty_allowlist_always_false() {
        let cfg = admin_cfg(&[]);
        assert!(!cfg.is_admin("admin@example.com"));
        assert!(!cfg.is_admin(""));
    }

    // --- DatabaseConfig::looks_like_production -----------------------------

    #[test]
    fn looks_like_production_true_for_public_https() {
        assert!(DatabaseConfig::looks_like_production(
            "https://forseti.example.com"
        ));
        assert!(DatabaseConfig::looks_like_production(
            "https://forseti.example.com/"
        ));
    }

    #[test]
    fn looks_like_production_false_for_http() {
        assert!(!DatabaseConfig::looks_like_production(
            "http://forseti.example.com"
        ));
    }

    #[test]
    fn looks_like_production_false_for_localhost() {
        assert!(!DatabaseConfig::looks_like_production("https://localhost"));
        assert!(!DatabaseConfig::looks_like_production("https://127.0.0.1"));
        assert!(!DatabaseConfig::looks_like_production("https://[::1]"));
    }

    #[test]
    fn looks_like_production_false_for_rfc1918() {
        assert!(!DatabaseConfig::looks_like_production("https://10.0.0.5"));
        assert!(!DatabaseConfig::looks_like_production(
            "https://192.168.1.1"
        ));
        assert!(!DatabaseConfig::looks_like_production("https://172.16.0.1"));
    }

    #[test]
    fn looks_like_production_false_for_ipv6_link_local() {
        assert!(!DatabaseConfig::looks_like_production("https://[fe80::1]/"));
    }

    #[test]
    fn looks_like_production_false_for_ipv6_ula() {
        assert!(!DatabaseConfig::looks_like_production("https://[fc00::1]/"));
    }

    #[test]
    fn looks_like_production_true_for_ipv6_documentation_prefix() {
        // 2001:db8::/32 is RFC 3849 documentation space, reserved for
        // examples, not private use. Treated as production-shaped.
        assert!(DatabaseConfig::looks_like_production(
            "https://[2001:db8::1]/"
        ));
    }

    #[test]
    fn looks_like_production_false_for_malformed_url() {
        assert!(!DatabaseConfig::looks_like_production("not a url"));
        assert!(!DatabaseConfig::looks_like_production(""));
    }

    #[test]
    fn database_backend_picks_postgres() {
        let cfg = DatabaseConfig {
            url: "postgres://u:p@host/db".into(),
            skip_migrations: false,
        };
        assert_eq!(cfg.backend(), DatabaseBackend::Postgres);
        let cfg2 = DatabaseConfig {
            url: "postgresql://u:p@host/db".into(),
            skip_migrations: false,
        };
        assert_eq!(cfg2.backend(), DatabaseBackend::Postgres);
    }

    #[test]
    fn database_backend_defaults_sqlite() {
        let cfg = DatabaseConfig {
            url: "sqlite://./forseti.db".into(),
            skip_migrations: false,
        };
        assert_eq!(cfg.backend(), DatabaseBackend::Sqlite);
        let cfg2 = DatabaseConfig {
            url: "garbage".into(),
            skip_migrations: false,
        };
        assert_eq!(cfg2.backend(), DatabaseBackend::Sqlite);
    }

    // --- SelfConfig::is_https ----------------------------------------------

    #[test]
    fn is_https_true_for_https() {
        let c = SelfConfig {
            url: "https://forseti.example.com".into(),
        };
        assert!(c.is_https());
    }

    #[test]
    fn is_https_false_for_http() {
        let c = SelfConfig {
            url: "http://forseti.example.com".into(),
        };
        assert!(!c.is_https());
    }

    // --- PosixConfig -------------------------------------------------------

    #[test]
    fn posix_config_defaults() {
        let p = PosixConfig::default();
        assert_eq!(p.uid_base, 1_000_000);
        assert_eq!(p.gid_base, 2_000_000);
        assert_eq!(p.default_shell, "/bin/sh");
        assert_eq!(p.home_prefix, "/home");
        assert_eq!(p.free_seats, 25);
        assert_eq!(p.pam_client_id, "forseti-linux-pam");
        assert!(p.pam_client_secret.is_none());
        assert_eq!(p.device_poll_cap_secs, 90);
        assert_eq!(p.id_token_iat_window_secs, 120);
        assert_eq!(p.mfa_auth_time_window_secs, 300);
    }

    #[test]
    fn posix_default_bands_are_disjoint() {
        let p = PosixConfig::default();
        // user gid band [gid_base, gid_base+size) must not overlap team-gid band.
        assert!(p.group_gid_base >= p.gid_base + p.user_gid_size);
        assert!(p.validate_bands().is_ok());
    }

    #[test]
    fn posix_overlapping_bands_rejected() {
        let mut p = PosixConfig::default();
        p.group_gid_base = p.gid_base; // overlap the user gid band
        assert!(p.validate_bands().is_err());
    }

    // --- clamp_rate_limits -------------------------------------------------

    #[test]
    fn clamp_rate_under_ceiling_is_noop() {
        assert_eq!(clamp_rate("x", 0, 1_000), 0);
        assert_eq!(clamp_rate("x", 50, 1_000), 50);
        assert_eq!(clamp_rate("x", 1_000, 1_000), 1_000);
    }

    #[test]
    fn clamp_rate_over_ceiling_clamps() {
        assert_eq!(clamp_rate("x", 1_001, 1_000), 1_000);
        assert_eq!(clamp_rate("x", 1_000_000, 1_000), 1_000);
        assert_eq!(clamp_rate("x", u32::MAX, 10_000), 10_000);
    }
}
