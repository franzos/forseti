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
    /// Dashboard "Your apps" cards. Optional — section is omitted when empty.
    #[serde(default)]
    pub apps: Vec<AppEntry>,
    /// OAuth2 scope descriptions surfaced on the consent screen.
    #[serde(default)]
    pub oauth: OAuthConfig,
    /// Admin-surface configuration. Defaulting to an empty allowlist means
    /// `/admin/*` is effectively closed until the operator opts in.
    #[serde(default)]
    pub admin: AdminConfig,
    /// Forseti-owned database. Defaulted so a freshly-cloned checkout boots
    /// against a local sqlite file without any explicit config.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Audit log configuration. Defaults are usable without any operator
    /// input except `webhook_token`, which is required for the Kratos
    /// webhook receiver to accept inbound events.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Internal HTTP listener for machine-to-machine endpoints (today: the
    /// audit webhook receiver). Lives on a separate listener so the trust
    /// boundary is configured at the network layer, not policed by
    /// per-handler ACLs.
    #[serde(default)]
    pub internal: InternalConfig,
    /// Commercial-tier license gate. All fields are optional — the OSS
    /// default ships with no license configured, surfaces an upsell on
    /// every gated feature, and uses a 14-day grace window when an
    /// activated license expires.
    #[serde(default)]
    pub license: LicenseConfig,
    /// Identity-management knobs. Today this only carries the
    /// `unverified-prune` TTL; future identity-shaped settings land here.
    #[serde(default)]
    pub identity: IdentityConfig,
    /// SMTP outbound for Forseti-originated mail (invite + claim-email).
    /// Kratos's courier handles its own self-service mail (verification,
    /// recovery); the Forseti-owned mails go through this transport.
    /// Disabled by default — when `enabled = false`, the send sites
    /// log + skip, leaving the token/code accessible via the DB so the
    /// operator can still hand-deliver in dev.
    #[serde(default)]
    pub smtp: SmtpConfig,
    /// Forseti-owned member profiles (bio, links, etc.). Off by default —
    /// flip to true on team/intranet deployments where users want to be
    /// findable; leave off for SaaS deployments where org-mates shouldn't
    /// see each other's profile data.
    #[serde(default)]
    pub profiles: ProfilesConfig,
    /// Outbound webhook signing. Currently used only by the
    /// account-deletion fan-out (`src/webhook.rs`) — payloads are signed
    /// as RFC 8417 Security Event Tokens (EdDSA / Ed25519 JWS, RFC 8037)
    /// and verified by receivers against Forseti's published JWKS at
    /// `/.well-known/webhook-jwks.json`. The key is auto-generated on
    /// first boot when the file is missing.
    #[serde(default)]
    pub webhook: WebhookConfig,
    /// Per-IP rate limits for `/claim-email` + `/claim-email/confirm`.
    /// Defaulted to the historical hardcoded values (5/min, 30/hour) so
    /// production behaviour is unchanged when the section is omitted.
    #[serde(default)]
    pub claim_email: ClaimEmailConfig,
    /// Per-IP rate limits for `/handoff*` plus referrer-cookie TTL.
    /// Caps probing of which `client_id` values exist in Hydra.
    /// Defaults (30/min, 300/hour, 1h cookie) keep legitimate users
    /// untouched while making enumeration slow.
    #[serde(default)]
    pub handoff: HandoffConfig,
    /// One-shot flash cookie + `secret_reveals` row TTLs. Defaults are
    /// 60 seconds for each — long enough for the browser to follow the
    /// redirect on a slow network, short enough that an admin who
    /// navigates away loses the reveal.
    #[serde(default)]
    pub flash: FlashConfig,
    /// Organizations subsystem knobs — active-org cookie TTL and
    /// invite expiry. Defaults: 30 days for the cookie, 7 days for
    /// invites.
    #[serde(default)]
    pub orgs: OrgsConfig,
    /// Deployment-shape knob: is Forseti behind a trusted reverse
    /// proxy that strips and re-adds `X-Forwarded-For` / `X-Real-IP`
    /// / `Forwarded`? Used by the audit middleware (audited client
    /// IP) and the per-IP rate limiters (DCR proxy, handoff,
    /// claim-email). One switch because the underlying question is
    /// the same regardless of consumer.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Operator-supplied secret material. Today this only carries
    /// `cookie_secret`, the master key the flash / active_org /
    /// app_referrer signed-cookie codec mixes with per-cookie salts.
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Operator-supplied secrets. `cookie_secret` seeds the HMAC keys
/// for every Forseti-signed cookie (flash banner, active org,
/// app referrer). Accepts a hex string (`openssl rand -hex 32`) or
/// raw bytes; falls back to a per-boot ephemeral key when unset, so
/// fresh checkouts boot without configuration but production
/// deployments survive restarts.
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
    // Surfaced in templates today as part of the configurable brand block,
    // and reserved for the support-email link on the future error/contact
    // pages. Kept on the parsed struct so the field is documented and
    // validated even before the templates pick it up.
    #[allow(dead_code)]
    pub support_email: Option<String>,
    pub logo_url: Option<String>,
    /// Intro paragraph rendered on `/oauth/consent` above the scope list.
    #[serde(default = "default_consent_intro")]
    pub consent_intro: String,
}

fn default_brand_name() -> String {
    "Forseti".to_string()
}

fn default_consent_intro() -> String {
    "The application below is requesting access to your account.".to_string()
}

/// One card on the dashboard "Your apps" section. Configured per deployment.
///
/// NOTE: a per-app icon used to live here (Material Symbols name). It was
/// dropped because the dashboard template never consumed it. If we want
/// icons back later, reintroduce `pub icon: Option<String>` and surface it
/// in `templates/dashboard.html`.
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
    /// the posted `client_name`. Operators replace the list entirely — if
    /// the key is absent from `config.toml`, the code-baked defaults in
    /// `crate::oauth::register::RESERVED_NAMES_DEFAULT` are used.
    #[serde(default)]
    pub dcr_reserved_names: Option<Vec<String>>,
    /// Per-IP rate limit on `POST /oauth2/register` — max requests per
    /// minute. In-memory, per-process. `None` falls back to the code-side
    /// default (10). Set to `0` to disable the per-minute bucket.
    #[serde(default)]
    pub dcr_ip_rate_per_minute: Option<u32>,
    /// Per-IP rate limit on `POST /oauth2/register` — max requests per
    /// hour. Enforced in parallel with the per-minute bucket. `None`
    /// falls back to 100. Set to `0` to disable the per-hour bucket.
    #[serde(default)]
    pub dcr_ip_rate_per_hour: Option<u32>,
    /// Per-IAT registration cap over a rolling 24-hour window opened by
    /// the first successful use. Counts successful registrations only
    /// (failed lookups, reserved-name rejects, Hydra failures don't
    /// count). `None` falls back to 50. Set to `0` to disable.
    #[serde(default)]
    pub dcr_iat_daily_limit: Option<u32>,
}

/// Admin-surface gating. Operators add the emails of users who should be
/// allowed through `/admin/*` here; everyone else gets a 403 even with a
/// valid session. AAL2 is enforced separately at the route guard.
///
/// Why a config allowlist rather than a Kratos identity-schema role: the
/// Forseti is operator-deployed infrastructure — keeping admin membership
/// in declarative config (a single source of truth, easy to diff in
/// version control) is simpler than carrying a `role` trait through the
/// schema and writing migrations for it. The trade-off is that adding a
/// new admin requires a config reload rather than a database write; for
/// the small number of operators this is aimed at, that's a feature.
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

/// Forseti-owned database. Separate from the Kratos/Hydra Postgres — schema
/// isolation, independent backups, no risk of colliding with Ory migrations.
///
/// The URL scheme picks the backend: `sqlite://...` or `postgres://...`. The
/// default — sqlite at `./forseti.db` next to the binary — is deliberate
/// self-hoster ergonomics. Operators who want Postgres set this explicitly.
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
                // NOT treated as non-prod — it's reserved for examples, not
                // private deployments.
                true
            }
        }
    }
}

/// Audit log configuration.
///
/// `webhook_token` gates the `/internal/audit/kratos` receiver and must be
/// shared with the Kratos config (`FORSETI_AUDIT__WEBHOOK_TOKEN` env var).
/// Forseti refuses to boot when this is empty — the audit webhook
/// endpoint requires bearer authentication and a misconfigured deployment
/// should fail loudly at startup rather than silently accept (or reject)
/// every inbound event.
///
/// `ip_salt` is optional. If unset, the salt is derived from `self.url`
/// plus a domain constant in `audit::ip_salt()`, mirroring the pattern in
/// `flash.rs`. Operators who want to rotate IP hashing without rotating
/// flash signatures set this explicitly.
///
/// `audit_retention_days` is the default for the `audit-prune` subcommand
/// when invoked without an explicit override.
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

/// Internal listener configuration. Today this binds the audit webhook
/// receiver; future machine-to-machine endpoints land on the same listener.
///
/// The default `127.0.0.1:8081` keeps the surface invisible from outside
/// the host — operators running Forseti inside a container or behind a
/// reverse proxy override `bind` to `0.0.0.0:8081` (or a specific private
/// interface) so Kratos in another container can reach it.
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

/// SMTP connection scheme. Picks lettre's transport builder at runtime:
/// plaintext goes through `builder_dangerous`, STARTTLS and SMTPS go
/// through the typed `relay`/`starttls_relay` constructors so a TLS
/// config slip is an init error rather than a `None.unwrap()` later.
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
    /// Gates `/settings/profile`'s extended-fields form, the public
    /// `/users/{id}` view, the members-roster link, and the
    /// `extended_profile` OIDC scope. Off by default — operators opt in
    /// per deployment.
    #[serde(default)]
    pub enabled: bool,
}

fn default_audit_retention_days() -> i64 {
    90
}

/// Commercial-tier configuration. Only two knobs the operator can tune —
/// where to send "upgrade" CTAs and how long the post-expiry grace window
/// runs. The signed license blob itself lives in the `forseti_license` DB
/// table; activation happens at `/admin/license`, not in `config.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct LicenseConfig {
    /// URL surfaced as the "Upgrade" CTA on the upsell page and lock
    /// badges. Empty default falls back to a mailto: link built from
    /// `brand.support_email` at render time.
    #[serde(default)]
    pub purchase_url: String,
    /// Days an expired license stays in "read-only" mode before gated
    /// features hard-gate. Default 14 — long enough that a forgotten
    /// renewal doesn't blow up production, short enough that the
    /// expired-banner stays scary. Override (e.g. `0`) for testing the
    /// hard-gate path.
    #[serde(default = "default_grace_days")]
    pub grace_days: i64,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            purchase_url: String::new(),
            grace_days: default_grace_days(),
        }
    }
}

fn default_grace_days() -> i64 {
    14
}

/// Identity-management knobs. Defaulted so the OSS deployment ships
/// reasonable values without `[identity]` in `config.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// Reaper window for the `unverified-prune` CLI / cron. Identities
    /// whose verifiable addresses include at least one unverified entry
    /// and whose `created_at` is older than this many days are deleted.
    /// Default 7 — aggressive but reasonable (GitHub uses 30, which is
    /// fine for a consumer site but too leniant for a single-tenant
    /// Forseti deployment where an unverified squatter blocks the legitimate owner
    /// for weeks). Operators dial up when they have a slower-onboarding
    /// flow.
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

/// Outbound-webhook signing config. Forseti owns one Ed25519 (EdDSA) key
/// that signs every account-lifecycle Security Event Token (see
/// `src/webhook.rs`). Receivers verify with the public half via the JWKS
/// endpoint at `/.well-known/webhook-jwks.json`.
///
/// `signing_key_path` is the on-disk PEM (PKCS#8) file. When missing on
/// boot, Forseti auto-generates a fresh Ed25519 key, writes it with `0600`
/// permissions, and logs a warning so the operator knows to back it up.
/// Same idiom as the sqlite default — self-hoster ergonomics first;
/// production deployments override.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    #[serde(default = "default_webhook_signing_key_path")]
    pub signing_key_path: String,
    /// Worker poll interval (seconds). The worker wakes every tick to
    /// drain the CONFIRMED outbox; lowering this trades CPU for delivery
    /// latency, raising it trades latency for less DB pressure.
    #[serde(default = "default_webhook_tick_seconds")]
    pub tick_seconds: u64,
    /// Maximum delivery attempts before a row is dead-lettered.
    #[serde(default = "default_webhook_max_attempts")]
    pub max_attempts: i32,
    /// Hard age cap (hours). A row that's been around longer than this
    /// gets dead-lettered on the next attempt regardless of
    /// `max_attempts` — guards against rows wedged by clock skew or
    /// permanently-broken receivers.
    #[serde(default = "default_webhook_max_age_hours")]
    pub max_age_hours: i64,
    /// Exponential-backoff ceiling (seconds). Retries grow as
    /// `60s * 2^attempts` capped at this value, with ±25% jitter.
    #[serde(default = "default_webhook_backoff_cap_seconds")]
    pub backoff_cap_seconds: i64,
    /// How long a worker holds a claim on an outbox row (seconds). The
    /// HTTP send has a 10s timeout, so the default 60s leaves comfortable
    /// room for bookkeeping. If a worker crashes between claim and send,
    /// the row becomes visible again after this window.
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

/// Per-IP rate-limit knobs for the Forseti-owned `/claim-email` flow.
///
/// The 6-digit one-time code on the claim-email confirm step is ~20
/// bits of entropy. The per-mint attempt cap (`MAX_CLAIM_CODE_ATTEMPTS`
/// in `identity::claim_email`) bounds one mint; without a per-IP cap an
/// attacker can mint repeatedly and grind in parallel. Defaults
/// (5/min + 30/hour) keep a legitimate user (mint → retype once or
/// twice) well inside the budget while making distributed grind take
/// days, not hours.
///
/// Operators dial these up in dev so integration tests (which share
/// the loopback bucket) don't 429 on subsequent runs.
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

/// Per-IP rate limits for `/handoff*` (RP-initiated account-management
/// deep-links). The handler hits Hydra's admin API on every entry —
/// without a cap, an attacker can probe for which `client_id` values
/// exist via timing or load on Hydra. The uniform 400 in
/// `invalid_referrer()` collapses the response body across all
/// validation failures; this knob caps the rate.
///
/// Defaults (30/min, 300/hour, 1h cookie) match the historical
/// hardcoded values and stay well above any legitimate user's pattern
/// (handoff entries are once-per-session, not per-page-view).
#[derive(Debug, Clone, Deserialize)]
pub struct HandoffConfig {
    #[serde(default = "default_handoff_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_handoff_per_hour")]
    pub rate_limit_per_hour: u32,
    /// TTL for the signed `forseti_app_referrer` cookie that drives the
    /// "Return to <App>" banner. After this elapses the banner stops
    /// appearing — the user is firmly back inside Forseti.
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

/// Flash cookie + secret-reveal TTLs. Both default to 60 seconds —
/// long enough for the browser to follow a redirect on a slow link
/// but short enough that a navigated-away admin loses the reveal.
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

/// Organizations subsystem TTLs. `active_org_cookie_ttl_seconds` is
/// how long the signed `forseti_active_org` cookie stays valid; 30
/// days matches the documented "session" feel of org switching.
/// `invite_ttl_days` is how long a freshly minted org invitation can
/// be redeemed before it expires — 7 days balances "let the invitee
/// see it next week" against "expired stale invites stop being
/// claimable."
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

/// Sanity ceilings for rate-limit knobs. An operator typo
/// (`per_window = 1_000_000`) shouldn't silently disable protection —
/// any value above the ceiling is clamped at config-load time with a
/// `tracing::warn!` so it's visible at boot. Ceilings are generous for
/// any legitimate Forseti rate-limited endpoint and act as a misconfig
/// sentinel.
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
        // 2001:db8::/32 is RFC 3849 documentation space — reserved for
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
