# Operator Guide

A reference for deploying `forseti` as the self-service UI and OAuth2 login/consent bridge for an Ory Kratos + Ory Hydra installation at, for example, `accounts.example.com`.

This guide assumes self-hosting the full stack: `forseti`, Kratos, Hydra, and Postgres. It does not assume prior familiarity with Kratos's surface area.

For app-developer documentation on how downstream applications consume Forseti as an OIDC Provider, see [`integration-guide.md`](./integration-guide.md). For project status and milestones, see [`../README.md`](../README.md) and [`../ROADMAP.md`](../ROADMAP.md).

## What this is

`forseti` is a Rust + Axum self-service UI for Ory Kratos and an OAuth2 login/consent/logout bridge for Ory Hydra. It renders Kratos's self-service flows (login, registration, recovery, verification, settings) and implements the three handlers Hydra delegates to the IdP: `/oauth/login`, `/oauth/consent`, `/oauth/logout`. Branding is config-driven; there are no hardcoded organization names. Licensing: AGPL-3.0-or-later for the OSS core, with `src/commercial/` under the proprietary source-available Forseti Commercial License 1.0 — see the [License section of the README](../README.md#license).

## Deployment topology

The recommended shape is **path-prefixed on a single host**: Forseti at the root, Hydra under `/hydra/*`, Kratos under `/kratos/*`. Everything is same-origin, cookies are host-only, no CORS to configure, only `:443` exposed. Hydra's production guide explicitly endorses this layout. The subdomain shape (`accounts.example.com` / `hydra.example.com` / `kratos.example.com`) is also supported when there's a reason to split — different rate-limit tiers, independent WAF rules, splitting Hydra to its own cluster. See [`operator-guide-proxy.md`](./operator-guide-proxy.md) for the comparison and haproxy configs.

```
                          Internet
                             |
                             v
                  +-----------------------+
                  |     Reverse proxy     |  TLS termination
                  |    (haproxy / nginx)  |  X-Forwarded-* headers
                  +-----------------------+      strip /hydra and /kratos prefixes
                             |
                             v
                  accounts.example.com:443
                     /        |         \
                    /         |          \
                   v          v           v
                  /        /hydra/*    /kratos/*
                  |           |            |
                  v           v            v
            +-----------+  +--------------+  +----------------+
            | forseti|  | Hydra public |  |  Kratos public |
            |   :3000   |  |    :4444     |  |     :4433      |
            +-----------+  +--------------+  +----------------+
                  |              |                  |
                  |  admin calls (server-to-server, on private network)
                  |              |                  |
                  v              v                  v
                  +- (Hydra admin :4445) (Kratos admin :4434) -+
                                       |
                                       v
                                  +--------+
                                  |Postgres|
                                  | :5432  |
                                  +--------+
```

- The reverse proxy is the only ingress. TLS terminates here. `X-Forwarded-Proto: https` and `X-Forwarded-Host` are mandatory — without them Hydra/Kratos emit `http://` URLs and CSRF cookies without `Secure`.
- Forseti listens on `:3000` and serves at the root.
- Hydra's **public** API is served under `/hydra/*` with the prefix stripped before the upstream sees it. Hydra's `issuer` and `public` URLs are set to `https://accounts.example.com/hydra` so discovery emits the right `jwks_uri`, `token_endpoint`, etc.
- Kratos's **public** API is served under `/kratos/*` with the prefix stripped. `serve.public.base_url` is set to `https://accounts.example.com/kratos`. The browser hits Kratos directly for some operations — CSRF token resolution, `whoami` cookie handling, `/.well-known/ory/webauthn.js`.
- Hydra and Kratos do **not** honour subpath mounting natively ([hydra#352](https://github.com/ory/hydra/issues/352), [kratos#1152](https://github.com/ory/kratos/issues/1152)) — the proxy strips the prefix, the upstreams serve at root, and the published URLs carry the prefix because the issuer/base_url config tells them to.
- Kratos's **admin** API (`:4434`) and Hydra's **admin** API (`:4445`) are bound to the internal network. Forseti calls them server-side. Never expose admin APIs through the public proxy.
- Postgres holds the identity store (Kratos), the OAuth2 state and JWKS (Hydra), and Forseti's own data. Internal-only.
- All cookies — Forseti session/CSRF, `ory_hydra_session`, `ory_kratos_session`, plus the per-flow CSRF cookies each service emits — are host-only on `accounts.example.com`, `SameSite=Lax`, `Secure`, `HttpOnly`. Don't set `cookies.domain` on Kratos or Hydra in this shape; host-only is tighter and there's no cross-subdomain traffic to enable.

## Prerequisites

- **Postgres** (>= 13). One database per service: `kratos`, `hydra`, optionally `forseti`. The playground's `init-db.sh` shows the bootstrap pattern.
- **Mail provider.** Mailcrab (used in `infra/docker-compose.yml`) is a development sink. In production, use a real provider. Two pieces of the stack send mail independently: **Kratos** (verification, recovery, MFA-enrol mails) speaks SMTP via `courier.smtp.connection_uri` in `kratos.yml`, and **Forseti** (org-invite + claim-email mails) sends via `[email]` in `config.toml`, which supports Lettermint, Postmark, SendGrid, or an SMTP relay. Both can point at the same SMTP relay.
- **DNS** records pointing `accounts.example.com`, `kratos.example.com`, and `hydra.example.com` (or a single hostname with path-based routing) at the reverse proxy.
- **TLS certificates.** Let's Encrypt via Caddy or `certbot`, or a managed cert solution.
- **Container runtime** if running Forseti as a container, or a Linux host with a writable working directory if running the static binary.

## Configuration

Forseti loads configuration from `config.toml` (or the path in `$FORSETI_CONFIG_PATH`) and overlays environment variables prefixed with `FORSETI_`. Section separator is a double underscore: `FORSETI_KRATOS__PUBLIC_URL` sets `kratos.public_url`.

The authoritative schema is `src/config.rs`. The example file is `config.example.toml`. Every key:

### `[kratos]`

| Key          | Type   | Default | Description                                                                                          |
|--------------|--------|---------|------------------------------------------------------------------------------------------------------|
| `public_url` | string | —       | Browser-facing Kratos URL. Forseti redirects users here to initialize flows and proxies cookies. |
| `admin_url`  | string | —       | Server-only Kratos admin URL. Used for identity reads, session enumeration, session revocation.     |

### `[hydra]`

| Key          | Type   | Default | Description                              |
|--------------|--------|---------|------------------------------------------|
| `public_url` | string | —       | Public Hydra issuer URL (token endpoint, JWKS, OAuth2 endpoints). |
| `admin_url`  | string | —       | Server-only Hydra admin URL. Used to fetch and accept login/consent/logout challenges. |

### `[self]`

| Key   | Type   | Default | Description                                                              |
|-------|--------|---------|--------------------------------------------------------------------------|
| `url` | string | —       | Forseti's own externally reachable URL. Used to build `return_to` round-trips. |

### `[security]`

| Key                | Type   | Default            | Description                                                            |
|--------------------|--------|--------------------|------------------------------------------------------------------------|
| `cookie_secret`    | string | ephemeral per-boot | Seeds the HMAC keys for every Forseti-signed cookie. Long random secret. |
| `frame_ancestors`  | string | `"'self'"`         | CSP `frame-ancestors` on every public_app response. `"'none'"` blocks framing entirely. |
| `x_frame_options`  | bool   | `true`             | Also emit `X-Frame-Options: SAMEORIGIN` for older browsers.            |

`cookie_secret` is the root key behind the HMAC for Forseti's signed cookies (one-shot flash, `active_org` switcher, `forseti_app_referrer` handoff, CSRF double-submit). Each cookie derives its own key from this secret plus a per-use domain-separation salt (see `src/flash.rs`, `src/orgs/cookie.rs`, `src/handoff/cookie.rs`).

Generate one with `openssl rand -hex 32` (a hex string is decoded to bytes; anything that isn't valid hex is taken as raw UTF-8 bytes). The decoded key must be at least 32 bytes or Forseti hard-fails at boot. Override via `FORSETI_SECURITY__COOKIE_SECRET`.

When unset, Forseti generates a 32-byte ephemeral key per process and logs a warning. That means flash, active-org, and app-referrer cookies don't survive a restart, and separate instances can't validate each other's cookies — so **set `cookie_secret` in production** and on any multi-instance deployment. None of these are Forseti's session cookie (that's Kratos), and none are catastrophic on their own (the flash banner is short-lived, the org cookie's selection is re-validated at use, the handoff cookie's `referrer_uri` is re-checked against the Hydra client), but a stable secret avoids the restart churn.

CSRF protection uses a double-submit token (`src/csrf.rs`) keyed off the same secret; there's nothing extra to configure for it.

### `[brand]`

| Key             | Type   | Default            | Description                                                            |
|-----------------|--------|--------------------|------------------------------------------------------------------------|
| `name`          | string | `"Forseti"`     | Brand name shown in the header, page titles, and email templates.      |
| `support_email` | string | none               | Support address rendered in footer / error pages.                      |
| `logo_url`      | string | none               | Optional logo URL. When omitted, the brand name is rendered as text.   |
| `consent_intro` | string | (generic sentence) | Intro paragraph rendered on `/oauth/consent` above the scope list.     |
| `theme_preset`  | string | none               | Global theme preset applied to every page: `default`, `midnight`, or `cyberpunk`. Each derives its own dark-mode variant automatically. A per-org preset overrides this within that org's scope. |
| `brand_primary` | string | none               | Global primary brand colour (`#rrggbb`). Overrides the preset's primary. |
| `brand_on_primary` | string | none            | Foreground colour used on top of `brand_primary` (`#rrggbb`); set it to keep text legible on a custom primary. |
| `brand_secondary`  | string | none            | Secondary / accent brand colour (`#rrggbb`). |
| `operator_trust_anchor` | string | none | Operator identity shown on pre-auth cards (login, consent, device verify). The strongest anti-phishing lever against a tenant impersonating the operator brand — never set this from tenant-controlled input. |

### `[[apps]]`

Zero or more entries. Each renders a card on the dashboard's "Your apps" section. Omit the section to hide the dashboard block.

| Key           | Type   | Default | Description                                                                       |
|---------------|--------|---------|-----------------------------------------------------------------------------------|
| `name`        | string | —       | Card title.                                                                       |
| `description` | string | `""`    | One-line description under the title.                                             |
| `url`         | string | —       | Link target.                                                                      |

### `[database]`

Forseti-owned database. Separate from the Kratos/Hydra Postgres — schema isolation, independent backups, no risk of colliding with Ory's migrations. Both sqlite and Postgres are first-class backends.

| Key               | Type    | Default                  | Description                                                                                                                                          |
|-------------------|---------|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `url`             | string  | `"sqlite://./forseti.db"` | `sqlite://path/to/file.db` (or a bare path) for single-binary self-hosters; `postgres://user:pass@host/db` for HA. URL scheme picks the backend.    |
| `skip_migrations` | bool    | `false`                  | When `true`, the boot-time migration run is skipped. Use this when schema changes are gated through a deploy pipeline instead of the running binary. |

Defaulting to sqlite-next-to-the-binary is deliberate: clone, run, get a working Forseti with persistent state. Operators who want Postgres set `[database]` explicitly.

**Multi-instance sqlite footgun.** sqlite + multiple Forseti instances corrupts the database. Forseti can't see other instances, only deployment shape — so at boot it logs a `warn!` and surfaces a banner on `/admin/status` when the backend is sqlite *and* `self.url` is `https://` with a non-loopback / non-RFC1918 host. Switch to Postgres for any HA setup.

Migrations run on startup by default (`FORSETI_DATABASE__SKIP_MIGRATIONS=1` to opt out). The two backends carry parallel SQL files under `migrations/{sqlite,postgres}/`.

The playground compose file ships a dedicated `forseti-postgres` sidecar on `127.0.0.1:5450` (separate from the Kratos/Hydra postgres, per the design's schema-isolation goal). Smoke-boot the Postgres path with:

```bash
FORSETI_DATABASE__URL="postgres://forseti:secret@localhost:5450/forseti" cargo run
```

### `[internal]`

| Key    | Type   | Default            | Description                                                                                                                          |
|--------|--------|--------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `bind` | string | `"127.0.0.1:8081"` | Bind address for the internal listener (the audit webhook receiver and the POSIX resolver). Never expose this on a public interface — see [Internal listener](#internal-listener). |

The `[posix]` table (uid/gid bases, default shell, home prefix, free-tier seat cap) is documented in [Linux authentication → `[posix]`](#posix).

### `[email]`

Forseti-owned outbound mail (org invites + claim-email). Kratos's courier handles its own self-service mail separately. Optional — omit the section (or set `enabled = false`) and the send sites log + skip so dev still works with the token / code accessible via the DB. Backed by [polymail](https://github.com/franzos/polymail-rs): `provider` selects the transport and the remaining fields are that provider's credentials, flattened in directly under `[email]`.

Sender identity and switch:

| Key            | Type   | Default | Description                                                                                     |
|----------------|--------|---------|-------------------------------------------------------------------------------------------------|
| `enabled`      | bool   | `true`  | Master switch. When `false` (or the section is absent), Forseti logs the would-be recipient and returns without sending. |
| `from_address` | string | —       | From address. Falls back to `noreply@<self.url host>` when unset. Required when `enabled = true`. |
| `from_name`    | string | —       | Optional display name paired with `from_address`.                                               |
| `provider`     | string | —       | Transport: `lettermint`, `postmark`, `sendgrid`, or `smtp`.                                      |

Provider fields (only those matching the chosen `provider`):

| Provider     | Fields                                                                                                        |
|--------------|--------------------------------------------------------------------------------------------------------------|
| `lettermint` | `token` (source from `FORSETI_EMAIL__TOKEN` in prod)                                                          |
| `postmark`   | `token` (source from `FORSETI_EMAIL__TOKEN` in prod)                                                          |
| `sendgrid`   | `api_key` (note: not `token`; source from `FORSETI_EMAIL__API_KEY`)                                           |
| `smtp`       | `host`; `port` (optional, defaults per `tls`: 465 implicit, 587 start_tls); `tls` one of `none`/`start_tls`/`implicit` (default `implicit`); `user`; `pass` (source from `FORSETI_EMAIL__PASS`) |

Environment variables override TOML field by field (Figment, `FORSETI_` prefix, `__` for nesting), so leave secrets blank in the file and inject them at runtime. polymail refuses to send SMTP credentials over `tls = "none"`, and Forseti fails startup on an enabled provider with a blank token / missing `from_address`.

### `[webhook]`

Outbound webhook signing (today: account-deletion fan-out, signed as RFC 8417 Security Event Tokens). Receivers verify via the JWKS at `/.well-known/webhook-jwks.json`.

| Key                | Type   | Default                          | Description                                                                                                                                                |
|--------------------|--------|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `signing_key_path` | string | `"data/webhook-signing-key.pem"` | On-disk PEM (PKCS#8) Ed25519 key. When missing on boot, Forseti auto-generates a fresh Ed25519 key, writes it `0600`, and logs a warning — back it up. Forseti uses Ed25519 (RFC 8037) per NIST SP 800-131A Rev 3 §5.6.4; a file at this path that isn't a valid Ed25519 PKCS#8 PEM is a hard startup error — remove or replace it. |

#### Rotating the webhook signing key

Rotation is a stop-replace-restart procedure today. There's no key-rollover window — Forseti signs every SET with whatever key it loaded at boot, and `kid` is derived deterministically from the public key, so a key swap means a new `kid`.

1. Generate a new PEM (Ed25519, PKCS#8) out-of-band, or just delete the existing file and let Forseti regenerate on boot.
2. Stop Forseti.
3. Replace `data/webhook-signing-key.pem` (mode `0600`, owned by the service user).
4. Start Forseti. It logs the new `kid` and serves the new public key at `/.well-known/webhook-jwks.json`.

**In-flight deliveries** queued before the swap are already signed with the old `kid` and stay in the outbox. They'll deliver successfully against receivers that re-fetch JWKS on `kid` miss (the integration guide recommends this — see *Idempotency and retries*). Receivers that cache JWKS aggressively and don't refetch on miss will reject them; if you have such integrators, drain `webhook_outbox` (wait for `CONFIRMED` count to reach 0) before rotating.

Keep at least one backup of the previous key for forensic verification of historical SETs. Don't reuse `kid`s.

### `[oauth.scope_descriptions]`

Map of scope name to human-readable description, surfaced on `/oauth/consent`. Unknown scopes fall back to the raw scope name. Example:

```toml
[oauth.scope_descriptions]
openid         = "Sign you in with your account"
email          = "Access your verified email address"
profile        = "View your basic profile (name)"
# `offline_access` is the OIDC Core 1.0 §11 standard name. `offline` is a
# Hydra-ism kept as a back-compat alias — both map to the same "issue a
# refresh token" semantics. Prefer `offline_access` for new clients.
offline_access = "Stay signed in by issuing refresh tokens"
offline        = "Stay signed in by issuing refresh tokens"
```

### `[oauth]` — DCR knobs

Per-IP / per-IAT rate limiting on `POST /oauth2/register`, plus the reserved-name denylist. Defaults are set in code; override per-deployment when needed. See [Dynamic Client Registration (RFC 7591)](#dynamic-client-registration-rfc-7591) for the full picture.

| Key                        | Type     | Default          | Description                                                                                                                                                |
|----------------------------|----------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `dcr_ip_rate_per_minute`   | u32      | `10`             | Per-IP rate limit on `POST /oauth2/register` — max requests per minute. In-memory, per-process. `0` disables this bucket.                                  |
| `dcr_ip_rate_per_hour`     | u32      | `100`            | Per-IP rate limit — max requests per hour. Enforced in parallel with the per-minute bucket. `0` disables.                                                  |
| `dcr_iat_daily_limit`      | u32      | `50`             | Per-IAT cap on successful registrations over a rolling 24h window opened by first use. `0` disables.                                                       |
| `dcr_reserved_names`       | string[] | (code-baked set) | DCR `client_name` denylist. Case-insensitive substring match. When the key is absent from `config.toml`, the defaults in `crate::oauth::register::RESERVED_NAMES_DEFAULT` are used; setting the key replaces the list entirely. |

Whether the per-IP limiter trusts forwarded-for headers is a single deployment-wide knob: `[proxy] trust_forwarded_for` (see below). The same flag drives the audit middleware (audited client IP) and the handoff + claim-email limiters — the underlying question ("is there a trusted reverse proxy?") doesn't change per-endpoint.

Every rate-limit knob across `[oauth]`, `[claim_email]`, and `[handoff]` is clamped at config-load time to a sanity ceiling — `1_000` per minute, `10_000` per hour, `100_000` per day. A clamped value emits a `tracing::warn!` at boot so an operator typo (`per_minute = 1_000_000`) is loud rather than silent. `0` is preserved as the documented "disable this bucket" sentinel.

### `[auth]` configuration

Per-IP + global rate limiting on `GET /registration`. These knobs apply to **every** Kratos-flow registration, not just external-org self-serve joins — `/registration` carries no per-org dimension in the URL (the target org lives inside the opaque Kratos flow), so there's no cheap way to key a bucket per org.

| Key                                    | Type | Default | Description                                                                                                    |
|-----------------------------------------|------|---------|------------------------------------------------------------------------------------------------------------------|
| `registration_ip_rate_per_minute`      | u32  | `10`    | Per-IP rate limit on `GET /registration`, requests per minute. `0` disables the bucket.                        |
| `registration_ip_rate_per_hour`        | u32  | `60`    | Per-IP rate limit on `GET /registration`, requests per hour, in parallel with the per-minute bucket. `0` disables. |
| `registration_global_rate_per_minute`  | u32  | `120`   | Global (all-callers-share-one-bucket) rate limit, requests per minute. Bounds total traffic even when a spoofed `X-Forwarded-For` defeats the per-IP bucket. `0` disables. |
| `registration_global_rate_per_hour`    | u32  | `1200`  | Global rate limit, requests per hour, in parallel with the per-minute global bucket. `0` disables.             |

These are clamped at load time under the same ceilings as `[oauth]`/`[orgs]`/`[claim_email]`/`[handoff]`. See [External access mode](#external-access-mode-public-self-serve) for what this limiter does and does not cover.

### `[proxy]` — reverse-proxy trust

| Key                    | Type | Default | Description                                                                                                                                                                                                                              |
|------------------------|------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `trust_forwarded_for`  | bool | `false` | Honour `X-Forwarded-For` / `X-Real-IP` / `Forwarded` when deriving the audited client IP and keying per-IP rate limiters. Set `true` ONLY when the upstream reverse proxy strips client-sent forwarded-for headers before re-adding its own — otherwise a direct caller can forge the header and spoof their IP. See [proxy guide](./operator-guide-proxy.md). |

### Environment overrides

Every key is overridable via env var:

```bash
FORSETI_KRATOS__PUBLIC_URL=https://kratos.example.com
FORSETI_KRATOS__ADMIN_URL=http://kratos.internal:4434
FORSETI_AUDIT__WEBHOOK_TOKEN="$(openssl rand -hex 32)"
FORSETI_BRAND__NAME="Example Accounts"
```

Recommended pattern: keep non-secret structural config in `config.toml`, load secrets from env (typically injected by your secrets manager or orchestrator).

## Appearance

Users choose between **System**, **Light**, and **Dark** from a control in the
page footer (on both signed-in pages and the login/registration screens). The
default is **System**, which follows the browser/OS setting.

The choice is stored in a per-browser cookie (`forseti_theme`), not on the
account — it doesn't follow a user across devices or browsers. The server reads
the cookie and renders the theme directly, so there's no flash on load;
operating the control itself requires JavaScript.

Branded deployments: the dark palette flips the brand colour to a light tone by
default. A single brand colour that passes contrast checks on a light
background usually won't on the dark one, so set a dark-mode brand override
under the `html.dark` scope if you ship custom brand colours.

### Language

The UI ships with nine locales: English (`en`, default), German (`de`), French
(`fr`), Spanish (`es`), Italian (`it`), Portuguese (`pt`), Russian (`ru`), Thai
(`th`), and Arabic (`ar`). Arabic renders right-to-left. Kratos's own error and
prompt messages are translated too, so a login failure reads in the visitor's
language rather than falling back to Kratos English.

A visitor picks a language from the footer switcher, which appends `?lang=<code>`
and persists the choice in a per-browser cookie (`forseti_locale`, one year,
`HttpOnly`, `SameSite=Lax`). With no cookie set, Forseti negotiates against the
browser's `Accept-Language` header and falls back to English. The set is
compile-time (translations live in `locales/`, embedded into the binary); there's
no config knob to add or restrict locales at runtime.

## Legal pages

Forseti serves three public, themed legal pages — `/privacy`, `/terms`, and
`/imprint` — linked from the footer on every page. These are **instance-level**
(the operator is the GDPR data controller), not per-org. Out of the box each
serves a short English stub embedded in the binary, meant to be replaced.

To override them, point `[legal].dir` at a directory and drop Markdown files
named `{doc}.{locale}.md` into it, where `doc` is `privacy`, `terms`, or
`imprint` and `locale` is one of the supported subtags (`en`, `de`, `fr`, …).
Resolution per request is `{doc}.{locale}.md` → `{doc}.en.md` → the shipped
default, so `privacy.de.md` serves German visitors while `privacy.en.md` covers
everyone else. You don't have to provide every doc or every language; anything
missing falls back down that chain.

```toml
[legal]
dir = "/etc/forseti/legal"
```

Notes:

- A **set-but-missing or unreadable** `dir` is a startup error (fail fast, not a
  silent fallback). Omit the section entirely to keep the built-in defaults.
- The Markdown is rendered with raw HTML **stripped** (`<script>`, embedded
  `<div>`, etc. are dropped, not emitted), so style the pages with Markdown, not
  inline HTML.
- Files are read on each request (off the async runtime), so editing a file
  takes effect without a restart.

## Admin surface

Forseti exposes an operator-facing admin surface under `/admin/*` for managing the Ory stack from the same UI users sign in through. There is no separate admin binary or out-of-band tooling.

### `[admin]`

| Key              | Type     | Default | Description                                                                 |
|------------------|----------|---------|-----------------------------------------------------------------------------|
| `allowed_emails` | string[] | `[]`    | Lowercased and matched case-insensitively against the session's `traits.email`. Empty list (or omitted section) closes `/admin/*` to everyone. |

Example:

```toml
[admin]
allowed_emails = ["alice@example.com", "ops@example.com"]
```

A config allowlist (rather than a Kratos identity-schema role) keeps admin membership declarative and reviewable in version control. The trade-off is that adding or removing an admin requires a config reload rather than a database write; for the small operator pool this is aimed at, that's a feature.

### Admin access model

There are **two tiers** of admin access. Same `/admin/*` URL prefix, different gates, different blast radius. This trips up operators who assume `[admin].allowed_emails` covers everything under `/admin/*` — it doesn't.

**Tier 1 — Forseti-wide admin (operator).** Reached by hitting `/admin/...` with no `?org=<slug>` query parameter. This is the surface that touches every identity, every Hydra client, every session, every audit row across the deployment. Gated by:

1. **Active Kratos session.** Anonymous requests are 303-redirected to `/login?return_to=...` so the user lands back on the admin page after signing in.
2. **Email allowlist.** The session's `traits.email` must appear in `[admin].allowed_emails`. Non-allowlisted users get a 403 page (rendered inside the admin shell so the rejection is unambiguous).
3. **AAL2.** Single-factor sessions are 303-redirected to `/login?aal=aal2&return_to=...`, forcing Kratos to demand a second factor before granting access.

The order matters: a non-allowlisted user with a valid AAL2 session still gets a 403. An allowlisted user with an AAL1 session is bounced to step-up before being told they're allowed in.

**Tier 2 — Org-scoped admin (org owner).** Reached by hitting `/admin/...?org=<slug>`. This is the surface an org owner uses to manage *their own* org — members, branding, invites, the org-scoped audit feed. Gated by:

1. **Active Kratos session** — same as Tier 1.
2. **Org ownership.** The caller must be an `owner` of the org named by `<slug>` (i.e. an `organization_members` row with `role = 'owner'`). Non-owners — including members with the `member` role and Forseti-wide admins who aren't members of that specific org — get a 403.
3. **AAL2** — same as Tier 1.
4. **Orgs license** — only for non-Default orgs. The Default org's admin surface stays OSS-tier; additional orgs are a commercial feature and a missing/expired license renders the upsell page instead.

**`[admin].allowed_emails` is not checked on Tier 2.** This is deliberate: org owners need to manage their own org without the operator having to add every customer's email to the allowlist. The trust boundary on Tier 2 is "you own this org", not "the operator vouches for you".

What this means in practice:

- A Forseti-wide admin (allowlisted email) who is *not* a member of `acme-corp` gets 403 on `/admin/identities?org=acme-corp`. The operator allowlist doesn't grant org-owner privileges; it grants global-operator privileges, which are a different thing.
- An org owner who is *not* on `[admin].allowed_emails` can manage their own org but cannot access `/admin/identities` (no `?org=`), `/admin/clients`, `/admin/license`, etc. They see a 403 on the global surfaces.
- If you want to restrict who can own an org — e.g. only allow paying customers — gate org creation, not the admin path. Org creation today goes through `/orgs/new` and is itself gated by the Orgs license; layer additional checks at the creation handler or via your billing flow.

The two-tier code lives at `src/admin/mod.rs::require_admin` (Tier 1) and `src/admin/mod.rs::require_admin_with_scope` (Tier 1 + Tier 2 routed by `?org=`).

### Admin pages

| Path                                  | Purpose                                                                                         |
|---------------------------------------|-------------------------------------------------------------------------------------------------|
| `/admin` → `/admin/status`            | Landing redirect.                                                                               |
| `/admin/status`                       | Kratos + Hydra health probes, courier queue (pending / failed counts), build versions, and audit-health counters (write failures + the two audit-webhook counters described below). |
| `/admin/clients`                      | List Hydra OAuth2 clients, filter by name.                                                      |
| `/admin/clients/new`                  | Create a new OAuth2 client. Returns to the show page with a one-time secret + registration access token reveal. |
| `/admin/clients/{id}`                 | View / edit a client. Rotate-secret and delete confirm pages live under here.                   |
| `/admin/identities`                   | List Kratos identities, filter by email (Kratos `credentials_identifier`).                       |
| `/admin/identities/{id}`              | View identity traits, credentials, verifiable addresses, and recent sessions. Trigger recovery codes, disable / enable, or delete from here. |
| `/admin/sessions`                     | List every active session across all identities. Toggle "active only" and revoke individual sessions. |
| `/admin/audit`                        | Append-only audit event log. Filter by email substring, action prefix, severity, and `since` timestamp. Backed by the Forseti-owned `audit_events` table (sqlite or Postgres); retention is operator-configured via `[audit].audit_retention_days` and pruning runs through the `forseti audit-prune` CLI subcommand (not auto-run inside the HTTP server). |
| `/admin/audit/{id}`                   | Full detail page for a single audit row — actor, target, metadata, IP hash, user agent.        |
| `/admin/webhooks`                     | Dead-lettered account-deletion webhook rows (12 attempts or 72 h exhausted). Per-row "Requeue" and "Discard" actions; a count banner surfaces on `/admin/status` when the table is non-empty. |
| `/admin/webhooks/{id}`                | Full detail page for a dead-lettered webhook row — payload, attempt history, last error.       |
| `/admin/webhooks/{id}/requeue`        | POST — flip a `DEAD` row back to `CONFIRMED` so the background worker picks it up again.        |
| `/admin/webhooks/{id}/discard`        | POST — drop the row without further delivery attempts.                                          |
| `/admin/dcr-tokens`                   | List Initial Access Tokens for `POST /oauth2/register`. Issue / revoke from here.               |
| `/admin/dcr-tokens/{id}/revoke`       | POST — revoke an IAT. Future registrations presenting it return 401 with `iat_exhausted`.       |
| `/admin/license`                      | View current license status (Unlicensed / Active / Grace / Expired), tier, expiry. Activate or deactivate from here. |
| `/admin/license/activate`             | POST — verify a pasted signed license blob against the baked-in Ed25519 pubkey and persist.    |
| `/admin/license/deactivate`           | POST — drop the current license row. Premium features fall back to the upsell page.             |
| `/admin/hosts`                        | Enrolled Linux hosts. Enroll a new host (one-time `host_id:secret` reveal), rotate its secret, or revoke it. See [Linux authentication](#linux-authentication). |
| `/admin/posix`                        | POSIX accounts. Provision a Kratos identity into a Linux account, manage its SSH keys, enable/disable/delete. Shows the current seat count against the cap. |

### App templates

`/admin/clients/new` shows a "Popular apps" group below the five base client types. Picking one (GitLab, Nextcloud, Grafana, …) pre-fills the create form for that app — redirect URIs, scope, token-endpoint auth method, PKCE, and any logout/webhook URLs — so you don't have to look up each app's OIDC quirks.

The picker at `/admin/clients/new` is always the source of truth, but the bundled templates are:

| Category | Apps |
| --- | --- |
| First-party | Stackpit, Formshive, Liwan |
| Git, CI/CD & infrastructure | GitLab, Gitea, Forgejo, Jenkins, Argo CD, Harbor, Rancher, Portainer, Proxmox VE, NetBox |
| Files, media & knowledge | Nextcloud, Seafile, Immich, Jellyfin, Audiobookshelf, Paperless-ngx, Outline, BookStack, HedgeDoc |
| Collaboration & productivity | Matrix Synapse, Discourse, Rocket.Chat, Mattermost\*, OpenProject\*, Plane\*, Vikunja, Mealie, Penpot, WordPress |
| Data, monitoring & feeds | Grafana, Apache Superset, Matomo, Miniflux, Open WebUI |
| Other | Mastodon, Vaultwarden, Actual Budget, Atlassian Data Center\* |

\* OIDC login requires that app's paid/enterprise tier — the template still works, but the form's guidance banner flags the licensing requirement.

The pre-filled URLs use literal placeholders you must replace before saving:

- `YOUR_DOMAIN` — the app's own hostname (e.g. `git.example.com`), not Forseti's. Several apps embed it in a fixed callback path.
- `PROVIDER_NAME` — for apps where the callback path includes the provider/auth-source name you configure app-side (Gitea, Forgejo, Vikunja, Paperless-ngx, Jellyfin). Replace it with whatever name you set there; some apps are case-sensitive about it.

Some templates carry a guidance banner on the form (e.g. PROVIDER_NAME notes, audience allow-list reminders) — read it before saving.

The template choice doesn't change the client's type: the stored `client_type` records the base preset (e.g. `web_app`), so the list filter and detail-page badge are unaffected by which app you started from. The template slug itself is recorded Forseti-side (purely so the app's logo can appear next to the client on the list) — it carries no trust or behaviour, and only clients created from a template after this shipped will show a logo.

After creating a client, its detail page (`/admin/clients/{id}`) shows a "Connection details" card with the issuer and OIDC endpoints (authorization, token, userinfo, JWKS, end-session) plus the client ID — everything you paste into the app's OIDC settings on the other end. The endpoints come from Hydra's discovery document; if Forseti can't reach Hydra at render time the card hides the endpoints and shows a note rather than guessing a (possibly wrong) issuer.

### Audit logging

Audit events are persisted to the Forseti-owned `audit_events` table (sqlite or Postgres). The table is **append-only at the DB layer** — a BEFORE UPDATE/DELETE trigger refuses modifications unless the pruner sets a single-transaction override flag (`current_setting('app.audit_purge')` on Postgres, a sentinel row in `_forseti_meta` on sqlite). The flag is defence against application-bug clobbering history, not against a malicious operator with direct DB access.

Three sources feed the table:

1. **Forseti-owned handlers — direct emit.** Logout, settings session revoke, OAuth consent (granted / denied), account self-deletion, every admin action (`/admin/clients/*`, `/admin/identities/*`, `/admin/sessions/*`, `/admin/webhooks/*`).
2. **Kratos flow webhooks** delivered to `POST /internal/audit/kratos` on the **internal listener**. Flow-completion events only: `identity.created` (registration), `auth.login` (login.{password,passkey} — AAL2 step-up methods intentionally don't fire so a single sign-in produces one row, not two), `password.changed` (settings.password), `password.recovered` (recovery), `verification.completed` (verification), `mfa.*` (settings.{totp,webauthn,lookup}). Kratos's admin API does not fire flow hooks, so admin-driven identity writes go through path 1.
3. **Hydra consent decisions** emitted from Forseti's own `src/oauth/consent.rs` (Hydra has thin hook surface; scraping logs is fragile).

#### Internal listener

Machine-to-machine endpoints live on a **separate HTTP listener** from the user-facing Forseti: today the audit webhook receiver (`POST /internal/audit/kratos`) and the POSIX resolver API (`GET /posix/v1/*`, consumed by enrolled Linux hosts' NSS/sshd). The split is the trust boundary — the internal listener should never be reachable from the public internet, while the public listener is built for it.

| Knob              | Default              | What to set in production                                                                                                                |
|-------------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `[internal].bind` | `127.0.0.1:8081`     | Loopback when Forseti and Kratos share a host. Bind to a specific private interface (e.g. `10.0.0.5:8081`) — or `0.0.0.0:8081` inside a container where the trust boundary is the docker / pod network — so Kratos in a separate container can reach it. **Never expose this on a public interface.** |

The internal listener does not mount `/readyz` or `/healthz`; those stay on the public listener so load balancers and orchestrators don't have to know about a second port. CSRF middleware is also not applied to the internal listener — these endpoints take JSON over `POST` (audit webhook) or authenticated `GET` (POSIX resolver), not cookie-bearing browser forms.

**Remote hosts and rebinding.** With the default loopback bind, only processes on the Forseti host can reach the resolver. Linux hosts elsewhere need the listener rebound to a private interface (`10.0.0.5:8081`) behind a firewall that admits only those hosts. Note the audit webhook and the resolver **share this listener** — rebinding to `0.0.0.0:8081` exposes *both*. The resolver authenticates each host with HTTP Basic (`host_id:secret`, SHA-256-hashed, constant-time compared), so its own auth holds, but the audit webhook's bearer token (`[audit].webhook_token`) and a network ACL in front of the listener both matter once it leaves loopback.

#### Audit webhook bearer

The `POST /internal/audit/kratos` endpoint authenticates inbound Kratos webhooks with a shared bearer token (`Authorization: Bearer <token>`). Forseti reads it from `[audit].webhook_token`; Kratos sends it from the `auth.config.value` field on each `web_hook` in `kratos.yml`.

**The token is mandatory.** Forseti refuses to boot when `webhook_token` is empty (exit code `1`, error on stderr): a misconfigured deployment is supposed to fail loudly at startup rather than silently accept or reject every inbound event.

**To rotate, use `forseti config rotate webhook-token`** (see [Rotating the audit webhook token](#rotating-the-audit-webhook-token)) rather than hand-editing both files: it stages the new token in an accept-list so Forseti keeps accepting the old one until every `web_hook` has picked up the new value, avoiding an audit-loss window. Hand-editing both files in one shot works too, but there's no online-rotation path that way. Kratos's Viper-based config loader does not support env-var overrides for fields inside arrays (see [ory/kratos#2663](https://github.com/ory/kratos/issues/2663)), so the token has to be a literal value in `kratos.yml`, and stopping Forseti before both files agree drops every webhook delivered in between. For real production deploys, template the config through your deploy tooling (Helm's `values.yaml`, Terraform, or equivalent) and source the token from your secret manager. Forseti-side value comes from `config.toml` (or `FORSETI_AUDIT__WEBHOOK_TOKEN`), where env-var binding works because Forseti's config is a flat struct.

#### Audit webhook replay protection

Bearer alone lets anyone who captures a single request replay it arbitrarily later — fabricating audit history. The real guard is the internal listener plus the bearer; on top of that the receiver adds a freshness signal:

**Freshness window.** The shared `audit_event.jsonnet` template emits `ctx.flow.issued_at` (RFC 3339) into the body. The receiver flags payloads whose `issued_at` is more than 1 hour old (`stale`) or skewed more than 1 minute into the future (`future`). The window covers the longest Kratos flow lifespan (settings flows default to 1h), so a stale reading means a genuinely old timestamp — replay or clock skew — not a slow user. Flagged payloads are **still recorded**, with a `metadata.freshness` marker, and counted on `/admin/status` (see below). Payloads missing `issued_at` are written unflagged — older Kratos versions omit the field on some hooks. The window is telemetry, not a hard reject: see the response-code note below for why the receiver never drops a parseable payload.

**Responses.** The receiver returns **401** on a missing/wrong bearer and **204** on everything else — accepted, flagged, malformed body, or unknown action. The hooks are fire-and-forget on the Kratos side (`response.ignore: true`), so Kratos never reads the status; the 401/204-only scheme is defence in depth so the receiver can't break a user's self-service flow even if a future Kratos config regresses to a blocking hook. Failures surface out-of-band on `/admin/status` and in `warn!` logs.

**Threat model: what this catches and what it doesn't.** Stripe / GitHub webhook signing computes an HMAC over the body with a shared secret, which catches both replay and tampering. Kratos's `web_hook` action ships static headers only: it can't compute an HMAC at send time. So the bearer + freshness flag is the realistic ceiling without a signing proxy. If your threat model includes a real-time MITM, terminate Kratos behind a reverse proxy that injects an HMAC header (haproxy + lua, nginx + lua, envoy + wasm) and check it in front of Forseti.

#### Audit webhook counters on `/admin/status`

Two in-process counters surface the receiver's out-of-band failure signal. Both reset on Forseti restart — they answer "did anything odd happen since the last boot?", not "what is the all-time total". Non-zero values render a hint on the status page.

- **Audit webhook rejected.** A payload was dropped before any row was written — either a malformed body or an unknown `?action=`. A non-zero count almost always means a Kratos hook or config mismatch (e.g. an `action` not in the receiver's vocabulary, or a template that emits a body the receiver can't parse). Check the `kratos audit webhook` `warn!` log lines for the specifics.
- **Audit webhook freshness anomalies.** A row was written but its `issued_at` fell outside the 1h freshness window — stamped `stale` or `future` in `metadata.freshness`. Usually a slow flow finished after the window or the Kratos / Forseti clocks have drifted. The row is still recorded; the counter is a heads-up to check for clock skew (or, rarely, replay).

#### Default-org floor

Default-org membership used to be driven by a second `web_hook` on the registration flow. That endpoint is gone — Forseti now applies the Default floor **lazily, in the `auto_join_default_org` middleware**, on the user's first authenticated request. No webhook wiring is required for org membership; only audit needs the webhook.

The Default org is a floor, not a permanent auto-join: a user is a member of it only while they hold no other org (allowlisted operators are always in it, as owner). The lazy check is one capped lookup that returns whether the identity is already in Default and how many non-default orgs it holds; when the floor is missing it runs a serialized transaction that inserts the Default row (owner for an allowlisted email, member for a non-default-less non-allowlisted one). Joining any other org drops the floor; leaving one's last other org restores it. See [organizations internals](./dev/organizations-internals.md#membership-the-default-floor-and-the-three-join-doors).

The `audit_metadata` column is operator-readable but goes through a `SafeMetadata` newtype that refuses sensitive-looking keys (`password`, `secret`, `token`, `cookie`, `authorization`, `otp`, `recovery`). Debug builds panic on offending keys; release builds drop them and `warn!` so a stray credential never reaches disk silently.

Sample events:

- `oauth.client.created` / `oauth.client.deleted` / `oauth.client.secret_rotated` — actor + client_id
- `admin.identity.disabled` / `admin.identity.deleted` — actor + identity_id
- `admin.session.revoked` — actor + session_id
- `account.self_deleted` — actor + event_id + webhook_targets count
- `oauth.consent.granted` / `oauth.consent.denied` — actor + client_id + scope
- `auth.logout`, `session.revoked`, `sessions.bulk_revoked` — actor
- `org.invite.created` / `org.invite.accepted` — actor + org_id + invitee email + role
- `org.member.added` / `org.member.removed` / `org.member.role_changed` — actor + identity_id + org_id (+ new role for role_changed)
- `identity.created`, `auth.login`, `password.changed`, `password.recovered`, `verification.completed`, `mfa.*` — flow-driven, delivered via Kratos webhook

#### Retention

Default 90 days, overridable via `[audit].audit_retention_days`. Pruning is **not** auto-run inside the HTTP server — operators schedule the `forseti audit-prune` subcommand via cron / pipeline:

```bash
# In a systemd timer or cron, daily at 03:15 UTC:
forseti audit-prune
```

The subcommand reads the same `config.toml` as the running server, runs migrations idempotently (so a fresh box that never ran the server still works), then deletes rows older than `audit_retention_days` inside a single transaction with the trigger override engaged.

### Known limitations

- **No granular roles inside a tier.** All Tier-1 allowlisted admins have identical privileges across the Forseti-wide surface; all Tier-2 org owners have identical privileges within their org. No read-only or per-surface scoping. Use Kratos's own access logs and the audit feed for fine-grained attribution.
- **Tier-1 allowlist is global.** A single `[admin].allowed_emails` controls operator access for the whole deployment; there's no per-realm partition. For per-customer scoping, use Tier 2 (org-scoped admin) instead (see [Admin access model](#admin-access-model)).
- **No CSV / JSON export.** Audit and identity lists render only in the UI for now.
- **No tamper-evidence (hash chain).** Append-only is enforced by the trigger; for stronger guarantees ship the row stream to an S3 archive with object-lock externally.
- **OIDC sign-ins are unaudited by default.** A `config init`-generated `kratos.yml` carries no audit `web_hook` nodes, so `forseti config oidc enable` has no existing hook to clone onto the new provider's login/registration flows and warns rather than silently leaving a gap (see [Enabling and disabling OIDC providers](#enabling-and-disabling-oidc-providers)). Wiring one up is a manual step today.

## Linux authentication

Forseti can back the login accounts on your Linux hosts. Instead of maintaining `/etc/passwd`, `/etc/group`, and per-user `~/.ssh/authorized_keys` by hand on every box, you provision a Kratos identity into a POSIX account once, and enrolled hosts resolve that account — uid/gid, login shell, home dir, and SSH keys — over a small HTTP API. The identity store stays the source of truth; a host is just a consumer.

This is the server side. The NSS/PAM client and the sshd / Guix wiring that actually plug a host into the resolver ship as the **`forseti-unix`** host client (under `forseti-unix/`, packaged for Guix in `infra/guix/`) — see [Connecting a host](#connecting-a-host) below.

### Trust model

The resolver lives on the **internal listener** (`[internal].bind`, default `127.0.0.1:8081`), the same loopback-by-default port as the audit webhook — see [Internal listener](#internal-listener) for the binding rules and the firewall warning. The short version: with the default bind only processes on the Forseti host reach it; remote hosts need the listener rebound to a private interface behind a firewall that admits only those hosts, and rebinding exposes the audit webhook on the same port.

Each request authenticates with the enrolled host's `host_id:secret` over HTTP Basic (the secret is stored SHA-256-hashed and compared in constant time). That credential is the only thing standing between a caller and your directory once the listener leaves loopback, so treat the network ACL in front of it as load-bearing, not optional. The resolver flow and route table are in [`docs/dev/flows.md` → POSIX resolver API](./dev/flows.md#posix-resolver-api-linux-integration).

### `[posix]`

Account-materialisation knobs plus the interactive PAM device-auth settings. The defaults work out of the box; for the resolver you'll typically only touch `default_shell` (it's OS-specific) and `free_seats`. The device-auth keys (everything below `free_seats`) only matter once you [enable PAM login](#enabling-pam-login-device-auth).

| Key                         | Type            | Default              | Description                                                                                                          |
|-----------------------------|-----------------|----------------------|--------------------------------------------------------------------------------------------------------------------|
| `uid_base`                  | u32             | `1000000`            | First uid handed out. Accounts allocate monotonically upward from here, and ids are never reused. |
| `gid_base`                  | u32             | `2000000`            | First gid handed out for auto-created user-private groups. Deliberately disjoint from the uid space so uids and gids never numerically collide. |
| `user_uid_size`             | u32             | `1000000`            | Size of the user uid band `[uid_base, uid_base + user_uid_size)`.                                                   |
| `user_gid_size`             | u32             | `1000000`            | Size of the user-private gid band `[gid_base, gid_base + user_gid_size)`.                                           |
| `group_gid_base`            | u32             | `3000000`            | First gid handed out for team groups. The team-gid band must not overlap the user-private gid band (Forseti refuses to boot if they collide). |
| `group_gid_size`            | u32             | `1000000`            | Size of the team-gid band `[group_gid_base, group_gid_base + group_gid_size)`.                                      |
| `default_shell`             | string          | `"/bin/sh"`          | Login shell written onto a new account unless overridden per account. OS-specific — `/bin/bash` on Debian, `/run/current-system/profile/bin/bash` on Guix System. `/bin/sh` is the safe default because Guix has no `/bin/bash`. |
| `home_prefix`               | string          | `"/home"`            | Home dir is `{home_prefix}/{username}` unless overridden per account.                                               |
| `free_seats`                | u32             | `25`                 | Free-tier seat cap — how many *enabled* accounts you can provision without a commercial license. See [Seat cap](#seat-cap). |
| `pam_client_id`             | string          | `"forseti-linux-pam"` | The confidential OAuth client id Forseti drives the device grant as for PAM login. Created (if absent) by `forseti posix-init-client`. |
| `pam_client_secret`         | string          | *(unset)*            | `client_secret_basic` secret for `pam_client_id`. Leave unset to let `posix-init-client` mint one (revealed once). **Device-auth hard-fails while this is unset/empty** — see [Enabling PAM login](#enabling-pam-login-device-auth). |
| `device_poll_cap_secs`      | u64             | `90`                 | Hard wall-clock cap (seconds) on a single device-auth poll loop. Keep it strictly **below sshd's `LoginGraceTime`** (default 120s) so an abandoned login can't pin the session. Forseti returns it so the daemon can bound its own polling. |
| `id_token_iat_window_secs`  | u64             | `120`                | `iat` freshness window (seconds) for the device id_token — rejects a token whose `iat` is older than this. A tight replay guard layered on top of `exp`. |
| `mfa_auth_time_window_secs` | u64             | `300`                | `auth_time` freshness window (seconds) for `force_mfa` hosts. An AAL2 session older than this won't unlock such a host — an hours-old MFA shouldn't grant a login. |
| `hydra_issuer`              | string          | *(unset)*            | Expected `iss` on the device id_token. Unset falls back to `[hydra].public_url`. Override when Hydra's own `urls.self.issuer` differs from that URL — see the [gotcha](#enabling-pam-login-device-auth) below. |

```toml
[posix]
uid_base = 1000000
gid_base = 2000000
user_uid_size = 1000000
user_gid_size = 1000000
group_gid_base = 3000000
group_gid_size = 1000000
default_shell = "/bin/sh"
home_prefix = "/home"
free_seats = 25

# Device-auth (PAM login) — only needed once you enable interactive login.
pam_client_id = "forseti-linux-pam"
# pam_client_secret = "..."          # mint via posix-init-client
device_poll_cap_secs = 90
id_token_iat_window_secs = 120
mfa_auth_time_window_secs = 300
# hydra_issuer = "http://localhost:4444"
```

The picked uid/gid bases sit well above the system range so Forseti-managed accounts never clash with packages that create their own service users.

Three numeric bands carve up the space: user uids `[uid_base, uid_base + user_uid_size)`, user-private gids `[gid_base, gid_base + user_gid_size)`, and team gids `[group_gid_base, group_gid_base + group_gid_size)`. The two gid bands must be disjoint, and Forseti validates this at startup, refusing to boot if they overlap, because a team gid colliding with a user-private gid would silently cross-grant file access. Ids are allocated monotonically and never reused (tracked in the `posix_sequences` table): a reused uid/gid would silently reassign ownership of files left on disk or in backups by a deleted account.

### Enrolling a host

A host has to identify itself to the resolver before it can resolve anything.

1. Go to **Admin → Hosts** (`/admin/hosts`), then **New** (`/admin/hosts/new`).
2. Name the host and submit. Forseti mints a `host_id` and a secret and shows the combined `host_id:secret` **once**. Copy it now — it's not stored in retrievable form and you can't see it again.
3. Put that credential into the host client's config — the `host-id` / `host-secret` fields of the `forseti-unix-configuration` (see [Connecting a host](#connecting-a-host)). For a manual check, it's the HTTP Basic username:password the resolver expects.

**Rotating** a host's secret: **Admin → Hosts → the host → Rotate** (`/admin/hosts/{id}/rotate`). This mints a fresh secret, reveals it once, and invalidates the old one immediately — so the host is locked out until you update its config. Rotate on a schedule, or right away if a host's credential might have leaked.

**Editing** a host: **Admin → Hosts → the host → Edit** (`/admin/hosts/{id}/edit`). Change the display name, the `force_mfa` flag, or the team scope (which of the org's teams the host resolves, covered below) after enrollment. A host's **organisation is fixed at enrollment** and can't be changed here; re-enroll under the right org if that has to change.

**Revoking** a host: **Admin → Hosts → the host → Revoke** (`/admin/hosts/{id}/revoke`). The host can no longer resolve anything. Use this when you're decommissioning a box.

**`force_mfa` is enforced on the PAM device-auth login path.** The enroll form captures a `force_mfa` flag against the host, and it's a real control on the [interactive PAM login](#enabling-pam-login-device-auth) — it does *not* gate the NSS resolver (resolving an already-provisioned account is never MFA-gated). For a `force_mfa` host, Forseti only tells the host `approved` when the approving session is a fresh AAL2 login: the id_token's `acr` must be `aal2`, its `amr` must carry a real second factor (TOTP, WebAuthn, or a recovery code — a password alone never counts), and its `auth_time` must fall within `mfa_auth_time_window_secs` (default 300s) so an hours-old MFA can't unlock a login. Forseti also suppresses the one-click `verification_uri_complete` link for these hosts, so the human has to type the user code by hand.

### Provisioning an account

Enrolling a host gives it the *right* to resolve; provisioning is what creates something to resolve.

1. Go to **Admin → POSIX accounts** (`/admin/posix`), then **New** (`/admin/posix/new`). This is a two-step, no-JS flow.
2. **Pick the identity.** Either click **Select user** to open the identity picker (a searchable, org-scoped list of identities — each row has a *Select* link that returns you to the form with that identity filled in), or type a Kratos identity UUID or an email address into the field. A typed email is resolved to its identity against Kratos at submit time. Identities that exist *only* via OIDC/SAML may not resolve by typed email — for those, use the picker; it's the reliable path.
3. **Set the account details.** Once an identity is chosen the form shows its email read-only and carries the resolved UUID. A **username** suggestion derived from the email's local-part is pre-filled and editable. uid, gid, login shell, and home dir default from `[posix]` (uid/gid auto-allocated, shell/home derived) — override them on the form if a particular account needs something specific. The login shell must exist on the device(s) that serve this account; `/bin/sh` is the safe cross-distro default (Guix has no `/bin/bash`).
4. Submit. Forseti creates the POSIX account plus its primary group.

On the account page (`/admin/posix/{id}`):

- **Add SSH keys** — paste a public key (`/admin/posix/{id}/keys`). The resolver serves these to sshd's `AuthorizedKeysCommand`. Remove a key from the same page (`/admin/posix/{id}/keys/{key_id}/delete`).
- **Disable / enable** — toggle the account (`/admin/posix/{id}/disable`, `/admin/posix/{id}/enable`). A disabled account stops resolving (no login, no keys) but its row, uid/gid, and keys are retained, so enabling it again restores the same identifiers. **Disabling frees a seat** — a disabled account doesn't count against the cap.
- **Delete** (`/admin/posix/{id}/delete`) — remove the account and its POSIX rows outright. Deleting the underlying Kratos identity also purges its POSIX rows at every delete path (admin delete, self-service account deletion, the unverified-prune reaper), and an hourly reconcile sweep catches identities deleted out-of-band via the Kratos admin API — so an orphaned POSIX account can't keep a deleted identity's login alive.

### Seat cap

Provisioning a *new* enabled account consumes a seat. The cap depends on your license state:

- **No license (OSS):** up to `[posix].free_seats` enabled accounts (default 25).
- **Commercial license with Linux authentication:** the license's `max_seats` raises the cap. Provisioning beyond it is blocked with a clear message naming the current count and cap.
- **Grace window:** a license that's expired but still in its 30-day grace period falls back to the **free** cap for new provisioning — provisioning a new account is a write, and grace is read-only for writes. Existing accounts keep working.
- **Resolution is never gated.** A host can always resolve an already-provisioned account, regardless of license state. A lapsed or missing license can stop you *adding* accounts; it can never lock an existing user out of a machine they already log in to.

Disabling an account frees its seat (see above); deleting one frees it too. The list page (`/admin/posix`) shows the current `enabled / cap` count so you can see how much headroom you have.

Each host belongs to one organisation (set at enrollment). You can scope a host to the whole org (it resolves all of that org's provisioned members) or to specific **teams** within the org (it resolves only those teams' members). Team membership is resolved live by the resolver at request time — there is no mirroring step, so changes take effect on the next lookup. Creating and managing teams requires the commercial **Organizations** feature; without it a host resolves its org as a whole. Provisioning a POSIX account always also creates that account's own primary group regardless of license.

### Enabling PAM login (device-auth)

The resolver hands a host the *shape* of an account (uid/gid, shell, home, keys). Interactive password/console login — `ssh` with a password, a TTY login, `sudo` re-auth — is a separate path built on the OAuth 2.0 Device Authorization Grant (RFC 8628). The host's PAM module starts a device flow for the named account, the human approves it in their browser, and Forseti binds the approving identity to the named account before the host is told the login is `approved`. The full mechanism is in [`docs/dev/flows.md` → POSIX device-auth login](./dev/flows.md#posix-device-auth-login-rfc-8628).

This path needs one extra thing the resolver doesn't: a confidential OAuth client Forseti authenticates as when it drives the device grant through Hydra.

1. **Mint the client.** Run

   ```sh
   forseti posix-init-client
   ```

   This creates the `forseti-linux-pam` confidential client in Hydra (if it doesn't already exist — it never overwrites one you've tuned) and prints the freshly-minted `client_secret` **once**. Hydra won't show it again.
2. **Store the secret.** Put that value into `[posix].pam_client_secret`. (If you'd rather supply your own secret, set it in config first and `posix-init-client` will use it instead of minting — it won't echo a secret you already hold.)

**Device-auth hard-fails while `pam_client_secret` is unset or empty.** A request to the device-auth endpoints in that state logs an error, returns `500`, and makes **no** call to Hydra — an empty secret would send `client_secret_basic` with a blank password, which Hydra rejects with a confusing `502`, so Forseti refuses up front. Set the secret before pointing any host's PAM stack at Forseti.

#### `hydra_issuer` gotcha

The device id_token's issuer (`iss`) must match what Forseti expects, or validation fails with `InvalidIssuer` and every login is denied. By default Forseti expects `[hydra].public_url`. But Hydra advertises whatever its own `urls.self.issuer` is set to, which is not always the same string — the playground, for instance, issues tokens with `host.containers.internal:4444` while `public_url` is `localhost:4444`. When the two differ, set `[posix].hydra_issuer` to Hydra's actual issuer.

### Connecting a host

The host-side piece — the NSS module, the daemon, the sshd `AuthorizedKeysCommand` hook, **and the `pam_forseti.so` PAM module that drives device-auth login** — ships as the **`forseti-unix` client workspace** (under `forseti-unix/`), packaged for GNU Guix. On a Guix System you wire it in with one service plus the system-wide name-service-switch; everything else (the daemon account, the runtime directories, the `pam_mkhomedir` session entry, the nscd module load) is handled by the service.

The package and service split across two places:

- The **`forseti-unix`** package (`forseti-unixd`, `libnss_forseti.so.2`, `forseti_ssh_authorizedkeys`) lives in the **panther** channel as `forseti-unix` in `(px packages authentication)`. It carries the generated ~190-crate set so it builds offline; the earlier in-repo stub couldn't and has been removed.
- `infra/guix/forseti-unix-service.scm` — `forseti-unix-service-type` (defaults to panther's package), plus the ready-made `%forseti-name-service-switch` and `%forseti-nscd-caches` values you drop into your `operating-system`.

Minimal `operating-system` wiring:

```scheme
(use-modules (forseti-unix)          ; the package
             (forseti-unix-service)) ; the service + nss/nscd helpers

(operating-system
  ;; …
  ;; Chain `forseti' after `files' for passwd/group. REQUIRED — without this
  ;; nscd loading the module does nothing; nsswitch must list it.
  (name-service-switch %forseti-name-service-switch)
  (services
   (cons*
    (service forseti-unix-service-type
             (forseti-unix-configuration
              (server-url "https://id.example.com")
              (host-id "host-abc")          ; from `/admin/hosts` enrollment
              (host-secret "REDACTED")))    ; the one-time secret reveal
    (service openssh-service-type
             (openssh-configuration
              ;; HARD PRECONDITION: pam_mkhomedir only runs under PAM. Without
              ;; `use-pam? #t' an SSH login never creates a home directory.
              (use-pam? #t)
              (authorized-keys-command
               (file-append forseti-unix "/bin/forseti_ssh_authorizedkeys"))
              (authorized-keys-command-user "forseti")))
    ;; Lower nscd's passwd/group positive TTL so it doesn't shadow the daemon's
    ;; own cache TTL with a long stale window.
    (modify-services %base-services
      (nscd-service-type config =>
        (nscd-configuration (inherit config) (caches %forseti-nscd-caches))))
    ;; … the rest of %base-services / %desktop-services
    )))
```

The credential from step 3 above (`host_id` + `host_secret`, the one-time reveal at `/admin/hosts`) goes into the `forseti-unix-configuration`. The service renders `/etc/forseti/unixd.toml` from those fields (tightened to `0600`, owner `forseti`), runs `forseti-unixd` as the unprivileged `forseti` user, and adds the NSS module to nscd. See the header comment block in `infra/guix/forseti-unix-service.scm` for the full mechanism notes.

**End-to-end (`getent` / `id` / key-based `ssh` landing in a `pam_mkhomedir` home) is the deferred Layer-5 test** — it needs a full `guix system vm` and a live enrolled host, so it isn't part of CI. The VM smoke procedure is in `infra/guix/README-linux-auth.md`.

**A `forseti-unixd` outage denies Forseti users but never your local ones.** The service installs `pam_forseti.so` as the *sole arbiter* of the account stack for Forseti (NSS-only) accounts with an explicit control map. When the daemon is unreachable, a Forseti user's `account` check returns `PAM_AUTHINFO_UNAVAIL`, which the control map maps to `die` — they **cannot log in** (fail-closed). A genuine local, shadow-backed account (root and friends) is classified by a `/etc/shadow` lookup and returns `PAM_IGNORE`, so it falls through to `pam_unix` and **logs in normally** (fail-open). So an outage fails closed for Forseti users and fail-open for local ones — you don't get locked out of your own boxes, but a directory outage does stop directory-backed logins. The exact PAM control-map detail is in [`infra/guix/README-linux-auth.md`](../infra/guix/README-linux-auth.md).

### Offline authentication

The [device-auth login](#enabling-pam-login-device-auth) above needs the network — it drives a browser device grant against Forseti. **Offline authentication** is an opt-in fallback for the case where a host's daemon is *up but cannot reach Forseti* (a laptop on a plane, a datacenter partition, Forseti maintenance): the host authenticates the user at the terminal against a **dedicated offline passphrase** they set earlier while online. Online device-auth is always preferred and always wins; offline is only offered when the server is genuinely unreachable.

This is **not** the same as the daemon being down. A `forseti-unixd` outage stays fail-closed (above) — offline auth needs the daemon running to verify the passphrase. It only kicks in on *server-unreachable, daemon-up*.

**How a user enables it.** While online, the user sets a passphrase at `/settings/offline-access` in their dashboard. It must be **at least 8 characters** and is **separate from their Forseti account password** — it's a dedicated offline credential, never the primary one. Forseti stores only an Argon2id verifier (m=64 MiB, t=3, p=1); enrolled hosts pull it on an interval and re-pepper it locally. Clearing the passphrase there withdraws it from every host on their next sync.

**`force_mfa` hosts refuse offline auth.** A host enrolled with `force_mfa` is provisioned **zero** offline verifiers — it always requires the network to log a user in. This is deliberate: it closes the AAL2-downgrade where a user could skip their second factor simply by going offline. If you depend on MFA at a host, leave `force_mfa` on and accept that a partition means no terminal login there.

**Reduced guarantee — state it plainly.** Offline auth is a weaker control than online device-auth, by construction. The host keeps its HMAC pepper in a `0600` file, so a **stolen host disk** *or* a **stolen server DB** permits an offline brute-force of the passphrase — bounded only by the Argon2id work factor times the passphrase's entropy. That's the whole reason for the 8-character floor. The per-user host lockout (`offline_lockout_max`) defends **live terminal guessing only**, not someone who walks off with the disk. TPM sealing (M3b) — which makes the verifier uncheckable off the host and is the planned hardening — is **not** in this release. Until then, treat a host that holds offline verifiers as carrying brute-forceable secrets at rest, and keep offline passphrases strong.

**Revocation latency.** Each provisioned verifier carries a TTL (`offline_ttl_hours`, default 24). A disabled, de-scoped, deleted, or passphrase-cleared user drops off the host's next pull — but on a *fully partitioned* host that pull may not happen, so the worst-case window between disabling an account and its offline credential becoming unusable is **≈ `offline_ttl_hours`**. A second hard cap (`offline_max_lifetime_secs`, default 168h, measured from the last successful *online* login) bounds it regardless of TTL refreshes. Offline-auth attempts are queued on the host and flushed into the server audit log on reconnect — so the events aren't lost, just delayed until the partition heals.

The full mechanism (the server-unreachable trigger, the gate, the host keystore, the explicit non-goals) is in [`docs/dev/flows.md` → POSIX offline auth](./dev/flows.md#posix-offline-auth-passphrase-server-unreachable).

**Server config** — `[posix]`:

| Key                          | Type | Default | Description                                                                                                      |
|------------------------------|------|---------|----------------------------------------------------------------------------------------------------------------|
| `offline_auth_enabled`       | bool | `true`  | Master switch. When off, no verifiers are provisioned and `/settings/offline-access` 404s.                       |
| `offline_ttl_hours`          | u64  | `24`    | TTL stamped on each provisioned verifier. Bounds the offline window since the host's last poll — and the worst-case disable-to-revocation latency on a partitioned host. |
| `offline_max_lifetime_hours` | u64  | `168`   | Hard cap (from the last successful *online* auth) on how long a host may keep using an offline credential, regardless of TTL refreshes. |
| `offline_min_len`            | usize| `8`     | Passphrase length floor, enforced server-side. Never honoured below the hard wall of 8.                          |

**Host config** — the `forseti-unix` client's flat TOML (rendered by the Guix service into `/etc/forseti/unixd.toml`):

| Key                        | Type   | Default                          | Description                                                                                      |
|----------------------------|--------|----------------------------------|--------------------------------------------------------------------------------------------------|
| `credentials_db`           | string | `/var/lib/forseti/credentials.db`| Path to the `forseti-unixd`-owned `0600` offline keystore (re-peppered verifiers, lockout, audit queue, host pepper). |
| `offline_lockout_max`      | u32    | `5`                              | Consecutive offline failures before a per-user lockout (live-guessing defence only).             |
| `offline_poll_secs`        | u64    | `300`                            | How often the daemon pulls the current verifier set and flushes queued audit events.             |
| `offline_max_lifetime_secs`| u64    | `604800`                         | Host-side hard ceiling (from the last successful online auth) on an offline credential's age. Mirror of the server's `offline_max_lifetime_hours`. |

## Two-factor authentication enforcement

This is the section to read carefully if you run your own Kratos. 2FA enforcement lives **in your Kratos config, not in Forseti code** — and if you get it wrong, the second factor becomes a decoration that anyone with the password (or a recovery email) can walk straight past.

> **Operator responsibility — read this.** Forseti does not, and cannot, enforce 2FA on its own self-service surface. Enforcement is two knobs in *your* `kratos.yml`. If those knobs are at `aal1`, there is **no 2FA enforcement at all**, and worse, the factor-removal bypass below is wide open. Forseti has no way to verify your live Kratos config — Kratos's API exposes only a version string and an opaque config hash, not the actual settings — so it can't warn you. You own this. The reference playground (`infra/kratos/kratos.yml`) ships with both knobs set correctly; if you copy from it you're fine. The one thing Forseti enforces regardless of Kratos config is its own admin surface (`/admin/*`), which does an independent AAL2 check in code.

It can't read your *live* config, but it can lint the config *files* — that's what `forseti config-check` is for. Point it at your `kratos.yml` and it'll tell you whether these two knobs (and a handful of related ones) are set the way they should be. See [Config CLI](#config-cli) below; running it in CI is the cheapest insurance against shipping a misconfigured Kratos.

### The two knobs

Both of these must be `highest_available`. Not one. Both.

```yaml
# kratos.yml
session:
  whoami:
    # Any identity with a second factor enrolled must complete AAL2 before
    # whoami returns a session. Kratos answers 403 for an AAL1 session;
    # Forseti maps that to a /login?aal=aal2 step-up. Users with NO second
    # factor are unaffected — they stay at AAL1 and never see a prompt.
    required_aal: highest_available

selfservice:
  flows:
    settings:
      # Changing or removing a second factor (or the password) requires AAL2.
      # This is the critical one. See "Why both" below.
      required_aal: highest_available
```

`highest_available` means "the highest AAL the identity *could* satisfy". A password-only user can only reach `aal1`, so they're held to `aal1` — no second factor is demanded of someone who never enrolled one. The moment a user enrols a second factor, their "highest available" becomes `aal2`, and from then on both gates demand it.

### Why both — the factor-removal bypass

`whoami.required_aal` alone looks like it's enough: it forces enrolled users to step up before they can see any protected page. It isn't enough.

Consider `settings.required_aal: aal1` while `whoami.required_aal: highest_available`. An attacker (or a user who recovered via email) holds an **AAL1** session — password-only, or a fresh email-recovery session. They can't view the dashboard (whoami 403s them). But they *can* open the settings flow, because settings only demands `aal1`. From there they **remove the second factor**. Now their identity's "highest available" drops back to `aal1`, whoami stops 403-ing, and they're fully in — 2FA defeated without ever presenting the second factor.

Email recovery is the realistic version of this attack: anyone who controls the inbox could otherwise strip 2FA. Setting `settings.required_aal: highest_available` closes it — an AAL1 session cannot touch credentials (2FA *or* password) until it steps up to AAL2 first. In normal use this adds no extra prompt, because an enrolled user is already AAL2 by the time they reach settings (they stepped up at login). It only ever blocks an un-stepped-up session.

### Behavior summary

| Situation | What happens |
|-----------|--------------|
| Login, user with **no** second factor | Password → AAL1. Stays AAL1, full access. No prompt. |
| Login, user **with** a second factor | Password → AAL1, then any protected page bounces to `/login?aal=aal2` → complete the second factor → AAL2 → access. Once per session. |
| OAuth login through Forseti's bridge, enrolled user | Same step-up is forced even if the relying party didn't ask for `acr_values=aal2`. The whoami 403 catches it. |
| Managing factors at `/settings/2fa`, or changing the password | Requires AAL2. |
| `/admin/*` | Independent AAL2 check in Forseti code — enforced regardless of Kratos config. |

The step-up is a one-time event per session: the user clears it once, the session is AAL2, and they don't see it again until the session ages out.

### Break-glass and recovery

This is the subtle part. Get the recovery model wrong and you'll lock users out — or leave a hole.

**Recovery codes are the only portable AAL2 factor.** TOTP and WebAuthn are tied to a device; lose the device and they're gone. Kratos `lookup_secret` recovery codes are not — a code satisfies AAL2 from any browser. So they're the lifeline for a lost-device user. Forseti pushes hard for them: a warning banner on `/settings/2fa` and a notice on the dashboard appear whenever a user has a device factor (TOTP/WebAuthn) but **no** recovery codes. It's a strong nudge at enrollment, not a hard per-request gate — so make sure your users act on it.

**Lost device, has recovery codes.** Log in with the password (AAL1) → step up at `/login?aal=aal2` using a **recovery code** instead of the missing device → in settings, remove and re-enrol factors. Self-service, no operator involvement.

**Forgot password, 2FA user.** Email recovery alone does *not* bypass 2FA — that's the whole point of `settings.required_aal: highest_available`. The recovered session is AAL1, so it can't reset the password until it steps up. The path is: email recovery → step up with the second factor *or* a recovery code → reset the password. Forseti preserves the focused password-reset page across the step-up by keeping the `?flow=` in the step-up's `return_to`, so the user lands back on the password form after clearing AAL2, not on a generic page.

**Lost device, no recovery codes, forgot password.** This user is locked out of self-service — by design. They have zero factors they can present, so there is nothing to recover with; that's exactly the property 2FA is supposed to have. The escape hatch is an **admin-minted recovery link or code**: `POST /admin/recovery/link` (driven from the admin identity page, `/admin/identities/{id}`). The operator hands it over out-of-band, the user completes a recovery flow, and re-enrols. This is *why* forcing recovery codes matters — every user without them is a future support ticket that only an admin can resolve.

## Config CLI

Forseti's 2FA enforcement lives entirely in Kratos config, and Kratos won't tell you over the wire whether you got it right. So Forseti ships subcommands that work on the config *files* directly: no DB, no running server, no Ory clients. They're pure file operations. `config-check` and `config-init` (below) started as standalone subcommands and are now also reachable as `forseti config check` / `forseti config init` under the unified `forseti config` surface. Both spellings work; the top-level ones are kept as hidden aliases for backward compatibility. See [Managing configuration with forseti config](#managing-configuration-with-forseti-config) for the rest of that surface: enabling/disabling OIDC providers, rotating secrets, SMTP, backups.

Every subcommand takes `--help` (also `-h`), and `forseti --help` lists them all. Running `forseti` with no subcommand starts the HTTP server.

### `config-check`

Lints an existing Kratos + Hydra config against Forseti's recommendations and prints a finding per check, grouped by file:

```bash
forseti config-check                                   # uses the discovery order below
forseti config-check --kratos /etc/kratos/kratos.yml --hydra /etc/hydra/hydra.yml
forseti config-check --strict                          # also fail the run on WARN, not just FAIL
```

**How it finds your config.** Each file is resolved independently, highest precedence first:

1. the `--kratos` / `--hydra` flag,
2. the `FORSETI_KRATOS_CONFIG` / `FORSETI_HYDRA_CONFIG` env var,
3. the dev default (`infra/kratos/kratos.yml` / `infra/hydra/hydra.yml`) — but **only if that file actually exists**.

If none of those resolves to a file, `config-check` doesn't silently proceed — it prints a clear error naming the missing config (e.g. `No Kratos config found. Pass --kratos <path> or set $FORSETI_KRATOS_CONFIG.`) and exits non-zero. The output header shows the resolved path and where it came from, so you can always see exactly which file was linted and why:

```
== Kratos (/etc/kratos/kratos.yml — from --kratos) ==
```

Each line is `[ OK ]` / `[WARN]` / `[FAIL]` followed by the key path, the current value, the recommended value, and a one-line note on what breaks if you ignore it. SMTP/DSN credentials are redacted in the output, so it's safe to paste into a CI log. The command **exits non-zero if any check FAILs** (WARN alone doesn't fail unless you pass `--strict`), which makes it a drop-in CI gate:

```yaml
# .github/workflows/...
- run: forseti config-check --kratos kratos.yml --hydra hydra.yml
```

The headline checks are the two 2FA knobs from the section above: `selfservice.flows.settings.required_aal` at anything other than `highest_available` is a **FAIL** (it's the factor-removal bypass), and `session.whoami.required_aal` not at `highest_available` is a **WARN**. It also covers recovery codes (`lookup_secret`), WebAuthn-as-second-factor (`passwordless: false`), self-service recovery, a non-placeholder SMTP URI, and the Kratos/Hydra secrets (presence, no obvious placeholders, and `secrets.cipher` being exactly 32 chars). On top of those specific checks it scans both files recursively and **FAILs** on any leftover `CHANGEME_*` placeholder (naming the dotted key path) — so a half-filled `config-init` output can't pass.

Running it against the playground reference config as-is (`forseti config-check --kratos infra/kratos/kratos.yml --hydra infra/hydra/hydra.yml`) exits `1` with well over a dozen FAILs: that's expected, not a bug. The playground ships Kratos/Hydra secrets unset and the literal `dev-playground-token-change-me` audit webhook bearer baked into every hook, both deliberately insecure defaults meant to be replaced before anything resembling production traffic touches the stack (see [`config-init`](#config-init) or [`forseti config`](#managing-configuration-with-forseti-config) below for generating or rotating real values). Don't be alarmed by a non-zero exit against the playground; be alarmed by one against a deployment you meant to be production-ready.

### `config-init`

Generates a recommended Kratos + Hydra config from the known-good reference, with your URLs/DSN/SMTP substituted in and fresh secrets minted from a CSPRNG. The security recommendations are baked in regardless of input — both `required_aal` knobs at `highest_available`, recovery codes on, WebAuthn as a second factor, TOTP on, recovery enabled.

```bash
forseti config-init \
  --forseti-url https://accounts.example.com \
  --kratos-public-url https://accounts.example.com/kratos \
  --kratos-admin-url http://kratos:4434 \
  --hydra-public-url https://accounts.example.com/hydra \
  --hydra-admin-url http://hydra:4445 \
  --kratos-db-dsn 'postgres://kratos:...@db/kratos' \
  --hydra-db-dsn  'postgres://hydra:...@db/hydra' \
  --smtp-uri      'smtps://user:pass@smtp.example.com:465' \
  --smtp-from-address 'no-reply@example.com' \
  --smtp-from-name    'Example Accounts' \
  --kratos-out kratos.yml --hydra-out hydra.yml
```

It refuses to clobber an existing file unless you pass `--force`. Anything you don't supply via a flag is written as a loud `CHANGEME_*` placeholder, and the command prints exactly which ones are still outstanding — so a half-filled config can't masquerade as complete. `config-check` then **FAILs on any leftover `CHANGEME_*`**, anywhere in either file. The WebAuthn `rp.id` is derived from the host of `--forseti-url` (e.g. `accounts.example.com`), which is correct for a single-host deployment; narrow it to a registrable parent domain by hand if you serve several subdomains. With `--forseti-url` absent it stays `CHANGEME_RP_ID` and `config-check` FAILs on it like any other placeholder. `--smtp-from-address` / `--smtp-from-name` are optional and, when supplied, are written under `courier.smtp` in `kratos.yml` alongside `connection_uri`.

The generated files carry no comments — `config-init` and the other `config` subcommands round-trip these files through `serde_yaml_ng`, which would silently drop any comments on the next parse/write, so keeping prose in the file would be misleading. See [Configuration rationale](#configuration-rationale) for why each baked-in recommendation is set the way it is. After writing, run the linter over what it produced to confirm the round-trip:

> **`--force` is a full regeneration, not a merge.** Re-running `config-init --force` against an existing `kratos.yml`/`hydra.yml` does not patch the file: it renders a brand-new pair from scratch, with fresh CSPRNG secrets throughout (cookie/cipher/system secrets, and Hydra's pairwise salt). Any OIDC providers you'd enabled with `forseti config oidc enable`, any flow hooks, and any rotation history (accept-lists from a prior `config rotate webhook-token`, multi-entry secret lists) are gone, overwritten with the from-scratch template. Only reach for `--force` on a config you're deliberately starting over; otherwise use the targeted `forseti config` subcommands below to change one thing at a time.

```bash
forseti config-init ... --kratos-out kratos.yml --hydra-out hydra.yml
forseti config-check --kratos kratos.yml --hydra hydra.yml   # should be 0 FAIL, 0 WARN
```

A note on the generated secrets: they're embedded directly in the files and grant full session/token control, so treat the output the way you'd treat any secret material — review it, lock down the file permissions, and don't commit it.

## Configuration rationale

Why `config-init`'s baked-in recommendations are set the way they are. This used to live as inline comments in the generated `kratos.yml` / `hydra.yml`, but those files are CLI-owned artifacts that round-trip through `serde_yaml_ng` on every later `config` subcommand, which drops comments on write — so the prose moved here instead.

**Kratos `session.whoami.required_aal: highest_available`.** `highest_available` forces any identity with a second factor enrolled to complete AAL2 before `whoami` returns a session — Kratos answers 403, which Forseti maps to a `/login?aal=aal2` step-up. Settings also requires AAL2 (see below) so an AAL1 session (password-only login, or an email-recovery session) can't strip a second factor and defeat 2FA. Lost-device users step up with a `lookup_secret` recovery code (which satisfies AAL2) to manage their factors.

**Kratos `selfservice.methods.webauthn.config.passwordless: false`.** This keeps WebAuthn as a second factor (AAL2). Flipping it to `true` makes it a first-factor login and it will not satisfy the AAL2 step-up.

**Kratos `selfservice.flows.settings.required_aal: highest_available`.** AAL2 is required for settings changes once the identity has a second factor. Otherwise an AAL1 session (password-only login, or an email-recovery session) could open the settings flow and remove the second factor, defeating 2FA entirely. With enforcement on, the user is already AAL2 by the time they reach settings (they stepped up at login), so this adds no extra prompt for normal use — it only blocks an un-stepped-up session from touching credentials.

**Hydra `urls.self.issuer`.** The issuer must be reachable under the same hostname from both the browser and any resource servers so the `iss` claim in id_tokens validates everywhere.

**Hydra `oidc.dynamic_client_registration`.** This is Dynamic Client Registration (RFC 7591). The portal advertises itself as the `registration_endpoint` and gates inbound requests with an Initial Access Token before forwarding to Hydra. See `src/oauth/register.rs`.

**Hydra `webfinger.oidc_discovery.client_registration_url`.** Points at the portal, not Hydra — the portal validates an Initial Access Token before forwarding to Hydra.

**Hydra `oauth2.pkce.enforced_for_public_clients: true`.** MCP 2025-06-18 requires PKCE with S256 for public clients.

**Hydra `strategies.access_token: jwt`.** Access tokens are JWTs by default. Resource servers validate locally against Hydra's JWKS. Flip to `opaque` if you need immediate revocation (and route every RS to the admin API on `:4445`).

## Managing configuration with forseti config

`config-check` and `config-init` cover linting and first-time generation. Once a deployment is live, day-2 operations (turning on a sign-in provider, rotating a secret, restoring from a backup) go through the rest of the `forseti config` surface. Like `config-check`/`config-init`, every subcommand here is a pure file operation: no DB, no running Forseti process, no live Kratos/Hydra API calls beyond a couple of best-effort read-only probes (counting affected identities/clients before a destructive change, when an admin URL is configured).

Bare `forseti config` (no subcommand) drops into an interactive menu when stdin is a TTY: it walks every setting `config check` knows about, lets you drill into one, and delegates to the same functions the subcommands below call. Outside a TTY (scripts, CI, systemd) it prints the subcommand help and exits `2` instead of hanging.

### Subcommand overview

| Command | What it does |
|---|---|
| `forseti config` | Interactive menu (TTY only) |
| `forseti config status [--json]` | One-line-per-setting summary: OIDC providers, secret rotation state, SMTP, webhook token |
| `forseti config check [--strict]` | The linter described above |
| `forseti config init ...` | The generator described above |
| `forseti config oidc enable <google\|github\|microsoft> --client-id <id> (--client-secret-env/-file/-stdin) [--microsoft-tenant <id>] [--keep-mapper]` | Add/replace an upstream sign-in provider |
| `forseti config oidc disable <id>` | Remove a provider |
| `forseti config rotate webhook-token` | Stage a new audit webhook token (accept-list, zero-loss) |
| `forseti config rotate kratos-secrets [--cookie \| --cipher]` | Prepend a new Kratos cookie and/or cipher secret |
| `forseti config rotate hydra-system` | Prepend a new Hydra system secret |
| `forseti config rotate pairwise-salt --i-understand-subs-change` | Overwrite Hydra's pairwise salt (irreversible) |
| `forseti config prune webhook-token` | Drop the old webhook token once every service has reloaded |
| `forseti config prune kratos-secrets [--cookie \| --cipher]` | Drop old Kratos secrets |
| `forseti config prune hydra-system` | Drop old Hydra system secrets |
| `forseti config restore [--from <unix-secs>]` | Restore a file from its `.bak.<ts>` ring |
| `forseti config smtp set (--uri-env/-file/-stdin) [--from-address] [--from-name]` | Set Kratos courier SMTP |

Global flags, valid on every `config` subcommand: `--kratos`/`--hydra` (aliases `--kratos-config`/`--hydra-config`, same discovery order as `config-check`), `--forseti-config` (path to `config.toml`; falls back to `$FORSETI_CONFIG_PATH` or the dev default), `--dry-run`, `--yes` (skip confirmation prompts), `--follow-symlink` (operate on a symlinked target instead of refusing it).

Every mutating subcommand backs up the file it's about to change first (see [Backups and restore](#backups-and-restore)) and shows a redacted unified diff of what it's about to write. Confirmation prompts before writing apply only to `oidc disable`, `rotate/prune kratos-secrets` and `hydra-system`, `rotate pairwise-salt` (which requires typing a specific phrase), and `restore`. Conversely, `oidc enable`, `smtp set`, and `rotate/prune webhook-token` write immediately without a generic gate, relying on the printed diff, backup ring, and `--dry-run` for preview. `--yes` suppresses confirmation prompts where they apply; `--dry-run` previews without writing. Writes are atomic (temp file + rename) and land `0600`.

### Enabling and disabling OIDC providers

`forseti config oidc enable <provider> --client-id <id> --client-secret-env <VAR>` writes the provider block into `kratos.yml` (literal `client_id`/`client_secret`: see the `${VAR}` note under [Kratos configuration → oidc](#oidc) above) and drops a reviewed mapper jsonnet next to it, gated on `email_verified` (Microsoft/Google) or treated as always-unverified (GitHub, which doesn't reliably send `email_verified`). The secret can come from an env var, a file, stdin, or (interactively) a masked prompt: never a bare CLI argument, so it doesn't end up in shell history or `ps`. Microsoft requires `--microsoft-tenant <tenant-id>`; `common` is refused (the nOAuth account-takeover class, see the note above).

If the target mapper file already exists with content that doesn't match Forseti's pinned body, `enable` refuses and asks for `--keep-mapper` to proceed without touching it: it won't silently clobber a mapper you've customized.

**The audit gap.** `config init`-generated `kratos.yml` files carry no audit `web_hook` nodes at all (see [Audit logging](#audit-logging): the reference playground has them, a from-scratch `config init` doesn't). `oidc enable` looks for an existing `web_hook` template on another flow to clone onto the OIDC login/registration flows; when it finds none, it still enables the provider but prints a loud warning that OIDC sign-ins won't reach the audit log until a webhook is wired up by hand. This is a known, documented gap, not a bug: wiring one up requires an audit-endpoint URL and bearer token that only the operator knows.

`forseti config oidc disable <id>` removes the provider block (and, best-effort, reports how many existing identities look like they signed in through it, when an admin URL is configured: this is advisory, not a block on proceeding).

### Rotating the audit webhook token

`[audit].webhook_token` authenticates inbound Kratos flow-completion webhooks (see [Audit webhook bearer](#audit-webhook-bearer)). The old manual procedure (stop Forseti, hand-edit both files, restart) has a hard availability trade-off: there's no window where both the old and new token work, so *any* ordering drops audit events for however long it takes to update both sides. `forseti config rotate webhook-token` avoids that by staging the change:

1. `forseti config rotate webhook-token` writes `config.toml`'s `[audit].webhook_token` as an accept-list `[new, old]`: Forseti will accept requests bearing *either* token, and only then rewrites `kratos.yml`'s hooks to send the new one. In interactive mode it stops and waits for you to restart Forseti before touching `kratos.yml`, so the accept-list is live before Kratos starts sending the new token. Non-interactively it writes both files back-to-back and prints a warning: restart Forseti immediately, since until it reloads `config.toml` it will 401 the new token Kratos is now sending.
2. Restart Forseti (it doesn't hot-reload `config.toml`). Kratos hot-reloads its config file on its own, so no Kratos restart is needed once `kratos.yml` is written.
3. Once you're satisfied every event source is using the new token, `forseti config prune webhook-token` drops the old entry from the accept-list back to a single value. `forseti config check`/`config status` report the rotation as pending for as long as the accept-list has more than one entry.

If the current token is a placeholder (`CHANGEME_*`) or unset, there's nothing live to protect a rotation window for, so rotation happens in one pass with no accept-list staging.

**`$FORSETI_AUDIT__WEBHOOK_TOKEN` shadowing.** Figment layers env vars over `config.toml` at boot. If that env var is set, it overrides whatever `[audit].webhook_token` this command writes, and Forseti won't see the accept-list until the env var is unset (or updated to match). The command detects a set env var and warns; it can't fix it for you, since unsetting an operator's environment isn't something a config-file tool should touch.

### Rotating Kratos and Hydra secrets

`secrets.cookie`/`secrets.cipher` (Kratos) and `secrets.system` (Hydra) follow Ory's own rotation convention: the **first** entry in the list signs/encrypts new values, but **every** entry in the list remains valid to verify/decrypt existing ones. `forseti config rotate kratos-secrets [--cookie|--cipher]` (neither flag rotates both) prepends a fresh secret; `forseti config rotate hydra-system` does the same for Hydra. Kratos hot-reloads, so no restart is needed there; Hydra does not, so a Hydra system-secret rotation needs a restart before the new secret takes effect for signing (it still verifies old sessions/tokens against the full list either way).

Prune (`forseti config prune kratos-secrets [--cookie|--cipher]`, `forseti config prune hydra-system`) drops everything except the current first entry, and refuses when there's only one entry to begin with (nothing to prune). **Prune `secrets.cookie` only after the max session lifetime has elapsed since rotation**: a leaked old cookie secret can still forge sessions for as long as it's listed, so pruning early doesn't buy you anything and pruning late is safe. The command prints this reminder whenever a cookie prune is requested.

### Rotating the pairwise salt

`oidc.subject_identifiers.pairwise.salt` (Hydra) is a **scalar overwrite, not a rotation list**: there's no prune step, because there's nothing to keep around. The salt derives every pairwise `sub` Hydra has ever issued per client; rotating it changes all of them, permanently, the moment the write is confirmed. Any downstream app that matches users by their pairwise `sub` will see what looks like a brand-new account for every user, forever. Hydra does not hot-reload, so the new salt only takes effect once Hydra restarts.

Because this is irreversible and blast-radius-wide, `--yes` does **not** satisfy the confirmation gate. Interactive mode requires typing a specific confirmation phrase verbatim; non-interactive mode requires `--i-understand-subs-change`. Before either, the command makes a best-effort call to Hydra's admin API (when an admin URL is configured in `hydra.yml`) to report how many pairwise clients will be affected. This is informational only; it never blocks the rotation.

### Backups and restore

Every write through `forseti config`'s mutating subcommands backs up the target file first, as `<file>.bak.<unix-secs>`, mode `0600`, in a ring capped at the 3 most recent generations per file (older backups are pruned automatically). `forseti config restore [--from <unix-secs>]` lists what's available per target (Kratos, Hydra, and `config.toml` when resolvable) and restores from a chosen generation: restoring is itself backed up first, so a restore is undoable too. Without `--from`, an interactive terminal is offered each target's newest backup one at a time; non-interactively you must pass `--from`. A restore copies the backup's bytes back verbatim (not re-serialized), so unlike every other `config` write it does **not** drop comments: restoring a hand-annotated file gives you the comments back exactly as they were.

`config.toml`/`kratos.yml`/`hydra.yml` are frequently git-tracked (the playground reference files are). Writes to `kratos.yml` and `hydra.yml` through the guarded YAML pipeline warn when the target is under git and remind you to gitignore the backups: add `*.bak.*` to `.gitignore` so a rotation doesn't litter the repo with secret-bearing backup files. (`config.toml` writes and `config restore` do not trigger this warning.)

### `--dry-run`

Every mutating subcommand accepts `--dry-run`: it computes and prints the same redacted unified diff it would otherwise write, backs up nothing, writes nothing, and any interactive confirmation prompt is skipped (there's nothing to confirm). Use it to preview a rotation or an OIDC enable/disable before committing to it, or in CI to confirm a scripted change would do what you expect.

### Offline schema validation

`forseti config check` lints Forseti's own recommendations, but it's not a substitute for validating that a hand-edited or CLI-generated `kratos.yml` actually parses as valid Kratos config. Kratos ships its own schema validator; run it offline against the pinned image version (see `infra/docker-compose.yml`) without standing up the full stack:

```bash
podman run --rm -v <dir-containing-kratos.yml>:/etc/config/kratos oryd/kratos:v26.2.0 \
  validate config /etc/config/kratos/kratos.yml
```

(substitute `docker` if that's your runtime). **Single-file bind mounts don't see atomic writes.** `forseti config`'s writes are temp-file-plus-rename (so a crash mid-write never corrupts the target), which replaces the file's inode. Docker/Podman bind-mounting a *single file* (`-v ./kratos.yml:/etc/config/kratos/kratos.yml`) binds to that specific inode at container-start time: a rename on the host is invisible to the container until it's restarted. So a config CLI write can silently not take effect from the container's point of view even though the file on the host disk is correct. Bind-mount the containing *directory* instead (as the playground `docker-compose.yml` does: `./kratos:/etc/config/kratos`), which doesn't have this problem, or restart the container after every config write if you must bind-mount a single file.

## Kratos configuration

Forseti is method-agnostic infrastructure: it renders whatever nodes Kratos serves on each self-service flow. Which methods are *available* is an operator decision made in `kratos.yml`. The reference playground config is at `infra/kratos/kratos.yml`.

### Methods

Each block under `selfservice.methods.*` toggles a method. Forseti renders nodes from any enabled method without further configuration.

#### `password`

Almost always enabled. Username/password (Kratos uses the identifier from the schema; typically email).

```yaml
selfservice:
  methods:
    password:
      enabled: true
```

#### `code`

Passwordless email codes. Useful as a first-factor alternative to passwords and as the channel for recovery and verification flows. Recommended.

```yaml
selfservice:
  methods:
    code:
      enabled: true
      config:
        lifespan: 15m
```

#### `totp`

Time-based one-time passwords (Google Authenticator, 1Password, etc.) as a second factor.

```yaml
selfservice:
  methods:
    totp:
      enabled: true
      config:
        issuer: example.com
```

The `issuer` string shows up in the user's authenticator app. Set to your brand or hostname.

#### `lookup_secret`

One-time recovery codes. Pair with `totp` so users have a fallback when they lose their authenticator.

```yaml
selfservice:
  methods:
    lookup_secret:
      enabled: true
```

#### `webauthn`

Hardware security keys (YubiKey, FIDO2) as a second factor. Requires a `traits.webauthn` field in the identity schema.

```yaml
selfservice:
  methods:
    webauthn:
      enabled: true
      config:
        rp:
          id: accounts.example.com
          display_name: Example Accounts
          origins:
            - https://accounts.example.com
```

The relying-party `id` must match the cookie-bearing domain. Origins must include every URL the WebAuthn ceremony can be initiated from.

#### `passkey`

Passwordless first-factor passkeys. Same identity-schema and RP-config requirements as `webauthn`.

```yaml
selfservice:
  methods:
    passkey:
      enabled: true
      config:
        rp:
          id: accounts.example.com
          display_name: Example Accounts
          origins:
            - https://accounts.example.com
```

#### `oidc`

Upstream OIDC providers (Google, GitHub, Microsoft). Operators register one OAuth app per provider on the provider's side; Forseti's `forseti config oidc enable` writes the client credentials into `kratos.yml` and renders one "Sign in with X" button per configured provider. See [Managing configuration with forseti config](#managing-configuration-with-forseti-config) below: that's the supported path for adding a provider; the manual YAML shape here is for reference (e.g. reading an existing `kratos.yml`) or for providers the CLI doesn't cover yet.

**`${VAR}` is not interpolated.** Kratos does **not** expand `${VAR}`-style environment references anywhere in `kratos.yml`: that's a common assumption carried over from tools like Docker Compose or Helm, but Kratos's own config loader has no such substitution step (confirmed against the upstream config loader; there's no `${...}` expansion pass on the parsed YAML). Every value, including `client_id` and `client_secret`, must be the literal string Kratos will use. `forseti config oidc enable` writes secrets in literal, plaintext form (redacted only in this CLI's own diff output) for exactly this reason. If you want secrets sourced from the environment at *deploy* time rather than baked into the file, template `kratos.yml` through your deploy tooling (Helm, Terraform, a `sops`/`envsubst` pre-render step) before Kratos ever reads it. Kratos itself never does that substitution.

Worked example for Google, via the CLI:

1. Go to <https://console.cloud.google.com/apis/credentials> and create an OAuth 2.0 Client ID.
2. Authorized redirect URI: `https://accounts.example.com/self-service/methods/oidc/callback/google`. Substitute `accounts.example.com` for your Kratos public hostname: the path is fixed by Kratos.
3. Capture the client ID and client secret.
4. `forseti config oidc enable google --client-id <id> --client-secret-env GOOGLE_CLIENT_SECRET` (export the secret into that env var first, or use `--client-secret-file`/`--client-secret-stdin`; omit the flag entirely and the CLI prompts, masked, on a TTY). This writes the `providers` entry into `kratos.yml`, including `requested_claims.id_token.email`/`email_verified` as essential, and drops the reviewed mapper jsonnet next to it.

The resulting YAML looks like this (shown here so you know what to expect, or if you're reading an existing config by hand):

```yaml
selfservice:
  methods:
    oidc:
      enabled: true
      config:
        providers:
          - id: google
            provider: google
            client_id: 1234567890-abc.apps.googleusercontent.com
            client_secret: GOCSPX-actual-secret-value
            mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
            scope: [openid, email, profile]
            requested_claims:
              id_token:
                email: { essential: true }
                email_verified: { essential: true }
```

The mapper CLI-writes at `oidc.google.jsonnet` gates the `email` trait on `claims.email_verified`: copying `email` without that gate is an account-takeover vector (anyone who controls an unverified alias at the provider could claim the matching Forseti account). Don't hand-edit the mapper unless you understand that invariant; `forseti config check` warns if a provider's mapper doesn't match Forseti's reviewed pinned body.

GitHub and Microsoft (Azure AD) follow the same `forseti config oidc enable <github|microsoft>` shape. GitHub's claims don't reliably carry `email_verified`, so its pinned mapper treats every GitHub-sourced email as unverified and Forseti's own verification flow gates trust instead. Microsoft requires `--microsoft-tenant <tenant-id>`: `common` (any Azure AD tenant or personal Microsoft account) is refused outright, since it opens the [nOAuth](https://www.descope.com/blog/post/noauth) account-takeover class where an attacker edits their own account's email in a tenant Microsoft doesn't verify.

### Flow URLs

Forseti owns every UI surface; Kratos must point at it. Set every flow's `ui_url` to the matching Forseti path.

```yaml
selfservice:
  default_browser_return_url: https://accounts.example.com/
  allowed_return_urls:
    - https://accounts.example.com
    # add downstream apps if they rely on Kratos return_to:
    - https://app.example.com

  flows:
    login:
      ui_url: https://accounts.example.com/login
      lifespan: 10m

    registration:
      ui_url: https://accounts.example.com/registration
      lifespan: 10m
      after:
        password:
          hooks:
            - hook: session
            - hook: show_verification_ui

    recovery:
      enabled: true
      ui_url: https://accounts.example.com/recovery

    verification:
      enabled: true
      ui_url: https://accounts.example.com/verification
      after:
        default_browser_return_url: https://accounts.example.com/

    settings:
      ui_url: https://accounts.example.com/settings
      privileged_session_max_age: 15m

    error:
      ui_url: https://accounts.example.com/error

    logout:
      after:
        default_browser_return_url: https://accounts.example.com/login
```

#### Per-method post-settings landing

Kratos supports per-method `selfservice.flows.settings.after.<method>.default_browser_return_url`. Use these to land users back on the relevant sub-page after a save instead of sending them to a generic dashboard:

```yaml
selfservice:
  flows:
    settings:
      after:
        password:
          default_browser_return_url: https://accounts.example.com/settings/password
        profile:
          default_browser_return_url: https://accounts.example.com/settings/profile
        totp:
          default_browser_return_url: https://accounts.example.com/settings/2fa
        lookup_secret:
          default_browser_return_url: https://accounts.example.com/settings/2fa
        webauthn:
          default_browser_return_url: https://accounts.example.com/settings/2fa
        passkey:
          default_browser_return_url: https://accounts.example.com/settings/2fa
```

### CORS

Kratos's public API serves CORS preflights when Forseti's browser-side JS (HTMX) calls it. Forseti's origin must appear in `serve.public.cors.allowed_origins`:

```yaml
serve:
  public:
    cors:
      enabled: true
      allowed_origins:
        - https://accounts.example.com
      allowed_methods: [POST, GET, PUT, PATCH, DELETE]
      allowed_headers: [Authorization, Cookie, Content-Type]
      exposed_headers: [Content-Type, Set-Cookie]
```

### Identity schema

The schema declares which traits an identity has (email, name, optional WebAuthn handles). Schemas are referenced by URL or file path. Place the schema file alongside `kratos.yml`:

```yaml
identity:
  default_schema_id: default
  schemas:
    - id: default
      url: file:///etc/config/kratos/identity.schema.json
```

Forseti renders whatever fields the schema declares; adding `traits.given_name` to the schema causes the registration and settings/profile flows to gain a corresponding input.

## Hydra configuration

Hydra is the OAuth2 server. Forseti is the IdP UI Hydra delegates to. Reference config: `infra/hydra/hydra.yml`.

### URLs

```yaml
urls:
  self:
    issuer: https://hydra.example.com
  login:   https://accounts.example.com/oauth/login
  consent: https://accounts.example.com/oauth/consent
  logout:  https://accounts.example.com/oauth/logout
```

- `issuer` is the public hostname downstream apps see in `iss` claims and use for OIDC discovery.
- `login`, `consent`, `logout` redirect the user to Forseti carrying a challenge query parameter. Forseti exchanges the challenge with Hydra's admin API and accepts or rejects it.

### Secrets

```yaml
secrets:
  system:
    - <64-byte random string>

oidc:
  subject_identifiers:
    supported_types: [pairwise, public]
    pairwise:
      salt: <32-byte random string>
```

`secrets.system` encrypts everything in Hydra's database (consent grants, refresh tokens). Rotate periodically; Hydra supports rolling rotation by appending the new secret as the first list element and keeping the previous one for decryption.

### Client registration

Use the `hydra` CLI against the admin API. Example for a first-party app:

```bash
hydra create client \
  --endpoint http://hydra-admin.internal:4445 \
  --name "Example App" \
  --grant-type authorization_code,refresh_token \
  --response-type code \
  --scope "openid offline_access email profile" \
  --redirect-uri https://app.example.com/auth/callback \
  --token-endpoint-auth-method client_secret_post \
  --backchannel-logout-uri https://app.example.com/auth/backchannel-logout \
  --metadata '{"skip_consent": true}'
```

- `skip_consent: true` in client metadata auto-grants consent without prompting. Set this only for clients the operator trusts to honor scope semantics (typically first-party apps).
- Capture the printed `client_id`, `client_secret`, and `registration_access_token` and pass them to the downstream app's operator.

See [`integration-guide.md`](./integration-guide.md) for the downstream-app perspective on registration parameters.

### Spec alignment (OAuth 2.1 / RFC 9700)

Where the playground sits relative to current OAuth / OIDC normative work (as of May 2026):

| Spec / behaviour | Status in this stack |
|---|---|
| OAuth 2.1 draft-15 — PKCE on every code flow (S256) | Enforced for public clients via Hydra `oauth2.pkce.enforced_for_public_clients: true` (`infra/hydra/hydra.yml:70`) |
| OAuth 2.1 — Implicit grant removed | Not enabled on the playground; do not add `response_type=token` clients |
| OAuth 2.1 — ROPC removed | Not enabled |
| OAuth 2.1 — Exact-string redirect matching | Hydra default; no wildcard / prefix matching |
| OAuth 2.1 — Refresh tokens sender-constrained OR rotated | Rotated (Hydra default; one-shot with reuse detection) |
| RFC 9068 JWT Access Token profile (`typ=at+jwt`) | Partial — Hydra v26 emits JWT access tokens with `typ: JWT`. Strict RFC 9068 validators that require `typ=at+jwt` will reject. Either relax your validator or stay on opaque tokens + introspection until Hydra ships the profile |
| RFC 8707 Resource Indicators (`resource=` parameter) | Hydra does not yet bind `resource=` into the access token's `aud` — use Hydra's `audience=` allow-list for that. Forseti *does* parse `resource=` off the original auth URL and records it as provenance on `oauth_client_metadata.resource_url` (`src/oauth/consent.rs:412-437`) |
| RFC 9449 DPoP | **Not implemented.** Tokens are bearer-only |
| RFC 8705 mTLS client auth + cert-bound tokens | Not configured |
| RFC 9126 PAR (Pushed Authorization Requests) | Supported by Hydra; no Forseti-side enforcement |
| RFC 9101 JAR (signed request objects) | Supported by Hydra; no Forseti-side enforcement |
| RFC 9396 RAR (Rich Authorization Requests) | Not used |
| RFC 9700 OAuth Security BCP (Jan 2025) | Reference document — the items above cover the BCP's MUST-level requirements except DPoP/mTLS |

### MCP support

Hydra works as the authorization server for [Model Context Protocol](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) servers (Claude Desktop, Claude Code, claude.ai, ChatGPT). Forseti handles the UX side — the admin UI's "MCP server" preset on `/admin/clients/new` pre-fills the right defaults (public client, PKCE, audience allow-list). This section is the operator-side checklist for the Hydra config that makes those clients work.

#### Required Hydra config

`infra/hydra/hydra.yml` for the playground shows the full shape. The MCP-relevant bits:

```yaml
oauth2:
  pkce:
    # MCP MUSTs PKCE with S256 for every client (not just public). We
    # scope this to public — Hydra still requires PKCE whenever a client
    # has token_endpoint_auth_method=none, and confidential clients can
    # opt in per-client. Without this flag, a misconfigured client
    # (auth method `none`, no code_challenge) is silently weakened.
    enforced_for_public_clients: true

oidc:
  dynamic_client_registration:
    # Required for MCP — Claude Code refuses any AS that doesn't expose
    # `/oauth2/register` (RFC 7591), even when client_id is pre-configured.
    enabled: true
    default_scope:
      - openid
      - offline
      - offline_access

webfinger:
  oidc_discovery:
    # Surfaces `registration_endpoint` in /.well-known/openid-configuration.
    client_registration_url: https://accounts.example.com/oauth2/register
```

#### Token validation: JWT access tokens (default and recommended)

The playground ships with **JWT access tokens and a 5-minute TTL**, pinned in `infra/hydra/hydra.yml`:

```yaml
strategies:
  access_token: jwt

ttl:
  access_token: 5m
```

Resource servers (MCP servers, downstream APIs) validate tokens **locally** against Hydra's JWKS at `https://hydra.example.com/.well-known/jwks.json` — same key material as id_tokens, same verification shape. No admin-API reachability needed; no introspection round-trip on the hot path.

Why this is the default:

- **Resource servers can live anywhere.** Serverless, third-party VPC, customer-managed infra — they need the public JWKS URL and nothing else.
- **Revocation lag is bounded to 5 minutes.** The `ttl.access_token: 5m` cap is the whole point — once a user revokes a grant from `/settings`, the next refresh fails and the worst-case window before a stolen/revoked token stops working is the access-token TTL. Refresh tokens are revoked at `/oauth2/token` exchange time, which is the natural choke-point.
- **Refresh-token rotation is on by default** (Hydra default). A replayed refresh token trips reuse detection and revokes the whole chain.

**RFC 9068 conformance.** Hydra v26 emits JWT access tokens with `typ: JWT`, not the `typ: at+jwt` that RFC 9068 requires. Strict RFC 9068 validators will reject. Options: (a) relax the validator on `typ`, (b) stay on opaque access tokens + introspection until Hydra ships the profile, (c) track Hydra's RFC 9068 issue and switch when it lands. Mandatory claims (`iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`) are all present in current Hydra output.

**If you need true immediate revocation, switch to opaque tokens — but be clear about the tradeoff.**

#### Token validation: opaque + introspection (alternative, private-network only)

Set `strategies.access_token: opaque` in `hydra.yml` to switch. The catch — and this is the tradeoff we want you to be **completely clear-eyed about**:

> **Opaque tokens require introspection on Hydra's admin API (`/admin/oauth2/introspect` on `:4445`). The admin API is private. It MUST NOT be exposed to the public internet.** Every resource server that needs to validate a token must have a route into your internal network to reach Hydra's admin port.

This works fine when:

- All your resource servers run on the same internal network as Hydra.
- You operate a service mesh or private-link transport between RSes and Hydra.
- You're willing to stand up an authenticated introspection proxy (no such proxy ships with Forseti today — you'd build it).

This **doesn't** work when:

- Your MCP server runs on a third-party platform (Cloudflare Workers, Vercel, a customer's VPC) without a route to your admin network.
- You're shipping the MCP server to integrators who can't be expected to set up private connectivity.
- You want third parties to validate tokens without granting them admin-network access.

If any of those apply, stay on the JWT default. The 5-minute revocation window is the price you pay for reachability, and for most use cases it's the right trade.

If you do flip to opaque, the response shape from `/admin/oauth2/introspect` is RFC 7662 standard plus a custom `ext` field (whatever Forseti stuffed in at consent time). See `src/oauth/consent.rs:build_id_token_claims` for the contents.

#### Audience allow-list (Hydra's non-standard `audience` parameter)

Hydra binds audiences at the auth-request level — clients pass `audience=<url>` on the authorization request, and Hydra issues a token with `aud: ["<url>"]`. The catch: **values must be pre-registered on the client**. Hydra does not yet implement [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) as of v26.2.0 (the current latest, March 2026), and emits no `invalid_target` error when a value isn't registered — it silently drops the audience binding.

The admin UI's MCP preset surfaces the audience textarea by default. Operators register their MCP server's canonical URL (e.g. `https://mcp.formshive.com`) there; clients reference it on the auth request.

Track the upstream: [`ory/hydra` RFC 8707 issues](https://github.com/ory/hydra/issues?q=RFC+8707). When shipped, the current allow-list flow keeps working as a fallback — useful even after RFC 8707 lands, because real-world MCP clients (Claude.ai as of January 2026) don't always send `resource` reliably.

#### Dynamic Client Registration (RFC 7591)

DCR is enabled because Claude Code refuses any authorization server that doesn't advertise `registration_endpoint` in its discovery document, even when a `client_id` is pre-configured ([anthropics/claude-code#38102](https://github.com/anthropics/claude-code/issues/38102)). Hydra's own `/oauth2/register` is fully anonymous once `enabled: true` — there is no Hydra-side token, allowlist, or CIDR gate.

**Anonymous DCR is the default.** Claude Code, Claude Desktop, and claude.ai have no way to present an Initial Access Token — they discover the registration endpoint from the OIDC document and POST to it directly. Locking DCR behind a mandatory bearer would make these clients unable to self-register, defeating the purpose of advertising the endpoint. Forseti therefore accepts anonymous registrations by default and relies on the **verification badge + admin review** as the safety mechanism: every DCR client lands as `unverified`, the consent screen renders a caution banner ("This application has not been reviewed by an administrator"), and end users see that banner every time until an operator reviews the client at `/admin/clients?verification=unverified` and explicitly promotes it via **Mark as verified**.

**What Forseti still does** (with or without an IAT):

- Strips any `metadata.forseti.*` keys from the inbound body — defence against a caller trying to pre-seed trust state on the Hydra client.
- Applies the reserved-name denylist (see below).
- Applies the per-IP rate limit (`oauth.dcr_ip_rate_per_minute` / `dcr_ip_rate_per_hour`, see below).
- Inserts a row into the Forseti-owned `oauth_client_metadata` table recording `source = "dcr"`, `verification = "unverified"`, and the registration timestamp. `dcr_iat_id` is set when an IAT was presented; NULL otherwise.
- Audits the registration as `oauth.client.dcr_registered`.
- Normalises Hydra's response before returning it to the caller — empty-string URL fields (`client_uri`, `policy_uri`, `tos_uri`, `logo_uri`) and `null` array fields (`contacts`) are stripped so strict-parser clients (Claude Code, others) don't reject a successful registration on `Invalid URL` / `expected array, received null`.

**Discovery URL.** Hydra is configured to advertise Forseti's URL as the `registration_endpoint`:

```yaml
webfinger:
  oidc_discovery:
    client_registration_url: https://accounts.example.com/oauth2/register
```

Hydra's response (including its `registration_access_token`) is passed back to the caller verbatim — follow-up `GET/PUT/DELETE /oauth2/register/{id}` calls go straight to Hydra, since the registration access token Hydra issues is Hydra-validated.

> **Why `oauth_client_metadata` lives Forseti-side**, not on the Hydra client's `metadata` JSON: RFC 7592 PUT `/oauth2/register/{id}` (handled by Hydra, not Forseti) replaces the full client representation including `metadata`. If verification state lived on `metadata.forseti.verification`, a self-registered client could flip its own badge from `"unverified"` to `"verified"` via the RAT Hydra issues on registration. Moving the trust-boundary fields into a Forseti-owned table puts them out of reach of the RAT.

**Optional Initial Access Tokens (IATs).** IATs are an opt-in for operators who want to:

- **Pre-vouch a partner integration** — issue an IAT to a known integrator so the resulting client lands attributable to a specific token (auditable via the `dcr_iat:<id>` actor on `oauth.client.dcr_registered`). Auto-promotion to Verified is not implemented yet; the operator still has to click Mark as verified.
- **Partition rate limits per tenant** — the per-IAT daily counter (`oauth.dcr_iat_daily_limit`) is independent of the per-IP limit, so high-volume integrators can be carved out with their own quota.
- **Reject specific callers** — when an IAT is revoked, registrations presenting it come back as 401 with the `iat_exhausted` audit reason.

`/admin/dcr-tokens` lists existing tokens and `/admin/dcr-tokens/new` mints fresh ones. Each token has:

- A free-form `note` (visible only to operators).
- An optional TTL in hours — blank = no expiry.
- An optional max-use count — blank = unlimited. **Single-use (`1`) is the safest default** for IATs you hand to a specific integrator; Forseti decrements `uses_remaining` inside the same transaction as the lookup so two concurrent registrations with the same single-use token can't both win.

The raw token (32 random bytes, base64url-encoded, no padding) is revealed exactly once on issue, via the same `SecretReveal` flash pattern as client secrets. Only `sha256(token)` is persisted — there is no way to recover a forgotten token; revoke and reissue.

A **malformed `Authorization` header** (wrong scheme, empty bearer value) is rejected with 401 + a `dcr_rejected` audit row, not silently treated as anonymous — that would let an attacker probe IATs without leaving a trail.

**Auditing.** Every successful registration emits `oauth.client.dcr_registered` with the returned `client_id`, posted `client_name` + `scope`, source IP hash, user agent, and a redirect-URI count (the full set is on the client itself). The actor is the IAT (`dcr_iat:<id>`) when one was presented, or `system` for anonymous registrations — the latter also carry `anonymous: true` in metadata. IAT lifecycle is auditable too: `oauth.client.dcr_iat_issued` and `oauth.client.dcr_iat_revoked` (the latter at `critical` severity so it surfaces in `/admin/audit?severity=critical`).

**Surfacing self-registered clients.** The `/admin/clients` list shows a "Self-registered" pill on rows whose Forseti-side `oauth_client_metadata.source == "dcr"`, alongside the per-client verification badge described below.

**Reviewing self-registered clients (Verified / Unverified).** Every OAuth2 client carries a verification state in the Forseti-owned `oauth_client_metadata` table:

- **`"verified"`** — green badge on the admin list + show page. The consent screen renders a subtle "Reviewed by your administrator" checkmark. Operator-created clients (anyone hitting `New client` on `/admin/clients`) are stamped verified at create time, since the act of an operator creating the client is the vouching. The `verified_by` and `verified_at` columns record who and when.
- **`"unverified"`** — yellow/red badge in the admin UI. The consent screen renders a prominent caution banner: **"This application has not been reviewed by an administrator. Only proceed if you trust it."** Self-registered DCR clients always start in this state. Forseti does not auto-promote — explicit admin action is required.

To review a self-registered client: open `/admin/clients?verification=unverified`, click into the client, eyeball the redirect URIs and `client_name`, and either:

- Click **Mark as verified** — POSTs to `/admin/clients/{id}/verify`, sets `verification = 'verified'`, `verified_by`, `verified_at`, and emits an `oauth.client.verified` audit row.
- Click **Delete** if the client is illegitimate.

To revoke a previously granted verification (e.g. the client started behaving badly), click **Revoke verification** on the show page. POSTs to `/admin/clients/{id}/unverify`, flips Forseti row back to `'unverified'`, records `verification_revoked_by` / `verification_revoked_at`, and emits a `critical`-severity `oauth.client.unverified` audit row. The consent screen reverts to the caution banner on the next consent request.

Clients that exist on Hydra without a matching `oauth_client_metadata` row default to verified — those came in through the admin UI before this table shipped, so the implicit-trust rule applies retroactively. Verify or unverify lazily creates the row; no backfill needed.

**Reserved-name denylist.** DCR registrations whose `client_name` matches any pattern in `oauth.dcr_reserved_names` are rejected with `invalid_client_metadata` (HTTP 400). The match is case-insensitive substring — `"Microsoft Login"`, `"forseti admin"`, and `"AdminBot"` all trip the default list. The default covers Forseti's own brand, upstream Ory brands, common consumer IDPs (Google, Apple, Microsoft, GitHub, GitLab), AI vendors (Anthropic, Claude, OpenAI, ChatGPT), other identity vendors (Okta, Auth0), and obvious privilege names (admin, portal, system, root). Replace the list entirely in `config.toml` if you need different behaviour. The HTTP response intentionally doesn't echo which pattern matched, so an attacker can't enumerate the list by probing — but a rejected attempt is recorded in the audit log as `oauth.client.dcr_rejected` with `reason = "reserved_name"`, the attempted name (truncated to 100 chars), the IAT id, and the source IP hash. The IAT use is **not** decremented when the name check fails, so an attacker can't drain someone else's single-use IAT by submitting reserved names.

> **Substring matching is too aggressive on short brand names.** Because the match is case-insensitive substring rather than word-boundary, short entries like `ory`, `hydra`, `kratos`, `claude`, `openai` collide with legitimate `client_name` values that merely *contain* them. In real-world testing, Claude Code's DCR was rejected because it sends `client_name: "Claude Code (ory-demo)"` — both `claude` and `ory` trip the default list. Word-boundary matching is a tracked follow-up; until it lands, operators running real Claude integrations should either remove the conflicting short strings from `oauth.dcr_reserved_names` (keeping the less collision-prone entries like `microsoft`, `google`, `apple`, `github`) or empty the list entirely if their threat model accepts it.

**Workflow (default — anonymous DCR).** No operator action required upfront. The MCP-client author calls:

```bash
curl -X POST https://accounts.example.com/oauth2/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP server",
    "redirect_uris": ["http://127.0.0.1:5000/cb"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": "openid offline_access"
  }'
```

Hydra's response carries `client_id` and `registration_access_token`; the author keeps both. The client now exists in Hydra and shows up on `/admin/clients` as **Self-registered + Unverified**. Operator opens `/admin/clients?verification=unverified`, eyeballs the redirect URIs, scopes, and `client_name`, then clicks **Mark as verified** (or **Delete** if it looks illegitimate). The consent banner clears on the next consent request.

**Workflow (optional — pre-vouching via IAT).** When you want to pre-attribute a registration to a known integrator: mint an IAT from `/admin/dcr-tokens/new`, hand the integrator the one-shot reveal, and they pass it on the call:

```bash
curl -X POST https://accounts.example.com/oauth2/register \
  -H "Authorization: Bearer <iat>" \
  -H "Content-Type: application/json" \
  -d '{ ... same body as above ... }'
```

The audit row for the registration is then keyed on `dcr_iat:<id>` instead of `system`, so an operator triaging suspicious activity can find every event back to that one issued token. The client still lands `unverified` — IAT presentation is not (yet) an auto-promotion signal.

**Rate limiting.** Two independent layers stack in front of `POST /oauth2/register`, both belt-and-suspenders to the IAT itself.

- **Per-IP** (in-memory, per-process). Two buckets enforced in parallel: 10 requests/minute and 100 requests/hour. Limits are configurable via `oauth.dcr_ip_rate_per_minute` and `oauth.dcr_ip_rate_per_hour` in `config.toml`; set either to `0` to disable that bucket. By default the limiter keys on the **TCP peer IP** (`proxy.trust_forwarded_for = false`) — unforgeable, but behind a reverse proxy that means every caller shares a single bucket (key = proxy's IP), so size the limits accordingly. To get per-real-client buckets, set `proxy.trust_forwarded_for = true` — the limiter then reads `X-Forwarded-For` (first hop), falling back to `X-Real-IP`, `Forwarded`, and the socket peer. **Only flip this on when your reverse proxy strips client-sent forwarded-for headers before re-adding its own**; otherwise a direct caller forges `X-Forwarded-For` and bypasses the bucket. The haproxy sketches in [`operator-guide-proxy.md`](./operator-guide-proxy.md) show the correct `http-request del-header X-Forwarded-For` + `set-header X-Forwarded-For %[src]` pattern. A throttled request gets `429 Too Many Requests` with `Retry-After: <seconds>` and an RFC 7591-shaped body (`error: "temporarily_unavailable"`). Per-IP hits are **not** audited — too noisy; a `trace`-level log line is emitted instead. State is in-memory only and does **not** cross-replicate; multi-instance deployments still get useful per-process gating but a determined attacker spread across replicas can exceed the nominal rate by Nx.
- **Per-IAT** (DB-backed, persists across restarts). Cap on successful registrations per IAT over a rolling 24-hour window opened by the first successful use. Default 50, configurable via `oauth.dcr_iat_daily_limit` (set to `0` to disable). The window resets in-place when 24h have elapsed since `daily_window_started_at`. Only **successful** registrations count — failed lookups, reserved-name rejects, and Hydra rejections don't burn the counter. Both the `uses_remaining` decrement and the daily-counter increment are gated by the UPDATE's `WHERE` clause inside a single transaction (`uses_remaining > 0` AND, when the window is live and `daily_limit > 0`, `daily_use_count < daily_limit`), so two concurrent successes at either boundary can't both win — the second UPDATE matches zero rows and falls through to the rejection path. A per-IAT rejection emits an audit row at `WARNING` severity (`oauth.client.dcr_rate_limited`, target = the IAT id) and returns `429` with `error: "temporarily_unavailable", error_description: "iat daily limit exceeded"`.

**Follow-ups tracked but not yet implemented:**

- TTL sweep for unused DCR clients (a self-registered client that never sees a token request after N days is probably abandoned).

If you don't want any DCR at all, set `dynamic_client_registration.enabled: false` in `hydra.yml` — but be aware Claude Code will refuse to talk to your AS.

#### RFC 9728 — Protected Resource Metadata

MCP servers advertise their authorization server via [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728). The chain:

1. Client hits MCP server unauthenticated → `401` with `WWW-Authenticate: Bearer resource_metadata="<url>"`.
2. Client fetches `<url>` (typically `/.well-known/oauth-protected-resource` on the MCP server's origin) → JSON pointing at Hydra.
3. Client follows `authorization_servers[0]` to `/.well-known/openid-configuration` on Hydra → standard OIDC discovery.

Forseti isn't in this chain — it's purely MCP-server-side. Sample resource-metadata document (the MCP-server author publishes this; operators just need to make sure Hydra's issuer URL is reachable):

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://hydra.example.com"],
  "scopes_supported": ["app:tool:invoke"],
  "bearer_methods_supported": ["header"]
}
```

#### Workflow: registering an MCP client from the admin UI

1. `/admin/clients/new` → click the **MCP server** card.
2. Name the client (e.g. "Claude Desktop — formshive MCP").
3. The form is pre-filled: `authorization_code` + `refresh_token`, `none` auth method, PKCE on, audience textarea visible, redirect-URI hints showing the common Claude callbacks.
4. Set the audience allow-list to the MCP server's canonical URL (one per line).
5. Paste the MCP client's redirect URIs. For Claude Desktop / Code these are loopback URLs (`http://127.0.0.1:PORT/cb`); for claude.ai, Anthropic's hosted callback (`https://claude.ai/api/mcp/auth_callback`).
6. Define custom scopes — `<app>:<resource>:<verb>` convention. Add corresponding descriptions under `[oauth.scope_descriptions]` in `config.toml` so the consent screen reads naturally. The client show page surfaces a warning banner for scopes that don't have a description.
7. Submit. The next page shows a one-shot reveal of the registration access token (no client secret — public client).

#### Verifying the discovery document

After bringing the stack up, confirm Hydra's discovery doc carries everything MCP clients read:

```bash
curl -s http://localhost:4444/.well-known/openid-configuration | jq '{
  issuer,
  registration_endpoint,
  code_challenge_methods_supported,
  grant_types_supported,
  token_endpoint_auth_methods_supported
}'
```

Expected:

- `registration_endpoint` present (DCR enabled).
- `code_challenge_methods_supported` includes `"S256"`.
- `grant_types_supported` includes `authorization_code`, `refresh_token`, `client_credentials`.
- `token_endpoint_auth_methods_supported` includes `"none"`, `"client_secret_post"`, `"client_secret_basic"`.

Hydra does not advertise `resource_indicators_supported` (no RFC 8707 yet). Spec-strict MCP clients haven't been observed to reject Hydra for that omission — track it in case behaviour changes.

#### State parameter

Even with PKCE, the [Ory MCP guide](https://www.ory.com/blog/mcp-server-oauth-with-ory-hydra-authentication-ai-agent-integration-guide) recommends MCP clients still send `state`. Belt-and-braces: PKCE prevents code-injection, `state` prevents CSRF on the redirect. Forseti doesn't enforce this; it's a client-side recommendation worth surfacing to MCP-server authors.

#### At-rest hashing for refresh tokens and introspection caches

If the MCP server caches introspection responses (defensible up to ~30s) or stores refresh tokens it received on behalf of the user, hash them at rest with SHA-256+ rather than storing raw values. Note this in the MCP-server's own deployment docs — Hydra and Forseti don't enforce it.

## SMTP

Two SMTP transports operate independently and can both point at the same relay:

- **Kratos courier** — verification codes, recovery codes, MFA enrolment notifications, and any Kratos-template-driven mail. Configured under `courier.smtp` in `kratos.yml`.
- **Forseti mailer** — org invites and the hand-rolled `/claim-email` verification code. Configured under `[email]` in `config.toml`. Forseti sends directly (via [polymail](https://github.com/franzos/polymail-rs)) because Kratos's admin API doesn't expose a one-off "send this message" endpoint in v26+.

### Kratos courier

Kratos sends verification, recovery, and code emails through SMTP. Replace the playground Mailcrab config with a real provider:

```yaml
courier:
  smtp:
    connection_uri: smtps://AKIAIOSFODNN7EXAMPLE:secret@email-smtp.us-east-1.amazonaws.com:465/?skip_ssl_verify=false
    from_address: no-reply@example.com
    from_name: Example Accounts
```

Worked example for Amazon SES:

1. Verify the sender domain (`example.com`) in the SES console.
2. Create an SMTP credential under "SMTP Settings".
3. Use the host `email-smtp.<region>.amazonaws.com:465`, SMTPS scheme, the credential as username/password.

For Postmark, substitute the connection URI: `smtps://<server-token>:<server-token>@smtp.postmarkapp.com:465/`.

### Forseti mailer

Lives Forseti-side. Without it, invite + claim-email mails are dropped (the underlying token / code stays valid in the DB so an operator can hand-deliver in dev, but end users won't see anything in their inbox). Pick a provider via `provider`; an SMTP relay (which can be the same one Kratos uses) looks like:

```toml
[email]
enabled      = true
from_address = "no-reply@example.com"
provider     = "smtp"
host         = "email-smtp.us-east-1.amazonaws.com"
port         = 465
tls          = "implicit"           # none | start_tls | implicit
user         = "AKIAIOSFODNN7EXAMPLE"
pass         = ""                    # set via FORSETI_EMAIL__PASS in prod
```

Or a transactional API provider (token injected via env):

```toml
[email]
enabled      = true
from_address = "no-reply@example.com"
provider     = "postmark"           # or lettermint
token        = ""                    # set via FORSETI_EMAIL__TOKEN
```

(SendGrid is the same shape but uses `api_key` instead of `token`, injected via `FORSETI_EMAIL__API_KEY`.)

Sanity-check: omitting the section (or `enabled = false`) leaves the mailer dormant — useful for OSS deployments that don't have a provider handy or for tests. Disabled-state callers `tracing::info!` the would-be recipient and continue without error, so the surrounding flow still completes.

### Email templates

Kratos ships default templates but they are plain. Override them per flow:

```yaml
courier:
  template_override_path: /etc/config/kratos/email-templates

selfservice:
  flows:
    verification:
      notify_unknown_recipients: false
    recovery:
      notify_unknown_recipients: false
```

Place templates at `/etc/config/kratos/email-templates/<flow>/<template>.gotmpl`. See <https://www.ory.sh/docs/kratos/concepts/email-templates>.

## Member profiles

Off by default. When `[profiles].enabled = true`:

- `/settings/profile` grows a **Public profile** form (bio, location, pronouns, website, avatar URL, links).
- `/users/{identity_id}` renders a profile view — only when the viewer shares at least one org with the target. Anonymous viewers and non-sharing viewers see a 404 (not 403; no "this page exists" leak).
- The members roster on `/settings/organization/members` links each row with a non-empty profile to that view page.
- Avatar: external `avatar_url` only — no upload pipeline. When unset, a deterministic SVG identicon (hash → 5-cell mirrored pattern) renders as fallback.
- Audit: `profile.updated` event on each save. No view-events.

```toml
[profiles]
enabled = true
```

### OIDC exposure

The `profile` scope picks up two additional standard OIDC claims when `[profiles].enabled` is on AND the user filled the fields:

- `picture` — the `avatar_url` value
- `website` — the `website` value

A new `extended_profile` scope exposes Forseti-specific claims:

- `bio` (string, up to ~280 chars)
- `pronouns` (string)
- `links` (array of `{label, url}` pairs)

Add a description under `[oauth.scope_descriptions]` so the consent screen reads naturally:

```toml
[oauth.scope_descriptions]
extended_profile = "View your bio, pronouns, and personal links"
```

Revocation is whole-grant — to stop sharing the extended block, the user revokes the OAuth client at `/settings/authorized-apps` and re-consents with a narrower scope set.

### When to leave it off

- SaaS-shape deployments where customers share an org tenant but shouldn't see each other's profile data.
- MCP / API-only deployments where users are mostly machines.
- Anywhere bio + links would be noise rather than helpful context.

The OSS default is off so these deployments don't accidentally surface a feature that doesn't fit their topology.

## Reverse proxy

The reverse proxy terminates TLS, forwards real client IPs, and routes to Forseti, Kratos public, and Hydra public.

Two topologies are supported:

- **Path-prefixed on one host** (`accounts.example.com/`, `/hydra/*`, `/kratos/*`) — **recommended.** Same-origin everywhere, host-only cookies, no CORS to configure, only `:443` exposed. Explicitly endorsed in Hydra's production guide.
- **Subdomains** (`accounts.example.com`, `hydra.example.com`, `kratos.example.com`) — workable, matches Ory's canonical examples. Cross-origin once anything in Forseti calls Kratos/Hydra from the browser, so you'll grow CORS config over time.

See [`operator-guide-proxy.md`](./operator-guide-proxy.md) for the full reasoning, the third shape we evaluated and rejected (distinct ports), and haproxy configs for both supported shapes. The diagram at the top of this guide shows the subdomain shape; both are valid.

### Nginx sketch (subdomain shape)

```nginx
server {
    listen 443 ssl http2;
    server_name accounts.example.com;
    ssl_certificate     /etc/letsencrypt/live/accounts.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/accounts.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }
}

server {
    listen 443 ssl http2;
    server_name kratos.example.com;
    location / {
        proxy_pass http://127.0.0.1:4433;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }
}

# repeat for hydra.example.com -> 127.0.0.1:4444
```

### Caddy sketch (subdomain shape)

```caddyfile
accounts.example.com {
    reverse_proxy 127.0.0.1:3000
}

kratos.example.com {
    reverse_proxy 127.0.0.1:4433
}

hydra.example.com {
    reverse_proxy 127.0.0.1:4444
}
```

Caddy injects `X-Forwarded-*` headers automatically and handles TLS via Let's Encrypt.

For the path-prefixed shape, the rewrite is the load-bearing bit — `/hydra/*` and `/kratos/*` must be stripped before the upstream sees them, since Hydra and Kratos don't honour subpath mounting. The haproxy example in the proxy doc shows the exact rewrite rules.

Forseti currently logs the peer IP it sees from the TCP socket. With a proxy in front, that is the proxy's IP. Forseti does not yet honor `X-Forwarded-For` for logging; treat the forwarded header as the source of truth in your log pipeline.

## Secrets management

The following secrets must be unique, long, and protected:

| Secret                                     | Where it lives               | Purpose                                            |
|--------------------------------------------|------------------------------|----------------------------------------------------|
| `hydra.yml: secrets.system`                | Hydra                        | Encrypts everything in Hydra's database.           |
| `hydra.yml: oidc.subject_identifiers.pairwise.salt` | Hydra               | Per-client pairwise subject identifier salt.       |
| `kratos.yml: secrets.cookie`               | Kratos                       | Signs Kratos session cookies.                      |
| `kratos.yml: secrets.cipher`               | Kratos                       | Encrypts sensitive trait values at rest.           |
| OIDC client secrets (per upstream)         | `kratos.yml` env substitution | Authenticate to upstream OIDC providers.          |

Recommended pattern: load secrets from environment variables injected by your orchestrator or secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler, 1Password Connect). Do not commit any of the above to a repository.

Generate fresh values with `openssl rand -base64 64` (cookie/session secrets) or `openssl rand -hex 32` (cipher keys requiring 32 bytes).

## Backups

- **Kratos's Postgres database** holds every identity, credential hash, and active session. Restoring it restores user accounts.
- **Hydra's Postgres database** holds OAuth2 client registrations, consent grants, refresh tokens, and the JWKS used to sign id_tokens. Losing the JWKS invalidates every previously-issued id_token's signature.
- Take daily logical backups (`pg_dump`) at minimum. Streaming replication or PITR is preferable for production.
- Test restore quarterly. A backup you have never restored is not a backup.

## Observability

### Logs

- Forseti emits JSON logs to stdout via `tracing_subscriber`. Levels: `info` (request lifecycle), `warn` (recoverable issues), `error` (handler failures). Forward to your aggregator (Loki, CloudWatch, Datadog).
- Kratos and Hydra also emit structured logs; set `log.format: json` and `log.level: info` in their respective configs.
- Set `log.leak_sensitive_values: false` in `kratos.yml` outside development.

### Health endpoints

| Endpoint              | Service | Purpose                                                |
|-----------------------|---------|--------------------------------------------------------|
| `/healthz`            | Forseti | Liveness. Returns `ok` if the process is up.           |
| `/readyz`             | Forseti | Readiness. Returns `ready` (200) when Forseti will serve. If the background webhook worker has been silent for more than 4x `[webhook].tick_seconds` (floor 20s), it still returns 200 but the body reads `ready (degraded: webhook worker stale, ...)`; page serving is unaffected, so a stuck worker does not pull the instance out of rotation. Monitor the body (or logs) to catch a stale worker before undelivered webhooks pile up. |
| `/health/alive`       | Kratos  | Liveness.                                              |
| `/health/ready`       | Kratos  | Readiness (checks DB connectivity).                    |
| `/health/alive`       | Hydra   | Liveness.                                              |
| `/health/ready`       | Hydra   | Readiness (checks DB connectivity).                    |

Wire all three readiness probes into your load balancer / orchestrator.

### Metrics

Forseti exposes a Prometheus `/metrics` endpoint on the internal listener (`[internal].bind`) as a commercial feature: it needs a license with the `observability` capability and a configured scrape token, and it 404s otherwise. It serves HTTP RED metrics (request counts, latency, by method/route/status) plus a couple of bridged operational gauges. See [Commercial: Observability](commercial/observability.md) for enabling it, what it exposes, and the scrape config.

Hydra and Kratos expose their own Prometheus metrics on their admin ports, independent of this.

## Common gotchas

### Cookie domain

In the playground all services bind to `127.0.0.1` so cookies are port-agnostic and the browser sends Kratos's session cookie back to Forseti at `:3000` without further scoping. In production:

- Kratos must serve from a hostname that shares a parent domain with Forseti. `accounts.example.com` (Forseti) and `kratos.example.com` (Kratos public) share `.example.com`, so Kratos can issue a cookie scoped to `.example.com` that both hostnames see.
- Forseti still calls Kratos's *admin* API on an internal hostname (e.g. `kratos.internal:4434`) for server-side operations. That call does not need cookie scoping.
- The browser must reach Kratos's *public* API on a publicly-resolvable hostname for cookie scoping to work. Path-rewriting Kratos behind Forseti's hostname is possible but adds complexity; a separate hostname is simpler.

### CORS

Kratos's `serve.public.cors.allowed_origins` must include Forseti's public URL. Without it, browser fetches to Kratos's public API (used by HTMX during flow submission) fail silently or with a preflight error.

### AAL2 auto-elevation after enrollment

When a user enrolls a second factor (TOTP, lookup_secret, WebAuthn, passkey) inside a privileged settings flow, Kratos automatically marks the session as `aal2` going forward. The user does not have to re-authenticate to use the new factor. This is correct behavior but surprises operators verifying their setup — the second factor "just works" immediately because the enrollment ceremony itself satisfied AAL2. (Enforcement of AAL2 on *subsequent* logins is a separate concern — see [Two-factor authentication enforcement](#two-factor-authentication-enforcement).)

### Settings flow per-method return URLs

Kratos's `selfservice.flows.settings.after.<method>.default_browser_return_url` is consulted per method, not globally. Without per-method overrides, every settings save lands users on the same generic page. See the [Flow URLs](#flow-urls) section.

### `allowed_return_urls`

Kratos refuses to redirect to a `return_to` URL not in `selfservice.allowed_return_urls`. Add every downstream app hostname that drives a Kratos flow with `?return_to=...`. Forseti's own base URL must be in the list.

### Issuer URL changes

If `urls.self.issuer` in `hydra.yml` ever changes, every previously-issued id_token becomes invalid (it embeds `iss`). Existing OAuth2 clients also discover endpoints via `<issuer>/.well-known/openid-configuration`, so OIDC discovery URLs change as well. Treat the issuer URL as immutable post-launch.

### WebAuthn / passkey requirements

Forseti supports both WebAuthn (typically as a second factor) and passkeys (passwordless first-factor sign-in) via Kratos's `webauthn` and `passkey` methods. End-user availability depends on browser + device support, which Forseti detects at page load:

- **WebAuthn buttons** ("Sign in with hardware key", "Add security key") need any FIDO2 authenticator — a USB security key, a platform credential, a Bluetooth/NFC device, or a software emulator. Most modern browsers on most devices satisfy this.
- **Passkey buttons** ("Sign in with passkey", "Sign up with passkey") need a **platform credential** specifically: Touch ID, Face ID, Windows Hello, an Android device passkey, or a synced passkey from iCloud Keychain / Google Password Manager / 1Password / Bitwarden / etc. Kratos's passkey method hardcodes `authenticatorAttachment: "platform"` in the WebAuthn challenge to enforce this — cross-platform authenticators are explicitly rejected.

When Forseti detects a missing platform credential (`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()` returns `false`), it disables the passkey button and shows an inline explanation. WebAuthn buttons remain enabled because cross-platform authenticators are valid for them.

For local development, the most common gotcha is **Linux + Firefox** without TPM or a browser-side passkey store — passkey sign-in won't work there. Workarounds:

- **Chrome DevTools virtual authenticator**: F12 → "..." menu → More tools → WebAuthn → "Enable virtual authenticator environment" → Add authenticator (transport: internal, residentKey: true).
- **Firefox soft token**: `about:config` → `security.webauth.webauthn_enable_softtoken` = `true`, restart.
- **Real device**: macOS (Touch ID / Safari), Windows (Windows Hello / Edge), or Android (any modern browser).

Also note: WebAuthn requires either HTTPS or the origin to be `localhost`. Bare-IP origins like `http://127.0.0.1:3000` are rejected by Firefox/LibreWolf as invalid RP IDs. The playground uses `localhost` deliberately for this reason. Production deployments must use HTTPS with a real domain.

### Silent failures from Kratos's helper

Kratos's served `webauthn.js` swallows ceremony errors via `.catch(err => console.error(err))`, which means without intervention users see no feedback when a WebAuthn or passkey attempt fails. Forseti patches `console.error` at page load to forward DOMException-shaped errors into a visible banner above the form — see `templates/partials/webauthn_helper.html`. Operators forking the templates should preserve this helper.

### Per-method registration hooks

`selfservice.flows.registration.after` is configured **per credential method**, not globally. If you enable a method (`passkey`, `webauthn`, `code`, `oidc`) but only configure hooks under `after.password`, users who sign up via the other methods complete registration but receive **no session** — they land on `/login` after signup with no clear indication they're already registered. Symptom: the password signup path works fine but passkey/webauthn signup looks like "nothing happened."

Add identical hook lists for every enabled method:

```yaml
selfservice:
  flows:
    registration:
      after:
        password:    { hooks: [{ hook: session }] }
        passkey:     { hooks: [{ hook: session }] }
        webauthn:    { hooks: [{ hook: session }] }
        code:        { hooks: [{ hook: session }] }
        oidc:        { hooks: [{ hook: session }] }
```

The `session` hook auto-logs the new user in so they land on the dashboard rather than getting bounced to `/login`. **Email verification is not enforced here by default** — the dashboard's verification banner prompts the user to verify at their leisure, and operators don't gate features on the verified flag. This is the consumer-SaaS default (Notion, Linear, etc.).

If your product requires verified email **before** any dashboard access (typical for fintech, healthcare, B2B with PII), add `{ hook: show_verification_ui }` after the `session` hook in each method. Kratos will then redirect to `/verification` after registration and only let the user proceed when the email is confirmed:

```yaml
password:    { hooks: [{ hook: session }, { hook: show_verification_ui }] }
```

Mirror the playground config in `infra/kratos/kratos.yml`.

## Commercial license

Forseti ships an offline-signed license gate under `src/commercial/` that unlocks the paid-tier features outlined in [`../MONETIZATION.md`](../MONETIZATION.md). The open-source build runs without a license and surfaces an upsell page on any gated capability — Organizations, SAML connectors, SCIM, SIEM streaming, bulk admin operations.

### Activation

Paste the license blob you received from sales at `/admin/license` and click **Activate**. Forseti verifies the Ed25519 signature against the public key baked into the binary (`src/commercial/pubkey.bin`); no network call is made during activation. Verified licenses are persisted in the Forseti-owned `forseti_license` table as a singleton row and survive restarts.

### Configuration

```toml
[license]
purchase_url = "https://example.com/buy"
```

- `purchase_url` — where the upsell page's CTA points. Empty default falls back to `mailto:<brand.support_email>`.

After `expires_at`, gated features stay read-only for a fixed **30 days** before hard-gating. This grace window is not operator-configurable.

### Revocation tradeoff

Licenses are **offline-verified**. Forseti never phones home, so once a blob is signed it can't be revoked remotely. Two mitigations:

- **Yearly licenses self-expire.** A leaked Pro or Enterprise blob is invalid within the renewal window, automatically.
- **Lifetime licenses are sold only on the Light tier**, where the blast radius of a leak is bounded by the per-license org cap.

If you need true revocation (e.g. a customer churns with 9 months left on their Pro renewal), the operational answer today is to re-issue every outstanding license against a rotated keypair — the leaked blob fails signature verification on the next deploy. Plan key rotation as a customer-facing event, not a routine operation.

### Pubkey rotation

To rotate the verification key:

1. In the issuer repo (`forseti-license`), run `ory-license keygen --force` to generate a fresh keypair.
2. Copy `keys/public.bin` into Forseti at `src/commercial/pubkey.bin` and rebuild.
3. Re-issue every outstanding license against the new private key and ship the new blobs to customers.
4. Roll out the new binary. Forseti logs `license: persisted blob no longer verifies (likely pubkey rotated); operator must re-activate` and falls back to `Unlicensed` for any unmigrated install.

No overlap window: an install on the new binary won't accept blobs signed by the old key.

## Organizations

Even OSS deployments carry a real `organizations` table (seeded with one "Default" row). Multi-org is a commercial feature gated on `Feature::Orgs`; the Default org is free.

### Default-org admin

`/settings/organization` is the operator UI for renaming the Default org, swapping its logo, setting a support email, and managing members. The page replaces the old "edit `config.toml` to add admins" workflow — `admin.allowed_emails` still works (it's the *Forseti-wide* allowlist, separate from per-org `owner`/`member` roles), but new admins land cleanly via Member promotion in the UI.

### First-user bootstrap

The first identity to complete registration on a fresh install is auto-promoted to `owner` of the Default org. The threat model assumes the operator is the first to register on a freshly-deployed instance.

Identities whose email matches `admin.allowed_emails` are also auto-promoted to Default-org `owner` regardless of registration order, so Forseti admins always have governance in the Default org.

### Per-org branding

An org owner sets branding on the org's settings page (`/settings/organization/branding`), and those values override `[brand]` in `config.toml` for any request resolved into that org's scope; unset fields fall back to `[brand]`. Branding covers:

- **Theme preset** — `default`, `midnight`, or `cyberpunk`, each with an auto-derived dark-mode variant.
- **Brand colours** — primary, on-primary (foreground on the primary), and secondary, entered as hex; the derived dark-mode palette is contrast-checked.
- **Logo** — either a `logo_url` (absolute HTTPS; private, loopback, and cloud-metadata addresses are rejected) or an **uploaded** image (PNG/JPEG/WebP, ≤256 KB, validated by magic bytes and served from Forseti at `/branding/{slug}/logo`).
- **Support email**, and the **public-login** toggle that exposes the org's landing page at `/o/{slug}`.

The active org's theme white-labels the whole authenticated app, not just the login screen. The Default org is treated like any other org for this resolution — operators who want a single brand for everyone leave the Default org's branding empty.

### `[orgs]` configuration

| Key                              | Type     | Default   | Description                                                                                  |
|-----------------------------------|----------|-----------|------------------------------------------------------------------------------------------------|
| `active_org_cookie_ttl_seconds`   | u64      | `2592000` (30d) | Validity of the signed `forseti_active_org` switcher cookie.                            |
| `invite_ttl_days`                 | i64      | `7`       | How long a minted org invite stays claimable.                                                  |
| `reserved_names`                  | string[] | (code-baked set) | Org-name denylist (create + rename), case-insensitive/confusable-folded substring match. When absent, falls back to the same built-in operator-brand denylist as `oauth.dcr_reserved_names`. |
| `logo_ip_rate_per_minute`         | u32      | `60`      | Per-IP rate limit on `GET /branding/{slug}/logo`, requests per minute. `0` disables the bucket. |
| `logo_ip_rate_per_hour`           | u32      | `600`     | Per-IP rate limit on `GET /branding/{slug}/logo`, requests per hour, in parallel with the per-minute bucket. `0` disables the bucket. |
| `landing_ip_rate_per_minute`      | u32      | `60`      | Per-IP rate limit on `GET /o/{slug}` (the public landing page), requests per minute. `0` disables the bucket. |
| `landing_ip_rate_per_hour`        | u32      | `600`     | Per-IP rate limit on `GET /o/{slug}`, requests per hour, in parallel with the per-minute bucket. `0` disables the bucket. |
| `landing_global_rate_per_minute`  | u32      | `300`     | Global (all-callers-share-one-bucket) rate limit on `GET /o/{slug}`, requests per minute, shared across every slug. `0` disables the bucket. |
| `landing_global_rate_per_hour`    | u32      | `3000`    | Global rate limit on `GET /o/{slug}`, requests per hour, in parallel with the per-minute global bucket. `0` disables the bucket. |
| `domain_verify_http_file_enabled` | bool     | `true`    | Offer the HTTP well-known-file domain-ownership method on the domains page. `false` disables it deployment-wide. |
| `domain_verify_dns_txt_enabled`   | bool     | `true`    | Offer the DNS TXT domain-ownership method. |
| `domain_verify_email_enabled`     | bool     | `true`    | Offer the email (`admin@`/`postmaster@`) domain-ownership method. |
| `domain_verify_http_timeout_seconds` | u64  | `10`      | Total timeout for the HTTP well-known-file fetch. |
| `domain_max_per_org`              | u32      | `100`     | Ceiling on registered domains (pending + verified) per org; bounds row growth and challenge-email fan-out. |

### External access mode (public self-serve)

A licensed, non-Default org can switch from **internal** (invite-only, the default) to **external**, which stands up a public landing page at `/o/<slug>` and a self-serve `/join/confirm` flow. Only an org owner with an active Orgs license can flip the switch (`require_external_mode_writable`); the Default org can never be external.

**Admins-only directory, hard-enforced.** Switching to external automatically sets the member-directory visibility to administrators-only and turns public login on. Unlike other visibility settings, administrators-only is **not** just a default for external orgs — it's enforced: an owner cannot loosen it to a more open policy while the org stays external. The attempt is rejected with a `400` and recorded in the audit log (`org.visibility_changed`, `warning` severity, marked failed) so a misconfigured or coerced owner leaves a trail. Switching the org back to internal lifts the restriction.

**No verification gate on join, by design.** `/join/confirm` joins the visitor as a **member** immediately on explicit CSRF-confirmed consent — there's no "verify your email first" step. This is deliberate: verification only gates placement that is *derived from the email* (domain auto-join, below). Public self-serve derives membership from an explicit action for a specific org, not from the email, so the email isn't the credential and a verification gate would add nothing. If your threat model needs verified-first public onboarding, force it at the identity layer by adding a Kratos `show_verification_ui` hook to the registration flow, and keep the [unverified-account reaper](#unverified-account-reaper) running as the backstop against unverified squatters.

**`trust_forwarded_for` prerequisite.** The rate limits on `/o/{slug}` and `/registration` are per-IP; they're only meaningful when `[proxy].trust_forwarded_for` is `true` **and** your reverse proxy actually strips inbound `X-Forwarded-For` before re-adding its own (see the [proxy guide](./operator-guide-proxy.md)). Behind a proxy that doesn't strip it, a caller can forge the header and dodge the per-IP bucket entirely — the global bucket (`[auth]`/`[orgs]` `*_global_rate_*`) is the backstop either way.

**Rate-limit posture and its limit.** `GET /o/{slug}` and `GET /registration` both carry paired per-IP + global buckets (see [`[orgs]` configuration](#orgs-configuration) and [`[auth]` configuration](#auth-configuration) above). The known gap: the actual registration **POST** goes straight from the browser to Kratos's own public endpoint — Forseti never sees it — so Forseti's `/registration` limit only bounds page *renders*, not submissions. Rate-limit Kratos's own public API at the reverse-proxy layer if you need to bound the POST itself.

**CAPTCHA: not implemented, by design.** Forseti doesn't own the registration POST (see above), so a server-enforced CAPTCHA would need a blocking Kratos `before` hook plus a new Forseti verify webhook plus a client-side widget plus org-conditional logic — a multi-system integration disproportionate to what this phase covers. A client-side-only widget with no server-side check would be a placebo, so none was built. If you need bot-resistant signup today, put a CAPTCHA-capable WAF or reverse-proxy rule in front of Kratos's public registration endpoint.

### Internal domain auto-join

The complement to external mode, for **internal** orgs: an owner registers email domains the org controls, and a user whose **verified** email matches an ownership-proven domain is offered a one-click prompt to join that org (as a `member`) — the workforce equivalent of "anyone with an `@acme.com` address can join the Acme org". Managed at `/settings/organization(s)/{slug}/domains`; owner-only, licensed, non-Default, and internal-only (external orgs use the self-serve path above instead).

**Opt-in and prompt-based, never silent.** Domain auto-join only happens when the owner sets the org's join policy to **auto-join** (the default is invite-only); an internal org with proven domains but the invite-only policy stays invite-only. Even with auto-join on, the user is *prompted* on their dashboard ("You have a verified `<domain>` address, join `<Org>`?") and joins only on explicit confirmation. The proven domain replaces the admin invite as the authorization, but the join is still an explicit act.

**Ownership must be proven** — a domain is not honoured until the org demonstrates control via one of three methods, each individually disableable in `[orgs]` config:

- **HTTP well-known file** (`domain_verify_http_file_enabled`) — Forseti fetches `https://<domain>/.well-known/forseti-domain-verify` and checks it contains the minted token. The fetch runs through the same SSRF guard as outbound webhooks (HTTPS-only, internal/loopback/link-local/IMDS addresses rejected, DNS-rebinding re-checked at connect, no redirects, size-capped, `domain_verify_http_timeout_seconds` timeout), so an owner cannot point a "domain" at an internal host.
- **DNS TXT** (`domain_verify_dns_txt_enabled`) — a TXT record at `_forseti-verify.<domain>` must contain the token.
- **Email** (`domain_verify_email_enabled`) — the token is mailed to `admin@<domain>` and `postmaster@<domain>`; the owner pastes it back. The confirmation is a constant-time compare, and the mail names the requesting org and actor so abuse of a paid account is attributable.

**Guardrails.** A domain can be verified under **at most one org** globally (a partial unique index, not just app logic), so no org can claim a domain another already owns or absorb its users. Freemail/public domains (gmail, outlook, proton, …) are rejected at add time. Eligibility is gated on the user's **specific** verified address (never the raw trait email), re-checked at the moment they confirm the prompt — so an unverified `ceo@victimcorp.com` registration is never offered or joined, and the prompt appears only once the user has clicked their verification link. `domain_max_per_org` caps how many domains an org can register.

**Prerequisite.** Because the join requires a genuinely verified address, this feature only works if Kratos email verification is enabled and identities are not created pre-verified (the playground default). Removing a domain stops future auto-join but does not remove members who already joined under it.

### `[identity]` configuration

```toml
[identity]
unverified_ttl_days = 7
```

- `unverified_ttl_days` — TTL applied by the `unverified-prune` CLI. Identities with at least one unverified verifiable address AND `created_at < now - N days` are deleted. Default `7`. GitHub uses `30`; we run more aggressive because a stuck unverified squatter blocks the legitimate owner. Operators with a slower onboarding flow can dial up.

### Unverified-account reaper

```bash
forseti unverified-prune
```

Walks Kratos's identity list and deletes any identity that's both old enough and still unverified. Mirrors `audit-prune` — same exit code semantics (0 = success, 1 = failure), same `[database].skip_migrations` plumbing (no migrations needed at all for this CLI; it only touches Kratos).

**Strongly recommended as a cron, not just a CLI you might forget to run.** Example systemd timer + service:

```ini
# /etc/systemd/system/forseti-unverified-prune.timer
[Unit]
Description=Daily unverified-account reaper

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target

# /etc/systemd/system/forseti-unverified-prune.service
[Unit]
Description=Run forseti unverified-prune
After=network.target

[Service]
Type=oneshot
User=forseti
WorkingDirectory=/opt/forseti
ExecStart=/opt/forseti/forseti unverified-prune
```

The reaper, together with the per-invite verified-only check and the hand-rolled claim-email flow at `/claim-email`, closes the unverified-email-squatting gap left by Kratos's default registration.

### Re-claim flow safety rails

The claim-email flow lets the legitimate owner of an email reclaim it from an unverified squatter. Two safety rails the operator should understand:

- **Admin-allowlist refusal.** If the squatter's email is in `admin.allowed_emails`, the claim is refused (both at mint and at confirm). Without this, an attacker watching for fresh entries in the allowlist could race the operator: as soon as a new admin email lands but before it's verified, an attacker could claim it and inherit Forseti-admin. The refusal logs `WARN claim-email: refused — target email is in admin.allowed_emails` with the email + target identity id, but externally returns the same generic banner as the not-found branch (no enumeration leak). When that warn fires, the right escape hatch is for the operator to delete the bogus identity via `/admin/identities` and let the legitimate owner register clean.
- **TOCTOU re-check at confirm.** If the legitimate owner happens to walk through `/verification` between the moment the claim code is minted and the moment the claimer submits it, the confirm path refuses to delete (now-verified identities are off-limits). Avoids the case where a verified user gets wiped because a race-window claim was already in flight.

The claim **destroys** the squatter's identity and redirects the claimer to a fresh `/registration`. The claimer does not inherit any state — they pick their own password, set their own traits, and get a new Kratos identity UUID. Email ownership proves only the right to delete + register-fresh; it does not transfer the existing account.

## Commercial features

Some features are gated behind a commercial license — see [`commercial/`](./commercial/) for the overview and licensing model. In particular, **Enterprise SAML SSO** (per-org `/sso/{slug}` login against a corporate IdP) is documented in [`commercial/saml.md`](./commercial/saml.md), and the multi-org model in [`commercial/organizations.md`](./commercial/organizations.md).

## Further reading

- [`../README.md`](../README.md) — project overview and quickstart
- [`../ROADMAP.md`](../ROADMAP.md) — milestone roadmap
- [`integration-guide.md`](./integration-guide.md) — downstream app integration
- [Ory Kratos docs](https://www.ory.sh/docs/kratos)
- [Ory Hydra docs](https://www.ory.sh/docs/hydra)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
