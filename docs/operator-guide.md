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
- **SMTP provider.** Mailcrab (used in `infra/docker-compose.yml`) is a development sink. In production, use a real provider: Amazon SES, Postmark, Resend, SendGrid, or Mailgun. Two pieces of the stack speak SMTP independently: **Kratos** (verification, recovery, MFA-enrol mails) via `courier.smtp.connection_uri` in `kratos.yml`, and **Forseti** (org-invite + claim-email mails) via `[smtp]` in `config.toml`. Both can point at the same relay.
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

### Cookie signing keys

There's no `[cookies]` block. The HMAC keys for Forseti's signed cookies (flash, `active_org`, `forseti_app_referrer`) are derived per-cookie via SHA-256 over `[self].url` plus a per-use domain-separation salt (see `src/flash.rs`, `src/orgs/cookie.rs`, `src/handoff/cookie.rs`). Rotating those keys means rotating `[self].url` — they're not security-critical on their own (the flash banner is short-lived, the org cookie's selection is re-validated at use, the handoff cookie's `referrer_uri` is re-checked against the Hydra client). Forseti does not own its own session cookie; that's Kratos.

CSRF protection uses a double-submit token (`src/csrf.rs`), not a server-side signing key, so there's nothing to configure for it either.

### `[brand]`

| Key             | Type   | Default            | Description                                                            |
|-----------------|--------|--------------------|------------------------------------------------------------------------|
| `name`          | string | `"Forseti"`     | Brand name shown in the header, page titles, and email templates.      |
| `support_email` | string | none               | Support address rendered in footer / error pages.                      |
| `logo_url`      | string | none               | Optional logo URL. When omitted, the brand name is rendered as text.   |
| `consent_intro` | string | (generic sentence) | Intro paragraph rendered on `/oauth/consent` above the scope list.     |

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
| `bind` | string | `"127.0.0.1:8081"` | Bind address for the internal listener (today: the audit webhook receiver). Never expose this on a public interface — see [Internal listener](#internal-listener). |

### `[smtp]`

Forseti-owned outbound mail (org invites + claim-email). Kratos's courier handles its own self-service mail separately. Disabled by default — when off, send sites log + skip so dev still works with the token / code accessible via the DB.

| Key               | Type   | Default       | Description                                                                                                       |
|-------------------|--------|---------------|-------------------------------------------------------------------------------------------------------------------|
| `enabled`         | bool   | `false`       | Master switch. When `false`, Forseti logs the would-be recipient and returns without contacting the SMTP server. |
| `host`            | string | `"127.0.0.1"` | SMTP server hostname.                                                                                             |
| `port`            | u16    | `1025`        | SMTP server port. Plaintext defaults to `1025` (Mailcrab); production typically uses `587` or `465`.  |
| `scheme`          | string | `"plaintext"` | Connection scheme: `plaintext`, `starttls`, or `smtps`.                                                           |
| `from`            | string | `""`          | From address. Falls back to `noreply@<self.url host>` when empty.                                                 |
| `username`        | string | `""`          | SMTP username. Empty means no auth.                                                                               |
| `password`        | string | `""`          | SMTP password. Source from env (`FORSETI_SMTP__PASSWORD`) in prod.                                                 |
| `skip_tls_verify` | bool   | `false`       | Accept self-signed / invalid TLS certs. Leave `false` in prod.    |

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
| `/admin/status`                       | Kratos + Hydra health probes, courier queue (pending / failed counts), and build versions for Forseti, Kratos, and Hydra. |
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

### App templates

`/admin/clients/new` shows a "Popular apps" group below the five base client types. Picking one (GitLab, Nextcloud, Grafana, …) pre-fills the create form for that app — redirect URIs, scope, token-endpoint auth method, PKCE, and any logout/webhook URLs — so you don't have to look up each app's OIDC quirks. There are around 23 templates.

The pre-filled URLs use literal placeholders you must replace before saving:

- `YOUR_DOMAIN` — the app's own hostname (e.g. `git.example.com`), not Forseti's. Several apps embed it in a fixed callback path.
- `PROVIDER_NAME` — for apps where the callback path includes the provider/auth-source name you configure app-side (Gitea, Forgejo, Vikunja, Paperless-ngx, Jellyfin). Replace it with whatever name you set there; some apps are case-sensitive about it.

Some templates carry a guidance banner on the form (e.g. PROVIDER_NAME notes, audience allow-list reminders) — read it before saving.

The template choice is not persisted. It only seeds the form; the client's stored `client_type` records the base preset (e.g. `web_app`), so the list filter and detail-page badge are unaffected by which app you started from.

After creating a client, its detail page (`/admin/clients/{id}`) shows a "Connection details" card with the issuer and OIDC endpoints (authorization, token, userinfo, JWKS, end-session) plus the client ID — everything you paste into the app's OIDC settings on the other end. The endpoints come from Hydra's discovery document; if Forseti can't reach Hydra at render time the card hides the endpoints and shows a note rather than guessing a (possibly wrong) issuer.

### Audit logging

Audit events are persisted to the Forseti-owned `audit_events` table (sqlite or Postgres). The table is **append-only at the DB layer** — a BEFORE UPDATE/DELETE trigger refuses modifications unless the pruner sets a single-transaction override flag (`current_setting('app.audit_purge')` on Postgres, a sentinel row in `_forseti_meta` on sqlite). The flag is defence against application-bug clobbering history, not against a malicious operator with direct DB access.

Three sources feed the table:

1. **Forseti-owned handlers — direct emit.** Logout, settings session revoke, OAuth consent (granted / denied), account self-deletion, every admin action (`/admin/clients/*`, `/admin/identities/*`, `/admin/sessions/*`, `/admin/webhooks/*`).
2. **Kratos flow webhooks** delivered to `POST /internal/audit/kratos` on the **internal listener**. Flow-completion events only: `identity.created` (registration), `auth.login` (login.{password,passkey} — AAL2 step-up methods intentionally don't fire so a single sign-in produces one row, not two), `password.changed` (settings.password), `password.recovered` (recovery), `verification.completed` (verification), `mfa.*` (settings.{totp,webauthn,lookup}). Kratos's admin API does not fire flow hooks, so admin-driven identity writes go through path 1.
3. **Hydra consent decisions** emitted from Forseti's own `src/oauth/consent.rs` (Hydra has thin hook surface; scraping logs is fragile).

#### Internal listener

Machine-to-machine endpoints (today: the audit webhook receiver) live on a **separate HTTP listener** from the user-facing Forseti. The split is the trust boundary — the internal listener should never be reachable from the public internet, while the public listener is built for it.

| Knob              | Default              | What to set in production                                                                                                                |
|-------------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `[internal].bind` | `127.0.0.1:8081`     | Loopback when Forseti and Kratos share a host. Bind to a specific private interface (e.g. `10.0.0.5:8081`) — or `0.0.0.0:8081` inside a container where the trust boundary is the docker / pod network — so Kratos in a separate container can reach it. **Never expose this on a public interface.** |

The internal listener does not mount `/readyz` or `/healthz`; those stay on the public listener so load balancers and orchestrators don't have to know about a second port. CSRF middleware is also not applied to the internal listener — these endpoints take JSON over `POST`, not cookie-bearing browser forms.

#### Audit webhook bearer

The `POST /internal/audit/kratos` endpoint authenticates inbound Kratos webhooks with a shared bearer token (`Authorization: Bearer <token>`). Forseti reads it from `[audit].webhook_token`; Kratos sends it from the `auth.config.value` field on each `web_hook` in `kratos.yml`.

**The token is mandatory.** Forseti refuses to boot when `webhook_token` is empty (exit code `1`, error on stderr) — a misconfigured deployment is supposed to fail loudly at startup rather than silently accept or reject every inbound event.

To rotate:

1. Stop Forseti process.
2. Update `[audit].webhook_token` in `config.toml` (or `FORSETI_AUDIT__WEBHOOK_TOKEN`) **and** the `auth.config.value` field on every `web_hook` in `infra/kratos/kratos.yml`.
3. Restart Forseti, then restart (or HUP) Kratos so it picks up the new value.

There's no online-rotation path: Kratos's Viper-based config loader does not support env-var overrides for fields inside arrays (see [ory/kratos#2663](https://github.com/ory/kratos/issues/2663)), so the playground `kratos.yml` embeds the dev token literally. For real production deploys, template the config through your deploy tooling — Helm's `values.yaml`, Terraform, or equivalent — and source the token from your secret manager. Forseti-side value comes from `config.toml` (or `FORSETI_AUDIT__WEBHOOK_TOKEN`), where env-var binding works because Forseti's config is a flat struct.

#### Audit webhook replay protection

Bearer alone lets anyone who captures a single request replay it arbitrarily later — fabricating audit history. The receiver layers two cheap mitigations on top:

1. **Freshness window.** The shared `audit_event.jsonnet` template emits `ctx.flow.issued_at` (RFC 3339) into the body. The receiver rejects payloads whose `issued_at` is more than 5 minutes old, or skewed more than 1 minute into the future. Payloads missing `issued_at` are accepted but logged at `debug` — older Kratos versions omit the field on some hooks and dropping them would lose legitimate events.
2. **Per-flow dedupe.** A bounded in-memory LRU (1024 entries) keyed by `metadata.flow_id` drops same-flow replays inside the freshness window. The cache is process-local — restart loses it, which is fine because the freshness window also resets.

**Threat model — what this catches and what it doesn't.** Stripe / GitHub webhook signing computes an HMAC over the body with a shared secret, which catches both replay and tampering. Kratos's `web_hook` action ships static headers only — it can't compute an HMAC at send time — so the freshness + dedupe approach is the realistic ceiling without a signing proxy. This stops the "captured payload replayed hours later" case but not a real-time MITM with both the bearer and a live freshness window. If your threat model includes that, terminate Kratos behind a reverse proxy that injects an HMAC header (haproxy + lua, nginx + lua, envoy + wasm) and check it in front of Forseti.

#### Default-org auto-join

Default-org membership used to be driven by a second `web_hook` on the registration flow. That endpoint is gone — Forseti now performs the check **lazily, inside `RequireSession`**, on the user's first authenticated request. No webhook wiring is required for org membership; only audit needs the webhook.

The lazy probe is one indexed lookup (`SELECT 1 FROM organization_members WHERE identity_id = ? LIMIT 1`) cached per request. When it misses, Forseti runs the same race-safe `auto_join_default_txn` (txn-wrapped, role decided inside the txn) that the old webhook called.

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
- **Tier-1 allowlist is global.** A single `[admin].allowed_emails` controls operator access for the whole deployment; there's no per-realm partition. For per-customer scoping, use Tier 2 (org-scoped admin) instead — see [Admin access model](#admin-access-model).
- **No CSV / JSON export.** Audit and identity lists render only in the UI for now.
- **No tamper-evidence (hash chain).** Append-only is enforced by the trigger; for stronger guarantees ship the row stream to an S3 archive with object-lock externally.

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

Upstream OIDC providers (Google, GitHub, Microsoft, Apple, custom). Operators register one OAuth app per provider on the provider's side, paste the client credentials into `kratos.yml`, and Forseti automatically renders one "Sign in with X" button per configured provider.

Worked example for Google:

1. Go to <https://console.cloud.google.com/apis/credentials> and create an OAuth 2.0 Client ID.
2. Authorized redirect URI: `https://accounts.example.com/self-service/methods/oidc/callback/google`. Substitute `accounts.example.com` for your Kratos public hostname — the path is fixed by Kratos.
3. Capture the client ID and client secret.
4. Add the provider to `kratos.yml`:

   ```yaml
   selfservice:
     methods:
       oidc:
         enabled: true
         config:
           providers:
             - id: google
               provider: google
               client_id: ${GOOGLE_CLIENT_ID}
               client_secret: ${GOOGLE_CLIENT_SECRET}
               mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
               scope:
                 - openid
                 - email
                 - profile
               requested_claims:
                 id_token:
                   email:
                     essential: true
                   email_verified:
                     essential: true
   ```

5. Provide an identity mapper at the referenced path. The mapper translates the upstream id_token claims into your Kratos identity traits. Minimum example mapping `email`:

   ```jsonnet
   local claims = std.extVar('claims');
   {
     identity: {
       traits: {
         email: claims.email,
       },
     },
   }
   ```

6. Pass the secret in via env at Kratos startup; Kratos expands `${VAR}` references in its config when started with `--config` and the env populated.

GitHub, Microsoft (Azure AD), Apple, and generic OIDC providers follow the same shape: register an OAuth app on the provider side, set the callback to `https://accounts.example.com/self-service/methods/oidc/callback/<id>`, and add a `providers` entry under `selfservice.methods.oidc.config.providers`.

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
- **Forseti mailer** — org invites and the hand-rolled `/claim-email` verification code. Configured under `[smtp]` in `config.toml`. Forseti speaks SMTP directly (via `lettre`) because Kratos's admin API doesn't expose a one-off "send this message" endpoint in v26+.

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

Mirrors the Kratos config but lives Forseti-side. Without it, invite + claim-email mails are dropped (the underlying token / code stays valid in the DB so an operator can hand-deliver in dev, but end users won't see anything in their inbox).

```toml
[smtp]
enabled         = true
host            = "email-smtp.us-east-1.amazonaws.com"
port            = 465
scheme          = "smtps"           # plaintext | starttls | smtps
username        = "AKIAIOSFODNN7EXAMPLE"
password        = "secret"          # use FORSETI_SMTP__PASSWORD env var in prod
from            = "no-reply@example.com"
skip_tls_verify = false             # set true only for self-signed dev relays
```

Sanity-check: `enabled = false` leaves the section dormant — useful for OSS deployments that don't have a relay handy or for tests. Disabled-state callers `tracing::info!` the would-be recipient and continue without error, so the surrounding flow still completes.

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
| `/readyz`             | Forseti | Readiness. Returns `ready` when Forseti will serve. Returns `503` if the background webhook worker has been silent for more than 20s (4× its tick) — surfaces a stuck worker before undelivered webhooks pile up. |
| `/health/alive`       | Kratos  | Liveness.                                              |
| `/health/ready`       | Kratos  | Readiness (checks DB connectivity).                    |
| `/health/alive`       | Hydra   | Liveness.                                              |
| `/health/ready`       | Hydra   | Readiness (checks DB connectivity).                    |

Wire all three readiness probes into your load balancer / orchestrator.

### Metrics

Hydra and Kratos expose Prometheus metrics on their admin ports. Forseti does not currently expose metrics; track its health via log-derived metrics and health checks.

## Common gotchas

### Cookie domain

In the playground all services bind to `127.0.0.1` so cookies are port-agnostic and the browser sends Kratos's session cookie back to Forseti at `:3000` without further scoping. In production:

- Kratos must serve from a hostname that shares a parent domain with Forseti. `accounts.example.com` (Forseti) and `kratos.example.com` (Kratos public) share `.example.com`, so Kratos can issue a cookie scoped to `.example.com` that both hostnames see.
- Forseti still calls Kratos's *admin* API on an internal hostname (e.g. `kratos.internal:4434`) for server-side operations. That call does not need cookie scoping.
- The browser must reach Kratos's *public* API on a publicly-resolvable hostname for cookie scoping to work. Path-rewriting Kratos behind Forseti's hostname is possible but adds complexity; a separate hostname is simpler.

### CORS

Kratos's `serve.public.cors.allowed_origins` must include Forseti's public URL. Without it, browser fetches to Kratos's public API (used by HTMX during flow submission) fail silently or with a preflight error.

### AAL2 auto-elevation after enrollment

When a user enrolls a second factor (TOTP, lookup_secret, WebAuthn, passkey) inside a privileged settings flow, Kratos automatically marks the session as `aal2` going forward. The user does not have to re-authenticate to use the new factor. This is correct behavior but surprises operators verifying their setup — the second factor "just works" immediately because the enrollment ceremony itself satisfied AAL2.

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
grace_days   = 14
```

- `purchase_url` — where the upsell page's CTA points. Empty default falls back to `mailto:<brand.support_email>`.
- `grace_days` — after `expires_at`, gated features stay read-only for this many days before hard-gating. Set to `0` to disable the grace window.

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

When an org sets `logo_url` / `support_email` on its settings page, those values override `[brand]` in `config.toml` for any request resolved into that org's scope. Unset fields fall back to `[brand]`. The Default org is treated like any other org for this resolution — operators who want a single brand for everyone leave the Default org's branding empty.

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

## Further reading

- [`../README.md`](../README.md) — project overview and quickstart
- [`../ROADMAP.md`](../ROADMAP.md) — milestone roadmap
- [`integration-guide.md`](./integration-guide.md) — downstream app integration
- [Ory Kratos docs](https://www.ory.sh/docs/kratos)
- [Ory Hydra docs](https://www.ory.sh/docs/hydra)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
