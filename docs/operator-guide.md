# Operator Guide

A reference for deploying `forseti` as the self-service UI and OAuth2 login/consent bridge for an Ory Hydra installation, with Ory Kratos or Forseti's native identity backend holding the identities, at, for example, `accounts.example.com`.

This guide assumes self-hosting the full stack: `forseti`, Hydra, Postgres, and on the Kratos build also Kratos. It does not assume prior familiarity with Kratos's surface area. It covers what both builds share; what only one build needs is in [Kratos identity backend](./operator-guide-kratos.md) and [Native identity backend](./operator-guide-native.md) (see [Choosing an identity backend](#choosing-an-identity-backend)).

For app-developer documentation on how downstream applications consume Forseti as an OIDC Provider, see [`integration-guide.md`](./integration-guide.md). For project status and milestones, see [`../README.md`](../README.md) and [`../ROADMAP.md`](../ROADMAP.md).

## What this is

`forseti` is a Rust + Axum self-service UI for Ory Kratos or its own native identity backend, and an OAuth2 login/consent/logout bridge for Ory Hydra. It renders the self-service flows (login, registration, recovery, verification, settings) and implements the three handlers Hydra delegates to the IdP: `/oauth/login`, `/oauth/consent`, `/oauth/logout`. Branding is config-driven; there are no hardcoded organization names. Licensing: AGPL-3.0-or-later for the OSS core, with `src/commercial/` under the proprietary source-available Forseti Commercial License 1.0 — see the [License section of the README](../README.md#license).

## Choosing an identity backend

Forseti builds with one of two identity backends, chosen at compile time with a cargo feature; a binary carries exactly one. The Kratos backend (`identity-ory`, the default) renders Ory Kratos's flows, and the native backend (`identity-native`) keeps identities, sessions and self-service flows in Forseti's own database. Ory Hydra provides OAuth2 and OIDC on both.

| | Kratos backend | Native backend |
|---|---|---|
| Services to run | Forseti, Kratos, Hydra | Forseti, Hydra |
| Self-service flows | login, registration, verification, recovery, settings, logout | the same |
| Second factors | TOTP, backup codes, WebAuthn security keys | the same |
| Passwordless sign-in | passkeys, email codes | passkeys (no email codes) |
| Upstream sign-in | every provider Kratos supports | OpenID Connect providers and GitHub (no Apple) |
| Enterprise SAML SSO | yes | yes |
| Mail | Kratos courier for flow mail, Forseti mailer for invites and claims | Forseti mailer for everything |
| Audit of flow events | Kratos webhooks to the internal listener | written directly |
| Config tooling | `forseti-config` verbs | none |
| Existing Kratos identities | in place | no import; fresh installs |
| How to get it | release tarballs, packages and the container image | build from source with `--no-default-features --features identity-native` |

Build-specific setup is in [Kratos identity backend](./operator-guide-kratos.md) and [Native identity backend](./operator-guide-native.md).

## Deployment topology

The recommended shape is **path-prefixed on a single host**: Forseti at the root, Hydra under `/hydra/*`, Kratos under `/kratos/*`. Everything is same-origin, cookies are host-only, no CORS to configure, only `:443` exposed. Hydra's production guide explicitly endorses this layout. The subdomain shape (`accounts.example.com` / `hydra.example.com` / `kratos.example.com`) is also supported when there's a reason to split — different rate-limit tiers, independent WAF rules, splitting Hydra to its own cluster. See [`operator-guide-proxy.md`](./operator-guide-proxy.md) for the comparison and haproxy configs. The diagram shows the Kratos build; the native build has no Kratos, so it drops the `/kratos/*` route, both Kratos ports and the Kratos database.

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

- **Postgres** (>= 13). One database per service: `kratos` (Kratos build only), `hydra`, optionally `forseti`. The playground's `init-db.sh` shows the bootstrap pattern.
- **Mail provider.** Mailcrab (used in `infra/docker-compose.yml`) is a development sink. In production, use a real provider. On the Kratos build, two pieces of the stack send mail independently: **Kratos** (verification, recovery, MFA-enrol mails) speaks SMTP via `courier.smtp.connection_uri` in `kratos.yml`, and **Forseti** (org-invite + claim-email mails) sends via `[email]` in `config.toml`, which supports Lettermint, Postmark, SendGrid, or an SMTP relay. Both can point at the same SMTP relay. The native build sends all of its mail, verification and recovery codes included, through `[email]`, and refuses to boot without it.
- **DNS** records pointing `accounts.example.com`, `hydra.example.com`, and on the Kratos build `kratos.example.com` (or a single hostname with path-based routing) at the reverse proxy.
- **TLS certificates.** Let's Encrypt via Caddy or `certbot`, or a managed cert solution.
- **Container runtime** if running Forseti as a container, or a Linux host with a writable working directory if running the static binary.

## Configuration

Forseti loads configuration from `config.toml` (or the path in `$FORSETI_CONFIG_PATH`) and overlays environment variables prefixed with `FORSETI_`. Section separator is a double underscore: `FORSETI_KRATOS__PUBLIC_URL` sets `kratos.public_url`.

The authoritative schema is `src/config.rs`. The example file is `config.example.toml`. Every key both builds read follows; `[kratos]` is in the [Kratos guide](./operator-guide-kratos.md#kratos), and the `[identity]` keys only the native build reads are in the [native guide](./operator-guide-native.md#identity-configuration).

### `[hydra]`

| Key          | Type   | Default | Description                              |
|--------------|--------|---------|------------------------------------------|
| `public_url` | string | —       | Hydra's public URL as reachable from Forseti (token endpoint, JWKS, OAuth2 endpoints). Forseti fetches Hydra's discovery document from here, so when the proxy routes `{issuer}/.well-known/openid-configuration` to Forseti, point this at Hydra directly (e.g. `http://hydra:4444`) and set `issuer` to the browser-facing URL. Through the proxy, the fetch lands on Forseti itself and recurses until it runs out of file descriptors. |
| `admin_url`  | string | —       | Server-only Hydra admin URL. Used to fetch and accept login/consent/logout challenges. |
| `issuer`     | string | unset (falls back to `public_url`) | Hydra's advertised issuer (`urls.self.issuer` in `hydra.yml`) when it differs from `public_url` — the normal case behind a front proxy, e.g. `https://accounts.example.com/hydra`. Drives the CSP `form-action` origin, the path-insertion well-known discovery routes, and the CIMD shim's redirect base. See [Fronting the issuer](#fronting-the-issuer-front-proxy-vs-haproxy). |
| `front_proxy`| bool   | `false` | Reverse-proxy `GET/POST /hydra/{path}` on Forseti's public listener to `public_url`, so Forseti itself owns the issuer origin (single-binary deployments, the dev playground). Keep `false` when an external proxy (haproxy) already routes `/hydra/` to Hydra. |

### `[self]`

| Key   | Type   | Default | Description                                                              |
|-------|--------|---------|--------------------------------------------------------------------------|
| `url` | string | —       | Forseti's own externally reachable URL. Used to build `return_to` round-trips. |

### `[security]`

| Key                | Type   | Default            | Description                                                            |
|--------------------|--------|--------------------|------------------------------------------------------------------------|
| `cookie_secret`    | string | ephemeral per-boot (Ory build); required (native build) | Seeds the HMAC keys for every Forseti-signed cookie. On the native build also the key material for stored TOTP secrets and one-time codes. Long random secret. |
| `frame_ancestors`  | string | `"'self'"`         | CSP `frame-ancestors` on every public_app response. `"'none'"` blocks framing entirely. |
| `x_frame_options`  | bool   | `true`             | Also emit `X-Frame-Options: SAMEORIGIN` for older browsers.            |
| `extra_form_action` | list of strings | `[]`      | Extra origins for the CSP `form-action` directive. Needed for an upstream OIDC provider added to `kratos.yml` by hand, or a host a provider bounces through. On the native build, for a configured provider whose authorization endpoint is on another host than its `issuer`. |

`cookie_secret` is the root key behind the HMAC for Forseti's signed cookies (one-shot flash, `active_org` switcher, `forseti_app_referrer` handoff, `forseti_claim_link` resource-claim link, CSRF double-submit). Each cookie derives its own key from this secret plus a per-use domain-separation salt (see `src/flash.rs`, `src/orgs/cookie.rs`, `src/handoff/cookie.rs`).

Generate one with `openssl rand -hex 32` (a hex string is decoded to bytes; anything that isn't valid hex is taken as raw UTF-8 bytes). The decoded key must be at least 32 bytes or Forseti hard-fails at boot. Override via `FORSETI_SECURITY__COOKIE_SECRET`.

On the Ory build, when unset, Forseti generates a 32-byte ephemeral key per process and logs a warning. That means flash, active-org, and app-referrer cookies don't survive a restart, and separate instances can't validate each other's cookies, so **set `cookie_secret` in production** and on any multi-instance deployment. On that build none of these are the session cookie (that's Kratos's), and none are catastrophic on their own (the flash banner is short-lived, the org cookie's selection is re-validated at use, the handoff cookie's `referrer_uri` is re-checked against the Hydra client), but a stable secret avoids the restart churn.

The native build refuses to boot without `cookie_secret`, because there the secret is durable key material: changing it makes stored TOTP secrets unreadable and invalidates outstanding codes, backup codes and logout links. See [`cookie_secret` is key material](./operator-guide-native.md#cookie_secret-is-key-material).

CSRF protection uses a double-submit token (`src/csrf.rs`) keyed off the same secret; there's nothing extra to configure for it.

### `[brand]`

| Key             | Type   | Default            | Description                                                            |
|-----------------|--------|--------------------|------------------------------------------------------------------------|
| `name`          | string | `"Forseti"`     | Brand name shown in the header, page titles, and email templates.      |
| `support_email` | string | none               | Support address rendered in footer / error pages.                      |
| `logo_url`      | string | none               | Optional logo URL. When omitted, the brand name is rendered as text.   |
| `consent_intro` | string | (localised sentence) | Intro paragraph rendered on `/oauth/consent` above the scope list. Unset, it follows the user's language; set, it's shown as written in every language. |
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
| `url`             | string  | `"sqlite://./forseti.db"` | `sqlite://path/to/file.db` (or a bare path) for single-binary self-hosters; `postgres://user:pass@host/db?connect_timeout=5` for HA. URL scheme picks the backend. |
| `skip_migrations` | bool    | `false`                  | When `true`, the boot-time migration run is skipped. Use this when schema changes are gated through a deploy pipeline instead of the running binary. |
| `max_connections` | usize   | twice the CPU count      | Postgres pool ceiling. Ignored for sqlite, whose pool is fixed at 8 (one writer at a time is the point).                                              |
| `acquire_timeout_secs` | u64 | `30`                   | How long a request waits for a free pooled connection before failing with a pool error (surfaces as a 500) instead of hanging. Both backends. Pool connection create and recycle timeouts are fixed at 5 s. |

Defaulting to sqlite-next-to-the-binary is deliberate: clone, run, get a working Forseti with persistent state. Operators who want Postgres set `[database]` explicitly.

**Multi-instance sqlite footgun.** sqlite + multiple Forseti instances corrupts the database. Forseti can't see other instances, only deployment shape — so at boot it logs a `warn!` and surfaces a banner on `/admin/status` when the backend is sqlite *and* `self.url` is `https://` with a non-loopback / non-RFC1918 host. Switch to Postgres for any HA setup.

**Per-process state in multi-instance deployments.** Postgres makes the database safe to share, but a few components are process-local, so running several instances changes their behavior:

- Webhook delivery: every instance runs its own outbox worker. Rows are claimed with a short lease before sending, so each row is delivered by exactly one worker; extra instances add polling, not duplicate deliveries.
- Rate limits: the per-IP and global buckets are in-memory, per instance. Behind a load balancer the effective limit is roughly the configured value times the instance count; size the configured limits with that in mind.
- Logo cache: each instance caches served org logos independently. After a logo is replaced or removed, the instance that handled the change drops its cached copy immediately; other instances may serve the previous version until the entry is evicted under cache pressure or the process restarts.
- Domain-challenge email cooldown: the one-hour cooldown between ownership-challenge emails to a domain is tracked per instance, so N instances can send up to N challenge emails per domain per hour.

Migrations run on startup by default (`FORSETI_DATABASE__SKIP_MIGRATIONS=1` to opt out). The two backends carry parallel SQL files under `migrations/{sqlite,postgres}/`.

The playground compose file ships a dedicated `forseti-postgres` sidecar on `127.0.0.1:5450` (separate from the Kratos/Hydra postgres, per the design's schema-isolation goal). Smoke-boot the Postgres path with:

```bash
FORSETI_DATABASE__URL="postgres://forseti:secret@localhost:5450/forseti?connect_timeout=5" cargo run
```

### `[internal]`

| Key    | Type   | Default            | Description                                                                                                                          |
|--------|--------|--------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `bind` | string | `"127.0.0.1:8081"` | Bind address for the internal listener (the audit webhook receiver and the POSIX resolver). Never expose this on a public interface — see [Internal listener](#internal-listener). |

The `[posix]` table (uid/gid bases, default shell, home prefix, free-tier seat cap) is documented in [Linux authentication → `[posix]`](#posix).

### `[email]`

Forseti-owned outbound mail (org invites + claim-email). On the Ory build Kratos's courier handles its own self-service mail separately, and this section is optional: omit it (or set `enabled = false`) and the send sites log + skip so dev still works with the token / code accessible via the DB. On the native build it also carries the verification and recovery codes and is required: Forseti refuses to boot unless `enabled = true`. Backed by [polymail](https://github.com/franzos/polymail-rs): `provider` selects the transport and the remaining fields are that provider's credentials, flattened in directly under `[email]`.

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

Map of scope name to human-readable description, surfaced on `/oauth/consent`. Unknown scopes fall back to the raw scope name. The keys are also part of the CIMD scope allowlist: a CIMD client can only get a custom scope onto its Hydra row when the scope is a key here, an entry in `[oauth.cimd].client_scope_extra`, in the client's own metadata document, or in the stored `scopes_supported` of the registry row the request's `resource=` names (see [Scope allowlist](#cimd-zero-config-client-onboarding)). Keys here apply to every resource; registry scopes apply to their own resource only. List step-up scopes, and the scopes of resource servers without RFC 9728 metadata, here. Example:

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

### `[oauth]` — audience policy

| Key                        | Type     | Default          | Description                                                                                                                                                |
|----------------------------|----------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `allowed_resource_audiences` | string[] | `[]`           | **Deprecated.** The consent-time audience allow-list lives in the [resource registry](#the-resource-registry-adminresources) now, managed at `/admin/resources`. Entries still listed here are imported into the registry once at startup (idempotent, `created_by = 'config-import'`) and a deprecation warning is logged; the values are never read at consent time. Cutover: deploy, verify the rows appear at `/admin/resources`, then delete the key. |

### `[oauth.cimd]` — CIMD shim knobs

Settings for the CIMD authorization shim at `GET /oauth2/authorize` (see [CIMD](#cimd-zero-config-client-onboarding) for the full picture). Defaults are set in code; override per-deployment when needed.

| Key                        | Type     | Default          | Description                                                                                                                                                |
|----------------------------|----------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `allow_private_targets`    | bool     | `false`          | Stand down the SSRF guard on outbound document fetches: allows `http://` and loopback/private-IP client_id and metadata URLs, so local fixture servers work in development and CI. **Never enable in production.** Forseti refuses to boot with it on when `[self].url` is production-shaped (`https` with any host except `localhost`, a loopback or private IPv4, or a loopback, unique-local or link-local IPv6), and `forseti-config check` reports it as FAIL. |
| `client_scope_extra`       | string[] | `[]`             | Scope entries every CIMD client's Hydra `scope` ceiling carries, after the built-in `openid offline offline_access` and before the document's `scope` and the request's allowlisted scopes. Each entry (whitespace-separated values count as separate scopes) is also on the [scope allowlist](#cimd-zero-config-client-onboarding) and applies to every resource; registry scopes are the per-resource source. Entries containing `*` are ignored. |
| `allowed_client_hosts`     | string[] | `[]`             | When non-empty, only client_id URLs whose host matches an entry exactly (case-insensitive; subdomains do NOT match) may use the shim. Empty = open: any HTTPS client_id host is accepted, consent-gated, per the MCP open-client model. A client-vendor list (`["claude.ai"]`), not a per-resource list. |
| `ip_rate_per_minute`       | u32      | `10`             | Per-IP rate limit on `GET /oauth2/authorize` — max requests per minute. In-memory, per-process. `0` disables this bucket.                                  |
| `ip_rate_per_hour`         | u32      | `100`            | Per-IP rate limit — max requests per hour. Enforced in parallel with the per-minute bucket. `0` disables.                                                  |
| `global_rate_per_minute`   | u32      | `40`             | Global (all-callers-share-one-bucket) limit on first sightings of a `client_id` (no metadata row yet, so a document fetch), per minute. Known clients are limited per IP only. `0` disables. |
| `global_rate_per_hour`     | u32      | `400`            | Global limit on first sightings of a `client_id`, per hour, in parallel with the per-minute window. `0` disables.                                         |
| `max_clients`              | u32      | `500`            | Ceiling on how many CIMD clients may exist in total. The rate keys above bound how fast clients are registered; this bounds the standing count, since every distinct client_id URL leaves a permanent Hydra client and metadata row behind. Only a *new* client_id is refused — everything already registered keeps working. `0` lifts the ceiling. |
| `max_clients_per_host`     | u32      | `50`             | Same ceiling, per client_id host, so one host can't consume the global allowance on its own. `0` lifts it.                                                |

#### RFC 8707 `resource` → access-token audience

OAuth clients that target a specific resource server — every MCP client, for instance — name it with RFC 8707 `resource=<uri>` on the authorize request. Hydra/fosite ignores that parameter entirely: it derives the requested audience only from Hydra's non-standard `audience=` form parameter. A client that does the standard thing would therefore receive a token with `aud: []`, and its resource server rejects it forever.

Enrolling the resource in the [resource registry](#the-resource-registry-adminresources) (`/admin/resources`) makes Forseti bridge the gap:

- Consent is the only place an audience is decided. It takes the union of both carriers — `resource=` on the authorize URL and Hydra's `audience=` — and grants a value only when it is **either** an enabled registry row **or** on the registered `audience` of a client Forseti knows an operator created. Everything else is dropped with a `tracing::warn!`.
- "Knows an operator created" means `oauth_client_metadata.source = 'admin'`, i.e. the client was made through Forseti's admin UI. Self-registered clients (`source = 'cimd'`, or historical `'dcr'` rows) and clients with no metadata row at all never count — their record content is not operator policy.
- So the registry is where an audience for **any other client** goes, including one created outside Forseti (`hydra create client`). Entries are matched verbatim first and canonically second, so a non-URI identifier like `stackpit-web` can be registered and works; URI entries additionally match across a trailing slash or fragment (`https://host/mcp` and `https://host/mcp/` are one resource, and the no-slash form is what gets granted).
- Granting an audience the client's record doesn't carry yet also registers it there (capped, idempotent). fosite re-validates the granted audience against the client record on the **refresh** grant (but not on the initial code exchange), so without that a client gets one working access token and then `invalid_request` on every refresh.

The registry is a ceiling, not a grant: an audience only reaches a token when the user consents to a request that actually asked for that resource. If the registry is unreadable at consent time, Forseti fails closed and denies every requested audience.

#### Access-token claims from `metadata_admin`

Some resource servers need a per-user value in the access token that no standard claim carries, such as forgejo-mcp, which reads the audience of the user's Forgejo Authorized Integration from `forgejo_aud`. This is the equivalent of Keycloak's user-attribute mapper or Auth0's `app_metadata` plus a custom claim: the value lives in the identity's `metadata_admin`, which only admins can write through Kratos's admin API, and the resource's [registry](#the-resource-registry-adminresources) row names the keys consent copies into tokens for that resource.

Set them on the row (**Access-token claims**, on create or via **Edit** in the list), separated by spaces. Only Forseti-wide admins can set them: an org-scoped admin could otherwise route any user's operator-written metadata to their own resource server. Names are letters, digits, `_`, `-`, `.` and `:`, up to 64 characters and 10 per row; claims Hydra sets itself (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `client_id`, `scp`, `ext`) and the ID-token-only `nonce` and `at_hash` are refused.

Hydra puts session claims under `ext` in the JWT. To have them at the top level as well, list them in `hydra.yml`:

```yaml
oauth2:
  allowed_top_level_claims:
    - forgejo_aud
```

Set the value on an identity through the Kratos admin API. The patch below replaces the whole `metadata_admin`, so carry over any keys already in it:

```bash
curl -X PATCH http://kratos:4434/admin/identities/<id> -H 'Content-Type: application/json' \
    -d '[{"op":"add","path":"/metadata_admin","value":{"forgejo_aud":"u:1:..."}}]'
```

A token carries a row's claims only when consent grants that resource as an audience, matched like the audience itself (verbatim, then canonically); disabled rows contribute none. Keys missing from `metadata_admin`, or set to `null`, are left out, and a failed registry read issues the token without them. Hydra stores the claims with the consent and reuses them for every refresh, so a change to `metadata_admin` or to the row reaches tokens only after the user's next authorization, not on refresh.

#### Self-service resource claims

Writing a value per user through the Kratos admin API doesn't scale past a handful of people. A registry row can instead let users set the value of one of its claims themselves, on **Settings > Resource accounts** (`/settings/resource-claims`). The user signs in at an upstream OIDC issuer, Forseti validates the ID token, derives the value from the token's `sub`, and writes `metadata_admin.<claim>` through the Kratos admin API, touching no other key. Users can't type a value in unverified: anyone who learns another user's value could otherwise act as them at the resource. Nothing from the upstream (tokens, profile) is stored.

The case it's built for is forgejo-mcp. It reads the audience of the user's Forgejo Authorized Integration from `forgejo_aud`, and Forgejo generates that audience itself as `u:<forgejo-user-id>:<uuid>`. The user creates the integration in Forgejo, pastes the audience on the settings page and signs in at Forgejo; Forseti checks that the `u:<id>` part is the Forgejo account they signed in with, then stores the value.

**Register a public OAuth2 application at the issuer.** In Forgejo, create an OAuth2 application (user **Settings > Applications**, or the site administration for an instance-wide one) with **Confidential client** unticked and the redirect URI `<self.url>/settings/resource-claims/callback`, e.g. `https://id.example.com/settings/resource-claims/callback`. One redirect URI covers every row that uses the application. There is no client secret to copy: Forseti is a public client with PKCE (S256). Forgejo requires PKCE for public clients and shows its consent screen, with the account name, on every link. Issuers that only allow confidential clients don't work.

**Configure the row.** On the row's claims page (**Edit** in the list, Forseti-wide admins only), the **Self-service** section takes four fields. All four empty turns self-service off; otherwise all four must be valid.

| Field | Value |
|-------|-------|
| Claim | One of the row's access-token claims, e.g. `forgejo_aud`. |
| Issuer URL | Exactly as the issuer's discovery document states `issuer`, character for character, trailing slash or not. Forgejo's is its `ROOT_URL` without the trailing slash, e.g. `https://git.example.com`. `https://` only, no credentials, query or fragment, no `localhost` or loopback/private IP literal, at most 2048 characters. |
| Client ID | The application's client id. Printable ASCII without spaces, at most 255 characters. |
| Value template | Letters, digits, `_`, `.`, `:` and `-`, with exactly one `{sub}` (the upstream subject) and at most one `{uuid}` (a canonical lowercase UUID the user enters), at most 128 characters. Forgejo: `u:{sub}:{uuid}`. A template without `{uuid}` needs no input; the user just signs in. |

The save writes one critical `admin.resource.claims_updated` audit row with the previous and new values of all fields, and the list shows a **Self-service** badge on the row. At every link Forseti fetches `<issuer>/.well-known/openid-configuration`; the document's `issuer` must equal the configured value byte for byte, its authorization, token and JWKS endpoints must sit on the issuer's origin, and when it lists `code_challenge_methods_supported` that list must include `S256`. ID tokens must be signed RS256 or ES256. The settings page adds each listed issuer's origin to its CSP `form-action`, so no `[security].extra_form_action` entry is needed.

**A self-service claim is global.** Consent copies a claim by name into tokens for every resource that lists it, so a self-service claim may appear on no other row, neither as that row's self-service claim nor in its access-token claims. Forseti checks both directions on the claims page and the create form (`claim "<name>" is already used by another resource`), and a partial unique index backs it. Ordinary claims can still be shared between rows.

**Who sees a row.** The settings page lists enabled rows with self-service configured. A row in the default org is visible to every user; a row in a named org only to that org's members. This gates the settings page and its link and remove actions only; consent copies claims without an org check.

**Linking.** When the template has `{uuid}`, the submitted value must match the template. On the way back Forseti renders the template with the verified `sub` and the submitted UUID and compares the result to the submitted value; a mismatch says the account doesn't match. A `sub` that renders outside the claim-value characters or past 255 characters is refused. Users can link again to replace the value, or remove it (a JSON Patch `remove`, no round trip). Each outcome is audited: `resource.claim.linked` and `resource.claim.removed` (both critical) and `resource.claim.link_failed` with a `reason`, each with the resource, the claim and, once known, the upstream `sub`. As with admin-written values, a change reaches tokens on the client's next authorization.

**Rate limits.** Starting a link is limited to 30 per 10 minutes per client IP and 10 per 10 minutes per identity, since each start fetches the issuer's discovery document. The callback has its own bucket of 60 per 10 minutes per client IP. Removing isn't limited. The numbers are fixed in code; client IPs follow [`[proxy]`](#proxy--reverse-proxy-trust).

**Turning self-service off leaves values in place.** Values already linked stay in `metadata_admin` and keep reaching tokens for the row, and the row drops off the settings page, so users can't remove them anymore. Remove one by hand through the Kratos admin API (Kratos rejects a `remove` of a key that isn't there):

```bash
curl -X PATCH http://kratos:4434/admin/identities/<id> -H 'Content-Type: application/json' \
    -d '[{"op":"remove","path":"/metadata_admin/forgejo_aud"}]'
```

To stop the claim reaching any token at once, also drop it from the row's access-token claims.

**In-flight links and `cookie_secret`.** A link is bound to a signed `forseti_claim_link` cookie (10 minutes, path `/settings/resource-claims`), and the PKCE verifier and nonce are derived from [`[security].cookie_secret`](#security). With `cookie_secret` unset, Forseti generates a random key per process (and refuses to boot on a production-looking `self.url`). A restart then invalidates every link in flight: a user who is at the issuer during the restart comes back to "The link request expired or doesn't belong to this session. Please start again." and nothing is written. The same happens when a multi-instance deployment doesn't share the secret. Two tabs linking at once share the one cookie, so the first one fails the same way.

**Top level or `ext`.** Hydra's `oauth2.allowed_top_level_claims` decides where the claim lands, exactly as for admin-written values above: listed, it's at the top level of the access token and under `ext`; not listed, only under `ext`. List the claim when the resource server reads it from the top level.

**Private issuers in development.** The issuer URL and every upstream fetch go through the same SSRF guard as CIMD. `[oauth.cimd].allow_private_targets = true` lets an `http://` or private issuer through, which is how the playground's mock issuer (`http://host.containers.internal:8092/default`) works. Never enable it in production.

Whether the per-IP limiter trusts forwarded-for headers is a single deployment-wide knob: `[proxy] trust_forwarded_for` plus `trusted_hops` (see below). The same settings drive the audit middleware (audited client IP) and every per-IP limiter — the underlying question ("is there a trusted reverse proxy, and how many?") doesn't change per-endpoint. Limiters without a global knob of their own (`/claim-email`, `/oauth/device`, `/handoff`) carry a derived global backstop of 20x their per-IP caps.

Every rate-limit knob across `[oauth]`, `[claim_email]`, and `[handoff]` is clamped at config-load time to a sanity ceiling — `1_000` per minute, `10_000` per hour, `100_000` per day. A clamped value emits a `tracing::warn!` at boot so an operator typo (`per_minute = 1_000_000`) is loud rather than silent. `0` is preserved as the documented "disable this bucket" sentinel.

### `[auth]` configuration

Per-IP + global rate limiting on `GET /registration`. These knobs apply to **every** Kratos-flow registration, not just external-org self-serve joins — `/registration` carries no per-org dimension in the URL (the target org lives inside the opaque Kratos flow), so there's no cheap way to key a bucket per org.

| Key                                    | Type | Default | Description                                                                                                    |
|-----------------------------------------|------|---------|------------------------------------------------------------------------------------------------------------------|
| `registration_ip_rate_per_minute`      | u32  | `30`    | Per-IP rate limit on `GET /registration`, requests per minute. `0` disables the bucket.                        |
| `registration_ip_rate_per_hour`        | u32  | `300`   | Per-IP rate limit on `GET /registration`, requests per hour, in parallel with the per-minute bucket. `0` disables. |
| `registration_global_rate_per_minute`  | u32  | `120`   | Global (all-callers-share-one-bucket) rate limit, requests per minute. Bounds total traffic even when a spoofed `X-Forwarded-For` defeats the per-IP bucket. `0` disables. |
| `registration_global_rate_per_hour`    | u32  | `1200`  | Global rate limit, requests per hour, in parallel with the per-minute global bucket. `0` disables.             |

These are clamped at load time under the same ceilings as `[oauth]`/`[orgs]`/`[claim_email]`/`[handoff]`. See [External access mode](#external-access-mode-public-self-serve) for what this limiter does and does not cover. On the native build the same values also limit `GET /self-service/registration/browser` and the registration form submit (`POST /self-service/registration`), each with its own buckets.

### `[proxy]` — reverse-proxy trust

| Key                    | Type | Default | Description                                                                                                                                                                                                                              |
|------------------------|------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `trust_forwarded_for`  | bool | `false` | Honour `X-Forwarded-For` when deriving the audited client IP and keying per-IP rate limiters. Set `true` ONLY when Forseti's listener is reachable solely through your reverse proxy. See [proxy guide](./operator-guide-proxy.md). |
| `trusted_hops`         | u8   | `1`     | Number of proxies in front of Forseti, each appending one `X-Forwarded-For` entry. The client is the entry this many from the right; everything further left is caller-supplied and ignored. `0` behaves as `1`. |

**How the chain is read.** Every proxy appends the address it accepted the connection from, so the rightmost `trusted_hops` entries were written by infrastructure you control and the entry just inside them is the real client. Forseti never reads the leftmost entry, which is whatever the caller sent. Your proxy therefore does not need to strip inbound `X-Forwarded-For` (nginx's default `$proxy_add_x_forwarded_for` append is fine), but it must *append*, not overwrite, and if it sets `X-Real-IP` it must overwrite that one. If the chain is shorter than `trusted_hops` (the request did not come through the proxy), Forseti falls back to the TCP peer. It never reads `X-Real-IP`.

**Safety precondition: the listener must be unreachable except through the trusted proxy.** There is no trusted-proxy allowlist. Anyone who can reach the listener directly is, from Forseti's point of view, the last proxy: they append nothing, so their own header becomes the chain and they choose both the audited IP and their rate-limit key. Bind the listener to loopback or a private interface, or firewall the port to the proxy's address, before enabling the flag. The global rate-limit buckets are the only backstop otherwise. With `trust_forwarded_for = false` (the default) Forseti keys on the TCP peer address, which cannot be forged.

**Limiter keys.** Per-IP limiters key an IPv6 client by its /64, since one host usually holds the whole prefix; an IPv4-mapped IPv6 address counts as IPv4. The audit `ip_hash` keeps the full address. When a request on the public listener carries `X-Forwarded-For` while `trust_forwarded_for` is off, Forseti logs one warning per process: behind a proxy that means every caller shares the proxy's bucket.

**Request timeout.** Forseti cuts a public-listener request at 30 s and answers `503`; the audit middleware still records it. The internal listener has no timeout. The timeout doesn't cover a client that sends its headers or body slowly, so the reverse proxy must enforce client header and body timeouts (haproxy `timeout http-request` and `timeout client`, nginx `client_header_timeout` and `client_body_timeout`).

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
2. **Email allowlist, verified.** The session's `traits.email` must appear in `[admin].allowed_emails` **and** be a verified address on the signed-in identity. Non-allowlisted users, and allowlisted users who have not verified that address, get a 403 page (rendered inside the admin shell so the rejection is unambiguous).
3. **AAL2.** Single-factor sessions are 303-redirected to `/login?aal=aal2&return_to=...`, forcing Kratos to demand a second factor before granting access.

The order matters: a non-allowlisted user with a valid AAL2 session still gets a 403. An allowlisted user with an AAL1 session is bounced to step-up before being told they're allowed in.

**Why "verified" is part of the gate.** Kratos issues a session at registration, before the address is verified. Without the verification requirement, anyone who signed up as an allowlisted address that was not yet a registered identity would land as a Tier-1 admin as soon as they enrolled their own second factor — an address on the allowlist that nobody has claimed yet is an open door, not a reservation. The same rule governs the Default-org owner floor: an unverified allowlisted address joins Default as a `member`, never an `owner`.

The practical consequence: **putting an address on the allowlist does nothing until somebody registers it and verifies it.** That is the intended behaviour. Adding a placeholder or a not-yet-hired colleague to `[admin].allowed_emails` is harmless.

Two Kratos hooks back this up (both written by `forseti-config init`, both linted by `forseti-config check`):

- `require_verified_address` on `selfservice.flows.login.after.password` and `.passkey` — refuses to re-authenticate an identity whose address is unverified. It is deliberately **not** on the AAL2 step-up methods, which elevate an existing session rather than authenticate; the hook there would strand a user mid-step-up.
- `show_verification_ui` on the registration flow — puts the verification screen in front of a new user immediately.

Neither closes the register-to-verify window on its own, because the registration-issued session never passes through the login flow. The admin gate above is the actual guard; these make the hole harder to leave open by accident.

**Tier 2 — Org-scoped admin (org owner).** Reached by hitting `/admin/...?org=<slug>`, and only on the surfaces listed below. This is what an org owner uses to manage *their own* org. Gated by:

1. **Active Kratos session** — same as Tier 1.
2. **Org ownership.** The caller must be an `owner` of the org named by `<slug>` (i.e. an `organization_members` row with `role = 'owner'`). Non-owners — including members with the `member` role and Forseti-wide admins who aren't members of that specific org — get a 403.
3. **AAL2** — same as Tier 1.
4. **Orgs license** — only for non-Default orgs. Additional orgs are a commercial feature and a missing/expired license renders the upsell page instead.
5. **Operator, for the Default org.** `?org=default` also requires the Tier-1 allowlist check (verified allowlisted address). The Default org holds the operator's own OAuth clients, so an ordinary identity that ends up owning Default must not manage them.

**`[admin].allowed_emails` is not checked on Tier 2 for non-Default orgs.** This is deliberate: org owners need to manage their own org without the operator having to add every customer's email to the allowlist. The trust boundary there is "you own this org", not "the operator vouches for you".

**Which surface is which.** Only four of the admin surfaces accept `?org=`; the rest are Tier 1 whatever you append to the URL.

| Surface                                | Tier                  | Notes                                                                                     |
|----------------------------------------|-----------------------|-------------------------------------------------------------------------------------------|
| `/admin/status`, `/admin/configuration`| Tier 1 only           | Deployment-wide health and live Ory config.                                                 |
| `/admin/identities/*`, `/admin/identity-picker` | Tier 1 only  | A Kratos identity is global — one identity spans every org — so an org-scoped view of it would hand an org owner the member's whole account, recovery codes included. Org owners get their member view at `/settings/organization/members`. |
| `/admin/sessions/*`                    | Tier 1 only           | Sessions belong to those same global identities.                                            |
| `/admin/hosts/*`, `/admin/posix/*`     | Tier 1 only           | Linux host enrollment and POSIX provisioning are deployment infrastructure.                 |
| `/admin/saml/*`, `/admin/license`      | Tier 1 only           | SSO connections and the installation's licence.                                             |
| `/admin/clients/*`                     | Tier 1 or Tier 2      | Org owners get OAuth client self-service for their own org, with the constraints below.     |
| `/admin/resources/*`                   | Tier 1 or Tier 2      | An org owner may only register resources on a **verified domain** of their org.             |
| `/admin/audit`, `/admin/webhooks`      | Tier 1 or Tier 2      | Scoped to the org's own rows.                                                               |

**What an org owner's OAuth client can't be.** A client created under `?org=<slug>` is held to what an org owner may vouch for, not what an operator may:

- `skip_consent` is forced off. An org owner can't mint a client that issues tokens to anyone who follows an authorize link without a consent screen.
- Every `audience` entry must be an enabled resource registered to that same org, so a client can't be pointed at another tenant's resource server.
- The metadata row is stamped `source = org` rather than `source = admin`. The consent path treats a registered audience as operator policy only for `source = admin`, so an org owner's declared audience is a request, not a policy statement.

A Forseti-wide admin creating the same client keeps all three capabilities.

What this means in practice:

- An allowlisted operator reaches every surface, `?org=` or not — on the Tier-2 surfaces the parameter narrows the view to one org rather than granting anything.
- An org owner who is *not* on `[admin].allowed_emails` manages clients, resources, audit and webhooks for their own org and gets a 403 everywhere else under `/admin/*` — including `/admin/identities` and `/admin/sessions` with or without `?org=`.
- If you want to restrict who can own an org — e.g. only allow paying customers — gate org creation, not the admin path. Org creation today goes through `/orgs/new` and is itself gated by the Orgs license; layer additional checks at the creation handler or via your billing flow.

The two-tier code lives at `src/admin/mod.rs::require_admin` (Tier 1) and `src/admin/mod.rs::require_admin_with_scope` (Tier 1 + Tier 2 routed by `?org=`).

### Admin pages

| Path                                  | Purpose                                                                                         |
|---------------------------------------|-------------------------------------------------------------------------------------------------|
| `/admin` → `/admin/status`            | Landing redirect.                                                                               |
| `/admin/status`                       | Kratos + Hydra health probes, courier queue (pending / failed counts), build versions, and audit-health counters (write failures + the two audit-webhook counters described in the [Kratos guide](./operator-guide-kratos.md#audit-webhook-counters-on-adminstatus)). |
| `/admin/clients`                      | List Hydra OAuth2 clients, filter by name.                                                      |
| `/admin/clients/new`                  | Create a new OAuth2 client. Returns to the show page with a one-time secret + registration access token reveal. |
| `/admin/clients/{id}`                 | View / edit a client. Rotate-secret and delete confirm pages live under here.                   |
| `/admin/identities`                   | List Kratos identities, filter by email (Kratos `credentials_identifier`).                       |
| `/admin/identities/{id}`              | View identity traits, credentials, verifiable addresses, and recent sessions. Trigger recovery codes, disable / enable, or delete from here. Delete runs the same deletion as the settings page and `forseti delete-identity` (see [Deleting an identity](#deleting-an-identity)). |
| `/admin/sessions`                     | List every active session across all identities. Toggle "active only" and revoke individual sessions. |
| `/admin/audit`                        | Append-only audit event log. Filter by email substring, action prefix, severity, and `since` timestamp. Backed by the Forseti-owned `audit_events` table (sqlite or Postgres); retention is operator-configured via `[audit].audit_retention_days` and pruning runs through the `forseti audit-prune` CLI subcommand (not auto-run inside the HTTP server). |
| `/admin/audit/{id}`                   | Full detail page for a single audit row — actor, target, metadata, IP hash, user agent.        |
| `/admin/webhooks`                     | Dead-lettered account-deletion webhook rows (12 attempts or 72 h exhausted). Per-row "Requeue" and "Discard" actions; a count banner surfaces on `/admin/status` when the table is non-empty. |
| `/admin/webhooks/{id}`                | Full detail page for a dead-lettered webhook row — payload, attempt history, last error.       |
| `/admin/webhooks/{id}/requeue`        | POST — flip a `DEAD` row back to `CONFIRMED` so the background worker picks it up again.        |
| `/admin/webhooks/{id}/discard`        | POST — drop the row without further delivery attempts.                                          |
| `/admin/resources`                    | The resource registry: MCP/API resource servers whose audiences consent may grant. List with corroboration badge, enable/disable toggle, delete. See [The resource registry](#the-resource-registry-adminresources). |
| `/admin/resources/new`                | Enroll a resource. Org-scoped admins may only register resources on a verified domain of their org. |
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
| First-party | Stackpit, Formshive, Kenning, Liwan |
| Git, CI/CD & infrastructure | GitLab, Gitea, Forgejo, Jenkins, Argo CD, Harbor, Rancher, Portainer, Proxmox VE, NetBox |
| Files, media & knowledge | Nextcloud, Seafile, Immich, Jellyfin, Audiobookshelf, Paperless-ngx, Outline, BookStack, HedgeDoc |
| Collaboration & productivity | Matrix Synapse, Discourse, Rocket.Chat, Mattermost\*, OpenProject\*, Plane\*, Vikunja, Mealie, Penpot, WordPress |
| Data, monitoring & feeds | Grafana, Apache Superset, Matomo, Miniflux, Open WebUI, Parseable |
| Other | Mastodon, Vaultwarden, Actual Budget, Atlassian Data Center\*, [Tailscale](#logging-into-tailscale) |

\* OIDC login requires that app's paid/enterprise tier — the template still works, but the form's guidance banner flags the licensing requirement.

The pre-filled URLs use literal placeholders you must replace before saving:

- `YOUR_DOMAIN` — the app's own hostname (e.g. `git.example.com`), not Forseti's. Several apps embed it in a fixed callback path.
- `PROVIDER_NAME` — for apps where the callback path includes the provider/auth-source name you configure app-side (Gitea, Forgejo, Vikunja, Paperless-ngx, Jellyfin). Replace it with whatever name you set there; some apps are case-sensitive about it.

Some templates carry a guidance banner on the form (e.g. PROVIDER_NAME notes, audience allow-list reminders) — read it before saving.

The template choice doesn't change the client's type: the stored `client_type` records the base preset (e.g. `web_app`), so the list filter and detail-page badge are unaffected by which app you started from. The template slug itself is recorded Forseti-side (purely so the app's logo can appear next to the client on the list) — it carries no trust or behaviour, and only clients created from a template after this shipped will show a logo.

After creating a client, its detail page (`/admin/clients/{id}`) shows a "Connection details" card with the issuer and OIDC endpoints (authorization, token, userinfo, JWKS, end-session) plus the client ID — everything you paste into the app's OIDC settings on the other end. The endpoints come from Hydra's discovery document; if Forseti can't reach Hydra at render time the card hides the endpoints and shows a note rather than guessing a (possibly wrong) issuer.

### Logging into Tailscale

Tailscale's [custom OIDC](https://tailscale.com/kb/1240/sso-custom-oidc) support takes any compliant provider, so a tailnet can sign in against your Forseti. Two of the requirements sit outside Forseti: the issuer has to be reachable from the public internet (Tailscale's servers fetch discovery and JWKS themselves, so a tailnet-only or LAN-only deployment won't do), and you have to prove control of your email domain with a WebFinger document. Tailscale reads both during tailnet creation; after that it behaves like any other provider.

1. **Create the client.** Pick the Tailscale template at `/admin/clients/new`. The callback is Tailscale's own (`https://login.tailscale.com/a/oauth_response`) and needs no editing; scope is `openid profile email`, authentication is `client_secret_basic`. Copy the client ID and secret.
2. **Publish WebFinger.** On the domain of your Tailscale admin's email address, serve `https://example.com/.well-known/webfinger` as `application/jrd+json`:

   ```json
   {
     "subject": "acct:admin@example.com",
     "links": [
       {
         "rel": "http://openid.net/specs/connect/1.0/issuer",
         "href": "https://auth.example.com"
       }
     ]
   }
   ```

   The `href` must be identical to the `issuer` in `https://auth.example.com/.well-known/openid-configuration` — that's Hydra's `urls.self.issuer`, trailing slash and all. A static file on the domain's web server is enough; Forseti doesn't serve this document, and it doesn't belong on the Forseti host unless Forseti is what answers for that domain.
3. **Hand Tailscale the details.** Issuer URL, client ID, client secret. Leave the prompt at the default `consent`; `select_account` is accepted by Hydra but ignored ([ory/hydra#1943](https://github.com/ory/hydra/issues/1943)), so it won't do what the name suggests.

What Tailscale reads from the id_token: `sub`, plus `email` and `email_verified` from the `email` scope and `name`/`preferred_username` from `profile`. Accounts are keyed on the email address. Hydra's default RS256 with a 2048-bit key satisfies Tailscale's "ES256 or RSA ≥ 2048" requirement.

Three limits worth knowing before you commit to it:

- **No provisioning.** Tailscale doesn't support user or group provisioning over custom OIDC, so Forseti's `groups`/`org`/`orgs` claims are ignored and ACL groups stay hand-maintained on the Tailscale side.
- **The whole domain moves at once.** Every user on that email domain authenticates through the same provider.
- **Logout isn't federated.** Signing out of Tailscale leaves the Forseti session standing, and vice versa.

Custom OIDC is free for up to three users; past that Tailscale gates it behind a paid plan.

#### Tailscale and organizations

Tailscale keys everything on the user's email domain, so [organizations](#organizations) don't carry across. A single tailnet corresponds to one email domain, not to one Forseti org:

- **One org, one email domain** (the default deployment): nothing to think about. One WebFinger document, one client, one tailnet.
- **Several orgs sharing one email domain** (departments of the same company): still one tailnet, and the org boundary is invisible on the far side — Tailscale reads neither the `groups` claim nor `org`/`orgs`, so tailnet access and ACL groups are maintained by hand in Tailscale.
- **Orgs on different email domains**: one tailnet per domain, each with its own WebFinger document on *that* domain — which means whoever controls that domain's web server has to publish it. The documents can all name the same Forseti issuer; give each tailnet its own client so secrets rotate independently. The tailnets themselves stay separate: separate ACLs, devices and billing.

Note that the org stamped on a client is an admin-visibility scope, not an access rule: a client created inside org B is managed by that org's admins, but any Forseti identity can authenticate to it. Nothing in the authorization flow checks membership. Who ends up in the tailnet is decided on Tailscale's side, by email domain.

One more thing to watch: the email address is the join key. A user who changes their email in account settings is a different user to Tailscale.

### Audit logging

Audit events are persisted to the Forseti-owned `audit_events` table (sqlite or Postgres). The table is **append-only at the DB layer** — a BEFORE UPDATE/DELETE trigger refuses modifications unless the pruner sets a single-transaction override flag (`current_setting('app.audit_purge')` on Postgres, a sentinel row in `_forseti_meta` on sqlite). The flag is defence against application-bug clobbering history, not against a malicious operator with direct DB access.

Three sources feed the table:

1. **Forseti-owned handlers — direct emit.** Logout, settings session revoke, OAuth consent (granted / denied), account self-deletion, every admin action (`/admin/clients/*`, `/admin/identities/*`, `/admin/sessions/*`, `/admin/webhooks/*`).
2. **Kratos flow webhooks** delivered to `POST /internal/audit/kratos` on the **internal listener**. Flow-completion events only: `identity.created` (registration), `auth.login` (login.{password,passkey} — AAL2 step-up methods intentionally don't fire so a single sign-in produces one row, not two), `password.changed` (settings.password), `password.recovered` (recovery), `verification.completed` (verification), `mfa.*` (settings.{totp,webauthn,lookup}). Kratos's admin API does not fire flow hooks, so admin-driven identity writes go through path 1.
3. **Hydra consent decisions** emitted from Forseti's own `src/oauth/consent.rs` (Hydra has thin hook surface; scraping logs is fragile).

The `password.changed` webhook does more than audit: Forseti ends the user's app sessions in their other browsers and revokes those sessions' grants, keeping the browser that made the change. A password reset counts too, since Kratos sets the new password through the same settings flow. This needs the `settings.after.password` hook and the `kratos_session_id` field the reference `audit_event.jsonnet` reads from `ctx.session`; a deployment without them keeps working, but skips this step (and logs a warning when the session id is missing).

The webhook receiver's bearer token, replay check and status counters are in the Kratos guide's [Audit logging](./operator-guide-kratos.md#audit-logging).

#### IP pseudonymization

Audit rows store a salted hash of the client IP, not the address itself, so events from the same address correlate without retaining the address. The salt comes from `[audit].ip_salt` when set; when unset it is derived from `[security].cookie_secret`, and a boot warning reminds you of that. The derived default has one operational consequence: rotating the cookie secret also rotates every `ip_hash`, so rows from before the rotation no longer correlate with rows after it. Set a dedicated `ip_salt` (`openssl rand -hex 32`) to decouple audit correlation from cookie-secret rotation.

#### Internal listener

Machine-to-machine endpoints live on a **separate HTTP listener** from the user-facing Forseti: today the audit webhook receiver (`POST /internal/audit/kratos`) and the POSIX resolver API (`GET /posix/v1/*`, consumed by enrolled Linux hosts' NSS/sshd). The split is the trust boundary — the internal listener should never be reachable from the public internet, while the public listener is built for it.

| Knob              | Default              | What to set in production                                                                                                                |
|-------------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `[internal].bind` | `127.0.0.1:8081`     | Loopback when Forseti and Kratos share a host. Bind to a specific private interface (e.g. `10.0.0.5:8081`) — or `0.0.0.0:8081` inside a container where the trust boundary is the docker / pod network — so Kratos in a separate container can reach it. **Never expose this on a public interface.** |

The internal listener does not mount `/readyz` or `/healthz`; those stay on the public listener so load balancers and orchestrators don't have to know about a second port. CSRF middleware is also not applied to the internal listener — these endpoints take JSON over `POST` (audit webhook) or authenticated `GET` (POSIX resolver), not cookie-bearing browser forms.

**Remote hosts and rebinding.** With the default loopback bind, only processes on the Forseti host can reach the resolver. Linux hosts elsewhere need the listener rebound to a private interface (`10.0.0.5:8081`) behind a firewall that admits only those hosts. Note the audit webhook and the resolver **share this listener** — rebinding to `0.0.0.0:8081` exposes *both*. The resolver authenticates each host with HTTP Basic (`host_id:secret`, SHA-256-hashed, constant-time compared), so its own auth holds, but the audit webhook's bearer token (`[audit].webhook_token`) and a network ACL in front of the listener both matter once it leaves loopback.

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
- **OIDC sign-ins are unaudited by default.** A `forseti-config init`-generated `kratos.yml` carries no audit `web_hook` nodes, so `forseti-config oidc enable` has no existing hook to clone onto the new provider's login/registration flows and warns rather than silently leaving a gap (see [Enabling and disabling OIDC providers](./operator-guide-kratos.md#enabling-and-disabling-oidc-providers)). Wiring one up is a manual step today.

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
- **Delete** (`/admin/posix/{id}/delete`) — remove the account and its POSIX rows outright. Deleting the underlying Kratos identity also purges its POSIX rows at every delete path (the settings page, the admin page, `forseti delete-identity`, email reclaim, `unverified-prune`; see [Deleting an identity](#deleting-an-identity)), and an hourly reconcile sweep catches identities deleted out-of-band via the Kratos admin API — so an orphaned POSIX account can't keep a deleted identity's login alive.

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

**Each user's first login on a host must be online.** A host is provisioned offline verifiers only for the accounts it has already seen: a user's verifier is served to a given host only after that user has completed an online device-auth login *on that host*. On a freshly enrolled host every user therefore has to log in once while the host can reach Forseti; every later login on that host can fall back to offline. The point is to bound what a compromised or decommissioned-but-unrevoked host can walk away with: an offline-crackable corpus for the people who actually use that host, not for the whole org. The record is per host and does not expire on its own (expiring it would lock a returning user out of a partitioned host), so withdrawal is deleting the host, disabling the account, or de-scoping it, exactly as with any other verifier.

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
  error:   https://accounts.example.com/error
  post_logout_redirect: https://accounts.example.com/signed-out
  registration: https://accounts.example.com/oauth/register

webfinger:
  oidc_discovery:
    supported_scope: [email, profile, org, orgs, groups, extended_profile]
    supported_claims: [sub, iss, aud, exp, iat, auth_time, nonce, acr, amr, sid, email, email_verified, name, given_name, family_name, picture, website, preferred_username, locale, updated_at, org, orgs, groups, bio, pronouns, links]
```

- `issuer` is the public hostname downstream apps see in `iss` claims and use for OIDC discovery.
- `login`, `consent`, `logout` redirect the user to Forseti carrying a challenge query parameter. Forseti exchanges the challenge with Hydra's admin API and accepts or rejects it.
- `error` is where Hydra sends OAuth errors it can't return to the client (unknown client, unregistered redirect URI). `post_logout_redirect` is the landing after a logout that names no registered `post_logout_redirect_uri`. `registration` serves `prompt=create`: Forseti's authorize endpoint rewrites it to Hydra's `prompt=registration`, and Hydra hands the challenge to this URL. Unset, users see Hydra's unbranded fallback pages.
- `webfinger.oidc_discovery` fills discovery's `scopes_supported` and `claims_supported`. Hydra adds `openid`, `offline` and `offline_access` itself.
- `forseti-config check` warns when any of these are unset or the three landings aren't on the same origin as `urls.login`.

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
- Capture the printed `client_id` and `client_secret` and pass them to the downstream app's operator. (With DCR retired, Hydra's RFC 7592 management endpoints are gone — a `registration_access_token` has nothing to talk to; client changes go through the admin UI or the admin API.)

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
| RFC 8707 Resource Indicators (`resource=` parameter) | Hydra ignores `resource=` entirely; Forseti's consent handler bridges it — a requested `resource` is bound into the access token's `aud` when it matches an enabled [resource registry](#the-resource-registry-adminresources) row (default deny). See [RFC 8707 `resource` → access-token audience](#rfc-8707-resource--access-token-audience) |
| RFC 9449 DPoP | **Not implemented.** Tokens are bearer-only |
| RFC 8705 mTLS client auth + cert-bound tokens | Not configured |
| RFC 9126 PAR (Pushed Authorization Requests) | Supported by Hydra; no Forseti-side enforcement |
| RFC 9101 JAR (signed request objects) | Supported by Hydra; no Forseti-side enforcement |
| RFC 9396 RAR (Rich Authorization Requests) | Not used |
| RFC 9700 OAuth Security BCP (Jan 2025) | Reference document — the items above cover the BCP's MUST-level requirements except DPoP/mTLS |
| CIMD (draft-ietf-oauth-client-id-metadata-document) | Implemented by Forseti's `/oauth2/authorize` shim + augmented discovery, since Hydra has no native support ([ory/hydra#4061](https://github.com/ory/hydra/issues/4061)). Public clients (`token_endpoint_auth_method: "none"`) only |

### MCP support

Hydra works as the authorization server for [Model Context Protocol](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) servers (Claude Desktop, Claude Code, claude.ai). Forseti supplies what Hydra lacks for MCP: CIMD client onboarding (Hydra has no native support, [ory/hydra#4061](https://github.com/ory/hydra/issues/4061)), the RFC 8707 `resource` → `aud` bridge at consent, and the augmented discovery documents that advertise both. This section is the operator-side checklist.

The moving pieces, in the order a first connection touches them:

1. **Discovery** — the MCP client fetches AS metadata at the RFC 8414 path-insertion URL (`/.well-known/oauth-authorization-server/hydra` on the issuer host). Forseti serves it: Hydra's own document with `client_id_metadata_document_supported: true` added and `authorization_endpoint` pointed at the shim. See [Fronting the issuer](#fronting-the-issuer-front-proxy-vs-haproxy).
2. **Client onboarding** — the client identifies itself with a URL-shaped `client_id` (CIMD); Forseti's `/oauth2/authorize` shim fetches, validates and upserts it as a Hydra client on the fly. Zero operator involvement per connection. See [CIMD](#cimd-zero-config-client-onboarding).
3. **Audience** — the token's `aud` binds to the requested `resource=` only when the resource is enrolled at `/admin/resources`. One registry row per MCP server, no restart. See [The resource registry](#the-resource-registry-adminresources).

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
  # DCR retired: CIMD clients are upserted through the Forseti shim, so no
  # anonymous registration endpoint exists anywhere. (The old "Claude Code
  # refuses an AS without /oauth2/register" claim was falsified once
  # client_id_metadata_document_supported was advertised.)
  dynamic_client_registration:
    enabled: false
```

#### Token validation: JWT access tokens (default and recommended)

The playground ships with **JWT access tokens and a 5-minute TTL**, pinned in `infra/hydra/hydra.yml`:

```yaml
strategies:
  access_token: jwt
  scope: exact

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

#### Audience binding (RFC 8707 `resource` and Hydra's non-standard `audience`)

Hydra binds audiences at the auth-request level — clients pass `audience=<url>` on the authorization request, and Hydra issues a token with `aud: ["<url>"]`, but **only for values pre-registered on the client**; anything else refuses the whole authorize request. Hydra does not implement [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) `resource=` at all as of v26.2.0.

Forseti's consent handler is where the actual audience decision happens (see [RFC 8707 `resource` → access-token audience](#rfc-8707-resource--access-token-audience) above): it unions both carriers and default-denies anything that is neither an enabled [resource registry](#the-resource-registry-adminresources) row nor the registered `audience` of an admin-created client. The registered `audience` counts as policy only for a client created through the admin UI (`oauth_client_metadata.source = 'admin'`); a CIMD client's record content is never policy — its `audience` array is written only by the consent-time refresh heal.

So the two enrolment paths for an MCP server's audience:

- **Registry row** (`/admin/resources`) — works for every client, including CIMD clients you've never seen. This is the normal path for MCP.
- **Client audience textarea** (admin UI's MCP preset on a pre-registered client) — binds the audience to that one client only.

Track the upstream: [`ory/hydra` RFC 8707 issues](https://github.com/ory/hydra/issues?q=RFC+8707). When shipped, the registry keeps working as the policy layer on top.

#### CIMD: zero-config client onboarding

CIMD ([Client ID Metadata Documents](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)) is the MCP spec's replacement for Dynamic Client Registration: the `client_id` **is** an HTTPS URL, and the authorization server fetches that URL to learn the client's metadata (name, redirect URIs, grant types). No registration endpoint, no per-connection operator work, and the client's identity is a URL whose host its operator provably controls. Claude Code and claude.ai implement it; Hydra doesn't ([ory/hydra#4061](https://github.com/ory/hydra/issues/4061)), so Forseti provides it as a shim in front of Hydra.

**The shim: `GET /oauth2/authorize`.** Forseti's augmented discovery advertises this route as the `authorization_endpoint`. On each request:

1. A `client_id` that is **not** an `https://` URL passes straight through — 302 to Hydra's real `/oauth2/auth` with the query string byte-identical. Pre-registered clients are unaffected.
2. An `https://` URL `client_id` takes the CIMD path: fetch the document through the SSRF guard (https only, public IPs only re-checked at DNS resolution, no redirects, 5 s timeout, 64 KiB cap, 512-byte URL cap, no credentials/fragment in the URL), validate it (its `client_id` member must equal the fetched URL byte-for-byte; `token_endpoint_auth_method` must be `"none"` — public clients only; `grant_types` must include `authorization_code`, and only `authorization_code` and `refresh_token` are carried onto the Hydra client (claude.ai also lists `jwt-bearer`, which is ignored); `response_types` = `["code"]`; every `redirect_uris` entry `https://` or loopback `http://`), match the request's `redirect_uri` against the document (exact, except loopback URIs match on any port per RFC 8252 §7.3), then create or update the matching Hydra client row and 302 into Hydra. Validation failures render a plain 400 naming the reason — never a redirect, because the redirect URI isn't trusted yet.

Documents are cached in-process (1024 entries, TTL from `Cache-Control: max-age` clamped to [60 s, 24 h], 300 s default, single-flight per URL, 1 h serve-stale-on-error grace), and a warm path skips the Hydra admin calls entirely when the document hash is unchanged and the redirect URI is already registered — the common repeat visit is cache hit → redirect, no writes.

**The `localhost` compensation.** Hydra's loopback redirect matching is IP-literal-only: a registered port-less `http://127.0.0.1/callback` matches any port, but `http://localhost/callback` does not — and Claude Code builds `http://localhost:{ephemeral}/callback` at runtime. The shim compensates by upserting the requested literal onto the Hydra row when it matched a loopback document entry only via the any-port rule. At most 5 such literals are kept (oldest evicted); document URIs are never evicted.

**Scope ceiling.** The Hydra row's `scope` is the union, in this order, of the row's existing entries (never removed), the built-in `openid offline offline_access`, `[oauth.cimd].client_scope_extra`, the document's own `scope`, and the request's allowlisted `scope` values. It's capped at 256 entries with a warning when the cap truncates; request scopes come last, so they never push out operator or document entries. The resource registry contributes at most 128 distinct scopes across all rows, oldest rows first (by creation time), so config sources plus registry scopes stay well under the cap. This is a ceiling, never a grant: the consent screen and the resource server's own role intersection remain the actual authorization.

**Scope allowlist.** A request scope reaches the ceiling only when it's on the allowlist. The global sources: the built-in `openid offline offline_access`, the consent screen's own `email profile org orgs groups extended_profile`, the keys of [`[oauth.scope_descriptions]`](#oauthscope_descriptions), the entries of `client_scope_extra`, and the client document's `scope`. The per-resource source: the stored `scopes_supported` of each enabled, counted [registry row](#the-resource-registry-adminresources) that one of the request's `resource=` values names (matched verbatim, then canonically; the first 5 values count). A request without a matching `resource=` gets the global sources only, which is what the MCP spec expects anyway: clients must send `resource=`.

When scopes are still dropped after the stored lists, and a `resource=` names a registry row with a fetchable URI, Forseti re-fetches that row's RFC 9728 document once, stores the result and filters again. One re-fetch per resource per 60 s, per process; the URL comes from the stored row, never from the request. A throttled or failed re-fetch keeps the stored list. So an MCP server release that adds a scope to `scopes_supported` works on the next request, with no Forseti change.

Any token containing `*` is dropped from every source and from the request: Hydra's default `wildcard` scope strategy would treat it as a pattern (see [`strategies.scope: exact`](./operator-guide-kratos.md#configuration-rationale)). Any other request scope stays off the Hydra row; Forseti passes the request to Hydra unchanged, Hydra answers `invalid_scope`, and Forseti logs one warning per request naming up to 5 of the dropped scopes. The global sources aren't per client: any listed scope can reach any CIMD client's ceiling, and consent gates the grant.

**Upgrade requirement: list step-up scopes in config.** A CIMD client that asks for a scope its Hydra row doesn't carry yet, and that no source allows, gets `invalid_scope` and can't connect. Scopes an MCP server publishes in its RFC 9728 `scopes_supported` are discovered per resource, as long as the server is enrolled in the registry and the client sends `resource=`. Two kinds still need config: step-up scopes a server deliberately leaves out of `scopes_supported`, and every scope of a server that publishes no RFC 9728 document. List those under `[oauth.scope_descriptions]` (or `client_scope_extra`); config scopes apply to every resource. `openid` and `offline_access` are built in and need no entry. Set Hydra's `strategies.scope: exact` as well. For Stackpit and Formshive, the step-up scopes:

```toml
[oauth.scope_descriptions]
"stackpit:admin"                = "Create and archive your Stackpit projects"
"formshive:forms:write"         = "Create and modify your forms"
"formshive:integrations:write"  = "Create and modify your form integrations"
"formshive:admin"               = "Delete your forms, submissions and integrations"
```

Descriptions for the discovered scopes are optional; without one, the consent screen shows the raw scope name.

**What CIMD clients can never do:**

- A `source='cimd'` metadata row never satisfies the operator-written-audience arm of consent — the client record is not policy (its `audience` is written only by the consent-time refresh heal).
- The shim refuses (400) any `client_id` that collides with an existing non-CIMD client — a CIMD flow can never mutate an admin-created client.
- The shim never sets `skip_consent`, `metadata.forseti.*`, or `audience` from document content.
- No RFC 7592 surface exists: admin-API-created rows carry no usable registration access token, and Hydra's `/oauth2/register/{id}` endpoints are disabled with DCR.
- Consent is always rendered — the auto-grant guard excludes `source = 'cimd'` rows outright, so neither a remembered consent, `skip_consent`, nor even an operator-verified row bypasses the screen.

**Consent display.** For a CIMD client, the consent screen shows the client_id URL's **host** (e.g. `claude.ai`) as the primary identity with the document's self-asserted `client_name` demoted to a secondary line — names inside the document are self-asserted; the host is what the operator of that URL provably controls. No verification badge is ever rendered for CIMD clients.

**Host policy and rate limits.** `[oauth.cimd].allowed_client_hosts` closes the fleet to named client vendors (exact host match); empty means open, consent-gated. The shim carries the same dual per-IP + global rate-limit shape as the other public endpoints (see the [`[oauth.cimd]`](#oauthcimd--cimd-shim-knobs) table).

**Client ceilings.** Rate limits bound how fast an unauthenticated caller can register clients, not how many end up existing — each distinct client_id URL leaves a permanent Hydra client and `oauth_client_metadata` row behind, so a patient caller still fills the tables. `max_clients` (500) and `max_clients_per_host` (50) bound the standing count. Only a client_id Forseti has never seen is refused, with `oauth.client.cimd_rejected` naming which ceiling was hit; everything already registered keeps authorizing. A deployment that legitimately needs more should raise the numbers rather than set them to `0`.

**Auditing.** Every completed shim pass emits `oauth.client.cimd_seen` (target = the client_id URL); every rejection emits `oauth.client.cimd_rejected` at WARNING with the reason.

**What happened to DCR?** Retired. The RFC 7591 proxy, the Initial Access Token machinery (`/admin/dcr-tokens`), the `dcr_*` config keys and the reserved-name denylist for client names are all gone; Hydra's `dynamic_client_registration` is `enabled: false` and no `registration_endpoint` is advertised anywhere. The old claim that Claude Code refuses an AS without `/oauth2/register` was falsified once `client_id_metadata_document_supported: true` was advertised — Claude Code 2.1.220 selects CIMD and never attempts DCR. Existing `oauth_client_metadata` rows with `source='dcr'` are kept (history + still-live refresh tokens), but nothing can create new ones. DCR-only clients (Cursor, as of mid-2026) will not work until they ship CIMD.

#### The resource registry (`/admin/resources`)

The registry is the consent-time audience allow-list: one row per resource server (MCP server, downstream API) whose URI consent may bind into an access token's `aud`. Enrolment is a web-UI action — a row, not a config edit, no restart. It replaces the deprecated `[oauth].allowed_resource_audiences` key (still imported at startup; see the [`[oauth]`](#oauth--audience-policy) table).

Each row carries:

- **`resource`** — the canonical resource URI (canonicalised on create; matched across a trailing slash or fragment), or a verbatim non-URI identifier for legacy audiences like `stackpit-web`.
- **`display_name`**, **`org_id`**, **`enabled`** (the toggle consent actually checks), **`created_by`**, **`created_at`**.
- **`access_token_claims`** — `metadata_admin` keys copied into tokens for this resource; Forseti-wide admins only. See [Access-token claims from `metadata_admin`](#access-token-claims-from-metadata_admin).
- **Self-service** (claim, issuer URL, client ID, value template): lets users link the value of one of those claims themselves; Forseti-wide admins only. See [Self-service resource claims](#self-service-resource-claims).
- **Corroboration badge** — an advisory RFC 9728 check, run on create and via the per-row "re-check" button: Forseti fetches `https://{host}/.well-known/oauth-protected-resource{path}` through the same SSRF guard as the CIMD fetcher and compares the document's `resource` and `authorization_servers` against the row and the configured issuer. Statuses: `unchecked` / `corroborated` / `unreachable` / `mismatch`. It **never gates** creation (the app may not be deployed yet) and never binds an audience; non-URI identifiers have nothing to fetch and stay `unchecked`.
- **Stored scopes** - the document's `scopes_supported`, kept on the row and refreshed on create, on re-check and by the CIMD shim's on-demand re-fetch. Only a `corroborated` document replaces the list; a corroborated document that drops a scope shrinks it, a missing or non-array `scopes_supported` leaves it as it is. On `mismatch` or `unreachable` the stored list stays, so an MCP server outage doesn't refuse scopes that worked a minute ago; disable the row to cut it off. Entries must be RFC 6749 scope tokens without `*`, at most 128 characters, at most 30 per row; anything else is skipped. Every change writes a `resource.scopes_changed` audit row with the added and removed names.

**Which rows count.** A row's stored scopes count when the row is enabled and either sits in the default org or its URI host is still a verified domain of its org. Losing or removing that verification stops its scopes counting (audience binding is unaffected). Put org-independent rows in the default org.

**Consent downscoping.** Per RFC 8707 section 2.2, a scope that comes only from registry rows (not built in, not a `scope_descriptions` key, not in `client_scope_extra`) is granted only when the token's audience includes a counted row that lists it; otherwise consent leaves it out of the grant, and the consent screen doesn't show it. This applies to every client: a registry scope can sit on a shared client's ceiling after one request for resource A, and Hydra then accepts it on a request for resource B, but the token for B won't carry it. A client's own scope (pre-registered, or from a CIMD document's `scope`) that some registry row also lists is held to the same rule; add it to config if it should apply everywhere. Scopes in no source at all pass through untouched.

**Org scoping.** A Forseti-wide admin can register any resource into any org. An org-scoped admin (`?org=<slug>`) sees only rows stamped with their org and may only create resources whose URI host is a **verified domain** of that org (fail closed) — domain-ownership proof via the existing org domains verification.

Disabling a row denies the audience on the next consent; deleting it does the same permanently. Already-issued tokens keep their `aud` until they expire (5-minute JWTs by default). Audit rows: `admin.resource.created`, `admin.resource.toggled`, `admin.resource.claims_updated`, `admin.resource.deleted` (the last two at critical severity) and `resource.scopes_changed` (from the admin or the CIMD shim).

#### Fronting the issuer (front proxy vs haproxy)

CIMD-capable clients discover the AS via RFC 8414 **path insertion**: for issuer `https://accounts.example.com/hydra` they fetch `/.well-known/oauth-authorization-server/hydra` (and the OIDC variant `/.well-known/openid-configuration/hydra`) on the issuer host. Forseti serves both routes with Hydra's own discovery document plus exactly three mutations: `client_id_metadata_document_supported: true`, `authorization_endpoint` → Forseti's `/oauth2/authorize` shim, and `registration_endpoint` removed. Everything else — `issuer` above all, since it's the `iss` in every token — passes through byte-identical. The response carries `Access-Control-Allow-Origin: *` (browser-based clients like claude.ai read it cross-origin).

For all of this to work, the issuer's origin must route three things to the right place:

- The two path-insertion well-known URLs **and** `/oauth2/authorize` → **Forseti**.
- `/hydra/*` (Hydra's real endpoints: `/hydra/oauth2/auth`, `/hydra/oauth2/token`, JWKS, userinfo) → **Hydra**.

Two ways to arrange that:

- **External proxy (haproxy, prod).** haproxy routes `path_beg /hydra/` to Hydra (stripping the prefix) and everything else — including the well-knowns and the shim — to Forseti. Forseti needs `[hydra].issuer` set to the browser-facing issuer and `[hydra].public_url` pointed at Hydra directly, not through haproxy, because haproxy routes the issuer's discovery URL back to Forseti. See [`operator-guide-proxy.md`](./operator-guide-proxy.md).
- **Front proxy (`[hydra].front_proxy = true`, single binary / dev).** Forseti itself reverse-proxies `GET/POST /hydra/{path}` to `[hydra].public_url`, so Forseti owns the whole issuer origin. The passthrough forwards `Cookie` and multi-valued `Set-Cookie` both ways (Hydra's login/consent CSRF cookies) and never follows Hydra's redirects — those belong to the browser. Bodies are buffered under a 2 MiB cap. `GET /hydra/.well-known/openid-configuration` through the passthrough is served augmented too, never verbatim.

Set `[hydra].issuer` to the browser-facing issuer in both cases. It drives three things: the path segment the well-known routes mount under, the CIMD shim's redirect base (a *relative* `/hydra/oauth2/auth` redirect, so the browser stays on the issuer origin and Hydra's host-scoped CSRF cookies survive), and the CSP `form-action` origin.

> **The CSP `form-action` requirement.** Forseti's CSP allows form POSTs to end only at known origins, and Chrome and Safari enforce `form-action` across every hop of the submission's redirect chain, not just the form's own action. Submitting the sign-in form runs Kratos → `/oauth/login` → Hydra before the chain ends on a Forseti page, so the issuer's browser-facing origin has to be right. It comes from `[hydra].issuer` (falling back to `[posix].hydra_issuer`, then `[hydra].public_url`). If that value is stale — pointing at an origin the browser never actually visits — the hop into Hydra is **silently blocked**: the server logs a clean 303, the browser sits on an unchanged page, and nothing errors. If sign-in "does nothing", check `[hydra].issuer` before anything else. OAuth client origins are not involved; Forseti ends the submission on its own origin before handing back to Hydra.

**Reviewing clients (Verified / Unverified).** Every OAuth2 client carries a verification state in the Forseti-owned `oauth_client_metadata` table (Forseti-owned so no client-held credential can ever rewrite it):

- **`"verified"`** — green badge on the admin list + show page. The consent screen renders a subtle "Reviewed by your administrator" checkmark. Operator-created clients (anyone hitting `New client` on `/admin/clients`) are stamped verified at create time, since the act of an operator creating the client is the vouching. The `verified_by` and `verified_at` columns record who and when.
- **`"unverified"`** — yellow/red badge in the admin UI. The consent screen renders a prominent caution banner: **"This application has not been reviewed by an administrator. Only proceed if you trust it."** CIMD clients always carry this state (and never auto-grant consent); the "Reviewed by your administrator" checkmark is never rendered for a CIMD client either way — the host-primary identity line is their trust signal. Forseti does not auto-promote — explicit admin action is required.

To review a client: open `/admin/clients?verification=unverified`, click into the client, eyeball the redirect URIs and `client_name`, and either:

- Click **Mark as verified** — POSTs to `/admin/clients/{id}/verify`, sets `verification = 'verified'`, `verified_by`, `verified_at`, and emits an `oauth.client.verified` audit row.
- Click **Delete** if the client is illegitimate.

To revoke a previously granted verification (e.g. the client started behaving badly), click **Revoke verification** on the show page. POSTs to `/admin/clients/{id}/unverify`, flips Forseti row back to `'unverified'`, records `verification_revoked_by` / `verification_revoked_at`, and emits a `critical`-severity `oauth.client.unverified` audit row. The consent screen reverts to the caution banner on the next consent request.

Clients that exist on Hydra without a matching `oauth_client_metadata` row default to verified — those came in through the admin UI before this table shipped, so the implicit-trust rule applies retroactively. Verify or unverify lazily creates the row; no backfill needed.

**Consent screen logo.** The client show page carries a **Consent screen logo** card. Upload a PNG, JPEG or WebP (256 KB max) and it replaces the generic icon at the top of that client's consent screen, so the user sees who they're handing data to. The surrounding chrome stays operator- or org-branded, and `/login` is untouched: the sign-in page never varies per app, which is what keeps "my IdP login always looks the same" usable as a phishing check.

Whoever can administer the client can upload — Forseti admins for any client, org-scoped admins for clients in their own org. The image is stored in Forseti's `client_logos` table and served from `/clients/{client_id}/logo` to signed-in callers only; anonymous requests get a 404 whether or not the client exists. The file type comes from the leading bytes, never the declared `Content-Type` or the filename, and SVG is rejected outright (it's script-capable and would be served from your own origin). Uploads and removals emit `oauth.client.logo_uploaded` / `oauth.client.logo_removed` audit rows.

The client's own `logo_uri` is deliberately *not* used here. It's client-controlled (a CIMD document carries it onto the Hydra row), and rendering a remote URL would make every user's browser hit the relying party's server from your consent page — leaking IP, user-agent and timing before the user has agreed to anything. Unverified clients still show their logo; the caution banner is the trust signal, and hiding the logo would only make "no logo" ambiguous between "not reviewed" and "never uploaded one".

**Rate-limit mechanics.** The CIMD shim's per-IP buckets share the deployment-wide behaviour of every other public limiter: in-memory, per-process (no cross-replica coordination), keyed on the TCP peer IP (IPv6 by its /64) unless `[proxy].trust_forwarded_for = true` behind an appending proxy (see [`[proxy]`](#proxy--reverse-proxy-trust) and the haproxy sketches in [`operator-guide-proxy.md`](./operator-guide-proxy.md)). The global windows count first sightings of a `client_id` only (no metadata row yet, so a document fetch), checked in the handler before the fetch; they bound how fast unknown clients cost a fetch even when a spoofed `X-Forwarded-For` defeats the per-IP buckets, while known clients are limited per IP only. A throttled request gets `429` with `Retry-After`.

#### RFC 9728 — Protected Resource Metadata

MCP servers advertise their authorization server via [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728). The chain:

1. Client hits MCP server unauthenticated → `401` with `WWW-Authenticate: Bearer resource_metadata="<url>"`.
2. Client fetches `<url>` (path-aware: `/.well-known/oauth-protected-resource{path}` on the MCP server's origin) → JSON pointing at the issuer.
3. Client resolves the issuer's AS metadata via RFC 8414 path insertion first — which lands on Forseti's augmented document (see [Fronting the issuer](#fronting-the-issuer-front-proxy-vs-haproxy)).

The document itself is MCP-server-side; Forseti's [corroboration check](#the-resource-registry-adminresources) fetches it when the resource is enrolled, on re-check and when a CIMD request needs a scope the stored list doesn't have. Forseti reads three fields: `resource` (must match the row, verbatim or canonically), `authorization_servers` (must list the issuer) and `scopes_supported` (stored per resource when the first two hold). Sample (the MCP-server author publishes this):

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://accounts.example.com/hydra"],
  "scopes_supported": ["app:tool:invoke"],
  "bearer_methods_supported": ["header"]
}
```

`authorization_servers` must list the issuer exactly (`[hydra].issuer`); the corroboration badge compares against it trailing-slash-insensitively.

#### Workflow: enrolling an MCP server

1. `/admin/resources/new` → enter the MCP server's canonical resource URI (e.g. `https://mcp.example.com/mcp`) and a display name. Org-scoped admins can only use hosts on a verified org domain.
2. Submit. The corroboration check runs immediately; an `unreachable` badge is normal when the app isn't deployed yet — use **Re-check** later.
3. Scopes the MCP server publishes in `scopes_supported` need nothing more: they're stored on the row and allowed for requests naming this resource. List step-up scopes the server leaves out of `scopes_supported`, and every scope of a server without an RFC 9728 document, under `[oauth.scope_descriptions]` in `config.toml` (`<app>:<resource>:<verb>` convention). Add a description for any scope whose raw name shouldn't be what the consent screen shows.
4. Done — CIMD clients (Claude Code, claude.ai) connect with no further operator work.

Pre-registering a client is only needed for non-CIMD clients: `/admin/clients/new` → the **MCP server** card pre-fills `authorization_code` + `refresh_token`, `none` auth method, PKCE, the audience textarea and redirect-URI hints. A client created this way is `verified`, and its registered audience counts as consent policy on its own.

#### Verifying the discovery document

After bringing the stack up, confirm the augmented discovery doc at the path-insertion URL carries everything MCP clients read (issuer `https://accounts.example.com/hydra` shown; adjust the path segment to your issuer's):

```bash
curl -s https://accounts.example.com/.well-known/oauth-authorization-server/hydra | jq '{
  issuer,
  authorization_endpoint,
  client_id_metadata_document_supported,
  registration_endpoint,
  code_challenge_methods_supported,
  token_endpoint_auth_methods_supported
}'
```

Expected:

- `issuer` byte-identical to Hydra's own (`urls.self.issuer`).
- `authorization_endpoint` pointing at Forseti's `/oauth2/authorize` on the issuer origin (the CIMD shim).
- `client_id_metadata_document_supported: true`.
- `registration_endpoint` **absent** (DCR retired).
- `code_challenge_methods_supported` includes `"S256"`; `token_endpoint_auth_methods_supported` includes `"none"`.

The same document must come back from `/.well-known/openid-configuration/hydra` and from `{issuer}/.well-known/openid-configuration`. With `front_proxy = true` Forseti serves both; behind haproxy the proxy has to rewrite `/hydra/.well-known/openid-configuration` to Forseti's path-insertion route (see [`operator-guide-proxy.md`](./operator-guide-proxy.md)). Hydra does not advertise `resource_indicators_supported` (no RFC 8707 yet); spec-strict MCP clients haven't been observed to reject it for that omission.

#### State parameter

Even with PKCE, the [Ory MCP guide](https://www.ory.com/blog/mcp-server-oauth-with-ory-hydra-authentication-ai-agent-integration-guide) recommends MCP clients still send `state`. Belt-and-braces: PKCE prevents code-injection, `state` prevents CSRF on the redirect. Forseti doesn't enforce this; it's a client-side recommendation worth surfacing to MCP-server authors.

#### At-rest hashing for refresh tokens and introspection caches

If the MCP server caches introspection responses (defensible up to ~30s) or stores refresh tokens it received on behalf of the user, hash them at rest with SHA-256+ rather than storing raw values. Note this in the MCP-server's own deployment docs — Hydra and Forseti don't enforce it.

## SMTP

On the Kratos build, two SMTP transports operate independently and can both point at the same relay:

- **Kratos courier** — verification codes, recovery codes, MFA enrolment notifications, and any Kratos-template-driven mail. Configured under `courier.smtp` in `kratos.yml`; see the Kratos guide's [SMTP](./operator-guide-kratos.md#smtp).
- **Forseti mailer** — org invites and the hand-rolled `/claim-email` verification code. Configured under `[email]` in `config.toml`. Forseti sends directly (via [polymail](https://github.com/franzos/polymail-rs)) because Kratos's admin API doesn't expose a one-off "send this message" endpoint in v26+.

The native build has no courier: the Forseti mailer also sends its verification and recovery codes.

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

Sanity-check: on the Kratos build, omitting the section (or `enabled = false`) leaves the mailer dormant — useful for OSS deployments that don't have a provider handy or for tests. Disabled-state callers `tracing::info!` the would-be recipient and continue without error, so the surrounding flow still completes. The native build refuses to start without `[email]`: it sends verification and recovery codes through it.

## Member profiles

The **Username** form on `/settings/profile` is always available; it is the handle downstream apps read as `preferred_username` (see [Usernames](#usernames) below). Everything else is off by default. When `[profiles].enabled = true`:

- `/settings/profile` grows a **Public profile** form (bio, location, pronouns, website, avatar URL, links).
- `/users/{identity_id}` renders a profile view — only when the viewer shares at least one org with the target. Anonymous viewers and non-sharing viewers see a 404 (not 403; no "this page exists" leak).
- The members roster on `/settings/organization/members` links each row with a non-empty profile to that view page.
- Avatar: external `avatar_url` only — no upload pipeline. When unset, a deterministic SVG identicon (hash → 5-cell mirrored pattern) renders as fallback.
- Audit: `profile.updated` event on each public-profile save. `profile.username_changed` (with the old and new handle) is logged whenever the username changes, feature on or off. No view-events.

```toml
[profiles]
enabled = true
```

### OIDC exposure

The `profile` scope always carries the handle when the user set one:

- `preferred_username` — the handle the user chose, omitted when unset
- `updated_at` — seconds since the epoch, last change to any portal-owned profile field

With `[profiles].enabled` on it picks up two more standard claims when the user filled the fields:

- `picture` — the `avatar_url` value
- `website` — the `website` value

#### Usernames

The username field is what downstream apps read as `preferred_username`. Several of them provision a local account from it — Forgejo and Gitea derive the local username from this claim, and with `ACCOUNT_LINKING = auto` they will match an *existing* local account by it. That makes a recycled handle an account-takeover path, so Forseti is stricter than OIDC Core requires:

- 2 to 39 characters, ASCII letters, digits, `.`, `_`, `-`, starting and ending alphanumeric. No `@`, so a handle can never be confused with an email address.
- Unique case-insensitively across the deployment, enforced by a unique index rather than an application check.
- Released handles are tombstoned and never reassigned; only the previous holder can reclaim one.
- At most one change per 30 days per user.
- A short denylist covers role words (`admin`, `root`, `support`, `security`, `postmaster`, …) and the vendor names already denied to self-registered clients.

Forseti never defaults the claim to the user's email. Apps that want an email-derived local username should configure that on their own side (in Forgejo, `[oauth2_client] USERNAME = email`).

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

Forseti keys the audit log and per-IP limiters on the TCP peer unless `[proxy].trust_forwarded_for` is on. With a proxy in front, the peer is the proxy's IP; set `trust_forwarded_for = true` and `trusted_hops` to read the client from `X-Forwarded-For` (see [`[proxy]`](#proxy--reverse-proxy-trust)).

## Secrets management

The following secrets must be unique, long, and protected:

| Secret                                     | Where it lives               | Purpose                                            |
|--------------------------------------------|------------------------------|----------------------------------------------------|
| `hydra.yml: secrets.system`                | Hydra                        | Encrypts everything in Hydra's database.           |
| `hydra.yml: oidc.subject_identifiers.pairwise.salt` | Hydra               | Per-client pairwise subject identifier salt.       |
| `kratos.yml: secrets.cookie`               | Kratos                       | Signs Kratos session cookies.                      |
| `kratos.yml: secrets.cipher`               | Kratos                       | Encrypts sensitive trait values at rest.           |
| OIDC client secrets (per upstream)         | `kratos.yml` env substitution | Authenticate to upstream OIDC providers.          |
| `[security].cookie_secret`                 | Forseti                      | Signs Forseti's cookies. On the native build also encrypts stored TOTP secrets and keys one-time codes, so it must be kept and backed up (see [`cookie_secret` is key material](./operator-guide-native.md#cookie_secret-is-key-material)). |

Recommended pattern: load secrets from environment variables injected by your orchestrator or secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler, 1Password Connect). Do not commit any of the above to a repository.

Generate fresh values with `openssl rand -base64 64` (cookie/session secrets) or `openssl rand -hex 32` (cipher keys requiring 32 bytes).

## Backups

- **Kratos's Postgres database** holds every identity, credential hash, and active session. Restoring it restores user accounts.
- **Hydra's Postgres database** holds OAuth2 client registrations, consent grants, refresh tokens, and the JWKS used to sign id_tokens. Losing the JWKS invalidates every previously-issued id_token's signature.
- **Forseti's own database** holds organizations, the audit log, the webhook outbox, the resource registry, client trust metadata, and POSIX accounts; on the native build also every identity, credential and session. Restore a native database with the same `[security].cookie_secret`, or its stored TOTP secrets stay unreadable. On the default sqlite backend that's `forseti.db` next to the binary: copy it while Forseti is stopped, or use `sqlite3 forseti.db ".backup backup.db"` online (a plain file copy of a live WAL-mode database can be inconsistent). On Postgres, include it in the `pg_dump` routine.
- **Forseti's webhook signing key** (`[webhook].signing_key_path`, default `data/webhook-signing-key.pem`, created `0600`) signs outbound Security Event Tokens. Without a backup, a rebuilt host mints a fresh key and `kid`, and receivers that pinned the old JWKS reject deliveries (see [Rotating the webhook signing key](#rotating-the-webhook-signing-key)).
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
| `/readyz`             | Forseti | Readiness. Returns `ready` (200) when Forseti will serve. If the background webhook worker has been silent for more than 4x `[webhook].tick_seconds` (floor 20s), it still returns 200 but the body reads `ready (degraded: webhook worker stale, ...)`; page serving is unaffected, so a stuck worker does not pull the instance out of rotation. On the native build the identity mail worker is checked the same way (silent for more than 20s: `ready (degraded: mail worker stale, ...)`). Monitor the body (or logs) to catch a stale worker before undelivered webhooks or codes pile up. |
| `/health/alive`       | Kratos  | Liveness.                                              |
| `/health/ready`       | Kratos  | Readiness (checks DB connectivity).                    |
| `/health/alive`       | Hydra   | Liveness.                                              |
| `/health/ready`       | Hydra   | Readiness (checks DB connectivity).                    |

Wire all three readiness probes into your load balancer / orchestrator.

### Metrics

Forseti exposes a Prometheus `/metrics` endpoint on the internal listener (`[internal].bind`) as a commercial feature: it needs a license with the `observability` capability and a configured scrape token, and it 404s otherwise. It serves HTTP RED metrics (request counts, latency, by method/route/status) plus a couple of bridged operational gauges. See [Commercial: Observability](commercial/observability.md) for enabling it, what it exposes, and the scrape config.

Hydra and Kratos expose their own Prometheus metrics on their admin ports, independent of this.

## Common gotchas

Gotchas specific to the Kratos build (cookie domain, CORS, AAL2, return URLs, WebAuthn, registration hooks) are in the Kratos guide's [Common gotchas](./operator-guide-kratos.md#common-gotchas).

### Issuer URL changes

If `urls.self.issuer` in `hydra.yml` ever changes, every previously-issued id_token becomes invalid (it embeds `iss`). Existing OAuth2 clients also discover endpoints via `<issuer>/.well-known/openid-configuration`, so OIDC discovery URLs change as well. Treat the issuer URL as immutable post-launch.

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
| `reserved_names`                  | string[] | (code-baked set) | Org-name denylist (create + rename), case-insensitive/confusable-folded substring match. When absent, falls back to the built-in operator-brand denylist (`src/orgs/reserved_names.rs`). |
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

**`trust_forwarded_for` prerequisite.** The rate limits on `/o/{slug}` and `/registration` are per-IP; behind a proxy they're only meaningful when `[proxy].trust_forwarded_for` is `true` and `trusted_hops` matches your proxy chain (see the [proxy guide](./operator-guide-proxy.md)). Otherwise every caller shares the proxy's address and one bucket — the global bucket (`[auth]`/`[orgs]` `*_global_rate_*`) is the backstop either way.

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

**Prerequisite.** Because the join requires a genuinely verified address, this feature only works if Kratos email verification is enabled and identities are not created pre-verified (the playground default). Social sign-ins through Apple, and through Google with a Gmail or Workspace address, are the deliberate exception — their addresses arrive already verified (see [Which providers' verification Forseti trusts](./operator-guide-kratos.md#which-providers-verification-forseti-trusts)), so a Google Workspace user on a domain your org has proven is eligible for auto-join on first sign-in. If you'd rather every auto-join be backed by a mail round-trip Forseti performed itself, hand-edit those mappers to drop the `verified_addresses` block. Removing a domain stops future auto-join but does not remove members who already joined under it.

### `[identity]` configuration

```toml
[identity]
unverified_ttl_days = 7
privileged_session_minutes = 15
```

- `unverified_ttl_days` — TTL applied by the `unverified-prune` CLI. Identities with at least one unverified verifiable address AND `created_at < now - N days` are deleted. Default `7`. GitHub uses `30`; we run more aggressive because a stuck unverified squatter blocks the legitimate owner. Operators with a slower onboarding flow can dial up.
- `privileged_session_minutes`: how long after sign-in a session may change settings without signing in again. Default `15`. Forseti uses it for the password-page deadline and for the settings pages it gates itself; on the Ory build Kratos enforces its own `selfservice.flows.settings.privileged_session_max_age`, so keep the two equal. On the native build it is the only setting for the window.

The native build reads more keys here (session lifespan, password policy, sign-in throttles, upstream providers); see the native guide's [`[identity]` configuration](./operator-guide-native.md#identity-configuration). The Kratos build reads no other `[identity]` keys; its identity settings live in `kratos.yml` (see [Kratos configuration](./operator-guide-kratos.md#kratos-configuration)).

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

### Deleting an identity

```bash
forseti delete-identity <id>            # asks for confirmation on a terminal
forseti delete-identity <id> --yes      # no prompt; required when stdin is not a terminal
forseti delete-identity <id> --force    # delete a sole organization owner anyway
```

`<id>` is the Kratos identity id (shown on `/admin/identities/{id}`). On a terminal the command prints the identity's verified email and waits for the id or that email to be typed back; a mismatch exits 1 without deleting. Off a terminal (cron, CI, a pipe) the prompt is refused with exit 2 unless `--yes` is given. Exit 0 means the identity is gone; exit 1 means the deletion was refused or failed before the Kratos delete, and the identity is intact.

The command reads the same `config.toml` as the server, runs migrations idempotently, and uses the webhook signing key at `[webhook].signing_key_path`; if the file is missing it generates one and says so, the same as the server does on boot.

Deletion refuses an identity that is the only owner of an organization with other members, for the settings page, the admin page and this command alike. Transfer ownership first, or pass `--force`: the identity is deleted, the organization keeps no owner, and the command prints one `left without an owner: <name>` line per organization (also recorded in the audit row as `orgs_left_without_owner`).

**What deletion removes and what it leaves.** Every entry point (the settings page, `/admin/identities/{id}/delete`, this command, the email-reclaim flow and `unverified-prune`) runs one deletion function, so the outcome is the same regardless of who triggered it:

- Removed: the Kratos identity with its credentials and sessions; Hydra login and consent sessions; organization and team memberships; the POSIX account, SSH keys, offline secret and device sessions; the member profile and username history; linked-provider and SAML link rows; invites addressed to the identity's verified addresses (settings page, admin page and CLI only; reclaim and prune keep them for the address's next owner).
- Left in place: audit rows naming the identity, which age out under `[audit].audit_retention_days`; organizations, teams, hosts, domains, SAML connections, resources and client verifications the identity created or added, with the `created_by`/`added_by`/`verified_by` reference set to NULL so the objects stay usable by their other members.
- Notified, not forced: every OAuth2 client the identity consented to that registered an `account_deletion_url` receives a signed `account-purged` event through the outbox (see [`[webhook]`](#webhook)). Receivers delete their own copy; Forseti never reaches into them.

The output lists what was removed (`removed: ...`) and, when a step after the Kratos delete failed, which steps left rows behind (`left as orphans: ...`). The audit row is `admin.identity.deleted` at critical severity with actor kind `system`, source `delete-identity`, and `reason = cli`.

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
