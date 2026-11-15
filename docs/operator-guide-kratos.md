# Kratos identity backend

For operators running the Kratos build (`identity-ory`, the default and the one the release artifacts carry). It covers what only that build needs: `[kratos]`, the Kratos audit webhook, 2FA enforcement in `kratos.yml`, the `forseti config` tooling, Kratos's own configuration and courier, and the Kratos-specific gotchas. Everything both builds share is in the [operator guide](./operator-guide.md); the build without Kratos has its own guide, [Native identity backend](./operator-guide-native.md).

## `[kratos]`

Ory build only; the native build does not read this section.

| Key          | Type   | Default | Description                                                                                          |
|--------------|--------|---------|------------------------------------------------------------------------------------------------------|
| `public_url` | string | —       | Browser-facing Kratos URL. Forseti redirects users here to initialize flows and proxies cookies. |
| `admin_url`  | string | —       | Server-only Kratos admin URL. Used for identity reads, session enumeration, session revocation.     |

## Audit logging

The Kratos flow webhooks reach Forseti's audit log through `POST /internal/audit/kratos` on the internal listener. The audit log itself, the internal listener and retention are in the operator guide's [Audit logging](./operator-guide.md#audit-logging).

### Audit webhook bearer

The `POST /internal/audit/kratos` endpoint authenticates inbound Kratos webhooks with a shared bearer token (`Authorization: Bearer <token>`). Forseti reads it from `[audit].webhook_token`; Kratos sends it from the `auth.config.value` field on each `web_hook` in `kratos.yml`.

This receiver and `[audit].webhook_token` exist on the Ory build only; the native build writes flow audit rows directly and does not read the token.

**The token is mandatory on the Ory build.** Forseti refuses to boot when `webhook_token` is empty (exit code `1`, error on stderr): a misconfigured deployment is supposed to fail loudly at startup rather than silently accept or reject every inbound event.

**Every entry must be at least 32 bytes** (`openssl rand -hex 32`). On a production-shaped `[self].url` (https, not localhost or a private address) Forseti refuses to boot when any accept-list entry is shorter; elsewhere it logs a warning. `forseti config check` reports the same rule as `audit.webhook_token.length`. To replace an existing short token on production, run `forseti config rotate webhook-token --yes` (the interactive form asks for a Forseti restart while the short entry is still staged, and that restart is refused), then `forseti config prune webhook-token` to drop the short entry, then restart Kratos and Forseti. Webhooks carrying the new token return 401 until the Forseti restart.

**To rotate, use `forseti config rotate webhook-token`** (see [Rotating the audit webhook token](#rotating-the-audit-webhook-token)) rather than hand-editing both files: it stages the new token in an accept-list so Forseti keeps accepting the old one until every `web_hook` has picked up the new value, avoiding an audit-loss window. Hand-editing both files in one shot works too, but there's no online-rotation path that way. Kratos's Viper-based config loader does not support env-var overrides for fields inside arrays (see [ory/kratos#2663](https://github.com/ory/kratos/issues/2663)), so the token has to be a literal value in `kratos.yml`, and stopping Forseti before both files agree drops every webhook delivered in between. For real production deploys, template the config through your deploy tooling (Helm's `values.yaml`, Terraform, or equivalent) and source the token from your secret manager. Forseti-side value comes from `config.toml` (or `FORSETI_AUDIT__WEBHOOK_TOKEN`), where env-var binding works because Forseti's config is a flat struct.

### Audit webhook replay protection

Bearer alone lets anyone who captures a single request replay it arbitrarily later — fabricating audit history. The real guard is the internal listener plus the bearer; on top of that the receiver adds a freshness signal:

**Freshness window.** The shared `audit_event.jsonnet` template emits `ctx.flow.issued_at` (RFC 3339) into the body. The receiver flags payloads whose `issued_at` is more than 1 hour old (`stale`) or skewed more than 1 minute into the future (`future`). The window covers the longest Kratos flow lifespan (settings flows default to 1h), so a stale reading means a genuinely old timestamp — replay or clock skew — not a slow user. Flagged payloads are **still recorded**, with a `metadata.freshness` marker, and counted on `/admin/status` (see below). Payloads missing `issued_at` are written unflagged — older Kratos versions omit the field on some hooks. The window is telemetry, not a hard reject: see the response-code note below for why the receiver never drops a parseable payload.

**Responses.** The receiver returns **401** on a missing/wrong bearer and **204** on everything else — accepted, flagged, malformed body, or unknown action. The hooks are fire-and-forget on the Kratos side (`response.ignore: true`), so Kratos never reads the status; the 401/204-only scheme is defence in depth so the receiver can't break a user's self-service flow even if a future Kratos config regresses to a blocking hook. Failures surface out-of-band on `/admin/status` and in `warn!` logs.

**Threat model: what this catches and what it doesn't.** Stripe / GitHub webhook signing computes an HMAC over the body with a shared secret, which catches both replay and tampering. Kratos's `web_hook` action ships static headers only: it can't compute an HMAC at send time. So the bearer + freshness flag is the realistic ceiling without a signing proxy. If your threat model includes a real-time MITM, terminate Kratos behind a reverse proxy that injects an HMAC header (haproxy + lua, nginx + lua, envoy + wasm) and check it in front of Forseti.

### Audit webhook counters on `/admin/status`

Two in-process counters surface the receiver's out-of-band failure signal. Both reset on Forseti restart — they answer "did anything odd happen since the last boot?", not "what is the all-time total". Non-zero values render a hint on the status page.

- **Audit webhook rejected.** A payload was dropped before any row was written — either a malformed body or an unknown `?action=`. A non-zero count almost always means a Kratos hook or config mismatch (e.g. an `action` not in the receiver's vocabulary, or a template that emits a body the receiver can't parse). Check the `kratos audit webhook` `warn!` log lines for the specifics.
- **Audit webhook freshness anomalies.** A row was written but its `issued_at` fell outside the 1h freshness window — stamped `stale` or `future` in `metadata.freshness`. Usually a slow flow finished after the window or the Kratos / Forseti clocks have drifted. The row is still recorded; the counter is a heads-up to check for clock skew (or, rarely, replay).

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

Ory build only: the native build has no `forseti config` verbs (including `config-check` and `config-init`), since its identity settings live in `config.toml` under `[identity]`.

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

The generated files carry no comments — `config-init` and the other `config` subcommands round-trip these files through a YAML parser, which would silently drop any comments on the next parse/write, so keeping prose in the file would be misleading. See [Configuration rationale](#configuration-rationale) for why each baked-in recommendation is set the way it is. After writing, run the linter over what it produced to confirm the round-trip:

> **`--force` is a full regeneration, not a merge.** Re-running `config-init --force` against an existing `kratos.yml`/`hydra.yml` does not patch the file: it renders a brand-new pair from scratch, with fresh CSPRNG secrets throughout (cookie/cipher/system secrets, and Hydra's pairwise salt). Any OIDC providers you'd enabled with `forseti config oidc enable`, any flow hooks, and any rotation history (accept-lists from a prior `config rotate webhook-token`, multi-entry secret lists) are gone, overwritten with the from-scratch template. Only reach for `--force` on a config you're deliberately starting over; otherwise use the targeted `forseti config` subcommands below to change one thing at a time.

```bash
forseti config-init ... --kratos-out kratos.yml --hydra-out hydra.yml
forseti config-check --kratos kratos.yml --hydra hydra.yml   # should be 0 FAIL, 0 WARN
```

A note on the generated secrets: they're embedded directly in the files and grant full session/token control, so treat the output the way you'd treat any secret material — review it, lock down the file permissions, and don't commit it.

## Configuration rationale

Why `config-init`'s baked-in recommendations are set the way they are. This used to live as inline comments in the generated `kratos.yml` / `hydra.yml`, but those files are CLI-owned artifacts that round-trip through a YAML parser on every later `config` subcommand, which drops comments on write — so the prose moved here instead.

**Kratos `session.whoami.required_aal: highest_available`.** `highest_available` forces any identity with a second factor enrolled to complete AAL2 before `whoami` returns a session — Kratos answers 403, which Forseti maps to a `/login?aal=aal2` step-up. Settings also requires AAL2 (see below) so an AAL1 session (password-only login, or an email-recovery session) can't strip a second factor and defeat 2FA. Lost-device users step up with a `lookup_secret` recovery code (which satisfies AAL2) to manage their factors.

**Kratos `selfservice.methods.webauthn.config.passwordless: false`.** This keeps WebAuthn as a second factor (AAL2). Flipping it to `true` makes it a first-factor login and it will not satisfy the AAL2 step-up.

**Kratos `selfservice.flows.settings.required_aal: highest_available`.** AAL2 is required for settings changes once the identity has a second factor. Otherwise an AAL1 session (password-only login, or an email-recovery session) could open the settings flow and remove the second factor, defeating 2FA entirely. With enforcement on, the user is already AAL2 by the time they reach settings (they stepped up at login), so this adds no extra prompt for normal use — it only blocks an un-stepped-up session from touching credentials.

**Hydra `urls.self.issuer`.** The issuer must be reachable under the same hostname from both the browser and any resource servers so the `iss` claim in id_tokens validates everywhere.

**Hydra `oidc.dynamic_client_registration: enabled: false`.** Dynamic Client Registration (RFC 7591) is retired: no anonymous registration surface, no `registration_endpoint` anywhere, and Hydra's RFC 7592 `/oauth2/register/{id}` management endpoints die with it. MCP clients self-identify via [CIMD](./operator-guide.md#cimd-zero-config-client-onboarding) instead; everything else is pre-registered through the admin UI. Do not set `webfinger.oidc_discovery.client_registration_url` either.

**Hydra `oauth2.pkce.enforced_for_public_clients: true`.** MCP 2025-06-18 requires PKCE with S256 for public clients.

**Hydra `strategies.access_token: jwt`.** Access tokens are JWTs by default. Resource servers validate locally against Hydra's JWKS. Flip to `opaque` if you need immediate revocation (and route every RS to the admin API on `:4445`).

**Hydra `strategies.scope: exact`.** Hydra's default `wildcard` strategy lets a `*` entry on a client's scope match every dot-free scope, so one stray `*` on a client turns its ceiling into "anything". RFC 6749 scopes are opaque strings with no wildcard semantics. Forseti drops `*` tokens before they reach a CIMD client, and `forseti config check` warns when `strategies.scope` isn't `exact`.

## Managing configuration with forseti config

Ory build only, like the rest of the `config` surface.

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
| `forseti config oidc enable apple --client-id <services-id> --apple-team-id <id> --apple-key-id <id> (--apple-private-key-env/-file/-stdin) [--keep-mapper]` | Add/replace Sign in with Apple |
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

`forseti config oidc enable <provider> --client-id <id> --client-secret-env <VAR>` writes the provider block into `kratos.yml` (literal `client_id`/`client_secret`: see the `${VAR}` note under [Kratos configuration → oidc](#oidc) above) and drops a reviewed mapper jsonnet next to it. Every pinned mapper gates the `email` trait on `claims.email_verified`; Apple, and Google for Gmail and Workspace addresses, additionally carry that verification into Kratos, so those users skip Forseti's own verification mail (see [Which providers' verification Forseti trusts](#which-providers-verification-forseti-trusts) below). The secret can come from an env var, a file, stdin, or (interactively) a masked prompt: never a bare CLI argument, so it doesn't end up in shell history or `ps`. Microsoft requires `--microsoft-tenant <tenant-id>`; the `common`, `organizations`, and `consumers` pseudo-tenants are all refused (the nOAuth account-takeover class, see the note above).

Apple is the exception to the client-secret shape. Apple issues no static secret: Kratos mints one per handshake as a JWT signed with the `.p8` key from the Apple Developer portal, so `enable apple` takes `--apple-team-id`, `--apple-key-id`, and the key itself through its own `--apple-private-key-env/-file/-stdin` group (no masked-prompt fallback: a PEM doesn't survive a single-line read). `--client-secret-*` is refused for Apple, and the `--apple-*` flags are refused for everyone else. The key lands in `kratos.yml` as a literal PEM block, and the diff `enable` prints redacts it line by line. `config check` knows the difference too: it lints Apple's three key fields instead of demanding a `client_secret`, and warns if a stale one is left behind.

If the target mapper file already exists with content that doesn't match Forseti's pinned body, `enable` refuses and asks for `--keep-mapper` to proceed without touching it: it won't silently clobber a mapper you've customized. A mapper Forseti itself shipped in an earlier release isn't treated as customized: `config check` reports it as out of date, and `enable` replaces it. The current pinned bodies also map the provider's `given_name`/`family_name` onto `traits.name`, so sign-up through a provider prefills the name.

**The audit gap.** `config init`-generated `kratos.yml` files carry no audit `web_hook` nodes at all (see [Audit logging](./operator-guide.md#audit-logging): the reference playground has them, a from-scratch `config init` doesn't). `oidc enable` looks for an existing `web_hook` template on another flow to clone onto the OIDC login/registration flows; when it finds none, it still enables the provider but prints a loud warning that OIDC sign-ins won't reach the audit log until a webhook is wired up by hand. This is a known, documented gap, not a bug: wiring one up requires an audit-endpoint URL and bearer token that only the operator knows.

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

`config.toml`/`kratos.yml`/`hydra.yml` are frequently git-tracked (the playground reference files are). Writes to `kratos.yml`, `hydra.yml`, and `config.toml` through the guarded write pipelines warn when the target is under git and remind you to gitignore the backups: add `*.bak.*` to `.gitignore` so a rotation doesn't litter the repo with secret-bearing backup files. (`config restore` does not trigger this warning.)

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

Upstream OIDC providers (Google, GitHub, Microsoft, Apple). Operators register one OAuth app per provider on the provider's side; Forseti's `forseti config oidc enable` writes the client credentials into `kratos.yml` and renders one "Sign in with X" button per configured provider. See [Managing configuration with forseti config](#managing-configuration-with-forseti-config) below: that's the supported path for adding a provider; the manual YAML shape here is for reference (e.g. reading an existing `kratos.yml`) or for providers the CLI doesn't cover yet.

**`${VAR}` is not interpolated.** Kratos does **not** expand `${VAR}`-style environment references anywhere in `kratos.yml`: that's a common assumption carried over from tools like Docker Compose or Helm, but Kratos's own config loader has no such substitution step (confirmed against the upstream config loader; there's no `${...}` expansion pass on the parsed YAML). Every value, including `client_id` and `client_secret`, must be the literal string Kratos will use. `forseti config oidc enable` writes secrets in literal, plaintext form (redacted only in this CLI's own diff output) for exactly this reason. If you want secrets sourced from the environment at *deploy* time rather than baked into the file, template `kratos.yml` through your deploy tooling (Helm, Terraform, a `sops`/`envsubst` pre-render step) before Kratos ever reads it. Kratos itself never does that substitution.

Worked example for Google, via the CLI:

1. Go to <https://console.cloud.google.com/apis/credentials> and create an OAuth 2.0 Client ID.
2. Authorized redirect URI: `https://accounts.example.com/self-service/methods/oidc/callback/google`. Substitute `accounts.example.com` for your Kratos public hostname: the path is fixed by Kratos.
3. Capture the client ID and client secret.
4. `forseti config oidc enable google --client-id <id> --client-secret-env GOOGLE_CLIENT_SECRET` (export the secret into that env var first, or use `--client-secret-file`/`--client-secret-stdin`; omit the flag entirely and the CLI prompts, masked, on a TTY). This writes the `providers` entry into `kratos.yml` and drops the reviewed mapper jsonnet next to it.

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
```

The mapper CLI-writes at `oidc.google.jsonnet` gates the `email` trait on `claims.email_verified`: copying `email` without that gate is an account-takeover vector (anyone who controls an unverified alias at the provider could claim the matching Forseti account). Don't hand-edit the mapper unless you understand that invariant; `forseti config check` warns if a provider's mapper doesn't match Forseti's reviewed pinned body.

Note the leading `local claims = { email_verified: false } + std.extVar('claims');` on every pinned body. Kratos serializes the claim with `omitempty`, so an upstream `false` reaches the mapper as a *missing* field, and jsonnet raises `Field does not exist: email_verified` rather than treating it as false. Without the default, an unverified upstream address fails the sign-in outright instead of falling through to Forseti's own verification flow.

**Custom providers need `[security].extra_form_action`.** A provider button, and the `idp_hint` hand-off page, POST the Kratos form, and Kratos answers with a redirect to the provider. The browser enforces `form-action` across that redirect, and Forseti only knows the origins of the four providers `forseti config oidc enable` supports. For any other provider id in `kratos.yml`, add its authorization origin (for example `extra_form_action = ["https://idp.example.com"]`), or the button does nothing and the hand-off page stays where it is.

Every enabled provider is also listed in Forseti's OpenID discovery as `idp_hints_supported`, so relying parties can render their own "Continue with X" buttons and send `idp_hint=<id>` (see the integration guide). Forseti reads the list off a Kratos login flow and caches it for an hour, so a newly enabled provider shows up in discovery within that window.

#### Which providers' verification Forseti trusts

Apple's mapper, and Google's for Gmail and Workspace addresses, also emit `identity.verified_addresses`, which Kratos honours at identity-creation time: an address the provider marked verified is stored as an already-verified Kratos address, so the user never receives Forseti's verification mail and is immediately eligible for verified-only features (org invites, verified-domain auto-join). GitHub's and Microsoft's mappers deliberately don't, so their users verify through Forseti's own flow.

The split is not about how strong each provider's verification is, it's about what the claim is bound to:

- **Google** — Google is authoritative for Gmail (its own namespace) and for Workspace accounts, which carry the `hd` claim: a Workspace admin can only assert addresses in domains their tenant owns, and Google enforces domain uniqueness across tenants. A consumer Google account can also sit on a third-party address (Yahoo, a company domain without Workspace); Google verified that once at signup and never re-checks it, so it says nothing about who controls the mailbox now. The pinned mapper therefore carries verification over only when the address ends in `@gmail.com` or `hd` is present, which is the line [Google's own guidance](https://developers.google.com/identity/openid-connect/openid-connect) draws. Any other verified Google address still becomes the `email` trait, but goes through Forseti's verification mail.
- **Apple** — Apple verifies the address at Apple ID creation, and operates the Hide My Email relay addresses itself. Carrying this over also avoids a dead end: relay addresses only accept mail from outbound domains you registered with Apple, so without the carry-over a Hide My Email user on a deployment that hasn't done that registration can never verify at all.
- **GitHub** — GitHub does verify addresses by confirmation link, and Kratos reads that flag straight off the account's primary address. But GitHub isn't an OIDC provider here (Kratos synthesizes `email_verified` from a REST field), nothing binds it to OIDC's semantics for that claim, and an address released from one account can later be verified on another.
- **Microsoft** — Entra ID issues no `email_verified` claim at all. Its equivalent is the `xms_edov` optional claim, which Kratos doesn't read. Entra's `email` is a mutable directory attribute a tenant admin can point at any address, which is why the pseudo-tenants are refused; even inside a pinned tenant, the claim carries no proof of mailbox control.

This is a deliberately conservative default rather than a ceiling. If your deployment federates only with a corporate IdP you have a contractual relationship with, carrying its verification over is defensible — but that's an operator decision, made by hand-editing the mapper and accepting the `config check` warning, not something `oidc enable` will do for you.

Carry-over applies at identity creation only. It does nothing for identities that already exist, so upgrading doesn't retroactively verify anyone, and it doesn't affect account linking (Kratos rejects a social sign-in whose email collides with an existing identity, rather than merging).

Apple is the one provider that doesn't fit that shape. Worked example:

1. In the [Apple Developer portal](https://developer.apple.com/account/resources/identifiers/list), enable **Sign in with Apple** on an App ID.
2. Create a **Services ID**. That string (e.g. `com.example.accounts.service`) is the `client_id` — not the Team ID, not the Bundle ID.
3. Configure the Services ID's domain and return URL: `https://accounts.example.com/self-service/methods/oidc/callback/apple`. Apple rejects `localhost` and plain HTTP, so testing against a dev box needs a tunnel on a domain registered here.
4. Create a **Sign in with Apple** key, download the `.p8` (Apple lets you download it once), and note the Key ID and your Team ID.
5. `forseti config oidc enable apple --client-id com.example.accounts.service --apple-team-id ABCDE12345 --apple-key-id XYZ9876543 --apple-private-key-file ./AuthKey_XYZ9876543.p8`

```yaml
selfservice:
  methods:
    oidc:
      enabled: true
      config:
        providers:
          - id: apple
            provider: apple
            client_id: com.example.accounts.service
            mapper_url: file:///etc/config/kratos/oidc.apple.jsonnet
            scope: [email]
            apple_team_id: ABCDE12345
            apple_private_key_id: XYZ9876543
            apple_private_key: |-
              -----BEGIN PRIVATE KEY-----
              ...contents of the .p8...
              -----END PRIVATE KEY-----
            issuer_url: https://appleid.apple.com
```

No `client_secret`: Kratos signs one per handshake from those three fields. The provider id must stay `apple` — Apple replies with `response_mode=form_post`, and Kratos only exempts that callback path from CSRF for the `apple` id. Apple's pinned mapper has the same `email_verified` gate as Google's and carries Apple's verification into Kratos for every address, without Google's Gmail/Workspace restriction. Two behaviours worth telling your support desk about: users who pick "Hide My Email" arrive at a relay address (`@privaterelay.appleid.com` or `@icloud.com` — check the `is_private_email` claim rather than sniffing the domain) that breaks if they later revoke the app, and Apple only sends the *name* claim on the very first authorization. The email claim does arrive on every sign-in.

GitHub and Microsoft (Azure AD) follow the same `forseti config oidc enable <github|microsoft>` shape, with the gate but not the carry-over. GitHub only returns an email when the `user:email` scope is granted, and Kratos reads the verified flag off the account's primary address rather than an id_token claim — an account whose primary is unverified arrives with no email at all and is asked for one during registration. Microsoft requires `--microsoft-tenant <tenant-id>`: `common`, `organizations`, and `consumers` are all refused outright, since each admits tenants you don't control and opens the [nOAuth](https://www.descope.com/blog/post/noauth) account-takeover class where an attacker edits their own account's email in a tenant Microsoft doesn't verify. Note that Entra issues no `email_verified` claim in the first place, so Microsoft users always register their email through Forseti and verify it there.

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

## SMTP

Kratos's courier sends the self-service mail. The Forseti mailer, which sends org invites and claim-email codes, is in the operator guide's [SMTP](./operator-guide.md#smtp).

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

## Common gotchas

Gotchas that apply to both builds, such as issuer URL changes, are in the operator guide's [Common gotchas](./operator-guide.md#common-gotchas).

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
