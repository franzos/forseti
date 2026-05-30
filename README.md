# Forseti

A self-service UI and OAuth2 login/consent/logout bridge for Ory Kratos + Ory Hydra, written in Rust. Deploy at `accounts.example.com`, theme it via config, drop the bundled `kratos-selfservice-ui-node`.

> License: AGPL-3.0-or-later for the OSS core; `src/commercial/` is proprietary, source-available under the Forseti Commercial License 1.0. See [License](#license).

## What this is

Forseti is the UI layer that sits in front of an Ory stack. It renders Kratos's self-service flows — login, registration, recovery, verification, settings — and implements the three handlers Hydra delegates to the IdP: `/oauth/login`, `/oauth/consent`, `/oauth/logout`. It's Rust + Axum + Askama, server-side HTML with only a sprinkle of inline JS where a flow needs it (WebAuthn/passkey), no Node toolchain at deploy time. Tailwind CSS is precompiled via the standalone CLI; the result is a single static binary plus a `static/` directory.

It's method-agnostic — Forseti renders whatever node groups Kratos serves (`password`, `code`, `oidc`, `totp`, `lookup_secret`, `webauthn`, `passkey`). Branding is config-driven; there are no hardcoded organization names. The repo also doubles as a working Kratos + Hydra playground under `infra/docker-compose.yml`, which the [integration test suite](tests/README.md) drives against.

On top of the Kratos/Hydra core, Forseti adds:

- **Organizations** — multi-org memberships, invites, branding, role-based access, with `org` / `orgs` claims surfaced to downstream apps.
- **Member profiles** — opt-in extended profile (avatar, website, bio, pronouns, links) and a public `/users/{id}` view, with `extended_profile` scope.
- **Handoff** — `/handoff?referrer=…&action=…` deep-link from downstream apps into Forseti self-service, with a "Return to <app>" banner.
- **Account-deletion webhooks** — RISC `account-purged` Security Event Tokens (RFC 8417) signed and delivered via an outbox saga with retries.
- **Dynamic Client Registration** — anonymous RFC 7591 self-registration, optional Initial Access Tokens for attribution, reserved-name denylist, and a Forseti-owned verification badge that gates the consent-screen caution banner.
- **MCP-server preset** — admin client form preconfigured for Model Context Protocol resource servers (public client, PKCE, audience allow-list).
- **License gate** — Ed25519-signed offline license unlocks paid features on top of the AGPL OSS core. See [License](#license).

## What this isn't

- Not the OAuth2 server (that's Hydra) or the identity store (that's Kratos) — it's the UI layer in front of both.
- Not a turnkey hosted service — you run it yourself.
- Not fully permissive OSS — the core is AGPL-3.0-or-later, and `src/commercial/` is proprietary source-available; running Forseti as a hosted service for third parties needs a separate commercial arrangement.
- The admin surface (clients, identities, sessions, audit, status) is gated behind a session + AAL2 + email-allowlist check; granular RBAC is out of scope.
- No metrics endpoint on Forseti itself; rely on log-derived metrics and the Kratos/Hydra Prometheus surface.

## Try it

The fastest path is the bundled `ory-up` skill if you're driving via Claude Code — it brings the stack up, registers a client, and walks you through a token exchange. The manual path works fine without it:

```bash
# 1. Playground: Kratos, Hydra, Mailcrab, Postgres.
podman-compose -f infra/docker-compose.yml up -d
# or: docker compose -f infra/docker-compose.yml up -d

# 2. Forseti config — copy the example, adjust if you like.
cp config.example.toml config.toml

# 3. Run Forseti at :3000 (Tailwind --watch + cargo run, in parallel).
make dev
```

Forseti listens at `http://localhost:3000` (binds `0.0.0.0:3000`). `/healthz` returns `ok`. Mailcrab catches verification and recovery emails at `http://127.0.0.1:4436`.

From there, register at `/registration`, verify the email out of Mailcrab, and you're signed in. For the full OAuth2 dance — register a Hydra client, run an auth-code flow, exchange a token — see [`.claude/skills/ory-up/SKILL.md`](.claude/skills/ory-up/SKILL.md) or the [integration guide](docs/integration-guide.md).

## Docs

- [`docs/operator-guide.md`](docs/operator-guide.md) — deployment topology, `kratos.yml` / `hydra.yml` configuration, secrets, backups, gotchas.
- [`docs/operator-guide-proxy.md`](docs/operator-guide-proxy.md) — reverse-proxy topology (path-prefixed vs subdomain), cookie / CSRF / CORS implications, haproxy sketches.
- [`docs/integration-guide.md`](docs/integration-guide.md) — for downstream app developers consuming Forseti as an OIDC Provider.

## How it fits together

```
      Browser
         |
         v
+------------------+        admin (server-only)
|     Forseti      | --------------------------------+
|   Rust / Axum    |                                 |
|       :3000      | --+                             |
+------------------+   |                             |
         |             |                             |
         | browser     | browser                     |
         |             |                             v
         v             v                    +-----------------+
   +------------+ +------------+             | Kratos admin   |
   | Kratos pub | | Hydra pub  |             | Hydra admin    |
   |   :4433    | |   :4444    |             | (internal only)|
   +------------+ +------------+             +-----------------+
```

The browser hits Forseti and the Kratos/Hydra **public** APIs directly. Forseti calls the Kratos/Hydra **admin** APIs server-side over a private network. Cookies share a parent domain (e.g. `.example.com`) so the browser carries Kratos's session cookie to both Forseti and Kratos's public endpoint.

A more detailed deployment topology — reverse proxy, TLS, ports — is in the [operator guide](docs/operator-guide.md#deployment-topology).

## Build & run

| Target           | What it does                                             |
|------------------|----------------------------------------------------------|
| `make dev`       | `cargo run` + Tailwind `--watch`, in parallel            |
| `make build`     | Compile CSS, then `cargo build --release --locked`       |
| `make check`     | `cargo check` + `cargo clippy -D warnings`               |
| `make css`       | Build `static/styles.css` once, minified                 |

GUIX note: the standalone Tailwind binary is dynamically linked against glibc + libgcc_s. The `Makefile` wraps each Tailwind invocation in `guix shell glibc gcc-toolchain` so it's transparent on GUIX; on other systems the wrapper is a no-op. Details on packaging, environment variables, and reverse-proxy setup are in the [operator guide](docs/operator-guide.md).

## Tests

Two suites run against a live playground:

- **Rust integration** (`tests/`) — HTTP + DB assertions covering login, registration, recovery, verification, logout, settings, the OAuth2 auth-code flow, DCR, account deletion, and the admin surface.
- **Playwright E2E** (`tests/e2e/`) — browser-driven scenarios for the flows where cross-origin cookies, redirect chains, or rendered DOM are the actual bug surface. Runs inside Microsoft's Playwright image — no host-side Node.

```bash
make stack-up          # Kratos + Hydra + Mailcrab + Postgres, blocks until ready
make seed-admin        # plant a deterministic admin (password + TOTP) for the admin-gated tests
make run               # Forseti at :3000
make test-integration  # Rust suite (serial — shares live Kratos/Hydra state)
make e2e               # Playwright (unlicensed bucket)
make stack-down        # wipe volumes + the sqlite DB (clean slate)
```

`make test-integration` is serial (`--test-threads=1`) because the suite shares live Kratos/Hydra state; re-runs stay clean because every test uses a unique-per-run email. The admin-gated tests need `make seed-admin` first — Kratos can't import TOTP, so the seed creates the identity and plants the credential directly. CI runs `make check` plus both suites against fresh volumes on every push — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Full details in [`tests/README.md`](tests/README.md) and [`tests/e2e/README.md`](tests/e2e/README.md).

## Contributing

Contributions to the AGPL-licensed core (everything outside `src/commercial/`) are welcome under the [Developer Certificate of Origin](https://developercertificate.org/) — sign off every commit with `git commit -s`. The proprietary `src/commercial/` subtree doesn't take external contributions under the DCO alone, because the DCO doesn't grant relicensing rights into that license. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full version.

Security issues: please email mail@gofranz.com rather than opening a public issue.

## License

Forseti is dual-licensed:

- **Everything outside `src/commercial/`** — [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later). You can use, modify, self-host, and redistribute the core freely. If you run a modified version as a network service, you must offer your users the corresponding source.
- **`src/commercial/`** — [Forseti Commercial License 1.0](LICENSE-COMMERCIAL), a proprietary source-available license. You can read, audit, and use the commercial features for development, evaluation, and personal hobbyist use without a license key. Production use requires a valid Ed25519-signed Commercial License Key, loaded at runtime via `/admin/license`. Operating Forseti as a hosted service for third parties requires a separate written agreement.

In practice: hobbyists and home users run the full thing for free; businesses running Forseti in production buy a commercial license key for the paid features; anyone wanting to resell Forseti as SaaS talks to me first. The Ed25519 verification path lives in `src/commercial/verify.rs` and the public key is baked in at build time from `src/commercial/pubkey.bin` — no phone-home.

To request a commercial license key or discuss a SaaS arrangement, contact mail@gofranz.com.

## Acknowledgements

Ory for [Kratos](https://github.com/ory/kratos), [Hydra](https://github.com/ory/hydra), and their design system. The directional visual mockups that guided the initial UI were generated with Google Stitch.
