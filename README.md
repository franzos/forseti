<div align="center">
  <img src="assets/icon.svg" alt="Forseti" width="120" height="120" />

  # Forseti

  **A self-service identity portal for [Ory Kratos](https://www.ory.sh/kratos/) and [Ory Hydra](https://www.ory.sh/hydra/)** — login, registration, account recovery, MFA, OAuth2 consent, and admin tooling, all server-rendered in Rust.

  [![CI](https://github.com/franzos/forseti/actions/workflows/ci.yml/badge.svg)](https://github.com/franzos/forseti/actions/workflows/ci.yml)
  [![Release](https://github.com/franzos/forseti/actions/workflows/release.yml/badge.svg)](https://github.com/franzos/forseti/actions/workflows/release.yml)
  [![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE)
  [![Container](https://img.shields.io/badge/ghcr.io-forseti-097aba?logo=docker&logoColor=white)](https://github.com/franzos/forseti/pkgs/container/forseti)

</div>

Forseti is the web frontend Ory doesn't ship: a single binary that speaks to Kratos (identity) and Hydra (OAuth2/OIDC) and gives your users real screens for every self-service flow, plus an admin surface for operators.

## Download

Prebuilt binaries for x86_64 and aarch64 Linux (glibc) are attached to every [release](https://github.com/franzos/forseti/releases/latest):

```bash
# binary + the static/ assets it serves
curl -L -o forseti.tar.gz https://github.com/franzos/forseti/releases/latest/download/forseti-x86_64-unknown-linux-gnu.tar.gz
tar -xzf forseti.tar.gz
cd forseti-x86_64-unknown-linux-gnu
cp config.example.toml config.toml   # then edit it
./forseti
```

Or pull the [container image](https://github.com/franzos/forseti/pkgs/container/forseti) from the GitHub Container Registry:

```bash
podman pull ghcr.io/franzos/forseti:latest
podman run --rm -p 3000:3000 \
  -v ./config.toml:/app/config.toml:ro \
  ghcr.io/franzos/forseti:latest
```

Both need a reachable Kratos and Hydra — see the [operator guide](docs/operator-guide.md). The binary reads `./config.toml` (override with `FORSETI_CONFIG_PATH`) and serves `./static` relative to its working directory.

> **Runtime note:** the binary links dynamically against `libpq` (the Postgres client). On a bare host install `libpq5` (Debian/Ubuntu) or `libpq` (most other distros); the container image already includes it. SQLite is bundled, so it needs nothing extra.

## Why Forseti

Ory's engines are excellent, but headless. You get APIs; your users need pages. Forseti fills that gap:

- **Every Kratos flow, server-rendered** — login, registration, recovery, verification, settings (profile, password, MFA/TOTP, social logins, sessions)
- **Hydra OAuth2 bridge** — login, consent, and logout screens for the OAuth2/OIDC authorization-code flow
- **Admin surface** — manage identities, sessions, OAuth2 clients; append-only audit log; status dashboard
- **Organizations** — multi-tenant orgs with members, invites, branding, and per-org OIDC claims
- **Production-minded** — CSRF on every form, signed cookies, rate-limited DCR, account-deletion webhook saga

## Status

**Pre-release / active development.** Core flows work end-to-end against the Ory playground; APIs, config, and schema are still moving. Pin a commit if you build on it.

## Build from source

```bash
# 1. Bring up the playground (Kratos, Hydra, Mailcrab, Postgres)
make stack-up

# 2. Seed a deterministic admin (password + TOTP)
make seed-admin

# 3. Run Forseti (debug build) at :3000
make run
```

Open <http://localhost:3000>. Register at `/registration`, grab the verification email from Mailcrab at <http://127.0.0.1:4436>, and you're in.

For the full OAuth2 dance — register a Hydra client, run an auth-code flow, exchange a token — see [`.claude/skills/ory-up/SKILL.md`](.claude/skills/ory-up/SKILL.md) or the [integration guide](docs/integration-guide.md).

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
   +------------+ +------------+             | Kratos admin   |
   |  Kratos    | |   Hydra    |             | Hydra admin    |
   |  public    | |  public    |             | (internal only)|
   +------------+ +------------+             +-----------------+
         |             |
         +------+------+
                |
                v
         +--------------+
         |  Database    |
         | Postgres /   |
         |   SQLite     |
         +--------------+
```

## Documentation

- [Operator guide](docs/operator-guide.md) — deployment topology, Kratos/Hydra config, secrets, backups
- [Operator guide — reverse proxy](docs/operator-guide-proxy.md) — proxy topology, cookies, CSRF, CORS
- [Integration guide](docs/integration-guide.md) — consuming Forseti as an OIDC provider
- [Commercial features](docs/commercial/) — licensing model, plus the [Organizations](docs/commercial/organizations.md) and [Enterprise SAML SSO](docs/commercial/saml.md) guides

## License

Forseti is dual-licensed:

- **AGPL-3.0** for the open-source core (everything outside `src/commercial/`)
- **Commercial license** for paid features in `src/commercial/` (see [`MONETIZATION.md`](MONETIZATION.md) and [`LICENSE-COMMERCIAL`](LICENSE-COMMERCIAL))

Built on [Ory Kratos](https://www.ory.sh/kratos/) and [Ory Hydra](https://www.ory.sh/hydra/).

---

Forseti — named for the Norse god of justice and reconciliation.
