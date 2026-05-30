# Integration tests

Rust integration suite under `tests/integration/`, driven via `reqwest`
against the running playground stack. **Tests do NOT spin the playground
up themselves** — bring it up in another terminal first.

## Prerequisites

```sh
# Bring up Kratos + Hydra + Mailcrab + Postgres and block until ready.
make stack-up                             # podman-compose under the hood

# Start the portal at :3000.
make run                                  # or: cargo run
```

`make stack-up` polls the Kratos/Hydra readiness endpoints before returning,
so the suite never races the stack. Verify the portal with
`curl http://127.0.0.1:3000/healthz` → `ok`.

## Run

```sh
make test-integration                     # cargo test --test integration -- --test-threads=1
```

`--test-threads=1` is REQUIRED. The tests share live Kratos / Hydra /
Mailcrab state — running concurrently produces non-deterministic failures
(email inbox contention, recovery code mix-ups, recovery flows reused across
identities, …). Every test still uses a unique nanosecond-timestamp prefix
in its email addresses to avoid colliding with stale state from earlier runs.

The admin happy-path tests are gated on `FORSETI_ADMIN_TEST_*` and skip when
unset (`common.rs:686`). To run them, plant an admin first:

```sh
make seed-admin                           # prints the FORSETI_ADMIN_TEST_* exports
```

`seed-admin` creates the identity via the Kratos admin API and inserts a TOTP
credential straight into Kratos's Postgres (its import API can't take TOTP).
The seeded `admin@example.com` must be in Forseti's `[admin].allowed_emails`.

## Layout

| File                                  | Coverage                                              |
|---------------------------------------|-------------------------------------------------------|
| `integration.rs`                      | Test-binary entry; loads the module tree              |
| `integration/common.rs`               | Helpers: HTTP clients, identity factory, Mailcrab, Hydra admin |
| `integration/login.rs`                | `/login` happy paths                                  |
| `integration/registration.rs`         | Two-step registration → signed-in dashboard           |
| `integration/recovery.rs`             | Email → 6-digit code → `/settings/password`           |
| `integration/verification.rs`         | Verification code flips `verified=true`               |
| `integration/logout.rs`               | CSRF + session teardown                               |
| `integration/settings.rs`             | Auth gating + rendering for each sub-page             |
| `integration/oauth.rs`                | Authorization-code flow with reduced scope            |
| `integration/dcr.rs`                  | DCR (RFC 7591) + MCP chain: IAT mint, register, PKCE auth-code, fake MCP introspection, refresh rotation; C1 + M1 regression coverage |
| `integration/regressions.rs`          | Bugs already fixed: AAL2, refresh=true, recovery hand-off, sub-page dispatcher, login flow-ID short-circuit, consent checkboxes |

## Cleaning up

The suite re-runs cleanly without manual cleanup because every test uses a
unique nanosecond-prefixed email, so stale identities never collide. Per-test
teardown (Kratos admin `DELETE`, Hydra client delete) is best-effort and is
skipped when a test panics, so failed runs leave stragglers behind. They're
harmless, but to get a true clean slate — volumes + the sqlite DB — run:

```sh
make stack-down        # podman-compose down -v + rm -f forseti.db
# or, to wipe and bring straight back up:
make stack-reset
```

CI leans on this: every pipeline run starts from `stack-up` on fresh volumes,
so accumulation never matters there.
