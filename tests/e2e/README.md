# tests/e2e

Playwright browser e2e for the Forseti stack. Runs inside Microsoft's
official Playwright Docker image (Chromium + every system library
pre-bundled), so the host stays clean of Node + browser dependencies — a
hard requirement on GUIX where dynamic-linked browser binaries don't see
the FHS paths they expect.

## Scope

Seven scenarios, chosen to complement (not duplicate) the Rust integration
suite in `tests/integration/`:

| File | What it covers | Why a browser is required |
|---|---|---|
| `tests/a-claim-email-prefill.spec.ts` | Claim-email round-trip including the rendered `traits.email` prefill on /registration | Verifies the DOM after Kratos's browser-init round-trip — `Set-Cookie` + 303 assertions live in the Rust suite, the rendered input value couldn't be cheaply asserted there |
| `tests/b-oauth-authorize-token.spec.ts` | OAuth authorize → consent → callback → token exchange | Real cross-origin cookie behaviour (Forseti :3000 ↔ Hydra :4444). Hydra's CSRF cookie is scoped to its `issuer` hostname; only a browser exercises that path |
| `tests/c-admin-aal2-stepup.spec.ts` | AAL2 step-up redirect chain at /admin/* for an AAL1-only session | Rust admin fixture signs in at AAL2 upfront and never observes the step-up chain |
| `tests/d-recovery-flow.spec.ts` | Forgot-password recovery: /recovery → mail code → /settings/password → sign back in with new pw | The recovery → privileged settings hand-off is browser-state-driven; Kratos drops the user on a fresh settings flow with a privileged session cookie the Rust suite would have to reverse-engineer |
| `tests/e-rp-initiated-logout.spec.ts` | OIDC `oauth2/sessions/logout?id_token_hint=...` → Forseti confirm → Kratos session cleared → post_logout_redirect_uri | The Hydra → Forseti → Hydra → RP redirect chain only resolves correctly when the cookie jar carries Hydra's logout_challenge cookie; pure-HTTP can't reproduce it |
| `tests/f-org-invite-redemption.spec.ts` | Admin sends invite → mailcrab delivers → invitee registers via `return_to=/invite/finalize` → CSRF-protected accept lands a `member` row | The hand-off cookie ride (Kratos registration session ↔ Forseti invite token ↔ verification gate) is exactly what breaks under multi-redirect chains |
| `tests/g-self-delete-confirm.spec.ts` | `/settings/account/delete` confirm: granted apps render in the notify card, empty-submit blocked by HTML5 validity, wrong-email rejected server-side, correct email runs the saga + clears session | The HTML5 `required` + server-side equality interplay is DOM-only |
| `tests/unlicensed/m-account-chooser.spec.ts` | Multi-account chooser: `remember_account` opt-in sets `forseti_known_accounts` cookie; a third authorize as B renders A in the switch list (not B); submitting the switch form tears down B's session and lands on /login | The consent DOM renders the new checkbox and chooser; the cross-origin switch-restart (Hydra → portal → Kratos → /login) is a browser-cookie-chain that can't be replicated in pure HTTP |

Everything else — webhook outbox state machines, audit row writes, signed
SET payloads, identity disable/enable, secret rotation — belongs in the
Rust suite (`tests/integration/bug_regressions.rs`). Browser tests are
slow and flaky relative to backend assertions; keep this directory tight.

## Run

```
make e2e
```

…from the repo root. The target:

1. `curl`s `http://localhost:3000/healthz` to confirm the playground is
   up. (Bring it up with `podman-compose -f infra/docker-compose.yml up
   -d` + a Forseti binary.)
2. Pulls `mcr.microsoft.com/playwright:v1.60.0-noble` on first run. The image
   tag is pinned to match the `@playwright/test` version in `package.json` —
   bumping one means bumping both (and re-running `npm install` to refresh
   the lock file).
3. Mounts `tests/e2e` into the container.
4. Uses a named podman volume (`forseti-e2e-node-modules`) so
   `node_modules/` survives between runs.
5. Runs `npm ci` (fast after the first run, ~5s) and `npx playwright
   test`.

To open the trace viewer for the most recent failed test:

```
make e2e-trace
```

### Env vars

| Var | Required | Meaning |
|---|---|---|
| `BASE_URL` | no (default `http://localhost:3000` — `make e2e` uses `--network host` so localhost resolves to the host's loopback) | Forseti base URL the tests hit |
| `MAILCRAB_BASE` | no (default `http://localhost:4436`) | Mailcrab API base — claim-email scenario needs this |
| `FORSETI_ADMIN_TEST_EMAIL` | for scenarios B, C, E, F, G | Admin allowed-emails entry (e.g. `mail@gofranz.com`) |
| `FORSETI_ADMIN_TEST_PASSWORD` | for scenarios B, C, E, F, G | Admin password |
| `FORSETI_ADMIN_TEST_TOTP_SECRET` | for scenarios B, C, E, F, G | Base32 TOTP secret (e.g. `cat /tmp/totp_secret.txt`). Single-code `_CODE` fallback is intentionally not supported — every admin scenario submits multiple TOTPs and Kratos rejects code reuse |

When the admin env vars are unset, scenarios B, C, E, F, G `test.skip(…)`
and the suite still reports them in the run output. Scenarios A and D
always run (no admin needed).

`make seed-admin` (run after `make stack-up`) plants a deterministic admin
into Kratos and prints these three values to export — Kratos can't import TOTP
via its API, so the script creates the identity with a password and inserts the
TOTP credential straight into Kratos's Postgres. CI runs it automatically; the
seeded `admin@example.com` matches `config.ci.toml`'s allowlist.

## Add a new test

1. Drop a `*.spec.ts` file in `tests/`. Use the existing scenarios as
   templates — each one self-registers a fresh user with `uniqueEmail()`
   so they don't depend on prior state.
2. Re-use the helpers in `helpers/` (`mailcrab.ts`, `register.ts`,
   `admin.ts`, `oauth.ts`, `totp.ts`) before adding new ones.
3. Keep the test count small. If the new scenario would be just as easy
   to assert in Rust (HTTP redirects, DB state, Set-Cookie attributes),
   prefer adding it to `tests/integration/bug_regressions.rs` — that
   layer runs in seconds vs. the ~30s a fresh Playwright run takes.

## Gotchas

* **`--network host`, not `--add-host`.** The Playwright base image ships
  `/etc/hosts` entries that hard-code `127.0.0.1 host.containers.internal`
  (alongside a long facebook.com block-list). A `--add-host
  host.containers.internal:host-gateway` flag layers a second entry on
  top, and Chromium picks the loopback one — which has nothing on :3000
  inside the container → ERR_CONNECTION_REFUSED. `--network host` shares
  the host's network namespace entirely, so `localhost` and
  `host.containers.internal` both resolve via the host's `/etc/hosts`
  exactly as `cargo test` sees them.
* **`host.containers.internal:4444` for Hydra.** Hydra's `issuer` is set
  to `http://host.containers.internal:4444` (see
  `infra/hydra/hydra.yml`). Authorize URLs MUST use that hostname or
  Hydra's CSRF cookie gets dropped between hops and consent 403s with
  `request_forbidden: No CSRF value available in the session cookie`.
  With `--network host`, the host's `/etc/hosts` entry (`127.0.0.1
  host.containers.internal`) does the right thing.
* **TOTP code reuse**. Kratos rejects re-used codes. Each scenario
  computes a fresh code from `FORSETI_ADMIN_TEST_TOTP_SECRET` per
  submission — never cache the return of `computeTotp()`.
* **Unreachable callback URI (Scenario B)**. The OAuth client registers
  `http://localhost:9876/cb`. There's no listener — Playwright
  intercepts the navigation via `page.waitForRequest()` and reads the
  `code` off the URL before the browser tries to actually load it. Don't
  add a `waitForURL(…callback…)` here; you'll race the
  ERR_CONNECTION_REFUSED.
* **First `npm i` is slow** (~30s — Playwright + transitive deps). The
  named podman volume caches `node_modules/` so subsequent runs run
  `npm ci` in ~5s.
* **Lock file (`package-lock.json`)** is generated by the first `npm ci`
  inside the container and is checked into git. Regenerate it (run with
  `npm install` instead of `npm ci`) only when bumping dependency
  versions in `package.json`.
* **Form submits — use Playwright's `.click()`.** The `form.requestSubmit(btn)`
  workaround in the e2e-review skill is MCP-specific (the
  claude-in-chrome browser doesn't reliably submit forms via `btn.click()`).
  Playwright handles cross-origin form posts correctly.
* **Don't `document.querySelector('form')`.** Always target by `action`
  attribute — the top-nav Sign Out form is often the first `<form>` on
  the page.
* **Workers = 1.** The playground stack is shared state; mirror the Rust
  suite's `--test-threads=1`. Don't crank workers up without redesigning
  for isolated state.
* **Kratos PUT silently drops `verified: true`** (Scenario F gotcha). The
  admin `PUT /admin/identities/{id}` endpoint treats `verifiable_addresses[].verified`
  as server-controlled — passing `true` in the body is accepted (200 OK)
  but the row stays `verified: false`. JSON Patch on
  `/verifiable_addresses/<i>/verified` IS honoured. The invite scenario
  uses PATCH for that reason; mirror this when faking verified addresses
  from any new test.
* **Kratos default recovery email is code-only.** The mail body is
  `Recover access to your account by entering the following code: <NNNNNN>`
  with NO link. Don't try to extract a flow URL from the body — the
  flow_id lives in the browser's URL bar after submitting the email at
  /recovery. Scenario D submits the code on the same /recovery?flow=
  page that the email step landed us on.
* **Hydra RP-initiated logout post_logout_redirect_uri** must be a
  string in the Hydra client's `post_logout_redirect_uris` array. The
  admin client form takes a newline-separated textarea
  (`name="post_logout_redirect_uris"`) — `helpers/clients.ts::createOAuthClient`
  joins with `\n`.
* **Self-delete privileged gate may bounce to /login?refresh=true**
  (Scenario G gotcha). Even though registration counts as a fresh
  authentication, the gate sometimes asks for `refresh=true` between
  the GET and the POST. Tests must be prepared to re-submit the
  password and come back — Scenario G does the bounce check around
  the navigation and the wrong-email submit.
* **Invitee branch flips on session identity**. The
  `/invite/accept?token=...` GET handler renders three different
  templates depending on (no session) vs. (signed-in matching) vs.
  (signed-in mismatch). Tests that "carry the admin's cookies" will
  hit the mismatch branch and see a `/logout?return_to=...` CTA, NOT
  the "Register as ..." CTA — always open the invitee flow in a
  fresh `browser.newContext()`.
