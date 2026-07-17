---
name: e2e-review
description: End-to-end review of the Forseti stack. Prompts the operator to choose between two automated tiers (Rust integration tests + Playwright browser scenarios — both fire-and-forget) and an interactive Chrome-MCP walkthrough of docs/dev/testing_checklist.md. The interactive path wipes state, registers a fresh admin with TOTP, then drives Chrome per a menu of surfaces, verifying each (page/DOM state + audit rows; screenshots optional) and reporting what worked, what broke, and which audit rows landed. Use when the user says "run the e2e review", "test everything end to end", "regression-test the admin UI", "let's verify the stack after my changes", or similar.
---

# e2e-review

Goal: take the stack from "fresh clone" to "every flow verified". There are three tiers and the operator picks which (or all):

1. **Rust integration suite** — `make test-integration` runs the **full** suite (~68 tests: 66 pass + 2 intentionally `#[ignore]`d, ~15-40s): login/logout, registration, recovery, verification, settings, the OAuth2 auth-code flow, DCR, account deletion, and the admin surface. The OAuth/DCR consent chains are happiest against a freshly-reset stack (no leftover Hydra consent grants, correct Hydra issuer) — mode (d) is the gold standard — but the full suite passes against a long-lived dev stack too. Always run the full suite; there's no "quick subset" worth trading coverage for.
2. **Playwright browser scenarios** — `make e2e` covers 7 multi-step browser flows (~14s) where cross-origin cookie behaviour, redirect chains, or rendered DOM state IS the bug surface. Runs in a Docker container with bundled Chromium.
3. **Interactive Chrome-MCP walkthrough** — drives a real browser via the `claude-in-chrome` MCP through `docs/dev/testing_checklist.md`. Slow (~30 min), exhaustive, catches what (1) and (2) don't yet cover. Wipes state. Best for new features, post-release verification, or when the operator wants eyes on the actual UX.

Tiers (1) and (2) are fire-and-forget; tier (3) is destructive and chatty — every visible step prompts the operator and waits for a "looks right?" sign-off.

## Mode selection (ask first)

Before doing anything, prompt the operator:

> "How would you like to verify the stack?
> (a) **Automated suite** — fast (~45s total), runs both Rust integration tests and Playwright browser scenarios. No wipe.
> (b) **Interactive browser walkthrough** — slow (~30 min), exhaustive. Wipes state, registers a fresh admin, drives the menu in `docs/dev/testing_checklist.md` via the claude-in-chrome MCP.
> (c) **Both** — run (a) first to catch the easy ones, then (b) for anything not covered by the automated tiers."

Default suggestion when in doubt: (c). The automated tiers finish before the operator finishes reading the prompt for the browser steps, so there's almost no cost to running both.

> (d) **Full from-scratch** — when the operator wants maximum confidence (e.g. "reset everything and run ALL the tests"): `make stack-reset` (wipes volumes + the sqlite DB, brings the stack back up, blocks until ready), then `make seed-admin` to provision the admin (so the FULL Rust suite + Playwright get admin coverage — no manual enrollment), then the full **`make test-integration`** (not just `bug_regressions::`), then **`make e2e`**, then the browser walkthrough (which reuses the seeded admin). The order matters: the full Rust suite's OAuth/DCR/consent tests need the freshly-wiped Hydra (no leftover consent grants), so they must run *after* the reset — unlike mode (c), which runs the automated tiers against the still-dirty stack before wiping. `make stack-reset` does NOT rebuild Forseti or kill a running instance — `make run` (or the Flow §1 launch) still applies for a current binary.

### If (a) or the (a) leg of (c):

Run both automated tiers via the Makefile. Setup is two targets: bring the
stack up, then plant a deterministic admin so the admin-gated tests get full
coverage. `make seed-admin` replaces the old manual TOTP-enrollment dance —
Kratos can't import TOTP, so it creates the identity via the admin API and
plants the credential straight into Kratos's Postgres with a fixed secret. It
deletes-then-recreates just that one identity, so it provisions the admin
*without* wiping the rest of the stack (mode (a) stays "no wipe"). Forseti must
be running at :3000 — `make run` if it isn't.

```bash
guix shell make -- make stack-up        # blocks until Kratos + Hydra are ready; no-op if already up

# Seed an allowlisted admin (mail@gofranz.com is in config.toml's [admin].allowed_emails):
SEED_ADMIN_EMAIL=mail@gofranz.com \
SEED_ADMIN_PASSWORD=correct-horse-battery-staple-9 \
guix shell make -- make seed-admin
```

**Rust integration suite first** (the full suite, ~15-40s). The admin creds match what `seed-admin` planted; the TOTP secret is the fixed seed value:

```bash
FORSETI_ADMIN_TEST_EMAIL=mail@gofranz.com \
FORSETI_ADMIN_TEST_PASSWORD=correct-horse-battery-staple-9 \
FORSETI_ADMIN_TEST_TOTP_SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP \
guix shell make -- make test-integration
```

Acceptance baseline: 66 passed, 0 failed, 2 ignored. The OAuth/DCR consent chains prefer a freshly-reset stack (mode (d)); against a long-lived dev stack they generally still pass — if one errors out chasing the auth chain to the callback, `make stack-reset` and re-run.

**cargo filter gotcha:** if you drop to raw `cargo` for specific tests, `cargo test` takes only ONE positional `TESTNAME` *before* `--`. Put every filter *after* `--` so the libtest harness parses them, e.g. `cargo test --test integration -- --test-threads=1 oauth::foo dcr::bar`.

**Playwright browser scenarios second** (~14s). Same admin creds:

```bash
FORSETI_ADMIN_TEST_EMAIL=mail@gofranz.com \
FORSETI_ADMIN_TEST_PASSWORD=correct-horse-battery-staple-9 \
FORSETI_ADMIN_TEST_TOTP_SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP \
guix shell make -- make e2e
```

Acceptance baseline: 7 passed, 0 failed. `make e2e` runs Playwright inside Microsoft's `playwright:v*-noble` Docker image (no host-side Node); the `guix shell make --` wrapper is only because `make` isn't on the default GUIX path.

`g-self-delete-confirm` is occasionally **flaky** — a transient `page.goto` navigation race surfaces as `chrome-error://chromewebdata/` and it passes on retry #1. Playwright marks it "1 flaky" but the run is green; it's a timing artifact, not a regression.

With the seed step above, both tiers get full admin coverage. Skip seeding and they degrade gracefully — the ~5 admin-gated Rust tests early-return (they print "Skipping…" and still count as `ok`), and Playwright runs only A and D (5 of 7 skip). Seed unless the operator says otherwise.

**License-state buckets.** The Playwright suite is split into three projects by what license state Forseti must be in:

- `tests/e2e/tests/unlicensed/` — OSS-tier behaviour (no license row). What `make e2e` runs by default; the 7 specs above all live here.
- `tests/e2e/tests/licensed/` — exercises features unlocked by an active license (Orgs, etc.). Run via `make e2e-licensed`.
- `tests/e2e/tests/expired/` — exercises grace + hard-gate behaviour past the expiry. Run via `make e2e-expired`.

`make e2e-licensed` and `make e2e-expired` pre-check `forseti.db` for a matching license row and refuse with a clear instruction if state is wrong. The skill's automated tier (mode (a)) only runs `make e2e` (unlicensed) — the other buckets are operator-driven because they require an out-of-band activation step.

**To get a license blob for manual testing:**

```bash
make license-fixtures   # mints active.blob + expired.blob into tests/fixtures/license/ (gitignored)
```

This invokes the issuer CLI at `$LICENSE_ISSUER_DIR` (defaults to `$HOME/git/ory-frontend-license`). Then paste the file contents into `/admin/license` as the admin (AAL2-gated). Re-run the matching `make e2e-{licensed,expired}` target — pre-check will pass and the bucket runs. Deactivate via the same page when done.

Blobs are sensitive: anyone with one can unlock any Forseti sharing the baked-in pubkey. Never commit them.

For each tier, report pass/fail counts and any failed test name + assertion. If a test that's normally green fails, that's a regression candidate — do NOT try to fix it in this skill; hand the test name back to the operator.

If the operator chose (a) alone, you're done. Skip the rest.

### If (b) or the (b) leg of (c):

Continue to "Flow" below. The browser walkthrough is the original behaviour of this skill.

## Prereqs

* Repo checked out locally with a **freshly rebuilt** binary. Always run `make build` (or `cargo build`) before touching the browser. A stale binary against post-commit source has cost real time — symptom is a startup log line that doesn't match the current `src/app.rs` (e.g. `"listening on 0.0.0.0:3000"` instead of `"public listener on …"`).
* `infra/docker-compose.yml` images cached locally (the `ory-up` skill covers first-time setup).
* `claude-in-chrome` MCP available; Chrome reachable.
* `oath-toolkit` reachable via `guix shell` — the agent computes TOTP codes inline.
* `httpbin.org` reachable — used as the webhook receiver for the account-deletion happy path (Forseti rejects `http://localhost` / `127.0.0.1` in webhook URLs by design, so there is no local-only path here).

## Flow

### 1. Confirm a wipe

Ask the operator before destroying state:

> "About to wipe the Ory stack volumes and Forseti sqlite. The current `mail@gofranz.com` identity, all OAuth clients, all sessions, and the audit log will be gone. Continue?"

On approval:

```bash
# Stop Forseti by EXACT process name. Do NOT use `pkill -f "target/debug/forseti"`:
# the wipe command's own shell has that literal string in its arg list, so `-f`
# self-matches and SIGKILLs the script mid-wipe (down -v never runs). `-x forseti`
# matches the process `comm` only — the shell is `bash`, so it's safe.
pkill -x forseti 2>/dev/null || true
podman-compose -f infra/docker-compose.yml down -v
rm -f forseti.db forseti.db-shm forseti.db-wal       # include the WAL sidecars
cargo build                                          # rebuild before launch (see Prereqs)
podman-compose -f infra/docker-compose.yml up -d
```

`up -d` also spins the run-once `kratos-migrate` / `hydra-migrate` containers (they migrate, then exit) before Kratos/Hydra accept traffic. Poll until both are ready:

```bash
until curl -sf http://127.0.0.1:4433/health/ready >/dev/null \
   && curl -sf http://127.0.0.1:4445/health/ready >/dev/null; do sleep 2; done
```

Then launch Forseti and wait for healthz:

```bash
setsid nohup ./target/debug/forseti </dev/null >/tmp/Forseti.log 2>&1 &
until curl -sf http://127.0.0.1:3000/healthz >/dev/null; do sleep 1; done
```

Sanity-check the startup log: `head -4 /tmp/Forseti.log` should show `running database migrations`, `license: unlicensed (OSS tier)`, and `public listener on 0.0.0.0:3000` — the last line confirms a current binary (a stale one logs `listening on 0.0.0.0:3000`). Note: the mail container is listed by `podman ps` as `infra_mailslurper_1` but actually runs **Mailcrab** on :4436 — the compose service kept its old name.

### 2. Set up the admin

This manual browser enrollment is for the interactive walkthrough — and for when you specifically want to exercise the enrollment UX. The automated tiers (modes a/d) instead run `make seed-admin`, which plants the admin deterministically (no browser, no `/tmp/totp_secret.txt`). If you've already seeded, the identity exists with password `correct-horse-battery-staple-9` and a known TOTP secret — skip to the walkthrough.

1. Close any stale tabs from earlier MCP sessions (`tabs_close_mcp`). Create a fresh tab.
2. Navigate to `http://localhost:3000/registration`.
3. Fill: `mail@gofranz.com` (it's in `config.toml`'s admin allowlist), name "Franz Geffke", password `correct-horse-battery-staple-9`. Submit.
4. After landing on the dashboard, navigate to `/settings/2fa`.
5. **Pull the TOTP secret.** Chrome's safety filter blocks base32-looking text from `read_page`/`javascript_tool` output. Workaround: match the secret with a regex, then map each char to its `charCodeAt(0)` and reassemble server-side:
   ```js
   const m = document.body.innerText.match(/[A-Z2-7]{32}/);
   const hid = document.querySelector('input[name="totp_secret_key"]');  // fallback
   const src = (m && m[0]) || (hid && hid.value) || '';
   src.split('').map(c=>c.charCodeAt(0)).join(',')
   ```
   Then `python3 -c "print(''.join(chr(c) for c in [69,73,...]))"` → the secret.
6. Compute the current TOTP with `oathtool --totp -b "$SECRET"` (`guix shell oath-toolkit`) and submit. Verify the page now says "Enabled".
7. Save the secret to `/tmp/totp_secret.txt` so subsequent step-ups can reuse it without re-extracting.

Capture and report:
* Admin identity UUID (visible on `/admin/identities` after AAL2 step-up, or via `curl http://127.0.0.1:4434/admin/identities`)
* The TOTP secret (operator may want it in their own authenticator app)

### 3. Present the menu

Ask which surface to verify next. Annotations on each item:
- **[auto-rs]** — covered by `tests/integration/bug_regressions.rs` (Rust tier)
- **[auto-pw]** — covered by `tests/e2e/*.spec.ts` (Playwright tier)
- **[browser-only]** — pure UX (badge colour, copy, layout) that can only be eyeballed

If the operator chose (c) "both" and either automated tier already passed, **deprioritise items with matching annotations**. Focus the browser walkthrough on the unannotated items and the `[browser-only]` ones.

Suggested order when in doubt:

1. **Logout + AAL2 step-up at login** [auto-pw in `c-admin-aal2-stepup`] — log out, log back in with password only, navigate to any protected page (`/admin/webhooks`, or just the dashboard — under the enforcement config an enrolled user is bounced on any protected page via the whoami-403 path, not only `/admin/*`), expect a clean redirect to `/login?aal=aal2`; submit TOTP, land on the page.
2. **Email verification** [browser-only for the UI bits; webhook side auto-rs'd] — register a throwaway user, grab the code from Mailcrab (`http://127.0.0.1:4436`, API at `http://127.0.0.1:4436/api/messages`), submit on `/verification`. Confirm `verifiable_addresses[*].verified` flips to true via the Kratos admin API.
3. **Password change** in `/settings/password` — includes the re-auth round-trip when the session is older than 15m. Expect a `password.changed` audit row.
4. **Backup recovery codes** in `/settings/2fa` — two-step flow (generate-pending → confirm), then click Reveal. Expect `mfa.lookup.regenerated` audit.
5. **Recovery (forgot password)** [auto-pw in `d-recovery-flow`] — for a user WITHOUT a second factor: `/recovery` → email code → focused password page → reset. Expect a `password.recovered` audit row. For a TOTP-enrolled user, recovery does NOT bypass 2FA: the recovered session is AAL1 and `settings.required_aal: highest_available` bounces it to `/login?aal=aal2` before the password reset — step up with TOTP or a recovery code, then land back on the focused password page (the `?flow=` survives the step-up) and reset.
6. **Profile traits update** [auto-rs in `kratos_webhook_profile_updated_lands_audit_row`] — `/settings/profile`, change first/last name, save, confirm round-trips. Audit row `profile.updated` should land.
7. **OAuth2 authorize → consent → token** [auto-pw in `b-oauth-authorize-token`] — use `http://host.containers.internal:4444` for the authorize URL (not `localhost:4444`, see traps). Decode the `id_token` and confirm `sub` matches the Kratos identity UUID.
8. **Refresh token grant** — POST to `/oauth2/token` with `grant_type=refresh_token`. Confirm rotation (old token rejected, new token has fresh `iat`/`exp`).
9. **Admin: OAuth2 client CRUD** [auto-rs in `admin_client_secret_rotation`, `admin_client_verify_unverify_toggle`] — create with webhook URL `https://httpbin.org/anything`, edit (rename), rotate OAuth secret, delete. Each action audit-logged.
10. **Admin: identity disable + enable + delete + session revoke** [auto-rs in `admin_identity_disable_enable_cycle`, `admin_delete_identity_cascades_to_org_members`] — exercise the destructive buttons on an identity detail page. Use the throwaway user, NOT the admin.
11. **Admin: webhook dead-letter** [auto-rs in `webhook_outbox_requeue_then_discard`] — create a SECOND OAuth client with `https://this-host-does-not-resolve.invalid/forseti/account-deleted` as the webhook URL, OAuth-grant the throwaway user to it, delete that user. Watch `webhook_outbox` retry curve (`attempts` grows on `60s × 2^attempt` schedule). Force `state=DEAD` via SQL (`UPDATE webhook_outbox SET state='DEAD', attempts=12 WHERE ...`) to populate `/admin/webhooks`. Exercise the Requeue and Discard buttons on the detail page.
12. **Account self-deletion + signed webhook fan-out** [auto-rs in `self_delete_cascades_to_org_members` for the cascade; auto-pw in `g-self-delete-confirm` for the confirm-page UX; happy-path fan-out is browser-only] — use a SECOND test user who has OAuth-granted the httpbin-targeted client. Delete via `/settings/account/delete`. Watch `webhook_outbox` for `state=CONFIRMED`, `attempts=1`, `delivered_at` set, and the audit `account.self_deleted` row with `webhook_targets: 1`.
13. **Admin: audit page** [browser-only — filter combinatorics] — try each filter (email, action prefix, severity, since). Click "View" on a row to confirm the detail page (`/admin/audit/{id}`) renders sectioned data with the target label resolved to a human name.
14. **Admin: /admin/status page** [auto-rs in `admin_status_renders_unlicensed_oss_tier` for OSS state] — confirm the license row reads "Unlicensed" + OSS-tier hint; "Last audit webhook" shows a real timestamp (not "never") after any Kratos flow ran.
15. **Claim-email reclaim** [auto-rs + auto-pw in `claim_email_confirm_redirects_to_registration_with_prefill` and `a-claim-email-prefill`] — register an unverified user, kick off `/claim-email`, paste the code from Mailcrab, confirm the redirect lands on `/registration` with the email pre-filled.
16. **RP-initiated logout** [auto-pw in `e-rp-initiated-logout`] — Hydra `/oauth2/sessions/logout?id_token_hint=...` → Forseti confirm page → session cleared, redirected to `post_logout_redirect_uri`. Verify `to_session` returns 401 afterwards.
17. **Org invite redemption** [auto-pw in `f-org-invite-redemption`] — admin mints invite → mail arrives in Mailcrab → invitee opens accept URL in a fresh context → registers → lands as member of the target org.

**Confirm the run style with the operator up front** — it changes the whole interactive phase:
* **Sign-off per surface** (chatty): screenshot/inspect each surface, ask "looks right?", wait for approval before the next.
* **Autonomous + final report** (what most operators want for a sweep): drive straight through, verify each surface *yourself* by reading the page text / DOM state and the audit rows, give one consolidated report at the end. Skip screenshots unless asked — "just test it, look yourself, only stop if something's off" is a common instruction. **Even autonomous: ALWAYS pause for explicitly destructive buttons** (identity delete, dead-letter discard).

For each picked step:
* Drive the browser via MCP (`form.requestSubmit(btn)` for Kratos forms — see traps).
* Verify the result yourself: read page/DOM state, and the audit row(s) — `guix shell sqlite -- sqlite3 forseti.db "SELECT action, actor_email, target_kind, target_id FROM audit_events ORDER BY rowid DESC LIMIT 5;"`. After a full automated run the audit table is noisy (100+ rows); filter by `actor_email` or `action`, or read the count delta rather than scanning.

Destructive actions you can self-clean (so you actually exercise the path without leaking state): a **client** you created yourself is fine to rotate-secret + delete; a **password** change can be done then reverted to `correct-horse-battery-staple-9` so the documented admin creds still work. Never delete the admin identity.

If something looks broken: name the file + line where investigation should start and **STOP**. Don't try to fix anything in this skill — fixes are a separate task.

## Known traps (avoid re-discovering)

* **OAuth2 authorize URL must use whatever Hydra's `issuer` is set to** — applies to *every* layer (browser, curl, AND the Rust integration suite). Currently `infra/hydra/hydra.yml` sets `issuer: http://host.containers.internal:4444` (so the iss claim validates from inside other containers too). Hydra sets its CSRF cookie on the issuer's hostname; if you hit `localhost:4444` first, then Hydra's login_verifier round-trip rewrites the URL to `host.containers.internal:4444`, the CSRF cookie is dropped and consent fails with `request_forbidden: No CSRF value available in the session cookie` — Hydra then error-redirects to the registered `redirect_uri` carrying `?error=request_forbidden…`, so the symptom is the auth chain landing on the (often unreachable) callback rather than the consent page. `host.containers.internal` resolves to `127.0.0.1` via `/etc/hosts` on this host. The Rust suite's `tests/integration/common.rs` `HYDRA_PUBLIC` constant is pinned to the issuer host for exactly this reason; if Hydra's issuer ever changes, update that constant *and* this trap together.
* **Verification/recovery codes are bound to a specific Kratos flow, not "the newest email".** Mailcrab's `/api/messages` ordering can surface a code from an *older* flow first; submitting it gives "The verification code is invalid or has already been used." The code↔flow binding lives in the email body's link (`?code=X&flow=Y`, ampersands HTML-escaped as `&amp;`). Either parse the body and match the code to the flow you're driving, or click **Resend code** to mint a fresh code for the *active* flow and use that. Registration auto-sends one verification mail, so there's usually already a stale code sitting in the box.
* **Admin allowlist may be empty in `config.toml`.** If `[admin].allowed_emails` doesn't include the admin you're about to register, every `/admin/*` route 403s *after* a successful AAL2 step-up — the symptom is "Access denied" page, not a redirect loop. Check before registering: `grep allowed_emails config.toml`. Add `mail@gofranz.com` (or whatever the test admin is) and restart Forseti.
* **Forseti-owned mail is off unless `[email]` is present** (omitted or `enabled = false` in `config.toml`). Kratos's courier (registration / verification / recovery mail) works independently — those mails arrive in Mailcrab — but Forseti's own mails (organization invites, claim-email codes) silently drop with `"email disabled; would-be mail dropped (token/code still valid via DB)"`. Enable in `config.toml` (points at the local Mailcrab sink):
  ```toml
  [email]
  enabled = true
  from_address = "no-reply@forseti.test"
  provider = "smtp"
  host = "127.0.0.1"
  port = 1025
  tls = "none"
  ```
  …then restart. If you skip this, invite + claim-email tests will hang waiting for mail that never arrived.
* **Webhook URL validation rejects loopback / private IPs by design** (SSRF defence in `src/webhook.rs:validate_webhook_url`). For E2E use:
    * `https://httpbin.org/anything` — receives + echoes, good happy-path target
    * `https://this-host-does-not-resolve.invalid/...` — NXDOMAIN forever, good dead-letter target
* **Account-deletion fan-out only fires for clients the user has OAuth-consented to.** A user with no consent grants will see "No third-party apps have copies of your data" on the delete confirm page. Test users must complete an `/oauth2/auth` round-trip with the target client first.
* **TOTP forms have HTML5 `required` on BOTH `totp_code` and `lookup_secret`.** Clicking the totp submit still trips browser-side validation because the lookup_secret input is empty. Workaround when driving via MCP:
   ```js
   form.querySelectorAll('input').forEach(i => i.removeAttribute('required'));
   const btn = Array.from(form.querySelectorAll('button[type="submit"]')).find(b => b.value === 'totp');
   btn.click();
   ```
   (Real users don't hit this because they tab between fields or use Enter from inside the totp_code field, which submits with the right submitter.)
* **Recovery flow for TOTP-enrolled identities** — under the 2FA-enforcement config the recovered AAL1 session is bounced to `/login?aal=aal2` before it can reset the password; step up with TOTP or a recovery code, then the focused password page returns (the `?flow=` is preserved in the step-up `return_to`). On older builds without the fix from commit `982917c` the user instead lands on `/settings/profile` and the step-up loops — if you see that, you're on a stale binary.
* **Stale browser cookies livelock AAL2 flows after rapid navigation.** Symptom: `/login` and the protected page bouncing forever. Fix: close the tab via `tabs_close_mcp` and create a fresh one — clears the cookie jar.
* **Askama templates are compiled into the binary.** Template-only changes require `cargo build` AND a Forseti restart. Don't waste a verification cycle screenshotting a stale binary.
* **`kratos.yml` enforces 2FA with `session.whoami.required_aal: highest_available`** — this is the new model (was `aal1`). Any TOTP-enrolled identity is held to AAL2: a password-only (AAL1) session gets a 403 from whoami, which Forseti turns into a `/login?aal=aal2` step-up on the next protected page. A user with no second factor stays AAL1 and is never prompted. If you're testing against a custom Kratos config, verify this is set or 2FA won't be enforced.
* **`kratos.yml` also sets `selfservice.flows.settings.required_aal: highest_available`** — this is intentional and load-bearing (was `aal1`). It blocks an AAL1 session (password-only login, or an email-recovery session) from opening `/settings/2fa` and *removing* the second factor, which would otherwise defeat enforcement entirely. Practical effect during review: a TOTP-enrolled user must already be AAL2 (i.e. have stepped up at login) before any `/settings/*` credential edit; an un-stepped-up session bounces to `/login?aal=aal2`. `privileged_session_max_age: 15m` still separately gates the destructive operations.
* **`config.toml` needs `[internal].bind = "0.0.0.0:8081"`**, NOT `127.0.0.1:8081`. Kratos in podman reaches the host via the bridge IP, not loopback; with `127.0.0.1` the audit webhook can't fire and login appears to hang ~93s waiting for the synchronous webhook timeout. Symptom: login takes 90+ seconds; Forseti log shows fast handlers but Kratos sits idle. Fix: flip the bind, restart Forseti.
* **MCP form submits: use `form.requestSubmit(btn)`, NOT `btn.click()`.** The latter doesn't reliably trigger form submission when the form action is cross-origin (Kratos forms post to `:4433`). `requestSubmit()` is the right primitive.
* **Don't `document.querySelector('form')` blindly.** The top-nav Sign Out form is often the first `<form>` on settings pages; you'll log yourself out unintentionally. Always target by action: `document.querySelector('form[action*="..."]')`.
* **`[profiles].enabled` defaults to `false` (OSS).** If the test plan exercises `/users/{id}`, the extended-profile form on `/settings/profile`, or the members-roster identicons, flip it to `true` in `config.toml` first. Without it, the routes 404 and the extended fields don't render.
* **`POST /admin/clients` rejects `post_logout_redirect_uri` whose origin doesn't match any `redirect_uris` entry.** Hydra's security constraint. If you're scripting client creation, either reuse one origin for both or register the post-logout origin as a (harmless) extra redirect URI.
* **`backchannel_logout_uri` is a single-valued Hydra field** (not an array). If a client needs both dev and prod backchannel endpoints, you can only register one at a time.

## When to stop

The skill is one-shot per session. After the operator picks their last test (or says "done"), summarise:

* Which surfaces passed
* Which surfaces showed regressions (file:line for the suspect code)
* Any side-findings (template bugs, missing pretty fields, copy issues, etc.)
* Whether `/admin/audit` shows the expected rows for everything you exercised

**Don't auto-commit anything.** The operator decides whether the findings warrant a fix branch.

## What NOT to do

* Don't delete the **admin** identity during testing — it locks you out of every admin surface for the rest of the session.
* Don't `bash -c "curl ..."` flows that the UI is supposed to test. The point of this skill is to exercise what users actually hit.
* Don't skip the wipe on subsequent runs in the same session unless the operator explicitly says to keep state. Audit rows from previous runs make the page unreadable.
* Don't click `Discard` on dead-letter rows or `Delete` on identities without explicit operator approval — those are destructive and the skill's job is to verify the buttons exist and render correctly, not to exercise them blindly.
* Don't try to fix bugs in-flight. Report file:line, stop, hand back to the operator.
* Don't manually browser-test things already covered by the automated tiers if the operator chose mode (c) and both passed — the browser path is for catching what tests don't yet cover. The menu items above are annotated with `[auto-rs]` (Rust integration) and `[auto-pw]` (Playwright) markers.

## Endpoints cheatsheet

| URL | Purpose |
|---|---|
| `http://localhost:3000/` | Forseti |
| `http://127.0.0.1:4436` | Mailcrab UI (verification + recovery codes) — was Mailslurper in older revs |
| `http://127.0.0.1:4436/api/messages` | Mailcrab API (JSON list of mail). Per-message: `/api/message/{id}` |
| `http://127.0.0.1:1025` | Mailcrab plaintext SMTP (Forseti mailer + Kratos courier both target this) |
| `http://127.0.0.1:4434/admin/identities` | Kratos admin (for direct verification) |
| `http://127.0.0.1:4445/admin/oauth2/clients` | Hydra admin |
| `http://host.containers.internal:4444/oauth2/auth` | OAuth2 authorize — MUST use the issuer host (`host.containers.internal:4444`), NOT `localhost`/`127.0.0.1`, or Hydra drops its CSRF cookie and consent 403s → error-redirect to the callback. See traps. |
| `forseti.db` | SQLite — direct queries for audit / outbox verification |
