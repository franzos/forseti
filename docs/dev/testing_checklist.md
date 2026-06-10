# Manual Testing Checklist

End-to-end manual QA pass for the forseti stack. Covers every user- and admin-facing surface plus the recent licensing/orgs/authorized-apps additions. The `/e2e-review` skill is the interactive driver — this list is the master spec it works against. Run sections roughly in order; later sections assume the earlier ones left the stack in a known state.

> **Browser-driven steps use the Chrome MCP (`claude-in-chrome`).** Every box in §§2–9 (and any other "click X / submit Y / page renders Z" item) is exercised by driving Chrome via the `mcp__claude-in-chrome__*` tools — navigate, find, form_input, javascript_tool, read_page, gif_creator for multi-step recordings, etc. Load each tool with `ToolSearch` before the first call (the tools are deferred). Don't `curl` flows that the UI is supposed to test — the point of the manual pass is to exercise what real users hit. Out-of-band `curl` / `sqlite3` / `hydra` calls are fine for verification (audit rows, Hydra state, Kratos identity probe), not for driving the flow itself.

## 0.5 UX rubric (apply to every flow in §§2–9)

For each section you exercise, don't just check that the page renders and the audit row lands — also answer these. Note findings in the report at the bottom.

- [ ] **Next step obvious?** Without reading docs, would a first-time user know what to click? Any dead-end pages?
- [ ] **Error messages actionable?** Does each error say *what to do next*, not just *what went wrong*?
- [ ] **Success feedback?** After a destructive or save action, is there a flash / toast / badge / redirect that confirms the action completed?
- [ ] **Empty states useful?** Empty lists and zero-state pages should explain what would populate them, ideally with a CTA — not just blank space.
- [ ] **Keyboard-only path works?** Can the flow be completed without the mouse? Are focus rings visible? Tab order sensible?
- [ ] **Screen-reader sanity?** Form labels present, buttons have text (icon-only buttons need `aria-label`), flash messages in an `aria-live` region.
- [ ] **Narrow viewport sane?** At ~400px width, sidebar collapses cleanly, dialogs reachable, no horizontal scroll on form pages.
- [ ] **Destructive POSTs guarded?** Double-click doesn't double-submit; pending state visible; confirm pages can be backed out of.
- [ ] **Copy reads naturally?** No unexplained jargon (`AAL2`, `IAT`, `SET`, `consent grant`) on user-facing pages; admin pages may use it but should still be self-explanatory in context.
- [ ] **Console clean?** No JS errors, no 4xx/5xx for static assets in DevTools network tab.

## 0. Pre-flight (automated sanity)

Run these first. If any of them fail, stop and triage before touching the browser — manual testing on a broken build wastes the wipe.

- [ ] `cargo test` — unit + integration tests pass (playground must be up)
- [ ] `tests/README.md` — re-read if any integration test failed, the runner has prereqs

## 1. Stack bring-up

- [ ] Wipe: `podman-compose -f infra/docker-compose.yml down -v && rm -f forseti.db`
- [ ] Boot: `podman-compose -f infra/docker-compose.yml up -d`
- [ ] Kratos ready: `curl http://127.0.0.1:4433/health/ready` → 200
- [ ] Hydra ready: `curl http://127.0.0.1:4445/health/ready` → 200
- [ ] Mailcrab UI reachable: `http://127.0.0.1:4436`
- [ ] Forseti up: `setsid nohup ./target/debug/forseti </dev/null >/tmp/forseti.log 2>&1 &`
- [ ] `curl http://127.0.0.1:3000/healthz` → `ok`
- [ ] `curl http://127.0.0.1:3000/readyz` → `ready` (proves the webhook worker ticked)
- [ ] Embedded migrations ran (check `tracing` log line, no errors)
- [ ] License starts `Unlicensed` (no license row in `forseti_license`)

## 2. Admin bootstrapping (TOTP-enabled operator)

- [ ] Register `mail@gofranz.com` via `/registration` (in the admin allowlist)
- [ ] Lands on dashboard, "Recent Activity" sidebar renders, "Account health" tile renders
- [ ] `/settings/2fa` — enroll TOTP, save secret to `/tmp/totp_secret.txt`
- [ ] Page shows "Enabled" after submit
- [ ] Audit row: `mfa.totp.enrolled`
- [ ] Logout → log back in with password only → navigate to `/admin/webhooks` → bounced to `/login?flow=…` rendering the TOTP step-up form (the bounce URL itself doesn't carry `aal=aal2` — Kratos derives `requested_aal` from the flow, not the query string) → submit TOTP → land on the admin page
- [ ] Default-org auto-join landed (`mail@gofranz.com` is `owner` of Default — see `/settings/organization/members`)

## 3. Authentication flows (user-facing)

### 3.1 Registration

- [ ] Password registration (throwaway user, distinct email)
- [ ] Validation errors (short password, taken email) render inline
- [ ] "Unverified email" banner shows on dashboard
- [ ] Audit row: `identity.created` (fired from Kratos webhook → `/internal/audit/kratos`)
- [ ] Passkey/WebAuthn buttons render and `webauthn_helper.html` disables them on environments without a platform authenticator
- [ ] Expired flow (>10m) → graceful restart redirect

### 3.2 Login

- [ ] Password login (throwaway user)
- [ ] Wrong password → inline error, same flow
- [ ] Already-logged-in user navigating to `/login` → short-circuits to `return_to` or `/`
- [ ] `?aal=aal2` carve-out works when the query param IS present (no infinite loop with `/oauth/login`); note that Forseti's own AAL-required bounce (e.g. `/admin/*` on an AAL1 session) does NOT add this query param — it relies on Kratos's flow state, not the URL
- [ ] `?refresh=true` carve-out works (no livelock on privileged-session re-auth)
- [ ] Audit row: `auth.login` (lands on session-AAL settle, i.e. AAL2 completion for TOTP-enrolled users — intermediate AAL1 password submit does not emit a separate row)

### 3.3 Recovery (forgot password)

- [ ] **AAL1 user only** (TOTP-enabled users have a known trap — see e2e-review skill)
- [ ] `/recovery` → submit email → mail in Mailcrab → click link → land on `/settings/password` in focused/handoff mode
- [ ] Privileged-deadline countdown renders
- [ ] New password sticks; redirected to `/` after success
- [ ] Audit row: `password.recovered`
- [ ] **Info-leak guard:** submit a non-existent email → identical response body and visible timing to a real submission; no audit row, no Mailcrab message, no `Set-Cookie` differences

### 3.4 Verification

- [ ] `/verification` flow for an unverified registrant
- [ ] Code from Mailcrab → submitted → Kratos admin shows `verifiable_addresses[*].verified=true`
- [ ] Audit row: `verification.completed`

### 3.5 Logout

- [ ] `POST /logout` from the user menu → session cleared, lands on `/login`
- [ ] CSRF mismatch → rejected
- [ ] Audit row: `auth.logout`

### 3.6 Error landing

- [ ] Trigger a CSRF violation on a Kratos form → `/error?id=...` renders a friendly page (not a stack trace)

## 4. Settings hub

- [ ] `/settings` hub redirects to the right sub-page when followed with `?flow=<id>`
- [ ] Sidebar highlights the active section in every sub-page

### 4.1 Profile (`/settings/profile`)

- [ ] Change first / last name → save → success message
- [ ] Re-auth round-trip when session is older than 15m (privileged-session)
- [ ] Audit row: `profile.updated`
- [ ] **Extended profile** (only when `[profiles].enabled = true`): bio, website, avatar URL, pronouns, links — save → row in `profiles` (or equivalent) → values stick after reload
- [ ] Bad URL in `website` / `avatar_url` (not http/https) → inline error, no DB write
- [ ] **Public profile page** `/users/{identity_id}` renders the extended fields; unset fields hide cleanly (no "null" leakage)
- [ ] Public profile for an identity that doesn't exist → 404, not panic
- [ ] Extended-fields form hidden when `[profiles].enabled = false`

### 4.2 Password (`/settings/password`)

- [ ] Change password → success message
- [ ] Privileged-session re-auth triggers when stale
- [ ] Mismatched / weak passwords → inline error
- [ ] Audit row: `password.changed`

### 4.3 Two-factor (`/settings/2fa`)

- [ ] TOTP enroll (covered in §2)
- [ ] TOTP disable → re-enroll path works
- [ ] Backup recovery codes — two-step generate-pending → confirm → Reveal once
- [ ] Reveal page renders the codes exactly once; reload shows empty state
- [ ] Audit row: `mfa.lookup.regenerated`
- [ ] WebAuthn / passkey enroll button renders; passkey method gated by browser support
- [ ] TOTP form: confirm submission works (real users tab into `totp_code` and Enter; HTML5 `required` trap documented in e2e-review)

### 4.4 Sessions (`/settings/sessions`)

- [ ] Active session list renders with humanised user-agent + last-seen
- [ ] Revoke a non-current session → row disappears
- [ ] "Revoke all others" button works → current session preserved
- [ ] Audit row: `session.revoked` (per revoke)
- [ ] CSRF rejected on direct POST without token

### 4.5 Linked providers (`/settings/linked-providers`)

- [ ] Page renders empty state when no OIDC providers configured
- [ ] (If a provider is enabled in `kratos.yml`) link/unlink round-trip

### 4.6 Authorized apps (`/settings/authorized-apps`) — NEW

- [ ] List shows every OAuth2 client the user has consented to
- [ ] Each row: client name, optional logo, scopes as chips with descriptions, "granted Nd ago" + tooltip with absolute timestamp
- [ ] Verified vs unverified badge renders correctly
- [ ] Revoke per-client → consent grant gone from Hydra (`hydra list oauth2-consent ...`)
- [ ] Audit row: `oauth.consent.revoked` (or equivalent — verify in `/admin/audit`)
- [ ] Empty state when no grants

### 4.7 Account / danger zone (`/settings/account` + `/settings/account/delete`)

- [ ] Landing page renders without privileged-session check
- [ ] Confirm page lists `notified_apps` — every client the user has OAuth-consented to
- [ ] User without any consent grants → "No third-party apps have copies of your data"
- [ ] Privileged-session refresh enforced before delete proceeds
- [ ] Self-delete → Kratos identity gone, `webhook_outbox` rows inserted in `PENDING`, worker drains to `CONFIRMED` with `attempts=1` + `delivered_at` set
- [ ] Audit row: `account.self_deleted` with `webhook_targets: N` matching the consent-grant count
- [ ] Lands on a "your account is gone" page (or `/login`)

## 5. OAuth2 / OIDC bridge

### 5.1 Authorize → consent → token (happy path)

- [ ] Register a test client with `hydra create client ...`
- [ ] Visit authorize URL using `http://localhost:4444/oauth2/auth?...` (**NOT** `127.0.0.1`)
- [ ] `/oauth/login` → Forseti shows the Kratos login form
- [ ] After login, `/oauth/consent` renders with client name + scope chips + verified-badge (or caution banner if unverified)
- [ ] Required scopes (`openid`) are checked-and-disabled with a hidden duplicate
- [ ] Allow → redirected to client `redirect_uri` with `code`
- [ ] Token exchange returns valid `access_token` + `id_token`; decoded `id_token.sub` matches the Kratos identity UUID
- [ ] Audit rows: `oauth.consent.granted`

### 5.2 Refresh token rotation

- [ ] `POST /oauth2/token` with `grant_type=refresh_token` → new tokens
- [ ] Old refresh token rejected (`invalid_grant`)
- [ ] New access token has fresh `iat` / `exp`

### 5.3 AAL2 step-up via `acr_values`

- [ ] Authorize URL with `acr_values=...` requesting AAL2 → step-up triggers cleanly
- [ ] Doesn't loop between `/oauth/login` and `/login`

### 5.4 Logout (`/oauth/logout`)

- [ ] RP-initiated logout flow from Hydra → Forseti confirm page → session cleared, redirected back to client
- [ ] Audit row: `auth.logout`

### 5.4.5 Authorize/token negatives (high-impact)

These are the classic spec-violation bugs custom IdPs ship. Drive each via Chrome MCP for the consent-screen steps, then `curl` the token endpoint with the captured `code`.

- [ ] **Authorization code reuse:** exchange the same `code` twice → second call → `invalid_grant`
- [ ] **`redirect_uri` mismatch on token exchange:** authorize with URI A, send URI B on `/oauth2/token` → `invalid_grant`
- [ ] **PKCE negatives:** start a flow with `code_challenge` + `S256`, then exchange (a) without `code_verifier` and (b) with a wrong verifier → both → `invalid_grant`
- [ ] **Consent "Deny":** repeat §5.1 happy path but click Deny → RP receives `error=access_denied`; no consent grant in `hydra list oauth2-consent`; no `oauth.consent.granted` audit row

### 5.5 Dynamic Client Registration (`/oauth2/register`)

- [ ] Anonymous DCR (no `Authorization` header) → 201 with `client_id` + `client_secret` + `registration_access_token`
- [ ] DCR client lands in `oauth_client_metadata` as `source='dcr'`, `verification='unverified'`
- [ ] Consent screen for an unverified DCR client shows the caution banner
- [ ] DCR with malformed `Authorization` header → 401 (no silent fallback)
- [ ] DCR with valid IAT → audit row keyed off the IAT actor; `uses_remaining` decrements
- [ ] DCR with revoked / expired IAT → 401
- [ ] Reserved client names rejected
- [ ] **`redirect_uri` scheme validation:** DCR requests with `http://` non-loopback, `javascript:`, `file://`, `data:`, or a raw IP literal in the host → 400, no client written
- [ ] `metadata.forseti.*` keys in the request body are stripped (verify via `hydra get client ...`)
- [ ] Rate limit: 11th request in a minute → 429 with a clean error body
- [ ] Audit rows: `dcr_registered` / `dcr_rejected`

## 6. Organizations (commercial-gated, OSS Default works)

### 6.1 OSS Default org

- [ ] `/settings/organization` overview — rename the Default org → success
- [ ] `/settings/organization/info` info panel renders the same data as the overview (read-only)
- [ ] `/settings/organization/branding` — logo URL + support email save and stick
- [ ] `/settings/organization/members` — list shows the admin + any auto-joined users
- [ ] Change a member's role owner ↔ member
- [ ] Remove a member (not the last owner — that should be blocked with a `409` + friendly error)
- [ ] Last-owner removal attempt: confirm the page comes back with a sensible message, member still listed
- [ ] Invite member: `POST /settings/organization/members/invite` → mail in Mailcrab → `/invite/accept?token=...` flow
- [ ] Invite redeems → new member joins as the role specified in the invite
- [ ] `/invite/finalize` step renders for a redeeming user that isn't logged in yet (or however the flow chains login → finalize) — no infinite loop
- [ ] Invite accepted by a user that is already a member of the target org → friendly "already a member" message, no duplicate row
- [ ] Expired invite token (>7d) rejected
- [ ] Invalid / reused invite token rejected with a friendly error
- [ ] Audit rows: `org.member.added`, `org.member.role_changed`, `org.member.removed`, `org.invite.created`, `org.invite.accepted`

### 6.2 Auto-join on first authenticated request

- [ ] Fresh registrant lands as `member` of Default (or `owner` if first user / admin-allowlisted)
- [ ] Auto-join is idempotent (re-login doesn't insert a second row)
- [ ] DB unique-constraint race on simultaneous first-requests doesn't crash the request

### 6.3 Multi-org (license-gated)

- [ ] Without a license: `/settings/organizations` → upsell page renders
- [ ] `/settings/organizations/create` POST blocked with upsell page
- [ ] Admin scope `?org=<slug>` for non-Default → upsell page if license is `Locked`
- [ ] Activate a paid license (see §8) → multi-org pages unlock
- [ ] Create new org → slug generated, owner = creator
- [ ] Switch active org via `/orgs/switch` POST → signed cookie set, dropdown reflects new active org
- [ ] Org branding shows on its own login/registration page (when accessed via per-org flow)
- [ ] Hard-delete an org (not Default) → all memberships, invites, clients cascaded
- [ ] Default org is non-deletable (the delete POST refuses)
- [ ] OIDC `orgs` claim appears in `id_token` for licensed deployments

### 6.4 Org-scoped admin

- [ ] Org owner (non-Forseti-admin) can access `/admin/?org=<slug>` and sees only their org's clients / identities / sessions / audit / webhooks
- [ ] **Cross-org isolation:** create two orgs A and B with distinct clients + identities; owner-of-A loading `/admin/clients?org=B` (and `/identities`, `/sessions`, `/audit`, `/webhooks`) → 403 or empty list, never B's data
- [ ] Non-owner gets a clean 403
- [ ] Forseti admin without `?org=` still sees the global view
- [ ] **Pagination** on `/admin/identities`, `/admin/sessions`, `/admin/audit`, `/admin/webhooks` — first page, middle, last page, beyond-last-page (renders empty, doesn't crash)
- [ ] Pagination `?org=<slug>` preserves the scope across page links

### 6.5 Enterprise SAML SSO (license-gated; needs `make stack-up-saml` + `[saml]` in config)

- [ ] Without a `saml`-featured license: `/sso/<slug>` → neutral "SSO unavailable" page; `/admin/saml` → upsell
- [ ] `/admin/saml/new` → create a connection for Default against mock-saml: fetch `http://127.0.0.1:4480/api/saml/metadata` and paste the XML (Jackson 26.x rejects plain-HTTP non-localhost metadata URLs, so the URL field won't take `http://mock-saml:4000/…`) → row appears with SP values card (ACS URL + entity id) + `/sso/<slug>` URL
- [ ] **Happy path:** logged-out browser → `/sso/default` → mock-saml login (any email + ACS pre-filled) → lands on the dashboard with a native `ory_kratos_session`, NOT on `/settings/password`
- [ ] JIT identity created in Kratos with the asserted email pre-verified; member row added to the org
- [ ] Second login with the same email reuses the linked identity (no duplicate)
- [ ] **Blocked unverified:** register an identity, leave it unverified, SSO with that email → blocked page, no session
- [ ] **Kill switch:** toggle the connection disabled → `/sso/default` renders the neutral unavailable page immediately; re-enable → flow works again
- [ ] **Delete:** delete the connection → confirm page → gone from Jackson and the list; `/sso/default` → neutral page
- [ ] SSO session is AAL1 — `/admin/*` still demands the second factor
- [ ] Audit rows: `saml.login.succeeded`, `saml.login.blocked_unverified`, `saml.identity.jit_created`, `saml.identity.linked`, `admin.saml.connection_created` / `_toggled` / `_deleted`

## 7. Admin surface (`/admin/*`)

All admin pages require AAL2 + Forseti-admin allowlist or org ownership.

### 7.1 Status (`/admin/status`)

- [ ] Renders Forseti version, DB backend, license status, webhook worker last-tick
- [ ] SQLite-in-production warning visible if applicable
- [ ] License state row reflects `Unlicensed` / `Active` / `Grace` / `Expired`

### 7.2 Clients (`/admin/clients`)

- [ ] List renders with verification badge + preset chip + created-at
- [ ] Create wizard: pick preset (Web app / Native / MCP / M2M / Custom) → form pre-filled with sensible defaults
- [ ] Create with webhook URL `https://httpbin.org/anything` succeeds (loopback URLs rejected)
- [ ] Client secret reveal once on creation (SecretReveal flash) — reload doesn't show it again
- [ ] Show page renders metadata + scope chips + verification state
- [ ] Edit (rename / change scopes / change redirect URIs) → audit row
- [ ] **Back-channel + front-channel logout URIs** can be set on create and edit; values persist; `hydra get client ...` reflects them
- [ ] Rotate OAuth secret → secret revealed once → old secret rejected by Hydra
- [ ] Verify / Unverify toggle → consent screen badge flips
- [ ] Delete with confirm → row gone, `oauth_client_metadata` cascade clean
- [ ] CSRF on all destructive POSTs
- [ ] Audit rows: `oauth.client.created`, `.updated`, `.deleted`, `.secret_rotated`, `.verified`, `.unverified`

### 7.3 DCR tokens (`/admin/dcr-tokens`)

- [ ] List renders existing IATs with `uses_remaining`, `expires_at`, `revoked_at`
- [ ] Issue new IAT → token revealed once
- [ ] Revoke IAT → `revoked_at` stamped → subsequent DCR with that token rejected
- [ ] Audit rows: `dcr.iat.issued`, `dcr.iat.revoked`

### 7.4 Identities (`/admin/identities`)

- [ ] List paginates, search/filter by email works
- [ ] Detail page renders traits, verifiable addresses, sessions, MFA enrolment
- [ ] Recovery: trigger admin recovery → one-shot link revealed once
- [ ] Disable identity → user can't log in (session whoami fails)
- [ ] **Live session bounce on disable:** log the target user in via a second browser, then disable from `/admin/identities` → their next request to any protected route → bounced to `/login`, not silently served from a cached session
- [ ] Enable identity → user can log in again
- [ ] Delete identity (throwaway user, NOT admin) → cascaded out of Hydra grants + webhook outbox row(s)
- [ ] Confirm pages render and reject without `confirm=yes`
- [ ] Audit rows: `identity.recovered`, `.disabled`, `.enabled`, `.deleted`

### 7.5 Sessions (`/admin/sessions`)

- [ ] List shows active sessions across the deployment
- [ ] Revoke a session → user gets bounced to `/login` on next request
- [ ] Audit row: `session.revoked`

### 7.6 Audit (`/admin/audit`)

- [ ] List paginates, newest first
- [ ] Filters: by email, action prefix, severity, since
- [ ] Detail page (`/admin/audit/{id}`) renders sectioned data — actor, target (resolved to human label), metadata pretty-printed
- [ ] Unknown actor / target IDs render gracefully (no panic)

### 7.7 Webhooks (`/admin/webhooks`) — dead-letter queue

- [ ] Page lists `DEAD` rows from the account-deletion fan-out
- [ ] Detail page renders payload, signature, last error, attempts curve
- [ ] Requeue → `attempts` reset, next worker tick re-attempts
- [ ] Discard → row marked `DISCARDED`
- [ ] Audit rows: `webhook.requeued`, `webhook.discarded`

### 7.8 Webhook outbox lifecycle (end-to-end)

- [ ] Create a 2nd OAuth client with webhook URL pointing at `https://this-host-does-not-resolve.invalid/...`
- [ ] OAuth-grant the throwaway user to that client
- [ ] Delete the throwaway user
- [ ] Watch `webhook_outbox`: `attempts` grows on the `60s × 2^attempt` schedule
- [ ] Force `state=DEAD` via SQL once attempts maxed out → row surfaces on `/admin/webhooks`
- [ ] Worker `seconds_since_last_tick` stays under the `WORKER_STALE_SECS` (20s) threshold → `/readyz` keeps returning 200
- [ ] Kill the worker (or simulate stale) → `/readyz` returns 503 with a sensible message

## 8. Commercial / licensing

### 8.1 `/admin/license`

- [ ] OSS (no license) → page renders "Unlicensed" state + purchase link
- [ ] Activate a valid signed blob → state flips to `Active`, customer + tier + features render, banner clears
- [ ] Activate an expired blob → `Grace` state if within `grace_days`, else `Expired`
- [ ] Activate a malformed / wrong-signature blob → friendly error, no row written
- [ ] Deactivate → row deleted, state back to `Unlicensed`
- [ ] Audit rows: `license.activated`, `license.deactivated`
- [ ] **Replay older blob:** activate an `active` blob → deactivate → re-activate an earlier-issued `active` blob (different `iat`, same pubkey) → succeeds (offline-friendly by design), but rendered tier + features reflect the re-activated blob, not the previous one (no ArcSwap staleness)

### 8.2 Feature gating

- [ ] OSS (Unlicensed) → multi-org pages render upsell; Default org pages work
- [ ] `Active` + `Orgs` feature → multi-org unlocked
- [ ] `Grace` + `Orgs` → multi-org read-only? (verify the design intent — `FeatureStatus::GraceReadOnly`)
- [ ] `Locked` (e.g. `Saml`, `Scim`, `SiemStreaming`, `BulkAdmin`) → upsell page when the surface exists
- [ ] Unknown feature in license blob → silently dropped (forward-compat)

### 8.3 Dashboard banner

- [ ] License in `Grace` → banner with deep-link to `/admin/license`
- [ ] License `Expired` → red banner, links to `/admin/license`
- [ ] License `Active` → no banner

## 9. Identity claim-email (squatting recovery)

- [ ] Register `user@example.com`, leave unverified
- [ ] Try to register `user@example.com` again → fails (Kratos rejects)
- [ ] `/claim-email` → submit email + new password → generic "if exists..." response (no info leak)
- [ ] Mailcrab shows a 6-digit code
- [ ] `/claim-email/confirm?token=...` → submit code → old unverified identity deleted → redirected to registration with email pre-filled
- [ ] Expired / wrong code → friendly error
- [ ] Claiming an already-verified email → refused (no delete)
- [ ] Audit row: `identity.deleted` with reason `claim_email`

## 9.5 Discovery + JWKS endpoints

These are all anonymous GETs — fine to drive with `curl`, this section is verification, not flow-exercise.

- [ ] `GET /.well-known/forseti-configuration` → 200 JSON; required fields present (issuer, version, capabilities, etc. — compare against `src/discovery.rs`)
- [ ] Content-Type is `application/json`; pretty-printing or compact, both fine
- [ ] `GET /.well-known/webhook-jwks.json` → 200 JSON; exactly one RSA key with `kty=RSA`, `use=sig`, `alg=RS256`, `kid` set
- [ ] Trigger an account-deletion event (re-use the §7.8 setup) → captured webhook payload is a compact JWS; header has `typ=secevent+jwt`, `alg=RS256`, `kid` matches the JWKS
- [ ] Decoded payload is a RFC 8417 SET: `iss`, `iat`, `jti`, `events` map with the RISC `account-purged` URI, `subject_type=email` or `iss-sub`, `subject.sub` matches the deleted identity id
- [ ] Signature verifies against the JWKS key (use `jose`, `step crypto jwt verify`, or equivalent)
- [ ] OIDC `.well-known/openid-configuration` (served by Hydra at `:4444`) reachable; `issuer` matches the value Forseti advertises in `id_token`

## 10. CSRF + cookie hygiene

- [ ] `forseti_csrf` cookie set on every page that renders a form
- [ ] Cookie is `HttpOnly` + `Secure` (when `[self_].url` is https) + `SameSite=Lax`
- [ ] Replay a POST with a swapped CSRF token → 403
- [ ] Replay a POST with no cookie → 403
- [ ] Kratos forms don't carry Forseti CSRF token (Kratos owns its own)
- [ ] `active_org` signed cookie verifies properly + rejects tampered values
- [ ] **Stale CSRF token:** open a form (e.g. `/settings/profile`), then clear the `forseti_csrf` cookie in DevTools (simulating cookie rotation), submit → friendly 403/error page, not 500, no panic
- [ ] **Cross-user token swap:** log in as A in one browser, copy A's `forseti_csrf` cookie; log in as B in a second browser, replace B's `forseti_csrf` with A's value, submit a Forseti-owned POST → rejected (proves the token is session-bound, not just present)

## 10.5 Cross-cutting flow disruption

What happens when normal assumptions (single tab, stable session, no back button) break. These only surface under real interaction — drive each via Chrome MCP, ideally with `gif_creator` capturing the multi-tab cases.

- [ ] **Session timeout mid-edit:** open `/settings/profile`, edit a field but don't submit; from a second browser logged in as admin, revoke that session via `/admin/sessions`; submit the original form → redirected to `/login?return_to=…`, no 500, no silent drop, no half-applied write
- [ ] **Logout tab A, action tab B:** open the dashboard in two tabs as the same identity; logout in tab A; click any destructive POST in tab B (revoke session, delete authorized app, etc.) → bounced cleanly to `/login`, no half-applied state, no panic
- [ ] **Back button after destructive POST:** delete a client at `/admin/clients` (or revoke a session) → hit Back → prior page is NOT re-submitted; ideally lands on a redirected post-action page; if the form re-shows, a second submit produces a friendly conflict, not a duplicate action / 500

## 11. Internal listener (`[internal].bind`, default `127.0.0.1:8081`)

- [ ] Public listener (`:3000`) refuses `/internal/audit/kratos` (404)
- [ ] Internal listener accepts `POST /internal/audit/kratos` with the configured bearer token
- [ ] Missing / wrong bearer → 401
- [ ] No CSRF cookie set on internal responses (no form rendering on this listener)

## 12. Observability + ops

- [ ] `tracing` JSON logs render structured events with `error =` fields when something fails
- [ ] No panics under any normal flow
- [ ] Graceful shutdown: `SIGTERM` to Forseti → both listeners stop, in-flight requests finish, exit clean
- [ ] Worker shuts down cleanly with the rest of the process

## 13. Docs sanity

After any flow change, walk `docs/dev/flows.md` and re-check the relevant section's mermaid diagram + handler `file:line` references. The doc is the source of truth — keep it honest.

- [ ] `docs/dev/flows.md` — diagrams still match handler behaviour
- [ ] `docs/operator-guide.md` — config snippets reflect current `config.example.toml`
- [ ] `docs/integration-guide.md` — OIDC discovery URLs + claims still accurate

---

## Reporting

For each section, capture:

* What worked
* What broke (file:line of the suspect handler)
* Audit rows that did / didn't land (`sqlite3 forseti.db "SELECT action, actor_email, target_kind, target_id FROM audit_events ORDER BY rowid DESC LIMIT 10;"`)
* Any side-findings (copy issues, missing pretty-fields, console errors)

Don't auto-fix anything in a single review pass — record findings, hand back to the operator.
