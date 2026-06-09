# Organizations

Forseti's multi-tenant model: organizations, membership, invites, branding, the org-scoped admin surface, and the OIDC `org` / `orgs` claims.

For operators deploying Forseti, see [`operator-guide.md`](./operator-guide.md). For apps consuming org claims over OIDC, see [`integration-guide.md`](./integration-guide.md). For the underlying flows, see [`dev/flows.md`](./dev/flows.md).

## The shape of it

Forseti is multi-org from the ground up — but OSS ships exactly **one** org, and the commercial license is what unlocks the rest.

The trick is that there's no synthetic "single-tenant" branch. The migration seeds a real `organizations` row with `id = "default"` (the `DEFAULT_ORG_ID` constant, `src/orgs/mod.rs:40`), and *every* code path queries that row the same way it would query any other. OSS users get a fully working org with one tenant; a Business license just lets them `INSERT` more rows. Nothing special-cases the single-org case.

| | OSS (unlicensed) | Business (`orgs` feature) |
|---|---|---|
| Default org | ✅ full read/write | ✅ |
| Additional orgs | ❌ create blocked | ✅ up to `max_orgs` |
| Invites to Default org | ✅ | ✅ |
| Invites to named orgs | ❌ | ✅ |
| Org-scoped admin (`?org=…`) | n/a (only Default exists) | ✅ owners see their own org |
| `org` / `orgs` OIDC claims | Default-only | full membership |

The whole feature is gated behind one license flag — `Feature::Orgs` (`src/commercial/license.rs:15-17`). See [Commercial licensing](#commercial-licensing) below.

## Data model

Three tables, defined once and mirrored across `migrations/sqlite/` and `migrations/postgres/` (single initial migration `20260517000000_initial_schema`). Diesel definitions in `src/schema.rs:72-106`.

### `organizations`

| Column | Notes |
|---|---|
| `id` | TEXT PK. Opaque. Default org is the literal `"default"`. |
| `slug` | TEXT UNIQUE. URL-safe, lowercase. Auto-generated via `slugify()` (`src/orgs/db.rs`). |
| `name` | TEXT. Human label. |
| `logo_url` | TEXT NULL. Per-org branding; overrides global `[brand]` when set. |
| `support_email` | TEXT NULL. Per-org branding. |
| `created_at`, `created_by` | provenance. |

The Default row is inserted by the migration itself (`migrations/postgres/20260517000000_initial_schema/up.sql`), so it always exists on a fresh install.

### `organization_members`

| Column | Notes |
|---|---|
| `org_id`, `identity_id` | composite PK. `identity_id` is the Kratos identity UUID. |
| `role` | TEXT, `CHECK (role IN ('owner', 'member'))`. **Only two roles exist.** |
| `added_at`, `added_by` | provenance. |

Indexed on both `identity_id` and `org_id`.

### `organization_invites`

| Column | Notes |
|---|---|
| `token` | TEXT PK. 48-char hex (24 random bytes). Opaque — the row is the authoritative state, not a signed token. |
| `org_id`, `email`, `role` | what the invite grants. `role` carries the same CHECK constraint. |
| `invited_by`, `created_at`, `expires_at` | mint metadata. |
| `accepted_at`, `accepted_by` | stamped atomically on accept; NULL until redeemed. |

Indexed on `org_id` and `email`.

## Roles

Two roles only — `owner` and `member` (`Role` enum, `src/orgs/mod.rs:48-52`), stored as lowercase strings:

- **owner** — runs governance: rename the org, edit branding, invite/remove members, change roles, delete the org, and access the [org-scoped admin surface](#org-scoped-admin).
- **member** — read-only for org-scoped resources.

Role strings round-trip through one vocabulary shared by form parsing, DB storage, and OIDC claim emission (`Role::as_str` / `FromStr`). Unknown strings fail closed — `is_owner_role()` logs a warning and returns `false` (`src/orgs/mod.rs:84-92`), so a constraint bypass can't silently grant owner.

## Membership

Membership is **automatic on the first authenticated request** — users never "join" the Default org by hand.

A Tower middleware, `auto_join_default_org` (`src/orgs/middleware.rs`), runs on every request carrying a Kratos session cookie. It calls `ensure_default_membership()` (`src/orgs/mod.rs:188-216`), which does a cheap indexed `has_any_membership` probe and, if the user has no row yet, runs the race-safe `auto_join_default_txn()`.

Role assignment happens *inside* that transaction so two concurrent first-registrations can't both observe the table as empty (`pick_default_role`, `src/orgs/mod.rs:225-237`):

1. Email on `admin.allowed_emails` → **owner** (admin emails get governance in Default).
2. First user on a fresh install (Default has zero members) → **owner**.
3. Everyone else → **member**.

Errors are swallowed and logged at `warn!` — a transient DB hiccup on the membership probe must not break the request that triggered it. The next request retries; the cost is one extra indexed lookup until the row lands.

The middleware also caches the `whoami` result as `CachedWhoami` in request extensions, so extractors downstream don't pay a second Kratos round-trip.

### Removing members / changing roles

Both live in `src/orgs/settings_page/members.rs`, owner-gated and license-gated. There's a **last-owner guard**: the app refuses to demote or remove the sole owner of any org. Note this guard is application-layer, not a DB constraint — nothing stops a direct `DELETE` of the final owner row.

When an identity is deleted, `remove_member_everywhere()` (`src/orgs/db.rs`) strips all of its memberships so no dangling rows survive.

## Active org

A user can belong to several orgs, so "which org am I acting as right now" is tracked per-browser in a **signed `forseti_active_org` cookie** (`src/orgs/cookie.rs`). It uses its own HMAC salt (`b"forseti::active_org::v1"`), distinct from the flash-cookie key, so the two never share signing material.

The cookie is never trusted on its own. `active_org()` (`src/orgs/mod.rs:137-153`) resolves the active org like this:

1. Read + verify the signed cookie. If valid **and** the identity is still a member of that org → use it.
2. Otherwise fall back to the first membership in the list.
3. Empty membership list → `None` (shouldn't happen — registration auto-joins Default).

The cookie is only *written* by `POST /orgs/switch` (`src/orgs/settings_page/switch.rs`) — a CSRF-protected target behind the nav dropdown that re-verifies membership before emitting the `Set-Cookie`. Default TTL is 30 days (`[orgs].active_org_cookie_ttl_seconds`).

Downstream apps can also pin the active org at auth time with the `organization_id=<id>` parameter on the `/oauth2/auth` URL — see [Active-org selection in the integration guide](./integration-guide.md#active-org-selection-org-scope). If the user isn't a member of the named org, the param is silently ignored (no error UX), so a stale link from a deactivated member doesn't break login.

## Invites

Full flow in `src/orgs/invite.rs`. Owner-only, and (for named orgs) license-gated.

1. **Mint** — an owner POSTs the members page (`/settings/organization/members/invite` for Default, `/settings/organizations/{slug}/members/invite` for named). The handler checks owner role + CSRF + the license gate, inserts a 48-hex token row, and sends the invite email via Forseti's own SMTP transport (`src/mailer.rs`) — **not** Kratos's courier.
2. **Accept** — the invitee opens `GET /invite/accept?token=…`, which branches three ways:
   - anonymous → bounce through Kratos registration with `return_to=/invite/finalize`,
   - signed in with the matching email → render a CSRF-protected accept form,
   - signed in with the *wrong* email → show a "sign out and retry" CTA.
3. **Finalize** — `POST /invite/accept` runs `finalize_invite_txn()`: insert the membership (idempotent on duplicate), then `UPDATE … WHERE accepted_at IS NULL`. Zero rows affected → the token was already redeemed (`AlreadyAccepted`). `GET /invite/finalize` has no side effects — it just bounces back to the accept GET.

Only **verified** emails can accept — the finalize path checks the identity's Kratos `verifiable_addresses`. Invite TTL defaults to 7 days (`[orgs].invite_ttl_days`); the bound `{ org_id, email, role, expires_at }` lives on the row, so a leaked URL can't be replayed after the row expires.

## Branding

Each org carries `logo_url` and `support_email`. When set, they override the global `[brand]` config — the active org's logo renders in the nav header and its support email surfaces on help/error pages.

The branding page (`src/orgs/settings_page/branding.rs`) is owner-only and validates inputs hard:

- **`logo_url`** — ≤ 2048 chars, must parse as an HTTPS URL, and must pass `validate_webhook_url()` (the same SSRF blocklist used for webhooks — rejects loopback, RFC 1918, and cloud-metadata IPs). Reusing that validator keeps the private-IP blocklist DRY.
- **`support_email`** — a single well-formed address (one `@`, non-empty local + domain, ≤ 254 chars, no control/whitespace).

## Org-scoped admin

Org owners get a **scoped slice of the admin surface** for their own org, without holding the Forseti-wide admin privilege (which is the config-driven `admin.allowed_emails` allowlist).

Reached by appending `?org=<slug>` to an admin URL. The `RequireAdminScoped` extractor (`src/extractors.rs:315`) reads that query param and resolves it via `resolve_admin_scope()` (`src/orgs/mod.rs:260-284`) into an `AdminScope`:

- **`AdminScope::Forseti`** — no `?org` param. The full operator surface, gated by the email allowlist + AAL2, exactly as before.
- **`AdminScope::Org { id, slug }`** — `?org=<slug>` resolved to an org the caller *owns*. Every query is then filtered to that org's rows. Unknown slug → `UnknownOrg`; not an owner → `NotOwner`.

Surfaces that honour the org scope (each filters its listing to the scoped org): clients (`src/admin/clients/`), identities, sessions, audit, and webhooks. So an org owner can manage their org's OAuth clients and read their org's audit trail without seeing anyone else's.

## OIDC claims

Two scopes surface org membership into OIDC tokens. Both are built in `build_id_token_claims()` (`src/oauth/consent.rs:569-624`), and the membership fetch is skipped entirely unless the grant actually includes one of them (`src/oauth/consent.rs:485`) — OSS deployments and plain `openid email` grants pay nothing.

| Scope | Claim |
|---|---|
| `org` | A single object for the **active** org: `{ id, slug, role, name }`. The active org is resolved from the `forseti_active_org` cookie at consent time, falling back to the first membership. |
| `orgs` | An array of `{ id, slug, role, name }` for **every** membership, capped at 32 entries (`ORGS_CLAIM_CAP`, `src/orgs/nav.rs`). Request this for a tenant-picker UI. |

Entries with an unparseable role are dropped with a `warn!` rather than emitting a malformed claim. These claims also appear at the `userinfo` endpoint. The full app-facing reference — including the `organization_id=` auth param and example tokens — lives in the [integration guide's scope reference](./integration-guide.md#scope-reference).

## Commercial licensing

Multi-org is the headline `Feature::Orgs` capability (wire name `"orgs"`, `src/commercial/license.rs:31`). The runtime check is a single wait-free `ArcSwap` pointer-load, `LicenseHandle::feature(Feature::Orgs)` (`src/commercial/mod.rs`), which returns a `FeatureStatus` (`src/commercial/license.rs:128-140`):

- **`Allowed`** — active license that includes `"orgs"`. Proceed.
- **`GraceReadOnly`** — license past expiry but inside the grace window (`grace_days`, default 14): reads stay accessible, hard writes (create org, invite to a named org) bail.
- **`Locked`** — no license, license missing the feature, or past grace. Render the upsell page.

Every org **write** path funnels through one helper, `gate_orgs_feature_or_upsell()` (`src/extractors.rs:356`), and **every gate short-circuits when `org_id == DEFAULT_ORG_ID`** — so the Default org is always fully usable in OSS. Gate call sites:

- `src/orgs/settings_page/mod.rs` — `require_org_owner_with_license()` (writes) and `require_org_license()` (reads).
- `src/orgs/settings_page/list_create.rs` — the create form is shown inline only when `Allowed` **and** under quota; the create POST re-checks before inserting.
- `src/orgs/invite.rs` — inviting to a named org (Default-org invites are OSS).

### The `max_orgs` cap

The license blob carries an optional `max_orgs` (`src/commercial/license.rs:83`): `None` = unlimited, `Some(n)` = hard cap. Enforced by `org_cap_allows(cap, current)` (`src/commercial/license.rs:67-69`) against a live `count_orgs()`. With no license the effective cap is `Some(0)` (`list_create.rs:62`), so the create path is closed and only the seeded Default org survives.

## Configuration

The `[orgs]` table (`src/config.rs:777-799`; documented in `config.example.toml`):

```toml
[orgs]
active_org_cookie_ttl_seconds = 2592000   # 30 days — lifetime of the signed active-org cookie
invite_ttl_days = 7                        # how long a minted invite stays redeemable
```

Both have defaults, so the table is optional. `max_orgs` is **not** an operator config knob — it comes from the license blob itself.

The org feature has no dedicated CLI verbs; invites simply expire in place (no prune subcommand). Identity deletion fans out to `remove_member_everywhere()` automatically.
