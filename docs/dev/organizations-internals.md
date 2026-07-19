# Organizations — internals

Contributor reference for the multi-org implementation: data model, membership/auto-join, invites, the active-org cookie, OIDC claim construction, and the commercial gate call sites. For the operator/owner/buyer-facing description of the feature, see [`commercial/organizations.md`](../commercial/organizations.md).

## No single-tenant branch

There's no synthetic "single-tenant" code path. The migration seeds a real `organizations` row with `id = "default"` (the `DEFAULT_ORG_ID` constant, `src/orgs/mod.rs:40`), and *every* code path queries that row the same way it would query any other. OSS users get a fully working org with one tenant; a Business license just lets them `INSERT` more rows. Nothing special-cases the single-org case.

The whole feature is gated behind one license flag — `Feature::Orgs` (`src/commercial/license.rs:15-17`). See [Commercial gate](#commercial-gate) below.

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
| `access_mode` | TEXT. `"internal"` (default) or `"external"`. See [Access modes](#access-modes). |

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

Two roles only — `owner` and `member` (`Role` enum, `src/orgs/mod.rs:48-52`), stored as lowercase strings. Role strings round-trip through one vocabulary shared by form parsing, DB storage, and OIDC claim emission (`Role::as_str` / `FromStr`). Unknown strings fail closed — `is_owner_role()` logs a warning and returns `false` (`src/orgs/mod.rs:84-92`), so a constraint bypass can't silently grant owner.

## Membership: the Default floor and the three join doors

Placement is never silent. There are exactly three ways into an org, all explicit, and one auto-managed "floor" org for people who belong to none:

1. **Invite** — any org; the accepting identity's matching address must be `verified` (kept as a deliberate control, see [Invites](#invites)).
2. **Domain auto-join** — internal orgs only, and only when the org set `domain_join_policy = auto_join`; a user with a **verified** address at an ownership-proven domain gets a profile prompt (see [Domain auto-join](#domain-auto-join-prompt-based)).
3. **Public self-serve** — external orgs only; any user can self-serve join via `/o/{slug}` → `/join/confirm` (verify-later, see below).

### The Default floor

The Default org is an auto-managed floor, not a first-request force-join. The invariant, split by operator status:

- **Allowlisted identities** (`admin.is_admin(email)`, i.e. on `admin.allowed_emails`) are always members of Default as **owner**, and are **exempt from the Default drop** — they may hold Default and tenant orgs at once (operators legitimately span both).
- **Non-allowlisted identities** are members of Default **iff** they hold zero non-default org memberships, always as **member**.

The floor is **verification-independent** — it grants nothing email-derived, so an unverified account still lands in Default. Default ownership is entirely allowlist-derived; the old "first user of an empty Default becomes owner" bootstrap is gone (it would re-fire under floor churn and promote an arbitrary user). A deployment with an empty `admin.allowed_emails` therefore has a Default with no owner — the same state in which the `/admin` panel is already inaccessible.

The Tower middleware `auto_join_default_org` (`src/orgs/middleware.rs`) runs on every request carrying a Kratos session cookie and calls `ensure_default_floor()` (`src/orgs/mod.rs`). That reads both facts it needs — is-in-Default and non-default-count — in a single capped query (`floor_membership_facts`, `src/orgs/db.rs`), then, inside one serialized transaction, inserts the Default row only if the add-condition holds (owner for allowlisted, member for a non-default-less non-allowlisted identity). Errors are swallowed and logged at `warn!`; the next request retries. The middleware also caches the `whoami` result as `CachedWhoami` so downstream extractors skip a second Kratos round-trip.

### Keeping the floor consistent on join and leave

The invariant is maintained by every join and leave path, not just the middleware:

- **Every non-default join** goes through `join_org_race_safe(db, identity_id, org_id, role, drop_default)` (`src/orgs/db.rs`): one serialized transaction that inserts the tenant row, then (for non-allowlisted identities only) deletes the Default row, insert-before-delete so a concurrent floor-add can't strand the user in both. Callers: org creation, invite finalize, the domain-join prompt, `/join/confirm`, and SAML SSO JIT-join (`src/saml/flow.rs`).
- **Genuine single leave** (`members_remove`, `src/orgs/settings_page/members.rs`) re-adds Default as member when a non-allowlisted identity drops to zero non-default orgs.
- **Identity deletion** (`remove_member_everywhere`, `src/orgs/db.rs`) is *not* a floor transition — it strips all rows and must leave no Default row (re-adding one would recreate a ghost membership for a deleted identity).
- **Org deletion** (`delete_org`) relies on the lazy floor to re-home affected members on their next request.

### Removing members / changing roles

Both live in `src/orgs/settings_page/members.rs`, owner-gated and license-gated. There's a **last-owner guard**: the app refuses to demote or remove the sole owner of any org. Note this guard is application-layer, not a DB constraint — nothing stops a direct `DELETE` of the final owner row.

When an identity is deleted, `remove_member_everywhere()` (`src/orgs/db.rs`) strips all of its memberships so no dangling rows survive.

## Active org

A user can belong to several orgs, so "which org am I acting as right now" is tracked per-browser in a **signed `forseti_active_org` cookie** (`src/orgs/cookie.rs`). It uses its own HMAC salt (`b"forseti::active_org::v1"`), distinct from the flash-cookie key, so the two never share signing material.

The cookie is never trusted on its own. `active_org()` (`src/orgs/mod.rs:137-153`) resolves the active org like this:

1. Read + verify the signed cookie. If valid **and** the identity is still a member of that org → use it.
2. Otherwise fall back to the first membership in the list.
3. Empty membership list → `None`. This is now a valid transient state: a freshly-registered identity can hit a handler before the Default floor middleware has added its row, so callers must tolerate `None` (claim emission suppresses the `org` claim rather than defaulting).

The cookie is only *written* by `POST /orgs/switch` (`src/orgs/settings_page/switch.rs`) — a CSRF-protected target behind the nav dropdown that re-verifies membership before emitting the `Set-Cookie`. Default TTL is 30 days (`[orgs].active_org_cookie_ttl_seconds`).

Downstream apps can also pin the active org at auth time with the `organization_id=<ref>` parameter on the `/oauth2/auth` URL, where `<ref>` is either the canonical org id or its slug (`org_by_ref()`, `src/orgs/db.rs`, tries id first, then slug). What happens next depends on the subject's membership:

- **Member of the pinned org** — the active-org cookie is set for it at `/oauth/login`, so the `org`/`groups` claims and the nav match without a manual `/orgs/switch`.
- **Non-member, org is `external` + `public_login_enabled = 1`** — `/oauth/login` redirects to a one-time `/join/confirm` interstitial instead of accepting the login challenge outright, so the app-scoped context is offered before the flow completes. See [Join interstitial for the OAuth pin](#join-interstitial-for-the-oauth-pin) below.
- **Non-member, org is `internal` or has public login disabled, or the ref doesn't resolve** — the pin is silently ignored (no error UX), same as before: a stale link from a deactivated member, a typo, or a private org just falls through to plain login.

The pin is resolved again, independently, when the consent challenge is finalized — see [Claim resolution is point-in-time](#claim-resolution-is-point-in-time) below.

### Join interstitial for the OAuth pin

Placement can't happen on the Hydra consent Allow (Hydra remembers consent, so Allow fires at most once and never again for a returning or skip-consent user) and it can't happen silently at `/oauth/login` (that's a GET; writing membership off a CSRF-forgeable request is the same class of bug the rest of this doc treats as a hard invariant elsewhere). So the pin is anchored on membership state instead, via a real interstitial page:

1. `resolve_pin_action()` (`src/oauth/login.rs`) decides, for a signed-in subject with an unresolved pin: already a member → `PinAction::Cookie`; eligible non-member → `PinAction::Interstitial`; anything else (unknown ref, ineligible org, or a declined pin) → `PinAction::Ignore`. No write happens in this function or anywhere in `/oauth/login`.
2. On `PinAction::Interstitial`, `/oauth/login` redirects to `/join/confirm?org=<slug>&return_to=<self /oauth/login URL, re-carrying login_challenge>`, plus `&client_id=<hydra client id>` when Hydra's login request carries one — advisory, front-channel, used only for audit attribution, never trusted for access control.
3. `/join/confirm` (`src/orgs/join.rs`) is the same two-step GET-then-POST used by the [public self-serve join flow](#public-self-serve-join-flow); reaching it from the OAuth pin vs. from `/o/{slug}` differs only in whether `client_id` and `return_to` are present. The POST is the **only** place that calls `join_org_race_safe()` for this path — `/oauth/login` and `finalize_consent` never write membership. `tests/oauth_no_membership_write.rs` asserts this statically (greps `src/oauth/login.rs` / `src/oauth/consent.rs` for the join call).
4. On success, the join is audited as `org.member.added` with `via=oauth_interstitial` and the advisory `client_id` in metadata (vs. `via=self_serve` for a direct `/o/{slug}` join), then the browser is bounced back to `return_to`, which resumes the OAuth flow at `/oauth/login` — this time the subject is a member, so `resolve_pin_action()` returns `PinAction::Cookie` and the login challenge is accepted normally.
5. **Decline** — the confirm page also renders a "continue without joining" link built by `decline_target()`: the sanitized `return_to` with `&skip_org_join=1` appended. It's a stateless, forgeable marker by design (it can only *decline* a join, never force one); `/oauth/login` reads it and short-circuits `resolve_pin_action()` to `Ignore` so the user isn't re-prompted on the same round trip. Login then completes with no membership change and no `org`/`groups` claims for that org.

Private orgs, and external orgs with public login disabled, are never eligible for the interstitial — `is_signup_eligible()` (`src/orgs/join.rs`, shared with `/o/{slug}`) is the single source of truth for that check, so the pin and the public landing page can't drift on what counts as "joinable".

Both `/join/confirm` and `/oauth/consent` carry a strict `frame-ancestors 'none'` CSP plus `X-Frame-Options: DENY`, applied by a dedicated middleware layer (`strict_frame_for_sensitive`, `src/app.rs`) that runs outermost and overrides the operator's global `[security].frame_ancestors`/`x_frame_options` setting. Both are CSRF-protected state-changing POSTs, so they must never be framable regardless of what the operator allows elsewhere.

### Claim resolution is point-in-time

`finalize_consent()` (`src/oauth/consent.rs`) re-resolves the pin independently of `/oauth/login`, via the same `org_by_ref()` id-or-slug lookup, to a canonical org id. If the subject is (by then) a member of that org, `org`/`groups` claims are pinned to it for this token; otherwise they fall back to the active-org cookie, then the first membership, then are suppressed entirely if the subject has none. This resolution happens once, at authorize/consent time — a later join, leave, or role change doesn't retroactively change an already-issued token; the subject gets the current picture on their next authorization.

## Invites

Full flow in `src/orgs/invite.rs`. Owner-only, and (for named orgs) license-gated.

1. **Mint** — an owner POSTs the members page (`/settings/organization/members/invite` for Default, `/settings/organizations/{slug}/members/invite` for named). The handler checks owner role + CSRF + the license gate, inserts a 48-hex token row, and sends the invite email via Forseti's own SMTP transport (`src/mailer.rs`) — **not** Kratos's courier.
2. **Accept** — the invitee opens `GET /invite/accept?token=…`, which branches three ways:
   - anonymous → bounce through Kratos registration with `return_to=/invite/finalize`,
   - signed in with the matching email → render a CSRF-protected accept form,
   - signed in with the *wrong* email → show a "sign out and retry" CTA.
3. **Finalize** — `POST /invite/accept` runs `finalize_invite_txn()`: insert the membership (idempotent on duplicate), then `UPDATE … WHERE accepted_at IS NULL`. Zero rows affected → the token was already redeemed (`AlreadyAccepted`). `GET /invite/finalize` has no side effects — it just bounces back to the accept GET.

Only **verified** emails can accept — the finalize path checks the identity's Kratos `verifiable_addresses`. Invite TTL defaults to 7 days (`[orgs].invite_ttl_days`); the bound `{ org_id, email, role, expires_at }` lives on the row, so a leaked URL can't be replayed after the row expires.

## Branding validation

The branding page (`src/orgs/settings_page/branding.rs`) is owner-only and validates inputs hard:

- **`logo_url`** — ≤ 2048 chars, must parse as an HTTPS URL, and must pass `validate_webhook_url()` (the same SSRF blocklist used for webhooks — rejects loopback, RFC 1918, and cloud-metadata IPs). Reusing that validator keeps the private-IP blocklist DRY.
- **`support_email`** — a single well-formed address (one `@`, non-empty local + domain, ≤ 254 chars, no control/whitespace).

When set, both override the global `[brand]` config — the active org's logo renders in the nav header and its support email surfaces on help/error pages.

## Org-scoped admin

Org owners get a **scoped slice of the admin surface** for their own org, without holding the Forseti-wide admin privilege (the config-driven `admin.allowed_emails` allowlist).

Reached by appending `?org=<slug>` to an admin URL. The `RequireAdminScoped` extractor (`src/extractors.rs:315`) reads that query param and resolves it via `resolve_admin_scope()` (`src/orgs/mod.rs:260-284`) into an `AdminScope`:

- **`AdminScope::Forseti`** — no `?org` param. The full operator surface, gated by the email allowlist + AAL2, exactly as before.
- **`AdminScope::Org { id, slug }`** — `?org=<slug>` resolved to an org the caller *owns*. Every query is then filtered to that org's rows. Unknown slug → `UnknownOrg`; not an owner → `NotOwner`.

Surfaces that honour the org scope (each filters its listing to the scoped org): clients (`src/admin/clients/`), identities, sessions, audit, and webhooks.

## OIDC claim construction

All three scopes surface org-derived data into OIDC tokens. All three are built in `build_id_token_claims()`, and the membership fetch is skipped entirely unless the grant includes one of them, so OSS deployments and plain `openid email` grants pay nothing.

| Scope | Claim |
|---|---|
| `org` | A single object for the **active** org: `{ id, slug, role, name }`. The active org is resolved from the `forseti_active_org` cookie at consent time, falling back to the first membership. |
| `orgs` | An array of `{ id, slug, role, name }` for **every** membership, capped at 32 entries (`ORGS_CLAIM_CAP`, `src/orgs/nav.rs`). |
| `groups` | A flat array of the user's **team** slugs in the active org (sourced from `org_teams` via `teams::group_slugs_for_identity`), for downstream group-to-role mapping. Sorted, de-duped, capped at 200 (`GROUPS_CLAIM_CAP`) with a `groups_truncated` flag, present-but-empty when the user has no teams. |

Entries with an unparseable role are dropped with a `warn!` rather than emitting a malformed claim. These claims also appear at the `userinfo` endpoint. The app-facing reference lives in the [integration guide's scope reference](../integration-guide.md#scope-reference).

## Commercial gate

Multi-org is the `Feature::Orgs` capability (wire name `"orgs"`, `src/commercial/license.rs:31`). The runtime check is a single wait-free `ArcSwap` pointer-load, `LicenseHandle::feature(Feature::Orgs)` (`src/commercial/mod.rs`), which returns a `FeatureStatus` (`src/commercial/license.rs:128-140`):

- **`Allowed`** — active license that includes `"orgs"`. Proceed.
- **`GraceReadOnly`** — license past expiry but inside the fixed 30-day grace window (`commercial::GRACE_DAYS`): reads stay accessible, hard writes (create org, invite to a named org) bail.
- **`Locked`** — no license, license missing the feature, or past grace. Render the upsell page.

Every org **write** path funnels through one helper, `gate_orgs_feature_or_upsell()` (`src/extractors.rs:356`), and **every gate short-circuits when `org_id == DEFAULT_ORG_ID`** — so the Default org is always fully usable in OSS. Gate call sites:

- `src/orgs/settings_page/mod.rs` — `require_org_owner_with_license()` (writes) and `require_org_license()` (reads).
- `src/orgs/settings_page/list_create.rs` — the create form is shown inline only when `Allowed` **and** under quota; the create POST re-checks before inserting.
- `src/orgs/invite.rs` — inviting to a named org (Default-org invites are OSS).

### The `max_orgs` cap

The license blob carries an optional `max_orgs` (`src/commercial/license.rs:83`): `None` = unlimited, `Some(n)` = hard cap. Enforced by `org_cap_allows(cap, current)` (`src/commercial/license.rs:67-69`) against a live `count_orgs()`. With no license the effective cap is `Some(0)` (`list_create.rs:62`), so the create path is closed and only the seeded Default org survives.

## Teams and the POSIX surface

Teams are an **org-domain** concept, first-class and single-copy. They are *not* `posix_groups`, and nothing is mirrored or synced into POSIX state: there is no `sync_org_groups` and no `org`-kind group rows. The POSIX resolver reads team membership directly at request time. This replaces the earlier "mirror org memberships into posix_groups" model entirely.

### Data model

Two tables, mirrored across `migrations/sqlite/` and `migrations/postgres/`, diesel definitions in `src/schema.rs:205-225`. CRUD lives in `src/orgs/teams.rs` (module carries `#![allow(dead_code)]` while the settings surface is wired incrementally over phases 2-4).

#### `org_teams`

| Column | Notes |
|---|---|
| `id` | TEXT PK. UUIDv4. Teams are referenced everywhere by this uuid, never by gid or name (no gid-reuse hazard on rename/delete). |
| `org_id` | TEXT. Owning org. `(org_id, slug)` is unique, so a name collides only within one org. |
| `name`, `slug` | human label + `slugify()`'d identifier. |
| `gid` | NULLABLE Integer. Allocated lazily the first time the team is attached to a host scope (`find_or_create_team_gid`, `src/posix/db.rs:182`); NULL until then. |
| `parent_id` | NULLABLE self-reference. Reserved for nested teams; unused this phase. |
| `created_at`, `created_by` | provenance. |

#### `org_team_members`

| Column | Notes |
|---|---|
| `team_id`, `identity_id` | composite PK. `identity_id` is the Kratos identity UUID. |
| `source` | TEXT. `"manual"` today; reserved for rule-derived membership later. |
| `added_at` | provenance. |

Cascades: `delete_team` removes the team, its members, and any `host_allowed_groups` rows referencing it in one transaction (`src/orgs/teams.rs:115`). Member-removal and identity-delete purge team rows via `remove_identity_from_org_teams` / `remove_identity_from_all_teams` (`src/orgs/teams.rs:227,250`).

### Hosts and scope

A host belongs to exactly one org (`host_enrollments.org_id`, `src/schema.rs:242`); that org is the outer access boundary. A host's scope is a set of team uuids in `host_allowed_groups.team_id` (`src/schema.rs:255`; the table keeps its legacy name but references team uuids, not posix_groups). Two cases, decided per request by `resolve_scope` (`src/posix/resolver.rs:107`):

- **Whole-org** (empty allowed-team set) — every provisioned member of the host's org is visible. Whole-org is an **access predicate**, not an enumerable group: no org-wide Unix group is emitted, and `group` enumeration lists only those org teams that carry a gid.
- **Team-scoped** (one or more allowed teams) — visibility and enumeration are both restricted to provisioned members of those teams (any-of-N). Each scoped team is emitted as a Unix group.

The single source of truth for "is this account visible on this host" is `scope::account_visible_on_host` (`src/posix/scope.rs:21`), shared by the resolver and the device-auth path so they can't drift. The host's org is asserted `== team.org_id` inside the db helpers (`is_team_member_provisioned`, `team_by_gid_in_org`), so a cross-org team can never widen visibility.

### Read-time resolution

There is no provisioned-membership cache or projection. The resolver computes the provisioned subset on every request by joining team/org membership against `posix_accounts(enabled = 1)` (`accounts_in_org` / `accounts_in_team`, `src/posix/db.rs:281,246`). Disabling an account or removing a team membership takes effect on the next pull, with no reconciliation step. Group lookups also resolve user-private groups (UPG) by single lookup only; UPGs are never enumerated.

### gid allocation

Team gids are drawn from globally-unique, never-reused high-water-mark counters in `posix_sequences` (`src/posix/sequences.rs`). `next_in_band(band, base)` takes and advances one row per band (`"uid"`, `"user_gid"`, `"team_gid"`) inside a transaction, so a freed gid is never reclaimed: reuse would silently reassign on-disk/backup file ownership to a different team across hosts. Bands are bounded disjoint intervals configured by `[posix].group_gid_base` / `group_gid_size` (and the user uid/gid bands); `PosixConfig::validate_bands()` (`src/config.rs:261`) rejects overlapping user-gid and team-gid bands, and it runs at startup in `src/app.rs:84` so a mis-banded config fails the boot rather than colliding at provision time.

### Access vs. visibility coupling

Scoping a host to a team is, deliberately, also a *visibility* grant: members of a host-scoped team can see each other as members of that Unix group on the host, not just authenticate. The team-attach UI should treat "add this team to a host" as "these members can see each other here", not merely "these members can log in". The web-directory counterpart of this coupling is the `same_group` member-visibility policy described next.

### Teams management UI

Team CRUD + membership lives at `/settings/organization/teams` (`src/orgs/settings_page/teams.rs`), with the usual two-route twin set: the Default org under `/settings/organization/teams` and named orgs under `/settings/organizations/{slug}/teams` (`src/orgs/settings_page/mod.rs:65,118`). Both resolve through the same handlers; the `slug` (`None` for Default) is the only difference.

The surface is **owner + `Feature::Orgs`**, enforced by `require_team_admin` (`src/orgs/settings_page/teams.rs:63`): it runs `require_org_owner` first (so a non-owner gets a `403`, not the upsell) and then `gate_orgs_feature_or_upsell`. The explicit license gate matters because **teams are commercial everywhere**, including the Default org. The members page uses `require_org_owner_with_license`, which short-circuits the gate for `DEFAULT_ORG_ID`; teams must not, so the gate is called directly here rather than going through that helper.

Routes (all CSRF-protected Forseti-owned POSTs; each re-checks `require_team_admin`):

| Route | Handler | Audit action |
|---|---|---|
| `GET …/teams[?team=<id>]` | `teams` → `render_teams` | — |
| `POST …/teams` | `teams_create` | `org.team.created` |
| `POST …/teams/{team_id}/rename` | `teams_rename` | `org.team.renamed` |
| `POST …/teams/{team_id}/delete` | `teams_delete` | `org.team.deleted` |
| `POST …/teams/{team_id}/members` | `teams_member_add` | `org.team.member_added` |
| `POST …/teams/{team_id}/members/{identity_id}/remove` | `teams_member_remove` | `org.team.member_removed` |

`GET …/teams?team=<id>` selects a team and drives the membership panel: `render_teams` lists all teams via `list_teams_with_counts` and, when a team is selected, splits the org roster into current members vs. addable members using `team_member_ids` (`src/orgs/teams.rs:145,162`). Adds are restricted to existing org members — `teams_member_add` rejects an `identity_id` with no `org_role` in the org (`400`). The audit actions are the `ORG_TEAM_*` constants (`src/audit/mod.rs:175-179`) targeting `target_kind::TEAM` (create/rename/delete) or `target_kind::IDENTITY` (member add/remove). The rendered page is `Cache-Control: private, no-store`.

Team **gids are not allocated at create time** — `create_team` leaves `gid` NULL. A gid is drawn lazily the first time the team is attached to a host scope (`find_or_create_team_gid`), so a team that's only ever used for `same_group` web visibility never consumes a gid band slot. See [gid allocation](#gid-allocation) above.

### Host enrollment and org selection

Host enrollment (`src/admin/hosts.rs`) is **Forseti-tier only** (`RequireAdmin`: session + AAL2 + `admin.allowed_emails`); it does not honour the `?org=<slug>` org-scoping convention. The enroll form (`new`/`issue`) presents an org `<select>` plus every org's teams grouped under their org name (`load_orgs_and_teams`, `team_groups`); the no-JS form renders all groups at once and the POST validates the submitted `team_ids` against the chosen `org_id`, rejecting any team that doesn't belong to it.

A host belongs to exactly one org, chosen at enrollment and **immutable thereafter**. The edit form (`edit`/`update`) renders the org name read-only and never reads an `org_id` off the form: `update` resolves the host's org from `host_org_id` (the source of truth) and validates the submitted teams against *that* org's teams, so a tampered form can't move the host or scope it to a foreign org's team. The team scope therefore always follows the host's own org. Both `issue` and `update` allocate gids for the chosen teams (`find_or_create_team_gid`) before writing `host_allowed_groups` via `set_host_allowed_team_ids`. Empty team set → whole-org host.

## Access modes

Every org carries an `access_mode` column, modelled by the `AccessMode` enum (`src/orgs/mod.rs`) with two variants today (`Internal`, `External`) and room for a future `customer` variant (Model 2) without a schema change. `parse_access_mode()` **fails closed to `Internal`** on any unknown string, mirroring `parse_access_mode`'s siblings elsewhere in the module (`is_owner_role`, `parse_visibility`) — an unrecognised value never opens self-serve. The Default org can never be `External` (`require_external_mode_writable` hard-rejects it regardless of caller).

### Switching to external

Flipping a licensed, non-Default org to `External` (`orgs::db::set_access_mode`) runs `apply_external_defaults()` (`src/orgs/db.rs`) in the same call site, which sets two defaults in one update: `member_visibility = admins_only` and `public_login_enabled = 1`. Both the overview mode-change path (`src/orgs/settings_page/overview.rs::access_mode_save`) and the create-form path (`src/orgs/settings_page/list_create.rs::orgs_create`) call this pair and both audit the transition as `org.access_mode.changed` — the create path adds `via=create` to its metadata so the two call sites are distinguishable in the audit feed.

### Hard enforcement: `visibility_allowed`

`visibility_allowed(mode, policy)` (`src/orgs/settings_page/members.rs`) is the single predicate gating the member-visibility POST: for `External` orgs, only `admins_only` is accepted; `Internal` orgs accept any policy. It's a pure function, exhaustively unit-tested in-module (`visibility_allowed_tests`). Two audit paths cover this surface:

- **Successful change** — `members_visibility` logs `org.visibility_changed` on any accepted policy write (unconditional on mode).
- **Blocked loosening attempt** — when `visibility_allowed` rejects the requested policy, `members_visibility` logs `org.visibility_changed` at `warning` severity, marked `.failed(...)`, with `attempted_visibility` in the metadata, **before** returning the unchanged `400`. This is a rejected-write audit trail, not a state change.

### Public self-serve join flow

`GET /o/{slug}` (`src/orgs/public_landing.rs::landing`) renders the themed landing page for any slug; `register_href()` binds the CTA to `/join/confirm?org=<slug>` only when `resolve_signup_org()` (`src/orgs/join.rs`) resolves the slug live — `External` **and** `public_login_enabled = 1`, re-checked at render time. Unknown/internal/disabled slugs fall through to the byte-identical global-theme fallback (anti-enumeration).

The page also renders a **sign-in CTA** (`login_href()`, `/login?organization_id=<slug>`) whenever the slug resolved to *any* branded org — including internal ones — since signing in doesn't carry the signup eligibility restriction: it just threads the slug into the login pin described above, so a returning member lands pre-selected into the org they already belong to. Unknown/disabled slugs keep `login_href` at `None`, preserving the anti-enumeration fallback.

`/join/confirm` (`src/orgs/join.rs`) is a two-step GET-then-POST:

1. `GET /join/confirm?org=<slug>` re-resolves the org (TOCTOU-safe against a mode/toggle flip since the landing page rendered), and branches on session state: anonymous → CTA into Kratos registration with `return_to=/join/confirm?org=<slug>`; already a member → redirect `/`; otherwise → CSRF-protected confirm form.
2. `POST /join/confirm` re-resolves the org again, re-checks membership, then writes the row via `join_org_race_safe(.., Role::Member, drop_default)` (`src/orgs/db.rs`) — so the join also drops the Default floor for non-allowlisted users — and logs `org.member.added` with `via=self_serve`.

**No verification gate (by design).** Public self-serve joins immediately on explicit CSRF-confirmed consent; there is no "verified email required" step. This is deliberate: verification only gates placement that is *derived from the email* (domain auto-join). Public self-serve derives membership from an explicit action for a specific org, not from the email, so the email is not the credential and verification adds nothing here. Operators who want verified-first public onboarding force it at the Kratos layer (`show_verification_ui` on the registration flow); see the [operator guide](../operator-guide.md#external-access-mode-public-self-serve).

### Domain auto-join (prompt-based)

Internal orgs can admit users whose **verified** email is at a domain the org has proven it owns — but the admission is an explicit prompt, never a silent join, and the org must opt in.

- **Policy toggle.** `organizations.domain_join_policy` (`DomainJoinPolicy`, `src/orgs/mod.rs`) is `invite_only` (default) or `auto_join`. `parse_domain_join_policy()` **fails closed to `invite_only`** on any unknown string, so an unrecognised value never opens the door. Owners set it on the domains settings page (internal, non-Default only). External orgs ignore it — public orgs are open to all by design, so a domain prompt on top would be redundant.
- **Eligibility.** `lookup_proven_org_for_email()` (`src/orgs/mod.rs`) returns an org only when: the address domain is not freemail, the org is internal and non-Default, a `verified_at` ownership row exists for the domain, and `domain_join_policy = auto_join`. All checks fail closed.
- **The prompt.** The dashboard (`src/dashboard.rs`) computes, from a **verified** session address (matched with `eq_ignore_ascii_case`), whether such an org exists that the user is not already in, and renders a CSRF-protected "join `<Org>`?" prompt (`resolve_prompt`, `src/orgs/domain_prompt.rs`).
- **The join.** `POST /orgs/domain-join` (`src/orgs/domain_prompt.rs`, in the CSRF router group) re-resolves the org from the session email at POST time (TOCTOU-safe — a form-supplied slug must match), re-checks the address is verified off the live session, then joins via `join_org_race_safe(.., Role::Member, drop_default)` and audits `via=domain_autojoin`. There is no user-controlled `return_to` (redirects to `/`).

This is why scenario "unverified corporate registrant" resolves cleanly: the floor puts them in Default while unverified; once they verify, the prompt appears and one click moves them to their company org (dropping Default).

### Rate limiting

Both `GET /o/{slug}` (`orgs::public_landing::router`) and `GET /registration` (`auth::registration_router`) are wrapped in `rate_limit::dual_window_with_global` — a per-IP pair (`[orgs].landing_ip_rate_per_*` / `[auth].registration_ip_rate_per_*`) plus a `GlobalKeyExtractor`-keyed pair (`*_global_rate_*`) that bounds total traffic even when a spoofed `X-Forwarded-For` defeats the per-IP bucket. `/registration` has no per-org dimension in its URL (the target org lives inside the opaque Kratos flow), so a per-org key extractor was declined as a third dimension — it isn't cheaply buildable there, and adding it for only one of the two routes would be inconsistent.

### CAPTCHA: deferred

No CAPTCHA gates either surface. Forseti's `/registration` is GET-only — the browser POSTs registration straight to Kratos's own public endpoint, which Forseti never sees — so a server-enforced CAPTCHA would need a blocking Kratos `before` hook, a new Forseti verify webhook, a client-side widget, and org-conditional logic across all of them. That's a multi-system integration out of proportion to this phase, and a client-side-only widget with no server-side check would be a placebo. Deferred; see the [operator guide](../operator-guide.md#external-access-mode-public-self-serve) for the operator-facing note.

## Member visibility

The member directory is gated per-org, so a tenant can decide how much its members can discover about each other. Two pieces of state plus one pure predicate.

### State

- **`organizations.member_visibility`** (`src/schema.rs:82`) — TEXT, one of `all` / `same_group` / `admins_only`, modelled by the `MemberVisibility` enum (`src/orgs/visibility.rs`). `parse_visibility()` **fails closed to `admins_only`** on any unknown string (mirrors `is_owner_role`). The migration seeds the Default org as **`admins_only`** — the safe default for the shared OSS tenant where everyone lands on the floor.
- **`organization_members.hidden_from_directory`** (`src/schema.rs:93`) — INTEGER 0/1, the per-member opt-out. A member can remove themselves from their org's directory regardless of policy.

### The predicate

`visible(policy, is_self, viewer_is_owner, viewer_is_admin, target_hidden, shares_team)` (`src/orgs/visibility.rs`) is a pure function — the single decision point, unit-tested in-module. Order of precedence:

1. `is_self || viewer_is_owner || viewer_is_admin` → **visible** (these override the opt-out too — an owner/admin must always be able to see and manage every member).
2. else `target_hidden` → **hidden** (the opt-out trumps `all`/`same_group`).
3. else by policy: `all` → visible; `admins_only` → hidden; `same_group` → visible **iff** `shares_team`.

`viewer_is_admin` MUST already fold in the AAL2 check at the call site — both call sites compute it as `admin.is_admin(email) && session_satisfies_aal2(session)`. The async wrapper `member_visible_to_in_org()` resolves the policy (`org_by_id`), viewer-owner (`org_role`), target opt-out (`find_member`), and shared-team (`teams::shared_team`) inputs, then applies `visible()`; an unknown org fails closed to not-visible.

### Surface 1 — the members page

`render_members` (`src/orgs/settings_page/members.rs`) is a **membership gate + server-side filter**:

- **Membership gate** — a signed-in user who is neither a member of the org nor a Forseti admin-at-AAL2 gets a `404` (not 403 — an outsider can't even confirm the org exists). For NON-default orgs the `require_org_license` upsell gate fires *before* this check.
- **Filter** — every candidate row runs through `visible(...)`; non-visible members are dropped before render. For `same_group` the co-team set is fetched once (`teams::co_team_member_ids`) and probed per row. Non-owners see a one-line policy statement matching the active policy; owners see every row plus a hidden-badge and the visibility `<select>`.

### Surface 2 — `/users/{id}`

`show_profile` (`src/profiles/view.rs`) gates on a **disjunction across shared orgs**: the page renders iff `is_self || admin_aal2 || the target is visible in at least one org the viewer shares` (each shared org tested via `member_visible_to_in_org`). Not visible anywhere → `404`, decided *before* the Kratos lookup so a hidden-but-existing target is indistinguishable from a nonexistent one (no status/timing oracle). The shared-org **chips** are derived from the *visible* orgs only, never the raw membership intersection, so a restrictive (`admins_only`) org the viewer happens to share doesn't leak as a chip. Unlike the members page, this surface has **no license gate**.

### Profile teams/hosts

Past the visibility gate, `show_profile` (`src/profiles/view.rs`) renders two further sections, each behind its own feature gate and audience rule. The audience for the two differs on purpose:

| Section | Feature gate | self | AAL2 global admin | org owner (of a shared+visible org) | plain member |
|---|---|---|---|---|---|
| Teams | `Feature::Orgs` | all teams | all teams | teams in orgs the viewer **owns** only | hidden |
| Reachable hosts | `Feature::LinuxAuth` | reachable hosts | reachable hosts | **hidden** | hidden |

Owners deliberately do **not** see the host section, only teams. The host set is an enumeration oracle for another org's infrastructure, so it's restricted to the subject (self) and the Forseti-wide AAL2 admin. Both feature gates accept `Allowed | GraceReadOnly` (a read-only surface stays visible during the grace window).

Hosts come from the read-only `hosts_reachable_by` projection (`src/posix/db.rs`): a set-based intersection of the subject's orgs + teams against per-host scopes (whole-org hosts always reach; team-scoped hosts need a team hit), gated on an *enabled* POSIX account. It's enumeration-only, never an auth decision — the resolver keeps its own O(1) `is_*_provisioned` checks. Teams come from `teams::teams_for_identity_any_org`, filtered to owned orgs for the owner audience.

The AAL2 admin POSIX detail page (`/admin/posix/{id}`, `src/admin/posix.rs`) mirrors both: the same team list and the same `hosts_reachable_by` projection, so an operator's view of an account matches what the account can reach.

### Owner controls and guardrails

- `members_visibility` (owner-only, license-gated for named orgs) sets the policy. It refuses `same_group` with a `400` when the org has **no teams** — otherwise the policy would silently hide every peer from every non-owner (no team to share).
- `members_hidden` (no license gate) flips the opt-out: an **owner may toggle anyone**, a non-owner may toggle **only their own** row (else `403`).

Both surfaces set `Cache-Control: private, no-store` — the rendered output now varies by viewer and per-org visibility, so it must never be cached.

### Tests

The `visible()` predicate has exhaustive unit tests in `src/orgs/visibility.rs`. Integration coverage lives in `tests/integration/member_visibility.rs`, driven over HTTP against the surfaces that aren't license-gated in the unlicensed suite: the `/users/{id}` predicate (all / same_group / admins_only / owner-override / opt-out / chip filter) against seeded non-default orgs, the `admins_only` filter on the Default members page, and the opt-out toggle routes. Members-list behaviour on named (license-gated) orgs and the `same_group`-needs-a-team `400` are deferred to the licensed e2e bucket (the integration harness has no license-activation path); see the header comment in that file.

## Related

- [Organizations (operator/buyer guide)](../commercial/organizations.md) — the customer-facing description of this feature.
- [Flow internals](flows.md) — sequence diagrams and handler references.
- [Enterprise SAML SSO flow](flows.md#enterprise-saml-sso-commercial) — SAML internals; orgs are the tenancy unit each connection attaches to.
