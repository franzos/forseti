# Organizations

> Commercial feature — additional organizations require a license that includes the `orgs` capability. The default org is always free. See [Commercial features](./index.md) for the licensing model.

Organizations let you run Forseti for more than one tenant: named orgs, per-org membership and invites, per-org branding, an org-scoped admin slice, and the OIDC `org` / `orgs` claims so your apps can do org-aware authorization.

Forseti is multi-org from the ground up. OSS ships exactly **one** org — the always-free Default org — and a commercial license unlocks the rest. There's no separate "single-tenant mode": the Default org is a real org and behaves like any other, so OSS users get a fully working single-tenant deployment with nothing stubbed out.

On the app side, [Stackpit](https://github.com/franzos/stackpit) (a self-hosted, single-binary Sentry alternative) is a first-class consumer of these claims: it maps your Forseti orgs and their owner/member roles straight into its own per-org access model, so SSO users land in the right org with the right role automatically. If you want to see the org claims doing real work in a downstream app, that's the reference pairing.

For app developers consuming org claims over OIDC, see the [integration guide](../integration-guide.md). For the implementation details, see [`dev/organizations-internals.md`](../dev/organizations-internals.md).

## Free vs paid

| | OSS (unlicensed) | Business (`orgs` feature) |
|---|---|---|
| Default org | ✅ full read/write | ✅ |
| Additional orgs | ❌ create blocked | ✅ up to the license cap |
| Invites to Default org | ✅ | ✅ |
| Invites to named orgs | ❌ | ✅ |
| Org-scoped admin | n/a (only Default exists) | ✅ owners manage their own org |
| `org` / `orgs` OIDC claims | Default-only | full membership |

The maximum number of orgs comes from your license, not from config. Unlicensed deployments are capped at the single Default org; a license raises the cap to whatever it grants.

## Roles

Every membership is one of two roles:

- **Owner** — runs governance for the org: rename it, edit branding, invite and remove members, change member roles, delete the org, and use the [org-scoped admin surface](#org-scoped-admin) for it.
- **Member** — belongs to the org and gets it in their OIDC claims, but has read-only access to org-scoped resources.

## Membership

Placement is never silent. There are three explicit ways into an org, plus one automatic "home" org for people who belong to none:

- **Invite** — into any org; the invitee must have a **verified** email (see [Invites](#invites)).
- **Domain auto-join** — an internal org that has proven it owns an email domain and opted into auto-join will offer anyone with a **verified** address at that domain a one-click prompt to join. No invite needed, but it is a prompt, not a silent join.
- **Public self-serve** — an external org's public page (`/o/<slug>`) lets anyone register and join it directly (see [Access modes](#access-modes)).

The **Default org is the home floor**: a user who belongs to no other org is automatically a member of it, and is moved out of it once they join a real org (and back in if they later leave their last one). Anyone whose email is on the operator's admin allowlist is always an **owner** of Default; everyone else is a **member**. If the allowlist is empty, Default has no owner (the same state in which the operator admin panel is inaccessible).

A user can belong to several orgs at once and switch between them from the org dropdown in the nav.

### When is a verified email required?

Only where membership is **derived from the email itself**. Domain auto-join trusts your email's domain, so it requires that specific address to be verified. Invite acceptance also requires verification (a deliberate belt-and-braces control, since an invite link is a secret that could leak). Public self-serve and the Default home floor do **not** require verification — you registered for that specific org explicitly, or it is just your catch-all home, so the email is not the credential. Operators who want stricter public onboarding can force email verification at the identity layer.

## Invites

Owners add people to a named org by inviting them:

1. The owner opens the org's members page and invites an email address, choosing the role (owner or member) the invite grants.
2. Forseti emails the invitee a link. Invites expire after a configurable window (7 days by default).
3. The invitee opens the link. If they're not signed in, they're walked through registration first; if they're signed in with the wrong email, they're told to sign out and retry. Otherwise they confirm and join.

Only **verified** email addresses can accept an invite — the invitee must have confirmed their email with Forseti before they can join. A leaked or forwarded invite link can't be replayed once it's expired or already been accepted.

## Teams

A team is a named subset of an org's members. Teams are a commercial feature everywhere, including the Default org: managing them requires a license with the Organizations capability.

Owners manage teams from the org's **Teams** page (`/settings/organization/teams`, or `/settings/organizations/<slug>/teams` for a named org). From there an owner can create a team, rename or delete it, and add or remove org members. Only people who already belong to the org can be added to its teams.

Teams do two things:

- **Member visibility.** With the `same_group` member-visibility policy, members can see each other in the directory only when they share at least one team. Teams are how you carve up who sees whom.
- **Host scoping.** When you enroll a Linux host, you pick which org it belongs to and then scope it either to the whole org (any member may log in) or to one or more of that org's teams (only members of those teams may log in, and they're grouped together on the host). A host belongs to exactly one org, fixed at enrollment: you can change its team scope later, but not its org.

Deleting a team removes it from any host that was scoped to it; the host falls back to whatever scope remains (whole-org if it had no other teams).

A member's public profile page surfaces the teams they belong to, so people can see how they're organized. Owners viewing another member's profile see only the teams that sit in orgs they own. For Linux hosts, a member can see which hosts their own account can reach, and a Forseti operator can see the same for any account from the admin surface; org owners deliberately can't enumerate another org's reachable hosts.

## Branding

Each org can carry its own **logo** and **support email**. When set, these override the global brand: the org's logo shows in the nav header and its support email appears on help and error pages, so each tenant sees their own branding.

The logo must be an **HTTPS URL** (private, loopback, and cloud-metadata addresses are rejected). The support email must be a single well-formed address.

## Access modes

Every non-Default org is **internal** by default: invite-only, no public presence. An owner can switch a named org to **external** (a licensed, Orgs-feature capability — the Default org can never be external), which unlocks self-serve public signup:

- A public landing page at `/o/<slug>`, themed with the org's branding.
- A `/join/confirm` flow: a visitor registers (or signs in) and explicitly confirms joining as a **member** — no invite needed.

Switching to external automatically applies two defaults: the member directory is set to **administrators-only** and public login is turned on. The administrators-only directory is **hard-enforced** for external orgs — an owner cannot loosen it to a more open visibility policy while the org stays external, and an attempt to do so is rejected and recorded in the audit log. Switching back to internal lifts the restriction.

Both the public landing page and the registration flow are per-IP and globally rate-limited (see the [operator guide](../operator-guide.md#external-access-mode-public-self-serve) for the specifics and their limitations).

## Org-scoped admin

An org owner gets a scoped slice of the admin surface for **their own org** without being a Forseti-wide operator. That lets a tenant owner manage their org's OAuth clients, identities, sessions, and audit trail — filtered to that org, never anyone else's — while the global operator surface stays gated behind the operator's admin allowlist.

Owners reach their org's admin view from the org settings; the Forseti operator continues to see the full, unfiltered surface.

## OIDC claims

Two OIDC scopes surface org membership to your apps:

- **`org`** — a single object describing the user's currently active org: its id, slug, role, and name.
- **`orgs`** — an array of every org the user belongs to, each with id, slug, role, and name. Request this when an app needs a tenant picker.

Both also appear at the `userinfo` endpoint. Apps that don't request either scope get nothing extra, so plain `openid email` logins are unaffected. The full app-facing reference — including how to pin the active org at login and example tokens — is in the [integration guide's scope reference](../integration-guide.md#scope-reference).

**A membership claim is not identity proof.** A user can be in the Default home org or in an open external org without a verified email, so relying apps must never treat an `org` claim (least of all `org.id = "default"`) as evidence of who the user is, and must never authorize on `email` without checking `email_verified`. See the [integration guide](../integration-guide.md#membership-and-verification-are-not-the-same).

## Enterprise SSO

Organizations are also the tenancy unit for commercial **SAML SSO**: each org can carry one operator-managed SAML connection, giving its members a `/sso/{org-slug}` login URL against your corporate IdP. Org owners see a read-only "Enterprise SSO" status line on their org's overview page; the operator manages connections. See [Enterprise SAML SSO](./saml.md).

## Configuration

The optional `[orgs]` table tunes two timeouts (both have defaults, so the table can be omitted):

```toml
[orgs]
active_org_cookie_ttl_seconds = 2592000   # 30 days — how long the active-org selection is remembered per browser
invite_ttl_days = 7                        # how long a minted invite stays redeemable
```

The maximum number of orgs (`max_orgs`) is **not** a config knob — it comes from the license blob. There are no org-specific CLI commands: invites simply expire in place, and deleting an identity automatically removes all of its memberships.

## Related

- [Commercial features](./index.md) — licensing model and the free/paid boundary.
- [Enterprise SAML SSO](./saml.md) — per-org SSO against a corporate IdP.
- [Integration guide](../integration-guide.md#scope-reference) — consuming `org` / `orgs` claims in your apps.
- [Organizations internals](../dev/organizations-internals.md) — contributor reference (data model, gate call sites).
