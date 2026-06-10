# Organizations

> Commercial feature — additional organizations require a license that includes the `orgs` capability. The default org is always free. See [Commercial features](./index.md) for the licensing model.

Organizations let you run Forseti for more than one tenant: named orgs, per-org membership and invites, per-org branding, an org-scoped admin slice, and the OIDC `org` / `orgs` claims so your apps can do org-aware authorization.

Forseti is multi-org from the ground up. OSS ships exactly **one** org — the always-free Default org — and a commercial license unlocks the rest. There's no separate "single-tenant mode": the Default org is a real org and behaves like any other, so OSS users get a fully working single-tenant deployment with nothing stubbed out.

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

Users never have to "join" the Default org by hand — the first time someone signs in, Forseti adds them to it automatically. The first user on a fresh install (and anyone whose email is on the operator's admin allowlist) becomes an **owner** of Default; everyone else joins as a **member**.

Membership in any *other* org happens by invitation only. A user can belong to several orgs at once and switch between them from the org dropdown in the nav.

## Invites

Owners add people to a named org by inviting them:

1. The owner opens the org's members page and invites an email address, choosing the role (owner or member) the invite grants.
2. Forseti emails the invitee a link. Invites expire after a configurable window (7 days by default).
3. The invitee opens the link. If they're not signed in, they're walked through registration first; if they're signed in with the wrong email, they're told to sign out and retry. Otherwise they confirm and join.

Only **verified** email addresses can accept an invite — the invitee must have confirmed their email with Forseti before they can join. A leaked or forwarded invite link can't be replayed once it's expired or already been accepted.

## Branding

Each org can carry its own **logo** and **support email**. When set, these override the global brand: the org's logo shows in the nav header and its support email appears on help and error pages, so each tenant sees their own branding.

The logo must be an **HTTPS URL** (private, loopback, and cloud-metadata addresses are rejected). The support email must be a single well-formed address.

## Org-scoped admin

An org owner gets a scoped slice of the admin surface for **their own org** without being a Forseti-wide operator. That lets a tenant owner manage their org's OAuth clients, identities, sessions, and audit trail — filtered to that org, never anyone else's — while the global operator surface stays gated behind the operator's admin allowlist.

Owners reach their org's admin view from the org settings; the Forseti operator continues to see the full, unfiltered surface.

## OIDC claims

Two OIDC scopes surface org membership to your apps:

- **`org`** — a single object describing the user's currently active org: its id, slug, role, and name.
- **`orgs`** — an array of every org the user belongs to, each with id, slug, role, and name. Request this when an app needs a tenant picker.

Both also appear at the `userinfo` endpoint. Apps that don't request either scope get nothing extra, so plain `openid email` logins are unaffected. The full app-facing reference — including how to pin the active org at login and example tokens — is in the [integration guide's scope reference](../integration-guide.md#scope-reference).

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
