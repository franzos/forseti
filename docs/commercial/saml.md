# Enterprise SAML SSO

> Commercial feature — requires a license that includes the `saml` capability. See [Commercial features](./index.md) for the licensing model.

Per-org SAML login at `/sso/{org-slug}`. Forseti doesn't speak SAML itself — it drives a [SAML Jackson / Ory Polis](https://www.ory.com/docs/polis) bridge that you deploy alongside it. Jackson handles assertion validation, signatures, and IdP quirks; Forseti talks plain OAuth2 to Jackson and owns identity resolution, org membership, and session establishment.

## Prerequisites

- A commercial license that includes the `saml` feature (activate at `/admin/license`).
- A deployed Jackson / Ory Polis instance reachable by both browsers and the Forseti server.
- Kratos with the recovery `link` method enabled — Forseti establishes the post-SSO session via an admin-minted recovery (magic) link, and Kratos refuses to mint one without:

```yaml
selfservice:
  methods:
    link:
      enabled: true
```

Without this, every SSO login fails at the final step. The playground's `infra/kratos/kratos.yml` already has it.

## `[saml]` configuration

```toml
[saml]
jackson_url = "https://sso.example.com"
jackson_internal_url = "http://jackson:5225"  # optional server-to-server override
jackson_api_key = "change-me"                 # one of Jackson's JACKSON_API_KEYS
client_secret_verifier = "change-me"          # Jackson's CLIENT_SECRET_VERIFIER
identity_schema_id = "default"                # Kratos schema for JIT identities
sp_entity_id = "https://saml.boxyhq.com"      # SP entity id; must match Jackson's samlAudience
```

- `jackson_url` — browser-facing base URL of the Jackson instance. Also used to derive the ACS URL shown on `/admin/saml`.
- `jackson_internal_url` — optional container-network address for server-to-server calls (token, userinfo, connection CRUD). Defaults to `jackson_url`.
- `jackson_api_key` — must match an entry in Jackson's `JACKSON_API_KEYS`; authorises connection create/delete against Jackson's admin API.
- `client_secret_verifier` — must match Jackson's `CLIENT_SECRET_VERIFIER`; it's the OAuth2 client secret paired with the dynamic per-org client id.
- `identity_schema_id` — the Kratos identity schema used for JIT-provisioned identities. Default `"default"`.
- `sp_entity_id` — optional; the SP entity id shown on `/admin/saml` and handed to the customer's IdP admin. Defaults to `https://saml.boxyhq.com`. Override it to match Jackson's `samlAudience` if you've changed that — otherwise the page shows a stale value and assertion-audience checks fail.

The table is strictly opt-in: leave it out and the `/sso/*` routes aren't even mounted.

## Deploying Jackson

The playground service in `infra/docker-compose.yml` (profile `saml`, brought up via `make stack-up-saml`) is the reference for the minimum env:

```yaml
environment:
  - EXTERNAL_URL=http://127.0.0.1:5225        # browser-facing URL — match [saml].jackson_url
  - JACKSON_API_KEYS=dev-jackson-api-key      # match [saml].jackson_api_key
  - CLIENT_SECRET_VERIFIER=dev-client-secret-verifier  # match [saml].client_secret_verifier
  - DB_ENGINE=sql
  - DB_TYPE=postgres
  - DB_URL=postgres://jackson:secret@postgres:5432/jackson?sslmode=disable
  - NEXTAUTH_SECRET=dev-nextauth-secret-32-chars-xx
  - NEXTAUTH_URL=http://127.0.0.1:5225
  - NEXTAUTH_ADMIN_CREDENTIALS=admin@example.com:secret
  - BOXYHQ_NO_ANALYTICS=1
```

For production hardening (TLS, DB choice, secrets), follow the [Ory Polis deployment docs](https://www.ory.com/docs/polis) — Forseti has no opinion beyond the URLs and the two shared secrets. One playground caveat: `make stack-down` does **not** remove the `saml`-profile containers; remove them explicitly if you need a truly clean slate.

## Creating a connection

Connections are operator-managed at `/admin/saml` (Forseti-tier admin only — org owners see a read-only status line on their org's overview page instead). One connection per org.

`/admin/saml/new` takes the org, a display name, and the IdP metadata as **either** a metadata URL **or** a raw XML paste. Jackson 26.x only fetches metadata URLs that are localhost or HTTPS — for an IdP serving plain-HTTP metadata, paste the XML.

Hand the customer's IdP admin the SP values shown on the `/admin/saml` list page:

- **ACS URL** — `{jackson_url}/api/oauth/saml`
- **SP entity id** — Jackson's `samlAudience`, default `https://saml.boxyhq.com`

## The per-org SSO URL

Each connected org gets `https://<forseti>/sso/{org-slug}` — that's the contract you give the customer. They wire it into their IdP portal, intranet bookmarks, or wherever their users start from. It's the only entry point: the flow is SP-initiated, and a login started at the IdP side won't land.

Any reason the URL can't start a login (unknown slug, no connection, connection disabled, license locked) renders one uniform "SSO unavailable" page — outsiders can't probe which orgs have SSO configured.

The **enable/disable toggle** on `/admin/saml` is an instant kill switch: disabled connections render that same neutral page. **Delete** removes the connection from Jackson first (IdP metadata included), then the local record and its email links.

## JIT provisioning and linking

Forseti resolves the assertion to a Kratos identity, in order:

0. **Durable subject link** — a prior SSO login recorded a link keyed on the stable SAML subject (NameID) for this org; reuse that identity. This is the primary key, so logins survive an email change at the IdP. Stale links (identity since deleted) are pruned automatically.
1. **Existing email link** — a legacy or bootstrap link for this (org, email) pair; reuse that identity and backfill its subject so step 0 carries it next time.
2. **Verified-email match** — an existing identity whose verified address matches is linked on first SSO login and used from then on.
3. **JIT create** — no match: a new identity is created via the Kratos admin API with the email pre-verified, under `[saml].identity_schema_id`.

Every link records the SAML subject alongside the email, so the (org, subject) pair becomes the durable key once a user has logged in at least once.

Three cases fail closed to a blocked page (no session is established):

- **Cross-org non-member** — a verified identity matches the asserted email but isn't yet a member of this org. Because Kratos identities and sessions are global, auto-linking would let one org's IdP assert another org's user's email and obtain a session as them. So a pre-existing verified identity is only linked when it's **already a member of this org**. To let an existing user sign in via a new org's SSO, pre-add them as a member first (invite or `/admin`); net-new users (no Kratos identity yet) are JIT-created and joined automatically.
- **Unverified match** — an existing identity holds the email but hasn't verified it. Linking would let an IdP assertion capture a squatted-but-unproven account. The user must verify the address (or you reap it via `unverified-prune`) before SSO works.
- **Email conflict** — the JIT create hits a 409 because an identity holds the address in a way the verified-lookup didn't surface (e.g. imported or passwordless identities). Resolve manually via `/admin/identities`.

Successful logins also ensure org membership: the identity is added to the org as `member` if not already a member.

Audit trail: `saml.login.succeeded` / `saml.login.failed` / `saml.login.blocked_unverified`, `saml.identity.jit_created` / `saml.identity.linked`, and `admin.saml.connection_created` / `_toggled` / `_deleted` for the admin surface.

## Session semantics

SSO sessions are established by redeeming a short-lived (15-minute) Kratos recovery link, so the browser ends up with a native `ory_kratos_session` cookie — no parallel session machinery. Two consequences:

- **Sessions are AAL1.** MFA happens at the corporate IdP; Forseti doesn't see it and doesn't step the session up. AAL2-gated surfaces (the admin UI) still require a second factor enrolled in Kratos.
- Users land on the dashboard, not the password-change page Kratos normally shows after recovery — Forseti intercepts that landing and bounces them home.

## Grace period

When the license is past expiry but inside the fixed 30-day grace window, SSO logins **keep working** — you don't lock a customer's workforce out over a lapsed renewal — but connection management (`/admin/saml` create/toggle/delete) goes read-only. Past grace, logins render the neutral unavailable page and the admin surface shows the upsell.

## Not in v1

- IdP-initiated logins (SP-initiated only).
- SAML Single Logout — Forseti logout ends the Kratos session; the IdP session survives.
- More than one connection per org.
- Self-serve connection management for org owners — connections are operator-managed; org owners get a read-only status line.
- **Per-connection subject override.** Linking keys on the stable SAML subject (NameID) once a user has logged in once, so email changes at the IdP are handled transparently — the durable link survives. The caveat: IdPs configured to send a transient or email-format NameID give an unstable or email-derived subject, and those connections fall back to email keying (so an email change orphans the link, as before). Pinning linking to a per-connection immutable attribute (e.g. an IdP `objectGUID`) regardless of NameID format is a future enhancement, not in v1.

## Related

- [Organizations](./organizations.md) — orgs are the tenancy unit each SAML connection attaches to.
- [Flow internals](https://github.com/franzos/forseti/blob/master/docs/dev/flows.md#enterprise-saml-sso-commercial) — sequence diagrams and handler references.
- [Integration guide](../integration-guide.md#enterprise-sso-saml) — what SAML means for downstream apps (spoiler: nothing — they keep doing OIDC).
