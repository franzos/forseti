# Commercial Features

Forseti's OSS core is everything you need to run a self-service identity portal in front of Kratos and Hydra. A commercial license unlocks a small set of features aimed at teams running Forseti for more than one tenant or wiring it into a corporate identity provider.

This page is the buyer/operator overview: what the license unlocks, how the offline licensing model works, and where the free/paid line sits. For the operator and integrator detail of each feature, follow the links below.

## What a license unlocks today

Two features are gated behind a commercial license. Both ship and work today:

- **[Organizations](./organizations.md)** — run Forseti for more than one tenant: named orgs beyond the always-free default, per-org membership and invites, per-org branding, an org-scoped admin slice, and the OIDC `org` / `orgs` claims for org-aware authorization.
- **[Enterprise SAML SSO](./saml.md)** — per-org SAML login (`/sso/{org-slug}`) against a customer's corporate identity provider, with just-in-time provisioning and verified-email linking. Your apps keep doing plain OIDC.

Nothing else is gated. Other capability names you might see referenced (SCIM provisioning, SIEM streaming, bulk admin) are **planned, not shipped** — they don't work yet, so don't plan around them.

## How licensing works

Licensing is **offline**. Forseti never calls out to validate a license; verification is fully offline. There's no license server and no outbound call at runtime — which matters if you self-host in a network that can't (or won't) reach the internet, including air-gapped deployments.

A license is a small signed file. You activate it by pasting the blob at **`/admin/license`**. Forseti verifies the signature itself, reads the customer name, expiry, the list of enabled features, and an optional cap on the number of orgs, then stores it. Each feature is unlocked independently — a license that includes Organizations but not SAML unlocks exactly that.

### Active, grace, and locked

A license can carry an expiry (lifetime licenses never expire). Forseti checks the license against the clock at startup and whenever you activate one, putting each licensed feature into one of three states:

| State | What it means operationally |
|---|---|
| **Active** | Licensed and before expiry. The feature works normally — reads and writes. |
| **Grace** | Past expiry but still inside the grace period. The feature goes **read-only**: existing data stays accessible and existing logins (including SAML SSO) keep working, but new writes — creating another org, minting an invite to a named org, creating or toggling a SAML connection — are blocked. |
| **Locked** | No license, the license doesn't include this feature, or the grace period has passed. The feature shows an upgrade prompt; the gated surface is unavailable. |

The grace period is a **safety net**: if a renewal is forgotten, your production deployment doesn't break the moment the license expires — existing users keep logging in, and you can't accidentally lose access to data you already created. You just can't add new paid resources (new orgs, SAML connections) until you renew, and then it hard-locks. The window is a fixed **30 days** of read-only operation after expiry and is **not operator-configurable**.

The feature set, expiry, and org cap come from the signed license itself, not from config — editing `config.toml` can't widen what a license grants.

## Free vs paid

The boundary is deliberately simple:

| | OSS (unlicensed) | Commercial |
|---|---|---|
| Default org | Full read/write — always free | Full read/write |
| Additional orgs | Create blocked | Up to the license cap |
| Org branding, invites to named orgs | n/a (only Default exists) | Yes |
| Org-scoped admin | n/a | Owners manage their own org |
| `org` / `orgs` OIDC claims | Default-only | Full membership |
| SAML SSO (`/sso/{slug}`) | Unavailable | Per-org connections |

OSS ships exactly one real default org and every code path treats it like any other org — there's no stubbed single-tenant mode. The license simply lets you add more orgs and switch SAML on, so an unlicensed deployment is always a fully working single tenant.

## The licensing split

Forseti is dual-licensed:

- The **OSS core** — everything that runs Forseti as a single-tenant portal — is **AGPL-3.0-or-later**. See [`LICENSE`](../../LICENSE).
- The **commercial gate** — the code that enforces the paid feature flags — is the proprietary, source-available **Forseti Commercial License 1.0**. See [`LICENSE-COMMERCIAL`](../../LICENSE-COMMERCIAL).

The gate is source-available so you can audit exactly what it does (it's an offline signature check, nothing more), but it isn't AGPL — running the paid features requires a license. The README's [License section](../../README.md#license) is the canonical statement.
