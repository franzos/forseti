# Contributing to Forseti

Thanks for taking the time to look. The short version:

- Forseti's AGPL-licensed core (everything outside `src/commercial/`) accepts pull requests under the Developer Certificate of Origin.
- `src/commercial/` is proprietary (source-available under `LICENSE-COMMERCIAL`). External contributions to that directory can't be accepted under the DCO and are reviewed case-by-case only if you reach out first.

## Licensing of the two halves

| Path | License | Contributions |
|---|---|---|
| Everything except `src/commercial/` | AGPL-3.0-or-later (see `LICENSE`) | Welcome under DCO sign-off |
| `src/commercial/` | Forseti Commercial License 1.0 (see `LICENSE-COMMERCIAL`) | Not accepted without prior agreement |

If your PR touches both halves, split it: the AGPL part can merge under DCO; the commercial part needs a separate conversation.

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by` line matching the author. This is the DCO 1.1 from <https://developercertificate.org/>; in plain English, signing off means:

1. You wrote the change, or you have the right to submit it under the project's open-source license, and
2. You agree it can be distributed under that license.

Add the trailer with `-s`:

```bash
git commit -s -m "fix: handle empty consent scope list"
```

That appends, verbatim:

```
Signed-off-by: Your Name <you@example.com>
```

No CLA, no signed paperwork. The sign-off is the agreement.

## What to send

- **Bug reports** — please include enough detail to reproduce against the playground stack (`make stack-up`). The `e2e-review` skill is a useful checklist.
- **Small fixes** — open a PR, sign off the commit, link any related issue. Aim for one logical change per PR.
- **Larger changes** — open an issue first to talk through the approach. Forseti has opinionated boundaries (Kratos vs Hydra vs Forseti, AGPL core vs commercial module, audit metadata rules, parallel sqlite/postgres migrations) and it's faster to surface those upfront than in review.
- **Documentation** — `docs/dev/flows.md` is the source of truth for user-facing flows. If you change a flow, update the doc in the same PR.

## House rules

- `make check` (cargo check + clippy -D warnings) must pass.
- Integration tests (`make test-integration`) must pass for changes that touch flows, handlers, or the DB layer. Tests drive a live Kratos/Hydra playground — don't mock them.
- Schema changes need parallel migrations under `migrations/sqlite/` AND `migrations/postgres/` plus a regenerated `src/schema.rs`.
- Audit metadata never carries credentials, tokens, or recovery codes; rely on `SafeMetadata` to enforce that.
- Code comments default to none. If the *why* is non-obvious (hidden constraint, subtle invariant, workaround), one short line is fine.

## Reporting security issues

Please do not open a public issue for security problems. Email mail@gofranz.com instead.
