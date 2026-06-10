# Licensed e2e specs

Specs in this bucket assume the portal has an **active** license row in
`portal.db` (no expiry, or expiry in the future). Activate
`tests/fixtures/license/active.blob` via `/admin/license` before running
`make e2e-licensed`.

Surfaces to cover: org create + member-invite happy paths, license-settings
page in "Active" state, feature-gated admin actions returning the real
handler instead of the upsell.

`a-saml-sso.spec.ts` covers enterprise SAML SSO end-to-end (connection
create at `/admin/saml`, JIT login via mock-saml, blocked-unverified) —
it additionally needs the `saml` compose profile (`make stack-up-saml`),
`[saml]` in the portal config, and the admin env vars, and skips otherwise.

## CI

The `e2e-licensed` job in `.github/workflows/ci.yml` runs this bucket
(including the SAML suite) on the GitHub runner. The licensed bucket needs an
active `saml` + `orgs` license, and the fixture blob is `.gitignored` by
design — so the job **mints a fresh one in CI** from the issuer signing key,
rather than committing a blob.

How it works:

1. Brings the playground up with the SAML profile
   (`make stack-up COMPOSE="docker compose" COMPOSE_PROFILE_FLAGS="--profile saml"`),
   seeds the admin, builds Forseti.
2. Checks out the sibling issuer repo (`ory-frontend-license`, the same minter
   `make license-fixtures` shells out to), decodes the secret key into
   `keys/private.bin`, and runs the issuer CLI's `issue` subcommand for a
   **lifetime** `business` blob with `--feature orgs --feature saml`. Output
   goes to `tests/fixtures/license/active.blob` — the path `make e2e-licensed`
   reads. The decoded key file is deleted as soon as the blob is signed.
3. Activates the license by seeding the singleton `forseti_license` row
   directly: boot once so diesel runs the migrations (creates the table),
   stop, `INSERT OR REPLACE` the row with the minted blob, boot again.
   `commercial::store::load` re-derives every field from the verified blob, so
   only the `blob` column has to be real. This is the same row `/admin/license`
   would write — it skips only the CSRF/AAL2 admin POST, not the verification.
4. Asserts `license: active` appears in the boot log (a key mismatch falls back
   to `Unlicensed` with a warning — caught here, not mid-suite), then runs
   `make e2e-licensed`.

### Required secrets

Franz must add these in **GitHub repo settings → Secrets and variables →
Actions** for the job to run. Until they exist, the job's
`if: ${{ secrets.FORSETI_LICENSE_ISSUER_KEY != '' }}` guard skips it (so forks
and external PRs never go red on a missing secret):

| Secret | What it is |
| --- | --- |
| `FORSETI_LICENSE_ISSUER_KEY` | **base64** of the 32-byte Ed25519 private key — the private half of the keypair whose public half is committed at `src/commercial/pubkey.bin`. Produce it with `base64 -w0 keys/private.bin` against the issuer repo's key. |
| `FORSETI_LICENSE_ISSUER_REPO` | `owner/repo` of the private issuer repo (e.g. `franzgeffke/ory-frontend-license`). |
| `FORSETI_LICENSE_ISSUER_TOKEN` | A PAT (or fine-grained token / deploy key) with read access to that private repo, so the runner can check it out and build the minter. |

### Security notes

- The signing key lives only in CI secrets, never in the tree. The minted blob
  is short-lived (one CI run), written under `tests/fixtures/license/`, and
  never committed — `.gitignore` keeps that directory out of git and is not
  weakened for this.
- The key must match `src/commercial/pubkey.bin`. If you ever rotate the issuer
  keypair, re-commit the new `pubkey.bin` **and** update
  `FORSETI_LICENSE_ISSUER_KEY` in the same change, or the boot-time
  verification fails and the job's "license is live" check trips.
- The blob is minted as a lifetime license so it never expires mid-run; the
  expired-bucket fixture is out of scope for this job.
