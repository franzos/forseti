# Real-Linux NSS/PAM/sshd harness

Proves the `forseti-unix` client actually works on a stock Linux distro: a
Debian container with the client installed resolves and logs in a
Forseti-provisioned POSIX account through the real glibc NSS → daemon →
resolver chain, with sshd's `AuthorizedKeysCommand` and `pam_mkhomedir` in the
loop. This is the **foreign-distro / M4 path** — the honest "someone else's
glibc and init" case. Guix-System wiring (nscd-dlopen, the Shepherd service,
`pam-root-service-type`) is verified separately by a marionette VM test
(future); this harness does not cover it.

## What it asserts

1. `getent passwd <user>` resolves the Forseti account with the correct
   uid/gid/home/shell — the NSS module loads and resolves.
2. `id <user>` works.
3. `ssh -i <key> <user>@localhost` succeeds via `AuthorizedKeysCommand`, landing
   in a `$HOME` that `pam_mkhomedir` created.
4. **Fail-open:** stop the daemon → local `getent passwd root` still works,
   `getent passwd <user>` returns empty (no hang), and `ssh` fails fast.

## Topology

- Forseti runs **on the host** (`cargo run`), internal resolver on
  `0.0.0.0:8081` (`config.toml` `[internal] bind`). The playground
  (Kratos/Hydra/Postgres) runs via the usual compose.
- The test container reaches Forseti at `host.containers.internal:8081` via
  `podman run --add-host=host.containers.internal:host-gateway`.
- The client is built **inside the container** against Debian's glibc — the
  foreign-distro case, not the Guix build.

## Prereqs (same convention as `make e2e`)

The harness does **not** bring the stack up. Have both running first:

```bash
podman-compose -f infra/docker-compose.yml up -d
guix shell -m manifest.scm -- cargo run        # serves :3000 and the :8081 resolver
```

Wait for `http://localhost:3000/healthz`.

## One command

`make` isn't on PATH outside a guix shell on this host, so:

```bash
guix shell make -- make test-linux-host
```

That target: seeds `forseti.db` (host enrollment + POSIX account + ssh key,
ephemeral keypair), builds the image, runs the container with the privkey
mounted and host_id/secret/user in env, captures the exit code, then unseeds
and removes the container. Exit 0 means all four assertions passed.

## Pieces

| File | Runs | Does |
|---|---|---|
| `Containerfile` | build | stage1 builds `forseti-unix/` (Debian glibc); stage2 = Debian + sshd + PAM + nscd, the 3 artifacts installed, NSS/PAM/sshd wired, `forseti` user created |
| `entrypoint.sh` | container | runtime dirs + config, start nscd/daemon/sshd, run the 4 assertions (PASS/FAIL per step, non-zero on any failure) |
| `seed.sh` | host | ephemeral ed25519 key; random secret; `sha256_hex(secret)`; `INSERT OR REPLACE` the rows via `guix shell sqlite`; write `.seed.env` |
| `unseed.sh` | host | delete the seeded rows + ephemeral keys |

## Helper targets

```bash
guix shell make -- make linux-test-build     # just build the image
guix shell make -- make linux-test-seed      # just seed forseti.db
guix shell make -- make linux-test-unseed    # just clean up
```

## Notes / gotchas

- **nscd is used** (mirroring Guix's nscd-dlopen path): the entrypoint creates
  `/run/nscd`, starts `nscd`, and invalidates `passwd`/`group` before each
  lookup. If nscd won't stay up it falls back to direct glibc loading and
  prints `USE_NSCD=0` — still a valid exercise of the `.so`, just without the
  cache layer. The run log states which path was used (`USE_NSCD=1` is the
  verified default here).
- **uid/gid must be inside the container's mapped id range.** Under rootless
  podman the user namespace maps gid 0 and one `/etc/subgid` block (typically
  `0..65535`); a gid *outside* it makes the kernel reject sshd's
  `setgroups()` at login with `EINVAL` — login fails even though `getent`/`id`
  resolve fine. So the defaults are `TEST_UID=60001`/`TEST_GID=60002` (high
  enough to dodge Debian's local accounts, low enough to stay mapped), not the
  1000000+ production base. For a rootful run, or with an extended `--gidmap`,
  override `TEST_UID`/`TEST_GID` to the real range.
- **PAM account stack.** Debian's `common-account` runs `pam_unix`, which
  returns `user_unknown` for an NSS-only account and then trips `pam_deny`
  ("Access denied by PAM account configuration"). The image prepends
  `account sufficient pam_succeed_if.so uid >= 1000 quiet` to `/etc/pam.d/sshd`
  so NSS-resolved users clear the account phase; pubkey-only auth via
  `AuthorizedKeysCommand` is the real gate. A dedicated forseti PAM account
  module is M2 work.
- **The host secret is hashed as plain `sha256_hex(secret)`** — single-pass
  SHA-256, lowercase hex — matching the server's `hash_token`. Not bcrypt, not
  salted.
- **Unscoped host** (`allowed_gid` NULL): resolves any enabled account by name
  and serves its `authorized_keys`; directory *enumeration* returns empty.
  The harness seeds a `user`-kind primary-group row alongside the account
  (real provisioning does this too) so the primary gid resolves by name.
- The seeded ssh key + env file under `infra/linux-test/.seed-keys/` and
  `.seed.env` are gitignored and regenerated each run.
