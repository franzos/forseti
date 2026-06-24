#!/usr/bin/env bash
# Runs on the HOST. Seeds a host enrollment + a POSIX account + an SSH key
# straight into Forseti's sqlite DB so the containerized NSS/PAM/sshd harness
# has something to resolve. Idempotent (INSERT OR REPLACE).
#
# The running Forseti uses WAL, so concurrent seeding against the live DB is
# safe. We hash the host secret exactly as the server does: sha256_hex(secret)
# (plain single-pass SHA-256, lowercase hex — see oauth/register/iat::hash_token).
#
# Emits a sourceable env file (default infra/linux-test/.seed.env, gitignored)
# carrying HOST_ID/HOST_SECRET/TEST_* + the ephemeral private-key path. The make
# target consumes it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB="${1:-${FORSETI_DB:-$HERE/../../forseti.db}}"
ENV_OUT="${SEED_ENV_OUT:-$HERE/.seed.env}"
KEY_DIR="${SEED_KEY_DIR:-$HERE/.seed-keys}"

# Fixed identifiers so a reseed replaces cleanly. host_id is a stable string;
# the server treats it as opaque (lookup by id, no UUID parsing on resolve).
HOST_ID="${HOST_ID:-linux-test-host}"
HOSTNAME_LABEL="${HOSTNAME_LABEL:-linux-test}"
TEST_USER="${TEST_USER:-linuxtester}"
# uid/gid must fall inside the container's mapped id range. Under rootless
# podman that's 0..65535 (one /etc/subgid block); a gid outside it makes the
# kernel reject sshd's setgroups() with EINVAL at login — see README. 60001/
# 60002 are high enough to dodge Debian's system + first-user accounts while
# staying mapped. Override (with a matching --gidmap) for a rootful run.
TEST_UID="${TEST_UID:-60001}"
TEST_GID="${TEST_GID:-60002}"
TEST_HOME="${TEST_HOME:-/home/${TEST_USER}}"
TEST_SHELL="${TEST_SHELL:-/bin/sh}"
IDENTITY_ID="${IDENTITY_ID:-00000000-0000-0000-0000-0000linuxtest}"

[ -f "$DB" ] || { echo "seed: forseti.db not found at $DB" >&2; exit 1; }

# sqlite3 + ssh-keygen aren't on the default PATH on this Guix host; wrap as the
# Makefile does for curl/jq. No-op (bare invocation) off Guix.
if command -v guix >/dev/null 2>&1; then
  SQLITE() { guix shell sqlite -- sqlite3 "$@"; }
  KEYGEN() { guix shell openssh -- ssh-keygen "$@"; }
else
  SQLITE() { sqlite3 "$@"; }
  KEYGEN() { ssh-keygen "$@"; }
fi

# --- ephemeral keypair: regenerate fresh each run ---
mkdir -p "$KEY_DIR"
KEY="$KEY_DIR/id_ed25519"
rm -f "$KEY" "$KEY.pub"
KEYGEN -t ed25519 -N '' -C "${TEST_USER}@linux-test" -f "$KEY" >/dev/null
PUBKEY="$(cat "$KEY.pub")"

# --- random host secret + its sha256_hex ---
HOST_SECRET="${HOST_SECRET:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
SECRET_HASH="$(printf '%s' "$HOST_SECRET" | sha256sum | cut -d' ' -f1)"

NOW="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
KEY_ID="linux-test-key"

# --- insert the three rows (unscoped host: allowed_gid NULL → resolves by name)
SQLITE "$DB" <<SQL
.timeout 5000
INSERT OR REPLACE INTO host_enrollments
  (id, hostname, secret_hash, allowed_gid, force_mfa, created_by, created_at, last_seen_at)
VALUES
  ('${HOST_ID}', '${HOSTNAME_LABEL}', '${SECRET_HASH}', NULL, 0, 'linux-test-seed', '${NOW}', NULL);

INSERT OR REPLACE INTO posix_accounts
  (identity_id, username, uid, gid, gecos, shell, home_dir, enabled, created_at, updated_at)
VALUES
  ('${IDENTITY_ID}', '${TEST_USER}', ${TEST_UID}, ${TEST_GID}, '', '${TEST_SHELL}', '${TEST_HOME}', 1, '${NOW}', '${NOW}');

-- Real provisioning also creates a 'user'-kind primary group + membership.
-- Without the group row, glibc's initgroups()/getgrgid for the primary gid
-- resolves to nothing and sshd's temporarily_use_uid fails with EINVAL.
INSERT OR REPLACE INTO posix_groups
  (gid, name, org_id, kind, created_at)
VALUES
  (${TEST_GID}, '${TEST_USER}', NULL, 'user', '${NOW}');

INSERT OR REPLACE INTO posix_group_members
  (gid, identity_id, added_at)
VALUES
  (${TEST_GID}, '${IDENTITY_ID}', '${NOW}');

INSERT OR REPLACE INTO ssh_authorized_keys
  (id, identity_id, public_key, comment, created_at, expires_at)
VALUES
  ('${KEY_ID}', '${IDENTITY_ID}', '${PUBKEY}', 'linux-test', '${NOW}', NULL);
SQL

cat > "$ENV_OUT" <<EOF
HOST_ID=${HOST_ID}
HOST_SECRET=${HOST_SECRET}
TEST_USER=${TEST_USER}
TEST_UID=${TEST_UID}
TEST_GID=${TEST_GID}
TEST_HOME=${TEST_HOME}
TEST_SHELL=${TEST_SHELL}
IDENTITY_ID=${IDENTITY_ID}
PRIVKEY_PATH=${KEY}
EOF

echo "seed: enrolled host '${HOST_ID}', account '${TEST_USER}' (uid ${TEST_UID}/gid ${TEST_GID})"
echo "seed: ephemeral key  ${KEY}"
echo "seed: env written to  ${ENV_OUT}"
