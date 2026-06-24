#!/usr/bin/env bash
# Runs on the HOST. Removes the rows seed.sh planted and the ephemeral keys.
# Mirrors seed.sh's identifiers; override via the same env vars if you changed
# them when seeding.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB="${1:-${FORSETI_DB:-$HERE/../../forseti.db}}"
ENV_OUT="${SEED_ENV_OUT:-$HERE/.seed.env}"
KEY_DIR="${SEED_KEY_DIR:-$HERE/.seed-keys}"

HOST_ID="${HOST_ID:-linux-test-host}"
IDENTITY_ID="${IDENTITY_ID:-00000000-0000-0000-0000-0000linuxtest}"
TEST_USER="${TEST_USER:-linuxtester}"
KEY_ID="linux-test-key"

if command -v guix >/dev/null 2>&1; then
  SQLITE() { guix shell sqlite -- sqlite3 "$@"; }
else
  SQLITE() { sqlite3 "$@"; }
fi

if [ -f "$DB" ]; then
  SQLITE "$DB" <<SQL
.timeout 5000
DELETE FROM ssh_authorized_keys  WHERE id = '${KEY_ID}' OR identity_id = '${IDENTITY_ID}';
DELETE FROM posix_group_members  WHERE identity_id = '${IDENTITY_ID}';
DELETE FROM posix_accounts       WHERE identity_id = '${IDENTITY_ID}';
DELETE FROM posix_groups         WHERE name = '${TEST_USER}' AND kind = 'user';
DELETE FROM host_enrollments     WHERE id = '${HOST_ID}';
SQL
  echo "unseed: removed seeded rows from $DB"
else
  echo "unseed: $DB not found; nothing to delete"
fi

rm -rf "$KEY_DIR"
rm -f "$ENV_OUT"
echo "unseed: removed ephemeral keys + env file"
