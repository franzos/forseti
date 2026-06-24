#!/usr/bin/env bash
# Runs INSIDE the Debian test container. Brings up nscd + forseti-unixd + sshd,
# then asserts the NSS/PAM/sshd chain against the host's Forseti resolver.
#
# Env contract (set by the `test-linux-host` make target / podman run):
#   SERVER_URL   resolver base, e.g. http://host.containers.internal:8081
#   HOST_ID      enrolled host id (matches the seeded host_enrollments row)
#   HOST_SECRET  enrolled host secret (plaintext; server stores sha256_hex)
#   TEST_USER    provisioned posix username to resolve
#   TEST_UID     expected uid
#   TEST_GID     expected gid
#   TEST_HOME    expected home dir
#   TEST_SHELL   expected login shell (must exist in the container)
# Mounts:
#   /test/id_key   the private ssh key whose pubkey was seeded for TEST_USER
set -euo pipefail

step()  { printf '\n=== %s\n' "$*"; }
pass()  { printf 'PASS: %s\n' "$*"; }
fail()  { printf 'FAIL: %s\n' "$*"; exit 1; }

: "${SERVER_URL:?}" "${HOST_ID:?}" "${HOST_SECRET:?}"
: "${TEST_USER:?}" "${TEST_UID:?}" "${TEST_GID:?}" "${TEST_HOME:?}" "${TEST_SHELL:?}"

# --- runtime dirs the daemon insists on (owned by forseti, not world-writable)
step "Preparing runtime dirs"
install -d -o forseti -g forseti -m 0755 /run/forseti
install -d -o forseti -g forseti -m 0700 /var/cache/forseti
install -d -o root    -g root    -m 0755 /etc/forseti

# --- render the daemon config from env
cat > /etc/forseti/unixd.toml <<EOF
server_url = "${SERVER_URL}"
host_id = "${HOST_ID}"
host_secret = "${HOST_SECRET}"
socket_path = "/run/forseti/unixd.sock"
cache_db = "/var/cache/forseti/unixd.db"
cache_ttl_secs = 30
request_timeout_secs = 3
EOF
chmod 0644 /etc/forseti/unixd.toml

# --- nscd: this is the glibc cache that dlopens the NSS module, mirroring the
#     Guix nscd-dlopen path. Start it and verify it's alive; if it won't run in
#     this container we fall back to direct glibc loading (still exercises the
#     module, just without the cache layer).
step "Starting nscd"
USE_NSCD=1
# nscd needs its runtime dir for the socket + pid; absent it forks and dies.
install -d -m 0755 /run/nscd
if nscd && sleep 1 && pgrep -x nscd >/dev/null; then
  echo "nscd running (mirrors Guix's nscd-dlopen path)"
else
  echo "note: nscd would not stay up; falling back to direct glibc NSS loading"
  USE_NSCD=0
fi
echo "USE_NSCD=${USE_NSCD}"

# nscd_invalidate: drop the passwd/group caches so a fresh lookup hits the
# daemon (no-op when nscd isn't running).
nscd_invalidate() {
  if [ "${USE_NSCD}" = "1" ]; then
    nscd -i passwd 2>/dev/null || true
    nscd -i group  2>/dev/null || true
  fi
}

# --- start the daemon as the unprivileged forseti user
step "Starting forseti-unixd (as forseti)"
runuser -u forseti -- env FORSETI_UNIXD_CONFIG=/etc/forseti/unixd.toml \
  RUST_LOG=info /usr/local/bin/forseti-unixd > /tmp/unixd.log 2>&1 &
DAEMON_PID=$!

# wait for the socket to appear
for _ in $(seq 1 50); do
  [ -S /run/forseti/unixd.sock ] && break
  sleep 0.1
done
if [ ! -S /run/forseti/unixd.sock ]; then
  echo "--- unixd.log ---"; cat /tmp/unixd.log || true
  fail "daemon socket never appeared"
fi
pass "daemon socket is up (pid ${DAEMON_PID})"
nscd_invalidate

# --- start sshd
step "Starting sshd"
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
/usr/sbin/sshd -e > /tmp/sshd.log 2>&1 &
for _ in $(seq 1 50); do
  ss -ltn 2>/dev/null | grep -q ':22 ' && break
  sleep 0.1
done
ss -ltn 2>/dev/null | grep -q ':22 ' || fail "sshd not listening on :22"
# sanity: sshd parses its config (UsePAM, AuthorizedKeysCommand) cleanly
/usr/sbin/sshd -T >/tmp/sshd-T.log 2>&1 || fail "sshd -T rejected the config"
grep -qi '^usepam yes' /tmp/sshd-T.log || fail "UsePAM is not yes (pam_mkhomedir would never run)"
pass "sshd listening; UsePAM yes"

#############################################################################
# Assertion 1: getent passwd <user> resolves the Forseti POSIX account
#############################################################################
step "Assertion 1: getent passwd ${TEST_USER}"
nscd_invalidate
ENT="$(getent passwd "${TEST_USER}" || true)"
[ -n "${ENT}" ] || { echo "--- unixd.log ---"; cat /tmp/unixd.log; fail "getent passwd ${TEST_USER} returned nothing (NSS module didn't resolve)"; }
echo "  ${ENT}"
# format: name:passwd:uid:gid:gecos:home:shell
IFS=: read -r g_name g_pw g_uid g_gid g_gecos g_home g_shell <<<"${ENT}"
[ "${g_name}"  = "${TEST_USER}"  ] || fail "name mismatch: ${g_name} != ${TEST_USER}"
[ "${g_uid}"   = "${TEST_UID}"   ] || fail "uid mismatch: ${g_uid} != ${TEST_UID}"
[ "${g_gid}"   = "${TEST_GID}"   ] || fail "gid mismatch: ${g_gid} != ${TEST_GID}"
[ "${g_home}"  = "${TEST_HOME}"  ] || fail "home mismatch: ${g_home} != ${TEST_HOME}"
[ "${g_shell}" = "${TEST_SHELL}" ] || fail "shell mismatch: ${g_shell} != ${TEST_SHELL}"
pass "getent resolved uid=${g_uid} gid=${g_gid} home=${g_home} shell=${g_shell}"

#############################################################################
# Assertion 2: id <user>
#############################################################################
step "Assertion 2: id ${TEST_USER}"
ID_OUT="$(id "${TEST_USER}")" || fail "id ${TEST_USER} failed"
echo "  ${ID_OUT}"
echo "${ID_OUT}" | grep -q "uid=${TEST_UID}" || fail "id did not report uid=${TEST_UID}"
pass "id resolved: ${ID_OUT}"

#############################################################################
# Assertion 3: key-based ssh via AuthorizedKeysCommand, landing in a
#              pam_mkhomedir-created $HOME
#############################################################################
step "Assertion 3: ssh -i <key> ${TEST_USER}@localhost"
[ -f /test/id_key ] || fail "private key not mounted at /test/id_key"
# Copy the key out of the (possibly host-owned) mount so ssh's strict perms pass.
cp /test/id_key /tmp/id_key
chmod 600 /tmp/id_key
# Pre-state: home must NOT exist yet — proves pam_mkhomedir creates it.
if [ -d "${TEST_HOME}" ]; then
  echo "note: ${TEST_HOME} already exists before first login"
fi
SSH_OUT="$(ssh -i /tmp/id_key \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes \
  -o ConnectTimeout=10 \
  "${TEST_USER}@localhost" \
  'echo SSH_OK uid=$(id -u) home=$HOME && test -d "$HOME" && echo HOME_EXISTS' 2>/tmp/ssh.log)" || {
    echo "--- ssh client log ---"; cat /tmp/ssh.log || true
    echo "--- sshd log ---";       cat /tmp/sshd.log || true
    echo "--- AuthorizedKeysCommand probe ---"
    runuser -u forseti -- /usr/local/bin/forseti_ssh_authorizedkeys "${TEST_USER}" || true
    fail "ssh login failed"
  }
echo "  ${SSH_OUT}"
echo "${SSH_OUT}" | grep -q 'SSH_OK'      || fail "ssh did not run the remote command"
echo "${SSH_OUT}" | grep -q 'HOME_EXISTS' || fail "\$HOME not present after login (pam_mkhomedir didn't run)"
[ -d "${TEST_HOME}" ] || fail "${TEST_HOME} was not created on the container fs"
HOME_OWNER="$(stat -c '%U' "${TEST_HOME}")"
[ "${HOME_OWNER}" = "${TEST_USER}" ] || fail "home owned by ${HOME_OWNER}, not ${TEST_USER}"
pass "ssh logged in; pam_mkhomedir created ${TEST_HOME} (owner ${HOME_OWNER})"

#############################################################################
# Assertion 4: fail-open. Stop the daemon, then:
#   - local getent passwd root still works
#   - getent passwd <user> returns empty (no hang)
#   - ssh fails fast (no hang)
#############################################################################
step "Assertion 4: fail-open with the daemon stopped"
kill "${DAEMON_PID}" 2>/dev/null || true
wait "${DAEMON_PID}" 2>/dev/null || true
rm -f /run/forseti/unixd.sock
nscd_invalidate

# 4a: local account still resolves (NSS fell through to `files`)
getent passwd root | grep -q '^root:' || fail "local getent passwd root broke with daemon down"
pass "local getent passwd root still works"

# 4b: forseti user returns empty, bounded in time (must not hang)
START=$(date +%s)
FORSETI_ENT="$(getent passwd "${TEST_USER}" || true)"
ELAPSED=$(( $(date +%s) - START ))
[ -z "${FORSETI_ENT}" ] || fail "getent passwd ${TEST_USER} returned data with daemon down: ${FORSETI_ENT}"
[ "${ELAPSED}" -le 8 ] || fail "getent passwd ${TEST_USER} hung ${ELAPSED}s with daemon down"
pass "getent passwd ${TEST_USER} returned empty in ${ELAPSED}s (no hang)"

# 4c: ssh fails fast (AuthorizedKeysCommand returns no keys → pubkey rejected)
START=$(date +%s)
if ssh -i /tmp/id_key \
     -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null \
     -o BatchMode=yes \
     -o ConnectTimeout=10 \
     "${TEST_USER}@localhost" true 2>/tmp/ssh-down.log; then
  fail "ssh unexpectedly succeeded with the daemon down"
fi
ELAPSED=$(( $(date +%s) - START ))
[ "${ELAPSED}" -le 15 ] || fail "ssh hung ${ELAPSED}s with daemon down"
pass "ssh failed fast in ${ELAPSED}s (no hang)"

step "ALL ASSERTIONS PASSED"
exit 0
