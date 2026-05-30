#!/usr/bin/env bash
# Seed a deterministic admin identity (password + TOTP) into the playground
# Kratos so admin-gated integration + Playwright tests can run unattended.
#
# Kratos's identity-import API can't import TOTP (only password/oidc), and
# enrolling TOTP through the self-service flow isn't reliable, so we create the
# identity via the admin API (Kratos hashes the password) and plant the TOTP
# credential directly in Kratos's Postgres with a known base32 secret.
#
# DB access goes through `$COMPOSE exec postgres`, so it works the same under
# podman-compose and `docker compose`. Requires curl + jq on PATH.
set -euo pipefail

KRATOS_ADMIN="${KRATOS_ADMIN_URL:-http://localhost:4434}"
COMPOSE="${COMPOSE:-podman-compose}"
COMPOSE_FILE="${COMPOSE_FILE:-infra/docker-compose.yml}"

EMAIL="${SEED_ADMIN_EMAIL:-admin@example.com}"
PASSWORD="${SEED_ADMIN_PASSWORD:-Sup3rSecretAdminPw!9}"
# 32-char base32 (20-byte) RFC 6238 secret. Fixed so generated codes are
# reproducible across the test harness (Rust + Playwright) and this seed.
SECRET="${SEED_ADMIN_TOTP_SECRET:-JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP}"

kratos_psql() {
	"$COMPOSE" -f "$COMPOSE_FILE" exec -T postgres psql -U kratos -d kratos "$@"
}

# 1. Idempotency: drop any existing identity with this email so a reseed is a
#    clean slate (matches the volumes-wiped-per-run model `make stack-down` uses).
for id in $(curl -fsS "$KRATOS_ADMIN/admin/identities?credentials_identifier=$EMAIL" | jq -r '.[].id'); do
	curl -fsS -o /dev/null -X DELETE "$KRATOS_ADMIN/admin/identities/$id"
	echo "seed-admin: deleted existing identity $id"
done

# 2. Create the identity with a password (Kratos hashes it) and a pre-verified
#    email so verification-gated admin surfaces are reachable.
created=$(curl -fsS -X POST "$KRATOS_ADMIN/admin/identities" \
	-H 'Content-Type: application/json' \
	-d "$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" '{
		schema_id: "default",
		traits: { email: $e },
		verifiable_addresses: [{ value: $e, verified: true, via: "email", status: "completed" }],
		credentials: { password: { config: { password: $p } } }
	}')")
iid=$(echo "$created" | jq -r '.id')
echo "seed-admin: created identity $iid ($EMAIL)"

# 3. Plant the TOTP credential + its identifier row directly in Postgres. The
#    totp identifier Kratos stores is the identity's own UUID.
kratos_psql -v ON_ERROR_STOP=1 -v iid="$iid" -v secret="$SECRET" <<'SQL'
WITH t AS (SELECT id FROM identity_credential_types WHERE name = 'totp'),
     n AS (SELECT nid FROM identities WHERE id = :'iid'),
     ins AS (
       INSERT INTO identity_credentials
         (id, config, identity_credential_type_id, identity_id, created_at, updated_at, nid, version)
       SELECT gen_random_uuid(),
              jsonb_build_object('totp_url',
                'otpauth://totp/forseti:' || :'iid' ||
                '?algorithm=SHA1&digits=6&issuer=forseti&period=30&secret=' || :'secret'),
              t.id, :'iid', now(), now(), n.nid, 0
       FROM t, n
       RETURNING id, identity_credential_type_id, nid
     )
INSERT INTO identity_credential_identifiers
  (id, identifier, identity_credential_id, created_at, updated_at, nid, identity_credential_type_id, identity_id)
SELECT gen_random_uuid(), :'iid', ins.id, now(), now(), ins.nid, ins.identity_credential_type_id, :'iid'
FROM ins;
SQL
echo "seed-admin: planted TOTP credential for $iid"

# 4. Emit the env contract the suites consume. In GitHub Actions, also persist
#    it to $GITHUB_ENV so later steps inherit it.
if [ -n "${GITHUB_ENV:-}" ]; then
	{
		echo "FORSETI_ADMIN_TEST_EMAIL=$EMAIL"
		echo "FORSETI_ADMIN_TEST_PASSWORD=$PASSWORD"
		echo "FORSETI_ADMIN_TEST_TOTP_SECRET=$SECRET"
	} >>"$GITHUB_ENV"
fi
cat <<EXPORTS
seed-admin: done. Export these for the test suites:
  export FORSETI_ADMIN_TEST_EMAIL='$EMAIL'
  export FORSETI_ADMIN_TEST_PASSWORD='$PASSWORD'
  export FORSETI_ADMIN_TEST_TOTP_SECRET='$SECRET'
EXPORTS
