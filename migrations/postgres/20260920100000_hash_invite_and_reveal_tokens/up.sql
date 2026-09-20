-- organization_invites.token and secret_reveals.token now hold SHA-256(raw
-- token) hex instead of the raw bearer value, matching the claim-email and
-- DCR token columns. The column keeps its name and type; only what goes in
-- it changes, so there is no ALTER here.
--
-- Existing rows can't be converted without pgcrypto, and both kinds are
-- short-lived by design, so they're cleared instead: a pending invite has to
-- be re-sent, a pending reveal re-minted. Accepted invites keep their audit
-- trail - who joined which org, when - with the spent token replaced by a
-- per-row placeholder, since the column is the primary key.

DELETE FROM organization_invites WHERE accepted_at IS NULL;

UPDATE organization_invites
SET token = 'spent-' || md5(random()::text || clock_timestamp()::text)
WHERE accepted_at IS NOT NULL;

DELETE FROM secret_reveals;
