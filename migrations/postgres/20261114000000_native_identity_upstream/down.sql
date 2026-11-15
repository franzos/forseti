DELETE FROM identity_codes WHERE identity_id IS NULL;
ALTER TABLE identity_codes ALTER COLUMN identity_id SET NOT NULL;
DELETE FROM identity_mail_outbox WHERE identity_id IS NULL;
ALTER TABLE identity_mail_outbox ALTER COLUMN identity_id SET NOT NULL;
ALTER TABLE identities DROP COLUMN first_verified_at;
DROP TABLE identity_oidc_links;
