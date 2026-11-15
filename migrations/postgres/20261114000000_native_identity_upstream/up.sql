-- Upstream provider links of the native identity backend: a (provider, subject) pair belongs
-- to one identity, an identity has at most one link per provider. Upstream tokens are not kept.
CREATE TABLE identity_oidc_links (
  provider    TEXT NOT NULL,
  subject     TEXT NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (provider, subject),
  UNIQUE (identity_id, provider)
);

-- When the address was first proven; an address change clears email_verified_at, not this.
ALTER TABLE identities ADD COLUMN first_verified_at TEXT;
UPDATE identities SET first_verified_at = email_verified_at;

-- A provider sign-up mails its code before the identity exists, so codes and mail may carry no
-- identity.
ALTER TABLE identity_codes ALTER COLUMN identity_id DROP NOT NULL;
ALTER TABLE identity_mail_outbox ALTER COLUMN identity_id DROP NOT NULL;
