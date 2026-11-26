-- Revoked access tokens of the native OAuth server by jti, kept until expires_at. A grant with
-- tokens_revoked_at set, the instant of its family revoke, has no access token in force.
CREATE TABLE oauth_revoked_tokens (
  jti        TEXT PRIMARY KEY NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_oauth_revoked_tokens_expires ON oauth_revoked_tokens (expires_at);

ALTER TABLE oauth_consent_grants ADD COLUMN tokens_revoked_at TEXT;
