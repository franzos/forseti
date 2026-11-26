-- Refresh tokens of the native OAuth server, stored as SHA-256 hex. A family is every token
-- descended from one authorization code; scope, audience and amr are JSON text.
CREATE TABLE oauth_refresh_tokens (
  id         TEXT PRIMARY KEY NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  family_id  TEXT NOT NULL,
  grant_id   TEXT NOT NULL REFERENCES oauth_consent_grants (id) ON DELETE CASCADE,
  client_id  TEXT NOT NULL,
  subject    TEXT NOT NULL,
  session_id TEXT NOT NULL,
  scope      TEXT NOT NULL,
  audience   TEXT NOT NULL,
  auth_time  TEXT NOT NULL,
  acr        TEXT,
  amr        TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at    TEXT
);

CREATE INDEX idx_oauth_refresh_tokens_family ON oauth_refresh_tokens (family_id);
CREATE INDEX idx_oauth_refresh_tokens_grant ON oauth_refresh_tokens (grant_id);
CREATE INDEX idx_oauth_refresh_tokens_expires ON oauth_refresh_tokens (expires_at);
