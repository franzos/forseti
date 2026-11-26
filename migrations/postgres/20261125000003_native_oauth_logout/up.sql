-- RP-initiated logout requests of the native OAuth server. client_id is set only when an
-- id_token_hint named the client; it has no foreign key, so an accept checks the redirect URI
-- against the client as it is registered then. browser_sid is the browser's forseti_op session
-- when a hint named another session of the same subject; accept ends both.
CREATE TABLE oauth_logout_requests (
  id                       TEXT PRIMARY KEY NOT NULL,
  challenge_hash           TEXT NOT NULL UNIQUE,
  client_id                TEXT,
  sid                      TEXT NOT NULL,
  browser_sid              TEXT,
  subject                  TEXT NOT NULL,
  post_logout_redirect_uri TEXT,
  oauth_state              TEXT,
  accepted_at              TEXT,
  created_at               TEXT NOT NULL,
  expires_at               TEXT NOT NULL
);

CREATE INDEX idx_oauth_logout_requests_expires ON oauth_logout_requests (expires_at);
