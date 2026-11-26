-- Authorization requests, OP login sessions, consent grants and authorization codes of the native
-- OAuth server. Challenges, verifiers and codes are stored as SHA-256 hex; list and claim columns
-- are JSON text. subject carries no foreign key: it names a Kratos identity on some builds.
CREATE TABLE oauth_authorize_requests (
  id                     TEXT PRIMARY KEY NOT NULL,
  client_id              TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  login_challenge_hash   TEXT NOT NULL UNIQUE,
  consent_challenge_hash TEXT UNIQUE,
  verifier_hash          TEXT UNIQUE,
  state                  TEXT NOT NULL,
  request_url            TEXT NOT NULL,
  redirect_uri           TEXT NOT NULL,
  response_mode          TEXT NOT NULL,
  oauth_state            TEXT,
  nonce                  TEXT,
  code_challenge         TEXT,
  requested_scope        TEXT NOT NULL,
  requested_audience     TEXT NOT NULL,
  requested_resource     TEXT NOT NULL,
  oidc_context           TEXT NOT NULL,
  session_id             TEXT NOT NULL,
  skip_login             INTEGER NOT NULL,
  subject                TEXT,
  skip_consent           INTEGER,
  login_result           TEXT,
  consent_result         TEXT,
  error                  TEXT,
  created_at             TEXT NOT NULL,
  expires_at             TEXT NOT NULL
);

CREATE INDEX idx_oauth_authorize_requests_expires ON oauth_authorize_requests (expires_at);
CREATE INDEX idx_oauth_authorize_requests_client ON oauth_authorize_requests (client_id);

CREATE TABLE oauth_login_sessions (
  sid        TEXT PRIMARY KEY NOT NULL,
  subject    TEXT NOT NULL,
  auth_time  TEXT NOT NULL,
  acr        TEXT,
  amr        TEXT NOT NULL,
  remember   INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_oauth_login_sessions_subject ON oauth_login_sessions (subject);
CREATE INDEX idx_oauth_login_sessions_expires ON oauth_login_sessions (expires_at);

CREATE TABLE oauth_consent_grants (
  id                  TEXT PRIMARY KEY NOT NULL,
  client_id           TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  subject             TEXT NOT NULL,
  session_id          TEXT NOT NULL,
  scope               TEXT NOT NULL,
  audience            TEXT NOT NULL,
  id_token_claims     TEXT NOT NULL,
  access_token_claims TEXT NOT NULL,
  remember            INTEGER NOT NULL,
  skipped             INTEGER NOT NULL,
  handled_at          TEXT NOT NULL
);

CREATE INDEX idx_oauth_consent_grants_subject_client ON oauth_consent_grants (subject, client_id);
CREATE INDEX idx_oauth_consent_grants_session ON oauth_consent_grants (session_id);
CREATE INDEX idx_oauth_consent_grants_client ON oauth_consent_grants (client_id);

CREATE TABLE oauth_authorization_codes (
  code_hash      TEXT PRIMARY KEY NOT NULL,
  grant_id       TEXT NOT NULL REFERENCES oauth_consent_grants (id) ON DELETE CASCADE,
  client_id      TEXT NOT NULL,
  subject        TEXT NOT NULL,
  session_id     TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT,
  nonce          TEXT,
  scope          TEXT NOT NULL,
  audience       TEXT NOT NULL,
  auth_time      TEXT NOT NULL,
  acr            TEXT,
  amr            TEXT NOT NULL,
  family_id      TEXT NOT NULL,
  created_at     TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  used_at        TEXT
);

CREATE INDEX idx_oauth_authorization_codes_grant ON oauth_authorization_codes (grant_id);
CREATE INDEX idx_oauth_authorization_codes_session ON oauth_authorization_codes (session_id);
CREATE INDEX idx_oauth_authorization_codes_expires ON oauth_authorization_codes (expires_at);
