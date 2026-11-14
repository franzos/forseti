-- Identities, credentials, sessions, self-service flows, one-time codes and
-- outgoing mail of the native identity backend. Timestamps are RFC 3339 text,
-- JSON is text. Child rows go with their identity through ON DELETE CASCADE.
CREATE TABLE identities (
  id                 TEXT PRIMARY KEY NOT NULL,
  email              TEXT NOT NULL,
  email_norm         TEXT NOT NULL UNIQUE,
  email_verified_at  TEXT,
  first_name         TEXT,
  last_name          TEXT,
  preferred_language TEXT,
  state              TEXT NOT NULL,
  state_changed_at   TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  metadata_public    TEXT,
  metadata_admin     TEXT
);

CREATE INDEX idx_identities_created ON identities (created_at, id);

CREATE TABLE identity_credentials (
  id          TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  config      TEXT NOT NULL,
  version     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE (identity_id, kind)
);

CREATE TABLE identity_sessions (
  id               TEXT PRIMARY KEY NOT NULL,
  identity_id      TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  token_hash       TEXT NOT NULL UNIQUE,
  aal              TEXT NOT NULL,
  methods          TEXT NOT NULL,
  issued_at        TEXT NOT NULL,
  authenticated_at TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  revoked_at       TEXT,
  ip_address       TEXT,
  user_agent       TEXT
);

CREATE INDEX idx_identity_sessions_identity ON identity_sessions (identity_id, issued_at);
CREATE INDEX idx_identity_sessions_issued ON identity_sessions (issued_at, id);
CREATE INDEX idx_identity_sessions_expires ON identity_sessions (expires_at);

CREATE TABLE identity_flows (
  id            TEXT PRIMARY KEY NOT NULL,
  kind          TEXT NOT NULL,
  state         TEXT NOT NULL,
  binding       TEXT,
  identity_id   TEXT REFERENCES identities (id) ON DELETE CASCADE,
  session_id    TEXT REFERENCES identity_sessions (id) ON DELETE CASCADE,
  requested_aal TEXT,
  refresh       INTEGER NOT NULL DEFAULT 0,
  return_to     TEXT,
  request_url   TEXT NOT NULL,
  context       TEXT NOT NULL,
  version       INTEGER NOT NULL DEFAULT 0,
  issued_at     TEXT NOT NULL,
  expires_at    TEXT NOT NULL
);

CREATE INDEX idx_identity_flows_identity ON identity_flows (identity_id);
CREATE INDEX idx_identity_flows_session ON identity_flows (session_id);
CREATE INDEX idx_identity_flows_expires ON identity_flows (expires_at);

CREATE TABLE identity_codes (
  id          TEXT PRIMARY KEY NOT NULL,
  flow_id     TEXT NOT NULL REFERENCES identity_flows (id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  address     TEXT NOT NULL,
  code_mac    TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  created_at  TEXT NOT NULL,
  UNIQUE (flow_id, purpose)
);

CREATE INDEX idx_identity_codes_identity ON identity_codes (identity_id);

CREATE TABLE identity_mail_outbox (
  id              TEXT PRIMARY KEY NOT NULL,
  identity_id     TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  recipient       TEXT NOT NULL,
  kind            TEXT NOT NULL,
  payload         TEXT NOT NULL,
  state           TEXT NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error      TEXT,
  created_at      TEXT NOT NULL,
  sent_at         TEXT
);

CREATE INDEX idx_identity_mail_outbox_due ON identity_mail_outbox (state, next_attempt_at);
CREATE INDEX idx_identity_mail_outbox_identity ON identity_mail_outbox (identity_id);
