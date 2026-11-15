DELETE FROM identity_codes WHERE identity_id IS NULL;
CREATE TABLE identity_codes_old (
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
INSERT INTO identity_codes_old (id, flow_id, purpose, identity_id, address, code_mac, attempts, expires_at, used_at, created_at)
  SELECT id, flow_id, purpose, identity_id, address, code_mac, attempts, expires_at, used_at, created_at FROM identity_codes;
DROP TABLE identity_codes;
ALTER TABLE identity_codes_old RENAME TO identity_codes;
CREATE INDEX idx_identity_codes_identity ON identity_codes (identity_id);

DELETE FROM identity_mail_outbox WHERE identity_id IS NULL;
CREATE TABLE identity_mail_outbox_old (
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
INSERT INTO identity_mail_outbox_old (id, identity_id, recipient, kind, payload, state, attempts, next_attempt_at, last_error, created_at, sent_at)
  SELECT id, identity_id, recipient, kind, payload, state, attempts, next_attempt_at, last_error, created_at, sent_at FROM identity_mail_outbox;
DROP TABLE identity_mail_outbox;
ALTER TABLE identity_mail_outbox_old RENAME TO identity_mail_outbox;
CREATE INDEX idx_identity_mail_outbox_due ON identity_mail_outbox (state, next_attempt_at);
CREATE INDEX idx_identity_mail_outbox_identity ON identity_mail_outbox (identity_id);

ALTER TABLE identities DROP COLUMN first_verified_at;
DROP TABLE identity_oidc_links;
