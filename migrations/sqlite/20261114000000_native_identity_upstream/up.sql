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
-- identity. sqlite cannot alter a column's nullability, so both tables are rebuilt; nothing
-- references them.
CREATE TABLE identity_codes_new (
  id          TEXT PRIMARY KEY NOT NULL,
  flow_id     TEXT NOT NULL REFERENCES identity_flows (id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL,
  identity_id TEXT REFERENCES identities (id) ON DELETE CASCADE,
  address     TEXT NOT NULL,
  code_mac    TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  created_at  TEXT NOT NULL,
  UNIQUE (flow_id, purpose)
);
INSERT INTO identity_codes_new (id, flow_id, purpose, identity_id, address, code_mac, attempts, expires_at, used_at, created_at)
  SELECT id, flow_id, purpose, identity_id, address, code_mac, attempts, expires_at, used_at, created_at FROM identity_codes;
DROP TABLE identity_codes;
ALTER TABLE identity_codes_new RENAME TO identity_codes;
CREATE INDEX idx_identity_codes_identity ON identity_codes (identity_id);

CREATE TABLE identity_mail_outbox_new (
  id              TEXT PRIMARY KEY NOT NULL,
  identity_id     TEXT REFERENCES identities (id) ON DELETE CASCADE,
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
INSERT INTO identity_mail_outbox_new (id, identity_id, recipient, kind, payload, state, attempts, next_attempt_at, last_error, created_at, sent_at)
  SELECT id, identity_id, recipient, kind, payload, state, attempts, next_attempt_at, last_error, created_at, sent_at FROM identity_mail_outbox;
DROP TABLE identity_mail_outbox;
ALTER TABLE identity_mail_outbox_new RENAME TO identity_mail_outbox;
CREATE INDEX idx_identity_mail_outbox_due ON identity_mail_outbox (state, next_attempt_at);
CREATE INDEX idx_identity_mail_outbox_identity ON identity_mail_outbox (identity_id);
