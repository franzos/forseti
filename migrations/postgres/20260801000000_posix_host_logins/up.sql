-- Which accounts have completed an ONLINE auth on which host (postgres twin).
-- Must stay in lockstep with migrations/sqlite/20260801000000_posix_host_logins/up.sql;
-- see that file for notes.

CREATE TABLE host_account_logins (
  host_id       TEXT NOT NULL,
  identity_id   TEXT NOT NULL,
  last_login_at TEXT NOT NULL,
  PRIMARY KEY (host_id, identity_id)
);

CREATE INDEX idx_host_account_logins_identity ON host_account_logins (identity_id);
