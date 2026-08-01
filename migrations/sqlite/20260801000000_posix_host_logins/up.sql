-- Which accounts have completed an ONLINE auth on which host (sqlite). Read by
-- `/posix/v1/offline_verifiers`: a host is served offline verifiers only for
-- the accounts it has actually seen, so one compromised or decommissioned host
-- can't walk off with an offline-crackable corpus for the whole org. The
-- consequence is that a user's FIRST login on a given host must be online.
--
-- Written in the same transaction as the device-session approval, so the record
-- can never claim a login that didn't happen. FK-free like the rest of the M1
-- posix tables; rows go with the host (delete_host) and with the account
-- (delete_account_rows).

CREATE TABLE host_account_logins (
  host_id       TEXT NOT NULL,
  identity_id   TEXT NOT NULL,
  last_login_at TEXT NOT NULL,
  PRIMARY KEY (host_id, identity_id)
);

CREATE INDEX idx_host_account_logins_identity ON host_account_logins (identity_id);
