-- Offline-auth verifiers (sqlite). One row per identity that has set a
-- dedicated offline passphrase (≥8 chars, NOT their Forseti password).
-- `verifier` is an Argon2id PHC string (salt + params embedded); the server
-- never stores a pepper — the host owns its own pepper. FK-free like the rest
-- of the M1 posix tables; reconcile purges rows for deleted identities.

CREATE TABLE offline_secrets (
  identity_id   TEXT PRIMARY KEY,
  verifier      TEXT NOT NULL,
  algo_version  INTEGER NOT NULL,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
