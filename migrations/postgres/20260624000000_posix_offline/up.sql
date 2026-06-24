-- Offline-auth verifiers (postgres twin). Must stay in lockstep with
-- migrations/sqlite/20260624000000_posix_offline/up.sql; see that file for notes.

CREATE TABLE offline_secrets (
  identity_id   TEXT PRIMARY KEY,
  verifier      TEXT NOT NULL,
  algo_version  INTEGER NOT NULL,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
