-- Device-authorization sessions (postgres twin). Must stay in lockstep with
-- migrations/sqlite/20260623000000_posix_device/up.sql; see that file for notes.

CREATE TABLE device_sessions (
  device_code        TEXT PRIMARY KEY,
  user_code          TEXT NOT NULL,
  host_id            TEXT NOT NULL,
  requested_username TEXT NOT NULL,
  status             TEXT NOT NULL,
  identity_id        TEXT,
  created_at         TEXT NOT NULL,
  expires_at         TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_device_sessions_user_code ON device_sessions (user_code);
CREATE INDEX idx_device_sessions_expires ON device_sessions (expires_at);
