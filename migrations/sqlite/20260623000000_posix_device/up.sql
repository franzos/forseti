-- Device-authorization sessions (sqlite). Each row tracks one RFC 8628 device
-- grant the daemon initiated for a host: device_code is the Hydra-issued bearer
-- secret (never logged), user_code is the correlation key for the verification
-- screen. No SQL FK to host_enrollments (the M1 posix tables avoid FKs and reap
-- app-side); host revoke + lazy prune clear stale rows.

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
