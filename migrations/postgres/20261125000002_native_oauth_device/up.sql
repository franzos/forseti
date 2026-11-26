-- RFC 8628 device authorizations of the native OAuth server. flow_id names the authorization
-- request of an accepted user code; it has no foreign key because expired requests are deleted
-- before their device rows. user_code is unique over every stored row.
CREATE TABLE oauth_device_codes (
  device_code_hash TEXT PRIMARY KEY NOT NULL,
  user_code        TEXT NOT NULL UNIQUE,
  client_id        TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
  scope            TEXT NOT NULL,
  status           TEXT NOT NULL,
  flow_id          TEXT,
  interval_secs    INTEGER NOT NULL,
  last_polled_at   TEXT,
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL
);

CREATE INDEX idx_oauth_device_codes_client ON oauth_device_codes (client_id, status);
CREATE INDEX idx_oauth_device_codes_expires ON oauth_device_codes (expires_at);
