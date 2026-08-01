-- Split the code the daemon holds from the code Hydra issued.
--
-- `device_code` stays Hydra's bearer secret and now never leaves this process:
-- Forseti is the RFC 8628 client (it holds `[posix].pam_client_secret` and does
-- the token exchange), so handing the AS's grant credential down to every
-- enrolled host would put it in a sphere that has no use for it. RFC 8628 §5.6
-- waves this away only because in the canonical topology the device already
-- holds the client credentials; here it deliberately does not.
--
-- `client_code_hash` is the SHA-256 of a server-minted opaque code returned to
-- the daemon (as `device_code`, keeping the response RFC 8628 §3.2-shaped).
-- Hashed at rest for the same reason `host_enrollments.secret_hash` is: a DB
-- read must not yield live codes.
--
-- Existing rows are dropped rather than backfilled: device sessions are
-- ephemeral (Hydra's user-code lifetime is 10m) and any in-flight flow simply
-- restarts on the daemon's next attempt.

DELETE FROM device_sessions;

ALTER TABLE device_sessions ADD COLUMN client_code_hash TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX idx_device_sessions_client_code ON device_sessions (client_code_hash);
