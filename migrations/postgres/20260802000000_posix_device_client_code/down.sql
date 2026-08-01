DROP INDEX IF EXISTS idx_device_sessions_client_code;

ALTER TABLE device_sessions DROP COLUMN client_code_hash;
