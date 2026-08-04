ALTER TABLE oauth_client_metadata
    ALTER COLUMN created_at DROP DEFAULT,
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz,
    ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
