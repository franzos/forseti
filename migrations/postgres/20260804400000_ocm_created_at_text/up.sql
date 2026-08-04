-- schema.rs maps created_at as Text (matching sqlite and every sibling
-- timestamp column); TIMESTAMPTZ made every Row read fail on postgres.
ALTER TABLE oauth_client_metadata
    ALTER COLUMN created_at DROP DEFAULT,
    ALTER COLUMN created_at TYPE TEXT USING to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    ALTER COLUMN created_at SET DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS');
