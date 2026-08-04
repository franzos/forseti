-- Recreate from the original DDL in 20260517000000_initial_schema (verbatim).
CREATE TABLE dcr_initial_access_tokens (
    id                       TEXT PRIMARY KEY NOT NULL,
    token_hash               TEXT NOT NULL UNIQUE,
    created_by               TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    expires_at               TEXT,
    uses_remaining           INTEGER,
    revoked_at               TEXT,
    note                     TEXT NOT NULL DEFAULT '',
    daily_use_count          INTEGER NOT NULL DEFAULT 0,
    daily_window_started_at  TEXT
);

CREATE INDEX idx_dcr_iat_token_hash ON dcr_initial_access_tokens (token_hash);
CREATE INDEX idx_dcr_iat_created_at ON dcr_initial_access_tokens (created_at DESC);
