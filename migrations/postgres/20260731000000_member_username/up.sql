-- User-chosen handle emitted as the OIDC `preferred_username` claim
-- (postgres twin). Must stay in lockstep with
-- migrations/sqlite/20260731000000_member_username/up.sql.

ALTER TABLE member_profiles ADD COLUMN username TEXT;
ALTER TABLE member_profiles ADD COLUMN username_lc TEXT;

CREATE UNIQUE INDEX idx_member_profiles_username_lc ON member_profiles (username_lc);

CREATE TABLE member_username_history (
    username_lc TEXT PRIMARY KEY NOT NULL,
    identity_id TEXT NOT NULL,
    released_at TEXT NOT NULL
);

CREATE INDEX idx_member_username_history_identity ON member_username_history (identity_id);
