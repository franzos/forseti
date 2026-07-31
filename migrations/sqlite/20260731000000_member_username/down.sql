-- DROP COLUMN is supported by the bundled SQLite (libsqlite3-sys 0.37,
-- SQLite 3.35+); no table-rebuild dance needed.

DROP TABLE member_username_history;

DROP INDEX IF EXISTS idx_member_profiles_username_lc;

ALTER TABLE member_profiles DROP COLUMN username_lc;
ALTER TABLE member_profiles DROP COLUMN username;
