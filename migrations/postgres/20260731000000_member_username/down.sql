DROP TABLE member_username_history;

DROP INDEX IF EXISTS idx_member_profiles_username_lc;

ALTER TABLE member_profiles DROP COLUMN username_lc;
ALTER TABLE member_profiles DROP COLUMN username;
