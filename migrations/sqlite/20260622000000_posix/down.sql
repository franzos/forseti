DROP INDEX IF EXISTS idx_group_members_identity;
DROP INDEX IF EXISTS idx_ssh_keys_identity;
DROP TABLE IF EXISTS ssh_authorized_keys;
DROP TABLE IF EXISTS host_enrollments;
DROP TABLE IF EXISTS posix_group_members;
DROP TABLE IF EXISTS posix_groups;
DROP TABLE IF EXISTS posix_accounts;
