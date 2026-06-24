-- POSIX/Linux account integration (sqlite). posix_accounts maps a Forseti
-- identity to a uid/gid/home/shell; posix_groups + posix_group_members model
-- supplementary group membership; host_enrollments registers nss/pam hosts;
-- ssh_authorized_keys holds per-identity public keys.

CREATE TABLE posix_accounts (
  identity_id TEXT PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  uid         INTEGER NOT NULL UNIQUE,
  gid         INTEGER NOT NULL,
  gecos       TEXT NOT NULL DEFAULT '',
  shell       TEXT NOT NULL,
  home_dir    TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE posix_groups (
  gid INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  org_id TEXT, kind TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE posix_group_members (
  gid INTEGER NOT NULL, identity_id TEXT NOT NULL, added_at TEXT NOT NULL,
  PRIMARY KEY (gid, identity_id)
);

CREATE TABLE host_enrollments (
  id TEXT PRIMARY KEY, hostname TEXT NOT NULL, secret_hash TEXT NOT NULL,
  allowed_gid INTEGER, force_mfa INTEGER NOT NULL DEFAULT 0,
  created_by TEXT, created_at TEXT NOT NULL, last_seen_at TEXT
);

CREATE TABLE ssh_authorized_keys (
  id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, public_key TEXT NOT NULL,
  comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT
);

CREATE INDEX idx_ssh_keys_identity ON ssh_authorized_keys (identity_id);
CREATE INDEX idx_group_members_identity ON posix_group_members (identity_id);
