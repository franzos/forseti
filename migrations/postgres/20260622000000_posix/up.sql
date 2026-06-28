-- POSIX/Linux account integration (postgres twin). Must stay in lockstep with
-- migrations/sqlite/20260622000000_posix/up.sql; see that file for design notes.

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
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE posix_group_members (
  gid INTEGER NOT NULL, identity_id TEXT NOT NULL, added_at TEXT NOT NULL,
  PRIMARY KEY (gid, identity_id)
);

CREATE TABLE org_teams (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  gid INTEGER UNIQUE,
  parent_id TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  UNIQUE (org_id, name),
  UNIQUE (org_id, slug)
);
CREATE INDEX idx_org_teams_org ON org_teams (org_id);

CREATE TABLE org_team_members (
  team_id TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',
  added_at TEXT NOT NULL,
  PRIMARY KEY (team_id, identity_id)
);
CREATE INDEX idx_org_team_members_identity ON org_team_members (identity_id);

CREATE TABLE posix_sequences (
  name TEXT PRIMARY KEY,
  next INTEGER NOT NULL
);

CREATE TABLE host_enrollments (
  id TEXT PRIMARY KEY, hostname TEXT NOT NULL, secret_hash TEXT NOT NULL,
  org_id TEXT NOT NULL,
  force_mfa INTEGER NOT NULL DEFAULT 0,
  created_by TEXT, created_at TEXT NOT NULL, last_seen_at TEXT
);

CREATE TABLE ssh_authorized_keys (
  id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, public_key TEXT NOT NULL,
  comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT
);

CREATE INDEX idx_ssh_keys_identity ON ssh_authorized_keys (identity_id);
CREATE INDEX idx_group_members_identity ON posix_group_members (identity_id);
