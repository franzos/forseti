ALTER TABLE organizations ADD COLUMN domain_join_policy TEXT NOT NULL DEFAULT 'invite_only';
