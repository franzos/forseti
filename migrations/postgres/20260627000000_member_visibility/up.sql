ALTER TABLE organizations
  ADD COLUMN member_visibility TEXT NOT NULL DEFAULT 'all'
  CHECK (member_visibility IN ('all','same_group','admins_only'));

ALTER TABLE organization_members
  ADD COLUMN hidden_from_directory INTEGER NOT NULL DEFAULT 0;

-- Fail the auto-join-everyone Default org closed.
UPDATE organizations SET member_visibility = 'admins_only' WHERE id = 'default';
