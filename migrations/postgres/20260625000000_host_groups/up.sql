-- Per-host team scoping. A host (single-org) may allow ANY-of-N of its org's
-- teams; empty set = whole-org access. References org_teams.id (uuid), so a
-- deleted team's id is never reused (no gid-reuse hazard).
CREATE TABLE host_allowed_groups (
  host_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  PRIMARY KEY (host_id, team_id)
);
