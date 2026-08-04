-- Operator-enrolled resource servers (RFC 8707 audiences). Replaces the
-- static [oauth].allowed_resource_audiences config list as the consent-time
-- audience allow-list; `corroboration` is the advisory RFC 9728 check result
-- and never gates anything.

CREATE TABLE resource_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT 'default',
    enabled INTEGER NOT NULL DEFAULT 1,
    corroboration TEXT NOT NULL DEFAULT 'unchecked',
    corroborated_at TIMESTAMP,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_resource_registry_org ON resource_registry(org_id);
