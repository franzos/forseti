-- Rebuild both tables with created_by NOT NULL, backfilling '' for NULL.

CREATE TABLE saml_connections_old (
    org_id       TEXT PRIMARY KEY NOT NULL REFERENCES organizations(id),
    enabled      INTEGER NOT NULL DEFAULT 1,
    display_name TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
INSERT INTO saml_connections_old (org_id, enabled, display_name, created_by, created_at, updated_at)
    SELECT org_id, enabled, display_name, COALESCE(created_by, ''), created_at, updated_at FROM saml_connections;
DROP TABLE saml_connections;
ALTER TABLE saml_connections_old RENAME TO saml_connections;

CREATE TABLE resource_registry_old (
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
INSERT INTO resource_registry_old (id, resource, display_name, org_id, enabled, corroboration, corroborated_at, created_by, created_at)
    SELECT id, resource, display_name, org_id, enabled, corroboration, corroborated_at, COALESCE(created_by, ''), created_at FROM resource_registry;
DROP TABLE resource_registry;
ALTER TABLE resource_registry_old RENAME TO resource_registry;
CREATE INDEX idx_resource_registry_org ON resource_registry(org_id);
