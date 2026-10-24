-- created_by points at an identity (saml_connections) or an admin email
-- (resource_registry); both become NULL when that identity is deleted.
-- sqlite cannot alter a column's nullability, so both tables are rebuilt.

CREATE TABLE saml_connections_new (
    org_id       TEXT PRIMARY KEY NOT NULL REFERENCES organizations(id),
    enabled      INTEGER NOT NULL DEFAULT 1,
    display_name TEXT NOT NULL,
    created_by   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
INSERT INTO saml_connections_new (org_id, enabled, display_name, created_by, created_at, updated_at)
    SELECT org_id, enabled, display_name, created_by, created_at, updated_at FROM saml_connections;
DROP TABLE saml_connections;
ALTER TABLE saml_connections_new RENAME TO saml_connections;

CREATE TABLE resource_registry_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT 'default',
    enabled INTEGER NOT NULL DEFAULT 1,
    corroboration TEXT NOT NULL DEFAULT 'unchecked',
    corroborated_at TIMESTAMP,
    created_by TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO resource_registry_new (id, resource, display_name, org_id, enabled, corroboration, corroborated_at, created_by, created_at)
    SELECT id, resource, display_name, org_id, enabled, corroboration, corroborated_at, created_by, created_at FROM resource_registry;
DROP TABLE resource_registry;
ALTER TABLE resource_registry_new RENAME TO resource_registry;
CREATE INDEX idx_resource_registry_org ON resource_registry(org_id);
