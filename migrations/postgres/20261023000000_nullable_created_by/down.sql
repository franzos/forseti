UPDATE saml_connections SET created_by = '' WHERE created_by IS NULL;
ALTER TABLE saml_connections ALTER COLUMN created_by SET NOT NULL;
UPDATE resource_registry SET created_by = '' WHERE created_by IS NULL;
ALTER TABLE resource_registry ALTER COLUMN created_by SET NOT NULL;
