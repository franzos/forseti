-- created_by points at an identity (saml_connections) or an admin email
-- (resource_registry); both become NULL when that identity is deleted.
ALTER TABLE saml_connections ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE resource_registry ALTER COLUMN created_by DROP NOT NULL;
