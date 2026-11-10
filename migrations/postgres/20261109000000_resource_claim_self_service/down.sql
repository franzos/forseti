DROP INDEX IF EXISTS idx_resource_registry_self_service_claim;
ALTER TABLE resource_registry DROP COLUMN self_service_template;
ALTER TABLE resource_registry DROP COLUMN self_service_client_id;
ALTER TABLE resource_registry DROP COLUMN self_service_issuer;
ALTER TABLE resource_registry DROP COLUMN self_service_claim;
