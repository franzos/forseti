-- One access-token claim per row that users set themselves after proving
-- their upstream account. Empty claim means self-service is off.

ALTER TABLE resource_registry ADD COLUMN self_service_claim TEXT NOT NULL DEFAULT '';
ALTER TABLE resource_registry ADD COLUMN self_service_issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE resource_registry ADD COLUMN self_service_client_id TEXT NOT NULL DEFAULT '';
ALTER TABLE resource_registry ADD COLUMN self_service_template TEXT NOT NULL DEFAULT '';

-- Consent copies claims by name across rows, so a self-service claim belongs
-- to exactly one row.
CREATE UNIQUE INDEX idx_resource_registry_self_service_claim
    ON resource_registry (self_service_claim)
    WHERE self_service_claim <> '';
