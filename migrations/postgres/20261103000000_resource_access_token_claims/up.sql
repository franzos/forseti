-- Space-separated metadata_admin keys that consent copies into the access
-- token when this resource is a granted audience. Empty for none.

ALTER TABLE resource_registry ADD COLUMN access_token_claims TEXT NOT NULL DEFAULT '';
