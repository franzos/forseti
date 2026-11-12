-- Space-separated scopes from the resource's RFC 9728 scopes_supported.
ALTER TABLE resource_registry ADD COLUMN scopes_supported TEXT NOT NULL DEFAULT '';
