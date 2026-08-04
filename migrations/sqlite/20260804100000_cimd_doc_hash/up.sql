-- SHA-256 (hex) of the CIMD document body as of the last Hydra client upsert.
-- The shim's warm path skips the Hydra admin write when the freshly fetched
-- document still hashes to this value and the requested redirect_uri is
-- already on the client row. NULL for non-CIMD rows and for CIMD rows created
-- before this column shipped (they take the cold path once and heal).

ALTER TABLE oauth_client_metadata ADD COLUMN cimd_doc_hash TEXT;
