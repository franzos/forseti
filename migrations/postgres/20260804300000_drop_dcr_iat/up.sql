-- DCR retirement: the RFC 7591 proxy and its Initial Access Tokens are gone.
DROP INDEX IF EXISTS idx_dcr_iat_created_at;
DROP INDEX IF EXISTS idx_dcr_iat_token_hash;
DROP TABLE IF EXISTS dcr_initial_access_tokens;
