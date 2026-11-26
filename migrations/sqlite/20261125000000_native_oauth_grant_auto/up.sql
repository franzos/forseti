-- A native OAuth grant accepted without a consent screen because its client has skip_consent.
-- Consent skip never builds on such a grant.
ALTER TABLE oauth_consent_grants ADD COLUMN auto_granted INTEGER NOT NULL DEFAULT 0;
