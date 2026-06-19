-- Curated app-template slug stamped at admin-create time, cosmetic only:
-- drives the app logo on the client list. Nullable — DCR clients and
-- pre-feature rows have none (sqlite).

ALTER TABLE oauth_client_metadata ADD COLUMN template_slug TEXT;
