-- Curated app-template slug stamped at admin-create time, cosmetic only:
-- drives the app logo on the client list (postgres twin). Must stay in
-- lockstep with migrations/sqlite/20260619000000_client_template_slug/up.sql.

ALTER TABLE oauth_client_metadata ADD COLUMN template_slug TEXT;
