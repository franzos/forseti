-- DROP COLUMN is supported by the bundled SQLite (libsqlite3-sys 0.37,
-- SQLite 3.35+); no table-rebuild dance needed.

ALTER TABLE oauth_client_metadata DROP COLUMN template_slug;
