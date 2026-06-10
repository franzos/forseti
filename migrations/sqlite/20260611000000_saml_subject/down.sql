-- DROP COLUMN is supported by the bundled SQLite (libsqlite3-sys 0.37,
-- SQLite 3.35+); no table-rebuild dance needed.

DROP INDEX IF EXISTS idx_saml_links_subject;

ALTER TABLE saml_links DROP COLUMN idp_subject;
