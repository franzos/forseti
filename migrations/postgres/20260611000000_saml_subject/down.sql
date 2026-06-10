DROP INDEX IF EXISTS idx_saml_links_subject;

ALTER TABLE saml_links DROP COLUMN idp_subject;
