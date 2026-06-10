-- Key SAML linking on the stable IdP subject (NameID) alongside email
-- (postgres twin). Must stay in lockstep with
-- migrations/sqlite/20260611000000_saml_subject/up.sql.

ALTER TABLE saml_links ADD COLUMN idp_subject TEXT;

CREATE INDEX idx_saml_links_subject ON saml_links (org_id, idp_subject);
