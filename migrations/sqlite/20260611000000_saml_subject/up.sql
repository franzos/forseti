-- Key SAML linking on the stable IdP subject (NameID) alongside email
-- (sqlite). idp_subject is nullable: existing email-only rows have none and
-- keep working; it's backfilled on the next login that re-links the row.

ALTER TABLE saml_links ADD COLUMN idp_subject TEXT;

CREATE INDEX idx_saml_links_subject ON saml_links (org_id, idp_subject);
