-- SAML SSO support (postgres twin). Must stay in lockstep with
-- migrations/sqlite/20260610000000_saml/up.sql; see that file for design notes.

CREATE TABLE saml_connections (
    org_id       TEXT PRIMARY KEY NOT NULL REFERENCES organizations(id),
    enabled      INTEGER NOT NULL DEFAULT 1,
    display_name TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE saml_links (
    org_id      TEXT NOT NULL,
    email       TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (org_id, email)
);

CREATE INDEX idx_saml_links_identity ON saml_links (identity_id);
