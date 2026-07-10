-- First time Forseti observed an OIDC provider linked to an identity. Approximates
-- the link moment across settings-link, login-collision-link, and admin-API link.
CREATE TABLE oidc_links (
    identity_id     TEXT NOT NULL,
    provider        TEXT NOT NULL,
    first_seen_at   TEXT NOT NULL,
    PRIMARY KEY (identity_id, provider)
);
