CREATE TABLE org_allowed_domains (
    org_id              TEXT NOT NULL,
    domain              TEXT NOT NULL,
    method              TEXT NOT NULL,
    verification_token  TEXT NOT NULL,
    verified_at         TEXT,
    added_by            TEXT,
    added_at            TEXT NOT NULL,
    PRIMARY KEY (org_id, domain)
);

-- Global invariant: a domain can have at most one VERIFIED owner across all
-- orgs. Pending (unverified) rows for the same domain under different orgs
-- are allowed to coexist (an ownership race resolves at verify time).
CREATE UNIQUE INDEX idx_org_allowed_domains_verified_domain
    ON org_allowed_domains (domain)
    WHERE verified_at IS NOT NULL;
