ALTER TABLE organizations ADD COLUMN has_logo INTEGER NOT NULL DEFAULT 0;
CREATE TABLE org_logos (
    org_id       TEXT PRIMARY KEY NOT NULL,
    bytes        BLOB NOT NULL,
    content_type TEXT NOT NULL,
    etag         TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
