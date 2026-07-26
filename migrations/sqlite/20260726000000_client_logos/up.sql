-- Operator-uploaded logo blob per OAuth2 client, shown on the consent
-- screen. No `has_logo` flag on oauth_client_metadata: this table is the
-- single source of truth, so the two can't diverge, and a legacy client
-- with no metadata row can still carry a logo (sqlite).

CREATE TABLE client_logos (
    client_id    TEXT PRIMARY KEY NOT NULL,
    bytes        BLOB NOT NULL,
    content_type TEXT NOT NULL,
    etag         TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
