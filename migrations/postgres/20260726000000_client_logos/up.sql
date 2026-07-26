-- Operator-uploaded logo blob per OAuth2 client (postgres twin). Must stay
-- in lockstep with migrations/sqlite/20260726000000_client_logos/up.sql.

CREATE TABLE client_logos (
    client_id    TEXT PRIMARY KEY NOT NULL,
    bytes        BYTEA NOT NULL,
    content_type TEXT NOT NULL,
    etag         TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
