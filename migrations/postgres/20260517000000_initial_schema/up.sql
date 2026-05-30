-- Forseti's initial schema (postgres twin). Must stay in lockstep with
-- migrations/sqlite/20260517000000_initial_schema/up.sql; see that file for the
-- per-table design notes.
--
-- Timestamps stay TEXT (ISO-8601 UTC strings) and booleans stay INTEGER to keep
-- the diesel mapping in src/schema.rs uniform across both backends. ISO-8601
-- UTC strings sort lexicographically the same way real timestamps do, so the
-- outbox / audit ordering workloads don't lose anything.

CREATE TABLE _forseti_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE webhook_outbox (
    id              TEXT PRIMARY KEY,
    event_id        TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    url             TEXT NOT NULL,
    payload         TEXT NOT NULL,
    state           TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT,
    created_at      TEXT NOT NULL,
    delivered_at    TEXT
);

CREATE INDEX idx_webhook_outbox_state_next
    ON webhook_outbox (state, next_attempt_at);

CREATE INDEX idx_webhook_outbox_event
    ON webhook_outbox (event_id);

-- Append-only audit log. Postgres enforces it via a plpgsql trigger gated on
-- `current_setting('app.audit_purge')`; the Rust pruner does
-- `SET LOCAL app.audit_purge = 'true'` inside the same transaction as the
-- DELETE, so commit / rollback clears it (no sentinel row like sqlite needs).
CREATE TABLE audit_events (
    id           TEXT PRIMARY KEY NOT NULL,
    created_at   TEXT NOT NULL,
    actor_kind   TEXT NOT NULL,
    actor_id     TEXT,
    actor_email  TEXT,
    action       TEXT NOT NULL,
    target_kind  TEXT,
    target_id    TEXT,
    org_id       TEXT,
    ip_hash      TEXT,
    user_agent   TEXT,
    request_id   TEXT,
    severity     TEXT NOT NULL DEFAULT 'info',
    success      INTEGER NOT NULL DEFAULT 1,
    metadata     TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_created_at ON audit_events (created_at DESC);
CREATE INDEX idx_audit_actor      ON audit_events (actor_id, created_at DESC);
CREATE INDEX idx_audit_action     ON audit_events (action,   created_at DESC);
CREATE INDEX idx_audit_target     ON audit_events (target_kind, target_id, created_at DESC);
CREATE INDEX idx_audit_severity   ON audit_events (severity, created_at DESC);

CREATE OR REPLACE FUNCTION audit_events_block_modify() RETURNS trigger AS $$
BEGIN
    IF current_setting('app.audit_purge', true) IS DISTINCT FROM 'true' THEN
        RAISE EXCEPTION 'audit_events is append-only';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_modify
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION audit_events_block_modify();

CREATE TABLE secret_reveals (
    token       TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_secret_reveals_created_at ON secret_reveals (created_at);

CREATE TABLE dcr_initial_access_tokens (
    id                       TEXT PRIMARY KEY NOT NULL,
    token_hash               TEXT NOT NULL UNIQUE,
    created_by               TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    expires_at               TEXT,
    uses_remaining           INTEGER,
    revoked_at               TEXT,
    note                     TEXT NOT NULL DEFAULT '',
    daily_use_count          INTEGER NOT NULL DEFAULT 0,
    daily_window_started_at  TEXT
);

CREATE INDEX idx_dcr_iat_token_hash ON dcr_initial_access_tokens (token_hash);
CREATE INDEX idx_dcr_iat_created_at ON dcr_initial_access_tokens (created_at DESC);

-- `created_at` is TIMESTAMPTZ for timezone-aware ordering; the verify/revoke
-- timestamps stay TEXT to match the rest of the schema.
CREATE TABLE oauth_client_metadata (
    client_id                TEXT PRIMARY KEY NOT NULL,
    verification             TEXT NOT NULL DEFAULT 'unverified',
    verified_by              TEXT,
    verified_at              TEXT,
    verification_revoked_by  TEXT,
    verification_revoked_at  TEXT,
    source                   TEXT NOT NULL DEFAULT 'admin',
    dcr_iat_id               TEXT,
    dcr_registered_at        TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    audience                 TEXT,
    resource_url             TEXT,
    org_id                   TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX idx_oauth_client_metadata_verification ON oauth_client_metadata (verification);
CREATE INDEX idx_oauth_client_metadata_source ON oauth_client_metadata (source);
CREATE INDEX idx_oauth_client_metadata_org ON oauth_client_metadata (org_id);

CREATE TABLE forseti_license (
    id              TEXT PRIMARY KEY NOT NULL CHECK (id = 'singleton'),
    blob            TEXT NOT NULL,
    license_id      TEXT NOT NULL,
    customer        TEXT NOT NULL,
    email           TEXT NOT NULL,
    tier            TEXT NOT NULL,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT,
    features        TEXT NOT NULL DEFAULT '[]',
    max_orgs        INTEGER,
    max_seats       INTEGER,
    activated_at    TEXT NOT NULL DEFAULT to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    verified_at     TEXT NOT NULL DEFAULT to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
);

CREATE TABLE organizations (
    id              TEXT PRIMARY KEY NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    logo_url        TEXT,
    support_email   TEXT,
    created_at      TEXT NOT NULL,
    created_by      TEXT
);

CREATE TABLE organization_members (
    org_id          TEXT NOT NULL,
    identity_id     TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    added_at        TEXT NOT NULL,
    added_by        TEXT,
    PRIMARY KEY (org_id, identity_id)
);

CREATE INDEX idx_org_members_identity ON organization_members (identity_id);
CREATE INDEX idx_org_members_org ON organization_members (org_id);

CREATE TABLE organization_invites (
    token           TEXT PRIMARY KEY NOT NULL,
    org_id          TEXT NOT NULL,
    email           TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    invited_by      TEXT,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    accepted_at     TEXT,
    accepted_by     TEXT
);

CREATE INDEX idx_org_invites_org ON organization_invites (org_id);
CREATE INDEX idx_org_invites_email ON organization_invites (email);

INSERT INTO organizations (id, slug, name, created_at, created_by)
VALUES (
    'default',
    'default',
    'Default',
    to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    NULL
);

CREATE TABLE member_profiles (
    identity_id     TEXT PRIMARY KEY NOT NULL,
    bio             TEXT,
    location        TEXT,
    pronouns        TEXT,
    website         TEXT,
    avatar_url      TEXT,
    links_json      TEXT,
    updated_at      TEXT NOT NULL
);

CREATE INDEX idx_member_profiles_updated ON member_profiles (updated_at);
