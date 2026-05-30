-- Forseti's initial schema (sqlite). Single consolidated migration for the
-- first release. The postgres twin under migrations/postgres/ must stay in
-- lockstep; src/schema.rs is the hand-written diesel mapping (every column
-- Text / Nullable<Text> / Integer, timestamps as ISO-8601 UTC strings).
--
-- Timestamps + booleans are TEXT / INTEGER throughout: the application is the
-- source of truth for ISO-8601 formatting, which keeps both backends identical
-- and lets a single diesel struct map either one.

-- Key/value table seeded on first boot. A stable place to stash install-level
-- facts (install id, schema-tier markers). The audit append-only triggers also
-- read a sentinel row here, so it must exist before audit_events.
CREATE TABLE _forseti_meta (
    key        TEXT PRIMARY KEY NOT NULL,
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Account-deletion outbox. A saga state machine: rows written PENDING during
-- the delete flow, flipped to CONFIRMED once Kratos has removed the identity,
-- then drained by a background worker. Failures retry with backoff; exhausted
-- rows transition to DEAD and surface in /admin/webhooks.
CREATE TABLE webhook_outbox (
    id              TEXT PRIMARY KEY NOT NULL,
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

-- Append-only audit event log. Who did what to whom, plus contextual columns
-- (ip_hash, user_agent, request_id) populated by the AuditCtx middleware.
-- `metadata` is free-form JSON gated through the SafeMetadata newtype in Rust
-- so credentials never reach disk. `org_id` is nullable.
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
-- `(severity, created_at DESC)` serves the /admin/audit severity filter + sort.
CREATE INDEX idx_audit_severity   ON audit_events (severity, created_at DESC);

-- Append-only enforcement. The triggers read a sentinel row in `_forseti_meta`
-- because sqlite has no session settings; the pruner sets it inside the same
-- transaction as the DELETE (via `audit::with_audit_purge`), so a crash
-- mid-prune rolls the lock back atomically.
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
WHEN COALESCE(
    (SELECT value FROM _forseti_meta WHERE key = 'audit_purge_lock'),
    'false'
) != 'true'
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
WHEN COALESCE(
    (SELECT value FROM _forseti_meta WHERE key = 'audit_purge_lock'),
    'false'
) != 'true'
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- One-shot secret-reveal store (client secret rotation, recovery codes,
-- claim-email codes). Survives multi-instance deploys where the minting
-- instance and the post-redirect GET land on different nodes. TTL enforced by
-- the application on take; rows are single-use (take = DELETE). `attempts`
-- lets code-entry reveals hard-fail after N wrong submissions.
CREATE TABLE secret_reveals (
    token       TEXT PRIMARY KEY NOT NULL,
    payload     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_secret_reveals_created_at ON secret_reveals (created_at);

-- Initial Access Tokens for the RFC 7591 DCR proxy at POST /oauth2/register.
-- `token_hash` is sha256(raw_token) hex; raw tokens shown once, never stored.
-- `uses_remaining` NULL = unlimited. `daily_use_count` + `daily_window_started_at`
-- back a rolling 24h cap so even an unlimited token can't be abused for bulk
-- registration (see oauth.dcr_iat_daily_limit).
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

-- Forseti-owned trust state for Hydra OAuth2 clients. Kept here, not on the
-- Hydra client's `metadata`, because RFC 7592 PUT lets the registration-access-
-- token holder rewrite that blob — a DCR client could otherwise forge its own
-- verification badge. `client_id` is a loose FK (Hydra owns its own DB).
-- `audience` / `resource_url` capture "what is this client for?" provenance;
-- `org_id` ties the client to its owning org (backfilled to 'default').
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
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    audience                 TEXT,
    resource_url             TEXT,
    org_id                   TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX idx_oauth_client_metadata_verification ON oauth_client_metadata (verification);
CREATE INDEX idx_oauth_client_metadata_source ON oauth_client_metadata (source);
CREATE INDEX idx_oauth_client_metadata_org ON oauth_client_metadata (org_id);

-- Commercial license. One row per installation, PK pinned to 'singleton' so the
-- "exactly one license" invariant is enforced at the DB layer. The signed blob
-- is the source of truth; the parsed columns are a denormalised cache for the
-- settings UI + boot logs. Empty table in the OSS default; deactivation is a
-- row DELETE.
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
    activated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    verified_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Organizations + membership. OSS ships exactly one "Default" org (seeded
-- below) so every code path uses the same query shape regardless of tier;
-- commercial licenses unlock additional rows. Soft multi-tenancy: org_id sits
-- on resources as a loose string FK (no real constraint) so audit rows survive
-- the eventual hard-delete of an org.
--
-- No SQL DEFAULT on `created_at` / `added_at`: every Rust insert path passes an
-- explicit `Utc::now().to_rfc3339()` string, and the seed below matches that
-- format so seeded timestamps are indistinguishable from application writes.
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

-- Token-backed org invitations (mirrors the secret_reveals pattern): the token
-- is the URL handle, the row carries the bound (org, email, role, expires_at).
-- Accepted / expired rows linger until the prune cutoff so the members page can
-- show "Expired" / "Accepted" status for recently-issued invites.
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

-- Seed the Default org. Operator can rename it; the hard-coded id keeps the
-- oauth_client_metadata.org_id 'default' backfill stable. RFC 3339 format
-- matches the Rust insert path.
INSERT INTO organizations (id, slug, name, created_at, created_by)
VALUES (
    'default',
    'default',
    'Default',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
    NULL
);

-- Portal-owned per-identity profile, gated by [profiles].enabled. Surfaces on
-- /users/{identity_id} and feeds the profile + extended_profile OIDC scopes.
-- Keyed on Kratos identity_id (loose FK). `links_json` is a JSON array of
-- {label, url}; handlers replace the whole list on save.
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
