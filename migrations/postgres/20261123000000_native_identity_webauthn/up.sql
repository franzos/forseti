-- WebAuthn keys of the native identity backend: passkeys (a way to sign in) and security keys
-- (kind 'webauthn', a second factor). A credential id belongs to one identity across the install.
-- credential is the webauthn-rs Passkey or SecurityKey as JSON: public key and metadata only.
CREATE TABLE identity_webauthn_keys (
  id            TEXT PRIMARY KEY NOT NULL,
  identity_id   TEXT NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  credential    TEXT NOT NULL,
  sign_count    BIGINT NOT NULL DEFAULT 0,
  version       INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE INDEX idx_identity_webauthn_keys_identity ON identity_webauthn_keys (identity_id, kind);
