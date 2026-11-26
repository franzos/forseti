-- Signing keys of the native OAuth server. kid is the RFC 7638 thumbprint of public_jwk;
-- private_sealed is the PKCS#8 private key sealed under a sub-key of [security].cookie_secret.
-- JWKS publishes every row; the one active row signs.
CREATE TABLE oauth_signing_keys (
  kid            TEXT PRIMARY KEY NOT NULL,
  alg            TEXT NOT NULL,
  public_jwk     TEXT NOT NULL,
  private_sealed TEXT NOT NULL,
  status         TEXT NOT NULL,
  created_at     TEXT NOT NULL,
  retired_at     TEXT
);

CREATE UNIQUE INDEX idx_oauth_signing_keys_active ON oauth_signing_keys (status) WHERE status = 'active';
