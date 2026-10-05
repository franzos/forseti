-- Consent requests Forseti accepted, keyed to the Hydra login session (`sid`)
-- they belong to, so revoking a session can revoke its grants by
-- `consent_request_id`. Hydra's consent listing omits skipped consents.
CREATE TABLE hydra_consent_grants (
  consent_request_id TEXT PRIMARY KEY,
  sid                TEXT NOT NULL,
  subject            TEXT NOT NULL,
  client_id          TEXT NOT NULL,
  created_at         TEXT NOT NULL
);

CREATE INDEX idx_hydra_consent_grants_sid ON hydra_consent_grants (sid);
