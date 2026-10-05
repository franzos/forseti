-- Hydra login sessions (`sid`) Forseti accepted, so logout can revoke them by
-- `sid`: Hydra sends back-channel logout only for a named `sid`, and it has no
-- API to list a subject's login sessions.
CREATE TABLE hydra_login_sessions (
  sid               TEXT PRIMARY KEY,
  subject           TEXT NOT NULL,
  kratos_session_id TEXT,
  created_at        TEXT NOT NULL
);

CREATE INDEX idx_hydra_login_sessions_subject ON hydra_login_sessions (subject);
CREATE INDEX idx_hydra_login_sessions_kratos ON hydra_login_sessions (kratos_session_id);
