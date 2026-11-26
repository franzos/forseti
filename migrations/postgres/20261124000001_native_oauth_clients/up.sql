-- OAuth clients of the native authorization server, in the Hydra client shape. List columns and
-- metadata are JSON text; extra is a JSON object of every other client field. secret_hash is an
-- Argon2id PHC string, NULL for a client without a secret.
CREATE TABLE oauth_clients (
  client_id                            TEXT PRIMARY KEY NOT NULL,
  client_name                          TEXT,
  secret_hash                          TEXT,
  token_endpoint_auth_method           TEXT NOT NULL,
  redirect_uris                        TEXT,
  post_logout_redirect_uris            TEXT,
  grant_types                          TEXT,
  response_types                       TEXT,
  audience                             TEXT,
  scope                                TEXT,
  skip_consent                         INTEGER,
  logo_uri                             TEXT,
  client_uri                           TEXT,
  backchannel_logout_uri               TEXT,
  backchannel_logout_session_required  INTEGER,
  frontchannel_logout_uri              TEXT,
  frontchannel_logout_session_required INTEGER,
  metadata                             TEXT,
  extra                                TEXT NOT NULL,
  created_at                           TEXT NOT NULL,
  updated_at                           TEXT NOT NULL
);

CREATE INDEX idx_oauth_clients_name ON oauth_clients (client_name, client_id);
