-- Reverse of the initial schema. Drops everything in reverse dependency order.
DROP INDEX IF EXISTS idx_member_profiles_updated;
DROP TABLE IF EXISTS member_profiles;

DROP INDEX IF EXISTS idx_org_invites_email;
DROP INDEX IF EXISTS idx_org_invites_org;
DROP TABLE IF EXISTS organization_invites;
DROP INDEX IF EXISTS idx_org_members_org;
DROP INDEX IF EXISTS idx_org_members_identity;
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;

DROP TABLE IF EXISTS forseti_license;

DROP INDEX IF EXISTS idx_oauth_client_metadata_org;
DROP INDEX IF EXISTS idx_oauth_client_metadata_source;
DROP INDEX IF EXISTS idx_oauth_client_metadata_verification;
DROP TABLE IF EXISTS oauth_client_metadata;

DROP INDEX IF EXISTS idx_dcr_iat_created_at;
DROP INDEX IF EXISTS idx_dcr_iat_token_hash;
DROP TABLE IF EXISTS dcr_initial_access_tokens;

DROP INDEX IF EXISTS idx_secret_reveals_created_at;
DROP TABLE IF EXISTS secret_reveals;

DROP TRIGGER IF EXISTS audit_events_no_modify ON audit_events;
DROP FUNCTION IF EXISTS audit_events_block_modify();
DROP INDEX IF EXISTS idx_audit_severity;
DROP INDEX IF EXISTS idx_audit_target;
DROP INDEX IF EXISTS idx_audit_action;
DROP INDEX IF EXISTS idx_audit_actor;
DROP INDEX IF EXISTS idx_audit_created_at;
DROP TABLE IF EXISTS audit_events;

DROP INDEX IF EXISTS idx_webhook_outbox_event;
DROP INDEX IF EXISTS idx_webhook_outbox_state_next;
DROP TABLE IF EXISTS webhook_outbox;

DROP TABLE IF EXISTS _forseti_meta;
