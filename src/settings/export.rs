//! `/settings/account/export`: everything Forseti holds about the signed-in
//! person as one JSON download in the shared account-export envelope.
//! Secrets (verifiers, hashes, tokens, credential `config`) never pass
//! through; their existence and metadata do.

use std::collections::{BTreeMap, HashMap};

use anyhow::Context as _;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde_json::{Value, json};

use crate::FlowQuery;
use crate::audit::{self, AuditCtx, AuditEvent, AuditFilter, AuditRow, action, target_kind};
use crate::audit_metadata;
use crate::db::DbPool;
use crate::ory::{self, Identity, OAuth2ConsentSession, Session};
use crate::state::AppState;

use super::{SettingsSection, fetch_settings_subpage};

pub(crate) const EXPORT_FORMAT: &str = "gofranz-account-export";
pub(crate) const EXPORT_FORMAT_VERSION: u64 = 1;

/// `audit::query` clamps `limit` to 200.
const AUDIT_PAGE: i64 = 200;

pub(crate) async fn settings_account_export(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
) -> Response {
    if let Err(resp) = fetch_settings_subpage(
        &state,
        &headers,
        &query,
        SettingsSection::Export,
        &sess,
        &locale,
    )
    .await
    {
        return resp;
    }

    let export = match build_export(&state, &sess.identity_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, identity_id = %sess.identity_id, "account export failed");
            return crate::web::render_error_boundary(
                &state,
                &locale,
                &crate::i18n::lookup(&locale, "error-boundary-account-export-title"),
                &crate::i18n::lookup(&locale, "error-boundary-account-export-failed"),
                "/settings/account",
                crate::i18n::lookup(&locale, "error-boundary-cta-back-to-account"),
            )
            .into_response();
        }
    };

    let audit_rows = export["audit"].as_array().map_or(0, Vec::len);
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ACCOUNT_EXPORTED)
            .actor_user(&sess.identity_id, &sess.email)
            .target(target_kind::IDENTITY, sess.identity_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!("audit_rows" => audit_rows)),
    )
    .await;

    let filename = format!("forseti-export-{}.json", Utc::now().format("%Y-%m-%d"));
    crate::web::download_json(&filename, &export)
}

/// Assemble the envelope. Any source failing fails the whole export: a
/// document silently missing a section is exactly the gap it exists to close.
pub(crate) async fn build_export(state: &AppState, identity_id: &str) -> anyhow::Result<Value> {
    let db = &state.db;
    let ory = &state.ory;

    let identity = ory::kratos::admin_get_identity_full(ory, identity_id)
        .await
        .context("kratos identity")?;
    let emails = identity_emails(&identity);
    let profile = crate::profiles::fetch(db, identity_id)
        .await
        .context("profile")?;
    let oidc_links = super::oidc_links_db::list_for_identity(db, identity_id)
        .await
        .context("oidc links")?;
    let sessions = ory::kratos::list_identity_sessions_all(ory, identity_id)
        .await
        .context("kratos sessions")?;
    let (as_actor, as_target) = audit_rows(db, identity_id).await.context("audit")?;
    let consents = ory::hydra::list_consent_sessions_by_subject(ory, identity_id)
        .await
        .context("hydra consents")?;
    let hydra_local = crate::oauth::op_sessions::rows_for_subject(db, identity_id)
        .await
        .context("hydra local rows")?;
    let memberships = memberships(db, identity_id).await.context("memberships")?;
    let teams = crate::orgs::teams::team_memberships_for_identity(db, identity_id)
        .await
        .context("teams")?;
    let invites = crate::orgs::db::invites_for_emails(db, &emails)
        .await
        .context("invites")?;
    let username_history = crate::profiles::username_history(db, identity_id)
        .await
        .context("username history")?;
    let saml_links = crate::saml::db::links_for_identity(db, identity_id)
        .await
        .context("saml links")?;
    let posix_account = crate::posix::db::account_by_identity(db, identity_id)
        .await
        .context("posix account")?;
    let ssh_keys = crate::posix::db::all_authorized_keys_for(db, identity_id)
        .await
        .context("ssh keys")?;
    let group_members = crate::posix::db::group_memberships_for_identity(db, identity_id)
        .await
        .context("posix group members")?;
    let host_logins = crate::posix::db::host_logins_for_identity(db, identity_id)
        .await
        .context("host logins")?;
    let device_sessions = crate::posix::db::device_sessions_for_identity(db, identity_id)
        .await
        .context("device sessions")?;
    let offline_secret = crate::posix::db::get_offline_secret(db, identity_id)
        .await
        .context("offline secret")?;

    let mut account = project_identity(&identity);
    account["username"] = json!(profile.username);

    Ok(json!({
        "format": EXPORT_FORMAT,
        "format_version": EXPORT_FORMAT_VERSION,
        "product": "forseti",
        "exported_at": Utc::now().to_rfc3339(),
        "account": account,
        "identities": linked_identities(&identity, &oidc_links),
        "sessions": project_sessions(&sessions),
        "billing": Value::Null,
        "audit": merge_audit(as_actor, as_target),
        "data": {
            "hydra_consents": project_consents(consents),
            "hydra_local": hydra_local,
            "orgs": {
                "memberships": memberships,
                "teams": teams.iter().map(|(t, source, added_at)| json!({
                    "id": t.id,
                    "org_id": t.org_id,
                    "name": t.name,
                    "slug": t.slug,
                    "gid": t.gid,
                    "parent_id": t.parent_id,
                    "created_at": t.created_at,
                    "source": source,
                    "added_at": added_at,
                })).collect::<Vec<_>>(),
                "invites": invites,
            },
            "profile": {
                "username": profile.username,
                "bio": profile.bio,
                "location": profile.location,
                "pronouns": profile.pronouns,
                "website": profile.website,
                "avatar_url": profile.avatar_url,
                "links": profile.links,
                "updated_at": profile.updated_at,
            },
            "username_history": username_history.iter().map(|(username, released_at)| json!({
                "username": username,
                "released_at": released_at,
            })).collect::<Vec<_>>(),
            "oidc_links": oidc_links.iter().map(|(provider, first_seen_at)| json!({
                "provider": provider,
                "first_seen_at": first_seen_at,
            })).collect::<Vec<_>>(),
            "saml_links": saml_links,
            "posix": {
                "account": posix_account,
                "ssh_keys": ssh_keys,
                "group_members": group_members.iter().map(|(gid, added_at)| json!({
                    "gid": gid,
                    "added_at": added_at,
                })).collect::<Vec<_>>(),
                "host_logins": host_logins,
                "device_sessions": device_sessions,
            },
            "offline_secret": {
                "set": offline_secret.is_some(),
                "algo_version": offline_secret.as_ref().map(|s| s.algo_version),
                "created_at": offline_secret.as_ref().map(|s| &s.created_at),
                "updated_at": offline_secret.as_ref().map(|s| &s.updated_at),
            },
        },
    }))
}

/// Whitelist projection of the Kratos identity: credentials reduced to their
/// metadata, `config` never read, `metadata_admin` left out.
fn project_identity(identity: &Identity) -> Value {
    let credentials: BTreeMap<&str, Value> = identity
        .credentials
        .iter()
        .flat_map(|m| m.iter())
        .map(|(kind, c)| {
            (
                kind.as_str(),
                json!({
                    "type": kind,
                    "identifiers": c.identifiers.clone().unwrap_or_default(),
                    "created_at": c.created_at,
                    "updated_at": c.updated_at,
                    "version": c.version,
                }),
            )
        })
        .collect();
    let verifiable_addresses: Vec<Value> = identity
        .verifiable_addresses
        .iter()
        .flatten()
        .map(|a| {
            json!({
                "id": a.id,
                "value": a.value,
                "via": a.via,
                "status": a.status,
                "verified": a.verified,
                "verified_at": a.verified_at,
                "created_at": a.created_at,
                "updated_at": a.updated_at,
            })
        })
        .collect();
    let recovery_addresses: Vec<Value> = identity
        .recovery_addresses
        .iter()
        .flatten()
        .map(|a| {
            json!({
                "id": a.id,
                "value": a.value,
                "via": a.via,
                "created_at": a.created_at,
                "updated_at": a.updated_at,
            })
        })
        .collect();
    json!({
        "id": identity.id,
        "schema_id": identity.schema_id,
        "state": identity.state,
        "state_changed_at": identity.state_changed_at,
        "created_at": identity.created_at,
        "updated_at": identity.updated_at,
        "external_id": identity.external_id,
        "organization_id": identity.organization_id.clone().flatten(),
        "traits": identity.traits,
        "metadata_public": identity.metadata_public.clone().flatten(),
        "verifiable_addresses": verifiable_addresses,
        "recovery_addresses": recovery_addresses,
        "credentials": credentials.into_values().collect::<Vec<_>>(),
    })
}

/// Every address the identity is known by, lowercased and de-duplicated.
fn identity_emails(identity: &Identity) -> Vec<String> {
    let mut emails: Vec<String> = identity
        .verifiable_addresses
        .iter()
        .flatten()
        .map(|a| a.value.as_str())
        .chain(
            identity
                .recovery_addresses
                .iter()
                .flatten()
                .map(|a| a.value.as_str()),
        )
        .chain(
            identity
                .traits
                .as_ref()
                .and_then(|t| t.get("email"))
                .and_then(Value::as_str),
        )
        .map(str::to_lowercase)
        .filter(|e| !e.is_empty())
        .collect();
    emails.sort();
    emails.dedup();
    emails
}

/// Upstream OIDC identities from the `provider:subject` credential
/// identifiers, joined with the date Forseti first saw each provider. The
/// upstream issuer, email and name are not stored.
fn linked_identities(identity: &Identity, oidc_links: &[(String, String)]) -> Vec<Value> {
    let first_seen: HashMap<&str, &str> = oidc_links
        .iter()
        .map(|(p, at)| (p.as_str(), at.as_str()))
        .collect();
    identity
        .credentials
        .as_ref()
        .and_then(|m| m.get("oidc"))
        .and_then(|c| c.identifiers.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|id| id.split_once(':'))
        .map(|(provider, sub)| {
            json!({
                "iss": Value::Null,
                "sub": sub,
                "provider": provider,
                "first_seen_at": first_seen.get(provider),
                "email": Value::Null,
                "name": Value::Null,
            })
        })
        .collect()
}

fn project_sessions(sessions: &[Session]) -> Vec<Value> {
    sessions
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "active": s.active,
                "issued_at": s.issued_at,
                "authenticated_at": s.authenticated_at,
                "expires_at": s.expires_at,
                "aal": s.authenticator_assurance_level,
                "methods": s.authentication_methods,
                "devices": s.devices.iter().flatten().map(|d| json!({
                    "ip_address": d.ip_address,
                    "user_agent": d.user_agent,
                    "location": d.location,
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// One row per Hydra consent session, flattened to the grant and the client.
fn project_consents(sessions: Vec<OAuth2ConsentSession>) -> Vec<Value> {
    sessions
        .into_iter()
        .map(|s| {
            let client = s.consent_request.as_ref().and_then(|r| r.client.as_ref());
            json!({
                "consent_request_id": s.consent_request_id,
                "client_id": client.and_then(|c| c.client_id.clone()),
                "client_name": client.and_then(|c| c.client_name.clone()),
                "scopes": s.grant_scope.unwrap_or_default(),
                "audience": s.grant_access_token_audience.unwrap_or_default(),
                "granted_at": s.handled_at,
                "remember": s.remember,
                "remember_for": s.remember_for,
                "login_session_id": s.consent_request.as_ref().and_then(|r| r.login_session_id.clone()),
            })
        })
        .collect()
}

/// Memberships with the row's own timestamps, without `added_by`. Uncapped.
async fn memberships(db: &DbPool, identity_id: &str) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::new();
    for m in crate::orgs::db::list_memberships_limited(db, identity_id, i64::MAX).await? {
        let row = crate::orgs::db::find_member(db, identity_id, &m.org_id).await?;
        out.push(json!({
            "org_id": m.org_id,
            "slug": m.slug,
            "name": m.name,
            "role": m.role,
            "added_at": row.as_ref().map(|r| &r.added_at),
            "hidden_from_directory": row.as_ref().map(|r| r.hidden_from_directory != 0),
        }));
    }
    Ok(out)
}

/// Every audit row naming the identity as actor, and every row naming it as
/// target, each paged to exhaustion.
async fn audit_rows(
    db: &DbPool,
    identity_id: &str,
) -> anyhow::Result<(Vec<AuditRow>, Vec<AuditRow>)> {
    let as_actor = audit_rows_matching(
        db,
        AuditFilter {
            actor_id: Some(identity_id.to_string()),
            ..Default::default()
        },
    )
    .await?;
    let as_target = audit_rows_matching(
        db,
        AuditFilter {
            target_id: Some(identity_id.to_string()),
            ..Default::default()
        },
    )
    .await?;
    Ok((as_actor, as_target))
}

async fn audit_rows_matching(db: &DbPool, filter: AuditFilter) -> anyhow::Result<Vec<AuditRow>> {
    let mut rows = Vec::new();
    let mut offset = 0;
    loop {
        let (page, total) = audit::query(
            db,
            AuditFilter {
                limit: AUDIT_PAGE,
                offset,
                ..filter.clone()
            },
        )
        .await?;
        let n = page.len() as i64;
        rows.extend(page);
        offset += n;
        if n == 0 || offset >= total {
            return Ok(rows);
        }
    }
}

/// Merge the two match sets, oldest first, tagging each row with the `role`
/// the identity played: `actor`, `target`, or `both`.
fn merge_audit(as_actor: Vec<AuditRow>, as_target: Vec<AuditRow>) -> Vec<Value> {
    let mut by_id: BTreeMap<(String, String), (AuditRow, &'static str)> = BTreeMap::new();
    for row in as_actor {
        by_id.insert((row.created_at.clone(), row.id.clone()), (row, "actor"));
    }
    for row in as_target {
        by_id
            .entry((row.created_at.clone(), row.id.clone()))
            .and_modify(|(_, role)| *role = "both")
            .or_insert((row, "target"));
    }
    by_id
        .into_values()
        .map(|(row, role)| {
            let metadata = serde_json::from_str::<Value>(&row.metadata)
                .unwrap_or(Value::String(row.metadata.clone()));
            json!({
                "id": row.id,
                "event": row.action,
                "at": row.created_at,
                "role": role,
                "success": row.succeeded(),
                "severity": row.severity,
                "actor_kind": row.actor_kind,
                "actor_id": row.actor_id,
                "actor_email": row.actor_email,
                "target_kind": row.target_kind,
                "target_id": row.target_id,
                "org_id": row.org_id,
                "ip_hash": row.ip_hash,
                "user_agent": row.user_agent,
                "request_id": row.request_id,
                "metadata": metadata,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ory_client::models::IdentityCredentials;

    const SECRET_KEYS: &[&str] = &[
        "verifier",
        "secret_hash",
        "password",
        "hashed_password",
        "config",
        "totp_url",
        "token",
        "code",
        "initial_access_token",
        "client_code_hash",
        "device_code",
        "user_code",
        "private_key",
        "secret",
    ];

    fn assert_no_secret_keys(v: &Value) {
        match v {
            Value::Object(map) => {
                for (k, v) in map {
                    assert!(
                        !SECRET_KEYS.contains(&k.as_str()),
                        "secret key `{k}` exported"
                    );
                    assert_no_secret_keys(v);
                }
            }
            Value::Array(items) => items.iter().for_each(assert_no_secret_keys),
            _ => {}
        }
    }

    fn row(id: &str, created_at: &str) -> AuditRow {
        AuditRow {
            id: id.to_string(),
            created_at: created_at.to_string(),
            actor_kind: "user".to_string(),
            actor_id: Some("ident-1".to_string()),
            actor_email: Some("a@example.com".to_string()),
            action: "auth.login".to_string(),
            target_kind: Some("identity".to_string()),
            target_id: Some("ident-1".to_string()),
            org_id: None,
            ip_hash: Some("abc".to_string()),
            user_agent: Some("ua".to_string()),
            request_id: None,
            severity: "info".to_string(),
            success: 1,
            metadata: r#"{"k":"v"}"#.to_string(),
        }
    }

    #[test]
    fn merge_audit_dedupes_by_id_tags_the_role_and_orders_oldest_first() {
        let as_actor = vec![
            row("b", "2026-01-02T00:00:00Z"),
            row("a", "2026-01-01T00:00:00Z"),
        ];
        let as_target = vec![
            row("b", "2026-01-02T00:00:00Z"),
            row("c", "2026-01-03T00:00:00Z"),
        ];
        let merged = merge_audit(as_actor, as_target);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0]["id"], "a");
        assert_eq!(merged[0]["role"], "actor");
        assert_eq!(merged[1]["id"], "b");
        assert_eq!(merged[1]["role"], "both");
        assert_eq!(merged[2]["id"], "c");
        assert_eq!(merged[2]["role"], "target");
        assert_eq!(merged[1]["event"], "auth.login");
        assert_eq!(merged[1]["success"], true);
        assert_eq!(merged[1]["metadata"]["k"], "v");
        assert_eq!(merged[1]["ip_hash"], "abc");
        assert_eq!(merged[1]["actor_id"], "ident-1");
        assert_eq!(merged[1]["actor_email"], "a@example.com");
        assert_no_secret_keys(&Value::Array(merged));
    }

    #[test]
    fn project_identity_drops_credential_config_and_admin_metadata() {
        let mut identity = Identity::new(
            "ident-1".to_string(),
            "default".to_string(),
            "http://kratos/schemas/default".to_string(),
            Some(json!({"email": "A@example.com"})),
        );
        identity.metadata_admin = Some(Some(json!({"note": "operator only"})));
        let mut password = IdentityCredentials::new();
        password.config = Some(json!({"hashed_password": "$argon2id$v=19$m=65536$SECRET-HASH"}));
        password.identifiers = Some(vec!["a@example.com".to_string()]);
        password.created_at = Some("2026-01-01T00:00:00Z".to_string());
        password.version = Some(1);
        let mut oidc = IdentityCredentials::new();
        oidc.config = Some(json!({
            "providers": [{"provider": "github", "subject": "123", "initial_access_token": "gho_SECRET"}]
        }));
        oidc.identifiers = Some(vec!["github:123".to_string()]);
        identity.credentials = Some(HashMap::from([
            ("password".to_string(), password),
            ("oidc".to_string(), oidc),
        ]));

        let out = project_identity(&identity);
        assert_no_secret_keys(&out);
        let text = out.to_string();
        assert!(!text.contains("SECRET-HASH"));
        assert!(!text.contains("gho_SECRET"));
        assert!(!text.contains("operator only"));
        assert!(out.get("metadata_admin").is_none());
        let creds = out["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0]["type"], "oidc");
        assert_eq!(creds[1]["type"], "password");
        assert_eq!(creds[1]["identifiers"][0], "a@example.com");
        assert_eq!(creds[1]["version"], 1);
        assert_eq!(out["traits"]["email"], "A@example.com");

        let ids = linked_identities(
            &identity,
            &[("github".into(), "2026-02-01T00:00:00Z".into())],
        );
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0]["provider"], "github");
        assert_eq!(ids[0]["sub"], "123");
        assert_eq!(ids[0]["first_seen_at"], "2026-02-01T00:00:00Z");
        assert_no_secret_keys(&Value::Array(ids));

        assert_eq!(
            identity_emails(&identity),
            vec!["a@example.com".to_string()]
        );
    }
}
