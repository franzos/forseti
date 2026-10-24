//! One deletion path for every entry point: the settings page, the admin
//! page, the CLI, the email-reclaim flow and `unverified-prune`.
//!
//! Order: guard, collect, enqueue the `account-purged` SETs as PENDING, end
//! the OP sessions, delete the Kratos identity (point of no return; the
//! outbox is confirmed or aborted here), delete the rows the Kratos cascade
//! never reaches, null the references other people's data keeps, write one
//! audit row. Everything after the Kratos call is best-effort and reported
//! as orphans rather than returned as an error.

use std::fmt;

use chrono::Utc;
use uuid::Uuid;

use crate::audit::{self, AuditCtx, AuditEvent, SafeMetadata, action, target_kind};
use crate::audit_metadata;
use crate::config::AppConfig;
use crate::db::DbPool;
use crate::oauth::op_sessions::{GrantRevocation, end_op_sessions_for_subject, forget_subject};
use crate::ory::{self, OryClients};
use crate::state::AppState;
use crate::webhook::{self, SetIssuers, SigningKey, WebhookTarget};

/// What a deletion needs from the process, borrowed so the server, the CLI
/// and the prune can all supply it.
pub struct DeleteEnv<'a> {
    pub db: &'a DbPool,
    pub ory: &'a OryClients,
    pub signing_key: &'a SigningKey,
    /// Envelope `iss` of the SET: Forseti's own URL.
    pub self_url: &'a str,
    /// `iss` of the `iss-sub` subject: the OIDC issuer.
    pub issuer: &'a str,
}

impl<'a> DeleteEnv<'a> {
    pub fn from_state(state: &'a AppState) -> Self {
        Self {
            db: &state.db,
            ory: &state.ory,
            signing_key: &state.signing_key,
            self_url: &state.cfg.self_.url,
            issuer: state.cfg.hydra.issuer_or_public(),
        }
    }
}

/// Load the webhook signing key the way the server does, for CLI callers.
/// Returns the key and whether a fresh one had to be generated.
pub(crate) fn signing_key_from_config(cfg: &AppConfig) -> anyhow::Result<(SigningKey, bool)> {
    let path = std::path::Path::new(&cfg.webhook.signing_key_path);
    let existed = path.exists();
    let key = SigningKey::load_or_generate(path)?;
    Ok((key, !existed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteReason {
    SelfService,
    Admin,
    Cli,
    Reclaim,
    Prune,
}

impl DeleteReason {
    fn action(self) -> &'static str {
        match self {
            DeleteReason::SelfService => action::ACCOUNT_SELF_DELETED,
            DeleteReason::Admin | DeleteReason::Cli => action::ADMIN_IDENTITY_DELETED,
            DeleteReason::Reclaim => action::IDENTITY_RECLAIMED,
            DeleteReason::Prune => action::IDENTITY_PRUNED,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DeleteReason::SelfService => "self_service",
            DeleteReason::Admin => "admin",
            DeleteReason::Cli => "cli",
            DeleteReason::Reclaim => "reclaim",
            DeleteReason::Prune => "prune",
        }
    }

    /// Reclaim and prune delete identities that own nothing; the guard is
    /// skipped there.
    fn guards_sole_owner(self) -> bool {
        matches!(
            self,
            DeleteReason::SelfService | DeleteReason::Admin | DeleteReason::Cli
        )
    }

    /// Reclaim hands the address to the person proving ownership, prune may
    /// free it for its real owner; their pending invites and the email-matched
    /// references must survive.
    fn removes_email_rows(self) -> bool {
        matches!(
            self,
            DeleteReason::SelfService | DeleteReason::Admin | DeleteReason::Cli
        )
    }
}

#[derive(Debug, Clone)]
pub enum DeleteActor {
    User { id: String, email: String },
    Admin { id: String, email: String },
    System { source: String },
}

pub struct DeleteRequest {
    pub identity_id: String,
    pub reason: DeleteReason,
    pub actor: DeleteActor,
    /// CLI only: proceed past the sole-owner guard.
    pub force: bool,
    pub ctx: Option<AuditCtx>,
    /// Extra audit metadata; merged under the deletion's own keys.
    pub metadata: SafeMetadata,
}

/// What each best-effort step removed.
#[derive(Debug, Clone, Default)]
pub struct Removed {
    pub webhook_targets: usize,
    pub org_memberships: usize,
    pub posix: bool,
    pub profile: bool,
    pub username_history: usize,
    pub oidc_links: usize,
    pub op_session_rows: bool,
    pub invites: usize,
    pub references_nulled: usize,
}

impl Removed {
    /// One line for logs and CLI output.
    pub fn summary(&self) -> String {
        let mut parts = vec![
            format!("webhook targets {}", self.webhook_targets),
            format!("org memberships {}", self.org_memberships),
        ];
        if self.posix {
            parts.push("posix rows".to_string());
        }
        if self.profile {
            parts.push("profile".to_string());
        }
        parts.push(format!("username history {}", self.username_history));
        parts.push(format!("oidc links {}", self.oidc_links));
        if self.op_session_rows {
            parts.push("op session rows".to_string());
        }
        parts.push(format!("invites {}", self.invites));
        parts.push(format!("references nulled {}", self.references_nulled));
        parts.join(", ")
    }
}

/// A step that failed after the point of no return.
#[derive(Debug, Clone)]
pub struct Orphan {
    pub step: &'static str,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct DeletionReport {
    pub identity_id: String,
    pub event_id: Uuid,
    /// Verified addresses the email-matched steps used.
    pub emails: Vec<String>,
    pub removed: Removed,
    pub orphans: Vec<Orphan>,
    /// Organizations whose only owner was deleted (CLI with `force`).
    pub orgs_left_without_owner: Vec<String>,
}

/// Which read of the collect step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectStep {
    /// Hydra consent sessions (the webhook targets).
    Consents,
    /// The Kratos identity (its verified addresses).
    Identity,
}

/// Failures before the point of no return; the identity is intact.
#[derive(Debug)]
pub enum DeleteError {
    /// Names of the organizations the identity is the sole owner of while
    /// other members remain.
    SoleOwner(Vec<String>),
    /// The sole-owner lookup itself failed.
    Guard(anyhow::Error),
    Collect(CollectStep, anyhow::Error),
    Outbox(anyhow::Error),
    Kratos(anyhow::Error),
}

impl fmt::Display for DeleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteError::SoleOwner(names) => {
                write!(f, "sole owner of {} with other members", names.join(", "))
            }
            DeleteError::Guard(e) => write!(f, "ownership check failed: {e}"),
            DeleteError::Collect(CollectStep::Consents, e) => {
                write!(f, "consent lookup failed: {e}")
            }
            DeleteError::Collect(CollectStep::Identity, e) => {
                write!(f, "identity lookup failed: {e}")
            }
            DeleteError::Outbox(e) => write!(f, "outbox write failed: {e}"),
            DeleteError::Kratos(e) => write!(f, "kratos delete failed: {e}"),
        }
    }
}

impl std::error::Error for DeleteError {}

/// A consented client that registered a deletion URL that passes the SSRF
/// guard. Hydra's RFC 7592 endpoint writes client metadata without the admin
/// form, so the save-time check is re-applied on every read.
pub(crate) struct NotifiedClient {
    pub client_id: String,
    pub name: String,
    pub url: String,
}

pub(crate) async fn notified_clients(
    ory: &OryClients,
    user_id: &str,
) -> anyhow::Result<Vec<NotifiedClient>> {
    let sessions = ory::hydra::list_consent_sessions_by_subject(ory, user_id).await?;
    let mut seen: std::collections::HashSet<String> = Default::default();
    let mut out = Vec::new();
    for sess in sessions {
        let Some(req) = sess.consent_request else {
            continue;
        };
        let Some(client) = req.client else { continue };
        let Some(client_id) = client.client_id else {
            continue;
        };
        if !seen.insert(client_id.clone()) {
            continue;
        }
        let Some(url) = deletion_url_from_metadata(client.metadata.as_ref()) else {
            continue;
        };
        if let Err(reason) = webhook::validate_webhook_url(&url) {
            tracing::warn!(
                client_id = %client_id,
                reason = %reason,
                "skipping account-deletion webhook target: unsafe URL"
            );
            continue;
        }
        out.push(NotifiedClient {
            name: client.client_name.unwrap_or_else(|| client_id.clone()),
            client_id,
            url,
        });
    }
    Ok(out)
}

/// `metadata.forseti.account_deletion_url` from a Hydra client.
fn deletion_url_from_metadata(metadata: Option<&serde_json::Value>) -> Option<String> {
    metadata?
        .get("forseti")?
        .get("account_deletion_url")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// The identity's verified addresses, lowercased and de-duplicated. Only
/// these drive the email-matched deletes: an unverified trait may be someone
/// else's address, whose invites and provenance must not go with this account.
/// Recovery addresses carry no verified flag in Kratos and are left out.
pub(crate) fn verified_emails(identity: &ory_client::models::Identity) -> Vec<String> {
    let mut emails: Vec<String> = Vec::new();
    for addr in identity.verifiable_addresses.iter().flatten() {
        if !addr.verified {
            continue;
        }
        let v = addr.value.trim().to_lowercase();
        if !v.is_empty() && !emails.contains(&v) {
            emails.push(v);
        }
    }
    emails
}

/// A missing identity yields an empty set.
async fn identity_verified_emails(ory: &OryClients, id: &str) -> anyhow::Result<Vec<String>> {
    Ok(ory::kratos::admin_get_identity_full_optional(ory, id)
        .await?
        .as_ref()
        .map(verified_emails)
        .unwrap_or_default())
}

pub async fn delete_identity(
    env: &DeleteEnv<'_>,
    req: DeleteRequest,
) -> Result<DeletionReport, DeleteError> {
    let id = req.identity_id.as_str();
    let event_id = Uuid::new_v4();
    let deleted_at = Utc::now();
    let reason = req.reason;

    tracing::info!(
        action = "identity.delete.start",
        reason = reason.as_str(),
        event_id = %event_id,
        identity_id = %id,
        "identity delete starting"
    );

    let mut orgs_left_without_owner = Vec::new();
    if reason.guards_sole_owner() {
        let blocking = crate::orgs::db::orgs_where_sole_owner_with_other_members(env.db, id)
            .await
            .map_err(DeleteError::Guard)?;
        if !blocking.is_empty() {
            let names: Vec<String> = blocking.into_iter().map(|(_, name)| name).collect();
            if reason == DeleteReason::Cli && req.force {
                orgs_left_without_owner = names;
            } else {
                return Err(DeleteError::SoleOwner(names));
            }
        }
    }

    // Reads before any write: a Hydra outage here is a clean refusal, while
    // an empty target list after the delete would leave integrators with a
    // copy nobody told them to drop.
    let targets: Vec<WebhookTarget> = notified_clients(env.ory, id)
        .await
        .map_err(|e| DeleteError::Collect(CollectStep::Consents, e))?
        .into_iter()
        .map(|c| WebhookTarget {
            client_id: c.client_id,
            url: c.url,
        })
        .collect();
    let emails = identity_verified_emails(env.ory, id)
        .await
        .map_err(|e| DeleteError::Collect(CollectStep::Identity, e))?;

    webhook::enqueue_pending(
        env.db,
        env.signing_key,
        SetIssuers {
            set: env.self_url,
            subject: env.issuer,
        },
        event_id,
        id,
        deleted_at,
        &targets,
    )
    .await
    .map_err(DeleteError::Outbox)?;

    end_op_sessions_for_subject(env.db, env.ory, id, None, GrantRevocation::Keep).await;

    if let Err(e) = ory::kratos::admin_delete_identity(env.ory, id).await {
        if let Err(e2) = webhook::abort_event(env.db, event_id).await {
            tracing::error!(error = %e2, event_id = %event_id, "outbox abort failed");
        }
        return Err(DeleteError::Kratos(e));
    }
    if let Err(e) = webhook::confirm_event(env.db, event_id).await {
        tracing::error!(
            error = %e,
            event_id = %event_id,
            "outbox confirm failed; rows stay PENDING and will be reconciled at startup"
        );
    }

    let mut removed = Removed {
        webhook_targets: targets.len(),
        ..Removed::default()
    };
    let mut orphans: Vec<Orphan> = Vec::new();
    let mut orphan = |step: &'static str, e: anyhow::Error| {
        orphans.push(Orphan {
            step,
            error: format!("{e:#}"),
        });
    };

    match crate::orgs::db::remove_member_everywhere(env.db, id).await {
        Ok(n) => removed.org_memberships = n,
        Err(e) => orphan("org_memberships", e),
    }
    match crate::posix::db::delete_account_rows(env.db, id).await {
        Ok(()) => removed.posix = true,
        Err(e) => orphan("posix", e),
    }
    match crate::profiles::delete_for_identity(env.db, id).await {
        Ok((profile, history)) => {
            removed.profile = profile;
            removed.username_history = history;
        }
        Err(e) => orphan("profile", e),
    }
    match crate::settings::oidc_links_db::delete_for_identity(env.db, id).await {
        Ok(n) => removed.oidc_links = n,
        Err(e) => orphan("oidc_links", e),
    }
    match forget_subject(env.db, id).await {
        Ok(()) => removed.op_session_rows = true,
        Err(e) => orphan("op_sessions", e),
    }
    if reason.removes_email_rows() && !emails.is_empty() {
        match crate::orgs::db::delete_invites_for_emails(env.db, &emails).await {
            Ok(n) => removed.invites = n,
            Err(e) => orphan("invites", e),
        }
    }
    let email_match: &[String] = if reason.removes_email_rows() {
        &emails
    } else {
        &[]
    };
    match super::pseudonymise::null_references(env.db, id, email_match).await {
        Ok(n) => removed.references_nulled = n,
        Err(e) => orphan("references", e),
    }

    let orphan_steps: Vec<&str> = orphans.iter().map(|o| o.step).collect();
    let mut metadata = req.metadata.merge(audit_metadata!(
        "reason" => reason.as_str(),
        "event_id" => event_id.to_string(),
        "webhook_targets" => targets.len(),
        "orphan_count" => orphans.len(),
        "orphans" => orphan_steps,
    ));
    if !orgs_left_without_owner.is_empty() {
        metadata = metadata.merge(audit_metadata!(
            "orgs_left_without_owner" => orgs_left_without_owner.clone(),
        ));
    }
    let mut event = AuditEvent::new(reason.action())
        .target(target_kind::IDENTITY, id.to_string())
        .critical()
        .metadata(metadata);
    event = match &req.actor {
        DeleteActor::User { id, email } => event.actor_user(id, email),
        DeleteActor::Admin { id, email } => event.actor_admin(id, email),
        DeleteActor::System { source } => event.actor_system(source),
    };
    if let Some(ctx) = req.ctx.as_ref() {
        event = event.with_ctx(ctx);
    }
    // The identity is already gone, so a failed row can't unwind anything;
    // `audit::log` emits the `audit_fallback` stderr line.
    if let Err(e) = audit::log(env.db, event).await {
        tracing::error!(
            error = %e,
            event_id = %event_id,
            identity_id = %id,
            "CRITICAL audit row for identity delete failed to persist; recover from audit_fallback stderr event"
        );
    }

    let report = DeletionReport {
        identity_id: req.identity_id,
        event_id,
        emails,
        removed,
        orphans,
        orgs_left_without_owner,
    };
    for o in &report.orphans {
        tracing::error!(
            identity_id = %report.identity_id,
            step = o.step,
            error = %o.error,
            "identity delete: step failed after the Kratos delete; rows left behind"
        );
    }
    if !report.orgs_left_without_owner.is_empty() {
        tracing::warn!(
            identity_id = %report.identity_id,
            orgs = %report.orgs_left_without_owner.join(", "),
            "identity delete: organizations left without an owner"
        );
    }
    tracing::info!(
        action = "identity.delete.done",
        reason = reason.as_str(),
        event_id = %report.event_id,
        identity_id = %report.identity_id,
        emails = report.emails.len(),
        removed = %report.removed.summary(),
        orphans = report.orphans.len(),
        "identity deleted"
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_url_is_read_from_the_forseti_namespace() {
        let meta = serde_json::json!({ "forseti": { "account_deletion_url": "https://x/y" } });
        assert_eq!(
            deletion_url_from_metadata(Some(&meta)).as_deref(),
            Some("https://x/y")
        );
        let empty = serde_json::json!({ "forseti": { "account_deletion_url": "" } });
        assert!(deletion_url_from_metadata(Some(&empty)).is_none());
        let other = serde_json::json!({ "account_deletion_url": "https://x/y" });
        assert!(deletion_url_from_metadata(Some(&other)).is_none());
        assert!(deletion_url_from_metadata(None).is_none());
    }

    #[test]
    fn only_verified_addresses_drive_email_matches() {
        use ory_client::models::verifiable_identity_address::ViaEnum;
        use ory_client::models::{Identity, VerifiableIdentityAddress};
        let addr = |value: &str, verified: bool| {
            VerifiableIdentityAddress::new(
                "completed".to_string(),
                value.to_string(),
                verified,
                ViaEnum::Email,
            )
        };
        let mut identity =
            Identity::new("id".to_string(), "default".to_string(), String::new(), None);
        identity.traits = Some(serde_json::json!({ "email": "Victim@Example.com" }));
        identity.verifiable_addresses = Some(vec![
            addr("Victim@Example.com", false),
            addr(" Mine@Example.com ", true),
            addr("mine@example.com", true),
        ]);
        assert_eq!(
            verified_emails(&identity),
            vec!["mine@example.com".to_string()]
        );
        identity.verifiable_addresses = None;
        assert!(verified_emails(&identity).is_empty());
    }

    #[test]
    fn reasons_map_to_actions_and_guards() {
        assert_eq!(
            DeleteReason::SelfService.action(),
            action::ACCOUNT_SELF_DELETED
        );
        assert_eq!(DeleteReason::Admin.action(), action::ADMIN_IDENTITY_DELETED);
        assert_eq!(DeleteReason::Cli.action(), action::ADMIN_IDENTITY_DELETED);
        assert_eq!(DeleteReason::Reclaim.action(), action::IDENTITY_RECLAIMED);
        assert_eq!(DeleteReason::Prune.action(), action::IDENTITY_PRUNED);
        for r in [
            DeleteReason::SelfService,
            DeleteReason::Admin,
            DeleteReason::Cli,
        ] {
            assert!(r.guards_sole_owner());
            assert!(r.removes_email_rows());
        }
        for r in [DeleteReason::Reclaim, DeleteReason::Prune] {
            assert!(!r.guards_sole_owner());
            assert!(!r.removes_email_rows());
        }
    }
}
