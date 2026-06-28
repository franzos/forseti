//! Reusable destructive-admin actions.
//!
//! Centralises the "delete identity + write audit row" recipe so call sites
//! outside the admin handlers (e.g. `identity::claim_email`) reuse one shape.

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent, SafeMetadata};
use crate::ory;
use crate::state::AppState;

/// Caller-supplied context for [`delete_identity_audited`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum DeleteReason {
    AdminInitiated,
    EmailReclaim,
}

impl DeleteReason {
    fn action(self) -> &'static str {
        match self {
            DeleteReason::AdminInitiated => action::ADMIN_IDENTITY_DELETED,
            DeleteReason::EmailReclaim => action::IDENTITY_RECLAIMED,
        }
    }
}

/// Actor attribution for [`delete_identity_audited`].
pub(crate) enum DeleteActor<'a> {
    Admin {
        identity_id: &'a str,
        email: &'a str,
    },
    /// User reclaiming their own email; `identity_id` is the doomed identity.
    User {
        identity_id: &'a str,
        email: &'a str,
    },
}

/// Delete a Kratos identity and emit the audit row in one place.
///
/// On Kratos failure no audit row is written and the error is returned. Audit
/// failures are swallowed by [`audit::log`]; the identity is gone regardless.
pub(crate) async fn delete_identity_audited(
    state: &AppState,
    target_identity_id: &str,
    actor: DeleteActor<'_>,
    reason: DeleteReason,
    metadata: SafeMetadata,
    ctx: Option<&AuditCtx>,
) -> anyhow::Result<()> {
    ory::kratos::admin_delete_identity(&state.ory, target_identity_id).await?;
    // Cascade: drop org memberships, else the members page lists ghost rows
    // and the last-owner guard counts ex-owners. Best-effort.
    match crate::orgs::db::remove_member_everywhere(&state.db, target_identity_id).await {
        Ok(n) if n > 0 => tracing::info!(
            target = target_identity_id,
            removed = n,
            "cascaded identity delete: removed org memberships"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            error = ?e,
            target = target_identity_id,
            "cascaded identity delete: org_members cleanup failed"
        ),
    }

    // Cascade: purge POSIX rows, else an orphaned posix_account keeps a usable
    // login (uid/ssh keys) for a deleted identity. Best-effort.
    if let Err(e) = crate::posix::db::delete_account_rows(&state.db, target_identity_id).await {
        tracing::error!(error = ?e, identity_id = %target_identity_id, "failed to purge posix rows on identity delete");
    }

    let mut event = AuditEvent::new(reason.action())
        .target(target_kind::IDENTITY, target_identity_id.to_string())
        .critical()
        .metadata(metadata);
    event = match actor {
        DeleteActor::Admin { identity_id, email } => event.actor_admin(identity_id, email),
        DeleteActor::User { identity_id, email } if !email.is_empty() => {
            event.actor_user(identity_id, email)
        }
        DeleteActor::User { .. } => event,
    };
    if let Some(c) = ctx {
        event = event.with_ctx(c);
    }
    let _ = audit::log(&state.db, event).await;
    Ok(())
}
