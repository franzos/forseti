//! Reusable destructive-admin actions.
//!
//! Centralises the "delete identity + write audit row" recipe so call
//! sites outside the admin handlers (e.g. `identity::claim_email`) don't
//! have to re-derive the audit-event shape — and so any post-delete
//! cleanup that grows in the future lands in one place.

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent, SafeMetadata};
use crate::ory;
use crate::state::AppState;

/// Caller-supplied context for [`delete_identity_audited`]. Distinct
/// from the audit `action` constants because the same recipe is used
/// from both the admin surface (`admin.identity.deleted`) and the
/// public claim-email flow (`identity.reclaimed`).
#[derive(Debug, Clone, Copy)]
pub(crate) enum DeleteReason {
    /// Initiated from the admin identity-delete handler. Actor is the
    /// admin running the action.
    AdminInitiated,
    /// Initiated from the public "claim this email" flow on a still-
    /// unverified identity. Actor is the deleted identity itself (the
    /// user re-claiming their own address).
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

/// Actor attribution for [`delete_identity_audited`]. Carries the shape
/// the audit row needs without leaking the broader caller context into
/// the helper.
pub(crate) enum DeleteActor<'a> {
    Admin {
        identity_id: &'a str,
        email: &'a str,
    },
    /// User reclaiming their own email — `identity_id` is the doomed
    /// identity itself; `email` is its address-of-record (best-effort).
    User {
        identity_id: &'a str,
        email: &'a str,
    },
}

/// Delete a Kratos identity and emit the audit row in one place.
///
/// On Kratos failure no audit row is written and the error is returned;
/// the caller decides how to surface the failure (HTML page, redirect,
/// etc.). Audit-side failures are swallowed by [`audit::log`] as usual
/// — the identity is gone regardless.
pub(crate) async fn delete_identity_audited(
    state: &AppState,
    target_identity_id: &str,
    actor: DeleteActor<'_>,
    reason: DeleteReason,
    metadata: SafeMetadata,
    ctx: Option<&AuditCtx>,
) -> anyhow::Result<()> {
    ory::kratos::admin_delete_identity(&state.ory, target_identity_id).await?;
    // Cascade: drop every org membership the deleted identity held.
    // Without this, the members page lists ghost rows and the last-owner
    // guard counts ex-owners as still present. Best-effort; the identity
    // is gone in Kratos regardless.
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

    // Cascade: purge POSIX rows. An orphaned posix_account would keep a
    // usable login (uid/ssh keys) for a deleted identity — log loudly but
    // never abort; the identity is gone in Kratos regardless.
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
