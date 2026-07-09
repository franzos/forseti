//! Verified-domain auto-join: the dashboard profile prompt and its explicit
//! `POST /orgs/domain-join` handler. Placement is always prompt-driven; there
//! is no silent background join.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::Router;
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::csrf::CsrfForm;
use crate::db::DbPool;
use crate::extractors::OptionalSession;
use crate::orgs::db::Org;
use crate::orgs::{self, Role};
use crate::ory;
use crate::state::AppState;

/// The resolved profile prompt: the proven `auto_join` org the caller may join,
/// plus the verified domain that authorized it (for the prompt copy).
pub(crate) struct ProvenJoin {
    pub(crate) org: Org,
    pub(crate) domain: String,
}

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/orgs/domain-join", post(domain_join_post))
}

/// True iff a verifiable address whose value equals `email` (ASCII
/// case-insensitive) is verified on the live session, mirroring the invite
/// flow's gate (`src/orgs/invite.rs`).
fn session_address_verified(session: &ory::Session, email: &str) -> bool {
    session
        .identity
        .as_ref()
        .and_then(|i| i.verifiable_addresses.as_ref())
        .map(|addrs| {
            addrs
                .iter()
                .any(|a| a.value.eq_ignore_ascii_case(email) && a.verified)
        })
        .unwrap_or(false)
}

/// Resolve the domain-join prompt for a live session: the proven `auto_join`
/// org the identity may join, when a VERIFIED session address's domain matches
/// and the identity isn't already a member. `None` when no prompt should show.
/// One `org_allowed_domains` lookup per call.
pub(crate) async fn resolve_prompt(
    db: &DbPool,
    session: &ory::Session,
    identity_id: &str,
    email: &str,
) -> Option<ProvenJoin> {
    if identity_id.is_empty() || email.is_empty() || !session_address_verified(session, email) {
        return None;
    }
    let org = orgs::lookup_proven_org_for_email(db, email)
        .await
        .ok()
        .flatten()?;
    if orgs::org_role(db, identity_id, &org.id).await.is_some() {
        return None;
    }
    let domain = orgs::email_domain(email)?;
    Some(ProvenJoin { org, domain })
}

#[derive(Debug, Deserialize)]
struct DomainJoinForm {
    /// Optional org slug from the prompt form; when present it must match the
    /// re-resolved proven org (defence against a stale/forged slug).
    #[serde(default)]
    org: Option<String>,
}

/// `POST /orgs/domain-join`: explicit verified-domain self-join. CSRF-protected,
/// no user-controlled `return_to` (always redirects to `/`). Re-resolves the
/// proven org and re-checks the verified address off the live session at POST
/// time (TOCTOU-safe), then joins as `Member` via the race-safe join + Default
/// drop helper.
async fn domain_join_post(
    State(state): State<AppState>,
    actx: AuditCtx,
    session: OptionalSession,
    CsrfForm(form): CsrfForm<DomainJoinForm>,
) -> Response {
    let session = match session {
        OptionalSession::Ok { session, .. } => *session,
        _ => return Redirect::to("/").into_response(),
    };
    let (identity_id, email) = crate::flow_view::session_principal(&session);
    let Some(proven) = resolve_prompt(&state.db, &session, &identity_id, &email).await else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    // A form-supplied slug must match the re-resolved proven org; never trust it.
    if let Some(slug) = form.org.as_deref().filter(|s| !s.is_empty()) {
        if slug != proven.org.slug {
            return (StatusCode::BAD_REQUEST, "org mismatch").into_response();
        }
    }
    let drop_default = !state.cfg.admin.is_admin(&email);
    if let Err(e) = orgs::db::join_org_race_safe(
        &state.db,
        &identity_id,
        &proven.org.id,
        Role::Member,
        drop_default,
    )
    .await
    {
        tracing::error!(error = ?e, org_id = %proven.org.id, "domain_join_post: join_org_race_safe failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not join").into_response();
    }
    let _ = audit::log(
        &state.db,
        AuditEvent::new(action::ORG_MEMBER_ADDED)
            .actor_user(&identity_id, &email)
            .target(target_kind::IDENTITY, identity_id.clone())
            .with_ctx(&actx)
            .metadata(audit_metadata!(
                "org_id" => &proven.org.id,
                "role" => Role::Member.as_str(),
                "via" => "domain_autojoin",
            )),
    )
    .await;
    Redirect::to("/").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::db::{self, test_pool};
    use crate::orgs::{AccessMode, DomainJoinPolicy, DEFAULT_ORG_ID};
    use ory_client::models::verifiable_identity_address::ViaEnum;
    use ory_client::models::{Identity, Session, VerifiableIdentityAddress};

    fn session_with(email: &str, verified: bool) -> Session {
        let addr = VerifiableIdentityAddress::new(
            "completed".to_string(),
            email.to_string(),
            verified,
            ViaEnum::Email,
        );
        let mut identity = Identity::new(
            "ident-1".to_string(),
            "default".to_string(),
            String::new(),
            None,
        );
        identity.traits = Some(serde_json::json!({ "email": email }));
        identity.verifiable_addresses = Some(vec![addr]);
        let mut session = Session::new("sess-1".to_string());
        session.identity = Some(Box::new(identity));
        session
    }

    async fn auto_join_org(db: &DbPool, id: &str, slug: &str, domain: &str) {
        db::create_org(db, id, slug, slug, None).await.unwrap();
        orgs::domains::add_pending_domain(db, id, domain, "dns_txt", "tok", None)
            .await
            .unwrap();
        orgs::domains::mark_domain_verified(db, id, domain)
            .await
            .unwrap();
        db::set_domain_join_policy(db, id, DomainJoinPolicy::AutoJoin)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prompt_resolves_for_verified_domain_user() {
        let db = test_pool().await;
        auto_join_org(&db, "acme-id", "acme", "acme.com").await;
        let session = session_with("owner@acme.com", true);
        let prompt = resolve_prompt(&db, &session, "ident-1", "owner@acme.com")
            .await
            .expect("prompt expected");
        assert_eq!(prompt.org.id, "acme-id");
        assert_eq!(prompt.domain, "acme.com");
    }

    #[tokio::test]
    async fn no_prompt_when_address_unverified() {
        let db = test_pool().await;
        auto_join_org(&db, "acme-id", "acme", "acme.com").await;
        let session = session_with("owner@acme.com", false);
        assert!(resolve_prompt(&db, &session, "ident-1", "owner@acme.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn no_prompt_for_invite_only_org() {
        let db = test_pool().await;
        // Proven domain but policy left at the invite_only default.
        db::create_org(&db, "acme-id", "acme", "Acme", None)
            .await
            .unwrap();
        orgs::domains::add_pending_domain(&db, "acme-id", "acme.com", "dns_txt", "tok", None)
            .await
            .unwrap();
        orgs::domains::mark_domain_verified(&db, "acme-id", "acme.com")
            .await
            .unwrap();
        let session = session_with("owner@acme.com", true);
        assert!(resolve_prompt(&db, &session, "ident-1", "owner@acme.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn no_prompt_for_non_matching_domain() {
        let db = test_pool().await;
        auto_join_org(&db, "acme-id", "acme", "acme.com").await;
        let session = session_with("user@other.com", true);
        assert!(resolve_prompt(&db, &session, "ident-1", "user@other.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn no_prompt_when_already_a_member() {
        let db = test_pool().await;
        auto_join_org(&db, "acme-id", "acme", "acme.com").await;
        db::add_member_race_safe(&db, "ident-1", "acme-id", Role::Member)
            .await
            .unwrap();
        let session = session_with("owner@acme.com", true);
        assert!(resolve_prompt(&db, &session, "ident-1", "owner@acme.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn no_prompt_for_external_org() {
        let db = test_pool().await;
        auto_join_org(&db, "acme-id", "acme", "acme.com").await;
        db::set_access_mode(&db, "acme-id", AccessMode::External)
            .await
            .unwrap();
        let session = session_with("owner@acme.com", true);
        assert!(resolve_prompt(&db, &session, "ident-1", "owner@acme.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn join_drops_default_and_makes_member() {
        // Mirrors the POST happy path at the db layer (drop_default = true for a
        // non-allowlisted identity): tenant membership added, Default dropped.
        let db = test_pool().await;
        auto_join_org(&db, "acme-id", "acme", "acme.com").await;
        db::add_member_race_safe(&db, "ident-1", DEFAULT_ORG_ID, Role::Member)
            .await
            .unwrap();
        db::join_org_race_safe(&db, "ident-1", "acme-id", Role::Member, true)
            .await
            .unwrap();
        assert_eq!(
            orgs::org_role(&db, "ident-1", "acme-id").await,
            Some(Role::Member)
        );
        assert_eq!(orgs::org_role(&db, "ident-1", DEFAULT_ORG_ID).await, None);
    }
}
