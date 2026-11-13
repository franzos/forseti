//! Tower middleware firing the lazy Default-org floor once per request when a
//! Kratos session is present, kept out of `RequireSession` so session
//! resolution stays a pure read.
//!
//! Caches the resolved session in request extensions so the extractors skip a
//! second whoami. Any failure forwards silently; auto-join is opportunistic
//! and the next authenticated request retries.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::backend::IdentityBackend;
use crate::backend::identity::WhoamiOutcome;
use crate::cookies;
use crate::state::AppState;

/// A request to this exact path is mid external-self-serve join; force-
/// joining Default here first would strand the user in the wrong org.
const JOIN_CONFIRM_PATH: &str = "/join/confirm";

fn is_join_confirm_path(path: &str) -> bool {
    path == JOIN_CONFIRM_PATH
}

pub async fn auto_join_default_org(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    if state.identity.has_session_cookie(req.headers()) {
        let cookie = cookies::cookie_header(req.headers());
        match state
            .identity
            .whoami((!cookie.is_empty()).then_some(cookie.as_str()))
            .await
        {
            Ok(outcome) => {
                if let WhoamiOutcome::Ok(session) = &outcome {
                    let (identity_id, email) = session.principal();
                    if !identity_id.is_empty() && !is_join_confirm_path(req.uri().path()) {
                        super::ensure_default_floor(
                            &state.db,
                            &state.cfg.admin,
                            &identity_id,
                            &email,
                            session.addresses(),
                        )
                        .await;
                    }
                }
                req.extensions_mut().insert(CachedWhoami(outcome));
            }
            Err(e) => {
                tracing::debug!(error = ?e, "auto_join_default_org: whoami failed; forwarding");
            }
        }
    }
    next.run(req).await
}

#[derive(Clone)]
pub(crate) struct CachedWhoami(pub(crate) WhoamiOutcome);

#[cfg(test)]
mod tests {
    #[test]
    fn join_confirm_path_matches_exactly() {
        assert!(super::is_join_confirm_path("/join/confirm"));
        assert!(!super::is_join_confirm_path("/join/confirm/"));
        assert!(!super::is_join_confirm_path("/"));
        assert!(!super::is_join_confirm_path("/join/confirmx"));
    }
}
