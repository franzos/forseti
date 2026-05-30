//! Tower middleware that fires the lazy auto-join into the Default org
//! once per request when a Kratos session is present. Hoisted out of the
//! `RequireSession` extractor so session resolution stays a pure read.
//!
//! Also caches the resolved [`ory::Session`] in request extensions so the
//! session extractors don't pay the whoami round-trip a second time. Any
//! failure (no cookie, Kratos transport hiccup) silently forwards to the
//! next handler — auto-join is opportunistic, the next authenticated
//! request retries.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::cookies;
use crate::ory;
use crate::state::AppState;

const KRATOS_SESSION_COOKIE: &str = "ory_kratos_session";

pub async fn auto_join_default_org(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    if cookies::read_cookie(req.headers(), KRATOS_SESSION_COOKIE).is_some() {
        let cookie = cookies::cookie_header(req.headers());
        match ory::kratos::whoami(&state.ory, (!cookie.is_empty()).then_some(cookie.as_str())).await
        {
            Ok(outcome) => {
                if let ory::kratos::WhoamiOutcome::Ok(session) = &outcome {
                    let (identity_id, email) = crate::flow_view::session_principal(session);
                    if !identity_id.is_empty() {
                        super::ensure_default_membership(
                            &state.db,
                            &state.cfg,
                            &identity_id,
                            &email,
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
pub(crate) struct CachedWhoami(pub(crate) ory::kratos::WhoamiOutcome);
