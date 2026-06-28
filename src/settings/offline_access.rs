//! `/settings/offline-access` — set, change, or clear a dedicated offline
//! passphrase. Forseti-owned POST surface (not a Kratos settings flow).
//!
//! The passphrase is NEVER echoed back, put in a redirect URL, logged, or
//! written to audit metadata: only the Argon2id verifier is stored, and the
//! audit row carries the identity id alone.

use crate::csrf::CsrfForm;
use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::audit::{self, action, target_kind, AuditCtx, AuditEvent};
use crate::audit_metadata;
use crate::flash;
use crate::page_chrome::PageChrome;
use crate::posix::{db, offline};
use crate::render::render;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "settings_offline_access.html")]
pub(crate) struct SettingsOfflineAccessTemplate {
    pub(crate) chrome: PageChrome,
    pub(crate) has_secret: bool,
    pub(crate) min_len: usize,
    pub(crate) flash: String,
    pub(crate) referrer_banner: Option<crate::handoff::ReferrerBannerView>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OfflinePassphraseForm {
    #[serde(default)]
    pub(crate) passphrase: String,
}

pub(crate) async fn settings_offline_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    csrf: crate::extractors::Csrf,
    banner: crate::handoff::ReferrerBanner,
) -> Response {
    if !state.cfg.posix.offline_auth_enabled {
        return (axum::http::StatusCode::NOT_FOUND, "offline auth disabled").into_response();
    }

    let has_secret = match db::get_offline_secret(&state.db, &sess.identity_id).await {
        Ok(row) => row.is_some(),
        Err(e) => {
            tracing::error!(error = ?e, "settings_offline_access: get_offline_secret failed");
            false
        }
    };

    let (flash_msg, clear_flash) = state.take_flash(&headers, "/settings/offline-access");
    let body = render(&SettingsOfflineAccessTemplate {
        chrome: PageChrome::from_parts(&state, sess.email, csrf.0),
        has_secret,
        min_len: state.cfg.posix.offline_min_len,
        flash: flash_msg,
        referrer_banner: banner.0,
    });
    flash::attach_set_cookie(body, clear_flash)
}

pub(crate) async fn settings_offline_access_save(
    State(state): State<AppState>,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    CsrfForm(form): CsrfForm<OfflinePassphraseForm>,
) -> Response {
    if !state.cfg.posix.offline_auth_enabled {
        return (axum::http::StatusCode::NOT_FOUND, "offline auth disabled").into_response();
    }

    let min_len = state
        .cfg
        .posix
        .offline_min_len
        .max(offline::OFFLINE_MIN_LEN);

    let msg = match offline::mint_verifier(&form.passphrase) {
        Ok(verifier) => {
            match db::upsert_offline_secret(
                &state.db,
                &sess.identity_id,
                &verifier,
                offline::OFFLINE_ALGO_VERSION,
            )
            .await
            {
                Ok(()) => {
                    let _ = audit::log(
                        &state.db,
                        AuditEvent::new(action::POSIX_OFFLINE_SECRET_SET)
                            .actor_user(&sess.identity_id, &sess.email)
                            .target(target_kind::IDENTITY, sess.identity_id.clone())
                            .with_ctx(&actx)
                            .metadata(audit_metadata!(
                                "algo_version" => i64::from(offline::OFFLINE_ALGO_VERSION),
                            )),
                    )
                    .await;
                    "Offline passphrase saved. Enrolled hosts will pick it up on their next sync."
                        .to_string()
                }
                Err(e) => {
                    tracing::error!(error = ?e, "settings_offline_access_save: upsert failed");
                    "Could not save your offline passphrase. Please try again.".to_string()
                }
            }
        }
        Err(offline::SetSecretError::TooShort) => {
            format!("Your offline passphrase must be at least {min_len} characters.")
        }
    };

    state.flash_redirect("/settings/offline-access", &msg)
}

pub(crate) async fn settings_offline_access_clear(
    State(state): State<AppState>,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    if !state.cfg.posix.offline_auth_enabled {
        return (axum::http::StatusCode::NOT_FOUND, "offline auth disabled").into_response();
    }

    let msg = match db::delete_offline_secret(&state.db, &sess.identity_id).await {
        Ok(removed) => {
            if removed {
                let _ = audit::log(
                    &state.db,
                    AuditEvent::new(action::POSIX_OFFLINE_SECRET_CLEARED)
                        .actor_user(&sess.identity_id, &sess.email)
                        .target(target_kind::IDENTITY, sess.identity_id.clone())
                        .with_ctx(&actx),
                )
                .await;
                "Offline passphrase removed. Hosts will drop it on their next sync."
            } else {
                "You don't have an offline passphrase set."
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "settings_offline_access_clear: delete failed");
            "Could not remove your offline passphrase. Please try again."
        }
    };

    state.flash_redirect("/settings/offline-access", msg)
}
