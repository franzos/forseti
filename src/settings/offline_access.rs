//! `/settings/offline-access` — set, change, or clear a dedicated offline
//! passphrase. Forseti-owned POST surface (not a Kratos settings flow).
//!
//! The passphrase is NEVER echoed back, put in a redirect URL, logged, or
//! written to audit metadata: only the Argon2id verifier is stored, and the
//! audit row carries the identity id alone.

use crate::csrf::CsrfForm;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use unic_langid::LanguageIdentifier;

use crate::audit::{self, AuditCtx, AuditEvent, action, target_kind};
use crate::audit_metadata;
use crate::flash;
use crate::page_chrome::{PageChrome, ThemedChrome};
use crate::posix::{db, offline};
use crate::render::render;
use crate::settings::{SettingsSection, fetch_settings_subpage};
use crate::state::AppState;
use crate::web::FlowQuery;

/// Require a recent sign-in, at AAL2 where the identity has a second factor.
/// The Kratos settings flow supplies the AAL check and the dispatcher the
/// recency check; its nodes are unused because this page isn't a Kratos flow.
/// Returns the flow id, which the page's forms carry back on submit.
async fn privileged_gate(
    state: &AppState,
    headers: &HeaderMap,
    query: &FlowQuery,
    sess: &crate::extractors::RequireSession,
    locale: &LanguageIdentifier,
) -> Result<String, Response> {
    let (_, flow) = fetch_settings_subpage(
        state,
        headers,
        query,
        SettingsSection::OfflineAccess,
        sess,
        locale,
    )
    .await?;
    Ok(flow
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string())
}

#[derive(Template)]
#[template(path = "settings_offline_access.html")]
pub(crate) struct SettingsOfflineAccessTemplate {
    pub(crate) chrome: PageChrome,
    /// Without it in the form actions, the POST bounces to a fresh Kratos init.
    pub(crate) flow_id: String,
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
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    banner: crate::handoff::ReferrerBanner,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    themed: ThemedChrome,
) -> Response {
    if !state.cfg.posix.offline_auth_enabled {
        return (axum::http::StatusCode::NOT_FOUND, "offline auth disabled").into_response();
    }

    // Gate the page too, so the bounce can't eat a typed passphrase.
    let flow_id = match privileged_gate(&state, &headers, &query, &sess, &locale).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let has_secret = match db::get_offline_secret(&state.db, &sess.identity_id).await {
        Ok(row) => row.is_some(),
        Err(e) => {
            tracing::error!(error = ?e, "settings_offline_access: get_offline_secret failed");
            false
        }
    };

    let (flash_msg, clear_flash) = state.take_flash(&headers, "/settings/offline-access");
    let body = render(&SettingsOfflineAccessTemplate {
        chrome: themed.chrome,
        flow_id,
        has_secret,
        min_len: state.cfg.posix.offline_min_len,
        flash: flash_msg,
        referrer_banner: banner.0,
    });
    flash::attach_set_cookie(body, clear_flash)
}

pub(crate) async fn settings_offline_access_save(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    CsrfForm(form): CsrfForm<OfflinePassphraseForm>,
) -> Response {
    if !state.cfg.posix.offline_auth_enabled {
        return (axum::http::StatusCode::NOT_FOUND, "offline auth disabled").into_response();
    }

    if let Err(resp) = privileged_gate(&state, &headers, &query, &sess, &locale).await {
        return resp;
    }

    let min_len = state
        .cfg
        .posix
        .offline_min_len
        .max(offline::OFFLINE_MIN_LEN);

    // Argon2id at m=64MiB/t=3 is too heavy to run on the async runtime, and
    // each concurrent hash reserves that 64 MiB. The rate limiter on the route
    // bounds one client; this bounds the process, so a spread of clients can't
    // turn the endpoint into a memory exhaustion primitive. `try_acquire`, not
    // `acquire`: queueing here would hold requests open and pile up the very
    // memory the permit is rationing.
    let Ok(_permit) = hash_semaphore(&state).try_acquire() else {
        tracing::warn!("settings/offline-access: hash concurrency cap reached; shedding");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            [("retry-after", "5")],
            "Busy. Try again in a moment.",
        )
            .into_response();
    };
    let minted =
        tokio::task::spawn_blocking(move || offline::mint_verifier(&form.passphrase, min_len))
            .await;

    let msg = match minted {
        Ok(Ok(verifier)) => {
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
                    crate::i18n::lookup(&locale, "flash-offline-passphrase-saved")
                }
                Err(e) => {
                    tracing::error!(error = ?e, "settings_offline_access_save: upsert failed");
                    crate::i18n::lookup(&locale, "flash-offline-passphrase-save-failed")
                }
            }
        }
        Ok(Err(offline::SetSecretError::TooShort)) => {
            let mut args: std::collections::HashMap<
                std::borrow::Cow<'static, str>,
                fluent_templates::fluent_bundle::FluentValue,
            > = std::collections::HashMap::new();
            args.insert(
                std::borrow::Cow::Borrowed("min_len"),
                (min_len as i64).into(),
            );
            crate::i18n::lookup_args(&locale, "flash-offline-passphrase-too-short", &args)
        }
        Err(e) => {
            tracing::error!(error = ?e, "settings_offline_access_save: mint task failed");
            crate::i18n::lookup(&locale, "flash-offline-passphrase-save-failed")
        }
    };

    state.flash_redirect("/settings/offline-access", &msg)
}

pub(crate) async fn settings_offline_access_clear(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
    headers: HeaderMap,
    sess: crate::extractors::RequireSession,
    actx: AuditCtx,
    crate::page_chrome::ReqLocale(locale): crate::page_chrome::ReqLocale,
    _: CsrfForm<crate::csrf::NoPayload>,
) -> Response {
    if !state.cfg.posix.offline_auth_enabled {
        return (axum::http::StatusCode::NOT_FOUND, "offline auth disabled").into_response();
    }

    if let Err(resp) = privileged_gate(&state, &headers, &query, &sess, &locale).await {
        return resp;
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
                crate::i18n::lookup(&locale, "flash-offline-passphrase-removed")
            } else {
                crate::i18n::lookup(&locale, "flash-offline-passphrase-none")
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "settings_offline_access_clear: delete failed");
            crate::i18n::lookup(&locale, "flash-offline-passphrase-remove-failed")
        }
    };

    state.flash_redirect("/settings/offline-access", &msg)
}

/// Process-wide permit pool for offline-passphrase hashing, sized from
/// `[posix].offline_hash_concurrency`. A `OnceLock` rather than a field on
/// `AppState` so the cap is shared by every clone of the state.
fn hash_semaphore(state: &AppState) -> &'static tokio::sync::Semaphore {
    static SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| tokio::sync::Semaphore::new(state.cfg.posix.offline_hash_concurrency.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrandConfig;

    #[test]
    fn both_forms_carry_the_flow_id() {
        let brand = BrandConfig {
            name: "Forseti".to_string(),
            support_email: None,
            logo_url: None,
            consent_intro: String::new(),
            theme_preset: None,
            brand_primary: None,
            brand_on_primary: None,
            brand_secondary: None,
            operator_trust_anchor: None,
        };
        let html = SettingsOfflineAccessTemplate {
            chrome: PageChrome::from_brand_with_admin(
                brand,
                String::new(),
                "csrf".to_string(),
                false,
                "en".parse().unwrap(),
            ),
            flow_id: "flow-123".to_string(),
            has_secret: true,
            min_len: 12,
            flash: String::new(),
            referrer_banner: None,
        }
        .render()
        .unwrap();
        assert!(html.contains(r#"action="/settings/offline-access?flow=flow-123""#));
        assert!(html.contains(r#"action="/settings/offline-access/clear?flow=flow-123""#));
    }
}
