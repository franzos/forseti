//! Shared page-chrome view-model embedded in every template struct.
//!
//! `base.html`, `card.html`, and `admin/admin_shell.html` all consume the
//! same four fields (brand, version, user_email, csrf_token). Before this
//! struct existed each child template re-declared them as four flat
//! fields, so adding a new chrome field meant editing ~34 structs and
//! every constructor. The embedded-struct shape collapses that to one
//! place: add a field here, then read it from `chrome.<field>` in the
//! base template.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;

use crate::config::BrandConfig;
use crate::extractors::{app_state, Csrf, OptionalSession};
use crate::state::AppState;
use crate::web::FORSETI_VERSION;

/// Page chrome shared by every template that extends `base.html` or
/// `card.html`. The four fields show up in the header (`user_email`,
/// `csrf_token` for the logout button) and footer (`version`,
/// `brand.name`).
pub(crate) struct PageChrome {
    pub(crate) brand: BrandConfig,
    pub(crate) version: &'static str,
    /// Empty string for anonymous pages — `base.html` hides the
    /// "Signed in as / Sign out" block when empty.
    pub(crate) user_email: String,
    /// Empty string for pages outside CSRF middleware. The logout button
    /// in `base.html` won't render usefully without it, but it stays
    /// hidden anyway when `user_email` is empty.
    pub(crate) csrf_token: String,
    /// True when `user_email` is in `[admin].allowed_emails`. Drives the
    /// "Admin" top-nav link in `base.html`.
    pub(crate) is_admin: bool,
    /// Appearance preference, read from the `forseti_theme` cookie by the
    /// `Chrome` extractor. Defaults to `System` for directly-constructed
    /// chrome (error boundary etc.) — the client script still applies it.
    pub(crate) theme_pref: crate::theme::ThemePref,
}

impl PageChrome {
    /// Build from pre-extracted parts. `user_email` is the empty string
    /// for anonymous / error pages; `csrf_token` is the empty string
    /// outside CSRF middleware. `is_admin` is derived from the operator
    /// allowlist, so anonymous pages (empty email) never get the flag.
    pub(crate) fn from_parts(state: &AppState, user_email: String, csrf_token: String) -> Self {
        let is_admin = state.cfg.admin.is_admin(&user_email);
        Self::from_brand_with_admin(state.cfg.brand.clone(), user_email, csrf_token, is_admin)
    }

    /// Assemble from an already-snapshotted brand plus an explicit admin
    /// verdict. The single place the chrome literal is built.
    pub(crate) fn from_brand_with_admin(
        brand: BrandConfig,
        user_email: String,
        csrf_token: String,
        is_admin: bool,
    ) -> Self {
        Self {
            brand,
            version: FORSETI_VERSION,
            user_email,
            csrf_token,
            is_admin,
            theme_pref: crate::theme::ThemePref::System,
        }
    }
}

/// Extractor that builds a [`PageChrome`] from the current request:
/// probes the session for the user email, reads the CSRF token from the
/// middleware-set extension, and snapshots the brand from state. Handlers
/// take this instead of plumbing `OptionalSession` + `Csrf` separately
/// when all they want is to render chrome.
pub(crate) struct Chrome(pub(crate) PageChrome);

impl<S> FromRequestParts<S> for Chrome
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = OptionalSession::from_request_parts(parts, state)
            .await
            .expect("OptionalSession extractor is infallible");
        let user_email = session.email().unwrap_or_default().to_string();
        let app_state = app_state(parts, state).await;
        let csrf = Csrf::from_request_parts(parts, state)
            .await
            .expect("Csrf extractor is infallible");
        let mut chrome = PageChrome::from_parts(&app_state, user_email, csrf.0);
        chrome.theme_pref = crate::theme::read_theme_cookie(&parts.headers);
        Ok(Chrome(chrome))
    }
}
